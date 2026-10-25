use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::RedemptionFailureReason::{
    EmailChanged, Expired, Malformed, SignupFinished, SignupUnfinished, Unknown, UserDisabled,
    UserNotFound, WrongPurpose,
};
use crate::audit::{AuditDispatch, AuditEventKind, RedemptionFailureReason, SecretKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::session::SessionContext;
use crate::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, RegistrationPurpose,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, User, UserId,
};
use crate::user_records::UserRecords;

pub(crate) trait SingleUseSecret {
    type Purpose: PartialEq + Copy;
    fn secret(purpose: Self::Purpose) -> SecretKind;
    fn purpose(&self) -> Self::Purpose;
    fn expires_at(&self) -> DateTime<Utc>;
}

pub(crate) trait OwnedSecret: SingleUseSecret {
    fn owner(&self) -> UserId;
    fn owner_email(&self) -> Option<&str>;
    fn signup_stage(purpose: Self::Purpose) -> SignupStage;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignupStage {
    Unfinished,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerRefusal {
    UserDisabled,
    WrongSignupStage,
}

// A secret belongs to its owner only while they are active and at the point in signup its purpose
// needs: a signup secret only until signup has finished, since from then on only recovery brings
// the user back, with its cool-down; every other secret only once it has.
pub(crate) fn owner_refusal(owner: &User, stage: SignupStage) -> Option<OwnerRefusal> {
    if !owner.status.is_active() {
        Some(OwnerRefusal::UserDisabled)
    } else if owner.has_finished_signup() != (stage == SignupStage::Finished) {
        Some(OwnerRefusal::WrongSignupStage)
    } else {
        None
    }
}

impl SingleUseSecret for EmailLink {
    type Purpose = EmailLinkPurpose;

    fn secret(purpose: EmailLinkPurpose) -> SecretKind {
        match purpose {
            EmailLinkPurpose::Signup => SecretKind::SignupLink,
            EmailLinkPurpose::Recovery => SecretKind::RecoveryLink,
            EmailLinkPurpose::EmailChange => SecretKind::EmailChangeLink,
        }
    }

    fn purpose(&self) -> EmailLinkPurpose {
        self.purpose
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl OwnedSecret for EmailLink {
    fn owner(&self) -> UserId {
        self.user_id
    }

    fn owner_email(&self) -> Option<&str> {
        self.owner_email.as_deref()
    }

    fn signup_stage(purpose: EmailLinkPurpose) -> SignupStage {
        match purpose {
            EmailLinkPurpose::Signup => SignupStage::Unfinished,
            EmailLinkPurpose::Recovery | EmailLinkPurpose::EmailChange => SignupStage::Finished,
        }
    }
}

impl SingleUseSecret for StoredPasskeyRegistration {
    type Purpose = RegistrationPurpose;

    fn secret(_: RegistrationPurpose) -> SecretKind {
        SecretKind::RegistrationChallenge
    }

    fn purpose(&self) -> RegistrationPurpose {
        self.purpose
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl OwnedSecret for StoredPasskeyRegistration {
    fn owner(&self) -> UserId {
        self.user_id
    }

    fn owner_email(&self) -> Option<&str> {
        self.owner_email.as_deref()
    }

    fn signup_stage(purpose: RegistrationPurpose) -> SignupStage {
        match purpose {
            RegistrationPurpose::Signup => SignupStage::Unfinished,
            RegistrationPurpose::Recovery | RegistrationPurpose::AddPasskey => {
                SignupStage::Finished
            }
        }
    }
}

impl SingleUseSecret for StoredPasskeyAuthentication {
    type Purpose = AuthenticationPurpose;

    fn secret(purpose: AuthenticationPurpose) -> SecretKind {
        match purpose {
            AuthenticationPurpose::Login => SecretKind::LoginChallenge,
            AuthenticationPurpose::Reauth => SecretKind::ReauthChallenge,
        }
    }

    fn purpose(&self) -> AuthenticationPurpose {
        self.purpose
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

#[derive(Clone)]
pub(crate) struct Redeemer {
    records: UserRecords,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl Redeemer {
    pub(crate) fn from_deps(deps: &CoreDeps) -> Self {
        Self {
            records: UserRecords::new(deps),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
        }
    }

    // `owner` is the user a refusal names, since the secret itself names nobody.
    pub(crate) async fn check<S: SingleUseSecret, T>(
        &self,
        taken: Option<S>,
        expected: S::Purpose,
        owner: Option<UserId>,
        decode: impl FnOnce(S) -> Result<T>,
        context: &SessionContext,
    ) -> Result<T> {
        let secret = S::secret(expected);
        let Some(taken) = taken else {
            return Err(self.refuse(secret, owner, Unknown, context).await);
        };
        let reason = if taken.purpose() != expected {
            WrongPurpose
        } else if taken.expires_at() <= self.clock.now() {
            Expired
        } else {
            match decode(taken) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    tracing::warn!(%error, "single-use secret payload did not decode");
                    Malformed
                }
            }
        };
        Err(self.refuse(secret, owner, reason, context).await)
    }

    // A secret issued against an email address is good only while that address is still its
    // owner's.
    pub(crate) async fn check_owned<S: OwnedSecret, T>(
        &self,
        taken: Option<S>,
        expected: S::Purpose,
        decode: impl FnOnce(S) -> Result<T>,
        context: &SessionContext,
    ) -> Result<(User, T)> {
        let secret = S::secret(expected);
        let Some((owner, owner_email)) = taken
            .as_ref()
            .map(|taken| (taken.owner(), taken.owner_email().map(str::to_owned)))
        else {
            return Err(self.refuse(secret, None, Unknown, context).await);
        };
        let value = self
            .check(taken, expected, Some(owner), decode, context)
            .await?;
        let stage = S::signup_stage(expected);
        let reason = match self.records.find(owner).await {
            Ok(user) => match owner_refusal(&user, stage) {
                Some(OwnerRefusal::UserDisabled) => UserDisabled,
                Some(OwnerRefusal::WrongSignupStage) => match stage {
                    SignupStage::Unfinished => SignupFinished,
                    SignupStage::Finished => SignupUnfinished,
                },
                None if owner_email.is_some() && user.email != owner_email => EmailChanged,
                None => return Ok((user, value)),
            },
            Err(Error::UserNotFound) => UserNotFound,
            Err(error) => return Err(error),
        };
        Err(self.refuse(secret, Some(owner), reason, context).await)
    }

    pub(crate) async fn refuse(
        &self,
        secret: SecretKind,
        user_id: Option<UserId>,
        reason: RedemptionFailureReason,
        context: &SessionContext,
    ) -> Error {
        self.audit
            .emit(
                context,
                AuditEventKind::RedemptionFailed {
                    user_id,
                    secret,
                    reason,
                },
            )
            .await;
        refusal_error(secret, reason)
    }
}

fn refusal_error(secret: SecretKind, reason: RedemptionFailureReason) -> Error {
    if reason == UserDisabled {
        return Error::UserDisabled;
    }
    match secret {
        SecretKind::RegistrationChallenge | SecretKind::LoginChallenge => {
            Error::InvalidPasskeyChallenge
        }
        SecretKind::ReauthChallenge => Error::ReauthRequired,
        SecretKind::SignupLink | SecretKind::RecoveryLink | SecretKind::EmailChangeLink => {
            Error::InvalidEmailLink
        }
    }
}
