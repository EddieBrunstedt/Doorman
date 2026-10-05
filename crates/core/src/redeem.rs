use std::sync::Arc;

use chrono::{DateTime, Utc};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

use crate::audit::RedemptionFailureReason::{
    AccountDisabled, Expired, Malformed, Unknown, UserNotFound, WrongPurpose,
};
use crate::audit::{
    Actor, AuditDispatch, AuditEvent, AuditEventKind, RedemptionFailureReason, SecretKind,
};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::{
    decode_authentication_state, decode_passkey_authentication_state, decode_registration_state,
};
use crate::session::SessionContext;
use crate::storage::{
    AuthenticationPurpose, PasskeyChallengeId, PasskeyChallengeStore, Storage, User, UserId,
    UserStore, VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use crate::token::hash_token;
use crate::user::find_active_user;

pub(crate) struct RedeemedRegistration {
    pub user: User,
    pub state: PasskeyRegistration,
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub(crate) struct Redeemer {
    users: Arc<dyn UserStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl Redeemer {
    pub(crate) fn new(storage: &Storage, clock: Arc<dyn Clock>, audit: AuditDispatch) -> Self {
        Self {
            users: storage.users.clone(),
            challenges: storage.passkey_challenges.clone(),
            tokens: storage.verification_tokens.clone(),
            clock,
            audit,
        }
    }

    pub(crate) fn from_deps(deps: &CoreDeps) -> Self {
        Self {
            users: deps.users.clone(),
            challenges: deps.passkey_challenges.clone(),
            tokens: deps.verification_tokens.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
        }
    }

    pub(crate) async fn registration(
        &self,
        id: PasskeyChallengeId,
        context: &SessionContext,
    ) -> Result<RedeemedRegistration> {
        let secret = SecretKind::RegistrationChallenge;
        let Some(stored) = self.challenges.take_registration(id).await? else {
            return Err(self.refuse(secret, None, Unknown, context).await);
        };
        let owner = Some(stored.user_id);
        self.check_live(secret, owner, true, stored.expires_at, context)
            .await?;
        let state = self
            .decode(
                secret,
                owner,
                decode_registration_state(&stored.state),
                context,
            )
            .await?;
        let user = self.owner(secret, stored.user_id, context).await?;
        Ok(RedeemedRegistration {
            user,
            state,
            recovery_cooldown_until: stored.recovery_cooldown_until,
        })
    }

    pub(crate) async fn login(
        &self,
        id: PasskeyChallengeId,
        context: &SessionContext,
    ) -> Result<DiscoverableAuthentication> {
        let secret = SecretKind::LoginChallenge;
        let Some(stored) = self.challenges.take_authentication(id).await? else {
            return Err(self.refuse(secret, None, Unknown, context).await);
        };
        let purpose_matches = stored.purpose == AuthenticationPurpose::Login;
        self.check_live(secret, None, purpose_matches, stored.expires_at, context)
            .await?;
        self.decode(
            secret,
            None,
            decode_authentication_state(&stored.state),
            context,
        )
        .await
    }

    pub(crate) async fn reauth(
        &self,
        id: PasskeyChallengeId,
        user_id: UserId,
        context: &SessionContext,
    ) -> Result<PasskeyAuthentication> {
        let secret = SecretKind::ReauthChallenge;
        let owner = Some(user_id);
        let Some(stored) = self.challenges.take_authentication(id).await? else {
            return Err(self.refuse(secret, owner, Unknown, context).await);
        };
        let purpose_matches = stored.purpose == AuthenticationPurpose::Reauth;
        self.check_live(secret, owner, purpose_matches, stored.expires_at, context)
            .await?;
        self.decode(
            secret,
            owner,
            decode_passkey_authentication_state(&stored.state),
            context,
        )
        .await
    }

    pub(crate) async fn link<T>(
        &self,
        token: &str,
        purpose: VerificationPurpose,
        context: &SessionContext,
        payload: impl FnOnce(&VerificationToken) -> Option<T>,
    ) -> Result<(User, T)> {
        let secret = link_secret(purpose);
        let hash = hash_token(token);
        let Some(record) = self.tokens.consume_token(&hash, purpose).await? else {
            return Err(self.refuse(secret, None, Unknown, context).await);
        };
        let owner = Some(record.user_id);
        self.check_live(
            secret,
            owner,
            record.purpose == purpose,
            record.expires_at,
            context,
        )
        .await?;
        let Some(value) = payload(&record) else {
            return Err(self.refuse(secret, owner, Malformed, context).await);
        };
        let user = self.owner(secret, record.user_id, context).await?;
        Ok((user, value))
    }

    async fn check_live(
        &self,
        secret: SecretKind,
        owner: Option<UserId>,
        purpose_matches: bool,
        expires_at: DateTime<Utc>,
        context: &SessionContext,
    ) -> Result<()> {
        let reason = if !purpose_matches {
            WrongPurpose
        } else if expires_at <= self.clock.now() {
            Expired
        } else {
            return Ok(());
        };
        Err(self.refuse(secret, owner, reason, context).await)
    }

    async fn decode<T>(
        &self,
        secret: SecretKind,
        owner: Option<UserId>,
        decoded: Result<T>,
        context: &SessionContext,
    ) -> Result<T> {
        match decoded {
            Ok(value) => Ok(value),
            Err(error) => {
                tracing::warn!(%error, "single-use secret payload did not decode");
                Err(self.refuse(secret, owner, Malformed, context).await)
            }
        }
    }

    async fn owner(
        &self,
        secret: SecretKind,
        user_id: UserId,
        context: &SessionContext,
    ) -> Result<User> {
        match find_active_user(self.users.as_ref(), user_id).await {
            Ok(user) => Ok(user),
            Err(Error::UserNotFound) => Err(self
                .refuse(secret, Some(user_id), UserNotFound, context)
                .await),
            Err(Error::AccountDisabled) => Err(self
                .refuse(secret, Some(user_id), AccountDisabled, context)
                .await),
            Err(error) => Err(error),
        }
    }

    async fn refuse(
        &self,
        secret: SecretKind,
        user_id: Option<UserId>,
        reason: RedemptionFailureReason,
        context: &SessionContext,
    ) -> Error {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::RedemptionFailed {
                    user_id,
                    secret,
                    reason,
                },
            })
            .await;
        refusal_error(secret, reason)
    }
}

fn link_secret(purpose: VerificationPurpose) -> SecretKind {
    match purpose {
        VerificationPurpose::Signup => SecretKind::SignupLink,
        VerificationPurpose::Recovery => SecretKind::RecoveryLink,
        VerificationPurpose::EmailChange => SecretKind::EmailChangeLink,
    }
}

fn refusal_error(secret: SecretKind, reason: RedemptionFailureReason) -> Error {
    if reason == AccountDisabled {
        return Error::AccountDisabled;
    }
    match secret {
        SecretKind::RegistrationChallenge | SecretKind::LoginChallenge => {
            Error::InvalidPasskeyChallenge
        }
        SecretKind::ReauthChallenge => Error::ReauthRequired,
        SecretKind::SignupLink | SecretKind::RecoveryLink | SecretKind::EmailChangeLink => {
            Error::InvalidVerificationToken
        }
    }
}
