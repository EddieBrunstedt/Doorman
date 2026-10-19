use std::num::NonZeroU32;
use std::sync::Arc;

use webauthn_rs::prelude::{RegisterPublicKeyCredential, Webauthn};

use crate::audit::{AuditDispatch, AuditEventKind};
use crate::challenge::{PasskeyChallenges, RedeemedRegistration};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::{PasskeyConfig, PasskeyMetadata, StartedRegistration, encode_passkey};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::session::{ResolvedSession, SessionContext};
use crate::storage::{
    PasskeyChallengeId, PasskeyStore, RegistrationPurpose, SessionId, StoredPasskey, User, UserId,
};
use crate::user_records::UserRecords;

#[derive(Debug, Clone, Copy)]
pub(crate) enum RegistrationSource<'a> {
    SignupLink(&'a User),
    RecoveryLink(&'a User),
    Session(&'a ResolvedSession),
}

impl RegistrationSource<'_> {
    const fn purpose(self) -> RegistrationPurpose {
        match self {
            Self::SignupLink(_) => RegistrationPurpose::Signup,
            Self::RecoveryLink(_) => RegistrationPurpose::Recovery,
            Self::Session(_) => RegistrationPurpose::AddPasskey,
        }
    }

    fn session_id(self) -> Option<SessionId> {
        match self {
            Self::SignupLink(_) | Self::RecoveryLink(_) => None,
            Self::Session(session) => Some(session.id),
        }
    }

    // An email link proved control of the owner's address, so its registration is good only
    // while that address is theirs; a session proves nothing about the address.
    fn owner_email(self) -> Option<String> {
        match self {
            Self::SignupLink(user) | Self::RecoveryLink(user) => user.email.clone(),
            Self::Session(_) => None,
        }
    }
}

// Who finishes a registration must be who started it: the same kind of email link, or the same
// session.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RegistrationFinish<'a> {
    SignupLink,
    RecoveryLink,
    Session(&'a ResolvedSession),
}

impl RegistrationFinish<'_> {
    const fn purpose(self) -> RegistrationPurpose {
        match self {
            Self::SignupLink => RegistrationPurpose::Signup,
            Self::RecoveryLink => RegistrationPurpose::Recovery,
            Self::Session(_) => RegistrationPurpose::AddPasskey,
        }
    }

    fn session_id(self) -> Option<SessionId> {
        match self {
            Self::SignupLink | Self::RecoveryLink => None,
            Self::Session(session) => Some(session.id),
        }
    }
}

pub(crate) struct RegisteredPasskey {
    pub user: User,
    pub passkey: StoredPasskey,
    pub passkey_count: u64,
}

#[derive(Clone)]
pub(crate) struct PasskeyRegistrations {
    records: UserRecords,
    passkeys: Arc<dyn PasskeyStore>,
    challenges: PasskeyChallenges,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    webauthn: Arc<Webauthn>,
    max_passkeys_per_user: Option<NonZeroU32>,
    recovery_cool_down: chrono::Duration,
}

impl PasskeyRegistrations {
    pub(crate) fn new(
        deps: &CoreDeps,
        config: &PasskeyConfig,
        webauthn: Arc<Webauthn>,
        recovery_cool_down: chrono::Duration,
    ) -> Self {
        Self {
            records: UserRecords::new(deps),
            passkeys: deps.passkeys.clone(),
            challenges: PasskeyChallenges::from_deps(deps, config, webauthn.clone()),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            webauthn,
            max_passkeys_per_user: config.max_passkeys_per_user,
            recovery_cool_down,
        }
    }

    // An email link proved its owner active a moment ago; a session names a user to look up.
    pub(crate) async fn start(
        &self,
        source: RegistrationSource<'_>,
    ) -> Result<StartedRegistration> {
        let now = self.clock.now();
        let (user, cool_down) = match source {
            RegistrationSource::SignupLink(user) => (user.clone(), RecoveryCoolDown::NONE),
            RegistrationSource::RecoveryLink(user) => (
                user.clone(),
                RecoveryCoolDown::start(now, self.recovery_cool_down),
            ),
            RegistrationSource::Session(session) => (
                self.records.find_active(session.user_id).await?,
                RecoveryCoolDown::of_session(session, now),
            ),
        };
        let (challenge_id, options) = self
            .challenges
            .issue_registration(
                &user,
                source.purpose(),
                source.session_id(),
                source.owner_email(),
                cool_down,
            )
            .await?;
        tracing::info!(outcome = "started", "passkey registration started");
        Ok(StartedRegistration {
            challenge_id,
            options,
        })
    }

    pub(crate) async fn finish(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: &SessionContext,
        finish: RegistrationFinish<'_>,
    ) -> Result<RegisteredPasskey> {
        let purpose = finish.purpose();
        let redeemed = self
            .challenges
            .redeem_registration(challenge_id, purpose, finish.session_id(), context)
            .await?;
        let user_id = redeemed.user.id;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));
        let held = self.passkeys.list_passkeys_for_user(user_id).await?.len() as u64;
        // A user who has lost their passkeys may still sit at the cap, and recovery is their way
        // back.
        if purpose != RegistrationPurpose::Recovery {
            self.enforce_passkey_cap(user_id, held)?;
        }
        let cool_down = match purpose {
            // A recovery starts its cool-down again when the registration finishes, so a slow
            // ceremony never eats into it; the later deadline wins.
            RegistrationPurpose::Recovery => redeemed.cool_down.extended_by(
                RecoveryCoolDown::start(self.clock.now(), self.recovery_cool_down),
            ),
            RegistrationPurpose::Signup | RegistrationPurpose::AddPasskey => redeemed.cool_down,
        };
        let passkey = self.verify(&redeemed, response, name, cool_down)?;
        // Marked before the passkey is stored: a failure in between leaves a user who has to
        // recover, never a signed-up user that a signup link still reaches.
        let user = if purpose == RegistrationPurpose::Signup {
            self.records.mark_signed_up(redeemed.user).await?
        } else {
            redeemed.user
        };

        self.passkeys.add_passkey(passkey.clone()).await?;
        self.audit
            .emit(context, AuditEventKind::PasskeyAdded { user_id })
            .await;
        Ok(RegisteredPasskey {
            user,
            passkey,
            passkey_count: held + 1,
        })
    }

    pub(crate) async fn invalidate_pending(&self, user_id: UserId) -> Result<()> {
        self.challenges.invalidate_registrations(user_id).await
    }

    fn enforce_passkey_cap(&self, user_id: UserId, held: u64) -> Result<()> {
        let Some(max) = self.max_passkeys_per_user else {
            return Ok(());
        };
        if held >= u64::from(max.get()) {
            tracing::warn!(%user_id, max = max.get(), "passkey registration rejected: passkey cap reached");
            return Err(Error::ResourceLimitExceeded {
                resource: "passkeys",
                limit: max.get(),
            });
        }
        Ok(())
    }

    fn verify(
        &self,
        registration: &RedeemedRegistration,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        cool_down: RecoveryCoolDown,
    ) -> Result<StoredPasskey> {
        let user_id = registration.user.id;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &registration.state)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let metadata = PasskeyMetadata::from_passkey(&passkey);
        if !metadata.user_verified {
            tracing::warn!(%user_id, outcome = "user_verification_missing", "passkey registration failed");
            return Err(Error::UserVerificationRequired);
        }
        Ok(StoredPasskey {
            credential_id: passkey.cred_id().to_vec(),
            user_id,
            passkey: encode_passkey(&passkey)?,
            name,
            created_at: self.clock.now(),
            last_used_at: None,
            aaguid: metadata.aaguid,
            transports: metadata.transports,
            backup_eligible: metadata.backup_eligible,
            backup_state: metadata.backup_state,
            recovery_cool_down_until: cool_down.until(),
        })
    }
}
