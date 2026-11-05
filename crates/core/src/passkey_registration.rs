use std::num::NonZeroU32;
use std::sync::Arc;

use webauthn_rs::prelude::{RegisterPublicKeyCredential, Webauthn};

use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::challenge::{PasskeyChallenges, RedeemedRegistration};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::{
    PasskeyConfig, PasskeyMetadata, PasskeyName, StartedRegistration, check_credential_id,
};
use crate::passkey_format;
use crate::recovery::CoolDownLength;
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::session::SessionContext;
use crate::session_records::LiveSession;
use crate::storage::{
    PasskeyChallengeId, RegistrationPurpose, SessionId, StoredPasskey, User, UserId,
};
use crate::user_records::{OwnerRefusal, UserRecords};

#[derive(Debug, Clone, Copy)]
pub(crate) enum RegistrationSource<'a> {
    SignupLink(&'a User),
    RecoveryLink(&'a User),
    Session(&'a LiveSession),
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

// Who finishes a registration must be who started it: a request following the same kind of email
// link, or the same session.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RegistrationFinish<'a> {
    SignupLink(&'a SessionContext),
    RecoveryLink(&'a SessionContext),
    Session(&'a LiveSession),
}

impl RegistrationFinish<'_> {
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

    fn actor(self) -> Actor {
        match self {
            Self::SignupLink(context) | Self::RecoveryLink(context) => Actor::from(context),
            Self::Session(session) => session.actor(),
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
    challenges: PasskeyChallenges,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    webauthn: Arc<Webauthn>,
    max_passkeys_per_user: Option<NonZeroU32>,
    recovery_cool_down: CoolDownLength,
}

impl PasskeyRegistrations {
    pub(crate) fn new(
        deps: &CoreDeps,
        config: &PasskeyConfig,
        recovery_cool_down: CoolDownLength,
    ) -> Self {
        Self {
            records: UserRecords::new(deps),
            challenges: PasskeyChallenges::from_deps(deps, config),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            webauthn: config.relying_party.webauthn().clone(),
            max_passkeys_per_user: config.max_passkeys_per_user,
            recovery_cool_down,
        }
    }

    // An email link proved its owner active a moment ago; a session names a user to look up.
    pub(crate) async fn start(
        &self,
        source: RegistrationSource<'_>,
    ) -> Result<std::result::Result<StartedRegistration, OwnerRefusal>> {
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
        let issued = self
            .challenges
            .issue_registration(
                &user,
                source.purpose(),
                source.session_id(),
                source.owner_email(),
                cool_down,
            )
            .await?;
        Ok(issued.map(|(challenge_id, options)| {
            tracing::info!(outcome = "started", "passkey registration started");
            StartedRegistration {
                challenge_id,
                options,
            }
        }))
    }

    pub(crate) async fn finish(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        finish: RegistrationFinish<'_>,
    ) -> Result<RegisteredPasskey> {
        // Parsed before the challenge is redeemed, so a refused name costs no ceremony.
        let name = PasskeyName::parse(name.as_deref())?;
        let purpose = finish.purpose();
        let actor = finish.actor();
        let redeemed = self
            .challenges
            .redeem_registration(challenge_id, purpose, finish.session_id(), &actor)
            .await?;
        let user_id = redeemed.user.id;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));
        let held = self.records.count_passkeys(user_id).await?;
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
        // The owner can be disabled or deleted after the redemption checked them, so the
        // registration is refused as if that had come first.
        let user = match self.store(&passkey, purpose).await? {
            Ok(user) => user,
            Err(refusal) => {
                return Err(self
                    .challenges
                    .refuse_registration_owner(purpose, user_id, refusal, &actor)
                    .await);
            }
        };
        self.audit
            .emit(actor, AuditEventKind::PasskeyAdded { user_id })
            .await;
        Ok(RegisteredPasskey {
            user,
            passkey,
            passkey_count: held + 1,
        })
    }

    async fn store(
        &self,
        passkey: &StoredPasskey,
        purpose: RegistrationPurpose,
    ) -> Result<std::result::Result<User, OwnerRefusal>> {
        // Marked before the passkey is stored: a failure in between leaves a user who has to
        // recover, never a signed-up user that a signup link still reaches.
        if purpose == RegistrationPurpose::Signup
            && let Err(refusal) = self.records.mark_signed_up(passkey.user_id).await?
        {
            return Ok(Err(refusal));
        }
        self.records.add_passkey(passkey).await
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
        name: Option<PasskeyName>,
        cool_down: RecoveryCoolDown,
    ) -> Result<StoredPasskey> {
        let user_id = registration.user.id;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &registration.state)
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        if let Err(err) = check_credential_id(passkey.cred_id()) {
            tracing::warn!(%user_id, outcome = "credential_id_too_long", "passkey registration failed");
            return Err(err);
        }

        let metadata = PasskeyMetadata::from_passkey(&passkey);
        if !metadata.user_verified {
            tracing::warn!(%user_id, outcome = "user_verification_missing", "passkey registration failed");
            return Err(Error::UserVerificationRequired);
        }
        Ok(StoredPasskey {
            credential_id: passkey.cred_id().to_vec(),
            user_id,
            passkey: passkey_format::encode(&passkey)?,
            name: name.map(PasskeyName::into_string),
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
