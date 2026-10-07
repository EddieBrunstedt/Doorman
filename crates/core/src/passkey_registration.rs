use std::num::NonZeroU32;
use std::sync::Arc;

use webauthn_rs::prelude::{RegisterPublicKeyCredential, Webauthn};

use crate::audit::{AuditDispatch, AuditEventKind};
use crate::challenge::{PasskeyChallenge, RedeemedRegistration, Registration};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::{PasskeyConfig, PasskeyMetadata, StartedRegistration, encode_passkey};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::session::SessionContext;
use crate::storage::{
    PasskeyChallengeId, PasskeyStore, RegistrationPurpose, StoredPasskey, User, UserId,
};
use crate::user_records::UserRecords;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyCap {
    Enforced,
    Exempt,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FinishRules {
    pub purpose: RegistrationPurpose,
    pub passkey_cap: PasskeyCap,
    // The cool-down stamped at start is kept; the later of the two deadlines wins.
    pub cool_down: RecoveryCoolDown,
}

pub(crate) struct RegisteredPasskey {
    pub user: User,
    pub passkey: StoredPasskey,
    pub cool_down: RecoveryCoolDown,
}

#[derive(Clone)]
pub(crate) struct PasskeyRegistrations {
    records: UserRecords,
    passkeys: Arc<dyn PasskeyStore>,
    challenges: PasskeyChallenge<Registration>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    webauthn: Arc<Webauthn>,
    max_passkeys_per_user: Option<NonZeroU32>,
}

impl PasskeyRegistrations {
    pub(crate) fn new(deps: &CoreDeps, config: &PasskeyConfig, webauthn: Arc<Webauthn>) -> Self {
        Self {
            records: UserRecords::new(deps),
            passkeys: deps.passkeys.clone(),
            challenges: PasskeyChallenge::from_deps(deps, config, webauthn.clone()),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            webauthn,
            max_passkeys_per_user: config.max_passkeys_per_user,
        }
    }

    pub(crate) async fn start(
        &self,
        user_id: UserId,
        purpose: RegistrationPurpose,
        cool_down: RecoveryCoolDown,
    ) -> Result<StartedRegistration> {
        let user = self.records.find_active(user_id).await?;
        let (challenge_id, options) = self.challenges.issue(&user, purpose, cool_down).await?;
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
        rules: FinishRules,
    ) -> Result<RegisteredPasskey> {
        let redeemed = self
            .challenges
            .redeem(challenge_id, rules.purpose, context)
            .await?;
        let user_id = redeemed.user.id;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));
        if rules.passkey_cap == PasskeyCap::Enforced {
            self.enforce_passkey_cap(user_id).await?;
        }
        let cool_down = redeemed.cool_down.extended_by(rules.cool_down);
        let passkey = self.verify(&redeemed, response, name, cool_down)?;

        self.passkeys.add_passkey(passkey.clone()).await?;
        self.audit
            .emit(context, AuditEventKind::PasskeyAdded { user_id })
            .await;
        Ok(RegisteredPasskey {
            user: redeemed.user,
            passkey,
            cool_down,
        })
    }

    pub(crate) async fn invalidate_pending(&self, user_id: UserId) -> Result<()> {
        self.challenges.invalidate_pending(user_id).await
    }

    async fn enforce_passkey_cap(&self, user_id: UserId) -> Result<()> {
        let Some(max) = self.max_passkeys_per_user else {
            return Ok(());
        };
        let count = self.passkeys.list_passkeys_for_user(user_id).await?.len();
        if count >= max.get() as usize {
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
