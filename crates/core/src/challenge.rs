use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyRegistration,
    RequestChallengeResponse, Webauthn,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::assertion::PendingAssertion;
use crate::audit::SecretKind;
use crate::clock::{Clock, expiry};
use crate::error::{Error, Result};
use crate::passkey::{PasskeyConfig, decode_passkey};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::redeem::{Candidate, Redeemer};
use crate::session::SessionContext;
use crate::storage::{
    AuthenticationPurpose, PasskeyChallengeId, PasskeyChallengeStore, PasskeyStore,
    RegistrationPurpose, StoredPasskeyAuthentication, StoredPasskeyRegistration, User, UserId,
};

pub(crate) enum Registration {}

pub(crate) enum Login {}

pub(crate) enum Reauth {}

pub(crate) struct RedeemedRegistration {
    pub user: User,
    pub state: PasskeyRegistration,
    pub cool_down: RecoveryCoolDown,
}

pub(crate) struct PasskeyChallenge<P> {
    webauthn: Arc<Webauthn>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    passkeys: Arc<dyn PasskeyStore>,
    redeemer: Redeemer,
    clock: Arc<dyn Clock>,
    lifetime: Duration,
    max_pending_registrations: Option<NonZeroU32>,
    purpose: PhantomData<fn() -> P>,
}

impl<P> Clone for PasskeyChallenge<P> {
    fn clone(&self) -> Self {
        Self {
            webauthn: self.webauthn.clone(),
            challenges: self.challenges.clone(),
            passkeys: self.passkeys.clone(),
            redeemer: self.redeemer.clone(),
            clock: self.clock.clone(),
            lifetime: self.lifetime,
            max_pending_registrations: self.max_pending_registrations,
            purpose: PhantomData,
        }
    }
}

impl<P> PasskeyChallenge<P> {
    pub(crate) fn new(
        config: &PasskeyConfig,
        webauthn: Arc<Webauthn>,
        challenges: Arc<dyn PasskeyChallengeStore>,
        passkeys: Arc<dyn PasskeyStore>,
        redeemer: Redeemer,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            webauthn,
            challenges,
            passkeys,
            redeemer,
            clock,
            lifetime: config.challenge_lifetime,
            max_pending_registrations: config.max_pending_registrations_per_user,
            purpose: PhantomData,
        }
    }

    async fn put_authentication<S: Serialize>(
        &self,
        purpose: AuthenticationPurpose,
        state: &S,
    ) -> Result<PasskeyChallengeId> {
        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        self.challenges
            .put_authentication(StoredPasskeyAuthentication {
                id,
                purpose,
                state: encode_state(state)?,
                created_at: now,
                expires_at: expiry(now, self.lifetime)?,
            })
            .await?;
        Ok(id)
    }

    async fn take_authentication<S: DeserializeOwned>(
        &self,
        id: PasskeyChallengeId,
        secret: SecretKind,
        purpose: AuthenticationPurpose,
        owner: Option<UserId>,
        context: &SessionContext,
    ) -> Result<S> {
        let stored = self.challenges.take_authentication(id).await?;
        let candidate = stored.map(|stored| Candidate {
            owner,
            purpose_matches: stored.purpose == purpose,
            expires_at: stored.expires_at,
            payload: decode_state(&stored.state),
        });
        self.redeemer.check(secret, owner, candidate, context).await
    }
}

impl PasskeyChallenge<Registration> {
    pub(crate) async fn issue(
        &self,
        user: &User,
        purpose: RegistrationPurpose,
        cool_down: RecoveryCoolDown,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let user_id = user.id;
        if let Some(max) = self.max_pending_registrations {
            let pending = self
                .challenges
                .count_registrations_for_user(user_id)
                .await?;
            if pending >= u64::from(max.get()) {
                tracing::warn!(%user_id, max = max.get(), "passkey registration rejected: too many pending challenges");
                return Err(Error::ResourceLimitExceeded {
                    resource: "pending registrations",
                    limit: max.get(),
                });
            }
        }

        let display_name = display_name_for(user);
        let existing = self.passkeys.list_passkeys_for_user(user_id).await?;
        let exclude = if existing.is_empty() {
            None
        } else {
            Some(
                existing
                    .iter()
                    .map(|c| CredentialID::from(c.credential_id.clone()))
                    .collect(),
            )
        };

        let (mut ccr, state) = self
            .webauthn
            .start_passkey_registration(user_id.0, &display_name, &display_name, exclude)
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        require_discoverable_credential(&mut ccr)?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        self.challenges
            .put_registration(StoredPasskeyRegistration {
                id,
                purpose,
                user_id,
                state: encode_state(&state)?,
                created_at: now,
                expires_at: expiry(now, self.lifetime)?,
                recovery_cool_down_until: cool_down.until(),
            })
            .await?;
        Ok((id, ccr))
    }

    pub(crate) async fn redeem(
        &self,
        id: PasskeyChallengeId,
        purpose: RegistrationPurpose,
        context: &SessionContext,
    ) -> Result<RedeemedRegistration> {
        let secret = SecretKind::RegistrationChallenge;
        let stored = self.challenges.take_registration(id).await?;
        let candidate = stored.map(|stored| Candidate {
            owner: Some(stored.user_id),
            purpose_matches: stored.purpose == purpose,
            expires_at: stored.expires_at,
            payload: decode_state(&stored.state).map(|state| {
                (
                    stored.user_id,
                    RecoveryCoolDown::of_registration(&stored),
                    state,
                )
            }),
        });
        let (user_id, cool_down, state) = self
            .redeemer
            .check(secret, None, candidate, context)
            .await?;
        let user = self.redeemer.active_owner(secret, user_id, context).await?;
        Ok(RedeemedRegistration {
            user,
            state,
            cool_down,
        })
    }

    pub(crate) async fn invalidate_pending(&self, user_id: UserId) -> Result<()> {
        let dropped = self
            .challenges
            .delete_registrations_for_user(user_id)
            .await?;
        if dropped > 0 {
            tracing::info!(%user_id, dropped, "pending passkey registrations invalidated");
        }
        Ok(())
    }
}

impl PasskeyChallenge<Login> {
    pub(crate) async fn issue(&self) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let (rcr, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        let id = self
            .put_authentication(AuthenticationPurpose::Login, &state)
            .await?;
        Ok((id, rcr))
    }

    pub(crate) async fn redeem(
        &self,
        id: PasskeyChallengeId,
        context: &SessionContext,
    ) -> Result<PendingAssertion> {
        let state = self
            .take_authentication(
                id,
                SecretKind::LoginChallenge,
                AuthenticationPurpose::Login,
                None,
                context,
            )
            .await?;
        Ok(PendingAssertion::Login(state))
    }
}

impl PasskeyChallenge<Reauth> {
    pub(crate) async fn issue(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let stored = self.passkeys.list_passkeys_for_user(user_id).await?;
        if stored.is_empty() {
            tracing::warn!(outcome = "no_passkeys", "reauth start refused");
            return Err(Error::PasskeyNotFound);
        }
        let passkeys = stored
            .iter()
            .map(|c| decode_passkey(&c.passkey))
            .collect::<Result<Vec<Passkey>>>()?;

        let (rcr, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        let id = self
            .put_authentication(AuthenticationPurpose::Reauth, &state)
            .await?;
        Ok((id, rcr))
    }

    pub(crate) async fn redeem(
        &self,
        id: PasskeyChallengeId,
        user_id: UserId,
        context: &SessionContext,
    ) -> Result<PendingAssertion> {
        let state = self
            .take_authentication(
                id,
                SecretKind::ReauthChallenge,
                AuthenticationPurpose::Reauth,
                Some(user_id),
                context,
            )
            .await?;
        Ok(PendingAssertion::Reauth { user_id, state })
    }
}

fn display_name_for(user: &User) -> String {
    user.email.clone().unwrap_or_else(|| user.id.to_string())
}

fn require_discoverable_credential(ccr: &mut CreationChallengeResponse) -> Result<()> {
    let selection = ccr
        .public_key
        .authenticator_selection
        .as_mut()
        .ok_or_else(|| {
            Error::Internal("passkey registration is missing authenticator selection".to_string())
        })?;
    selection.require_resident_key = true;
    selection.resident_key = Some(ResidentKeyRequirement::Required);
    Ok(())
}

fn encode_state<S: Serialize>(state: &S) -> Result<Vec<u8>> {
    serde_json::to_vec(state)
        .map_err(|e| Error::Internal(format!("serialise passkey challenge state: {e}")))
}

fn decode_state<S: DeserializeOwned>(bytes: &[u8]) -> Result<S> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Internal(format!("deserialise passkey challenge state: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;
    use uuid::Uuid;
    use webauthn_rs::prelude::WebauthnBuilder;
    use webauthn_rs_proto::UserVerificationPolicy;

    fn webauthn() -> Webauthn {
        let origin = Url::parse("https://example.com").expect("valid url");
        WebauthnBuilder::new("example.com", &origin)
            .expect("valid relying party")
            .build()
            .expect("webauthn builds")
    }

    #[test]
    fn require_discoverable_forces_resident_key_when_selection_present() {
        let (mut ccr, _state) = webauthn()
            .start_passkey_registration(Uuid::new_v4(), "user", "user", None)
            .expect("registration starts");

        require_discoverable_credential(&mut ccr)
            .expect("authenticator selection present on fresh webauthn output");

        let selection = ccr
            .public_key
            .authenticator_selection
            .as_ref()
            .expect("authenticator selection present");
        assert!(selection.require_resident_key);
        assert_eq!(
            selection.resident_key,
            Some(ResidentKeyRequirement::Required)
        );
    }

    #[test]
    fn registration_requests_user_verification_required() {
        let (ccr, _state) = webauthn()
            .start_passkey_registration(Uuid::new_v4(), "user", "user", None)
            .expect("registration starts");
        let selection = ccr
            .public_key
            .authenticator_selection
            .as_ref()
            .expect("authenticator selection present");
        assert_eq!(
            selection.user_verification,
            UserVerificationPolicy::Required,
            "webauthn-rs changed its passkey registration UV default; doorman enforces \
             user verification at finish assuming Required — reconcile before bumping",
        );
    }

    #[test]
    fn discoverable_authentication_requests_user_verification_required() {
        let (rcr, _state) = webauthn()
            .start_discoverable_authentication()
            .expect("discoverable authentication starts");
        assert_eq!(
            rcr.public_key.user_verification,
            UserVerificationPolicy::Required,
            "webauthn-rs changed its discoverable-auth UV default; doorman enforces user \
             verification at finish assuming Required — reconcile before bumping",
        );
    }
}
