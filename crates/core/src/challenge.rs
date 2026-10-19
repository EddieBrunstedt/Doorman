use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    RequestChallengeResponse, Webauthn,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::assertion::PendingAssertion;
use crate::audit::RedemptionFailureReason::WrongSession;
use crate::audit::SecretKind;
use crate::clock::{Clock, expiry};
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::{PasskeyConfig, decode_passkey};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::redeem::Redeemer;
use crate::session::{ResolvedSession, SessionContext};
use crate::storage::{
    AuthenticationPurpose, PasskeyChallengeId, PasskeyChallengeStore, PasskeyStore,
    RegistrationPurpose, SessionId, StoredPasskeyAuthentication, StoredPasskeyRegistration, User,
    UserId,
};

pub(crate) struct RedeemedRegistration {
    pub user: User,
    pub state: PasskeyRegistration,
    pub cool_down: RecoveryCoolDown,
}

#[derive(Clone)]
pub(crate) struct PasskeyChallenges {
    webauthn: Arc<Webauthn>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    passkeys: Arc<dyn PasskeyStore>,
    redeemer: Redeemer,
    clock: Arc<dyn Clock>,
    lifetime: Duration,
    max_pending_registrations: Option<NonZeroU32>,
}

// A passkey added from a session can be finished only by that session, so revoking a stolen
// session also kills the registrations it started.
#[derive(Serialize, Deserialize)]
struct RegistrationChallengeState {
    session_id: Option<SessionId>,
    state: PasskeyRegistration,
}

impl PasskeyChallenges {
    pub(crate) fn from_deps(
        deps: &CoreDeps,
        config: &PasskeyConfig,
        webauthn: Arc<Webauthn>,
    ) -> Self {
        Self {
            webauthn,
            challenges: deps.passkey_challenges.clone(),
            passkeys: deps.passkeys.clone(),
            redeemer: Redeemer::from_deps(deps),
            clock: deps.clock.clone(),
            lifetime: config.challenge_lifetime,
            max_pending_registrations: config.max_pending_registrations_per_user,
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
        purpose: AuthenticationPurpose,
        owner: Option<UserId>,
        context: &SessionContext,
    ) -> Result<S> {
        let taken = self.challenges.take_authentication(id).await?;
        self.redeemer
            .check(
                taken,
                purpose,
                owner,
                |stored| decode_state(&stored.state),
                context,
            )
            .await
    }

    pub(crate) async fn issue_registration(
        &self,
        user: &User,
        purpose: RegistrationPurpose,
        session_id: Option<SessionId>,
        owner_email: Option<String>,
        cool_down: RecoveryCoolDown,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let user_id = user.id;
        if let Some(max) = self.max_pending_registrations {
            let now = self.clock.now();
            let pending = self
                .challenges
                .list_registrations_for_user(user_id)
                .await?
                .iter()
                .filter(|registration| registration.expires_at > now)
                .count();
            if pending >= max.get() as usize {
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
        let state = RegistrationChallengeState { session_id, state };

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        self.challenges
            .put_registration(StoredPasskeyRegistration {
                id,
                purpose,
                user_id,
                state: encode_state(&state)?,
                owner_email,
                created_at: now,
                expires_at: expiry(now, self.lifetime)?,
                recovery_cool_down_until: cool_down.until(),
            })
            .await?;
        Ok((id, ccr))
    }

    pub(crate) async fn redeem_registration(
        &self,
        id: PasskeyChallengeId,
        purpose: RegistrationPurpose,
        session_id: Option<SessionId>,
        context: &SessionContext,
    ) -> Result<RedeemedRegistration> {
        let taken = self.challenges.take_registration(id).await?;
        let (user, (started_by, state, cool_down)) = self
            .redeemer
            .check_owned(
                taken,
                purpose,
                |stored| {
                    let RegistrationChallengeState { session_id, state } =
                        decode_state(&stored.state)?;
                    Ok((
                        session_id,
                        state,
                        RecoveryCoolDown::of_registration(&stored),
                    ))
                },
                context,
            )
            .await?;
        if started_by != session_id {
            return Err(self
                .redeemer
                .refuse(
                    SecretKind::RegistrationChallenge,
                    Some(user.id),
                    WrongSession,
                    context,
                )
                .await);
        }
        Ok(RedeemedRegistration {
            user,
            state,
            cool_down,
        })
    }

    pub(crate) async fn invalidate_registrations(&self, user_id: UserId) -> Result<()> {
        let dropped = self
            .challenges
            .delete_registrations_for_user(user_id)
            .await?;
        if dropped > 0 {
            tracing::info!(%user_id, dropped, "pending passkey registrations invalidated");
        }
        Ok(())
    }

    pub(crate) async fn issue_login(
        &self,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let (rcr, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        let id = self
            .put_authentication(AuthenticationPurpose::Login, &state)
            .await?;
        Ok((id, rcr))
    }

    pub(crate) async fn redeem_login(
        &self,
        id: PasskeyChallengeId,
        context: &SessionContext,
    ) -> Result<PendingAssertion> {
        let state = self
            .take_authentication(id, AuthenticationPurpose::Login, None, context)
            .await?;
        Ok(PendingAssertion::Login(state))
    }
}

// Re-authentication proves possession within one session, so a challenge records the session
// that started it and another session cannot spend it.
#[derive(Serialize, Deserialize)]
struct ReauthChallengeState {
    session_id: SessionId,
    state: PasskeyAuthentication,
}

impl PasskeyChallenges {
    pub(crate) async fn issue_reauth(
        &self,
        session: &ResolvedSession,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let stored = self
            .passkeys
            .list_passkeys_for_user(session.user_id)
            .await?;
        if stored.is_empty() {
            tracing::warn!(outcome = "no_passkeys", "reauth start refused");
            return Err(Error::PasskeyNotFound);
        }
        // webauthn-rs accepts a proof only from a passkey the challenge names, so leaving one out
        // refuses it. A passkey's cool-down is fixed when it is registered, so one left in can't
        // enter cool-down before the proof comes back.
        let stored = RecoveryCoolDown::refuse_reauthentication(stored, self.clock.now())
            .inspect_err(|_| {
                tracing::info!(outcome = "recovery_cool_down", "reauth start refused")
            })?;
        let passkeys = stored
            .iter()
            .map(|c| decode_passkey(&c.passkey))
            .collect::<Result<Vec<Passkey>>>()?;

        let (rcr, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        let state = ReauthChallengeState {
            session_id: session.id,
            state,
        };
        let id = self
            .put_authentication(AuthenticationPurpose::Reauth, &state)
            .await?;
        Ok((id, rcr))
    }

    pub(crate) async fn redeem_reauth(
        &self,
        id: PasskeyChallengeId,
        session: &ResolvedSession,
        context: &SessionContext,
    ) -> Result<PendingAssertion> {
        let user_id = session.user_id;
        let ReauthChallengeState { session_id, state } = self
            .take_authentication(id, AuthenticationPurpose::Reauth, Some(user_id), context)
            .await?;
        if session_id != session.id {
            return Err(self
                .redeemer
                .refuse(
                    SecretKind::ReauthChallenge,
                    Some(user_id),
                    WrongSession,
                    context,
                )
                .await);
        }
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
