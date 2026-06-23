//! Re-authentication: prove session recency before a destructive action.
//!
//! Re-authentication requires a **fresh, user-verified passkey assertion**
//! immediately before an irreversible self-service action (delete account,
//! email-change request, passkey removal). It is the WebAuthn equivalent of
//! "confirm your password" before something dangerous.
//!
//! # What it is, and is not
//!
//! Call this **re-authentication**, never "step-up". Step-up classically means
//! raising the *assurance level* (adding or upgrading a factor). doorman is
//! single-factor and the passkey is already the strongest rung — there is
//! nothing to step up to. What re-auth proves is **recency**: that the human
//! behind this session is still present *right now*.
//!
//! ## Threat model
//!
//! - **Defends against** a *stolen or stale session* — an XSS-exfiltrated
//!   bearer token, a borrowed unlocked laptop, a session left open. The
//!   attacker holds a valid session but cannot produce a fresh user-verified
//!   passkey assertion.
//! - **Does not defend against** a stolen *authenticator*. An attacker who
//!   holds the passkey and can satisfy user verification is indistinguishable
//!   from the user. That is out of scope.
//! - **Complements, never replaces, the recovery cool-down.** The cool-down
//!   distrusts a *freshly-recovered* session; re-auth distrusts an *old* one.
//!   Both gate the same actions, and the cool-down is checked first — it is a
//!   hard block you cannot re-auth your way out of.
//!
//! # Shape
//!
//! Re-auth is an **inline, per-action assertion** — no intermediate token, no
//! session stamp:
//!
//! 1. [`ReauthManager::start`] mints a single-use, user-scoped challenge.
//! 2. The destructive request carries a [`ReauthProof`] (`challenge_id` +
//!    `assertion`). The destructive manager calls [`ReauthManager::ensure`],
//!    which verifies the assertion inline, consumes the challenge, and lets the
//!    action proceed.
//!
//! This is stateless and per-action: it needs no storage migration, reusing
//! the existing [`PasskeyChallengeStore`] to hold the ceremony state.
//!
//! # No rate limiting
//!
//! The re-auth endpoints are deliberately **not** rate-limited. Re-auth is
//! authenticated (a valid session is required to reach it), sends no email,
//! exposes no enumeration surface, and guards an *unforgeable* signature — so
//! none of the reasons the library throttles other endpoints (brute-force,
//! enumeration, email/quota abuse, unauthenticated amplification) apply. The
//! lever against a stolen session is **revocation**, not throttling.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use webauthn_rs::prelude::{
    Passkey, PublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnError,
};

use crate::audit::{
    Actor, AuditDispatch, AuditEvent, AuditEventKind, AuditSink, ReauthFailureReason,
};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::passkey::{
    PasskeyConfig, build_webauthn, challenge_lifetime, decode_credential,
    decode_passkey_authentication_state, encode_passkey_authentication_state,
};
use crate::session::SessionContext;
use crate::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, Session,
    StoredPasskeyAuthentication, UserId,
};

/// A destructive self-service action that may be gated behind re-authentication.
///
/// The set mirrors the recovery-cool-down protected set: the same irreversible
/// actions a phished recovery session is held back from are the ones a stale
/// session is asked to prove recency for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReauthAction {
    /// [`AccountManager::delete_account`](crate::account::AccountManager::delete_account).
    DeleteAccount,
    /// [`AccountManager::request_email_change`](crate::account::AccountManager::request_email_change)
    /// — the session-authenticated *request* step. `confirm_email_change` is
    /// token-based with no session and is never gated.
    RequestEmailChange,
    /// [`PasskeyManager::remove_passkey`](crate::passkey::PasskeyManager::remove_passkey).
    RemovePasskey,
}

/// Which destructive actions require a fresh re-authentication.
///
/// There is **no default**: a host must make an explicit decision, either
/// listing the protected actions with [`required_for`](Self::required_for) or
/// opting out with [`disabled`](Self::disabled). The high-level builders fail
/// closed until one is supplied, mirroring the CSRF decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReauthPolicy {
    delete_account: bool,
    request_email_change: bool,
    remove_passkey: bool,
}

impl ReauthPolicy {
    /// Require re-authentication for exactly the listed actions; every other
    /// action is left ungated. Duplicate entries are harmless.
    pub fn required_for(actions: impl IntoIterator<Item = ReauthAction>) -> Self {
        let mut policy = Self::disabled();
        for action in actions {
            match action {
                ReauthAction::DeleteAccount => policy.delete_account = true,
                ReauthAction::RequestEmailChange => policy.request_email_change = true,
                ReauthAction::RemovePasskey => policy.remove_passkey = true,
            }
        }
        policy
    }

    /// Gate nothing: every destructive action proceeds without a re-auth proof.
    /// The deliberate opt-out a host passes when it does not want this gate.
    pub const fn disabled() -> Self {
        Self {
            delete_account: false,
            request_email_change: false,
            remove_passkey: false,
        }
    }

    /// Whether `action` requires a re-auth proof under this policy.
    pub const fn requires(&self, action: ReauthAction) -> bool {
        match action {
            ReauthAction::DeleteAccount => self.delete_account,
            ReauthAction::RequestEmailChange => self.request_email_change,
            ReauthAction::RemovePasskey => self.remove_passkey,
        }
    }
}

/// The proof a client supplies on a destructive request to satisfy
/// re-authentication: the `challenge_id` returned by [`ReauthManager::start`]
/// and the WebAuthn `assertion` the browser produced for it.
#[derive(Debug, Clone)]
pub struct ReauthProof {
    /// The challenge id from the [`ReauthManager::start`] response.
    pub challenge_id: PasskeyChallengeId,
    /// The assertion `navigator.credentials.get` produced for the challenge.
    pub assertion: PublicKeyCredential,
}

/// Mints and verifies re-authentication challenges, and gates destructive
/// actions behind the configured [`ReauthPolicy`].
///
/// Holds its own `webauthn-rs` [`Webauthn`] handle. The handle is stateless
/// across ceremonies (the per-ceremony state lives in the serialized
/// challenge), so building a second handle from the same [`PasskeyConfig`] the
/// [`PasskeyManager`](crate::passkey::PasskeyManager) uses is functionally
/// equivalent to sharing one — and it keeps this manager constructible from the
/// shared [`CoreDeps`](crate::context::CoreDeps) bundle without threading the
/// handle out of the passkey manager. The single source of truth for the
/// relying-party id / origin remains the one [`PasskeyConfig`].
#[derive(Clone)]
pub struct ReauthManager {
    webauthn: Arc<Webauthn>,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    challenge_lifetime: std::time::Duration,
    policy: ReauthPolicy,
}

impl ReauthManager {
    /// Build a re-authentication manager.
    ///
    /// The relying-party [`PasskeyConfig`] is used only to construct the
    /// `webauthn-rs` handle (and to read the challenge lifetime); supply the
    /// same config the [`PasskeyManager`](crate::passkey::PasskeyManager) is
    /// built with. The [`ReauthPolicy`] is a **required** argument — there is
    /// no default, so a low-level host that wires managers by hand cannot
    /// silently skip the decision.
    pub fn new(
        config: &PasskeyConfig,
        credentials: Arc<dyn PasskeyCredentialStore>,
        challenges: Arc<dyn PasskeyChallengeStore>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        policy: ReauthPolicy,
    ) -> Result<Self> {
        Ok(Self {
            webauthn: Arc::new(build_webauthn(config)?),
            credentials,
            challenges,
            clock,
            audit: AuditDispatch::new(audit),
            challenge_lifetime: config.challenge_lifetime,
            policy,
        })
    }

    /// The configured policy, so a destructive manager can answer
    /// [`requires`](ReauthPolicy::requires) without re-running a ceremony.
    pub fn policy(&self) -> ReauthPolicy {
        self.policy
    }

    /// Begin a re-authentication ceremony scoped to `user_id`'s own
    /// credentials.
    ///
    /// Unlike sign-in (which is discoverable — any user, identified at finish),
    /// re-auth already knows the user from their session, so it uses the
    /// allow-list-scoped `start_passkey_authentication` against *that user's*
    /// registered credentials. `webauthn-rs` requests
    /// `UserVerificationPolicy::Required` for this ceremony, and
    /// [`ensure`](Self::ensure) re-checks the user-verified flag on finish — the
    /// whole point is a deliberate human gesture.
    ///
    /// Returns [`Error::PasskeyNotFound`] if the user has no credentials: there
    /// is nothing to assert, so they cannot re-authenticate.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn start(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let stored = self.credentials.list_passkeys_for_user(user_id).await?;
        if stored.is_empty() {
            tracing::warn!(outcome = "no_credentials", "reauth start refused");
            return Err(Error::PasskeyNotFound);
        }
        let passkeys = stored
            .iter()
            .map(|c| decode_credential(&c.passkey))
            .collect::<Result<Vec<Passkey>>>()?;

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        self.challenges
            .put_authentication(StoredPasskeyAuthentication {
                id,
                state: encode_passkey_authentication_state(&auth_state)?,
                created_at: now,
                expires_at: now + challenge_lifetime(self.challenge_lifetime),
            })
            .await?;
        tracing::info!(outcome = "started", "reauth started");
        Ok((id, rcr))
    }

    /// Gate `action` for the acting `session`.
    ///
    /// - If the policy does not require `action`, returns `Ok(())` immediately.
    /// - Otherwise a [`ReauthProof`] is mandatory: a missing one is
    ///   [`Error::ReauthRequired`] (the caller should run [`start`](Self::start)
    ///   and retry).
    /// - With a proof, the challenge is consumed single-use, the assertion is
    ///   verified, user verification is required, and the asserted credential
    ///   must belong to `session.user_id` (defense in depth — the challenge is
    ///   already user-scoped). A counter regression maps to
    ///   [`Error::PasskeyPossibleCompromise`].
    ///
    /// The challenge is **generic and single-use, not bound to a specific
    /// action**. `start` does not know the target action, and that is fine: the
    /// security property is "a fresh user-verified assertion by the session
    /// user, consumed once". Binding to an action would add coupling for no real
    /// gain — obtaining any valid assertion already requires the authenticator
    /// plus user verification.
    #[tracing::instrument(skip(self, session, proof, context), fields(user_id = %session.user_id))]
    pub async fn ensure(
        &self,
        action: ReauthAction,
        session: &Session,
        proof: Option<&ReauthProof>,
        context: &SessionContext,
    ) -> Result<()> {
        if !self.policy.requires(action) {
            return Ok(());
        }
        let user_id = session.user_id;
        let Some(proof) = proof else {
            tracing::info!(outcome = "proof_required", "reauth required");
            return Err(Error::ReauthRequired);
        };

        let now = self.clock.now();
        let Some(stored) = self
            .challenges
            .take_authentication(proof.challenge_id)
            .await?
        else {
            self.emit_failed(now, context, user_id, ReauthFailureReason::InvalidChallenge)
                .await;
            return Err(Error::ReauthRequired);
        };
        if stored.expires_at <= now {
            self.emit_failed(now, context, user_id, ReauthFailureReason::InvalidChallenge)
                .await;
            return Err(Error::ReauthRequired);
        }

        let auth_state = decode_passkey_authentication_state(&stored.state)?;
        let result = match self
            .webauthn
            .finish_passkey_authentication(&proof.assertion, &auth_state)
        {
            Ok(result) => result,
            // A non-advancing signature counter is webauthn-rs's possible
            // cloned-authenticator signal; surface it distinctly, the same way
            // sign-in does at `passkey.rs`.
            Err(WebauthnError::CredentialPossibleCompromise) => {
                self.emit_failed(
                    now,
                    context,
                    user_id,
                    ReauthFailureReason::CounterRegression,
                )
                .await;
                return Err(Error::PasskeyPossibleCompromise);
            }
            Err(e) => {
                self.emit_failed(now, context, user_id, ReauthFailureReason::BadAssertion)
                    .await;
                return Err(Error::Webauthn(e.to_string()));
            }
        };

        if !result.user_verified() {
            self.emit_failed(
                now,
                context,
                user_id,
                ReauthFailureReason::UserVerificationMissing,
            )
            .await;
            return Err(Error::UserVerificationRequired);
        }

        // Defense in depth: confirm the asserted credential belongs to the
        // session user. The ceremony was already scoped to this user's
        // credentials, but re-checking the resolved owner closes any gap
        // between the allow-list and the stored binding.
        let cred_id: &[u8] = result.cred_id().as_ref();
        match self
            .credentials
            .find_passkey_by_credential_id(cred_id)
            .await?
        {
            Some(credential) if credential.user_id == user_id => {}
            _ => {
                self.emit_failed(
                    now,
                    context,
                    user_id,
                    ReauthFailureReason::OwnershipMismatch,
                )
                .await;
                return Err(Error::PasskeyOwnershipMismatch);
            }
        }

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::ReauthSucceeded { user_id },
            })
            .await;
        Ok(())
    }

    /// Emit a [`ReauthFailed`](AuditEventKind::ReauthFailed) event. Centralised
    /// so every rejection path records the same shape, mirroring
    /// `emit_auth_failure` on the passkey manager.
    async fn emit_failed(
        &self,
        now: DateTime<Utc>,
        context: &SessionContext,
        user_id: UserId,
        reason: ReauthFailureReason,
    ) {
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::ReauthFailed { user_id, reason },
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_for_gates_only_listed_actions() {
        let policy =
            ReauthPolicy::required_for([ReauthAction::DeleteAccount, ReauthAction::RemovePasskey]);
        assert!(policy.requires(ReauthAction::DeleteAccount));
        assert!(policy.requires(ReauthAction::RemovePasskey));
        assert!(!policy.requires(ReauthAction::RequestEmailChange));
    }

    #[test]
    fn disabled_gates_nothing() {
        let policy = ReauthPolicy::disabled();
        assert!(!policy.requires(ReauthAction::DeleteAccount));
        assert!(!policy.requires(ReauthAction::RequestEmailChange));
        assert!(!policy.requires(ReauthAction::RemovePasskey));
    }
}
