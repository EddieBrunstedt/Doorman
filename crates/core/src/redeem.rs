//! Redemption of single-use secrets: passkey ceremony challenges and emailed
//! link tokens.
//!
//! Every secret is redeemed the same way: take it from its store (which
//! deletes it, so it cannot be replayed), check it was issued for this
//! ceremony or flow, check it is still live, read its payload, and — when it
//! is bound to a user — require that user to be active. [`Redeemer`] owns that
//! sequence. A caller gets back a live, typed payload, or a refusal that has
//! already been audited as [`AuditEventKind::RedemptionFailed`].
//!
//! A refused secret stays consumed: presenting a challenge to the wrong
//! ceremony, or a link after its owner was disabled, burns it. Only a secret
//! the store does not recognise is left untouched, because there is nothing
//! to take.

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

/// A redeemed registration challenge.
pub(crate) struct RedeemedRegistration {
    /// The active user the ceremony enrols a passkey for.
    pub user: User,
    /// The `webauthn-rs` ceremony state.
    pub state: PasskeyRegistration,
    /// Recovery cool-down deadline the ceremony was started with, if any.
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

/// Takes single-use secrets from their stores and turns each into a live,
/// typed payload or an audited refusal.
///
/// Cheap to clone: every field is `Arc`-backed.
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

    /// Redeem a registration challenge. Refusals return
    /// [`Error::InvalidPasskeyChallenge`], or [`Error::AccountDisabled`] when
    /// the user it was started for has since been disabled.
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

    /// Redeem a discoverable sign-in challenge. Refusals return
    /// [`Error::InvalidPasskeyChallenge`]. The challenge names no user; the
    /// caller resolves one from the assertion.
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

    /// Redeem a re-authentication challenge for the session user `user_id`.
    /// Refusals return [`Error::ReauthRequired`], so the caller restarts the
    /// re-authentication handshake. The session was already resolved as an
    /// active user, so no owner lookup runs.
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

    /// Redeem a signup or recovery link and return its active owner. Refusals
    /// return [`Error::InvalidVerificationToken`], or
    /// [`Error::AccountDisabled`] for a disabled owner.
    pub(crate) async fn enrollment_link(
        &self,
        token: &str,
        purpose: VerificationPurpose,
        context: &SessionContext,
    ) -> Result<User> {
        let (user, _) = self.link(token, purpose, context, |_| Some(())).await?;
        Ok(user)
    }

    /// Redeem an email-change link, returning its active owner and the
    /// already-normalized address the link moves the account to. Refusals
    /// return [`Error::InvalidVerificationToken`], or
    /// [`Error::AccountDisabled`] for a disabled owner.
    pub(crate) async fn email_change_link(
        &self,
        token: &str,
        context: &SessionContext,
    ) -> Result<(User, String)> {
        self.link(token, VerificationPurpose::EmailChange, context, |record| {
            record.new_email.clone()
        })
        .await
    }

    /// The shared link-token path: consume by hash and purpose, re-check the
    /// purpose and lifetime, read the payload with `payload`, then require
    /// the owner to be active.
    async fn link<T>(
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
        // The store is asked for this purpose only, but the returned record is
        // re-checked so a store that ignores the filter can never let one
        // flow's link redeem on another.
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

    /// Refuse a secret issued for another purpose, or one past its lifetime.
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

    /// Refuse a secret whose stored ceremony state does not decode.
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

    /// Load the user a secret is bound to and require the account to be
    /// active.
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

    /// Audit a refusal and return the error the caller surfaces for it.
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

/// The error a refused `secret` surfaces as. A disabled owner is a deliberate
/// refusal the caller can act on, so it keeps its own error; every other
/// reason reads as the secret simply no longer being valid.
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
