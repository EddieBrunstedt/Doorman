//! The user record's owner: lookups, account standing, field changes, and
//! the account-deletion cascade.
//!
//! Managers reach the user record only through [`UserRecords`], never the raw
//! [`UserStore`], so "find the user or refuse", "is this account usable", and
//! "remove everything that hangs off a user" each have one definition.
//!
//! # Account standing
//!
//! [`ensure_active`] is the account-status rule and [`find_active_user`] the
//! lookup built on it. Every flow that acts *as* the user goes through
//! them: login, per-request session resolution, passkey registration,
//! signup and recovery link consumption, recovery requests, and email-change
//! confirmation. Operator flows deliberately use [`UserRecords::find`]
//! instead — an operator must be able to inspect, delete, and re-enable a
//! disabled account.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result, StorageErrorKind};
use crate::session::SessionManager;
use crate::storage::{
    AccountStatus, PasskeyChallengeStore, PasskeyCredentialStore, User, UserId, UserStore,
    VerificationPurpose, VerificationTokenStore,
};

/// Every verification-token purpose, so account deletion can sweep tokens of
/// all kinds for a user. Kept as a list (rather than iterating an open match)
/// so a new purpose forces a compile error pointing back at the cascade.
const ALL_TOKEN_PURPOSES: [VerificationPurpose; 3] = [
    VerificationPurpose::Signup,
    VerificationPurpose::Recovery,
    VerificationPurpose::EmailChange,
];

/// Require `user`'s account to be usable: [`Error::AccountDisabled`] unless
/// its status is [`active`](AccountStatus::is_active).
pub(crate) fn ensure_active(user: &User) -> Result<()> {
    if user.status.is_active() {
        Ok(())
    } else {
        Err(Error::AccountDisabled)
    }
}

/// Load `user_id` and require its account to be active.
///
/// Returns [`Error::UserNotFound`] for a missing user and
/// [`Error::AccountDisabled`] for a disabled one. A free function over the
/// bare store so [`SessionResolver`](crate::resolve::SessionResolver) and the
/// single-use-secret redeemer, which hold no [`UserRecords`], apply the same
/// gate.
pub(crate) async fn find_active_user(users: &dyn UserStore, user_id: UserId) -> Result<User> {
    let user = users
        .find_user_by_id(user_id)
        .await?
        .ok_or(Error::UserNotFound)?;
    ensure_active(&user)?;
    Ok(user)
}

/// Lookups, field-level changes, and deletion for user records.
///
/// Built from [`CoreDeps`] inside each manager's constructor. Cheap to clone:
/// every field is `Arc`-backed.
#[derive(Clone)]
pub(crate) struct UserRecords {
    users: Arc<dyn UserStore>,
    sessions: SessionManager,
    credentials: Arc<dyn PasskeyCredentialStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl UserRecords {
    pub(crate) fn new(deps: &CoreDeps) -> Self {
        Self {
            users: deps.users.clone(),
            sessions: deps.sessions.clone(),
            credentials: deps.passkey_credentials.clone(),
            tokens: deps.verification_tokens.clone(),
            challenges: deps.passkey_challenges.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
        }
    }

    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    /// Load `user_id` whatever its account status, or
    /// [`Error::UserNotFound`].
    pub(crate) async fn find(&self, user_id: UserId) -> Result<User> {
        self.users
            .find_user_by_id(user_id)
            .await?
            .ok_or(Error::UserNotFound)
    }

    /// Load `user_id` and require its account to be active; see
    /// [`find_active_user`].
    pub(crate) async fn find_active(&self, user_id: UserId) -> Result<User> {
        find_active_user(self.users.as_ref(), user_id).await
    }

    /// Look up a user by an already-normalized email address.
    pub(crate) async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        Ok(self.users.find_user_by_email(email).await?)
    }

    /// Create an active user with an unverified `email` and return it, or
    /// `None` if another user already holds `email`. The store's uniqueness
    /// rule decides, so of two concurrent creates for one address exactly
    /// one gets the user.
    pub(crate) async fn create_unverified(&self, email: &str) -> Result<Option<User>> {
        let now = self.now();
        let user = User {
            id: UserId::new(),
            email: Some(email.to_owned()),
            email_verified_at: None,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        };
        match self.users.create_user(user.clone()).await {
            Ok(()) => Ok(Some(user)),
            Err(e) if e.kind() == StorageErrorKind::Conflict => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Record `user`'s current address as verified, unless it already is.
    pub(crate) async fn mark_email_verified(&self, user: &User) -> Result<()> {
        if user.email_verified_at.is_none() {
            self.users.mark_email_verified(user.id, self.now()).await?;
        }
        Ok(())
    }

    /// Move `user_id` to the verified address `email` and return the user as
    /// stored afterwards.
    ///
    /// Refuses with [`Error::EmailAlreadyInUse`] when another user holds
    /// `email`, and with [`Error::UserNotFound`] when `user_id` is gone. The
    /// store's uniqueness rule decides, so a concurrent claim on `email`
    /// cannot slip in between a check and the write. The returned user is
    /// re-read rather than patched, so it reflects any change another flow
    /// made in between.
    pub(crate) async fn change_email(&self, user_id: UserId, email: &str) -> Result<User> {
        match self.users.set_user_email(user_id, email, self.now()).await {
            Ok(()) => self.find(user_id).await,
            Err(e) => Err(match e.kind() {
                StorageErrorKind::Conflict => Error::EmailAlreadyInUse,
                StorageErrorKind::NotFound => Error::UserNotFound,
                _ => e.into(),
            }),
        }
    }

    /// Disable `user_id` and revoke every live session, returning how many
    /// were revoked.
    ///
    /// The revoke goes through the [`SessionManager`] so its invalidation hook
    /// evicts any cached session and the lockout is immediate. Disabling an
    /// already-disabled account re-stamps the status and re-runs the sweep.
    pub(crate) async fn disable(&self, user_id: UserId) -> Result<u64> {
        let now = self.now();
        self.users
            .set_user_status(user_id, AccountStatus::Disabled { at: now }, now)
            .await?;
        self.sessions.revoke_all_for_user(user_id).await
    }

    /// Return `user_id` to [`AccountStatus::Active`]. Sessions are not
    /// touched: disabling already revoked them.
    pub(crate) async fn enable(&self, user_id: UserId) -> Result<()> {
        self.users
            .set_user_status(user_id, AccountStatus::Active, self.now())
            .await?;
        Ok(())
    }

    /// Irreversibly delete `user_id` and every row that hangs off it, then
    /// emit [`AuditEventKind::AccountDeleted`] attributed to `actor`.
    ///
    /// A missing user fails with [`Error::UserNotFound`] before any store is
    /// touched, so a caller never sees success for a cascade that removed
    /// nothing.
    ///
    /// The order is load-bearing: sessions first (through the
    /// [`SessionManager`], so the cache is evicted while the other rows still
    /// exist), then credentials, verification tokens of every purpose, and
    /// pending registration ceremonies, and the user row last so a failure
    /// midway never orphans children. Pending ceremonies are swept once more
    /// after the user row is gone, reclaiming any a concurrent registration
    /// slipped in during the cascade. There is no cross-store transaction;
    /// `docs/operators.md` documents the remaining non-atomicity.
    pub(crate) async fn delete(&self, user_id: UserId, actor: Actor) -> Result<()> {
        self.find(user_id).await?;

        self.sessions.revoke_all_for_user(user_id).await?;
        self.credentials.delete_passkeys_for_user(user_id).await?;
        for purpose in ALL_TOKEN_PURPOSES {
            self.tokens.delete_tokens_for_user(user_id, purpose).await?;
        }
        self.challenges
            .delete_registrations_for_user(user_id)
            .await?;
        self.users.delete_user(user_id).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: self.now(),
                actor,
                kind: AuditEventKind::AccountDeleted { user_id },
            })
            .await;

        self.challenges
            .delete_registrations_for_user(user_id)
            .await?;
        Ok(())
    }
}
