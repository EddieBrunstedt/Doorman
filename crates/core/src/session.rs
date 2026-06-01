//! Server-side opaque session management.
//!
//! [`SessionManager`] issues high-entropy bearer tokens, stores only their
//! hashes, validates incoming tokens, and revokes sessions immediately via
//! the configured [`SessionStore`].

use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::email::SecurityEmailNotifier;
use crate::error::{Error, Result};
use crate::storage::{Session, SessionId, SessionStore, TokenHash, User, UserId};
use crate::token::generate_token;
pub use crate::token::hash_token;

/// A session that has just been issued, paired with the plaintext token to
/// hand back to the client. The token is never persisted in plaintext.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub session: Session,
    pub token: String,
}

/// Default session lifetime (30 days). The single source for the figure:
/// the cookie `Max-Age` default in `bauth-axum` derives from this so the
/// two cannot drift apart.
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Configuration for session issuance.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub lifetime: Duration,
    /// Cap on concurrent active sessions per user. When issuing a session
    /// would exceed it, the user's oldest active session(s) are revoked first
    /// (evict-oldest) so the new login always succeeds and per-user growth is
    /// bounded. `None` (the default) disables the cap; a host concerned about
    /// unbounded per-user session rows sets a value such as 100. Enforcing it
    /// costs one `list_for_user` read per login, hence opt-in.
    pub max_sessions_per_user: Option<NonZeroU32>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            lifetime: DEFAULT_SESSION_LIFETIME,
            max_sessions_per_user: None,
        }
    }
}

/// Request metadata captured when an auth flow creates or audits a session.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Observer that is notified whenever the [`SessionManager`] invalidates
/// a session out-of-band of a fresh `validate()` call. Implementations
/// live outside `bauth-core`; the canonical user is `bauth-axum`'s
/// session-resolution cache, which needs to evict stale entries when a
/// session is revoked or a user is logged out everywhere.
///
/// Hooks are called on a best-effort basis — failures during invalidation
/// must not propagate, so the trait returns `()` rather than `Result`.
#[async_trait]
pub trait SessionInvalidationHook: Send + Sync {
    async fn on_session_invalidated(&self, session_id: SessionId);
    async fn on_user_sessions_invalidated(&self, user_id: UserId);
}

/// Default hook that ignores every event. Used when no observer is wired
/// up, which is the common case for non-axum hosts.
pub struct NoopSessionInvalidationHook;

#[async_trait]
impl SessionInvalidationHook for NoopSessionInvalidationHook {
    async fn on_session_invalidated(&self, _: SessionId) {}
    async fn on_user_sessions_invalidated(&self, _: UserId) {}
}

/// Manager for issuing, validating, listing, and revoking sessions.
#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<dyn SessionStore>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    /// The invalidation observer, held behind a shared, mutable cell that
    /// every `clone()` aliases. Installing a hook through any handle (see
    /// [`SessionManager::set_invalidation_hook`]) is therefore visible to
    /// every other clone regardless of when it was taken — install order
    /// cannot leave a manager wired to a stale observer.
    invalidation_hook: Arc<RwLock<Arc<dyn SessionInvalidationHook>>>,
    /// Best-effort notifier for session-revocation security notices. Wired
    /// at the composition root via [`SessionManager::with_security_notifier`];
    /// when absent the revoke paths still run, they just send no email. Held
    /// so the notices originate in core — every host driving the manager gets
    /// them, not only the bundled axum routes.
    notifier: Option<SecurityEmailNotifier>,
    config: SessionConfig,
}

impl SessionManager {
    pub fn new(
        sessions: Arc<dyn SessionStore>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        config: SessionConfig,
    ) -> Self {
        Self {
            sessions,
            clock,
            audit,
            invalidation_hook: Arc::new(RwLock::new(Arc::new(NoopSessionInvalidationHook))),
            notifier: None,
            config,
        }
    }

    /// Install the best-effort security [`SecurityEmailNotifier`] used for
    /// session-revocation notices and return `self`. Set this at the
    /// composition root *before* the manager is cloned into the other
    /// managers so every clone carries it.
    pub fn with_security_notifier(mut self, notifier: SecurityEmailNotifier) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Install `hook` as the invalidation observer and return `self`.
    ///
    /// The hook lives in a cell shared by every clone of this manager, so
    /// the install is visible to clones taken _before_ this call as well as
    /// after. Construction order between the manager and its dependents
    /// (`PasskeyManager`, `SignupManager`, …) therefore does not matter.
    pub fn with_invalidation_hook(self, hook: Arc<dyn SessionInvalidationHook>) -> Self {
        self.set_invalidation_hook(hook);
        self
    }

    /// Install `hook` as the invalidation observer, in place. Because the
    /// observer is held behind a cell shared by every clone, this is visible
    /// to all existing and future clones of the manager — there is no "too
    /// late" ordering hazard.
    pub fn set_invalidation_hook(&self, hook: Arc<dyn SessionInvalidationHook>) {
        *self
            .invalidation_hook
            .write()
            .expect("invalidation hook lock poisoned") = hook;
    }

    /// Borrow the clock this manager reads time through. Framework layers
    /// that need to answer a clock-dependent question consistently with the
    /// manager (e.g. the axum `AuthSession` recovery-cool-down helper) take
    /// the clock from here rather than reading `chrono::Utc::now()` directly,
    /// so a host that injected a custom or mock clock is honoured everywhere.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Snapshot the currently installed invalidation observer. Cloned out so
    /// the lock guard is never held across an `.await`.
    fn invalidation_hook(&self) -> Arc<dyn SessionInvalidationHook> {
        self.invalidation_hook
            .read()
            .expect("invalidation hook lock poisoned")
            .clone()
    }

    #[tracing::instrument(skip(self, context), fields(user_id = %user_id))]
    pub async fn create(&self, user_id: UserId, context: SessionContext) -> Result<IssuedSession> {
        self.issue(user_id, context, None).await
    }

    /// Issue a session restricted by a post-recovery cool-down. The
    /// resulting session reports `is_in_recovery_cooldown(now)` until
    /// `cooldown_until`; routes that gate on the cool-down (delete
    /// passkey, revoke other sessions, etc.) refuse to proceed while that
    /// is true.
    #[tracing::instrument(
        skip(self, context),
        fields(user_id = %user_id, cooldown_until = %cooldown_until),
    )]
    pub async fn create_restricted(
        &self,
        user_id: UserId,
        context: SessionContext,
        cooldown_until: DateTime<Utc>,
    ) -> Result<IssuedSession> {
        self.issue(user_id, context, Some(cooldown_until)).await
    }

    async fn issue(
        &self,
        user_id: UserId,
        context: SessionContext,
        cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<IssuedSession> {
        if let Some(max) = self.config.max_sessions_per_user {
            self.enforce_session_cap(user_id, max.get()).await?;
        }

        let (token, token_hash) = generate_token();
        let now = self.clock.now();
        let expires_at = now
            + chrono::Duration::from_std(self.config.lifetime)
                .expect("session lifetime overflows chrono::Duration; configure a smaller value");

        let session = Session {
            id: SessionId::new(),
            user_id,
            token_hash,
            created_at: now,
            expires_at,
            ip: context.ip.clone(),
            user_agent: context.user_agent.clone(),
            recovery_cooldown_until: cooldown_until,
        };

        self.sessions.create_session(session.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::SessionCreated {
                    user_id,
                    session_id: session.id,
                },
            })
            .await;

        tracing::info!(session_id = %session.id, outcome = "created", "session created");
        Ok(IssuedSession { session, token })
    }

    /// Evict the user's oldest active sessions so that issuing one more keeps
    /// the active count at or below `max`. Revoking goes through
    /// [`revoke_session`](Self::revoke_session) so each eviction notifies the
    /// invalidation hook (cache eviction) and records a `SessionRevoked`
    /// audit event like any other revocation.
    async fn enforce_session_cap(&self, user_id: UserId, max: u32) -> Result<()> {
        let mut active = self.list_for_user(user_id).await?;
        // Room must remain for the session about to be created, so we need
        // strictly fewer than `max` active sessions before issuing.
        let max = max as usize;
        if active.len() < max {
            return Ok(());
        }
        let evict = active.len() + 1 - max;
        // Oldest first, so the longest-idle sessions are the ones dropped.
        active.sort_by_key(|s| s.created_at);
        for session in active.into_iter().take(evict) {
            self.revoke_session(session).await?;
        }
        Ok(())
    }

    pub async fn validate(&self, token: &str) -> Result<Session> {
        self.validate_by_hash(&hash_token(token)).await
    }

    /// Validate a session directly from its token hash. Callers that have
    /// already hashed the token (e.g. a framework cache keyed by
    /// [`TokenHash`]) use this to avoid hashing twice per request.
    #[tracing::instrument(skip(self, hash), fields(user_id = tracing::field::Empty, session_id = tracing::field::Empty))]
    pub async fn validate_by_hash(&self, hash: &TokenHash) -> Result<Session> {
        let Some(session) = self.sessions.find_session_by_token_hash(hash).await? else {
            tracing::warn!(outcome = "not_found", "session validate failed");
            return Err(Error::SessionNotFound);
        };
        let span = tracing::Span::current();
        span.record("user_id", tracing::field::display(session.user_id));
        span.record("session_id", tracing::field::display(session.id));

        let now = self.clock.now();
        if session.expires_at <= now {
            self.audit
                .emit(AuditEvent {
                    timestamp: now,
                    ip: session.ip.clone(),
                    user_agent: session.user_agent.clone(),
                    kind: AuditEventKind::SessionExpired {
                        user_id: session.user_id,
                        session_id: session.id,
                    },
                })
                .await;
            tracing::warn!(outcome = "expired", "session validate failed");
            return Err(Error::SessionExpired);
        }

        Ok(session)
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn revoke(&self, token: &str) -> Result<()> {
        let hash = hash_token(token);
        let Some(session) = self.sessions.find_session_by_token_hash(&hash).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        self.revoke_session(session).await
    }

    #[tracing::instrument(skip(self), fields(session_id = %session_id))]
    pub async fn revoke_by_id(&self, session_id: SessionId) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        self.revoke_session(session).await
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<u64> {
        let count = self.sessions.delete_sessions_for_user(user_id).await?;
        self.invalidation_hook()
            .on_user_sessions_invalidated(user_id)
            .await;
        tracing::info!(count, outcome = "revoked_all", "user sessions revoked");
        Ok(count)
    }

    /// Return `session`'s active post-recovery cool-down deadline using
    /// this manager's clock. Expired cool-downs are treated as inactive.
    pub fn active_recovery_cooldown_until(&self, session: &Session) -> Option<DateTime<Utc>> {
        session.active_recovery_cooldown_until(self.clock.now())
    }

    /// Report whether `session` is currently inside its post-recovery
    /// cool-down window, using this manager's clock. Routes call this
    /// to decide whether to reject destructive actions with
    /// [`Error::RecoveryCooldownActive`].
    pub fn is_in_recovery_cooldown(&self, session: &Session) -> bool {
        self.active_recovery_cooldown_until(session).is_some()
    }

    /// Return every still-valid session belonging to `user_id`. Sessions
    /// whose `expires_at` has already passed are filtered out here so
    /// adapters don't have to encode the expiry rule.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Session>> {
        let now = self.clock.now();
        let sessions = self.sessions.list_for_user(user_id).await?;
        Ok(sessions
            .into_iter()
            .filter(|s| s.expires_at > now)
            .collect())
    }

    /// Revoke every session belonging to `user` *except* `except`. The
    /// retained session is the caller's "current" device on the typical
    /// "sign out everywhere else" path. Notifies the invalidation hook so
    /// any framework-side cache evicts the removed sessions, and — when
    /// anything was revoked — sends the best-effort "other sessions revoked"
    /// security notice so the notice originates here rather than in each
    /// host's HTTP layer.
    #[tracing::instrument(skip(self, user), fields(user_id = %user.id, session_id = %except))]
    pub async fn revoke_others_for_user(&self, user: &User, except: SessionId) -> Result<u64> {
        let count = self
            .sessions
            .delete_other_sessions_for_user(user.id, except)
            .await?;
        if count > 0 {
            self.invalidation_hook()
                .on_user_sessions_invalidated(user.id)
                .await;
            if let Some(notifier) = &self.notifier {
                notifier.other_sessions_revoked(user).await;
            }
        }
        tracing::info!(
            count,
            outcome = "revoked_others",
            "other user sessions revoked"
        );
        Ok(count)
    }

    /// Revoke a single session the caller owns, identified by `session_id`.
    ///
    /// Reads the target once, rejects a missing session or one owned by a
    /// different user with [`Error::SessionNotFound`] (so a probe cannot
    /// learn whether another user's session id exists), then revokes it.
    /// When the revoked session is not the caller's current one
    /// (`current_session_id`) the best-effort "session revoked" security
    /// notice is sent — self-revocation stays silent. Keeping this in the
    /// manager means the notice originates in core for every host.
    #[tracing::instrument(
        skip(self, user),
        fields(user_id = %user.id, session_id = %session_id),
    )]
    pub async fn revoke_owned_session(
        &self,
        user: &User,
        session_id: SessionId,
        current_session_id: SessionId,
    ) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        if session.user_id != user.id {
            tracing::warn!(outcome = "not_owned", "session revoke failed");
            return Err(Error::SessionNotFound);
        }
        self.revoke_session(session).await?;
        if session_id != current_session_id
            && let Some(notifier) = &self.notifier
        {
            notifier.other_session_revoked(user).await;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn purge_expired(&self) -> Result<u64> {
        let now = self.clock.now();
        let count = self.sessions.purge_expired(now).await?;
        tracing::info!(count, outcome = "purged", "expired sessions purged");
        Ok(count)
    }

    async fn revoke_session(&self, session: Session) -> Result<()> {
        self.sessions.delete_session(session.id).await?;
        self.invalidation_hook()
            .on_session_invalidated(session.id)
            .await;
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: session.ip,
                user_agent: session.user_agent,
                kind: AuditEventKind::SessionRevoked {
                    user_id: session.user_id,
                    session_id: session.id,
                },
            })
            .await;
        tracing::info!(
            user_id = %session.user_id,
            session_id = %session.id,
            outcome = "revoked",
            "session revoked",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_builds() {
        let _ = SessionConfig::default();
    }
}
