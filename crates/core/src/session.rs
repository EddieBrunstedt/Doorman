//! Server-side opaque session management.
//!
//! [`SessionManager`] issues high-entropy bearer tokens, stores only their
//! hashes, validates incoming tokens, and revokes sessions immediately via
//! the configured [`SessionStore`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

/// Length of the random token in bytes. 256 bits of entropy. Shared by
/// session tokens and verification tokens (see [`generate_token`]).
const TOKEN_BYTES: usize = 32;

/// A session that has just been issued, paired with the plaintext token to
/// hand back to the client. The token is never persisted in plaintext.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub session: Session,
    pub token: String,
}

/// Configuration for session issuance.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub lifetime: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // 30 days
            lifetime: Duration::from_secs(60 * 60 * 24 * 30),
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
    /// The hook is captured at construction (or rebuild) time and shared
    /// by every subsequent `clone()`. Hosts that need a framework cache
    /// (e.g. `bauth-axum`'s session-resolution cache) build the hook
    /// first and call [`SessionManager::with_invalidation_hook`] _before_
    /// handing clones to dependent managers, so every clone sees the same
    /// observer.
    invalidation_hook: Arc<dyn SessionInvalidationHook>,
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
            invalidation_hook: Arc::new(NoopSessionInvalidationHook),
            config,
        }
    }

    /// Return a new `SessionManager` with `hook` installed as the
    /// invalidation observer.
    ///
    /// The hook is captured by value: existing clones of the original
    /// manager (including any held by `PasskeyManager` or `SignupManager`
    /// constructed earlier) keep their previous hook. Hosts that need every
    /// dependent manager to observe invalidations should call this _before_
    /// constructing the dependent managers and pass the resulting
    /// `SessionManager` to them.
    pub fn with_invalidation_hook(mut self, hook: Arc<dyn SessionInvalidationHook>) -> Self {
        self.invalidation_hook = hook;
        self
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

    #[tracing::instrument(skip(self, token), fields(user_id = tracing::field::Empty, session_id = tracing::field::Empty))]
    pub async fn validate(&self, token: &str) -> Result<Session> {
        let hash = hash_token(token);
        let Some(session) = self.sessions.find_session_by_token_hash(&hash).await? else {
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
        self.invalidation_hook
            .on_user_sessions_invalidated(user_id)
            .await;
        tracing::info!(count, outcome = "revoked_all", "user sessions revoked");
        Ok(count)
    }

    /// Report whether `session` is currently inside its post-recovery
    /// cool-down window, using this manager's clock. Routes call this
    /// to decide whether to reject destructive actions with
    /// [`Error::RecoveryCooldownActive`].
    pub fn is_in_recovery_cooldown(&self, session: &Session) -> bool {
        session.is_in_recovery_cooldown(self.clock.now())
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

    /// Revoke every session belonging to `user_id` *except* `except`. The
    /// retained session is the caller's "current" device on the typical
    /// "sign out everywhere else" path. Notifies the invalidation hook so
    /// any framework-side cache evicts the removed sessions.
    #[tracing::instrument(skip(self), fields(user_id = %user_id, session_id = %except))]
    pub async fn revoke_others_for_user(&self, user_id: UserId, except: SessionId) -> Result<u64> {
        let count = self
            .sessions
            .delete_other_sessions_for_user(user_id, except)
            .await?;
        if count > 0 {
            self.invalidation_hook
                .on_user_sessions_invalidated(user_id)
                .await;
        }
        tracing::info!(
            count,
            outcome = "revoked_others",
            "other user sessions revoked"
        );
        Ok(count)
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
        self.invalidation_hook
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

pub fn hash_token(token: &str) -> TokenHash {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    TokenHash(out)
}

/// Generate a fresh random token and its at-rest hash. The cleartext token
/// is handed to the client (session cookie or email link); only the hash is
/// persisted. Shared by [`SessionManager`] and the verification flows.
pub(crate) fn generate_token() -> (String, TokenHash) {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_url_safe_and_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
        for ch in a.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "token contains non-url-safe char: {ch:?}"
            );
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_token("hello");
        let b = hash_token("hello");
        assert_eq!(a, b);
    }

    #[test]
    fn default_config_builds() {
        let _ = SessionConfig::default();
    }
}
