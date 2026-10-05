//! Server-side opaque session management.
//!
//! [`SessionManager`] issues high-entropy bearer tokens, stores only their
//! hashes, validates incoming tokens, and revokes sessions immediately via
//! the configured [`SessionStore`].

use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::storage::{Session, SessionId, SessionStore, SessionSummary, TokenHash, UserId};
use crate::sync;
use crate::token::generate_token;
pub use crate::token::hash_token;

/// A session that has just been issued, paired with the plaintext token to
/// hand back to the client. The token is never persisted in plaintext.
///
/// The cleartext `token` is a live bearer credential, so the [`Debug`] impl
/// redacts it: an accidental `tracing::debug!(?issued)` cannot spill a usable
/// session token into logs. The field is still public — the host reads it once
/// to set the cookie / response body — but it never renders itself.
#[derive(Clone)]
pub struct IssuedSession {
    /// The persisted session row.
    pub session: Session,
    /// The plaintext bearer token to return to the client once. Never stored.
    pub token: String,
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedSession")
            .field("session", &self.session)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Default session lifetime (30 days). The single source for the figure:
/// the cookie `Max-Age` default in `doorman-axum` derives from this so the
/// two cannot drift apart.
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Configuration for session issuance.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Hard cap measured from `created_at`; the session dies here no matter
    /// what activity occurs.
    pub absolute_lifetime: Duration,
    /// Idle window. `None` (the default) is pure absolute expiry — no
    /// sliding, no touch writes, behavior identical to a fixed lifetime.
    /// `Some(d)` makes the session expire `d` after its last use, sliding the
    /// deadline forward on each use and capped at `absolute_lifetime`. Sliding
    /// happens in [`SessionResolver::resolve`](crate::resolve::SessionResolver::resolve),
    /// which also documents how the idle window must relate to the cache TTL.
    pub idle_timeout: Option<Duration>,
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
            absolute_lifetime: DEFAULT_SESSION_LIFETIME,
            idle_timeout: None,
            max_sessions_per_user: None,
        }
    }
}

/// Request metadata captured when an auth flow creates or audits a session.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// Canonical client IP from a trusted source, if the host captured one.
    /// Core treats this as an opaque rate-limit key and session/audit metadata;
    /// callers must validate and normalize it (for example with
    /// `IpAddr::to_canonical().to_string()`) and establish its provenance.
    /// `None` skips per-IP rate limits even when configured. HTTP integrations
    /// should require identity before invoking managers with per-IP protection.
    pub ip: Option<String>,
    /// Client user-agent, if the host captured one.
    pub user_agent: Option<String>,
}

/// Observer that is notified whenever the [`SessionManager`] invalidates
/// a session out-of-band of a fresh `validate()` call. The canonical user is
/// the [`SessionResolver`](crate::resolve::SessionResolver)'s cache, which
/// needs to evict stale entries when a session is revoked or a user is logged
/// out everywhere.
///
/// Hooks are called on a best-effort basis — failures during invalidation
/// must not propagate, so the trait returns `()` rather than `Result`.
#[async_trait]
pub(crate) trait SessionInvalidationHook: Send + Sync {
    /// Called when a single session is invalidated (revoked or deleted).
    async fn on_session_invalidated(&self, session_id: SessionId);
    /// Called when every session for a user is invalidated at once
    /// (log-out-everywhere, account deletion).
    async fn on_user_sessions_invalidated(&self, user_id: UserId);
}

/// Default hook that ignores every event. Used until a
/// [`SessionResolver`](crate::resolve::SessionResolver) installs its cache
/// invalidator.
pub(crate) struct NoopSessionInvalidationHook;

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
    audit: AuditDispatch,
    /// The invalidation observer, held behind a shared, mutable cell that
    /// every `clone()` aliases. Installing a hook through any handle (see
    /// [`SessionManager::set_invalidation_hook`]) is therefore visible to
    /// every other clone regardless of when it was taken — install order
    /// cannot leave a manager wired to a stale observer.
    invalidation_hook: Arc<RwLock<Arc<dyn SessionInvalidationHook>>>,
    config: SessionConfig,
}

impl SessionManager {
    /// Build a session manager from the session store, clock, audit sink, and
    /// config. No invalidation hook is wired yet; the
    /// [`SessionResolver`](crate::resolve::SessionResolver) installs its cache
    /// invalidator with [`set_invalidation_hook`](Self::set_invalidation_hook).
    pub(crate) fn new(
        sessions: Arc<dyn SessionStore>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        config: SessionConfig,
    ) -> Self {
        Self {
            sessions,
            clock,
            audit: AuditDispatch::new(audit),
            invalidation_hook: Arc::new(RwLock::new(Arc::new(NoopSessionInvalidationHook))),
            config,
        }
    }

    /// The configured idle window, or `None` when sliding is disabled.
    pub(crate) fn idle_timeout(&self) -> Option<Duration> {
        self.config.idle_timeout
    }

    /// The longest a session can go unused before it ends: the idle window
    /// when sliding is on, otherwise the absolute lifetime. A front end that
    /// mirrors the session client-side (a cookie `Max-Age`) must not outlive
    /// it.
    pub fn unused_lifetime(&self) -> Duration {
        self.config
            .idle_timeout
            .unwrap_or(self.config.absolute_lifetime)
    }

    /// Install `hook` as the invalidation observer, in place. Because the
    /// observer is held behind a cell shared by every clone, this is visible
    /// to all existing and future clones of the manager — there is no "too
    /// late" ordering hazard, and construction order between the manager and
    /// its dependents (`PasskeyManager`, `SignupManager`, …) does not matter.
    pub(crate) fn set_invalidation_hook(&self, hook: Arc<dyn SessionInvalidationHook>) {
        *sync::write(&self.invalidation_hook) = hook;
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
        sync::read(&self.invalidation_hook).clone()
    }

    /// Issue an ordinary (non-cool-down) session for `user_id`, returning the
    /// row and its plaintext token.
    #[tracing::instrument(skip(self, context), fields(user_id = %user_id))]
    pub async fn create(&self, user_id: UserId, context: SessionContext) -> Result<IssuedSession> {
        self.issue(user_id, context, None).await
    }

    /// Issue a session restricted by a post-recovery cool-down. The
    /// resulting session reports `is_in_recovery_cooldown(now)` until
    /// `cooldown_until`, and [`ReauthManager::ensure`](crate::reauth::ReauthManager::ensure)
    /// refuses every [`ReauthAction`](crate::reauth::ReauthAction) for it
    /// until then. Only recovery and sign-in with a cool-down-bound passkey
    /// mint one.
    #[tracing::instrument(
        skip(self, context),
        fields(user_id = %user_id, cooldown_until = %cooldown_until),
    )]
    pub(crate) async fn create_restricted(
        &self,
        user_id: UserId,
        context: SessionContext,
        cooldown_until: DateTime<Utc>,
    ) -> Result<IssuedSession> {
        self.issue(user_id, context, Some(cooldown_until)).await
    }

    /// Shared session-issuing body taking the cool-down deadline as an
    /// `Option`. [`create`](Self::create) / [`create_restricted`](Self::create_restricted)
    /// pass `None` / `Some(..)`; passkey enrolment
    /// ([`PasskeyManager::enroll`](crate::passkey::PasskeyManager::enroll))
    /// calls this directly so it threads its already-`Option`al deadline
    /// through one call.
    pub(crate) async fn issue(
        &self,
        user_id: UserId,
        context: SessionContext,
        cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<IssuedSession> {
        if let Some(max) = self.config.max_sessions_per_user {
            self.enforce_session_cap(user_id, max.get()).await?;
        }

        let (token, token_hash) = generate_token()?;
        let now = self.clock.now();

        let session = Session {
            id: SessionId::new(),
            user_id,
            token_hash,
            created_at: now,
            last_used_at: now,
            expires_at: self.deadline(now, now),
            ip: context.ip.clone(),
            user_agent: context.user_agent.clone(),
            recovery_cooldown_until: cooldown_until,
        };

        self.sessions.create_session(session.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip,
                    user_agent: context.user_agent,
                },
                kind: AuditEventKind::SessionCreated {
                    user_id,
                    session_id: session.id,
                },
            })
            .await;

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
            let actor = Actor::Subject {
                ip: session.ip.clone(),
                user_agent: session.user_agent.clone(),
            };
            self.revoke_session(session, actor).await?;
        }
        Ok(())
    }

    /// The effective deadline of a session created at `created_at` and last
    /// used at `last_used`: the absolute cap, pulled in to one idle window
    /// after `last_used` when sliding is on. The single place the deadline
    /// rule lives — issue and slide both call it. Saturates instead of
    /// panicking on an out-of-range lifetime; the assembly bounds lifetimes
    /// well inside the range anyway.
    fn deadline(&self, created_at: DateTime<Utc>, last_used: DateTime<Utc>) -> DateTime<Utc> {
        let after = |start: DateTime<Utc>, span: Duration| {
            chrono::Duration::from_std(span)
                .ok()
                .and_then(|span| start.checked_add_signed(span))
                .unwrap_or(DateTime::<Utc>::MAX_UTC)
        };
        let absolute = after(created_at, self.config.absolute_lifetime);
        match self.config.idle_timeout {
            Some(idle) => absolute.min(after(last_used, idle)),
            None => absolute,
        }
    }

    /// Look up a plaintext session token, returning the live session or a
    /// not-found/expired error. Hashes once and delegates to
    /// [`validate_by_hash`](Self::validate_by_hash).
    ///
    /// This is a read: it never slides an idle deadline or consults the user.
    /// To authenticate a request, use
    /// [`SessionResolver::resolve`](crate::resolve::SessionResolver::resolve).
    pub async fn validate(&self, token: &str) -> Result<Session> {
        self.validate_by_hash(&hash_token(token)).await
    }

    /// Look up a session directly from its token hash, returning the live
    /// session or a not-found/expired error. Like
    /// [`validate`](Self::validate), it never slides the deadline.
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
                    actor: Actor::Subject {
                        ip: session.ip.clone(),
                        user_agent: session.user_agent.clone(),
                    },
                    kind: AuditEventKind::SessionExpired {
                        user_id: session.user_id,
                        session_id: session.id,
                    },
                })
                .await;
            return Err(Error::SessionExpired);
        }

        Ok(session)
    }

    /// Slide `session`'s idle deadline forward to `now` and persist it,
    /// returning the session to serve and whether its deadline moved.
    ///
    /// Does nothing (returns `false`) when sliding is off or the session was
    /// last touched less than `granularity` ago — the throttle that keeps an
    /// active session from writing on every request. The write is
    /// best-effort: a touch failure must never fail an otherwise-valid
    /// request, so on error the un-slid row is returned and the caller's
    /// cache mirrors storage truth. Driven only by
    /// [`SessionResolver::resolve`](crate::resolve::SessionResolver::resolve).
    pub(crate) async fn slide(
        &self,
        session: Session,
        now: DateTime<Utc>,
        granularity: Duration,
    ) -> (Session, bool) {
        let due = (now - session.last_used_at)
            .to_std()
            .is_ok_and(|since_used| since_used >= granularity);
        if self.config.idle_timeout.is_none() || !due {
            return (session, false);
        }

        let mut updated = session.clone();
        updated.last_used_at = now;
        updated.expires_at = self.deadline(session.created_at, now);
        match self
            .sessions
            .touch_session(updated.id, updated.last_used_at, updated.expires_at)
            .await
        {
            Ok(()) => {
                tracing::debug!(session_id = %updated.id, "session deadline slid");
                (updated, true)
            }
            Err(error) => {
                tracing::warn!(
                    session_id = %session.id,
                    %error,
                    "session touch failed; serving un-slid session",
                );
                (session, false)
            }
        }
    }

    /// Revoke the session identified by a plaintext token. Returns
    /// [`Error::SessionNotFound`] if the token does not resolve.
    #[tracing::instrument(skip(self, token))]
    pub async fn revoke(&self, token: &str) -> Result<()> {
        let hash = hash_token(token);
        let Some(session) = self.sessions.find_session_by_token_hash(&hash).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        let actor = Actor::Subject {
            ip: session.ip.clone(),
            user_agent: session.user_agent.clone(),
        };
        self.revoke_session(session, actor).await
    }

    /// Revoke a session by its id, firing the invalidation hook. Returns
    /// [`Error::SessionNotFound`] if the id does not resolve.
    #[tracing::instrument(skip(self), fields(session_id = %session_id))]
    pub async fn revoke_by_id(&self, session_id: SessionId) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        let actor = Actor::Subject {
            ip: session.ip.clone(),
            user_agent: session.user_agent.clone(),
        };
        self.revoke_session(session, actor).await
    }

    /// Revoke every session belonging to a user, firing the
    /// user-sessions-invalidated hook when any were removed. Returns the count.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<u64> {
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, None)
            .await?;
        // Only notify the invalidation hook when something was actually
        // revoked, matching `revoke_others`'s guarded shape — a zero-count
        // sweep evicts nothing, so there is nothing to invalidate.
        if count > 0 {
            self.invalidation_hook()
                .on_user_sessions_invalidated(user_id)
                .await;
        }
        tracing::info!(count, outcome = "revoked_all", "user sessions revoked");
        Ok(count)
    }

    /// Return every still-valid session belonging to `user_id`. Sessions
    /// whose `expires_at` has already passed are filtered out here so
    /// adapters don't have to encode the expiry rule.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Session>> {
        let now = self.clock.now();
        let sessions = self.sessions.list_for_user(user_id, now).await?;
        // Adapters that push `expires_at > now` into the query already exclude
        // dead rows; this filter is the belt-and-suspenders that keeps the
        // in-memory reference store (which returns everything) correct too.
        Ok(sessions
            .into_iter()
            .filter(|s| s.expires_at > now)
            .collect())
    }

    /// Return a [`SessionSummary`] for every still-valid session belonging to
    /// `user_id`. Projects the full rows from [`list_for_user`](Self::list_for_user)
    /// so the session `token_hash` never leaves the manager — the projection
    /// is what an operator session listing is meant to consume.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_summaries_for_user(&self, user_id: UserId) -> Result<Vec<SessionSummary>> {
        let sessions = self.list_for_user(user_id).await?;
        Ok(sessions.iter().map(SessionSummary::from).collect())
    }

    /// Revoke every session belonging to `user_id` except `keep`, firing the
    /// user-sessions-invalidated hook when any were removed. Returns the count.
    /// The ungated core of
    /// [`AccountManager::revoke_other_sessions`](crate::account::AccountManager::revoke_other_sessions),
    /// which owns the cool-down and re-auth gate and the security notice.
    pub(crate) async fn revoke_others(&self, user_id: UserId, keep: SessionId) -> Result<u64> {
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, Some(keep))
            .await?;
        if count > 0 {
            self.invalidation_hook()
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

    /// Revoke `session_id` after asserting it belongs to `target_user_id`,
    /// attributing the audit event to `actor` and firing the invalidation hook
    /// through [`revoke_session`](Self::revoke_session). The id-keyed core both
    /// self-service
    /// [`AccountManager::revoke_session`](crate::account::AccountManager::revoke_session)
    /// and the operator single-session-revoke flow drive; the two diverge only
    /// on the recorded `actor` ([`Actor::Subject`] versus [`Actor::Operator`]).
    ///
    /// Reads the target once and rejects a missing session — or one owned by a
    /// different user — with [`Error::SessionNotFound`], so the ownership
    /// re-bind is part of the core rather than a concern the operator path
    /// could skip. The cool-down, current-session protection, and notice are
    /// the self-service caller's concerns, layered on top.
    pub(crate) async fn revoke_session_for_target(
        &self,
        target_user_id: UserId,
        session_id: SessionId,
        actor: Actor,
    ) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        if session.user_id != target_user_id {
            tracing::warn!(outcome = "not_owned", "session revoke failed");
            return Err(Error::SessionNotFound);
        }
        self.revoke_session(session, actor).await
    }

    /// Delete every session past its expiry, returning the number removed.
    #[tracing::instrument(skip(self))]
    pub async fn purge_expired(&self) -> Result<u64> {
        let now = self.clock.now();
        let count = self.sessions.purge_expired(now).await?;
        tracing::info!(count, outcome = "purged", "expired sessions purged");
        Ok(count)
    }

    /// Delete `session`, fire the per-session invalidation hook, and emit the
    /// `SessionRevoked` audit event attributed to `actor`. Self-service callers
    /// pass an [`Actor::Subject`] built from the session's own request
    /// metadata; the operator single-session revoke passes
    /// [`Actor::Operator`] so the audit row carries the operator's identity
    /// rather than the subject's network metadata.
    async fn revoke_session(&self, session: Session, actor: Actor) -> Result<()> {
        self.sessions.delete_session(session.id).await?;
        self.invalidation_hook()
            .on_session_invalidated(session.id)
            .await;
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor,
                kind: AuditEventKind::SessionRevoked {
                    user_id: session.user_id,
                    session_id: session.id,
                },
            })
            .await;
        Ok(())
    }
}

impl From<Session> for SessionSummary {
    fn from(value: Session) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            expires_at: value.expires_at,
            ip: value.ip,
            user_agent: value.user_agent,
            recovery_cooldown_until: value.recovery_cooldown_until,
        }
    }
}

impl From<&Session> for SessionSummary {
    /// Borrowed projection for callers that hold full sessions and need
    /// summaries without consuming them. Clones only the metadata fields —
    /// never the `token_hash`, which is the point of the summary.
    fn from(value: &Session) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            expires_at: value.expires_at,
            ip: value.ip.clone(),
            user_agent: value.user_agent.clone(),
            recovery_cooldown_until: value.recovery_cooldown_until,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAuditSink;
    use crate::clock::SystemClock;
    use crate::memory::InMemorySessionStore;
    use std::sync::Mutex;

    #[test]
    fn default_config_builds() {
        let _ = SessionConfig::default();
    }

    /// The `SessionSummary` projection must carry every operator-useful field
    /// across unchanged while dropping the live bearer-token hash. The hash
    /// only exists on `Session`, so its absence on `SessionSummary` is a
    /// compile-time guarantee; this asserts the surviving fields match.
    #[test]
    fn session_summary_preserves_fields_and_drops_token_hash() {
        use crate::token::TokenHash;
        use chrono::{TimeZone, Utc};

        let created_at = Utc.timestamp_opt(1_000, 0).single().expect("ts");
        let last_used_at = Utc.timestamp_opt(1_200, 0).single().expect("ts");
        let expires_at = Utc.timestamp_opt(2_000, 0).single().expect("ts");
        let cooldown = Utc.timestamp_opt(1_500, 0).single().expect("ts");
        let session = Session {
            id: SessionId::new(),
            user_id: UserId::new(),
            token_hash: TokenHash([7u8; 32]),
            created_at,
            last_used_at,
            expires_at,
            ip: Some("203.0.113.7".to_string()),
            user_agent: Some("doorman-test/1.0".to_string()),
            recovery_cooldown_until: Some(cooldown),
        };

        let summary = SessionSummary::from(&session);
        assert_eq!(summary.id, session.id);
        assert_eq!(summary.user_id, session.user_id);
        assert_eq!(summary.created_at, created_at);
        assert_eq!(summary.last_used_at, last_used_at);
        assert_eq!(summary.expires_at, expires_at);
        assert_eq!(summary.ip, session.ip);
        assert_eq!(summary.user_agent, session.user_agent);
        assert_eq!(summary.recovery_cooldown_until, Some(cooldown));

        // The owning projection drops the same field.
        assert_eq!(SessionSummary::from(session.clone()), summary);
    }

    /// The cleartext bearer token must never render through `Debug`: an
    /// accidental `?issued` in a log line would otherwise spill a live
    /// session credential. The field is still public and serializes/derefs
    /// normally; only its `Debug` rendering is redacted.
    #[test]
    fn issued_session_debug_redacts_token() {
        use chrono::{TimeZone, Utc};

        let now = Utc.timestamp_opt(1_000, 0).single().expect("ts");
        let session = Session {
            id: SessionId::new(),
            user_id: UserId::new(),
            token_hash: hash_token("does-not-matter"),
            created_at: now,
            last_used_at: now,
            expires_at: now,
            ip: None,
            user_agent: None,
            recovery_cooldown_until: None,
        };
        let issued = IssuedSession {
            session,
            token: "super-secret-bearer-token".to_string(),
        };

        let rendered = format!("{issued:?}");
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "Debug output leaked the cleartext token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
        // The token is still readable through the public field.
        assert_eq!(issued.token, "super-secret-bearer-token");
    }

    /// Records every invalidation the manager reports, in order.
    #[derive(Default)]
    struct RecordingHook {
        sessions: Mutex<Vec<SessionId>>,
        users: Mutex<Vec<UserId>>,
    }

    impl RecordingHook {
        fn sessions(&self) -> Vec<SessionId> {
            sync::lock(&self.sessions).clone()
        }

        fn users(&self) -> Vec<UserId> {
            sync::lock(&self.users).clone()
        }
    }

    #[async_trait]
    impl SessionInvalidationHook for RecordingHook {
        async fn on_session_invalidated(&self, session_id: SessionId) {
            sync::lock(&self.sessions).push(session_id);
        }
        async fn on_user_sessions_invalidated(&self, user_id: UserId) {
            sync::lock(&self.users).push(user_id);
        }
    }

    fn plain_manager() -> SessionManager {
        SessionManager::new(
            Arc::new(InMemorySessionStore::new()),
            Arc::new(SystemClock),
            Arc::new(NoopAuditSink),
            SessionConfig::default(),
        )
    }

    fn manager_with_hook(hook: Arc<RecordingHook>) -> SessionManager {
        let manager = plain_manager();
        manager.set_invalidation_hook(hook);
        manager
    }

    #[tokio::test]
    async fn revoke_notifies_hook_with_session_id() {
        let hook = Arc::new(RecordingHook::default());
        let manager = manager_with_hook(hook.clone());

        let issued = manager
            .create(UserId::new(), SessionContext::default())
            .await
            .expect("create");
        manager.revoke(&issued.token).await.expect("revoke");

        assert_eq!(hook.sessions(), vec![issued.session.id]);
        assert!(
            hook.users().is_empty(),
            "no user-level hook on single revoke"
        );
    }

    #[tokio::test]
    async fn revoke_by_id_notifies_hook_with_session_id() {
        let hook = Arc::new(RecordingHook::default());
        let manager = manager_with_hook(hook.clone());

        let issued = manager
            .create(UserId::new(), SessionContext::default())
            .await
            .expect("create");
        manager
            .revoke_by_id(issued.session.id)
            .await
            .expect("revoke_by_id");

        assert_eq!(hook.sessions(), vec![issued.session.id]);
    }

    /// The hook lives in a cell shared by every clone, so installing it is
    /// visible to clones taken _before_ the install as well as after. The
    /// resolver's cache invalidator is installed after the dependent managers
    /// cloned the session manager, and must still be told about revocations.
    #[tokio::test]
    async fn hook_install_order_does_not_matter() {
        let manager = plain_manager();
        let early_clone = manager.clone();
        let hook = Arc::new(RecordingHook::default());
        manager.set_invalidation_hook(hook.clone());

        let issued = early_clone
            .create(UserId::new(), SessionContext::default())
            .await
            .expect("create");
        early_clone
            .revoke(&issued.token)
            .await
            .expect("revoke via early clone");
        assert_eq!(
            hook.sessions(),
            vec![issued.session.id],
            "a clone taken before the install still observes invalidation",
        );

        let late_clone = manager.clone();
        let issued = late_clone
            .create(UserId::new(), SessionContext::default())
            .await
            .expect("create");
        late_clone
            .revoke(&issued.token)
            .await
            .expect("revoke via late clone");
        assert_eq!(hook.sessions().len(), 2, "a later clone shares the hook");
    }

    /// `revoke_all_for_user` must only notify the invalidation hook when it
    /// actually revoked something — matching `revoke_others`'s guarded
    /// shape. A zero-count sweep evicts nothing.
    #[tokio::test]
    async fn revoke_all_does_not_notify_hook_on_zero_count() {
        let hook = Arc::new(RecordingHook::default());
        let manager = manager_with_hook(hook.clone());

        let count = manager
            .revoke_all_for_user(UserId::new())
            .await
            .expect("revoke all");
        assert_eq!(count, 0, "no sessions to revoke");
        assert!(
            hook.users().is_empty(),
            "a zero-count sweep must not notify the hook",
        );
    }

    #[tokio::test]
    async fn revoke_all_notifies_hook_when_sessions_removed() {
        let hook = Arc::new(RecordingHook::default());
        let manager = manager_with_hook(hook.clone());
        let user_id = UserId::new();
        manager
            .create(user_id, SessionContext::default())
            .await
            .expect("create session");

        let count = manager
            .revoke_all_for_user(user_id)
            .await
            .expect("revoke all");
        assert_eq!(count, 1);
        assert_eq!(
            hook.users(),
            vec![user_id],
            "revoking sessions notifies the hook exactly once",
        );
        assert!(
            hook.sessions().is_empty(),
            "a bulk revoke does not notify per session",
        );
    }

    /// `revoke_others` removes only the user's other sessions and notifies
    /// the invalidation hook once when it removed any.
    #[tokio::test]
    async fn revoke_others_keeps_the_exception_and_notifies_hook() {
        let hook = Arc::new(RecordingHook::default());
        let manager = manager_with_hook(hook.clone());
        let user_id = UserId::new();
        let keep = manager
            .create(user_id, SessionContext::default())
            .await
            .expect("keep");
        manager
            .create(user_id, SessionContext::default())
            .await
            .expect("other");

        let count = manager
            .revoke_others(user_id, keep.session.id)
            .await
            .expect("revoke others");
        assert_eq!(count, 1);
        let remaining: Vec<SessionId> = manager
            .list_for_user(user_id)
            .await
            .expect("list")
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(remaining, vec![keep.session.id]);
        assert_eq!(hook.users(), vec![user_id]);
    }

    #[tokio::test]
    async fn revoke_others_does_not_notify_hook_on_zero_count() {
        let hook = Arc::new(RecordingHook::default());
        let manager = manager_with_hook(hook.clone());
        let user_id = UserId::new();
        let only = manager
            .create(user_id, SessionContext::default())
            .await
            .expect("only");

        let count = manager
            .revoke_others(user_id, only.session.id)
            .await
            .expect("revoke others");
        assert_eq!(count, 0);
        assert!(
            hook.users().is_empty(),
            "a no-op revoke must not spam the cache invalidator",
        );
    }
}
