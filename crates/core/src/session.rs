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

#[derive(Clone)]
pub struct IssuedSession {
    pub session: Session,
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

pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub absolute_lifetime: Duration,
    pub idle_timeout: Option<Duration>,
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

#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[async_trait]
pub(crate) trait SessionInvalidationHook: Send + Sync {
    async fn on_session_invalidated(&self, session_id: SessionId);
    async fn on_user_invalidated(&self, user_id: UserId);
}

pub(crate) struct NoopSessionInvalidationHook;

#[async_trait]
impl SessionInvalidationHook for NoopSessionInvalidationHook {
    async fn on_session_invalidated(&self, _: SessionId) {}
    async fn on_user_invalidated(&self, _: UserId) {}
}

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<dyn SessionStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    invalidation_hook: Arc<RwLock<Arc<dyn SessionInvalidationHook>>>,
    config: SessionConfig,
}

impl SessionManager {
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

    pub(crate) fn idle_timeout(&self) -> Option<Duration> {
        self.config.idle_timeout
    }

    pub fn unused_lifetime(&self) -> Duration {
        self.config
            .idle_timeout
            .unwrap_or(self.config.absolute_lifetime)
    }

    pub(crate) fn set_invalidation_hook(&self, hook: Arc<dyn SessionInvalidationHook>) {
        *sync::write(&self.invalidation_hook) = hook;
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub(crate) async fn forget_cached_user(&self, user_id: UserId) {
        self.invalidation_hook().on_user_invalidated(user_id).await;
    }

    fn invalidation_hook(&self) -> Arc<dyn SessionInvalidationHook> {
        sync::read(&self.invalidation_hook).clone()
    }

    #[tracing::instrument(skip(self, context), fields(user_id = %user_id))]
    pub async fn create(&self, user_id: UserId, context: SessionContext) -> Result<IssuedSession> {
        self.issue(user_id, context, None).await
    }

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

    async fn enforce_session_cap(&self, user_id: UserId, max: u32) -> Result<()> {
        let mut active = self.list_for_user(user_id).await?;
        let max = max as usize;
        if active.len() < max {
            return Ok(());
        }
        let evict = active.len() + 1 - max;
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

    pub async fn validate(&self, token: &str) -> Result<Session> {
        self.validate_by_hash(&hash_token(token)).await
    }

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

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<u64> {
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, None)
            .await?;
        if count > 0 {
            self.invalidation_hook().on_user_invalidated(user_id).await;
        }
        tracing::info!(count, outcome = "revoked_all", "user sessions revoked");
        Ok(count)
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Session>> {
        let now = self.clock.now();
        Ok(self.sessions.list_for_user(user_id, now).await?)
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_summaries_for_user(&self, user_id: UserId) -> Result<Vec<SessionSummary>> {
        let sessions = self.list_for_user(user_id).await?;
        Ok(sessions.iter().map(SessionSummary::from).collect())
    }

    pub(crate) async fn revoke_others(&self, user_id: UserId, keep: SessionId) -> Result<u64> {
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, Some(keep))
            .await?;
        if count > 0 {
            self.invalidation_hook().on_user_invalidated(user_id).await;
        }
        tracing::info!(
            count,
            outcome = "revoked_others",
            "other user sessions revoked"
        );
        Ok(count)
    }

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

        assert_eq!(SessionSummary::from(session.clone()), summary);
    }

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
        assert_eq!(issued.token, "super-secret-bearer-token");
    }

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
        async fn on_user_invalidated(&self, user_id: UserId) {
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
