use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::assembly::AssemblyError;
use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::storage::{
    Session, SessionId, SessionStore, SessionSummary, TokenHash, User, UserId, UserStore,
};
use crate::token::generate_token;
pub use crate::token::hash_token;
use crate::user_records::find_active_user;

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

pub const DEFAULT_SLIDE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub absolute_lifetime: Duration,
    pub idle_timeout: Option<Duration>,
    pub slide_interval: Duration,
    pub max_sessions_per_user: Option<NonZeroU32>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            absolute_lifetime: DEFAULT_SESSION_LIFETIME,
            idle_timeout: None,
            slide_interval: DEFAULT_SLIDE_INTERVAL,
            max_sessions_per_user: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSession {
    pub session: Session,
    pub slid: bool,
}

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<dyn SessionStore>,
    users: Arc<dyn UserStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    config: SessionConfig,
}

impl SessionManager {
    pub(crate) fn new(
        sessions: Arc<dyn SessionStore>,
        users: Arc<dyn UserStore>,
        clock: Arc<dyn Clock>,
        audit: AuditDispatch,
        config: SessionConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        if let Some(idle_timeout) = config.idle_timeout
            && config.slide_interval >= idle_timeout
        {
            return Err(AssemblyError::IdleTimeoutInvalid {
                idle_timeout,
                reason: "must be strictly greater than the slide interval so an active session slides before it idles out",
            });
        }
        Ok(Self {
            sessions,
            users,
            clock,
            audit,
            config,
        })
    }

    pub fn unused_lifetime(&self) -> Duration {
        self.config
            .idle_timeout
            .unwrap_or(self.config.absolute_lifetime)
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    #[tracing::instrument(
        skip_all,
        fields(session_id = tracing::field::Empty, user_id = tracing::field::Empty),
    )]
    pub async fn resolve(&self, token: &str) -> Result<ResolvedSession> {
        let session = self.validate_by_hash(&hash_token(token)).await?;
        let span = tracing::Span::current();
        span.record("session_id", tracing::field::display(session.id));
        span.record("user_id", tracing::field::display(session.user_id));
        let (session, slid) = self.slide(session, self.clock.now()).await;
        Ok(ResolvedSession { session, slid })
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id))]
    pub async fn find_user(&self, session: &Session) -> Result<User> {
        self.users
            .find_user_by_id(session.user_id)
            .await?
            .ok_or(Error::UserNotFound)
    }

    #[tracing::instrument(skip(self, context), fields(user_id = %user_id))]
    pub async fn create(&self, user_id: UserId, context: SessionContext) -> Result<IssuedSession> {
        self.issue(user_id, context, RecoveryCoolDown::NONE).await
    }

    pub(crate) async fn issue(
        &self,
        user_id: UserId,
        context: SessionContext,
        cool_down: RecoveryCoolDown,
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
            recovery_cool_down_until: cool_down.until(),
        };

        self.sessions.create_session(session.clone()).await?;
        // Disable and delete change the user before deleting their sessions, so if that delete
        // missed this session, this read sees the change. The token is handed out only after it.
        if let Err(error) = find_active_user(self.users.as_ref(), user_id).await {
            if let Err(cleanup) = self.sessions.delete_session(session.id).await {
                tracing::warn!(
                    session_id = %session.id,
                    error = %cleanup,
                    "refused session left behind; its token was never handed out",
                );
            }
            return Err(error);
        }

        self.audit
            .emit(
                &context,
                AuditEventKind::SessionCreated {
                    user_id,
                    session_id: session.id,
                },
            )
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
            self.revoke_session(&session, Actor::of_session(&session))
                .await?;
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
                .emit(
                    Actor::of_session(&session),
                    AuditEventKind::SessionExpired {
                        user_id: session.user_id,
                        session_id: session.id,
                    },
                )
                .await;
            return Err(Error::SessionExpired);
        }

        Ok(session)
    }

    fn slide_due(&self, session: &Session, now: DateTime<Utc>) -> bool {
        self.config.idle_timeout.is_some()
            && (now - session.last_used_at)
                .to_std()
                .is_ok_and(|since_used| since_used >= self.config.slide_interval)
    }

    async fn slide(&self, session: Session, now: DateTime<Utc>) -> (Session, bool) {
        if !self.slide_due(&session, now) {
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
        self.revoke_session(&session, Actor::of_session(&session))
            .await
    }

    #[tracing::instrument(skip(self), fields(session_id = %session_id))]
    pub async fn revoke_by_id(&self, session_id: SessionId) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        self.revoke_session(&session, Actor::of_session(&session))
            .await
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<u64> {
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, None)
            .await?;
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
        self.revoke_session(&session, actor).await
    }

    async fn revoke_session(&self, session: &Session, actor: Actor) -> Result<()> {
        self.sessions.delete_session(session.id).await?;
        self.audit
            .emit(
                actor,
                AuditEventKind::SessionRevoked {
                    user_id: session.user_id,
                    session_id: session.id,
                },
            )
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
            recovery_cool_down_until: value.recovery_cool_down_until,
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
            recovery_cool_down_until: value.recovery_cool_down_until,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cool_down = Utc.timestamp_opt(1_500, 0).single().expect("ts");
        let session = Session {
            id: SessionId::new(),
            user_id: UserId::new(),
            token_hash: TokenHash([7u8; 32]),
            created_at,
            last_used_at,
            expires_at,
            ip: Some("203.0.113.7".to_string()),
            user_agent: Some("doorman-test/1.0".to_string()),
            recovery_cool_down_until: Some(cool_down),
        };

        let summary = SessionSummary::from(&session);
        assert_eq!(summary.id, session.id);
        assert_eq!(summary.user_id, session.user_id);
        assert_eq!(summary.created_at, created_at);
        assert_eq!(summary.last_used_at, last_used_at);
        assert_eq!(summary.expires_at, expires_at);
        assert_eq!(summary.ip, session.ip);
        assert_eq!(summary.user_agent, session.user_agent);
        assert_eq!(summary.recovery_cool_down_until, Some(cool_down));

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
            recovery_cool_down_until: None,
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
}
