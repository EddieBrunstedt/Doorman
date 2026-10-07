use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::audit::Actor;
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::SecurityNotices;
use crate::error::Result;
use crate::reauth::{ReauthAction, ReauthManager, ReauthProof};
use crate::session_records::SessionRecords;
use crate::storage::{Session, SessionId, SessionSummary, User};
pub use crate::token::hash_token;
use crate::user_records::UserRecords;

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
    records: SessionRecords,
    users: UserRecords,
    reauth: ReauthManager,
    notices: SecurityNotices,
}

impl SessionManager {
    pub(crate) fn new(deps: &CoreDeps) -> Self {
        Self {
            records: deps.sessions.clone(),
            users: UserRecords::new(deps),
            reauth: deps.reauth.clone(),
            notices: deps.notices.clone(),
        }
    }

    pub fn unused_lifetime(&self) -> Duration {
        self.records.unused_lifetime()
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        self.records.clock()
    }

    pub async fn resolve(&self, token: &str) -> Result<ResolvedSession> {
        self.records.resolve(token).await
    }

    pub async fn find_user(&self, session: &Session) -> Result<User> {
        self.records.find_user(session).await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id))]
    pub async fn list(&self, session: &Session) -> Result<Vec<SessionSummary>> {
        self.records.list_summaries_for_user(session.user_id).await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id, session_id = %session.id))]
    pub async fn log_out(&self, session: &Session) -> Result<()> {
        self.records
            .revoke_owned(session.user_id, session.id, Actor::of_session(session))
            .await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id, session_id = %session.id))]
    pub async fn log_out_everywhere(
        &self,
        session: &Session,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        self.revoke_others(session, reauth, context).await?;
        self.log_out(session).await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id, session_id = %target))]
    pub async fn revoke(
        &self,
        session: &Session,
        target: SessionId,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        if target == session.id {
            return self.log_out(session).await;
        }
        self.reauth
            .ensure(
                ReauthAction::RevokeSession,
                session,
                reauth.as_ref(),
                &context,
            )
            .await?;
        self.records
            .revoke_owned(session.user_id, target, Actor::of_session(session))
            .await?;
        if let Some(user) = self
            .users
            .find_for_notice(session.user_id, "other-session revoked")
            .await
        {
            self.notices.other_session_revoked(&user).await;
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id, session_id = %session.id))]
    pub async fn revoke_others(
        &self,
        session: &Session,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<u64> {
        self.reauth
            .ensure(
                ReauthAction::RevokeOtherSessions,
                session,
                reauth.as_ref(),
                &context,
            )
            .await?;
        let count = self
            .records
            .revoke_others(session, Actor::of_session(session))
            .await?;
        if count > 0
            && let Some(user) = self
                .users
                .find_for_notice(session.user_id, "other-sessions revoked")
                .await
        {
            self.notices.other_sessions_revoked(&user).await;
        }
        Ok(count)
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
    use crate::storage::UserId;

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
