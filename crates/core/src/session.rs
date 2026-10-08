use std::fmt;
use std::num::NonZeroU32;
use std::ops::Deref;
use std::time::Duration;

use chrono::{DateTime, Utc};

use webauthn_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::context::CoreDeps;
use crate::destructive::{CurrentSession, DestructiveAction, DestructiveActions};
use crate::error::Result;
use crate::passkey::PasskeyManager;
use crate::reauth::{ReauthManager, ReauthProof};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::session_records::SessionRecords;
use crate::storage::{
    PasskeyChallengeId, PasskeySummary, Session, SessionSummary, TokenHash, User,
};
pub use crate::token::hash_token;
use crate::user_records::UserRecords;

#[derive(Clone)]
pub struct IssuedSession {
    pub session: ResolvedSession,
    pub token: String,
    // No slide moves the absolute deadline, so a client may keep the token this long without
    // ever refreshing it; the server alone decides whether it idled out sooner.
    pub absolute_lifetime: Duration,
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedSession")
            .field("session", &self.session)
            .field("token", &"<redacted>")
            .field("absolute_lifetime", &self.absolute_lifetime)
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

// Only core builds one, so a method that takes it acts on a session core resolved or issued, with
// its real recovery cool-down, never on a row the caller made up. Its cool-down holds as of that
// moment, so a request needs no clock of its own.
#[derive(Debug, Clone)]
pub struct ResolvedSession {
    summary: SessionSummary,
    token_hash: TokenHash,
    in_recovery_cool_down: bool,
}

impl ResolvedSession {
    pub(crate) fn new(session: Session, now: DateTime<Utc>) -> Self {
        let token_hash = session.token_hash;
        let summary = SessionSummary::from(session);
        Self {
            in_recovery_cool_down: RecoveryCoolDown::of_session(&summary, now)
                != RecoveryCoolDown::NONE,
            summary,
            token_hash,
        }
    }

    pub fn is_in_recovery_cool_down(&self) -> bool {
        self.in_recovery_cool_down
    }

    pub(crate) fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }
}

impl Deref for ResolvedSession {
    type Target = SessionSummary;

    fn deref(&self) -> &SessionSummary {
        &self.summary
    }
}

#[derive(Clone)]
pub struct SessionManager {
    records: SessionRecords,
    users: UserRecords,
    passkey: PasskeyManager,
    reauth: ReauthManager,
    destructive: DestructiveActions,
}

impl SessionManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        passkey: PasskeyManager,
        reauth: ReauthManager,
        destructive: DestructiveActions,
    ) -> Self {
        Self {
            records: deps.sessions.clone(),
            users: UserRecords::new(deps),
            passkey,
            reauth,
            destructive,
        }
    }

    pub async fn resolve(&self, token: &str) -> Result<Option<ResolvedSession>> {
        self.records.resolve(token).await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id))]
    pub async fn find_user(&self, session: &ResolvedSession) -> Result<User> {
        self.users.find(session.user_id).await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id))]
    pub async fn list_sessions(&self, session: &ResolvedSession) -> Result<Vec<SessionSummary>> {
        self.records.list_summaries_for_user(session.user_id).await
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id, session_id = %session.id))]
    pub async fn log_out(&self, session: &ResolvedSession) -> Result<()> {
        self.records.log_out(session).await
    }

    pub async fn start_passkey_registration(
        &self,
        session: &ResolvedSession,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.passkey.start_registration(session).await
    }

    pub async fn finish_passkey_registration(
        &self,
        session: &ResolvedSession,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<PasskeySummary> {
        self.passkey
            .finish_registration(session, challenge_id, response, name, context)
            .await
    }

    pub async fn list_passkeys(&self, session: &ResolvedSession) -> Result<Vec<PasskeySummary>> {
        self.passkey.list_passkeys(session.user_id).await
    }

    pub async fn rename_passkey(
        &self,
        session: &ResolvedSession,
        credential_id: &[u8],
        name: Option<String>,
        context: SessionContext,
    ) -> Result<PasskeySummary> {
        self.passkey
            .rename_passkey(session, credential_id, name, context)
            .await
    }

    pub async fn start_reauth(
        &self,
        session: &ResolvedSession,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        self.reauth.start(session).await
    }

    pub async fn perform(
        &self,
        session: &ResolvedSession,
        action: DestructiveAction,
        proof: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<CurrentSession> {
        self.destructive
            .perform(session, action, proof, context)
            .await
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
    use crate::storage::{SessionId, UserId};

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
            session: ResolvedSession::new(session, now),
            token: "super-secret-bearer-token".to_string(),
            absolute_lifetime: DEFAULT_SESSION_LIFETIME,
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
