use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;
use doorman_core::Error;
use doorman_core::clock::Clock;
use doorman_core::session::{ResolvedSession, SessionContext};
use doorman_core::storage::User;

use crate::error::ErrorResponse;
use crate::session::AuthContext;

#[derive(Clone)]
pub struct AuthSession {
    pub session: ResolvedSession,
    pub token: String,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession")
            .field("session", &self.session)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AuthSession {
    pub fn is_in_recovery_cool_down(&self) -> bool {
        self.session.is_in_recovery_cool_down(self.clock.now())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthContext>() {
            Some(ctx) => Ok(AuthSession {
                session: ctx.session.clone(),
                token: ctx.token.clone(),
                clock: ctx.clock.clone(),
            }),
            None => Err(ErrorResponse(Error::SessionNotFound)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser(pub User);

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(ctx) = parts.extensions.get::<AuthContext>() else {
            return Err(ErrorResponse(Error::SessionNotFound));
        };
        Ok(AuthUser(ctx.sessions.find_user(&ctx.session).await?))
    }
}

#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<User>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalAuthUser {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(ctx) = parts.extensions.get::<AuthContext>() else {
            return Ok(OptionalAuthUser(None));
        };
        Ok(OptionalAuthUser(Some(
            ctx.sessions.find_user(&ctx.session).await?,
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

#[derive(Debug, Clone)]
pub struct RequestContext(pub SessionContext);

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ClientIp>()
            .map(|client| client.0)
            .or_else(|| {
                parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|peer| peer.0.ip())
            })
            .ok_or_else(|| {
                ErrorResponse(Error::Internal(
                    "client IP unavailable: serve with ConnectInfo<SocketAddr> or insert a trusted ClientIp extension"
                        .to_owned(),
                ))
            })?;
        let user_agent = parts
            .headers
            .get(USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned)
            .filter(|s| !s.is_empty());
        Ok(RequestContext(SessionContext {
            ip: Some(ip.to_canonical().to_string()),
            user_agent,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use doorman_core::assembly::AuthCore;
    use doorman_core::audit::NoopAuditSink;
    use doorman_core::email::TerminalEmailSender;
    use doorman_core::email_link::TOKEN_PLACEHOLDER;
    use doorman_core::memory::InMemoryStorage;
    use doorman_core::passkey::PasskeyConfig;
    use doorman_core::rate_limit::NoopRateLimiter;
    use doorman_core::reauth::ReauthPolicy;
    use doorman_core::recovery::RecoveryConfig;
    use doorman_core::signup::SignupConfig;
    use doorman_core::storage::{Session, SessionId, UserId};
    use doorman_core::token::hash_token;
    use doorman_core::user::UserConfig;
    use doorman_test_support::MockClock;

    fn start() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    async fn auth_session(
        token: &str,
        cool_down_until: Option<DateTime<Utc>>,
        clock: Arc<MockClock>,
    ) -> AuthSession {
        let storage = InMemoryStorage::new();
        let core = AuthCore::builder(storage.all_stores())
            .clock(clock.clone())
            .audit(Arc::new(NoopAuditSink))
            .email(Arc::new(TerminalEmailSender))
            .limiter(Arc::new(NoopRateLimiter))
            .passkey(PasskeyConfig::new(
                "localhost",
                "http://localhost".parse().expect("origin"),
                "doorman",
            ))
            .signup(SignupConfig {
                url_template: format!("http://localhost/signup?token={TOKEN_PLACEHOLDER}"),
                ..SignupConfig::default()
            })
            .recovery(RecoveryConfig {
                url_template: format!("http://localhost/recover?token={TOKEN_PLACEHOLDER}"),
                ..RecoveryConfig::default()
            })
            .user(UserConfig {
                url_template: format!("http://localhost/email?token={TOKEN_PLACEHOLDER}"),
                ..UserConfig::default()
            })
            .reauthentication(ReauthPolicy::disabled())
            .build()
            .expect("core assembles");
        let now = clock.now();
        storage
            .session_store()
            .create_session(Session {
                id: SessionId::new(),
                user_id: UserId::new(),
                token_hash: hash_token(token),
                created_at: now,
                last_used_at: now,
                expires_at: now + Duration::days(30),
                ip: None,
                user_agent: None,
                recovery_cool_down_until: cool_down_until,
            })
            .await
            .expect("store session");
        AuthSession {
            session: core.sessions.resolve(token).await.expect("resolve"),
            token: token.into(),
            clock,
        }
    }

    #[tokio::test]
    async fn auth_session_cool_down_answers_through_injected_clock() {
        let clock = Arc::new(MockClock::new(start()));
        let cool_down_until = start() + Duration::hours(24);
        let auth = auth_session("cool-down-token", Some(cool_down_until), clock.clone()).await;

        assert!(auth.is_in_recovery_cool_down());
        clock.advance(Duration::hours(24) + Duration::seconds(1));
        assert!(!auth.is_in_recovery_cool_down());
    }

    #[tokio::test]
    async fn auth_session_debug_redacts_token() {
        let clock = Arc::new(MockClock::new(start()));
        let auth = auth_session("super-secret-bearer-token", None, clock).await;

        let rendered = format!("{auth:?}");
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "Debug output leaked the cleartext token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
        assert_eq!(auth.token, "super-secret-bearer-token");
    }
}
