use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;
use doorman_core::Error;
use doorman_core::clock::Clock;
use doorman_core::session::SessionContext;
use doorman_core::storage::{Session, User};

use crate::error::ErrorResponse;
use crate::session::AuthContext;

#[derive(Clone)]
pub struct AuthSession {
    pub session: Session,
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

    #[test]
    fn auth_session_cool_down_answers_through_injected_clock() {
        use chrono::{Duration, TimeZone, Utc};
        use doorman_core::storage::{Session, SessionId, UserId, UserStatus};
        use doorman_core::token::hash_token;
        use doorman_test_support::MockClock;

        let start = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let clock = Arc::new(MockClock::new(start));
        let cool_down_until = start + Duration::hours(24);

        let user = User {
            id: UserId::new(),
            email: Some("alice@example.com".into()),
            email_verified_at: Some(start),
            status: UserStatus::Active,
            created_at: start,
            updated_at: start,
        };
        let session = Session {
            id: SessionId::new(),
            user_id: user.id,
            token_hash: hash_token("cool-down-token"),
            created_at: start,
            last_used_at: start,
            expires_at: start + Duration::days(30),
            ip: None,
            user_agent: None,
            recovery_cool_down_until: Some(cool_down_until),
        };
        let auth = AuthSession {
            session,
            token: "cool-down-token".into(),
            clock: clock.clone(),
        };

        assert!(auth.is_in_recovery_cool_down());
        clock.advance(Duration::hours(24) + Duration::seconds(1));
        assert!(!auth.is_in_recovery_cool_down());
    }

    #[test]
    fn auth_session_debug_redacts_token() {
        use chrono::{Duration, TimeZone, Utc};
        use doorman_core::storage::{Session, SessionId, UserId, UserStatus};
        use doorman_core::token::hash_token;
        use doorman_test_support::MockClock;

        let start = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let user = User {
            id: UserId::new(),
            email: Some("alice@example.com".into()),
            email_verified_at: Some(start),
            status: UserStatus::Active,
            created_at: start,
            updated_at: start,
        };
        let session = Session {
            id: SessionId::new(),
            user_id: user.id,
            token_hash: hash_token("super-secret-bearer-token"),
            created_at: start,
            last_used_at: start,
            expires_at: start + Duration::days(30),
            ip: None,
            user_agent: None,
            recovery_cool_down_until: None,
        };
        let auth = AuthSession {
            session,
            token: "super-secret-bearer-token".into(),
            clock: Arc::new(MockClock::new(start)),
        };

        let rendered = format!("{auth:?}");
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "Debug output leaked the cleartext token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
        assert_eq!(auth.token, "super-secret-bearer-token");
    }
}
