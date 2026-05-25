//! Request extractors.
//!
//! All four play against the same per-request [`AuthContext`] (populated
//! by [`SessionLayer`](crate::session::SessionLayer)) and the request
//! headers; they never reach back into storage themselves.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;
use bauth_core::Error;
use bauth_core::session::SessionContext;
use bauth_core::storage::{Session, User};

use crate::error::ErrorResponse;
use crate::session::AuthContext;

/// Extractor that requires an authenticated user; rejects with `401
/// session_not_found` if none is attached. Use in handler signatures:
///
/// ```ignore
/// async fn me(AuthUser(user): AuthUser) -> Json<UserDto> { ... }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUser(pub User);

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthContext>() {
            Some(ctx) => Ok(AuthUser(ctx.user.clone())),
            None => Err(ErrorResponse(Error::SessionNotFound)),
        }
    }
}

/// Extractor that surfaces the user when present and `None` when not.
/// Never rejects.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<User>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalAuthUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalAuthUser(
            parts
                .extensions
                .get::<AuthContext>()
                .map(|ctx| ctx.user.clone()),
        ))
    }
}

/// Like [`AuthUser`] but also yields the underlying [`Session`] and the
/// raw bearer token. Useful for endpoints that need to revoke or rotate
/// the *current* session (e.g. logout).
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user: User,
    pub session: Session,
    pub token: String,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthContext>() {
            Some(ctx) => Ok(AuthSession {
                user: ctx.user.clone(),
                session: ctx.session.clone(),
                token: ctx.token.clone(),
            }),
            None => Err(ErrorResponse(Error::SessionNotFound)),
        }
    }
}

/// Extractor that builds a [`SessionContext`] from the request headers.
/// Walks `X-Forwarded-For` (first hop) → `X-Real-IP` for the client IP and
/// `User-Agent` for the UA. Never rejects.
#[derive(Debug, Clone)]
pub struct RequestContext(pub SessionContext);

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(RequestContext(session_context_from_headers(&parts.headers)))
    }
}

pub(crate) fn session_context_from_headers(headers: &HeaderMap) -> SessionContext {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        });
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .filter(|s| !s.is_empty());
    SessionContext { ip, user_agent }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn xff_takes_first_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 10.0.0.1"),
        );
        let ctx = session_context_from_headers(&headers);
        assert_eq!(ctx.ip.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn x_real_ip_used_when_no_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.7"));
        let ctx = session_context_from_headers(&headers);
        assert_eq!(ctx.ip.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn user_agent_is_captured() {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));
        let ctx = session_context_from_headers(&headers);
        assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert!(ctx.ip.is_none());
    }

    #[test]
    fn empty_headers_yield_empty_context() {
        let ctx = session_context_from_headers(&HeaderMap::new());
        assert!(ctx.ip.is_none());
        assert!(ctx.user_agent.is_none());
    }
}
