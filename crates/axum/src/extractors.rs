//! Request extractors.
//!
//! Authentication extractors read the per-request [`AuthContext`] populated
//! by [`SessionLayer`](crate::session::SessionLayer). [`RequestContext`] reads
//! trusted connection metadata and the user-agent header. None access storage.

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

/// Extractor that requires an authenticated user; rejects with `401
/// session_not_found` if none is attached. Use in handler signatures:
///
/// ```ignore
/// async fn me(AuthUser(user): AuthUser) -> Json<UserDto> { ... }
/// ```
///
/// The wrapped [`User`] is an [`Arc`] shared with the session cache, so
/// extracting it is a refcount bump, not a deep clone.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Arc<User>);

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
pub struct OptionalAuthUser(pub Option<Arc<User>>);

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
#[derive(Clone)]
pub struct AuthSession {
    /// The authenticated user.
    pub user: Arc<User>,
    /// The resolved session row.
    pub session: Arc<Session>,
    /// The plaintext token the request presented (for self-logout/revoke).
    pub token: String,
    /// The clock the session layer resolved this request through; the
    /// recovery-cool-down helper answers through it so a host's custom or
    /// mock clock is honoured rather than reading wall-clock time directly.
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Clock` is not `Debug`; omit it rather than require the bound.
        // `token` is a live bearer credential — redact it so it cannot leak
        // into logs via an accidental `?session`.
        f.debug_struct("AuthSession")
            .field("user", &self.user)
            .field("session", &self.session)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AuthSession {
    /// `true` if the underlying session is still within the post-recovery
    /// cool-down window, judged by the same clock the session layer resolved
    /// the request through. Handlers gate destructive actions on this and
    /// return [`doorman_core::Error::RecoveryCooldownActive`] when it holds.
    pub fn is_in_recovery_cooldown(&self) -> bool {
        self.session.is_in_recovery_cooldown(self.clock.now())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthContext>() {
            Some(ctx) => Ok(AuthSession {
                user: ctx.user.clone(),
                session: ctx.session.clone(),
                token: ctx.token.clone(),
                clock: ctx.clock.clone(),
            }),
            None => Err(ErrorResponse(Error::SessionNotFound)),
        }
    }
}

/// Client IP resolved by trusted host middleware and inserted into request
/// extensions before routing to doorman. Takes precedence over
/// [`ConnectInfo<SocketAddr>`], including when no socket metadata is available.
///
/// This is a host trust boundary, not a header extractor. Behind proxies, the
/// host must authenticate the immediate peer, resolve the forwarding chain
/// according to its deployment's trust policy, and parse the result as an
/// [`IpAddr`] before inserting this value. Never copy an unchecked client header
/// into this extension. Doorman does not interpret forwarding headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Extractor that builds a [`SessionContext`] with a trusted client IP.
///
/// Uses [`ClientIp`] from request extensions first, otherwise the socket IP
/// from [`ConnectInfo<SocketAddr>`]. Serve the router with
/// [`into_make_service_with_connect_info::<SocketAddr>()`](axum::Router::into_make_service_with_connect_info)
/// to supply socket metadata. Forwarding headers are always ignored. Addresses
/// are canonicalized, including converting IPv4-mapped IPv6 addresses to IPv4;
/// source ports never form part of the identity. `User-Agent` is untrusted metadata.
///
/// Rejects with `500 internal_error` if neither extension is present. This is a
/// server integration error, even when rate-limit policies are disabled: every
/// route using this extractor requires identity for consistent rate limits,
/// sessions, and audit events. Core managers accept optional IPs separately.
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
    fn auth_session_cooldown_answers_through_injected_clock() {
        use chrono::{Duration, TimeZone, Utc};
        use doorman_core::storage::{AccountStatus, Session, SessionId, UserId};
        use doorman_core::token::hash_token;
        use doorman_test_support::MockClock;

        let start = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let clock = Arc::new(MockClock::new(start));
        let cooldown_until = start + Duration::hours(24);

        let user = User {
            id: UserId::new(),
            email: Some("alice@example.com".into()),
            email_verified_at: Some(start),
            status: AccountStatus::Active,
            created_at: start,
            updated_at: start,
        };
        let session = Session {
            id: SessionId::new(),
            user_id: user.id,
            token_hash: hash_token("cooldown-token"),
            created_at: start,
            last_used_at: start,
            expires_at: start + Duration::days(30),
            ip: None,
            user_agent: None,
            recovery_cooldown_until: Some(cooldown_until),
        };
        let auth = AuthSession {
            user: Arc::new(user),
            session: Arc::new(session),
            token: "cooldown-token".into(),
            clock: clock.clone(),
        };

        // Active while the mock clock is before the deadline...
        assert!(auth.is_in_recovery_cooldown());
        // ...and the helper tracks the injected clock, not wall time: advance
        // past the deadline and it reports inactive.
        clock.advance(Duration::hours(24) + Duration::seconds(1));
        assert!(!auth.is_in_recovery_cooldown());
    }

    /// `AuthSession` carries the raw bearer token so self-logout can revoke
    /// the current session, but its `Debug` must redact it — an accidental
    /// `?session` in a handler log would otherwise leak a live credential.
    #[test]
    fn auth_session_debug_redacts_token() {
        use chrono::{Duration, TimeZone, Utc};
        use doorman_core::storage::{AccountStatus, Session, SessionId, UserId};
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
            status: AccountStatus::Active,
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
            recovery_cooldown_until: None,
        };
        let auth = AuthSession {
            user: Arc::new(user),
            session: Arc::new(session),
            token: "super-secret-bearer-token".into(),
            clock: Arc::new(MockClock::new(start)),
        };

        let rendered = format!("{auth:?}");
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "Debug output leaked the cleartext token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
        // The token is still readable through the public field for revoke.
        assert_eq!(auth.token, "super-secret-bearer-token");
    }
}
