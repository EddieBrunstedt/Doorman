//! Session-loading middleware and the resolved per-request `AuthContext`.
//!
//! The layer reads a session token from either the configured cookie or an
//! `Authorization: Bearer <token>` header, resolves it through the
//! framework-agnostic [`SessionResolver`], and — on success — attaches an
//! [`AuthContext`] to the request extensions. Extractors elsewhere in the
//! crate (`AuthUser`, `OptionalAuthUser`, `AuthSession`) read from that
//! extension instead of re-validating the session per handler.
//!
//! A token that is missing, malformed, or no longer valid never produces
//! a hard error from the layer itself: the request continues without an
//! [`AuthContext`], and protected handlers reject through their own
//! extractor (which returns 401). This keeps `OPTIONS` preflights, public
//! endpoints, and the login endpoints from being short-circuited. The one
//! exception is a disabled account, refused with 403.
//!
//! [`SessionResolver`]: doorman_core::resolve::SessionResolver

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, header};
use axum::response::Response;
use doorman_core::Error;
use doorman_core::clock::Clock;
use doorman_core::resolve::SessionResolver;
use doorman_core::storage::{Session, User};
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

use crate::config::CookieConfig;
use crate::cookies::{bearer_token, read_cookie, session_cookie_with_max_age};
use crate::csrf::{self, CsrfConfig};
use crate::error::{csrf_rejection_response, error_response};

/// Successfully resolved authentication state for a request.
///
/// Inserted as a request extension by [`SessionLayer`]; consumed by
/// [`AuthUser`](crate::extractors::AuthUser),
/// [`OptionalAuthUser`](crate::extractors::OptionalAuthUser), and
/// [`AuthSession`](crate::extractors::AuthSession).
#[derive(Clone)]
pub struct AuthContext {
    /// Shared with the session cache: on a cache hit this is the very
    /// `Arc<User>` the cache holds, so populating the context is a refcount
    /// bump rather than a deep clone.
    pub user: Arc<User>,
    /// Shared with the session cache; see [`AuthContext::user`].
    pub session: Arc<Session>,
    /// The raw bearer token, as it appeared in the request. Kept so
    /// `logout` (and any other "revoke this session" path) can call
    /// [`SessionManager::revoke`] without re-deriving it.
    ///
    /// [`SessionManager::revoke`]: doorman_core::session::SessionManager::revoke
    pub token: String,
    /// The clock sessions are resolved by, threaded so the
    /// [`AuthSession`](crate::extractors::AuthSession) recovery-cool-down
    /// helper answers through the configured clock rather than reading
    /// `chrono::Utc::now()` directly.
    pub(crate) clock: Arc<dyn Clock>,
}

/// Internal shared state for [`SessionLayer`] services.
pub(crate) struct SessionLayerState {
    pub(crate) resolver: SessionResolver,
    /// Full cookie attribute set (name, Secure, SameSite, Path, …). Held so a
    /// sliding-renewal refresh can re-emit the session cookie with every
    /// attribute matching the one issued at login, only changing `Max-Age`.
    pub(crate) cookie: CookieConfig,
    pub(crate) csrf: Option<CsrfConfig>,
}

/// Tower layer constructed via
/// [`AuthService::session_layer`](crate::AuthService::session_layer) and applied
/// once to the router that mounts the auth routes (and any application
/// routes that want `AuthUser` extraction to work).
#[derive(Clone)]
pub struct SessionLayer {
    state: Arc<SessionLayerState>,
}

impl SessionLayer {
    pub(crate) fn new(state: Arc<SessionLayerState>) -> Self {
        Self { state }
    }
}

/// Service produced by [`SessionLayer`] for a concrete inner service.
#[derive(Clone)]
pub struct SessionService<S> {
    inner: S,
    state: Arc<SessionLayerState>,
}

impl<S> Layer<S> for SessionLayer {
    type Service = SessionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SessionService {
            inner,
            state: self.state.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for SessionService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // tower contract: a Service must be `poll_ready`-ed before each
        // call, and the readiness belongs to the cloned instance — not the
        // one we leave behind for the next request. The std::mem::replace
        // pattern hands the ready instance to the future while installing
        // a fresh, not-yet-ready clone in `self`.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let state = self.state.clone();
        let span = tracing::info_span!(
            "doorman.session",
            session_id = tracing::field::Empty,
            user_id = tracing::field::Empty,
        );
        Box::pin(
            async move {
                let cookie_name = &state.cookie.session_cookie_name;
                if let Some(config) = state.csrf.as_ref()
                    && csrf::should_reject(req.method(), req.headers(), cookie_name, config)
                {
                    return Ok(csrf_rejection_response());
                }

                // When resolution slides a cookie-sourced session, hold the
                // `Set-Cookie` to append after the inner service runs so the
                // browser's expiry tracks the slid server deadline. Bearer
                // clients track expiry themselves.
                let mut cookie_refresh: Option<HeaderValue> = None;
                if let Some((token, source)) = extract_token(req.headers(), cookie_name) {
                    match state.resolver.resolve(&token).await {
                        Ok(resolved) => {
                            let span = tracing::Span::current();
                            span.record("session_id", tracing::field::display(resolved.session.id));
                            span.record("user_id", tracing::field::display(resolved.user.id));
                            if resolved.slid && source == TokenSource::Cookie {
                                let remaining = (resolved.session.expires_at
                                    - state.resolver.clock().now())
                                .to_std()
                                .unwrap_or(Duration::ZERO);
                                cookie_refresh = Some(session_cookie_with_max_age(
                                    &state.cookie,
                                    &token,
                                    remaining,
                                ));
                            }
                            req.extensions_mut().insert(AuthContext {
                                user: resolved.user,
                                session: resolved.session,
                                token,
                                clock: state.resolver.clock().clone(),
                            });
                        }
                        // A disabled account is refused outright (403) so the
                        // host can tell "disabled" from "no session".
                        Err(error @ Error::AccountDisabled) => {
                            return Ok(error_response(&error));
                        }
                        // Any other refusal leaves the request
                        // unauthenticated; protected extractors reject it.
                        Err(_) => {}
                    }
                }
                let mut response = inner.call(req).await?;
                if let Some(cookie) = cookie_refresh {
                    response.headers_mut().append(header::SET_COOKIE, cookie);
                }
                Ok(response)
            }
            .instrument(span),
        )
    }
}

/// Where a request's session token came from. The cookie is refreshed on a
/// slide only for [`Cookie`](TokenSource::Cookie)-sourced tokens; bearer
/// clients manage their own token lifetime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TokenSource {
    Cookie,
    Bearer,
}

/// Extract a session token (and its source) from the request. Bearer header
/// wins over the cookie when both are present — non-browser clients (mobile,
/// CLI) tend to use only the header and shouldn't be tripped up by a stale
/// cookie that happened to ride along.
pub(crate) fn extract_token(
    headers: &HeaderMap,
    cookie_name: &str,
) -> Option<(String, TokenSource)> {
    if let Some(token) = bearer_token(headers) {
        return Some((token.to_owned(), TokenSource::Bearer));
    }
    read_cookie(headers, cookie_name).map(|token| (token, TokenSource::Cookie))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    #[test]
    fn bearer_header_wins_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("doorman_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "doorman_session"),
            Some(("header-token".into(), TokenSource::Bearer))
        );
    }

    #[test]
    fn cookie_fallback_when_no_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("doorman_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "doorman_session"),
            Some(("cookie-token".into(), TokenSource::Cookie))
        );
    }

    #[test]
    fn no_token_returns_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_token(&headers, "doorman_session"), None);
    }

    #[test]
    fn bearer_without_value_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer  "));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("doorman_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "doorman_session"),
            Some(("cookie-token".into(), TokenSource::Cookie))
        );
    }
}
