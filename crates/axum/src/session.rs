//! Session-loading middleware and the resolved per-request `AuthContext`.
//!
//! The layer reads a session token from either the configured cookie or an
//! `Authorization: Bearer <token>` header, validates it through the
//! framework-agnostic [`SessionManager`], and — on success — attaches an
//! [`AuthContext`] to the request extensions. Extractors elsewhere in the
//! crate (`AuthUser`, `OptionalAuthUser`, `AuthSession`) read from that
//! extension instead of re-validating the session per handler.
//!
//! A token that is missing, malformed, or no longer valid never produces
//! a hard error from the layer itself: the request continues without an
//! [`AuthContext`], and protected handlers reject through their own
//! extractor (which returns 401). This keeps `OPTIONS` preflights, public
//! endpoints, and the login endpoints from being short-circuited.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, header};
use axum::response::Response;
use doorman_core::Error;
use doorman_core::clock::Clock;
use doorman_core::metrics::{MetricEvent, MetricSink};
use doorman_core::session::SessionManager;
use doorman_core::storage::{Session, User, UserStore};
use doorman_core::token::hash_token;
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

use crate::cache::SessionCache;
use crate::config::CookieConfig;
use crate::cookies::{bearer_token, read_cookie, session_cookie_with_max_age};
use crate::csrf::{self, CsrfConfig};
use crate::error::error_response;

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
    pub token: String,
    /// The clock the session manager reads time through, threaded so the
    /// [`AuthSession`](crate::extractors::AuthSession) recovery-cool-down
    /// helper answers through the configured clock rather than reading
    /// `chrono::Utc::now()` directly.
    pub(crate) clock: Arc<dyn Clock>,
}

/// Internal shared state for [`SessionLayer`] services.
pub(crate) struct SessionLayerState {
    pub(crate) session_manager: SessionManager,
    pub(crate) user_store: Arc<dyn UserStore>,
    /// Full cookie attribute set (name, Secure, SameSite, Path, …). Held so a
    /// sliding-renewal refresh can re-emit the session cookie with every
    /// attribute matching the one issued at login, only changing `Max-Age`.
    pub(crate) cookie: CookieConfig,
    pub(crate) cache: SessionCache,
    pub(crate) csrf: Option<CsrfConfig>,
    pub(crate) metrics: Arc<dyn MetricSink>,
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
                    return Ok(csrf::rejection_response());
                }

                // When sliding renewal refreshes a cookie-sourced session, hold
                // the `Set-Cookie` to append after the inner service runs so the
                // browser's expiry tracks the slid server deadline.
                let mut cookie_refresh: Option<axum::http::HeaderValue> = None;
                if let Some((token, source)) = extract_token(req.headers(), cookie_name) {
                    // Hash the token exactly once per request; both the cache
                    // lookup and the on-miss validate path are keyed by hash.
                    let token_hash = hash_token(&token);
                    let now = state.session_manager.clock().now();
                    // A cached entry whose effective deadline has passed is
                    // treated as a miss: the in-memory expiry re-check makes the
                    // cache self-correcting independent of its TTL, so an expired
                    // session is never served from a still-warm entry.
                    let cached = state
                        .cache
                        .get(&token_hash)
                        .filter(|cached| cached.session.expires_at > now);
                    // Cache hit short-circuits both the session lookup and the
                    // user-store fetch. On miss, fall through to the canonical
                    // validate path and seed the cache with the result.
                    if let Some(cached) = cached {
                        state.metrics.record(MetricEvent::CacheHit);
                        let span = tracing::Span::current();
                        span.record("session_id", tracing::field::display(cached.session.id));
                        span.record("user_id", tracing::field::display(cached.user.id));
                        req.extensions_mut().insert(AuthContext {
                            user: cached.user.clone(),
                            session: cached.session.clone(),
                            token,
                            clock: state.session_manager.clock().clone(),
                        });
                    } else {
                        // Miss: the cache did not serve this token, regardless
                        // of whether the fall-through validate then succeeds.
                        state.metrics.record(MetricEvent::CacheMiss);
                        if let Ok(session) =
                            state.session_manager.validate_by_hash(&token_hash).await
                            && let Ok(Some(user)) =
                                state.user_store.find_user_by_id(session.user_id).await
                        {
                            // Read-time disable gate. A disabled account is
                            // refused outright (403) rather than silently
                            // dropped to unauthenticated, so the host can tell
                            // "disabled" from "no session". The shared
                            // `AccountStatus::is_active` predicate is the single
                            // place the enum is interpreted. Rejecting here,
                            // before the cache insert below, also keeps a
                            // disabled user from ever entering the cache.
                            //
                            // Immediacy depends on the write-time cache
                            // invalidation wired in with the operator `disable`
                            // flow: a warm cache hit (the branch above) serves a
                            // still-active snapshot and can mask a fresh disable
                            // for up to the cache TTL until that invalidation
                            // evicts the entry.
                            if !user.status.is_active() {
                                return Ok(error_response(&Error::AccountDisabled));
                            }
                            let span = tracing::Span::current();
                            span.record("session_id", tracing::field::display(session.id));
                            span.record("user_id", tracing::field::display(user.id));
                            let session = Arc::new(session);
                            let user = Arc::new(user);
                            state
                                .cache
                                .insert(token_hash, session.clone(), user.clone());
                            // Slide the cookie only for cookie-sourced tokens and
                            // only when an idle window is configured. Bearer
                            // clients track expiry themselves, and with sliding
                            // off the cookie behaviour is byte-for-byte unchanged.
                            if source == TokenSource::Cookie
                                && state.session_manager.idle_timeout().is_some()
                            {
                                let remaining = (session.expires_at - now)
                                    .to_std()
                                    .unwrap_or(Duration::ZERO);
                                cookie_refresh = Some(session_cookie_with_max_age(
                                    &state.cookie,
                                    &token,
                                    remaining,
                                ));
                            }
                            req.extensions_mut().insert(AuthContext {
                                user,
                                session,
                                token,
                                clock: state.session_manager.clock().clone(),
                            });
                        }
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
