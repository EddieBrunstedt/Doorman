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

use axum::body::Body;
use axum::http::{HeaderMap, Request, header};
use axum::response::Response;
use bauth_core::session::{SessionManager, hash_token};
use bauth_core::storage::{Session, User, UserStore};
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

use crate::cache::SessionCache;
use crate::cookies::read_cookie;
use crate::csrf::{self, CsrfConfig};

/// Successfully resolved authentication state for a request.
///
/// Inserted as a request extension by [`SessionLayer`]; consumed by
/// [`AuthUser`](crate::extractors::AuthUser),
/// [`OptionalAuthUser`](crate::extractors::OptionalAuthUser), and
/// [`AuthSession`](crate::extractors::AuthSession).
#[derive(Clone)]
pub struct AuthContext {
    pub user: User,
    pub session: Session,
    /// The raw bearer token, as it appeared in the request. Kept so
    /// `logout` (and any other "revoke this session" path) can call
    /// [`SessionManager::revoke`] without re-deriving it.
    pub token: String,
}

pub(crate) struct SessionLayerState {
    pub(crate) session_manager: SessionManager,
    pub(crate) user_store: Arc<dyn UserStore>,
    pub(crate) cookie_name: String,
    pub(crate) cache: SessionCache,
    pub(crate) csrf: Option<CsrfConfig>,
}

/// Tower layer constructed via
/// [`BauthAxum::session_layer`](crate::BauthAxum::session_layer) and applied
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
            "bauth.session",
            session_id = tracing::field::Empty,
            user_id = tracing::field::Empty,
        );
        Box::pin(
            async move {
                if let Some(config) = state.csrf.as_ref()
                    && csrf::should_reject(req.method(), req.headers(), &state.cookie_name, config)
                {
                    return Ok(csrf::rejection_response());
                }

                if let Some(token) = extract_token(req.headers(), &state.cookie_name) {
                    let token_hash = hash_token(&token);
                    // Cache hit short-circuits both the session lookup and the
                    // user-store fetch. On miss, fall through to the canonical
                    // validate path and seed the cache with the result.
                    if let Some(cached) = state.cache.get(&token_hash) {
                        let span = tracing::Span::current();
                        span.record("session_id", tracing::field::display(cached.session.id));
                        span.record("user_id", tracing::field::display(cached.user.id));
                        req.extensions_mut().insert(AuthContext {
                            user: cached.user,
                            session: cached.session,
                            token,
                        });
                    } else if let Ok(session) = state.session_manager.validate(&token).await
                        && let Ok(Some(user)) =
                            state.user_store.find_user_by_id(session.user_id).await
                    {
                        let span = tracing::Span::current();
                        span.record("session_id", tracing::field::display(session.id));
                        span.record("user_id", tracing::field::display(user.id));
                        state
                            .cache
                            .insert(token_hash, session.clone(), user.clone());
                        req.extensions_mut().insert(AuthContext {
                            user,
                            session,
                            token,
                        });
                    }
                }
                inner.call(req).await
            }
            .instrument(span),
        )
    }
}

/// Extract a session token from the request. Bearer header wins over the
/// cookie when both are present — non-browser clients (mobile, CLI) tend
/// to use only the header and shouldn't be tripped up by a stale cookie
/// that happened to ride along.
pub(crate) fn extract_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    if let Some(raw) = headers.get(header::AUTHORIZATION)
        && let Ok(value) = raw.to_str()
        && let Some(rest) = value.strip_prefix("Bearer ")
    {
        let trimmed = rest.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    read_cookie(headers, cookie_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_header_wins_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bauth_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "bauth_session"),
            Some("header-token".into())
        );
    }

    #[test]
    fn cookie_fallback_when_no_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bauth_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "bauth_session"),
            Some("cookie-token".into())
        );
    }

    #[test]
    fn no_token_returns_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_token(&headers, "bauth_session"), None);
    }

    #[test]
    fn bearer_without_value_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer  "));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bauth_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "bauth_session"),
            Some("cookie-token".into())
        );
    }
}
