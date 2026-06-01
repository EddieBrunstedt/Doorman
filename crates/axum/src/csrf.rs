//! CSRF origin-check middleware.
//!
//! Cookie-backed sessions are ambient authority: a browser will attach the
//! session cookie to a cross-site form POST unless the application rejects
//! the request. [`CsrfLayer`] implements the simple, storage-free defence
//! bauth recommends for Axum hosts: state-changing requests that carry the
//! configured session cookie must present a same-origin `Origin` header, or
//! a same-origin `Referer` when `Origin` is absent. Requests authenticated
//! with `Authorization: Bearer ...` are not in CSRF scope.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Json;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tower_layer::Layer;
use tower_service::Service;
use url::Url;

use crate::cookies::{bearer_token, read_cookie};
use crate::error::{ErrorBody, ErrorPayload};

/// CSRF origin-check configuration.
///
/// `CsrfConfig::new(origin)` enables checks against the supplied public
/// application origin. `CsrfConfig::disabled()` is the explicit escape
/// hatch for tests and known non-browser deployments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfConfig {
    external_origin: Option<Url>,
}

impl CsrfConfig {
    /// Enable CSRF origin checks against the public application origin.
    /// Only the URL origin (scheme, host, and port) is compared; any path
    /// prefix on the URL is ignored.
    pub fn new(external_origin: Url) -> Self {
        Self {
            external_origin: Some(external_origin),
        }
    }

    /// Disable CSRF checks.
    pub fn disabled() -> Self {
        Self {
            external_origin: None,
        }
    }

    /// `true` when CSRF checks are enabled.
    pub fn is_enabled(&self) -> bool {
        self.external_origin.is_some()
    }

    pub(crate) fn enabled_config(self) -> Option<Self> {
        if self.is_enabled() { Some(self) } else { None }
    }

    fn external_origin(&self) -> Option<&Url> {
        self.external_origin.as_ref()
    }
}

/// Tower layer that rejects cross-site state-changing requests carrying a
/// bauth session cookie.
///
/// [`BauthAxum`](crate::BauthAxum) wires the same check into
/// [`session_layer`](crate::BauthAxum::session_layer) automatically when
/// an external origin is configured. Use this standalone layer only when
/// composing your own middleware stack.
#[derive(Clone)]
pub struct CsrfLayer {
    state: Arc<CsrfState>,
}

#[derive(Debug)]
struct CsrfState {
    config: CsrfConfig,
    session_cookie_name: String,
}

impl CsrfLayer {
    /// Construct a CSRF layer for the named session cookie.
    pub fn new(config: CsrfConfig, session_cookie_name: impl Into<String>) -> Self {
        Self {
            state: Arc::new(CsrfState {
                config,
                session_cookie_name: session_cookie_name.into(),
            }),
        }
    }
}

/// Service produced by [`CsrfLayer`] for a concrete inner service.
#[derive(Clone)]
pub struct CsrfService<S> {
    inner: S,
    state: Arc<CsrfState>,
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            state: self.state.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for CsrfService<S>
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

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if should_reject(
            req.method(),
            req.headers(),
            &self.state.session_cookie_name,
            &self.state.config,
        ) {
            return Box::pin(async { Ok(rejection_response()) });
        }

        // tower contract: hand the ready service instance to the future and
        // leave a fresh clone behind for the next request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { inner.call(req).await })
    }
}

pub(crate) fn should_reject(
    method: &Method,
    headers: &HeaderMap,
    session_cookie_name: &str,
    config: &CsrfConfig,
) -> bool {
    if is_safe_method(method) || bearer_token(headers).is_some() {
        return false;
    }

    let Some(expected_origin) = config.external_origin() else {
        return false;
    };

    let has_cookie_session = read_cookie(headers, session_cookie_name)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if !has_cookie_session {
        return false;
    }

    if let Some(matches) = origin_matches(headers, expected_origin) {
        return !matches;
    }

    if let Some(matches) = referer_matches(headers, expected_origin) {
        return !matches;
    }

    true
}

pub(crate) fn rejection_response() -> Response {
    let body = ErrorBody {
        error: ErrorPayload {
            code: "csrf_origin_mismatch",
            message: "CSRF origin check failed".to_string(),
        },
    };
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}

fn is_safe_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

/// Returns `None` when the header is absent. A present-but-malformed
/// header returns `Some(false)` so callers fail closed instead of falling
/// through to a weaker signal.
fn origin_matches(headers: &HeaderMap, expected: &Url) -> Option<bool> {
    let raw = headers.get(header::ORIGIN)?;
    Some(
        raw.to_str()
            .ok()
            .and_then(|value| Url::parse(value).ok())
            .map(|origin| same_origin(&origin, expected))
            .unwrap_or(false),
    )
}

/// Returns `None` when the header is absent. A present-but-malformed
/// header returns `Some(false)` so callers fail closed.
fn referer_matches(headers: &HeaderMap, expected: &Url) -> Option<bool> {
    let raw = headers.get(header::REFERER)?;
    Some(
        raw.to_str()
            .ok()
            .and_then(|value| Url::parse(value).ok())
            .map(|referer| same_origin(&referer, expected))
            .unwrap_or(false),
    )
}

fn same_origin(candidate: &Url, expected: &Url) -> bool {
    candidate.scheme() == expected.scheme()
        && candidate.host_str() == expected.host_str()
        && candidate.port_or_known_default() == expected.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn config() -> CsrfConfig {
        CsrfConfig::new(Url::parse("https://app.test/base").expect("valid url"))
    }

    fn headers(
        cookie: bool,
        origin: Option<&'static str>,
        referer: Option<&'static str>,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if cookie {
            headers.insert(
                header::COOKIE,
                HeaderValue::from_static("bauth_session=tok"),
            );
        }
        if let Some(origin) = origin {
            headers.insert(header::ORIGIN, HeaderValue::from_static(origin));
        }
        if let Some(referer) = referer {
            headers.insert(header::REFERER, HeaderValue::from_static(referer));
        }
        headers
    }

    #[test]
    fn same_origin_post_is_allowed() {
        let headers = headers(true, Some("https://app.test"), None);
        assert!(!should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn cross_origin_post_with_cookie_is_rejected() {
        let headers = headers(true, Some("https://evil.test"), None);
        assert!(should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn referer_is_used_when_origin_is_absent() {
        let headers = headers(true, None, Some("https://app.test/account/settings"));
        assert!(!should_reject(
            &Method::DELETE,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn origin_takes_precedence_over_referer() {
        let headers = headers(
            true,
            Some("https://evil.test"),
            Some("https://app.test/account/settings"),
        );
        assert!(should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn bearer_request_is_allowed_even_with_cookie() {
        let mut headers = headers(true, Some("https://evil.test"), None);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bearer-token"),
        );
        assert!(!should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn missing_origin_and_referer_with_cookie_is_rejected() {
        // Fail closed: a state-changing cookie request that presents neither
        // an Origin nor a Referer header gives the layer no same-origin
        // signal, so it must be rejected rather than waved through.
        let headers = headers(true, None, None);
        assert!(should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn missing_origin_and_referer_without_cookie_is_allowed() {
        // No cookie session means nothing for CSRF to protect.
        let headers = headers(false, None, None);
        assert!(!should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn safe_methods_are_allowed() {
        let headers = headers(true, Some("https://evil.test"), None);
        assert!(!should_reject(
            &Method::GET,
            &headers,
            "bauth_session",
            &config()
        ));
    }

    #[test]
    fn disabled_config_allows_everything() {
        let headers = headers(true, Some("https://evil.test"), None);
        assert!(!should_reject(
            &Method::POST,
            &headers,
            "bauth_session",
            &CsrfConfig::disabled()
        ));
    }
}
