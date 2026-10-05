//! CSRF origin check.
//!
//! Cookie-backed sessions are ambient authority: a browser will attach the
//! session cookie to a cross-site form POST unless the application rejects
//! the request. [`AuthService::session_layer`](crate::AuthService::session_layer)
//! runs the simple, storage-free defence doorman recommends for Axum hosts
//! whenever a [`CsrfConfig`] enables it: state-changing requests that carry the
//! configured session cookie must present a same-origin `Origin` header, or
//! a same-origin `Referer` when `Origin` is absent. Requests authenticated
//! with `Authorization: Bearer ...` are not in CSRF scope.

use axum::http::{HeaderMap, Method, header};
use url::Url;

use crate::cookies::{bearer_token, read_cookie};

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

    // Origin is the stronger signal, so it wins when present: a matching
    // Origin allows, a mismatched one rejects.
    if let Some(matches) = header_origin_matches(headers, header::ORIGIN, expected_origin) {
        return !matches;
    }

    // Fall back to Referer only when Origin is absent (some same-origin
    // navigations omit Origin).
    if let Some(matches) = header_origin_matches(headers, header::REFERER, expected_origin) {
        return !matches;
    }

    // Fail closed: a state-changing cookie request that presents neither a
    // usable Origin nor Referer gives us no same-origin proof, so we must
    // reject rather than wave it through. Reaching here means a cookie session
    // is in play and the safe-method / bearer escape hatches did not apply.
    true
}

fn is_safe_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

/// Compare a URL-valued header (`Origin` or `Referer`) against the expected
/// origin. Returns `None` when the header is absent; a present-but-malformed
/// header returns `Some(false)` so callers fail closed instead of falling
/// through to a weaker signal.
fn header_origin_matches(
    headers: &HeaderMap,
    name: header::HeaderName,
    expected: &Url,
) -> Option<bool> {
    let raw = headers.get(name)?;
    Some(
        raw.to_str()
            .ok()
            .and_then(|value| Url::parse(value).ok())
            .map(|url| same_origin(&url, expected))
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
                HeaderValue::from_static("doorman_session=tok"),
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
            "doorman_session",
            &config()
        ));
    }

    #[test]
    fn cross_origin_post_with_cookie_is_rejected() {
        let headers = headers(true, Some("https://evil.test"), None);
        assert!(should_reject(
            &Method::POST,
            &headers,
            "doorman_session",
            &config()
        ));
    }

    #[test]
    fn referer_is_used_when_origin_is_absent() {
        let headers = headers(true, None, Some("https://app.test/account/settings"));
        assert!(!should_reject(
            &Method::DELETE,
            &headers,
            "doorman_session",
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
            "doorman_session",
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
            "doorman_session",
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
            "doorman_session",
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
            "doorman_session",
            &config()
        ));
    }

    #[test]
    fn safe_methods_are_allowed() {
        let headers = headers(true, Some("https://evil.test"), None);
        assert!(!should_reject(
            &Method::GET,
            &headers,
            "doorman_session",
            &config()
        ));
    }

    #[test]
    fn disabled_config_allows_everything() {
        let headers = headers(true, Some("https://evil.test"), None);
        assert!(!should_reject(
            &Method::POST,
            &headers,
            "doorman_session",
            &CsrfConfig::disabled()
        ));
    }
}
