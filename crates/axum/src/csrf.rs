use axum::http::{HeaderMap, Method, header};
use url::Url;

use crate::cookies::{bearer_token, read_cookie};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfConfig {
    external_origin: Option<Url>,
}

impl CsrfConfig {
    pub fn new(external_origin: Url) -> Self {
        Self {
            external_origin: Some(external_origin),
        }
    }

    pub fn disabled() -> Self {
        Self {
            external_origin: None,
        }
    }

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

    if let Some(matches) = header_origin_matches(headers, header::ORIGIN, expected_origin) {
        return !matches;
    }

    if let Some(matches) = header_origin_matches(headers, header::REFERER, expected_origin) {
        return !matches;
    }

    true
}

fn is_safe_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

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
