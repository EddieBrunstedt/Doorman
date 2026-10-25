use axum::http::{HeaderMap, HeaderName, Method, header};
use url::Url;

use crate::cookies::{bearer_token, read_cookie};

const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

#[derive(Debug, Clone)]
pub(crate) struct TrustedOrigins(Vec<Url>);

impl TrustedOrigins {
    pub(crate) fn new(origins: impl IntoIterator<Item = Url>) -> Self {
        Self(origins.into_iter().collect())
    }

    fn contains(&self, candidate: &Url) -> bool {
        self.0.iter().any(|trusted| same_origin(candidate, trusted))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    UntrustedOrigin,
    UnknownOrigin,
}

// Every state-changing request is checked, not only those carrying the session cookie: one
// that starts a session would otherwise let another site log the browser in as someone else.
pub(crate) fn check(
    method: &Method,
    headers: &HeaderMap,
    session_cookie_name: &str,
    trusted: &TrustedOrigins,
) -> Result<(), Refusal> {
    // A browser can attach a bearer token only by holding it, so it is no ambient credential.
    if is_safe_method(method) || bearer_token(headers).is_some() {
        return Ok(());
    }

    if let Some(site) = headers.get(SEC_FETCH_SITE) {
        if matches!(site.as_bytes(), b"same-origin" | b"none") {
            return Ok(());
        }
        return origin_is_trusted(headers, trusted);
    }

    if headers.contains_key(header::ORIGIN) {
        return origin_is_trusted(headers, trusted);
    }

    // Every browser names the request's origin in one of the headers above, so a request with
    // neither came from something other than a browser page, unless it carries the cookie.
    if has_session_cookie(headers, session_cookie_name) {
        return Err(Refusal::UnknownOrigin);
    }
    Ok(())
}

fn is_safe_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

fn origin_is_trusted(headers: &HeaderMap, trusted: &TrustedOrigins) -> Result<(), Refusal> {
    let Some(raw) = headers.get(header::ORIGIN) else {
        return Err(Refusal::UnknownOrigin);
    };
    let origin = raw.to_str().ok().and_then(|value| Url::parse(value).ok());
    match origin {
        Some(origin) if trusted.contains(&origin) => Ok(()),
        _ => Err(Refusal::UntrustedOrigin),
    }
}

fn has_session_cookie(headers: &HeaderMap, session_cookie_name: &str) -> bool {
    read_cookie(headers, session_cookie_name).is_some_and(|value| !value.trim().is_empty())
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

    const APP: &str = "https://app.test";
    const API_CLIENT: &str = "https://admin.app.test";
    const EVIL: &str = "https://evil.test";

    fn trusted() -> TrustedOrigins {
        TrustedOrigins::new([
            Url::parse("https://app.test/base").expect("valid url"),
            Url::parse(API_CLIENT).expect("valid url"),
        ])
    }

    #[derive(Debug, Clone, Copy)]
    enum Credential {
        Absent,
        Cookie,
        Bearer,
        Both,
    }

    #[derive(Debug)]
    struct Case {
        method: Method,
        credential: Credential,
        sec_fetch_site: Option<&'static str>,
        origin: Option<&'static str>,
        referer: Option<&'static str>,
        expected: Result<(), Refusal>,
    }

    fn case(
        credential: Credential,
        sec_fetch_site: Option<&'static str>,
        origin: Option<&'static str>,
        expected: Result<(), Refusal>,
    ) -> Case {
        Case {
            method: Method::POST,
            credential,
            sec_fetch_site,
            origin,
            referer: None,
            expected,
        }
    }

    fn headers(case: &Case) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if matches!(case.credential, Credential::Cookie | Credential::Both) {
            headers.insert(
                header::COOKIE,
                HeaderValue::from_static("doorman_session=tok"),
            );
        }
        if matches!(case.credential, Credential::Bearer | Credential::Both) {
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer bearer-token"),
            );
        }
        let named = [
            (SEC_FETCH_SITE, case.sec_fetch_site),
            (header::ORIGIN, case.origin),
            (header::REFERER, case.referer),
        ];
        for (name, value) in named {
            if let Some(value) = value {
                headers.insert(name, HeaderValue::from_static(value));
            }
        }
        headers
    }

    #[test]
    fn a_state_changing_request_must_come_from_the_application() {
        use Credential::*;
        let untrusted = Err(Refusal::UntrustedOrigin);
        let unknown = Err(Refusal::UnknownOrigin);
        let cases = [
            case(Cookie, Some("same-origin"), None, Ok(())),
            case(Cookie, Some("none"), None, Ok(())),
            case(Cookie, Some("same-site"), Some(API_CLIENT), Ok(())),
            case(Cookie, Some("cross-site"), Some(APP), Ok(())),
            case(Cookie, Some("cross-site"), Some(EVIL), untrusted),
            case(Cookie, Some("same-site"), None, unknown),
            case(Cookie, Some("same-site"), Some("null"), untrusted),
            case(Cookie, None, Some(APP), Ok(())),
            case(Cookie, None, Some("https://app.test:8443"), untrusted),
            case(Cookie, None, Some("http://app.test"), untrusted),
            case(Cookie, None, Some(EVIL), untrusted),
            case(Cookie, None, None, unknown),
            case(Absent, Some("same-origin"), None, Ok(())),
            case(Absent, Some("cross-site"), Some(EVIL), untrusted),
            case(Absent, Some("cross-site"), None, unknown),
            case(Absent, None, Some(EVIL), untrusted),
            case(Absent, None, None, Ok(())),
            case(Bearer, Some("cross-site"), Some(EVIL), Ok(())),
            case(Both, Some("cross-site"), Some(EVIL), Ok(())),
            Case {
                referer: Some("https://app.test/settings"),
                ..case(Cookie, None, None, unknown)
            },
            Case {
                method: Method::GET,
                ..case(Cookie, Some("cross-site"), Some(EVIL), Ok(()))
            },
            Case {
                method: Method::DELETE,
                ..case(Absent, Some("cross-site"), Some(EVIL), untrusted)
            },
        ];

        for case in cases {
            let result = check(&case.method, &headers(&case), "doorman_session", &trusted());
            assert_eq!(result, case.expected, "{case:?}");
        }
    }
}
