//! Cookie helpers shared by session-issuing flows.
//!
//! Kept small on purpose: we use the `cookie` crate for the heavy lifting
//! (parsing, attribute formatting) and only wrap the patterns the rest of
//! the crate needs — read by name, build a Set-Cookie value, build a
//! cleared-cookie value.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};
use cookie::time::OffsetDateTime;
use cookie::{Cookie, CookieBuilder};

use crate::config::CookieConfig;

/// Find the value of the cookie named `name` in the request headers.
/// Returns the first match; duplicate cookies of the same name are
/// pathological and we don't try to disambiguate them.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for raw in headers.get_all(header::COOKIE).iter() {
        let Ok(text) = raw.to_str() else { continue };
        // Borrow the header text: `split_parse` accepts `&str` and we only ever
        // return an owned copy of the matched value, so no allocation of the
        // whole header is needed per request.
        for piece in Cookie::split_parse(text).flatten() {
            if piece.name() == name {
                return Some(piece.value().to_owned());
            }
        }
    }
    None
}

/// Extract the token from an `Authorization: Bearer <token>` header.
///
/// Returns the trimmed token when the header is present, well-formed, and
/// carries a non-empty value; `None` otherwise. Shared by the session layer
/// (which decides *which* token to validate) and the CSRF layer (which
/// decides *whether* a request authenticates outside cookie scope) so the
/// two cannot disagree about what counts as a bearer request.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() { None } else { Some(token) }
}

/// Build a `Set-Cookie` header value for the session cookie.
pub fn session_cookie(config: &CookieConfig, value: &str) -> HeaderValue {
    encode(
        build_cookie(
            &config.session_cookie_name,
            value.to_owned(),
            config,
            Some(config.session_max_age),
        )
        .build(),
    )
}

/// Build a `Set-Cookie` header value for the session cookie with an explicit
/// `Max-Age`, rather than the configured default.
///
/// Used by the session layer when sliding renewal refreshes the cookie so the
/// browser's expiry tracks the server's effective deadline
/// (`session.expires_at - now`) instead of the fixed login `Max-Age`.
pub fn session_cookie_with_max_age(
    config: &CookieConfig,
    value: &str,
    max_age: Duration,
) -> HeaderValue {
    encode(
        build_cookie(
            &config.session_cookie_name,
            value.to_owned(),
            config,
            Some(max_age),
        )
        .build(),
    )
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn clear_session_cookie(config: &CookieConfig) -> HeaderValue {
    encode(clear_cookie(&config.session_cookie_name, config))
}

fn build_cookie<'a>(
    name: &'a str,
    value: String,
    config: &'a CookieConfig,
    max_age: Option<Duration>,
) -> CookieBuilder<'a> {
    let mut builder = Cookie::build((name.to_owned(), value))
        .path(config.path.clone())
        .http_only(true)
        .secure(config.secure)
        .same_site(config.same_site);
    if let Some(domain) = config.domain.as_deref() {
        builder = builder.domain(domain.to_owned());
    }
    if let Some(max_age) = max_age {
        let secs = max_age.as_secs().min(i64::MAX as u64) as i64;
        builder = builder.max_age(cookie::time::Duration::seconds(secs));
    }
    builder
}

fn clear_cookie(name: &str, config: &CookieConfig) -> Cookie<'static> {
    let mut builder = Cookie::build((name.to_owned(), String::new()))
        .path(config.path.clone())
        .http_only(true)
        .secure(config.secure)
        .same_site(config.same_site)
        .max_age(cookie::time::Duration::ZERO)
        .expires(OffsetDateTime::UNIX_EPOCH);
    if let Some(domain) = config.domain.as_deref() {
        builder = builder.domain(domain.to_owned());
    }
    builder.build()
}

fn encode(cookie: Cookie<'_>) -> HeaderValue {
    // `Display` on a cookie produces the exact `Set-Cookie` value (no
    // header name prefix). We pass it through HeaderValue::from_str which
    // validates ASCII / no CR-LF.
    HeaderValue::from_str(&cookie.to_string())
        .expect("cookie attributes only contain header-safe characters")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// `read_cookie` must never panic on an arbitrary `Cookie` header, no
        /// matter how malformed: it parses untrusted request input on every
        /// request, so it has to degrade to `None` rather than crash.
        #[test]
        fn read_cookie_never_panics(header in ".*", name in ".*") {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&header) {
                headers.insert(header::COOKIE, value);
            }
            // The contract is "does not panic"; the value is irrelevant here.
            let _ = read_cookie(&headers, &name);
        }

        /// A single, well-formed `name=value` pair round-trips: reading the
        /// cookie back by name yields the value. Restricted to the unreserved
        /// cookie-token/value characters so the pair needs no quoting and the
        /// `cookie` crate parses it verbatim.
        #[test]
        fn read_cookie_round_trips_simple_pair(
            name in "[A-Za-z0-9_]{1,16}",
            value in "[A-Za-z0-9_]{0,32}",
        ) {
            let mut headers = HeaderMap::new();
            let header = format!("{name}={value}");
            headers.insert(header::COOKIE, HeaderValue::from_str(&header).expect("ascii"));
            let read = read_cookie(&headers, &name);
            prop_assert_eq!(read.as_deref(), Some(value.as_str()));
        }

        /// `bearer_token` never panics on an arbitrary `Authorization` header.
        #[test]
        fn bearer_token_never_panics(header in ".*") {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&header) {
                headers.insert(header::AUTHORIZATION, value);
            }
            let _ = bearer_token(&headers);
        }

        /// A `Bearer <token>` header parses back to the token, trimmed of the
        /// surrounding whitespace `bearer_token` strips. The generated token
        /// itself contains no whitespace and is non-empty, so the trimmed
        /// result equals it exactly.
        #[test]
        fn bearer_token_round_trips_non_empty(token in "[A-Za-z0-9._~+/=-]{1,64}") {
            let mut headers = HeaderMap::new();
            let header = format!("Bearer {token}");
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&header).expect("ascii"),
            );
            prop_assert_eq!(bearer_token(&headers), Some(token.as_str()));
        }
    }

    fn cfg() -> CookieConfig {
        CookieConfig {
            secure: false,
            ..CookieConfig::default()
        }
    }

    fn secure_cfg() -> CookieConfig {
        CookieConfig {
            secure: true,
            ..CookieConfig::default()
        }
    }

    #[test]
    fn session_cookie_has_expected_attributes() {
        let value = session_cookie(&cfg(), "tok");
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session=tok"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Max-Age="));
        // `secure: false` must not emit the `Secure` attribute, so the flag is
        // genuinely driven by config rather than always-on.
        assert!(!s.contains("Secure"));
    }

    #[test]
    fn session_cookie_is_secure_when_configured() {
        let value = session_cookie(&secure_cfg(), "tok");
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session=tok"));
        assert!(s.contains("Secure"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("SameSite=Lax"));
    }

    #[test]
    fn clear_session_cookie_sets_zero_max_age() {
        let value = clear_session_cookie(&cfg());
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session="));
        assert!(s.contains("Max-Age=0"));
    }

    #[test]
    fn clear_session_cookie_is_secure_when_configured() {
        let value = clear_session_cookie(&secure_cfg());
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session="));
        assert!(s.contains("Max-Age=0"));
        assert!(s.contains("Secure"));
        assert!(s.contains("HttpOnly"));
    }

    #[test]
    fn read_cookie_finds_named_pair() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; doorman_session=tok-123; baz=qux"),
        );
        assert_eq!(
            read_cookie(&headers, "doorman_session").as_deref(),
            Some("tok-123")
        );
        assert_eq!(read_cookie(&headers, "missing"), None);
    }
}
