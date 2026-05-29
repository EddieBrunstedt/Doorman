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
        for piece in Cookie::split_parse(text.to_owned()).flatten() {
            if piece.name() == name {
                return Some(piece.value().to_owned());
            }
        }
    }
    None
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

    fn cfg() -> CookieConfig {
        CookieConfig {
            secure: false,
            ..CookieConfig::default()
        }
    }

    #[test]
    fn session_cookie_has_expected_attributes() {
        let value = session_cookie(&cfg(), "tok");
        let s = value.to_str().unwrap();
        assert!(s.contains("bauth_session=tok"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Max-Age="));
    }

    #[test]
    fn clear_session_cookie_sets_zero_max_age() {
        let value = clear_session_cookie(&cfg());
        let s = value.to_str().unwrap();
        assert!(s.contains("bauth_session="));
        assert!(s.contains("Max-Age=0"));
    }

    #[test]
    fn read_cookie_finds_named_pair() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; bauth_session=tok-123; baz=qux"),
        );
        assert_eq!(
            read_cookie(&headers, "bauth_session").as_deref(),
            Some("tok-123")
        );
        assert_eq!(read_cookie(&headers, "missing"), None);
    }
}
