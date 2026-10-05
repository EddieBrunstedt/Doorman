use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};
use cookie::time::OffsetDateTime;
use cookie::{Cookie, CookieBuilder};

use doorman_core::Error;

use crate::config::CookieConfig;

pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for raw in headers.get_all(header::COOKIE).iter() {
        let Ok(text) = raw.to_str() else { continue };
        for piece in Cookie::split_parse(text).flatten() {
            if piece.name() == name {
                return Some(piece.value().to_owned());
            }
        }
    }
    None
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() { None } else { Some(token) }
}

pub fn session_cookie(config: &CookieConfig, value: &str) -> Result<HeaderValue, Error> {
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

pub fn session_cookie_with_max_age(
    config: &CookieConfig,
    value: &str,
    max_age: Duration,
) -> Result<HeaderValue, Error> {
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

pub fn clear_session_cookie(config: &CookieConfig) -> Result<HeaderValue, Error> {
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

fn encode(cookie: Cookie<'_>) -> Result<HeaderValue, Error> {
    HeaderValue::from_str(&cookie.to_string())
        .map_err(|_| Error::Internal("cookie attributes are not header-safe".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn read_cookie_never_panics(header in ".*", name in ".*") {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&header) {
                headers.insert(header::COOKIE, value);
            }
            let _ = read_cookie(&headers, &name);
        }

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

        #[test]
        fn bearer_token_never_panics(header in ".*") {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&header) {
                headers.insert(header::AUTHORIZATION, value);
            }
            let _ = bearer_token(&headers);
        }

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
        let value = session_cookie(&cfg(), "tok").expect("encodes");
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session=tok"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Max-Age="));
        assert!(!s.contains("Secure"));
    }

    #[test]
    fn session_cookie_is_secure_when_configured() {
        let value = session_cookie(&secure_cfg(), "tok").expect("encodes");
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session=tok"));
        assert!(s.contains("Secure"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("SameSite=Lax"));
    }

    #[test]
    fn clear_session_cookie_sets_zero_max_age() {
        let value = clear_session_cookie(&cfg()).expect("encodes");
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session="));
        assert!(s.contains("Max-Age=0"));
    }

    #[test]
    fn clear_session_cookie_is_secure_when_configured() {
        let value = clear_session_cookie(&secure_cfg()).expect("encodes");
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
