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

pub fn session_cookie(
    config: &CookieConfig,
    token: &str,
    max_age: Duration,
) -> Result<HeaderValue, Error> {
    encode(build_cookie(&config.name, token.to_owned(), config, Some(max_age)).build())
}

pub fn clear_session_cookie(config: &CookieConfig) -> Result<HeaderValue, Error> {
    encode(clear_cookie(&config.name, config))
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

        // `CookieConfig::build` is the only check a cookie's attributes get.
        #[test]
        fn a_config_that_builds_writes_a_cookie_a_header_can_carry(
            name in "(__Host-|__Secure-)?[!-~]{0,8}",
            path in proptest::option::of("/?[ -~]{0,12}"),
            domain in proptest::option::of("[a-z0-9.;-]{0,12}"),
            insecure in any::<bool>(),
            same_site in prop_oneof![
                Just(cookie::SameSite::Strict),
                Just(cookie::SameSite::Lax),
                Just(cookie::SameSite::None),
            ],
            token in "[A-Za-z0-9_-]{43}",
        ) {
            let mut builder = CookieConfig::builder(name).same_site(same_site);
            if let Some(path) = path {
                builder = builder.path(path);
            }
            if let Some(domain) = domain {
                builder = builder.domain(domain);
            }
            if insecure {
                builder = builder.insecure();
            }
            if let Ok(config) = builder.build() {
                let written = session_cookie(&config, &token, Duration::from_secs(60))
                    .expect("a session cookie encodes");
                let mut headers = HeaderMap::new();
                headers.insert(header::COOKIE, written);
                prop_assert!(read_cookie(&headers, config.name()).is_some());
                prop_assert!(clear_session_cookie(&config).is_ok());
            }
        }
    }

    fn cfg() -> CookieConfig {
        CookieConfig::builder(CookieConfig::DEFAULT_NAME)
            .insecure()
            .build()
            .expect("an unprefixed cookie may be insecure")
    }

    fn secure_cfg() -> CookieConfig {
        CookieConfig::default()
    }

    #[test]
    fn session_cookie_has_expected_attributes() {
        let value = session_cookie(&cfg(), "tok", Duration::from_secs(60)).expect("encodes");
        let s = value.to_str().expect("ascii header value");
        assert!(s.contains("doorman_session=tok"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Max-Age=60"));
        assert!(!s.contains("Secure"));
    }

    #[test]
    fn session_cookie_is_secure_when_configured() {
        let value = session_cookie(&secure_cfg(), "tok", Duration::from_secs(60)).expect("encodes");
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
