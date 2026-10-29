use axum::http::HeaderMap;

use crate::cookies::read_cookie;
use crate::dpop::dpop_token;

// How a request's session token travels; which key a DPoP token is bound to is for core to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenTransport {
    Cookie,
    Dpop,
}

pub(crate) struct SessionToken {
    pub(crate) token: String,
    pub(crate) transport: TokenTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AmbiguousSessionToken;

pub(crate) fn read(
    headers: &HeaderMap,
    cookie_name: &str,
    dpop_sessions: bool,
) -> Result<Option<SessionToken>, AmbiguousSessionToken> {
    let cookie = read_cookie(headers, cookie_name).filter(|value| !value.trim().is_empty());
    // Without DPoP sessions doorman has no use for the header, so the host may use it freely.
    let dpop = dpop_token(headers)
        .filter(|_| dpop_sessions)
        .map(ToOwned::to_owned);
    match (cookie, dpop) {
        (Some(_), Some(_)) => Err(AmbiguousSessionToken),
        (Some(token), None) => Ok(Some(SessionToken {
            token,
            transport: TokenTransport::Cookie,
        })),
        (None, Some(token)) => Ok(Some(SessionToken {
            token,
            transport: TokenTransport::Dpop,
        })),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    fn headers(cookie: Option<&'static str>, dpop: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(cookie) = cookie {
            headers.insert(header::COOKIE, HeaderValue::from_static(cookie));
        }
        if let Some(dpop) = dpop {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(dpop));
        }
        headers
    }

    #[test]
    fn a_request_presents_at_most_one_session_token() {
        use TokenTransport::{Cookie, Dpop};
        let ambiguous = Err(AmbiguousSessionToken);
        let cases = [
            (None, None, true, Ok(None)),
            (
                Some("doorman_session=c"),
                None,
                true,
                Ok(Some(("c", Cookie))),
            ),
            (Some("doorman_session="), None, true, Ok(None)),
            (Some("other=c"), None, true, Ok(None)),
            (None, Some("DPoP d"), true, Ok(Some(("d", Dpop)))),
            (None, Some("DPoP  "), true, Ok(None)),
            (None, Some("Bearer d"), true, Ok(None)),
            (None, Some("DPoP d"), false, Ok(None)),
            (Some("doorman_session=c"), Some("DPoP d"), true, ambiguous),
            (
                Some("doorman_session="),
                Some("DPoP d"),
                true,
                Ok(Some(("d", Dpop))),
            ),
            (
                Some("doorman_session=c"),
                Some("DPoP d"),
                false,
                Ok(Some(("c", Cookie))),
            ),
        ];

        for (cookie, dpop, dpop_sessions, expected) in cases {
            let read = read(&headers(cookie, dpop), "doorman_session", dpop_sessions);
            let read = read.map(|found| found.map(|c| (c.token, c.transport)));
            let expected = expected.map(|found| found.map(|(t, kind)| (t.to_owned(), kind)));
            assert_eq!(read, expected, "{cookie:?} {dpop:?} {dpop_sessions}");
        }
    }
}
