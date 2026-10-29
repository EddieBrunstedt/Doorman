use axum::http::HeaderMap;
use doorman_core::storage::SessionTransport;

use crate::cookies::{bearer_token, read_cookie};

pub(crate) struct SessionToken {
    pub(crate) token: String,
    pub(crate) transport: SessionTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AmbiguousSessionToken;

pub(crate) fn read(
    headers: &HeaderMap,
    cookie_name: &str,
    bearer_sessions: bool,
) -> Result<Option<SessionToken>, AmbiguousSessionToken> {
    let cookie = read_cookie(headers, cookie_name).filter(|value| !value.trim().is_empty());
    // Without bearer sessions doorman has no use for the header, so the host may use it freely.
    let bearer = bearer_token(headers)
        .filter(|_| bearer_sessions)
        .map(ToOwned::to_owned);
    match (cookie, bearer) {
        (Some(_), Some(_)) => Err(AmbiguousSessionToken),
        (Some(token), None) => Ok(Some(SessionToken {
            token,
            transport: SessionTransport::Cookie,
        })),
        (None, Some(token)) => Ok(Some(SessionToken {
            token,
            transport: SessionTransport::Bearer,
        })),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    fn headers(cookie: Option<&'static str>, bearer: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(cookie) = cookie {
            headers.insert(header::COOKIE, HeaderValue::from_static(cookie));
        }
        if let Some(bearer) = bearer {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(bearer));
        }
        headers
    }

    #[test]
    fn a_request_presents_at_most_one_session_token() {
        use SessionTransport::{Bearer, Cookie};
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
            (None, Some("Bearer b"), true, Ok(Some(("b", Bearer)))),
            (None, Some("Bearer  "), true, Ok(None)),
            (None, Some("Basic b"), true, Ok(None)),
            (None, Some("Bearer b"), false, Ok(None)),
            (Some("doorman_session=c"), Some("Bearer b"), true, ambiguous),
            (
                Some("doorman_session="),
                Some("Bearer b"),
                true,
                Ok(Some(("b", Bearer))),
            ),
            (
                Some("doorman_session=c"),
                Some("Bearer b"),
                false,
                Ok(Some(("c", Cookie))),
            ),
        ];

        for (cookie, bearer, bearer_sessions, expected) in cases {
            let read = read(&headers(cookie, bearer), "doorman_session", bearer_sessions);
            let read = read.map(|found| found.map(|c| (c.token, c.transport)));
            let expected = expected.map(|found| found.map(|(t, kind)| (t.to_owned(), kind)));
            assert_eq!(read, expected, "{cookie:?} {bearer:?} {bearer_sessions}");
        }
    }
}
