use axum::http::{HeaderMap, HeaderName, header};

pub(crate) const DPOP: HeaderName = HeaderName::from_static("dpop");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnreadableProof;

// RFC 9449 gives a request one proof; with two, which one counts would be left to chance.
pub(crate) fn read_proof(headers: &HeaderMap) -> Result<Option<&str>, UnreadableProof> {
    let mut values = headers.get_all(DPOP).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(UnreadableProof);
    }
    match value.to_str().map(str::trim) {
        Ok(proof) if !proof.is_empty() => Ok(Some(proof)),
        _ => Err(UnreadableProof),
    }
}

pub(crate) fn dpop_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    // An authentication scheme is case-insensitive (RFC 9110 §11.1).
    if !scheme.eq_ignore_ascii_case("DPoP") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use proptest::prelude::*;

    fn headers(name: HeaderName, values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name.clone(), HeaderValue::from_static(value));
        }
        headers
    }

    proptest! {
        #[test]
        fn dpop_token_never_panics(header in ".*") {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&header) {
                headers.insert(header::AUTHORIZATION, value);
            }
            let _ = dpop_token(&headers);
        }

        #[test]
        fn dpop_token_round_trips_non_empty(token in "[A-Za-z0-9._~+/=-]{1,64}") {
            let mut headers = HeaderMap::new();
            let header = format!("DPoP {token}");
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&header).expect("ascii"),
            );
            prop_assert_eq!(dpop_token(&headers), Some(token.as_str()));
        }
    }

    #[test]
    fn only_the_dpop_scheme_carries_a_dpop_token() {
        let cases = [
            ("DPoP t", Some("t")),
            ("dpop t", Some("t")),
            ("DPoP  ", None),
            ("Bearer t", None),
            ("DPoPt", None),
        ];
        for (value, expected) in cases {
            let headers = headers(header::AUTHORIZATION, &[value]);
            assert_eq!(dpop_token(&headers), expected, "{value:?}");
        }
    }

    #[test]
    fn a_request_carries_at_most_one_proof() {
        let unreadable = Err(UnreadableProof);
        let cases = [
            (vec![], Ok(None)),
            (vec!["a.b.c"], Ok(Some("a.b.c"))),
            (vec![" "], unreadable),
            (vec!["a.b.c", "d.e.f"], unreadable),
        ];
        for (values, expected) in cases {
            assert_eq!(read_proof(&headers(DPOP, &values)), expected, "{values:?}");
        }
    }
}
