use axum::http::{HeaderMap, HeaderName, header};

pub(crate) const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

// Every browser names the origin of a state-changing request in one of these headers, and no page
// script can remove them, so a request with neither came from something other than a browser page.
pub(crate) fn sent_by_browser(headers: &HeaderMap) -> bool {
    headers.contains_key(SEC_FETCH_SITE) || headers.contains_key(header::ORIGIN)
}
