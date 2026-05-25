//! OAuth HTTP routes.
//!
//! Mounted under `/auth/oauth` by [`crate::routes::router`] only when an
//! [`OAuthManager`] was supplied to the builder.
//!
//! Flow:
//!
//! 1. The frontend navigates the browser to
//!    `GET /auth/oauth/{provider}/start?return_to=/somewhere`.
//! 2. We mint a CSRF state via [`OAuthManager::start_authorization`],
//!    write a short-lived `bauth_oauth_state` cookie containing the
//!    state value and the host-supplied `return_to`, and respond with a
//!    `303 See Other` pointing at the provider's consent URL.
//! 3. The provider redirects back to the callback URL we registered with
//!    them — `/auth/oauth/{provider}/callback?code=…&state=…`.
//! 4. We read the cookie, verify the round-tripped state matches it,
//!    exchange the code via [`OAuthManager::finish_authorization`], set
//!    the session cookie, clear the OAuth state cookie, and redirect the
//!    browser to `return_to` (or `/` if it was missing).
//! 5. On any failure during step 4, we redirect to `return_to` with a
//!    `?bauth_error=<code>` query parameter so the host frontend can
//!    surface it; the URL shape is intentionally minimal because the
//!    plan keeps post-OAuth UX out of scope.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bauth_core::oauth::OAuthManager;
use bauth_core::storage::OAuthStateId;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use url::Url;

use crate::config::CookieConfig;
use crate::cookies::{clear_oauth_state_cookie, oauth_state_cookie, read_cookie, session_cookie};
use crate::dto::OAuthIdentityDto;
use crate::error::ErrorResponse;
use crate::extractors::{AuthUser, OptionalAuthUser, RequestContext};
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/oauth/{provider}/start", get(start))
        .route("/oauth/{provider}/callback", get(callback))
        .route("/oauth", get(list))
        .route("/oauth/{provider}/{subject}", delete(unlink))
}

fn manager(state: &BauthState) -> &OAuthManager {
    state
        .oauth
        .as_ref()
        .expect("oauth manager missing but oauth routes were mounted")
}

#[derive(Debug, Deserialize)]
struct StartQuery {
    /// Where the browser should land after a successful callback. Must be
    /// a same-origin path beginning with `/`; rejected otherwise to avoid
    /// turning this endpoint into an open redirect.
    #[serde(default)]
    return_to: Option<String>,
}

async fn start(
    State(state): State<BauthState>,
    Path(provider): Path<String>,
    Query(query): Query<StartQuery>,
    OptionalAuthUser(current_user): OptionalAuthUser,
) -> Result<Response, ErrorResponse> {
    let external_origin = state
        .external_origin
        .as_ref()
        .expect("oauth routes mounted without an external_origin configured");
    let redirect_uri = callback_uri(external_origin, &provider);
    let started = manager(&state)
        .start_authorization(
            &provider,
            redirect_uri.as_str(),
            current_user.as_ref().map(|u| u.id),
        )
        .await?;

    let return_to = sanitize_return_to(query.return_to.as_deref());
    let cookie_value = encode_state_cookie(&started.state.0, &return_to);

    let mut response = redirect(started.authorize_url.as_str());
    response.headers_mut().insert(
        header::SET_COOKIE,
        oauth_state_cookie(state.cookie_config(), &cookie_value),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    /// Provider-side error (e.g. user denied consent). Forwarded to the
    /// frontend as `?bauth_error=<code>`.
    error: Option<String>,
}

async fn callback(
    State(state): State<BauthState>,
    Path(_provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    RequestContext(context): RequestContext,
    headers: HeaderMap,
) -> Response {
    // The provider in the URL is informational; the authoritative provider
    // name lives in the PendingOAuthAuthorization the state cookie points
    // at. Skipping the cross-check keeps the redirect URI generation in
    // `start` the only place that path segment matters.
    let cookie_config = state.cookie_config();
    let cookie_value = read_cookie(&headers, &cookie_config.oauth_state_cookie_name);
    let Some((cookie_state, return_to)) = cookie_value.as_deref().and_then(decode_state_cookie)
    else {
        return failure_redirect(cookie_config, "/", "invalid_oauth_state");
    };

    if let Some(err) = query.error.as_deref() {
        return failure_redirect(cookie_config, &return_to, err);
    }

    let (Some(code), Some(query_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return failure_redirect(cookie_config, &return_to, "invalid_oauth_state");
    };

    if !constant_time_eq(query_state, &cookie_state) {
        return failure_redirect(cookie_config, &return_to, "invalid_oauth_state");
    }

    let outcome = match manager(&state)
        .finish_authorization(&OAuthStateId(cookie_state), code, context)
        .await
    {
        Ok(o) => o,
        Err(err) => {
            let code = error_code(&err);
            return failure_redirect(cookie_config, &return_to, code);
        }
    };

    let mut response = redirect(&return_to);
    let h = response.headers_mut();
    h.append(
        header::SET_COOKIE,
        session_cookie(cookie_config, &outcome.session.token),
    );
    h.append(header::SET_COOKIE, clear_oauth_state_cookie(cookie_config));
    response
}

async fn list(
    State(state): State<BauthState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<OAuthIdentityDto>>, ErrorResponse> {
    let identities = manager(&state).list_identities(user.id).await?;
    Ok(Json(
        identities.into_iter().map(OAuthIdentityDto::from).collect(),
    ))
}

async fn unlink(
    State(state): State<BauthState>,
    AuthUser(user): AuthUser,
    RequestContext(context): RequestContext,
    Path((provider, subject)): Path<(String, String)>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .unlink(user.id, &provider, &subject, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn callback_uri(origin: &Url, provider: &str) -> Url {
    let mut url = origin.clone();
    let base_path = url.path().trim_end_matches('/').to_owned();
    let new_path = format!("{base_path}/auth/oauth/{provider}/callback");
    url.set_path(&new_path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn sanitize_return_to(input: Option<&str>) -> String {
    match input {
        Some(s) if is_safe_return_to(s) => s.to_owned(),
        _ => "/".to_owned(),
    }
}

/// Same-origin relative path only. Reject schemes, authority components,
/// and protocol-relative `//host` forms.
fn is_safe_return_to(input: &str) -> bool {
    if !input.starts_with('/') {
        return false;
    }
    if input.starts_with("//") {
        return false;
    }
    if input.contains('\\') {
        return false;
    }
    true
}

fn encode_state_cookie(state: &str, return_to: &str) -> String {
    let encoded_return = URL_SAFE_NO_PAD.encode(return_to.as_bytes());
    format!("{state}.{encoded_return}")
}

fn decode_state_cookie(raw: &str) -> Option<(String, String)> {
    let (state, encoded) = raw.split_once('.')?;
    if state.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()?;
    let return_to = String::from_utf8(bytes).ok()?;
    Some((state.to_owned(), return_to))
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or(HeaderValue::from_static("/")),
    );
    response
}

fn failure_redirect(cookie_config: &CookieConfig, return_to: &str, code: &str) -> Response {
    let location = append_query(return_to, "bauth_error", code);
    let mut response = redirect(&location);
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_oauth_state_cookie(cookie_config));
    response
}

fn append_query(url: &str, key: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{}={}", urlencode(key), urlencode(value))
}

fn urlencode(input: &str) -> String {
    // Minimal application/x-www-form-urlencoded encoder for the small set
    // of bytes we ever pass (alphanumeric error codes and the param name).
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn error_code(err: &bauth_core::Error) -> &'static str {
    use bauth_core::Error::*;
    match err {
        InvalidOAuthState => "invalid_oauth_state",
        OAuthProvider(_) => "oauth_provider_error",
        OAuthProviderNotConfigured(_) => "oauth_provider_not_configured",
        OAuthIdentityAlreadyLinked => "oauth_identity_already_linked",
        OAuthEmailTaken => "oauth_email_taken",
        OAuthEmailMissing => "oauth_email_missing",
        RateLimited { .. } => "rate_limited",
        _ => "internal_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_must_be_relative_path() {
        assert!(is_safe_return_to("/dashboard"));
        assert!(is_safe_return_to("/a/b?x=1&y=2"));
        assert!(!is_safe_return_to("dashboard"));
        assert!(!is_safe_return_to("//evil.example.com"));
        assert!(!is_safe_return_to("https://evil.example.com/"));
        assert!(!is_safe_return_to("/x\\y"));
    }

    #[test]
    fn state_cookie_round_trips() {
        let raw = encode_state_cookie("opaque_state_token", "/dashboard?ok=1");
        let (state, ret) = decode_state_cookie(&raw).unwrap();
        assert_eq!(state, "opaque_state_token");
        assert_eq!(ret, "/dashboard?ok=1");
    }

    #[test]
    fn callback_uri_appends_path() {
        let origin = Url::parse("https://app.test").unwrap();
        let uri = callback_uri(&origin, "google");
        assert_eq!(uri.as_str(), "https://app.test/auth/oauth/google/callback");
    }

    #[test]
    fn callback_uri_preserves_origin_path_prefix() {
        let origin = Url::parse("https://app.test/api").unwrap();
        let uri = callback_uri(&origin, "github");
        assert_eq!(
            uri.as_str(),
            "https://app.test/api/auth/oauth/github/callback"
        );
    }

    #[test]
    fn append_query_handles_existing_query() {
        assert_eq!(append_query("/x", "k", "v"), "/x?k=v");
        assert_eq!(append_query("/x?a=1", "k", "v"), "/x?a=1&k=v");
    }
}
