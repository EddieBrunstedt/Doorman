//! Mountable HTTP router.
//!
//! [`router`] is called by [`BauthAxum::router`](crate::BauthAxum::router)
//! to assemble the per-method route trees gated by the corresponding
//! feature flags and only when their backing manager has been supplied.

use axum::Router;

#[cfg(any(feature = "password", feature = "passkey"))]
use axum::Json;
#[cfg(any(feature = "password", feature = "passkey"))]
use axum::http::{StatusCode, header};
#[cfg(any(feature = "password", feature = "passkey"))]
use axum::response::{IntoResponse, Response};

#[cfg(any(feature = "password", feature = "passkey"))]
use crate::config::CookieConfig;
#[cfg(any(feature = "password", feature = "passkey"))]
use crate::cookies::session_cookie;
#[cfg(any(feature = "password", feature = "passkey"))]
use crate::dto::AuthResponse;
use crate::state::BauthState;

#[cfg(feature = "oauth")]
pub(crate) mod oauth;
#[cfg(feature = "passkey")]
pub(crate) mod passkey;
#[cfg(feature = "password")]
pub(crate) mod password;

/// Build a JSON response that issues a session cookie alongside an
/// [`AuthResponse`] body. Shared by the password and passkey routes; the
/// OAuth callback uses cookies + a 303 redirect instead.
#[cfg(any(feature = "password", feature = "passkey"))]
pub(crate) fn auth_success(
    status: StatusCode,
    cookie_config: &CookieConfig,
    body: AuthResponse,
) -> Response {
    let cookie = session_cookie(cookie_config, &body.token);
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

pub(crate) fn router(state: BauthState) -> Router {
    #[allow(unused_mut)]
    let mut router: Router<BauthState> = Router::new();

    #[cfg(feature = "password")]
    if state.password.is_some() {
        router = router.merge(password::routes());
    }

    #[cfg(feature = "passkey")]
    if state.passkey.is_some() {
        router = router.merge(passkey::routes());
    }

    #[cfg(feature = "oauth")]
    if state.oauth.is_some() {
        router = router.merge(oauth::routes());
    }

    router.with_state(state)
}
