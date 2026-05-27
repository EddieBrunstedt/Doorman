//! Mountable HTTP router.
//!
//! [`router`] is called by [`BauthAxum::router`](crate::BauthAxum::router)
//! to assemble the per-method route trees gated by the corresponding
//! feature flags and only when their backing manager has been supplied.

use axum::Router;

#[cfg(feature = "passkey")]
use axum::Json;
#[cfg(feature = "passkey")]
use axum::http::{StatusCode, header};
#[cfg(feature = "passkey")]
use axum::response::{IntoResponse, Response};

#[cfg(feature = "passkey")]
use crate::config::CookieConfig;
#[cfg(feature = "passkey")]
use crate::cookies::session_cookie;
#[cfg(feature = "passkey")]
use crate::dto::AuthResponse;
use crate::state::BauthState;

#[cfg(feature = "passkey")]
pub(crate) mod passkey;
pub(crate) mod sessions;
#[cfg(feature = "passkey")]
pub(crate) mod signup;

/// Build a JSON response that issues a session cookie alongside an
/// [`AuthResponse`] body. Shared by the passkey and signup routes.
#[cfg(feature = "passkey")]
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
    // `mut` is only needed when at least one auth-method feature is enabled.
    #[allow(unused_mut)]
    let mut router: Router<BauthState> = Router::new().merge(sessions::routes());

    #[cfg(feature = "passkey")]
    if state.passkey.is_some() {
        router = router.merge(passkey::routes());
    }

    #[cfg(feature = "passkey")]
    if state.signup.is_some() {
        router = router.merge(signup::routes());
    }

    router.with_state(state)
}
