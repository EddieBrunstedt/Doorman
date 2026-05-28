//! Mountable HTTP router.
//!
//! [`router`] is called by [`BauthAxum::router`](crate::BauthAxum::router)
//! to assemble the always-on passkey, signup, recovery, and session route
//! trees.

use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::config::CookieConfig;
use crate::cookies::session_cookie;
use crate::dto::AuthResponse;
use crate::state::BauthState;

pub(crate) mod passkey;
pub(crate) mod recovery;
pub(crate) mod sessions;
pub(crate) mod signup;

/// Build a JSON response that issues a session cookie alongside an
/// [`AuthResponse`] body. Shared by every route that issues a session.
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
    Router::new()
        .merge(passkey::routes())
        .merge(signup::routes())
        .merge(recovery::routes())
        .merge(sessions::routes())
        .with_state(state)
}
