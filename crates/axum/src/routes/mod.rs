//! Mountable HTTP router.
//!
//! [`router`] is called by [`BauthAxum::router`](crate::BauthAxum::router)
//! to assemble the always-on passkey, signup, recovery, and session route
//! trees.

use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use bauth_core::storage::PasskeyChallengeId;
use bauth_core::verification::{EnrollmentOutcome, VerificationConsumeOutcome};
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::config::CookieConfig;
use crate::cookies::session_cookie;
use crate::dto::{AuthResponse, PasskeyChallenge};
use crate::error::ErrorResponse;
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

/// Parse a client-supplied challenge id string into a
/// [`PasskeyChallengeId`], mapping a malformed value to
/// [`Error::InvalidPasskeyChallenge`](bauth_core::Error::InvalidPasskeyChallenge).
/// Shared by every route that echoes a challenge id back at finish time.
pub(crate) fn parse_challenge_id(raw: &str) -> Result<PasskeyChallengeId, ErrorResponse> {
    Uuid::parse_str(raw)
        .map(PasskeyChallengeId)
        .map_err(|_| ErrorResponse(bauth_core::Error::InvalidPasskeyChallenge))
}

/// Build the challenge payload returned by the signup/recovery `consume`
/// step from a manager [`VerificationConsumeOutcome`]. Both enrollment
/// flows hand the same shape to `navigator.credentials.create`.
pub(crate) fn consume_response(
    outcome: VerificationConsumeOutcome,
) -> Json<PasskeyChallenge<CreationChallengeResponse>> {
    Json(PasskeyChallenge {
        challenge_id: outcome.challenge_id.0.to_string(),
        options: outcome.options,
    })
}

/// Turn a completed enrollment ([`EnrollmentOutcome`]) into a session-
/// issuing response. Shared by the signup/recovery `finish` steps, which
/// differ only in which manager produced the outcome.
pub(crate) async fn enrollment_success(
    state: &BauthState,
    outcome: EnrollmentOutcome,
) -> Result<Response, ErrorResponse> {
    let passkey_count = state.passkey.list_passkeys(outcome.user.id).await?.len();
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session, passkey_count),
    ))
}

pub(crate) fn router(state: BauthState) -> Router {
    Router::new()
        .merge(passkey::routes())
        .merge(signup::routes())
        .merge(recovery::routes())
        .merge(sessions::routes())
        .with_state(state)
}
