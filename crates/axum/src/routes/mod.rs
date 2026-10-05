//! Mountable HTTP router.
//!
//! [`router`] is called by [`AuthService::router`](crate::AuthService::router)
//! to assemble the always-on passkey, signup, recovery, session, and account
//! route trees.

use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use doorman_core::reauth::ReauthProof;
use doorman_core::storage::PasskeyChallengeId;
use doorman_core::verification::{EnrollmentOutcome, VerificationConsumeOutcome};
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::config::CookieConfig;
use crate::cookies::{clear_session_cookie, session_cookie};
use crate::dto::{AuthResponse, PasskeyChallenge, Reauthentication};
use crate::error::ErrorResponse;
use crate::state::AuthState;

pub(crate) mod account;
pub(crate) mod passkey;
pub(crate) mod reauth;
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

/// Build a `204 No Content` response that clears the session cookie, so the
/// browser stops replaying a token the server just invalidated. Shared by
/// logout, logout-all, and account deletion.
pub(crate) fn no_content_clearing_session_cookie(cookie_config: &CookieConfig) -> Response {
    let cookie = clear_session_cookie(cookie_config);
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

/// Parse a client-supplied challenge id string into a
/// [`PasskeyChallengeId`], mapping a malformed value to
/// [`Error::InvalidPasskeyChallenge`](doorman_core::Error::InvalidPasskeyChallenge).
/// Shared by every route that echoes a challenge id back at finish time.
pub(crate) fn parse_challenge_id(raw: &str) -> Result<PasskeyChallengeId, ErrorResponse> {
    Uuid::parse_str(raw)
        .map(PasskeyChallengeId)
        .map_err(|_| ErrorResponse(doorman_core::Error::InvalidPasskeyChallenge))
}

/// Convert an optional wire [`Reauthentication`] into the core
/// [`ReauthProof`], parsing (and validating) the challenge id. Shared by every
/// destructive route that threads a proof into its core call; `None` stays
/// `None` so the manager's policy decides whether the absence is an error.
pub(crate) fn reauth_proof(
    reauth: Option<Reauthentication>,
) -> Result<Option<ReauthProof>, ErrorResponse> {
    reauth
        .map(|r| {
            Ok(ReauthProof {
                challenge_id: parse_challenge_id(&r.challenge_id)?,
                assertion: r.assertion,
            })
        })
        .transpose()
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
    state: &AuthState,
    outcome: EnrollmentOutcome,
) -> Result<Response, ErrorResponse> {
    let passkey_count = state.passkey.count_passkeys(outcome.user.id).await?;
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session, passkey_count),
    ))
}

pub(crate) fn router(state: AuthState) -> Router {
    Router::new()
        .merge(passkey::routes())
        .merge(reauth::routes())
        .merge(signup::routes())
        .merge(recovery::routes())
        .merge(sessions::routes())
        .merge(account::routes())
        .with_state(state)
}
