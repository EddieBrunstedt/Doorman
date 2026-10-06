use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use doorman_core::passkey::{RegistrationOutcome, StartedRegistration};
use doorman_core::reauth::ReauthProof;
use doorman_core::storage::PasskeyChallengeId;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::config::CookieConfig;
use crate::cookies::{clear_session_cookie, session_cookie};
use crate::dto::{AuthResponse, PasskeyChallenge, Reauthentication};
use crate::error::ErrorResponse;
use crate::state::AuthState;

pub(crate) mod passkey;
pub(crate) mod reauth;
pub(crate) mod recovery;
pub(crate) mod sessions;
pub(crate) mod signup;
pub(crate) mod user;

pub(crate) fn auth_success(
    status: StatusCode,
    cookie_config: &CookieConfig,
    body: AuthResponse,
) -> Result<Response, ErrorResponse> {
    let cookie = session_cookie(cookie_config, &body.token)?;
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

pub(crate) fn no_content_clearing_session_cookie(
    cookie_config: &CookieConfig,
) -> Result<Response, ErrorResponse> {
    let cookie = clear_session_cookie(cookie_config)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

pub(crate) fn parse_challenge_id(raw: &str) -> Result<PasskeyChallengeId, ErrorResponse> {
    Uuid::parse_str(raw)
        .map(PasskeyChallengeId)
        .map_err(|_| ErrorResponse(doorman_core::Error::InvalidPasskeyChallenge))
}

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

pub(crate) fn redeem_response(
    outcome: StartedRegistration,
) -> Json<PasskeyChallenge<CreationChallengeResponse>> {
    Json(PasskeyChallenge {
        challenge_id: outcome.challenge_id.0.to_string(),
        options: outcome.options,
    })
}

pub(crate) async fn registration_success(
    state: &AuthState,
    outcome: RegistrationOutcome,
) -> Result<Response, ErrorResponse> {
    let passkey_count = state.core.passkey.count_passkeys(outcome.user.id).await?;
    auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session, passkey_count),
    )
}

pub(crate) fn router(state: AuthState) -> Router {
    Router::new()
        .merge(passkey::routes())
        .merge(reauth::routes())
        .merge(signup::routes())
        .merge(recovery::routes())
        .merge(sessions::routes())
        .merge(user::routes())
        .with_state(state)
}
