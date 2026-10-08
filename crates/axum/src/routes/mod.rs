use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use doorman_core::destructive::DestructiveAction;
use doorman_core::passkey::{RegistrationOutcome, StartedRegistration};
use doorman_core::reauth::ReauthProof;
use doorman_core::session::{IssuedSession, SessionContext};
use doorman_core::storage::{PasskeyChallengeId, User};
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::config::CookieConfig;
use crate::cookies::{clear_session_cookie, session_cookie};
use crate::dto::{AuthResponse, PasskeyChallenge, Reauthentication};
use crate::error::ErrorResponse;
use crate::extractors::AuthSession;
use crate::state::AuthState;

pub(crate) mod passkey;
pub(crate) mod reauth;
pub(crate) mod recovery;
pub(crate) mod sessions;
pub(crate) mod signup;
pub(crate) mod user;

pub(crate) fn auth_success(
    cookie_config: &CookieConfig,
    user: &User,
    passkey_count: u64,
    issued: IssuedSession,
) -> Result<Response, ErrorResponse> {
    let max_age = issued.session.remaining_lifetime();
    let cookie = session_cookie(cookie_config, &issued.token, max_age)?;
    let body = AuthResponse::from_issued(user, passkey_count, issued);
    let mut response = Json(body).into_response();
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

impl TryFrom<Reauthentication> for ReauthProof {
    type Error = ErrorResponse;

    fn try_from(reauth: Reauthentication) -> Result<Self, ErrorResponse> {
        Ok(ReauthProof {
            challenge_id: parse_challenge_id(&reauth.challenge_id)?,
            assertion: reauth.assertion,
        })
    }
}

pub(crate) async fn perform(
    state: &AuthState,
    auth: &AuthSession,
    action: DestructiveAction,
    reauth: Option<Reauthentication>,
    context: SessionContext,
) -> Result<(), ErrorResponse> {
    let proof = reauth.map(ReauthProof::try_from).transpose()?;
    state
        .core
        .destructive_actions
        .perform(&auth.session, action, proof, context)
        .await?;
    Ok(())
}

pub(crate) fn redeem_response(
    outcome: StartedRegistration,
) -> Json<PasskeyChallenge<CreationChallengeResponse>> {
    Json(PasskeyChallenge {
        challenge_id: outcome.challenge_id.0.to_string(),
        options: outcome.options,
    })
}

pub(crate) fn registration_success(
    state: &AuthState,
    outcome: RegistrationOutcome,
) -> Result<Response, ErrorResponse> {
    auth_success(
        state.cookie_config(),
        &outcome.user,
        outcome.passkey_count,
        outcome.session,
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
