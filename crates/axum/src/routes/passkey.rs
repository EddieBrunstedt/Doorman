//! Passkey (WebAuthn) HTTP routes.
//!
//! Mounted under `/auth/passkey` by [`crate::routes::router`].

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bauth_core::passkey::PasskeyManager;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use crate::dto::{
    AuthResponse, PasskeyAuthenticateFinishRequest, PasskeyChallenge, PasskeyDto,
    RegistrationFinishRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, AuthUser, RequestContext};
use crate::routes::{auth_success, parse_challenge_id};
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/passkey/register/start", post(register_start))
        .route("/passkey/register/finish", post(register_finish))
        .route("/passkey/authenticate/start", post(authenticate_start))
        .route("/passkey/authenticate/finish", post(authenticate_finish))
        .route("/passkey", get(list))
        .route("/passkey/{credential_id}", delete(remove))
}

fn manager(state: &BauthState) -> &PasskeyManager {
    &state.passkey
}

async fn register_start(
    State(state): State<BauthState>,
    auth: AuthSession,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let recovery_cooldown_until = state
        .session_manager
        .active_recovery_cooldown_until(&auth.session);
    let (id, options) = manager(&state)
        .start_registration_with_recovery_cooldown(auth.user.id, recovery_cooldown_until)
        .await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}

async fn register_finish(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RegistrationFinishRequest>,
) -> Result<Json<PasskeyDto>, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let stored = manager(&state)
        .finish_registration(challenge_id, &body.response, body.name, context)
        .await?;
    Ok(Json(stored.into()))
}

async fn authenticate_start(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
) -> Result<Json<PasskeyChallenge<RequestChallengeResponse>>, ErrorResponse> {
    let (id, options) = manager(&state).start_authentication(context).await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}

async fn authenticate_finish(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<PasskeyAuthenticateFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let issued = manager(&state)
        .finish_authentication(challenge_id, &body.response, context)
        .await?;
    let user = state
        .user_store
        .find_user_by_id(issued.session.user_id)
        .await
        .map_err(bauth_core::Error::from)?
        .ok_or(ErrorResponse(bauth_core::Error::UserNotFound))?;
    let passkey_count = manager(&state).list_passkey_summaries(user.id).await?.len();
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(user, issued, passkey_count),
    ))
}

async fn list(
    State(state): State<BauthState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<PasskeyDto>>, ErrorResponse> {
    let creds = manager(&state).list_passkey_summaries(user.id).await?;
    Ok(Json(creds.into_iter().map(PasskeyDto::from).collect()))
}

async fn remove(
    State(state): State<BauthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    if state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(bauth_core::Error::RecoveryCooldownActive));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_id.as_bytes())
        .map_err(|_| ErrorResponse(bauth_core::Error::PasskeyNotFound))?;
    manager(&state)
        .remove_passkey(auth.user.id, &bytes, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
