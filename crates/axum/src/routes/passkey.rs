use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use doorman_core::destructive::DestructiveAction;
use doorman_core::passkey::PasskeyManager;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use crate::dto::{
    AuthResponse, DestructiveActionRequest, PasskeyAuthenticateFinishRequest, PasskeyChallenge,
    PasskeyDto, PasskeyRenameRequest, RegistrationFinishRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{auth_success, parse_challenge_id, perform};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/passkey/register/start", post(register_start))
        .route("/passkey/register/finish", post(register_finish))
        .route("/passkey/authenticate/start", post(authenticate_start))
        .route("/passkey/authenticate/finish", post(authenticate_finish))
        .route("/passkey", get(list))
        .route("/passkey/{credential_id}", delete(remove).patch(rename))
}

fn manager(state: &AuthState) -> &PasskeyManager {
    &state.core.passkey
}

async fn register_start(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let (id, options) = manager(&state).start_registration(&auth.session).await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}

async fn register_finish(
    State(state): State<AuthState>,
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
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
) -> Result<Json<PasskeyChallenge<RequestChallengeResponse>>, ErrorResponse> {
    let (id, options) = manager(&state).start_authentication(context).await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}

async fn authenticate_finish(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<PasskeyAuthenticateFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let outcome = manager(&state)
        .finish_authentication(challenge_id, &body.response, context)
        .await?;
    let passkey_count = manager(&state).count_passkeys(outcome.user.id).await?;
    auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session, passkey_count),
    )
}

async fn list(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<Vec<PasskeyDto>>, ErrorResponse> {
    let passkeys = manager(&state)
        .list_passkey_summaries(auth.session.user_id)
        .await?;
    Ok(Json(passkeys.into_iter().map(PasskeyDto::from).collect()))
}

async fn remove(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Path(credential_id): Path<String>,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<StatusCode, ErrorResponse> {
    let credential_id = URL_SAFE_NO_PAD
        .decode(credential_id.as_bytes())
        .map_err(|_| ErrorResponse(doorman_core::Error::PasskeyNotFound))?;
    let reauth = body.and_then(|Json(b)| b.reauthentication);
    let action = DestructiveAction::RemovePasskey { credential_id };
    perform(&state, &auth, action, reauth, context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rename(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Path(credential_id): Path<String>,
    Json(body): Json<PasskeyRenameRequest>,
) -> Result<Json<PasskeyDto>, ErrorResponse> {
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_id.as_bytes())
        .map_err(|_| ErrorResponse(doorman_core::Error::PasskeyNotFound))?;
    let updated = manager(&state)
        .rename_passkey(&auth.session, &bytes, body.name, context)
        .await?;
    Ok(Json(updated.into()))
}
