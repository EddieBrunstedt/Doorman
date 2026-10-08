use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use doorman_core::destructive::DestructiveAction;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use crate::dto::{
    DestructiveActionRequest, PasskeyAuthenticateFinishRequest, PasskeyChallenge, PasskeyDto,
    PasskeyRenameRequest, RegistrationFinishRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{auth_success, no_content, parse_challenge_id, perform};
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

async fn register_start(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let (id, options) = state
        .core
        .sessions
        .start_passkey_registration(&auth.session)
        .await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}

async fn register_finish(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Json(body): Json<RegistrationFinishRequest>,
) -> Result<Json<PasskeyDto>, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let passkey = state
        .core
        .sessions
        .finish_passkey_registration(
            &auth.session,
            challenge_id,
            &body.response,
            body.name,
            context,
        )
        .await?;
    Ok(Json(passkey.into()))
}

async fn authenticate_start(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
) -> Result<Json<PasskeyChallenge<RequestChallengeResponse>>, ErrorResponse> {
    let (id, options) = state.core.passkey.start_authentication(context).await?;
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
    let outcome = state
        .core
        .passkey
        .finish_authentication(challenge_id, &body.response, context)
        .await?;
    auth_success(
        &state,
        &outcome.user,
        outcome.passkey_count,
        outcome.session,
    )
}

async fn list(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<Vec<PasskeyDto>>, ErrorResponse> {
    let passkeys = state.core.sessions.list_passkeys(&auth.session).await?;
    Ok(Json(passkeys.into_iter().map(PasskeyDto::from).collect()))
}

async fn remove(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Path(credential_id): Path<String>,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<Response, ErrorResponse> {
    let credential_id = URL_SAFE_NO_PAD
        .decode(credential_id.as_bytes())
        .map_err(|_| ErrorResponse(doorman_core::Error::PasskeyNotFound))?;
    let reauth = body.and_then(|Json(b)| b.reauthentication);
    let action = DestructiveAction::RemovePasskey { credential_id };
    let current = perform(&state, &auth, action, reauth, context).await?;
    no_content(&state, current)
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
    let updated = state
        .core
        .sessions
        .rename_passkey(&auth.session, &bytes, body.name, context)
        .await?;
    Ok(Json(updated.into()))
}
