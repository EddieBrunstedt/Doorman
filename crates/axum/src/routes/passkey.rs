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
use doorman_core::passkey::PasskeyManager;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use crate::dto::{
    AuthResponse, PasskeyAuthenticateFinishRequest, PasskeyChallenge, PasskeyDto,
    PasskeyRenameRequest, RegistrationFinishRequest, RemovePasskeyRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, AuthUser, RequestContext};
use crate::routes::{auth_success, parse_challenge_id, reauth_proof};
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
    &state.passkey
}

async fn register_start(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    // Core derives the active post-recovery cool-down from the session and
    // stamps it onto the ceremony, so a passkey enrolled during the lock-down
    // inherits the deadline rather than the route having to thread it through.
    let (id, options) = manager(&state)
        .start_registration_for_session(&auth.session)
        .await?;
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
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<PasskeyDto>>, ErrorResponse> {
    let creds = manager(&state).list_passkey_summaries(user.id).await?;
    Ok(Json(creds.into_iter().map(PasskeyDto::from).collect()))
}

async fn remove(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Path(credential_id): Path<String>,
    body: Option<Json<RemovePasskeyRequest>>,
) -> Result<StatusCode, ErrorResponse> {
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_id.as_bytes())
        .map_err(|_| ErrorResponse(doorman_core::Error::PasskeyNotFound))?;
    // The body is optional: the proof-less first attempt sends none. The
    // post-recovery cool-down and re-auth gates live in the manager, so they
    // hold for every host driving core — not just this route.
    let proof = reauth_proof(body.and_then(|Json(b)| b.reauthentication))?;
    manager(&state)
        .remove_passkey(&auth.session, &bytes, proof, context)
        .await?;
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
    // Relabelling is cosmetic, so the manager applies the ownership check but
    // no cool-down gate — see `PasskeyManager::rename_passkey`.
    let updated = manager(&state)
        .rename_passkey(&auth.session, &bytes, body.name, context)
        .await?;
    Ok(Json(updated.into()))
}
