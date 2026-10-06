use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use doorman_core::recovery::RecoveryManager;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::dto::{
    PasskeyChallenge, RecoveryConsumeRequest, RecoveryRequest, RegistrationFinishRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::{consume_response, parse_challenge_id, registration_success};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/recovery/request", post(request))
        .route("/recovery/consume", post(consume))
        .route("/recovery/finish", post(finish))
}

fn manager(state: &AuthState) -> &RecoveryManager {
    &state.core.recovery
}

async fn request(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .request_recovery(&body.email, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn consume(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryConsumeRequest>,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let outcome = manager(&state)
        .consume_recovery(&body.token, context)
        .await?;
    Ok(consume_response(outcome))
}

async fn finish(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RegistrationFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let outcome = manager(&state)
        .finish_recovery(challenge_id, &body.response, body.name, context)
        .await?;
    registration_success(&state, outcome).await
}
