//! Recovery HTTP routes.
//!
//! Mounted under `/auth/recovery` by [`crate::routes::router`]. The three
//! endpoints mirror the three-step recovery flow: request a link, consume
//! the link and start a passkey registration ceremony, finish the
//! registration and receive a session.

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
use crate::routes::{consume_response, enrollment_success, parse_challenge_id};
use crate::state::DoormanState;

pub(crate) fn routes() -> Router<DoormanState> {
    Router::new()
        .route("/recovery/request", post(request))
        .route("/recovery/consume", post(consume))
        .route("/recovery/finish", post(finish))
}

fn manager(state: &DoormanState) -> &RecoveryManager {
    &state.recovery
}

async fn request(
    State(state): State<DoormanState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .request_recovery(&body.email, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn consume(
    State(state): State<DoormanState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryConsumeRequest>,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let outcome = manager(&state)
        .consume_recovery(&body.token, context)
        .await?;
    Ok(consume_response(outcome))
}

async fn finish(
    State(state): State<DoormanState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RegistrationFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let outcome = manager(&state)
        .finish_recovery(challenge_id, &body.response, body.name, context)
        .await?;
    enrollment_success(&state, outcome).await
}
