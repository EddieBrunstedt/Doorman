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
use bauth_core::recovery::RecoveryManager;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::dto::{
    PasskeyChallenge, RecoveryConsumeRequest, RecoveryFinishRequest, RecoveryRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::{consume_response, enrollment_success, parse_challenge_id};
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/recovery/request", post(request))
        .route("/recovery/consume", post(consume))
        .route("/recovery/finish", post(finish))
}

fn manager(state: &BauthState) -> &RecoveryManager {
    &state.recovery
}

async fn request(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .request_recovery(&body.email, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn consume(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryConsumeRequest>,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let outcome = manager(&state)
        .consume_recovery(&body.token, context)
        .await?;
    Ok(consume_response(outcome))
}

async fn finish(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = parse_challenge_id(&body.challenge_id)?;
    let outcome = manager(&state)
        .finish_recovery(challenge_id, &body.response, body.name, context)
        .await?;
    enrollment_success(&state, outcome).await
}
