//! Recovery HTTP routes.
//!
//! Mounted under `/auth/recovery` by [`crate::routes::router`] only when a
//! [`RecoveryManager`] was supplied to the builder. The three endpoints
//! mirror the three-step recovery flow: request a link, consume the link
//! and start a passkey registration ceremony, finish the registration
//! and receive a session.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use bauth_core::recovery::RecoveryManager;
use bauth_core::storage::PasskeyChallengeId;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::dto::{
    AuthResponse, PasskeyChallenge, RecoveryConsumeRequest, RecoveryFinishRequest, RecoveryRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::auth_success;
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/recovery/request", post(request))
        .route("/recovery/consume", post(consume))
        .route("/recovery/finish", post(finish))
}

fn manager(state: &BauthState) -> &RecoveryManager {
    state
        .recovery
        .as_ref()
        .expect("recovery manager missing but recovery routes were mounted")
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
    Ok(Json(PasskeyChallenge {
        challenge_id: outcome.challenge_id.0.to_string(),
        options: outcome.options,
    }))
}

async fn finish(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = Uuid::parse_str(&body.challenge_id)
        .map(PasskeyChallengeId)
        .map_err(|_| ErrorResponse(bauth_core::Error::InvalidPasskeyChallenge))?;
    let outcome = manager(&state)
        .finish_recovery(challenge_id, &body.response, body.name, context)
        .await?;
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session),
    ))
}
