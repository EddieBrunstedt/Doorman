use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use doorman_core::recovery::RecoveryManager;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::dto::{
    PasskeyChallenge, RecoveryRedeemRequest, RecoveryRequest, RegistrationFinishRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::{parse_challenge_id, redeem_response, registration_success};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/recovery/request", post(request))
        .route("/recovery/redeem", post(redeem))
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

async fn redeem(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RecoveryRedeemRequest>,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let outcome = manager(&state)
        .redeem_recovery_link(&body.token, context)
        .await?;
    Ok(redeem_response(outcome))
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
    registration_success(&state, outcome)
}
