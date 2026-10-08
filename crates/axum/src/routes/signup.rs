use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use doorman_core::signup::SignupManager;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::dto::{PasskeyChallenge, RegistrationFinishRequest, SignupRedeemRequest, SignupRequest};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::{parse_challenge_id, redeem_response, registration_success};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/signup/request", post(request))
        .route("/signup/redeem", post(redeem))
        .route("/signup/finish", post(finish))
}

fn manager(state: &AuthState) -> &SignupManager {
    &state.core.signup
}

async fn request(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<SignupRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .request_signup(&body.email, body.invite_token.as_deref(), context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn redeem(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<SignupRedeemRequest>,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let outcome = manager(&state)
        .redeem_signup_link(&body.token, context)
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
        .finish_signup(challenge_id, &body.response, body.name, context)
        .await?;
    registration_success(&state, outcome)
}
