//! Signup HTTP routes.
//!
//! Mounted under `/auth/signup` by [`crate::routes::router`] only when a
//! [`SignupManager`] was supplied to the builder. The three endpoints
//! mirror the three-step signup flow: request a link, consume the link
//! and start a passkey registration ceremony, finish the registration
//! and receive a session.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use bauth_core::signup::SignupManager;
use bauth_core::storage::PasskeyChallengeId;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::dto::{
    AuthResponse, PasskeyChallenge, SignupConsumeRequest, SignupFinishRequest, SignupRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::auth_success;
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/signup/request", post(request))
        .route("/signup/consume", post(consume))
        .route("/signup/finish", post(finish))
}

fn manager(state: &BauthState) -> &SignupManager {
    state
        .signup
        .as_ref()
        .expect("signup manager missing but signup routes were mounted")
}

async fn request(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<SignupRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state).request_signup(&body.email, context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn consume(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<SignupConsumeRequest>,
) -> Result<Json<PasskeyChallenge<CreationChallengeResponse>>, ErrorResponse> {
    let outcome = manager(&state).consume_signup(&body.token, context).await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: outcome.challenge_id.0.to_string(),
        options: outcome.options,
    }))
}

async fn finish(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<SignupFinishRequest>,
) -> Result<Response, ErrorResponse> {
    let challenge_id = Uuid::parse_str(&body.challenge_id)
        .map(PasskeyChallengeId)
        .map_err(|_| ErrorResponse(bauth_core::Error::InvalidPasskeyChallenge))?;
    let outcome = manager(&state)
        .finish_signup(challenge_id, &body.response, body.name, context)
        .await?;
    let passkey_count = state
        .passkey
        .as_ref()
        .expect("passkey manager missing but signup routes were mounted")
        .list_passkeys(outcome.user.id)
        .await?
        .len();
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session, passkey_count),
    ))
}
