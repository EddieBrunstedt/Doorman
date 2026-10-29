use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::dto::PasskeyChallenge;
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new().route("/reauth/start", post(reauth_start))
}

async fn reauth_start(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
) -> Result<Json<PasskeyChallenge<RequestChallengeResponse>>, ErrorResponse> {
    let (id, options) = state
        .core
        .sessions
        .start_reauth(&auth.session, context)
        .await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}
