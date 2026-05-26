//! Magic-link HTTP routes.
//!
//! Mounted under `/auth/magic-link` by [`crate::routes::router`] only when
//! a [`MagicLinkManager`] was supplied to the builder.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use bauth_core::magic_link::MagicLinkManager;

use crate::dto::{AuthResponse, MagicLinkConsumeRequest, RequestMagicLinkRequest};
use crate::error::ErrorResponse;
use crate::extractors::RequestContext;
use crate::routes::auth_success;
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/magic-link/request", post(request))
        .route("/magic-link/consume", post(consume))
}

fn manager(state: &BauthState) -> &MagicLinkManager {
    state
        .magic_link
        .as_ref()
        .expect("magic-link manager missing but magic-link routes were mounted")
}

async fn request(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RequestMagicLinkRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .request_magic_link(&body.email, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn consume(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<MagicLinkConsumeRequest>,
) -> Result<Response, ErrorResponse> {
    let outcome = manager(&state)
        .consume_magic_link(&body.token, context)
        .await?;
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(outcome.user, outcome.session),
    ))
}
