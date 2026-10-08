use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{delete, post};
use doorman_core::destructive::DestructiveAction;

use crate::dto::{
    DestructiveActionRequest, EmailChangeConfirmRequest, EmailChangeRequest, UserDto,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{no_content, perform};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/user/email", post(request_email_change))
        .route("/user/email/confirm", post(confirm_email_change))
        .route("/user", delete(delete_user))
}

async fn request_email_change(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeRequest>,
) -> Result<Response, ErrorResponse> {
    let action = DestructiveAction::RequestEmailChange {
        new_email: body.new_email,
    };
    let current = perform(&state, &auth, action, body.reauthentication, context).await?;
    Ok(no_content(current))
}

async fn confirm_email_change(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeConfirmRequest>,
) -> Result<Json<UserDto>, ErrorResponse> {
    let outcome = state
        .core
        .user
        .confirm_email_change(&body.token, context)
        .await?;
    Ok(Json(UserDto::from_user(
        &outcome.user,
        outcome.passkey_count,
    )))
}

async fn delete_user(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<Response, ErrorResponse> {
    let reauth = body.and_then(|Json(b)| b.reauthentication);
    let current = perform(
        &state,
        &auth,
        DestructiveAction::DeleteUser,
        reauth,
        context,
    )
    .await?;
    Ok(no_content(current))
}
