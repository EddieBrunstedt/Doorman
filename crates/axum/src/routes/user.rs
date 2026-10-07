use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, post};
use doorman_core::destructive::DestructiveAction;

use crate::dto::{
    DestructiveActionRequest, EmailChangeConfirmRequest, EmailChangeRequest, UserDto,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{no_content_clearing_session_cookie, perform};
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
) -> Result<StatusCode, ErrorResponse> {
    let action = DestructiveAction::RequestEmailChange {
        new_email: body.new_email,
    };
    perform(&state, &auth, action, body.reauthentication, context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn confirm_email_change(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeConfirmRequest>,
) -> Result<Json<UserDto>, ErrorResponse> {
    let user = state
        .core
        .user
        .confirm_email_change(&body.token, context)
        .await?;
    let passkey_count = state.core.passkey.count_passkeys(user.id).await?;
    Ok(Json(UserDto::from_user(&user, passkey_count)))
}

async fn delete_user(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<Response, ErrorResponse> {
    let reauth = body.and_then(|Json(b)| b.reauthentication);
    perform(
        &state,
        &auth,
        DestructiveAction::DeleteUser,
        reauth,
        context,
    )
    .await?;
    no_content_clearing_session_cookie(&state.cookie_config)
}
