use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, post};

use crate::dto::{DeleteAccountRequest, EmailChangeConfirmRequest, EmailChangeRequest, UserDto};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{no_content_clearing_session_cookie, reauth_proof};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/account/email", post(request_email_change))
        .route("/account/email/confirm", post(confirm_email_change))
        .route("/account", delete(delete_account))
}

async fn request_email_change(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeRequest>,
) -> Result<StatusCode, ErrorResponse> {
    let proof = reauth_proof(body.reauthentication)?;
    state
        .core
        .account
        .request_email_change(&auth.session, &body.new_email, proof, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn confirm_email_change(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeConfirmRequest>,
) -> Result<Json<UserDto>, ErrorResponse> {
    let user = state
        .core
        .account
        .confirm_email_change(&body.token, context)
        .await?;
    let passkey_count = state.core.passkey.count_passkeys(user.id).await?;
    Ok(Json(UserDto::from_user(&user, passkey_count)))
}

async fn delete_account(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    body: Option<Json<DeleteAccountRequest>>,
) -> Result<Response, ErrorResponse> {
    let proof = reauth_proof(body.and_then(|Json(b)| b.reauthentication))?;
    state
        .core
        .account
        .delete_account(&auth.session, proof, context)
        .await?;
    no_content_clearing_session_cookie(&state.cookie_config)
}
