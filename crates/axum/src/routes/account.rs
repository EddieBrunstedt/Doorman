//! Account-management HTTP routes.
//!
//! Mounted under `/auth/account` by [`crate::routes::router`]. Covers the
//! verified email-change flow and account deletion. Both mutating operations
//! are blocked while the caller's session is inside the post-recovery
//! cool-down window, the same way passkey removal and "sign out everywhere
//! else" are — a phished recovery session must not be able to repoint the
//! account's email or delete it before the legitimate owner can react.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, post};

use crate::dto::{EmailChangeConfirmRequest, EmailChangeRequest, UserDto};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::no_content_clearing_session_cookie;
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/account/email", post(request_email_change))
        .route("/account/email/confirm", post(confirm_email_change))
        .route("/account", delete(delete_account))
}

/// Start a verified email change. Mails a confirmation link to the new
/// address and notifies the current one; the account's email is not changed
/// until the link is confirmed.
async fn request_email_change(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeRequest>,
) -> Result<StatusCode, ErrorResponse> {
    if state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(doorman_core::Error::RecoveryCooldownActive));
    }
    state
        .account
        .request_email_change(&auth.user, &body.new_email, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Confirm a verified email change by redeeming the token from the link. No
/// session is required — possession of the single-use token (delivered to the
/// new address) authorises the change. Returns the updated user.
async fn confirm_email_change(
    State(state): State<AuthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<EmailChangeConfirmRequest>,
) -> Result<Json<UserDto>, ErrorResponse> {
    let user = state
        .account
        .confirm_email_change(&body.token, context)
        .await?;
    let passkey_count = state.passkey.list_passkey_summaries(user.id).await?.len();
    Ok(Json(UserDto::from_user(&user, passkey_count)))
}

/// Irreversibly delete the caller's account and every row tied to it, then
/// clear the session cookie so the browser stops replaying the now-dead token.
async fn delete_account(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
) -> Result<Response, ErrorResponse> {
    if state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(doorman_core::Error::RecoveryCooldownActive));
    }
    state.account.delete_account(&auth.user, context).await?;
    Ok(no_content_clearing_session_cookie(&state.cookie_config))
}
