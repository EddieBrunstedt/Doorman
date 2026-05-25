//! Password-auth HTTP routes.
//!
//! Mounted under `/auth/password` by [`crate::routes::router`] only when
//! a [`PasswordAuthManager`] was supplied to the builder. Each handler
//! delegates to the manager, translates the result through
//! [`AuthResponse`] / [`ErrorResponse`], and — for endpoints that issue
//! or revoke a session — sets or clears the session cookie via the shared
//! [`CookieConfig`].

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bauth_core::password_auth::PasswordAuthManager;

use crate::cookies::clear_session_cookie;
use crate::dto::{
    AuthResponse, ChangePasswordRequest, LoginRequest, RegisterRequest,
    RequestPasswordResetRequest, ResetPasswordRequest, UserDto, VerifyEmailRequest,
};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, AuthUser, RequestContext};
use crate::routes::auth_success;
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/password/register", post(register))
        .route("/password/login", post(login))
        .route("/password/logout", post(logout))
        .route("/password/change", post(change_password))
        .route(
            "/password/verify-email/request",
            post(request_email_verification),
        )
        .route("/password/verify-email", post(verify_email))
        .route("/password/reset/request", post(request_password_reset))
        .route("/password/reset", post(reset_password))
}

fn manager(state: &BauthState) -> &PasswordAuthManager {
    state
        .password
        .as_ref()
        .expect("password manager missing but password routes were mounted")
}

async fn register(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RegisterRequest>,
) -> Result<Response, ErrorResponse> {
    let outcome = manager(&state)
        .register(&body.email, &body.password, context)
        .await?;
    match outcome.session {
        Some(issued) => Ok(auth_success(
            StatusCode::CREATED,
            state.cookie_config(),
            AuthResponse::from_issued(outcome.user, issued),
        )),
        None => {
            // require_email_verification = true: user created, no session.
            Ok((StatusCode::CREATED, Json(UserDto::from(outcome.user))).into_response())
        }
    }
}

async fn login(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ErrorResponse> {
    let issued = manager(&state)
        .login(&body.email, &body.password, context)
        .await?;
    let user = state
        .user_store
        .find_user_by_id(issued.session.user_id)
        .await
        .map_err(bauth_core::Error::from)?
        .ok_or(ErrorResponse(bauth_core::Error::UserNotFound))?;
    Ok(auth_success(
        StatusCode::OK,
        state.cookie_config(),
        AuthResponse::from_issued(user, issued),
    ))
}

async fn logout(State(state): State<BauthState>, auth: AuthSession) -> Response {
    // Best-effort: if the session is already gone we still want to clear
    // the cookie on the client.
    let _ = state.session_manager.revoke(&auth.token).await;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        clear_session_cookie(state.cookie_config()),
    );
    response
}

async fn change_password(
    State(state): State<BauthState>,
    AuthUser(user): AuthUser,
    RequestContext(context): RequestContext,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .change_password(user.id, &body.current_password, &body.new_password, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn request_email_verification(
    State(state): State<BauthState>,
    AuthUser(user): AuthUser,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state).request_email_verification(user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_email(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state).verify_email(&body.token, context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn request_password_reset(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<RequestPasswordResetRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .request_password_reset(&body.email, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reset_password(
    State(state): State<BauthState>,
    RequestContext(context): RequestContext,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<StatusCode, ErrorResponse> {
    manager(&state)
        .reset_password(&body.token, &body.new_password, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
