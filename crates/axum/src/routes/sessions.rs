//! Session-management HTTP routes.
//!
//! Mounted under `/auth/sessions`. Always available since every flow that
//! issues a session (passkey login, signup finish, and recovery finish)
//! produces a session managed by the same [`SessionManager`].

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use bauth_core::storage::SessionId;
use uuid::Uuid;

use crate::cookies::clear_session_cookie;
use crate::dto::SessionDto;
use crate::error::ErrorResponse;
use crate::extractors::AuthSession;
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/sessions", get(list).delete(remove_others))
        .route("/sessions/{id}", delete(remove))
}

/// End the caller's *own* session: revoke it server-side and clear the
/// session cookie so the browser stops replaying a dead token.
///
/// Not gated by the post-recovery cool-down — signing out of your own
/// session is always allowed, the same way `DELETE /sessions/{id}` lets you
/// drop the current session during the cool-down window. The session
/// layer's origin check covers CSRF for cookie-bearing POSTs.
async fn logout(
    State(state): State<BauthState>,
    auth: AuthSession,
) -> Result<Response, ErrorResponse> {
    state.session_manager.revoke(&auth.token).await?;
    let cookie = clear_session_cookie(&state.cookie_config);
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

async fn list(
    State(state): State<BauthState>,
    auth: AuthSession,
) -> Result<Json<Vec<SessionDto>>, ErrorResponse> {
    let current_id = auth.session.id;
    let sessions = state.session_manager.list_for_user(auth.user.id).await?;
    let dtos = sessions
        .into_iter()
        .map(|s| {
            let is_current = s.id == current_id;
            SessionDto::from_session(s, is_current)
        })
        .collect();
    Ok(Json(dtos))
}

async fn remove(
    State(state): State<BauthState>,
    auth: AuthSession,
    Path(raw_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let id = Uuid::parse_str(&raw_id)
        .map(SessionId)
        .map_err(|_| ErrorResponse(bauth_core::Error::SessionNotFound))?;

    // The post-recovery cool-down blocks revoking *other* sessions so a
    // phished link cannot kick the legitimate user off their devices. The
    // recovery session itself stays revocable so the user can still sign
    // out of the cool-down session.
    if id != auth.session.id && state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(bauth_core::Error::RecoveryCooldownActive));
    }

    // Ownership check: a user can only revoke their own sessions, and a
    // missing session reads as "not yours" rather than leaking the
    // existence of someone else's id.
    let owned = state
        .session_manager
        .list_for_user(auth.user.id)
        .await?
        .into_iter()
        .any(|s| s.id == id);
    if !owned {
        return Err(ErrorResponse(bauth_core::Error::SessionNotFound));
    }

    state.session_manager.revoke_by_id(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revoke every session belonging to the caller *except* the current one.
/// Powers the "sign out everywhere else" surface. Blocked while the
/// current session is within the post-recovery cool-down window.
async fn remove_others(
    State(state): State<BauthState>,
    auth: AuthSession,
) -> Result<StatusCode, ErrorResponse> {
    if state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(bauth_core::Error::RecoveryCooldownActive));
    }
    state
        .session_manager
        .revoke_others_for_user(auth.user.id, auth.session.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
