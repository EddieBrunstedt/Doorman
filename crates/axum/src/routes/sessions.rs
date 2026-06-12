//! Session-management HTTP routes.
//!
//! Mounted under `/auth/sessions`. Always available since every flow that
//! issues a session (passkey login, signup finish, and recovery finish)
//! produces a session managed by the same [`SessionManager`].

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use doorman_core::storage::SessionId;
use uuid::Uuid;

use crate::dto::SessionDto;
use crate::error::ErrorResponse;
use crate::extractors::AuthSession;
use crate::routes::no_content_clearing_session_cookie;
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
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
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Response, ErrorResponse> {
    state.session_manager.revoke(&auth.token).await?;
    Ok(no_content_clearing_session_cookie(&state.cookie_config))
}

/// "Log out everywhere": revoke *every* session the caller has, including the
/// current one, then clear the session cookie. Wired to
/// [`revoke_all_for_user`](doorman_core::session::SessionManager::revoke_all_for_user).
///
/// Not gated by the post-recovery cool-down: this revokes the caller's own
/// sessions across all devices (the legitimate owner can always re-authenticate
/// with a passkey), so unlike "sign out everywhere *else*" it cannot be used to
/// strand the real user.
async fn logout_all(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Response, ErrorResponse> {
    state
        .session_manager
        .revoke_all_for_user(auth.user.id)
        .await?;
    Ok(no_content_clearing_session_cookie(&state.cookie_config))
}

async fn list(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<Vec<SessionDto>>, ErrorResponse> {
    let current_id = auth.session.id;
    let sessions = state.session_manager.list_for_user(auth.user.id).await?;
    let dtos = sessions
        .into_iter()
        .map(|s| {
            let is_current = s.id == current_id;
            SessionDto::from_session(&s, is_current)
        })
        .collect();
    Ok(Json(dtos))
}

async fn remove(
    State(state): State<AuthState>,
    auth: AuthSession,
    Path(raw_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let id = Uuid::parse_str(&raw_id)
        .map(SessionId)
        .map_err(|_| ErrorResponse(doorman_core::Error::SessionNotFound))?;

    // The post-recovery cool-down blocks revoking *other* sessions so a
    // phished link cannot kick the legitimate user off their devices. The
    // recovery session itself stays revocable so the user can still sign
    // out of the cool-down session.
    if id != auth.session.id && state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(doorman_core::Error::RecoveryCooldownActive));
    }

    // Ownership, revocation, and the best-effort "other session revoked"
    // notice all live in the manager: it reads the target once, treats a
    // missing or not-owned session as "not yours" (rather than leaking the
    // existence of someone else's id), and notifies only when the revoked
    // session is not the caller's own.
    state
        .session_manager
        .revoke_owned_session(&auth.user, id, auth.session.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revoke every session belonging to the caller *except* the current one.
/// Powers the "sign out everywhere else" surface. Blocked while the
/// current session is within the post-recovery cool-down window.
async fn remove_others(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<StatusCode, ErrorResponse> {
    if state.session_manager.is_in_recovery_cooldown(&auth.session) {
        return Err(ErrorResponse(doorman_core::Error::RecoveryCooldownActive));
    }
    // The manager fires the "other sessions revoked" notice itself when it
    // revokes anything, so the route only drives it.
    state
        .session_manager
        .revoke_others_for_user(&auth.user, auth.session.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
