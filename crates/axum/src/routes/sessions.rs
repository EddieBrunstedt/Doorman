//! Session-management HTTP routes.
//!
//! Mounted under `/auth/sessions`. Always available since every flow that
//! issues a session (passkey login, signup finish, and recovery finish)
//! produces a session managed by the same [`SessionManager`]. Revoking
//! *other* sessions goes through the [`AccountManager`], which applies the
//! post-recovery cool-down and re-auth gate.
//!
//! [`SessionManager`]: doorman_core::session::SessionManager
//! [`AccountManager`]: doorman_core::account::AccountManager

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use doorman_core::storage::SessionId;
use uuid::Uuid;

use crate::dto::{RevokeSessionRequest, SessionDto};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{no_content_clearing_session_cookie, reauth_proof};
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
    state.core.session_manager.revoke(&auth.token).await?;
    no_content_clearing_session_cookie(&state.cookie_config)
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
        .core
        .session_manager
        .revoke_all_for_user(auth.user.id)
        .await?;
    no_content_clearing_session_cookie(&state.cookie_config)
}

async fn list(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<Vec<SessionDto>>, ErrorResponse> {
    let current_id = auth.session.id;
    let sessions = state
        .core
        .session_manager
        .list_for_user(auth.user.id)
        .await?;
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
    RequestContext(context): RequestContext,
    Path(raw_id): Path<String>,
    body: Option<Json<RevokeSessionRequest>>,
) -> Result<StatusCode, ErrorResponse> {
    let id = Uuid::parse_str(&raw_id)
        .map(SessionId)
        .map_err(|_| ErrorResponse(doorman_core::Error::SessionNotFound))?;

    // The body is optional: the proof-less first attempt sends none. Ownership,
    // the cool-down and re-auth gate, revocation, and the "other session
    // revoked" notice all live in the manager. It treats a missing or
    // not-owned session as "not yours", and never gates revoking the current
    // session, so the user can always sign it out.
    let proof = reauth_proof(body.and_then(|Json(b)| b.reauthentication))?;
    state
        .core
        .account
        .revoke_session(&auth.user, &auth.session, id, proof, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revoke every session belonging to the caller *except* the current one.
/// Powers the "sign out everywhere else" surface. The manager applies the
/// post-recovery cool-down and re-auth gate and fires the "other sessions
/// revoked" notice itself, so the route only drives it.
async fn remove_others(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    body: Option<Json<RevokeSessionRequest>>,
) -> Result<StatusCode, ErrorResponse> {
    let proof = reauth_proof(body.and_then(|Json(b)| b.reauthentication))?;
    state
        .core
        .account
        .revoke_other_sessions(&auth.user, &auth.session, proof, context)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
