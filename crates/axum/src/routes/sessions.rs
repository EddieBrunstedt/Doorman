//! Session-management HTTP routes.
//!
//! Mounted under `/auth/sessions`. Always available regardless of which
//! auth methods are enabled, since every issuer (`passkey`, `magic_link`)
//! produces sessions managed by the same
//! [`SessionManager`].

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use bauth_core::storage::SessionId;
use uuid::Uuid;

use crate::dto::SessionDto;
use crate::error::ErrorResponse;
use crate::extractors::AuthSession;
use crate::state::BauthState;

pub(crate) fn routes() -> Router<BauthState> {
    Router::new()
        .route("/sessions", get(list))
        .route("/sessions/{id}", delete(remove))
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
