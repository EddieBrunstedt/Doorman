use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use doorman_core::destructive::DestructiveAction;
use doorman_core::storage::SessionId;
use uuid::Uuid;

use crate::dto::{DestructiveActionRequest, SessionDto};
use crate::error::ErrorResponse;
use crate::extractors::{AuthSession, RequestContext};
use crate::routes::{no_content_clearing_session_cookie, perform};
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(list).delete(remove_others))
        .route("/sessions/{id}", delete(remove))
}

async fn logout(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Response, ErrorResponse> {
    state.core.sessions.log_out(&auth.session).await?;
    no_content_clearing_session_cookie(&state.cookie_config)
}

async fn logout_all(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<Response, ErrorResponse> {
    let reauth = body.and_then(|Json(b)| b.reauthentication);
    let action = DestructiveAction::LogOutEverywhere;
    perform(&state, &auth, action, reauth, context).await?;
    no_content_clearing_session_cookie(&state.cookie_config)
}

async fn list(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<Vec<SessionDto>>, ErrorResponse> {
    let current_id = auth.session.id;
    let sessions = state.core.sessions.list_sessions(&auth.session).await?;
    let dtos = sessions
        .iter()
        .map(|s| SessionDto::new(s, s.id == current_id))
        .collect();
    Ok(Json(dtos))
}

async fn remove(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    Path(raw_id): Path<String>,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<StatusCode, ErrorResponse> {
    let id = Uuid::parse_str(&raw_id)
        .map(SessionId)
        .map_err(|_| ErrorResponse(doorman_core::Error::SessionNotFound))?;

    let reauth = body.and_then(|Json(b)| b.reauthentication);
    let action = DestructiveAction::RevokeSession { id };
    perform(&state, &auth, action, reauth, context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_others(
    State(state): State<AuthState>,
    auth: AuthSession,
    RequestContext(context): RequestContext,
    body: Option<Json<DestructiveActionRequest>>,
) -> Result<StatusCode, ErrorResponse> {
    let reauth = body.and_then(|Json(b)| b.reauthentication);
    let action = DestructiveAction::RevokeOtherSessions;
    perform(&state, &auth, action, reauth, context).await?;
    Ok(StatusCode::NO_CONTENT)
}
