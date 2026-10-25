use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::Extensions;
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;
use doorman_core::Error;
use doorman_core::client_ip::ClientIp;
use doorman_core::error::StorageError;
use doorman_core::session::{ResolvedSession, SessionContext};
use doorman_core::storage::User;

use crate::error::ErrorResponse;
use crate::session::{AuthContext, SessionLayerApplied, SessionUnresolved};

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub session: ResolvedSession,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match auth_context(&parts.extensions)? {
            Some(ctx) => Ok(AuthSession {
                session: ctx.session.clone(),
            }),
            None => Err(ErrorResponse(Error::SessionNotFound)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser(pub User);

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(ctx) = auth_context(&parts.extensions)? else {
            return Err(ErrorResponse(Error::SessionNotFound));
        };
        Ok(AuthUser(ctx.sessions.find_user(&ctx.session).await?))
    }
}

#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<User>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalAuthUser {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(ctx) = auth_context(&parts.extensions)? else {
            return Ok(OptionalAuthUser(None));
        };
        Ok(OptionalAuthUser(Some(
            ctx.sessions.find_user(&ctx.session).await?,
        )))
    }
}

fn auth_context(extensions: &Extensions) -> Result<Option<&AuthContext>, ErrorResponse> {
    // Without the layer no request has a session, so answering 401 would hide the mistake.
    if extensions.get::<SessionLayerApplied>().is_none() {
        return Err(ErrorResponse(Error::Internal(
            "no SessionLayer handled this request: apply AuthService::session_layer() to the route"
                .to_owned(),
        )));
    }
    if extensions.get::<SessionUnresolved>().is_some() {
        return Err(ErrorResponse(Error::Storage(StorageError::msg(
            "the request's session could not be resolved",
        ))));
    }
    Ok(extensions.get::<AuthContext>())
}

#[derive(Debug, Clone)]
pub struct RequestContext(pub SessionContext);

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .or_else(|| {
                parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|peer| ClientIp::new(peer.0.ip()))
            })
            .ok_or_else(|| {
                ErrorResponse(Error::Internal(
                    "client IP unavailable: serve with ConnectInfo<SocketAddr> or insert a trusted ClientIp extension"
                        .to_owned(),
                ))
            })?;
        let user_agent = parts.headers.get(USER_AGENT).and_then(|h| h.to_str().ok());
        Ok(RequestContext(SessionContext::new(ip, user_agent)))
    }
}
