use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use doorman_core::session::{ResolvedSession, SessionManager};
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

use crate::config::CookieConfig;
use crate::credential::{self, Credential};
use crate::csrf::{self, TrustedOrigins};
use crate::error::LayerRefusal;

#[derive(Clone)]
pub struct AuthContext {
    pub session: ResolvedSession,
    pub(crate) sessions: SessionManager,
}

// The session store failed while resolving the request's token, so whether the request has a
// session is unknown; the extractors refuse rather than answer as if it had none.
#[derive(Clone, Copy)]
pub(crate) struct SessionUnresolved;

#[derive(Clone, Copy)]
pub(crate) struct SessionLayerApplied;

pub(crate) struct SessionLayerState {
    pub(crate) sessions: SessionManager,
    pub(crate) cookie: CookieConfig,
    pub(crate) trusted_origins: TrustedOrigins,
}

#[derive(Clone)]
pub struct SessionLayer {
    state: Arc<SessionLayerState>,
}

impl SessionLayer {
    pub(crate) fn new(state: Arc<SessionLayerState>) -> Self {
        Self { state }
    }
}

#[derive(Clone)]
pub struct SessionService<S> {
    inner: S,
    state: Arc<SessionLayerState>,
}

impl<S> Layer<S> for SessionLayer {
    type Service = SessionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SessionService {
            inner,
            state: self.state.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for SessionService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        // doorman's router applies this layer to its own routes, and the host applies it again
        // around them; the outer one has already checked and resolved the request.
        if req.extensions().get::<SessionLayerApplied>().is_some() {
            return Box::pin(inner.call(req));
        }
        req.extensions_mut().insert(SessionLayerApplied);
        let state = self.state.clone();
        let span = tracing::info_span!(
            "doorman.session",
            session_id = tracing::field::Empty,
            user_id = tracing::field::Empty,
        );
        Box::pin(
            async move {
                let credential = match credential::read(
                    req.headers(),
                    &state.cookie.session_cookie_name,
                    state.sessions.allows_bearer_sessions(),
                ) {
                    Ok(credential) => credential,
                    Err(_) => {
                        tracing::info!("refused a request carrying two credentials");
                        return Ok(LayerRefusal::AmbiguousCredential.into_response());
                    }
                };
                if let Err(refusal) = csrf::check(
                    req.method(),
                    req.headers(),
                    credential.as_ref().map(|c| c.transport),
                    &state.trusted_origins,
                ) {
                    tracing::info!(?refusal, "refused a cross-origin request");
                    return Ok(LayerRefusal::CrossOrigin.into_response());
                }

                if let Some(Credential { token, transport }) = credential {
                    match state.sessions.resolve(&token, transport).await {
                        Ok(Some(resolved)) => {
                            let span = tracing::Span::current();
                            span.record("session_id", tracing::field::display(resolved.id));
                            span.record("user_id", tracing::field::display(resolved.user_id));
                            req.extensions_mut().insert(AuthContext {
                                session: resolved,
                                sessions: state.sessions.clone(),
                            });
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(%error, "session resolve failed");
                            req.extensions_mut().insert(SessionUnresolved);
                        }
                    }
                }
                inner.call(req).await
            }
            .instrument(span),
        )
    }
}
