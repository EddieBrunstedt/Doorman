use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::OriginalUri;
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use doorman_core::Error;
use doorman_core::dpop::{DpopProof, ProvenDpopKey};
use doorman_core::session::{RequestTransport, ResolvedSession, SessionManager};
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

use crate::config::CookieConfig;
use crate::csrf::{self, TrustedOrigins};
use crate::dpop::read_proof;
use crate::error::{LayerRefusal, error_response};
use crate::session_token::{self, SessionToken, TokenTransport};

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
                let token = match session_token::read(
                    req.headers(),
                    &state.cookie.name,
                    state.sessions.allows_dpop_sessions(),
                ) {
                    Ok(token) => token,
                    Err(_) => {
                        tracing::info!("refused a request carrying two session tokens");
                        return Ok(LayerRefusal::AmbiguousSessionToken.into_response());
                    }
                };
                if let Err(refusal) = csrf::check(
                    req.method(),
                    req.headers(),
                    token.as_ref().map(|t| t.transport),
                    &state.trusted_origins,
                ) {
                    tracing::info!(?refusal, "refused a cross-origin request");
                    return Ok(LayerRefusal::CrossOrigin.into_response());
                }

                // Proven here and nowhere else, so the one proof a request carries is used once,
                // whether it resolves the session the request carries, starts a new one, or both.
                let proof = presented_proof(&req, state.sessions.allows_dpop_sessions());
                let key = match prove_dpop(&state.sessions, proof, token.as_ref()).await {
                    Ok(key) => key,
                    Err(error) => return Ok(error_response(&error)),
                };
                if let Some(key) = &key {
                    req.extensions_mut().insert(key.clone());
                }

                if let Some(SessionToken { token, transport }) = token {
                    let transport = match (transport, key) {
                        (TokenTransport::Cookie, _) => RequestTransport::Cookie,
                        (TokenTransport::Dpop, Some(key)) => RequestTransport::Dpop(key),
                        (TokenTransport::Dpop, None) => {
                            return Ok(error_response(&Error::InvalidDpopProof));
                        }
                    };
                    match state.sessions.resolve(&token, &transport).await {
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
                        Err(error @ Error::InvalidDpopProof) => {
                            return Ok(error_response(&error));
                        }
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

// Without DPoP sessions doorman leaves the header to the host, as it does a DPoP token.
fn presented_proof(req: &Request<Body>, dpop_sessions: bool) -> Result<Option<DpopProof>, Error> {
    if !dpop_sessions {
        return Ok(None);
    }
    let Some(jwt) = read_proof(req.headers()).map_err(|_| Error::InvalidDpopProof)? else {
        return Ok(None);
    };
    // A router the host nests doorman under strips its prefix from the URI, but the client
    // signed the whole path.
    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().path(), |original| original.path());
    Ok(Some(DpopProof::new(jwt, req.method().as_str(), path)))
}

async fn prove_dpop(
    sessions: &SessionManager,
    proof: Result<Option<DpopProof>, Error>,
    token: Option<&SessionToken>,
) -> Result<Option<ProvenDpopKey>, Error> {
    let Some(proof) = proof? else {
        return Ok(None);
    };
    let token = token
        .filter(|t| t.transport == TokenTransport::Dpop)
        .map(|t| t.token.as_str());
    sessions.prove_dpop(&proof, token).await.map(Some)
}
