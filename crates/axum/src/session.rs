use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, Request, header};
use axum::response::{IntoResponse, Response};
use doorman_core::session::{ResolvedSession, SessionManager};
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument;

use crate::config::CookieConfig;
use crate::cookies::{SessionCookie, bearer_token, read_cookie};
use crate::csrf::{self, CsrfConfig};
use crate::error::{ErrorResponse, csrf_rejection_response};

#[derive(Clone)]
pub struct AuthContext {
    pub session: ResolvedSession,
    pub token: String,
    pub(crate) sessions: SessionManager,
}

pub(crate) struct SessionLayerState {
    pub(crate) sessions: SessionManager,
    pub(crate) cookie: CookieConfig,
    pub(crate) csrf: Option<CsrfConfig>,
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
        let state = self.state.clone();
        let span = tracing::info_span!(
            "doorman.session",
            session_id = tracing::field::Empty,
            user_id = tracing::field::Empty,
        );
        Box::pin(
            async move {
                let cookie_name = &state.cookie.session_cookie_name;
                if let Some(config) = state.csrf.as_ref()
                    && csrf::should_reject(req.method(), req.headers(), cookie_name, config)
                {
                    return Ok(csrf_rejection_response());
                }

                let mut refresh: Option<SessionCookie> = None;
                if let Some((token, source)) = extract_token(req.headers(), cookie_name)
                    && let Ok(resolved) = state.sessions.resolve(&token).await
                {
                    let span = tracing::Span::current();
                    span.record("session_id", tracing::field::display(resolved.id));
                    span.record("user_id", tracing::field::display(resolved.user_id));
                    if resolved.slid() && source == TokenSource::Cookie {
                        refresh = Some(SessionCookie::Issue {
                            token: token.clone(),
                            max_age: resolved.remaining_lifetime(),
                        });
                    }
                    req.extensions_mut().insert(AuthContext {
                        session: resolved,
                        token,
                        sessions: state.sessions.clone(),
                    });
                }
                let response = inner.call(req).await?;
                Ok(set_session_cookie(response, refresh, &state.cookie))
            }
            .instrument(span),
        )
    }
}

// The handler ran after the slide and may have ended or replaced the session, so its decision
// outranks the refresh.
fn set_session_cookie(
    mut response: Response,
    refresh: Option<SessionCookie>,
    config: &CookieConfig,
) -> Response {
    let (cookie, from_handler) = match response.extensions_mut().remove::<SessionCookie>() {
        Some(decided) => (decided, true),
        None => match refresh {
            Some(refresh) => (refresh, false),
            None => return response,
        },
    };
    match cookie.header(config) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
            response
        }
        // Without a refresh the cookie only expires sooner; without the handler's cookie the
        // response would claim a login or logout the browser never sees.
        Err(err) if from_handler => ErrorResponse(err).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "session cookie refresh skipped");
            response
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TokenSource {
    Cookie,
    Bearer,
}

pub(crate) fn extract_token(
    headers: &HeaderMap,
    cookie_name: &str,
) -> Option<(String, TokenSource)> {
    if let Some(token) = bearer_token(headers) {
        return Some((token.to_owned(), TokenSource::Bearer));
    }
    read_cookie(headers, cookie_name).map(|token| (token, TokenSource::Cookie))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    #[test]
    fn bearer_header_wins_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("doorman_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "doorman_session"),
            Some(("header-token".into(), TokenSource::Bearer))
        );
    }

    #[test]
    fn cookie_fallback_when_no_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("doorman_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "doorman_session"),
            Some(("cookie-token".into(), TokenSource::Cookie))
        );
    }

    #[test]
    fn no_token_returns_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_token(&headers, "doorman_session"), None);
    }

    #[test]
    fn bearer_without_value_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer  "));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("doorman_session=cookie-token"),
        );
        assert_eq!(
            extract_token(&headers, "doorman_session"),
            Some(("cookie-token".into(), TokenSource::Cookie))
        );
    }
}
