use axum::Json;
use axum::Router;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use doorman_core::Error;
use doorman_core::destructive::{CurrentSession, DestructiveAction};
use doorman_core::dpop::ProvenDpopKey;
use doorman_core::passkey::{RegistrationOutcome, StartedRegistration};
use doorman_core::reauth::ReauthProof;
use doorman_core::session::{IssuedSession, RequestTransport, SessionContext};
use doorman_core::storage::{PasskeyChallengeId, SessionTransport, User};
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::browser::sent_by_browser;
use crate::cookies::{clear_session_cookie, session_cookie};
use crate::dpop::DPOP;
use crate::dto::{AuthResponse, DpopAuthResponse, PasskeyChallenge, Reauthentication};
use crate::error::ErrorResponse;
use crate::extractors::AuthSession;
use crate::state::AuthState;

pub(crate) mod passkey;
pub(crate) mod reauth;
pub(crate) mod recovery;
pub(crate) mod sessions;
pub(crate) mod signup;
pub(crate) mod user;

// What a request that starts a session asks for: a DPoP session if it carries a DPoP proof, and
// a cookie session otherwise.
pub(crate) struct RequestedTransport(pub(crate) RequestTransport);

impl<S: Send + Sync> FromRequestParts<S> for RequestedTransport {
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if !parts.headers.contains_key(DPOP) {
            return Ok(Self(RequestTransport::Cookie));
        }
        // A page script can read any response body, so a request a browser sends never starts a
        // session whose token travels in one. The refusal comes before the ceremony uses
        // anything up.
        if sent_by_browser(&parts.headers) {
            return Err(ErrorResponse(Error::DpopSessionNotAllowed));
        }
        // The session layer proves the request's proof whenever the host allows DPoP sessions.
        match parts.extensions.get::<ProvenDpopKey>() {
            Some(key) => Ok(Self(RequestTransport::Dpop(key.clone()))),
            None => Err(ErrorResponse(Error::DpopSessionNotAllowed)),
        }
    }
}

// Only the routes that start or end a session write its cookie. A cookie written on any other
// response could reach the browser after a newer one and overwrite it.
pub(crate) fn auth_success(
    state: &AuthState,
    user: &User,
    passkey_count: u64,
    issued: IssuedSession,
) -> Result<Response, ErrorResponse> {
    match issued.session.transport {
        SessionTransport::Cookie => {
            let cookie = session_cookie(
                state.cookie_config(),
                &issued.token,
                issued.absolute_lifetime,
            )?;
            let body = AuthResponse::new(user, passkey_count, &issued.session);
            let mut response = Json(body).into_response();
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            Ok(response)
        }
        SessionTransport::Dpop { .. } => {
            let body = DpopAuthResponse::from_issued(user, passkey_count, issued);
            Ok(Json(body).into_response())
        }
    }
}

pub(crate) fn no_content(
    state: &AuthState,
    auth: &AuthSession,
    current: CurrentSession,
) -> Result<Response, ErrorResponse> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    if current == CurrentSession::Ended && auth.session.transport == SessionTransport::Cookie {
        let cookie = clear_session_cookie(state.cookie_config())?;
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

pub(crate) fn parse_challenge_id(raw: &str) -> Result<PasskeyChallengeId, ErrorResponse> {
    Uuid::parse_str(raw)
        .map(PasskeyChallengeId)
        .map_err(|_| ErrorResponse(doorman_core::Error::InvalidPasskeyChallenge))
}

impl TryFrom<Reauthentication> for ReauthProof {
    type Error = ErrorResponse;

    fn try_from(reauth: Reauthentication) -> Result<Self, ErrorResponse> {
        Ok(ReauthProof {
            challenge_id: parse_challenge_id(&reauth.challenge_id)?,
            assertion: reauth.assertion,
        })
    }
}

pub(crate) async fn perform(
    state: &AuthState,
    auth: &AuthSession,
    action: DestructiveAction,
    reauth: Option<Reauthentication>,
    context: SessionContext,
) -> Result<CurrentSession, ErrorResponse> {
    let proof = reauth.map(ReauthProof::try_from).transpose()?;
    Ok(state
        .core
        .sessions
        .perform(&auth.session, action, proof, context)
        .await?)
}

pub(crate) fn redeem_response(
    outcome: StartedRegistration,
) -> Json<PasskeyChallenge<CreationChallengeResponse>> {
    Json(PasskeyChallenge {
        challenge_id: outcome.challenge_id.0.to_string(),
        options: outcome.options,
    })
}

pub(crate) fn registration_success(
    state: &AuthState,
    outcome: RegistrationOutcome,
) -> Result<Response, ErrorResponse> {
    auth_success(state, &outcome.user, outcome.passkey_count, outcome.session)
}

pub(crate) fn router(state: AuthState) -> Router {
    Router::new()
        .merge(passkey::routes())
        .merge(reauth::routes())
        .merge(signup::routes())
        .merge(recovery::routes())
        .merge(sessions::routes())
        .merge(user::routes())
        .with_state(state)
}
