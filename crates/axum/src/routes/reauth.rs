//! Re-authentication HTTP route.
//!
//! Mounted under `/auth/reauth` by [`crate::routes::router`]. Exposes the
//! single `start` ceremony a client runs to obtain a fresh passkey assertion
//! before retrying a destructive action (account deletion, email-change
//! request, passkey removal).
//!
//! The recovery recipe is identical for every protected action:
//!
//! 1. Call the destructive endpoint with no proof.
//! 2. On `401 reauth_required`, `POST /auth/reauth/start` for a challenge.
//! 3. Run `navigator.credentials.get(options)`.
//! 4. Re-call the destructive endpoint, now carrying
//!    `{ "reauthentication": { "challenge_id", "assertion" } }`.
//!
//! Like every mutation the route inherits the CSRF origin-check layer. It is
//! deliberately **not** rate-limited: it is authenticated, sends no email,
//! exposes no enumeration surface, and guards an unforgeable signature.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::dto::PasskeyChallenge;
use crate::error::ErrorResponse;
use crate::extractors::AuthSession;
use crate::state::AuthState;

pub(crate) fn routes() -> Router<AuthState> {
    Router::new().route("/reauth/start", post(reauth_start))
}

/// Begin a re-authentication ceremony for the authenticated session's user.
/// Returns the `{ challenge_id, options }` payload the client feeds to
/// `navigator.credentials.get`. A user with no registered credentials gets a
/// clear error — there is nothing to assert, so they cannot re-authenticate.
async fn reauth_start(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> Result<Json<PasskeyChallenge<RequestChallengeResponse>>, ErrorResponse> {
    let (id, options) = state.core.reauth.start(auth.user.id).await?;
    Ok(Json(PasskeyChallenge {
        challenge_id: id.0.to_string(),
        options,
    }))
}
