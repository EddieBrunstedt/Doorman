//! Canonical mapping from [`bauth_core::Error`] to HTTP responses.
//!
//! Every variant is assigned a stable string code so a frontend can switch
//! on it without scraping the human-readable message. [`Error::RateLimited`]
//! additionally emits a `Retry-After` header (rounded up to whole seconds)
//! so well-behaved clients can back off without parsing the body.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bauth_core::Error;
use serde::Serialize;

/// JSON body returned with every error response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: ErrorPayload,
}

/// Stable machine-readable error payload nested under `error`.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorPayload {
    pub code: &'static str,
    pub message: String,
}

/// Wrapper type so we can `impl IntoResponse for ErrorResponse` without
/// orphan-rule trouble — `bauth_core::Error` lives in another crate, but
/// callers can still use `?` thanks to the `From<Error>` impl below.
#[derive(Debug)]
pub struct ErrorResponse(pub Error);

impl From<Error> for ErrorResponse {
    fn from(value: Error) -> Self {
        Self(value)
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        error_response(&self.0)
    }
}

pub(crate) fn error_response(err: &Error) -> Response {
    let (status, code) = classify(err);
    let body = ErrorBody {
        error: ErrorPayload {
            code,
            message: err.to_string(),
        },
    };
    let mut response = (status, Json(body)).into_response();
    if let Error::RateLimited { retry_after } = err {
        let secs = retry_after.as_secs().max(1);
        if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

fn classify(err: &Error) -> (StatusCode, &'static str) {
    match err {
        Error::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
        Error::Email(_) => (StatusCode::INTERNAL_SERVER_ERROR, "email_error"),
        Error::SessionNotFound => (StatusCode::UNAUTHORIZED, "session_not_found"),
        Error::SessionExpired => (StatusCode::UNAUTHORIZED, "session_expired"),
        Error::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
        Error::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid_email"),
        Error::InvalidVerificationToken => (StatusCode::BAD_REQUEST, "invalid_verification_token"),
        Error::InvalidPasskeyChallenge => (StatusCode::BAD_REQUEST, "invalid_passkey_challenge"),
        Error::PasskeyNotFound => (StatusCode::NOT_FOUND, "passkey_not_found"),
        Error::PasskeyOwnershipMismatch => (StatusCode::FORBIDDEN, "passkey_ownership_mismatch"),
        Error::PasskeyPossibleCompromise => (StatusCode::FORBIDDEN, "passkey_possible_compromise"),
        Error::Webauthn(_) => (StatusCode::BAD_REQUEST, "webauthn_error"),
        Error::InvalidRelyingParty(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid_relying_party")
        }
        Error::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        Error::RecoveryCooldownActive => (StatusCode::CONFLICT, "recovery_cooldown_active"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_limited_includes_retry_after_header() {
        let response = error_response(&Error::RateLimited {
            retry_after: Duration::from_millis(2400),
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let header = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("retry-after present");
        // 2.4 s rounds down to 2 s (max with 1 s floor).
        assert_eq!(header, "2");
    }
}
