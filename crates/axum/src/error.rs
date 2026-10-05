//! Canonical mapping from [`doorman_core::Error`] to HTTP responses.
//!
//! Every variant is assigned a stable string code so a frontend can switch
//! on it without scraping the human-readable message. [`Error::RateLimited`]
//! additionally emits a `Retry-After` header (rounded up to whole seconds)
//! so well-behaved clients can back off without parsing the body. The one
//! HTTP-only rejection, the CSRF origin check, takes its code from here too,
//! so every error response shares one body shape and one code table.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use doorman_core::Error;
use serde::Serialize;

/// JSON body returned with every error response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    /// The error payload, nested under the `error` key.
    pub error: ErrorPayload,
}

/// Stable machine-readable error payload nested under `error`.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorPayload {
    /// Stable machine-readable code clients map to user-facing copy.
    pub code: &'static str,
    /// Human-readable English description; not a stable API.
    pub message: String,
}

/// Wrapper type so we can `impl IntoResponse for ErrorResponse` without
/// orphan-rule trouble — `doorman_core::Error` lives in another crate, but
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
    // Client-facing messages stay coarse for server-side failures: the inner
    // detail (DB driver text, SMTP transport errors, relying-party config) can
    // carry sensitive internals, so it is logged here and replaced with an
    // opaque message. The stable `code` still lets a client distinguish the
    // category. Client errors (4xx) carry domain messages that are safe to
    // surface.
    let message = if status.is_server_error() {
        tracing::error!(error = %err, code, "doorman request failed with internal error");
        "internal server error".to_owned()
    } else {
        err.to_string()
    };
    let mut response = json_error(status, code, message);
    if let Error::RateLimited { retry_after } = err {
        // Round up to whole seconds (floored at 1) so a client that waits the
        // advertised time is past the window, never told to retry while the
        // limiter would still reject. Truncating would under-state the back-off
        // by up to ~1s.
        let round_up = u64::from(retry_after.subsec_nanos() > 0);
        let secs = retry_after.as_secs().saturating_add(round_up).max(1);
        if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

/// The response for a cookie-authenticated state-changing request that failed
/// the CSRF origin check. Not a [`doorman_core::Error`]: the check is an HTTP
/// concern that core never sees.
pub(crate) fn csrf_rejection_response() -> Response {
    json_error(
        StatusCode::FORBIDDEN,
        "csrf_origin_mismatch",
        "CSRF origin check failed".to_owned(),
    )
}

fn json_error(status: StatusCode, code: &'static str, message: String) -> Response {
    let body = ErrorBody {
        error: ErrorPayload { code, message },
    };
    (status, Json(body)).into_response()
}

fn classify(err: &Error) -> (StatusCode, &'static str) {
    match err {
        Error::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
        Error::Email(_) => (StatusCode::INTERNAL_SERVER_ERROR, "email_error"),
        Error::SessionNotFound => (StatusCode::UNAUTHORIZED, "session_not_found"),
        Error::SessionExpired => (StatusCode::UNAUTHORIZED, "session_expired"),
        Error::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
        Error::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid_email"),
        Error::EmailAlreadyInUse => (StatusCode::CONFLICT, "email_already_in_use"),
        Error::InvalidVerificationToken => (StatusCode::BAD_REQUEST, "invalid_verification_token"),
        Error::InvalidPasskeyChallenge => (StatusCode::BAD_REQUEST, "invalid_passkey_challenge"),
        Error::PasskeyNotFound => (StatusCode::NOT_FOUND, "passkey_not_found"),
        Error::PasskeyOwnershipMismatch => (StatusCode::FORBIDDEN, "passkey_ownership_mismatch"),
        Error::PasskeyPossibleCompromise => (StatusCode::FORBIDDEN, "passkey_possible_compromise"),
        Error::UserVerificationRequired => (StatusCode::BAD_REQUEST, "user_verification_required"),
        Error::Webauthn(_) => (StatusCode::BAD_REQUEST, "webauthn_error"),
        Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        Error::InvalidRelyingParty(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid_relying_party")
        }
        Error::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        Error::RecoveryCooldownActive => (StatusCode::CONFLICT, "recovery_cooldown_active"),
        // 401, not 403: the session is valid but the action needs fresh proof.
        // 401 + the machine-readable `reauth_required` code is the step-up
        // convention and keeps the client's retry branch simple (403 reads as
        // "forbidden, don't retry", the wrong signal — the client *should*
        // retry after re-authenticating).
        Error::ReauthRequired => (StatusCode::UNAUTHORIZED, "reauth_required"),
        Error::AccountDisabled => (StatusCode::FORBIDDEN, "account_disabled"),
        Error::SignupNotAllowed => (StatusCode::FORBIDDEN, "signup_not_allowed"),
        Error::ResourceLimitExceeded { .. } => (StatusCode::CONFLICT, "resource_limit_exceeded"),
        Error::InvalidOperatorActor { .. } => (StatusCode::BAD_REQUEST, "invalid_operator_actor"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use doorman_core::error::{EmailError, StorageError};
    use std::time::Duration;

    fn retry_after_secs(retry_after: Duration) -> String {
        let response = error_response(&Error::RateLimited { retry_after });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("retry-after present")
            .to_str()
            .expect("ascii header")
            .to_owned()
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        // 2.4 s rounds up to 3 s: a client waiting the advertised time is past
        // the window.
        assert_eq!(retry_after_secs(Duration::from_millis(2400)), "3");
        // Whole seconds are not inflated.
        assert_eq!(retry_after_secs(Duration::from_secs(2)), "2");
        // Sub-second and zero back-offs floor at 1 s.
        assert_eq!(retry_after_secs(Duration::from_millis(10)), "1");
        assert_eq!(retry_after_secs(Duration::ZERO), "1");
    }

    /// Every `Error` variant must map to a stable `(status, code)`. This pins
    /// the contract a frontend switches on: a mis-edit turning a 4xx into a 5xx,
    /// or renaming a code, fails here.
    #[test]
    fn classify_covers_every_variant() {
        use StatusCode as S;
        let cases: &[(Error, StatusCode, &str)] = &[
            (
                Error::Storage(StorageError::msg("x")),
                S::INTERNAL_SERVER_ERROR,
                "storage_error",
            ),
            (
                Error::Email(EmailError::msg("x")),
                S::INTERNAL_SERVER_ERROR,
                "email_error",
            ),
            (Error::SessionNotFound, S::UNAUTHORIZED, "session_not_found"),
            (Error::SessionExpired, S::UNAUTHORIZED, "session_expired"),
            (Error::UserNotFound, S::NOT_FOUND, "user_not_found"),
            (Error::InvalidEmail, S::BAD_REQUEST, "invalid_email"),
            (
                Error::EmailAlreadyInUse,
                S::CONFLICT,
                "email_already_in_use",
            ),
            (
                Error::InvalidVerificationToken,
                S::BAD_REQUEST,
                "invalid_verification_token",
            ),
            (
                Error::InvalidPasskeyChallenge,
                S::BAD_REQUEST,
                "invalid_passkey_challenge",
            ),
            (Error::PasskeyNotFound, S::NOT_FOUND, "passkey_not_found"),
            (
                Error::PasskeyOwnershipMismatch,
                S::FORBIDDEN,
                "passkey_ownership_mismatch",
            ),
            (
                Error::PasskeyPossibleCompromise,
                S::FORBIDDEN,
                "passkey_possible_compromise",
            ),
            (
                Error::UserVerificationRequired,
                S::BAD_REQUEST,
                "user_verification_required",
            ),
            (
                Error::Webauthn("x".to_owned()),
                S::BAD_REQUEST,
                "webauthn_error",
            ),
            (
                Error::Internal("x".to_owned()),
                S::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            (
                Error::InvalidRelyingParty("x".to_owned()),
                S::INTERNAL_SERVER_ERROR,
                "invalid_relying_party",
            ),
            (
                Error::RateLimited {
                    retry_after: Duration::from_secs(1),
                },
                S::TOO_MANY_REQUESTS,
                "rate_limited",
            ),
            (
                Error::RecoveryCooldownActive,
                S::CONFLICT,
                "recovery_cooldown_active",
            ),
            (Error::ReauthRequired, S::UNAUTHORIZED, "reauth_required"),
            (Error::AccountDisabled, S::FORBIDDEN, "account_disabled"),
            (Error::SignupNotAllowed, S::FORBIDDEN, "signup_not_allowed"),
            (
                Error::ResourceLimitExceeded {
                    resource: "credentials",
                    limit: 5,
                },
                S::CONFLICT,
                "resource_limit_exceeded",
            ),
            (
                Error::InvalidOperatorActor {
                    field: "id",
                    limit: 256,
                },
                S::BAD_REQUEST,
                "invalid_operator_actor",
            ),
        ];
        for (err, status, code) in cases {
            let (got_status, got_code) = classify(err);
            assert_eq!(got_status, *status, "status for {code}");
            assert_eq!(got_code, *code, "code mismatch");
        }
    }

    #[test]
    fn csrf_rejection_uses_the_shared_body() {
        let response = csrf_rejection_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes(response)).expect("json body");
        assert_eq!(body["error"]["code"], "csrf_origin_mismatch");
        assert_eq!(body["error"]["message"], "CSRF origin check failed");
    }

    /// Server-error responses must not leak the inner error detail into the
    /// client-facing message; the stable code is still present.
    #[test]
    fn internal_errors_do_not_leak_detail() {
        let secret = "connection refused to db.internal:5432 (password=hunter2)";
        let response = error_response(&Error::Storage(StorageError::msg(secret)));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = body_bytes(response);
        let body = std::str::from_utf8(&bytes).expect("utf8 body");
        assert!(
            !body.contains("hunter2") && !body.contains("db.internal"),
            "internal detail leaked into response body: {body}"
        );
        assert!(
            body.contains("storage_error"),
            "stable code missing from body: {body}"
        );
    }

    /// `Error::Internal` carries opaque-blob (de)serialisation detail meant for
    /// operators only; like other 5xx it must be coarsened, never surfaced.
    #[test]
    fn internal_variant_does_not_leak_detail() {
        let secret = "deserialise credential: unexpected token at byte 0xdeadbeef";
        let response = error_response(&Error::Internal(secret.to_owned()));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = body_bytes(response);
        let body = std::str::from_utf8(&bytes).expect("utf8 body");
        assert!(
            !body.contains("deadbeef") && !body.contains("deserialise credential"),
            "internal detail leaked into response body: {body}"
        );
        assert!(
            body.contains("internal_error"),
            "stable code missing from body: {body}"
        );
    }

    fn body_bytes(response: Response) -> Vec<u8> {
        // The error body is a small in-memory JSON value, so collecting it
        // synchronously via a minimal runtime is fine for a unit test.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body")
                .to_vec()
        })
    }
}
