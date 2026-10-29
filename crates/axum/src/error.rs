use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use doorman_core::Error;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: ErrorPayload,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorPayload {
    pub code: &'static str,
    pub message: String,
}

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
    let message = if status.is_server_error() {
        tracing::error!(error = %err, code, "doorman request failed with internal error");
        "internal server error".to_owned()
    } else {
        err.to_string()
    };
    let mut response = json_error(status, code, message);
    if let Error::RateLimited { retry_after } = err {
        let round_up = u64::from(retry_after.subsec_nanos() > 0);
        let secs = retry_after.as_secs().saturating_add(round_up).max(1);
        if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

// The session layer refuses these before any route runs, so they have no domain error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerRefusal {
    CrossOrigin,
    AmbiguousSessionToken,
}

impl IntoResponse for LayerRefusal {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            LayerRefusal::CrossOrigin => (
                StatusCode::FORBIDDEN,
                "csrf_origin_mismatch",
                "CSRF origin check failed",
            ),
            LayerRefusal::AmbiguousSessionToken => (
                StatusCode::BAD_REQUEST,
                "ambiguous_session_token",
                "the request carries both a session cookie and a bearer token",
            ),
        };
        json_error(status, code, message.to_owned())
    }
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
        Error::BearerSessionNotAllowed => (StatusCode::FORBIDDEN, "bearer_session_not_allowed"),
        Error::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
        Error::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid_email"),
        Error::InvalidPasskeyName => (StatusCode::BAD_REQUEST, "invalid_passkey_name"),
        Error::EmailAlreadyInUse => (StatusCode::CONFLICT, "email_already_in_use"),
        Error::InvalidEmailLink => (StatusCode::BAD_REQUEST, "invalid_email_link"),
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
        Error::RecoveryCoolDownActive => (StatusCode::CONFLICT, "recovery_cool_down_active"),
        Error::ReauthRequired => (StatusCode::UNAUTHORIZED, "reauth_required"),
        Error::ActingSessionNotRevocable => {
            (StatusCode::BAD_REQUEST, "acting_session_not_revocable")
        }
        Error::UserDisabled => (StatusCode::FORBIDDEN, "user_disabled"),
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
        assert_eq!(retry_after_secs(Duration::from_millis(2400)), "3");
        assert_eq!(retry_after_secs(Duration::from_secs(2)), "2");
        assert_eq!(retry_after_secs(Duration::from_millis(10)), "1");
        assert_eq!(retry_after_secs(Duration::ZERO), "1");
    }

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
            (
                Error::BearerSessionNotAllowed,
                S::FORBIDDEN,
                "bearer_session_not_allowed",
            ),
            (Error::UserNotFound, S::NOT_FOUND, "user_not_found"),
            (Error::InvalidEmail, S::BAD_REQUEST, "invalid_email"),
            (
                Error::InvalidPasskeyName,
                S::BAD_REQUEST,
                "invalid_passkey_name",
            ),
            (
                Error::EmailAlreadyInUse,
                S::CONFLICT,
                "email_already_in_use",
            ),
            (
                Error::InvalidEmailLink,
                S::BAD_REQUEST,
                "invalid_email_link",
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
                Error::RecoveryCoolDownActive,
                S::CONFLICT,
                "recovery_cool_down_active",
            ),
            (Error::ReauthRequired, S::UNAUTHORIZED, "reauth_required"),
            (
                Error::ActingSessionNotRevocable,
                S::BAD_REQUEST,
                "acting_session_not_revocable",
            ),
            (Error::UserDisabled, S::FORBIDDEN, "user_disabled"),
            (Error::SignupNotAllowed, S::FORBIDDEN, "signup_not_allowed"),
            (
                Error::ResourceLimitExceeded {
                    resource: "passkeys",
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
    fn layer_refusals_use_the_shared_body() {
        let cases = [
            (
                LayerRefusal::CrossOrigin,
                StatusCode::FORBIDDEN,
                "csrf_origin_mismatch",
            ),
            (
                LayerRefusal::AmbiguousSessionToken,
                StatusCode::BAD_REQUEST,
                "ambiguous_session_token",
            ),
        ];
        for (refusal, status, code) in cases {
            let response = refusal.into_response();
            assert_eq!(response.status(), status, "{refusal:?}");
            let body: serde_json::Value =
                serde_json::from_slice(&body_bytes(response)).expect("json body");
            assert_eq!(body["error"]["code"], code, "{refusal:?}");
        }
    }

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

    #[test]
    fn internal_variant_does_not_leak_detail() {
        let secret = "deserialise passkey: unexpected token at byte 0xdeadbeef";
        let response = error_response(&Error::Internal(secret.to_owned()));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = body_bytes(response);
        let body = std::str::from_utf8(&bytes).expect("utf8 body");
        assert!(
            !body.contains("deadbeef") && !body.contains("deserialise passkey"),
            "internal detail leaked into response body: {body}"
        );
        assert!(
            body.contains("internal_error"),
            "stable code missing from body: {body}"
        );
    }

    fn body_bytes(response: Response) -> Vec<u8> {
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
