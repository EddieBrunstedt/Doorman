//! Shared error types returned by core managers and storage adapters.
//!
//! [`enum@Error`] is the manager-facing error enum. [`StorageError`] and
//! [`EmailError`] wrap backend-specific failures without exposing their
//! concrete types in public APIs.

use std::fmt;
use std::time::Duration;

use thiserror::Error;

/// Result alias used by public manager APIs.
pub type Result<T> = std::result::Result<T, Error>;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned by doorman managers.
#[derive(Debug, Error)]
pub enum Error {
    /// A storage backend operation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// An email transport operation failed.
    #[error(transparent)]
    Email(#[from] EmailError),

    /// No session matched the presented token.
    #[error("session not found")]
    SessionNotFound,

    /// The session existed but has passed its expiry.
    #[error("session expired")]
    SessionExpired,

    /// No user matched the lookup.
    #[error("user not found")]
    UserNotFound,

    /// The supplied email address did not pass validation.
    #[error("invalid email address")]
    InvalidEmail,

    /// The target email address is already registered to another account.
    #[error("email address is already in use by another account")]
    EmailAlreadyInUse,

    /// The verification token was unknown, already consumed, or expired.
    #[error("verification token is invalid or expired")]
    InvalidVerificationToken,

    /// The passkey ceremony was unknown, already consumed, or expired.
    #[error("passkey ceremony is invalid or has expired")]
    InvalidPasskeyChallenge,

    /// The asserted credential is not registered.
    #[error("passkey credential is not registered")]
    PasskeyNotFound,

    /// The credential does not belong to the expected user (e.g. a
    /// user-handle binding that does not match the stored owner).
    #[error("passkey credential does not belong to the expected user")]
    PasskeyOwnershipMismatch,

    /// The signature counter regressed, indicating a possible cloned
    /// authenticator; the assertion is rejected.
    #[error(
        "passkey authentication rejected: signature counter regressed, indicating a possible cloned authenticator"
    )]
    PasskeyPossibleCompromise,

    /// A WebAuthn ceremony failed verification for some other reason.
    #[error("webauthn ceremony failed: {0}")]
    Webauthn(String),

    /// The relying-party configuration (origin / rp_id / rp_name) is invalid.
    #[error("invalid relying party configuration: {0}")]
    InvalidRelyingParty(String),

    /// A rate-limit policy rejected the request.
    #[error("rate limit exceeded; retry after {} ms", retry_after.as_millis())]
    RateLimited {
        /// How long the caller should wait before retrying.
        retry_after: Duration,
    },

    /// The action is blocked by the post-recovery cool-down.
    #[error(
        "the action is blocked because the session is within the post-recovery cool-down window"
    )]
    RecoveryCooldownActive,

    /// A configured per-user resource cap was reached.
    #[error("per-user limit for {resource} reached ({limit})")]
    ResourceLimitExceeded {
        /// Which capped resource was exhausted (e.g. `"credentials"`,
        /// `"pending registrations"`).
        resource: &'static str,
        /// The configured cap that was hit.
        limit: u32,
    },
}

/// Opaque storage-backend failure.
#[derive(Debug, Error)]
#[error("storage error: {0}")]
pub struct StorageError(BoxError);

impl StorageError {
    /// Wrap a concrete backend error as an opaque [`StorageError`].
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(err))
    }

    /// Build a [`StorageError`] from a plain message (no source error).
    pub fn msg(message: impl Into<String>) -> Self {
        Self(Box::new(MessageError(message.into())))
    }
}

/// Result alias used by storage traits.
pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// Opaque email-transport failure.
#[derive(Debug, Error)]
#[error("email error: {0}")]
pub struct EmailError(BoxError);

impl EmailError {
    /// Wrap a concrete transport error as an opaque [`EmailError`].
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(err))
    }

    /// Build an [`EmailError`] from a plain message (no source error).
    pub fn msg(message: impl Into<String>) -> Self {
        Self(Box::new(MessageError(message.into())))
    }
}

/// Result alias used by email transports.
pub type EmailResult<T> = std::result::Result<T, EmailError>;

#[derive(Debug)]
struct MessageError(String);

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MessageError {}
