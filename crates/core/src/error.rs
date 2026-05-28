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

/// Errors returned by bauth managers.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Email(#[from] EmailError),

    #[error("session not found")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,

    #[error("user not found")]
    UserNotFound,

    #[error("user has no email address on file")]
    UserHasNoEmail,

    #[error("invalid email address")]
    InvalidEmail,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("email address is not verified")]
    EmailNotVerified,

    #[error("email address is already in use")]
    EmailAlreadyTaken,

    #[error("email address is already verified")]
    EmailAlreadyVerified,

    #[error("verification token is invalid or expired")]
    InvalidVerificationToken,

    #[error("passkey ceremony is invalid or has expired")]
    InvalidPasskeyChallenge,

    #[error("passkey credential is not registered")]
    PasskeyNotFound,

    #[error("passkey credential does not belong to the expected user")]
    PasskeyOwnershipMismatch,

    #[error("webauthn ceremony failed: {0}")]
    Webauthn(String),

    #[error("invalid relying party configuration: {0}")]
    InvalidRelyingParty(String),

    #[error("rate limit exceeded; retry after {} ms", retry_after.as_millis())]
    RateLimited { retry_after: Duration },

    #[error(
        "the action is blocked because the session is within the post-recovery cool-down window"
    )]
    RecoveryCooldownActive,
}

/// Opaque storage-backend failure.
#[derive(Debug, Error)]
#[error("storage error: {0}")]
pub struct StorageError(BoxError);

impl StorageError {
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(err))
    }

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
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(err))
    }

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
