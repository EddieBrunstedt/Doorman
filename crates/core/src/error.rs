use std::fmt;
use std::time::Duration;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Email(#[from] EmailError),

    #[error("session not found")]
    SessionNotFound,

    #[error("user not found")]
    UserNotFound,

    #[error("invalid email address")]
    InvalidEmail,

    #[error("email address is already in use by another user")]
    EmailAlreadyInUse,

    #[error("email link is invalid or expired")]
    InvalidEmailLink,

    #[error("passkey ceremony is invalid or has expired")]
    InvalidPasskeyChallenge,

    #[error("passkey is not registered")]
    PasskeyNotFound,

    #[error("passkey does not belong to the expected user")]
    PasskeyOwnershipMismatch,

    #[error(
        "passkey authentication rejected: signature counter regressed, indicating a possible cloned authenticator"
    )]
    PasskeyPossibleCompromise,

    #[error("passkey ceremony did not include user verification")]
    UserVerificationRequired,

    #[error("webauthn ceremony failed: {0}")]
    Webauthn(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("invalid relying party configuration: {0}")]
    InvalidRelyingParty(String),

    #[error("rate limit exceeded; retry after {} ms", retry_after.as_millis())]
    RateLimited { retry_after: Duration },

    #[error("the action is refused because the session is in its recovery cool-down")]
    RecoveryCoolDownActive,

    #[error("the action requires a fresh passkey re-authentication")]
    ReauthRequired,

    #[error("user is disabled")]
    UserDisabled,

    #[error("signup is not allowed")]
    SignupNotAllowed,

    #[error("per-user limit for {resource} reached ({limit})")]
    ResourceLimitExceeded { resource: &'static str, limit: u32 },

    #[error("operator actor field `{field}` exceeds the {limit}-byte limit")]
    InvalidOperatorActor { field: &'static str, limit: usize },
}

#[derive(Debug, Error)]
#[error("storage error: {inner}")]
pub struct StorageError {
    kind: StorageErrorKind,
    inner: BoxError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageErrorKind {
    Conflict,
    NotFound,
    Backend,
}

impl StorageError {
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: StorageErrorKind::Backend,
            inner: Box::new(err),
        }
    }

    pub fn msg(message: impl Into<String>) -> Self {
        Self::with_kind(StorageErrorKind::Backend, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::with_kind(StorageErrorKind::Conflict, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::with_kind(StorageErrorKind::NotFound, message)
    }

    pub fn kind(&self) -> StorageErrorKind {
        self.kind
    }

    fn with_kind(kind: StorageErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            inner: Box::new(MessageError(message.into())),
        }
    }
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;

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

pub type EmailResult<T> = std::result::Result<T, EmailError>;

#[derive(Debug)]
struct MessageError(String);

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MessageError {}
