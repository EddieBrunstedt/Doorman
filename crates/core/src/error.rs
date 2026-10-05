//! Shared error types returned by core managers and storage adapters.
//!
//! [`enum@Error`] is the manager-facing error enum. [`StorageError`] and
//! [`EmailError`] wrap backend-specific failures without exposing their
//! concrete types in public APIs; a [`StorageError`] still tells a conflict
//! or a missing row apart from an outage through [`StorageErrorKind`].

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

    /// A passkey ceremony completed without user verification (the authenticator
    /// did not set the UV flag). doorman requires user-verified passkeys on every
    /// ceremony, so the assertion/registration is rejected.
    #[error("passkey ceremony did not include user verification")]
    UserVerificationRequired,

    /// A WebAuthn ceremony failed verification for some other reason. This is a
    /// client-facing rejection of the presented assertion/registration; the
    /// detail comes from `webauthn-rs` and is safe to surface.
    #[error("webauthn ceremony failed: {0}")]
    Webauthn(String),

    /// An internal invariant broke — e.g. a stored opaque blob (credential or
    /// ceremony state) failed to (de)serialise, or a library handle we built
    /// ourselves returned an unexpected shape. The caller did nothing wrong, so
    /// this maps to a server error and the detail is for operators, not clients
    /// (the HTTP layer logs it and returns an opaque message).
    #[error("internal error: {0}")]
    Internal(String),

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

    /// The action requires a fresh passkey re-authentication that was not
    /// supplied (or whose challenge was missing/expired). The session is
    /// otherwise valid; the caller should run the
    /// [`ReauthManager`](crate::reauth::ReauthManager) `start` ceremony and
    /// retry the action carrying the resulting proof.
    #[error("the action requires a fresh passkey re-authentication")]
    ReauthRequired,

    /// The account has been disabled by an operator. Both authentication and
    /// recovery refuse a disabled account until it is re-enabled; this is a
    /// deliberate refusal, distinct from a missing or expired session.
    #[error("account is disabled")]
    AccountDisabled,

    /// The host's [`SignupPolicy`](crate::signup::SignupPolicy) rejected the
    /// request with [`SignupDecision::Deny`](crate::signup::SignupDecision::Deny).
    /// The host's reason, if any, is recorded at the denial site rather than
    /// carried here, so nothing account-specific reaches the wire.
    #[error("signup is not allowed")]
    SignupNotAllowed,

    /// A configured per-user resource cap was reached.
    #[error("per-user limit for {resource} reached ({limit})")]
    ResourceLimitExceeded {
        /// Which capped resource was exhausted (e.g. `"credentials"`,
        /// `"pending registrations"`).
        resource: &'static str,
        /// The configured cap that was hit.
        limit: u32,
    },

    /// An operator actor descriptor field exceeded its documented length
    /// bound and was rejected rather than silently truncated.
    #[error("operator actor field `{field}` exceeds the {limit}-byte limit")]
    InvalidOperatorActor {
        /// Which field was too long (e.g. `"id"`, `"correlation_id"`).
        field: &'static str,
        /// The byte-length cap that was exceeded.
        limit: usize,
    },
}

/// Storage-backend failure, opaque apart from its [`kind`](Self::kind).
///
/// Adapters report a uniqueness violation as [`StorageErrorKind::Conflict`]
/// and a write to a missing row as [`StorageErrorKind::NotFound`], so core
/// can let the store's own constraints decide a race instead of reading
/// first. Everything else is [`StorageErrorKind::Backend`].
#[derive(Debug, Error)]
#[error("storage error: {inner}")]
pub struct StorageError {
    kind: StorageErrorKind,
    inner: BoxError,
}

/// What a [`StorageError`] reports, as far as a caller can act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageErrorKind {
    /// The write would break a uniqueness rule: another row already holds
    /// the id, email address, credential id or token hash. Nothing was
    /// written.
    Conflict,
    /// The write targets a row that does not exist. Nothing was written.
    NotFound,
    /// The backend failed, or returned data that does not decode.
    Backend,
}

impl StorageError {
    /// Wrap a concrete backend error as a [`StorageErrorKind::Backend`]
    /// failure.
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: StorageErrorKind::Backend,
            inner: Box::new(err),
        }
    }

    /// Build a [`StorageErrorKind::Backend`] failure from a plain message.
    pub fn msg(message: impl Into<String>) -> Self {
        Self::with_kind(StorageErrorKind::Backend, message)
    }

    /// Build a [`StorageErrorKind::Conflict`] from a plain message.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::with_kind(StorageErrorKind::Conflict, message)
    }

    /// Build a [`StorageErrorKind::NotFound`] from a plain message.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::with_kind(StorageErrorKind::NotFound, message)
    }

    /// What this failure reports.
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
