use std::fmt;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

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

    #[error("password does not meet policy: minimum length is {min_length}")]
    WeakPassword { min_length: usize },

    #[error("password hashing failed: {0}")]
    PasswordHashing(String),

    #[error("stored password hash is corrupt")]
    PasswordHashCorrupt,
}

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
