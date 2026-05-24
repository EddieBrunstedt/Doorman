use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::StorageResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// SHA-256 digest of a session token. Sessions are stored keyed by hash so
/// that a database breach does not yield usable tokens.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenHash(pub [u8; 32]);

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenHash(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: TokenHash,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: User) -> StorageResult<()>;

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>>;

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>>;

    async fn update_user(&self, user: User) -> StorageResult<()>;

    async fn delete_user(&self, id: UserId) -> StorageResult<()>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, session: Session) -> StorageResult<()>;

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>>;

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>>;

    async fn delete_session(&self, id: SessionId) -> StorageResult<()>;

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

/// A stored Argon2id password hash bound to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCredential {
    pub user_id: UserId,
    /// The PHC-formatted hash string, including algorithm parameters and salt.
    pub hash: String,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait PasswordCredentialStore: Send + Sync {
    /// Insert or replace the password credential for a user. Implementations
    /// must overwrite any previous credential for the same `user_id`.
    async fn set_password(&self, credential: PasswordCredential) -> StorageResult<()>;

    async fn get_password(&self, user_id: UserId) -> StorageResult<Option<PasswordCredential>>;

    async fn delete_password(&self, user_id: UserId) -> StorageResult<()>;
}

/// What a verification token authorises. Tokens are kept distinct per
/// purpose so that a leaked password-reset link can never act as an
/// email-verification link, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPurpose {
    EmailVerification,
    PasswordReset,
}

/// A single-use, time-limited token issued for an out-of-band flow such
/// as email verification or password reset. Stored keyed by token hash so
/// that a database breach does not yield usable tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationToken {
    pub token_hash: TokenHash,
    pub user_id: UserId,
    pub purpose: VerificationPurpose,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait VerificationTokenStore: Send + Sync {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()>;

    /// Atomically look up and remove a token matching `(hash, purpose)`.
    /// Implementations MUST delete the token before returning it, so the
    /// same token can never be redeemed twice.
    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>>;

    async fn find_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>>;

    /// Drop all outstanding tokens of a given purpose for a user. Used
    /// when issuing a fresh token to invalidate older ones.
    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}
