use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::error::StorageResult;

/// Composite handle to every storage trait the managers need.
///
/// Bundles the eight per-concern `Arc<dyn ...>` stores so a host can pass
/// one value to the quickstart builder (or assemble it once and reuse it
/// across multiple managers) instead of threading each store through by
/// hand. Storage adapters typically expose a `fn storage(&self) -> Storage`
/// that returns this struct populated against a single backend; hosts that
/// want to mix backends (e.g. SQLx for most stores, a Redis-backed
/// `SessionStore` for cross-process revoke speed) construct the struct
/// directly and swap individual fields.
#[derive(Clone)]
pub struct Storage {
    pub users: Arc<dyn UserStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub passwords: Arc<dyn PasswordCredentialStore>,
    pub verification_tokens: Arc<dyn VerificationTokenStore>,
    pub passkey_credentials: Arc<dyn PasskeyCredentialStore>,
    pub passkey_challenges: Arc<dyn PasskeyChallengeStore>,
    pub oauth_identities: Arc<dyn OAuthIdentityStore>,
    pub oauth_states: Arc<dyn OAuthStateStore>,
}

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
/// that a database breach does not yield usable tokens. Equality is
/// constant-time so that any in-process comparison (including HashMap
/// bucket disambiguation) does not leak the matched prefix length via
/// timing.
#[derive(Clone, Copy, Hash, Serialize, Deserialize)]
pub struct TokenHash(pub [u8; 32]);

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for TokenHash {}

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

/// Identifier for an in-progress passkey ceremony (registration or
/// authentication). The plaintext value is returned to the client so it
/// can submit it back at the `finish` step; the actual ceremony state is
/// only ever held server-side via [`PasskeyChallengeStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasskeyChallengeId(pub Uuid);

impl PasskeyChallengeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PasskeyChallengeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PasskeyChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A passkey credential bound to a user. The `passkey` field carries the
/// serialisable `webauthn-rs` representation; a host adapter that
/// persists this to a database is expected to (de)serialise it as JSON or
/// CBOR.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    /// Raw credential id, as a byte string. Duplicates `passkey.cred_id()`
    /// but kept top-level so storage backends can index on it without
    /// having to deserialise the passkey blob.
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    pub passkey: Passkey,
    /// Optional friendly device name set by the user at registration time
    /// ("Eddie's iPhone", "Yubikey 5"). The library does not interpret it.
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// In-progress passkey registration ceremony state. The `state` field is
/// a `webauthn-rs` opaque value that must be preserved verbatim between
/// start and finish.
#[derive(Debug, Clone)]
pub struct StoredPasskeyRegistration {
    pub id: PasskeyChallengeId,
    pub user_id: UserId,
    pub state: PasskeyRegistration,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// In-progress passkey authentication ceremony state.
#[derive(Debug, Clone)]
pub struct StoredPasskeyAuthentication {
    pub id: PasskeyChallengeId,
    /// The user the ceremony was started for, if username-first. `None`
    /// is reserved for future usernameless / discoverable flows.
    pub user_id: Option<UserId>,
    pub state: PasskeyAuthentication,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    /// Update an existing passkey, typically to advance its signature
    /// counter or backup-state flags after a successful authentication.
    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>>;

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>>;

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()>;
}

#[async_trait]
pub trait PasskeyChallengeStore: Send + Sync {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()>;

    /// Atomically look up and remove a registration challenge. MUST
    /// delete before returning so the same challenge cannot be replayed.
    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>>;

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()>;

    /// Atomically look up and remove an authentication challenge.
    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

/// A federated identity issued by an OAuth provider, bound to a local user.
/// One user can own multiple identities (e.g. Google + GitHub); a single
/// provider+subject pair belongs to at most one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthIdentity {
    /// Stable identifier for the provider, matching
    /// [`OAuthProvider::name`](crate::oauth::OAuthProvider::name).
    pub provider: String,
    /// Provider-side stable user id (the OIDC `sub` claim, GitHub's
    /// numeric user id, etc.). Never the email — emails change.
    pub subject: String,
    pub user_id: UserId,
    /// Email address as reported by the provider at link time, lower-cased.
    /// Stored for convenience; the authoritative copy lives on [`User`].
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait OAuthIdentityStore: Send + Sync {
    /// Persist a freshly linked identity. Implementations MUST reject the
    /// insert if a record already exists for `(provider, subject)`.
    async fn link(&self, identity: OAuthIdentity) -> StorageResult<()>;

    async fn find_by_provider_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> StorageResult<Option<OAuthIdentity>>;

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<OAuthIdentity>>;

    async fn unlink(&self, provider: &str, subject: &str) -> StorageResult<()>;
}

/// Identifier for an in-progress OAuth authorization. The plaintext value is
/// returned to the client (typically as a cookie + as the `state` URL
/// parameter sent to the provider), and is used as the lookup key when the
/// callback arrives. High-entropy random; never derived from user data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OAuthStateId(pub String);

impl fmt::Display for OAuthStateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Server-side state for an OAuth authorization round-trip, persisted
/// between the `start` and `finish` calls. The PKCE verifier never leaves
/// the server; the `state_id` doubles as the CSRF token echoed back by the
/// provider.
#[derive(Debug, Clone)]
pub struct PendingOAuthAuthorization {
    pub state_id: OAuthStateId,
    /// Provider name this authorization targets. Must match
    /// [`OAuthIdentity::provider`].
    pub provider: String,
    /// PKCE code verifier (RFC 7636). Sent verbatim to the provider's
    /// token endpoint at exchange time.
    pub pkce_verifier: String,
    /// Redirect URI the provider was told to use. Echoed back at token
    /// exchange because OAuth servers tie the code to this exact value.
    pub redirect_uri: String,
    /// If `Some`, the caller is an already-authenticated user adding an
    /// identity to their account. The new identity will be linked to this
    /// user instead of provisioning a new one.
    pub link_user_id: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    async fn put(&self, value: PendingOAuthAuthorization) -> StorageResult<()>;

    /// Atomically look up and remove a pending authorization. MUST delete
    /// before returning so the same state cannot be replayed.
    async fn take(
        &self,
        state_id: &OAuthStateId,
    ) -> StorageResult<Option<PendingOAuthAuthorization>>;

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
