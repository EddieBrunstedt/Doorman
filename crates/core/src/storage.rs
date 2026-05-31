//! Persistence contracts the managers run against.
//!
//! The `*Store` traits in this module are the boundary between
//! `bauth-core` and the host's database. The managers do not know or
//! care how rows land on disk — they only call the trait methods.
//!
//! ## Picking an adapter
//!
//! - **SQLx hosts** (SQLite or Postgres) should depend on `bauth-sqlx`
//!   and let `SqliteStorage::storage()` / `PostgresStorage::storage()`
//!   populate the [`Storage`] composite for them.
//! - **Hosts on other stacks** (Diesel, sea-orm, Redis, a bespoke
//!   driver) implement these traits directly. The in-memory stores in
//!   [`crate::memory`] are a worked reference for what each method must
//!   guarantee — in particular the atomic `take_*` / `consume_*`
//!   semantics that single-use tokens rely on.
//!
//! The trait surface is the contract. Adapter crates (`bauth-sqlx` and
//! any future siblings) are conveniences on top of it, not part of it.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{DiscoverableAuthentication, Passkey, PasskeyRegistration};

use crate::error::StorageResult;
pub use crate::token::TokenHash;

/// Composite handle to every storage trait the managers need.
///
/// Bundles the per-concern `Arc<dyn ...>` stores so a host can pass
/// one value to the high-level builder (or assemble it once and reuse it
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
    pub verification_tokens: Arc<dyn VerificationTokenStore>,
    pub passkey_credentials: Arc<dyn PasskeyCredentialStore>,
    pub passkey_challenges: Arc<dyn PasskeyChallengeStore>,
}

/// Stable local user identifier.
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

/// Stable server-side session identifier.
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

/// Local user record shared by all auth methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Persisted session row keyed by a hashed bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: TokenHash,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// When set, the session was issued via the recovery flow and any
    /// destructive action (delete passkey, revoke other sessions, etc.) must
    /// be refused with [`crate::error::Error::RecoveryCooldownActive`] until
    /// this instant passes. `None` means an ordinary session with no
    /// restriction.
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

impl Session {
    /// Return the active recovery cool-down deadline, if any. The comparison
    /// is `now < cool-down`; sessions whose cool-down has already elapsed are
    /// treated as unrestricted and return `None`.
    pub fn active_recovery_cooldown_until(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.recovery_cooldown_until
            .as_ref()
            .filter(|until| now < **until)
            .cloned()
    }

    /// Returns `true` if the session is currently restricted by a recovery
    /// cool-down. The comparison is `now < cool-down`; sessions whose
    /// cool-down has already elapsed are treated as unrestricted.
    pub fn is_in_recovery_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.active_recovery_cooldown_until(now).is_some()
    }
}

/// Persistence contract for local user records.
#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: User) -> StorageResult<()>;

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>>;

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>>;

    async fn update_user(&self, user: User) -> StorageResult<()>;

    async fn delete_user(&self, id: UserId) -> StorageResult<()>;
}

/// Persistence contract for server-side sessions.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, session: Session) -> StorageResult<()>;

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>>;

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>>;

    /// Return every unexpired session belonging to a user. Implementations
    /// MAY return expired sessions; callers (e.g. `SessionManager::list_for_user`)
    /// are expected to filter on `expires_at` so adapters are not forced to
    /// re-implement the expiry rule.
    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>>;

    async fn delete_session(&self, id: SessionId) -> StorageResult<()>;

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    /// Delete every session belonging to `user_id` *except* the one with
    /// `except`. Implementations return the number of sessions removed.
    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64>;

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
    /// When set, sessions created by authenticating with this passkey may
    /// inherit the recovery cool-down restriction until this instant. `None`
    /// means the credential is unrestricted.
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

/// Metadata-only view of a registered passkey.
///
/// Carries every field a management UI needs to list a user's credentials
/// (id, friendly name, timestamps, cool-down) *without* the `webauthn-rs`
/// [`Passkey`] credential blob. The listing path
/// ([`PasskeyCredentialStore::list_passkey_summaries_for_user`]) returns
/// this so an adapter never has to deserialise the blob just to render the
/// "your passkeys" view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    /// Raw credential id, matching [`StoredPasskey::credential_id`].
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    /// Friendly device name set at registration, if any.
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

impl From<StoredPasskey> for PasskeySummary {
    fn from(value: StoredPasskey) -> Self {
        Self {
            credential_id: value.credential_id,
            user_id: value.user_id,
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            recovery_cooldown_until: value.recovery_cooldown_until,
        }
    }
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
    /// Optional recovery cool-down metadata associated with this in-progress
    /// registration ceremony.
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

/// In-progress discoverable passkey authentication ceremony state.
#[derive(Debug, Clone)]
pub struct StoredPasskeyAuthentication {
    pub id: PasskeyChallengeId,
    pub state: DiscoverableAuthentication,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Persistence contract for registered passkey credentials.
#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    /// Update an existing passkey, typically to advance its signature
    /// counter or backup-state flags after a successful authentication.
    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>>;

    /// List the user's credentials as metadata-only [`PasskeySummary`]
    /// values. Adapters MUST satisfy this without deserialising the
    /// credential blob; it backs the "your passkeys" listing/count paths
    /// where the blob is never read.
    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>>;

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>>;

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()>;
}

/// Persistence contract for in-progress passkey ceremony state.
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

/// What a verification token authorises. Tokens are kept distinct per
/// purpose so that a leaked link of one kind can never act as a link of
/// another kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPurpose {
    Signup,
    Recovery,
}

/// A single-use, time-limited token issued for an out-of-band flow such
/// as the signup link emailed to a prospective user. Stored keyed by token
/// hash so that a database breach does not yield usable tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationToken {
    pub token_hash: TokenHash,
    pub user_id: UserId,
    pub purpose: VerificationPurpose,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Persistence contract for single-use verification tokens.
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

    /// Drop all outstanding tokens of a given purpose for a user. Used
    /// when issuing a fresh token to invalidate older ones.
    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}
