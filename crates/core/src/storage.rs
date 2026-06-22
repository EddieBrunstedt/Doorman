//! Persistence contracts the managers run against.
//!
//! The `*Store` traits in this module are the boundary between
//! `doorman-core` and the host's database. The managers do not know or
//! care how rows land on disk — they only call the trait methods.
//!
//! ## Picking an adapter
//!
//! - **Single-backend hosts** depend on a first-party adapter — `doorman-sqlx`
//!   (SQLite/Postgres/MySQL), `doorman-dynamodb`, `doorman-mongodb`, or
//!   `doorman-redb` — and let its `all_stores()` populate the [`Storage`]
//!   composite in one call.
//! - **Multi-replica deployments** can move the ephemeral, TTL-bearing
//!   stores ([`SessionStore`], [`VerificationTokenStore`],
//!   [`PasskeyChallengeStore`]) and the rate limiter onto Redis or Valkey
//!   with `doorman-redis`, paired with a SQL backend for the
//!   system-of-record stores. Assemble a [`Storage`] literal naming each
//!   backend per trait (see below); Redis cannot fill `users` /
//!   `passkey_credentials`, so it offers no `all_stores()`.
//! - **Hosts on other stacks** (Diesel, sea-orm, a bespoke driver)
//!   implement these traits directly. The in-memory stores in
//!   [`crate::memory`] are a worked reference for what each method must
//!   guarantee — in particular the atomic `take_*` / `consume_*`
//!   semantics that single-use tokens rely on.
//!
//! ## Choosing where each store lives
//!
//! Backends are chosen per trait. The system-of-record stores ([`UserStore`],
//! [`PasskeyCredentialStore`]) hold data that never expires and wants
//! relational guarantees, so they belong in SQL. The ephemeral stores carry a
//! TTL and benefit from a shared, fast backend in a multi-replica deployment.
//! The canonical wiring is an explicit [`Storage`] struct literal — one line
//! per trait, the compiler enforcing that all five are set — with the
//! single-backend `all_stores()` shortcut for hosts that keep everything in one
//! place. The rate limiter is a separate collaborator wired on the builder, not
//! part of [`Storage`].
//!
//! ## Implementing a key-value adapter
//!
//! Adapters on a key-value store (Redis/Valkey, or similar) without
//! per-member-TTL collections must honour four expectations the SQL adapters
//! get for free:
//!
//! - **Atomic take.** `consume_token`, `take_registration`, and
//!   `take_authentication` must delete-before-return so that under concurrency
//!   exactly one caller observes the value (Redis's `GETDEL` is one way).
//! - **Secondary indexes are best-effort.** A user-scoped index of ids/hashes
//!   may briefly point at a row whose TTL already evicted it. Reads that resolve
//!   members ([`SessionStore::list_for_user`] and friends) must skip and
//!   opportunistically drop such dangling members, and the manager re-applies
//!   the `expires_at > now` filter, so correctness never depends on the index
//!   being pristine.
//! - **`purge_expired` is a real reclamation pass, not a no-op.** TTL evicts the
//!   value keys, but dangling index members for users who never return are
//!   reclaimed only by `purge_expired`. It returns the count reclaimed (expired
//!   rows plus any dangling index members it drops, so the count MAY exceed the
//!   rows deleted); the conformance suite asserts a non-zero count.
//! - **`create_*` MAY be an upsert.** The reference stores reject a duplicate id
//!   or token hash; a key-value adapter keyed directly on those (random UUIDs,
//!   256-bit hashes) MAY instead overwrite with a plain `SET`. The managers
//!   never issue two creates under one id, so the distinction is unobservable in
//!   practice — do not rely on `create_session`, `create_token`, or
//!   `put_registration` returning an error on a collision.
//!
//! The trait surface is the contract. Adapter crates (`doorman-sqlx`,
//! `doorman-redis`, and any future siblings) are conveniences on top of it, not
//! part of it. The published `doorman-conformance` crate exercises the contract
//! against any adapter.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::StorageResult;
pub use crate::token::TokenHash;

/// Composite handle to every storage trait the managers need.
///
/// Bundles the per-concern `Arc<dyn ...>` stores so a host can pass
/// one value to the high-level builder (or assemble it once and reuse it
/// across multiple managers) instead of threading each store through by
/// hand. Storage adapters that can fill every field typically expose a
/// `fn all_stores(&self) -> Storage` that returns this struct populated against
/// a single backend; hosts that want to mix backends (e.g. SQLx for most
/// stores, a Redis-backed `SessionStore` for cross-process revoke speed)
/// construct the struct directly and swap individual fields.
#[derive(Clone)]
pub struct Storage {
    /// Local user records.
    pub users: Arc<dyn UserStore>,
    /// Server-side session rows.
    pub sessions: Arc<dyn SessionStore>,
    /// Single-use verification tokens (signup, recovery, email change).
    pub verification_tokens: Arc<dyn VerificationTokenStore>,
    /// Registered passkey credentials.
    pub passkey_credentials: Arc<dyn PasskeyCredentialStore>,
    /// In-progress passkey ceremony state.
    pub passkey_challenges: Arc<dyn PasskeyChallengeStore>,
}

/// Stable local user identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    /// Generate a fresh random identifier (UUIDv4).
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
    /// Generate a fresh random identifier (UUIDv4).
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

/// Whether a user account is usable or has been frozen by an operator.
///
/// `Disabled` is a reversible hold: both authentication and recovery refuse a
/// disabled account, and an operator can return it to `Active`. The timestamp
/// lives inside the `Disabled` variant rather than as a separate nullable
/// column so an account can never be "disabled with no `at`" or "active with a
/// stray `at`".
///
/// `#[non_exhaustive]` reserves room to add further held states later without
/// breaking host `match`es.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    /// The account is usable: auth and recovery proceed normally.
    #[default]
    Active,
    /// The account has been disabled by an operator at the given instant.
    /// Both auth and recovery refuse it until it is re-enabled.
    Disabled {
        /// When the account was disabled.
        at: DateTime<Utc>,
    },
}

impl AccountStatus {
    /// Returns `true` when the account is [`Active`](AccountStatus::Active).
    /// The single shared predicate both auth and recovery gate on, so the enum
    /// is never re-matched inline at each enforcement seam.
    pub fn is_active(&self) -> bool {
        matches!(self, AccountStatus::Active)
    }

    /// The instant the account was disabled, or `None` when it is active.
    pub fn disabled_at(&self) -> Option<DateTime<Utc>> {
        match self {
            AccountStatus::Disabled { at } => Some(*at),
            AccountStatus::Active => None,
        }
    }
}

/// Local user record shared by all auth methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Stable user identifier.
    pub id: UserId,
    /// Verified email address, or `None` before the address is set.
    pub email: Option<String>,
    /// When the email address was verified, if it has been.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Whether the account is active or has been disabled by an operator;
    /// disabled accounts are refused by both auth and recovery.
    pub status: AccountStatus,
    /// When the user record was created.
    pub created_at: DateTime<Utc>,
    /// When the user record was last modified.
    pub updated_at: DateTime<Utc>,
}

/// Persisted session row keyed by a hashed bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Stable session identifier.
    pub id: SessionId,
    /// Owner of the session.
    pub user_id: UserId,
    /// SHA-256 hash of the bearer token; the plaintext is never stored.
    pub token_hash: TokenHash,
    /// When the session was created. The absolute anchor: the session dies
    /// at `created_at + absolute_lifetime` regardless of activity.
    pub created_at: DateTime<Utc>,
    /// When the session last validated and slid its idle deadline forward.
    /// Set to `created_at` at issuance and rewritten on each material touch.
    /// Not consulted for enforcement — [`expires_at`](Self::expires_at) already
    /// carries the effective deadline — but it is the "last active" field a
    /// session listing surfaces and what makes the three-bound model legible.
    pub last_used_at: DateTime<Utc>,
    /// The effective, already-`min`'d expiry deadline; enforced on read with a
    /// single `now >= expires_at` comparison. With an idle timeout configured
    /// this is `min(created_at + absolute_lifetime, last_used_at + idle_timeout)`
    /// and slides forward on use; without one it is `created_at + absolute_lifetime`
    /// and never moves.
    pub expires_at: DateTime<Utc>,
    /// Client IP captured at creation, if available.
    pub ip: Option<String>,
    /// Client user-agent captured at creation, if available.
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
        self.recovery_cooldown_until.filter(|&until| now < until)
    }

    /// Returns `true` if the session is currently restricted by a recovery
    /// cool-down. The comparison is `now < cool-down`; sessions whose
    /// cool-down has already elapsed are treated as unrestricted.
    pub fn is_in_recovery_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.active_recovery_cooldown_until(now).is_some()
    }
}

/// Metadata-only view of a session.
///
/// Carries the fields an operator session listing needs (id, owner,
/// timestamps, the request context captured at creation, and any recovery
/// cool-down) *without* the [`Session::token_hash`]. The hash is the SHA-256
/// of the live bearer token — a sensitive capability identifier — so it must
/// never cross into an operator-facing view, its logs, or its JSON. The
/// projection is produced in [`crate::session::SessionManager`] so
/// `token_hash` never leaves the manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Stable session identifier, matching [`Session::id`].
    pub id: SessionId,
    /// Owner of the session, matching [`Session::user_id`].
    pub user_id: UserId,
    /// When the session was created, matching [`Session::created_at`].
    pub created_at: DateTime<Utc>,
    /// When the session was last used, matching [`Session::last_used_at`].
    pub last_used_at: DateTime<Utc>,
    /// When the session expires, matching [`Session::expires_at`].
    pub expires_at: DateTime<Utc>,
    /// Client IP captured at creation, mirroring [`Session::ip`].
    pub ip: Option<String>,
    /// Client user-agent captured at creation, mirroring [`Session::user_agent`].
    pub user_agent: Option<String>,
    /// Active recovery cool-down deadline, mirroring
    /// [`Session::recovery_cooldown_until`].
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

/// Persistence contract for local user records.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Insert a new user row.
    async fn create_user(&self, user: User) -> StorageResult<()>;

    /// Look up a user by id, or `None` if absent.
    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>>;

    /// Look up a user by email, or `None` if absent. The lookup is on the
    /// normalized address the managers store.
    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>>;

    /// Overwrite an existing user row (matched by id).
    async fn update_user(&self, user: User) -> StorageResult<()>;

    /// Remove a user row. Callers cascade related rows first; this only
    /// removes the user record.
    async fn delete_user(&self, id: UserId) -> StorageResult<()>;
}

/// Persistence contract for server-side sessions.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Insert a new session row.
    async fn create_session(&self, session: Session) -> StorageResult<()>;

    /// Persist a slid session deadline on use. The caller passes a `session`
    /// it has just resolved with `last_used_at` and `expires_at` already updated
    /// to the new values; the store writes those (and, for backends with native
    /// auto-eviction, the eviction timer) for the matching row.
    ///
    /// MUST be a conditional write: if no row with `session.id` currently
    /// exists, this is a no-op returning `Ok(())`. It MUST NOT create a row —
    /// see "the resurrection hazard" below.
    ///
    /// The caller treats failures as best-effort (see `validate_by_hash`): a
    /// storage error here MUST NOT fail an otherwise-valid request.
    async fn touch_session(&self, session: &Session) -> StorageResult<()>;

    /// Resolve a session by its token hash, or `None` if absent. The hot
    /// per-request lookup.
    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>>;

    /// Resolve a session by id, or `None` if absent.
    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>>;

    /// Return the sessions belonging to a user. `now` is the caller's clock
    /// instant: database-backed adapters SHOULD push `expires_at > now` into
    /// the query so dead rows never leave the store, while the in-memory
    /// reference store MAY return expired rows. Either way
    /// [`SessionManager::list_for_user`](crate::session::SessionManager::list_for_user)
    /// applies the same `expires_at > now` filter, so a caller never observes
    /// an expired session regardless of which adapter is in use.
    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>>;

    /// Delete a single session by id.
    async fn delete_session(&self, id: SessionId) -> StorageResult<()>;

    /// Delete every session belonging to `user_id`, returning the number
    /// removed. Backs "log out everywhere" and account deletion.
    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    /// Delete every session belonging to `user_id` *except* the one with
    /// `except`. Implementations return the number of sessions removed.
    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64>;

    /// Delete every session whose `expires_at` is at or before `now`,
    /// returning the number of entries reclaimed. For a key-value adapter whose
    /// rows are TTL-evicted behind a best-effort secondary index, this also
    /// reclaims dangling index members (see the "Implementing a key-value
    /// adapter" notes above), so the count is expired rows plus reclaimed
    /// dangling members and MAY exceed the number of rows deleted.
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
    /// Generate a fresh random identifier (UUIDv4).
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

/// A passkey credential bound to a user. The `passkey` field is the
/// serialised `webauthn-rs` credential as opaque bytes: `doorman-core`
/// (de)serialises it on the way in and out, and the store persists it
/// verbatim. A host's store therefore needs no `webauthn-rs` dependency
/// and must not attempt to interpret the blob.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    /// Raw credential id, as a byte string. Kept top-level so storage
    /// backends can index on it without having to inspect the opaque
    /// `passkey` blob.
    pub credential_id: Vec<u8>,
    /// Owner of the credential.
    pub user_id: UserId,
    /// Opaque serialised credential blob. Persist and return it verbatim;
    /// only `doorman-core` parses it.
    pub passkey: Vec<u8>,
    /// Optional friendly device name set by the user at registration time
    /// ("Eddie's iPhone", "Yubikey 5"). The library does not interpret it.
    pub name: Option<String>,
    /// When the credential was registered.
    pub created_at: DateTime<Utc>,
    /// When the credential was last used to authenticate, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Authenticator Attestation GUID identifying the make/model of the
    /// authenticator, when the ceremony produced one. Passkey registration
    /// requests no attestation, so this is usually `None`; it is populated
    /// only when the authenticator volunteered packed/TPM attestation
    /// metadata. Captured at registration from the credential.
    pub aaguid: Option<Uuid>,
    /// Transport hints the authenticator advertised (`"usb"`, `"nfc"`,
    /// `"ble"`, `"internal"`, `"hybrid"`). A UI hint only, not a security
    /// property. Captured at registration; empty when none were advertised.
    pub transports: Vec<String>,
    /// `true` when the credential's private key may be backed up or synced
    /// across devices (the WebAuthn BE flag). Captured at registration and
    /// refreshed on each authentication.
    pub backup_eligible: bool,
    /// `true` when the credential is currently backed up or synced (the
    /// WebAuthn BS flag). Captured at registration and refreshed on each
    /// authentication, since it can change over the credential's life.
    pub backup_state: bool,
    /// When set, sessions created by authenticating with this passkey may
    /// inherit the recovery cool-down restriction until this instant. `None`
    /// means the credential is unrestricted.
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

impl StoredPasskey {
    /// Return the active recovery cool-down deadline, if any. Mirrors
    /// [`Session::active_recovery_cooldown_until`] so the "still live?"
    /// predicate has one shape per type: the comparison is `now < cool-down`,
    /// and a credential whose cool-down has already elapsed is treated as
    /// unrestricted and returns `None`.
    pub fn active_recovery_cooldown_until(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.recovery_cooldown_until.filter(|&until| now < until)
    }

    /// Returns `true` if the credential still carries an active recovery
    /// cool-down. Mirrors [`Session::is_in_recovery_cooldown`].
    pub fn is_in_recovery_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.active_recovery_cooldown_until(now).is_some()
    }
}

/// Metadata-only view of a registered passkey.
///
/// Carries every field a management UI needs to list a user's credentials
/// (id, friendly name, timestamps, device metadata, cool-down) *without* the
/// `webauthn-rs` `Passkey` credential blob. The listing path
/// ([`PasskeyCredentialStore::list_passkey_summaries_for_user`]) returns
/// this so an adapter never has to deserialise the blob just to render the
/// "your passkeys" view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    /// Raw credential id, matching [`StoredPasskey::credential_id`].
    pub credential_id: Vec<u8>,
    /// Owner of the credential.
    pub user_id: UserId,
    /// Friendly device name set at registration, if any.
    pub name: Option<String>,
    /// When the credential was registered.
    pub created_at: DateTime<Utc>,
    /// When the credential was last used to authenticate, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Authenticator AAGUID, mirroring [`StoredPasskey::aaguid`].
    pub aaguid: Option<Uuid>,
    /// Advertised transport hints, mirroring [`StoredPasskey::transports`].
    pub transports: Vec<String>,
    /// Backup-eligibility flag, mirroring [`StoredPasskey::backup_eligible`].
    pub backup_eligible: bool,
    /// Backup-state flag, mirroring [`StoredPasskey::backup_state`].
    pub backup_state: bool,
    /// Active recovery cool-down deadline, mirroring
    /// [`StoredPasskey::recovery_cooldown_until`].
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
            aaguid: value.aaguid,
            transports: value.transports,
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
            recovery_cooldown_until: value.recovery_cooldown_until,
        }
    }
}

impl From<&StoredPasskey> for PasskeySummary {
    /// Borrowed projection for adapters that hold full credentials and need
    /// summaries without consuming them. Clones only the metadata fields —
    /// never the opaque `passkey` blob, which is the point of the summary.
    fn from(value: &StoredPasskey) -> Self {
        Self {
            credential_id: value.credential_id.clone(),
            user_id: value.user_id,
            name: value.name.clone(),
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            aaguid: value.aaguid,
            transports: value.transports.clone(),
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
            recovery_cooldown_until: value.recovery_cooldown_until,
        }
    }
}

/// In-progress passkey registration ceremony state. The `state` field is
/// the serialised `webauthn-rs` ceremony state as opaque bytes, preserved
/// verbatim between start and finish; only `doorman-core` parses it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskeyRegistration {
    /// Ceremony identifier returned to the client for the `finish` step.
    pub id: PasskeyChallengeId,
    /// User the registration is for.
    pub user_id: UserId,
    /// Opaque serialised ceremony state. Persist and return it verbatim.
    pub state: Vec<u8>,
    /// When the ceremony started.
    pub created_at: DateTime<Utc>,
    /// When the ceremony state expires; a `finish` after this is rejected.
    pub expires_at: DateTime<Utc>,
    /// Optional recovery cool-down metadata associated with this in-progress
    /// registration ceremony.
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

/// In-progress discoverable passkey authentication ceremony state. The
/// `state` field is the serialised `webauthn-rs` ceremony state as opaque
/// bytes, preserved verbatim between start and finish; only `doorman-core`
/// parses it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskeyAuthentication {
    /// Ceremony identifier returned to the client for the `finish` step.
    pub id: PasskeyChallengeId,
    /// Opaque serialised ceremony state. Persist and return it verbatim.
    pub state: Vec<u8>,
    /// When the ceremony started.
    pub created_at: DateTime<Utc>,
    /// When the ceremony state expires; a `finish` after this is rejected.
    pub expires_at: DateTime<Utc>,
}

/// Persistence contract for registered passkey credentials.
#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    /// Persist a newly-registered credential.
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    /// Update an existing passkey, typically to advance its signature
    /// counter or backup-state flags after a successful authentication.
    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    /// List the user's credentials, including the credential blob. Prefer
    /// [`list_passkey_summaries_for_user`](Self::list_passkey_summaries_for_user)
    /// for UI listings that do not need the blob.
    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>>;

    /// List the user's credentials as metadata-only [`PasskeySummary`]
    /// values. Adapters MUST satisfy this without deserialising the
    /// credential blob; it backs the "your passkeys" listing/count paths
    /// where the blob is never read.
    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>>;

    /// Resolve a credential by its raw credential id, or `None` if absent.
    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>>;

    /// Delete a credential by its raw credential id. Callers verify
    /// ownership before calling.
    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()>;

    /// Delete every credential belonging to `user_id`, returning the number
    /// removed. Backs account deletion's credential cascade; prefer this over
    /// a per-credential [`delete_passkey`](Self::delete_passkey) loop.
    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64>;
}

/// Persistence contract for in-progress passkey ceremony state.
#[async_trait]
pub trait PasskeyChallengeStore: Send + Sync {
    /// Persist a new registration ceremony's state.
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()>;

    /// Atomically look up and remove a registration challenge. MUST
    /// delete before returning so the same challenge cannot be replayed.
    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>>;

    /// Delete every outstanding registration challenge for `user_id`,
    /// returning the number removed. Recovery completion calls this to
    /// invalidate any registration ceremony that began *before* the recovery,
    /// so a pre-recovery challenge cannot be finished afterwards to attach a
    /// credential outside the post-recovery cool-down.
    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    /// Count the outstanding registration challenges for `user_id`. Backs the
    /// per-user "outstanding challenges" cap enforced by
    /// [`PasskeyManager::start_registration`](crate::passkey::PasskeyManager::start_registration):
    /// a count at or above the cap rejects a fresh ceremony so an attacker with
    /// a foothold cannot grow the table without bound. Implementations MAY
    /// include challenges that have technically expired (the cap is a coarse
    /// resource bound, not an exact live count).
    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    /// Persist a new authentication ceremony's state.
    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()>;

    /// Atomically look up and remove an authentication challenge.
    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>>;

    /// Delete every ceremony (registration or authentication) whose
    /// `expires_at` is at or before `now`, returning the number of entries
    /// reclaimed. As with the other ephemeral stores, a key-value adapter MAY
    /// also reclaim dangling index members here, so the count MAY exceed the
    /// number of rows deleted.
    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

/// What a verification token authorises. Tokens are kept distinct per
/// purpose so that a leaked link of one kind can never act as a link of
/// another kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPurpose {
    /// Bootstraps a new account: the link starts first-passkey registration.
    Signup,
    /// Re-enrols a user who lost every passkey: the link starts a new
    /// passkey registration under the recovery cool-down.
    Recovery,
    /// Confirms a verified email-change request. The token is emailed to the
    /// *new* address (proving the user controls it) and, when redeemed,
    /// moves the account's email to the value carried in
    /// [`VerificationToken::new_email`].
    EmailChange,
}

/// A single-use, time-limited token issued for an out-of-band flow such
/// as the signup link emailed to a prospective user. Stored keyed by token
/// hash so that a database breach does not yield usable tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationToken {
    /// SHA-256 hash of the token; the plaintext is never stored.
    pub token_hash: TokenHash,
    /// User the token is bound to.
    pub user_id: UserId,
    /// What the token authorises. Re-checked at consumption so a token of
    /// one purpose cannot be redeemed on another flow.
    pub purpose: VerificationPurpose,
    /// Target address for an [`EmailChange`](VerificationPurpose::EmailChange)
    /// token: the already-normalized address the account moves to when the
    /// token is redeemed. `None` for signup and recovery tokens, which carry
    /// no payload beyond the user binding.
    pub new_email: Option<String>,
    /// When the token was issued.
    pub created_at: DateTime<Utc>,
    /// When the token expires; a consume after this is rejected.
    pub expires_at: DateTime<Utc>,
}

/// Persistence contract for single-use verification tokens.
#[async_trait]
pub trait VerificationTokenStore: Send + Sync {
    /// Persist a freshly-issued token (stored by hash).
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

    /// Delete every token whose `expires_at` is at or before `now`, returning
    /// the number of entries reclaimed. As with the other ephemeral stores, a
    /// key-value adapter MAY also reclaim dangling index members here, so the
    /// count MAY exceed the number of rows deleted.
    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::hash_token;
    use chrono::TimeZone;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("valid timestamp")
    }

    /// Every ephemeral struct the Redis adapter persists must survive a JSON
    /// round trip unchanged, since `doorman-redis` stores them as `serde_json`
    /// values. These guard the serde derives that adapter relies on.
    #[test]
    fn session_json_round_trips() {
        let session = Session {
            id: SessionId::new(),
            user_id: UserId::new(),
            token_hash: hash_token("a-session-token"),
            created_at: ts(1_000),
            last_used_at: ts(1_000),
            expires_at: ts(2_000),
            ip: Some("203.0.113.7".to_string()),
            user_agent: Some("doorman-test/1.0".to_string()),
            recovery_cooldown_until: Some(ts(1_500)),
        };
        let json = serde_json::to_string(&session).expect("serialize session");
        let back: Session = serde_json::from_str(&json).expect("deserialize session");
        assert_eq!(session, back);
    }

    #[test]
    fn verification_token_json_round_trips() {
        let token = VerificationToken {
            token_hash: hash_token("a-verification-token"),
            user_id: UserId::new(),
            purpose: VerificationPurpose::EmailChange,
            new_email: Some("new@example.com".to_string()),
            created_at: ts(1_000),
            expires_at: ts(2_000),
        };
        let json = serde_json::to_string(&token).expect("serialize token");
        let back: VerificationToken = serde_json::from_str(&json).expect("deserialize token");
        assert_eq!(token, back);
    }

    #[test]
    fn stored_passkey_registration_json_round_trips() {
        let reg = StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            user_id: UserId::new(),
            state: vec![0x00, 0x01, 0xfe, 0xff],
            created_at: ts(1_000),
            expires_at: ts(2_000),
            recovery_cooldown_until: None,
        };
        let json = serde_json::to_string(&reg).expect("serialize registration");
        let back: StoredPasskeyRegistration =
            serde_json::from_str(&json).expect("deserialize registration");
        // `StoredPasskeyRegistration` is not `PartialEq`, so compare fields.
        assert_eq!(reg.id, back.id);
        assert_eq!(reg.user_id, back.user_id);
        assert_eq!(reg.state, back.state);
        assert_eq!(reg.created_at, back.created_at);
        assert_eq!(reg.expires_at, back.expires_at);
        assert_eq!(reg.recovery_cooldown_until, back.recovery_cooldown_until);
    }

    #[test]
    fn stored_passkey_authentication_json_round_trips() {
        let auth = StoredPasskeyAuthentication {
            id: PasskeyChallengeId::new(),
            state: vec![0xde, 0xad, 0xbe, 0xef],
            created_at: ts(1_000),
            expires_at: ts(2_000),
        };
        let json = serde_json::to_string(&auth).expect("serialize authentication");
        let back: StoredPasskeyAuthentication =
            serde_json::from_str(&json).expect("deserialize authentication");
        assert_eq!(auth.id, back.id);
        assert_eq!(auth.state, back.state);
        assert_eq!(auth.created_at, back.created_at);
        assert_eq!(auth.expires_at, back.expires_at);
    }
}
