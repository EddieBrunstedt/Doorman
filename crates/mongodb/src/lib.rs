//! MongoDB storage adapter for `doorman-core`.
//!
//! `doorman-mongodb` fills **all five** storage traits against a MongoDB
//! database. It uses one collection per record kind — `users`, `sessions`,
//! `verification_tokens`, `passkey_credentials`, `passkey_registrations`, and
//! `passkey_authentications` — with native TTL indexes for the ephemeral stores
//! and unique indexes for the system-of-record stores.
//!
//! ## Design highlights
//!
//! - **Atomic single-use.** `consume_token`, `take_registration`, and
//!   `take_authentication` are a `findOneAndDelete` call. MongoDB serializes
//!   writes per document, so exactly one concurrent caller observes the old
//!   image — the single-use guarantee tokens and ceremonies rely on.
//! - **Email uniqueness.** A partial unique index on `email` (covering only
//!   documents where the field is a string) enforces email uniqueness while
//!   allowing multiple email-less users to coexist without a uniqueness conflict.
//!   No companion guard document or transaction is needed; a standalone MongoDB
//!   node (no replica set) suffices.
//! - **Expiry.** MongoDB's TTL monitor runs roughly every 60 seconds and is
//!   a production memory-reclamation backstop only. The `ttl` field is written
//!   only for future-dated expiries, so past-dated conformance fixtures are not
//!   swept during test runs. Reads push `expires_at > now` into the query (on
//!   the listing paths) and `purge_expired` is the authoritative, immediate
//!   reclamation path (`deleteMany` with `expires_at <= now`).
//! - **Timestamps.** Stored as BSON `Date` (millisecond precision, MongoDB's
//!   native temporal type) so they sort correctly and drive the TTL monitor.
//! - **TLS.** The driver's ring-backed `rustls-tls` feature is enabled and
//!   `rustls-tls-aws-lc` left off, keeping the workspace on its single ring
//!   crypto stack.
//!
//! ## Usage
//!
//! ```ignore
//! use doorman_mongodb::MongoDbStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = mongodb::Client::with_uri_str("mongodb://localhost:27017").await?;
//! let database = client.database("my_app");
//!
//! let storage = MongoDbStorage::new(database);
//! storage.ensure_indexes().await?; // idempotent; safe on every boot
//!
//! let composite = storage.all_stores();
//! # let _ = composite;
//! # Ok(()) }
//! ```

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test helpers.
#![deny(missing_docs)]

mod db;
mod model;
mod stores;

use std::sync::Arc;

use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, Storage, UserStore,
    VerificationTokenStore,
};

use crate::db::MongoDb;

/// Handle to a MongoDB backend for doorman's storage.
///
/// Construct one at startup with [`new`](Self::new) from a [`mongodb::Database`],
/// provision the indexes once with [`ensure_indexes`](Self::ensure_indexes), then
/// either hand [`all_stores`](Self::all_stores) to `AuthService::builder` or pull
/// individual stores when wiring managers by hand. Cloning is cheap — `Database`
/// is reference-counted internally.
#[derive(Clone)]
pub struct MongoDbStorage {
    db: MongoDb,
}

impl MongoDbStorage {
    /// Build a storage handle over `database`.
    ///
    /// The caller owns the `mongodb::Client` (and with it the connection pool,
    /// credentials, TLS configuration, and read/write concern). This adapter
    /// issues operations through the provided `Database` unchanged.
    pub fn new(database: mongodb::Database) -> Self {
        Self {
            db: MongoDb::new(database),
        }
    }

    /// Provision the collection indexes.
    ///
    /// Idempotent and safe to call on every boot: MongoDB's `createIndex` is a
    /// no-op when an index with the same definition already exists. A host that
    /// manages its own infrastructure can create the indexes out of band and
    /// skip this call.
    ///
    /// ## Required indexes
    ///
    /// | Collection              | Index                                        |
    /// | ----------------------- | -------------------------------------------- |
    /// | `users`                 | Partial unique on `email` (where string)     |
    /// | `sessions`              | Unique on `token_hash`                       |
    /// | `sessions`              | `user_id`                                    |
    /// | `sessions`              | TTL on `ttl`                                 |
    /// | `verification_tokens`   | `(user_id, purpose)`                         |
    /// | `verification_tokens`   | TTL on `ttl`                                 |
    /// | `passkey_credentials`   | `user_id`                                    |
    /// | `passkey_registrations` | `user_id`                                    |
    /// | `passkey_registrations` | TTL on `ttl`                                 |
    /// | `passkey_authentications` | TTL on `ttl`                               |
    pub async fn ensure_indexes(&self) -> StorageResult<()> {
        self.db.ensure_indexes().await
    }

    /// Build a [`Storage`] populated with every per-trait store backed by this
    /// database — the single-backend shortcut for hosts keeping everything in
    /// MongoDB.
    pub fn all_stores(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }

    /// The user store backed by this database.
    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(stores::user::MongoUserStore::new(self.db.users()))
    }

    /// The session store backed by this database.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::MongoSessionStore::new(self.db.sessions()))
    }

    /// The verification-token store backed by this database.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(stores::verification::MongoVerificationTokenStore::new(
            self.db.verification_tokens(),
        ))
    }

    /// The passkey-credential store backed by this database.
    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(stores::passkey_cred::MongoPasskeyCredentialStore::new(
            self.db.passkey_credentials(),
        ))
    }

    /// The passkey-challenge store backed by this database.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::MongoPasskeyChallengeStore::new(
            self.db.passkey_registrations(),
            self.db.passkey_authentications(),
        ))
    }
}
