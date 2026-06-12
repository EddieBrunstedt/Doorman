//! redb embedded key-value storage adapter for `doorman-core`.
//!
//! `doorman-redb` fills **all five** storage traits against a single
//! [redb](https://crates.io/crates/redb) database file — a pure-Rust,
//! ACID-transactional, copy-on-write B-tree. No C libraries are bundled, no
//! server is needed, and no network is required: ideal for single-binary
//! self-hosted deployments that want a lighter footprint than SQLite or a
//! truly C-free build.
//!
//! ## Trade-offs vs the SQLite adapter
//!
//! Both are embedded ACID databases that compile into the binary without a
//! server. SQLite additionally gives SQL: uniqueness constraints, `WHERE`
//! clauses, and secondary indexes are declarative. redb is a raw key-value
//! store, so this adapter maintains secondary indexes by hand (the same
//! approach `doorman-redis` uses) and emulates expiry with `purge_expired`.
//! The upside is **no C toolchain**: redb is pure Rust, so it cross-compiles
//! without a `libsqlite3` build dependency.
//!
//! ## No native TTL
//!
//! redb has no per-record TTL. Expiry is emulated entirely via
//! `expires_at > now` filters in every listing path and an authoritative
//! `purge_expired` sweep that physically removes expired rows. Register
//! `purge_expired` with a background task or a periodic maintenance job in
//! production.
//!
//! ## Usage
//!
//! ```no_run
//! use doorman_redb::RedbStorage;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = RedbStorage::open("doorman.redb")?;
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
mod stores;

use std::path::Path;
use std::sync::Arc;

use doorman_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, Storage, UserStore,
    VerificationTokenStore,
};
use redb::Database;

use crate::db::RedbHandle;

/// Handle to a redb backend for doorman's storage.
///
/// Construct one at startup with [`open`](Self::open) (or
/// [`from_database`](Self::from_database)) — no migration step is needed,
/// the tables are provisioned automatically — then either hand
/// [`all_stores`](Self::all_stores) to `AuthService::builder` or pull
/// individual stores when wiring managers by hand.
///
/// Cloning is cheap: the underlying [`Database`] is reference-counted and
/// shared across all clones.
#[derive(Clone)]
pub struct RedbStorage {
    handle: RedbHandle,
}

impl RedbStorage {
    /// Open or create a redb database file at `path`.
    ///
    /// Creates the file (and all required tables) if it does not exist;
    /// opens an existing file in-place otherwise. An exclusive OS-level lock
    /// prevents two processes from opening the same file concurrently.
    #[allow(clippy::result_large_err)]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        Self::from_database(db)
    }

    /// Build a storage handle over an already-constructed [`Database`].
    ///
    /// Provisions every required table (idempotent), then wraps the database
    /// in a shared `Arc`. Use this when you need full control over the
    /// [`Database`] builder options — for example to tune the cache size or
    /// to pass a custom backend.
    #[allow(clippy::result_large_err)]
    pub fn from_database(db: Database) -> Result<Self, redb::Error> {
        db::ensure_tables(&db)?;
        Ok(Self {
            handle: RedbHandle::new(Arc::new(db)),
        })
    }

    /// Build a [`Storage`] populated with every per-trait store backed by
    /// this database — the single-backend shortcut for hosts keeping
    /// everything in redb.
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
        Arc::new(stores::user::RedbUserStore::new(self.handle.clone()))
    }

    /// The session store backed by this database.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::RedbSessionStore::new(self.handle.clone()))
    }

    /// The verification-token store backed by this database.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(stores::verification::RedbVerificationTokenStore::new(
            self.handle.clone(),
        ))
    }

    /// The passkey-credential store backed by this database.
    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(stores::passkey_cred::RedbPasskeyCredentialStore::new(
            self.handle.clone(),
        ))
    }

    /// The passkey-challenge store backed by this database.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::RedbPasskeyChallengeStore::new(
            self.handle.clone(),
        ))
    }
}
