//! fjall LSM-tree embedded key-value storage adapter for `doorman-core`.
//!
//! `doorman-fjall` fills **all five** storage traits against a single
//! [fjall](https://crates.io/crates/fjall) database directory — a pure-Rust,
//! ACID-transactional, LSM-tree store. No C libraries are bundled, no server
//! is needed, and no network is required: ideal for single-binary self-hosted
//! deployments that want write-optimised throughput and a lighter footprint
//! than SQLite or a truly C-free build.
//!
//! ## Trade-offs vs the redb adapter
//!
//! Both are embedded ACID stores with no server dependency and no C toolchain.
//! redb uses a copy-on-write B-tree and is read-optimised. fjall uses an
//! LSM-tree and is write-optimised: high write throughput with lower
//! write-amplification at the cost of slightly higher read-amplification and
//! compaction background work. For authentication workloads the difference is
//! negligible; the choice comes down to operational preference.
//!
//! ## Trade-offs vs the SQLite adapter
//!
//! Both are embedded ACID databases that compile into the binary without a
//! server. SQLite additionally gives SQL: uniqueness constraints, `WHERE`
//! clauses, and secondary indexes are declarative. fjall is a raw key-value
//! store, so this adapter maintains secondary indexes by hand (the same
//! approach `doorman-redis` and `doorman-redb` use) and emulates expiry with
//! `purge_expired`. The upside is **no C toolchain**: fjall is pure Rust, so
//! it cross-compiles without a `libsqlite3` build dependency.
//!
//! ## No native TTL
//!
//! fjall has no per-record TTL. Expiry is emulated entirely via
//! `expires_at > now` filters in every listing path and an authoritative
//! `purge_expired` sweep that physically removes expired rows. Register
//! `purge_expired` with a background task or a periodic maintenance job in
//! production.
//!
//! ## Usage
//!
//! ```no_run
//! use doorman_fjall::FjallStorage;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = FjallStorage::open("doorman.fjall")?;
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
use fjall::SingleWriterTxDatabase;

use crate::db::FjallHandle;

/// Handle to a fjall backend for doorman's storage.
///
/// Construct one at startup with [`open`](Self::open) (or
/// [`from_database`](Self::from_database)) — no migration step is needed,
/// the partitions are provisioned automatically — then either hand
/// [`all_stores`](Self::all_stores) to `AuthService::builder` or pull
/// individual stores when wiring managers by hand.
///
/// Cloning is cheap: the underlying [`SingleWriterTxDatabase`] is reference-
/// counted and shared across all clones.
#[derive(Clone)]
pub struct FjallStorage {
    handle: FjallHandle,
}

impl FjallStorage {
    /// Open or create a fjall database directory at `path`.
    ///
    /// Creates the directory (and all required partitions) if it does not
    /// exist; opens an existing database in-place otherwise. An OS-level lock
    /// prevents two processes from opening the same database concurrently.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, fjall::Error> {
        let db = SingleWriterTxDatabase::builder(path).open()?;
        Self::from_database(db)
    }

    /// Build a storage handle over an already-constructed
    /// [`SingleWriterTxDatabase`].
    ///
    /// Provisions every required partition (idempotent), then wraps the
    /// database in a shared handle. Use this when you need full control over
    /// the database builder options — for example to tune the block cache size
    /// or to share a database instance with other parts of your application.
    pub fn from_database(db: SingleWriterTxDatabase) -> Result<Self, fjall::Error> {
        let handle = db::open_partitions(&db)?;
        Ok(Self { handle })
    }

    /// Build a [`Storage`] populated with every per-trait store backed by
    /// this database — the single-backend shortcut for hosts keeping
    /// everything in fjall.
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
        Arc::new(stores::user::FjallUserStore::new(self.handle.clone()))
    }

    /// The session store backed by this database.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::FjallSessionStore::new(self.handle.clone()))
    }

    /// The verification-token store backed by this database.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(stores::verification::FjallVerificationTokenStore::new(
            self.handle.clone(),
        ))
    }

    /// The passkey-credential store backed by this database.
    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(stores::passkey_cred::FjallPasskeyCredentialStore::new(
            self.handle.clone(),
        ))
    }

    /// The passkey-challenge store backed by this database.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::FjallPasskeyChallengeStore::new(
            self.handle.clone(),
        ))
    }
}

// Re-export the database type so callers using `from_database` don't need a
// direct `fjall` dependency just for the builder.
pub use fjall::{KeyspaceCreateOptions as FjallKeyspaceOptions, SingleWriterTxDatabase as FjallDb};
