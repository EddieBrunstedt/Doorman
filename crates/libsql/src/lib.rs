//! libSQL / Turso storage adapter for `doorman-core`.
//!
//! `doorman-libsql` fills **all five** storage traits against a remote
//! [Turso](https://turso.tech) / libSQL database over the Hrana protocol, built
//! on the official [`libsql`] client. libSQL speaks SQLite's SQL dialect, so the
//! schema and queries mirror the SQLite adapter in `doorman-sqlx`; what this
//! crate adds is the remote, edge-friendly connection model that a Turso
//! deployment uses.
//!
//! ## Why remote-only
//!
//! libSQL's embedded engine (local files, in-memory, embedded replicas) bundles
//! its own SQLite C library, which collides at link time with `doorman-sqlx`'s
//! SQLite adapter (both statically link a `sqlite3.c`) — so a single binary
//! cannot carry both, and pulling the engine in here would break the workspace's
//! `--all-features` build. This adapter therefore bundles **no** SQLite engine
//! and connects only to a remote server. A local file is already covered by
//! `doorman-sqlx`'s SQLite adapter; a host that specifically wants a libSQL
//! local file or an embedded replica enables those `libsql` features in its
//! *own* manifest, builds the [`libsql::Database`], and hands it to
//! [`from_database`](LibsqlStorage::from_database) (such a host must then not
//! also link `doorman-sqlx`'s SQLite adapter).
//!
//! ## Choosing a constructor
//!
//! - [`connect_remote`](LibsqlStorage::connect_remote) — a remote Turso database
//!   addressed by URL and auth token. Nothing is stored locally.
//! - [`from_database`](LibsqlStorage::from_database) — hand over an
//!   already-built [`libsql::Database`] for any configuration `connect_remote`
//!   does not cover (a local file or embedded replica with the engine features
//!   enabled in your manifest, encryption, custom builder options).
//!
//! After constructing, call [`migrate`](LibsqlStorage::migrate) once to create
//! the schema (idempotent), then hand [`all_stores`](LibsqlStorage::all_stores)
//! to `AuthService::builder`.
//!
//! ## Connection model
//!
//! The adapter holds a single libSQL connection, shared (cheaply, by reference)
//! across all five stores: one connection multiplexes requests to the server
//! over Hrana, so this is the natural shape. A host that wants several
//! independent connections can construct several `LibsqlStorage` values over the
//! same [`libsql::Database`] via [`from_database`](LibsqlStorage::from_database).
//!
//! ## Usage
//!
//! ```ignore
//! use doorman_libsql::LibsqlStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = LibsqlStorage::connect_remote(
//!     "libsql://my-db.turso.io".to_string(),
//!     std::env::var("TURSO_AUTH_TOKEN")?,
//! ).await?;
//! storage.migrate().await?;
//!
//! let composite = storage.all_stores();
//! # let _ = composite;
//! # Ok(()) }
//! ```

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test helpers.
#![deny(missing_docs)]

mod conn;
mod convert;
mod stores;

use std::sync::Arc;

use doorman_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, Storage, UserStore,
    VerificationTokenStore,
};
use libsql::{Builder, Database};

use crate::conn::LibsqlConn;

/// The consolidated schema [`migrate`](LibsqlStorage::migrate) applies.
const SCHEMA: &str = include_str!("../schema.sql");

/// Handle to a libSQL backend for doorman's storage.
///
/// Construct one at startup with [`connect_remote`](Self::connect_remote) (or
/// [`from_database`](Self::from_database)), run [`migrate`](Self::migrate) once,
/// then either hand [`all_stores`](Self::all_stores) to `AuthService::builder`
/// or pull individual stores when wiring managers by hand. Cloning is cheap —
/// the underlying connection and database handle are reference-counted.
#[derive(Clone)]
pub struct LibsqlStorage {
    db: Arc<Database>,
    conn: LibsqlConn,
}

impl LibsqlStorage {
    /// Connect to a remote Turso database addressed by `url` (for example
    /// `libsql://my-db.turso.io`) and authenticated with `auth_token`. Nothing
    /// is persisted locally.
    pub async fn connect_remote(url: String, auth_token: String) -> Result<Self, libsql::Error> {
        let db = Builder::new_remote(url, auth_token).build().await?;
        Self::from_database(db).await
    }

    /// Build a storage handle over an already-constructed [`libsql::Database`].
    ///
    /// The escape hatch for configurations [`connect_remote`](Self::connect_remote)
    /// does not cover — including a local file or embedded replica, when the
    /// caller has enabled libSQL's engine features (`core` / `replication`) in
    /// its own manifest and built the [`libsql::Database`] itself. Opens one
    /// connection on the database and enables foreign-key enforcement on it.
    pub async fn from_database(db: Database) -> Result<Self, libsql::Error> {
        let conn = db.connect()?;
        // SQLite leaves foreign keys off per connection; the schema declares
        // them (with `ON DELETE CASCADE`), so turn enforcement on.
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        Ok(Self {
            db: Arc::new(db),
            conn: LibsqlConn::new(conn),
        })
    }

    /// The underlying [`libsql::Database`], for sharing with the rest of the app
    /// — for example to open additional connections, or to drive `sync()` on a
    /// database the caller built as an embedded replica.
    pub fn database(&self) -> &Arc<Database> {
        &self.db
    }

    /// Apply the schema. Idempotent (every statement is `IF NOT EXISTS`), so it
    /// is safe to call on every boot.
    pub async fn migrate(&self) -> Result<(), libsql::Error> {
        self.raw_connection().execute_batch(SCHEMA).await?;
        Ok(())
    }

    /// Build a [`Storage`] populated with every per-trait store backed by this
    /// connection — the single-backend shortcut for hosts keeping everything in
    /// libSQL.
    pub fn all_stores(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }

    /// The user store backed by this connection.
    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(stores::user::LibsqlUserStore::new(self.conn.clone()))
    }

    /// The session store backed by this connection.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::LibsqlSessionStore::new(self.conn.clone()))
    }

    /// The verification-token store backed by this connection.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(stores::verification::LibsqlVerificationTokenStore::new(
            self.conn.clone(),
        ))
    }

    /// The passkey-credential store backed by this connection.
    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(stores::passkey_cred::LibsqlPasskeyCredentialStore::new(
            self.conn.clone(),
        ))
    }

    /// The passkey-challenge store backed by this connection.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::LibsqlPasskeyChallengeStore::new(
            self.conn.clone(),
        ))
    }

    fn raw_connection(&self) -> libsql::Connection {
        self.conn.raw()
    }
}
