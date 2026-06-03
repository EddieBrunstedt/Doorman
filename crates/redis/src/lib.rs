//! Redis/Valkey-backed ephemeral storage for `doorman-core`.
//!
//! `doorman-redis` moves the **ephemeral, TTL-bearing** auth state — sessions,
//! verification tokens, and passkey ceremony challenges — onto Redis or Valkey,
//! so a multi-replica deployment shares them (instant cross-process revoke, one
//! rate-limit budget) instead of keeping per-process copies. A single adapter
//! built on `redis-rs` connects to either server; they share the wire protocol
//! and the command set this crate uses.
//!
//! It deliberately does **not** implement `UserStore` or
//! `PasskeyCredentialStore`: those hold the system-of-record (accounts and the
//! actual passkey material), which never expires and wants relational
//! guarantees, so it belongs in a SQL backend. [`RedisStorage`] therefore has
//! no `all_stores()`; it is always assembled into a
//! [`Storage`](doorman_core::storage::Storage) literal alongside a SQL adapter:
//!
//! ```ignore
//! use doorman_core::storage::Storage;
//! use doorman_redis::RedisStorage;
//! use doorman_sqlx::PostgresStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let pg = PostgresStorage::connect("postgres://localhost/app").await?;
//! pg.migrate().await?;
//! let redis = RedisStorage::connect("redis://localhost:6379").await?;
//!
//! let storage = Storage {
//!     users:               pg.user_store(),
//!     passkey_credentials: pg.passkey_credential_store(),
//!     sessions:            redis.session_store(),
//!     verification_tokens: redis.verification_token_store(),
//!     passkey_challenges:  redis.passkey_challenge_store(),
//! };
//! # let _ = storage;
//! # Ok(()) }
//! ```
//!
//! Minimum server version: Redis 6.2 / Valkey 7.2.

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test helpers.
#![deny(missing_docs)]
// Scaffolding: the key schema and JSON helpers are exercised by the store
// implementations, which land in the next workstream. Removed once the stores
// are filled in.
#![allow(dead_code)]

mod client;
mod keys;
mod stores;

use std::sync::Arc;

use doorman_core::error::StorageResult;
use doorman_core::storage::{PasskeyChallengeStore, SessionStore, VerificationTokenStore};
use redis::aio::ConnectionManager;

use crate::client::RedisClient;

/// Handle to a Redis/Valkey backend for doorman's ephemeral stores.
///
/// Construct one at startup with [`connect`](Self::connect) and pull the
/// per-trait stores via [`session_store`](Self::session_store),
/// [`verification_token_store`](Self::verification_token_store), and
/// [`passkey_challenge_store`](Self::passkey_challenge_store) when assembling a
/// [`Storage`](doorman_core::storage::Storage) literal. Cloning is cheap (it
/// shares the underlying multiplexed connection).
#[derive(Clone)]
pub struct RedisStorage {
    client: RedisClient,
}

impl RedisStorage {
    /// The default key prefix (`doorman:`) every key is namespaced under.
    pub const DEFAULT_PREFIX: &'static str = "doorman:";

    /// Connect to `url` (e.g. `redis://127.0.0.1:6379`) using a multiplexed,
    /// auto-reconnecting [`ConnectionManager`]. The same `redis://` URL scheme
    /// addresses Valkey. Keys are namespaced under
    /// [`DEFAULT_PREFIX`](Self::DEFAULT_PREFIX); override with
    /// [`with_prefix`](Self::with_prefix).
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Self::from_client(client).await
    }

    /// Build from an existing `redis::Client`, opening a connection manager
    /// over it. Useful when the host configures TLS, auth, or timeouts on the
    /// client itself.
    pub async fn from_client(client: redis::Client) -> Result<Self, redis::RedisError> {
        let manager = client.get_connection_manager().await?;
        Ok(Self::from_connection_manager(manager))
    }

    /// Build from an already-established [`ConnectionManager`], for hosts that
    /// manage the connection lifecycle themselves.
    pub fn from_connection_manager(manager: ConnectionManager) -> Self {
        Self {
            client: RedisClient::new(manager, Self::DEFAULT_PREFIX.to_string()),
        }
    }

    /// Override the key prefix (default [`DEFAULT_PREFIX`](Self::DEFAULT_PREFIX)).
    /// Consuming builder: `RedisStorage::connect(url).await?.with_prefix("app:")`.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.client = self.client.with_prefix(prefix.into());
        self
    }

    /// The configured key prefix.
    pub fn key_prefix(&self) -> &str {
        self.client.keys().prefix()
    }

    /// A clone of the underlying connection manager, for sharing the same
    /// multiplexed connection with the rest of the application.
    pub fn connection_manager(&self) -> ConnectionManager {
        self.client.conn()
    }

    /// Health check: round-trips a `PING`. There is no `migrate()` — Redis is
    /// schemaless.
    pub async fn ping(&self) -> StorageResult<()> {
        self.client.ping().await
    }

    /// The session store backed by this connection.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::RedisSessionStore::new(self.client.clone()))
    }

    /// The verification-token store backed by this connection.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(stores::verification::RedisVerificationTokenStore::new(
            self.client.clone(),
        ))
    }

    /// The passkey-challenge store backed by this connection.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::RedisPasskeyChallengeStore::new(
            self.client.clone(),
        ))
    }
}
