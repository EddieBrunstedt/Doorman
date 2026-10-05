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
// Lock in rustdoc quality alongside the coverage above: broken intra-doc links,
// malformed code blocks, bare URLs, and the rest of the rustdoc lint group warn
// here and become hard errors under the `-D warnings` doc gate.
#![warn(rustdoc::all)]

mod client;
mod keys;
mod rate_limit;
mod scripts;
mod stores;

use std::sync::Arc;

use doorman_core::clock::{Clock, SystemClock};
use doorman_core::error::StorageResult;
use doorman_core::rate_limit::RateLimiter;
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

    /// A shared, cross-replica [`RateLimiter`] backed by this connection.
    ///
    /// The limiter is not a store, so it is wired separately from the `Storage`
    /// literal — pass it to the builder via
    /// `AuthCore::builder(storage).limiter(redis.rate_limiter())`. It uses a
    /// sliding-window log matching the in-memory limiter's semantics, sourcing
    /// `now` from a [`SystemClock`]. Use
    /// [`rate_limiter_with_clock`](Self::rate_limiter_with_clock) to inject a
    /// different clock (e.g. a mock clock in tests).
    pub fn rate_limiter(&self) -> Arc<dyn RateLimiter> {
        self.rate_limiter_with_clock(Arc::new(SystemClock))
    }

    /// A shared [`RateLimiter`] sourcing `now` from `clock`.
    ///
    /// The same value the rest of doorman would supply (a [`SystemClock`] in
    /// production, a mock clock under test) so the limiter's rolling window
    /// agrees with the managers' notion of time.
    pub fn rate_limiter_with_clock(&self, clock: Arc<dyn Clock>) -> Arc<dyn RateLimiter> {
        Arc::new(rate_limit::RedisRateLimiter::new(
            self.client.clone(),
            clock,
        ))
    }
}
