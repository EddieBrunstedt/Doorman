//! Connection management, key prefixing, and JSON (de)serialization.
//!
//! The adapter talks to Redis/Valkey over a [`ConnectionManager`] — the
//! multiplexed, auto-reconnecting handle from `redis-rs`. It is cheap to clone
//! (the clone shares the underlying connection), so each store holds a
//! [`RedisClient`] and clones the manager per call to get the `&mut` the
//! command API wants.

use doorman_core::error::{StorageError, StorageResult};
use redis::aio::ConnectionManager;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::keys::KeySchema;

/// A cloneable handle bundling the connection manager with the key schema.
#[derive(Clone)]
pub(crate) struct RedisClient {
    conn: ConnectionManager,
    keys: KeySchema,
}

impl RedisClient {
    /// Build a client from a connection manager and a key prefix.
    pub(crate) fn new(conn: ConnectionManager, prefix: String) -> Self {
        Self {
            conn,
            keys: KeySchema::new(prefix),
        }
    }

    /// A fresh handle to the multiplexed connection. Cloning is cheap; the
    /// command API needs an owned `&mut`, so callers clone per operation.
    pub(crate) fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// The key schema for building namespaced keys.
    pub(crate) fn keys(&self) -> &KeySchema {
        &self.keys
    }

    /// Replace the key prefix, keeping the same underlying connection.
    pub(crate) fn with_prefix(mut self, prefix: String) -> Self {
        self.keys = KeySchema::new(prefix);
        self
    }

    /// Round-trip a `PING`, surfacing connectivity failures as storage errors.
    pub(crate) async fn ping(&self) -> StorageResult<()> {
        let mut conn = self.conn.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map(|_| ())
            .map_err(StorageError::new)
    }
}

/// Serialize a value to the JSON wire format stored in Redis.
pub(crate) fn to_json<T: Serialize>(value: &T) -> StorageResult<String> {
    serde_json::to_string(value).map_err(StorageError::new)
}

/// Deserialize a value from its JSON wire format.
pub(crate) fn from_json<T: DeserializeOwned>(raw: &str) -> StorageResult<T> {
    serde_json::from_str(raw).map_err(StorageError::new)
}
