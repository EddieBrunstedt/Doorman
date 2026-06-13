//! Connection management, key prefixing, and JSON (de)serialization.
//!
//! The adapter talks to Redis/Valkey over a [`ConnectionManager`] — the
//! multiplexed, auto-reconnecting handle from `redis-rs`. It is cheap to clone
//! (the clone shares the underlying connection), so each store holds a
//! [`RedisClient`] and clones the manager per call to get the `&mut` the
//! command API wants.

use chrono::{DateTime, Utc};
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

/// The `PEXPIREAT` argument (Unix epoch milliseconds) to attach to a freshly
/// written key, or `None` when no server-side TTL should be set.
///
/// A TTL is layered on **only** when `expires_at` is strictly in the
/// wall-clock future. Expiry *correctness* never depends on it — the stores
/// filter on a caller-supplied logical `now` at read time and reclaim in
/// `purge_expired` — so TTL is purely a production memory-reclamation
/// safety net. Skipping it for already-past timestamps is what lets the
/// logical-clock conformance suite, whose fixed test instants sit in the real
/// past, exercise the read-filter/purge path instead of having its rows
/// evicted the moment they are written.
pub(crate) fn ttl_at_ms(expires_at: DateTime<Utc>) -> Option<i64> {
    (expires_at > Utc::now()).then(|| expires_at.timestamp_millis())
}

/// `GET` a raw string value (used for the session hash index, whose value is a
/// plain id rather than a JSON document).
pub(crate) async fn get_string(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Option<String>> {
    redis::cmd("GET")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

/// `GET` a key and deserialize its JSON value, or `None` when the key is absent.
pub(crate) async fn get_json<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Option<T>> {
    match get_string(conn, key).await? {
        Some(raw) => Ok(Some(from_json(&raw)?)),
        None => Ok(None),
    }
}

/// Atomically `GETDEL` a key and deserialize its JSON value. The single step
/// is what gives the single-use guarantee: under concurrency exactly one
/// caller observes the value.
pub(crate) async fn getdel_json<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Option<T>> {
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)?;
    match raw {
        Some(raw) => Ok(Some(from_json(&raw)?)),
        None => Ok(None),
    }
}

/// `MGET` a batch of keys and deserialize each present JSON value, preserving
/// order (and `None` for absent keys) so callers can zip the result back
/// against the keys that produced it.
pub(crate) async fn mget_json<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    keys: &[String],
) -> StorageResult<Vec<Option<T>>> {
    // MGET rejects a zero-argument call; an empty batch is simply empty.
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let raws: Vec<Option<String>> = redis::cmd("MGET")
        .arg(keys)
        .query_async(conn)
        .await
        .map_err(StorageError::new)?;
    raws.into_iter()
        .map(|raw| raw.map(|raw| from_json(&raw)).transpose())
        .collect()
}

/// `SMEMBERS` of a SET as owned strings.
pub(crate) async fn smembers(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Vec<String>> {
    redis::cmd("SMEMBERS")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

/// `SCARD` of a SET.
pub(crate) async fn scard(conn: &mut ConnectionManager, key: &str) -> StorageResult<u64> {
    redis::cmd("SCARD")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

/// `SREM` members from a SET, returning the number actually removed. A
/// re-`SREM` of an already-removed member returns 0, so summing these counts
/// stays correct even when a `SCAN` revisits the same SET.
pub(crate) async fn srem(
    conn: &mut ConnectionManager,
    key: &str,
    members: &[String],
) -> StorageResult<u64> {
    if members.is_empty() {
        return Ok(0);
    }
    redis::cmd("SREM")
        .arg(key)
        .arg(members)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

/// `DEL` a batch of keys, returning the number that existed and were removed.
pub(crate) async fn del(conn: &mut ConnectionManager, keys: &[String]) -> StorageResult<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    redis::cmd("DEL")
        .arg(keys)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

/// Collect every key matching `pattern` with a cursor-driven `SCAN`.
///
/// `SCAN` is non-blocking and never disturbs other keys, unlike `KEYS`. It may
/// report a key more than once across iterations; the result is de-duplicated
/// so callers process each key exactly once. A modest `COUNT` keeps each round
/// trip cheap without making the scan span too many calls.
pub(crate) async fn scan_all(
    conn: &mut ConnectionManager,
    pattern: &str,
) -> StorageResult<Vec<String>> {
    let mut cursor: u64 = 0;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(256)
            .query_async(conn)
            .await
            .map_err(StorageError::new)?;
        for key in batch {
            if seen.insert(key.clone()) {
                out.push(key);
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(out)
}
