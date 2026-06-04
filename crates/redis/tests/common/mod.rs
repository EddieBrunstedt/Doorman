//! Shared helpers for the Redis/Valkey integration tests.
//!
//! Each test binary compiles this module independently, and not every binary
//! uses every helper, so allow dead code here rather than per item.
#![allow(dead_code)]

use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::Storage;
use doorman_redis::RedisStorage;
use redis::aio::MultiplexedConnection;
use uuid::Uuid;

/// Build a [`Storage`] whose three ephemeral stores are Redis-backed and whose
/// two system-of-record stores are filled by an in-memory backend.
///
/// Pairing the Redis ephemeral stores with in-memory `users` /
/// `passkey_credentials` lets the shared conformance suite run end to end: the
/// suite exercises every Redis-backed method, and the in-memory fillers stand
/// in only for the two stores the adapter intentionally omits (§6).
///
/// Returns `None` (with a skip message) when `url_var` is unset, mirroring the
/// `PG_URL` pattern.
pub async fn storage(url_var: &str) -> Option<Storage> {
    storage_with_raw(url_var)
        .await
        .map(|(storage, _, _)| storage)
}

/// Like [`storage`], but also returns a raw connection to the same server and
/// the key prefix the Redis stores use.
///
/// Tests that must reach behind the store API — to delete a primary row
/// directly and simulate TTL eviction, or to assert a key was reclaimed — build
/// the namespaced key from `prefix` (mirroring `keys.rs`) and issue commands on
/// the raw connection. Each call uses a unique key prefix, so concurrently
/// running test binaries on one server never collide and the prefix-scoped purge
/// scans observe only this test's keys — isolation without a destructive
/// `FLUSHDB` that a parallel binary could see mid-run.
pub async fn storage_with_raw(url_var: &str) -> Option<(Storage, MultiplexedConnection, String)> {
    let url = match std::env::var(url_var) {
        Ok(url) => url,
        Err(_) => {
            eprintln!("{url_var} not set; skipping suite");
            return None;
        }
    };
    let prefix = format!("doorman-test:{}:", Uuid::new_v4());
    let redis = RedisStorage::connect(&url)
        .await
        .expect("connect to redis/valkey")
        .with_prefix(prefix.clone());
    let raw = redis::Client::open(url)
        .expect("open raw redis client")
        .get_multiplexed_async_connection()
        .await
        .expect("open raw redis connection");
    let mem = InMemoryStorage::new();
    let storage = Storage {
        users: mem.user_store(),
        passkey_credentials: mem.passkey_credential_store(),
        sessions: redis.session_store(),
        verification_tokens: redis.verification_token_store(),
        passkey_challenges: redis.passkey_challenge_store(),
    };
    Some((storage, raw, prefix))
}
