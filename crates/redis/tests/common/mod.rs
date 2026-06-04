//! Shared helpers for the Redis/Valkey integration tests.

use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::Storage;
use doorman_redis::RedisStorage;
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
/// `PG_URL` pattern. Each call uses a unique key prefix, so concurrently-running
/// test binaries on one server never collide and the prefix-scoped purge scans
/// observe only this test's keys — isolation without a destructive `FLUSHDB`
/// that a parallel binary could see mid-run.
pub async fn storage(url_var: &str) -> Option<Storage> {
    let url = match std::env::var(url_var) {
        Ok(url) => url,
        Err(_) => {
            eprintln!("{url_var} not set; skipping suite");
            return None;
        }
    };
    let redis = RedisStorage::connect(&url)
        .await
        .expect("connect to redis/valkey")
        .with_prefix(format!("doorman-test:{}:", Uuid::new_v4()));
    let mem = InMemoryStorage::new();
    Some(Storage {
        users: mem.user_store(),
        passkey_credentials: mem.passkey_credential_store(),
        sessions: redis.session_store(),
        verification_tokens: redis.verification_token_store(),
        passkey_challenges: redis.passkey_challenge_store(),
    })
}
