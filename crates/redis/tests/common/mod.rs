//! Shared helpers for the Redis/Valkey integration tests.
//!
//! Each test binary compiles this module independently, and not every binary
//! uses every helper, so allow dead code here rather than per item.
#![allow(dead_code)]

use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::Storage;
use doorman_redis::RedisStorage;
use redis::aio::MultiplexedConnection;
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::valkey::Valkey;
use uuid::Uuid;

/// Which RESP server a test targets. Running the identical suite against both
/// is what catches any Redis/Valkey drift mechanically (§3).
#[derive(Clone, Copy)]
pub enum Backend {
    Redis,
    Valkey,
}

/// Keeps a throwaway container alive for the duration of a test; dropping it
/// removes the container. The two backends produce different container types,
/// so this enum gives the helpers one return type to hand back.
pub enum ContainerGuard {
    Redis(ContainerAsync<Redis>),
    Valkey(ContainerAsync<Valkey>),
}

/// Start a throwaway container for `backend` and return its guard plus a
/// `redis://` URL pointing at it. Valkey speaks the same RESP protocol, so the
/// `redis` client library connects to either unchanged.
///
/// The returned guard must stay in scope for the whole test — drop it and the
/// container (and the server) goes away.
pub async fn start(backend: Backend) -> (ContainerGuard, String) {
    match backend {
        Backend::Redis => {
            // The module defaults to redis:5.0, which predates GETDEL (6.2+),
            // a command this adapter relies on; pin a modern tag.
            let node = Redis::default()
                .with_tag("7-alpine")
                .start()
                .await
                .expect("start redis container");
            let host = node.get_host().await.expect("container host");
            let port = node.get_host_port_ipv4(6379).await.expect("container port");
            (
                ContainerGuard::Redis(node),
                format!("redis://{host}:{port}"),
            )
        }
        Backend::Valkey => {
            let node = Valkey::default()
                .start()
                .await
                .expect("start valkey container");
            let host = node.get_host().await.expect("container host");
            let port = node.get_host_port_ipv4(6379).await.expect("container port");
            (
                ContainerGuard::Valkey(node),
                format!("redis://{host}:{port}"),
            )
        }
    }
}

/// Build a [`Storage`] whose three ephemeral stores are backed by a throwaway
/// `backend` container and whose two system-of-record stores are filled by an
/// in-memory backend.
///
/// Pairing the Redis ephemeral stores with in-memory `users` /
/// `passkey_credentials` lets the shared conformance suite run end to end: the
/// suite exercises every Redis-backed method, and the in-memory fillers stand
/// in only for the two stores the adapter intentionally omits (§6).
pub async fn storage(backend: Backend) -> (ContainerGuard, Storage) {
    let (guard, storage, _, _) = storage_with_raw(backend).await;
    (guard, storage)
}

/// Like [`storage`], but also returns a raw connection to the same server and
/// the key prefix the Redis stores use.
///
/// Tests that must reach behind the store API — to delete a primary row
/// directly and simulate TTL eviction, or to assert a key was reclaimed — build
/// the namespaced key from `prefix` (mirroring `keys.rs`) and issue commands on
/// the raw connection. Each container is private to its test, so the prefix is
/// not needed for isolation, but the stores still namespace under it and the
/// raw-connection tests reconstruct keys from it.
pub async fn storage_with_raw(
    backend: Backend,
) -> (ContainerGuard, Storage, MultiplexedConnection, String) {
    let (guard, url) = start(backend).await;
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
    (guard, storage, raw, prefix)
}
