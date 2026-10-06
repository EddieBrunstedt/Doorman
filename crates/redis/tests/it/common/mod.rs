use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::Storage;
use doorman_redis::RedisStorage;
use redis::aio::MultiplexedConnection;
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::valkey::Valkey;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub enum Backend {
    Redis,
    Valkey,
}

// Only held so the container lives as long as the test.
pub type ContainerGuard = Box<dyn std::any::Any + Send>;

pub async fn start(backend: Backend) -> (ContainerGuard, String) {
    match backend {
        Backend::Redis => {
            let node = Redis::default()
                .with_tag("7-alpine")
                .start()
                .await
                .expect("start redis container");
            let host = node.get_host().await.expect("container host");
            let port = node.get_host_port_ipv4(6379).await.expect("container port");
            (Box::new(node), format!("redis://{host}:{port}"))
        }
        Backend::Valkey => {
            let node = Valkey::default()
                .start()
                .await
                .expect("start valkey container");
            let host = node.get_host().await.expect("container host");
            let port = node.get_host_port_ipv4(6379).await.expect("container port");
            (Box::new(node), format!("redis://{host}:{port}"))
        }
    }
}

pub async fn storage(backend: Backend) -> (ContainerGuard, Storage) {
    let (guard, storage, _, _) = storage_with_raw(backend).await;
    (guard, storage)
}

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
        passkeys: mem.passkey_store(),
        sessions: redis.session_store(),
        email_links: redis.email_link_store(),
        passkey_challenges: redis.passkey_challenge_store(),
    };
    (guard, storage, raw, prefix)
}
