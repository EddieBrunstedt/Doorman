use doorman_core::storage::ExpiringStores;
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

pub async fn stores(backend: Backend) -> (ContainerGuard, ExpiringStores) {
    let (guard, stores, _, _) = stores_with_raw(backend).await;
    (guard, stores)
}

pub async fn stores_with_raw(
    backend: Backend,
) -> (
    ContainerGuard,
    ExpiringStores,
    MultiplexedConnection,
    String,
) {
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
    (guard, redis.expiring(), raw, prefix)
}
