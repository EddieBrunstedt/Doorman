use crate::common;

use crate::common::Backend;

async fn run(backend: Backend) {
    let (_node, stores) = common::stores(backend).await;
    doorman_conformance::run_expiring(&stores).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_storage_conformance() {
    run(Backend::Redis).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valkey_storage_conformance() {
    run(Backend::Valkey).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_cluster_storage_conformance() {
    run(Backend::RedisCluster).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valkey_cluster_storage_conformance() {
    run(Backend::ValkeyCluster).await;
}
