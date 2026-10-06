use crate::common;

use crate::common::Backend;

#[tokio::test]
async fn redis_storage_conformance() {
    let (_node, storage) = common::storage(Backend::Redis).await;
    doorman_conformance::run(&storage).await;
}

#[tokio::test]
async fn valkey_storage_conformance() {
    let (_node, storage) = common::storage(Backend::Valkey).await;
    doorman_conformance::run(&storage).await;
}
