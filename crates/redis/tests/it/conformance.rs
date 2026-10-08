use crate::common;

use crate::common::Backend;

#[tokio::test]
async fn redis_storage_conformance() {
    let (_node, stores) = common::stores(Backend::Redis).await;
    doorman_conformance::run_expiring(&stores).await;
}

#[tokio::test]
async fn valkey_storage_conformance() {
    let (_node, stores) = common::stores(Backend::Valkey).await;
    doorman_conformance::run_expiring(&stores).await;
}
