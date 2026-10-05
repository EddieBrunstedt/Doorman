mod common;

use common::Backend;

#[tokio::test]
async fn valkey_storage_conformance() {
    let (_node, storage) = common::storage(Backend::Valkey).await;
    doorman_conformance::run(&storage).await;
}
