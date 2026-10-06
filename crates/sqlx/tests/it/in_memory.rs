use doorman_core::memory::InMemoryStorage;

#[tokio::test]
async fn in_memory_storage_conformance() {
    let storage = InMemoryStorage::new().all_stores();
    doorman_conformance::run(&storage).await;
}
