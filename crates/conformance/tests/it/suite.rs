use doorman_core::memory::InMemoryStorage;

#[tokio::test]
#[should_panic(expected = "needs at least 2 runtime workers, got 1")]
async fn the_suite_refuses_a_runtime_that_cannot_race() {
    let storage = InMemoryStorage::new().all_stores();
    doorman_conformance::run(&storage).await;
}
