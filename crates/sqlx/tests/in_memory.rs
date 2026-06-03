//! Runs the storage-conformance suite against the in-memory reference
//! stores in `doorman-core`. This verifies the stores the docs point hosts
//! at as a worked reference actually satisfy the same contract enforced
//! against the SQLx adapters, with no database or feature flag required.

mod conformance;

use doorman_core::memory::InMemoryStorage;

#[tokio::test]
async fn in_memory_storage_conformance() {
    let storage = InMemoryStorage::new().all_stores();
    conformance::run(&storage).await;
}
