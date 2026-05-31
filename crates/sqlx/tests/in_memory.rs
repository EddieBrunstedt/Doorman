//! Runs the storage-conformance suite against the in-memory reference
//! stores in `bauth-core`. This verifies the stores the docs point hosts
//! at as a worked reference actually satisfy the same contract enforced
//! against the SQLx adapters, with no database or feature flag required.

mod conformance;

use bauth_core::storage::Storage;

#[tokio::test]
async fn in_memory_storage_conformance() {
    let storage = Storage::in_memory();
    conformance::run(&storage).await;
}
