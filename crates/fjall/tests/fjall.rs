//! Runs the shared storage-conformance suite against the fjall adapter.
//!
//! Self-contained: a temporary directory is created by `tempfile` and removed
//! when the test process exits. No Docker daemon and no external server are
//! needed.

use doorman_fjall::FjallStorage;

#[tokio::test]
async fn fjall_storage_conformance() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("conformance.fjall");

    let storage = FjallStorage::open(&path).expect("open fjall");

    doorman_conformance::run(&storage.all_stores()).await;
    // fjall pushes the `expires_at > now` predicate into `list_for_user`,
    // so the database-backed extra assertions hold too.
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
