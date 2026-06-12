//! Runs the shared storage-conformance suite against the redb adapter.
//!
//! Self-contained: a temporary file is created by `tempfile` and removed when
//! the test process exits. No Docker daemon and no external server are needed.

use doorman_redb::RedbStorage;

#[tokio::test]
async fn redb_storage_conformance() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("conformance.redb");

    let storage = RedbStorage::open(&path).expect("open redb");

    doorman_conformance::run(&storage.all_stores()).await;
    // redb pushes the `expires_at > now` predicate into `list_for_user`,
    // so the database-backed extra assertions hold too.
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
