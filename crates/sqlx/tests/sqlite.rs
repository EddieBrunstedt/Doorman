//! Runs the shared storage-conformance suite against the SQLx + SQLite
//! adapter. The assertions live in `doorman-conformance`; this file only stands up
//! a fresh in-memory SQLite database and points the suite at it.

#![cfg(feature = "sqlite")]

use doorman_sqlx::SqliteStorage;

#[tokio::test]
async fn sqlite_storage_conformance() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    doorman_conformance::run(&storage.all_stores()).await;
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
