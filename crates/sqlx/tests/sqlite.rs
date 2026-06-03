//! Runs the shared storage-conformance suite against the SQLx + SQLite
//! adapter. The assertions live in `conformance`; this file only stands up
//! a fresh in-memory SQLite database and points the suite at it.

#![cfg(feature = "sqlite")]

mod conformance;

use doorman_sqlx::SqliteStorage;

#[tokio::test]
async fn sqlite_storage_conformance() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    conformance::run(&storage.storage()).await;
    conformance::run_db_backed(&storage.storage()).await;
}
