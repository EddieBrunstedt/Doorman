#![cfg(feature = "sqlite")]

use doorman_sqlx::SqliteStorage;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_storage_conformance() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");
    doorman_conformance::run(&storage.all_stores()).await;
}
