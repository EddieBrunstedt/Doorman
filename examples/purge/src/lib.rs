use std::env;

use doorman::core::storage::Storage;
use doorman::sqlx::SqliteStorage;

pub async fn build_storage() -> Storage {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://doorman-purge-example.db?mode=rwc".to_owned());

    let storage = SqliteStorage::connect(&database_url)
        .await
        .expect("connect to the configured database");
    storage.migrate().await.expect("run storage migrations");
    storage.all_stores()
}
