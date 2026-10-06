use doorman_sqlx::MySqlStorage;
use sqlx::MySqlPool;

pub async fn run_conformance(url: &str) {
    let pool = MySqlPool::connect(url).await.expect("mysql connect");
    let storage = MySqlStorage::from_pool(pool);
    storage.migrate().await.expect("migrate");
    doorman_conformance::run(&storage.all_stores()).await;
}
