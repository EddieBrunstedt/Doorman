#![cfg(feature = "postgres")]

use doorman_sqlx::PostgresStorage;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn postgres_storage_conformance() {
    let node = Postgres::default()
        .start()
        .await
        .expect("start postgres container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(5432).await.expect("container port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let pool = PgPool::connect(&url).await.expect("pg connect");
    let storage = PostgresStorage::from_pool(pool);
    storage.migrate().await.expect("migrate");
    doorman_conformance::run(&storage.all_stores()).await;
}
