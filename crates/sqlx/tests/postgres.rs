//! Runs the shared storage-conformance suite against the SQLx + Postgres
//! adapter.
//!
//! Self-contained: it starts a throwaway Postgres container via
//! `testcontainers`, so it needs a running Docker daemon and nothing else.
//! There is no environment-variable branch and no external database — every
//! run gets a fresh, empty server that is removed when the test ends. A running
//! Docker daemon is therefore a prerequisite for the workspace test run.

#![cfg(feature = "postgres")]

use doorman_sqlx::PostgresStorage;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn postgres_storage_conformance() {
    // The container is removed when this guard drops at the end of the test.
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
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
