//! Runs the shared storage-conformance suite against the SQLx + Postgres
//! adapter.
//!
//! Skipped unless the `PG_URL` environment variable points at a
//! disposable test database. CI provides this via a containerised
//! Postgres; locally you can set
//! `PG_URL=postgres://postgres:postgres@localhost/doorman_test`.
//!
//! The test wipes the database's `public` schema before running so the
//! migration state is fresh on every invocation. Do not point `PG_URL`
//! at a database whose `public` schema holds data you want to keep.

#![cfg(feature = "postgres")]

mod conformance;

use doorman_sqlx::PostgresStorage;
use sqlx::PgPool;

#[tokio::test]
async fn postgres_storage_conformance() {
    let url = match std::env::var("PG_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("PG_URL not set; skipping Postgres conformance suite");
            return;
        }
    };

    let pool = PgPool::connect(&url).await.expect("pg connect");
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&pool)
        .await
        .expect("drop schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("create schema");

    let storage = PostgresStorage::from_pool(pool);
    storage.migrate().await.expect("migrate");
    conformance::run(&storage.all_stores()).await;
    conformance::run_db_backed(&storage.all_stores()).await;
}
