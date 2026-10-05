//! Shared tail for the MySQL/MariaDB conformance tests.
//!
//! Each suite starts its own throwaway container (MySQL and MariaDB
//! respectively) and then runs the identical storage-conformance suite through
//! the one sqlx `MySql` driver against that fresh server. This helper holds the
//! part they share: connect, migrate, run. Running both servers is what catches
//! MySQL/MariaDB drift mechanically rather than by inspection.
//!
//! Each test binary compiles this module independently, so allow dead code here
//! rather than per item.
#![allow(dead_code)]

use doorman_sqlx::MySqlStorage;
use sqlx::MySqlPool;

/// Connect to the MySQL/MariaDB server at `url`, run the migrations against its
/// fresh schema, and execute the full storage-conformance suite.
///
/// The caller supplies a just-started, empty container, so there is no schema to
/// reset first — the migrations apply from scratch.
pub async fn run_conformance(url: &str) {
    let pool = MySqlPool::connect(url).await.expect("mysql connect");
    let storage = MySqlStorage::from_pool(pool);
    storage.migrate().await.expect("migrate");
    doorman_conformance::run(&storage.all_stores()).await;
}
