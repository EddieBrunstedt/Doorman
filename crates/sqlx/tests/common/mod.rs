//! Shared helpers for the MySQL/MariaDB conformance tests.
//!
//! Each test binary compiles this module independently, and not every binary
//! uses every helper, so allow dead code here rather than per item.
#![allow(dead_code)]

use doorman_sqlx::MySqlStorage;
use sqlx::MySqlPool;

/// Connect to the database named by `url_var`, reset its schema, run the
/// migrations, and execute the full storage-conformance suite against it.
///
/// Returns early with a skip message when the env var is unset, mirroring the
/// `PG_URL` pattern. The same sqlx `MySql` driver serves both MySQL and
/// MariaDB, so this one helper backs both server suites; running both is what
/// catches MySQL/MariaDB drift mechanically rather than by inspection.
pub async fn run_conformance(url_var: &str) {
    let url = match std::env::var(url_var) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("{url_var} not set; skipping MySQL/MariaDB conformance suite");
            return;
        }
    };

    let pool = MySqlPool::connect(&url).await.expect("mysql connect");
    reset(&pool).await;

    let storage = MySqlStorage::from_pool(pool);
    storage.migrate().await.expect("migrate");
    doorman_conformance::run(&storage.all_stores()).await;
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}

/// Drop every table this adapter owns — children before parents so the foreign
/// keys never block the drop — plus sqlx's `_sqlx_migrations` ledger, so each
/// run starts from a clean schema and re-applies the migrations from scratch.
///
/// Do not point the URL at a database whose tables hold data you want to keep.
async fn reset(pool: &MySqlPool) {
    for table in [
        "passkey_authentications",
        "passkey_registrations",
        "passkey_credentials",
        "verification_tokens",
        "sessions",
        "users",
        "_sqlx_migrations",
    ] {
        let sql = format!("DROP TABLE IF EXISTS {table}");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(pool)
            .await
            .expect("drop table");
    }
}
