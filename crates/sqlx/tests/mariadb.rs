//! Runs the shared storage-conformance suite against MariaDB.
//!
//! MariaDB speaks the same wire protocol and the SQL this adapter emits, so the
//! identical suite runs unchanged through the one sqlx `MySql` driver; only the
//! target server differs. Skipped unless `MARIADB_URL` points at a disposable
//! test database (e.g. `MARIADB_URL=mysql://root:root@localhost:3307/doorman_test`,
//! which `just up` provides). Running both this and the MySQL suite is what
//! catches any MySQL/MariaDB drift mechanically rather than by inspection.

#![cfg(feature = "mysql")]

mod common;

#[tokio::test]
#[ignore = "pending testcontainers migration; see postgres.rs"]
async fn mariadb_storage_conformance() {
    common::run_conformance("MARIADB_URL").await;
}
