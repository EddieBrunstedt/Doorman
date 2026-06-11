//! Runs the shared storage-conformance suite against MariaDB.
//!
//! MariaDB speaks the same wire protocol and the SQL this adapter emits, so the
//! identical suite runs unchanged through the one sqlx `MySql` driver; only the
//! target server differs. Running both this and the MySQL suite is what catches
//! any MySQL/MariaDB drift mechanically rather than by inspection.
//!
//! Self-contained: it starts a throwaway MariaDB container via `testcontainers`,
//! so it needs a running Docker daemon and nothing else. There is no
//! environment-variable branch and no external database — every run gets a
//! fresh, empty server that is removed when the test ends.
//!
//! It is `#[ignore]`d so the plain `cargo test` / `--all-features` run (which
//! also executes inside the containerised CI jobs that have no Docker socket)
//! does not invoke it. Run it explicitly where Docker is available — the CI
//! `conformance` job and `just test-mysql` pass `--include-ignored`.

#![cfg(feature = "mysql")]

mod common;

use testcontainers_modules::mariadb::Mariadb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
#[ignore = "requires Docker (testcontainers); run via the conformance job or --include-ignored"]
async fn mariadb_storage_conformance() {
    // The container is removed when this guard drops at the end of the test. The
    // image starts the root user with no password and a `test` database.
    let node = Mariadb::default()
        .start()
        .await
        .expect("start mariadb container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(3306).await.expect("container port");
    let url = format!("mysql://root@{host}:{port}/test");

    common::run_conformance(&url).await;
}
