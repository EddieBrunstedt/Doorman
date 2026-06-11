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
//! fresh, empty server that is removed when the test ends. A running Docker
//! daemon is therefore a prerequisite for the workspace test run.

#![cfg(feature = "mysql")]

mod common;

use testcontainers_modules::mariadb::Mariadb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
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
