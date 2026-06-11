//! Runs the shared storage-conformance suite against the SQLx + MySQL adapter.
//!
//! Self-contained: it starts a throwaway MySQL container via `testcontainers`,
//! so it needs a running Docker daemon and nothing else. There is no
//! environment-variable branch and no external database — every run gets a
//! fresh, empty server that is removed when the test ends. A running Docker
//! daemon is therefore a prerequisite for the workspace test run.

#![cfg(feature = "mysql")]

mod common;

use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn mysql_storage_conformance() {
    // The container is removed when this guard drops at the end of the test. The
    // image starts the root user with no password and a `test` database.
    let node = Mysql::default()
        .start()
        .await
        .expect("start mysql container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(3306).await.expect("container port");
    let url = format!("mysql://root@{host}:{port}/test");

    common::run_conformance(&url).await;
}
