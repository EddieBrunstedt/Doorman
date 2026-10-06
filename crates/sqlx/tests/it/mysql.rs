#![cfg(feature = "mysql")]

use crate::common;

use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn mysql_storage_conformance() {
    let node = Mysql::default()
        .start()
        .await
        .expect("start mysql container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(3306).await.expect("container port");
    let url = format!("mysql://root@{host}:{port}/test");

    common::run_conformance(&url).await;
}
