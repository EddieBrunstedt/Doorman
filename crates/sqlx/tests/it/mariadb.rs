#![cfg(feature = "mysql")]

use crate::common;

use testcontainers_modules::mariadb::Mariadb;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::core::Mount;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn mariadb_storage_conformance() {
    // A tmpfs data directory cuts the server's first-boot initialisation from
    // about 25s to 6s.
    let node = Mariadb::default()
        .with_mount(Mount::tmpfs_mount("/var/lib/mysql"))
        .start()
        .await
        .expect("start mariadb container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(3306).await.expect("container port");
    let url = format!("mysql://root@{host}:{port}/test");

    common::run_conformance(&url).await;
}
