//! Runs the shared storage-conformance suite against a remote libSQL server.
//!
//! Self-contained: it starts a throwaway [libsql-server (sqld)] container via
//! `testcontainers`, so it needs a running Docker daemon and nothing else. Every
//! run gets a fresh, empty server that is removed when the test ends. This is
//! the adapter's only connection mode — the Hrana/remote client a Turso
//! deployment uses — so it is the whole conformance surface.
//!
//! The container is reached over plain HTTP with an empty auth token: a default
//! sqld enables no JWT auth, so no credentials are needed.
//!
//! [libsql-server (sqld)]: https://github.com/tursodatabase/libsql/tree/main/libsql-server

use doorman_libsql::LibsqlStorage;
use testcontainers_modules::testcontainers::GenericImage;
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn remote_storage_conformance() {
    // `_node` keeps the container alive until the end of the test.
    let node = GenericImage::new("ghcr.io/tursodatabase/libsql-server", "latest")
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stdout(
            "listening for incoming user HTTP connection",
        ))
        .start()
        .await
        .expect("start libsql-server container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(8080).await.expect("container port");

    let storage = LibsqlStorage::connect_remote(format!("http://{host}:{port}"), String::new())
        .await
        .expect("connect to remote libsql-server");
    storage.migrate().await.expect("migrate");

    doorman_conformance::run(&storage.all_stores()).await;
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
