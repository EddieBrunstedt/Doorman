//! Runs the shared storage-conformance suite against the MongoDB adapter.
//!
//! Self-contained: it starts a throwaway MongoDB container via
//! `testcontainers`, so it needs a running Docker daemon and nothing else.
//! Every run gets a fresh, empty server removed when the test ends — no
//! external URI or environment variable is consulted.
//!
//! The adapter uses a standalone MongoDB node (no replica set), which is
//! sufficient because the uniqueness and atomicity guarantees that doorman
//! relies on are provided by MongoDB's unique indexes and per-document write
//! serialisation rather than by multi-document transactions.

use doorman_mongodb::MongoDbStorage;
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn mongodb_storage_conformance() {
    // `_node` keeps the container alive until the end of the test.
    let node = Mongo::default()
        .start()
        .await
        .expect("start mongodb container");
    let host = node.get_host().await.expect("container host");
    let port = node
        .get_host_port_ipv4(27017)
        .await
        .expect("container port");

    let client = mongodb::Client::with_uri_str(format!("mongodb://{host}:{port}/"))
        .await
        .expect("connect to mongodb");
    let database = client.database("doorman_conformance");

    let storage = MongoDbStorage::new(database);
    storage.ensure_indexes().await.expect("ensure indexes");

    doorman_conformance::run(&storage.all_stores()).await;
    // The session store pushes `expires_at > now` into `list_for_user`, so it
    // satisfies the database-backed assertions too.
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
