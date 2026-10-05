//! Runs the shared storage-conformance suite against the DynamoDB adapter.
//!
//! Self-contained: it starts a throwaway DynamoDB Local container via
//! `testcontainers`, so it needs a running Docker daemon and nothing else.
//! There is no environment-variable branch and no external table — every run
//! provisions a fresh table in a throwaway container that is removed when the
//! test ends. A running Docker daemon is therefore a prerequisite for the
//! workspace test run.
//!
//! The SDK client is built with a ring-backed rustls HTTP client (rather than
//! `aws-config`, whose default TLS pulls `aws-lc`) so the test tree stays on the
//! workspace's single ring crypto stack. Credentials are dummies: DynamoDB Local
//! does not authenticate.
//!
//! DynamoDB Local's GSIs need not lag the way a real table's do, so passing
//! here does not show that a path is safe against GSI lag.

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use doorman_dynamodb::DynamoDbStorage;
use testcontainers_modules::dynamodb_local::DynamoDb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn dynamodb_storage_conformance() {
    // `_node` keeps the container alive until the end of the test.
    let node = DynamoDb::default()
        .start()
        .await
        .expect("start dynamodb-local container");
    let host = node.get_host().await.expect("container host");
    let port = node.get_host_port_ipv4(8000).await.expect("container port");

    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
        .build_https();
    let config = aws_sdk_dynamodb::config::Builder::default()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("fake", "fake", None, None, "test"))
        .endpoint_url(format!("http://{host}:{port}"))
        .http_client(http)
        .build();
    let client = aws_sdk_dynamodb::Client::from_conf(config);

    let storage = DynamoDbStorage::new(client, "doorman-conformance");
    storage.create_table().await.expect("create table");

    doorman_conformance::run(&storage.all_stores()).await;
}
