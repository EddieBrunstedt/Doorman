use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use doorman_dynamodb::DynamoDbStorage;
use testcontainers_modules::dynamodb_local::DynamoDb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn dynamodb_storage_conformance() {
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
