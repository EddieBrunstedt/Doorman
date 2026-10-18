use doorman_mongodb::MongoDbStorage;
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mongodb_storage_conformance() {
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
}
