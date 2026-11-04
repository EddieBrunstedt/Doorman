use chrono::Utc;
use doorman_core::error::StorageErrorKind;
use doorman_core::storage::{User, UserId, UserStatus};
use doorman_mongodb::MongoDbStorage;
use mongodb::bson::{Document, doc};
use mongodb::error::ErrorKind;
use mongodb::{Client, IndexModel};
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

async fn mongo() -> (ContainerAsync<Mongo>, Client) {
    let node = Mongo::default()
        .start()
        .await
        .expect("start mongodb container");
    let host = node.get_host().await.expect("container host");
    let port = node
        .get_host_port_ipv4(27017)
        .await
        .expect("container port");
    let client = Client::with_uri_str(format!("mongodb://{host}:{port}/"))
        .await
        .expect("connect to mongodb");
    (node, client)
}

fn user(email: &str) -> User {
    let now = Utc::now();
    User {
        id: UserId::new(),
        email: Some(email.into()),
        signed_up_at: Some(now),
        status: UserStatus::Active,
        created_at: now,
        updated_at: now,
    }
}

// Every process the host starts opens the storage again on the same database.
#[tokio::test]
async fn storage_opens_again_on_a_database_it_already_set_up() {
    let (_node, client) = mongo().await;
    let database = client.database("doorman_open_again");

    MongoDbStorage::new(database.clone())
        .await
        .expect("open storage")
        .records()
        .users
        .create_user(user("alice@example.com"))
        .await
        .expect("create user");

    let reopened = MongoDbStorage::new(database)
        .await
        .expect("open storage again");
    let duplicate = reopened
        .records()
        .users
        .create_user(user("alice@example.com"))
        .await
        .expect_err("a second user with the same email");
    assert_eq!(duplicate.kind(), StorageErrorKind::Conflict);
}

// An index left under doorman's name without its uniqueness would let two users share an email.
#[tokio::test]
async fn storage_refuses_to_open_over_an_index_it_did_not_build() {
    let (_node, client) = mongo().await;
    let database = client.database("doorman_conflicting_index");
    database
        .collection::<Document>("users")
        .create_index(
            IndexModel::builder()
                .keys(doc! { "email": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .name("idx_users_email".to_string())
                        .build(),
                )
                .build(),
        )
        .await
        .expect("create a non-unique email index");

    let refused = MongoDbStorage::new(database)
        .await
        .err()
        .expect("the storage doesn't open without its unique email index");
    assert!(
        matches!(
            refused.kind.as_ref(),
            ErrorKind::Command(command) if command.code_name == "IndexKeySpecsConflict",
        ),
        "refused for the conflicting index, not {refused}",
    );
}
