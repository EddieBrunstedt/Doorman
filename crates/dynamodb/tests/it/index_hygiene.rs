use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use chrono::{DateTime, Duration, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{Session, SessionId, UserId};
use doorman_dynamodb::DynamoDbStorage;
use testcontainers_modules::dynamodb_local::DynamoDb;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const TABLE: &str = "doorman-index-hygiene";

fn session(user_id: UserId, token: &str, now: DateTime<Utc>) -> Session {
    Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(token),
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    }
}

async fn evict(client: &Client, id: SessionId) {
    client
        .delete_item()
        .table_name(TABLE)
        .key("pk", AttributeValue::S(format!("session#{}", id.0)))
        .send()
        .await
        .expect("evict session row");
}

async fn indexed_ids(client: &Client, user_id: UserId) -> Option<Vec<String>> {
    let item = client
        .get_item()
        .table_name(TABLE)
        .key("pk", AttributeValue::S(format!("usess#{}", user_id.0)))
        .consistent_read(true)
        .send()
        .await
        .expect("get session index item")
        .item?;
    let mut ids = match item.get("session_ids") {
        Some(AttributeValue::Ss(ids)) => ids.clone(),
        _ => Vec::new(),
    };
    ids.sort();
    Some(ids)
}

async fn start() -> (ContainerAsync<DynamoDb>, Client, DynamoDbStorage) {
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
    let client = Client::from_conf(config);
    let storage = DynamoDbStorage::new(client.clone(), TABLE);
    storage.create_table().await.expect("create table");
    (node, client, storage)
}

#[tokio::test]
async fn dangling_session_ids_are_reclaimed() {
    let (_node, client, storage) = start().await;
    let sessions = storage.session_store();

    let now = Utc::now();
    let user_id = UserId::new();
    let kept = session(user_id, "hygiene-kept", now);
    let listed_away = session(user_id, "hygiene-listed-away", now);
    let purged_away = session(user_id, "hygiene-purged-away", now);
    for s in [&kept, &listed_away, &purged_away] {
        sessions
            .create_session(s.clone())
            .await
            .expect("create session");
    }

    evict(&client, listed_away.id).await;
    let listed = sessions.list_for_user(user_id).await.expect("list");
    let mut listed_ids: Vec<_> = listed.iter().map(|s| s.id).collect();
    listed_ids.sort_by_key(|id| id.0);
    let mut expected = vec![kept.id, purged_away.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(listed_ids, expected, "the evicted session is not listed");
    let mut expected_ids = vec![kept.id.0.to_string(), purged_away.id.0.to_string()];
    expected_ids.sort();
    assert_eq!(
        indexed_ids(&client, user_id).await,
        Some(expected_ids),
        "the listing dropped the dangling id",
    );

    evict(&client, purged_away.id).await;
    assert!(
        sessions.purge_expired(now).await.expect("purge") >= 1,
        "the purge counts the dangling id it reclaimed",
    );
    assert_eq!(
        indexed_ids(&client, user_id).await,
        Some(vec![kept.id.0.to_string()]),
        "the purge dropped the dangling id and kept the live one",
    );

    assert_eq!(
        sessions
            .delete_sessions_for_user(user_id, None)
            .await
            .expect("revoke"),
        1,
    );
    assert_eq!(
        indexed_ids(&client, user_id).await,
        None,
        "the emptied index item is deleted",
    );
}

#[tokio::test]
async fn dangling_token_hash_items_are_reclaimed() {
    let (_node, client, storage) = start().await;
    let sessions = storage.session_store();

    let now = Utc::now();
    let user_id = UserId::new();
    let kept = session(user_id, "hash-kept", now);
    let found_away = session(user_id, "hash-found-away", now);
    let purged_away = session(user_id, "hash-purged-away", now);
    for s in [&kept, &found_away, &purged_away] {
        sessions
            .create_session(s.clone())
            .await
            .expect("create session");
    }

    evict(&client, found_away.id).await;
    assert!(
        sessions
            .find_session_by_token_hash(&found_away.token_hash)
            .await
            .expect("find by hash")
            .is_none(),
        "an evicted session does not resolve by its token hash",
    );
    assert!(
        !hash_item_exists(&client, &found_away).await,
        "the lookup dropped the dangling token hash item",
    );

    evict(&client, purged_away.id).await;
    sessions.purge_expired(now).await.expect("purge");
    assert!(
        !hash_item_exists(&client, &purged_away).await,
        "the purge dropped the dangling token hash item",
    );
    assert!(
        hash_item_exists(&client, &kept).await,
        "the purge kept the live session's token hash item",
    );
}

async fn hash_item_exists(client: &Client, session: &Session) -> bool {
    client
        .get_item()
        .table_name(TABLE)
        .key(
            "pk",
            AttributeValue::S(format!(
                "shash#{}",
                doorman_core::encoding::hex(&session.token_hash.0)
            )),
        )
        .consistent_read(true)
        .send()
        .await
        .expect("get token hash item")
        .item
        .is_some()
}
