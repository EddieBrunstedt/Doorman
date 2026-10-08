use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::{AttributeValue, TimeToLiveStatus};
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use chrono::{DateTime, Duration, Utc};
use doorman_core::encoding::hex;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, PasskeyChallengeId, RegistrationPurpose,
    Session, SessionId, StoredPasskeyAuthentication, StoredPasskeyRegistration, UserId,
};
use doorman_dynamodb::DynamoDbStorage;
use testcontainers_modules::dynamodb_local::DynamoDb;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const TABLE: &str = "doorman-native-expiry";

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

async fn ttl_of(client: &Client, pk: String) -> Option<i64> {
    let item = client
        .get_item()
        .table_name(TABLE)
        .key("pk", AttributeValue::S(pk.clone()))
        .consistent_read(true)
        .send()
        .await
        .expect("get item")
        .item
        .unwrap_or_else(|| panic!("{pk} exists"));
    match item.get("ttl") {
        Some(AttributeValue::N(n)) => Some(n.parse().expect("numeric ttl")),
        _ => None,
    }
}

fn deadline(expires_at: DateTime<Utc>) -> Option<i64> {
    Some(expires_at.timestamp())
}

#[tokio::test]
async fn every_row_expires_at_its_deadline() {
    let (_node, client, storage) = start().await;
    let stores = storage.expiring();
    let now = Utc::now();

    let ttl = client
        .describe_time_to_live()
        .table_name(TABLE)
        .send()
        .await
        .expect("describe time to live")
        .time_to_live_description
        .expect("time to live description");
    assert_eq!(ttl.attribute_name(), Some("ttl"));
    assert_eq!(ttl.time_to_live_status(), Some(&TimeToLiveStatus::Enabled));

    let session = Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token("native-expiry-session"),
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let session_pk = format!("session#{}", session.id.0);
    stores
        .sessions
        .create_session(session.clone())
        .await
        .expect("create session");
    assert_eq!(
        ttl_of(&client, session_pk.clone()).await,
        deadline(session.expires_at),
        "the session expires at its deadline",
    );

    let slid = now + Duration::hours(2);
    stores
        .sessions
        .touch_session(session.id, now, slid)
        .await
        .expect("touch session");
    assert_eq!(
        ttl_of(&client, session_pk).await,
        deadline(slid),
        "the session expires at the slid deadline",
    );

    let link = EmailLink {
        token_hash: hash_token("native-expiry-link"),
        user_id: UserId::new(),
        purpose: EmailLinkPurpose::Signup,
        new_email: None,
        created_at: now,
        expires_at: now + Duration::minutes(30),
    };
    stores
        .email_links
        .replace_link(link.clone())
        .await
        .expect("replace link");
    assert_eq!(
        ttl_of(&client, format!("email_link#{}", hex(&link.token_hash.0))).await,
        deadline(link.expires_at),
        "the email link expires at its deadline",
    );

    let registration = StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        purpose: RegistrationPurpose::Signup,
        user_id: UserId::new(),
        state: b"registration-state".to_vec(),
        created_at: now,
        expires_at: now + Duration::minutes(5),
        recovery_cool_down_until: None,
    };
    stores
        .passkey_challenges
        .put_registration(registration.clone())
        .await
        .expect("put registration");
    assert_eq!(
        ttl_of(&client, format!("pkreg#{}", registration.id.0)).await,
        deadline(registration.expires_at),
        "the passkey registration expires at its deadline",
    );

    let authentication = StoredPasskeyAuthentication {
        id: PasskeyChallengeId::new(),
        purpose: AuthenticationPurpose::Login,
        state: b"authentication-state".to_vec(),
        created_at: now,
        expires_at: now + Duration::minutes(4),
    };
    stores
        .passkey_challenges
        .put_authentication(authentication.clone())
        .await
        .expect("put authentication");
    assert_eq!(
        ttl_of(&client, format!("pkauth#{}", authentication.id.0)).await,
        deadline(authentication.expires_at),
        "the passkey authentication expires at its deadline",
    );
}
