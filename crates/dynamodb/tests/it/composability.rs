use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::{AttributeValue, Put, TransactWriteItem};
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use chrono::{DateTime, Duration, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::session::hash_token;
use doorman_core::storage::{
    Session, SessionId, SessionStore, Storage, TokenHash, User, UserId, UserStatus,
};
use doorman_dynamodb::{DynamoDbStorage, create_session_writes};
use testcontainers_modules::dynamodb_local::DynamoDb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

struct AuditedSessions {
    inner: Arc<dyn SessionStore>,
    client: Client,
    table: String,
}

#[async_trait]
impl SessionStore for AuditedSessions {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let mut writes = create_session_writes(&self.table, &session)?;
        let audit_put = Put::builder()
            .table_name(&self.table)
            .item("pk", AttributeValue::S(format!("audit#{}", session.id.0)))
            .item("event", AttributeValue::S("session.created".to_string()))
            .build()
            .map_err(|e| StorageError::msg(e.to_string()))?;
        writes.push(TransactWriteItem::builder().put(audit_put).build());
        self.client
            .transact_write_items()
            .set_transact_items(Some(writes))
            .send()
            .await
            .map_err(|e| StorageError::msg(e.to_string()))?;
        Ok(())
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.touch_session(id, last_used_at, expires_at).await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        self.inner.find_session_by_token_hash(hash).await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.inner.find_session_by_id(id).await
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        self.inner.list_for_user(user_id, now).await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.inner.delete_session(id).await
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        self.inner.delete_sessions_for_user(user_id, except).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.inner.purge_expired(now).await
    }
}

#[tokio::test]
async fn override_create_session_reuses_bundled_reads() {
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

    let storage = DynamoDbStorage::new(client.clone(), "doorman-composability");
    storage.create_table().await.expect("create table");

    let composite = Storage {
        sessions: Arc::new(AuditedSessions {
            inner: storage.session_store(),
            client: client.clone(),
            table: storage.table_name().to_string(),
        }),
        ..storage.all_stores()
    };

    let user_id = UserId::new();
    composite
        .users
        .create_user(User {
            id: user_id,
            email: Some("audited@example.com".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .expect("create user");

    let now = Utc::now();
    let session = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("composability-token"),
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    };

    composite
        .sessions
        .create_session(session.clone())
        .await
        .expect("transactional create_session");

    let found = composite
        .sessions
        .find_session_by_token_hash(&session.token_hash)
        .await
        .expect("delegated read")
        .expect("session present");
    assert_eq!(found.id, session.id);
    assert_eq!(found.user_id, user_id);
    assert_eq!(
        composite
            .sessions
            .list_for_user(user_id, now)
            .await
            .expect("delegated list")
            .len(),
        1,
        "the session is listed",
    );

    let audit = client
        .get_item()
        .table_name(storage.table_name())
        .key("pk", AttributeValue::S(format!("audit#{}", session.id.0)))
        .send()
        .await
        .expect("get audit item");
    assert!(audit.item().is_some(), "audit item present");

    assert_eq!(
        composite
            .sessions
            .delete_sessions_for_user(user_id, None)
            .await
            .expect("delegated revoke"),
        1,
    );
    assert!(
        composite
            .sessions
            .find_session_by_id(session.id)
            .await
            .expect("find after revoke")
            .is_none(),
        "the revoke deleted the session",
    );
}
