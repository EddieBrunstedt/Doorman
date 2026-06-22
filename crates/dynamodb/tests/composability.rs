//! Proves the "override one sub-store method, reuse the rest" pattern on the
//! DynamoDB adapter: a host wraps the bundled `Arc<dyn SessionStore>` and makes
//! `create_session` a single [`TransactWriteItems`] over the public
//! [`session_item`] plus its own audit item — fail-closed audit, committed
//! atomically — while delegating every read/delete. The delegated reads then
//! find the row, proving the host's write carries the encoding the bundled
//! reads expect.
//!
//! Self-contained: starts a throwaway DynamoDB Local container, which supports
//! `TransactWriteItems`, so the transaction is exercised for real.
//!
//! [`TransactWriteItems`]: aws_sdk_dynamodb::operation::transact_write_items

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
    AccountStatus, Session, SessionId, SessionStore, Storage, TokenHash, User, UserId,
};
use doorman_dynamodb::{DynamoDbStorage, session_item};
use testcontainers_modules::dynamodb_local::DynamoDb;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// A host's `SessionStore` that commits the session item and its own audit item
/// in one DynamoDB transaction, delegating every read/delete to the bundled
/// store.
struct AuditedSessions {
    inner: Arc<dyn SessionStore>,
    client: Client,
    table: String,
}

#[async_trait]
impl SessionStore for AuditedSessions {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        // `session_item` produces the byte-identical item the bundled reads
        // expect (including the GSI keys), so a row written here is later found
        // by the delegated `find_session_by_token_hash`.
        let session_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(session_item(&session)))
            .build()
            .map_err(|e| StorageError::msg(e.to_string()))?;
        let audit_put = Put::builder()
            .table_name(&self.table)
            .item("pk", AttributeValue::S(format!("audit#{}", session.id.0)))
            .item("event", AttributeValue::S("session.created".to_string()))
            .build()
            .map_err(|e| StorageError::msg(e.to_string()))?;
        self.client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(session_put).build())
            .transact_items(TransactWriteItem::builder().put(audit_put).build())
            .send()
            .await
            .map_err(|e| StorageError::msg(e.to_string()))?;
        Ok(())
    }

    async fn touch_session(&self, session: &Session) -> StorageResult<()> {
        self.inner.touch_session(session).await
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

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.inner.delete_sessions_for_user(user_id).await
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        self.inner
            .delete_other_sessions_for_user(user_id, except)
            .await
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
            status: AccountStatus::Active,
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
        recovery_cooldown_until: None,
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

    // The host's audit item committed in the same transaction.
    let audit = client
        .get_item()
        .table_name(storage.table_name())
        .key("pk", AttributeValue::S(format!("audit#{}", session.id.0)))
        .send()
        .await
        .expect("get audit item");
    assert!(audit.item().is_some(), "audit item present");
}
