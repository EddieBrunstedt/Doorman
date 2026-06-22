//! Proves the "override one sub-store method, reuse the rest" pattern on the
//! MongoDB adapter: a host wraps the bundled `Arc<dyn SessionStore>`, writes the
//! session via the public [`session_to_document`] encoder into the public
//! [`MongoDbStorage::sessions_collection`], writes its own audit document, and
//! delegates every read/delete. The delegated reads still find the row, proving
//! the host's write carries the encoding the bundled reads expect.
//!
//! The throwaway container is a **standalone** node, so the two inserts here run
//! sequentially rather than in one transaction. On a replica set a host would
//! wrap both in a `mongodb::ClientSession` transaction for fail-closed audit;
//! that atomicity is a property of the deployment, not of this adapter, and is
//! not what this test guards — it guards the encoding parity and wiring.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use doorman_core::error::StorageResult;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AccountStatus, Session, SessionId, SessionStore, Storage, TokenHash, User, UserId,
};
use doorman_mongodb::{MongoDbStorage, session_to_document};
use mongodb::Collection;
use mongodb::bson::{Document, doc};
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// A host's `SessionStore` that writes the session and its own audit document,
/// delegating every read/delete to the bundled store.
struct AuditedSessions {
    inner: Arc<dyn SessionStore>,
    sessions: Collection<Document>,
    audit: Collection<Document>,
}

#[async_trait]
impl SessionStore for AuditedSessions {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        // `session_to_document` produces the byte-identical encoding the bundled
        // reads expect, so a document written here is later found by the
        // delegated `find_session_by_token_hash`.
        self.sessions
            .insert_one(session_to_document(&session))
            .await
            .map_err(|e| doorman_core::error::StorageError::msg(e.to_string()))?;
        self.audit
            .insert_one(doc! {
                "_id": session.id.0.to_string(),
                "event": "session.created",
            })
            .await
            .map_err(|e| doorman_core::error::StorageError::msg(e.to_string()))?;
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
    let database = client.database("doorman_composability");
    let storage = MongoDbStorage::new(database.clone());
    storage.ensure_indexes().await.expect("ensure indexes");

    let composite = Storage {
        sessions: Arc::new(AuditedSessions {
            inner: storage.session_store(),
            sessions: storage.sessions_collection(),
            audit: database.collection::<Document>("audit_outbox"),
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
        .expect("custom create_session");

    let found = composite
        .sessions
        .find_session_by_token_hash(&session.token_hash)
        .await
        .expect("delegated read")
        .expect("session present");
    assert_eq!(found.id, session.id);
    assert_eq!(found.user_id, user_id);

    let audit_count = database
        .collection::<Document>("audit_outbox")
        .count_documents(doc! { "_id": session.id.0.to_string() })
        .await
        .expect("count audit docs");
    assert_eq!(audit_count, 1);
}
