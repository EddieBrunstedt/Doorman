//! Proves the "override one sub-store method, reuse the rest" pattern on the
//! redb adapter: a host wraps the bundled `Arc<dyn SessionStore>` and makes
//! `create_session` write the session (via the public [`write_session`], which
//! maintains all three session tables) plus its own audit row in **one** redb
//! write transaction — fail-closed audit, committed atomically — while
//! delegating every read/delete. The delegated reads then find the row, proving
//! the host's write maintained the indexes the bundled reads depend on.
//!
//! Self-contained: a temporary redb file, no Docker or external server.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AccountStatus, Session, SessionId, SessionStore, Storage, TokenHash, User, UserId,
};
use doorman_redb::{RedbStorage, write_session};
use redb::{Database, ReadableDatabase as _, TableDefinition};

/// The host's own audit table, living in the same redb file as doorman's tables.
const AUDIT: TableDefinition<&str, &str> = TableDefinition::new("audit_outbox");

fn err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError {
    StorageError::new(e)
}

/// A host's `SessionStore` that commits the session and its own audit row in one
/// write transaction, delegating every read/delete to the bundled store.
struct AuditedSessions {
    inner: Arc<dyn SessionStore>,
    db: Arc<Database>,
}

#[async_trait]
impl SessionStore for AuditedSessions {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let wtxn = db.begin_write().map_err(err)?;
            // `write_session` maintains all three session tables the bundled
            // reads depend on; the host adds its own audit row to the same
            // transaction so the two commit atomically.
            write_session(&wtxn, &session)?;
            {
                let mut audit = wtxn.open_table(AUDIT).map_err(err)?;
                audit
                    .insert(session.id.0.to_string().as_str(), "session.created")
                    .map_err(err)?;
            }
            wtxn.commit().map_err(err)?;
            Ok(())
        })
        .await
        .map_err(err)?
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
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("composability.redb");
    let storage = RedbStorage::open(&path).expect("open redb");

    let db = storage.database();
    let composite = Storage {
        sessions: Arc::new(AuditedSessions {
            inner: storage.session_store(),
            db: db.clone(),
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

    // The delegated reads find the row the overridden write committed, proving
    // every session index was maintained.
    let by_hash = composite
        .sessions
        .find_session_by_token_hash(&session.token_hash)
        .await
        .expect("delegated read")
        .expect("session present");
    assert_eq!(by_hash.id, session.id);
    let listed = composite
        .sessions
        .list_for_user(user_id, now)
        .await
        .expect("delegated list");
    assert!(listed.iter().any(|s| s.id == session.id));

    // The host's audit row committed in the same transaction.
    let rtxn = db.begin_read().expect("read txn");
    let audit = rtxn.open_table(AUDIT).expect("open audit");
    let row = audit
        .get(session.id.0.to_string().as_str())
        .expect("get audit");
    assert_eq!(
        row.map(|g| g.value().to_owned()),
        Some("session.created".to_string())
    );
}
