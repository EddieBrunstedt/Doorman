use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::session::hash_token;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};
use doorman_redb::{RedbStorage, write_session};
use redb::{Database, ReadableDatabase as _, TableDefinition};

const AUDIT: TableDefinition<&str, &str> = TableDefinition::new("audit_outbox");

fn err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError {
    StorageError::new(e)
}

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

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        self.inner.list_for_user(user_id).await
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
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("composability.redb");
    let storage = RedbStorage::open(&path).expect("open redb");

    let db = storage.database();
    let mut composite = storage.all_stores();
    composite.expiring.sessions = Arc::new(AuditedSessions {
        inner: composite.expiring.sessions.clone(),
        db: db.clone(),
    });

    let user_id = UserId::new();

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
        .expiring
        .sessions
        .create_session(session.clone())
        .await
        .expect("transactional create_session");

    let by_hash = composite
        .expiring
        .sessions
        .find_session_by_token_hash(&session.token_hash)
        .await
        .expect("delegated read")
        .expect("session present");
    assert_eq!(by_hash.id, session.id);
    let listed = composite
        .expiring
        .sessions
        .list_for_user(user_id)
        .await
        .expect("delegated list");
    assert!(listed.iter().any(|s| s.id == session.id));

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
