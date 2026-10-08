#![cfg(feature = "sqlite")]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use doorman_core::error::StorageResult;
use doorman_core::session::hash_token;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};
use doorman_sqlx::SqliteStorage;
use sqlx::SqlitePool;

struct AuditedSessions {
    inner: Arc<dyn SessionStore>,
    pool: SqlitePool,
}

#[async_trait]
impl SessionStore for AuditedSessions {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, last_used_at, expires_at, ip, user_agent, recovery_cool_down_until)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.0.as_bytes().to_vec())
        .bind(session.user_id.0.as_bytes().to_vec())
        .bind(session.token_hash.0.to_vec())
        .bind(session.created_at)
        .bind(session.last_used_at)
        .bind(session.expires_at)
        .bind(&session.ip)
        .bind(&session.user_agent)
        .bind(session.recovery_cool_down_until)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        sqlx::query("INSERT INTO audit_outbox (session_id, event) VALUES (?, ?)")
            .bind(session.id.0.as_bytes().to_vec())
            .bind("session.created")
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
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

fn storage(e: sqlx::Error) -> doorman_core::error::StorageError {
    doorman_core::error::StorageError::msg(e.to_string())
}

#[tokio::test]
async fn override_create_session_reuses_bundled_reads() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    sqlx::query("CREATE TABLE audit_outbox (session_id BLOB NOT NULL, event TEXT NOT NULL)")
        .execute(storage.pool())
        .await
        .expect("create audit table");

    let mut composite = storage.all_stores();
    composite.expiring.sessions = Arc::new(AuditedSessions {
        inner: composite.expiring.sessions.clone(),
        pool: storage.pool().clone(),
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

    let found = composite
        .expiring
        .sessions
        .find_session_by_token_hash(&session.token_hash)
        .await
        .expect("delegated read")
        .expect("session present");
    assert_eq!(found.id, session.id);
    assert_eq!(found.user_id, user_id);

    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_outbox WHERE session_id = ?")
            .bind(session.id.0.as_bytes().to_vec())
            .fetch_one(storage.pool())
            .await
            .expect("count audit rows");
    assert_eq!(audit_count, 1);
}
