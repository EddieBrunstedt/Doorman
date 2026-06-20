//! Proves the "override one sub-store method, reuse the rest" pattern on the
//! SQLx adapter, which is the transactional-audit beachhead: a host that needs
//! "no audit, no action" writes the session row and its own audit/outbox row in
//! a single transaction, and delegates every other `SessionStore` method to the
//! bundled store.
//!
//! This needs zero library code beyond the already-public `pool()`: the host
//! wraps the `Arc<dyn SessionStore>` doorman hands out, writes its own `INSERT`
//! in its own `tx`, and the bundled (delegated) reads still find the row. If
//! this stops compiling for want of a missing `pub`, that gap is the only SQLx
//! work; otherwise SQLx needs nothing. It is also a permanent regression guard.

#![cfg(feature = "sqlite")]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use doorman_core::error::StorageResult;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AccountStatus, Session, SessionId, SessionStore, Storage, TokenHash, User, UserId,
};
use doorman_sqlx::SqliteStorage;
use sqlx::SqlitePool;

/// A host's `SessionStore` that commits the session row and its own audit row
/// in one transaction, delegating every read/delete to the bundled store.
struct AuditedSessions {
    inner: Arc<dyn SessionStore>,
    pool: SqlitePool,
}

#[async_trait]
impl SessionStore for AuditedSessions {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        // The host owns the transaction. The session row is written with the
        // same column encoding the bundled reads expect (UUIDs as their raw 16
        // bytes, the token hash as its raw bytes), so a row written here is
        // later found by the delegated `find_session_by_token_hash`.
        let mut tx = self.pool.begin().await.map_err(storage)?;
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.0.as_bytes().to_vec())
        .bind(session.user_id.0.as_bytes().to_vec())
        .bind(session.token_hash.0.to_vec())
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(&session.ip)
        .bind(&session.user_agent)
        .bind(session.recovery_cooldown_until)
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

fn storage(e: sqlx::Error) -> doorman_core::error::StorageError {
    doorman_core::error::StorageError::msg(e.to_string())
}

#[tokio::test]
async fn override_create_session_reuses_bundled_reads() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    // The host's own table, living alongside doorman's schema.
    sqlx::query("CREATE TABLE audit_outbox (session_id BLOB NOT NULL, event TEXT NOT NULL)")
        .execute(storage.pool())
        .await
        .expect("create audit table");

    // Swap one slot, keep the rest.
    let composite = Storage {
        sessions: Arc::new(AuditedSessions {
            inner: storage.session_store(),
            pool: storage.pool().clone(),
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

    // The delegated read finds the row the overridden write committed.
    let found = composite
        .sessions
        .find_session_by_token_hash(&session.token_hash)
        .await
        .expect("delegated read")
        .expect("session present");
    assert_eq!(found.id, session.id);
    assert_eq!(found.user_id, user_id);

    // The host's audit row committed in the same transaction.
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_outbox WHERE session_id = ?")
            .bind(session.id.0.as_bytes().to_vec())
            .fetch_one(storage.pool())
            .await
            .expect("count audit rows");
    assert_eq!(audit_count, 1);
}
