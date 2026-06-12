//! libSQL-backed [`SessionStore`].
//!
//! One row per session keyed on the BLOB `id`, with a `UNIQUE` `token_hash` for
//! the hot per-request lookup and a `user_id` index for the per-user queries.
//! `list_for_user` pushes the `expires_at > now` predicate into the query, so
//! expired rows never leave the store, and `purge_expired` is the authoritative
//! reclamation pass.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::conn::LibsqlConn;
use crate::convert::{
    bind_hash, bind_opt_text, bind_opt_ts, bind_ts, bind_uuid, col_hash, col_opt_text, col_opt_ts,
    col_ts, col_uuid,
};

const COLUMNS: &str =
    "id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until";

pub(crate) struct LibsqlSessionStore {
    conn: LibsqlConn,
}

impl LibsqlSessionStore {
    pub(crate) fn new(conn: LibsqlConn) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl SessionStore for LibsqlSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO sessions
                 (id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    bind_uuid(session.id.0),
                    bind_uuid(session.user_id.0),
                    bind_hash(&session.token_hash),
                    bind_ts(session.created_at),
                    bind_ts(session.expires_at),
                    bind_opt_text(session.ip),
                    bind_opt_text(session.user_agent),
                    bind_opt_ts(session.recovery_cooldown_until),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let row = self
            .conn
            .query_opt(
                &format!("SELECT {COLUMNS} FROM sessions WHERE token_hash = ?"),
                vec![bind_hash(hash)],
            )
            .await?;
        row.map(|r| row_to_session(&r)).transpose()
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let row = self
            .conn
            .query_opt(
                &format!("SELECT {COLUMNS} FROM sessions WHERE id = ?"),
                vec![bind_uuid(id.0)],
            )
            .await?;
        row.map(|r| row_to_session(&r)).transpose()
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        self.conn
            .query_map(
                &format!("SELECT {COLUMNS} FROM sessions WHERE user_id = ? AND expires_at > ?"),
                vec![bind_uuid(user_id.0), bind_ts(now)],
                row_to_session,
            )
            .await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE id = ?", vec![bind_uuid(id.0)])
            .await?;
        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.conn
            .execute(
                "DELETE FROM sessions WHERE user_id = ?",
                vec![bind_uuid(user_id.0)],
            )
            .await
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        self.conn
            .execute(
                "DELETE FROM sessions WHERE user_id = ? AND id != ?",
                vec![bind_uuid(user_id.0), bind_uuid(except.0)],
            )
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.conn
            .execute(
                "DELETE FROM sessions WHERE expires_at <= ?",
                vec![bind_ts(now)],
            )
            .await
    }
}

fn row_to_session(row: &libsql::Row) -> StorageResult<Session> {
    Ok(Session {
        id: SessionId(col_uuid(row, 0)?),
        user_id: UserId(col_uuid(row, 1)?),
        token_hash: col_hash(row, 2)?,
        created_at: col_ts(row, 3)?,
        expires_at: col_ts(row, 4)?,
        ip: col_opt_text(row, 5)?,
        user_agent: col_opt_text(row, 6)?,
        recovery_cooldown_until: col_opt_ts(row, 7)?,
    })
}
