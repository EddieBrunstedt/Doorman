//! libSQL-backed [`UserStore`].
//!
//! One row per user keyed on the BLOB `id`, with a `UNIQUE` email column for the
//! by-email lookup. `create_user` relies on the primary-key and unique
//! constraints to reject a duplicate id or email; `update_user` reports "not
//! found" when no row matched.

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{User, UserId, UserStore};

use crate::conn::LibsqlConn;
use crate::convert::{
    bind_opt_text, bind_opt_ts, bind_text, bind_ts, bind_uuid, col_opt_text, col_opt_ts, col_ts,
    col_uuid,
};

const COLUMNS: &str = "id, email, email_verified_at, created_at, updated_at";

pub(crate) struct LibsqlUserStore {
    conn: LibsqlConn,
}

impl LibsqlUserStore {
    pub(crate) fn new(conn: LibsqlConn) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl UserStore for LibsqlUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO users (id, email, email_verified_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?)",
                vec![
                    bind_uuid(user.id.0),
                    bind_opt_text(user.email),
                    bind_opt_ts(user.email_verified_at),
                    bind_ts(user.created_at),
                    bind_ts(user.updated_at),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        let row = self
            .conn
            .query_opt(
                &format!("SELECT {COLUMNS} FROM users WHERE id = ?"),
                vec![bind_uuid(id.0)],
            )
            .await?;
        row.map(|r| row_to_user(&r)).transpose()
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let row = self
            .conn
            .query_opt(
                &format!("SELECT {COLUMNS} FROM users WHERE email = ?"),
                vec![bind_text(email)],
            )
            .await?;
        row.map(|r| row_to_user(&r)).transpose()
    }

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let affected = self
            .conn
            .execute(
                "UPDATE users
                 SET email = ?, email_verified_at = ?, updated_at = ?
                 WHERE id = ?",
                vec![
                    bind_opt_text(user.email),
                    bind_opt_ts(user.email_verified_at),
                    bind_ts(user.updated_at),
                    bind_uuid(user.id.0),
                ],
            )
            .await?;
        if affected == 0 {
            return Err(StorageError::msg("user not found"));
        }
        Ok(())
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        self.conn
            .execute("DELETE FROM users WHERE id = ?", vec![bind_uuid(id.0)])
            .await?;
        Ok(())
    }
}

fn row_to_user(row: &libsql::Row) -> StorageResult<User> {
    Ok(User {
        id: UserId(col_uuid(row, 0)?),
        email: col_opt_text(row, 1)?,
        email_verified_at: col_opt_ts(row, 2)?,
        created_at: col_ts(row, 3)?,
        updated_at: col_ts(row, 4)?,
    })
}
