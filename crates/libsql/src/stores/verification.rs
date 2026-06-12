//! libSQL-backed [`VerificationTokenStore`].
//!
//! A token is one row keyed on `(token_hash, purpose)` — purpose is part of the
//! key, so a leaked token of one purpose can never be redeemed under another.
//! `consume_token` is the atomic delete-and-return `DELETE ... RETURNING`: the
//! statement removes the row and hands back its old contents in one step, so the
//! token is single-use even under concurrency.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

use crate::conn::LibsqlConn;
use crate::convert::{
    bind_hash, bind_opt_text, bind_text, bind_ts, bind_uuid, col_hash, col_opt_text, col_text,
    col_ts, col_uuid, purpose_from_str, purpose_to_str,
};

const COLUMNS: &str = "token_hash, purpose, user_id, new_email, created_at, expires_at";

pub(crate) struct LibsqlVerificationTokenStore {
    conn: LibsqlConn,
}

impl LibsqlVerificationTokenStore {
    pub(crate) fn new(conn: LibsqlConn) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl VerificationTokenStore for LibsqlVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO verification_tokens
                 (token_hash, purpose, user_id, new_email, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    bind_hash(&token.token_hash),
                    bind_text(purpose_to_str(token.purpose)),
                    bind_uuid(token.user_id.0),
                    bind_opt_text(token.new_email),
                    bind_ts(token.created_at),
                    bind_ts(token.expires_at),
                ],
            )
            .await?;
        Ok(())
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let row = self
            .conn
            .query_opt(
                &format!(
                    "DELETE FROM verification_tokens
                     WHERE token_hash = ? AND purpose = ?
                     RETURNING {COLUMNS}"
                ),
                vec![bind_hash(hash), bind_text(purpose_to_str(purpose))],
            )
            .await?;
        row.map(|r| row_to_token(&r)).transpose()
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        self.conn
            .execute(
                "DELETE FROM verification_tokens WHERE user_id = ? AND purpose = ?",
                vec![bind_uuid(user_id.0), bind_text(purpose_to_str(purpose))],
            )
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.conn
            .execute(
                "DELETE FROM verification_tokens WHERE expires_at <= ?",
                vec![bind_ts(now)],
            )
            .await
    }
}

fn row_to_token(row: &libsql::Row) -> StorageResult<VerificationToken> {
    Ok(VerificationToken {
        token_hash: col_hash(row, 0)?,
        purpose: purpose_from_str(&col_text(row, 1)?)?,
        user_id: UserId(col_uuid(row, 2)?),
        new_email: col_opt_text(row, 3)?,
        created_at: col_ts(row, 4)?,
        expires_at: col_ts(row, 5)?,
    })
}
