//! libSQL-backed [`PasskeyChallengeStore`].
//!
//! Two tables behind one store: `passkey_registrations` (user-scoped, with a
//! per-user count and bulk delete) and `passkey_authentications` (not
//! user-scoped). Both `take_*` paths are the atomic `DELETE ... RETURNING`, so a
//! challenge is single-use even under concurrency. `purge_expired` sweeps both
//! tables and returns the combined count.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::conn::LibsqlConn;
use crate::convert::{
    bind_blob, bind_opt_ts, bind_ts, bind_uuid, col_blob, col_opt_ts, col_ts, col_uuid,
};

const REGISTRATION_COLUMNS: &str =
    "id, user_id, state, created_at, expires_at, recovery_cooldown_until";
const AUTHENTICATION_COLUMNS: &str = "id, state, created_at, expires_at";

pub(crate) struct LibsqlPasskeyChallengeStore {
    conn: LibsqlConn,
}

impl LibsqlPasskeyChallengeStore {
    pub(crate) fn new(conn: LibsqlConn) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl PasskeyChallengeStore for LibsqlPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO passkey_registrations
                 (id, user_id, state, created_at, expires_at, recovery_cooldown_until)
                 VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    bind_uuid(value.id.0),
                    bind_uuid(value.user_id.0),
                    bind_blob(value.state),
                    bind_ts(value.created_at),
                    bind_ts(value.expires_at),
                    bind_opt_ts(value.recovery_cooldown_until),
                ],
            )
            .await?;
        Ok(())
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        let row = self
            .conn
            .query_opt(
                &format!(
                    "DELETE FROM passkey_registrations WHERE id = ? RETURNING {REGISTRATION_COLUMNS}"
                ),
                vec![bind_uuid(id.0)],
            )
            .await?;
        row.map(|r| row_to_registration(&r)).transpose()
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.conn
            .execute(
                "DELETE FROM passkey_registrations WHERE user_id = ?",
                vec![bind_uuid(user_id.0)],
            )
            .await
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.conn
            .count(
                "SELECT COUNT(*) FROM passkey_registrations WHERE user_id = ?",
                vec![bind_uuid(user_id.0)],
            )
            .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO passkey_authentications (id, state, created_at, expires_at)
                 VALUES (?, ?, ?, ?)",
                vec![
                    bind_uuid(value.id.0),
                    bind_blob(value.state),
                    bind_ts(value.created_at),
                    bind_ts(value.expires_at),
                ],
            )
            .await?;
        Ok(())
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        let row = self
            .conn
            .query_opt(
                &format!(
                    "DELETE FROM passkey_authentications WHERE id = ? RETURNING {AUTHENTICATION_COLUMNS}"
                ),
                vec![bind_uuid(id.0)],
            )
            .await?;
        row.map(|r| row_to_authentication(&r)).transpose()
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let registrations = self
            .conn
            .execute(
                "DELETE FROM passkey_registrations WHERE expires_at <= ?",
                vec![bind_ts(now)],
            )
            .await?;
        let authentications = self
            .conn
            .execute(
                "DELETE FROM passkey_authentications WHERE expires_at <= ?",
                vec![bind_ts(now)],
            )
            .await?;
        Ok(registrations + authentications)
    }
}

fn row_to_registration(row: &libsql::Row) -> StorageResult<StoredPasskeyRegistration> {
    Ok(StoredPasskeyRegistration {
        id: PasskeyChallengeId(col_uuid(row, 0)?),
        user_id: UserId(col_uuid(row, 1)?),
        state: col_blob(row, 2)?,
        created_at: col_ts(row, 3)?,
        expires_at: col_ts(row, 4)?,
        recovery_cooldown_until: col_opt_ts(row, 5)?,
    })
}

fn row_to_authentication(row: &libsql::Row) -> StorageResult<StoredPasskeyAuthentication> {
    Ok(StoredPasskeyAuthentication {
        id: PasskeyChallengeId(col_uuid(row, 0)?),
        state: col_blob(row, 1)?,
        created_at: col_ts(row, 2)?,
        expires_at: col_ts(row, 3)?,
    })
}
