//! libSQL-backed [`PasskeyCredentialStore`].
//!
//! One row per credential keyed on the BLOB `credential_id`, with a `user_id`
//! index for the per-user listings. The credential blob and the device metadata
//! captured at registration round-trip verbatim; the summary listing projects
//! every column *except* the blob, so the "your passkeys" view never has to read
//! it.

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{PasskeyCredentialStore, PasskeySummary, StoredPasskey, UserId};

use crate::conn::LibsqlConn;
use crate::convert::{
    bind_aaguid, bind_blob, bind_bool, bind_bytes, bind_opt_text, bind_opt_ts, bind_text, bind_ts,
    bind_uuid, col_aaguid, col_blob, col_bool, col_opt_text, col_opt_ts, col_text, col_ts,
    col_uuid, transports_from_str, transports_to_str,
};

/// Full projection, including the credential blob.
const COLUMNS: &str = "credential_id, user_id, passkey, name, created_at, last_used_at, \
     aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until";

/// Metadata-only projection: the same columns minus the `passkey` blob.
const SUMMARY_COLUMNS: &str = "credential_id, user_id, name, created_at, last_used_at, \
     aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until";

pub(crate) struct LibsqlPasskeyCredentialStore {
    conn: LibsqlConn,
}

impl LibsqlPasskeyCredentialStore {
    pub(crate) fn new(conn: LibsqlConn) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl PasskeyCredentialStore for LibsqlPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO passkey_credentials
                 (credential_id, user_id, passkey, name, created_at, last_used_at,
                  aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    bind_blob(credential.credential_id),
                    bind_uuid(credential.user_id.0),
                    bind_blob(credential.passkey),
                    bind_opt_text(credential.name),
                    bind_ts(credential.created_at),
                    bind_opt_ts(credential.last_used_at),
                    bind_aaguid(credential.aaguid),
                    bind_text(transports_to_str(&credential.transports)),
                    bind_bool(credential.backup_eligible),
                    bind_bool(credential.backup_state),
                    bind_opt_ts(credential.recovery_cooldown_until),
                ],
            )
            .await?;
        Ok(())
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let affected = self
            .conn
            .execute(
                "UPDATE passkey_credentials
                 SET user_id = ?, passkey = ?, name = ?, created_at = ?, last_used_at = ?,
                     aaguid = ?, transports = ?, backup_eligible = ?, backup_state = ?,
                     recovery_cooldown_until = ?
                 WHERE credential_id = ?",
                vec![
                    bind_uuid(credential.user_id.0),
                    bind_blob(credential.passkey),
                    bind_opt_text(credential.name),
                    bind_ts(credential.created_at),
                    bind_opt_ts(credential.last_used_at),
                    bind_aaguid(credential.aaguid),
                    bind_text(transports_to_str(&credential.transports)),
                    bind_bool(credential.backup_eligible),
                    bind_bool(credential.backup_state),
                    bind_opt_ts(credential.recovery_cooldown_until),
                    bind_blob(credential.credential_id),
                ],
            )
            .await?;
        if affected == 0 {
            return Err(StorageError::msg("passkey credential not found"));
        }
        Ok(())
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        self.conn
            .query_map(
                &format!("SELECT {COLUMNS} FROM passkey_credentials WHERE user_id = ?"),
                vec![bind_uuid(user_id.0)],
                row_to_passkey,
            )
            .await
    }

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        self.conn
            .query_map(
                &format!("SELECT {SUMMARY_COLUMNS} FROM passkey_credentials WHERE user_id = ?"),
                vec![bind_uuid(user_id.0)],
                row_to_summary,
            )
            .await
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let row = self
            .conn
            .query_opt(
                &format!("SELECT {COLUMNS} FROM passkey_credentials WHERE credential_id = ?"),
                vec![bind_bytes(credential_id)],
            )
            .await?;
        row.map(|r| row_to_passkey(&r)).transpose()
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM passkey_credentials WHERE credential_id = ?",
                vec![bind_bytes(credential_id)],
            )
            .await?;
        Ok(())
    }
}

fn row_to_passkey(row: &libsql::Row) -> StorageResult<StoredPasskey> {
    Ok(StoredPasskey {
        credential_id: col_blob(row, 0)?,
        user_id: UserId(col_uuid(row, 1)?),
        passkey: col_blob(row, 2)?,
        name: col_opt_text(row, 3)?,
        created_at: col_ts(row, 4)?,
        last_used_at: col_opt_ts(row, 5)?,
        aaguid: col_aaguid(row, 6)?,
        transports: transports_from_str(&col_text(row, 7)?),
        backup_eligible: col_bool(row, 8)?,
        backup_state: col_bool(row, 9)?,
        recovery_cooldown_until: col_opt_ts(row, 10)?,
    })
}

// The summary projection drops the `passkey` blob, so every column after
// `user_id` shifts down by one relative to [`row_to_passkey`].
fn row_to_summary(row: &libsql::Row) -> StorageResult<PasskeySummary> {
    Ok(PasskeySummary {
        credential_id: col_blob(row, 0)?,
        user_id: UserId(col_uuid(row, 1)?),
        name: col_opt_text(row, 2)?,
        created_at: col_ts(row, 3)?,
        last_used_at: col_opt_ts(row, 4)?,
        aaguid: col_aaguid(row, 5)?,
        transports: transports_from_str(&col_text(row, 6)?),
        backup_eligible: col_bool(row, 7)?,
        backup_state: col_bool(row, 8)?,
        recovery_cooldown_until: col_opt_ts(row, 9)?,
    })
}
