//! redb-backed [`PasskeyCredentialStore`].
//!
//! Credentials are system-of-record: each is stored under its hex-encoded
//! credential id in `passkey_creds`, with a per-user index entry in
//! `user_creds_idx` (key `"{user_id}\x00{cred_id_hex}"`).
//!
//! `add_passkey` rejects a duplicate credential id; `update_passkey` rejects
//! an absent one. Both constraints are checked and satisfied inside a single
//! serialized write transaction.
//!
//! `list_passkey_summaries_for_user` projects each record to a
//! [`PasskeySummary`](doorman_core::storage::PasskeySummary) without reading
//! the opaque credential blob into the `StoredPasskey` domain type.

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{PasskeyCredentialStore, PasskeySummary, StoredPasskey, UserId};

use redb::{ReadableDatabase as _, ReadableTable as _};

use crate::db::{self, RedbHandle};

pub(crate) struct RedbPasskeyCredentialStore {
    handle: RedbHandle,
}

impl RedbPasskeyCredentialStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl PasskeyCredentialStore for RedbPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let cred_key = db::hex_bytes(&credential.credential_id);
            let user_idx_key =
                db::user_creds_idx_key(credential.user_id, &credential.credential_id);
            let encoded = db::encode_passkey(&credential)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut creds = wtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_CREDS_IDX).map_err(db::err)?;

                if creds.get(cred_key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::msg("credential id already exists"));
                }
                creds
                    .insert(cred_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                user_idx
                    .insert(user_idx_key.as_str(), ())
                    .map_err(db::err)?;
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let cred_key = db::hex_bytes(&credential.credential_id);
            let encoded = db::encode_passkey(&credential)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut creds = wtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;

                if creds.get(cred_key.as_str()).map_err(db::err)?.is_none() {
                    return Err(StorageError::msg("credential not found"));
                }
                // The user_creds_idx entry does not change on update (same
                // user_id and credential_id), so only the primary row is updated.
                creds
                    .insert(cred_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_creds_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let rtxn = db.begin_read().map_err(db::err)?;
            let cred_keys: Vec<String> = {
                let idx_tbl = rtxn.open_table(db::USER_CREDS_IDX).map_err(db::err)?;
                idx_tbl
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, _)| {
                            // Extract cred_id_hex after the separator.
                            k.value()
                                .split_once('\x00')
                                .map(|x| x.1.to_owned())
                                .ok_or_else(|| StorageError::msg("malformed user_creds_idx key"))
                        })
                    })
                    .collect::<StorageResult<_>>()?
            };

            let creds_tbl = rtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;
            let mut out = Vec::with_capacity(cred_keys.len());
            for key in &cred_keys {
                if let Some(guard) = creds_tbl.get(key.as_str()).map_err(db::err)? {
                    out.push(db::decode_passkey(guard.value())?);
                }
            }
            Ok(out)
        })
        .await
        .map_err(db::err)?
    }

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_creds_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let rtxn = db.begin_read().map_err(db::err)?;
            let cred_keys: Vec<String> = {
                let idx_tbl = rtxn.open_table(db::USER_CREDS_IDX).map_err(db::err)?;
                idx_tbl
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, _)| {
                            k.value()
                                .split_once('\x00')
                                .map(|x| x.1.to_owned())
                                .ok_or_else(|| StorageError::msg("malformed user_creds_idx key"))
                        })
                    })
                    .collect::<StorageResult<_>>()?
            };

            let creds_tbl = rtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;
            let mut out = Vec::with_capacity(cred_keys.len());
            for key in &cred_keys {
                if let Some(guard) = creds_tbl.get(key.as_str()).map_err(db::err)? {
                    out.push(db::decode_passkey_summary(guard.value())?);
                }
            }
            Ok(out)
        })
        .await
        .map_err(db::err)?
    }

    async fn count_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            // The index entry and the credential row are written and removed
            // in the same transaction, so counting the index is exact.
            let prefix = db::user_creds_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let rtxn = db.begin_read().map_err(db::err)?;
            let idx_tbl = rtxn.open_table(db::USER_CREDS_IDX).map_err(db::err)?;
            let count = idx_tbl
                .range(prefix.as_str()..end.as_str())
                .map_err(db::err)?
                .count() as u64;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let key = db::hex_bytes(credential_id);
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let rtxn = db.begin_read().map_err(db::err)?;
            let creds_tbl = rtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;
            match creds_tbl.get(key.as_str()).map_err(db::err)? {
                Some(guard) => Ok(Some(db::decode_passkey(guard.value())?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        let cred_key = db::hex_bytes(credential_id);
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut creds = wtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_CREDS_IDX).map_err(db::err)?;

                if let Some(guard) = creds.remove(cred_key.as_str()).map_err(db::err)? {
                    let cred = db::decode_passkey(guard.value())?;
                    let user_idx_key = db::user_creds_idx_key(cred.user_id, &cred.credential_id);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_creds_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let wtxn = db.begin_write().map_err(db::err)?;
            let removed = {
                let mut creds = wtxn.open_table(db::PASSKEY_CREDS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_CREDS_IDX).map_err(db::err)?;

                // Each index key is `"{user_id}\x00{cred_id_hex}"`, and the
                // cred_id_hex segment is the primary key in `passkey_creds`.
                let entries: Vec<(String, String)> = user_idx
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, _)| {
                            let idx_key = k.value().to_owned();
                            let cred_key = idx_key
                                .split_once('\x00')
                                .map(|x| x.1.to_owned())
                                .ok_or_else(|| StorageError::msg("malformed user_creds_idx key"))?;
                            Ok((idx_key, cred_key))
                        })
                    })
                    .collect::<StorageResult<_>>()?;

                let mut count = 0u64;
                for (idx_key, cred_key) in &entries {
                    if creds.remove(cred_key.as_str()).map_err(db::err)?.is_some() {
                        count += 1;
                    }
                    user_idx.remove(idx_key.as_str()).map_err(db::err)?;
                }
                count
            };
            wtxn.commit().map_err(db::err)?;
            Ok(removed)
        })
        .await
        .map_err(db::err)?
    }
}
