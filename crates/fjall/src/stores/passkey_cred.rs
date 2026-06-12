//! fjall-backed [`PasskeyCredentialStore`].
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
use fjall::Readable as _;

use crate::db::{self, FjallHandle};

pub(crate) struct FjallPasskeyCredentialStore {
    handle: FjallHandle,
}

impl FjallPasskeyCredentialStore {
    pub(crate) fn new(handle: FjallHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl PasskeyCredentialStore for FjallPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let cred_key = db::hex_bytes(&credential.credential_id);
            let user_idx_key =
                db::user_creds_idx_key(credential.user_id, &credential.credential_id);
            let encoded = db::encode_passkey(&credential)?;

            let mut tx = handle.db.write_tx();
            if tx
                .get(&handle.passkey_creds, cred_key.as_bytes())
                .map_err(db::err)?
                .is_some()
            {
                return Err(StorageError::msg("credential id already exists"));
            }
            tx.insert(
                &handle.passkey_creds,
                cred_key.as_bytes(),
                encoded.as_slice(),
            );
            tx.insert(&handle.user_creds_idx, user_idx_key.as_bytes(), b"");
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let cred_key = db::hex_bytes(&credential.credential_id);
            let encoded = db::encode_passkey(&credential)?;

            let mut tx = handle.db.write_tx();
            if tx
                .get(&handle.passkey_creds, cred_key.as_bytes())
                .map_err(db::err)?
                .is_none()
            {
                return Err(StorageError::msg("credential not found"));
            }
            // The user_creds_idx entry does not change on update (same
            // user_id and credential_id), so only the primary row is updated.
            tx.insert(
                &handle.passkey_creds,
                cred_key.as_bytes(),
                encoded.as_slice(),
            );
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_creds_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let cred_keys: Vec<String> = handle
                .user_creds_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .map(|guard| {
                    let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                    let key_str = std::str::from_utf8(&key_bytes).map_err(db::err)?;
                    // Extract cred_id_hex after the separator.
                    key_str
                        .splitn(2, '\x00')
                        .nth(1)
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| StorageError::msg("malformed user_creds_idx key"))
                })
                .collect::<StorageResult<_>>()?;

            let mut out = Vec::with_capacity(cred_keys.len());
            for key in &cred_keys {
                if let Some(bytes) = handle.passkey_creds.get(key.as_bytes()).map_err(db::err)? {
                    out.push(db::decode_passkey(&bytes)?);
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
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_creds_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let cred_keys: Vec<String> = handle
                .user_creds_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .map(|guard| {
                    let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                    let key_str = std::str::from_utf8(&key_bytes).map_err(db::err)?;
                    key_str
                        .splitn(2, '\x00')
                        .nth(1)
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| StorageError::msg("malformed user_creds_idx key"))
                })
                .collect::<StorageResult<_>>()?;

            let mut out = Vec::with_capacity(cred_keys.len());
            for key in &cred_keys {
                if let Some(bytes) = handle.passkey_creds.get(key.as_bytes()).map_err(db::err)? {
                    out.push(db::decode_passkey_summary(&bytes)?);
                }
            }
            Ok(out)
        })
        .await
        .map_err(db::err)?
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let key = db::hex_bytes(credential_id);
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            match handle.passkey_creds.get(key.as_bytes()).map_err(db::err)? {
                Some(bytes) => Ok(Some(db::decode_passkey(&bytes)?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        let cred_key = db::hex_bytes(credential_id);
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let mut tx = handle.db.write_tx();

            if let Some(bytes) = tx
                .take(&handle.passkey_creds, cred_key.as_bytes())
                .map_err(db::err)?
            {
                let cred = db::decode_passkey(&bytes)?;
                let user_idx_key = db::user_creds_idx_key(cred.user_id, &cred.credential_id);
                tx.remove(&handle.user_creds_idx, user_idx_key.as_bytes());
            }
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }
}
