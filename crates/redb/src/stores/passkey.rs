use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{PasskeyStore, PasskeySummary, PasskeyUse, StoredPasskey, UserId};

use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

pub(crate) struct RedbPasskeyStore {
    handle: RedbHandle,
}

impl RedbPasskeyStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }

    async fn modify(
        &self,
        credential_id: &[u8],
        change: impl FnOnce(&mut StoredPasskey) + Send + 'static,
    ) -> StorageResult<()> {
        let passkey_key = db::hex_bytes(credential_id);
        self.handle
            .write(move |wtxn| {
                let mut passkeys = wtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut passkey = {
                    let guard = passkeys
                        .get(passkey_key.as_str())
                        .map_err(db::err)?
                        .ok_or_else(|| StorageError::not_found("passkey not found"))?;
                    db::decode_passkey(guard.value())?
                };
                change(&mut passkey);
                let encoded = db::encode_passkey(&passkey)?;
                passkeys
                    .insert(passkey_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl PasskeyStore for RedbPasskeyStore {
    async fn add_passkey(&self, passkey: StoredPasskey) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let passkey_key = db::hex_bytes(&passkey.credential_id);
                let user_idx_key =
                    db::user_passkeys_idx_key(passkey.user_id, &passkey.credential_id);
                let encoded = db::encode_passkey(&passkey)?;

                let mut passkeys = wtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;

                if passkeys
                    .get(passkey_key.as_str())
                    .map_err(db::err)?
                    .is_some()
                {
                    return Err(StorageError::conflict("credential ID already exists"));
                }
                passkeys
                    .insert(passkey_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                user_idx
                    .insert(user_idx_key.as_str(), ())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }

    async fn record_passkey_use(
        &self,
        credential_id: &[u8],
        used: PasskeyUse,
    ) -> StorageResult<()> {
        self.modify(credential_id, move |passkey| {
            passkey.passkey = used.passkey;
            passkey.backup_eligible = used.backup_eligible;
            passkey.backup_state = used.backup_state;
            passkey.last_used_at = Some(used.used_at);
        })
        .await
    }

    async fn set_passkey_name(
        &self,
        credential_id: &[u8],
        name: Option<&str>,
    ) -> StorageResult<()> {
        let name = name.map(str::to_owned);
        self.modify(credential_id, move |passkey| passkey.name = name)
            .await
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        self.handle
            .read(move |rtxn| {
                let prefix = db::user_creds_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let passkey_keys: Vec<String> = {
                    let idx_tbl = rtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;
                    idx_tbl
                        .range(prefix.as_str()..end.as_str())
                        .map_err(db::err)?
                        .map(|r| {
                            r.map_err(db::err).and_then(|(k, _)| {
                                k.value()
                                    .split_once('\x00')
                                    .map(|x| x.1.to_owned())
                                    .ok_or_else(|| {
                                        StorageError::msg("malformed user_creds_idx key")
                                    })
                            })
                        })
                        .collect::<StorageResult<_>>()?
                };

                let creds_tbl = rtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut out = Vec::with_capacity(passkey_keys.len());
                for key in &passkey_keys {
                    if let Some(guard) = creds_tbl.get(key.as_str()).map_err(db::err)? {
                        out.push(db::decode_passkey(guard.value())?);
                    }
                }
                Ok(out)
            })
            .await
    }

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        self.handle
            .read(move |rtxn| {
                let prefix = db::user_creds_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let passkey_keys: Vec<String> = {
                    let idx_tbl = rtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;
                    idx_tbl
                        .range(prefix.as_str()..end.as_str())
                        .map_err(db::err)?
                        .map(|r| {
                            r.map_err(db::err).and_then(|(k, _)| {
                                k.value()
                                    .split_once('\x00')
                                    .map(|x| x.1.to_owned())
                                    .ok_or_else(|| {
                                        StorageError::msg("malformed user_creds_idx key")
                                    })
                            })
                        })
                        .collect::<StorageResult<_>>()?
                };

                let creds_tbl = rtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut out = Vec::with_capacity(passkey_keys.len());
                for key in &passkey_keys {
                    if let Some(guard) = creds_tbl.get(key.as_str()).map_err(db::err)? {
                        out.push(db::decode_passkey_summary(guard.value())?);
                    }
                }
                Ok(out)
            })
            .await
    }

    async fn count_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .read(move |rtxn| {
                let prefix = db::user_creds_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let idx_tbl = rtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;
                let count = idx_tbl
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db::err)?
                    .count() as u64;
                Ok(count)
            })
            .await
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let key = db::hex_bytes(credential_id);
        self.handle
            .read(move |rtxn| {
                let creds_tbl = rtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                match creds_tbl.get(key.as_str()).map_err(db::err)? {
                    Some(guard) => Ok(Some(db::decode_passkey(guard.value())?)),
                    None => Ok(None),
                }
            })
            .await
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        let passkey_key = db::hex_bytes(credential_id);
        self.handle
            .write(move |wtxn| {
                let mut passkeys = wtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;

                if let Some(guard) = passkeys.remove(passkey_key.as_str()).map_err(db::err)? {
                    let passkey = db::decode_passkey(guard.value())?;
                    let user_idx_key =
                        db::user_passkeys_idx_key(passkey.user_id, &passkey.credential_id);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(())
            })
            .await
    }

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let prefix = db::user_creds_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let mut passkeys = wtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;

                let entries: Vec<(String, String)> = user_idx
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, _)| {
                            let idx_key = k.value().to_owned();
                            let passkey_key = idx_key
                                .split_once('\x00')
                                .map(|x| x.1.to_owned())
                                .ok_or_else(|| StorageError::msg("malformed user_creds_idx key"))?;
                            Ok((idx_key, passkey_key))
                        })
                    })
                    .collect::<StorageResult<_>>()?;

                let mut count = 0u64;
                for (idx_key, passkey_key) in &entries {
                    if passkeys
                        .remove(passkey_key.as_str())
                        .map_err(db::err)?
                        .is_some()
                    {
                        count += 1;
                    }
                    user_idx.remove(idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }
}
