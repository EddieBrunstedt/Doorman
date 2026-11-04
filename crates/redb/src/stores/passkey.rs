use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{PasskeyStore, PasskeyUse, StoredPasskey, UserId};

use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};
use crate::rows;

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
                    rows::decode::<StoredPasskey>(guard.value())?
                };
                change(&mut passkey);
                let encoded = rows::encode(&passkey)?;
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
                let user_idx_key = db::owner_key(passkey.user_id, &passkey_key);
                let encoded = rows::encode(&passkey)?;

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
                let user_idx = rtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;
                let passkey_keys = db::owned_members(&user_idx, user_id)?;

                let creds_tbl = rtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut out = Vec::with_capacity(passkey_keys.len());
                for key in &passkey_keys {
                    if let Some(guard) = creds_tbl.get(key.as_str()).map_err(db::err)? {
                        out.push(rows::decode::<StoredPasskey>(guard.value())?);
                    }
                }
                Ok(out)
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
                    Some(guard) => Ok(Some(rows::decode::<StoredPasskey>(guard.value())?)),
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
                    let passkey = rows::decode::<StoredPasskey>(guard.value())?;
                    let user_idx_key = db::owner_key(passkey.user_id, &passkey_key);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(())
            })
            .await
    }

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut passkeys = wtxn.open_table(db::PASSKEYS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PASSKEYS_IDX).map_err(db::err)?;

                let mut count = 0u64;
                for passkey_key in db::owned_members(&user_idx, user_id)? {
                    if passkeys
                        .remove(passkey_key.as_str())
                        .map_err(db::err)?
                        .is_some()
                    {
                        count += 1;
                    }
                    let user_idx_key = db::owner_key(user_id, &passkey_key);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }
}
