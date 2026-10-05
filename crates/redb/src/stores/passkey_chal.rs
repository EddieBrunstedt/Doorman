use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};
use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

pub(crate) struct RedbPasskeyChallengeStore {
    handle: RedbHandle,
}

impl RedbPasskeyChallengeStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl PasskeyChallengeStore for RedbPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let key = value.id.0.to_string();
                let user_idx_key = db::user_pkregs_idx_key(value.user_id, value.id);
                let encoded = db::encode(&value)?;

                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                pkregs
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                user_idx
                    .insert(user_idx_key.as_str(), ())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        self.handle
            .write(move |wtxn| {
                let key = id.0.to_string();
                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                let Some(guard) = pkregs.remove(key.as_str()).map_err(db::err)? else {
                    return Ok(None);
                };
                let reg: StoredPasskeyRegistration = db::decode(guard.value())?;
                let user_idx_key = db::user_pkregs_idx_key(reg.user_id, reg.id);
                user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                Ok(Some(reg))
            })
            .await
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let prefix = db::user_pkregs_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                let idx_keys: Vec<String> = {
                    user_idx
                        .range(prefix.as_str()..end.as_str())
                        .map_err(db::err)?
                        .map(|r| r.map_err(db::err).map(|(k, _)| k.value().to_owned()))
                        .collect::<StorageResult<_>>()?
                };

                let mut count = 0u64;
                for idx_key in &idx_keys {
                    let challenge_id = idx_key
                        .split_once('\x00')
                        .map(|x| x.1)
                        .ok_or_else(|| StorageError::msg("malformed user_pkregs_idx key"))?;
                    if pkregs.remove(challenge_id).map_err(db::err)?.is_some() {
                        count += 1;
                    }
                    user_idx.remove(idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .read(move |rtxn| {
                let prefix = db::user_pkregs_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let idx_tbl = rtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;
                let count = idx_tbl
                    .range(prefix.as_str()..end.as_str())
                    .map_err(db::err)?
                    .count() as u64;
                Ok(count)
            })
            .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let key = value.id.0.to_string();
                let encoded = db::encode(&value)?;

                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;
                pkauths
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        self.handle
            .write(move |wtxn| {
                let key = id.0.to_string();
                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;
                match pkauths.remove(key.as_str()).map_err(db::err)? {
                    Some(guard) => Ok(Some(db::decode(guard.value())?)),
                    None => Ok(None),
                }
            })
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;
                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;

                let expired_regs: Vec<(String, StoredPasskeyRegistration)> = pkregs
                    .iter()
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, v)| {
                            let key = k.value().to_owned();
                            let reg = db::decode::<StoredPasskeyRegistration>(v.value())?;
                            Ok((key, reg))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, reg)| reg.expires_at <= now))
                    .collect::<StorageResult<_>>()?;

                let expired_auths: Vec<String> = pkauths
                    .iter()
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, v)| {
                            let key = k.value().to_owned();
                            let auth = db::decode::<StoredPasskeyAuthentication>(v.value())?;
                            Ok((key, auth))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, a)| a.expires_at <= now))
                    .map(|r| r.map(|(k, _)| k))
                    .collect::<StorageResult<_>>()?;

                for (key, reg) in &expired_regs {
                    pkregs.remove(key.as_str()).map_err(db::err)?;
                    let user_idx_key = db::user_pkregs_idx_key(reg.user_id, reg.id);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                for key in &expired_auths {
                    pkauths.remove(key.as_str()).map_err(db::err)?;
                }
                Ok((expired_regs.len() + expired_auths.len()) as u64)
            })
            .await
    }
}
