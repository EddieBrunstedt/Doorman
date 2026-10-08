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
                let user_idx_key = db::owner_key(value.user_id, value.id);
                let encoded = db::encode(&value)?;

                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                if pkregs.get(key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::conflict(
                        "registration challenge id already exists",
                    ));
                }
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
                let user_idx_key = db::owner_key(reg.user_id, reg.id);
                user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                Ok(Some(reg))
            })
            .await
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                let mut count = 0u64;
                for challenge_id in db::owned_members(&user_idx, user_id)? {
                    if pkregs
                        .remove(challenge_id.as_str())
                        .map_err(db::err)?
                        .is_some()
                    {
                        count += 1;
                    }
                    let user_idx_key = db::owner_key(user_id, &challenge_id);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>> {
        self.handle
            .read(move |rtxn| {
                let user_idx = rtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;
                let challenge_ids = db::owned_members(&user_idx, user_id)?;

                let pkregs = rtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut out = Vec::with_capacity(challenge_ids.len());
                for id in &challenge_ids {
                    if let Some(guard) = pkregs.get(id.as_str()).map_err(db::err)? {
                        out.push(db::decode(guard.value())?);
                    }
                }
                Ok(out)
            })
            .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let key = value.id.0.to_string();
                let encoded = db::encode(&value)?;

                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;
                if pkauths.get(key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::conflict(
                        "authentication challenge id already exists",
                    ));
                }
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
                    let user_idx_key = db::owner_key(reg.user_id, reg.id);
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
