//! redb-backed [`PasskeyChallengeStore`].
//!
//! Registration ceremonies occupy `pkregs` (primary) and `user_pkregs_idx`
//! (per-user index, key `"{user_id}\x00{challenge_id}"`), supporting the
//! per-user count and bulk-delete the recovery flow relies on. Authentication
//! ceremonies are a bare `pkauths` row — they carry no user scope, so no
//! secondary index is needed.
//!
//! Both `take_registration` and `take_authentication` are atomic
//! delete-and-return operations executed in a single write transaction: redb
//! serializes writers, so exactly one concurrent caller can observe the value.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};
use redb::{ReadableDatabase as _, ReadableTable as _};

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
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = value.id.0.to_string();
            let user_idx_key = db::user_pkregs_idx_key(value.user_id, value.id);
            let encoded = db::encode(&value)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                pkregs
                    .insert(key.as_str(), encoded.as_slice())
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

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let wtxn = db.begin_write().map_err(db::err)?;
            let result = {
                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;

                match pkregs.remove(key.as_str()).map_err(db::err)? {
                    None => None,
                    Some(guard) => {
                        let reg: StoredPasskeyRegistration = db::decode(guard.value())?;
                        let user_idx_key = db::user_pkregs_idx_key(reg.user_id, reg.id);
                        user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                        Some(reg)
                    }
                }
            };
            wtxn.commit().map_err(db::err)?;
            Ok(result)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_pkregs_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let wtxn = db.begin_write().map_err(db::err)?;
            let removed = {
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
                count
            };
            wtxn.commit().map_err(db::err)?;
            Ok(removed)
        })
        .await
        .map_err(db::err)?
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_pkregs_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let rtxn = db.begin_read().map_err(db::err)?;
            let idx_tbl = rtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;
            let count = idx_tbl
                .range(prefix.as_str()..end.as_str())
                .map_err(db::err)?
                .count() as u64;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = value.id.0.to_string();
            let encoded = db::encode(&value)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;
                pkauths
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let wtxn = db.begin_write().map_err(db::err)?;
            let result = {
                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;
                match pkauths.remove(key.as_str()).map_err(db::err)? {
                    None => None,
                    Some(guard) => Some(db::decode::<StoredPasskeyAuthentication>(guard.value())?),
                }
            };
            wtxn.commit().map_err(db::err)?;
            Ok(result)
        })
        .await
        .map_err(db::err)?
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let wtxn = db.begin_write().map_err(db::err)?;
            let count = {
                let mut pkregs = wtxn.open_table(db::PKREGS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_PKREGS_IDX).map_err(db::err)?;
                let mut pkauths = wtxn.open_table(db::PKAUTHS).map_err(db::err)?;

                // Scan inside the write transaction so the expiry check and the
                // removal see the same row (redb serializes writers).
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
                (expired_regs.len() + expired_auths.len()) as u64
            };
            wtxn.commit().map_err(db::err)?;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }
}
