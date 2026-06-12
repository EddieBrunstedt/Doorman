//! fjall-backed [`PasskeyChallengeStore`].
//!
//! Registration ceremonies occupy `pkregs` (primary) and `user_pkregs_idx`
//! (per-user index, key `"{user_id}\x00{challenge_id}"`), supporting the
//! per-user count and bulk-delete the recovery flow relies on. Authentication
//! ceremonies are a bare `pkauths` row — they carry no user scope, so no
//! secondary index is needed.
//!
//! Both `take_registration` and `take_authentication` are atomic
//! delete-and-return operations executed in a single write transaction: fjall
//! serializes writers, so exactly one concurrent caller can observe the value.

use crate::db::{self, FjallHandle};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

pub(crate) struct FjallPasskeyChallengeStore {
    handle: FjallHandle,
}

impl FjallPasskeyChallengeStore {
    pub(crate) fn new(handle: FjallHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl PasskeyChallengeStore for FjallPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = value.id.0.to_string();
            let user_idx_key = db::user_pkregs_idx_key(value.user_id, value.id);
            let encoded = db::encode(&value)?;

            let mut tx = handle.db.write_tx();
            tx.insert(&handle.pkregs, key.as_bytes(), encoded.as_slice());
            tx.insert(&handle.user_pkregs_idx, user_idx_key.as_bytes(), b"");
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let mut tx = handle.db.write_tx();

            let result = match tx.take(&handle.pkregs, key.as_bytes()).map_err(db::err)? {
                None => None,
                Some(bytes) => {
                    let reg: StoredPasskeyRegistration = db::decode(&bytes)?;
                    let user_idx_key = db::user_pkregs_idx_key(reg.user_id, reg.id);
                    tx.remove(&handle.user_pkregs_idx, user_idx_key.as_bytes());
                    Some(reg)
                }
            };
            tx.commit().map_err(db::err)?;
            Ok(result)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_pkregs_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let idx_keys: Vec<String> = handle
                .user_pkregs_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .map(|guard| {
                    let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                    std::str::from_utf8(&key_bytes)
                        .map(ToOwned::to_owned)
                        .map_err(db::err)
                })
                .collect::<StorageResult<_>>()?;

            if idx_keys.is_empty() {
                return Ok(0);
            }

            let mut tx = handle.db.write_tx();
            let mut count = 0u64;
            for idx_key in &idx_keys {
                let challenge_id = idx_key
                    .splitn(2, '\x00')
                    .nth(1)
                    .ok_or_else(|| StorageError::msg("malformed user_pkregs_idx key"))?;
                if tx
                    .take(&handle.pkregs, challenge_id.as_bytes())
                    .map_err(db::err)?
                    .is_some()
                {
                    count += 1;
                }
                tx.remove(&handle.user_pkregs_idx, idx_key.as_bytes());
            }
            tx.commit().map_err(db::err)?;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_pkregs_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let count = handle
                .user_pkregs_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .count() as u64;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = value.id.0.to_string();
            let encoded = db::encode(&value)?;

            let mut tx = handle.db.write_tx();
            tx.insert(&handle.pkauths, key.as_bytes(), encoded.as_slice());
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let mut tx = handle.db.write_tx();

            let result = tx
                .take(&handle.pkauths, key.as_bytes())
                .map_err(db::err)?
                .map(|bytes| db::decode::<StoredPasskeyAuthentication>(&bytes))
                .transpose()?;

            tx.commit().map_err(db::err)?;
            Ok(result)
        })
        .await
        .map_err(db::err)?
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            // Collect expired registration keys and their user_ids (for index cleanup).
            let expired_regs: Vec<(Vec<u8>, StoredPasskeyRegistration)> = handle
                .pkregs
                .as_ref()
                .iter()
                .map(|guard| {
                    let (key, value) = guard.into_inner().map_err(db::err)?;
                    let reg: StoredPasskeyRegistration = db::decode(&value)?;
                    Ok((key.to_vec(), reg))
                })
                .filter(|r: &StorageResult<_>| {
                    r.as_ref().map_or(true, |(_, reg)| reg.expires_at <= now)
                })
                .collect::<StorageResult<_>>()?;

            // Collect expired authentication keys.
            let expired_auths: Vec<Vec<u8>> = handle
                .pkauths
                .as_ref()
                .iter()
                .map(|guard| {
                    let (key, value) = guard.into_inner().map_err(db::err)?;
                    let auth: StoredPasskeyAuthentication = db::decode(&value)?;
                    Ok((key.to_vec(), auth))
                })
                .filter(|r: &StorageResult<_>| {
                    r.as_ref().map_or(true, |(_, a)| a.expires_at <= now)
                })
                .map(|r: StorageResult<_>| r.map(|(k, _)| k))
                .collect::<StorageResult<_>>()?;

            if expired_regs.is_empty() && expired_auths.is_empty() {
                return Ok(0);
            }

            let mut tx = handle.db.write_tx();
            let mut n = 0u64;

            for (key, reg) in &expired_regs {
                if tx
                    .take(&handle.pkregs, key.as_slice())
                    .map_err(db::err)?
                    .is_some()
                {
                    let user_idx_key = db::user_pkregs_idx_key(reg.user_id, reg.id);
                    tx.remove(&handle.user_pkregs_idx, user_idx_key.as_bytes());
                    n += 1;
                }
            }
            for key in &expired_auths {
                if tx
                    .take(&handle.pkauths, key.as_slice())
                    .map_err(db::err)?
                    .is_some()
                {
                    n += 1;
                }
            }
            tx.commit().map_err(db::err)?;
            Ok(n)
        })
        .await
        .map_err(db::err)?
    }
}
