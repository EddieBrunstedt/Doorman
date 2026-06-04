//! Redis-backed [`PasskeyChallengeStore`].
//!
//! Two ceremony kinds share this store (§5.4). A registration is its JSON row
//! under `pkreg:{id}` plus membership in the per-user `user:{uid}:pkregs` SET,
//! which backs the per-user count and bulk-delete the recovery flow relies on.
//! An authentication is a bare `pkauth:{id}` row with **no** secondary index —
//! nothing queries authentications by user — so it is pure TTL, and its purge
//! scans the rows directly. Both `take_*` use the atomic `GETDEL` primitive
//! (§5.5) so a challenge can never be replayed.
//!
//! `put_registration` and `put_authentication` write with a plain `SET`, so
//! they are upserts: a repeated ceremony id overwrites rather than erroring,
//! which the trait permits for key-value adapters. The ids are random, so a
//! collision is not a real-world case.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::client::{self, RedisClient};

/// Passkey-challenge store backed by a Redis/Valkey connection.
pub(crate) struct RedisPasskeyChallengeStore {
    client: RedisClient,
}

impl RedisPasskeyChallengeStore {
    /// Build a passkey-challenge store over `client`.
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyChallengeStore for RedisPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        let keys = self.client.keys();
        let reg_key = keys.pkreg(value.id);
        let user_key = keys.user_pkregs(value.user_id);
        let id = value.id.0.to_string();
        let json = client::to_json(&value)?;
        let mut conn = self.client.conn();

        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("SET").arg(&reg_key).arg(&json).ignore();
        pipe.cmd("SADD").arg(&user_key).arg(&id).ignore();
        if let Some(ms) = client::ttl_at_ms(value.expires_at) {
            pipe.cmd("PEXPIREAT").arg(&reg_key).arg(ms).ignore();
        }
        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(StorageError::new)?;
        Ok(())
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        let keys = self.client.keys();
        let reg_key = keys.pkreg(id);
        let mut conn = self.client.conn();

        let Some(registration) =
            client::getdel_json::<StoredPasskeyRegistration>(&mut conn, &reg_key).await?
        else {
            return Ok(None);
        };
        // Best-effort index cleanup; a lingering member is reclaimed by purge,
        // and `count_registrations_for_user` is explicitly allowed to be coarse.
        let user_key = keys.user_pkregs(registration.user_id);
        let _ = client::srem(&mut conn, &user_key, &[id.0.to_string()]).await;
        Ok(Some(registration))
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let keys = self.client.keys();
        let user_key = keys.user_pkregs(user_id);
        let mut conn = self.client.conn();

        let members = client::smembers(&mut conn, &user_key).await?;
        if members.is_empty() {
            return Ok(0);
        }
        let reg_keys: Vec<String> = members.iter().map(|m| keys.pkreg_key_for(m)).collect();
        let removed = client::del(&mut conn, &reg_keys).await?;
        client::del(&mut conn, &[user_key]).await?;
        Ok(removed)
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        // SCARD counts members directly, including any that have technically
        // expired — the trait permits this coarse bound (§5.6), and it avoids
        // fetching every row just to size the set.
        let user_key = self.client.keys().user_pkregs(user_id);
        let mut conn = self.client.conn();
        client::scard(&mut conn, &user_key).await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let keys = self.client.keys();
        let auth_key = keys.pkauth(value.id);
        let json = client::to_json(&value)?;
        let mut conn = self.client.conn();

        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("SET").arg(&auth_key).arg(&json).ignore();
        if let Some(ms) = client::ttl_at_ms(value.expires_at) {
            pipe.cmd("PEXPIREAT").arg(&auth_key).arg(ms).ignore();
        }
        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(StorageError::new)?;
        Ok(())
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        let auth_key = self.client.keys().pkauth(id);
        let mut conn = self.client.conn();
        client::getdel_json(&mut conn, &auth_key).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();
        let mut removed = 0u64;

        // Registrations: reachable through their per-user SETs, which is also
        // where dangling members are reclaimed.
        let set_keys = client::scan_all(&mut conn, &keys.user_pkregs_pattern()).await?;
        for set_key in set_keys {
            let members = client::smembers(&mut conn, &set_key).await?;
            if members.is_empty() {
                continue;
            }
            let reg_keys: Vec<String> = members.iter().map(|m| keys.pkreg_key_for(m)).collect();
            let rows: Vec<Option<StoredPasskeyRegistration>> =
                client::mget_json(&mut conn, &reg_keys).await?;

            let mut del_keys = Vec::new();
            let mut srem_members = Vec::new();
            for (member, row) in members.iter().zip(rows) {
                match row {
                    Some(reg) if reg.expires_at <= now => {
                        del_keys.push(keys.pkreg_key_for(member));
                        srem_members.push(member.clone());
                    }
                    Some(_) => {}
                    None => srem_members.push(member.clone()),
                }
            }
            client::del(&mut conn, &del_keys).await?;
            removed += client::srem(&mut conn, &set_key, &srem_members).await?;
        }

        // Authentications carry no index, so scan the rows directly and delete
        // the expired ones.
        let auth_keys = client::scan_all(&mut conn, &keys.pkauth_pattern()).await?;
        if !auth_keys.is_empty() {
            let rows: Vec<Option<StoredPasskeyAuthentication>> =
                client::mget_json(&mut conn, &auth_keys).await?;
            let expired: Vec<String> = auth_keys
                .into_iter()
                .zip(rows)
                .filter_map(|(key, row)| match row {
                    Some(auth) if auth.expires_at <= now => Some(key),
                    _ => None,
                })
                .collect();
            removed += client::del(&mut conn, &expired).await?;
        }

        Ok(removed)
    }
}
