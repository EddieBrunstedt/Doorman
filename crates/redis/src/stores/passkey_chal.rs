use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::client::{self, RedisClient};
use crate::stores;

pub(crate) struct RedisPasskeyChallengeStore {
    client: RedisClient,
}

impl RedisPasskeyChallengeStore {
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

        let mut removed = stores::purge_index_sets::<StoredPasskeyRegistration>(
            &mut conn,
            keys,
            &keys.user_pkregs_pattern(),
            |id| keys.pkreg_key_for(id),
            now,
        )
        .await?;

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
