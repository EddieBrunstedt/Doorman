use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
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

        stores::insert_absent(
            &mut conn,
            &[(&reg_key, &json)],
            value.expires_at,
            Some(stores::OwnerIndex {
                set: &user_key,
                member: &id,
            }),
            "registration challenge id",
        )
        .await
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
        let mut conn = self.client.conn();
        stores::delete_indexed::<StoredPasskeyRegistration>(
            &mut conn,
            keys,
            &keys.user_pkregs(user_id),
            |m| keys.pkreg_key_for(m),
            None,
        )
        .await
    }

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();
        stores::list_indexed(&mut conn, &keys.user_pkregs(user_id), |m| {
            keys.pkreg_key_for(m)
        })
        .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let auth_key = self.client.keys().pkauth(value.id);
        let json = client::to_json(&value)?;
        let mut conn = self.client.conn();

        stores::insert_absent(
            &mut conn,
            &[(&auth_key, &json)],
            value.expires_at,
            None,
            "authentication challenge id",
        )
        .await
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
