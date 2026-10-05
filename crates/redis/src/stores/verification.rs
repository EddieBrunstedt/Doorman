use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

use crate::client::{self, RedisClient};
use crate::keys;
use crate::stores;

pub(crate) struct RedisVerificationTokenStore {
    client: RedisClient,
}

impl RedisVerificationTokenStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl VerificationTokenStore for RedisVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        let keys = self.client.keys();
        let vtoken_key = keys.vtoken(token.purpose, &token.token_hash);
        let user_key = keys.user_vtokens(token.user_id, token.purpose);
        let member = keys::token_hash_hex(&token.token_hash);
        let json = client::to_json(&token)?;
        let mut conn = self.client.conn();

        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("SET").arg(&vtoken_key).arg(&json).ignore();
        pipe.cmd("SADD").arg(&user_key).arg(&member).ignore();
        if let Some(ms) = client::ttl_at_ms(token.expires_at) {
            pipe.cmd("PEXPIREAT").arg(&vtoken_key).arg(ms).ignore();
        }
        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(StorageError::new)?;
        Ok(())
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let keys = self.client.keys();
        let vtoken_key = keys.vtoken(purpose, hash);
        let mut conn = self.client.conn();

        let Some(token) = client::getdel_json::<VerificationToken>(&mut conn, &vtoken_key).await?
        else {
            return Ok(None);
        };
        let user_key = keys.user_vtokens(token.user_id, purpose);
        let member = keys::token_hash_hex(hash);
        let _ = client::srem(&mut conn, &user_key, &[member]).await;
        Ok(Some(token))
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        let keys = self.client.keys();
        let user_key = keys.user_vtokens(user_id, purpose);
        let mut conn = self.client.conn();

        let members = client::smembers(&mut conn, &user_key).await?;
        if members.is_empty() {
            return Ok(0);
        }
        let vtoken_keys: Vec<String> = members
            .iter()
            .map(|hex| keys.vtoken_key_for(purpose, hex))
            .collect();
        let removed = client::del(&mut conn, &vtoken_keys).await?;
        client::del(&mut conn, &[user_key]).await?;
        Ok(removed)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        let mut removed = 0u64;
        for purpose in keys::ALL_PURPOSES {
            removed += stores::purge_index_sets::<VerificationToken>(
                &mut conn,
                keys,
                &keys.user_vtokens_pattern(purpose),
                |hex| keys.vtoken_key_for(purpose, hex),
                now,
            )
            .await?;
        }
        Ok(removed)
    }
}
