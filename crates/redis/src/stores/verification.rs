//! Redis-backed [`VerificationTokenStore`].
//!
//! A token is stored as its JSON row under `vtoken:{purpose}:{hash}` plus
//! membership in the per-user, per-purpose `user:{uid}:vtokens:{purpose}` SET.
//! Purpose is part of the key so a leaked token of one purpose can never be
//! redeemed under another. Redemption is the atomic `GETDEL` primitive:
//! exactly one concurrent caller observes the value, giving the single-use
//! guarantee; the index `SREM` is a best-effort follow-up.
//!
//! `create_token` writes with a plain `SET`, so it is an upsert: a repeated
//! `(purpose, hash)` overwrites rather than erroring, which the trait permits
//! for key-value adapters. The 256-bit hashes are random, so a collision is not
//! a real-world case.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

use crate::client::{self, RedisClient};
use crate::keys;

/// Verification-token store backed by a Redis/Valkey connection.
pub(crate) struct RedisVerificationTokenStore {
    client: RedisClient,
}

impl RedisVerificationTokenStore {
    /// Build a verification-token store over `client`.
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
        // Best-effort index cleanup; a lingering member is reclaimed by purge.
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
        // DEL counts only the rows that existed, so dangling members are not
        // mistaken for live tokens; then drop the SET.
        let removed = client::del(&mut conn, &vtoken_keys).await?;
        client::del(&mut conn, &[user_key]).await?;
        Ok(removed)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        // The purpose lives in the SET key, so iterate the known purposes and
        // scan each purpose's SETs; that pins the purpose needed to rebuild
        // each value key exactly.
        let mut removed = 0u64;
        for purpose in keys::ALL_PURPOSES {
            let set_keys = client::scan_all(&mut conn, &keys.user_vtokens_pattern(purpose)).await?;
            for set_key in set_keys {
                let members = client::smembers(&mut conn, &set_key).await?;
                if members.is_empty() {
                    continue;
                }
                let vtoken_keys: Vec<String> = members
                    .iter()
                    .map(|hex| keys.vtoken_key_for(purpose, hex))
                    .collect();
                let rows: Vec<Option<VerificationToken>> =
                    client::mget_json(&mut conn, &vtoken_keys).await?;

                let mut del_keys = Vec::new();
                let mut srem_members = Vec::new();
                for (member, row) in members.iter().zip(rows) {
                    match row {
                        Some(token) if token.expires_at <= now => {
                            del_keys.push(keys.vtoken_key_for(purpose, member));
                            srem_members.push(member.clone());
                        }
                        Some(_) => {}
                        None => srem_members.push(member.clone()),
                    }
                }
                client::del(&mut conn, &del_keys).await?;
                removed += client::srem(&mut conn, &set_key, &srem_members).await?;
            }
        }
        Ok(removed)
    }
}
