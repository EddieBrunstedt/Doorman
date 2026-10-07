use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, TokenHash, UserId};

use crate::client::{self, RedisClient};
use crate::keys;
use crate::stores;

pub(crate) struct RedisEmailLinkStore {
    client: RedisClient,
}

impl RedisEmailLinkStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EmailLinkStore for RedisEmailLinkStore {
    async fn create_link(&self, token: EmailLink) -> StorageResult<()> {
        let keys = self.client.keys();
        let email_link_key = keys.email_link(&token.token_hash);
        let user_key = keys.user_email_links(token.user_id, token.purpose);
        let member = keys::token_hash_hex(&token.token_hash);
        let json = client::to_json(&token)?;
        let mut conn = self.client.conn();

        stores::insert_absent(
            &mut conn,
            &[(&email_link_key, &json)],
            token.expires_at,
            Some(stores::OwnerIndex {
                set: &user_key,
                member: &member,
            }),
            "email link token hash",
        )
        .await
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let keys = self.client.keys();
        let email_link_key = keys.email_link(hash);
        let mut conn = self.client.conn();

        let Some(token) = client::getdel_json::<EmailLink>(&mut conn, &email_link_key).await?
        else {
            return Ok(None);
        };
        let user_key = keys.user_email_links(token.user_id, token.purpose);
        let member = keys::token_hash_hex(hash);
        let _ = client::srem(&mut conn, &user_key, &[member]).await;
        Ok(Some(token))
    }

    async fn delete_links_for_user(
        &self,
        user_id: UserId,
        purpose: EmailLinkPurpose,
    ) -> StorageResult<u64> {
        let keys = self.client.keys();
        let user_key = keys.user_email_links(user_id, purpose);
        let mut conn = self.client.conn();

        let members = client::smembers(&mut conn, &user_key).await?;
        if members.is_empty() {
            return Ok(0);
        }
        let email_link_keys: Vec<String> = members
            .iter()
            .map(|hex| keys.email_link_key_for(hex))
            .collect();
        let removed = client::del(&mut conn, &email_link_keys).await?;
        client::del(&mut conn, &[user_key]).await?;
        Ok(removed)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        let mut removed = 0u64;
        for purpose in keys::ALL_PURPOSES {
            removed += stores::purge_index_sets::<EmailLink>(
                &mut conn,
                keys,
                &keys.user_email_links_pattern(purpose),
                |hex| keys.email_link_key_for(hex),
                now,
            )
            .await?;
        }
        Ok(removed)
    }
}
