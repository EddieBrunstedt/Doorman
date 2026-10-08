use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{EmailLink, EmailLinkStore, TokenHash, UserId};

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
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        let keys = self.client.keys();
        let email_link_key = keys.email_link(&link.token_hash);
        let user_key = keys.user_email_links(link.user_id);
        let member = keys::token_hash_hex(&link.token_hash);
        let json = client::to_json(&link)?;
        let mut conn = self.client.conn();

        stores::insert_absent(
            &mut conn,
            &[(&email_link_key, &json)],
            link.expires_at,
            Some(stores::OwnerIndex {
                set: &user_key,
                member: &member,
            }),
            "email link token hash",
        )
        .await?;

        let others: Vec<String> = client::smembers(&mut conn, &user_key)
            .await?
            .into_iter()
            .filter(|other| *other != member)
            .collect();
        let other_keys: Vec<String> = others
            .iter()
            .map(|hex| keys.email_link_key_for(hex))
            .collect();
        let rows: Vec<Option<EmailLink>> = client::mget_json(&mut conn, &other_keys).await?;
        let mut replaced_keys = Vec::new();
        let mut replaced_members = Vec::new();
        for ((other, key), row) in others.into_iter().zip(other_keys).zip(rows) {
            match row {
                Some(row) if row.purpose != link.purpose => {}
                _ => {
                    replaced_keys.push(key);
                    replaced_members.push(other);
                }
            }
        }
        client::del(&mut conn, &replaced_keys).await?;
        client::srem(&mut conn, &user_key, &replaced_members).await?;
        Ok(())
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let keys = self.client.keys();
        let email_link_key = keys.email_link(hash);
        let mut conn = self.client.conn();

        let Some(link) = client::getdel_json::<EmailLink>(&mut conn, &email_link_key).await? else {
            return Ok(None);
        };
        let user_key = keys.user_email_links(link.user_id);
        let member = keys::token_hash_hex(hash);
        let _ = client::srem(&mut conn, &user_key, &[member]).await;
        Ok(Some(link))
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let keys = self.client.keys();
        let user_key = keys.user_email_links(user_id);
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

        stores::purge_index_sets::<EmailLink>(
            &mut conn,
            keys,
            &keys.user_email_links_pattern(),
            |hex| keys.email_link_key_for(hex),
            now,
        )
        .await
    }
}
