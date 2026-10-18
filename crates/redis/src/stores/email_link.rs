use std::sync::LazyLock;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::encoding::purpose_to_str;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{EmailLink, EmailLinkStore, TokenHash, UserId};

use crate::client::{self, RedisClient};
use crate::keys;
use crate::scripts;

static REPLACE_EMAIL_LINK: LazyLock<redis::Script> =
    LazyLock::new(|| redis::Script::new(scripts::REPLACE_EMAIL_LINK));

static DELETE_EMAIL_LINKS: LazyLock<redis::Script> =
    LazyLock::new(|| redis::Script::new(scripts::DELETE_EMAIL_LINKS));

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
        let mut conn = self.client.conn();

        let inserted: i64 = REPLACE_EMAIL_LINK
            .key(keys.email_link(&link.token_hash))
            .key(keys.user_email_links(link.user_id))
            .arg(client::to_json(&link)?)
            .arg(link.expires_at.timestamp_millis())
            .arg(purpose_to_str(link.purpose))
            .arg(keys::token_hash_hex(&link.token_hash))
            .arg(keys.email_link_key_for(""))
            .invoke_async(&mut conn)
            .await
            .map_err(StorageError::new)?;
        if inserted == 0 {
            return Err(StorageError::conflict(
                "email link token hash already exists",
            ));
        }
        Ok(())
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        // The owner's hash may still name the redeemed row; replacing or
        // deleting it then finds no row, so it is left to expire.
        client::getdel_json(&mut conn, &keys.email_link(hash)).await
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        DELETE_EMAIL_LINKS
            .key(keys.user_email_links(user_id))
            .arg(keys.email_link_key_for(""))
            .invoke_async(&mut conn)
            .await
            .map_err(StorageError::new)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        let link_keys = client::scan_all(&mut conn, &keys.email_link_pattern()).await?;
        if link_keys.is_empty() {
            return Ok(0);
        }
        let rows: Vec<Option<EmailLink>> = client::mget_json(&mut conn, &link_keys).await?;
        let expired: Vec<String> = link_keys
            .into_iter()
            .zip(rows)
            .filter_map(|(key, row)| match row {
                Some(link) if link.expires_at <= now => Some(key),
                _ => None,
            })
            .collect();
        client::del(&mut conn, &expired).await
    }
}
