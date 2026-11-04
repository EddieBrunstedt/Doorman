use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::encoding::purpose_to_str;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{EmailLink, EmailLinkStore, TokenHash, UserId};

use crate::client::RedisClient;
use crate::keys::{self, Family, Ownership};
use crate::table::{Expiring, Insert, Table};

impl Expiring for EmailLink {
    const FAMILY: Family = Family {
        row: "email_link",
        rows: "email_links",
        ownership: Ownership::Field,
    };

    fn id(&self) -> String {
        keys::token_hash_hex(&self.token_hash)
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn owner(&self) -> Option<UserId> {
        Some(self.user_id)
    }

    fn owner_field(&self) -> &'static str {
        purpose_to_str(self.purpose)
    }
}

pub(crate) struct RedisEmailLinkStore {
    table: Table<EmailLink>,
}

impl RedisEmailLinkStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self {
            table: Table::new(client),
        }
    }
}

#[async_trait]
impl EmailLinkStore for RedisEmailLinkStore {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        match self.table.replace(&link).await? {
            Insert::Done => Ok(()),
            Insert::Conflict => Err(StorageError::conflict(
                "email link token hash already exists",
            )),
        }
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        self.table.take(&keys::token_hash_hex(hash)).await
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.table.delete_owned(user_id, None).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.table.purge(now).await
    }
}
