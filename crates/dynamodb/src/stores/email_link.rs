use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{EmailLink, EmailLinkStore, TokenHash, UserId};

use crate::client::{self, DynamoClient};
use crate::model::{self, ENTITY_EMAIL_LINK};

pub(crate) struct DynamoEmailLinkStore {
    client: DynamoClient,
}

impl DynamoEmailLinkStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EmailLinkStore for DynamoEmailLinkStore {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        let pk = model::email_link_pk(&link.token_hash);
        self.client
            .put_new(model::email_link_item(&link), "email link token hash")
            .await?;
        let mut replaced = Vec::new();
        for item in self
            .client
            .query_owner(&model::user_email_links_key(link.user_id))
            .await?
        {
            let item_pk = client::item_pk(&item)?;
            if item_pk != pk && model::email_link_from_item(&item)?.purpose == link.purpose {
                replaced.push(item_pk);
            }
        }
        self.client.batch_delete(replaced).await
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        match self.client.take(&model::email_link_pk(hash)).await? {
            Some(item) => Ok(Some(model::email_link_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.client
            .delete_owned(&model::user_email_links_key(user_id))
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.client.delete_expired(&[ENTITY_EMAIL_LINK], now).await
    }
}
