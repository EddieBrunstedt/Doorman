use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, TokenHash, UserId};

use crate::client::DynamoClient;
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
    async fn create_link(&self, token: EmailLink) -> StorageResult<()> {
        self.client.put(model::email_link_item(&token)).await
    }

    async fn redeem_link(
        &self,
        hash: &TokenHash,
        purpose: EmailLinkPurpose,
    ) -> StorageResult<Option<EmailLink>> {
        match self
            .client
            .take(&model::email_link_pk(purpose, hash))
            .await?
        {
            Some(item) => Ok(Some(model::email_link_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn delete_links_for_user(
        &self,
        user_id: UserId,
        purpose: EmailLinkPurpose,
    ) -> StorageResult<u64> {
        self.client
            .delete_owned(&model::user_email_links_key(user_id, purpose))
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.client.delete_expired(&[ENTITY_EMAIL_LINK], now).await
    }
}
