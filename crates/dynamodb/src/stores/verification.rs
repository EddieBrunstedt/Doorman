use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

use crate::client::DynamoClient;
use crate::model::{self, ENTITY_VTOKEN};

pub(crate) struct DynamoVerificationTokenStore {
    client: DynamoClient,
}

impl DynamoVerificationTokenStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl VerificationTokenStore for DynamoVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        self.client.put(model::vtoken_item(&token)).await
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        match self.client.take(&model::vtoken_pk(purpose, hash)).await? {
            Some(item) => Ok(Some(model::vtoken_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        self.client
            .delete_owned(&model::user_vtokens_key(user_id, purpose))
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.client.delete_expired(&[ENTITY_VTOKEN], now).await
    }
}
