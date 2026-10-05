use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::client::DynamoClient;
use crate::model::{self, ENTITY_PKAUTH, ENTITY_PKREG};

pub(crate) struct DynamoPasskeyChallengeStore {
    client: DynamoClient,
}

impl DynamoPasskeyChallengeStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyChallengeStore for DynamoPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.client.put(model::pkreg_item(&value)).await
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        match self.client.take(&model::pkreg_pk(id)).await? {
            Some(item) => Ok(Some(model::pkreg_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.client
            .delete_owned(&model::user_pkregs_key(user_id))
            .await
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.client
            .count_owner(&model::user_pkregs_key(user_id))
            .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.client.put(model::pkauth_item(&value)).await
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        match self.client.take(&model::pkauth_pk(id)).await? {
            Some(item) => Ok(Some(model::pkauth_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.client
            .delete_expired(&[ENTITY_PKREG, ENTITY_PKAUTH], now)
            .await
    }
}
