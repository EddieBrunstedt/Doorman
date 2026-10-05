use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model::{self, purpose_str, to_bson_dt, vtoken_id};

pub(crate) struct MongoVerificationTokenStore {
    coll: Coll,
}

impl MongoVerificationTokenStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }
}

#[async_trait]
impl VerificationTokenStore for MongoVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        self.coll
            .insert_one(model::vtoken_to_doc(&token))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let filter = doc! { "_id": vtoken_id(purpose, hash) };
        match self.coll.find_one_and_delete(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::vtoken_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        let filter = doc! {
            "user_id": user_id.0.to_string(),
            "purpose": purpose_str(purpose),
        };
        let result = self.coll.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let filter = doc! { "expires_at": { "$lte": to_bson_dt(now) } };
        let result = self.coll.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }
}
