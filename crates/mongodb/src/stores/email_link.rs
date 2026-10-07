use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, TokenHash, UserId};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model::{self, email_link_id, purpose_str, to_bson_dt};

pub(crate) struct MongoEmailLinkStore {
    coll: Coll,
}

impl MongoEmailLinkStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }
}

#[async_trait]
impl EmailLinkStore for MongoEmailLinkStore {
    async fn create_link(&self, token: EmailLink) -> StorageResult<()> {
        self.coll
            .insert_one(model::email_link_to_doc(&token))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let filter = doc! { "_id": email_link_id(hash) };
        match self.coll.find_one_and_delete(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::email_link_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn delete_links_for_user(
        &self,
        user_id: UserId,
        purpose: EmailLinkPurpose,
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
