use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{AccountStatus, User, UserId, UserStore};
use mongodb::bson::{Document, doc};

use crate::db::{Coll, err};
use crate::model;

pub(crate) struct MongoUserStore {
    coll: Coll,
}

impl MongoUserStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }

    async fn update(&self, id: UserId, update: Document) -> StorageResult<()> {
        let filter = doc! { "_id": model::user_id_str(id) };
        let result = self.coll.update_one(filter, update).await.map_err(err)?;
        if result.matched_count == 0 {
            return Err(StorageError::not_found("user not found"));
        }
        Ok(())
    }
}

#[async_trait]
impl UserStore for MongoUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        self.coll
            .insert_one(model::user_to_doc(&user))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        let filter = doc! { "_id": model::user_id_str(id) };
        match self.coll.find_one(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::user_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let filter = doc! { "email": email };
        match self.coll.find_one(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::user_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn set_user_status(
        &self,
        id: UserId,
        status: AccountStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let mut set = doc! {
            "status": model::account_status_to_str(&status),
            "updated_at": model::to_bson_dt(at),
        };
        let update = match status.disabled_at() {
            Some(disabled_at) => {
                set.insert("disabled_at", model::to_bson_dt(disabled_at));
                doc! { "$set": set }
            }
            None => doc! { "$set": set, "$unset": { "disabled_at": "" } },
        };
        self.update(id, update).await
    }

    async fn set_user_email(
        &self,
        id: UserId,
        email: &str,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let update = doc! {
            "$set": {
                "email": email,
                "email_verified_at": model::to_bson_dt(at),
                "updated_at": model::to_bson_dt(at),
            }
        };
        self.update(id, update).await
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        let update = doc! {
            "$set": {
                "email_verified_at": model::to_bson_dt(at),
                "updated_at": model::to_bson_dt(at),
            }
        };
        self.update(id, update).await
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        let filter = doc! { "_id": model::user_id_str(id) };
        self.coll.delete_one(filter).await.map_err(err)?;
        Ok(())
    }
}
