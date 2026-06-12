//! MongoDB-backed [`UserStore`].
//!
//! One document per user, keyed by the user's UUID string as `_id`. The email
//! uniqueness constraint is enforced by a **partial unique index** on `email`
//! (partial so documents without an email don't collide on a missing field). No
//! companion guard document or transaction is needed — MongoDB's unique index
//! provides the constraint directly, and a standalone server (no replica set)
//! suffices because the constraint is index-level, not transaction-level.
//!
//! - `create_user` → `insert_one`: the unique `_id` and the partial unique
//!   `email` index jointly reject a duplicate id or a duplicate email.
//! - `update_user` → `replace_one` (matched by `_id`): the index rejects a
//!   conflicting email change, and `matched_count == 0` surfaces "not found".
//! - Reads use `find_one` with a strongly-consistent primary read (the default
//!   for a standalone node).

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{User, UserId, UserStore};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model;

/// User store backed by a MongoDB collection.
pub(crate) struct MongoUserStore {
    coll: Coll,
}

impl MongoUserStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
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

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let filter = doc! { "_id": model::user_id_str(user.id) };
        let replacement = model::user_to_doc(&user);
        let result = self
            .coll
            .replace_one(filter, replacement)
            .await
            .map_err(err)?;
        if result.matched_count == 0 {
            return Err(StorageError::msg("user not found"));
        }
        Ok(())
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        let filter = doc! { "_id": model::user_id_str(id) };
        self.coll.delete_one(filter).await.map_err(err)?;
        Ok(())
    }
}
