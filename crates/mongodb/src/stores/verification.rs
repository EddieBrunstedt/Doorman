//! MongoDB-backed [`VerificationTokenStore`].
//!
//! One document per token. The document `_id` is `{purpose}#{token_hash_hex}`,
//! which encodes both the purpose and the hash into the primary key. This
//! means:
//!
//! - **Atomic single-use** — `consume_token` is a `findOneAndDelete` on
//!   `_id`: MongoDB serializes writes per document, so exactly one concurrent
//!   caller observes the old image, giving the single-use guarantee.
//! - **Purpose scoping** — a token of one purpose can never be redeemed under
//!   another, because the `_id` lookup for the wrong purpose finds nothing.
//! - **No extra transaction** — the `_id` provides the uniqueness guarantee
//!   directly; no companion guard item or replica-set transaction is needed.
//!
//! A compound `(user_id, purpose)` index backs the per-purpose bulk delete
//! that `delete_tokens_for_user` performs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model::{self, purpose_str, to_bson_dt, vtoken_id};

/// Verification-token store backed by a MongoDB collection.
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
