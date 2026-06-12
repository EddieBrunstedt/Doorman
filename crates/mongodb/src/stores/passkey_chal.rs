//! MongoDB-backed [`PasskeyChallengeStore`].
//!
//! Two ceremony kinds share this store, each in its own collection:
//!
//! - **`passkey_registrations`** — keyed by challenge UUID; carries a `user_id`
//!   for the per-user count and bulk-delete paths that the recovery flow needs.
//! - **`passkey_authentications`** — keyed by challenge UUID; no `user_id`
//!   (discoverable-credential flow doesn't know the user upfront). Reached only
//!   by id and by the TTL monitor / `purge_expired` scan.
//!
//! Both `take_*` operations use `findOneAndDelete`: MongoDB serializes writes
//! per document, so exactly one concurrent caller observes the old image —
//! the single-use guarantee ceremonies rely on.
//!
//! `purge_expired` issues a `deleteMany` with `expires_at <= now` on both
//! collections and returns the combined count.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model::{self, challenge_id_str, to_bson_dt};

/// Passkey-challenge store backed by two MongoDB collections.
pub(crate) struct MongoPasskeyChallengeStore {
    registrations: Coll,
    authentications: Coll,
}

impl MongoPasskeyChallengeStore {
    pub(crate) fn new(registrations: Coll, authentications: Coll) -> Self {
        Self {
            registrations,
            authentications,
        }
    }
}

#[async_trait]
impl PasskeyChallengeStore for MongoPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.registrations
            .insert_one(model::pkreg_to_doc(&value))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        let filter = doc! { "_id": challenge_id_str(id) };
        match self
            .registrations
            .find_one_and_delete(filter)
            .await
            .map_err(err)?
        {
            Some(doc) => Ok(Some(model::pkreg_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let filter = doc! { "user_id": user_id.0.to_string() };
        let result = self.registrations.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        // Counts all challenges for the user, including technically-expired ones
        // that `purge_expired` has not yet reclaimed — per the trait contract.
        let filter = doc! { "user_id": user_id.0.to_string() };
        self.registrations
            .count_documents(filter)
            .await
            .map_err(err)
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.authentications
            .insert_one(model::pkauth_to_doc(&value))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        let filter = doc! { "_id": challenge_id_str(id) };
        match self
            .authentications
            .find_one_and_delete(filter)
            .await
            .map_err(err)?
        {
            Some(doc) => Ok(Some(model::pkauth_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let filter = doc! { "expires_at": { "$lte": to_bson_dt(now) } };
        let reg_result = self
            .registrations
            .delete_many(filter.clone())
            .await
            .map_err(err)?;
        let auth_result = self
            .authentications
            .delete_many(filter)
            .await
            .map_err(err)?;
        Ok(reg_result.deleted_count + auth_result.deleted_count)
    }
}
