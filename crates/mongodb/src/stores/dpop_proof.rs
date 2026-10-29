use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageErrorKind, StorageResult};
use doorman_core::storage::{DpopProofStore, UsedDpopProof};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model::{self, to_bson_dt};

pub(crate) struct MongoDpopProofStore {
    coll: Coll,
}

impl MongoDpopProofStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }
}

#[async_trait]
impl DpopProofStore for MongoDpopProofStore {
    async fn use_proof(&self, proof: UsedDpopProof) -> StorageResult<bool> {
        // The `_id` makes the insert the check, so racing uses can't both succeed.
        match self.coll.insert_one(model::dpop_proof_to_doc(&proof)).await {
            Ok(_) => Ok(true),
            Err(error) => {
                let error = err(error);
                if error.kind() == StorageErrorKind::Conflict {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let filter = doc! { "expires_at": { "$lte": to_bson_dt(now) } };
        let result = self.coll.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }
}
