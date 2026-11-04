use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{DpopProofStore, UsedDpopProof};

use crate::db::{self, RedbHandle};
use crate::expiring::{Expiring, Family, Writer};

impl Expiring for UsedDpopProof {
    const FAMILY: Family = db::DPOP_PROOFS;

    fn key(&self) -> String {
        db::hex_bytes(&self.id.0)
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

pub(crate) struct RedbDpopProofStore {
    handle: RedbHandle,
}

impl RedbDpopProofStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl DpopProofStore for RedbDpopProofStore {
    async fn use_proof(&self, proof: UsedDpopProof) -> StorageResult<bool> {
        self.handle
            .write(move |wtxn| Writer::open(wtxn)?.insert(&proof))
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| Writer::<UsedDpopProof>::open(wtxn)?.purge(now))
            .await
    }
}
