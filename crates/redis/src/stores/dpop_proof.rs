use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{DpopProofStore, UsedDpopProof};

use crate::client::RedisClient;
use crate::keys::{Family, Ownership};
use crate::table::{Insert, Row, Table};

impl Row for UsedDpopProof {
    const FAMILY: Family = Family {
        row: "dpop_proof",
        rows: "dpop_proofs",
        ownership: Ownership::None,
    };

    fn id(&self) -> String {
        doorman_core::encoding::hex(&self.id.0)
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

pub(crate) struct RedisDpopProofStore {
    table: Table<UsedDpopProof>,
}

impl RedisDpopProofStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self {
            table: Table::new(client),
        }
    }
}

#[async_trait]
impl DpopProofStore for RedisDpopProofStore {
    async fn use_proof(&self, proof: UsedDpopProof) -> StorageResult<bool> {
        Ok(matches!(self.table.insert(&proof).await?, Insert::Done))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.table.purge(now).await
    }
}
