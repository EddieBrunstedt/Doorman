use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{DpopProofStore, UsedDpopProof};
use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

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
            .write(move |wtxn| {
                let key = db::hex_bytes(&proof.id.0);
                let mut proofs = wtxn.open_table(db::DPOP_PROOFS).map_err(db::err)?;
                if proofs.get(key.as_str()).map_err(db::err)?.is_some() {
                    return Ok(false);
                }
                let encoded = db::encode(&proof)?;
                proofs
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                Ok(true)
            })
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut proofs = wtxn.open_table(db::DPOP_PROOFS).map_err(db::err)?;
                let expired: Vec<String> = proofs
                    .iter()
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, v)| {
                            let proof = db::decode::<UsedDpopProof>(v.value())?;
                            Ok((k.value().to_owned(), proof))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, p)| p.expires_at <= now))
                    .map(|r| r.map(|(k, _)| k))
                    .collect::<StorageResult<_>>()?;
                for key in &expired {
                    proofs.remove(key.as_str()).map_err(db::err)?;
                }
                Ok(expired.len() as u64)
            })
            .await
    }
}
