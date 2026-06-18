//! DynamoDB-backed [`VerificationTokenStore`].
//!
//! A token is one item under `vtoken#<purpose>#<hash>` — purpose is part of the
//! key, so a leaked token of one purpose can never be redeemed under another —
//! plus an `owner-index` entry keyed on `(user, purpose)` that backs the
//! per-purpose bulk delete. Redemption is the atomic delete-and-return `take`
//! (`DeleteItem` with `ALL_OLD`): exactly one concurrent caller observes the
//! value, giving the single-use guarantee.
//!
//! `create_token` is a plain `PutItem` upsert; the 256-bit hashes are random, so
//! a collision is not a real-world case. Native TTL evicts spent rows in
//! production; `purge_expired` is the authoritative reclamation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

use crate::client::{self, DynamoClient};
use crate::model::{self, ENTITY_VTOKEN};

/// Verification-token store backed by a DynamoDB connection.
pub(crate) struct DynamoVerificationTokenStore {
    client: DynamoClient,
}

impl DynamoVerificationTokenStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl VerificationTokenStore for DynamoVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        self.client.put(model::vtoken_item(&token)).await
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        match self.client.take(&model::vtoken_pk(purpose, hash)).await? {
            Some(item) => Ok(Some(model::vtoken_from_item(&item)?)),
            None => Ok(None),
        }
    }

    /// Enumerates the user's tokens of this purpose through the eventually-consistent
    /// `owner-index` GSI, so a token created immediately before this revoke may
    /// not yet be visible and can survive it; it is reclaimed on a later revoke
    /// or by `purge_expired` / native TTL. This bulk revoke is best-effort under
    /// write-after-write.
    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        let items = self
            .client
            .query_owner(&model::user_vtokens_key(user_id, purpose))
            .await?;
        let keys = items
            .iter()
            .map(client::item_pk)
            .collect::<StorageResult<Vec<_>>>()?;
        let removed = keys.len() as u64;
        self.client.batch_delete(keys).await?;
        Ok(removed)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let items = self.client.scan_entities(&[ENTITY_VTOKEN]).await?;
        let mut keys = Vec::new();
        for item in &items {
            if client::get_ts(item, client::EXPIRES_AT)? <= now {
                keys.push(client::item_pk(item)?);
            }
        }
        let removed = keys.len() as u64;
        self.client.batch_delete(keys).await?;
        Ok(removed)
    }
}
