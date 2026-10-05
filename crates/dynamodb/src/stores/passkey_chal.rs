//! DynamoDB-backed [`PasskeyChallengeStore`].
//!
//! Two ceremony kinds share this store. A registration is one item under
//! `pkreg#<id>` plus an `owner-index` entry on its user, which backs the
//! per-user count and bulk-delete the recovery flow relies on. An
//! authentication is a bare `pkauth#<id>` item with **no** owner index — nothing
//! queries authentications by user — so it is pure TTL, and its purge reaches it
//! by table scan. Both `take_*` use the atomic delete-and-return `take`, so a
//! challenge can never be replayed.
//!
//! `put_*` are plain `PutItem` upserts; the ids are random, so a collision is
//! not a real-world case. Native TTL evicts spent ceremonies in production;
//! `purge_expired` is the authoritative reclamation across both kinds.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::client::DynamoClient;
use crate::model::{self, ENTITY_PKAUTH, ENTITY_PKREG};

/// Passkey-challenge store backed by a DynamoDB connection.
pub(crate) struct DynamoPasskeyChallengeStore {
    client: DynamoClient,
}

impl DynamoPasskeyChallengeStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyChallengeStore for DynamoPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.client.put(model::pkreg_item(&value)).await
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        match self.client.take(&model::pkreg_pk(id)).await? {
            Some(item) => Ok(Some(model::pkreg_from_item(&item)?)),
            None => Ok(None),
        }
    }

    /// Enumerates the user's registration ceremonies through the eventually-consistent
    /// `owner-index` GSI, so a ceremony created immediately before this revoke may
    /// not yet be visible and can survive it; it is reclaimed on a later revoke
    /// or by `purge_expired` / native TTL. This bulk revoke is best-effort under
    /// write-after-write.
    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.client
            .delete_owned(&model::user_pkregs_key(user_id))
            .await
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        // A GSI count, which the trait permits to be coarse: it may include
        // ceremonies that have technically expired but are not yet reclaimed.
        self.client
            .count_owner(&model::user_pkregs_key(user_id))
            .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.client.put(model::pkauth_item(&value)).await
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        match self.client.take(&model::pkauth_pk(id)).await? {
            Some(item) => Ok(Some(model::pkauth_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.client
            .delete_expired(&[ENTITY_PKREG, ENTITY_PKAUTH], now)
            .await
    }
}
