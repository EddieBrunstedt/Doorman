//! Redis-backed [`PasskeyChallengeStore`].
//!
//! Scaffold: the trait is wired up so
//! `RedisStorage::passkey_challenge_store()` returns a working
//! `Arc<dyn PasskeyChallengeStore>`, but the method bodies are filled in by the
//! storage-implementation workstream.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::client::RedisClient;

/// Passkey-challenge store backed by a Redis/Valkey connection.
pub(crate) struct RedisPasskeyChallengeStore {
    client: RedisClient,
}

impl RedisPasskeyChallengeStore {
    /// Build a passkey-challenge store over `client`.
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

fn unimplemented<T>() -> StorageResult<T> {
    Err(StorageError::msg(
        "doorman-redis: PasskeyChallengeStore is not yet implemented",
    ))
}

#[async_trait]
impl PasskeyChallengeStore for RedisPasskeyChallengeStore {
    async fn put_registration(&self, _value: StoredPasskeyRegistration) -> StorageResult<()> {
        unimplemented()
    }

    async fn take_registration(
        &self,
        _id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        unimplemented()
    }

    async fn delete_registrations_for_user(&self, _user_id: UserId) -> StorageResult<u64> {
        unimplemented()
    }

    async fn count_registrations_for_user(&self, _user_id: UserId) -> StorageResult<u64> {
        unimplemented()
    }

    async fn put_authentication(&self, _value: StoredPasskeyAuthentication) -> StorageResult<()> {
        unimplemented()
    }

    async fn take_authentication(
        &self,
        _id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        unimplemented()
    }

    async fn purge_expired(&self, _now: DateTime<Utc>) -> StorageResult<u64> {
        unimplemented()
    }
}
