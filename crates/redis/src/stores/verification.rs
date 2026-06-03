//! Redis-backed [`VerificationTokenStore`].
//!
//! Scaffold: the trait is wired up so
//! `RedisStorage::verification_token_store()` returns a working
//! `Arc<dyn VerificationTokenStore>`, but the method bodies are filled in by
//! the storage-implementation workstream.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

use crate::client::RedisClient;

/// Verification-token store backed by a Redis/Valkey connection.
pub(crate) struct RedisVerificationTokenStore {
    client: RedisClient,
}

impl RedisVerificationTokenStore {
    /// Build a verification-token store over `client`.
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

fn unimplemented<T>() -> StorageResult<T> {
    Err(StorageError::msg(
        "doorman-redis: VerificationTokenStore is not yet implemented",
    ))
}

#[async_trait]
impl VerificationTokenStore for RedisVerificationTokenStore {
    async fn create_token(&self, _token: VerificationToken) -> StorageResult<()> {
        unimplemented()
    }

    async fn consume_token(
        &self,
        _hash: &TokenHash,
        _purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        unimplemented()
    }

    async fn delete_tokens_for_user(
        &self,
        _user_id: UserId,
        _purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        unimplemented()
    }

    async fn purge_expired(&self, _now: DateTime<Utc>) -> StorageResult<u64> {
        unimplemented()
    }
}
