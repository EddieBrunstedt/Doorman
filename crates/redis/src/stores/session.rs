//! Redis-backed [`SessionStore`].
//!
//! Scaffold: the trait is wired up so `RedisStorage::session_store()` returns a
//! working `Arc<dyn SessionStore>`, but the method bodies are filled in by the
//! storage-implementation workstream.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::client::RedisClient;

/// Session store backed by a Redis/Valkey connection.
pub(crate) struct RedisSessionStore {
    client: RedisClient,
}

impl RedisSessionStore {
    /// Build a session store over `client`.
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

fn unimplemented<T>() -> StorageResult<T> {
    Err(StorageError::msg(
        "doorman-redis: SessionStore is not yet implemented",
    ))
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(&self, _session: Session) -> StorageResult<()> {
        unimplemented()
    }

    async fn find_session_by_token_hash(
        &self,
        _hash: &TokenHash,
    ) -> StorageResult<Option<Session>> {
        unimplemented()
    }

    async fn find_session_by_id(&self, _id: SessionId) -> StorageResult<Option<Session>> {
        unimplemented()
    }

    async fn list_for_user(
        &self,
        _user_id: UserId,
        _now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        unimplemented()
    }

    async fn delete_session(&self, _id: SessionId) -> StorageResult<()> {
        unimplemented()
    }

    async fn delete_sessions_for_user(&self, _user_id: UserId) -> StorageResult<u64> {
        unimplemented()
    }

    async fn delete_other_sessions_for_user(
        &self,
        _user_id: UserId,
        _except: SessionId,
    ) -> StorageResult<u64> {
        unimplemented()
    }

    async fn purge_expired(&self, _now: DateTime<Utc>) -> StorageResult<u64> {
        unimplemented()
    }
}
