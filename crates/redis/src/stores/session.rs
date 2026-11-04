use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::client::RedisClient;
use crate::keys::{Family, Key, Keys, Ownership};
use crate::table::{Expiring, Insert, Table};

impl Expiring for Session {
    const FAMILY: Family = Family {
        row: "session",
        rows: "sessions",
        ownership: Ownership::Set,
    };

    fn id(&self) -> String {
        self.id.0.to_string()
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn owner(&self) -> Option<UserId> {
        Some(self.user_id)
    }

    fn lookups(&self, keys: &Keys) -> Vec<Key> {
        vec![keys.session_by_token_hash(&self.token_hash)]
    }
}

pub(crate) struct RedisSessionStore {
    client: RedisClient,
    table: Table<Session>,
}

impl RedisSessionStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self {
            table: Table::new(client.clone()),
            client,
        }
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        match self.table.insert(&session).await? {
            Insert::Done => Ok(()),
            Insert::Conflict => Err(StorageError::conflict(
                "session id or token hash already exists",
            )),
        }
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let Some(mut session) = self.table.get(&id.0.to_string()).await? else {
            return Ok(());
        };
        session.last_used_at = last_used_at;
        session.expires_at = expires_at;
        self.table.update(&session).await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        self.table
            .get_by(&self.client.keys().session_by_token_hash(hash))
            .await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.table.get(&id.0.to_string()).await
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        self.table.list_owned(user_id).await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.table.delete(&id.0.to_string()).await.map(|_| ())
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        let except = except.map(|id| id.0.to_string());
        self.table.delete_owned(user_id, except.as_deref()).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.table.purge(now).await
    }
}
