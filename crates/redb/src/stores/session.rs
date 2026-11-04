use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};
use redb::WriteTransaction;

use crate::db::{self, RedbHandle};
use crate::expiring::{Family, Reader, Row, Writer};

impl Row for Session {
    const FAMILY: Family = db::SESSIONS;

    fn key(&self) -> String {
        self.id.to_string()
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn owner(&self) -> Option<UserId> {
        Some(self.user_id)
    }

    fn lookup(&self) -> Option<String> {
        Some(db::token_hash_hex(&self.token_hash))
    }
}

pub(crate) fn write_session(wtxn: &WriteTransaction, session: &Session) -> StorageResult<()> {
    if Writer::open(wtxn)?.insert(session)? {
        Ok(())
    } else {
        Err(StorageError::conflict(
            "session id or token hash already exists",
        ))
    }
}

pub(crate) struct RedbSessionStore {
    handle: RedbHandle,
}

impl RedbSessionStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl SessionStore for RedbSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| write_session(wtxn, &session))
            .await
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let mut sessions = Writer::<Session>::open(wtxn)?;
                // Taken and written again, so its deadline entry moves with it.
                if let Some(mut session) = sessions.take(&id.to_string())? {
                    session.last_used_at = last_used_at;
                    session.expires_at = expires_at;
                    sessions.insert(&session)?;
                }
                Ok(())
            })
            .await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let lookup = db::token_hash_hex(hash);
        self.handle
            .read(move |rtxn| Reader::<Session>::open(rtxn)?.get_by(&lookup))
            .await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.handle
            .read(move |rtxn| Reader::<Session>::open(rtxn)?.get(&id.to_string()))
            .await
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        self.handle
            .read(move |rtxn| Reader::<Session>::open(rtxn)?.list_owned(user_id))
            .await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                Writer::<Session>::open(wtxn)?.remove(&id.to_string())?;
                Ok(())
            })
            .await
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let except = except.map(|id| id.to_string());
                Writer::<Session>::open(wtxn)?.remove_owned(user_id, except.as_deref())
            })
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| Writer::<Session>::open(wtxn)?.purge(now))
            .await
    }
}
