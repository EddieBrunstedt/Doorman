use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

pub(crate) struct RedbSessionStore {
    handle: RedbHandle,
}

impl RedbSessionStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

fn session_id_from_idx_key(key: &str) -> StorageResult<&str> {
    key.split_once('\x00')
        .map(|x| x.1)
        .ok_or_else(|| StorageError::msg("malformed user_sessions_idx key"))
}

#[async_trait]
impl SessionStore for RedbSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                db::write_session(wtxn, &session)?;
                Ok(())
            })
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
                let key = id.0.to_string();
                let mut sessions = wtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let existing = match sessions.get(key.as_str()).map_err(db::err)? {
                    Some(guard) => Some(db::decode::<Session>(guard.value())?),
                    None => None,
                };
                if let Some(mut existing) = existing {
                    existing.last_used_at = last_used_at;
                    existing.expires_at = expires_at;
                    let bytes = db::encode(&existing)?;
                    sessions
                        .insert(key.as_str(), bytes.as_slice())
                        .map_err(db::err)?;
                }
                Ok(())
            })
            .await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let hash_hex = db::token_hash_hex(hash);
        self.handle
            .read(move |rtxn| {
                let session_key = {
                    let hash_tbl = rtxn.open_table(db::SESSION_HASH_IDX).map_err(db::err)?;
                    match hash_tbl.get(hash_hex.as_str()).map_err(db::err)? {
                        Some(guard) => guard.value().to_owned(),
                        None => return Ok(None),
                    }
                };
                let sessions = rtxn.open_table(db::SESSIONS).map_err(db::err)?;
                match sessions.get(session_key.as_str()).map_err(db::err)? {
                    Some(guard) => Ok(Some(db::decode(guard.value())?)),
                    None => Ok(None),
                }
            })
            .await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.handle
            .read(move |rtxn| {
                let key = id.0.to_string();
                let sessions = rtxn.open_table(db::SESSIONS).map_err(db::err)?;
                match sessions.get(key.as_str()).map_err(db::err)? {
                    Some(guard) => Ok(Some(db::decode(guard.value())?)),
                    None => Ok(None),
                }
            })
            .await
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        self.handle
            .read(move |rtxn| {
                let prefix = db::user_sessions_prefix(user_id);
                let end = db::prefix_end(&prefix);

                let session_ids: Vec<String> = {
                    let idx_tbl = rtxn.open_table(db::USER_SESSIONS_IDX).map_err(db::err)?;
                    idx_tbl
                        .range(prefix.as_str()..end.as_str())
                        .map_err(db::err)?
                        .map(|r| {
                            r.map_err(db::err).and_then(|(k, _)| {
                                session_id_from_idx_key(k.value()).map(ToOwned::to_owned)
                            })
                        })
                        .collect::<StorageResult<Vec<_>>>()?
                };

                let sessions_tbl = rtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let mut out = Vec::with_capacity(session_ids.len());
                for id in &session_ids {
                    if let Some(guard) = sessions_tbl.get(id.as_str()).map_err(db::err)? {
                        let session: Session = db::decode(guard.value())?;
                        if session.expires_at > now {
                            out.push(session);
                        }
                    }
                }
                Ok(out)
            })
            .await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let key = id.0.to_string();
                let mut sessions = wtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let mut hash_idx = wtxn.open_table(db::SESSION_HASH_IDX).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_SESSIONS_IDX).map_err(db::err)?;

                if let Some(guard) = sessions.remove(key.as_str()).map_err(db::err)? {
                    let session: Session = db::decode(guard.value())?;
                    let hash_hex = db::token_hash_hex(&session.token_hash);
                    let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
                    hash_idx.remove(hash_hex.as_str()).map_err(db::err)?;
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
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
                let prefix = db::user_sessions_prefix(user_id);
                let end = db::prefix_end(&prefix);
                let except_key = except.map(|id| id.0.to_string());

                let mut sessions = wtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let mut hash_idx = wtxn.open_table(db::SESSION_HASH_IDX).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_SESSIONS_IDX).map_err(db::err)?;

                let idx_keys: Vec<String> = {
                    user_idx
                        .range(prefix.as_str()..end.as_str())
                        .map_err(db::err)?
                        .map(|r| r.map_err(db::err).map(|(k, _)| k.value().to_owned()))
                        .collect::<StorageResult<_>>()?
                };

                let mut count = 0u64;
                for idx_key in &idx_keys {
                    let sid = session_id_from_idx_key(idx_key)?;
                    if except_key.as_deref() == Some(sid) {
                        continue;
                    }
                    if let Some(guard) = sessions.remove(sid).map_err(db::err)? {
                        let session: Session = db::decode(guard.value())?;
                        let hash_hex = db::token_hash_hex(&session.token_hash);
                        hash_idx.remove(hash_hex.as_str()).map_err(db::err)?;
                        count += 1;
                    }
                    user_idx.remove(idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut sessions = wtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let mut hash_idx = wtxn.open_table(db::SESSION_HASH_IDX).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_SESSIONS_IDX).map_err(db::err)?;

                let expired: Vec<(String, Session)> = sessions
                    .iter()
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, v)| {
                            let key = k.value().to_owned();
                            let s = db::decode::<Session>(v.value())?;
                            Ok((key, s))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, s)| s.expires_at <= now))
                    .collect::<StorageResult<_>>()?;

                for (key, session) in &expired {
                    sessions.remove(key.as_str()).map_err(db::err)?;
                    let hash_hex = db::token_hash_hex(&session.token_hash);
                    let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
                    hash_idx.remove(hash_hex.as_str()).map_err(db::err)?;
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(expired.len() as u64)
            })
            .await
    }
}
