//! redb-backed [`SessionStore`].
//!
//! Sessions span three tables: the primary record (`sessions`), a
//! token-hash → session-id index (`session_hash_idx`), and a per-user
//! compound-key index (`user_sessions_idx`) whose keys have the form
//! `"{user_id}\x00{session_id}"`. All three are updated atomically inside a
//! single write transaction.
//!
//! There is no native TTL: every expiry is emulated by the `expires_at > now`
//! filter in `list_for_user` and the authoritative `purge_expired` sweep.

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

/// Extract the session-id component from a `user_sessions_idx` key of the
/// form `"{user_id}\x00{session_id}"`.
fn session_id_from_idx_key(key: &str) -> StorageResult<&str> {
    key.splitn(2, '\x00')
        .nth(1)
        .ok_or_else(|| StorageError::msg("malformed user_sessions_idx key"))
}

#[async_trait]
impl SessionStore for RedbSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let session_key = session.id.0.to_string();
            let hash_key = db::token_hash_hex(&session.token_hash);
            let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
            let encoded = db::encode(&session)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut sessions = wtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let mut hash_idx = wtxn.open_table(db::SESSION_HASH_IDX).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_SESSIONS_IDX).map_err(db::err)?;

                sessions
                    .insert(session_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                hash_idx
                    .insert(hash_key.as_str(), session_key.as_str())
                    .map_err(db::err)?;
                user_idx
                    .insert(user_idx_key.as_str(), ())
                    .map_err(db::err)?;
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let hash_hex = db::token_hash_hex(hash);
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let rtxn = db.begin_read().map_err(db::err)?;
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
        .map_err(db::err)?
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let rtxn = db.begin_read().map_err(db::err)?;
            let sessions = rtxn.open_table(db::SESSIONS).map_err(db::err)?;
            match sessions.get(key.as_str()).map_err(db::err)? {
                Some(guard) => Ok(Some(db::decode(guard.value())?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_sessions_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let rtxn = db.begin_read().map_err(db::err)?;
            // Collect session ids from the index.
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
                    // expired or missing: skip (dangling index entry)
                }
            }
            Ok(out)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let wtxn = db.begin_write().map_err(db::err)?;
            {
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
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_sessions_prefix(user_id);
            let end = db::prefix_end(&prefix);

            let wtxn = db.begin_write().map_err(db::err)?;
            let removed = {
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
                    if let Some(guard) = sessions.remove(sid).map_err(db::err)? {
                        let session: Session = db::decode(guard.value())?;
                        let hash_hex = db::token_hash_hex(&session.token_hash);
                        hash_idx.remove(hash_hex.as_str()).map_err(db::err)?;
                        count += 1;
                    }
                    user_idx.remove(idx_key.as_str()).map_err(db::err)?;
                }
                count
            };
            wtxn.commit().map_err(db::err)?;
            Ok(removed)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_sessions_prefix(user_id);
            let end = db::prefix_end(&prefix);
            let except_key = except.0.to_string();

            let wtxn = db.begin_write().map_err(db::err)?;
            let removed = {
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
                    if sid == except_key.as_str() {
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
                count
            };
            wtxn.commit().map_err(db::err)?;
            Ok(removed)
        })
        .await
        .map_err(db::err)?
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            // Read pass: find all expired sessions.
            let expired: Vec<(String, Session)> = {
                let rtxn = db.begin_read().map_err(db::err)?;
                let sessions_tbl = rtxn.open_table(db::SESSIONS).map_err(db::err)?;
                sessions_tbl
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
                    .collect::<StorageResult<_>>()?
            };

            if expired.is_empty() {
                return Ok(0);
            }

            // Write pass: delete each expired session and its index entries.
            let wtxn = db.begin_write().map_err(db::err)?;
            let count = {
                let mut sessions = wtxn.open_table(db::SESSIONS).map_err(db::err)?;
                let mut hash_idx = wtxn.open_table(db::SESSION_HASH_IDX).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_SESSIONS_IDX).map_err(db::err)?;

                let mut n = 0u64;
                for (key, session) in &expired {
                    if sessions.remove(key.as_str()).map_err(db::err)?.is_some() {
                        let hash_hex = db::token_hash_hex(&session.token_hash);
                        let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
                        hash_idx.remove(hash_hex.as_str()).map_err(db::err)?;
                        user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                        n += 1;
                    }
                }
                n
            };
            wtxn.commit().map_err(db::err)?;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }
}
