//! fjall-backed [`SessionStore`].
//!
//! Sessions span three partitions: the primary record (`sessions`), a
//! token-hash → session-id index (`session_hash_idx`), and a per-user
//! compound-key index (`user_sessions_idx`) whose keys have the form
//! `"{user_id}\x00{session_id}"`. All three are updated atomically inside a
//! single write transaction.
//!
//! There is no native TTL: every expiry is emulated by the `expires_at > now`
//! filter in `list_for_user` and the authoritative `purge_expired` sweep.

use crate::db::{self, FjallHandle};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

pub(crate) struct FjallSessionStore {
    handle: FjallHandle,
}

impl FjallSessionStore {
    pub(crate) fn new(handle: FjallHandle) -> Self {
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
impl SessionStore for FjallSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let session_key = session.id.0.to_string();
            let hash_key = db::token_hash_hex(&session.token_hash);
            let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
            let encoded = db::encode(&session)?;

            let mut tx = handle.db.write_tx();
            tx.insert(&handle.sessions, session_key.as_bytes(), encoded.as_slice());
            tx.insert(
                &handle.session_hash_idx,
                hash_key.as_bytes(),
                session_key.as_bytes(),
            );
            tx.insert(&handle.user_sessions_idx, user_idx_key.as_bytes(), b"");
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let hash_hex = db::token_hash_hex(hash);
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let session_id_bytes = match handle
                .session_hash_idx
                .get(hash_hex.as_bytes())
                .map_err(db::err)?
            {
                Some(b) => b,
                None => return Ok(None),
            };
            let session_key = std::str::from_utf8(&session_id_bytes).map_err(db::err)?;
            match handle
                .sessions
                .get(session_key.as_bytes())
                .map_err(db::err)?
            {
                Some(bytes) => Ok(Some(db::decode(&bytes)?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            match handle.sessions.get(key.as_bytes()).map_err(db::err)? {
                Some(bytes) => Ok(Some(db::decode(&bytes)?)),
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
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_sessions_prefix(user_id);
            let end = db::prefix_end(&prefix);

            // Collect session ids from the index.
            let session_ids: Vec<String> = {
                handle
                    .user_sessions_idx
                    .as_ref()
                    .range(prefix.as_bytes()..end.as_bytes())
                    .map(|guard| {
                        let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                        let key_str = std::str::from_utf8(&key_bytes).map_err(db::err)?.to_owned();
                        session_id_from_idx_key(&key_str).map(ToOwned::to_owned)
                    })
                    .collect::<StorageResult<_>>()?
            };

            let mut out = Vec::with_capacity(session_ids.len());
            for id in &session_ids {
                if let Some(bytes) = handle.sessions.get(id.as_bytes()).map_err(db::err)? {
                    let session: Session = db::decode(&bytes)?;
                    if session.expires_at > now {
                        out.push(session);
                    }
                }
            }
            Ok(out)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let mut tx = handle.db.write_tx();

            if let Some(bytes) = tx.take(&handle.sessions, key.as_bytes()).map_err(db::err)? {
                let session: Session = db::decode(&bytes)?;
                let hash_hex = db::token_hash_hex(&session.token_hash);
                let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
                tx.remove(&handle.session_hash_idx, hash_hex.as_bytes());
                tx.remove(&handle.user_sessions_idx, user_idx_key.as_bytes());
            }
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_sessions_prefix(user_id);
            let end = db::prefix_end(&prefix);

            // Collect index keys first (outside the write transaction).
            let idx_keys: Vec<String> = handle
                .user_sessions_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .map(|guard| {
                    let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                    std::str::from_utf8(&key_bytes)
                        .map(ToOwned::to_owned)
                        .map_err(db::err)
                })
                .collect::<StorageResult<_>>()?;

            if idx_keys.is_empty() {
                return Ok(0);
            }

            let mut tx = handle.db.write_tx();
            let mut count = 0u64;
            for idx_key in &idx_keys {
                let sid = session_id_from_idx_key(idx_key)?;
                if let Some(bytes) = tx.take(&handle.sessions, sid.as_bytes()).map_err(db::err)? {
                    let session: Session = db::decode(&bytes)?;
                    let hash_hex = db::token_hash_hex(&session.token_hash);
                    tx.remove(&handle.session_hash_idx, hash_hex.as_bytes());
                    count += 1;
                }
                tx.remove(&handle.user_sessions_idx, idx_key.as_bytes());
            }
            tx.commit().map_err(db::err)?;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_sessions_prefix(user_id);
            let end = db::prefix_end(&prefix);
            let except_key = except.0.to_string();

            let idx_keys: Vec<String> = handle
                .user_sessions_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .map(|guard| {
                    let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                    std::str::from_utf8(&key_bytes)
                        .map(ToOwned::to_owned)
                        .map_err(db::err)
                })
                .collect::<StorageResult<_>>()?;

            if idx_keys.is_empty() {
                return Ok(0);
            }

            let mut tx = handle.db.write_tx();
            let mut count = 0u64;
            for idx_key in &idx_keys {
                let sid = session_id_from_idx_key(idx_key)?;
                if sid == except_key.as_str() {
                    continue;
                }
                if let Some(bytes) = tx.take(&handle.sessions, sid.as_bytes()).map_err(db::err)? {
                    let session: Session = db::decode(&bytes)?;
                    let hash_hex = db::token_hash_hex(&session.token_hash);
                    tx.remove(&handle.session_hash_idx, hash_hex.as_bytes());
                    count += 1;
                }
                tx.remove(&handle.user_sessions_idx, idx_key.as_bytes());
            }
            tx.commit().map_err(db::err)?;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            // Read pass: find all expired sessions.
            let expired: Vec<(Vec<u8>, Session)> = handle
                .sessions
                .as_ref()
                .iter()
                .map(|guard| {
                    let (key, value) = guard.into_inner().map_err(db::err)?;
                    let session: Session = db::decode(&value)?;
                    Ok((key.to_vec(), session))
                })
                .filter(|r: &StorageResult<_>| {
                    r.as_ref().map_or(true, |(_, s)| s.expires_at <= now)
                })
                .collect::<StorageResult<_>>()?;

            if expired.is_empty() {
                return Ok(0);
            }

            // Write pass: delete each expired session and its index entries.
            let mut tx = handle.db.write_tx();
            let mut n = 0u64;
            for (key, session) in &expired {
                if tx
                    .take(&handle.sessions, key.as_slice())
                    .map_err(db::err)?
                    .is_some()
                {
                    let hash_hex = db::token_hash_hex(&session.token_hash);
                    let user_idx_key = db::user_sessions_idx_key(session.user_id, session.id);
                    tx.remove(&handle.session_hash_idx, hash_hex.as_bytes());
                    tx.remove(&handle.user_sessions_idx, user_idx_key.as_bytes());
                    n += 1;
                }
            }
            tx.commit().map_err(db::err)?;
            Ok(n)
        })
        .await
        .map_err(db::err)?
    }
}
