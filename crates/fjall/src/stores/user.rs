//! fjall-backed [`UserStore`].
//!
//! Users are the system of record, so this store reproduces the relational
//! guarantees a SQL backend gives for free:
//!
//! - **Duplicate id** — rejected: `create_user` checks the `users` partition
//!   before inserting; the check and insert share a single write transaction
//!   (fjall serializes writers), so they are effectively atomic.
//! - **Email uniqueness** — a dedicated `email_guard` partition maps every
//!   in-use address to its owner. The same write transaction checks and writes
//!   the guard, so a concurrent attempt at the same address fails.
//! - **Email lookup** — `find_user_by_email` reads the guard to get the user
//!   id, then fetches the user record.

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{User, UserId, UserStore};
use fjall::Readable as _;

use crate::db::{self, FjallHandle};

pub(crate) struct FjallUserStore {
    handle: FjallHandle,
}

impl FjallUserStore {
    pub(crate) fn new(handle: FjallHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl UserStore for FjallUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let user_key = user.id.0.to_string();
            let encoded = db::encode(&user)?;

            let mut tx = handle.db.write_tx();

            if tx
                .get(&handle.users, user_key.as_bytes())
                .map_err(db::err)?
                .is_some()
            {
                return Err(StorageError::msg("user id already exists"));
            }
            if let Some(email) = user.email.as_deref() {
                if tx
                    .get(&handle.email_guard, email.as_bytes())
                    .map_err(db::err)?
                    .is_some()
                {
                    return Err(StorageError::msg("email already in use"));
                }
                tx.insert(&handle.email_guard, email.as_bytes(), user_key.as_bytes());
            }
            tx.insert(&handle.users, user_key.as_bytes(), encoded.as_slice());
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            match handle.users.get(key.as_bytes()).map_err(db::err)? {
                Some(bytes) => Ok(Some(db::decode(&bytes)?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let email = email.to_owned();
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let user_id_bytes = match handle.email_guard.get(email.as_bytes()).map_err(db::err)? {
                Some(b) => b,
                None => return Ok(None),
            };
            let user_key = std::str::from_utf8(&user_id_bytes).map_err(db::err)?;
            match handle.users.get(user_key.as_bytes()).map_err(db::err)? {
                Some(bytes) => Ok(Some(db::decode(&bytes)?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let user_key = user.id.0.to_string();
            let new_email = user.email.clone();
            let encoded = db::encode(&user)?;

            let mut tx = handle.db.write_tx();

            let old_email = {
                let bytes = tx
                    .get(&handle.users, user_key.as_bytes())
                    .map_err(db::err)?
                    .ok_or_else(|| StorageError::msg("user not found"))?;
                let current: User = db::decode(&bytes)?;
                current.email
            };

            if old_email != new_email {
                if let Some(old) = old_email.as_deref() {
                    tx.remove(&handle.email_guard, old.as_bytes());
                }
                if let Some(new) = new_email.as_deref() {
                    if tx
                        .get(&handle.email_guard, new.as_bytes())
                        .map_err(db::err)?
                        .is_some()
                    {
                        return Err(StorageError::msg("email already in use"));
                    }
                    tx.insert(&handle.email_guard, new.as_bytes(), user_key.as_bytes());
                }
            }
            tx.insert(&handle.users, user_key.as_bytes(), encoded.as_slice());
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let mut tx = handle.db.write_tx();

            if let Some(bytes) = tx.take(&handle.users, key.as_bytes()).map_err(db::err)? {
                let user: User = db::decode(&bytes)?;
                if let Some(email) = user.email.as_deref() {
                    tx.remove(&handle.email_guard, email.as_bytes());
                }
            }
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }
}
