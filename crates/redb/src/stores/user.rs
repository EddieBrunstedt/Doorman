//! redb-backed [`UserStore`].
//!
//! Users are the system of record, so this store reproduces the relational
//! guarantees a SQL backend gives for free:
//!
//! - **Duplicate id** — rejected: `create_user` checks the `users` table
//!   before inserting; the check and insert share a single write transaction
//!   (redb serializes writers), so they are effectively atomic.
//! - **Email uniqueness** — a dedicated `email_guard` table maps every in-use
//!   address to its owner. The same write transaction checks and writes the
//!   guard, so a concurrent attempt at the same address fails.
//! - **Email lookup** — `find_user_by_email` reads the guard to get the
//!   user id, then fetches the user record; both reads are in one read
//!   transaction for snapshot consistency.

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{User, UserId, UserStore};

use redb::{ReadableDatabase as _, ReadableTable as _};

use crate::db::{self, RedbHandle};

pub(crate) struct RedbUserStore {
    handle: RedbHandle,
}

impl RedbUserStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl UserStore for RedbUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let user_key = user.id.0.to_string();
            let encoded = db::encode(&user)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                if users.get(user_key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::msg("user id already exists"));
                }
                if let Some(email) = user.email.as_deref() {
                    if email_guard.get(email).map_err(db::err)?.is_some() {
                        return Err(StorageError::msg("email already in use"));
                    }
                    email_guard
                        .insert(email, user_key.as_str())
                        .map_err(db::err)?;
                }
                users
                    .insert(user_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let rtxn = db.begin_read().map_err(db::err)?;
            let table = rtxn.open_table(db::USERS).map_err(db::err)?;
            match table.get(key.as_str()).map_err(db::err)? {
                Some(guard) => Ok(Some(db::decode(guard.value())?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let email = email.to_owned();
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let rtxn = db.begin_read().map_err(db::err)?;
            // Look up the user id via the email guard.
            let user_id_str = {
                let guard_tbl = rtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;
                match guard_tbl.get(email.as_str()).map_err(db::err)? {
                    Some(guard) => guard.value().to_owned(),
                    None => return Ok(None),
                }
                // guard_tbl dropped here, releasing its borrow of rtxn.
            };
            // Now look up the user record using the same read transaction.
            let users_tbl = rtxn.open_table(db::USERS).map_err(db::err)?;
            match users_tbl.get(user_id_str.as_str()).map_err(db::err)? {
                Some(guard) => Ok(Some(db::decode(guard.value())?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(db::err)?
    }

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let user_key = user.id.0.to_string();
            let new_email = user.email.clone();
            let encoded = db::encode(&user)?;

            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                let old_email = {
                    let guard = users
                        .get(user_key.as_str())
                        .map_err(db::err)?
                        .ok_or_else(|| StorageError::msg("user not found"))?;
                    let current: User = db::decode(guard.value())?;
                    current.email
                };

                if old_email != new_email {
                    if let Some(old) = old_email.as_deref() {
                        email_guard.remove(old).map_err(db::err)?;
                    }
                    if let Some(new) = new_email.as_deref() {
                        if email_guard.get(new).map_err(db::err)?.is_some() {
                            return Err(StorageError::msg("email already in use"));
                        }
                        email_guard
                            .insert(new, user_key.as_str())
                            .map_err(db::err)?;
                    }
                }
                users
                    .insert(user_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let key = id.0.to_string();
            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                if let Some(guard) = users.remove(key.as_str()).map_err(db::err)? {
                    let user: User = db::decode(guard.value())?;
                    if let Some(email) = user.email.as_deref() {
                        email_guard.remove(email).map_err(db::err)?;
                    }
                }
            }
            wtxn.commit().map_err(db::err)?;
            Ok(())
        })
        .await
        .map_err(db::err)?
    }
}
