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
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{AccountStatus, User, UserId, UserStore};

use redb::{ReadableDatabase as _, ReadableTable as _};

use crate::db::{self, RedbHandle};

pub(crate) struct RedbUserStore {
    handle: RedbHandle,
}

impl RedbUserStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }

    /// Read the user, apply `change`, and write it back in one write
    /// transaction. redb serializes writers, so no other change can land
    /// between the read and the write. `change` also gets the email guard
    /// table, for the one change that moves the user's address.
    async fn modify(
        &self,
        id: UserId,
        change: impl FnOnce(
            &mut User,
            &mut redb::Table<'_, &'static str, &'static str>,
        ) -> StorageResult<()>
        + Send
        + 'static,
    ) -> StorageResult<()> {
        let db = self.handle.db();
        tokio::task::spawn_blocking(move || {
            let user_key = id.0.to_string();
            let wtxn = db.begin_write().map_err(db::err)?;
            {
                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                let mut user: User = {
                    let guard = users
                        .get(user_key.as_str())
                        .map_err(db::err)?
                        .ok_or_else(|| StorageError::msg("user not found"))?;
                    db::decode(guard.value())?
                };
                change(&mut user, &mut email_guard)?;
                let encoded = db::encode(&user)?;
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

    async fn set_user_status(
        &self,
        id: UserId,
        status: AccountStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.modify(id, move |user, _| {
            user.status = status;
            user.updated_at = at;
            Ok(())
        })
        .await
    }

    async fn set_user_email(
        &self,
        id: UserId,
        email: &str,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let email = email.to_owned();
        let user_key = id.0.to_string();
        self.modify(id, move |user, email_guard| {
            if let Some(owner) = email_guard.get(email.as_str()).map_err(db::err)?
                && owner.value() != user_key
            {
                return Err(StorageError::msg("email already in use"));
            }
            if let Some(old) = user.email.as_deref() {
                email_guard.remove(old).map_err(db::err)?;
            }
            email_guard
                .insert(email.as_str(), user_key.as_str())
                .map_err(db::err)?;
            user.email = Some(email);
            user.email_verified_at = Some(at);
            user.updated_at = at;
            Ok(())
        })
        .await
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        self.modify(id, move |user, _| {
            user.email_verified_at = Some(at);
            user.updated_at = at;
            Ok(())
        })
        .await
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
