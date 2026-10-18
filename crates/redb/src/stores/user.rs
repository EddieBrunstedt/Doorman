use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{User, UserId, UserStatus, UserStore};

use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

pub(crate) struct RedbUserStore {
    handle: RedbHandle,
}

impl RedbUserStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }

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
        self.handle
            .write(move |wtxn| {
                let user_key = id.0.to_string();
                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                let mut user: User = {
                    let guard = users
                        .get(user_key.as_str())
                        .map_err(db::err)?
                        .ok_or_else(|| StorageError::not_found("user not found"))?;
                    db::decode(guard.value())?
                };
                change(&mut user, &mut email_guard)?;
                let encoded = db::encode(&user)?;
                users
                    .insert(user_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl UserStore for RedbUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let user_key = user.id.0.to_string();
                let encoded = db::encode(&user)?;

                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                if users.get(user_key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::conflict("user id already exists"));
                }
                if let Some(email) = user.email.as_deref() {
                    if email_guard.get(email).map_err(db::err)?.is_some() {
                        return Err(StorageError::conflict("email already in use"));
                    }
                    email_guard
                        .insert(email, user_key.as_str())
                        .map_err(db::err)?;
                }
                users
                    .insert(user_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        self.handle
            .read(move |rtxn| {
                let key = id.0.to_string();
                let table = rtxn.open_table(db::USERS).map_err(db::err)?;
                match table.get(key.as_str()).map_err(db::err)? {
                    Some(guard) => Ok(Some(db::decode(guard.value())?)),
                    None => Ok(None),
                }
            })
            .await
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let email = email.to_owned();
        self.handle
            .read(move |rtxn| {
                let user_id_str = {
                    let guard_tbl = rtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;
                    match guard_tbl.get(email.as_str()).map_err(db::err)? {
                        Some(guard) => guard.value().to_owned(),
                        None => return Ok(None),
                    }
                };
                let users_tbl = rtxn.open_table(db::USERS).map_err(db::err)?;
                match users_tbl.get(user_id_str.as_str()).map_err(db::err)? {
                    Some(guard) => Ok(Some(db::decode(guard.value())?)),
                    None => Ok(None),
                }
            })
            .await
    }

    async fn set_user_status(
        &self,
        id: UserId,
        status: UserStatus,
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
                return Err(StorageError::conflict("email already in use"));
            }
            if let Some(old) = user.email.as_deref() {
                email_guard.remove(old).map_err(db::err)?;
            }
            email_guard
                .insert(email.as_str(), user_key.as_str())
                .map_err(db::err)?;
            user.email = Some(email);
            user.updated_at = at;
            Ok(())
        })
        .await
    }

    async fn mark_signed_up(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        self.modify(id, move |user, _| {
            user.signed_up_at = Some(at);
            user.updated_at = at;
            Ok(())
        })
        .await
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let key = id.0.to_string();
                let mut users = wtxn.open_table(db::USERS).map_err(db::err)?;
                let mut email_guard = wtxn.open_table(db::EMAIL_GUARD).map_err(db::err)?;

                if let Some(guard) = users.remove(key.as_str()).map_err(db::err)? {
                    let user: User = db::decode(guard.value())?;
                    if let Some(email) = user.email.as_deref() {
                        email_guard.remove(email).map_err(db::err)?;
                    }
                }
                Ok(())
            })
            .await
    }
}
