// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod db;
mod stores;

use std::path::Path;
use std::sync::Arc;

use doorman_core::error::StorageResult;
use doorman_core::storage::{
    EmailLinkStore, PasskeyChallengeStore, PasskeyStore, Session, SessionStore, Storage, UserStore,
};
use redb::{Database, WriteTransaction};

use crate::db::RedbHandle;

#[derive(Clone)]
pub struct RedbStorage {
    handle: RedbHandle,
}

impl RedbStorage {
    #[allow(clippy::result_large_err)]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        Self::from_database(db)
    }

    #[allow(clippy::result_large_err)]
    pub fn from_database(db: Database) -> Result<Self, redb::Error> {
        db::ensure_tables(&db)?;
        Ok(Self {
            handle: RedbHandle::new(Arc::new(db)),
        })
    }

    pub fn all_stores(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            email_links: self.email_link_store(),
            passkeys: self.passkey_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }

    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(stores::user::RedbUserStore::new(self.handle.clone()))
    }

    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::RedbSessionStore::new(self.handle.clone()))
    }

    pub fn email_link_store(&self) -> Arc<dyn EmailLinkStore> {
        Arc::new(stores::email_link::RedbEmailLinkStore::new(
            self.handle.clone(),
        ))
    }

    pub fn passkey_store(&self) -> Arc<dyn PasskeyStore> {
        Arc::new(stores::passkey::RedbPasskeyStore::new(self.handle.clone()))
    }

    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::RedbPasskeyChallengeStore::new(
            self.handle.clone(),
        ))
    }

    pub fn database(&self) -> Arc<Database> {
        self.handle.db()
    }
}

pub fn write_session(wtxn: &WriteTransaction, session: &Session) -> StorageResult<()> {
    db::write_session(wtxn, session)
}
