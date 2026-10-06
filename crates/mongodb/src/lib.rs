// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod db;
mod model;
mod stores;

use std::sync::Arc;

use doorman_core::error::StorageResult;
use doorman_core::storage::{
    EmailLinkStore, PasskeyChallengeStore, PasskeyStore, Session, SessionStore, Storage, UserStore,
};
use mongodb::Collection;
use mongodb::bson::Document;

use crate::db::MongoDb;

#[derive(Clone)]
pub struct MongoDbStorage {
    db: MongoDb,
}

impl MongoDbStorage {
    pub fn new(database: mongodb::Database) -> Self {
        Self {
            db: MongoDb::new(database),
        }
    }

    pub async fn ensure_indexes(&self) -> StorageResult<()> {
        self.db.ensure_indexes().await
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
        Arc::new(stores::user::MongoUserStore::new(self.db.users()))
    }

    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::MongoSessionStore::new(self.db.sessions()))
    }

    pub fn email_link_store(&self) -> Arc<dyn EmailLinkStore> {
        Arc::new(stores::email_link::MongoEmailLinkStore::new(
            self.db.email_links(),
        ))
    }

    pub fn passkey_store(&self) -> Arc<dyn PasskeyStore> {
        Arc::new(stores::passkey::MongoPasskeyStore::new(self.db.passkeys()))
    }

    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::MongoPasskeyChallengeStore::new(
            self.db.passkey_registrations(),
            self.db.passkey_authentications(),
        ))
    }

    pub fn sessions_collection(&self) -> Collection<Document> {
        self.db.sessions()
    }
}

pub fn session_to_document(session: &Session) -> Document {
    model::session_to_doc(session)
}

pub fn session_from_document(doc: &Document) -> StorageResult<Session> {
    model::session_from_doc(doc)
}
