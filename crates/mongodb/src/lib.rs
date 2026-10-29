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
use doorman_core::storage::{ExpiringStores, RecordStores, Session, Storage};
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
            records: self.records(),
            expiring: self.expiring(),
        }
    }

    pub fn records(&self) -> RecordStores {
        RecordStores {
            users: Arc::new(stores::user::MongoUserStore::new(self.db.users())),
            passkeys: Arc::new(stores::passkey::MongoPasskeyStore::new(self.db.passkeys())),
        }
    }

    pub fn expiring(&self) -> ExpiringStores {
        ExpiringStores {
            sessions: Arc::new(stores::session::MongoSessionStore::new(self.db.sessions())),
            email_links: Arc::new(stores::email_link::MongoEmailLinkStore::new(
                self.db.email_links(),
            )),
            passkey_challenges: Arc::new(stores::passkey_chal::MongoPasskeyChallengeStore::new(
                self.db.passkey_registrations(),
                self.db.passkey_authentications(),
            )),
            dpop_proofs: Arc::new(stores::dpop_proof::MongoDpopProofStore::new(
                self.db.dpop_proofs(),
            )),
        }
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
