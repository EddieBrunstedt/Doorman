use std::time::Duration;

use doorman_core::error::StorageError;
use mongodb::bson::doc;
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::options::{
    Acknowledgment, CollectionOptions, IndexOptions, ReadConcern, ReadPreference,
    SelectionCriteria, WriteConcern,
};
use mongodb::{Collection, Database, IndexModel};

pub(crate) type Coll = Collection<mongodb::bson::Document>;

const DUPLICATE_KEY: i32 = 11000;

pub(crate) fn err(e: mongodb::error::Error) -> StorageError {
    match e.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(write)) if write.code == DUPLICATE_KEY => {
            StorageError::conflict(e.to_string())
        }
        _ => StorageError::new(e),
    }
}

#[derive(Clone)]
pub(crate) struct MongoDb {
    db: Database,
}

impl MongoDb {
    // The unique indexes are what refuse a second user with one email, or a second session or
    // email link with one token hash, so no store exists until every index does.
    pub(crate) async fn open(db: Database) -> mongodb::error::Result<Self> {
        let db = Self { db };
        db.build_indexes().await?;
        Ok(db)
    }

    // Core refuses a login to a disabled user, and a request to a revoked session, only if every
    // read sees every write that finished before it, from any process. The host's client may
    // prefer secondaries or acknowledge unreplicated writes, so every collection overrides both.
    fn collection(&self, name: &str) -> Coll {
        self.db.collection_with_options(
            name,
            CollectionOptions::builder()
                .selection_criteria(SelectionCriteria::ReadPreference(ReadPreference::Primary))
                .read_concern(ReadConcern::majority())
                .write_concern(
                    WriteConcern::builder()
                        .w(Acknowledgment::Majority)
                        .journal(true)
                        .build(),
                )
                .build(),
        )
    }

    pub(crate) fn users(&self) -> Coll {
        self.collection("users")
    }

    pub(crate) fn sessions(&self) -> Coll {
        self.collection("sessions")
    }

    pub(crate) fn email_links(&self) -> Coll {
        self.collection("email_links")
    }

    pub(crate) fn passkeys(&self) -> Coll {
        self.collection("passkeys")
    }

    pub(crate) fn passkey_registrations(&self) -> Coll {
        self.collection("passkey_registrations")
    }

    pub(crate) fn passkey_authentications(&self) -> Coll {
        self.collection("passkey_authentications")
    }

    pub(crate) fn dpop_proofs(&self) -> Coll {
        self.collection("dpop_proofs")
    }

    // Creating an index that already exists with the same options does nothing, so every
    // process that opens the database runs this; one whose options changed fails it.
    async fn build_indexes(&self) -> mongodb::error::Result<()> {
        let collections = [
            (
                self.users(),
                vec![
                    // Users who haven't given an email hold none, and any number of them may.
                    IndexModel::builder()
                        .keys(doc! { "email": 1 })
                        .options(
                            IndexOptions::builder()
                                .name("idx_users_email".to_string())
                                .unique(true)
                                .partial_filter_expression(doc! { "email": { "$type": "string" } })
                                .build(),
                        )
                        .build(),
                ],
            ),
            (
                self.sessions(),
                vec![
                    unique("idx_sessions_token_hash", "token_hash"),
                    lookup("idx_sessions_user_id", "user_id"),
                    expiry("idx_sessions_expires_at"),
                ],
            ),
            (
                self.email_links(),
                vec![
                    unique("idx_email_links_token_hash", "token_hash"),
                    lookup("idx_email_links_user_id", "user_id"),
                    expiry("idx_email_links_expires_at"),
                ],
            ),
            (
                self.passkeys(),
                vec![lookup("idx_passkey_creds_user_id", "user_id")],
            ),
            (
                self.passkey_registrations(),
                vec![
                    lookup("idx_pkreg_user_id", "user_id"),
                    expiry("idx_pkreg_expires_at"),
                ],
            ),
            (
                self.passkey_authentications(),
                vec![expiry("idx_pkauth_expires_at")],
            ),
            (
                self.dpop_proofs(),
                vec![expiry("idx_dpop_proofs_expires_at")],
            ),
        ];
        for (collection, indexes) in collections {
            collection.create_indexes(indexes).await?;
        }
        Ok(())
    }
}

fn index(name: &str, field: &str, mut options: IndexOptions) -> IndexModel {
    options.name = Some(name.to_string());
    IndexModel::builder()
        .keys(doc! { field: 1 })
        .options(options)
        .build()
}

fn lookup(name: &str, field: &str) -> IndexModel {
    index(name, field, IndexOptions::default())
}

fn unique(name: &str, field: &str) -> IndexModel {
    index(name, field, IndexOptions::builder().unique(true).build())
}

fn expiry(name: &str) -> IndexModel {
    index(
        name,
        "expires_at",
        IndexOptions::builder().expire_after(Duration::ZERO).build(),
    )
}
