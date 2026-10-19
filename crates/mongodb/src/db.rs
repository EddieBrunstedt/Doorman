use std::time::Duration;

use doorman_core::error::{StorageError, StorageResult};
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
    pub(crate) fn new(db: Database) -> Self {
        Self { db }
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

    pub(crate) async fn ensure_indexes(&self) -> StorageResult<()> {
        self.ensure_user_indexes().await?;
        self.ensure_session_indexes().await?;
        self.ensure_email_link_indexes().await?;
        self.ensure_passkey_indexes().await?;
        self.ensure_pkreg_indexes().await?;
        self.ensure_pkauth_indexes().await?;
        Ok(())
    }

    async fn ensure_user_indexes(&self) -> StorageResult<()> {
        self.users()
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "email": 1 })
                    .options(
                        IndexOptions::builder()
                            .unique(true)
                            .name("idx_users_email".to_string())
                            .partial_filter_expression(doc! { "email": { "$type": "string" } })
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_session_indexes(&self) -> StorageResult<()> {
        self.sessions()
            .create_indexes(vec![
                IndexModel::builder()
                    .keys(doc! { "token_hash": 1 })
                    .options(
                        IndexOptions::builder()
                            .unique(true)
                            .name("idx_sessions_token_hash".to_string())
                            .build(),
                    )
                    .build(),
                IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_sessions_user_id".to_string())
                            .build(),
                    )
                    .build(),
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_sessions_expires_at".to_string())
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            ])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_email_link_indexes(&self) -> StorageResult<()> {
        self.email_links()
            .create_indexes(vec![
                IndexModel::builder()
                    .keys(doc! { "token_hash": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_email_links_token_hash".to_string())
                            .unique(true)
                            .build(),
                    )
                    .build(),
                IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_email_links_user_id".to_string())
                            .build(),
                    )
                    .build(),
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_email_links_expires_at".to_string())
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            ])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_passkey_indexes(&self) -> StorageResult<()> {
        self.passkeys()
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_passkey_creds_user_id".to_string())
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_pkreg_indexes(&self) -> StorageResult<()> {
        self.passkey_registrations()
            .create_indexes(vec![
                IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_pkreg_user_id".to_string())
                            .build(),
                    )
                    .build(),
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_pkreg_expires_at".to_string())
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            ])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_pkauth_indexes(&self) -> StorageResult<()> {
        self.passkey_authentications()
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_pkauth_expires_at".to_string())
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(err)?;
        Ok(())
    }
}
