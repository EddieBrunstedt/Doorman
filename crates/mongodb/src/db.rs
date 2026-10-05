//! MongoDB connection handle, collection accessors, and index provisioning.
//!
//! The adapter uses **one collection per record kind**:
//!
//! | Collection              | `_id` scheme               | Notable indexes                          |
//! | ----------------------- | -------------------------- | ---------------------------------------- |
//! | `users`                 | UUID string                | Partial unique on `email`                |
//! | `sessions`              | UUID string                | Unique on `token_hash`; `user_id`; TTL   |
//! | `verification_tokens`   | `{purpose}#{hash hex}`     | `(user_id, purpose)`; TTL                |
//! | `passkey_credentials`   | credential-id hex string   | `user_id`                                |
//! | `passkey_registrations` | UUID string                | `user_id`; TTL                           |
//! | `passkey_authentications` | UUID string              | TTL                                      |
//!
//! TTL indexes are created on a separate `ttl` field that is only written when
//! `expires_at` is in the wall-clock future. This mirrors the Redis `PEXPIREAT`
//! gate and the DynamoDB `ttl` gate: the conformance suite's fixed past-dated
//! test fixtures exercise the read-filter/purge path rather than being swept
//! by the TTL monitor, which runs every ~60 s.

use std::time::Duration;

use doorman_core::error::{StorageError, StorageResult};
use mongodb::bson::doc;
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};

/// BSON document type alias for `Collection<Document>`.
pub(crate) type Coll = Collection<mongodb::bson::Document>;

/// The server's error code for a write that breaks a unique index.
const DUPLICATE_KEY: i32 = 11000;

/// Map a MongoDB driver error to a [`StorageError`], reporting a write that
/// breaks a unique index (`_id` or the partial `email` index) as
/// [`StorageErrorKind::Conflict`](doorman_core::error::StorageErrorKind::Conflict).
pub(crate) fn err(e: mongodb::error::Error) -> StorageError {
    match e.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(write)) if write.code == DUPLICATE_KEY => {
            StorageError::conflict(e.to_string())
        }
        _ => StorageError::new(e),
    }
}

/// A cloneable handle to a MongoDB database.
///
/// Cloning is cheap — `Database` is internally reference-counted.
#[derive(Clone)]
pub(crate) struct MongoDb {
    db: Database,
}

impl MongoDb {
    pub(crate) fn new(db: Database) -> Self {
        Self { db }
    }

    pub(crate) fn users(&self) -> Coll {
        self.db.collection("users")
    }

    pub(crate) fn sessions(&self) -> Coll {
        self.db.collection("sessions")
    }

    pub(crate) fn verification_tokens(&self) -> Coll {
        self.db.collection("verification_tokens")
    }

    pub(crate) fn passkey_credentials(&self) -> Coll {
        self.db.collection("passkey_credentials")
    }

    pub(crate) fn passkey_registrations(&self) -> Coll {
        self.db.collection("passkey_registrations")
    }

    pub(crate) fn passkey_authentications(&self) -> Coll {
        self.db.collection("passkey_authentications")
    }

    /// Provision all collection indexes idempotently.
    ///
    /// MongoDB's `createIndex` is a no-op when the index already exists with
    /// the same definition, so this is safe to call on every boot.
    pub(crate) async fn ensure_indexes(&self) -> StorageResult<()> {
        self.ensure_user_indexes().await?;
        self.ensure_session_indexes().await?;
        self.ensure_vtoken_indexes().await?;
        self.ensure_passkey_cred_indexes().await?;
        self.ensure_pkreg_indexes().await?;
        self.ensure_pkauth_indexes().await?;
        Ok(())
    }

    async fn ensure_user_indexes(&self) -> StorageResult<()> {
        // Partial unique index on `email`: multiple users may have no email
        // (email-less accounts) without triggering the uniqueness constraint,
        // while two users with the same non-null email are rejected.
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
                // Unique index for the by-token-hash lookup (the hot per-request path).
                IndexModel::builder()
                    .keys(doc! { "token_hash": 1 })
                    .options(
                        IndexOptions::builder()
                            .unique(true)
                            .name("idx_sessions_token_hash".to_string())
                            .build(),
                    )
                    .build(),
                // Index for per-user listing and bulk-delete.
                IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_sessions_user_id".to_string())
                            .build(),
                    )
                    .build(),
                // TTL index: the `ttl` field is only written for future expiries
                // (see `model::ttl_bson`), so past-dated fixtures are unaffected.
                IndexModel::builder()
                    .keys(doc! { "ttl": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_sessions_ttl".to_string())
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            ])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_vtoken_indexes(&self) -> StorageResult<()> {
        self.verification_tokens()
            .create_indexes(vec![
                // Compound index for `delete_tokens_for_user(user_id, purpose)`.
                IndexModel::builder()
                    .keys(doc! { "user_id": 1, "purpose": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_vtokens_user_purpose".to_string())
                            .build(),
                    )
                    .build(),
                // TTL index (gated field, same rationale as sessions).
                IndexModel::builder()
                    .keys(doc! { "ttl": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_vtokens_ttl".to_string())
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            ])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn ensure_passkey_cred_indexes(&self) -> StorageResult<()> {
        // Index for per-user listing.
        self.passkey_credentials()
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
                // Index for per-user count and bulk-delete.
                IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_pkreg_user_id".to_string())
                            .build(),
                    )
                    .build(),
                // TTL index (gated field).
                IndexModel::builder()
                    .keys(doc! { "ttl": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_pkreg_ttl".to_string())
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
        // TTL index only — authentication ceremonies are not user-scoped and
        // are reached by _id alone; only purge_expired and the TTL monitor
        // need to scan them.
        self.passkey_authentications()
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "ttl": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("idx_pkauth_ttl".to_string())
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
