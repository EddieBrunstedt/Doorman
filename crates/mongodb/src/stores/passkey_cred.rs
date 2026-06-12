//! MongoDB-backed [`PasskeyCredentialStore`].
//!
//! One document per credential, keyed by the hex-encoded credential id as
//! `_id`. The raw credential id bytes are also stored in a `credential_id`
//! field so they round-trip exactly without re-parsing the hex. A `user_id`
//! index backs the per-user listing paths.
//!
//! - `add_passkey` → `insert_one` with unique `_id`: a duplicate credential
//!   id is rejected by the default `_id` uniqueness constraint.
//! - `update_passkey` → `replace_one` matched by `_id`: `matched_count == 0`
//!   surfaces "not found".
//! - `list_passkey_summaries_for_user` projects to [`PasskeySummary`] values
//!   without reading the `passkey` blob, satisfying the "no blob deserialisation
//!   on the listing path" contract.

use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{PasskeyCredentialStore, PasskeySummary, StoredPasskey, UserId};
use mongodb::bson::doc;

use crate::db::{Coll, err};
use crate::model::{self, passkey_id};

/// Passkey-credential store backed by a MongoDB collection.
pub(crate) struct MongoPasskeyCredentialStore {
    coll: Coll,
}

impl MongoPasskeyCredentialStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }
}

#[async_trait]
impl PasskeyCredentialStore for MongoPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        self.coll
            .insert_one(model::passkey_to_doc(&credential))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let filter = doc! { "_id": passkey_id(&credential.credential_id) };
        let replacement = model::passkey_to_doc(&credential);
        let result = self
            .coll
            .replace_one(filter, replacement)
            .await
            .map_err(err)?;
        if result.matched_count == 0 {
            return Err(StorageError::msg("passkey credential not found"));
        }
        Ok(())
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        let filter = doc! { "user_id": user_id.0.to_string() };
        let mut cursor = self.coll.find(filter).await.map_err(err)?;
        let mut out = Vec::new();
        while cursor.advance().await.map_err(err)? {
            out.push(model::passkey_from_doc(
                &cursor.deserialize_current().map_err(err)?,
            )?);
        }
        Ok(out)
    }

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        let filter = doc! { "user_id": user_id.0.to_string() };
        let mut cursor = self.coll.find(filter).await.map_err(err)?;
        let mut out = Vec::new();
        while cursor.advance().await.map_err(err)? {
            out.push(model::passkey_summary_from_doc(
                &cursor.deserialize_current().map_err(err)?,
            )?);
        }
        Ok(out)
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let filter = doc! { "_id": passkey_id(credential_id) };
        match self.coll.find_one(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::passkey_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        let filter = doc! { "_id": passkey_id(credential_id) };
        self.coll.delete_one(filter).await.map_err(err)?;
        Ok(())
    }
}
