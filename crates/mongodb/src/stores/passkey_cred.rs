use async_trait::async_trait;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyCredentialStore, PasskeySummary, PasskeyUse, StoredPasskey, UserId,
};
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, Document, doc};

use crate::db::{Coll, err};
use crate::model::{self, passkey_id};

pub(crate) struct MongoPasskeyCredentialStore {
    coll: Coll,
}

impl MongoPasskeyCredentialStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }

    async fn update(&self, credential_id: &[u8], update: Document) -> StorageResult<()> {
        let filter = doc! { "_id": passkey_id(credential_id) };
        let result = self.coll.update_one(filter, update).await.map_err(err)?;
        if result.matched_count == 0 {
            return Err(StorageError::not_found("passkey credential not found"));
        }
        Ok(())
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

    async fn record_passkey_use(
        &self,
        credential_id: &[u8],
        used: PasskeyUse,
    ) -> StorageResult<()> {
        let update = doc! {
            "$set": {
                "passkey": Binary { subtype: BinarySubtype::Generic, bytes: used.passkey },
                "backup_eligible": used.backup_eligible,
                "backup_state": used.backup_state,
                "last_used_at": model::to_bson_dt(used.used_at),
            }
        };
        self.update(credential_id, update).await
    }

    async fn set_passkey_name(
        &self,
        credential_id: &[u8],
        name: Option<&str>,
    ) -> StorageResult<()> {
        let update = match name {
            Some(name) => doc! { "$set": { "name": name } },
            None => doc! { "$unset": { "name": "" } },
        };
        self.update(credential_id, update).await
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

    async fn count_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let filter = doc! { "user_id": user_id.0.to_string() };
        self.coll.count_documents(filter).await.map_err(err)
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

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let filter = doc! { "user_id": user_id.0.to_string() };
        let result = self.coll.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }
}
