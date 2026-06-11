//! DynamoDB-backed [`PasskeyCredentialStore`].
//!
//! A credential is the system of record, so each is one item under
//! `passkey#<credential id>` with an `owner-index` entry on its user for the
//! "your passkeys" listing. The credential id and the opaque `webauthn-rs` blob
//! are stored verbatim as binary attributes and returned unchanged — the store
//! never interprets them.
//!
//! Writes use conditions to reproduce the relational guarantees: `add_passkey`
//! is guarded by `attribute_not_exists` so a duplicate credential id is
//! rejected, and `update_passkey` by `attribute_exists` so updating a missing
//! credential errors. The metadata-only summary listing projects each row to a
//! [`PasskeySummary`](doorman_core::storage::PasskeySummary) without ever reading
//! the credential blob.

use async_trait::async_trait;
use doorman_core::error::StorageResult;
use doorman_core::storage::{PasskeyCredentialStore, PasskeySummary, StoredPasskey, UserId};

use crate::client::{self, DynamoClient, PK};
use crate::model;

/// Passkey-credential store backed by a DynamoDB connection.
pub(crate) struct DynamoPasskeyCredentialStore {
    client: DynamoClient,
}

impl DynamoPasskeyCredentialStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyCredentialStore for DynamoPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        self.client
            .inner()
            .put_item()
            .table_name(self.client.table())
            .set_item(Some(model::passkey_item(&credential)))
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .send()
            .await
            .map_err(client::err)?;
        Ok(())
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        // `attribute_exists` makes the put a true update: a missing credential
        // fails the condition and surfaces as an error, matching the reference
        // store's "not found" rejection.
        self.client
            .inner()
            .put_item()
            .table_name(self.client.table())
            .set_item(Some(model::passkey_item(&credential)))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .send()
            .await
            .map_err(client::err)?;
        Ok(())
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        let items = self
            .client
            .query_owner(&model::user_passkeys_key(user_id))
            .await?;
        items.iter().map(model::passkey_from_item).collect()
    }

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        let items = self
            .client
            .query_owner(&model::user_passkeys_key(user_id))
            .await?;
        items.iter().map(model::passkey_summary_from_item).collect()
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        match self.client.get(&model::passkey_pk(credential_id)).await? {
            Some(item) => Ok(Some(model::passkey_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        self.client.delete(&model::passkey_pk(credential_id)).await
    }
}
