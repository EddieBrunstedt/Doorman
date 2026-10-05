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
//! rejected, and the field-level writes (`record_passkey_use`,
//! `set_passkey_name`) are `UpdateItem`s guarded by `attribute_exists` so
//! updating a missing credential reports it missing. The metadata-only summary listing
//! projects each row to a
//! [`PasskeySummary`](doorman_core::storage::PasskeySummary) without ever
//! reading the credential blob.

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyCredentialStore, PasskeySummary, PasskeyUse, StoredPasskey, UserId,
};

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

    /// Apply a field-level `UpdateItem` to the existing credential
    /// `credential_id`. The write touches only the attributes `expression`
    /// names, so concurrent changes to other attributes survive; it fails if
    /// the credential does not exist.
    async fn update(
        &self,
        credential_id: &[u8],
        expression: &str,
        names: &[(&str, &str)],
        values: Vec<(&str, AttributeValue)>,
    ) -> StorageResult<()> {
        let mut request = self
            .client
            .inner()
            .update_item()
            .table_name(self.client.table())
            .key(PK, client::s(model::passkey_pk(credential_id)))
            .update_expression(expression)
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK);
        for (name, attribute) in names {
            request = request.expression_attribute_names(*name, *attribute);
        }
        for (name, value) in values {
            request = request.expression_attribute_values(name, value);
        }
        request.send().await.map_err(|e| {
            client::condition_err(e, || {
                StorageError::not_found("passkey credential not found")
            })
        })?;
        Ok(())
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
            .map_err(|e| {
                client::condition_err(e, || {
                    StorageError::conflict("passkey credential id already registered")
                })
            })?;
        Ok(())
    }

    async fn record_passkey_use(
        &self,
        credential_id: &[u8],
        used: PasskeyUse,
    ) -> StorageResult<()> {
        self.update(
            credential_id,
            "SET #passkey = :passkey, #backup_eligible = :backup_eligible, \
             #backup_state = :backup_state, #last_used_at = :last_used_at",
            &[
                ("#passkey", "passkey"),
                ("#backup_eligible", "backup_eligible"),
                ("#backup_state", "backup_state"),
                ("#last_used_at", "last_used_at"),
            ],
            vec![
                (":passkey", client::b(used.passkey)),
                (":backup_eligible", client::boolean(used.backup_eligible)),
                (":backup_state", client::boolean(used.backup_state)),
                (":last_used_at", client::s(client::fmt_ts(used.used_at))),
            ],
        )
        .await
    }

    async fn set_passkey_name(
        &self,
        credential_id: &[u8],
        name: Option<&str>,
    ) -> StorageResult<()> {
        // A cleared name drops the attribute, mirroring `passkey_item`, which
        // omits it when there is no name.
        match name {
            Some(name) => {
                self.update(
                    credential_id,
                    "SET #name = :name",
                    &[("#name", "name")],
                    vec![(":name", client::s(name))],
                )
                .await
            }
            None => {
                self.update(credential_id, "REMOVE #name", &[("#name", "name")], vec![])
                    .await
            }
        }
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

    async fn count_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.client
            .count_owner(&model::user_passkeys_key(user_id))
            .await
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

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.client
            .delete_owned(&model::user_passkeys_key(user_id))
            .await
    }
}
