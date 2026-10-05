//! DynamoDB-backed [`UserStore`].
//!
//! A user is the system of record, so this store reproduces the relational
//! guarantees a SQL backend gives for free. Each user is one item under
//! `user#<id>`; the secondary lookup and uniqueness constraint on the email
//! address are carried by a second **guard item** under `email#<email>` (a GSI
//! could neither enforce uniqueness nor be read strongly-consistently). The two
//! are written together with [`TransactWriteItems`], each guarded by
//! `attribute_not_exists`, so a duplicate id *or* a duplicate email aborts the
//! whole write — matching the reference store's rejection of both.
//!
//! Reads go straight to the main table with strongly-consistent `GetItem`, so a
//! user is visible the instant it is created (the email lookup is a consistent
//! read of the guard followed by a consistent read of the user).
//!
//! [`TransactWriteItems`]: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html

use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem, Update};
use chrono::{DateTime, Utc};
use doorman_core::encoding::account_status_to_str;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{AccountStatus, User, UserId, UserStore};

use crate::client::{self, DynamoClient, Item, PK};
use crate::model;

/// User store backed by a DynamoDB connection.
pub(crate) struct DynamoUserStore {
    client: DynamoClient,
}

impl DynamoUserStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }

    /// A `Put` of `item` guarded by the absence of its key (a fresh insert).
    fn put_new(&self, item: Item) -> StorageResult<TransactWriteItem> {
        let put = Put::builder()
            .table_name(self.client.table())
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .build()
            .map_err(client::err)?;
        Ok(TransactWriteItem::builder().put(put).build())
    }

    /// A `Delete` of the item at `pk`.
    fn delete(&self, pk: String) -> StorageResult<TransactWriteItem> {
        let delete = Delete::builder()
            .table_name(self.client.table())
            .key(PK, client::s(pk))
            .build()
            .map_err(client::err)?;
        Ok(TransactWriteItem::builder().delete(delete).build())
    }

    /// Apply a field-level `UpdateItem` to the existing user `id`. The write
    /// touches only the attributes `expression` names, so concurrent changes
    /// to other attributes survive; it fails if the user does not exist.
    async fn update(
        &self,
        id: UserId,
        expression: &str,
        names: &[(&str, &str)],
        values: Vec<(&str, AttributeValue)>,
    ) -> StorageResult<()> {
        let mut request = self
            .client
            .inner()
            .update_item()
            .table_name(self.client.table())
            .key(PK, client::s(model::user_pk(id)))
            .update_expression(expression)
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK);
        for (name, attribute) in names {
            request = request.expression_attribute_names(*name, *attribute);
        }
        for (name, value) in values {
            request = request.expression_attribute_values(name, value);
        }
        request.send().await.map_err(client::err)?;
        Ok(())
    }

    async fn transact(&self, items: Vec<TransactWriteItem>) -> StorageResult<()> {
        self.client
            .inner()
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
            .map_err(client::err)?;
        Ok(())
    }
}

#[async_trait]
impl UserStore for DynamoUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let mut writes = vec![self.put_new(model::user_item(&user))?];
        if let Some(email) = user.email.as_deref() {
            writes.push(self.put_new(model::email_item(email, user.id))?);
        }
        self.transact(writes).await
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        match self.client.get(&model::user_pk(id)).await? {
            Some(item) => Ok(Some(model::user_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let Some(guard) = self.client.get(&model::email_pk(email)).await? else {
            return Ok(None);
        };
        let user_id = model::email_item_user_id(&guard)?;
        match self.client.get(&model::user_pk(user_id)).await? {
            Some(item) => Ok(Some(model::user_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn set_user_status(
        &self,
        id: UserId,
        status: AccountStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let mut values = vec![
            (":status", client::s(account_status_to_str(&status))),
            (":updated_at", client::s(client::fmt_ts(at))),
        ];
        let expression = match status.disabled_at() {
            Some(disabled_at) => {
                values.push((":disabled_at", client::s(client::fmt_ts(disabled_at))));
                "SET #status = :status, #disabled_at = :disabled_at, #updated_at = :updated_at"
            }
            None => "SET #status = :status, #updated_at = :updated_at REMOVE #disabled_at",
        };
        self.update(
            id,
            expression,
            &[
                ("#status", "status"),
                ("#disabled_at", "disabled_at"),
                ("#updated_at", "updated_at"),
            ],
            values,
        )
        .await
    }

    async fn set_user_email(
        &self,
        id: UserId,
        email: &str,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        // Moving the address means moving its guard item, so read the current
        // address first. The user update is conditioned on that address still
        // being current, so a concurrent email change aborts this transaction
        // rather than orphaning a guard.
        let Some(current) = self.client.get(&model::user_pk(id)).await? else {
            return Err(StorageError::msg("user not found"));
        };
        let old_email = model::user_from_item(&current)?.email;

        let names = [
            ("#pk", PK),
            ("#email", "email"),
            ("#email_verified_at", "email_verified_at"),
            ("#updated_at", "updated_at"),
        ];
        let mut values = vec![
            (":email", client::s(email)),
            (":at", client::s(client::fmt_ts(at))),
        ];
        let condition = match old_email.as_deref() {
            Some(old) => {
                values.push((":old_email", client::s(old)));
                "attribute_exists(#pk) AND #email = :old_email"
            }
            None => "attribute_exists(#pk) AND attribute_not_exists(#email)",
        };
        let update = Update::builder()
            .table_name(self.client.table())
            .key(PK, client::s(model::user_pk(id)))
            .update_expression("SET #email = :email, #email_verified_at = :at, #updated_at = :at")
            .condition_expression(condition)
            .set_expression_attribute_names(Some(
                names
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ))
            .set_expression_attribute_values(Some(
                values
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            ))
            .build()
            .map_err(client::err)?;

        let mut writes = vec![TransactWriteItem::builder().update(update).build()];
        if old_email.as_deref() != Some(email) {
            if let Some(old) = old_email.as_deref() {
                writes.push(self.delete(model::email_pk(old))?);
            }
            writes.push(self.put_new(model::email_item(email, id))?);
        }
        self.transact(writes).await
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        self.update(
            id,
            "SET #email_verified_at = :at, #updated_at = :at",
            &[
                ("#email_verified_at", "email_verified_at"),
                ("#updated_at", "updated_at"),
            ],
            vec![(":at", client::s(client::fmt_ts(at)))],
        )
        .await
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        // Remove the user and, if present, its email guard. Reading the row
        // first is what lets us reclaim the guard keyed by the email address.
        let mut keys = vec![model::user_pk(id)];
        if let Some(item) = self.client.get(&model::user_pk(id)).await?
            && let Some(email) = model::user_from_item(&item)?.email
        {
            keys.push(model::email_pk(&email));
        }
        self.client.batch_delete(keys).await
    }
}
