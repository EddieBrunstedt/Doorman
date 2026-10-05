use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem, Update};
use chrono::{DateTime, Utc};
use doorman_core::encoding::account_status_to_str;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{AccountStatus, User, UserId, UserStore};

use crate::client::{self, DynamoClient, Item, PK};
use crate::model;

pub(crate) struct DynamoUserStore {
    client: DynamoClient,
}

impl DynamoUserStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }

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

    fn delete(&self, pk: String) -> StorageResult<TransactWriteItem> {
        let delete = Delete::builder()
            .table_name(self.client.table())
            .key(PK, client::s(pk))
            .build()
            .map_err(client::err)?;
        Ok(TransactWriteItem::builder().delete(delete).build())
    }

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
        request
            .send()
            .await
            .map_err(|e| client::condition_err(e, || StorageError::not_found("user not found")))?;
        Ok(())
    }

    async fn transact(
        &self,
        items: Vec<TransactWriteItem>,
        on_conditions: impl FnOnce(&[usize]) -> StorageError,
    ) -> StorageResult<()> {
        let result = self
            .client
            .inner()
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => match client::failed_conditions(&e).as_slice() {
                [] => Err(client::err(e)),
                failed => Err(on_conditions(failed)),
            },
        }
    }
}

#[async_trait]
impl UserStore for DynamoUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let mut writes = vec![self.put_new(model::user_item(&user))?];
        if let Some(email) = user.email.as_deref() {
            writes.push(self.put_new(model::email_item(email, user.id))?);
        }
        self.transact(writes, |_| {
            StorageError::conflict("user id or email already exists")
        })
        .await
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
        let Some(current) = self.client.get(&model::user_pk(id)).await? else {
            return Err(StorageError::not_found("user not found"));
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
        let mut new_guard = None;
        if old_email.as_deref() != Some(email) {
            if let Some(old) = old_email.as_deref() {
                writes.push(self.delete(model::email_pk(old))?);
            }
            new_guard = Some(writes.len());
            writes.push(self.put_new(model::email_item(email, id))?);
        }
        self.transact(writes, |failed| {
            if new_guard.is_some_and(|guard| failed.contains(&guard)) {
                StorageError::conflict("email already in use")
            } else {
                StorageError::msg("user changed during the email change")
            }
        })
        .await
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
        let mut keys = vec![model::user_pk(id)];
        if let Some(item) = self.client.get(&model::user_pk(id)).await?
            && let Some(email) = model::user_from_item(&item)?.email
        {
            keys.push(model::email_pk(&email));
        }
        self.client.batch_delete(keys).await
    }
}
