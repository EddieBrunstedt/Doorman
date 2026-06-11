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
use aws_sdk_dynamodb::types::{Delete, Put, TransactWriteItem};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{User, UserId, UserStore};

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

    async fn update_user(&self, user: User) -> StorageResult<()> {
        // The email may have changed, which means moving the guard item; read the
        // current row to learn the old address and to reject an update of a
        // user that does not exist.
        let Some(current) = self.client.get(&model::user_pk(user.id)).await? else {
            return Err(StorageError::msg("user not found"));
        };
        let old_email = model::user_from_item(&current)?.email;
        let new_email = user.email.clone();
        let user_item = model::user_item(&user);

        if old_email == new_email {
            // No guard change: a single conditional put suffices.
            self.client
                .inner()
                .put_item()
                .table_name(self.client.table())
                .set_item(Some(user_item))
                .condition_expression("attribute_exists(#pk)")
                .expression_attribute_names("#pk", PK)
                .send()
                .await
                .map_err(client::err)?;
            return Ok(());
        }

        // Move the guard atomically with the user update: drop the old address'
        // guard and claim the new one (rejecting a collision).
        let mut writes = vec![{
            let put = Put::builder()
                .table_name(self.client.table())
                .set_item(Some(user_item))
                .condition_expression("attribute_exists(#pk)")
                .expression_attribute_names("#pk", PK)
                .build()
                .map_err(client::err)?;
            TransactWriteItem::builder().put(put).build()
        }];
        if let Some(old) = old_email.as_deref() {
            writes.push(self.delete(model::email_pk(old))?);
        }
        if let Some(new) = new_email.as_deref() {
            writes.push(self.put_new(model::email_item(new, user.id))?);
        }
        self.transact(writes).await
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
