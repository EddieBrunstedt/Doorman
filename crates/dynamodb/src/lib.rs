// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod client;
mod model;
mod stores;

use std::sync::Arc;

use aws_sdk_dynamodb::types::TransactWriteItem;
use doorman_core::error::StorageResult;
use doorman_core::storage::{ExpiringStores, RecordStores, Session, Storage};

use crate::client::DynamoClient;

#[derive(Clone)]
pub struct DynamoDbStorage {
    client: DynamoClient,
}

impl DynamoDbStorage {
    pub fn new(client: aws_sdk_dynamodb::Client, table_name: impl Into<String>) -> Self {
        Self {
            client: DynamoClient::new(client, table_name.into()),
        }
    }

    pub fn table_name(&self) -> &str {
        self.client.table()
    }

    pub async fn create_table(&self) -> StorageResult<()> {
        self.client.ensure_table().await
    }

    pub fn all_stores(&self) -> Storage {
        Storage {
            records: self.records(),
            expiring: self.expiring(),
        }
    }

    pub fn records(&self) -> RecordStores {
        RecordStores {
            users: Arc::new(stores::user::DynamoUserStore::new(self.client.clone())),
            passkeys: Arc::new(stores::passkey::DynamoPasskeyStore::new(
                self.client.clone(),
            )),
        }
    }

    pub fn expiring(&self) -> ExpiringStores {
        ExpiringStores {
            sessions: Arc::new(stores::session::DynamoSessionStore::new(
                self.client.clone(),
            )),
            email_links: Arc::new(stores::email_link::DynamoEmailLinkStore::new(
                self.client.clone(),
            )),
            passkey_challenges: Arc::new(stores::passkey_chal::DynamoPasskeyChallengeStore::new(
                self.client.clone(),
            )),
        }
    }
}

pub fn create_session_writes(
    table_name: &str,
    session: &Session,
) -> StorageResult<Vec<TransactWriteItem>> {
    stores::session::create_writes(table_name, session)
}
