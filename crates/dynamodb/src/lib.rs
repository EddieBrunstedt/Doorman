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
use doorman_core::storage::{
    EmailLinkStore, PasskeyChallengeStore, PasskeyStore, Session, SessionStore, Storage, UserStore,
};

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
            users: self.user_store(),
            sessions: self.session_store(),
            email_links: self.email_link_store(),
            passkeys: self.passkey_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }

    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(stores::user::DynamoUserStore::new(self.client.clone()))
    }

    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::DynamoSessionStore::new(
            self.client.clone(),
        ))
    }

    pub fn email_link_store(&self) -> Arc<dyn EmailLinkStore> {
        Arc::new(stores::email_link::DynamoEmailLinkStore::new(
            self.client.clone(),
        ))
    }

    pub fn passkey_store(&self) -> Arc<dyn PasskeyStore> {
        Arc::new(stores::passkey::DynamoPasskeyStore::new(
            self.client.clone(),
        ))
    }

    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::DynamoPasskeyChallengeStore::new(
            self.client.clone(),
        ))
    }
}

pub fn create_session_writes(
    table_name: &str,
    session: &Session,
) -> StorageResult<Vec<TransactWriteItem>> {
    stores::session::create_writes(table_name, session)
}
