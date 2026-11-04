use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::client::RedisClient;
use crate::keys::{Family, Ownership};
use crate::table::{Expiring, Insert, Table};

impl Expiring for StoredPasskeyRegistration {
    const FAMILY: Family = Family {
        row: "pkreg",
        rows: "pkregs",
        ownership: Ownership::Set,
    };

    fn id(&self) -> String {
        self.id.0.to_string()
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn owner(&self) -> Option<UserId> {
        Some(self.user_id)
    }
}

impl Expiring for StoredPasskeyAuthentication {
    const FAMILY: Family = Family {
        row: "pkauth",
        rows: "pkauths",
        ownership: Ownership::None,
    };

    fn id(&self) -> String {
        self.id.0.to_string()
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

pub(crate) struct RedisPasskeyChallengeStore {
    registrations: Table<StoredPasskeyRegistration>,
    authentications: Table<StoredPasskeyAuthentication>,
}

impl RedisPasskeyChallengeStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self {
            registrations: Table::new(client.clone()),
            authentications: Table::new(client),
        }
    }
}

fn inserted(insert: Insert, what: &str) -> StorageResult<()> {
    match insert {
        Insert::Done => Ok(()),
        Insert::Conflict => Err(StorageError::conflict(format!(
            "{what} challenge id already exists"
        ))),
    }
}

#[async_trait]
impl PasskeyChallengeStore for RedisPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        inserted(self.registrations.insert(&value).await?, "registration")
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        self.registrations.take(&id.0.to_string()).await
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.registrations.delete_owned(user_id, None).await
    }

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>> {
        self.registrations.list_owned(user_id).await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        inserted(self.authentications.insert(&value).await?, "authentication")
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        self.authentications.take(&id.0.to_string()).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        Ok(self.registrations.purge(now).await? + self.authentications.purge(now).await?)
    }
}
