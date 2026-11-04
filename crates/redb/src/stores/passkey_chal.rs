use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::db::{self, RedbHandle};
use crate::expiring::{Expiring, Family, Reader, Writer};

impl Expiring for StoredPasskeyRegistration {
    const FAMILY: Family = db::PASSKEY_REGISTRATIONS;

    fn key(&self) -> String {
        self.id.to_string()
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn owner(&self) -> Option<UserId> {
        Some(self.user_id)
    }
}

impl Expiring for StoredPasskeyAuthentication {
    const FAMILY: Family = db::PASSKEY_AUTHENTICATIONS;

    fn key(&self) -> String {
        self.id.to_string()
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

pub(crate) struct RedbPasskeyChallengeStore {
    handle: RedbHandle,
}

impl RedbPasskeyChallengeStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl PasskeyChallengeStore for RedbPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                if Writer::open(wtxn)?.insert(&value)? {
                    Ok(())
                } else {
                    Err(StorageError::conflict(
                        "registration challenge id already exists",
                    ))
                }
            })
            .await
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        self.handle
            .write(move |wtxn| Writer::open(wtxn)?.take(&id.to_string()))
            .await
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                Writer::<StoredPasskeyRegistration>::open(wtxn)?.remove_owned(user_id, None)
            })
            .await
    }

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>> {
        self.handle
            .read(move |rtxn| Reader::open(rtxn)?.list_owned(user_id))
            .await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                if Writer::open(wtxn)?.insert(&value)? {
                    Ok(())
                } else {
                    Err(StorageError::conflict(
                        "authentication challenge id already exists",
                    ))
                }
            })
            .await
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        self.handle
            .write(move |wtxn| Writer::open(wtxn)?.take(&id.to_string()))
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let registrations = Writer::<StoredPasskeyRegistration>::open(wtxn)?.purge(now)?;
                let authentications =
                    Writer::<StoredPasskeyAuthentication>::open(wtxn)?.purge(now)?;
                Ok(registrations + authentications)
            })
            .await
    }
}
