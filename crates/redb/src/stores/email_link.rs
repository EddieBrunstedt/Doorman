use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{EmailLink, EmailLinkStore, TokenHash, UserId};

use crate::db::{self, RedbHandle};
use crate::expiring::{Expiring, Family, Writer};

impl Expiring for EmailLink {
    const FAMILY: Family = db::EMAIL_LINKS;

    fn key(&self) -> String {
        db::token_hash_hex(&self.token_hash)
    }

    fn deadline(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn owner(&self) -> Option<UserId> {
        Some(self.user_id)
    }
}

pub(crate) struct RedbEmailLinkStore {
    handle: RedbHandle,
}

impl RedbEmailLinkStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl EmailLinkStore for RedbEmailLinkStore {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let mut links = Writer::<EmailLink>::open(wtxn)?;
                if !links.insert(&link)? {
                    return Err(StorageError::conflict(
                        "email link token hash already exists",
                    ));
                }
                let key = link.key();
                for other in links.owned_keys(link.user_id)? {
                    if other != key
                        && links
                            .get(&other)?
                            .is_some_and(|other| other.purpose == link.purpose)
                    {
                        links.remove(&other)?;
                    }
                }
                Ok(())
            })
            .await
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let key = db::token_hash_hex(hash);
        self.handle
            .write(move |wtxn| Writer::<EmailLink>::open(wtxn)?.take(&key))
            .await
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| Writer::<EmailLink>::open(wtxn)?.remove_owned(user_id, None))
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| Writer::<EmailLink>::open(wtxn)?.purge(now))
            .await
    }
}
