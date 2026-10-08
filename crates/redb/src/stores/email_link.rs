use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, TokenHash, UserId};
use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

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
    async fn create_link(&self, token: EmailLink) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let vt_key = db::token_hash_hex(&token.token_hash);
                let user_idx_key =
                    db::owner_key(db::email_links_owner(token.user_id, token.purpose), &vt_key);
                let encoded = db::encode(&token)?;

                let mut email_links = wtxn.open_table(db::EMAIL_LINKS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_EMAIL_LINKS_IDX).map_err(db::err)?;

                if email_links.get(vt_key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::conflict(
                        "email link token hash already exists",
                    ));
                }
                email_links
                    .insert(vt_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                user_idx
                    .insert(user_idx_key.as_str(), ())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let vt_key = db::token_hash_hex(hash);
        self.handle
            .write(move |wtxn| {
                let mut email_links = wtxn.open_table(db::EMAIL_LINKS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_EMAIL_LINKS_IDX).map_err(db::err)?;

                let Some(guard) = email_links.remove(vt_key.as_str()).map_err(db::err)? else {
                    return Ok(None);
                };
                let token: EmailLink = db::decode(guard.value())?;
                let user_idx_key = db::owner_key(
                    db::email_links_owner(token.user_id, token.purpose),
                    db::token_hash_hex(&token.token_hash),
                );
                user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                Ok(Some(token))
            })
            .await
    }

    async fn delete_links_for_user(
        &self,
        user_id: UserId,
        purpose: EmailLinkPurpose,
    ) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let owner = db::email_links_owner(user_id, purpose);

                let mut email_links = wtxn.open_table(db::EMAIL_LINKS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_EMAIL_LINKS_IDX).map_err(db::err)?;

                let mut count = 0u64;
                for hash_hex in db::owned_members(&user_idx, &owner)? {
                    if email_links
                        .remove(hash_hex.as_str())
                        .map_err(db::err)?
                        .is_some()
                    {
                        count += 1;
                    }
                    let user_idx_key = db::owner_key(&owner, &hash_hex);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut email_links = wtxn.open_table(db::EMAIL_LINKS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_EMAIL_LINKS_IDX).map_err(db::err)?;

                let expired: Vec<(String, EmailLink)> = email_links
                    .iter()
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, v)| {
                            let key = k.value().to_owned();
                            let token = db::decode::<EmailLink>(v.value())?;
                            Ok((key, token))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, t)| t.expires_at <= now))
                    .collect::<StorageResult<_>>()?;

                for (key, token) in &expired {
                    email_links.remove(key.as_str()).map_err(db::err)?;
                    let user_idx_key = db::owner_key(
                        db::email_links_owner(token.user_id, token.purpose),
                        db::token_hash_hex(&token.token_hash),
                    );
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(expired.len() as u64)
            })
            .await
    }
}
