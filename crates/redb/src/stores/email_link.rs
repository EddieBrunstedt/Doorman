use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{EmailLink, EmailLinkStore, TokenHash, UserId};
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

fn index_key(link: &EmailLink) -> String {
    db::owner_key(link.user_id, db::token_hash_hex(&link.token_hash))
}

#[async_trait]
impl EmailLinkStore for RedbEmailLinkStore {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let vt_key = db::token_hash_hex(&link.token_hash);
                let encoded = db::encode(&link)?;

                let mut email_links = wtxn.open_table(db::EMAIL_LINKS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_EMAIL_LINKS_IDX).map_err(db::err)?;

                if email_links.get(vt_key.as_str()).map_err(db::err)?.is_some() {
                    return Err(StorageError::conflict(
                        "email link token hash already exists",
                    ));
                }
                for hash_hex in db::owned_members(&user_idx, link.user_id)? {
                    let replaced = match email_links.get(hash_hex.as_str()).map_err(db::err)? {
                        Some(guard) => {
                            db::decode::<EmailLink>(guard.value())?.purpose == link.purpose
                        }
                        None => true,
                    };
                    if replaced {
                        email_links.remove(hash_hex.as_str()).map_err(db::err)?;
                        let user_idx_key = db::owner_key(link.user_id, &hash_hex);
                        user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                    }
                }
                email_links
                    .insert(vt_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                user_idx
                    .insert(index_key(&link).as_str(), ())
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
                let link: EmailLink = db::decode(guard.value())?;
                user_idx
                    .remove(index_key(&link).as_str())
                    .map_err(db::err)?;
                Ok(Some(link))
            })
            .await
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut email_links = wtxn.open_table(db::EMAIL_LINKS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_EMAIL_LINKS_IDX).map_err(db::err)?;

                let mut count = 0u64;
                for hash_hex in db::owned_members(&user_idx, user_id)? {
                    if email_links
                        .remove(hash_hex.as_str())
                        .map_err(db::err)?
                        .is_some()
                    {
                        count += 1;
                    }
                    let user_idx_key = db::owner_key(user_id, &hash_hex);
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
                            let link = db::decode::<EmailLink>(v.value())?;
                            Ok((key, link))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, l)| l.expires_at <= now))
                    .collect::<StorageResult<_>>()?;

                for (key, link) in &expired {
                    email_links.remove(key.as_str()).map_err(db::err)?;
                    user_idx.remove(index_key(link).as_str()).map_err(db::err)?;
                }
                Ok(expired.len() as u64)
            })
            .await
    }
}
