//! fjall-backed [`VerificationTokenStore`].
//!
//! Tokens occupy two partitions: the primary record (`vtokens`) keyed by
//! `"{purpose}\x00{hash_hex}"` (purpose is part of the key so a token can
//! never be redeemed under a different flow), and a per-user per-purpose index
//! (`user_vtokens_idx`) keyed by `"{user_id}\x00{purpose}\x00{hash_hex}"`.
//!
//! `consume_token` is the atomic delete-and-return: a single write transaction
//! removes the primary record and its index entry (fjall serializes writers)
//! so exactly one concurrent caller observes the token.

use crate::db::{self, FjallHandle};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};

pub(crate) struct FjallVerificationTokenStore {
    handle: FjallHandle,
}

impl FjallVerificationTokenStore {
    pub(crate) fn new(handle: FjallHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl VerificationTokenStore for FjallVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let vt_key = db::vtoken_key(token.purpose, &token.token_hash);
            let user_idx_key =
                db::user_vtokens_idx_key(token.user_id, token.purpose, &token.token_hash);
            let encoded = db::encode(&token)?;

            let mut tx = handle.db.write_tx();
            tx.insert(&handle.vtokens, vt_key.as_bytes(), encoded.as_slice());
            tx.insert(&handle.user_vtokens_idx, user_idx_key.as_bytes(), b"");
            tx.commit().map_err(db::err)
        })
        .await
        .map_err(db::err)?
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let vt_key = db::vtoken_key(purpose, hash);
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let mut tx = handle.db.write_tx();

            let result = match tx
                .take(&handle.vtokens, vt_key.as_bytes())
                .map_err(db::err)?
            {
                None => None,
                Some(bytes) => {
                    let token: VerificationToken = db::decode(&bytes)?;
                    let user_idx_key =
                        db::user_vtokens_idx_key(token.user_id, token.purpose, &token.token_hash);
                    tx.remove(&handle.user_vtokens_idx, user_idx_key.as_bytes());
                    Some(token)
                }
            };
            tx.commit().map_err(db::err)?;
            Ok(result)
        })
        .await
        .map_err(db::err)?
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = db::user_vtokens_prefix(user_id, purpose);
            let end = db::prefix_end(&prefix);

            // Collect index keys first (prefix = "{uid}\x00{purpose}\x00").
            let idx_keys: Vec<String> = handle
                .user_vtokens_idx
                .as_ref()
                .range(prefix.as_bytes()..end.as_bytes())
                .map(|guard| {
                    let (key_bytes, _) = guard.into_inner().map_err(db::err)?;
                    std::str::from_utf8(&key_bytes)
                        .map(ToOwned::to_owned)
                        .map_err(db::err)
                })
                .collect::<StorageResult<_>>()?;

            if idx_keys.is_empty() {
                return Ok(0);
            }

            let mut tx = handle.db.write_tx();
            let mut count = 0u64;
            for idx_key in &idx_keys {
                // The hash_hex is everything after the prefix.
                let hash_hex = &idx_key[prefix.len()..];
                let vt_key = db::vtoken_key_raw(purpose, hash_hex);
                if tx
                    .take(&handle.vtokens, vt_key.as_bytes())
                    .map_err(db::err)?
                    .is_some()
                {
                    count += 1;
                }
                tx.remove(&handle.user_vtokens_idx, idx_key.as_bytes());
            }
            tx.commit().map_err(db::err)?;
            Ok(count)
        })
        .await
        .map_err(db::err)?
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            let expired: Vec<(Vec<u8>, VerificationToken)> = handle
                .vtokens
                .as_ref()
                .iter()
                .map(|guard| {
                    let (key, value) = guard.into_inner().map_err(db::err)?;
                    let token: VerificationToken = db::decode(&value)?;
                    Ok((key.to_vec(), token))
                })
                .filter(|r: &StorageResult<_>| {
                    r.as_ref().map_or(true, |(_, t)| t.expires_at <= now)
                })
                .collect::<StorageResult<_>>()?;

            if expired.is_empty() {
                return Ok(0);
            }

            let mut tx = handle.db.write_tx();
            let mut n = 0u64;
            for (key, token) in &expired {
                if tx
                    .take(&handle.vtokens, key.as_slice())
                    .map_err(db::err)?
                    .is_some()
                {
                    let user_idx_key =
                        db::user_vtokens_idx_key(token.user_id, token.purpose, &token.token_hash);
                    tx.remove(&handle.user_vtokens_idx, user_idx_key.as_bytes());
                    n += 1;
                }
            }
            tx.commit().map_err(db::err)?;
            Ok(n)
        })
        .await
        .map_err(db::err)?
    }
}
