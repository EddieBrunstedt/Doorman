//! redb-backed [`VerificationTokenStore`].
//!
//! Tokens occupy two tables: the primary record (`vtokens`) keyed by
//! `"{purpose}\x00{hash_hex}"` (purpose is part of the key so a token can
//! never be redeemed under a different flow), and a per-user per-purpose index
//! (`user_vtokens_idx`) keyed by `"{user_id}\x00{purpose}\x00{hash_hex}"`.
//!
//! `consume_token` is the atomic delete-and-return: a single write transaction
//! removes the record (redb serializes writers) so exactly one concurrent
//! caller observes the token.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    TokenHash, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use redb::ReadableTable as _;

use crate::db::{self, RedbHandle};

pub(crate) struct RedbVerificationTokenStore {
    handle: RedbHandle,
}

impl RedbVerificationTokenStore {
    pub(crate) fn new(handle: RedbHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl VerificationTokenStore for RedbVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        self.handle
            .write(move |wtxn| {
                let vt_key = db::vtoken_key(token.purpose, &token.token_hash);
                let user_idx_key =
                    db::user_vtokens_idx_key(token.user_id, token.purpose, &token.token_hash);
                let encoded = db::encode(&token)?;

                let mut vtokens = wtxn.open_table(db::VTOKENS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_VTOKENS_IDX).map_err(db::err)?;

                vtokens
                    .insert(vt_key.as_str(), encoded.as_slice())
                    .map_err(db::err)?;
                user_idx
                    .insert(user_idx_key.as_str(), ())
                    .map_err(db::err)?;
                Ok(())
            })
            .await
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let vt_key = db::vtoken_key(purpose, hash);
        self.handle
            .write(move |wtxn| {
                let mut vtokens = wtxn.open_table(db::VTOKENS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_VTOKENS_IDX).map_err(db::err)?;

                let Some(guard) = vtokens.remove(vt_key.as_str()).map_err(db::err)? else {
                    return Ok(None);
                };
                let token: VerificationToken = db::decode(guard.value())?;
                let user_idx_key =
                    db::user_vtokens_idx_key(token.user_id, token.purpose, &token.token_hash);
                user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                Ok(Some(token))
            })
            .await
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let prefix = db::user_vtokens_prefix(user_id, purpose);
                let end = db::prefix_end(&prefix);

                let mut vtokens = wtxn.open_table(db::VTOKENS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_VTOKENS_IDX).map_err(db::err)?;

                // Collect the index keys first (prefix = "{uid}\x00{purpose}\x00").
                let idx_keys: Vec<String> = {
                    user_idx
                        .range(prefix.as_str()..end.as_str())
                        .map_err(db::err)?
                        .map(|r| r.map_err(db::err).map(|(k, _)| k.value().to_owned()))
                        .collect::<StorageResult<_>>()?
                };

                let mut count = 0u64;
                for idx_key in &idx_keys {
                    // The hash_hex is everything after the prefix.
                    let hash_hex = &idx_key[prefix.len()..];
                    let vt_key = db::vtoken_key_raw(purpose, hash_hex);
                    if vtokens.remove(vt_key.as_str()).map_err(db::err)?.is_some() {
                        count += 1;
                    }
                    user_idx.remove(idx_key.as_str()).map_err(db::err)?;
                }
                Ok(count)
            })
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.handle
            .write(move |wtxn| {
                let mut vtokens = wtxn.open_table(db::VTOKENS).map_err(db::err)?;
                let mut user_idx = wtxn.open_table(db::USER_VTOKENS_IDX).map_err(db::err)?;

                // Scan inside the write transaction so the expiry check and the
                // removal see the same row (redb serializes writers).
                let expired: Vec<(String, VerificationToken)> = vtokens
                    .iter()
                    .map_err(db::err)?
                    .map(|r| {
                        r.map_err(db::err).and_then(|(k, v)| {
                            let key = k.value().to_owned();
                            let token = db::decode::<VerificationToken>(v.value())?;
                            Ok((key, token))
                        })
                    })
                    .filter(|r| r.as_ref().map_or(true, |(_, t)| t.expires_at <= now))
                    .collect::<StorageResult<_>>()?;

                for (key, token) in &expired {
                    vtokens.remove(key.as_str()).map_err(db::err)?;
                    let user_idx_key =
                        db::user_vtokens_idx_key(token.user_id, token.purpose, &token.token_hash);
                    user_idx.remove(user_idx_key.as_str()).map_err(db::err)?;
                }
                Ok(expired.len() as u64)
            })
            .await
    }
}
