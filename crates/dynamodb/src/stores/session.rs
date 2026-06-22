//! DynamoDB-backed [`SessionStore`].
//!
//! A session is one item under `session#<id>` carrying two GSI keys: a
//! `lookup-index` entry on its hashed bearer token (the hot per-request lookup)
//! and an `owner-index` entry on its user (the listing and bulk-delete paths).
//! DynamoDB maintains both indexes, so a delete or a TTL eviction drops the
//! index entries for free, with no dangling-member bookkeeping.
//!
//! The bulk-delete paths ([`delete_sessions_for_user`](DynamoSessionStore::delete_sessions_for_user),
//! [`delete_other_sessions_for_user`](DynamoSessionStore::delete_other_sessions_for_user))
//! enumerate the user's sessions through the `owner-index` GSI, and GSI reads
//! are eventually consistent. A session created immediately before a bulk revoke
//! may not yet be visible to the GSI, so it can survive that revoke and is
//! reclaimed only on a later revoke or by
//! [`purge_expired`](DynamoSessionStore::purge_expired) / native TTL. Bulk
//! revocation on DynamoDB is therefore best-effort under write-after-write;
//! `docs/security.md` records the trade-off and points hosts that need hard
//! immediate revocation at a SQL system-of-record.
//!
//! `create_session` is a plain `PutItem` (an upsert); the random id and 256-bit
//! token hash make a real collision a non-issue, and the contract permits the
//! upsert for key-value adapters. Native TTL is a memory backstop only: reads
//! re-apply `expires_at > now` and [`purge_expired`](DynamoSessionStore::purge_expired)
//! does the authoritative reclamation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::client::{self, DynamoClient};
use crate::model::{self, ENTITY_SESSION};

/// Session store backed by a DynamoDB connection.
pub(crate) struct DynamoSessionStore {
    client: DynamoClient,
}

impl DynamoSessionStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SessionStore for DynamoSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.client.put(model::session_item(&session)).await
    }

    async fn touch_session(&self, session: &Session) -> StorageResult<()> {
        // Conditional put guarded by `attribute_exists(pk)`: it rewrites the
        // whole item — including the native TTL attribute (TTL coupling) and
        // the slid `last_used_at`/`expires_at` — only if the row still exists,
        // so a session revoked between resolution and touch is never
        // resurrected.
        self.client
            .put_if_exists(model::session_item(session))
            .await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let items = self
            .client
            .query_lookup(&model::session_hash_key(hash))
            .await?;
        match items.first() {
            Some(item) => Ok(Some(model::session_from_item(item)?)),
            None => Ok(None),
        }
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        match self.client.get(&model::session_pk(id)).await? {
            Some(item) => Ok(Some(model::session_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        let items = self
            .client
            .query_owner(&model::user_sessions_key(user_id))
            .await?;
        let mut out = Vec::with_capacity(items.len());
        for item in &items {
            let session = model::session_from_item(item)?;
            // Push the expiry predicate into the store, like the SQL adapters:
            // an expired-but-present row never leaves via the listing (purge
            // reclaims it).
            if session.expires_at > now {
                out.push(session);
            }
        }
        Ok(out)
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.client.delete(&model::session_pk(id)).await
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let items = self
            .client
            .query_owner(&model::user_sessions_key(user_id))
            .await?;
        let keys = items
            .iter()
            .map(client::item_pk)
            .collect::<StorageResult<Vec<_>>>()?;
        let removed = keys.len() as u64;
        self.client.batch_delete(keys).await?;
        Ok(removed)
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        let except_pk = model::session_pk(except);
        let items = self
            .client
            .query_owner(&model::user_sessions_key(user_id))
            .await?;
        let mut keys = Vec::new();
        for item in &items {
            let pk = client::item_pk(item)?;
            if pk != except_pk {
                keys.push(pk);
            }
        }
        let removed = keys.len() as u64;
        self.client.batch_delete(keys).await?;
        Ok(removed)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let items = self.client.scan_entities(&[ENTITY_SESSION]).await?;
        let mut keys = Vec::new();
        for item in &items {
            if client::get_ts(item, client::EXPIRES_AT)? <= now {
                keys.push(client::item_pk(item)?);
            }
        }
        let removed = keys.len() as u64;
        self.client.batch_delete(keys).await?;
        Ok(removed)
    }
}
