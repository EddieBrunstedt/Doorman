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

use crate::client::{self, DynamoClient, PK};
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

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        // `UpdateItem` guarded by `attribute_exists(pk)`: it writes the slid
        // `last_used_at`/`expires_at` and the native TTL attribute (TTL
        // coupling) only if the row still exists, so a session revoked between
        // resolution and touch is never resurrected. Mirroring `session_item`,
        // the TTL attribute is present only for a future-dated expiry.
        let mut request = self
            .client
            .inner()
            .update_item()
            .table_name(self.client.table())
            .key(PK, client::s(model::session_pk(id)))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .expression_attribute_names("#last_used_at", "last_used_at")
            .expression_attribute_names("#expires_at", client::EXPIRES_AT)
            .expression_attribute_names("#ttl", client::TTL)
            .expression_attribute_values(":last_used_at", client::s(client::fmt_ts(last_used_at)))
            .expression_attribute_values(":expires_at", client::s(client::fmt_ts(expires_at)));
        request = match client::ttl_attr(expires_at) {
            Some(ttl) => request
                .update_expression(
                    "SET #last_used_at = :last_used_at, #expires_at = :expires_at, #ttl = :ttl",
                )
                .expression_attribute_values(":ttl", ttl),
            None => request.update_expression(
                "SET #last_used_at = :last_used_at, #expires_at = :expires_at REMOVE #ttl",
            ),
        };
        match request.send().await {
            Ok(_) => Ok(()),
            // The row no longer exists; the conditional touch is a no-op.
            Err(e)
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(e) => Err(client::err(e)),
        }
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
        self.client
            .delete_owned(&model::user_sessions_key(user_id))
            .await
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
        self.client.delete_expired(&[ENTITY_SESSION], now).await
    }
}
