//! MongoDB-backed [`SessionStore`].
//!
//! One document per session keyed by the session UUID. Two additional indexes
//! back the secondary access patterns:
//!
//! - **`token_hash` unique index** — the hot per-request lookup by hashed
//!   bearer token. `find_session_by_token_hash` hits this index with a single
//!   `find_one`.
//! - **`user_id` index** — backs `list_for_user` and `delete_sessions_for_user`.
//!
//! The `ttl` field is written only for future-dated expiries (see
//! `model::ttl_bson`), driving the TTL index without sweeping past-dated
//! conformance fixtures. `purge_expired` is the authoritative reclamation
//! path: it issues a `deleteMany` with `expires_at <= now`, which is
//! immediately consistent.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, Bson, doc};

use crate::db::{Coll, err};
use crate::model::{self, to_bson_dt};

/// Session store backed by a MongoDB collection.
pub(crate) struct MongoSessionStore {
    coll: Coll,
}

impl MongoSessionStore {
    pub(crate) fn new(coll: Coll) -> Self {
        Self { coll }
    }
}

#[async_trait]
impl SessionStore for MongoSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.coll
            .insert_one(model::session_to_doc(&session))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        // `update_one` without `upsert` is inherently safe against the
        // resurrection hazard: a session deleted between resolution and touch
        // matches no document, so the update affects zero rows rather than
        // recreating it. The TTL index reads `expires_at`/`ttl` live, so
        // rewriting them is all the TTL coupling MongoDB needs.
        let filter = doc! { "_id": model::session_id_str(id) };
        let mut set = doc! {
            "last_used_at": to_bson_dt(last_used_at),
            "expires_at": to_bson_dt(expires_at),
        };
        let mut update = doc! {};
        // Mirror `session_to_doc`: the `ttl` field (which drives the TTL index)
        // is present only for future-dated expiries. Set it when the slid
        // deadline is in the future, otherwise drop any stale `ttl`.
        match model::ttl_bson(expires_at) {
            Some(ttl) => {
                set.insert("ttl", ttl);
            }
            None => {
                update.insert("$unset", doc! { "ttl": "" });
            }
        }
        update.insert("$set", set);
        self.coll.update_one(filter, update).await.map_err(err)?;
        Ok(())
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let hash_bin = Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes: hash.0.to_vec(),
        });
        let filter = doc! { "token_hash": hash_bin };
        match self.coll.find_one(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::session_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let filter = doc! { "_id": model::session_id_str(id) };
        match self.coll.find_one(filter).await.map_err(err)? {
            Some(doc) => Ok(Some(model::session_from_doc(&doc)?)),
            None => Ok(None),
        }
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        // Push the `expires_at > now` predicate into the query so expired rows
        // never leave the store, as the trait contract requires.
        let filter = doc! {
            "user_id": user_id.0.to_string(),
            "expires_at": { "$gt": to_bson_dt(now) },
        };
        let mut cursor = self.coll.find(filter).await.map_err(err)?;
        let mut out = Vec::new();
        while cursor.advance().await.map_err(err)? {
            out.push(model::session_from_doc(
                &cursor.deserialize_current().map_err(err)?,
            )?);
        }
        Ok(out)
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let filter = doc! { "_id": model::session_id_str(id) };
        self.coll.delete_one(filter).await.map_err(err)?;
        Ok(())
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        // `deleteMany` removes each matching document atomically with its index
        // entries, so a session inserted concurrently is either deleted or left
        // whole.
        let mut filter = doc! { "user_id": user_id.0.to_string() };
        if let Some(except) = except {
            filter.insert("_id", doc! { "$ne": model::session_id_str(except) });
        }
        let result = self.coll.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let filter = doc! { "expires_at": { "$lte": to_bson_dt(now) } };
        let result = self.coll.delete_many(filter).await.map_err(err)?;
        Ok(result.deleted_count)
    }
}
