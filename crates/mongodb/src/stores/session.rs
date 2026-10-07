use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, Bson, doc};

use crate::db::{Coll, err};
use crate::model::{self, to_bson_dt};

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
        let filter = doc! { "_id": model::session_id_str(id) };
        let mut set = doc! {
            "last_used_at": to_bson_dt(last_used_at),
            "expires_at": to_bson_dt(expires_at),
        };
        let mut update = doc! {};
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

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        let filter = doc! { "user_id": user_id.0.to_string() };
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
