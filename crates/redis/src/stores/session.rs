use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::client::{self, RedisClient};
use crate::stores;

pub(crate) struct RedisSessionStore {
    client: RedisClient,
}

impl RedisSessionStore {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let keys = self.client.keys();
        let session_key = keys.session(session.id);
        let hash_key = keys.session_hash_index(&session.token_hash);
        let user_key = keys.user_sessions(session.user_id);
        let id = session.id.0.to_string();
        let json = client::to_json(&session)?;
        let mut conn = self.client.conn();

        stores::insert_absent(
            &mut conn,
            &[(&session_key, &json), (&hash_key, &id)],
            session.expires_at,
            Some(stores::OwnerIndex {
                set: &user_key,
                member: &id,
            }),
            "session id or token hash",
        )
        .await
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let keys = self.client.keys();
        let session_key = keys.session(id);
        let mut conn = self.client.conn();

        let Some(mut current) = client::get_json::<Session>(&mut conn, &session_key).await? else {
            return Ok(());
        };
        current.last_used_at = last_used_at;
        current.expires_at = expires_at;
        let hash_key = keys.session_hash_index(&current.token_hash);
        let json = client::to_json(&current)?;

        let mut pipe = redis::pipe();
        pipe.atomic();
        let pxat = current.expires_at.timestamp_millis();
        // `XX` turns a delete that lands after the GET into a no-op instead of
        // a resurrected session.
        pipe.cmd("SET")
            .arg(&session_key)
            .arg(&json)
            .arg("XX")
            .arg("PXAT")
            .arg(pxat)
            .ignore();
        pipe.cmd("PEXPIREAT").arg(&hash_key).arg(pxat).ignore();
        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(StorageError::new)?;
        Ok(())
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let keys = self.client.keys();
        let hash_key = keys.session_hash_index(hash);
        let mut conn = self.client.conn();

        let Some(id) = client::get_string(&mut conn, &hash_key).await? else {
            return Ok(None);
        };
        let session_key = keys.session_key_for(&id);
        match client::get_json::<Session>(&mut conn, &session_key).await? {
            Some(session) => Ok(Some(session)),
            None => {
                let _ = client::del(&mut conn, &[hash_key]).await;
                Ok(None)
            }
        }
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let session_key = self.client.keys().session(id);
        let mut conn = self.client.conn();
        client::get_json(&mut conn, &session_key).await
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();
        stores::list_indexed(&mut conn, &keys.user_sessions(user_id), |m| {
            keys.session_key_for(m)
        })
        .await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let keys = self.client.keys();
        let session_key = keys.session(id);
        let mut conn = self.client.conn();

        let Some(session) = client::get_json::<Session>(&mut conn, &session_key).await? else {
            return Ok(());
        };
        let hash_key = keys.session_hash_index(&session.token_hash);
        let user_key = keys.user_sessions(session.user_id);
        let id = id.0.to_string();

        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("DEL").arg(&session_key).arg(&hash_key).ignore();
        pipe.cmd("SREM").arg(&user_key).arg(&id).ignore();
        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(StorageError::new)?;
        Ok(())
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        let keys = self.client.keys();
        let except = except.map(|id| id.0.to_string());
        let mut conn = self.client.conn();
        stores::delete_indexed::<Session>(
            &mut conn,
            keys,
            &keys.user_sessions(user_id),
            |m| keys.session_key_for(m),
            except.as_deref(),
        )
        .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        stores::purge_index_sets::<Session>(
            &mut conn,
            keys,
            &keys.user_sessions_pattern(),
            |id| keys.session_key_for(id),
            now,
        )
        .await
    }
}
