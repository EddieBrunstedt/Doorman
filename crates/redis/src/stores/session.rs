//! Redis-backed [`SessionStore`].
//!
//! A session is stored as three keys: the JSON row under `session:{id}`,
//! a `session:hash:{hash}` index resolving the hashed bearer token to the id
//! (the hot per-request lookup), and membership in the per-user
//! `user:{uid}:sessions` SET that backs the listing and bulk-delete paths. The
//! row and hash index carry a `PEXPIREAT` TTL when the expiry is in the
//! wall-clock future; the user SET cannot (its members expire at different
//! instants and Redis SETs have no per-member TTL), so its hygiene is kept by
//! read-time cleanup and the [`purge_expired`](RedisSessionStore::purge_expired)
//! backstop.
//!
//! `create_session` writes with a plain `SET`, so it is an upsert: a repeated
//! id or token hash overwrites rather than erroring, which the trait permits for
//! key-value adapters. The ids and 256-bit hashes are random, so a collision is
//! not a real-world case.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::client::{self, RedisClient};

/// Session store backed by a Redis/Valkey connection.
pub(crate) struct RedisSessionStore {
    client: RedisClient,
}

impl RedisSessionStore {
    /// Build a session store over `client`.
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

        // One MULTI/EXEC so the row, its hash index, and the user-set membership
        // all land together (or not at all).
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("SET").arg(&session_key).arg(&json).ignore();
        pipe.cmd("SET").arg(&hash_key).arg(&id).ignore();
        pipe.cmd("SADD").arg(&user_key).arg(&id).ignore();
        if let Some(ms) = client::ttl_at_ms(session.expires_at) {
            pipe.cmd("PEXPIREAT").arg(&session_key).arg(ms).ignore();
            pipe.cmd("PEXPIREAT").arg(&hash_key).arg(ms).ignore();
        }
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
                // The index outlived the row it pointed at (an evicted session).
                // Drop the dangling index so the next lookup is a single GET.
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

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        let keys = self.client.keys();
        let user_key = keys.user_sessions(user_id);
        let mut conn = self.client.conn();

        let members = client::smembers(&mut conn, &user_key).await?;
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let session_keys: Vec<String> = members.iter().map(|m| keys.session_key_for(m)).collect();
        let rows: Vec<Option<Session>> = client::mget_json(&mut conn, &session_keys).await?;

        let mut out = Vec::new();
        let mut dangling = Vec::new();
        for (member, row) in members.iter().zip(rows) {
            match row {
                // Push the expiry predicate into the store like the SQL
                // adapters: an expired-but-present row stays (purge reclaims it)
                // but never leaves via this listing.
                Some(session) if session.expires_at > now => out.push(session),
                Some(_) => {}
                None => dangling.push(member.clone()),
            }
        }
        // Opportunistic read-time hygiene: drop members whose row is gone.
        let _ = client::srem(&mut conn, &user_key, &dangling).await;
        Ok(out)
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let keys = self.client.keys();
        let session_key = keys.session(id);
        let mut conn = self.client.conn();

        // Read the row first to learn its token hash and owner so the hash index
        // and user-set membership can be removed alongside it.
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

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let keys = self.client.keys();
        let user_key = keys.user_sessions(user_id);
        let mut conn = self.client.conn();

        let members = client::smembers(&mut conn, &user_key).await?;
        if members.is_empty() {
            return Ok(0);
        }
        let session_keys: Vec<String> = members.iter().map(|m| keys.session_key_for(m)).collect();
        let rows: Vec<Option<Session>> = client::mget_json(&mut conn, &session_keys).await?;

        let mut del_keys = Vec::new();
        let mut removed = 0u64;
        for (member, row) in members.iter().zip(rows) {
            if let Some(session) = row {
                del_keys.push(keys.session_key_for(member));
                del_keys.push(keys.session_hash_index(&session.token_hash));
                removed += 1;
            }
        }
        // Drop the SET itself, taking any dangling members with it.
        del_keys.push(user_key);
        client::del(&mut conn, &del_keys).await?;
        Ok(removed)
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        let keys = self.client.keys();
        let user_key = keys.user_sessions(user_id);
        let except = except.0.to_string();
        let mut conn = self.client.conn();

        let members = client::smembers(&mut conn, &user_key).await?;
        if members.is_empty() {
            return Ok(0);
        }
        let session_keys: Vec<String> = members.iter().map(|m| keys.session_key_for(m)).collect();
        let rows: Vec<Option<Session>> = client::mget_json(&mut conn, &session_keys).await?;

        let mut del_keys = Vec::new();
        let mut srem_members = Vec::new();
        let mut removed = 0u64;
        for (member, row) in members.iter().zip(rows) {
            if *member == except {
                continue;
            }
            // SREM every other member (so dangling ones are reclaimed too), but
            // only count the sessions that actually existed as removed.
            srem_members.push(member.clone());
            if let Some(session) = row {
                del_keys.push(keys.session_key_for(member));
                del_keys.push(keys.session_hash_index(&session.token_hash));
                removed += 1;
            }
        }
        client::del(&mut conn, &del_keys).await?;
        client::srem(&mut conn, &user_key, &srem_members).await?;
        Ok(removed)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let keys = self.client.keys();
        let mut conn = self.client.conn();

        // Every session is reachable through exactly one user SET, so scanning
        // the SETs reaches every row and is also where dangling members are
        // reclaimed. The returned count is the number of members reclaimed
        // (expired rows plus already-evicted ones), as the `SessionStore`
        // contract permits for key-value adapters.
        let set_keys = client::scan_all(&mut conn, &keys.user_sessions_pattern()).await?;
        let mut removed = 0u64;
        for set_key in set_keys {
            let members = client::smembers(&mut conn, &set_key).await?;
            if members.is_empty() {
                continue;
            }
            let session_keys: Vec<String> =
                members.iter().map(|m| keys.session_key_for(m)).collect();
            let rows: Vec<Option<Session>> = client::mget_json(&mut conn, &session_keys).await?;

            let mut del_keys = Vec::new();
            let mut srem_members = Vec::new();
            for (member, row) in members.iter().zip(rows) {
                match row {
                    Some(session) if session.expires_at <= now => {
                        del_keys.push(keys.session_key_for(member));
                        del_keys.push(keys.session_hash_index(&session.token_hash));
                        srem_members.push(member.clone());
                    }
                    Some(_) => {}
                    None => srem_members.push(member.clone()),
                }
            }
            client::del(&mut conn, &del_keys).await?;
            removed += client::srem(&mut conn, &set_key, &srem_members).await?;
        }
        Ok(removed)
    }
}
