use crate::common;

use std::fmt::Write as _;

use crate::common::Backend;
use chrono::{DateTime, Duration, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{Session, SessionId, UserId};
use redis::aio::MultiplexedConnection;

fn session_key(prefix: &str, id: SessionId) -> String {
    format!("{prefix}session:{}", id.0)
}

fn hash_index_key(prefix: &str, token: &str) -> String {
    let mut hex = String::new();
    for byte in hash_token(token).0 {
        let _ = write!(hex, "{byte:02x}");
    }
    format!("{prefix}session:hash:{hex}")
}

fn user_sessions_key(prefix: &str, user_id: UserId) -> String {
    format!("{prefix}user:{}:sessions", user_id.0)
}

fn session(user_id: UserId, token: &str, now: DateTime<Utc>) -> Session {
    Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(token),
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    }
}

async fn del(conn: &mut MultiplexedConnection, key: String) -> i64 {
    redis::cmd("DEL")
        .arg(key)
        .query_async(conn)
        .await
        .expect("DEL")
}

async fn scard(conn: &mut MultiplexedConnection, key: String) -> i64 {
    redis::cmd("SCARD")
        .arg(key)
        .query_async(conn)
        .await
        .expect("SCARD")
}

async fn exists(conn: &mut MultiplexedConnection, key: String) -> i64 {
    redis::cmd("EXISTS")
        .arg(key)
        .query_async(conn)
        .await
        .expect("EXISTS")
}

async fn run_index_hygiene(backend: Backend) {
    let (_node, storage, mut raw, prefix) = common::storage_with_raw(backend).await;
    let sessions = &storage.sessions;
    let now = Utc::now();

    let lister = UserId::new();
    let list_session = session(lister, "dangling-list-token", now);
    sessions
        .create_session(list_session.clone())
        .await
        .expect("create list session");
    assert_eq!(
        del(&mut raw, session_key(&prefix, list_session.id)).await,
        1,
        "the primary row existed before the simulated eviction",
    );
    assert!(
        sessions
            .list_for_user(lister)
            .await
            .expect("list")
            .is_empty(),
        "a session whose row is gone is not listed",
    );
    assert_eq!(
        scard(&mut raw, user_sessions_key(&prefix, lister)).await,
        0,
        "list_for_user reclaimed the dangling SET member",
    );

    let finder = UserId::new();
    let find_token = "dangling-hash-token";
    let find_session = session(finder, find_token, now);
    sessions
        .create_session(find_session.clone())
        .await
        .expect("create find session");
    del(&mut raw, session_key(&prefix, find_session.id)).await;
    assert!(
        sessions
            .find_session_by_token_hash(&hash_token(find_token))
            .await
            .expect("find by hash")
            .is_none(),
        "a hash index pointing at a gone row resolves to nothing",
    );
    assert_eq!(
        exists(&mut raw, hash_index_key(&prefix, find_token)).await,
        0,
        "find_session_by_token_hash dropped the orphaned hash index",
    );

    let purger = UserId::new();
    let purge_session = session(purger, "dangling-purge-token", now);
    sessions
        .create_session(purge_session.clone())
        .await
        .expect("create purge session");
    del(&mut raw, session_key(&prefix, purge_session.id)).await;
    assert!(
        sessions.purge_expired(now).await.expect("purge") >= 1,
        "purge_expired reports the reclaimed dangling member",
    );
    assert_eq!(
        scard(&mut raw, user_sessions_key(&prefix, purger)).await,
        0,
        "purge_expired reclaimed the dangling SET member",
    );
}

#[tokio::test]
async fn redis_dangling_index_members_are_reclaimed() {
    run_index_hygiene(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_dangling_index_members_are_reclaimed() {
    run_index_hygiene(Backend::Valkey).await;
}
