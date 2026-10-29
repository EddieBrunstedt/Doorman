use crate::common;

use std::time::Duration as StdDuration;

use crate::common::{Backend, link, registration, session};
use chrono::{Duration, Utc};
use doorman_core::encoding::hex;
use doorman_core::storage::UserId;
use redis::aio::MultiplexedConnection;

async fn exists(raw: &mut MultiplexedConnection, key: String) -> bool {
    redis::cmd("EXISTS")
        .arg(key)
        .query_async::<i64>(raw)
        .await
        .expect("EXISTS")
        == 1
}

async fn zrange(raw: &mut MultiplexedConnection, key: String) -> Vec<String> {
    redis::cmd("ZRANGE")
        .arg(key)
        .arg(0)
        .arg(-1)
        .query_async(raw)
        .await
        .expect("ZRANGE")
}

async fn hgetall(raw: &mut MultiplexedConnection, key: String) -> Vec<(String, String)> {
    redis::cmd("HGETALL")
        .arg(key)
        .query_async(raw)
        .await
        .expect("HGETALL")
}

async fn del(raw: &mut MultiplexedConnection, key: String) {
    let _: i64 = redis::cmd("DEL")
        .arg(key)
        .query_async(raw)
        .await
        .expect("DEL");
}

async fn run_indexes_drop_rows_the_server_expired_without_a_sweep(backend: Backend) {
    let (_node, stores, mut raw, ns) = common::stores_with_raw(backend).await;
    let user = UserId::new();
    // The long-lived session keeps both indexes alive past the short one's deadline.
    let first = session(user, "long-lived", Utc::now() + Duration::hours(1));
    let short = session(
        user,
        "short-lived",
        Utc::now() + Duration::milliseconds(300),
    );
    for s in [&first, &short] {
        stores
            .sessions
            .create_session(s.clone())
            .await
            .expect("create session");
    }
    let other = UserId::new();
    stores
        .passkey_challenges
        .put_registration(registration(
            other,
            Utc::now() + Duration::milliseconds(300),
        ))
        .await
        .expect("put a short-lived registration");

    tokio::time::sleep(StdDuration::from_millis(600)).await;

    let next = session(user, "next", Utc::now() + Duration::hours(1));
    stores
        .sessions
        .create_session(next.clone())
        .await
        .expect("create the next session");
    let live = vec![first.id.0.to_string(), next.id.0.to_string()];
    assert_eq!(
        zrange(
            &mut raw,
            common::key(&ns, &format!("user:{}:sessions", user.0))
        )
        .await,
        live,
        "the next write dropped the expired session from its owner's index",
    );
    assert_eq!(
        zrange(&mut raw, common::key(&ns, "deadline:sessions")).await,
        live,
        "the next write dropped the expired session from the deadline index",
    );
    for gone in [
        format!("user:{}:pkregs", other.0),
        "deadline:pkregs".to_owned(),
    ] {
        assert!(
            !exists(&mut raw, common::key(&ns, &gone)).await,
            "{gone} expired with its last row",
        );
    }
}

async fn run_a_sweep_takes_a_row_with_its_lookup_and_index_entries(backend: Backend) {
    let (_node, stores, mut raw, ns) = common::stores_with_raw(backend).await;
    let now = Utc::now();
    let user = UserId::new();
    let expiring = session(user, "swept", now + Duration::hours(1));
    let slid = session(user, "slid", now + Duration::hours(1));
    for s in [&expiring, &slid] {
        stores
            .sessions
            .create_session(s.clone())
            .await
            .expect("create session");
    }
    stores
        .sessions
        .touch_session(slid.id, now, now + Duration::hours(3))
        .await
        .expect("slide a session");

    assert_eq!(
        stores
            .sessions
            .purge_expired(now + Duration::hours(2))
            .await
            .expect("purge"),
        1,
        "only the session due at the sweep's clock went",
    );
    for gone in [
        format!("session:{}", expiring.id.0),
        format!("session:hash:{}", hex(&expiring.token_hash.0)),
    ] {
        assert!(!exists(&mut raw, common::key(&ns, &gone)).await, "{gone}");
    }
    let slid_id = slid.id.0.to_string();
    assert_eq!(
        zrange(
            &mut raw,
            common::key(&ns, &format!("user:{}:sessions", user.0))
        )
        .await,
        vec![slid_id.clone()],
    );
    assert_eq!(
        zrange(&mut raw, common::key(&ns, "deadline:sessions")).await,
        [slid_id],
    );
}

async fn run_a_vanished_row_is_skipped_and_its_lookup_dropped(backend: Backend) {
    let (_node, stores, mut raw, ns) = common::stores_with_raw(backend).await;
    let user = UserId::new();
    let evicted = session(user, "evicted", Utc::now() + Duration::hours(1));
    stores
        .sessions
        .create_session(evicted.clone())
        .await
        .expect("create session");
    del(
        &mut raw,
        common::key(&ns, &format!("session:{}", evicted.id.0)),
    )
    .await;

    assert!(
        stores
            .sessions
            .list_for_user(user)
            .await
            .expect("list")
            .is_empty(),
        "a session whose row is gone is not listed",
    );
    assert!(
        stores
            .sessions
            .find_session_by_token_hash(&evicted.token_hash)
            .await
            .expect("find by token hash")
            .is_none()
    );
    assert!(
        !exists(
            &mut raw,
            common::key(&ns, &format!("session:hash:{}", hex(&evicted.token_hash.0))),
        )
        .await,
        "the lookup naming a gone row was dropped",
    );
}

async fn run_a_link_leaves_its_owners_links_when_replaced_or_redeemed(backend: Backend) {
    let (_node, stores, mut raw, ns) = common::stores_with_raw(backend).await;
    let user = UserId::new();
    let owner_links = common::key(&ns, &format!("user:{}:email_links", user.0));
    let first = link(user, "first");
    let second = link(user, "second");
    for l in [&first, &second] {
        stores
            .email_links
            .replace_link(l.clone())
            .await
            .expect("replace link");
    }
    let second_id = hex(&second.token_hash.0);
    assert_eq!(
        hgetall(&mut raw, owner_links.clone()).await,
        [("signup".to_owned(), second_id.clone())],
    );
    assert_eq!(
        zrange(&mut raw, common::key(&ns, "deadline:email_links")).await,
        [second_id],
        "the replaced link left the deadline index",
    );

    stores
        .email_links
        .redeem_link(&second.token_hash)
        .await
        .expect("redeem")
        .expect("the link was there");
    assert!(
        !exists(&mut raw, owner_links).await,
        "the redeemed link left its owner's links",
    );
    assert!(
        !exists(&mut raw, common::key(&ns, "deadline:email_links")).await,
        "the redeemed link left the deadline index",
    );
}

async fn run_a_namespace_never_touches_another(backend: Backend) {
    let (_node, server) = common::start(backend).await;
    let base = format!("doorman-test:{}", uuid::Uuid::new_v4());
    let ours = server
        .confined_storage(&format!("{base}:app*"))
        .await
        .expiring();
    let theirs = server
        .confined_storage(&format!("{base}:app2"))
        .await
        .expiring();
    let user = UserId::new();
    let now = Utc::now();
    let their_session = session(user, "theirs", now + Duration::hours(1));
    theirs
        .sessions
        .create_session(their_session.clone())
        .await
        .expect("create their session");
    ours.sessions
        .create_session(session(user, "ours", now + Duration::hours(1)))
        .await
        .expect("create our session");

    let far_future = now + Duration::days(365);
    ours.sessions
        .purge_expired(far_future)
        .await
        .expect("purge");
    ours.email_links
        .purge_expired(far_future)
        .await
        .expect("purge");
    ours.passkey_challenges
        .purge_expired(far_future)
        .await
        .expect("purge");
    ours.sessions
        .delete_sessions_for_user(user, None)
        .await
        .expect("delete our sessions");

    assert_eq!(
        theirs.sessions.list_for_user(user).await.expect("list"),
        [their_session],
        "another namespace's session is still listed",
    );
    assert_eq!(
        theirs
            .sessions
            .delete_sessions_for_user(user, None)
            .await
            .expect("delete their sessions"),
        1,
        "another namespace's session is still found by its owner",
    );
}

#[tokio::test]
async fn redis_indexes_drop_rows_the_server_expired_without_a_sweep() {
    run_indexes_drop_rows_the_server_expired_without_a_sweep(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_indexes_drop_rows_the_server_expired_without_a_sweep() {
    run_indexes_drop_rows_the_server_expired_without_a_sweep(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_a_sweep_takes_a_row_with_its_lookup_and_index_entries() {
    run_a_sweep_takes_a_row_with_its_lookup_and_index_entries(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_a_sweep_takes_a_row_with_its_lookup_and_index_entries() {
    run_a_sweep_takes_a_row_with_its_lookup_and_index_entries(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_a_vanished_row_is_skipped_and_its_lookup_dropped() {
    run_a_vanished_row_is_skipped_and_its_lookup_dropped(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_a_vanished_row_is_skipped_and_its_lookup_dropped() {
    run_a_vanished_row_is_skipped_and_its_lookup_dropped(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_a_link_leaves_its_owners_links_when_replaced_or_redeemed() {
    run_a_link_leaves_its_owners_links_when_replaced_or_redeemed(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_a_link_leaves_its_owners_links_when_replaced_or_redeemed() {
    run_a_link_leaves_its_owners_links_when_replaced_or_redeemed(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_a_namespace_never_touches_another() {
    run_a_namespace_never_touches_another(Backend::Redis).await;
}

#[tokio::test]
async fn redis_cluster_a_namespace_never_touches_another() {
    run_a_namespace_never_touches_another(Backend::RedisCluster).await;
}
