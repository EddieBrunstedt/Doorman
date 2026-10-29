use crate::common;

use crate::common::{Backend, link, registration, session};
use chrono::{Duration, Utc};
use doorman_core::storage::UserId;
use doorman_redis::{ConnectError, EvictionPolicyError};

async fn run_a_server_that_may_evict_is_refused(backend: Backend) {
    let (_node, server) = common::start(backend).await;
    let namespace = common::namespace();
    let storage = server.confined_storage(&namespace).await;
    storage.ping().await.expect("noeviction passes the ping");

    server.config_set("maxmemory-policy", "volatile-lru").await;

    storage
        .ping()
        .await
        .expect_err("the ping notices the policy changed");
    let refused = server.connect_confined(&namespace, &[]).await;
    assert!(
        matches!(
            refused,
            Err(ConnectError::EvictionPolicy(EvictionPolicyError::Evicting { ref policy }))
                if policy == "volatile-lru"
        ),
        "{:?}",
        refused.err(),
    );
}

async fn run_a_user_who_cant_read_the_policy_is_refused(backend: Backend) {
    let (_node, server) = common::start(backend).await;
    let refused = server
        .connect_confined(&common::namespace(), &["info"])
        .await;
    assert!(
        matches!(
            refused,
            Err(ConnectError::EvictionPolicy(
                EvictionPolicyError::Unreadable(_)
            ))
        ),
        "{:?}",
        refused.err(),
    );
}

// What a disable deletes, once the server is too full to write.
async fn run_a_full_server_still_deletes_a_users_rows(backend: Backend) {
    let (_node, server) = common::start(backend).await;
    let stores = server
        .confined_storage(&common::namespace())
        .await
        .expiring();
    let user = UserId::new();
    let deadline = Utc::now() + Duration::hours(1);
    let live = session(user, "full-server", deadline);
    stores
        .sessions
        .create_session(live.clone())
        .await
        .expect("create session");
    stores
        .email_links
        .replace_link(link(user, "full-server-link"))
        .await
        .expect("issue link");
    stores
        .passkey_challenges
        .put_registration(registration(user, deadline))
        .await
        .expect("put registration");

    server.config_set("maxmemory", "1").await;

    stores
        .sessions
        .create_session(session(user, "refused", deadline))
        .await
        .expect_err("a full server refuses writes");
    assert_eq!(
        stores
            .sessions
            .delete_sessions_for_user(user, None)
            .await
            .expect("delete sessions"),
        1,
    );
    assert_eq!(
        stores
            .email_links
            .delete_links_for_user(user)
            .await
            .expect("delete links"),
        1,
    );
    assert_eq!(
        stores
            .passkey_challenges
            .delete_registrations_for_user(user)
            .await
            .expect("delete registrations"),
        1,
    );
    assert!(
        stores
            .sessions
            .find_session_by_token_hash(&live.token_hash)
            .await
            .expect("find session")
            .is_none(),
    );
}

#[tokio::test]
async fn redis_a_server_that_may_evict_is_refused() {
    run_a_server_that_may_evict_is_refused(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_a_server_that_may_evict_is_refused() {
    run_a_server_that_may_evict_is_refused(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_cluster_a_server_that_may_evict_is_refused() {
    run_a_server_that_may_evict_is_refused(Backend::RedisCluster).await;
}

#[tokio::test]
async fn valkey_cluster_a_server_that_may_evict_is_refused() {
    run_a_server_that_may_evict_is_refused(Backend::ValkeyCluster).await;
}

#[tokio::test]
async fn redis_a_user_who_cant_read_the_policy_is_refused() {
    run_a_user_who_cant_read_the_policy_is_refused(Backend::Redis).await;
}

#[tokio::test]
async fn redis_cluster_a_user_who_cant_read_the_policy_is_refused() {
    run_a_user_who_cant_read_the_policy_is_refused(Backend::RedisCluster).await;
}

#[tokio::test]
async fn redis_a_full_server_still_deletes_a_users_rows() {
    run_a_full_server_still_deletes_a_users_rows(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_a_full_server_still_deletes_a_users_rows() {
    run_a_full_server_still_deletes_a_users_rows(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_cluster_a_full_server_still_deletes_a_users_rows() {
    run_a_full_server_still_deletes_a_users_rows(Backend::RedisCluster).await;
}
