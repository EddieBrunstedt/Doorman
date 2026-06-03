//! Verifies that the session-resolution cache wired in by the builder is
//! actually evicted when the framework-agnostic `SessionManager` revokes a
//! session (single revoke and bulk-by-user). This is the integration-side
//! coverage for the `SessionInvalidationHook` plumbing.
//!
//! Sessions are minted directly via the in-process `SessionManager`
//! ([`common::login`]) so the test focuses on cache invalidation rather
//! than on rerunning the signup ceremony. [`common::TestApp`] surfaces the
//! live, invalidation-hooked manager and the cache it feeds.

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{TestApp, login};
use doorman_core::session::hash_token;

async fn me(client: &reqwest::Client, app: &TestApp, token: &str) -> StatusCode {
    client
        .get(app.url("/me"))
        .bearer_auth(token)
        .send()
        .await
        .expect("me")
        .status()
}

#[tokio::test]
async fn revoke_invalidates_cache() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "alice@example.com").await;

    // First /me populates the cache.
    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);
    assert!(
        app.cache.get(&hash_token(&auth.token)).is_some(),
        "cache populated on first authenticated request"
    );

    // Revoke through the framework-agnostic manager — the cache should
    // see the invalidation hook fire and drop the entry.
    app.session_manager
        .revoke(&auth.token)
        .await
        .expect("revoke");
    assert!(
        app.cache.get(&hash_token(&auth.token)).is_none(),
        "revoke evicts the cached entry"
    );

    // And the wire reflects it: next request is 401, not 200 from a
    // stale cache.
    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::UNAUTHORIZED,
        "request after revoke is unauthorised, not a stale cache hit"
    );

    app.shutdown().await;
}

#[tokio::test]
async fn revoke_all_for_user_invalidates_cache() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let first = login(&client, &app, "bob@example.com").await;
    let second = login(&client, &app, "bob@example.com").await;

    assert_eq!(me(&client, &app, &first.token).await, StatusCode::OK);
    assert_eq!(me(&client, &app, &second.token).await, StatusCode::OK);
    assert!(app.cache.get(&hash_token(&first.token)).is_some());
    assert!(app.cache.get(&hash_token(&second.token)).is_some());

    // Bulk-revoke through the SessionManager.
    let removed = app
        .session_manager
        .revoke_all_for_user(first.user.id)
        .await
        .expect("revoke_all_for_user");
    assert_eq!(removed, 2);

    assert!(
        app.cache.get(&hash_token(&first.token)).is_none(),
        "bulk revoke evicts first session"
    );
    assert!(
        app.cache.get(&hash_token(&second.token)).is_none(),
        "bulk revoke evicts second session"
    );

    assert_eq!(
        me(&client, &app, &first.token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        me(&client, &app, &second.token).await,
        StatusCode::UNAUTHORIZED
    );

    app.shutdown().await;
}

#[tokio::test]
async fn cache_warms_on_first_authenticated_request() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "carol@example.com").await;
    let hash = hash_token(&auth.token);

    assert!(
        app.cache.get(&hash).is_none(),
        "direct session creation does not warm the cache"
    );

    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);
    assert!(
        app.cache.get(&hash).is_some(),
        "first /me populates the cache"
    );

    app.shutdown().await;
}
