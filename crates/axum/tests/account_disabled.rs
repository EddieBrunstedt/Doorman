//! Verifies the read-time disable gate in the session layer: a user whose
//! account status is `Disabled` can no longer authenticate a request, while an
//! active user is unaffected. Status is flipped directly through the store
//! (the operator `disable` flow that also invalidates the cache lands in a
//! later step), so the gate is exercised on a cold cache — the request is a
//! cache miss that resolves the now-disabled user and refuses it.

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{TestApp, login};
use doorman_core::audit::OperatorActor;
use doorman_core::session::hash_token;
use doorman_core::storage::AccountStatus;

fn operator() -> OperatorActor {
    OperatorActor::new("support-agent-7", None, None, None).expect("operator actor")
}

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
async fn disabled_user_is_refused_with_403() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "disabled@example.com").await;

    // Disable before the first authenticated request so the cache is never
    // warmed with the active snapshot: the request below is a cache miss that
    // hits the read-time gate.
    app.set_user_status(
        auth.user.id,
        AccountStatus::Disabled {
            at: chrono::Utc::now(),
        },
    )
    .await;

    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::FORBIDDEN,
        "a disabled account is refused, not served"
    );

    // The refusal happens before the cache insert, so a disabled user never
    // enters the cache.
    assert!(
        app.cache.get(&hash_token(&auth.token)).is_none(),
        "a disabled user is not cached"
    );

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_response_carries_stable_code() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "coded@example.com").await;
    app.set_user_status(
        auth.user.id,
        AccountStatus::Disabled {
            at: chrono::Utc::now(),
        },
    )
    .await;

    let response = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = response.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "account_disabled");

    app.shutdown().await;
}

#[tokio::test]
async fn active_user_is_unaffected() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "active@example.com").await;

    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::OK,
        "an active user still authenticates"
    );

    // Explicitly setting the status back to Active is a no-op for an
    // already-active user and must not change the outcome.
    app.set_user_status(auth.user.id, AccountStatus::Active)
        .await;
    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn operator_disable_locks_out_live_session_then_enable_restores() {
    // End-to-end through the real operator flow: `disable` flips the status,
    // revokes the live session, and fires the invalidation hook so the warm
    // cache is evicted. The very next authenticated request is refused (Step 2
    // auth gate), and `enable` lifts the freeze.
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "locked@example.com").await;

    // Warm the cache with an authenticated request so we prove `disable`
    // evicts it rather than relying on a cold miss.
    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::OK,
        "an active user authenticates and warms the cache",
    );
    assert!(
        app.cache.get(&hash_token(&auth.token)).is_some(),
        "the active session is cached",
    );

    app.operator
        .disable(auth.user.id, operator())
        .await
        .expect("operator disable");

    // The disable revoked the live session and evicted the cache, so the token
    // no longer authenticates.
    assert!(
        app.cache.get(&hash_token(&auth.token)).is_none(),
        "disable evicted the warm cache entry",
    );
    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::UNAUTHORIZED,
        "the revoked session no longer resolves after disable",
    );

    // Re-enable: the account is active again. The old token stays revoked, but
    // a fresh login authenticates, proving the gate was lifted.
    app.operator
        .enable(auth.user.id, operator())
        .await
        .expect("operator enable");

    let reauth = login(&client, &app, "locked@example.com").await;
    assert_eq!(
        me(&client, &app, &reauth.token).await,
        StatusCode::OK,
        "a re-enabled account can authenticate a fresh session",
    );

    app.shutdown().await;
}
