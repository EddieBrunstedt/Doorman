mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use common::TestApp;
use doorman_core::clock::Clock;
use doorman_test_support::MockClock;

#[tokio::test]
async fn authenticated_request_is_rejected_once_the_session_lifetime_elapses() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app =
        TestApp::start_with_clock(Router::new(), false, clock.clone() as Arc<dyn Clock>).await;
    let client = reqwest::Client::new();

    let session = common::login(&client, &app, "alice@example.com").await;

    let before = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("me before expiry");
    assert_eq!(
        before.status(),
        StatusCode::OK,
        "the freshly minted session authenticates"
    );

    clock.advance(ChronoDuration::days(30) + ChronoDuration::seconds(1));

    let after = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("me after expiry");
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "the session no longer authenticates once its lifetime has elapsed"
    );
    let body: serde_json::Value = after.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "session_not_found");

    app.shutdown().await;
}
