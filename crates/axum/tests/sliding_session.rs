mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::Router;
use axum::http::StatusCode;
use axum::http::header::SET_COOKIE;
use chrono::{Duration as ChronoDuration, Utc};
use common::TestApp;
use doorman_axum::config::CookieConfig;
use doorman_core::clock::Clock;
use doorman_core::session::SessionConfig;
use doorman_test_support::MockClock;

const IDLE: StdDuration = StdDuration::from_secs(60 * 60);

async fn sliding_app(clock: Arc<MockClock>) -> TestApp {
    TestApp::start_configured(
        Router::new(),
        false,
        move |b| {
            b.clock(clock as Arc<dyn Clock>).session(SessionConfig {
                absolute_lifetime: StdDuration::from_secs(60 * 60 * 24),
                idle_timeout: Some(IDLE),
                max_sessions_per_user: None,
            })
        },
        |b| {
            b.cookie(CookieConfig {
                secure: false,
                session_max_age: IDLE,
                ..CookieConfig::default()
            })
        },
    )
    .await
}

async fn me_with_cookie(client: &reqwest::Client, app: &TestApp, token: &str) -> reqwest::Response {
    client
        .get(app.url("/me"))
        .header("Cookie", format!("doorman_session={token}"))
        .send()
        .await
        .expect("cookie request")
}

#[tokio::test]
async fn slid_cookie_session_gets_a_refreshed_cookie() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app = sliding_app(clock.clone()).await;
    let client = reqwest::Client::new();
    let session = common::login(&client, &app, "alice@example.com").await;

    clock.advance(ChronoDuration::minutes(2));
    let resp = me_with_cookie(&client, &app, &session.token).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let set_cookie = resp
        .headers()
        .get(SET_COOKIE)
        .expect("a slid cookie-sourced session refreshes the cookie")
        .to_str()
        .expect("ascii cookie");
    assert!(
        set_cookie.contains(&format!("doorman_session={}", session.token)),
        "the refreshed cookie re-issues the session token, got: {set_cookie}",
    );
    assert!(
        set_cookie.contains(&format!("Max-Age={}", IDLE.as_secs())),
        "the refreshed Max-Age tracks the slid deadline, got: {set_cookie}",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn unslid_request_sets_no_cookie() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app = sliding_app(clock).await;
    let client = reqwest::Client::new();
    let session = common::login(&client, &app, "carol@example.com").await;

    let resp = me_with_cookie(&client, &app, &session.token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(SET_COOKIE).is_none(),
        "no slide, no cookie refresh",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn slid_bearer_session_gets_no_cookie() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app = sliding_app(clock.clone()).await;
    let client = reqwest::Client::new();
    let session = common::login(&client, &app, "bob@example.com").await;

    clock.advance(ChronoDuration::minutes(2));
    let resp = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("bearer request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(SET_COOKIE).is_none(),
        "bearer clients track expiry themselves",
    );

    app.shutdown().await;
}
