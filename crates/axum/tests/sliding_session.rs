//! HTTP coverage for the sliding-renewal / idle-expiry feature: the cache-hit
//! expiry re-check (cache rule #2) and the cookie refresh on a sliding response
//! (cache rule #3). Both run on in-memory storage; no Docker is needed.

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

/// Cache rule #2: a still-warm cache entry whose effective deadline has passed
/// is treated as a miss, so an expired session is never served from cache.
///
/// The first request warms the cache. Advancing the injected clock past the
/// session's absolute lifetime makes the cached snapshot's `expires_at` lie in
/// the past while the cache TTL (real-time, default 60s) keeps the entry warm.
/// If the in-memory re-check were missing, the warm entry would authenticate
/// the second request (200); with it, the entry is dropped, the fall-through
/// re-resolve finds the storage row likewise expired, and the request is 401.
#[tokio::test]
async fn cache_hit_serving_an_expired_snapshot_is_rejected() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    // Use the default (non-zero) cache TTL so the warmed entry stays warm
    // across both requests — `start_with_clock` would zero the TTL and evict
    // the entry for the wrong reason, masking the re-check under test.
    let app = TestApp::start_with(Router::new(), false, {
        let clock = clock.clone();
        move |b| b.clock(clock.clone() as Arc<dyn Clock>)
    })
    .await;
    let client = reqwest::Client::new();

    let session = common::login(&client, &app, "alice@example.com").await;

    // Warm the cache with a live snapshot.
    let warmed = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("warm request");
    assert_eq!(
        warmed.status(),
        StatusCode::OK,
        "live session authenticates"
    );
    assert!(
        app.cache
            .get(&doorman_core::session::hash_token(&session.token))
            .is_some(),
        "first authenticated request warms the cache",
    );

    // Jump past the 30-day default absolute lifetime: the cached snapshot's
    // `expires_at` is now in the past, but the cache TTL has not lapsed.
    clock.advance(ChronoDuration::days(30) + ChronoDuration::seconds(1));

    let after = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("post-expiry request");
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "an expired cached snapshot is rejected, not served from the warm entry",
    );

    app.shutdown().await;
}

/// Build an app with sliding enabled (idle window comfortably above the cache
/// TTL) and a cookie `Max-Age` no larger than the idle window so the build-time
/// cookie invariant holds.
async fn sliding_app() -> TestApp {
    TestApp::start_with(Router::new(), false, |b| {
        b.session(SessionConfig {
            absolute_lifetime: StdDuration::from_secs(60 * 60 * 24),
            idle_timeout: Some(StdDuration::from_secs(60 * 60)),
            max_sessions_per_user: None,
        })
        .cookie(CookieConfig {
            secure: false,
            session_max_age: StdDuration::from_secs(60 * 60),
            ..CookieConfig::default()
        })
    })
    .await
}

/// Cache rule #3: on a sliding response (idle window configured) a refreshed
/// `Set-Cookie` for the session cookie is emitted for a cookie-sourced token so
/// the browser's expiry tracks the slid server deadline. The cache is cold
/// after `login` mints directly, so the first request is a miss that slides.
#[tokio::test]
async fn sliding_response_refreshes_the_session_cookie_for_cookie_clients() {
    let app = sliding_app().await;
    let client = reqwest::Client::new();
    let session = common::login(&client, &app, "alice@example.com").await;

    let resp = client
        .get(app.url("/me"))
        .header("Cookie", format!("doorman_session={}", session.token))
        .send()
        .await
        .expect("cookie request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "cookie session authenticates"
    );

    let set_cookie = resp
        .headers()
        .get(SET_COOKIE)
        .expect("a sliding cookie-sourced response refreshes the session cookie")
        .to_str()
        .expect("ascii cookie");
    assert!(
        set_cookie.contains("doorman_session="),
        "the refreshed cookie names the session cookie, got: {set_cookie}",
    );
    assert!(
        set_cookie.contains("Max-Age="),
        "the refreshed cookie carries a Max-Age tracking the slid deadline, got: {set_cookie}",
    );

    app.shutdown().await;
}

/// The converse of the rule above: a bearer-sourced token gets no `Set-Cookie`
/// even when sliding is on — bearer clients track expiry themselves.
#[tokio::test]
async fn sliding_response_does_not_refresh_a_cookie_for_bearer_clients() {
    let app = sliding_app().await;
    let client = reqwest::Client::new();
    let session = common::login(&client, &app, "bob@example.com").await;

    let resp = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("bearer request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "bearer session authenticates"
    );
    assert!(
        resp.headers().get(SET_COOKIE).is_none(),
        "a bearer-sourced token must not trigger a session-cookie refresh",
    );

    app.shutdown().await;
}
