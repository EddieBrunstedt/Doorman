mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use common::{TestApp, login};
use doorman_core::metrics::{MetricEvent, MetricSink};
use doorman_test_support::CapturingMetrics;

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
async fn session_layer_records_cache_miss_then_hit() {
    let metrics = Arc::new(CapturingMetrics::new());
    let metrics_for_app = metrics.clone();
    let app = TestApp::start_with(Router::new(), false, move |b| {
        b.metrics(metrics_for_app as Arc<dyn MetricSink>)
    })
    .await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "alice@example.com").await;

    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);
    assert_eq!(
        metrics.count(MetricEvent::CacheMiss),
        1,
        "one miss recorded"
    );
    assert_eq!(metrics.count(MetricEvent::CacheHit), 0, "no hit yet");

    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);
    assert_eq!(
        metrics.count(MetricEvent::CacheHit),
        1,
        "second request is a cache hit"
    );
    assert_eq!(
        metrics.count(MetricEvent::CacheMiss),
        1,
        "miss count unchanged on the hit"
    );

    app.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_request_records_no_cache_observation() {
    let metrics = Arc::new(CapturingMetrics::new());
    let metrics_for_app = metrics.clone();
    let app = TestApp::start_with(Router::new(), false, move |b| {
        b.metrics(metrics_for_app as Arc<dyn MetricSink>)
    })
    .await;
    let client = reqwest::Client::new();

    assert_eq!(
        client
            .get(app.url("/me"))
            .send()
            .await
            .expect("me")
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(metrics.count(MetricEvent::CacheHit), 0);
    assert_eq!(metrics.count(MetricEvent::CacheMiss), 0);

    app.shutdown().await;
}
