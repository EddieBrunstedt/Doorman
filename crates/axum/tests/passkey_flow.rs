//! End-to-end HTTP test for the passkey authentication-start route.

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::TestApp;
use serde_json::Value;

#[tokio::test]
async fn authenticate_start_accepts_empty_body_and_returns_discoverable_options() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let response = client
        .post(app.url("/auth/passkey/authenticate/start"))
        .send()
        .await
        .expect("request authenticate start");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.json::<Value>().await.expect("json body");
    assert!(body["challenge_id"].as_str().is_some());
    assert_eq!(
        body["options"]["publicKey"]["allowCredentials"]
            .as_array()
            .expect("allowCredentials array")
            .len(),
        0
    );

    app.shutdown().await;
}
