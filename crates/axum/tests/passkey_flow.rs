mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{SignupClient, TestApp};
use doorman_axum::dto::PasskeyDto;
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

#[tokio::test]
async fn rename_passkey_updates_name_over_http() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let mut signup = SignupClient::new(&app);
    let auth = signup.signup(&client, &app, "rename@example.com").await;
    let bearer = auth.token;

    let list: Vec<PasskeyDto> = client
        .get(app.url("/auth/passkey"))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("list passkeys")
        .json()
        .await
        .expect("list body");
    assert_eq!(list.len(), 1);
    let credential_id = list[0].credential_id.clone();

    let response = client
        .patch(app.url(&format!("/auth/passkey/{credential_id}")))
        .bearer_auth(&bearer)
        .json(&serde_json::json!({ "name": "My Laptop" }))
        .send()
        .await
        .expect("rename passkey");
    assert_eq!(response.status(), StatusCode::OK);
    let updated: PasskeyDto = response.json().await.expect("rename body");
    assert_eq!(updated.credential_id, credential_id);
    assert_eq!(updated.name.as_deref(), Some("My Laptop"));

    let list: Vec<PasskeyDto> = client
        .get(app.url("/auth/passkey"))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("list passkeys again")
        .json()
        .await
        .expect("list body");
    assert_eq!(list[0].name.as_deref(), Some("My Laptop"));

    app.shutdown().await;
}

#[tokio::test]
async fn rename_passkey_requires_authentication() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let response = client
        .patch(app.url("/auth/passkey/some-passkey-id"))
        .json(&serde_json::json!({ "name": "nope" }))
        .send()
        .await
        .expect("rename without auth");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}
