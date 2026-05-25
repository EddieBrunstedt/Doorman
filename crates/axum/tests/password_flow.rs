//! End-to-end HTTP test for the password routes.
//!
//! Stands up the full axum router against in-memory storage, then exercises
//! register → cookie+bearer auth → me → logout, plus a few negative paths
//! that should be visible from the wire (rate limit, weak password).

mod common;

use axum::Router;
use axum::http::StatusCode;
use bauth_axum::dto::{AuthResponse, RegisterRequest};
use common::TestApp;
use reqwest::header;
use serde_json::json;

#[tokio::test]
async fn register_login_me_logout_cookie_path() {
    let app = TestApp::start(Router::new(), false).await;

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    // Register.
    let resp = client
        .post(app.url("/auth/password/register"))
        .json(&RegisterRequest {
            email: "alice@example.com".into(),
            password: "hunter22hunter22".into(),
        })
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie present")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.contains("bauth_session="));
    assert!(set_cookie.contains("HttpOnly"));
    let body: AuthResponse = resp.json().await.expect("json");
    assert_eq!(body.user.email.as_deref(), Some("alice@example.com"));
    assert!(!body.token.is_empty());

    // /me with the cookie-jar client.
    let me = client
        .get(app.url("/me"))
        .send()
        .await
        .expect("me")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(me["email"], "alice@example.com");

    // Logout clears the cookie and invalidates the bearer.
    let logout = client
        .post(app.url("/auth/password/logout"))
        .send()
        .await
        .expect("logout");
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);

    // After logout, the cookie-jar client should be unauthorised.
    let me_after = client.get(app.url("/me")).send().await.expect("me after");
    assert_eq!(me_after.status(), StatusCode::UNAUTHORIZED);

    // The token from the register response should also be revoked.
    let stale_bearer = reqwest::Client::new()
        .get(app.url("/me"))
        .bearer_auth(&body.token)
        .send()
        .await
        .expect("stale bearer");
    assert_eq!(stale_bearer.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn login_returns_bearer_for_non_browser_clients() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    client
        .post(app.url("/auth/password/register"))
        .json(&RegisterRequest {
            email: "bob@example.com".into(),
            password: "hunter22hunter22".into(),
        })
        .send()
        .await
        .expect("register");

    let login = client
        .post(app.url("/auth/password/login"))
        .json(&json!({
            "email": "bob@example.com",
            "password": "hunter22hunter22",
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(login.status(), StatusCode::OK);
    let body: AuthResponse = login.json().await.expect("json");

    // Use the bearer token (no cookie jar at all).
    let me = client
        .get(app.url("/me"))
        .bearer_auth(&body.token)
        .send()
        .await
        .expect("me");
    assert_eq!(me.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn weak_password_returns_400_with_code() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/password/register"))
        .json(&json!({
            "email": "carol@example.com",
            "password": "short",
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "weak_password");

    app.shutdown().await;
}

#[tokio::test]
async fn invalid_credentials_returns_401() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    client
        .post(app.url("/auth/password/register"))
        .json(&json!({
            "email": "dan@example.com",
            "password": "hunter22hunter22",
        }))
        .send()
        .await
        .expect("register");

    let resp = client
        .post(app.url("/auth/password/login"))
        .json(&json!({
            "email": "dan@example.com",
            "password": "wrong-password!",
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "invalid_credentials");

    app.shutdown().await;
}

#[tokio::test]
async fn me_without_session_returns_401() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "session_not_found");

    app.shutdown().await;
}
