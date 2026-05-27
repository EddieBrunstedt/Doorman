//! Quickstart builder smoke test.
//!
//! Drives the three-step signup flow end-to-end through the `quickstart`
//! wiring path. Validates that the quickstart-built app produces a working
//! session cookie, a working bearer token, and that the resulting session
//! resolves through the session layer on a host route.

mod common;

use axum::Router;
use bauth_axum::dto::AuthResponse;
use common::{SignupClient, TestApp};

#[tokio::test]
async fn quickstart_signup_and_me() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let auth: AuthResponse = SignupClient::new(&app)
        .signup(&client, &app, "alice@example.com")
        .await;
    assert_eq!(auth.user.email.as_deref(), Some("alice@example.com"));
    assert!(auth.user.email_verified);
    assert!(!auth.token.is_empty());

    // Cookie-based call: the SignupClient used cookie_store, so the
    // Set-Cookie from /signup/finish should be replayed automatically.
    let me_cookie = client
        .get(app.url("/me"))
        .send()
        .await
        .expect("me cookie")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(me_cookie["email"], "alice@example.com");

    // Bearer-based call against a fresh client (no cookies).
    let bearer = reqwest::Client::new();
    let me_bearer = bearer
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me bearer");
    assert_eq!(me_bearer.status(), reqwest::StatusCode::OK);

    app.shutdown().await;
}
