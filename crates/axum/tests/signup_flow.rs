//! End-to-end HTTP tests for the signup routes.
//!
//! Exercises the quickstart wiring path so the test covers manager
//! construction, route mounting, email delivery, the passkey ceremony at
//! consume / finish time, session cookie issuance, and the session layer
//! loading the newly issued session.

mod common;

use axum::Router;
use axum::http::StatusCode;
use bauth_axum::dto::{AuthResponse, SignupConsumeRequest, SignupRequest};
use common::{SignupClient, TestApp, token_from_email};
use reqwest::header;

#[tokio::test]
async fn full_signup_round_trip_cookie_path() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let auth: AuthResponse = SignupClient::new(&app)
        .signup(&client, &app, "Alice@Example.com")
        .await;

    let sent = app.email.sent();
    assert_eq!(sent.len(), 1, "one signup email queued");
    assert_eq!(sent[0].to, "alice@example.com");
    assert_eq!(sent[0].subject, "Finish setting up your account");

    assert_eq!(auth.user.email.as_deref(), Some("alice@example.com"));
    assert!(auth.user.email_verified);
    assert!(!auth.token.is_empty());

    // Cookie-based call: the SignupClient used a cookie store, so the
    // Set-Cookie from /signup/finish replays automatically.
    let me = client
        .get(app.url("/me"))
        .send()
        .await
        .expect("me cookie")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(me["email"], "alice@example.com");

    // Bearer-based call against a fresh client (no cookies).
    let bearer_only = reqwest::Client::new();
    let bearer = bearer_only
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("bearer me");
    assert_eq!(bearer.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn signup_request_for_existing_email_is_silent() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    // First request creates the user record.
    let initial = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("first request");
    assert_eq!(initial.status(), StatusCode::NO_CONTENT);
    assert_eq!(app.email.sent().len(), 1, "first request sent one email");

    // Second request: same email → silent, no new email.
    let again = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("second request");
    assert_eq!(
        again.status(),
        StatusCode::NO_CONTENT,
        "response is identical for already-registered email",
    );
    assert_eq!(
        app.email.sent().len(),
        1,
        "no second email queued for already-registered email",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn consume_with_invalid_token_returns_400_with_code() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/signup/consume"))
        .json(&SignupConsumeRequest {
            token: "not-a-real-token".into(),
        })
        .send()
        .await
        .expect("consume");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "invalid_verification_token");

    app.shutdown().await;
}

#[tokio::test]
async fn request_rejects_invalid_email_with_code() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "not-an-email".into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "invalid_email");

    app.shutdown().await;
}

#[tokio::test]
async fn consume_replay_is_rejected() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    // Fresh request → grab the token but only consume it once via the
    // full flow; the second attempt should fail because consume deletes
    // the token atomically.
    let resp = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "replay@example.com".into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let token = token_from_email(&app.email.sent()[0].body_text);

    let first = client
        .post(app.url("/auth/signup/consume"))
        .json(&SignupConsumeRequest {
            token: token.clone(),
        })
        .send()
        .await
        .expect("first consume");
    assert_eq!(first.status(), StatusCode::OK);

    let second = client
        .post(app.url("/auth/signup/consume"))
        .json(&SignupConsumeRequest { token })
        .send()
        .await
        .expect("second consume");
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = second.json().await.expect("body");
    assert_eq!(body["error"]["code"], "invalid_verification_token");

    app.shutdown().await;
}

#[tokio::test]
async fn signup_finish_emits_set_cookie() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let mut signup = SignupClient::new(&app);
    let _: AuthResponse = signup.signup(&client, &app, "cookie@example.com").await;

    // The cookie store on `client` is off, but a follow-up cookie-aware
    // client should be able to obtain a Set-Cookie too — re-running signup
    // for a fresh user via a cookie-bearing client gives us the header.
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");
    let mut signup_cookie = SignupClient::new(&app);
    let _ = signup_cookie
        .signup(&cookie_client, &app, "cookie2@example.com")
        .await;
    let me = cookie_client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(me.status(), StatusCode::OK);
    // Sanity-check the header constant stays imported.
    let _ = header::SET_COOKIE;

    app.shutdown().await;
}
