mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{TestApp, token_from_email_with};
use doorman_axum::dto::{AuthResponse, UserDto};

const EMAIL_CHANGE_URL: &str = "https://app.test/email-change?token={token}";

async fn login(client: &reqwest::Client, app: &TestApp, email: &str) -> AuthResponse {
    common::login(client, app, email).await
}

#[tokio::test]
async fn logout_all_revokes_every_session_and_clears_cookie() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let first = login(&client, &app, "ivy@example.com").await;
    let second = login(&client, &app, "ivy@example.com").await;

    let resp = client
        .post(app.url("/auth/logout-all"))
        .bearer_auth(&first.token)
        .send()
        .await
        .expect("logout-all");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("Set-Cookie present")
        .to_str()
        .expect("ascii cookie");
    assert!(set_cookie.contains("Max-Age=0"));

    for token in [&first.token, &second.token] {
        let stale = client
            .get(app.url("/me"))
            .bearer_auth(token)
            .send()
            .await
            .expect("me stale");
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    }

    app.shutdown().await;
}

#[tokio::test]
async fn logout_all_requires_authentication() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/logout-all"))
        .send()
        .await
        .expect("logout-all anon");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn email_change_request_confirm_updates_address() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let session = login(&client, &app, "before@example.com").await;
    let mail_before = app.email.sent().len();

    let resp = client
        .post(app.url("/auth/user/email"))
        .bearer_auth(&session.token)
        .json(&serde_json::json!({ "new_email": "after@example.com" }))
        .send()
        .await
        .expect("request email change");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    let new_mail = &sent[mail_before..];
    let confirmation = new_mail
        .iter()
        .find(|e| e.subject == "Confirm your new email address")
        .expect("confirmation email queued");
    assert_eq!(confirmation.to, "after@example.com");
    let token = token_from_email_with(&confirmation.body_text, EMAIL_CHANGE_URL);

    let confirm = client
        .post(app.url("/auth/user/email/confirm"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("confirm email change");
    assert_eq!(confirm.status(), StatusCode::OK);
    let user: UserDto = confirm.json().await.expect("confirm body");
    assert_eq!(user.email.as_deref(), Some("after@example.com"));
    assert!(user.email_verified, "confirming verifies the new address");

    app.shutdown().await;
}

#[tokio::test]
async fn email_change_to_taken_address_conflicts() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let session = login(&client, &app, "mover@example.com").await;
    let _ = login(&client, &app, "occupied@example.com").await;

    let resp = client
        .post(app.url("/auth/user/email"))
        .bearer_auth(&session.token)
        .json(&serde_json::json!({ "new_email": "occupied@example.com" }))
        .send()
        .await
        .expect("request email change");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "email_already_in_use");

    app.shutdown().await;
}

#[tokio::test]
async fn email_change_request_requires_authentication() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/user/email"))
        .json(&serde_json::json!({ "new_email": "x@example.com" }))
        .send()
        .await
        .expect("request anon");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn delete_user_revokes_session_and_clears_cookie() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let session = login(&client, &app, "gone@example.com").await;

    let resp = client
        .delete(app.url("/auth/user"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("delete user");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("Set-Cookie present")
        .to_str()
        .expect("ascii cookie");
    assert!(set_cookie.contains("Max-Age=0"));

    let stale = client
        .get(app.url("/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .expect("me stale");
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn delete_user_requires_authentication() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .delete(app.url("/auth/user"))
        .send()
        .await
        .expect("delete anon");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}
