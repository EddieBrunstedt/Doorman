mod common;

use axum::Router;
use axum::http::StatusCode;
use common::TestApp;
use doorman_axum::dto::{AuthResponse, SessionDto};

const OTHER_SESSION_REVOKED_NOTICE_SUBJECT: &str = "Security notice: session revoked";
const OTHER_SESSIONS_REVOKED_NOTICE_SUBJECT: &str = "Security notice: other sessions revoked";

async fn login(client: &reqwest::Client, app: &TestApp, email: &str) -> AuthResponse {
    common::login(client, app, email).await
}

#[tokio::test]
async fn list_sessions_marks_caller_session_as_current() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let first = login(&client, &app, "alice@example.com").await;
    let second = login(&client, &app, "alice@example.com").await;
    let third = login(&client, &app, "alice@example.com").await;

    let resp = client
        .get(app.url("/auth/sessions"))
        .bearer_auth(&second.token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), StatusCode::OK);
    let sessions: Vec<SessionDto> = resp.json().await.expect("list body");
    assert_eq!(sessions.len(), 3, "all three active sessions are returned");

    let current: Vec<_> = sessions.iter().filter(|s| s.is_current).collect();
    assert_eq!(current.len(), 1, "exactly one session is marked current");
    assert_eq!(
        current[0].id, second.session.id,
        "the caller's session is the current one"
    );

    let ids: std::collections::HashSet<_> = sessions.iter().map(|s| s.id).collect();
    assert!(ids.contains(&first.session.id));
    assert!(ids.contains(&second.session.id));
    assert!(ids.contains(&third.session.id));

    app.shutdown().await;
}

#[tokio::test]
async fn delete_session_revokes_target_and_leaves_caller_authenticated() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let caller = login(&client, &app, "dan@example.com").await;
    let other = login(&client, &app, "dan@example.com").await;

    let mail_before = app.email.sent().len();
    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", other.session.id)))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    let new_mail = &sent[mail_before..];
    assert_eq!(new_mail.len(), 1, "revocation notice queued");
    assert_eq!(new_mail[0].subject, OTHER_SESSION_REVOKED_NOTICE_SUBJECT);
    assert_eq!(new_mail[0].to, "dan@example.com");

    let mine = client
        .get(app.url("/auth/sessions"))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("list");
    assert_eq!(mine.status(), StatusCode::OK);
    let after: Vec<SessionDto> = mine.json().await.expect("list body");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, caller.session.id);

    let stale = client
        .get(app.url("/me"))
        .bearer_auth(&other.token)
        .send()
        .await
        .expect("me stale");
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn delete_sessions_revokes_other_sessions_and_sends_notice() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let caller = login(&client, &app, "frank@example.com").await;
    let other = login(&client, &app, "frank@example.com").await;
    let third = login(&client, &app, "frank@example.com").await;

    let mail_before = app.email.sent().len();
    let resp = client
        .delete(app.url("/auth/sessions"))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("delete others");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    let new_mail = &sent[mail_before..];
    assert_eq!(new_mail.len(), 1, "bulk revocation notice queued");
    assert_eq!(new_mail[0].subject, OTHER_SESSIONS_REVOKED_NOTICE_SUBJECT);
    assert_eq!(new_mail[0].to, "frank@example.com");

    let mine = client
        .get(app.url("/auth/sessions"))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("list");
    assert_eq!(mine.status(), StatusCode::OK);
    let after: Vec<SessionDto> = mine.json().await.expect("list body");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, caller.session.id);

    for stale_token in [&other.token, &third.token] {
        let stale = client
            .get(app.url("/me"))
            .bearer_auth(stale_token)
            .send()
            .await
            .expect("me stale");
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    }

    app.shutdown().await;
}

#[tokio::test]
async fn delete_current_session_does_not_send_notice() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let caller = login(&client, &app, "grace@example.com").await;
    let mail_before = app.email.sent().len();

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", caller.session.id)))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("delete self");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        app.email.sent().len(),
        mail_before,
        "self-revoke sends no security notice"
    );

    let stale = client
        .get(app.url("/me"))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("me stale");
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn session_revocation_notice_failure_does_not_undo_revocation() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let caller = login(&client, &app, "heidi@example.com").await;
    let other = login(&client, &app, "heidi@example.com").await;
    app.email.fail_after_successful_sends(0);

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", other.session.id)))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("delete other");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        app.email.sent().is_empty(),
        "configured send failure captured no mail"
    );

    let stale = client
        .get(app.url("/me"))
        .bearer_auth(&other.token)
        .send()
        .await
        .expect("me stale");
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn logout_revokes_current_session_and_clears_cookie() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let caller = login(&client, &app, "erin@example.com").await;
    let mail_before = app.email.sent().len();

    let resp = client
        .post(app.url("/auth/logout"))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("Set-Cookie present")
        .to_str()
        .expect("ascii cookie");
    assert!(set_cookie.contains("doorman_session="));
    assert!(set_cookie.contains("Max-Age=0"));
    assert_eq!(
        app.email.sent().len(),
        mail_before,
        "self-logout sends no security notice"
    );

    let stale = client
        .get(app.url("/me"))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("me stale");
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn logout_requires_authentication() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/logout"))
        .send()
        .await
        .expect("logout anon");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "session_not_found");

    app.shutdown().await;
}

#[tokio::test]
async fn delete_session_owned_by_another_user_returns_session_not_found() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let alice = login(&client, &app, "alice@example.com").await;
    let bob = login(&client, &app, "bob@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", bob.session.id)))
        .bearer_auth(&alice.token)
        .send()
        .await
        .expect("delete cross-user");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "session_not_found");

    let bobs = client
        .get(app.url("/me"))
        .bearer_auth(&bob.token)
        .send()
        .await
        .expect("bob me");
    assert_eq!(bobs.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn list_sessions_requires_authentication() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(app.url("/auth/sessions"))
        .send()
        .await
        .expect("list anon");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "session_not_found");

    app.shutdown().await;
}

#[tokio::test]
async fn delete_session_with_malformed_id_returns_session_not_found() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let alice = login(&client, &app, "alice@example.com").await;

    let resp = client
        .delete(app.url("/auth/sessions/not-a-uuid"))
        .bearer_auth(&alice.token)
        .send()
        .await
        .expect("delete malformed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "session_not_found");

    app.shutdown().await;
}
