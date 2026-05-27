//! HTTP tests for the `/auth/sessions` management endpoints.

mod common;

use axum::Router;
use axum::http::StatusCode;
use bauth_axum::dto::{AuthResponse, MagicLinkConsumeRequest, RequestMagicLinkRequest, SessionDto};
use common::{TestApp, token_from_email};

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

    // Hit the list endpoint with the second session's bearer token; expect
    // exactly that one to be flagged is_current.
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
async fn list_sessions_exposes_ip_and_user_agent() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    // Drive the magic-link flow supplying an X-Forwarded-For + User-Agent so
    // the recorded SessionContext is non-empty.
    let resp = client
        .post(app.url("/auth/magic-link/request"))
        .header("x-forwarded-for", "203.0.113.5")
        .header(reqwest::header::USER_AGENT, "test-agent/1.0")
        .json(&RequestMagicLinkRequest {
            email: "carol@example.com".into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    let token = token_from_email(&sent.last().expect("email").body_text);

    let consume = client
        .post(app.url("/auth/magic-link/consume"))
        .header("x-forwarded-for", "203.0.113.5")
        .header(reqwest::header::USER_AGENT, "test-agent/1.0")
        .json(&MagicLinkConsumeRequest { token })
        .send()
        .await
        .expect("consume");
    assert_eq!(consume.status(), StatusCode::OK);
    let issued: AuthResponse = consume.json().await.expect("body");

    let sessions: Vec<SessionDto> = client
        .get(app.url("/auth/sessions"))
        .bearer_auth(&issued.token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("list body");

    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(sessions[0].user_agent.as_deref(), Some("test-agent/1.0"));
    assert!(sessions[0].is_current);

    app.shutdown().await;
}

#[tokio::test]
async fn delete_session_revokes_target_and_leaves_caller_authenticated() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let caller = login(&client, &app, "dan@example.com").await;
    let other = login(&client, &app, "dan@example.com").await;

    // Caller revokes the other session.
    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", other.session.id)))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Caller's session still works.
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

    // Other session is no longer authenticated.
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
async fn delete_session_owned_by_another_user_returns_session_not_found() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let alice = login(&client, &app, "alice@example.com").await;
    let bob = login(&client, &app, "bob@example.com").await;

    // Alice tries to delete Bob's session by id.
    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", bob.session.id)))
        .bearer_auth(&alice.token)
        .send()
        .await
        .expect("delete cross-user");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "session_not_found");

    // Bob's session is intact.
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
