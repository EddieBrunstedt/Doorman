//! End-to-end HTTP tests for the signup routes.
//!
//! Exercises the high-level builder wiring path so the test covers manager
//! construction, route mounting, email delivery, the passkey ceremony at
//! consume / finish time, session cookie issuance, and the session layer
//! loading the newly issued session.

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::http::StatusCode;
use common::{SIGNUP_URL, SignupClient, TestApp, token_from_email};
use doorman_axum::dto::{AuthResponse, SignupConsumeRequest, SignupRequest};
use doorman_core::error::Result;
use doorman_core::session::SessionContext;
use doorman_core::signup::{SignupConfig, SignupDecision, SignupPolicy, SignupRateLimits};
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
    assert_eq!(sent.len(), 2, "signup link + passkey notification queued");
    let subjects: Vec<&str> = sent.iter().map(|e| e.subject.as_str()).collect();
    let signup_email = sent
        .iter()
        .find(|e| e.subject == "Finish setting up your account")
        .expect("signup email queued");
    let passkey_notification = sent
        .iter()
        .find(|e| e.subject == "Security notice: passkey registered")
        .expect("passkey notification queued");
    assert!(
        subjects.contains(&"Finish setting up your account")
            && subjects.contains(&"Security notice: passkey registered")
    );
    assert_eq!(signup_email.to, "alice@example.com");
    assert!(passkey_notification.body_text.contains("test device"));

    assert_eq!(auth.user.email.as_deref(), Some("alice@example.com"));
    assert!(auth.user.email_verified);
    assert_eq!(
        auth.user.passkey_count, 1,
        "freshly-registered user owns exactly the passkey just enrolled"
    );
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
async fn signup_request_for_credentialed_email_is_silent() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    // Full signup leaves the user with a passkey on their account.
    SignupClient::new(&app)
        .signup(&cookie_client, &app, "alice@example.com")
        .await;
    let emails_before = app.email.sent().len();

    // Second request for the now-credentialed email → silent, no new email.
    let again = reqwest::Client::new()
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
            invite_token: None,
        })
        .send()
        .await
        .expect("second request");
    assert_eq!(
        again.status(),
        StatusCode::NO_CONTENT,
        "response is identical for an already-registered email",
    );
    assert_eq!(
        app.email.sent().len(),
        emails_before,
        "no email queued for an already-credentialed email",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn signup_request_for_passkeyless_user_reissues_link() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    // First request creates the user record but no passkey is enrolled, so the
    // account holds zero credentials.
    let initial = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
            invite_token: None,
        })
        .send()
        .await
        .expect("first request");
    assert_eq!(initial.status(), StatusCode::NO_CONTENT);
    assert_eq!(app.email.sent().len(), 1, "first request sent one email");

    // Second request: the passkey-less account gets a fresh link rather than a
    // silent no-op, while the response shape stays identical (204).
    let again = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
            invite_token: None,
        })
        .send()
        .await
        .expect("second request");
    assert_eq!(again.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        app.email.sent().len(),
        2,
        "fresh link re-sent to the passkey-less user",
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
            invite_token: None,
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
            invite_token: None,
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
async fn passkey_count_reflects_register_and_delete() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    // Signup leaves the user with exactly one passkey on their account.
    let mut primary = SignupClient::new(&app);
    let auth: AuthResponse = primary.signup(&client, &app, "count@example.com").await;
    assert_eq!(auth.user.passkey_count, 1);

    let me_after_signup = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me after signup")
        .json::<serde_json::Value>()
        .await
        .expect("me json");
    assert_eq!(me_after_signup["passkey_count"], 1);

    // A fresh SoftPasskey enrols a distinct credential against the same
    // authenticated session, so the count climbs to two.
    let mail_before_backup = app.email.sent().len();
    let mut backup = SignupClient::new(&app);
    let backup_passkey = backup
        .register_additional_passkey(&client, &app, &auth.token)
        .await;
    let sent = app.email.sent();
    let backup_mail = &sent[mail_before_backup..];
    assert_eq!(backup_mail.len(), 1, "backup passkey notification queued");
    assert_eq!(
        backup_mail[0].subject,
        "Security notice: passkey registered"
    );
    assert!(backup_mail[0].body_text.contains("backup device"));

    let me_after_backup = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me after backup")
        .json::<serde_json::Value>()
        .await
        .expect("me json");
    assert_eq!(me_after_backup["passkey_count"], 2);

    // Deleting the backup credential drops the count back to one.
    let delete = client
        .delete(app.url(&format!("/auth/passkey/{}", backup_passkey.credential_id)))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete passkey");
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let me_after_delete = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me after delete")
        .json::<serde_json::Value>()
        .await
        .expect("me json");
    assert_eq!(me_after_delete["passkey_count"], 1);

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

// ---------------------------------------------------------------------------
// Signup gating policy (HTTP surface)
// ---------------------------------------------------------------------------

enum StubOutcome {
    DenySilently,
    Deny,
}

/// Test [`SignupPolicy`] returning a preset decision and recording the
/// invite token doorman handed it, so the HTTP tests can assert both the
/// wire-level denial behavior and the verbatim token pass-through.
struct StubPolicy {
    outcome: StubOutcome,
    tokens: Mutex<Vec<Option<String>>>,
}

impl StubPolicy {
    fn new(outcome: StubOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            tokens: Mutex::new(Vec::new()),
        })
    }

    fn tokens(&self) -> Vec<Option<String>> {
        self.tokens.lock().expect("policy tokens lock").clone()
    }
}

#[async_trait]
impl SignupPolicy for StubPolicy {
    async fn evaluate(
        &self,
        _email: &str,
        invite_token: Option<&str>,
        _context: &SessionContext,
    ) -> Result<SignupDecision> {
        self.tokens
            .lock()
            .expect("policy tokens lock")
            .push(invite_token.map(ToOwned::to_owned));
        match self.outcome {
            StubOutcome::DenySilently => Ok(SignupDecision::DenySilently),
            StubOutcome::Deny => Ok(SignupDecision::Deny {
                reason: Some("no invite".into()),
            }),
        }
    }
}

async fn app_with_policy(policy: Arc<StubPolicy>) -> TestApp {
    TestApp::start_with(Router::new(), false, move |b| {
        b.signup(SignupConfig {
            url_template: SIGNUP_URL.to_string(),
            rate_limits: SignupRateLimits::disabled(),
            policy: policy.clone(),
            ..SignupConfig::default()
        })
    })
    .await
}

#[tokio::test]
async fn deny_silently_returns_204_and_sends_no_email() {
    let policy = StubPolicy::new(StubOutcome::DenySilently);
    let app = app_with_policy(policy).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "blocked@example.com".into(),
            invite_token: None,
        })
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "silent denial is indistinguishable from an accepted request",
    );
    assert_eq!(app.email.sent().len(), 0, "no link sent on silent denial");

    app.shutdown().await;
}

#[tokio::test]
async fn deny_returns_403_with_code_and_sends_no_email() {
    let policy = StubPolicy::new(StubOutcome::Deny);
    let app = app_with_policy(policy).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "blocked@example.com".into(),
            invite_token: None,
        })
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "signup_not_allowed");
    assert!(
        !body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no invite"),
        "host reason must not reach the wire",
    );
    assert_eq!(app.email.sent().len(), 0, "no link sent on denial");

    app.shutdown().await;
}

#[tokio::test]
async fn invite_token_reaches_policy_verbatim_from_the_wire() {
    let policy = StubPolicy::new(StubOutcome::DenySilently);
    let app = app_with_policy(policy.clone()).await;
    let client = reqwest::Client::new();

    let with_token = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "invited@example.com".into(),
            invite_token: Some("opaque-invite-blob-123".into()),
        })
        .send()
        .await
        .expect("request with token");
    assert_eq!(with_token.status(), StatusCode::NO_CONTENT);

    // Omitting the field entirely must still parse (serde default) and arrive
    // as `None` at the policy.
    let without_token = client
        .post(app.url("/auth/signup/request"))
        .json(&serde_json::json!({ "email": "walkin@example.com" }))
        .send()
        .await
        .expect("request without token");
    assert_eq!(without_token.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        policy.tokens(),
        vec![Some("opaque-invite-blob-123".to_owned()), None],
        "token crosses the wire byte-for-byte; omission arrives as None",
    );

    app.shutdown().await;
}
