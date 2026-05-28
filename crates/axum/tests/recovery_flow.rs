//! End-to-end HTTP tests for the recovery routes.
//!
//! Exercises the quickstart wiring path so the test covers manager
//! construction, route mounting, email delivery (link + notification),
//! the passkey ceremony at consume / finish time, session cookie
//! issuance, and the session layer loading the newly issued session.

mod common;

use axum::Router;
use axum::http::StatusCode;
use bauth_axum::dto::{
    AuthResponse, PasskeyChallenge, RecoveryConsumeRequest, RecoveryFinishRequest, RecoveryRequest,
    SignupRequest,
};
use common::{RECOVERY_URL, SignupClient, TestApp, token_from_email, token_from_email_with};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::CreationChallengeResponse;

const RECOVERY_LINK_SUBJECT: &str = "Recover access to your account";
const RECOVERY_NOTIFICATION_SUBJECT: &str = "Security notice: account recovery activity";

#[tokio::test]
async fn full_recovery_round_trip() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    // Provision a real user via the signup flow so recovery has someone
    // to recover.
    let signed_up: AuthResponse = SignupClient::new(&app)
        .signup(&cookie_client, &app, "alice@example.com")
        .await;

    let mail_before = app.email.sent().len();

    // Recovery request.
    let req = cookie_client
        .post(app.url("/auth/recovery/request"))
        .json(&RecoveryRequest {
            email: "Alice@Example.com".into(),
        })
        .send()
        .await
        .expect("recovery request");
    assert_eq!(req.status(), StatusCode::NO_CONTENT);

    let new_mail = &app.email.sent()[mail_before..];
    assert_eq!(new_mail.len(), 2, "link + notification");
    let link_email = new_mail
        .iter()
        .find(|e| e.subject == RECOVERY_LINK_SUBJECT)
        .expect("link queued");
    assert!(
        new_mail
            .iter()
            .any(|e| e.subject == RECOVERY_NOTIFICATION_SUBJECT),
        "notification queued",
    );
    let token = token_from_email_with(&link_email.body_text, RECOVERY_URL);

    // Recovery consume → returns a passkey-registration challenge.
    let consume = cookie_client
        .post(app.url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest {
            token: token.clone(),
        })
        .send()
        .await
        .expect("recovery consume");
    assert_eq!(consume.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        consume.json().await.expect("consume body");

    // Drive the WebAuthn ceremony to enrol a new passkey.
    let mut sp = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let auth_origin = AuthUrl::parse(app.rp_origin.as_str()).expect("rp origin");
    let mut options = challenge.options;
    let selection = options
        .public_key
        .authenticator_selection
        .as_mut()
        .expect("authenticator selection present");
    selection.require_resident_key = false;
    selection.resident_key = None;
    let attestation = sp
        .do_registration(auth_origin, options)
        .expect("authenticator register");

    let mail_before_finish = app.email.sent().len();

    let finish = cookie_client
        .post(app.url("/auth/recovery/finish"))
        .json(&RecoveryFinishRequest {
            challenge_id: challenge.challenge_id,
            response: attestation,
            name: Some("recovery device".into()),
        })
        .send()
        .await
        .expect("recovery finish");
    assert_eq!(finish.status(), StatusCode::OK);
    let body: AuthResponse = finish.json().await.expect("finish body");
    assert_eq!(body.user.id, signed_up.user.id);
    assert!(!body.token.is_empty());

    // Success notification email.
    let after_finish = &app.email.sent()[mail_before_finish..];
    assert!(
        after_finish
            .iter()
            .any(|e| e.subject == RECOVERY_NOTIFICATION_SUBJECT),
        "success notification queued",
    );

    // The Set-Cookie from /recovery/finish should let the cookie client
    // hit a protected route.
    let me = cookie_client
        .get(app.url("/me"))
        .send()
        .await
        .expect("me cookie");
    assert_eq!(me.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn recovery_request_for_unknown_email_is_silent() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/recovery/request"))
        .json(&RecoveryRequest {
            email: "ghost@example.com".into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "response is identical for unknown email",
    );
    assert!(
        app.email.sent().is_empty(),
        "no email sent for unknown address",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn recovery_request_for_registered_email_sends_link_and_notification() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    // Register a user first.
    let _ = SignupClient::new(&app)
        .signup(&cookie_client, &app, "alice@example.com")
        .await;

    let mail_before = app.email.sent().len();
    let plain = reqwest::Client::new();
    let resp = plain
        .post(app.url("/auth/recovery/request"))
        .json(&RecoveryRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("recovery request");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let new_mail = &app.email.sent()[mail_before..];
    assert_eq!(new_mail.len(), 2);
    let subjects: Vec<&str> = new_mail.iter().map(|e| e.subject.as_str()).collect();
    assert!(subjects.contains(&RECOVERY_LINK_SUBJECT));
    assert!(subjects.contains(&RECOVERY_NOTIFICATION_SUBJECT));

    app.shutdown().await;
}

#[tokio::test]
async fn recovery_consume_with_invalid_token_returns_400() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest {
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
async fn recovery_consume_replay_is_rejected() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let _ = SignupClient::new(&app)
        .signup(&cookie_client, &app, "alice@example.com")
        .await;

    let plain = reqwest::Client::new();
    let mail_before = app.email.sent().len();
    plain
        .post(app.url("/auth/recovery/request"))
        .json(&RecoveryRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("recovery request");
    let link_email = app.email.sent()[mail_before..]
        .iter()
        .find(|e| e.subject == RECOVERY_LINK_SUBJECT)
        .expect("link queued")
        .clone();
    let token = token_from_email_with(&link_email.body_text, RECOVERY_URL);

    let first = plain
        .post(app.url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest {
            token: token.clone(),
        })
        .send()
        .await
        .expect("first consume");
    assert_eq!(first.status(), StatusCode::OK);

    let second = plain
        .post(app.url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest { token })
        .send()
        .await
        .expect("second consume");
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = second.json().await.expect("body");
    assert_eq!(body["error"]["code"], "invalid_verification_token");

    app.shutdown().await;
}

#[tokio::test]
async fn recovery_request_rejects_invalid_email_with_code() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/recovery/request"))
        .json(&RecoveryRequest {
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

/// Drive a full signup + recovery round trip and return the auth response
/// from `/auth/recovery/finish`. The returned session is restricted by the
/// post-recovery cool-down.
async fn provision_recovery_session(
    app: &TestApp,
    cookie_client: &reqwest::Client,
    email: &str,
) -> AuthResponse {
    let _signed_up: AuthResponse = SignupClient::new(app)
        .signup(cookie_client, app, email)
        .await;
    let mail_before = app.email.sent().len();

    let req = cookie_client
        .post(app.url("/auth/recovery/request"))
        .json(&RecoveryRequest {
            email: email.into(),
        })
        .send()
        .await
        .expect("recovery request");
    assert_eq!(req.status(), StatusCode::NO_CONTENT);
    let link_email = app.email.sent()[mail_before..]
        .iter()
        .find(|e| e.subject == RECOVERY_LINK_SUBJECT)
        .expect("link queued")
        .clone();
    let token = token_from_email_with(&link_email.body_text, RECOVERY_URL);

    let consume = cookie_client
        .post(app.url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest { token })
        .send()
        .await
        .expect("recovery consume");
    assert_eq!(consume.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        consume.json().await.expect("consume body");

    let mut sp = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let auth_origin = AuthUrl::parse(app.rp_origin.as_str()).expect("rp origin");
    let mut options = challenge.options;
    let selection = options
        .public_key
        .authenticator_selection
        .as_mut()
        .expect("authenticator selection present");
    selection.require_resident_key = false;
    selection.resident_key = None;
    let attestation = sp
        .do_registration(auth_origin, options)
        .expect("authenticator register");

    let finish = cookie_client
        .post(app.url("/auth/recovery/finish"))
        .json(&RecoveryFinishRequest {
            challenge_id: challenge.challenge_id,
            response: attestation,
            name: Some("backup".into()),
        })
        .send()
        .await
        .expect("recovery finish");
    assert_eq!(finish.status(), StatusCode::OK);
    finish.json().await.expect("finish body")
}

#[tokio::test]
async fn delete_passkey_during_cooldown_returns_409() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let auth = provision_recovery_session(&app, &cookie_client, "alice@example.com").await;

    // List passkeys to find one to attempt deleting.
    let list = cookie_client
        .get(app.url("/auth/passkey"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("list");
    assert_eq!(list.status(), StatusCode::OK);
    let passkeys: Vec<bauth_axum::dto::PasskeyDto> = list.json().await.expect("list body");
    let first = passkeys.first().expect("at least one passkey").clone();

    let resp = cookie_client
        .delete(app.url(&format!("/auth/passkey/{}", first.credential_id)))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete passkey");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "recovery_cooldown_active");

    app.shutdown().await;
}

#[tokio::test]
async fn delete_other_session_during_cooldown_returns_409() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    // Sign up + recover (puts the cookie client into a restricted session).
    let recovery_auth = provision_recovery_session(&app, &cookie_client, "alice@example.com").await;
    // Mint a second session for the same user via the in-process manager so
    // there's something to try to revoke.
    let other = common::login(&cookie_client, &app, "alice@example.com").await;

    let resp = cookie_client
        .delete(app.url(&format!("/auth/sessions/{}", other.session.id)))
        .bearer_auth(&recovery_auth.token)
        .send()
        .await
        .expect("delete other session");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "recovery_cooldown_active");

    app.shutdown().await;
}

#[tokio::test]
async fn revoke_others_during_cooldown_returns_409() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let auth = provision_recovery_session(&app, &cookie_client, "alice@example.com").await;
    let _other = common::login(&cookie_client, &app, "alice@example.com").await;

    let resp = cookie_client
        .delete(app.url("/auth/sessions"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete /auth/sessions");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "recovery_cooldown_active");

    app.shutdown().await;
}

#[tokio::test]
async fn register_start_during_cooldown_is_allowed() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let auth = provision_recovery_session(&app, &cookie_client, "alice@example.com").await;

    // Adding another passkey is explicitly *not* blocked during cool-down.
    let resp = cookie_client
        .post(app.url("/auth/passkey/register/start"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("register start");
    assert_eq!(resp.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn deleting_own_recovery_session_is_allowed_during_cooldown() {
    let app = TestApp::start(Router::new(), false).await;
    let cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let auth = provision_recovery_session(&app, &cookie_client, "alice@example.com").await;

    // Signing out of the recovery session itself is the one
    // self-revoke that the cool-down does not block.
    let resp = cookie_client
        .delete(app.url(&format!("/auth/sessions/{}", auth.session.id)))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete self");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn signup_token_is_not_accepted_at_recovery_consume() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    // Drive a signup request without consuming it, then try to redeem
    // the token via recovery — the manager must reject because the
    // verification purposes are distinct.
    let resp = client
        .post(app.url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "fresh@example.com".into(),
        })
        .send()
        .await
        .expect("signup request");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let token = token_from_email(&app.email.sent()[0].body_text);

    let resp = client
        .post(app.url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest { token })
        .send()
        .await
        .expect("recovery consume");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["error"]["code"], "invalid_verification_token");

    app.shutdown().await;
}
