use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::http::StatusCode;
use doorman_axum::dto::{PasskeyDto, SessionDto, SignupRequest, UserDto};
use doorman_core::error::Result;
use doorman_core::session::SessionContext;
use doorman_core::signup::{SignupConfig, SignupDecision, SignupPolicy};
use serde_json::{Value, json};

use crate::common::{Client, ResidentAuthenticator, TestApp, USER_URL, harness_core, rp_origin};

#[tokio::test]
async fn signup_registers_a_passkey_and_starts_a_session() {
    let app = TestApp::new();

    let (auth, _) = app.signup("Alice@Example.com").await;

    assert_eq!(auth.user.email.as_deref(), Some("alice@example.com"));
    assert_eq!(auth.user.passkey_count, 1);
    assert!(app.is_authenticated(&auth).await);
}

#[tokio::test]
async fn signup_request_hands_the_invite_token_to_the_policy() {
    struct RecordingPolicy(Mutex<Vec<Option<String>>>);

    #[async_trait]
    impl SignupPolicy for RecordingPolicy {
        async fn evaluate(
            &self,
            _email: &str,
            invite_token: Option<&str>,
            _context: &SessionContext,
        ) -> Result<SignupDecision> {
            self.0
                .lock()
                .expect("policy lock")
                .push(invite_token.map(ToOwned::to_owned));
            Ok(SignupDecision::DenySilently)
        }
    }

    let policy = Arc::new(RecordingPolicy(Mutex::new(Vec::new())));
    let app = TestApp::with(
        {
            let policy = policy.clone();
            move |r| {
                harness_core(r).signup(SignupConfig {
                    policy,
                    ..SignupConfig::default()
                })
            }
        },
        |b| b,
    );

    let with_token = app
        .post("/auth/signup/request")
        .json(&SignupRequest {
            email: "invited@example.com".into(),
            invite_token: Some("opaque-invite-blob-123".into()),
        })
        .send()
        .await;
    assert_eq!(with_token.status, StatusCode::NO_CONTENT);
    let without_token = app
        .post("/auth/signup/request")
        .json(&json!({ "email": "walk-in@example.com" }))
        .send()
        .await;
    assert_eq!(without_token.status, StatusCode::NO_CONTENT);

    assert_eq!(
        *policy.0.lock().expect("policy lock"),
        vec![Some("opaque-invite-blob-123".to_owned()), None],
    );
}

#[tokio::test]
async fn login_is_discoverable_and_starts_a_session() {
    let app = TestApp::new();
    let (signed_up, mut authenticator) = app.signup("alice@example.com").await;

    let start = app.post("/auth/passkey/authenticate/start").send().await;
    assert_eq!(start.status, StatusCode::OK);
    let options: Value = start.json();
    assert_eq!(
        options["options"]["publicKey"]["allowCredentials"],
        json!([]),
        "login names no user, so it allows no particular passkey",
    );

    let credential_id = authenticator.credential_ids()[0].clone();
    let login = app.log_in(&mut authenticator, &credential_id).await;
    assert_eq!(login.status, StatusCode::OK);
    let logged_in = login.session(Client::Dpop);
    assert_eq!(logged_in.user.id, signed_up.user.id);
    assert!(app.is_authenticated(&logged_in).await);
}

#[tokio::test]
async fn passkeys_are_added_listed_renamed_and_removed() {
    let app = TestApp::new();
    let (auth, mut authenticator) = app.signup("alice@example.com").await;

    let added = app.register_passkey(&mut authenticator, &auth).await;
    assert_eq!(added.name.as_deref(), Some("backup device"));

    let list = app.get("/auth/passkey").session(&auth).send().await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json::<Vec<PasskeyDto>>().len(), 2);

    let path = format!("/auth/passkey/{}", added.credential_id);
    let renamed = app
        .patch(&path)
        .session(&auth)
        .json(&json!({ "name": "My Laptop" }))
        .send()
        .await;
    assert_eq!(renamed.status, StatusCode::OK);
    let renamed: PasskeyDto = renamed.json();
    assert_eq!(renamed.credential_id, added.credential_id);
    assert_eq!(renamed.name.as_deref(), Some("My Laptop"));

    let removed = app.delete(&path).session(&auth).send().await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let list = app.get("/auth/passkey").session(&auth).send().await;
    let remaining: Vec<PasskeyDto> = list.json();
    assert_eq!(remaining.len(), 1);
    assert_ne!(remaining[0].credential_id, added.credential_id);
}

#[tokio::test]
async fn sessions_are_listed_and_revoked() {
    let app = TestApp::new();
    let caller = app.session_for("alice@example.com").await;
    let other = app.session_for("alice@example.com").await;
    let third = app.session_for("alice@example.com").await;

    let list = app.get("/auth/sessions").session(&caller).send().await;
    assert_eq!(list.status, StatusCode::OK);
    let sessions: Vec<SessionDto> = list.json();
    assert_eq!(sessions.len(), 3);
    let current: Vec<_> = sessions.iter().filter(|s| s.is_current).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].id, caller.session.id);

    let revoke_one = app
        .delete(&format!("/auth/sessions/{}", other.session.id))
        .session(&caller)
        .send()
        .await;
    assert_eq!(revoke_one.status, StatusCode::NO_CONTENT);
    assert!(!app.is_authenticated(&other).await);
    assert!(app.is_authenticated(&third).await);

    let revoke_others = app.delete("/auth/sessions").session(&caller).send().await;
    assert_eq!(revoke_others.status, StatusCode::NO_CONTENT);
    assert!(!app.is_authenticated(&third).await);
    assert!(app.is_authenticated(&caller).await);
}

#[tokio::test]
async fn an_email_change_is_requested_and_confirmed() {
    let app = TestApp::new();
    let session = app.session_for("before@example.com").await;

    let request = app
        .post("/auth/user/email")
        .session(&session)
        .json(&json!({ "new_email": "after@example.com" }))
        .send()
        .await;
    assert_eq!(request.status, StatusCode::NO_CONTENT);

    let confirm = app
        .post("/auth/user/email/confirm")
        .json(&json!({ "token": app.last_link(USER_URL) }))
        .send()
        .await;
    assert_eq!(confirm.status, StatusCode::OK);
    let user: UserDto = confirm.json();
    assert_eq!(user.email.as_deref(), Some("after@example.com"));
}

#[tokio::test]
async fn recovery_registers_a_new_passkey_and_starts_a_session() {
    let app = TestApp::new();
    let (signed_up, _) = app.signup("alice@example.com").await;

    let mut new_authenticator = ResidentAuthenticator::new(&rp_origin());
    let recovered = app
        .recover("alice@example.com", &mut new_authenticator)
        .await;

    assert_eq!(recovered.user.id, signed_up.user.id);
    assert_eq!(recovered.user.passkey_count, 2);
    assert!(app.is_authenticated(&recovered).await);
}
