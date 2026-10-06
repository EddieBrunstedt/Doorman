mod common;

use std::sync::Arc;

use axum::Router;
use common::TestApp;
use doorman_core::email::{Email, EmailTemplates};
use doorman_core::storage::User;

const SIGNUP_SUBJECT: &str = "Acme: finish signing up";
const RECOVERY_SUBJECT: &str = "Acme: recover your access";
const SESSION_REVOKED_SUBJECT: &str = "Acme: a session was revoked";

struct AcmeEmails;

impl EmailTemplates for AcmeEmails {
    fn signup_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: SIGNUP_SUBJECT.to_string(),
            body_text: format!("Open {url}"),
            body_html: None,
        }
    }

    fn recovery_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: RECOVERY_SUBJECT.to_string(),
            body_text: format!("Open {url}"),
            body_html: None,
        }
    }

    fn other_session_revoked_notice_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: SESSION_REVOKED_SUBJECT.to_string(),
            body_text: "A session was revoked.".to_string(),
            body_html: None,
        }
    }
}

#[tokio::test]
async fn emails_brands_signup_recovery_and_security_notices() {
    let app = TestApp::start_with(Router::new(), false, |b| b.emails(Arc::new(AcmeEmails))).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/signup/request"))
        .json(&serde_json::json!({ "email": "newcomer@example.com" }))
        .send()
        .await
        .expect("signup request");
    assert!(
        resp.status().is_success(),
        "signup request: {}",
        resp.status()
    );
    let signup_mail = app
        .email
        .sent()
        .into_iter()
        .next_back()
        .expect("signup email queued");
    assert_eq!(signup_mail.subject, SIGNUP_SUBJECT);

    let caller = common::login(&client, &app, "member@example.com").await;
    let other = common::login(&client, &app, "member@example.com").await;

    let before = app.email.sent().len();
    let resp = client
        .post(app.url("/auth/recovery/request"))
        .json(&serde_json::json!({ "email": "member@example.com" }))
        .send()
        .await
        .expect("recovery request");
    assert!(
        resp.status().is_success(),
        "recovery request: {}",
        resp.status()
    );
    let recovery_mail = app.email.sent()[before..]
        .iter()
        .find(|m| m.subject == RECOVERY_SUBJECT)
        .cloned();
    assert!(
        recovery_mail.is_some(),
        "recovery email should use the branded subject"
    );

    let before = app.email.sent().len();
    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", other.session.id)))
        .bearer_auth(&caller.token)
        .send()
        .await
        .expect("delete other session");
    assert!(
        resp.status().is_success(),
        "delete session: {}",
        resp.status()
    );
    let revoke_mail = &app.email.sent()[before..];
    assert_eq!(revoke_mail.len(), 1, "one revocation notice queued");
    assert_eq!(revoke_mail[0].subject, SESSION_REVOKED_SUBJECT);

    app.shutdown().await;
}
