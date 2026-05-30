mod common;

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::AuditEventKind;
use bauth_core::clock::Clock;
use bauth_core::email::{BauthEmails, Email};
use bauth_core::error::Error;
use bauth_core::memory::InMemoryRateLimiter;
use bauth_core::rate_limit::{RateLimitPolicy, RateLimiter};
use bauth_core::session::SessionContext;
use bauth_core::signup::{SignupConfig, SignupRateLimits};
use bauth_core::storage::{User, UserStore};
use bauth_test_support::MockClock;
use chrono::Duration as ChronoDuration;

use common::{Harness, SIGNUP_URL, authenticator, kinds, signup_config, token_from_email, ts};

#[tokio::test]
async fn request_provisions_user_for_new_email() {
    let h = Harness::fresh();
    h.signup
        .request_signup("Alice@Example.com", SessionContext::default())
        .await
        .expect("request");

    let user = h
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find user")
        .expect("user provisioned");
    assert!(user.email_verified_at.is_none(), "unverified until consume");
    assert_eq!(h.tokens.len(), 1, "token persisted");
    assert_eq!(h.email.sent().len(), 1, "signup email queued");
    assert_eq!(h.email.sent()[0].subject, "Finish setting up your account");
    assert!(matches!(
        kinds(&h.audit.events()).last(),
        Some(AuditEventKind::SignupRequested { .. })
    ));
}

#[tokio::test]
async fn request_for_existing_email_is_silent_and_audited() {
    let h = Harness::fresh();
    // First request creates the user.
    h.signup
        .request_signup("alice@example.com", SessionContext::default())
        .await
        .expect("first request");
    let emails_before = h.email.sent().len();
    let tokens_before = h.tokens.len();

    // Second request: user exists → silent no-op, no new email or token.
    h.signup
        .request_signup("alice@example.com", SessionContext::default())
        .await
        .expect("silent ok");
    assert_eq!(h.email.sent().len(), emails_before, "no extra email sent");
    assert_eq!(h.tokens.len(), tokens_before, "no extra token created");
    // Only the user record is observable; no duplicate user.
    let only = h
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find user")
        .expect("user present");
    let _ = only;

    // Audit emitted on both attempts.
    let signup_requested: Vec<_> = kinds(&h.audit.events())
        .into_iter()
        .filter(|k| matches!(k, AuditEventKind::SignupRequested { .. }))
        .collect();
    assert_eq!(signup_requested.len(), 2, "both requests audited");
}

#[tokio::test]
async fn consume_verifies_email_and_starts_passkey_registration() {
    let h = Harness::fresh();
    h.signup
        .request_signup("user@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    let outcome = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("consume");
    let _ = outcome.challenge_id;
    let _ = outcome.options;

    assert_eq!(h.tokens.len(), 0, "token consumed");
    let user = h
        .users
        .find_user_by_email("user@example.com")
        .await
        .expect("find user")
        .expect("user present");
    assert!(
        user.email_verified_at.is_some(),
        "email verified on consume"
    );
    assert!(
        kinds(&h.audit.events())
            .iter()
            .any(|k| matches!(k, AuditEventKind::SignupConsumed { .. })),
    );
}

#[tokio::test]
async fn consume_then_finish_registers_passkey_and_issues_session() {
    let h = Harness::fresh();
    h.signup
        .request_signup("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    let consume = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("consume");

    let mail_before_finish = h.email.sent().len();
    let mut wa = authenticator();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .signup
        .finish_signup(
            consume.challenge_id,
            &attestation,
            Some("alice device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");

    assert_eq!(outcome.user.email.as_deref(), Some("alice@example.com"));
    assert!(outcome.user.email_verified_at.is_some());
    assert_eq!(h.sessions.len(), 1, "session issued");
    assert_eq!(h.credentials.len(), 1, "passkey registered");
    let sent = h.email.sent();
    let after_finish = &sent[mail_before_finish..];
    assert_eq!(
        after_finish.len(),
        1,
        "passkey registration notification sent",
    );
    assert_eq!(
        after_finish[0].subject,
        "Security notice: passkey registered",
    );
    assert!(after_finish[0].body_text.contains("alice device"));
    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::CredentialAdded { .. }))
    );
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. }))
    );
}

#[tokio::test]
async fn notification_send_failure_does_not_undo_successful_finish() {
    let h = Harness::fresh();
    h.signup
        .request_signup("notify-fails@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);
    let consume = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("consume");

    let mail_before_finish = h.email.sent().len();
    h.email.fail_after_successful_sends(mail_before_finish);

    let mut wa = authenticator();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .signup
        .finish_signup(
            consume.challenge_id,
            &attestation,
            Some("failing notifier device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish still succeeds");

    assert_eq!(
        outcome.user.email.as_deref(),
        Some("notify-fails@example.com")
    );
    assert_eq!(h.credentials.len(), 1, "passkey still stored");
    assert_eq!(h.sessions.len(), 1, "session still issued");
    assert_eq!(
        h.email.sent().len(),
        mail_before_finish,
        "failed notification was not captured",
    );
}

#[tokio::test]
async fn consume_rejects_replayed_token() {
    let h = Harness::fresh();
    h.signup
        .request_signup("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    h.signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("first consume");
    let err = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("second consume");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn consume_rejects_expired_token() {
    let h = Harness::builder()
        .signup_config(SignupConfig {
            token_lifetime: Duration::from_secs(60),
            ..signup_config()
        })
        .build();
    h.signup
        .request_signup("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn request_rejects_invalid_email() {
    let h = Harness::fresh();
    let err = h
        .signup
        .request_signup("not-an-email", SessionContext::default())
        .await
        .expect_err("invalid");
    assert!(matches!(err, Error::InvalidEmail));
}

#[tokio::test]
async fn rate_limit_per_ip_blocks_after_budget() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = Harness::builder()
        .signup_limiter(limiter)
        .signup_config(SignupConfig {
            rate_limits: SignupRateLimits {
                request_per_ip: Some(policy),
                ..SignupRateLimits::disabled()
            },
            ..signup_config()
        })
        .build();

    let ctx = SessionContext {
        ip: Some("9.9.9.9".into()),
        user_agent: None,
    };
    h.signup
        .request_signup("a@example.com", ctx.clone())
        .await
        .expect("1");
    h.signup
        .request_signup("b@example.com", ctx.clone())
        .await
        .expect("2");
    let err = h
        .signup
        .request_signup("c@example.com", ctx)
        .await
        .expect_err("limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn rate_limit_per_identifier_blocks_across_ips() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = Harness::builder()
        .signup_limiter(limiter)
        .signup_config(SignupConfig {
            rate_limits: SignupRateLimits {
                request_per_identifier: Some(policy),
                ..SignupRateLimits::disabled()
            },
            ..signup_config()
        })
        .build();

    for ip in ["1.1.1.1", "2.2.2.2"] {
        h.signup
            .request_signup(
                "target@example.com",
                SessionContext {
                    ip: Some(ip.into()),
                    user_agent: None,
                },
            )
            .await
            .expect("within identifier budget");
    }

    let err = h
        .signup
        .request_signup(
            "target@example.com",
            SessionContext {
                ip: Some("3.3.3.3".into()),
                user_agent: None,
            },
        )
        .await
        .expect_err("identifier limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

struct BrandedEmails;

impl BauthEmails for BrandedEmails {
    fn signup_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme signup".to_string(),
            body_text: format!("Open {url}"),
            body_html: Some(format!("<a href=\"{url}\">Open</a>")),
        }
    }
}

#[tokio::test]
async fn custom_emails_override_signup_subject_and_html() {
    let h = Harness::builder()
        .signup_config(SignupConfig {
            emails: Arc::new(BrandedEmails),
            ..signup_config()
        })
        .build();

    h.signup
        .request_signup("user@example.com", SessionContext::default())
        .await
        .expect("request");

    let sent = h.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Acme signup");
    assert!(sent[0].body_text.starts_with("Open "));
    assert!(sent[0].body_html.is_some());
}
