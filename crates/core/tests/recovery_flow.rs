mod common;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::{AuditEventKind, RecoveryFailureReason};
use doorman_core::clock::Clock;
use doorman_core::email::{Email, EmailTemplates};
use doorman_core::error::Error;
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::{RateLimitPolicy, RateLimiter};
use doorman_core::recovery::{
    MIN_COOLDOWN, RecoveryConfig, RecoveryConfigError, RecoveryManager, RecoveryRateLimits,
};
use doorman_core::session::SessionContext;
use doorman_core::storage::{AccountStatus, PasskeyCredentialStore, User, UserStore};
use doorman_test_support::MockClock;

use common::{
    Harness, RECOVERY_URL, RP_ID, RP_NAME, ResidentTestAuthenticator, authenticator, kinds,
    make_user, provision_user, recovery_config, register_passkey, rp_origin, token_from_email,
};

#[tokio::test]
async fn request_for_registered_email_sends_link_and_notification() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    let mail_before = h.email.sent().len();

    h.recovery
        .request_recovery("Alice@Example.com", SessionContext::default())
        .await
        .expect("recovery request");

    let new = &h.email.sent()[mail_before..];
    assert_eq!(new.len(), 2, "link + notification queued");
    let subjects: Vec<&str> = new.iter().map(|e| e.subject.as_str()).collect();
    let Some(link_email) = new
        .iter()
        .find(|e| e.subject == "Recover access to your account")
    else {
        panic!("recovery link sent ({subjects:?})");
    };
    let Some(requested_notification) = new
        .iter()
        .find(|e| e.subject == "Security notice: account recovery requested")
    else {
        panic!("requested notification sent ({subjects:?})");
    };
    assert_ne!(
        link_email.subject.as_str(),
        requested_notification.subject.as_str()
    );
    assert_ne!(
        link_email.body_text.as_str(),
        requested_notification.body_text.as_str(),
    );
    assert!(
        requested_notification
            .body_text
            .contains("request to recover")
    );
    assert!(
        requested_notification
            .body_text
            .contains("If this was not you")
    );

    let audit_kinds = kinds(&h.audit.events());
    assert!(audit_kinds.iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryRequested { user_id: Some(id) } if *id == user.id,
    )));
    assert_eq!(h.tokens.len(), 1, "exactly one recovery token persisted");
}

#[tokio::test]
async fn request_for_unknown_email_sends_nothing_but_audits() {
    let h = Harness::fresh();
    h.recovery
        .request_recovery("ghost@example.com", SessionContext::default())
        .await
        .expect("silent ok");

    assert!(h.email.sent().is_empty(), "no email sent for unknown email");
    assert!(h.tokens.is_empty(), "no token created for unknown email");
    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::RecoveryRequested { user_id: None }))
    );
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::UnknownEmail,
            ..
        }
    )));
}

/// Flip `user` to [`AccountStatus::Disabled`] directly through the store, the
/// way the operator disable flow will. Step 3 proves the recovery gate holds by
/// disabling through the store; the audited operator-facing setter lands in
/// Step 4.
async fn disable_user(h: &Harness, user: &User) {
    let now = h.clock.now();
    let disabled = User {
        status: AccountStatus::Disabled { at: now },
        updated_at: now,
        ..user.clone()
    };
    h.users.update_user(disabled).await.expect("disable user");
}

#[tokio::test]
async fn request_for_disabled_user_sends_nothing_but_audits() {
    // A disabled account must not be able to recover its way back in, and the
    // refusal must be indistinguishable from the unknown-email path to an
    // outside caller: same `Ok(())`, no link, no token.
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    disable_user(&h, &user).await;
    let mail_before = h.email.sent().len();
    let tokens_before = h.tokens.len();

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("silent ok for disabled account");

    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no email sent for a disabled account",
    );
    assert_eq!(
        h.tokens.len(),
        tokens_before,
        "no recovery token issued for a disabled account",
    );
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::AccountDisabled,
            user_id: Some(id),
        } if *id == user.id,
    )));
}

#[tokio::test]
async fn consume_refused_for_disabled_user() {
    // A link issued while the account was active must not redeem after the
    // account is disabled: the consume seam refuses with `AccountDisabled`.
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request while active");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    disable_user(&h, &user).await;

    let err = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect_err("consume refused for disabled account");
    assert!(matches!(err, Error::AccountDisabled));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::AccountDisabled,
            user_id: Some(id),
        } if *id == user.id,
    )));
}

#[tokio::test]
async fn finish_refused_for_disabled_user_enrolls_nothing() {
    // Backstop: even if the token was consumed and the registration ceremony
    // completed in the browser while the account was still active, finishing
    // after the disable lands must refuse — no passkey enrolled, no session
    // issued.
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    let credentials_before = h.credentials.len();
    let sessions_before = h.sessions.len();

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request while active");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume while active");
    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);

    // The disable lands after the ceremony was driven but before finish.
    disable_user(&h, &user).await;

    let err = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("backup device".into()),
            SessionContext::default(),
        )
        .await
        .expect_err("finish refused for disabled account");
    assert!(matches!(err, Error::AccountDisabled));
    assert_eq!(
        h.credentials.len(),
        credentials_before,
        "no passkey enrolled onto a disabled account",
    );
    assert_eq!(
        h.sessions.len(),
        sessions_before,
        "no session issued for a disabled account",
    );
}

#[tokio::test]
async fn rate_limit_per_email_blocks_after_budget() {
    let clock_for_limiter = Arc::new(MockClock::new(common::ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = Harness::builder()
        .recovery_limiter(limiter)
        .recovery_config(RecoveryConfig {
            rate_limits: RecoveryRateLimits {
                request_per_identifier: Some(policy),
                ..RecoveryRateLimits::disabled()
            },
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "target@example.com").await;

    for _ in 0..2 {
        h.recovery
            .request_recovery("target@example.com", SessionContext::default())
            .await
            .expect("within budget");
    }
    let err = h
        .recovery
        .request_recovery("target@example.com", SessionContext::default())
        .await
        .expect_err("limited");
    assert!(matches!(err, Error::RateLimited { .. }));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::RateLimited,
            ..
        }
    )));
}

#[tokio::test]
async fn rate_limit_per_ip_blocks_after_budget() {
    let clock_for_limiter = Arc::new(MockClock::new(common::ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = Harness::builder()
        .recovery_limiter(limiter)
        .recovery_config(RecoveryConfig {
            rate_limits: RecoveryRateLimits {
                request_per_ip: Some(policy),
                ..RecoveryRateLimits::disabled()
            },
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "a@example.com").await;
    let _ = provision_user(&h, "b@example.com").await;
    let _ = provision_user(&h, "c@example.com").await;

    let ctx = SessionContext {
        ip: Some("9.9.9.9".into()),
        user_agent: None,
    };
    h.recovery
        .request_recovery("a@example.com", ctx.clone())
        .await
        .expect("1");
    h.recovery
        .request_recovery("b@example.com", ctx.clone())
        .await
        .expect("2");
    let err = h
        .recovery
        .request_recovery("c@example.com", ctx)
        .await
        .expect_err("limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn consume_rejects_replayed_token() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    h.recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("first consume");
    let err = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect_err("replay");
    assert!(matches!(err, Error::InvalidVerificationToken));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::InvalidToken,
            ..
        }
    )));
}

#[tokio::test]
async fn consume_rejects_expired_token_without_notification() {
    let h = Harness::builder()
        .recovery_config(RecoveryConfig {
            token_lifetime: Duration::from_secs(60),
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let mail_before = h.email.sent().len();

    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidVerificationToken));
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no notification on expired click",
    );
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::ExpiredToken,
            ..
        }
    )));
}

#[tokio::test]
async fn successful_recovery_enrols_passkey_and_sends_success_notification() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    let credentials_before = h.credentials.len();

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let requested_notification = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Security notice: account recovery requested")
        .expect("requested notification queued");

    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");

    let mail_before_finish = h.email.sent().len();
    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("backup device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");

    assert_eq!(outcome.user.id, user.id);
    assert_eq!(
        h.credentials.len(),
        credentials_before + 1,
        "new passkey enrolled",
    );
    let user_credentials = h
        .credentials
        .list_passkeys_for_user(user.id)
        .await
        .expect("list");
    assert!(
        user_credentials
            .iter()
            .any(|c| c.name.as_deref() == Some("backup device")),
        "recovery-enrolled passkey shows up in list_passkeys for the user",
    );
    assert!(!h.sessions.is_empty(), "session issued");

    let sent = h.email.sent();
    let after_finish = &sent[mail_before_finish..];
    assert_eq!(
        after_finish.len(),
        2,
        "passkey + completed notifications sent",
    );
    let subjects: Vec<&str> = after_finish.iter().map(|e| e.subject.as_str()).collect();
    let Some(passkey_notification) = after_finish
        .iter()
        .find(|e| e.subject == "Security notice: passkey registered")
    else {
        panic!("passkey notification sent ({subjects:?})");
    };
    let Some(completed_notification) = after_finish
        .iter()
        .find(|e| e.subject == "Security notice: account recovery completed")
    else {
        panic!("completed notification sent ({subjects:?})");
    };
    assert!(passkey_notification.body_text.contains("backup device"));
    assert_ne!(
        completed_notification.subject.as_str(),
        requested_notification.subject.as_str(),
    );
    assert_ne!(
        completed_notification.body_text.as_str(),
        requested_notification.body_text.as_str(),
    );
    assert!(
        completed_notification
            .body_text
            .contains("Account recovery just completed")
    );
    assert!(
        completed_notification
            .body_text
            .contains("If this was not you")
    );

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryConsumed { user_id } if *user_id == user.id,
    )));
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
async fn consume_with_unknown_token_audits_invalid_token() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;

    let err = h
        .recovery
        .consume_recovery("not-a-real-token", SessionContext::default())
        .await
        .expect_err("invalid");
    assert!(matches!(err, Error::InvalidVerificationToken));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::InvalidToken,
            ..
        }
    )));
}

#[tokio::test]
async fn request_rejects_invalid_email() {
    let h = Harness::fresh();
    let err = h
        .recovery
        .request_recovery("not-an-email", SessionContext::default())
        .await
        .expect_err("invalid email");
    assert!(matches!(err, Error::InvalidEmail));
}

#[tokio::test]
async fn signup_token_cannot_be_redeemed_via_recovery_consume() {
    let h = Harness::fresh();
    // Take a fresh signup token (the user is in an "unverified" state
    // after signup request but before signup consume).
    h.signup
        .request_signup("pending@example.com", None, SessionContext::default())
        .await
        .expect("signup request");
    let signup_email = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Finish setting up your account")
        .expect("signup link queued");
    let token = token_from_email(&signup_email.body_text, common::SIGNUP_URL);

    // Recovery consume must refuse it: distinct purpose, distinct surface.
    let err = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect_err("cross-purpose redeem");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn recovery_request_invalidates_prior_recovery_token() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("first");
    let first_link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("first link");
    let first_token = token_from_email(&first_link.body_text, RECOVERY_URL);

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("second");

    // Replacing the token means the older one no longer redeems.
    let err = h
        .recovery
        .consume_recovery(&first_token, SessionContext::default())
        .await
        .expect_err("first now invalid");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn request_response_shape_is_identical_known_unknown_and_on_send_failure() {
    // Enumeration resistance: a registered address sends a link plus a
    // requested-recovery notification while an unknown address sends nothing,
    // yet both must return the same shape (`Ok`). A transport failure on either
    // of the registered-path sends must not turn into an error response, or a
    // forced bounce would distinguish a registered address from an unknown one.
    let h = Harness::fresh();
    let _ = provision_user(&h, "known@example.com").await;

    // Unknown address -> Ok (silent), known address -> Ok (two sends).
    h.recovery
        .request_recovery("ghost@example.com", SessionContext::default())
        .await
        .expect("unknown Ok");
    h.recovery
        .request_recovery("known@example.com", SessionContext::default())
        .await
        .expect("known Ok");

    // Fail every subsequent send. The known path attempts two sends, both of
    // which now bounce — the response must still be Ok, identical to the
    // unknown path.
    h.email.fail_after_successful_sends(h.email.sent().len());
    h.recovery
        .request_recovery("known@example.com", SessionContext::default())
        .await
        .expect("known Ok despite send failures");
    h.recovery
        .request_recovery("ghost@example.com", SessionContext::default())
        .await
        .expect("unknown Ok despite send failures");

    // Delivery is decoupled from token issuance: the failed sends did not stop
    // the fresh single-use token from being persisted for the known user.
    assert_eq!(
        h.tokens.len(),
        1,
        "recovery token issued despite send failure"
    );
}

struct BrandedEmails;

impl EmailTemplates for BrandedEmails {
    fn recovery_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme recovery".to_string(),
            body_text: format!("Open {url}"),
            body_html: Some(format!("<a href=\"{url}\">Open</a>")),
        }
    }

    fn recovery_requested_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme recovery requested".to_string(),
            body_text: "Recovery requested".to_string(),
            body_html: None,
        }
    }

    fn recovery_completed_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme recovery completed".to_string(),
            body_text: "Recovery completed".to_string(),
            body_html: None,
        }
    }
}

#[tokio::test]
async fn finish_recovery_stores_same_cooldown_on_session_and_passkey() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    let now_at_finish = h.clock.now();
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("backup device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");

    let expected = now_at_finish + ChronoDuration::hours(24);
    assert_eq!(
        outcome.session.session.recovery_cooldown_until,
        Some(expected),
    );
    assert_eq!(outcome.passkey.recovery_cooldown_until, Some(expected));

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&outcome.passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey stored");
    assert_eq!(stored.recovery_cooldown_until, Some(expected));
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );
}

#[tokio::test]
async fn recovery_created_passkey_login_inherits_active_cooldown() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");

    let (auth_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(options, &outcome.passkey.credential_id);
    let issued = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("finish auth");

    assert_eq!(
        issued.session.recovery_cooldown_until,
        outcome.session.session.recovery_cooldown_until,
    );
    assert!(issued.session.is_in_recovery_cooldown(h.clock.now()));
}

#[tokio::test]
async fn pre_existing_passkey_login_stays_unrestricted_during_recovery_cooldown() {
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut existing_wa = authenticator();
    let existing = register_passkey(&h, user.id, &mut existing_wa, Some("primary")).await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut recovery_wa = authenticator();
    let attestation = recovery_wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );

    let (auth_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = existing_wa.do_authentication(options, &existing.credential_id);
    let issued = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("finish auth");

    assert_eq!(issued.session.recovery_cooldown_until, None);
}

#[tokio::test]
async fn recovery_created_passkey_login_after_cooldown_is_unrestricted() {
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut wa = authenticator();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");
    assert_eq!(outcome.user.id, user.id);
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );

    h.clock
        .advance(ChronoDuration::hours(24) + ChronoDuration::seconds(1));

    let (auth_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(options, &outcome.passkey.credential_id);
    let issued = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("finish auth");

    assert_eq!(issued.session.recovery_cooldown_until, None);
}

#[tokio::test]
async fn recovery_cooldown_expires_after_window() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect("finish");

    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );
    h.clock
        .advance(ChronoDuration::hours(24) + ChronoDuration::seconds(1));
    assert!(
        !outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );
}

#[tokio::test]
async fn pre_recovery_registration_challenge_cannot_finish_after_recovery() {
    // A registration ceremony begun before recovery completes is minted
    // without the cool-down stamp. Finishing it after recovery would attach a
    // credential outside the cool-down — the bypass this test guards against.
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;

    // Pre-recovery: start (but do not finish) a registration ceremony.
    let (pre_challenge_id, pre_ccr) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("start pre-recovery registration");
    let mut pre_wa = authenticator();
    let pre_attestation = pre_wa.do_registration(pre_ccr);

    // Drive the recovery flow to completion on a separate authenticator.
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut recovery_wa = authenticator();
    let attestation = recovery_wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );

    // The pre-recovery challenge must have been invalidated by recovery
    // completion, so finishing it now fails rather than attaching an
    // unrestricted credential.
    let err = h
        .passkey
        .finish_registration(
            pre_challenge_id,
            &pre_attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("pre-recovery challenge must be invalidated");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));

    // Only the recovery-created credential exists; the pre-recovery one never
    // landed.
    let creds = h
        .credentials
        .list_passkeys_for_user(user.id)
        .await
        .expect("list");
    assert_eq!(creds.len(), 1);
    assert_eq!(
        creds[0].recovery_cooldown_until,
        outcome.passkey.recovery_cooldown_until
    );
}

#[tokio::test]
async fn pre_recovery_challenge_is_invalidated_before_recovery_session() {
    // Ordering guarantee: on the recovery success path the pre-recovery
    // bypass sweep runs before the recovery session is issued. This test pins
    // the success-path outcome of that ordering — the recovery session exists
    // AND the pre-recovery challenge is gone — so a regression that lets a
    // committed session coexist with a finishable bypass challenge is caught.
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;

    // Pre-recovery: start (but do not finish) a registration ceremony.
    let (pre_challenge_id, pre_ccr) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("start pre-recovery registration");
    let mut pre_wa = authenticator();
    let pre_attestation = pre_wa.do_registration(pre_ccr);

    // Drive a full recovery: request -> consume -> finish.
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut recovery_wa = authenticator();
    let attestation = recovery_wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish recovery succeeds");

    // The sweep ran before issuance, so the recovery session was still minted
    // and carries the recovery cool-down.
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now()),
        "recovery session must be issued with the cool-down on the success path"
    );

    // And the pre-recovery challenge can no longer be finished.
    let err = h
        .passkey
        .finish_registration(
            pre_challenge_id,
            &pre_attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("pre-recovery challenge must be invalidated");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn signup_does_not_invalidate_other_pending_registrations() {
    // The bypass closure is recovery-specific: a signup finish must not sweep
    // a user's other in-flight registration ceremonies.
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;

    // Start a second registration ceremony for the same user and leave it
    // pending.
    let (pending_id, pending_ccr) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("start pending registration");
    let mut wa = authenticator();
    let pending_attestation = wa.do_registration(pending_ccr);

    // Run another full signup for the same address. It silently no-ops on the
    // known email, but exercising a signup finish is what matters: provision a
    // fresh user and finish a signup so the shared `finish` path runs with
    // `FlowKind::Signup`.
    let other = provision_user(&h, "bob@example.com").await;
    assert_ne!(other.id, user.id);

    // alice's pending challenge is still finishable — signup did not sweep it.
    let stored = h
        .passkey
        .finish_registration(
            pending_id,
            &pending_attestation,
            Some("second device".into()),
            SessionContext::default(),
        )
        .await
        .expect("pending registration still valid");
    assert_eq!(stored.user_id, user.id);
    assert_eq!(stored.recovery_cooldown_until, None);
}

#[test]
fn recovery_config_with_subhour_cooldown_is_rejected() {
    let h = Harness::fresh();
    let result = RecoveryManager::new(
        h.recovery_flow.clone(),
        RecoveryConfig {
            cooldown: Duration::from_secs(60 * 30),
            ..recovery_config()
        },
    );
    assert!(matches!(
        result.err(),
        Some(RecoveryConfigError::CooldownTooShort {
            configured,
            minimum,
        }) if configured == Duration::from_secs(60 * 30) && minimum == MIN_COOLDOWN
    ));
}

#[test]
fn recovery_config_at_floor_is_accepted() {
    let h = Harness::fresh();
    assert!(
        RecoveryManager::new(
            h.recovery_flow.clone(),
            RecoveryConfig {
                cooldown: MIN_COOLDOWN,
                ..recovery_config()
            },
        )
        .is_ok()
    );
}

/// Drive a full recovery (request → consume → finish) for `email` against
/// `h` and return the [`EnrollmentOutcome`], so the cool-down assertions can
/// read the deadline stamped on the recovery session and passkey.
async fn drive_recovery_finish(
    h: &Harness,
    email: &str,
) -> doorman_core::verification::EnrollmentOutcome {
    h.recovery
        .request_recovery(email, SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    h.recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish")
}

#[tokio::test]
async fn recovery_config_with_subhour_cooldown_honors_configured_cooldown() {
    // The escape hatch must actually apply the configured sub-floor cool-down,
    // not silently clamp it back up to the floor: a 60-second cool-down yields a
    // deadline exactly 60 seconds out.
    let cooldown = Duration::from_secs(60);
    let h = Harness::builder()
        .recovery_config(RecoveryConfig {
            cooldown,
            danger_allow_cooldown_below_floor: true,
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "alice@example.com").await;

    let now_at_finish = h.clock.now();
    let outcome = drive_recovery_finish(&h, "alice@example.com").await;

    let expected = now_at_finish + ChronoDuration::seconds(60);
    assert_eq!(
        outcome.session.session.recovery_cooldown_until,
        Some(expected),
        "the configured sub-floor cool-down is honored, not clamped to the floor",
    );
    assert_eq!(outcome.passkey.recovery_cooldown_until, Some(expected));
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now()),
        "the cool-down is active immediately after finish",
    );
    // Stepping past the short window releases it.
    h.clock.advance(ChronoDuration::seconds(61));
    assert!(
        !outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );
}

#[tokio::test]
async fn recovery_config_with_zero_cooldown_yields_inactive_deadline() {
    // A zero cool-down via the escape hatch stamps a deadline equal to "now",
    // which the predicate treats as already lapsed (comparison is `now < until`).
    let h = Harness::builder()
        .recovery_config(RecoveryConfig {
            cooldown: Duration::ZERO,
            danger_allow_cooldown_below_floor: true,
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "alice@example.com").await;

    let now_at_finish = h.clock.now();
    let outcome = drive_recovery_finish(&h, "alice@example.com").await;

    assert_eq!(
        outcome.session.session.recovery_cooldown_until,
        Some(now_at_finish),
        "a zero cool-down stamps the deadline at the finish instant",
    );
    assert_eq!(outcome.passkey.recovery_cooldown_until, Some(now_at_finish));
    assert!(
        !outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now()),
        "a zero cool-down is already inactive",
    );
}

#[tokio::test]
async fn custom_emails_override_recovery_subjects_and_html() {
    let h = Harness::builder().emails(Arc::new(BrandedEmails)).build();
    let _ = provision_user(&h, "user@example.com").await;
    let mail_before = h.email.sent().len();

    h.recovery
        .request_recovery("user@example.com", SessionContext::default())
        .await
        .expect("request");

    let new = &h.email.sent()[mail_before..];
    assert_eq!(new.len(), 2);
    let subjects: Vec<&str> = new.iter().map(|e| e.subject.as_str()).collect();
    assert!(subjects.contains(&"Acme recovery"));
    assert!(subjects.contains(&"Acme recovery requested"));
    assert!(!subjects.contains(&"Acme recovery completed"));
}

/// A [`PasskeyConfig`] for the harness relying party with the per-user
/// credential cap set to `cap`.
fn capped_passkey_config(cap: u32) -> PasskeyConfig {
    PasskeyConfig {
        max_credentials_per_user: NonZeroU32::new(cap),
        ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
    }
}

#[tokio::test]
async fn recovery_succeeds_when_at_credential_cap() {
    // Recovery is the all-credentials-lost escape hatch: it must land its one
    // new passkey even when the user already sits at the per-user cap, or the
    // cap would brick recovery and lock the user out permanently.
    const CAP: u32 = 2;
    let h = Harness::builder()
        .passkey_config(capped_passkey_config(CAP))
        .build();

    // `provision_user` enrols the first passkey; top up to the cap.
    let user = provision_user(&h, "alice@example.com").await;
    let mut filler = authenticator();
    register_passkey(&h, user.id, &mut filler, Some("second device")).await;
    let at_cap = h
        .credentials
        .list_passkey_summaries_for_user(user.id)
        .await
        .expect("list summaries")
        .len();
    assert_eq!(at_cap, CAP as usize, "user starts exactly at the cap");

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access to your account")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    let consume = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut recovery_wa = ResidentTestAuthenticator::new();
    let attestation = recovery_wa.do_registration(consume.options);
    let outcome = h
        .recovery
        .finish_recovery(
            consume.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("recovery finishes despite the credential cap");

    // The recovery passkey was enrolled and a session was issued.
    assert!(!outcome.session.token.is_empty(), "recovery session issued");
    assert_eq!(outcome.session.session.user_id, user.id);

    let after = h
        .credentials
        .list_passkey_summaries_for_user(user.id)
        .await
        .expect("list summaries")
        .len();
    assert_eq!(
        after,
        CAP as usize + 1,
        "recovery added a credential past the cap"
    );

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&outcome.passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("recovery passkey stored");
    assert_eq!(stored.user_id, user.id);
}

#[tokio::test]
async fn ordinary_registration_still_rejected_at_cap() {
    // Bypassing the cap is reachable only from recovery: an ordinary
    // authenticated re-enrollment at the cap must still be rejected.
    const CAP: u32 = 2;
    let h = Harness::builder()
        .passkey_config(capped_passkey_config(CAP))
        .build();

    let user = provision_user(&h, "alice@example.com").await;
    let mut filler = authenticator();
    register_passkey(&h, user.id, &mut filler, Some("second device")).await;
    assert_eq!(
        h.credentials
            .list_passkey_summaries_for_user(user.id)
            .await
            .expect("list summaries")
            .len(),
        CAP as usize,
        "user starts exactly at the cap",
    );

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("start allowed at the cap");
    let response = filler.do_registration(ccr);
    let err = h
        .passkey
        .finish_registration(
            challenge_id,
            &response,
            Some("third device".into()),
            SessionContext::default(),
        )
        .await
        .expect_err("ordinary registration rejected at the cap");
    assert!(matches!(
        err,
        Error::ResourceLimitExceeded {
            resource: "credentials",
            limit: 2,
        }
    ));
    assert_eq!(
        h.credentials
            .list_passkey_summaries_for_user(user.id)
            .await
            .expect("list summaries")
            .len(),
        CAP as usize,
        "no credential added past the cap",
    );
}
