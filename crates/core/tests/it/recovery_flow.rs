use crate::common;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::{
    AuditEventKind, RecoveryFailureReason, RedemptionFailureReason, SecretKind,
};
use doorman_core::clock::Clock;
use doorman_core::email::{EmailContent, EmailTemplates};
use doorman_core::error::Error;
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::{RateLimitPolicy, RateLimiter};
use doorman_core::recovery::{RecoveryConfig, RecoveryRateLimits};
use doorman_core::session::{SessionConfig, SessionContext};
use doorman_core::storage::{PasskeyStore, User, UserStatus, UserStore};
use doorman_test_support::MockClock;

use crate::common::{
    Harness, RECOVERY_URL, RP_ID, RP_NAME, authenticator, kinds, make_user, passkey_count,
    provision_user, recovery_config, register_passkey, rp_origin, session_count, session_for,
    token_from_email,
};

#[tokio::test]
async fn request_for_registered_email_sends_link_and_notice() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    let mail_before = h.email.sent().len();

    h.recovery
        .request_recovery("Alice@Example.com", SessionContext::default())
        .await
        .expect("recovery request");

    let new = &h.email.sent()[mail_before..];
    assert_eq!(new.len(), 2, "link + notice queued");
    let subjects: Vec<&str> = new.iter().map(|e| e.subject.as_str()).collect();
    let Some(link_email) = new
        .iter()
        .find(|e| e.subject == "Recover access with a new passkey")
    else {
        panic!("recovery link sent ({subjects:?})");
    };
    let Some(requested_notice) = new
        .iter()
        .find(|e| e.subject == "Security notice: recovery requested")
    else {
        panic!("requested notice sent ({subjects:?})");
    };
    assert_ne!(
        link_email.subject.as_str(),
        requested_notice.subject.as_str()
    );
    assert_ne!(
        link_email.body_text.as_str(),
        requested_notice.body_text.as_str(),
    );
    assert!(requested_notice.body_text.contains("request to recover"));
    assert!(requested_notice.body_text.contains("If this was not you"));

    let audit_kinds = kinds(&h.audit.events());
    assert!(audit_kinds.iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryRequested { user_id: Some(id) } if *id == user.id,
    )));
    h.recovery
        .redeem_recovery_link(
            &token_from_email(&link_email.body_text, RECOVERY_URL),
            SessionContext::default(),
        )
        .await
        .expect("recovery token persisted: the emailed link redeems");
}

#[tokio::test]
async fn request_for_unknown_email_sends_nothing_but_audits() {
    let h = Harness::fresh();
    h.recovery
        .request_recovery("ghost@example.com", SessionContext::default())
        .await
        .expect("silent ok");

    assert!(h.email.sent().is_empty(), "no link sent for unknown email");
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

async fn disable_user(h: &Harness, user: &User) {
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");
}

#[tokio::test]
async fn request_for_disabled_user_sends_nothing_but_audits() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    disable_user(&h, &user).await;
    let mail_before = h.email.sent().len();

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("silent ok for disabled user");

    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no link sent for a disabled user",
    );
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RecoveryFailed {
            reason: RecoveryFailureReason::UserDisabled,
            user_id: Some(id),
        } if *id == user.id,
    )));
}

#[tokio::test]
async fn redeem_refused_for_disabled_user() {
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
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    disable_user(&h, &user).await;

    let err = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect_err("redeem refused for disabled user");
    assert!(matches!(err, Error::UserDisabled));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::RecoveryLink,
            reason: RedemptionFailureReason::UserDisabled,
        } if *id == user.id,
    )));
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
async fn finish_sends_only_the_recovery_completed_notice() {
    let h = Harness::fresh();
    provision_user(&h, "alice@example.com").await;
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");

    let mail_before_finish = h.email.sent().len();
    h.recovery
        .finish_recovery(
            started.challenge_id,
            &authenticator().do_registration(started.options),
            Some("backup device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");

    let sent = h.email.sent();
    let subjects: Vec<&str> = sent[mail_before_finish..]
        .iter()
        .map(|e| e.subject.as_str())
        .collect();
    assert_eq!(subjects, vec!["Security notice: recovery completed"]);
    let completed = &sent[mail_before_finish].body_text;
    assert!(completed.contains("A recovery just completed"));
    assert!(completed.contains("If this was not you"));
}

#[tokio::test]
async fn notice_send_failure_does_not_undo_successful_finish() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let passkeys_before = passkey_count(&h, user.id).await;
    let sessions_before = session_count(&h, user.id).await;

    let mail_before_finish = h.email.sent().len();
    h.email.fail_after_successful_sends(mail_before_finish);

    h.recovery
        .finish_recovery(
            started.challenge_id,
            &authenticator().do_registration(started.options),
            Some("failing notices device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish still succeeds");

    assert_eq!(
        passkey_count(&h, user.id).await,
        passkeys_before + 1,
        "passkey still stored"
    );
    assert_eq!(
        session_count(&h, user.id).await,
        sessions_before + 1,
        "session still issued"
    );
    assert_eq!(
        h.email.sent().len(),
        mail_before_finish,
        "failed notice was not captured",
    );
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
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("first link");
    let first_token = token_from_email(&first_link.body_text, RECOVERY_URL);

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("second");

    let err = h
        .recovery
        .redeem_recovery_link(&first_token, SessionContext::default())
        .await
        .expect_err("first now invalid");
    assert!(matches!(err, Error::InvalidEmailLink));
}

#[tokio::test]
async fn request_response_shape_is_identical_known_unknown_and_on_send_failure() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "known@example.com").await;

    h.recovery
        .request_recovery("ghost@example.com", SessionContext::default())
        .await
        .expect("unknown Ok");
    h.recovery
        .request_recovery("known@example.com", SessionContext::default())
        .await
        .expect("known Ok");

    let first_link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("first link sent");
    let first_token = token_from_email(&first_link.body_text, RECOVERY_URL);

    h.email.fail_after_successful_sends(h.email.sent().len());
    h.recovery
        .request_recovery("known@example.com", SessionContext::default())
        .await
        .expect("known Ok despite send failures");
    h.recovery
        .request_recovery("ghost@example.com", SessionContext::default())
        .await
        .expect("unknown Ok despite send failures");

    let bounced_link = h
        .email
        .bounced()
        .into_iter()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("the second link was attempted");
    let err = h
        .recovery
        .redeem_recovery_link(&first_token, SessionContext::default())
        .await
        .expect_err("the earlier link was invalidated");
    assert!(matches!(err, Error::InvalidEmailLink));
    h.recovery
        .redeem_recovery_link(
            &token_from_email(&bounced_link.body_text, RECOVERY_URL),
            SessionContext::default(),
        )
        .await
        .expect("recovery token issued despite send failure");
}

struct BrandedEmails;

impl EmailTemplates for BrandedEmails {
    fn recovery_email(&self, _user: &User, url: &str) -> EmailContent {
        EmailContent {
            subject: "Acme recovery".to_string(),
            body_text: format!("Open {url}"),
            body_html: Some(format!("<a href=\"{url}\">Open</a>")),
        }
    }

    fn recovery_requested_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Acme recovery requested".to_string(),
            body_text: "Recovery requested".to_string(),
            body_html: None,
        }
    }

    fn recovery_completed_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Acme recovery completed".to_string(),
            body_text: "Recovery completed".to_string(),
            body_html: None,
        }
    }
}

#[tokio::test]
async fn recovery_cool_down_runs_from_the_later_of_redeem_and_finish() {
    for (case, clock_step) in [
        ("slow ceremony", ChronoDuration::minutes(4)),
        ("clock stepped back", -ChronoDuration::hours(1)),
    ] {
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
            .find(|e| e.subject == "Recover access with a new passkey")
            .expect("link queued");
        let token = token_from_email(&link.body_text, RECOVERY_URL);

        let redeemed_at = h.clock.now();
        let started = h
            .recovery
            .redeem_recovery_link(&token, SessionContext::default())
            .await
            .expect("redeem");
        let mut wa = authenticator();
        let attestation = wa.do_registration(started.options);
        h.clock.advance(clock_step);
        let finished_at = h.clock.now();
        let outcome = h
            .recovery
            .finish_recovery(
                started.challenge_id,
                &attestation,
                Some("backup device".into()),
                SessionContext::default(),
            )
            .await
            .expect("finish");

        let expected = redeemed_at.max(finished_at) + ChronoDuration::hours(24);
        assert_eq!(
            outcome.session.session.recovery_cool_down_until,
            Some(expected),
            "{case}",
        );
        assert_eq!(
            outcome.passkey.recovery_cool_down_until,
            Some(expected),
            "{case}"
        );
        let stored = h
            .passkeys
            .find_passkey_by_credential_id(&outcome.passkey.credential_id)
            .await
            .expect("find passkey")
            .expect("passkey stored");
        assert_eq!(stored.recovery_cool_down_until, Some(expected), "{case}");
    }
}

#[tokio::test]
async fn recovery_created_passkey_login_inherits_active_cool_down() {
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
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let mut wa = authenticator();
    let attestation = wa.do_registration(started.options);
    let outcome = h
        .recovery
        .finish_recovery(
            started.challenge_id,
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
        .expect("finish auth")
        .session;

    assert_eq!(
        issued.session.recovery_cool_down_until,
        outcome.session.session.recovery_cool_down_until,
    );
    assert!(issued.session.is_in_recovery_cool_down());
}

#[tokio::test]
async fn pre_existing_passkey_login_stays_outside_recovery_cool_down() {
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
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let mut recovery_wa = authenticator();
    let attestation = recovery_wa.do_registration(started.options);
    let outcome = h
        .recovery
        .finish_recovery(
            started.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");
    assert!(outcome.session.session.is_in_recovery_cool_down());

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
        .expect("finish auth")
        .session;

    assert_eq!(issued.session.recovery_cool_down_until, None);
}

#[tokio::test]
async fn recovery_created_passkey_login_after_cool_down_carries_no_cool_down() {
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
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let mut wa = authenticator();
    let attestation = wa.do_registration(started.options);
    let outcome = h
        .recovery
        .finish_recovery(
            started.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");
    assert_eq!(outcome.user.id, user.id);
    assert!(outcome.session.session.is_in_recovery_cool_down());

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
        .expect("finish auth")
        .session;

    assert_eq!(issued.session.recovery_cool_down_until, None);
}

#[tokio::test]
async fn passkey_registered_during_cool_down_inherits_its_deadline() {
    let h = Harness::fresh();
    let _ = provision_user(&h, "alice@example.com").await;
    let outcome = drive_recovery_finish(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::minutes(10));
    let resolved = h
        .session_manager
        .resolve(&outcome.session.token)
        .await
        .expect("the recovery session is live");

    let mut wa = authenticator();
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&resolved)
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let passkey = h
        .session_manager
        .finish_passkey_registration(
            &resolved,
            challenge_id,
            &response,
            None,
            SessionContext::default(),
        )
        .await
        .expect("finish_registration");

    assert!(outcome.session.session.recovery_cool_down_until.is_some());
    assert_eq!(
        passkey.recovery_cool_down_until,
        outcome.session.session.recovery_cool_down_until,
    );

    let (auth_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(options, &passkey.credential_id);
    let issued = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("finish auth")
        .session;
    assert_eq!(
        issued.session.recovery_cool_down_until,
        outcome.session.session.recovery_cool_down_until,
    );
}

#[tokio::test]
async fn passkey_registered_after_cool_down_carries_no_cool_down() {
    let h = Harness::builder()
        .session_config(SessionConfig::default())
        .build();
    let _ = provision_user(&h, "alice@example.com").await;
    let outcome = drive_recovery_finish(&h, "alice@example.com").await;
    h.clock
        .advance(ChronoDuration::hours(24) + ChronoDuration::seconds(1));
    let resolved = h
        .session_manager
        .resolve(&outcome.session.token)
        .await
        .expect("the recovery session outlives its cool-down");
    assert!(resolved.recovery_cool_down_until.is_some());
    assert!(!resolved.is_in_recovery_cool_down());

    let mut wa = authenticator();
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&resolved)
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let passkey = h
        .session_manager
        .finish_passkey_registration(
            &resolved,
            challenge_id,
            &response,
            None,
            SessionContext::default(),
        )
        .await
        .expect("finish_registration");

    assert_eq!(passkey.recovery_cool_down_until, None);
}

async fn drive_recovery_finish(
    h: &Harness,
    email: &str,
) -> doorman_core::passkey::RegistrationOutcome {
    h.recovery
        .request_recovery(email, SessionContext::default())
        .await
        .expect("request");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);
    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let mut wa = authenticator();
    let attestation = wa.do_registration(started.options);
    h.recovery
        .finish_recovery(
            started.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish")
}

#[tokio::test]
async fn recovery_config_with_subhour_cool_down_honors_configured_cool_down() {
    let cool_down = Duration::from_secs(60);
    let h = Harness::builder()
        .recovery_config(RecoveryConfig {
            cool_down,
            danger_allow_cool_down_below_floor: true,
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "alice@example.com").await;

    let now_at_finish = h.clock.now();
    let outcome = drive_recovery_finish(&h, "alice@example.com").await;

    let expected = now_at_finish + ChronoDuration::seconds(60);
    assert_eq!(
        outcome.session.session.recovery_cool_down_until,
        Some(expected),
        "the configured sub-floor cool-down is honored, not clamped to the floor",
    );
    assert_eq!(outcome.passkey.recovery_cool_down_until, Some(expected));
    assert!(
        outcome.session.session.is_in_recovery_cool_down(),
        "the cool-down is active immediately after finish",
    );
    h.clock.advance(ChronoDuration::seconds(61));
    let resolved = h
        .session_manager
        .resolve(&outcome.session.token)
        .await
        .expect("the recovery session outlives its cool-down");
    assert!(!resolved.is_in_recovery_cool_down());
}

#[tokio::test]
async fn recovery_config_with_zero_cool_down_yields_inactive_deadline() {
    let h = Harness::builder()
        .recovery_config(RecoveryConfig {
            cool_down: Duration::ZERO,
            danger_allow_cool_down_below_floor: true,
            ..recovery_config()
        })
        .build();
    let _ = provision_user(&h, "alice@example.com").await;

    let now_at_finish = h.clock.now();
    let outcome = drive_recovery_finish(&h, "alice@example.com").await;

    assert_eq!(
        outcome.passkey.recovery_cool_down_until,
        Some(now_at_finish),
        "a zero cool-down stamps the deadline at the finish instant",
    );
    assert_eq!(
        outcome.session.session.recovery_cool_down_until, None,
        "the session inherits no cool-down that is already over",
    );
    assert!(
        !outcome.session.session.is_in_recovery_cool_down(),
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

fn capped_passkey_config(cap: u32) -> PasskeyConfig {
    PasskeyConfig {
        max_passkeys_per_user: NonZeroU32::new(cap),
        ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
    }
}

#[tokio::test]
async fn recovery_succeeds_when_at_passkey_cap() {
    const CAP: u32 = 2;
    let h = Harness::builder()
        .passkey_config(capped_passkey_config(CAP))
        .build();

    let user = provision_user(&h, "alice@example.com").await;
    let mut filler = authenticator();
    register_passkey(&h, user.id, &mut filler, Some("second device")).await;
    let at_cap = h
        .passkeys
        .list_passkeys_for_user(user.id)
        .await
        .expect("list passkeys")
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
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    let started = h
        .recovery
        .redeem_recovery_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let mut recovery_wa = authenticator();
    let attestation = recovery_wa.do_registration(started.options);
    let outcome = h
        .recovery
        .finish_recovery(
            started.challenge_id,
            &attestation,
            Some("recovery device".into()),
            SessionContext::default(),
        )
        .await
        .expect("recovery finishes despite the passkey cap");

    assert!(!outcome.session.token.is_empty(), "recovery session issued");
    assert_eq!(outcome.session.session.user_id, user.id);

    let after = h
        .passkeys
        .list_passkeys_for_user(user.id)
        .await
        .expect("list passkeys")
        .len();
    assert_eq!(
        after,
        CAP as usize + 1,
        "recovery added a passkey past the cap"
    );

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&outcome.passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("recovery passkey stored");
    assert_eq!(stored.user_id, user.id);
}

#[tokio::test]
async fn ordinary_registration_still_rejected_at_cap() {
    const CAP: u32 = 2;
    let h = Harness::builder()
        .passkey_config(capped_passkey_config(CAP))
        .build();

    let user = provision_user(&h, "alice@example.com").await;
    let mut filler = authenticator();
    register_passkey(&h, user.id, &mut filler, Some("second device")).await;
    assert_eq!(
        passkey_count(&h, user.id).await,
        u64::from(CAP),
        "user starts exactly at the cap",
    );

    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session)
        .await
        .expect("start allowed at the cap");
    let response = filler.do_registration(ccr);
    let err = h
        .session_manager
        .finish_passkey_registration(
            &session,
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
            resource: "passkeys",
            limit: 2,
        }
    ));
    assert_eq!(
        passkey_count(&h, user.id).await,
        u64::from(CAP),
        "no passkey added past the cap",
    );
}
