use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::email::{EmailContent, EmailTemplates};
use doorman_core::error::{Error, Result, StorageError};
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::rate_limit::{RateLimitPolicy, RateLimiter};
use doorman_core::session::SessionContext;
use doorman_core::signup::{SignupConfig, SignupDecision, SignupPolicy, SignupRateLimits};
use doorman_core::storage::{PasskeyStore, User, UserStore};
use doorman_test_support::MockClock;

use crate::common::{
    Harness, SIGNUP_URL, authenticator, kinds, provision_user, signup_config, token_from_email, ts,
    within_deadline,
};

#[tokio::test]
async fn request_provisions_user_for_new_email() {
    let h = Harness::fresh();
    h.signup
        .request_signup("Alice@Example.com", None, SessionContext::default())
        .await
        .expect("request");

    let user = h
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find user")
        .expect("user provisioned");
    assert!(
        user.signed_up_at.is_none(),
        "signup unfinished until its passkey is registered"
    );
    assert_eq!(h.email.sent().len(), 1, "signup email queued");
    assert_eq!(h.email.sent()[0].subject, "Finish signing up");
    assert!(matches!(
        kinds(&h.audit.events()).last(),
        Some(AuditEventKind::SignupRequested { .. })
    ));

    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);
    h.signup
        .redeem_signup_link(&token, SessionContext::default())
        .await
        .expect("token persisted: the emailed link redeems");
}

#[tokio::test]
async fn concurrent_requests_for_one_new_email_both_succeed() {
    let h = Harness::fresh();
    let release = h.user_store.hold_user_creates(2);

    let (first, second, _) = within_deadline(async {
        tokio::join!(
            h.signup
                .request_signup("race@example.com", None, SessionContext::default()),
            h.signup
                .request_signup("race@example.com", None, SessionContext::default()),
            release.wait(),
        )
    })
    .await;
    first.expect("first request");
    second.expect("the request that lost the race still succeeds");

    let sent = h.email.sent();
    assert_eq!(sent.len(), 2, "one link per request");
    let token = token_from_email(&sent[1].body_text, SIGNUP_URL);
    h.signup
        .redeem_signup_link(&token, SessionContext::default())
        .await
        .expect("the latest link redeems");
}

#[tokio::test]
async fn request_for_email_with_passkeys_is_silent_and_audited() {
    let h = Harness::fresh();
    provision_user(&h, "alice@example.com").await;
    let emails_before = h.email.sent().len();
    let signup_requested_before = kinds(&h.audit.events())
        .into_iter()
        .filter(|k| matches!(k, AuditEventKind::SignupRequested { .. }))
        .count();

    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("silent ok");
    assert_eq!(h.email.sent().len(), emails_before, "no extra link sent");

    let signup_requested = kinds(&h.audit.events())
        .into_iter()
        .filter(|k| matches!(k, AuditEventKind::SignupRequested { .. }))
        .count();
    assert_eq!(
        signup_requested,
        signup_requested_before + 1,
        "silent request still audited",
    );
}

#[tokio::test]
async fn request_before_signup_finished_reissues_signup_link() {
    let h = Harness::fresh();
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("first request");
    assert_eq!(h.email.sent().len(), 1, "first link sent");
    let first_token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("reissue");
    assert_eq!(h.email.sent().len(), 2, "fresh link re-sent");

    let second_token = token_from_email(&h.email.sent()[1].body_text, SIGNUP_URL);
    assert_ne!(first_token, second_token, "a fresh token was minted");
    let err = h
        .signup
        .redeem_signup_link(&first_token, SessionContext::default())
        .await
        .expect_err("prior token no longer valid");
    assert!(matches!(err, Error::InvalidEmailLink));
    h.signup
        .redeem_signup_link(&second_token, SessionContext::default())
        .await
        .expect("the fresh token redeems");

    let user = h
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find user")
        .expect("user present");
    let _ = user;

    let signup_requested = kinds(&h.audit.events())
        .into_iter()
        .filter(|k| matches!(k, AuditEventKind::SignupRequested { .. }))
        .count();
    assert_eq!(signup_requested, 2, "both requests audited");
}

#[tokio::test]
async fn request_after_signup_finished_sends_no_link_even_without_passkeys() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;
    h.passkeys
        .delete_passkeys_for_user(user.id)
        .await
        .expect("drop every passkey");
    let mail_before = h.email.sent().len();

    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("silent ok");

    assert_eq!(h.email.sent().len(), mail_before, "no signup link sent");
    assert!(matches!(
        kinds(&h.audit.events()).last(),
        Some(AuditEventKind::SignupRequested { user_id }) if *user_id == user.id
    ));
}

fn last_signup_token(h: &Harness) -> String {
    let mail = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Finish signing up")
        .expect("signup link queued");
    token_from_email(&mail.body_text, SIGNUP_URL)
}

fn assert_last_refused_as_signup_finished(h: &Harness, secret: SecretKind) {
    let last = h.audit.events().last().map(|e| e.kind.clone());
    assert!(
        matches!(
            last,
            Some(AuditEventKind::RedemptionFailed {
                user_id: Some(_),
                secret: s,
                reason: RedemptionFailureReason::SignupFinished,
            }) if s == secret
        ),
        "expected {secret:?} refused as signup finished, got {last:?}",
    );
}

#[tokio::test]
async fn signup_link_issued_before_signup_finished_is_refused_after() {
    let h = Harness::fresh();
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("first request");
    let started = h
        .signup
        .redeem_signup_link(&last_signup_token(&h), SessionContext::default())
        .await
        .expect("redeem first link");
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("second request");
    let spare = last_signup_token(&h);
    let outcome = h
        .signup
        .finish_signup(
            started.challenge_id,
            &authenticator().do_registration(started.options),
            None,
            SessionContext::default(),
        )
        .await
        .expect("finish signup");

    let err = h
        .signup
        .redeem_signup_link(&spare, SessionContext::default())
        .await
        .expect_err("the spare link no longer reaches the user");
    assert!(matches!(err, Error::InvalidEmailLink), "{err:?}");
    assert_last_refused_as_signup_finished(&h, SecretKind::SignupLink);
    assert_eq!(
        h.passkeys
            .list_passkeys_for_user(outcome.user.id)
            .await
            .expect("list passkeys")
            .len(),
        1,
    );
}

#[tokio::test]
async fn signup_registration_cannot_finish_once_signup_finished_elsewhere() {
    let h = Harness::fresh();
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let started = h
        .signup
        .redeem_signup_link(&last_signup_token(&h), SessionContext::default())
        .await
        .expect("redeem");
    let user = h
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find user")
        .expect("user present");
    // Stands in for a racing signup registration that finished first.
    h.users
        .mark_signed_up(user.id, h.clock.now())
        .await
        .expect("finish signup elsewhere");

    let err = h
        .signup
        .finish_signup(
            started.challenge_id,
            &authenticator().do_registration(started.options),
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("a signup registration never reaches a user who finished signup");
    assert!(matches!(err, Error::InvalidPasskeyChallenge), "{err:?}");
    assert_last_refused_as_signup_finished(&h, SecretKind::RegistrationChallenge);
    assert!(
        h.passkeys
            .list_passkeys_for_user(user.id)
            .await
            .expect("list passkeys")
            .is_empty(),
    );
}

#[tokio::test]
async fn redeem_starts_passkey_registration() {
    let h = Harness::fresh();
    h.signup
        .request_signup("user@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    let outcome = h
        .signup
        .redeem_signup_link(&token, SessionContext::default())
        .await
        .expect("redeem");
    let _ = outcome.challenge_id;
    let _ = outcome.options;

    let err = h
        .signup
        .redeem_signup_link(&token, SessionContext::default())
        .await
        .expect_err("token redeemed: the link cannot be replayed");
    assert!(matches!(err, Error::InvalidEmailLink));
    let user = h
        .users
        .find_user_by_email("user@example.com")
        .await
        .expect("find user")
        .expect("user present");
    assert!(
        user.signed_up_at.is_none(),
        "signup unfinished until its passkey is registered",
    );
    assert!(
        kinds(&h.audit.events())
            .iter()
            .any(|k| matches!(k, AuditEventKind::SignupLinkRedeemed { .. })),
    );
}

#[tokio::test]
async fn finish_sends_no_security_notice() {
    let h = Harness::fresh();
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);
    let started = h
        .signup
        .redeem_signup_link(&token, SessionContext::default())
        .await
        .expect("redeem");

    let mail_before_finish = h.email.sent().len();
    let outcome = h
        .signup
        .finish_signup(
            started.challenge_id,
            &authenticator().do_registration(started.options),
            Some("alice device".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish");

    assert!(outcome.user.signed_up_at.is_some(), "signup finished");
    assert_eq!(h.email.sent().len(), mail_before_finish);
}

#[tokio::test]
async fn request_rejects_invalid_email() {
    let h = Harness::fresh();
    let err = h
        .signup
        .request_signup("not-an-email", None, SessionContext::default())
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

    let ctx = SessionContext::new(Some("9.9.9.9".parse().expect("ip")), None);
    h.signup
        .request_signup("a@example.com", None, ctx.clone())
        .await
        .expect("1");
    h.signup
        .request_signup("b@example.com", None, ctx.clone())
        .await
        .expect("2");
    let err = h
        .signup
        .request_signup("c@example.com", None, ctx)
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
                None,
                SessionContext::new(Some(ip.parse().expect("ip")), None),
            )
            .await
            .expect("within identifier budget");
    }

    let err = h
        .signup
        .request_signup(
            "target@example.com",
            None,
            SessionContext::new(Some("3.3.3.3".parse().expect("ip")), None),
        )
        .await
        .expect_err("identifier limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn request_response_shape_is_identical_known_unknown_and_on_send_failure() {
    let h = Harness::fresh();

    h.signup
        .request_signup("fresh@example.com", None, SessionContext::default())
        .await
        .expect("unknown address Ok");
    h.signup
        .request_signup("fresh@example.com", None, SessionContext::default())
        .await
        .expect("known address Ok");

    h.email.fail_after_successful_sends(h.email.sent().len());
    h.signup
        .request_signup("another@example.com", None, SessionContext::default())
        .await
        .expect("unknown address Ok despite send failure");
    h.signup
        .request_signup("fresh@example.com", None, SessionContext::default())
        .await
        .expect("known address Ok despite send failure");

    let provisioned = h
        .users
        .find_user_by_email("another@example.com")
        .await
        .expect("find user")
        .expect("user provisioned despite send failure");
    assert!(provisioned.signed_up_at.is_none());
}

struct BrandedEmails;

impl EmailTemplates for BrandedEmails {
    fn signup_email(&self, _user: &User, url: &str) -> EmailContent {
        EmailContent {
            subject: "Acme signup".to_string(),
            body_text: format!("Open {url}"),
            body_html: Some(format!("<a href=\"{url}\">Open</a>")),
        }
    }
}

#[tokio::test]
async fn custom_emails_override_signup_subject_and_html() {
    let h = Harness::builder().emails(Arc::new(BrandedEmails)).build();

    h.signup
        .request_signup("user@example.com", None, SessionContext::default())
        .await
        .expect("request");

    let sent = h.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Acme signup");
    assert!(sent[0].body_text.starts_with("Open "));
    assert!(sent[0].body_html.is_some());
}

enum StubOutcome {
    Allow,
    DenySilently,
    Deny(Option<String>),
    Error,
}

#[derive(Clone)]
struct StubCall {
    email: String,
    invite_token: Option<String>,
}

struct StubPolicy {
    outcome: StubOutcome,
    calls: Mutex<Vec<StubCall>>,
}

impl StubPolicy {
    fn new(outcome: StubOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<StubCall> {
        self.calls.lock().expect("policy calls lock").clone()
    }
}

#[async_trait]
impl SignupPolicy for StubPolicy {
    async fn evaluate(
        &self,
        email: &str,
        invite_token: Option<&str>,
        _context: &SessionContext,
    ) -> Result<SignupDecision> {
        self.calls
            .lock()
            .expect("policy calls lock")
            .push(StubCall {
                email: email.to_owned(),
                invite_token: invite_token.map(ToOwned::to_owned),
            });
        match &self.outcome {
            StubOutcome::Allow => Ok(SignupDecision::Allow),
            StubOutcome::DenySilently => Ok(SignupDecision::DenySilently),
            StubOutcome::Deny(reason) => Ok(SignupDecision::Deny {
                reason: reason.clone(),
            }),
            StubOutcome::Error => Err(Error::Storage(StorageError::msg("invite store down"))),
        }
    }
}

fn harness_with_policy(policy: Arc<dyn SignupPolicy>) -> Harness {
    Harness::builder()
        .signup_config(SignupConfig {
            policy,
            ..signup_config()
        })
        .build()
}

#[tokio::test]
async fn default_open_policy_completes_signup() {
    let h = Harness::fresh();
    h.signup
        .request_signup("open@example.com", None, SessionContext::default())
        .await
        .expect("default-open request succeeds");

    assert_eq!(h.email.sent().len(), 1, "signup link sent");
    assert!(
        h.users
            .find_user_by_email("open@example.com")
            .await
            .expect("find user")
            .is_some(),
        "user provisioned under the open policy"
    );
}

#[tokio::test]
async fn deny_silently_returns_ok_without_email_or_user() {
    let policy = StubPolicy::new(StubOutcome::DenySilently);
    let h = harness_with_policy(policy.clone());

    h.signup
        .request_signup("blocked@example.com", None, SessionContext::default())
        .await
        .expect("silent denial returns Ok");

    assert_eq!(h.email.sent().len(), 0, "no link sent on silent denial");
    assert!(
        h.users
            .find_user_by_email("blocked@example.com")
            .await
            .expect("find user")
            .is_none(),
        "no user provisioned on silent denial"
    );
    assert!(
        matches!(
            kinds(&h.audit.events()).last(),
            Some(AuditEventKind::SignupDenied)
        ),
        "silent denial is audited"
    );
}

#[tokio::test]
async fn deny_returns_typed_error_without_email_or_user() {
    let policy = StubPolicy::new(StubOutcome::Deny(Some("not on the allowlist".into())));
    let h = harness_with_policy(policy.clone());

    let err = h
        .signup
        .request_signup("blocked@example.com", None, SessionContext::default())
        .await
        .expect_err("deny surfaces a typed error");
    assert!(matches!(err, Error::SignupNotAllowed));

    assert_eq!(h.email.sent().len(), 0, "no link sent on denial");
    assert!(
        h.users
            .find_user_by_email("blocked@example.com")
            .await
            .expect("find user")
            .is_none(),
        "no user provisioned on denial"
    );
    assert!(matches!(
        kinds(&h.audit.events()).last(),
        Some(AuditEventKind::SignupDenied)
    ));
}

#[tokio::test]
async fn invite_token_is_passed_through_verbatim() {
    let policy = StubPolicy::new(StubOutcome::Allow);
    let h = harness_with_policy(policy.clone());

    h.signup
        .request_signup(
            "invited@example.com",
            Some("opaque-invite-blob-123"),
            SessionContext::default(),
        )
        .await
        .expect("request");
    h.signup
        .request_signup("walkin@example.com", None, SessionContext::default())
        .await
        .expect("request");

    let calls = policy.calls();
    assert_eq!(calls.len(), 2, "policy evaluated on every request");
    assert_eq!(calls[0].email, "invited@example.com");
    assert_eq!(
        calls[0].invite_token.as_deref(),
        Some("opaque-invite-blob-123"),
        "token handed to the policy byte-for-byte",
    );
    assert_eq!(calls[1].invite_token, None, "absent token arrives as None");
}

#[tokio::test]
async fn policy_error_propagates_and_provisions_nothing() {
    let policy = StubPolicy::new(StubOutcome::Error);
    let h = harness_with_policy(policy.clone());

    let err = h
        .signup
        .request_signup("err@example.com", None, SessionContext::default())
        .await
        .expect_err("policy store failure propagates");
    assert!(matches!(err, Error::Storage(_)));

    assert_eq!(
        h.email.sent().len(),
        0,
        "no link sent when the policy errors"
    );
    assert!(
        h.users
            .find_user_by_email("err@example.com")
            .await
            .expect("find user")
            .is_none(),
        "no user provisioned when the policy errors"
    );
}

#[tokio::test]
async fn denied_attempt_still_spends_rate_limit_budget() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = StubPolicy::new(StubOutcome::Deny(None));
    let h = Harness::builder()
        .signup_limiter(limiter)
        .signup_config(SignupConfig {
            rate_limits: SignupRateLimits {
                request_per_ip: Some(RateLimitPolicy::new(1, Duration::from_secs(60 * 60))),
                ..SignupRateLimits::disabled()
            },
            policy: policy.clone(),
            ..signup_config()
        })
        .build();

    let ctx = SessionContext::new(Some("7.7.7.7".parse().expect("ip")), None);

    let first = h
        .signup
        .request_signup("a@example.com", None, ctx.clone())
        .await
        .expect_err("first attempt denied by policy");
    assert!(matches!(first, Error::SignupNotAllowed));

    let second = h
        .signup
        .request_signup("b@example.com", None, ctx)
        .await
        .expect_err("second attempt rejected by the spent budget");
    assert!(matches!(second, Error::RateLimited { .. }));

    assert_eq!(
        policy.calls().len(),
        1,
        "policy not reached once budget spent"
    );
}
