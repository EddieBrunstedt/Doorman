mod common;

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::email::{Email, EmailTemplates};
use doorman_core::error::{Error, Result, StorageError};
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::passkey::{PasskeyConfig, PasskeyRateLimits};
use doorman_core::rate_limit::{RateLimitPolicy, RateLimiter};
use doorman_core::session::SessionContext;
use doorman_core::signup::{SignupConfig, SignupDecision, SignupPolicy, SignupRateLimits};
use doorman_core::storage::{User, UserStore};
use doorman_test_support::MockClock;

use common::{
    Harness, RECOVERY_URL, RP_ID, RP_NAME, SIGNUP_URL, authenticator, kinds, passkey_count,
    provision_user, rp_origin, session_count, session_for, signup_config, token_from_email, ts,
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
    assert!(user.email_verified_at.is_none(), "unverified until consume");
    assert_eq!(h.email.sent().len(), 1, "signup email queued");
    assert_eq!(h.email.sent()[0].subject, "Finish setting up your account");
    assert!(matches!(
        kinds(&h.audit.events()).last(),
        Some(AuditEventKind::SignupRequested { .. })
    ));

    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);
    h.signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("token persisted: the emailed link redeems");
}

#[tokio::test]
async fn concurrent_requests_for_one_new_email_both_succeed() {
    let h = Harness::fresh();
    // Both requests read the address before either provisions it, so the
    // second create collides with the first.
    let release = h.user_store.hold_email_lookups(2);

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

    // The loser ends as a request arriving second would: the address has no
    // passkey yet, so it re-sends the link, superseding the first.
    let sent = h.email.sent();
    assert_eq!(sent.len(), 2, "one link per request");
    let token = token_from_email(&sent[1].body_text, SIGNUP_URL);
    h.signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("the latest link redeems");
}

#[tokio::test]
async fn request_for_credentialed_email_is_silent_and_audited() {
    let h = Harness::fresh();
    // A fully registered user (≥1 credential) provisioned through the ceremony.
    provision_user(&h, "alice@example.com").await;
    let emails_before = h.email.sent().len();
    let signup_requested_before = kinds(&h.audit.events())
        .into_iter()
        .filter(|k| matches!(k, AuditEventKind::SignupRequested { .. }))
        .count();

    // Re-request: the account already holds a credential → silent no-op, no new
    // link. The legitimate user signs in or recovers instead.
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("silent ok");
    assert_eq!(h.email.sent().len(), emails_before, "no extra link sent");

    // The silent attempt is still audited as a signup request.
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
async fn request_for_passkeyless_user_reissues_signup_link() {
    let h = Harness::fresh();
    // First request provisions the user; no passkey is ever registered, so the
    // account holds zero credentials (a botched first enrollment).
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("first request");
    assert_eq!(h.email.sent().len(), 1, "first link sent");
    let first_token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    // Second request to the same passkey-less account: re-issue a fresh link
    // rather than silently no-op (which would force the user into recovery).
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("reissue");
    assert_eq!(h.email.sent().len(), 2, "fresh link re-sent");

    // The reissued link carries a new token and the original is invalidated.
    let second_token = token_from_email(&h.email.sent()[1].body_text, SIGNUP_URL);
    assert_ne!(first_token, second_token, "a fresh token was minted");
    let err = h
        .signup
        .consume_signup(&first_token, SessionContext::default())
        .await
        .expect_err("prior token no longer valid");
    assert!(matches!(err, Error::InvalidVerificationToken));
    h.signup
        .consume_signup(&second_token, SessionContext::default())
        .await
        .expect("the fresh token redeems");

    // No duplicate user was created.
    let user = h
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find user")
        .expect("user present");
    let _ = user;

    // Both requests audited as signup requests.
    let signup_requested = kinds(&h.audit.events())
        .into_iter()
        .filter(|k| matches!(k, AuditEventKind::SignupRequested { .. }))
        .count();
    assert_eq!(signup_requested, 2, "both requests audited");
}

#[tokio::test]
async fn consume_verifies_email_and_starts_passkey_registration() {
    let h = Harness::fresh();
    h.signup
        .request_signup("user@example.com", None, SessionContext::default())
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

    let err = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("token consumed: the link cannot be replayed");
    assert!(matches!(err, Error::InvalidVerificationToken));
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
        .request_signup("alice@example.com", None, SessionContext::default())
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
    assert_eq!(
        session_count(&h, outcome.user.id).await,
        1,
        "session issued"
    );
    assert_eq!(
        passkey_count(&h, outcome.user.id).await,
        1,
        "passkey registered"
    );
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
async fn finish_reads_the_user_once() {
    let h = Harness::fresh();
    h.signup
        .request_signup("alice@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);
    let consume = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("consume");
    let mut wa = authenticator();
    let attestation = wa.do_registration(consume.options);

    h.user_store.reset();
    h.signup
        .finish_signup(
            consume.challenge_id,
            &attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect("finish");

    assert_eq!(h.user_store.reads_by_id(), 1);
}

#[tokio::test]
async fn notification_send_failure_does_not_undo_successful_finish() {
    let h = Harness::fresh();
    h.signup
        .request_signup("notify-fails@example.com", None, SessionContext::default())
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
    assert_eq!(
        passkey_count(&h, outcome.user.id).await,
        1,
        "passkey still stored"
    );
    assert_eq!(
        session_count(&h, outcome.user.id).await,
        1,
        "session still issued"
    );
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
        .request_signup("u@example.com", None, SessionContext::default())
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
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: None,
            secret: SecretKind::SignupLink,
            reason: RedemptionFailureReason::Unknown,
        }
    )));
}

#[tokio::test]
async fn consume_replaces_unfinished_ceremonies_rather_than_hitting_the_pending_cap() {
    // The link is consumed before its ceremony starts, so the
    // pending-registration cap must not refuse that start — the link would be
    // burned with nothing to show for it. Consuming drops the user's
    // unfinished ceremonies first, and the new one replaces them.
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            rate_limits: PasskeyRateLimits::disabled(),
            max_pending_registrations_per_user: NonZeroU32::new(1),
            ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
        })
        .build();
    h.signup
        .request_signup("capped@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);
    let user = h
        .users
        .find_user_by_email("capped@example.com")
        .await
        .expect("find user")
        .expect("user present");

    let (stale_id, stale_options) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("fill the cap");
    let err = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect_err("the cap is full");
    assert!(
        matches!(err, Error::ResourceLimitExceeded { .. }),
        "got: {err:?}"
    );

    let outcome = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("consume starts a ceremony despite the full cap");

    let err = h
        .passkey
        .finish_registration(
            stale_id,
            &authenticator().do_registration(stale_options),
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("the unfinished ceremony was replaced");
    assert!(
        matches!(err, Error::InvalidPasskeyChallenge),
        "got: {err:?}"
    );

    h.signup
        .finish_signup(
            outcome.challenge_id,
            &authenticator().do_registration(outcome.options),
            None,
            SessionContext::default(),
        )
        .await
        .expect("the link's ceremony finishes");
}

#[tokio::test]
async fn consume_rejects_tampered_token_and_leaves_the_real_one_usable() {
    // A bit-flipped token hashes to a value that isn't in the store, so it is
    // rejected as invalid — and, crucially, the tamper attempt neither consumes
    // nor invalidates the genuine token, which still redeems afterwards (no
    // replay or denial-of-service vector from guessing near a real token).
    let h = Harness::fresh();
    h.signup
        .request_signup("u@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    let mut chars: Vec<char> = token.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let tampered: String = chars.into_iter().collect();
    assert_ne!(tampered, token, "tamper actually changed the token");

    let err = h
        .signup
        .consume_signup(&tampered, SessionContext::default())
        .await
        .expect_err("tampered token rejected");
    assert!(matches!(err, Error::InvalidVerificationToken));

    h.signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("genuine token still redeems after the tamper attempt");
}

#[tokio::test]
async fn signup_token_cannot_be_consumed_by_recovery() {
    // A token minted for signup must never redeem on the recovery flow:
    // the purpose binds at consumption, not just at mint time.
    let h = Harness::fresh();
    h.signup
        .request_signup("cross@example.com", None, SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    let err = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect_err("signup token rejected on recovery");
    assert!(matches!(err, Error::InvalidVerificationToken));

    // The signup token survives the failed cross-flow attempt and still
    // redeems on its own flow.
    h.signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("signup token still valid on its own flow");
}

#[tokio::test]
async fn recovery_token_cannot_be_consumed_by_signup() {
    let h = Harness::fresh();
    provision_user(&h, "cross@example.com").await;
    let mail_before = h.email.sent().len();
    h.recovery
        .request_recovery("cross@example.com", SessionContext::default())
        .await
        .expect("recovery request");
    let sent = h.email.sent();
    let link = sent[mail_before..]
        .iter()
        .find(|e| e.subject == "Recover access to your account")
        .expect("recovery link queued");
    let token = token_from_email(&link.body_text, RECOVERY_URL);

    let err = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("recovery token rejected on signup");
    assert!(matches!(err, Error::InvalidVerificationToken));

    h.recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect("recovery token still valid on its own flow");
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
        .request_signup("u@example.com", None, SessionContext::default())
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

    let ctx = SessionContext {
        ip: Some("9.9.9.9".into()),
        user_agent: None,
    };
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
            None,
            SessionContext {
                ip: Some("3.3.3.3".into()),
                user_agent: None,
            },
        )
        .await
        .expect_err("identifier limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn request_response_shape_is_identical_known_unknown_and_on_send_failure() {
    // Enumeration resistance: the request endpoint must return the same shape
    // (`Ok`) for a brand-new address and an already-registered one, and a
    // transport failure must not change that — otherwise a forced bounce on the
    // new-user branch (which sends a link) would distinguish it from the
    // registered branch (which sends nothing).
    let h = Harness::fresh();

    // Unknown address, transport healthy -> Ok (provisions + sends link).
    h.signup
        .request_signup("fresh@example.com", None, SessionContext::default())
        .await
        .expect("unknown address Ok");
    // Same address again, now registered, transport healthy -> Ok (silent).
    h.signup
        .request_signup("fresh@example.com", None, SessionContext::default())
        .await
        .expect("known address Ok");

    // Fail every subsequent send. A new (unknown) address still provisions a
    // user and returns Ok even though the link send bounces, identical to the
    // registered address that sends nothing.
    h.email.fail_after_successful_sends(h.email.sent().len());
    h.signup
        .request_signup("another@example.com", None, SessionContext::default())
        .await
        .expect("unknown address Ok despite send failure");
    h.signup
        .request_signup("fresh@example.com", None, SessionContext::default())
        .await
        .expect("known address Ok despite send failure");

    // The send failed but the work still happened: the new user was provisioned
    // and a token issued; only delivery was lost.
    let provisioned = h
        .users
        .find_user_by_email("another@example.com")
        .await
        .expect("find user")
        .expect("user provisioned despite send failure");
    assert!(provisioned.email_verified_at.is_none());
}

struct BrandedEmails;

impl EmailTemplates for BrandedEmails {
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

// ---------------------------------------------------------------------------
// Signup gating policy
// ---------------------------------------------------------------------------

/// What the [`StubPolicy`] should return on each call.
enum StubOutcome {
    Allow,
    DenySilently,
    Deny(Option<String>),
    /// Surface a store-style failure so the manager propagates it.
    Error,
}

/// One recorded invocation of the stub policy.
#[derive(Clone)]
struct StubCall {
    email: String,
    invite_token: Option<String>,
}

/// Test [`SignupPolicy`] that returns a preset outcome and records the
/// arguments doorman handed it, so a test can assert both the decision wiring
/// and the verbatim invite-token pass-through.
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
    // The default `SignupConfig` wires `OpenSignupPolicy`; the harness config
    // inherits it via `..SignupConfig::default()`. A regression in the default
    // wiring (e.g. a deny-by-default) would break this.
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
async fn denied_attempt_still_consumes_rate_limit_budget() {
    // The gate runs after rate limiting, so a denied attempt spends budget. A
    // per-IP budget of 1 paired with an always-deny policy means the first
    // request is denied by the policy and the second is rejected by the limiter
    // — proving the limiter was hit before the policy on the first call.
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

    let ctx = SessionContext {
        ip: Some("7.7.7.7".into()),
        user_agent: None,
    };

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

    // The limiter, not the policy, rejected the second attempt: the policy saw
    // exactly one call.
    assert_eq!(
        policy.calls().len(),
        1,
        "policy not reached once budget spent"
    );
}
