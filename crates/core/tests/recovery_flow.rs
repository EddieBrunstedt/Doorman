use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditEvent, AuditEventKind, AuditSink, RecoveryFailureReason};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::email::{BauthEmails, Email, EmailSender};
use bauth_core::error::Error;
use bauth_core::memory::{
    CapturingEmailSender, InMemoryAuditSink, InMemoryPasskeyChallengeStore,
    InMemoryPasskeyCredentialStore, InMemoryRateLimiter, InMemorySessionStore, InMemoryUserStore,
    InMemoryVerificationTokenStore,
};
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimitPolicy, RateLimiter};
use bauth_core::recovery::{
    RecoveryConfig, RecoveryManager, RecoveryRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use bauth_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, User, UserStore,
    VerificationTokenStore,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
const RP_ID: &str = "localhost";
const RP_NAME: &str = "bauth tests";

fn rp_origin() -> Url {
    Url::parse("http://localhost:8080").expect("valid url")
}

fn auth_origin() -> AuthUrl {
    AuthUrl::parse("http://localhost:8080").expect("valid auth url")
}

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

#[allow(dead_code)]
struct Harness {
    recovery: RecoveryManager,
    signup: SignupManager,
    users: Arc<InMemoryUserStore>,
    sessions: Arc<InMemorySessionStore>,
    tokens: Arc<InMemoryVerificationTokenStore>,
    credentials: Arc<InMemoryPasskeyCredentialStore>,
    audit: Arc<InMemoryAuditSink>,
    email: Arc<CapturingEmailSender>,
    clock: Arc<MockClock>,
}

fn default_config() -> RecoveryConfig {
    RecoveryConfig {
        url_template: RECOVERY_URL.to_string(),
        rate_limits: RecoveryRateLimits::disabled(),
        ..RecoveryConfig::default()
    }
}

fn fresh(config: RecoveryConfig) -> Harness {
    fresh_with_limiter(config, Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>)
}

fn fresh_with_limiter(config: RecoveryConfig, limiter: Arc<dyn RateLimiter>) -> Harness {
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let tokens: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let credentials: Arc<InMemoryPasskeyCredentialStore> =
        Arc::new(InMemoryPasskeyCredentialStore::new());
    let challenges: Arc<InMemoryPasskeyChallengeStore> =
        Arc::new(InMemoryPasskeyChallengeStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let session_manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let passkey_manager = PasskeyManager::new(
        users.clone() as Arc<dyn UserStore>,
        credentials.clone() as Arc<dyn PasskeyCredentialStore>,
        challenges.clone() as Arc<dyn PasskeyChallengeStore>,
        session_manager.clone(),
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
    )
    .expect("build passkey manager");
    let signup = SignupManager::new(
        users.clone() as Arc<dyn UserStore>,
        tokens.clone() as Arc<dyn VerificationTokenStore>,
        passkey_manager.clone(),
        session_manager.clone(),
        email.clone() as Arc<dyn EmailSender>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>,
        SignupConfig {
            url_template: SIGNUP_URL.to_string(),
            rate_limits: SignupRateLimits::disabled(),
            ..SignupConfig::default()
        },
    );
    let recovery = RecoveryManager::new(
        users.clone() as Arc<dyn UserStore>,
        tokens.clone() as Arc<dyn VerificationTokenStore>,
        passkey_manager,
        session_manager,
        email.clone() as Arc<dyn EmailSender>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        limiter,
        config,
    );
    Harness {
        recovery,
        signup,
        users,
        sessions,
        tokens,
        credentials,
        audit,
        email,
        clock,
    }
}

fn token_from_email(body: &str, template: &str) -> String {
    let prefix = template
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("token follows prefix")
        .to_string()
}

fn kinds(events: &[AuditEvent]) -> Vec<AuditEventKind> {
    events.iter().map(|e| e.kind.clone()).collect()
}

/// Drive a full signup flow against `h` so subsequent recovery tests
/// have a registered user with a passkey.
async fn provision_user(h: &Harness, email: &str) -> User {
    h.signup
        .request_signup(email, SessionContext::default())
        .await
        .expect("signup request");
    let signup_email = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Finish setting up your account")
        .expect("signup link queued");
    let token = token_from_email(&signup_email.body_text, SIGNUP_URL);

    let consume = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("signup consume");

    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .signup
        .finish_signup(
            consume.challenge_id,
            &attestation,
            Some("initial device".into()),
            SessionContext::default(),
        )
        .await
        .expect("signup finish");
    outcome.user
}

/// Test authenticator that wraps a SoftPasskey and relaxes resident-key
/// requirements (SoftPasskey can't create resident keys).
struct ResidentTestAuthenticator {
    inner: WebauthnAuthenticator<SoftPasskey>,
}

impl ResidentTestAuthenticator {
    fn new() -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
        }
    }

    fn do_registration(
        &mut self,
        challenge: CreationChallengeResponse,
    ) -> RegisterPublicKeyCredential {
        let mut compatible = challenge;
        let selection = compatible
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("authenticator selection present");
        selection.require_resident_key = false;
        selection.resident_key = None;
        self.inner
            .do_registration(auth_origin(), compatible)
            .expect("authenticator register")
    }
}

#[tokio::test]
async fn request_for_registered_email_sends_link_and_notification() {
    let h = fresh(default_config());
    let user = provision_user(&h, "alice@example.com").await;
    let mail_before = h.email.sent().len();

    h.recovery
        .request_recovery("Alice@Example.com", SessionContext::default())
        .await
        .expect("recovery request");

    let new = &h.email.sent()[mail_before..];
    assert_eq!(new.len(), 2, "link + notification queued");
    let subjects: Vec<&str> = new.iter().map(|e| e.subject.as_str()).collect();
    assert!(
        subjects.contains(&"Recover access to your account"),
        "recovery link sent ({subjects:?})",
    );
    assert!(
        subjects.contains(&"Security notice: account recovery activity"),
        "notification sent ({subjects:?})",
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
    let h = fresh(default_config());
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

#[tokio::test]
async fn rate_limit_per_email_blocks_after_budget() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = fresh_with_limiter(
        RecoveryConfig {
            rate_limits: RecoveryRateLimits {
                request_per_identifier: Some(policy),
                ..RecoveryRateLimits::disabled()
            },
            ..default_config()
        },
        limiter,
    );
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
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = fresh_with_limiter(
        RecoveryConfig {
            rate_limits: RecoveryRateLimits {
                request_per_ip: Some(policy),
                ..RecoveryRateLimits::disabled()
            },
            ..default_config()
        },
        limiter,
    );
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
    let h = fresh(default_config());
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
    let h = fresh(RecoveryConfig {
        token_lifetime: Duration::from_secs(60),
        ..default_config()
    });
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
    let h = fresh(default_config());
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

    let after_finish = &h.email.sent()[mail_before_finish..];
    assert_eq!(after_finish.len(), 1, "success notification sent");
    assert_eq!(
        after_finish[0].subject,
        "Security notice: account recovery activity",
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
    let h = fresh(default_config());
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
    let h = fresh(default_config());
    let err = h
        .recovery
        .request_recovery("not-an-email", SessionContext::default())
        .await
        .expect_err("invalid email");
    assert!(matches!(err, Error::InvalidEmail));
}

#[tokio::test]
async fn signup_token_cannot_be_redeemed_via_recovery_consume() {
    let h = fresh(default_config());
    // Take a fresh signup token (the user is in an "unverified" state
    // after signup request but before signup consume).
    h.signup
        .request_signup("pending@example.com", SessionContext::default())
        .await
        .expect("signup request");
    let signup_email = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Finish setting up your account")
        .expect("signup link queued");
    let token = token_from_email(&signup_email.body_text, SIGNUP_URL);

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
    let h = fresh(default_config());
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

struct BrandedEmails;

impl BauthEmails for BrandedEmails {
    fn recovery_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme recovery".to_string(),
            body_text: format!("Open {url}"),
            body_html: Some(format!("<a href=\"{url}\">Open</a>")),
        }
    }

    fn recovery_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme alert".to_string(),
            body_text: "Recovery activity".to_string(),
            body_html: None,
        }
    }
}

#[tokio::test]
async fn finish_recovery_issues_session_with_cooldown_until() {
    let h = fresh(default_config());
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
    assert!(
        outcome
            .session
            .session
            .is_in_recovery_cooldown(h.clock.now())
    );
}

#[tokio::test]
async fn recovery_cooldown_expires_after_window() {
    let h = fresh(default_config());
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

#[test]
#[should_panic(expected = "below the documented floor")]
fn recovery_config_with_subhour_cooldown_panics() {
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let tokens: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let credentials: Arc<InMemoryPasskeyCredentialStore> =
        Arc::new(InMemoryPasskeyCredentialStore::new());
    let challenges: Arc<InMemoryPasskeyChallengeStore> =
        Arc::new(InMemoryPasskeyChallengeStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let session_manager = SessionManager::new(
        sessions as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let passkey_manager = PasskeyManager::new(
        users.clone() as Arc<dyn UserStore>,
        credentials as Arc<dyn PasskeyCredentialStore>,
        challenges as Arc<dyn PasskeyChallengeStore>,
        session_manager.clone(),
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
    )
    .expect("build passkey manager");
    let _ = RecoveryManager::new(
        users as Arc<dyn UserStore>,
        tokens as Arc<dyn VerificationTokenStore>,
        passkey_manager,
        session_manager,
        email as Arc<dyn EmailSender>,
        clock as Arc<dyn Clock>,
        audit as Arc<dyn AuditSink>,
        Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>,
        RecoveryConfig {
            cooldown: Duration::from_secs(60 * 30),
            ..default_config()
        },
    );
}

#[tokio::test]
async fn custom_emails_override_recovery_subjects_and_html() {
    let h = fresh(RecoveryConfig {
        emails: Arc::new(BrandedEmails),
        ..default_config()
    });
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
    assert!(subjects.contains(&"Acme alert"));
}
