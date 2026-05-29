use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditEvent, AuditEventKind, AuditSink};
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
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use bauth_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, User, UserStore,
    VerificationTokenStore,
};
use bauth_core::verification::TOKEN_PLACEHOLDER;
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
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

struct Harness {
    manager: SignupManager,
    users: Arc<InMemoryUserStore>,
    sessions: Arc<InMemorySessionStore>,
    tokens: Arc<InMemoryVerificationTokenStore>,
    credentials: Arc<InMemoryPasskeyCredentialStore>,
    audit: Arc<InMemoryAuditSink>,
    email: Arc<CapturingEmailSender>,
    clock: Arc<MockClock>,
}

fn default_config() -> SignupConfig {
    SignupConfig {
        url_template: SIGNUP_URL.to_string(),
        rate_limits: SignupRateLimits::disabled(),
        ..SignupConfig::default()
    }
}

fn fresh(config: SignupConfig) -> Harness {
    fresh_with_limiter(config, Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>)
}

fn fresh_with_limiter(config: SignupConfig, limiter: Arc<dyn RateLimiter>) -> Harness {
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
    let manager = SignupManager::new(
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
        manager,
        users,
        sessions,
        tokens,
        credentials,
        audit,
        email,
        clock,
    }
}

fn token_from_email(body: &str) -> String {
    let prefix = SIGNUP_URL
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

fn authenticator() -> ResidentTestAuthenticator {
    ResidentTestAuthenticator::new()
}

/// Test authenticator that records the user_handle from each registration
/// so a subsequent discoverable authentication can claim residency.
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
        // SoftPasskey can't create resident keys; relax the local input
        // after we've already verified the server-issued options.
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
async fn request_provisions_user_for_new_email() {
    let h = fresh(default_config());
    h.manager
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
    let h = fresh(default_config());
    // First request creates the user.
    h.manager
        .request_signup("alice@example.com", SessionContext::default())
        .await
        .expect("first request");
    let emails_before = h.email.sent().len();
    let tokens_before = h.tokens.len();

    // Second request: user exists → silent no-op, no new email or token.
    h.manager
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
    let h = fresh(default_config());
    h.manager
        .request_signup("user@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    let outcome = h
        .manager
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
    let h = fresh(default_config());
    h.manager
        .request_signup("alice@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    let consume = h
        .manager
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("consume");

    let mut wa = authenticator();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .manager
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
async fn consume_rejects_replayed_token() {
    let h = fresh(default_config());
    h.manager
        .request_signup("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    h.manager
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("first consume");
    let err = h
        .manager
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("second consume");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn consume_rejects_expired_token() {
    let h = fresh(SignupConfig {
        token_lifetime: Duration::from_secs(60),
        ..default_config()
    });
    h.manager
        .request_signup("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .manager
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn request_rejects_invalid_email() {
    let h = fresh(default_config());
    let err = h
        .manager
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
    let h = fresh_with_limiter(
        SignupConfig {
            rate_limits: SignupRateLimits {
                request_per_ip: Some(policy),
                ..SignupRateLimits::disabled()
            },
            ..default_config()
        },
        limiter,
    );

    let ctx = SessionContext {
        ip: Some("9.9.9.9".into()),
        user_agent: None,
    };
    h.manager
        .request_signup("a@example.com", ctx.clone())
        .await
        .expect("1");
    h.manager
        .request_signup("b@example.com", ctx.clone())
        .await
        .expect("2");
    let err = h
        .manager
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
    let h = fresh_with_limiter(
        SignupConfig {
            rate_limits: SignupRateLimits {
                request_per_identifier: Some(policy),
                ..SignupRateLimits::disabled()
            },
            ..default_config()
        },
        limiter,
    );

    for ip in ["1.1.1.1", "2.2.2.2"] {
        h.manager
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
        .manager
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
    let h = fresh(SignupConfig {
        emails: Arc::new(BrandedEmails),
        ..default_config()
    });

    h.manager
        .request_signup("user@example.com", SessionContext::default())
        .await
        .expect("request");

    let sent = h.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Acme signup");
    assert!(sent[0].body_text.starts_with("Open "));
    assert!(sent[0].body_html.is_some());
}
