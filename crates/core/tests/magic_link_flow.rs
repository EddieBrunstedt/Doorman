use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditEvent, AuditEventKind, AuditSink, AuthMethod};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::email::{BauthEmails, Email, EmailSender};
use bauth_core::error::Error;
use bauth_core::magic_link::{
    MagicLinkConfig, MagicLinkManager, MagicLinkRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::memory::{
    CapturingEmailSender, InMemoryAuditSink, InMemoryRateLimiter, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimitPolicy, RateLimiter};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{SessionStore, User, UserStore, VerificationTokenStore};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};

const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

struct Harness {
    manager: MagicLinkManager,
    users: Arc<InMemoryUserStore>,
    sessions: Arc<InMemorySessionStore>,
    tokens: Arc<InMemoryVerificationTokenStore>,
    audit: Arc<InMemoryAuditSink>,
    email: Arc<CapturingEmailSender>,
    clock: Arc<MockClock>,
}

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn default_config() -> MagicLinkConfig {
    MagicLinkConfig {
        url_template: MAGIC_URL.to_string(),
        rate_limits: MagicLinkRateLimits::disabled(),
        ..MagicLinkConfig::default()
    }
}

fn fresh(config: MagicLinkConfig) -> Harness {
    fresh_with_limiter(config, Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>)
}

fn fresh_with_limiter(config: MagicLinkConfig, limiter: Arc<dyn RateLimiter>) -> Harness {
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let tokens: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
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
    let manager = MagicLinkManager::new(
        users.clone() as Arc<dyn UserStore>,
        tokens.clone() as Arc<dyn VerificationTokenStore>,
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
        audit,
        email,
        clock,
    }
}

fn token_from_email(body: &str) -> String {
    let prefix = MAGIC_URL
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

#[tokio::test]
async fn request_provisions_user_when_signup_allowed() {
    let h = fresh(default_config());
    h.manager
        .request_magic_link("Alice@Example.com", SessionContext::default())
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
    assert_eq!(h.email.sent().len(), 1, "magic-link email queued");
    assert_eq!(h.email.sent()[0].subject, "Your sign-in link");

    let events = kinds(&h.audit.events());
    assert!(matches!(
        events.last(),
        Some(AuditEventKind::MagicLinkRequested { .. })
    ));
}

#[tokio::test]
async fn request_silent_for_unknown_when_signup_disabled() {
    let h = fresh(MagicLinkConfig {
        allow_signup: false,
        ..default_config()
    });
    h.manager
        .request_magic_link("ghost@example.com", SessionContext::default())
        .await
        .expect("silent ok");
    assert_eq!(h.tokens.len(), 0);
    assert_eq!(h.email.sent().len(), 0);
    assert!(
        h.users
            .find_user_by_email("ghost@example.com")
            .await
            .expect("find ghost")
            .is_none(),
        "no user provisioned"
    );
    let events = kinds(&h.audit.events());
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, AuditEventKind::MagicLinkRequested { .. })),
        "no audit event for unknown email when signup disabled"
    );
}

#[tokio::test]
async fn request_for_existing_user_does_not_create_duplicate() {
    let h = fresh(default_config());
    h.manager
        .request_magic_link("user@example.com", SessionContext::default())
        .await
        .expect("first");
    h.manager
        .request_magic_link("user@example.com", SessionContext::default())
        .await
        .expect("second");
    assert_eq!(h.email.sent().len(), 2);
    // Only one user record exists.
    let user = h
        .users
        .find_user_by_email("user@example.com")
        .await
        .expect("find user")
        .expect("user exists");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user by id")
            .is_some()
    );
    // Latest request supersedes earlier token, so only one is outstanding.
    assert_eq!(h.tokens.len(), 1, "previous token invalidated");
}

#[tokio::test]
async fn consume_issues_session_and_marks_email_verified_on_first_use() {
    let h = fresh(default_config());
    h.manager
        .request_magic_link("user@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    let outcome = h
        .manager
        .consume_magic_link(&token, SessionContext::default())
        .await
        .expect("consume");

    assert!(outcome.is_new_user);
    assert!(outcome.user.email_verified_at.is_some());
    assert_eq!(h.sessions.len(), 1);
    assert_eq!(h.tokens.len(), 0, "token consumed");

    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::MagicLinkConsumed { .. }))
    );
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::LoginSucceeded {
            method: AuthMethod::MagicLink,
            ..
        }
    )));
}

#[tokio::test]
async fn consume_rejects_used_token() {
    let h = fresh(default_config());
    h.manager
        .request_magic_link("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    h.manager
        .consume_magic_link(&token, SessionContext::default())
        .await
        .expect("first consume");
    let err = h
        .manager
        .consume_magic_link(&token, SessionContext::default())
        .await
        .expect_err("second consume");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn consume_rejects_expired_token() {
    let h = fresh(MagicLinkConfig {
        token_lifetime: Duration::from_secs(60),
        ..default_config()
    });
    h.manager
        .request_magic_link("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let token = token_from_email(&h.email.sent()[0].body_text);

    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .manager
        .consume_magic_link(&token, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn second_request_invalidates_first_token() {
    let h = fresh(default_config());
    h.manager
        .request_magic_link("u@example.com", SessionContext::default())
        .await
        .expect("first");
    let first_token = token_from_email(&h.email.sent()[0].body_text);

    h.manager
        .request_magic_link("u@example.com", SessionContext::default())
        .await
        .expect("second");

    let err = h
        .manager
        .consume_magic_link(&first_token, SessionContext::default())
        .await
        .expect_err("stale token");
    assert!(matches!(err, Error::InvalidVerificationToken));

    let second_token = token_from_email(&h.email.sent()[1].body_text);
    h.manager
        .consume_magic_link(&second_token, SessionContext::default())
        .await
        .expect("fresh token works");
}

#[tokio::test]
async fn consume_for_already_verified_user_does_not_touch_verified_at() {
    let h = fresh(default_config());
    // First request + consume → user provisioned and email verified.
    h.manager
        .request_magic_link("u@example.com", SessionContext::default())
        .await
        .expect("request 1");
    let token1 = token_from_email(&h.email.sent()[0].body_text);
    let first = h
        .manager
        .consume_magic_link(&token1, SessionContext::default())
        .await
        .expect("consume 1");
    assert!(first.is_new_user);
    let verified_at = first
        .user
        .email_verified_at
        .expect("verified after first consume");

    // Advance clock so a new updated_at would be visible if we touched it.
    h.clock.advance(ChronoDuration::hours(1));

    h.manager
        .request_magic_link("u@example.com", SessionContext::default())
        .await
        .expect("request 2");
    let token2 = token_from_email(&h.email.sent()[1].body_text);
    let second = h
        .manager
        .consume_magic_link(&token2, SessionContext::default())
        .await
        .expect("consume 2");

    assert!(!second.is_new_user);
    assert_eq!(
        second.user.email_verified_at,
        Some(verified_at),
        "email_verified_at unchanged"
    );
}

#[tokio::test]
async fn request_rejects_invalid_email() {
    let h = fresh(default_config());
    let err = h
        .manager
        .request_magic_link("not-an-email", SessionContext::default())
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
        MagicLinkConfig {
            rate_limits: MagicLinkRateLimits {
                request_per_ip: Some(policy),
                ..MagicLinkRateLimits::disabled()
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
        .request_magic_link("a@example.com", ctx.clone())
        .await
        .expect("1");
    h.manager
        .request_magic_link("b@example.com", ctx.clone())
        .await
        .expect("2");
    let err = h
        .manager
        .request_magic_link("c@example.com", ctx)
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
        MagicLinkConfig {
            rate_limits: MagicLinkRateLimits {
                request_per_identifier: Some(policy),
                ..MagicLinkRateLimits::disabled()
            },
            ..default_config()
        },
        limiter,
    );

    for ip in ["1.1.1.1", "2.2.2.2"] {
        h.manager
            .request_magic_link(
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
        .request_magic_link(
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
    fn magic_link_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Acme magic link".to_string(),
            body_text: format!("Open {url}"),
            body_html: Some(format!("<a href=\"{url}\">Open</a>")),
        }
    }
}

#[tokio::test]
async fn custom_emails_override_magic_link_subject_and_html() {
    let h = fresh(MagicLinkConfig {
        emails: Arc::new(BrandedEmails),
        ..default_config()
    });

    h.manager
        .request_magic_link("user@example.com", SessionContext::default())
        .await
        .expect("request");

    let sent = h.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Acme magic link");
    assert!(sent[0].body_text.starts_with("Open "));
    assert!(sent[0].body_html.is_some());
}

#[tokio::test]
async fn default_emails_match_legacy_subject_lines() {
    let h = fresh(default_config());

    h.manager
        .request_magic_link("user@example.com", SessionContext::default())
        .await
        .expect("request");

    let sent = h.email.sent();
    assert_eq!(sent[0].subject, "Your sign-in link");
}
