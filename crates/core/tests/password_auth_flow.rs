use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{
    AuditEventKind, AuditSink, AuthMethod, CredentialKind, LoginFailureReason,
};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::email::EmailSender;
use bauth_core::error::Error;
use bauth_core::memory::{
    InMemoryAuditSink, InMemoryEmailSender, InMemoryPasswordCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::password::PasswordPolicy;
use bauth_core::password_auth::{
    PasswordAuthConfig, PasswordAuthManager, PasswordRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimitPolicy, RateLimiter};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{
    PasswordCredentialStore, SessionStore, UserStore, VerificationPurpose, VerificationTokenStore,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};

const VERIFICATION_URL: &str = "https://app.test/verify-email?token={token}";
const RESET_URL: &str = "https://app.test/reset-password?token={token}";

struct Harness {
    manager: PasswordAuthManager,
    users: Arc<InMemoryUserStore>,
    sessions: Arc<InMemorySessionStore>,
    passwords: Arc<InMemoryPasswordCredentialStore>,
    tokens: Arc<InMemoryVerificationTokenStore>,
    audit: Arc<InMemoryAuditSink>,
    email: Arc<InMemoryEmailSender>,
    clock: Arc<MockClock>,
}

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn default_config() -> PasswordAuthConfig {
    PasswordAuthConfig {
        password_policy: PasswordPolicy { min_length: 8 },
        verification_url_template: VERIFICATION_URL.to_string(),
        password_reset_url_template: RESET_URL.to_string(),
        // Default tests don't exercise the limiter; keep its accounting
        // bookkeeping out of the way by disabling every policy. The
        // dedicated rate_limit tests below opt back in.
        rate_limits: PasswordRateLimits::disabled(),
        ..PasswordAuthConfig::default()
    }
}

fn fresh(config: PasswordAuthConfig) -> Harness {
    fresh_with_limiter(config, Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>)
}

fn fresh_with_limiter(config: PasswordAuthConfig, limiter: Arc<dyn RateLimiter>) -> Harness {
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let passwords: Arc<InMemoryPasswordCredentialStore> =
        Arc::new(InMemoryPasswordCredentialStore::new());
    let tokens: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let email: Arc<InMemoryEmailSender> = Arc::new(InMemoryEmailSender::new());
    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let session_manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let manager = PasswordAuthManager::new(
        users.clone() as Arc<dyn UserStore>,
        passwords.clone() as Arc<dyn PasswordCredentialStore>,
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
        passwords,
        tokens,
        audit,
        email,
        clock,
    }
}

fn token_from_email(template: &str, body: &str) -> String {
    let prefix = template
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix before placeholder");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("token follows prefix")
        .to_string()
}

fn kinds(events: &[bauth_core::audit::AuditEvent]) -> Vec<AuditEventKind> {
    events.iter().map(|e| e.kind.clone()).collect()
}

#[tokio::test]
async fn register_creates_user_password_session_and_sends_verification_email() {
    let h = fresh(default_config());

    let outcome = h
        .manager
        .register(
            "Alice@Example.com",
            "hunter22hunter22",
            SessionContext {
                ip: Some("1.1.1.1".into()),
                user_agent: Some("test".into()),
            },
        )
        .await
        .expect("register");

    assert_eq!(outcome.user.email.as_deref(), Some("alice@example.com"));
    assert!(outcome.user.email_verified_at.is_none());
    let session = outcome.session.expect("auto session issued");
    assert_eq!(session.session.user_id, outcome.user.id);

    assert!(
        h.passwords
            .get_password(outcome.user.id)
            .await
            .unwrap()
            .is_some(),
        "password credential persisted"
    );
    assert_eq!(h.sessions.len(), 1);
    assert_eq!(h.email.sent().len(), 1, "verification email queued");
    assert_eq!(h.tokens.len(), 1, "verification token persisted");

    let events = kinds(&h.audit.events());
    assert!(matches!(
        events[0],
        AuditEventKind::CredentialAdded {
            credential_kind: CredentialKind::Password,
            ..
        }
    ));
    assert!(matches!(events[1], AuditEventKind::SessionCreated { .. }));
}

#[tokio::test]
async fn register_rejects_weak_password() {
    let h = fresh(default_config());
    let err = h
        .manager
        .register("user@example.com", "short", SessionContext::default())
        .await
        .expect_err("weak password");
    assert!(matches!(err, Error::WeakPassword { min_length: 8 }));
    assert!(
        h.users
            .find_user_by_email("user@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn register_rejects_invalid_email() {
    let h = fresh(default_config());
    let err = h
        .manager
        .register(
            "not-an-email",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect_err("invalid email");
    assert!(matches!(err, Error::InvalidEmail));
}

#[tokio::test]
async fn register_rejects_duplicate_email() {
    let h = fresh(default_config());
    h.manager
        .register(
            "dup@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("first");
    let err = h
        .manager
        .register(
            "DUP@example.com",
            "different22pass",
            SessionContext::default(),
        )
        .await
        .expect_err("dup");
    assert!(matches!(err, Error::EmailAlreadyTaken));
}

#[tokio::test]
async fn register_without_auto_login_when_email_verification_required() {
    let h = fresh(PasswordAuthConfig {
        require_email_verification: true,
        ..default_config()
    });
    let outcome = h
        .manager
        .register(
            "user@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    assert!(outcome.session.is_none());
    assert_eq!(h.sessions.len(), 0);
    assert_eq!(h.email.sent().len(), 1);
}

#[tokio::test]
async fn login_succeeds_with_correct_password() {
    let h = fresh(default_config());
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let starting_sessions = h.sessions.len();

    let issued = h
        .manager
        .login(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("login");

    assert_eq!(h.sessions.len(), starting_sessions + 1);
    let kinds = kinds(&h.audit.events());
    assert!(
        kinds.iter().any(|k| matches!(
            k,
            AuditEventKind::LoginSucceeded {
                method: AuthMethod::Password,
                ..
            }
        )),
        "login success event emitted",
    );
    // The returned session is valid through the underlying manager.
    let found = h
        .sessions
        .find_session_by_id(issued.session.id)
        .await
        .unwrap();
    assert!(found.is_some());
}

#[tokio::test]
async fn login_fails_with_wrong_password() {
    let h = fresh(default_config());
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let err = h
        .manager
        .login("u@example.com", "WRONG", SessionContext::default())
        .await
        .expect_err("wrong pw");
    assert!(matches!(err, Error::InvalidCredentials));

    let failure_logged = h.audit.events().iter().any(|e| {
        matches!(
            &e.kind,
            AuditEventKind::LoginFailed {
                reason: LoginFailureReason::InvalidCredential,
                ..
            }
        )
    });
    assert!(failure_logged);
}

#[tokio::test]
async fn login_fails_for_unknown_user() {
    let h = fresh(default_config());
    let err = h
        .manager
        .login("nobody@example.com", "whatever", SessionContext::default())
        .await
        .expect_err("unknown");
    assert!(matches!(err, Error::InvalidCredentials));
    let failure_logged = h.audit.events().iter().any(|e| {
        matches!(
            &e.kind,
            AuditEventKind::LoginFailed {
                reason: LoginFailureReason::UserNotFound,
                ..
            }
        )
    });
    assert!(failure_logged);
}

#[tokio::test]
async fn login_requires_verified_email_when_configured() {
    let h = fresh(PasswordAuthConfig {
        require_email_verification: true,
        ..default_config()
    });
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let err = h
        .manager
        .login(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect_err("not verified");
    assert!(matches!(err, Error::EmailNotVerified));
}

#[tokio::test]
async fn logout_revokes_session() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let token = outcome.session.expect("session").token;

    h.manager.logout(&token).await.expect("logout");
    assert_eq!(h.sessions.len(), 0);

    let err = h
        .manager
        .logout(&token)
        .await
        .expect_err("already logged out");
    assert!(matches!(err, Error::SessionNotFound));
}

#[tokio::test]
async fn email_verification_consumes_token_and_marks_user_verified() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let sent = h.email.sent();
    let body = &sent[0].body_text;
    let token = token_from_email(VERIFICATION_URL, body);

    h.manager
        .verify_email(&token, SessionContext::default())
        .await
        .expect("verify");

    let user = h
        .users
        .find_user_by_id(outcome.user.id)
        .await
        .unwrap()
        .expect("user exists");
    assert!(user.email_verified_at.is_some());
    assert_eq!(h.tokens.len(), 0, "token consumed");

    let kinds = kinds(&h.audit.events());
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, AuditEventKind::EmailVerified { .. }))
    );
}

#[tokio::test]
async fn email_verification_rejects_used_token() {
    let h = fresh(default_config());
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let token = token_from_email(VERIFICATION_URL, &h.email.sent()[0].body_text);

    h.manager
        .verify_email(&token, SessionContext::default())
        .await
        .expect("first");
    let err = h
        .manager
        .verify_email(&token, SessionContext::default())
        .await
        .expect_err("second");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn email_verification_rejects_expired_token() {
    let h = fresh(PasswordAuthConfig {
        email_verification_lifetime: Duration::from_secs(60),
        ..default_config()
    });
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let token = token_from_email(VERIFICATION_URL, &h.email.sent()[0].body_text);

    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .manager
        .verify_email(&token, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn request_email_verification_replaces_previous_token() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let first_token = token_from_email(VERIFICATION_URL, &h.email.sent()[0].body_text);

    h.manager
        .request_email_verification(outcome.user.id)
        .await
        .expect("re-request");

    let sent = h.email.sent();
    assert_eq!(sent.len(), 2);
    let second_token = token_from_email(VERIFICATION_URL, &sent[1].body_text);
    assert_ne!(first_token, second_token);

    let err = h
        .manager
        .verify_email(&first_token, SessionContext::default())
        .await
        .expect_err("old token revoked");
    assert!(matches!(err, Error::InvalidVerificationToken));

    h.manager
        .verify_email(&second_token, SessionContext::default())
        .await
        .expect("new token works");
}

#[tokio::test]
async fn request_email_verification_rejects_already_verified() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let token = token_from_email(VERIFICATION_URL, &h.email.sent()[0].body_text);
    h.manager
        .verify_email(&token, SessionContext::default())
        .await
        .expect("verify");

    let err = h
        .manager
        .request_email_verification(outcome.user.id)
        .await
        .expect_err("already verified");
    assert!(matches!(err, Error::EmailAlreadyVerified));
}

#[tokio::test]
async fn request_password_reset_sends_email_for_known_user() {
    let h = fresh(default_config());
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let emails_before = h.email.sent().len();

    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("request");

    let sent = h.email.sent();
    assert_eq!(sent.len(), emails_before + 1);
    assert_eq!(sent.last().unwrap().subject, "Reset your password");

    let kinds = kinds(&h.audit.events());
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasswordResetRequested { .. })),
        "reset request audit event emitted"
    );
}

#[tokio::test]
async fn request_password_reset_silent_for_unknown_email() {
    let h = fresh(default_config());
    h.manager
        .request_password_reset("ghost@example.com", SessionContext::default())
        .await
        .expect("silent ok");
    assert_eq!(h.email.sent().len(), 0);
    assert_eq!(h.tokens.len(), 0);
    let kinds = kinds(&h.audit.events());
    assert!(
        !kinds
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasswordResetRequested { .. })),
        "no audit event for unknown email"
    );
}

#[tokio::test]
async fn reset_password_changes_credential_and_revokes_sessions() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    let original_session = outcome.session.expect("auto session");

    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("reset request");
    let sent = h.email.sent();
    let reset_email = sent
        .iter()
        .rev()
        .find(|e| e.subject == "Reset your password")
        .expect("reset email");
    let token = token_from_email(RESET_URL, &reset_email.body_text);

    h.manager
        .reset_password(&token, "newpass22newpass", SessionContext::default())
        .await
        .expect("reset");

    // Old password no longer works.
    let err = h
        .manager
        .login(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect_err("old pw");
    assert!(matches!(err, Error::InvalidCredentials));

    // Existing sessions are gone.
    assert!(
        h.sessions
            .find_session_by_id(original_session.session.id)
            .await
            .unwrap()
            .is_none(),
        "old session revoked"
    );

    // New password works.
    h.manager
        .login(
            "u@example.com",
            "newpass22newpass",
            SessionContext::default(),
        )
        .await
        .expect("new pw login");

    let kinds = kinds(&h.audit.events());
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasswordChanged { .. }))
    );
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasswordResetCompleted { .. }))
    );
}

#[tokio::test]
async fn reset_password_rejects_used_token() {
    let h = fresh(default_config());
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let reset_body = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Reset your password")
        .expect("reset email")
        .body_text;
    let token = token_from_email(RESET_URL, &reset_body);

    h.manager
        .reset_password(&token, "firstpass22first", SessionContext::default())
        .await
        .expect("first reset");

    let err = h
        .manager
        .reset_password(&token, "secondpass22second", SessionContext::default())
        .await
        .expect_err("second reset");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn reset_password_rejects_expired_token() {
    let h = fresh(PasswordAuthConfig {
        password_reset_lifetime: Duration::from_secs(60),
        ..default_config()
    });
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("request");
    let reset_body = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Reset your password")
        .expect("reset email")
        .body_text;
    let token = token_from_email(RESET_URL, &reset_body);

    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .manager
        .reset_password(&token, "newpass22newpass", SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn request_password_reset_invalidates_previous_token() {
    let h = fresh(default_config());
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("first request");
    let first_token = token_from_email(
        RESET_URL,
        &h.email
            .sent()
            .into_iter()
            .rev()
            .find(|e| e.subject == "Reset your password")
            .unwrap()
            .body_text,
    );

    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("second request");

    let err = h
        .manager
        .reset_password(&first_token, "newpass22newpass", SessionContext::default())
        .await
        .expect_err("stale token");
    assert!(matches!(err, Error::InvalidVerificationToken));

    let second_token = token_from_email(
        RESET_URL,
        &h.email
            .sent()
            .into_iter()
            .rev()
            .find(|e| e.subject == "Reset your password")
            .unwrap()
            .body_text,
    );
    h.manager
        .reset_password(&second_token, "newpass22newpass", SessionContext::default())
        .await
        .expect("fresh token works");
}

#[tokio::test]
async fn change_password_requires_current_password() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let err = h
        .manager
        .change_password(
            outcome.user.id,
            "WRONG",
            "newpass22newpass",
            SessionContext::default(),
        )
        .await
        .expect_err("wrong current pw");
    assert!(matches!(err, Error::InvalidCredentials));

    h.manager
        .change_password(
            outcome.user.id,
            "hunter22hunter22",
            "newpass22newpass",
            SessionContext::default(),
        )
        .await
        .expect("change");

    h.manager
        .login(
            "u@example.com",
            "newpass22newpass",
            SessionContext::default(),
        )
        .await
        .expect("login with new pw");

    let kinds = kinds(&h.audit.events());
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasswordChanged { .. }))
    );
}

#[tokio::test]
async fn change_password_rejects_weak_new_password() {
    let h = fresh(default_config());
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let err = h
        .manager
        .change_password(
            outcome.user.id,
            "hunter22hunter22",
            "short",
            SessionContext::default(),
        )
        .await
        .expect_err("weak");
    assert!(matches!(err, Error::WeakPassword { .. }));
}

#[tokio::test]
async fn verification_token_store_purges_expired() {
    let h = fresh(PasswordAuthConfig {
        email_verification_lifetime: Duration::from_secs(60),
        ..default_config()
    });
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    assert_eq!(h.tokens.len(), 1);

    h.clock.advance(ChronoDuration::seconds(120));
    let removed = h.tokens.purge_expired(h.clock.now()).await.unwrap();
    assert_eq!(removed, 1);
    assert_eq!(h.tokens.len(), 0);
}

#[tokio::test]
async fn password_credential_store_round_trip() {
    let store = InMemoryPasswordCredentialStore::new();
    let user_id = bauth_core::storage::UserId::new();
    let credential = bauth_core::storage::PasswordCredential {
        user_id,
        hash: "$argon2id$...".to_string(),
        updated_at: ts(2026, 1, 1),
    };
    store.set_password(credential.clone()).await.unwrap();
    assert_eq!(store.get_password(user_id).await.unwrap(), Some(credential));

    let updated = bauth_core::storage::PasswordCredential {
        user_id,
        hash: "$argon2id$new...".to_string(),
        updated_at: ts(2026, 1, 2),
    };
    store.set_password(updated.clone()).await.unwrap();
    assert_eq!(store.get_password(user_id).await.unwrap(), Some(updated));

    store.delete_password(user_id).await.unwrap();
    assert!(store.get_password(user_id).await.unwrap().is_none());
}

#[tokio::test]
async fn verification_token_store_rejects_hash_collision_per_purpose() {
    use bauth_core::session::hash_token;

    let store = InMemoryVerificationTokenStore::new();
    let user_id = bauth_core::storage::UserId::new();
    let hash = hash_token("token-a");
    let now = ts(2026, 1, 1);
    let make = |purpose| bauth_core::storage::VerificationToken {
        token_hash: hash,
        user_id,
        purpose,
        created_at: now,
        expires_at: now + ChronoDuration::hours(1),
    };
    store
        .create_token(make(VerificationPurpose::EmailVerification))
        .await
        .expect("first");
    // Same hash, different purpose: should be allowed (different namespace).
    store
        .create_token(make(VerificationPurpose::PasswordReset))
        .await
        .expect("different purpose ok");
    // Same hash, same purpose: must error.
    store
        .create_token(make(VerificationPurpose::EmailVerification))
        .await
        .expect_err("collision");
}

fn rate_limited_config(rate_limits: PasswordRateLimits) -> PasswordAuthConfig {
    PasswordAuthConfig {
        rate_limits,
        ..default_config()
    }
}

#[tokio::test]
async fn login_rate_limit_per_ip_blocks_after_budget() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(3, Duration::from_secs(60));
    let h = fresh_with_limiter(
        rate_limited_config(PasswordRateLimits {
            login_per_ip: Some(policy),
            ..PasswordRateLimits::disabled()
        }),
        limiter.clone(),
    );
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let ctx = SessionContext {
        ip: Some("9.9.9.9".into()),
        user_agent: None,
    };
    for _ in 0..3 {
        let err = h
            .manager
            .login("u@example.com", "WRONG", ctx.clone())
            .await
            .expect_err("wrong pw");
        assert!(matches!(err, Error::InvalidCredentials));
    }

    let err = h
        .manager
        .login("u@example.com", "WRONG", ctx.clone())
        .await
        .expect_err("limit");
    assert!(matches!(err, Error::RateLimited { .. }));

    // A different IP should still get through (subject to its own bucket).
    let other = SessionContext {
        ip: Some("8.8.8.8".into()),
        user_agent: None,
    };
    let err = h
        .manager
        .login("u@example.com", "WRONG", other)
        .await
        .expect_err("other ip still allowed");
    assert!(matches!(err, Error::InvalidCredentials));
}

#[tokio::test]
async fn login_rate_limit_per_identifier_blocks_across_ips() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 15));
    let h = fresh_with_limiter(
        rate_limited_config(PasswordRateLimits {
            login_per_identifier: Some(policy),
            ..PasswordRateLimits::disabled()
        }),
        limiter,
    );
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    for ip in ["1.1.1.1", "2.2.2.2"] {
        let err = h
            .manager
            .login(
                "u@example.com",
                "WRONG",
                SessionContext {
                    ip: Some(ip.into()),
                    user_agent: None,
                },
            )
            .await
            .expect_err("wrong pw");
        assert!(matches!(err, Error::InvalidCredentials));
    }

    let err = h
        .manager
        .login(
            "u@example.com",
            "WRONG",
            SessionContext {
                ip: Some("3.3.3.3".into()),
                user_agent: None,
            },
        )
        .await
        .expect_err("identifier bucket exhausted regardless of ip");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn password_reset_rate_limit_engages() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = fresh_with_limiter(
        rate_limited_config(PasswordRateLimits {
            password_reset_per_identifier: Some(policy),
            ..PasswordRateLimits::disabled()
        }),
        limiter,
    );
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("first");
    h.manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect("second");

    let err = h
        .manager
        .request_password_reset("u@example.com", SessionContext::default())
        .await
        .expect_err("limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn verification_email_rate_limit_engages() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60 * 60));
    let h = fresh_with_limiter(
        rate_limited_config(PasswordRateLimits {
            verification_email_per_user: Some(policy),
            ..PasswordRateLimits::disabled()
        }),
        limiter,
    );
    let outcome = h
        .manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    h.manager
        .request_email_verification(outcome.user.id)
        .await
        .expect("first re-request");
    h.manager
        .request_email_verification(outcome.user.id)
        .await
        .expect("second re-request");

    let err = h
        .manager
        .request_email_verification(outcome.user.id)
        .await
        .expect_err("limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn rate_limit_clears_after_window() {
    let clock_for_limiter = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let limiter = Arc::new(InMemoryRateLimiter::new(
        clock_for_limiter.clone() as Arc<dyn Clock>
    )) as Arc<dyn RateLimiter>;
    let policy = RateLimitPolicy::new(1, Duration::from_secs(60));
    let h = fresh_with_limiter(
        rate_limited_config(PasswordRateLimits {
            login_per_ip: Some(policy),
            ..PasswordRateLimits::disabled()
        }),
        limiter,
    );
    h.manager
        .register(
            "u@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");

    let ctx = SessionContext {
        ip: Some("1.2.3.4".into()),
        user_agent: None,
    };
    let _ = h
        .manager
        .login("u@example.com", "WRONG", ctx.clone())
        .await
        .expect_err("first attempt fails on password");

    let err = h
        .manager
        .login("u@example.com", "WRONG", ctx.clone())
        .await
        .expect_err("limited");
    assert!(matches!(err, Error::RateLimited { .. }));

    // Advance the limiter's clock past the window; the bucket should drain.
    clock_for_limiter.advance(ChronoDuration::seconds(120));
    let err = h
        .manager
        .login("u@example.com", "WRONG", ctx)
        .await
        .expect_err("window cleared, password is still wrong");
    assert!(matches!(err, Error::InvalidCredentials));
}
