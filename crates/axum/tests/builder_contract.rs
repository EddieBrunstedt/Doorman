//! Build-time configuration contract for `AuthService::builder().build()`
//! and `AuthService::from_managers().build()`.
//!
//! The builder is strict by default: a missing required collaborator, a
//! placeholder URL, an undecided CSRF posture, or any other misconfiguration
//! is a hard [`BuilderError`] rather than a silenceable warning. These tests
//! pin each failure mode and the successful happy path.

use std::sync::Arc;
use std::time::Duration;

use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_axum::{AuthService, AuthServiceBuilder, BuilderError};
use doorman_core::account::{AccountConfig, AccountManager};
use doorman_core::audit::{AuditSink, NoopAuditSink};
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::context::CoreDeps;
use doorman_core::email::{DefaultEmailTemplates, EmailSender, SecurityEmailNotifier};
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::passkey::{PasskeyConfig, PasskeyManager};
use doorman_core::rate_limit::{NoopRateLimiter, RateLimiter};
use doorman_core::recovery::{RecoveryConfig, RecoveryManager};
use doorman_core::session::{SessionConfig, SessionContext, SessionManager};
use doorman_core::signup::{SignupConfig, SignupManager};
use doorman_core::storage::{Storage, UserId};
use doorman_core::verification::EnrollmentFlow;
use doorman_test_support::CapturingEmailSender;

fn fresh_storage() -> Storage {
    Storage {
        users: Arc::new(InMemoryUserStore::new()),
        sessions: Arc::new(InMemorySessionStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
    }
}

fn capturing_email() -> Arc<dyn EmailSender> {
    Arc::new(CapturingEmailSender::new())
}

fn noop_audit() -> Arc<dyn AuditSink> {
    Arc::new(NoopAuditSink)
}

fn in_memory_limiter() -> Arc<dyn RateLimiter> {
    Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock)))
}

fn passkey_config() -> PasskeyConfig {
    PasskeyConfig::new(
        "localhost",
        "http://localhost:8080".parse().expect("rp origin"),
        "doorman tests",
    )
}

const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
const ACCOUNT_URL: &str = "https://app.test/email-change?token={token}";

fn real_signup() -> SignupConfig {
    SignupConfig {
        url_template: SIGNUP_URL.to_string(),
        ..SignupConfig::default()
    }
}

fn real_recovery() -> RecoveryConfig {
    RecoveryConfig {
        url_template: RECOVERY_URL.to_string(),
        ..RecoveryConfig::default()
    }
}

fn real_account() -> AccountConfig {
    AccountConfig {
        url_template: ACCOUNT_URL.to_string(),
        ..AccountConfig::default()
    }
}

/// A builder with every required input wired correctly, so `build()`
/// succeeds. Tests that probe a single validation start here and override the
/// one field under test; tests that probe a *missing* required input build a
/// chain by hand instead (you cannot un-set a builder field).
fn valid_builder() -> AuthServiceBuilder {
    AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .csrf(CsrfConfig::disabled())
}

// --- A fully-wired builder succeeds ---

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

// --- Required collaborators (strict by default, no silent defaults) ---

#[test]
fn missing_email_sender_returns_build_error() {
    let err = AuthService::builder(fresh_storage()).build().err();
    assert!(
        matches!(err, Some(BuilderError::MissingEmailSender)),
        "expected MissingEmailSender, got: {err:?}"
    );
}

#[test]
fn missing_passkey_config_returns_build_error() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::MissingPasskeyConfig)),
        "expected MissingPasskeyConfig, got: {err:?}"
    );
}

#[test]
fn missing_audit_sink_returns_build_error() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .csrf(CsrfConfig::disabled())
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::MissingAuditSink)),
        "expected MissingAuditSink when no audit sink is wired, got: {err:?}"
    );
}

#[test]
fn missing_rate_limiter_returns_build_error() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .csrf(CsrfConfig::disabled())
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::MissingRateLimiter)),
        "expected MissingRateLimiter when no limiter is wired, got: {err:?}"
    );
}

#[test]
fn explicit_noop_collaborators_are_accepted() {
    // The dev/opt-out choices are still available — they are just explicit
    // now, so they build without any warning.
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(Arc::new(NoopRateLimiter))
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .csrf(CsrfConfig::disabled())
        .build()
        .err();
    assert!(
        err.is_none(),
        "explicitly chosen noop collaborators should build, got: {err:?}"
    );
}

// --- CSRF decision is required ---

#[test]
fn csrf_decision_required_when_neither_origin_nor_config_set() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::CsrfDecisionRequired)),
        "expected CsrfDecisionRequired with neither origin nor csrf config, got: {err:?}"
    );
}

#[test]
fn external_origin_satisfies_the_csrf_decision() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .external_origin("https://app.test".parse().expect("origin"))
        .build()
        .err();
    assert!(
        err.is_none(),
        "setting an external origin should satisfy the CSRF decision, got: {err:?}"
    );
}

#[test]
fn explicit_csrf_disabled_satisfies_the_csrf_decision() {
    let err = valid_builder().build().err();
    assert!(
        err.is_none(),
        "explicit CsrfConfig::disabled() should satisfy the CSRF decision, got: {err:?}"
    );
}

// --- Placeholder URL templates fail closed ---

#[test]
fn default_signup_template_is_rejected_as_placeholder() {
    // Leave signup at its example.invalid default; recovery and account real.
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .recovery(real_recovery())
        .account(real_account())
        .csrf(CsrfConfig::disabled())
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::PlaceholderUrlTemplate { flow: "signup", .. })
        ),
        "expected PlaceholderUrlTemplate for signup, got: {err:?}"
    );
}

#[test]
fn default_recovery_template_is_rejected_as_placeholder() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .account(real_account())
        .csrf(CsrfConfig::disabled())
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::PlaceholderUrlTemplate {
                flow: "recovery",
                ..
            })
        ),
        "expected PlaceholderUrlTemplate for recovery, got: {err:?}"
    );
}

#[test]
fn default_account_template_is_rejected_as_placeholder() {
    let err = AuthService::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .csrf(CsrfConfig::disabled())
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::PlaceholderUrlTemplate {
                flow: "account email change",
                ..
            })
        ),
        "expected PlaceholderUrlTemplate for account, got: {err:?}"
    );
}

// --- URL templates must still carry the token placeholder ---

#[test]
fn signup_url_template_without_token_is_rejected() {
    let err = valid_builder()
        .signup(SignupConfig {
            url_template: "https://app.test/signup".to_string(),
            ..SignupConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidUrlTemplate { flow: "signup", .. })
        ),
        "expected InvalidUrlTemplate for signup, got: {err:?}"
    );
}

#[test]
fn recovery_url_template_without_token_is_rejected() {
    let err = valid_builder()
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery".to_string(),
            ..RecoveryConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidUrlTemplate {
                flow: "recovery",
                ..
            })
        ),
        "expected InvalidUrlTemplate for recovery, got: {err:?}"
    );
}

// --- Low-level `from_managers` builder ---

#[test]
fn low_level_builder_rejects_missing_passkey_manager() {
    let storage = fresh_storage();
    let session_manager = SessionManager::new(
        storage.sessions.clone(),
        Arc::new(SystemClock),
        Arc::new(NoopAuditSink),
        SessionConfig::default(),
    );

    let err = AuthService::from_managers()
        .session_manager(session_manager)
        .user_store(storage.users.clone())
        .build()
        .err();

    assert!(
        matches!(err, Some(BuilderError::MissingPasskeyManager)),
        "expected MissingPasskeyManager, got: {err:?}"
    );
}

#[tokio::test]
async fn low_level_from_managers_wires_managers_built_from_core_deps() {
    // Build every core manager from one shared `CoreDeps` and hand them to
    // the low-level `from_managers` builder. Asserts the path builds and,
    // crucially, that the `EnrollmentFlow` reaches its email transport
    // through the shared context (it no longer holds its own copy): a signup
    // request must enqueue a link email on the sender that lives in `deps`.
    let storage = fresh_storage();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email = Arc::new(CapturingEmailSender::new());
    let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);

    let emails = Arc::new(DefaultEmailTemplates);
    let notifier =
        SecurityEmailNotifier::new(email.clone() as Arc<dyn EmailSender>, emails.clone());
    let session_manager = SessionManager::new(
        storage.sessions.clone(),
        clock.clone(),
        audit.clone(),
        SessionConfig::default(),
    )
    .with_security_notifier(notifier.clone());

    let deps = CoreDeps::new(
        clock,
        audit,
        email.clone() as Arc<dyn EmailSender>,
        emails,
        notifier,
        limiter,
        session_manager.clone(),
        storage.clone(),
    );

    let passkey = PasskeyManager::new(&deps, passkey_config()).expect("passkey manager");
    let flow = EnrollmentFlow::new(&deps, passkey.clone());
    let signup = SignupManager::new(flow.clone(), SignupConfig::default());
    let recovery =
        RecoveryManager::new(flow, RecoveryConfig::default()).expect("recovery cooldown valid");
    let account = AccountManager::new(&deps, AccountConfig::default());

    let auth = AuthService::from_managers()
        .session_manager(session_manager)
        .user_store(storage.users.clone())
        .passkey_manager(passkey)
        .signup_manager(signup)
        .recovery_manager(recovery)
        .account_manager(account)
        // Pre-built managers already own their transport; the only build-time
        // decision left on this path is the CSRF posture.
        .csrf(CsrfConfig::disabled())
        .build()
        .expect("low-level build should succeed when every manager is supplied");

    // The `AuthState` flow accessors must reach the very managers the
    // routes drive. Driving signup through `state().signup()` (rather than a
    // separately held handle) proves the accessor returns the wired manager:
    // the request must enqueue a link email on the shared transport.
    auth.state()
        .signup()
        .request_signup("wire@example.com", SessionContext::default())
        .await
        .expect("request signup");
    assert_eq!(
        email.sent().len(),
        1,
        "signup request should enqueue exactly one link email via the shared transport"
    );

    // The passkey and recovery accessors reach usable managers too: a fresh
    // user has no credentials, and recovery cool-down config is readable.
    let summaries = auth
        .state()
        .passkey()
        .list_passkey_summaries(UserId::new())
        .await
        .expect("list summaries");
    assert!(summaries.is_empty());
    let _ = auth.state().recovery();
}

// --- Build-time validation (fail closed on misconfiguration) ---

#[test]
fn subfloor_recovery_cooldown_is_rejected() {
    let err = valid_builder()
        .recovery(RecoveryConfig {
            cooldown: Duration::from_secs(60),
            url_template: RECOVERY_URL.to_string(),
            ..RecoveryConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::RecoveryCooldownTooShort(_))),
        "expected RecoveryCooldownTooShort, got: {err:?}"
    );
}

#[test]
fn host_prefixed_cookie_without_secure_is_rejected() {
    let err = valid_builder()
        .cookie(CookieConfig {
            session_cookie_name: "__Host-doorman".to_string(),
            secure: false,
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidCookiePrefix {
                prefix: "__Host-",
                ..
            })
        ),
        "expected InvalidCookiePrefix for __Host- without Secure, got: {err:?}"
    );
}

#[test]
fn host_prefixed_cookie_with_domain_is_rejected() {
    let err = valid_builder()
        .cookie(CookieConfig {
            session_cookie_name: "__Host-doorman".to_string(),
            secure: true,
            domain: Some("app.test".to_string()),
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidCookiePrefix {
                prefix: "__Host-",
                ..
            })
        ),
        "expected InvalidCookiePrefix for __Host- with a Domain attribute, got: {err:?}"
    );
}

#[test]
fn secure_prefixed_cookie_without_secure_is_rejected() {
    let err = valid_builder()
        .cookie(CookieConfig {
            session_cookie_name: "__Secure-doorman".to_string(),
            secure: false,
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidCookiePrefix {
                prefix: "__Secure-",
                ..
            })
        ),
        "expected InvalidCookiePrefix for __Secure- without Secure, got: {err:?}"
    );
}

#[test]
fn host_prefixed_cookie_with_correct_attributes_builds() {
    let err = valid_builder()
        .cookie(CookieConfig {
            session_cookie_name: "__Host-doorman".to_string(),
            secure: true,
            domain: None,
            path: "/".to_string(),
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        err.is_none(),
        "a __Host- cookie with Secure, Path=/, and no Domain should build; got: {err:?}"
    );
}

#[test]
fn zero_session_lifetime_is_rejected() {
    let err = valid_builder()
        .session(SessionConfig {
            lifetime: Duration::ZERO,
            ..SessionConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidLifetime {
                field: "session lifetime",
                ..
            })
        ),
        "expected InvalidLifetime for a zero session lifetime, got: {err:?}"
    );
}

#[test]
fn zero_signup_token_lifetime_is_rejected() {
    let err = valid_builder()
        .signup(SignupConfig {
            url_template: SIGNUP_URL.to_string(),
            token_lifetime: Duration::ZERO,
            ..SignupConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidLifetime {
                field: "signup token_lifetime",
                ..
            })
        ),
        "expected InvalidLifetime for a zero signup token lifetime, got: {err:?}"
    );
}

#[test]
fn cookie_max_age_exceeding_session_lifetime_is_rejected() {
    let err = valid_builder()
        .session(SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
            ..SessionConfig::default()
        })
        .cookie(CookieConfig {
            session_max_age: Duration::from_secs(60 * 60 * 2),
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::CookieMaxAgeExceedsSessionLifetime { .. })
        ),
        "expected CookieMaxAgeExceedsSessionLifetime, got: {err:?}"
    );
}
