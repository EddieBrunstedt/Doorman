use std::sync::Arc;
use std::time::Duration;

use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_axum::{AuthService, AuthServiceBuilder, BuilderError};
use doorman_core::account::AccountConfig;
use doorman_core::assembly::{AuthCore, AuthCoreBuilder};
use doorman_core::audit::NoopAuditSink;
use doorman_core::email::EmailSender;
use doorman_core::memory::InMemoryStorage;
use doorman_core::operator::{NotificationPolicy, OperatorNotice};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::NoopRateLimiter;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::{SessionConfig, SessionContext};
use doorman_core::signup::SignupConfig;
use doorman_core::storage::UserId;
use doorman_test_support::CapturingEmailSender;

fn core_builder(email: Arc<dyn EmailSender>) -> AuthCoreBuilder {
    AuthCore::builder(InMemoryStorage::new().all_stores())
        .email(email)
        .passkey(PasskeyConfig::new(
            "localhost",
            "http://localhost:8080".parse().expect("rp origin"),
            "doorman tests",
        ))
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(NoopRateLimiter))
        .signup(SignupConfig {
            url_template: "https://app.test/signup?token={token}".to_string(),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery?token={token}".to_string(),
            ..RecoveryConfig::default()
        })
        .account(AccountConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..AccountConfig::default()
        })
        .reauthentication(ReauthPolicy::disabled())
}

fn core() -> AuthCore {
    core_builder(Arc::new(CapturingEmailSender::new()))
        .build()
        .expect("core")
}

fn valid_builder() -> AuthServiceBuilder {
    AuthService::builder(core()).csrf(CsrfConfig::disabled())
}

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

#[tokio::test]
async fn service_drives_the_managers_the_core_assembled() {
    let email = Arc::new(CapturingEmailSender::new());
    let policy = NotificationPolicy {
        sessions_revoked: OperatorNotice::Send,
        ..NotificationPolicy::default()
    };
    let core = core_builder(email.clone() as Arc<dyn EmailSender>)
        .notification_policy(policy)
        .build()
        .expect("core");
    let auth = AuthService::builder(core)
        .csrf(CsrfConfig::disabled())
        .build()
        .expect("build");

    assert_eq!(*auth.state().operator().notification_policy(), policy);

    auth.state()
        .signup()
        .request_signup("wire@example.com", None, SessionContext::default())
        .await
        .expect("request signup");
    assert_eq!(
        email.sent().len(),
        1,
        "signup request should enqueue exactly one link email via the core's transport"
    );

    let summaries = auth
        .state()
        .passkey()
        .list_passkey_summaries(UserId::new())
        .await
        .expect("list summaries");
    assert!(summaries.is_empty());
}

#[test]
fn csrf_decision_required_when_neither_origin_nor_config_set() {
    let err = AuthService::builder(core()).build().err();
    assert!(
        matches!(err, Some(BuilderError::CsrfDecisionRequired)),
        "expected CsrfDecisionRequired with neither origin nor csrf config, got: {err:?}"
    );
}

#[test]
fn external_origin_satisfies_the_csrf_decision() {
    let err = AuthService::builder(core())
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
fn cookie_attributes_a_header_cannot_carry_are_rejected() {
    let err = valid_builder()
        .cookie(CookieConfig {
            path: "/\n".to_string(),
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::InvalidCookieAttributes)),
        "expected InvalidCookieAttributes for a path with a newline, got: {err:?}"
    );
}

#[test]
fn cookie_max_age_exceeding_session_lifetime_is_rejected() {
    let core = core_builder(Arc::new(CapturingEmailSender::new()))
        .session(SessionConfig {
            absolute_lifetime: Duration::from_secs(60 * 60),
            ..SessionConfig::default()
        })
        .build()
        .expect("core");
    let err = AuthService::builder(core)
        .csrf(CsrfConfig::disabled())
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

#[test]
fn cookie_max_age_is_bounded_by_the_idle_window_when_sliding() {
    let idle = Duration::from_secs(60 * 60);
    let core = core_builder(Arc::new(CapturingEmailSender::new()))
        .session(SessionConfig {
            absolute_lifetime: Duration::from_secs(60 * 60 * 24),
            idle_timeout: Some(idle),
            ..SessionConfig::default()
        })
        .build()
        .expect("core");
    let err = AuthService::builder(core)
        .csrf(CsrfConfig::disabled())
        .cookie(CookieConfig {
            session_max_age: idle * 2,
            ..CookieConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::CookieMaxAgeExceedsSessionLifetime { session_lifetime, .. })
                if session_lifetime == idle
        ),
        "expected CookieMaxAgeExceedsSessionLifetime against the idle window, got: {err:?}"
    );
}
