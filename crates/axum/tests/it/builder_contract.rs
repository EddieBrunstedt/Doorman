use std::sync::Arc;

use doorman_axum::config::CookieConfig;
use doorman_axum::{AuthService, AuthServiceBuilder, BuilderError};
use doorman_core::assembly::{AuthCore, AuthCoreBuilder};
use doorman_core::audit::NoopAuditSink;
use doorman_core::email::EmailSender;
use doorman_core::memory::InMemoryStorage;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::NoopRateLimiter;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::security_notice::{NoticePolicy, OperatorNotice};
use doorman_core::signup::SignupConfig;
use doorman_core::user::UserConfig;
use doorman_test_support::{CapturingEmailSender, request_context};

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
        .user(UserConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..UserConfig::default()
        })
        .reauthentication(ReauthPolicy::disabled())
}

fn core() -> AuthCore {
    core_builder(Arc::new(CapturingEmailSender::new()))
        .build()
        .expect("core")
}

fn valid_builder() -> AuthServiceBuilder {
    AuthService::builder(core())
}

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

#[tokio::test]
async fn service_drives_the_managers_the_core_assembled() {
    let email = Arc::new(CapturingEmailSender::new());
    let policy = NoticePolicy::default().send(OperatorNotice::SessionsRevoked);
    let core = core_builder(email.clone() as Arc<dyn EmailSender>)
        .notice_policy(policy.clone())
        .build()
        .expect("core");
    let auth = AuthService::builder(core).build().expect("build");

    assert_eq!(*auth.state().operator().notice_policy(), policy);

    auth.state()
        .signup()
        .request_signup("wire@example.com", None, request_context())
        .await
        .expect("request signup");
    assert_eq!(
        email.sent().len(),
        1,
        "signup request should enqueue exactly one link email via the core's transport"
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
