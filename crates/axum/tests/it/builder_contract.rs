use std::sync::Arc;
use std::time::Duration;

use doorman_axum::config::CookieConfig;
use doorman_axum::{AuthService, AuthServiceBuilder, BuilderError, PurgeSchedule};
use doorman_core::assembly::AuthCore;
use doorman_core::email::EmailSender;
use doorman_core::memory::InMemoryStorage;
use doorman_core::security_notice::{NoticePolicy, OperatorNotice};
use doorman_test_support::{CapturingEmailSender, request_context};

use crate::common::core_builder;

fn core() -> AuthCore {
    core_builder(
        InMemoryStorage::new().all_stores(),
        Arc::new(CapturingEmailSender::new()),
    )
    .build()
    .expect("core")
}

fn valid_builder() -> AuthServiceBuilder {
    AuthService::builder(core()).purge(PurgeSchedule::External)
}

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

#[test]
fn a_service_without_a_purge_schedule_is_refused() {
    let err = AuthService::builder(core()).build().err();
    assert!(
        matches!(err, Some(BuilderError::PurgeDecisionRequired)),
        "expected PurgeDecisionRequired, got: {err:?}"
    );
}

#[tokio::test]
async fn an_in_process_purge_schedule_with_no_interval_is_refused() {
    let err = valid_builder()
        .purge(PurgeSchedule::InProcess {
            every: Duration::ZERO,
        })
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::InvalidPurgeInterval { every }) if every.is_zero()),
        "expected InvalidPurgeInterval, got: {err:?}"
    );
}

#[test]
fn an_in_process_purge_schedule_outside_a_runtime_is_refused() {
    let err = valid_builder()
        .purge(PurgeSchedule::InProcess {
            every: Duration::from_secs(3600),
        })
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::PurgeNeedsRuntime)),
        "expected PurgeNeedsRuntime, got: {err:?}"
    );
}

#[tokio::test]
async fn service_drives_the_managers_the_core_assembled() {
    let email = Arc::new(CapturingEmailSender::new());
    let policy = NoticePolicy::default().send(OperatorNotice::SessionsRevoked);
    let core = core_builder(
        InMemoryStorage::new().all_stores(),
        email.clone() as Arc<dyn EmailSender>,
    )
    .notice_policy(policy.clone())
    .build()
    .expect("core");
    let auth = AuthService::builder(core)
        .purge(PurgeSchedule::External)
        .build()
        .expect("build");

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
