use std::sync::Arc;
use std::time::Duration;

use doorman_axum::config::{CookieConfig, CookieConfigError, SameSite};
use doorman_axum::{
    AuthService, AuthServiceBuilder, BuilderError, PurgeIntervalError, PurgeSchedule,
};
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
}

fn valid_builder() -> AuthServiceBuilder {
    AuthService::builder(core(), PurgeSchedule::external())
}

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

#[test]
fn an_in_process_purge_interval_is_greater_than_zero_and_a_reachable_instant_away() {
    for (every, accepted) in [
        (Duration::ZERO, false),
        (Duration::from_nanos(1), true),
        (Duration::from_secs(3600), true),
        (Duration::MAX, false),
    ] {
        let expected = if accepted {
            Ok(())
        } else {
            Err(PurgeIntervalError(every))
        };
        assert_eq!(
            PurgeSchedule::in_process(every).map(|_| ()),
            expected,
            "{every:?}"
        );
    }
}

#[test]
fn an_in_process_purge_schedule_outside_a_runtime_is_refused() {
    let purge = PurgeSchedule::in_process(Duration::from_secs(3600)).expect("purge schedule");
    let err = AuthService::builder(core(), purge).build().err();
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
    .build();
    let auth = AuthService::builder(core, PurgeSchedule::external())
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
fn a_cookie_name_that_is_not_a_token_is_refused() {
    for name in ["", "a b", "a=b", "a;b", "a\nb", "sess\u{e9}", "a\"b", "a,b"] {
        assert_eq!(
            CookieConfig::builder(name).build().err(),
            Some(CookieConfigError::InvalidName(name.to_owned())),
            "{name:?}"
        );
    }
}

#[test]
fn a_cookie_path_that_cannot_be_an_attribute_is_refused() {
    for path in ["", "relative", "/a;b", "/a\nb", "/caf\u{e9}"] {
        assert_eq!(
            CookieConfig::builder("s").path(path).build().err(),
            Some(CookieConfigError::InvalidPath(path.to_owned())),
            "{path:?}"
        );
    }
    assert!(CookieConfig::builder("s").path("/app").build().is_ok());
}

#[test]
fn a_cookie_domain_must_be_a_domain_name() {
    for domain in [
        "",
        ".",
        "a..b",
        "example.com;",
        "exa mple.com",
        "b\u{fc}cher.de",
    ] {
        assert_eq!(
            CookieConfig::builder("s").domain(domain).build().err(),
            Some(CookieConfigError::InvalidDomain(domain.to_owned())),
            "{domain:?}"
        );
    }
    for domain in [
        "example.com",
        ".example.com",
        "xn--bcher-kva.de",
        "localhost",
    ] {
        assert!(
            CookieConfig::builder("s").domain(domain).build().is_ok(),
            "{domain:?}"
        );
    }
}

#[test]
fn a_host_prefixed_cookie_must_be_secure_with_the_root_path_and_no_domain() {
    // Browsers match the prefix whatever its case.
    for name in ["__Host-s", "__host-s", "__HOST-s"] {
        assert!(CookieConfig::builder(name).build().is_ok(), "{name}");
        assert_eq!(
            CookieConfig::builder(name).insecure().build().err(),
            Some(CookieConfigError::PrefixNeedsSecure("__Host-")),
            "{name}"
        );
        assert_eq!(
            CookieConfig::builder(name).path("/app").build().err(),
            Some(CookieConfigError::HostPrefixNeedsRootPath),
            "{name}"
        );
        assert_eq!(
            CookieConfig::builder(name)
                .domain("example.com")
                .build()
                .err(),
            Some(CookieConfigError::HostPrefixForbidsDomain),
            "{name}"
        );
    }
}

#[test]
fn a_secure_prefixed_cookie_must_be_secure() {
    for name in ["__Secure-s", "__secure-s"] {
        assert!(
            CookieConfig::builder(name)
                .domain("example.com")
                .path("/app")
                .build()
                .is_ok(),
            "{name}"
        );
        assert_eq!(
            CookieConfig::builder(name).insecure().build().err(),
            Some(CookieConfigError::PrefixNeedsSecure("__Secure-")),
            "{name}"
        );
    }
}

#[test]
fn a_same_site_none_cookie_must_be_secure() {
    assert!(
        CookieConfig::builder("s")
            .same_site(SameSite::None)
            .build()
            .is_ok()
    );
    assert_eq!(
        CookieConfig::builder("s")
            .same_site(SameSite::None)
            .insecure()
            .build()
            .err(),
        Some(CookieConfigError::SameSiteNoneNeedsSecure)
    );
}

#[test]
fn an_unprefixed_cookie_may_be_insecure() {
    assert!(CookieConfig::builder("s").insecure().build().is_ok());
}
