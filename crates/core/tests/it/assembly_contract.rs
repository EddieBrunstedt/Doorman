use std::sync::Arc;
use std::time::Duration;

use doorman_core::assembly::{AuthCore, AuthCoreBuilder, AuthCoreRequired};
use doorman_core::audit::NoopAuditSink;
use doorman_core::dpop::{DpopOrigin, OpaqueDpopOrigin};
use doorman_core::email_link::{LinkTemplate, LinkTemplateError, LinkTemplates};
use doorman_core::lifetime::{Lifetime, LifetimeError};
use doorman_core::memory::InMemoryStorage;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::RateLimiting;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{CoolDownLength, CoolDownTooShort};
use doorman_core::session::{IdleTimeout, IdleTimeoutError, SessionExpiry, SessionExpiryError};
use doorman_test_support::{CapturingEmailSender, lifetime};
use url::Url;

fn passkey_config() -> PasskeyConfig {
    PasskeyConfig::new(
        "localhost",
        "http://localhost:8080".parse().expect("rp origin"),
        "doorman tests",
    )
}

fn link_template(template: &str) -> LinkTemplate {
    LinkTemplate::parse(template).expect("link template")
}

fn required() -> AuthCoreRequired {
    AuthCoreRequired {
        storage: InMemoryStorage::new().all_stores(),
        email_sender: Arc::new(CapturingEmailSender::new()),
        audit_sink: Arc::new(NoopAuditSink),
        passkey: passkey_config(),
        reauthentication: ReauthPolicy::disabled(),
        rate_limiting: RateLimiting::Disabled,
        links: LinkTemplates {
            signup: link_template("https://app.test/signup?token={token}"),
            recovery: link_template("https://app.test/recovery?token={token}"),
            email_change: link_template("https://app.test/email-change?token={token}"),
        },
    }
}

fn valid_builder() -> AuthCoreBuilder {
    AuthCore::builder(required())
}

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

#[test]
fn a_link_template_needs_the_token_placeholder_and_an_absolute_url() {
    for (template, expected) in [
        ("https://app.test/signup?token={token}", Ok(())),
        ("https://app.test/recover/{token}", Ok(())),
        ("app.example://recover?token={token}", Ok(())),
        (
            "https://app.test/signup",
            Err(LinkTemplateError::MissingToken),
        ),
        (
            "https://app.test/signup?token={TOKEN}",
            Err(LinkTemplateError::MissingToken),
        ),
        (
            "/signup?token={token}",
            Err(LinkTemplateError::NotAUrl(
                url::ParseError::RelativeUrlWithoutBase,
            )),
        ),
        (
            "https://?token={token}",
            Err(LinkTemplateError::NotAUrl(url::ParseError::EmptyHost)),
        ),
    ] {
        let parsed = LinkTemplate::parse(template).map(|parsed| parsed.as_str().to_owned());

        assert_eq!(parsed, expected.map(|()| template.to_owned()), "{template}");
    }
}

#[test]
fn a_lifetime_is_greater_than_zero_and_at_most_the_maximum() {
    let max = Lifetime::MAX.get();
    let nanosecond = Duration::from_nanos(1);
    for (lifetime, expected) in [
        (Duration::ZERO, Err(LifetimeError::Zero)),
        (nanosecond, Ok(nanosecond)),
        (max, Ok(max)),
        (
            max + nanosecond,
            Err(LifetimeError::TooLong(max + nanosecond)),
        ),
        (Duration::MAX, Err(LifetimeError::TooLong(Duration::MAX))),
    ] {
        assert_eq!(
            Lifetime::new(lifetime).map(Lifetime::get),
            expected,
            "{lifetime:?}"
        );
    }
}

#[test]
fn a_slide_interval_must_be_shorter_than_its_idle_timeout() {
    let timeout = Duration::from_secs(60 * 10);
    let second = Duration::from_secs(1);
    for (slide_interval, accepted) in [
        (Duration::ZERO, true),
        (timeout - second, true),
        (timeout, false),
        (timeout + second, false),
    ] {
        let idle_timeout = IdleTimeout::new(lifetime(timeout), slide_interval);
        let expected = if accepted {
            Ok(slide_interval)
        } else {
            Err(IdleTimeoutError {
                timeout,
                slide_interval,
            })
        };
        assert_eq!(
            idle_timeout.map(IdleTimeout::slide_interval),
            expected,
            "{slide_interval:?}"
        );
    }
}

#[test]
fn an_idle_timeout_must_not_outlast_the_session_lifetime() {
    let session_lifetime = Duration::from_secs(60 * 60);
    let second = Duration::from_secs(1);
    for (idle_timeout, accepted) in [
        (session_lifetime - second, true),
        (session_lifetime, true),
        (session_lifetime + second, false),
    ] {
        let idle = IdleTimeout::new(lifetime(idle_timeout), IdleTimeout::DEFAULT_SLIDE_INTERVAL)
            .expect("idle timeout");
        let expiry = SessionExpiry::sliding(lifetime(session_lifetime), idle);
        let expected = if accepted {
            Ok(Some(idle))
        } else {
            Err(SessionExpiryError {
                lifetime: session_lifetime,
                idle_timeout,
            })
        };
        assert_eq!(
            expiry.map(SessionExpiry::idle_timeout),
            expected,
            "{idle_timeout:?}"
        );
    }
}

#[test]
fn a_recovery_cool_down_lasts_at_least_the_floor_unless_the_host_names_the_danger() {
    let below = CoolDownLength::MIN - Duration::from_secs(1);
    assert_eq!(
        CoolDownLength::new(lifetime(below)),
        Err(CoolDownTooShort(below))
    );
    assert_eq!(
        CoolDownLength::danger_below_floor(lifetime(below))
            .get()
            .get(),
        below
    );
    assert_eq!(
        CoolDownLength::new(lifetime(CoolDownLength::MIN)).map(|length| length.get().get()),
        Ok(CoolDownLength::MIN)
    );
}

#[test]
fn an_opaque_dpop_origin_is_refused() {
    let opaque = Url::parse("data:text/plain,api").expect("url").origin();
    assert_eq!(DpopOrigin::new(opaque), Err(OpaqueDpopOrigin));

    let tuple = Url::parse("https://api.app.test").expect("url").origin();
    assert_eq!(
        DpopOrigin::new(tuple.clone()).map(|origin| origin.as_origin().clone()),
        Ok(tuple)
    );
}
