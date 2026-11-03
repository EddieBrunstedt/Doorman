use std::sync::Arc;
use std::time::Duration;

use doorman_core::assembly::{AuthCore, AuthCoreRequired};
use doorman_core::audit::NoopAuditSink;
use doorman_core::dpop::{DpopOrigin, OpaqueDpopOrigin};
use doorman_core::email_link::{LinkTemplate, LinkTemplateError, LinkTemplates};
use doorman_core::lifetime::{Lifetime, LifetimeError};
use doorman_core::memory::InMemoryStorage;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::RateLimiting;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{CoolDownLength, CoolDownTooShort};
use doorman_core::relying_party::{RelyingParty, RelyingPartyError};
use doorman_core::session::{IdleTimeout, IdleTimeoutError, SessionExpiry, SessionExpiryError};
use doorman_test_support::{CapturingEmailSender, lifetime, relying_party, request_context};
use url::Url;

fn passkey_config() -> PasskeyConfig {
    PasskeyConfig::new(relying_party(url("http://localhost:8080")))
}

fn url(raw: &str) -> Url {
    Url::parse(raw).expect("valid url")
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

async fn ceremony_rp_id(relying_party: RelyingParty) -> String {
    let core = AuthCore::builder(AuthCoreRequired {
        passkey: PasskeyConfig::new(relying_party),
        ..required()
    })
    .build();
    let (_, options) = core
        .passkey
        .start_authentication(request_context())
        .await
        .expect("authentication starts");
    options.public_key.rp_id
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

#[tokio::test]
async fn a_relying_party_from_an_origin_takes_its_id_from_the_origins_domain() {
    let relying_party = RelyingParty::from_origin(url("https://app.example.com:8443/auth"), "App")
        .expect("the origin has a domain");
    assert_eq!(ceremony_rp_id(relying_party).await, "app.example.com");
}

#[tokio::test]
async fn a_relying_party_id_may_be_a_parent_of_the_origins_domain() {
    let relying_party = RelyingParty::builder(url("https://app.example.com"), "App")
        .id("example.com")
        .build()
        .expect("example.com is a parent of app.example.com");
    assert_eq!(ceremony_rp_id(relying_party).await, "example.com");
}

#[test]
fn a_relying_party_id_outside_the_origins_domain_is_refused() {
    let origin = url("https://app.example.com");
    for id in [
        "other.com",
        "ample.com",
        "app.example.com.evil",
        "sub.app.example.com",
    ] {
        assert_eq!(
            RelyingParty::builder(origin.clone(), "App")
                .id(id)
                .build()
                .err(),
            Some(RelyingPartyError::IdOutsideOrigin {
                id: id.to_owned(),
                origin: origin.clone(),
            }),
            "{id}"
        );
    }
}

#[test]
fn a_relying_party_origin_without_a_domain_is_refused() {
    for origin in [
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
        "data:text/plain,hi",
    ] {
        assert_eq!(
            RelyingParty::from_origin(url(origin), "App").err(),
            Some(RelyingPartyError::NoDomain(url(origin))),
            "{origin}"
        );
        assert_eq!(
            RelyingParty::builder(url(origin), "App")
                .id("localhost")
                .build()
                .err(),
            Some(RelyingPartyError::NoDomain(url(origin))),
            "{origin} with an explicit ID"
        );
    }
}

#[test]
fn a_relying_party_trusts_its_origin_then_its_additional_origins() {
    let origin = url("https://example.com");
    assert_eq!(
        RelyingParty::from_origin(origin.clone(), "App")
            .expect("the origin has a domain")
            .origins(),
        std::slice::from_ref(&origin)
    );

    let related = url("https://example.co.uk");
    let android = url("android:apk-key-hash:pNxxqHowXQk");
    let relying_party = RelyingParty::builder(origin.clone(), "App")
        .additional_origin(related.clone())
        .additional_origin(android.clone())
        .build()
        .expect("additional origins are not checked against the ID");
    assert_eq!(relying_party.origins(), &[origin, related, android]);
}
