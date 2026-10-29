use std::sync::Arc;
use std::time::Duration;

use doorman_core::assembly::{AssemblyError, AuthCore, AuthCoreBuilder, AuthCoreRequired};
use doorman_core::audit::NoopAuditSink;
use doorman_core::email_link::{LinkTemplate, LinkTemplateError, LinkTemplates};
use doorman_core::memory::InMemoryStorage;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::RateLimiting;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{RecoveryConfig, RecoveryConfigError};
use doorman_core::session::SessionConfig;
use doorman_core::signup::SignupConfig;
use doorman_test_support::CapturingEmailSender;

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
fn zero_session_lifetime_is_rejected() {
    let err = valid_builder()
        .session(SessionConfig {
            absolute_lifetime: Duration::ZERO,
            ..SessionConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::InvalidLifetime {
                field: "session absolute_lifetime",
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
            token_lifetime: Duration::ZERO,
            ..SignupConfig::default()
        })
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::InvalidLifetime {
                field: "signup token_lifetime",
                ..
            })
        ),
        "expected InvalidLifetime for a zero signup token lifetime, got: {err:?}"
    );
}

#[test]
fn oversized_passkey_challenge_lifetime_is_rejected() {
    let err = AuthCore::builder(AuthCoreRequired {
        passkey: PasskeyConfig {
            challenge_lifetime: Duration::MAX,
            ..passkey_config()
        },
        ..required()
    })
    .build()
    .err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::InvalidLifetime {
                field: "passkey challenge_lifetime",
                ..
            })
        ),
        "expected InvalidLifetime for an oversized challenge lifetime, got: {err:?}"
    );
}

fn with_recovery_cool_down(cool_down: Duration) -> Result<AuthCore, AssemblyError> {
    valid_builder()
        .recovery(RecoveryConfig {
            cool_down,
            ..RecoveryConfig::default()
        })
        .build()
}

#[test]
fn recovery_cool_down_below_the_floor_is_rejected() {
    let configured = RecoveryConfig::MIN_COOL_DOWN - Duration::from_secs(1);
    assert!(matches!(
        with_recovery_cool_down(configured).err(),
        Some(AssemblyError::RecoveryCoolDown(RecoveryConfigError::CoolDownTooShort {
            configured: c,
            minimum,
        })) if c == configured && minimum == RecoveryConfig::MIN_COOL_DOWN
    ));
}

#[test]
fn recovery_cool_down_above_the_ceiling_is_rejected() {
    let configured = RecoveryConfig::MAX_COOL_DOWN + Duration::from_secs(1);
    assert!(matches!(
        with_recovery_cool_down(configured).err(),
        Some(AssemblyError::RecoveryCoolDown(RecoveryConfigError::CoolDownTooLong {
            configured: c,
            maximum,
        })) if c == configured && maximum == RecoveryConfig::MAX_COOL_DOWN
    ));
}

#[test]
fn recovery_cool_down_at_the_floor_is_accepted() {
    assert!(with_recovery_cool_down(RecoveryConfig::MIN_COOL_DOWN).is_ok());
}
