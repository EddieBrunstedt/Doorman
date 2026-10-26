use std::sync::Arc;
use std::time::Duration;

use doorman_core::assembly::{AssemblyError, AuthCore, AuthCoreBuilder};
use doorman_core::audit::{AuditSink, NoopAuditSink};
use doorman_core::clock::SystemClock;
use doorman_core::email::EmailSender;
use doorman_core::memory::{InMemoryRateLimiter, InMemoryStorage};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::{RateLimitPolicy, RateLimiter, RateLimits};
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{RecoveryConfig, RecoveryConfigError};
use doorman_core::session::SessionConfig;
use doorman_core::signup::SignupConfig;
use doorman_core::storage::Storage;
use doorman_core::user::UserConfig;
use doorman_test_support::CapturingEmailSender;

fn fresh_storage() -> Storage {
    InMemoryStorage::new().all_stores()
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
const USER_URL: &str = "https://app.test/email-change?token={token}";

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

fn real_user() -> UserConfig {
    UserConfig {
        url_template: USER_URL.to_string(),
        ..UserConfig::default()
    }
}

fn valid_builder() -> AuthCoreBuilder {
    AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .user(real_user())
        .reauthentication(ReauthPolicy::disabled())
}

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

#[test]
fn missing_email_sender_returns_build_error() {
    let err = AuthCore::builder(fresh_storage()).build().err();
    assert!(
        matches!(err, Some(AssemblyError::MissingEmailSender)),
        "expected MissingEmailSender, got: {err:?}"
    );
}

#[test]
fn missing_passkey_config_returns_build_error() {
    let err = AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::MissingPasskeyConfig)),
        "expected MissingPasskeyConfig, got: {err:?}"
    );
}

#[test]
fn missing_audit_sink_returns_build_error() {
    let err = AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .user(real_user())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::MissingAuditSink)),
        "expected MissingAuditSink when no audit sink is wired, got: {err:?}"
    );
}

#[test]
fn a_rate_limiter_is_required_unless_every_rate_limit_is_off() {
    let one_on = RateLimits {
        recovery_request_global: Some(RateLimitPolicy::new(1, Duration::from_secs(60))),
        ..RateLimits::disabled()
    };
    for (limits, needs_limiter) in [
        (None, true),
        (Some(RateLimits::default()), true),
        (Some(one_on), true),
        (Some(RateLimits::disabled()), false),
    ] {
        let mut builder = AuthCore::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .audit(noop_audit())
            .signup(real_signup())
            .recovery(real_recovery())
            .user(real_user())
            .reauthentication(ReauthPolicy::disabled());
        if let Some(limits) = limits {
            builder = builder.rate_limits(limits);
        }

        let err = builder.build().err();

        if needs_limiter {
            assert!(
                matches!(err, Some(AssemblyError::MissingRateLimiter)),
                "{limits:?}: {err:?}"
            );
        } else {
            assert!(err.is_none(), "{limits:?}: {err:?}");
        }
    }
}

#[test]
fn reauth_decision_required_when_policy_not_set() {
    let err = AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .user(real_user())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::ReauthDecisionRequired)),
        "expected ReauthDecisionRequired when no policy is wired, got: {err:?}"
    );
}

#[test]
fn default_signup_template_is_rejected_as_placeholder() {
    let err = valid_builder()
        .signup(SignupConfig::default())
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::PlaceholderUrlTemplate { flow: "signup", .. })
        ),
        "expected PlaceholderUrlTemplate for signup, got: {err:?}"
    );
}

#[test]
fn default_recovery_template_is_rejected_as_placeholder() {
    let err = valid_builder()
        .recovery(RecoveryConfig::default())
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::PlaceholderUrlTemplate {
                flow: "recovery",
                ..
            })
        ),
        "expected PlaceholderUrlTemplate for recovery, got: {err:?}"
    );
}

#[test]
fn default_email_change_template_is_rejected_as_placeholder() {
    let err = valid_builder().user(UserConfig::default()).build().err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::PlaceholderUrlTemplate {
                flow: "email change",
                ..
            })
        ),
        "expected PlaceholderUrlTemplate for email change, got: {err:?}"
    );
}

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
            Some(AssemblyError::InvalidUrlTemplate { flow: "signup", .. })
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
            Some(AssemblyError::InvalidUrlTemplate {
                flow: "recovery",
                ..
            })
        ),
        "expected InvalidUrlTemplate for recovery, got: {err:?}"
    );
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
            ..real_signup()
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
    let err = valid_builder()
        .passkey(PasskeyConfig {
            challenge_lifetime: Duration::MAX,
            ..passkey_config()
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
            ..real_recovery()
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
