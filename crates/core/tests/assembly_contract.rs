use std::sync::Arc;
use std::time::Duration;

use doorman_core::account::AccountConfig;
use doorman_core::assembly::{AssemblyError, AuthCore, AuthCoreBuilder};
use doorman_core::audit::{AuditSink, NoopAuditSink};
use doorman_core::cache::{MAX_CACHE_TTL, SessionCacheConfig, SessionCachePolicy};
use doorman_core::clock::SystemClock;
use doorman_core::email::EmailSender;
use doorman_core::memory::{InMemoryRateLimiter, InMemoryStorage};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::{NoopRateLimiter, RateLimiter};
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::SessionConfig;
use doorman_core::signup::SignupConfig;
use doorman_core::storage::Storage;
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

fn valid_builder() -> AuthCoreBuilder {
    AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .session_cache(SessionCachePolicy::disabled())
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
        .account(real_account())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::MissingAuditSink)),
        "expected MissingAuditSink when no audit sink is wired, got: {err:?}"
    );
}

#[test]
fn missing_rate_limiter_returns_build_error() {
    let err = AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::MissingRateLimiter)),
        "expected MissingRateLimiter when no limiter is wired, got: {err:?}"
    );
}

#[test]
fn explicit_noop_collaborators_are_accepted() {
    let err = valid_builder()
        .audit(noop_audit())
        .limiter(Arc::new(NoopRateLimiter))
        .build()
        .err();
    assert!(
        err.is_none(),
        "explicitly chosen noop collaborators should build, got: {err:?}"
    );
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
        .account(real_account())
        .session_cache(SessionCachePolicy::disabled())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::ReauthDecisionRequired)),
        "expected ReauthDecisionRequired when no policy is wired, got: {err:?}"
    );
}

#[test]
fn session_cache_decision_required_when_policy_not_set() {
    let err = AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .reauthentication(ReauthPolicy::disabled())
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::SessionCacheDecisionRequired)),
        "expected SessionCacheDecisionRequired when no policy is wired, got: {err:?}"
    );
}

#[test]
fn session_cache_ttl_is_capped() {
    let build = |ttl| {
        valid_builder()
            .session_cache(SessionCachePolicy::per_process(SessionCacheConfig {
                ttl,
                ..SessionCacheConfig::default()
            }))
            .build()
            .err()
    };

    for ttl in [Duration::ZERO, MAX_CACHE_TTL + Duration::from_secs(1)] {
        let err = build(ttl);
        assert!(
            matches!(
                err,
                Some(AssemblyError::InvalidLifetime { field: "session cache ttl", value, .. })
                    if value == ttl
            ),
            "a ttl of {ttl:?} is refused, got: {err:?}"
        );
    }
    let err = build(MAX_CACHE_TTL);
    assert!(err.is_none(), "a ttl at the cap builds, got: {err:?}");
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
fn default_account_template_is_rejected_as_placeholder() {
    let err = valid_builder()
        .account(AccountConfig::default())
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(AssemblyError::PlaceholderUrlTemplate {
                flow: "account email change",
                ..
            })
        ),
        "expected PlaceholderUrlTemplate for account, got: {err:?}"
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
fn subfloor_recovery_cooldown_is_rejected() {
    let err = valid_builder()
        .recovery(RecoveryConfig {
            cooldown: Duration::from_secs(60),
            ..real_recovery()
        })
        .build()
        .err();
    assert!(
        matches!(err, Some(AssemblyError::RecoveryCooldown(_))),
        "expected RecoveryCooldown, got: {err:?}"
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
