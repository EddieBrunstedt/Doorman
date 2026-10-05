//! Build-time configuration contract for `AuthCore::builder().build()`.
//!
//! The assembly is strict by default: a missing required collaborator, a
//! placeholder URL, an undecided re-auth posture, or any other portable
//! misconfiguration is a hard [`AssemblyError`] rather than a silenceable
//! warning. These tests pin each failure mode and the successful happy path.
//! The HTTP settings a front end layers on top are pinned in that front end's
//! own contract tests.

use std::sync::Arc;
use std::time::Duration;

use doorman_core::account::AccountConfig;
use doorman_core::assembly::{AssemblyError, AuthCore, AuthCoreBuilder};
use doorman_core::audit::{AuditSink, NoopAuditSink};
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

/// A builder with every required input wired correctly, so `build()`
/// succeeds. Tests that probe a single validation start here and override the
/// one field under test; tests that probe a *missing* required input build a
/// chain by hand instead (you cannot un-set a builder field).
fn valid_builder() -> AuthCoreBuilder {
    AuthCore::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .audit(noop_audit())
        .limiter(in_memory_limiter())
        .signup(real_signup())
        .recovery(real_recovery())
        .account(real_account())
        .reauthentication(ReauthPolicy::disabled())
}

// --- A fully-wired builder succeeds ---

#[test]
fn fully_wired_builder_builds() {
    valid_builder().build().expect("build");
}

// --- Required collaborators (strict by default, no silent defaults) ---

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
    // The dev/opt-out choices are still available — they are just explicit,
    // so they build without any warning.
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

// --- Re-authentication decision is required ---

#[test]
fn reauth_decision_required_when_policy_not_set() {
    // Every other input is valid; only the re-auth decision is missing. The
    // build refuses to guess whether destructive actions should require a
    // fresh passkey assertion.
    let err = AuthCore::builder(fresh_storage())
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
        matches!(err, Some(AssemblyError::ReauthDecisionRequired)),
        "expected ReauthDecisionRequired when no policy is wired, got: {err:?}"
    );
}

// --- Placeholder URL templates fail closed ---

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

// --- Lifetimes and the recovery cool-down ---

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
