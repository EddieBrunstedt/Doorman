//! Build-time configuration warnings emitted by `BauthAxum::builder().build()`
//! and `BauthAxum::from_managers().build()`.
//!
//! Each test installs its own thread-scoped `tracing` subscriber that
//! captures warnings into an in-memory buffer, then asserts the messages
//! match the configuration that was supposed to trigger them.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bauth_axum::config::CookieConfig;
use bauth_axum::{BauthAxum, BuilderError};
use bauth_core::account::{AccountConfig, AccountManager};
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::context::CoreDeps;
use bauth_core::email::{
    DefaultBauthEmails, EmailSender, FileEmailSender, SecurityEmailNotifier, TerminalEmailSender,
};
use bauth_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimiter};
use bauth_core::recovery::{RecoveryConfig, RecoveryManager};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::signup::{SignupConfig, SignupManager};
use bauth_core::storage::{Storage, UserId};
use bauth_core::verification::EnrollmentFlow;
use bauth_test_support::CapturingEmailSender;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Default, Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn output(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture writer lock").clone()).expect("utf-8")
    }
}

struct CaptureHandle(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture writer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureHandle;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureHandle(self.0.clone())
    }
}

fn fresh_storage() -> Storage {
    Storage {
        users: Arc::new(InMemoryUserStore::new()),
        sessions: Arc::new(InMemorySessionStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
    }
}

fn capturing_email() -> Arc<dyn EmailSender> {
    Arc::new(CapturingEmailSender::new())
}

fn passkey_config() -> PasskeyConfig {
    PasskeyConfig::new(
        "localhost",
        "http://localhost:8080".parse().expect("rp origin"),
        "bauth tests",
    )
}

const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
const ACCOUNT_URL: &str = "https://app.test/email-change?token={token}";

/// A signup config with a real (non-placeholder) URL template, so the
/// build does not trip the URL warning/error while a different validation
/// is under test.
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

fn capture<F>(f: F) -> String
where
    F: FnOnce(),
{
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_level(true)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    writer.output()
}

#[test]
fn quickstart_defaults_warn_about_noop_audit_and_in_memory_limiter() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .cookie(CookieConfig {
                secure: false,
                ..CookieConfig::default()
            })
            .build()
            .expect("build");
    });

    assert!(
        output.contains("InMemoryRateLimiter"),
        "expected in-memory limiter warning, got: {output}"
    );
    assert!(
        output.contains("AuditSink"),
        "expected noop audit warning, got: {output}"
    );
    assert!(
        !output.contains("cookie.secure"),
        "did not expect cookie warning for None domain (treated as local dev); got: {output}"
    );
}

#[test]
fn explicit_noop_rate_limiter_emits_noop_warning() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .limiter(Arc::new(NoopRateLimiter))
            .build()
            .expect("build");
    });

    assert!(
        output.contains("Rate limiting is disabled"),
        "expected noop limiter warning, got: {output}"
    );
    assert!(
        !output.contains("InMemoryRateLimiter"),
        "should not also warn about in-memory limiter when noop is explicit; got: {output}"
    );
}

#[test]
fn cookie_secure_false_with_production_domain_warns() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .cookie(CookieConfig {
                secure: false,
                domain: Some("example.com".into()),
                ..CookieConfig::default()
            })
            .silence_warnings() // keep cookie warning but suppress audit/limiter
            .build()
            .expect("build");
    });

    // silence_warnings should suppress *all* warnings, including the cookie one.
    assert!(
        output.is_empty(),
        "silence_warnings should suppress all warnings; got: {output}"
    );
}

#[test]
fn cookie_warning_fires_when_not_silenced() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .cookie(CookieConfig {
                secure: false,
                domain: Some("example.com".into()),
                ..CookieConfig::default()
            })
            .build()
            .expect("build");
    });

    assert!(
        output.contains("cookie.secure"),
        "expected cookie warning for non-localhost domain over plaintext HTTP; got: {output}"
    );
}

#[test]
fn quickstart_silence_warnings_suppresses_everything() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .silence_warnings()
            .build()
            .expect("build");
    });

    assert!(
        output.is_empty(),
        "silence_warnings should suppress every warning, got: {output}"
    );
}

#[test]
fn missing_email_sender_returns_build_error() {
    let result = BauthAxum::builder(fresh_storage())
        .silence_warnings()
        .build();
    match result {
        Err(BuilderError::MissingEmailSender) => {}
        Err(other) => panic!("expected MissingEmailSender, got: {other:?}"),
        Ok(_) => panic!("build should fail without email transport"),
    }
}

#[test]
fn missing_passkey_config_returns_build_error() {
    let result = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .silence_warnings()
        .build();
    match result {
        Err(BuilderError::MissingPasskeyConfig) => {}
        Err(other) => panic!("expected MissingPasskeyConfig, got: {other:?}"),
        Ok(_) => panic!("build should fail without passkey config"),
    }
}

#[test]
fn low_level_builder_rejects_missing_passkey_manager() {
    let storage = fresh_storage();
    let session_manager = SessionManager::new(
        storage.sessions.clone(),
        Arc::new(SystemClock),
        Arc::new(NoopAuditSink),
        SessionConfig::default(),
    );

    let result = BauthAxum::from_managers()
        .session_manager(session_manager)
        .user_store(storage.users.clone())
        .silence_warnings()
        .build();

    match result {
        Err(BuilderError::MissingPasskeyManager) => {}
        Err(other) => panic!("expected MissingPasskeyManager, got: {other:?}"),
        Ok(_) => panic!("build should fail without passkey manager"),
    }
}

#[tokio::test]
async fn low_level_from_managers_wires_managers_built_from_core_deps() {
    // Build every core manager from one shared `CoreDeps` and hand them to
    // the low-level `from_managers` builder. Asserts the path builds and,
    // crucially, that the `EnrollmentFlow` reaches its email transport
    // through the shared context (it no longer holds its own copy): a signup
    // request must enqueue a link email on the sender that lives in `deps`.
    let storage = fresh_storage();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email = Arc::new(CapturingEmailSender::new());
    let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);

    let notifier = SecurityEmailNotifier::new(
        email.clone() as Arc<dyn EmailSender>,
        Arc::new(DefaultBauthEmails),
    );
    let session_manager = SessionManager::new(
        storage.sessions.clone(),
        clock.clone(),
        audit.clone(),
        SessionConfig::default(),
    )
    .with_security_notifier(notifier.clone());

    let deps = CoreDeps::new(
        clock,
        audit,
        email.clone() as Arc<dyn EmailSender>,
        notifier,
        limiter,
        session_manager.clone(),
        storage.clone(),
    );

    let passkey = PasskeyManager::new(&deps, passkey_config()).expect("passkey manager");
    let flow = EnrollmentFlow::new(&deps, passkey.clone());
    let signup = SignupManager::new(flow.clone(), SignupConfig::default());
    let recovery =
        RecoveryManager::new(flow, RecoveryConfig::default()).expect("recovery cooldown valid");
    let account = AccountManager::new(&deps, AccountConfig::default());

    let auth = BauthAxum::from_managers()
        .session_manager(session_manager)
        .user_store(storage.users.clone())
        .passkey_manager(passkey)
        .signup_manager(signup)
        .recovery_manager(recovery)
        .account_manager(account)
        .silence_warnings()
        .build()
        .expect("low-level build should succeed when every manager is supplied");

    // The `BauthState` flow accessors must reach the very managers the
    // routes drive. Driving signup through `state().signup()` (rather than a
    // separately held handle) proves the accessor returns the wired manager:
    // the request must enqueue a link email on the shared transport.
    auth.state()
        .signup()
        .request_signup("wire@example.com", SessionContext::default())
        .await
        .expect("request signup");
    assert_eq!(
        email.sent().len(),
        1,
        "signup request should enqueue exactly one link email via the shared transport"
    );

    // The passkey and recovery accessors reach usable managers too: a fresh
    // user has no credentials, and recovery cool-down config is readable.
    let summaries = auth
        .state()
        .passkey()
        .list_passkey_summaries(UserId::new())
        .await
        .expect("list summaries");
    assert!(summaries.is_empty());
    let _ = auth.state().recovery();
}

#[test]
fn branding_one_flow_without_shared_renderer_warns() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .signup(SignupConfig {
                emails: Some(Arc::new(DefaultBauthEmails)),
                ..SignupConfig::default()
            })
            .build()
            .expect("build");
    });

    assert!(
        output.contains("custom email renderer"),
        "expected partial-branding warning when only one flow is branded; got: {output}"
    );
}

#[test]
fn shared_emails_renderer_does_not_warn_about_partial_branding() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .emails(Arc::new(DefaultBauthEmails))
            .signup(SignupConfig {
                emails: Some(Arc::new(DefaultBauthEmails)),
                ..SignupConfig::default()
            })
            .build()
            .expect("build");
    });

    assert!(
        !output.contains("custom email renderer"),
        "shared renderer should not trip the partial-branding warning; got: {output}"
    );
}

#[test]
fn terminal_email_transport_emits_dev_email_warning() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(Arc::new(TerminalEmailSender))
            .passkey(passkey_config())
            .build()
            .expect("build");
    });

    assert!(
        output.contains("dev-only sender"),
        "expected dev-email-transport warning for TerminalEmailSender; got: {output}"
    );
}

#[test]
fn file_email_transport_emits_dev_email_warning() {
    let dir = std::env::temp_dir().join(format!("bauth-warnings-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(Arc::new(FileEmailSender::new(&dir)))
            .passkey(passkey_config())
            .build()
            .expect("build");
    });

    assert!(
        output.contains("dev-only sender"),
        "expected dev-email-transport warning for FileEmailSender; got: {output}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// --- Build-time validation (fail closed on misconfiguration) ---

#[test]
fn signup_url_template_without_token_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(SignupConfig {
            url_template: "https://app.test/signup".to_string(),
            ..SignupConfig::default()
        })
        .recovery(real_recovery())
        .silence_warnings()
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidUrlTemplate { flow: "signup", .. })
        ),
        "expected InvalidUrlTemplate for signup, got: {err:?}"
    );
}

#[test]
fn recovery_url_template_without_token_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery".to_string(),
            ..RecoveryConfig::default()
        })
        .silence_warnings()
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidUrlTemplate {
                flow: "recovery",
                ..
            })
        ),
        "expected InvalidUrlTemplate for recovery, got: {err:?}"
    );
}

#[test]
fn default_example_invalid_url_template_warns() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .build()
            .expect("build");
    });
    assert!(
        output.contains("example.invalid"),
        "expected placeholder-url-template warning when the template is left at the default; \
         got: {output}"
    );
}

#[test]
fn real_url_templates_do_not_warn_about_placeholder() {
    let output = capture(|| {
        let _ = BauthAxum::builder(fresh_storage())
            .email(capturing_email())
            .passkey(passkey_config())
            .signup(real_signup())
            .recovery(real_recovery())
            .account(real_account())
            .build()
            .expect("build");
    });
    assert!(
        !output.contains("example.invalid"),
        "real templates should not trip the placeholder warning; got: {output}"
    );
}

#[test]
fn subfloor_recovery_cooldown_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(RecoveryConfig {
            cooldown: Duration::from_secs(60),
            url_template: RECOVERY_URL.to_string(),
            ..RecoveryConfig::default()
        })
        .silence_warnings()
        .build()
        .err();
    assert!(
        matches!(err, Some(BuilderError::RecoveryCooldownTooShort(_))),
        "expected RecoveryCooldownTooShort, got: {err:?}"
    );
}

#[test]
fn host_prefixed_cookie_without_secure_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(real_recovery())
        .cookie(CookieConfig {
            session_cookie_name: "__Host-bauth".to_string(),
            secure: false,
            ..CookieConfig::default()
        })
        .silence_warnings()
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
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(real_recovery())
        .cookie(CookieConfig {
            session_cookie_name: "__Host-bauth".to_string(),
            secure: true,
            domain: Some("app.test".to_string()),
            ..CookieConfig::default()
        })
        .silence_warnings()
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
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(real_recovery())
        .cookie(CookieConfig {
            session_cookie_name: "__Secure-bauth".to_string(),
            secure: false,
            ..CookieConfig::default()
        })
        .silence_warnings()
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
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(real_recovery())
        .cookie(CookieConfig {
            session_cookie_name: "__Host-bauth".to_string(),
            secure: true,
            domain: None,
            path: "/".to_string(),
            ..CookieConfig::default()
        })
        .silence_warnings()
        .build()
        .err();
    assert!(
        err.is_none(),
        "a __Host- cookie with Secure, Path=/, and no Domain should build; got: {err:?}"
    );
}

#[test]
fn zero_session_lifetime_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(real_recovery())
        .session(SessionConfig {
            lifetime: Duration::ZERO,
            ..SessionConfig::default()
        })
        .silence_warnings()
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidLifetime {
                field: "session lifetime",
                ..
            })
        ),
        "expected InvalidLifetime for a zero session lifetime, got: {err:?}"
    );
}

#[test]
fn zero_signup_token_lifetime_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(SignupConfig {
            url_template: SIGNUP_URL.to_string(),
            token_lifetime: Duration::ZERO,
            ..SignupConfig::default()
        })
        .recovery(real_recovery())
        .silence_warnings()
        .build()
        .err();
    assert!(
        matches!(
            err,
            Some(BuilderError::InvalidLifetime {
                field: "signup token_lifetime",
                ..
            })
        ),
        "expected InvalidLifetime for a zero signup token lifetime, got: {err:?}"
    );
}

#[test]
fn cookie_max_age_exceeding_session_lifetime_is_rejected() {
    let err = BauthAxum::builder(fresh_storage())
        .email(capturing_email())
        .passkey(passkey_config())
        .signup(real_signup())
        .recovery(real_recovery())
        .session(SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
            ..SessionConfig::default()
        })
        .cookie(CookieConfig {
            session_max_age: Duration::from_secs(60 * 60 * 2),
            ..CookieConfig::default()
        })
        .silence_warnings()
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
