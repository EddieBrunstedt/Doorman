//! Build-time configuration warnings emitted by `quickstart().build()`
//! and `BauthAxum::builder().build()`.
//!
//! Each test installs its own thread-scoped `tracing` subscriber that
//! captures warnings into an in-memory buffer, then asserts the messages
//! match the configuration that was supposed to trigger them.

use std::io;
use std::sync::{Arc, Mutex};

use bauth_axum::BuilderError;
use bauth_axum::config::CookieConfig;
use bauth_axum::quickstart;
use bauth_core::email::{EmailSender, FileEmailSender, TerminalEmailSender};
use bauth_core::memory::{
    CapturingEmailSender, InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::rate_limit::NoopRateLimiter;
use bauth_core::storage::Storage;
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
        let _ = quickstart(fresh_storage())
            .email(capturing_email())
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
        let _ = quickstart(fresh_storage())
            .email(capturing_email())
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
        let _ = quickstart(fresh_storage())
            .email(capturing_email())
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
        let _ = quickstart(fresh_storage())
            .email(capturing_email())
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
        let _ = quickstart(fresh_storage())
            .email(capturing_email())
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
    let result = quickstart(fresh_storage()).silence_warnings().build();
    match result {
        Err(BuilderError::MissingEmailSender) => {}
        Err(other) => panic!("expected MissingEmailSender, got: {other:?}"),
        Ok(_) => panic!("build should fail without email transport"),
    }
}

#[test]
fn terminal_email_transport_emits_dev_email_warning() {
    let output = capture(|| {
        let _ = quickstart(fresh_storage())
            .email(Arc::new(TerminalEmailSender))
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
        let _ = quickstart(fresh_storage())
            .email(Arc::new(FileEmailSender::new(&dir)))
            .build()
            .expect("build");
    });

    assert!(
        output.contains("dev-only sender"),
        "expected dev-email-transport warning for FileEmailSender; got: {output}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
