//! Signup-request bench: the work `request_signup` does behind an
//! enrollment flow — email normalize/validate, rate-limit check, user
//! provisioning, single-use token issuance, link render, and the (captured,
//! non-networked) email send.
//!
//! Each iteration runs against a fresh, empty manager (built in the
//! untimed `iter_batched` setup) so it measures the steady-state cost of a
//! single provision-and-issue against an empty store. Reusing one manager
//! across iterations would instead measure the cost of an ever-growing
//! token store (the `Vec`-backed in-memory store scans every entry on each
//! write), which is a property of the test double, not the signup path.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p doorman-core --bench enrollment
//! ```

use std::sync::Arc;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use doorman_core::audit::{AuditSink, NoopAuditSink};
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::context::CoreDeps;
use doorman_core::email::{DefaultEmailTemplates, EmailSender, SecurityEmailNotifier};
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::passkey::{PasskeyConfig, PasskeyManager};
use doorman_core::rate_limit::{NoopRateLimiter, RateLimiter};
use doorman_core::session::{SessionConfig, SessionContext, SessionManager};
use doorman_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use doorman_core::storage::{SessionStore, Storage};
use doorman_core::verification::EnrollmentFlow;
use doorman_test_support::CapturingEmailSender;
use tokio::runtime::Runtime;
use url::Url;

fn signup_manager() -> SignupManager {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let tokens: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let credentials: Arc<InMemoryPasskeyCredentialStore> =
        Arc::new(InMemoryPasskeyCredentialStore::new());
    let challenges: Arc<InMemoryPasskeyChallengeStore> =
        Arc::new(InMemoryPasskeyChallengeStore::new());
    let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());

    let session_manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone(),
        audit.clone(),
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
            ..SessionConfig::default()
        },
    );

    let storage = Storage {
        users,
        sessions,
        verification_tokens: tokens,
        passkey_credentials: credentials,
        passkey_challenges: challenges,
    };
    let email = email as Arc<dyn EmailSender>;
    let emails = Arc::new(DefaultEmailTemplates);
    let notifier = SecurityEmailNotifier::new(email.clone(), emails.clone());
    let deps = CoreDeps::new(
        clock,
        audit,
        email,
        emails,
        notifier,
        Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>,
        session_manager,
        storage,
    );

    let passkey = PasskeyManager::new(
        &deps,
        PasskeyConfig::new(
            "localhost",
            Url::parse("http://localhost:8080").expect("rp origin"),
            "doorman bench",
        ),
    )
    .expect("build passkey manager");

    let flow = EnrollmentFlow::new(&deps, passkey);
    SignupManager::new(
        flow,
        SignupConfig {
            url_template: "https://app.test/signup?token={token}".to_string(),
            rate_limits: SignupRateLimits::disabled(),
            ..SignupConfig::default()
        },
    )
}

fn enrollment(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    c.bench_function("signup_request", |b| {
        b.to_async(&runtime).iter_batched(
            signup_manager,
            |manager| async move {
                manager
                    .request_signup("user@example.com", SessionContext::default())
                    .await
                    .expect("request signup");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, enrollment);
criterion_main!(benches);
