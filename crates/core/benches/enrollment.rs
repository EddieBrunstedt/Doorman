//! Signup-request bench: the work `request_signup` does behind an
//! enrollment flow — email normalize/validate, rate-limit check, user
//! provisioning, single-use token issuance, link render, and the (captured,
//! non-networked) email send.
//!
//! Each iteration uses a fresh email so it exercises the full
//! provision-and-issue path rather than the cheaper "already registered"
//! silent branch.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-core --bench enrollment
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimiter};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use bauth_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, UserStore, VerificationTokenStore,
};
use bauth_core::verification::EnrollmentFlow;
use bauth_test_support::CapturingEmailSender;
use criterion::{Criterion, criterion_group, criterion_main};
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
        sessions as Arc<dyn SessionStore>,
        clock.clone(),
        audit.clone(),
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let passkey = PasskeyManager::new(
        users.clone() as Arc<dyn UserStore>,
        credentials as Arc<dyn PasskeyCredentialStore>,
        challenges as Arc<dyn PasskeyChallengeStore>,
        session_manager.clone(),
        clock.clone(),
        audit.clone(),
        PasskeyConfig::new(
            "localhost",
            Url::parse("http://localhost:8080").expect("rp origin"),
            "bauth bench",
        ),
    )
    .expect("build passkey manager");

    let flow = EnrollmentFlow::new(
        users as Arc<dyn UserStore>,
        tokens as Arc<dyn VerificationTokenStore>,
        passkey,
        session_manager,
        email as Arc<dyn EmailSender>,
        clock,
        audit,
        Arc::new(NoopRateLimiter) as Arc<dyn RateLimiter>,
    );
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
    let manager = signup_manager();
    let counter = AtomicU64::new(0);

    c.bench_function("signup_request", |b| {
        b.to_async(&runtime).iter(|| async {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let email = format!("user{n}@example.com");
            manager
                .request_signup(&email, SessionContext::default())
                .await
                .expect("request signup");
        });
    });
}

criterion_group!(benches, enrollment);
criterion_main!(benches);
