//! End-to-end password-login bench.
//!
//! Exercises [`PasswordAuthManager::login`] against the in-memory storage
//! stack with default Argon2 parameters. The dominant cost is
//! hardware-dependent Argon2id hashing, so this bench is what catches
//! regressions in the "is the hashing on the blocking pool?" wiring as
//! well as anything that would inflate the password-login critical path.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-core --bench password_login
//! ```

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    InMemoryEmailSender, InMemoryPasswordCredentialStore, InMemorySessionStore, InMemoryUserStore,
    InMemoryVerificationTokenStore,
};
use bauth_core::password::PasswordPolicy;
use bauth_core::password_auth::{PasswordAuthConfig, PasswordAuthManager, PasswordRateLimits};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimiter};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{
    PasswordCredentialStore, SessionStore, UserStore, VerificationTokenStore,
};
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

const EMAIL: &str = "bench@example.com";
const PASSWORD: &str = "hunter22hunter22";

fn build_manager() -> PasswordAuthManager {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email: Arc<dyn EmailSender> = Arc::new(InMemoryEmailSender::new());
    let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);

    let user_store: Arc<dyn UserStore> = Arc::new(InMemoryUserStore::new());
    let session_store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    let password_store: Arc<dyn PasswordCredentialStore> =
        Arc::new(InMemoryPasswordCredentialStore::new());
    let token_store: Arc<dyn VerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());

    let session_manager = SessionManager::new(
        session_store,
        clock.clone(),
        audit.clone(),
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );

    PasswordAuthManager::new(
        user_store,
        password_store,
        token_store,
        session_manager,
        email,
        clock,
        audit,
        limiter,
        PasswordAuthConfig {
            password_policy: PasswordPolicy { min_length: 8 },
            rate_limits: PasswordRateLimits::disabled(),
            ..PasswordAuthConfig::default()
        },
    )
}

fn password_login(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    let manager = build_manager();
    runtime.block_on(async {
        manager
            .register(EMAIL, PASSWORD, SessionContext::default())
            .await
            .expect("register seed user");
    });

    let mut group = c.benchmark_group("password");
    // Argon2 dominates the benchmark; cap the sample count so the whole
    // run stays under a minute on a developer laptop.
    group.sample_size(20);

    group.bench_function("login_end_to_end", |b| {
        b.to_async(&runtime).iter(|| async {
            manager
                .login(EMAIL, PASSWORD, SessionContext::default())
                .await
                .expect("login");
        });
    });

    group.finish();
}

criterion_group!(benches, password_login);
criterion_main!(benches);
