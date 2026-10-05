//! Shared bench scaffolding: an [`AuthCore`] over fresh in-memory storage,
//! assembled through the production builder so the benches measure the
//! wiring a host gets.

use std::sync::Arc;
use std::time::Duration;

use doorman_axum::SessionCacheConfig;
use doorman_core::account::AccountConfig;
use doorman_core::assembly::AuthCore;
use doorman_core::audit::NoopAuditSink;
use doorman_core::memory::InMemoryStorage;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::NoopRateLimiter;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::SessionConfig;
use doorman_core::signup::SignupConfig;
use doorman_test_support::CapturingEmailSender;
use url::Url;

/// Assemble an [`AuthCore`] over fresh in-memory storage with the given
/// session-cache config: one-hour sessions, no rate limiting,
/// re-authentication disabled, and captured (never sent) email.
pub fn in_memory_core(cache: SessionCacheConfig) -> AuthCore {
    AuthCore::builder(InMemoryStorage::new().all_stores())
        .email(Arc::new(CapturingEmailSender::new()))
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(NoopRateLimiter))
        .passkey(PasskeyConfig::new(
            "localhost",
            Url::parse("http://localhost:8080").expect("rp origin"),
            "doorman bench",
        ))
        .reauthentication(ReauthPolicy::disabled())
        .session(SessionConfig {
            absolute_lifetime: Duration::from_secs(60 * 60),
            ..SessionConfig::default()
        })
        .cache(cache)
        .signup(SignupConfig {
            url_template: "https://app.test/signup?token={token}".to_string(),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery?token={token}".to_string(),
            ..RecoveryConfig::default()
        })
        .account(AccountConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..AccountConfig::default()
        })
        .build()
        .expect("bench core assembles")
}
