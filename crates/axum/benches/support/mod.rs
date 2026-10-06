use std::sync::Arc;
use std::time::Duration;

use doorman_axum::SessionCachePolicy;
use doorman_core::account::AccountConfig;
use doorman_core::assembly::AuthCore;
use doorman_core::audit::NoopAuditSink;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::NoopRateLimiter;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::SessionConfig;
use doorman_core::signup::SignupConfig;
use doorman_core::storage::Storage;
use doorman_test_support::CapturingEmailSender;
use url::Url;

pub fn in_memory_core(storage: Storage, cache: SessionCachePolicy) -> AuthCore {
    AuthCore::builder(storage)
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
        .session_cache(cache)
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
