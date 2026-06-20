//! `AuthService::purge_expired` delegates to the composite storage the
//! high-level builder was handed, so an in-process job or test can sweep
//! expired rows through the built service rather than the raw `Storage`.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use doorman_axum::AuthService;
use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_core::account::AccountConfig;
use doorman_core::audit::NoopAuditSink;
use doorman_core::clock::SystemClock;
use doorman_core::email::{EmailSender, TerminalEmailSender};
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::recovery::{RecoveryConfig, RecoveryRateLimits};
use doorman_core::signup::{SignupConfig, SignupRateLimits};
use doorman_core::storage::{
    Session, SessionId, Storage, TokenHash, UserId, VerificationPurpose, VerificationToken,
};
use url::Url;

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

/// Build a service through the high-level builder over in-memory storage,
/// returning the service plus a clone of the storage to seed rows through. The
/// clone shares the same `Arc` stores, so rows seeded via it are visible to the
/// service's sweep.
fn service_with_storage() -> (AuthService, Storage) {
    let storage = Storage {
        users: Arc::new(InMemoryUserStore::new()),
        sessions: Arc::new(InMemorySessionStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
    };
    let seed = storage.clone();

    let origin = Url::parse("http://localhost:8080").expect("origin");
    let service = AuthService::builder(storage)
        .email(Arc::new(TerminalEmailSender) as Arc<dyn EmailSender>)
        .passkey(PasskeyConfig::new("localhost", origin, "doorman tests"))
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig {
            url_template: "https://app.test/signup?token={token}".to_string(),
            rate_limits: SignupRateLimits::disabled(),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery?token={token}".to_string(),
            rate_limits: RecoveryRateLimits::disabled(),
            ..RecoveryConfig::default()
        })
        .account(AccountConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..AccountConfig::default()
        })
        .csrf(CsrfConfig::disabled())
        .cookie(CookieConfig::default())
        .build()
        .expect("service built");

    (service, seed)
}

#[tokio::test]
async fn purge_expired_sweeps_the_builder_storage_and_matches_a_direct_sweep() {
    let now = ts(1_000_000);
    let (service, storage) = service_with_storage();

    let user_id = UserId::new();
    let expired = now - Duration::hours(1);
    let live = now + Duration::hours(1);

    let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
        id: SessionId::new(),
        user_id,
        token_hash: TokenHash([tag; 32]),
        created_at: now - Duration::hours(2),
        expires_at,
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    storage
        .sessions
        .create_session(mk_session(1, expired))
        .await
        .expect("expired session");
    storage
        .sessions
        .create_session(mk_session(2, live))
        .await
        .expect("live session");

    let mk_token = |tag: u8, expires_at: DateTime<Utc>| VerificationToken {
        token_hash: TokenHash([tag; 32]),
        user_id,
        purpose: VerificationPurpose::Signup,
        new_email: None,
        created_at: now - Duration::hours(2),
        expires_at,
    };
    storage
        .verification_tokens
        .create_token(mk_token(3, expired))
        .await
        .expect("expired token");

    // The delegate reports exactly the expired rows.
    let summary = service.purge_expired(now).await.expect("purge via service");
    assert_eq!(summary.sessions, 1);
    assert_eq!(summary.verification_tokens, 1);
    assert_eq!(summary.passkey_challenges, 0);
    assert_eq!(summary.total(), 2);

    // It swept the very same stores the builder was handed: a direct sweep over
    // the shared storage now finds nothing left to remove.
    let direct = storage
        .purge_all_expired(now)
        .await
        .expect("direct sweep over shared storage");
    assert_eq!(direct, doorman_core::purge::PurgeSummary::default());
}
