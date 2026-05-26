//! End-to-end smoke test for the SQLx + SQLite adapter.
//!
//! Wires every storage trait through `SqliteStorage` and runs the
//! happy-path password flow against it: register -> verify email ->
//! login -> reset password -> login with the new password. Also
//! exercises the OAuth identity store and verification-token purging
//! since those have query shapes the password flow doesn't reach.

#![cfg(feature = "sqlite")]

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::email::EmailSender;
use bauth_core::memory::{InMemoryEmailSender, InMemoryRateLimiter};
use bauth_core::password::PasswordPolicy;
use bauth_core::password_auth::{
    PasswordAuthConfig, PasswordAuthManager, PasswordRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{OAuthIdentity, UserId, VerificationPurpose};
use bauth_sqlx::SqliteStorage;
use chrono::{TimeZone, Utc};

const VERIFY_URL: &str = "https://app.test/verify-email?token={token}";
const RESET_URL: &str = "https://app.test/reset-password?token={token}";

fn token_from_email(template: &str, body: &str) -> String {
    let prefix = template
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after.split_whitespace().next().unwrap().to_string()
}

async fn setup() -> (SqliteStorage, PasswordAuthManager, Arc<InMemoryEmailSender>) {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let clock: Arc<MockClock> = Arc::new(MockClock::new(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ));
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email: Arc<InMemoryEmailSender> = Arc::new(InMemoryEmailSender::new());
    let limiter: Arc<dyn RateLimiter> =
        Arc::new(InMemoryRateLimiter::new(clock.clone() as Arc<dyn Clock>));

    let session_manager = SessionManager::new(
        storage.session_store(),
        clock.clone() as Arc<dyn Clock>,
        audit.clone(),
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let manager = PasswordAuthManager::new(
        storage.user_store(),
        storage.password_credential_store(),
        storage.verification_token_store(),
        session_manager,
        email.clone() as Arc<dyn EmailSender>,
        clock as Arc<dyn Clock>,
        audit,
        limiter,
        PasswordAuthConfig {
            password_policy: PasswordPolicy { min_length: 8 },
            verification_url_template: VERIFY_URL.to_string(),
            password_reset_url_template: RESET_URL.to_string(),
            rate_limits: PasswordRateLimits::disabled(),
            ..PasswordAuthConfig::default()
        },
    );

    (storage, manager, email)
}

#[tokio::test]
async fn full_password_flow_against_sqlite() {
    let (storage, manager, email) = setup().await;

    let outcome = manager
        .register(
            "alice@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("register");
    assert!(outcome.session.is_some(), "session issued on register");

    let users = storage.user_store();
    let persisted = users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find")
        .expect("user persisted");
    assert_eq!(persisted.id, outcome.user.id);

    let verify_body = email
        .sent()
        .into_iter()
        .find(|e| e.subject == "Verify your email address")
        .expect("verify email queued")
        .body_text;
    let verify_token = token_from_email(VERIFY_URL, &verify_body);
    manager
        .verify_email(&verify_token, SessionContext::default())
        .await
        .expect("verify");

    let after_verify = users
        .find_user_by_id(outcome.user.id)
        .await
        .expect("find")
        .expect("user");
    assert!(after_verify.email_verified_at.is_some());

    manager
        .login(
            "alice@example.com",
            "hunter22hunter22",
            SessionContext::default(),
        )
        .await
        .expect("login");

    manager
        .request_password_reset("alice@example.com", SessionContext::default())
        .await
        .expect("reset request");
    let reset_body = email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Reset your password")
        .expect("reset email queued")
        .body_text;
    let reset_token = token_from_email(RESET_URL, &reset_body);
    manager
        .reset_password(&reset_token, "newpass22newpass", SessionContext::default())
        .await
        .expect("reset");

    manager
        .login(
            "alice@example.com",
            "newpass22newpass",
            SessionContext::default(),
        )
        .await
        .expect("login with new pw");

    let tokens = storage.verification_token_store();
    let purged = tokens
        .purge_expired(Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap())
        .await
        .expect("purge");
    assert_eq!(purged, 0, "no outstanding tokens after consume");
}

#[tokio::test]
async fn oauth_identity_round_trip_against_sqlite() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let user_id = UserId::new();
    storage
        .user_store()
        .create_user(bauth_core::storage::User {
            id: user_id,
            email: Some("alice@example.com".into()),
            email_verified_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        })
        .await
        .expect("create user");

    let identities = storage.oauth_identity_store();
    identities
        .link(OAuthIdentity {
            provider: "google".into(),
            subject: "sub-123".into(),
            user_id,
            email: Some("alice@example.com".into()),
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        })
        .await
        .expect("link");

    let found = identities
        .find_by_provider_subject("google", "sub-123")
        .await
        .expect("find")
        .expect("identity present");
    assert_eq!(found.user_id, user_id);

    let listed = identities.list_for_user(user_id).await.expect("list");
    assert_eq!(listed.len(), 1);

    identities
        .unlink("google", "sub-123")
        .await
        .expect("unlink");
    assert!(
        identities
            .find_by_provider_subject("google", "sub-123")
            .await
            .expect("find after unlink")
            .is_none()
    );
}

#[tokio::test]
async fn verification_token_consume_is_atomic() {
    use bauth_core::session::hash_token;
    use bauth_core::storage::VerificationToken;

    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let user_id = UserId::new();
    storage
        .user_store()
        .create_user(bauth_core::storage::User {
            id: user_id,
            email: Some("u@example.com".into()),
            email_verified_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        })
        .await
        .expect("user");

    let tokens = storage.verification_token_store();
    let hash = hash_token("test-token");
    tokens
        .create_token(VerificationToken {
            token_hash: hash,
            user_id,
            purpose: VerificationPurpose::MagicLink,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await
        .expect("create");

    let first = tokens
        .consume_token(&hash, VerificationPurpose::MagicLink)
        .await
        .expect("consume");
    assert!(first.is_some(), "first consume returns the token");

    let second = tokens
        .consume_token(&hash, VerificationPurpose::MagicLink)
        .await
        .expect("consume again");
    assert!(second.is_none(), "second consume returns nothing");
}

#[tokio::test]
async fn session_list_and_delete_others_against_sqlite() {
    use bauth_core::session::hash_token;
    use bauth_core::storage::{Session, SessionId};
    use chrono::Duration as ChronoDuration;

    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let user_id = UserId::new();
    storage
        .user_store()
        .create_user(bauth_core::storage::User {
            id: user_id,
            email: Some("sessions@example.com".into()),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");

    let other_user = UserId::new();
    storage
        .user_store()
        .create_user(bauth_core::storage::User {
            id: other_user,
            email: Some("other@example.com".into()),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("other user");

    let sessions = storage.session_store();
    let mk_session = |token: &str, user: UserId| Session {
        id: SessionId::new(),
        user_id: user,
        token_hash: hash_token(token),
        created_at: now,
        expires_at: now + ChronoDuration::hours(1),
        ip: Some("203.0.113.1".into()),
        user_agent: Some("agent".into()),
    };

    let s_keep = mk_session("keep", user_id);
    let s_other_a = mk_session("other-a", user_id);
    let s_other_b = mk_session("other-b", user_id);
    let s_neighbour = mk_session("neighbour", other_user);

    sessions
        .create_session(s_keep.clone())
        .await
        .expect("create keep");
    sessions
        .create_session(s_other_a.clone())
        .await
        .expect("create other a");
    sessions
        .create_session(s_other_b.clone())
        .await
        .expect("create other b");
    sessions
        .create_session(s_neighbour.clone())
        .await
        .expect("create neighbour");

    let listed = sessions.list_for_user(user_id).await.expect("list");
    let listed_ids: std::collections::HashSet<_> = listed.iter().map(|s| s.id).collect();
    assert_eq!(listed.len(), 3);
    assert!(listed_ids.contains(&s_keep.id));
    assert!(listed_ids.contains(&s_other_a.id));
    assert!(listed_ids.contains(&s_other_b.id));

    let removed = sessions
        .delete_other_sessions_for_user(user_id, s_keep.id)
        .await
        .expect("delete others");
    assert_eq!(removed, 2);

    let listed_after = sessions.list_for_user(user_id).await.expect("list after");
    assert_eq!(listed_after.len(), 1);
    assert_eq!(listed_after[0].id, s_keep.id);

    // The neighbouring user's session is untouched.
    assert!(
        sessions
            .find_session_by_id(s_neighbour.id)
            .await
            .expect("find neighbour")
            .is_some()
    );
}

#[tokio::test]
async fn storage_composite_returns_every_store() {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let composite = storage.storage();
    let user_id = UserId::new();
    composite
        .users
        .create_user(bauth_core::storage::User {
            id: user_id,
            email: Some("composite@example.com".into()),
            email_verified_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        })
        .await
        .expect("create user via composite");

    let again = composite
        .users
        .find_user_by_id(user_id)
        .await
        .expect("find")
        .expect("user");
    assert_eq!(again.id, user_id);
}
