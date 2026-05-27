//! End-to-end smoke test for the SQLx + SQLite adapter.
//!
//! Wires every storage trait through `SqliteStorage` and runs a
//! happy-path magic-link flow against it. Also exercises verification-token
//! purging and session-management queries.

#![cfg(feature = "sqlite")]

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::email::EmailSender;
use bauth_core::magic_link::{
    MagicLinkConfig, MagicLinkManager, MagicLinkRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::memory::{CapturingEmailSender, InMemoryRateLimiter};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{UserId, VerificationPurpose};
use bauth_sqlx::SqliteStorage;
use chrono::{DateTime, TimeZone, Utc};

const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn token_from_email(body: &str) -> String {
    let prefix = MAGIC_URL
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("token follows prefix")
        .to_string()
}

async fn setup() -> (SqliteStorage, MagicLinkManager, Arc<CapturingEmailSender>) {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
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
    let manager = MagicLinkManager::new(
        storage.user_store(),
        storage.verification_token_store(),
        session_manager,
        email.clone() as Arc<dyn EmailSender>,
        clock as Arc<dyn Clock>,
        audit,
        limiter,
        MagicLinkConfig {
            url_template: MAGIC_URL.to_string(),
            rate_limits: MagicLinkRateLimits::disabled(),
            ..MagicLinkConfig::default()
        },
    );

    (storage, manager, email)
}

#[tokio::test]
async fn full_magic_link_flow_against_sqlite() {
    let (storage, manager, email) = setup().await;

    manager
        .request_magic_link("alice@example.com", SessionContext::default())
        .await
        .expect("request");

    let users = storage.user_store();
    let persisted = users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find")
        .expect("user persisted");
    assert!(persisted.email_verified_at.is_none());

    let magic_body = email
        .sent()
        .into_iter()
        .find(|e| e.subject == "Your sign-in link")
        .expect("magic-link email queued")
        .body_text;
    let token = token_from_email(&magic_body);
    let outcome = manager
        .consume_magic_link(&token, SessionContext::default())
        .await
        .expect("consume");
    assert!(outcome.is_new_user, "first consume verifies signup user");
    assert!(outcome.user.email_verified_at.is_some());
    assert_eq!(outcome.user.id, persisted.id);
    assert_eq!(outcome.session.session.user_id, persisted.id);

    manager
        .request_magic_link("alice@example.com", SessionContext::default())
        .await
        .expect("second request");
    let second_body = email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Your sign-in link")
        .expect("second magic-link email queued")
        .body_text;
    let second_token = token_from_email(&second_body);
    let second = manager
        .consume_magic_link(&second_token, SessionContext::default())
        .await
        .expect("second consume");
    assert!(!second.is_new_user, "existing verified user stays existing");

    let tokens = storage.verification_token_store();
    let purged = tokens.purge_expired(ts(2099, 1, 1)).await.expect("purge");
    assert_eq!(purged, 0, "no outstanding tokens after consume");
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
            created_at: ts(2026, 1, 1),
            updated_at: ts(2026, 1, 1),
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
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
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

    let now = ts(2026, 1, 1);
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
            created_at: ts(2026, 1, 1),
            updated_at: ts(2026, 1, 1),
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
