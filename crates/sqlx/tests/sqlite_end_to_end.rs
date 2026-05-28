//! End-to-end smoke test for the SQLx + SQLite adapter.
//!
//! Wires the verification-token, user, and session stores through
//! `SqliteStorage` and exercises the surface the signup flow relies on
//! without driving the full WebAuthn ceremony against a real database.

#![cfg(feature = "sqlite")]

use bauth_core::storage::{UserId, VerificationPurpose};
use bauth_sqlx::SqliteStorage;
use chrono::{DateTime, TimeZone, Utc};

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
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
            purpose: VerificationPurpose::Signup,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create");

    let first = tokens
        .consume_token(&hash, VerificationPurpose::Signup)
        .await
        .expect("consume");
    assert!(first.is_some(), "first consume returns the token");

    let second = tokens
        .consume_token(&hash, VerificationPurpose::Signup)
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
        recovery_cooldown_until: None,
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
