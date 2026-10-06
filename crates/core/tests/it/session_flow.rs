use std::num::NonZeroU32;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::AuditEventKind;
use doorman_core::clock::Clock;
use doorman_core::error::Error;
use doorman_core::session::{SessionConfig, SessionContext, hash_token};
use doorman_core::storage::{
    Session, SessionId, SessionStore, StoredPasskey, UserId, UserStatus, UserStore,
};

use crate::common::{Harness, make_user, ts};

fn harness_with_lifetime(absolute_lifetime: Duration) -> Harness {
    Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime,
            ..SessionConfig::default()
        })
        .build()
}

async fn new_user(h: &Harness) -> UserId {
    make_user(h, &format!("{}@example.com", UserId::new()))
        .await
        .id
}

#[tokio::test]
async fn create_is_refused_for_a_user_who_cannot_log_in() {
    let h = Harness::fresh();
    let disabled = new_user(&h).await;
    let now = h.clock.now();
    h.users
        .set_user_status(disabled, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable");

    let err = h
        .session_manager
        .create(disabled, SessionContext::default())
        .await
        .err();
    assert!(matches!(err, Some(Error::UserDisabled)), "got {err:?}");
    let err = h
        .session_manager
        .create(UserId::new(), SessionContext::default())
        .await
        .err();
    assert!(matches!(err, Some(Error::UserNotFound)), "got {err:?}");
    assert!(h.sessions.is_empty(), "a refused session leaves no row");
    assert!(
        !h.audit
            .events()
            .iter()
            .any(|e| matches!(e.kind, AuditEventKind::SessionCreated { .. })),
        "a refused session is not audited as created",
    );
}

#[test]
fn session_recovery_cool_down_ignores_expired_deadlines() {
    let now = ts(2026, 1, 1);
    let active_until = now + ChronoDuration::minutes(10);
    let session = Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token("cool-down"),
        created_at: now,
        last_used_at: now,
        expires_at: now + ChronoDuration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: Some(active_until),
    };

    assert!(session.is_in_recovery_cool_down(now));

    let expired = Session {
        recovery_cool_down_until: Some(now - ChronoDuration::seconds(1)),
        ..session.clone()
    };
    assert!(!expired.is_in_recovery_cool_down(now));

    let outside_cool_down = Session {
        recovery_cool_down_until: None,
        ..session
    };
    assert!(!outside_cool_down.is_in_recovery_cool_down(now));
}

#[test]
fn stored_passkey_cool_down_predicate_mirrors_session() {
    let now = ts(2026, 1, 1);
    let active_until = now + ChronoDuration::hours(24);
    let passkey = StoredPasskey {
        credential_id: vec![1, 2, 3],
        user_id: UserId::new(),
        passkey: b"opaque-blob".to_vec(),
        name: None,
        created_at: now,
        last_used_at: None,
        aaguid: None,
        transports: Vec::new(),
        backup_eligible: false,
        backup_state: false,
        recovery_cool_down_until: Some(active_until),
    };

    assert!(passkey.is_in_recovery_cool_down(now));
    assert!(!passkey.is_in_recovery_cool_down(active_until));

    let outside_cool_down = StoredPasskey {
        recovery_cool_down_until: None,
        ..passkey
    };
    assert!(!outside_cool_down.is_in_recovery_cool_down(now));
}

#[tokio::test]
async fn create_then_validate_returns_same_session() {
    let h = Harness::fresh();
    let (manager, sessions, audit) = (&h.session_manager, &h.sessions, &h.audit);
    let user_id = new_user(&h).await;

    let issued = manager
        .create(
            user_id,
            SessionContext {
                ip: Some("1.2.3.4".into()),
                user_agent: Some("test-agent".into()),
            },
        )
        .await
        .expect("create");

    assert_eq!(sessions.len(), 1);
    assert_eq!(issued.session.user_id, user_id);
    assert_eq!(issued.session.ip.as_deref(), Some("1.2.3.4"));
    assert_eq!(hash_token(&issued.token), issued.session.token_hash);

    let validated = manager.validate(&issued.token).await.expect("validate");
    assert_eq!(validated.id, issued.session.id);
    assert_eq!(validated.user_id, user_id);

    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].kind,
        AuditEventKind::SessionCreated { user_id: u, session_id: s }
            if u == user_id && s == issued.session.id
    ));
}

#[tokio::test]
async fn revoke_deletes_session_and_emits_audit() {
    let h = Harness::fresh();
    let (manager, sessions, audit) = (&h.session_manager, &h.sessions, &h.audit);
    let user_id = new_user(&h).await;

    let issued = manager
        .create(user_id, SessionContext::default())
        .await
        .expect("create");

    manager.revoke(&issued.token).await.expect("revoke");
    assert_eq!(sessions.len(), 0);

    let err = manager
        .validate(&issued.token)
        .await
        .expect_err("validating revoked token should fail");
    assert!(matches!(err, Error::SessionNotFound));

    let kinds: Vec<_> = audit.events().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds.len(), 2);
    assert!(matches!(kinds[0], AuditEventKind::SessionCreated { .. }));
    assert!(matches!(kinds[1], AuditEventKind::SessionRevoked { .. }));
}

#[tokio::test]
async fn session_cap_evicts_oldest_active_session_for_that_user() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime: Duration::from_secs(60 * 60),
            idle_timeout: None,
            max_sessions_per_user: NonZeroU32::new(2),
            ..SessionConfig::default()
        })
        .build();
    let (manager, sessions, audit, clock) = (&h.session_manager, &h.sessions, &h.audit, &h.clock);

    let alice = new_user(&h).await;
    let bob = new_user(&h).await;

    let first = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 1");
    clock.advance(ChronoDuration::seconds(1));
    let bob_session = manager
        .create(bob, SessionContext::default())
        .await
        .expect("bob");
    clock.advance(ChronoDuration::seconds(1));
    let second = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 2");
    clock.advance(ChronoDuration::seconds(1));
    let third = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 3 evicts oldest");

    let mut alice_ids: Vec<SessionId> = manager
        .list_for_user(alice)
        .await
        .expect("list alice")
        .into_iter()
        .map(|s| s.id)
        .collect();
    alice_ids.sort_by_key(|id| id.0);
    let mut expected = vec![second.session.id, third.session.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(alice_ids, expected, "cap keeps the two newest sessions");

    let err = manager
        .validate(&first.token)
        .await
        .expect_err("evicted session is gone");
    assert!(matches!(err, Error::SessionNotFound));

    assert!(
        audit.events().iter().any(
            |e| matches!(e.kind, AuditEventKind::SessionRevoked { session_id, .. }
                if session_id == first.session.id)
        ),
        "evicting a capped-out session emits SessionRevoked",
    );

    assert!(
        sessions
            .find_session_by_id(bob_session.session.id)
            .await
            .expect("find bob")
            .is_some()
    );
}

#[tokio::test]
async fn revoke_unknown_token_errors() {
    let h = Harness::fresh();
    let manager = &h.session_manager;
    let err = manager
        .revoke("not-a-real-token")
        .await
        .expect_err("revoke should fail");
    assert!(matches!(err, Error::SessionNotFound));
}

#[tokio::test]
async fn validate_unknown_token_errors() {
    let h = Harness::fresh();
    let manager = &h.session_manager;
    let err = manager
        .validate("not-a-real-token")
        .await
        .expect_err("validate should fail");
    assert!(matches!(err, Error::SessionNotFound));
}

#[tokio::test]
async fn expired_session_fails_validation_and_logs() {
    let h = harness_with_lifetime(Duration::from_secs(60));
    let (manager, audit, clock) = (&h.session_manager, &h.audit, &h.clock);

    let issued = manager
        .create(new_user(&h).await, SessionContext::default())
        .await
        .expect("create");

    clock.advance(ChronoDuration::seconds(120));

    let err = manager
        .validate(&issued.token)
        .await
        .expect_err("expired session should not validate");
    assert!(matches!(err, Error::SessionExpired));

    let last_kind = audit
        .events()
        .into_iter()
        .last()
        .expect("at least one event")
        .kind;
    assert!(matches!(last_kind, AuditEventKind::SessionExpired { .. }));
}

#[tokio::test]
async fn revoke_by_id_removes_session() {
    let h = Harness::fresh();
    let (manager, sessions) = (&h.session_manager, &h.sessions);
    let issued = manager
        .create(new_user(&h).await, SessionContext::default())
        .await
        .expect("create");

    manager
        .revoke_by_id(issued.session.id)
        .await
        .expect("revoke_by_id");
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn revoke_all_for_user_clears_only_that_user() {
    let h = Harness::fresh();
    let (manager, sessions) = (&h.session_manager, &h.sessions);
    let alice = new_user(&h).await;
    let bob = new_user(&h).await;

    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 1");
    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 2");
    let bob_session = manager
        .create(bob, SessionContext::default())
        .await
        .expect("bob");

    let removed = manager
        .revoke_all_for_user(alice)
        .await
        .expect("revoke_all");
    assert_eq!(removed, 2);
    assert_eq!(sessions.len(), 1);
    assert!(
        sessions
            .find_session_by_id(bob_session.session.id)
            .await
            .expect("find bob")
            .is_some()
    );
}

#[tokio::test]
async fn list_for_user_returns_only_active_sessions_for_that_user() {
    let h = harness_with_lifetime(Duration::from_secs(60));
    let (manager, clock) = (&h.session_manager, &h.clock);

    let alice = new_user(&h).await;
    let bob = new_user(&h).await;

    let alice_first = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 1");
    let alice_second = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 2");
    manager
        .create(bob, SessionContext::default())
        .await
        .expect("bob");

    let listed = manager.list_for_user(alice).await.expect("list");
    let mut ids: Vec<SessionId> = listed.iter().map(|s| s.id).collect();
    ids.sort_by_key(|id| id.0);
    let mut expected = vec![alice_first.session.id, alice_second.session.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(ids, expected, "list returns only Alice's sessions");

    clock.advance(ChronoDuration::seconds(120));
    let fresh = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 3 (fresh)");

    let listed_after = manager.list_for_user(alice).await.expect("list after");
    let ids_after: Vec<SessionId> = listed_after.iter().map(|s| s.id).collect();
    assert_eq!(
        ids_after,
        vec![fresh.session.id],
        "expired sessions are not listed even while storage retains them"
    );
}

#[tokio::test]
async fn purge_expired_deletes_only_expired() {
    let h = harness_with_lifetime(Duration::from_secs(60));
    let (manager, sessions, clock) = (&h.session_manager, &h.sessions, &h.clock);

    let short = manager
        .create(new_user(&h).await, SessionContext::default())
        .await
        .expect("short");

    clock.advance(ChronoDuration::seconds(30));
    let long = manager
        .create(new_user(&h).await, SessionContext::default())
        .await
        .expect("long");

    clock.advance(ChronoDuration::seconds(45));
    let summary = h
        .storage
        .purge_all_expired(clock.now())
        .await
        .expect("purge");
    assert_eq!(summary.sessions, 1);
    assert!(
        sessions
            .find_session_by_id(short.session.id)
            .await
            .expect("find short")
            .is_none()
    );
    assert!(
        sessions
            .find_session_by_id(long.session.id)
            .await
            .expect("find long")
            .is_some()
    );
}
