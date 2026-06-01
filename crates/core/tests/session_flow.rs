use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bauth_core::audit::{AuditEventKind, AuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::{DefaultBauthEmails, Email, EmailSender, SecurityEmailNotifier};
use bauth_core::error::Error;
use bauth_core::memory::{InMemorySessionStore, InMemoryUserStore};
use bauth_core::session::{
    SessionConfig, SessionContext, SessionInvalidationHook, SessionManager, hash_token,
};
use bauth_core::storage::{Session, SessionId, SessionStore, User, UserId, UserStore};
use bauth_test_support::{CapturingEmailSender, InMemoryAuditSink, MockClock};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use std::sync::Mutex;

fn fresh_manager() -> (
    SessionManager,
    Arc<InMemorySessionStore>,
    Arc<InMemoryAuditSink>,
) {
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    (manager, sessions, audit)
}

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

/// A bare [`User`] with the given id. `SessionManager` does not own a user
/// store, so the revoke APIs take the caller's already-loaded user; tests
/// fabricate one carrying just the fields the notices read.
fn user_with_id(id: UserId, email: Option<&str>) -> User {
    User {
        id,
        email: email.map(str::to_owned),
        email_verified_at: None,
        created_at: ts(2026, 1, 1),
        updated_at: ts(2026, 1, 1),
    }
}

#[test]
fn session_active_recovery_cooldown_until_filters_expired_deadlines() {
    let now = ts(2026, 1, 1);
    let active_until = now + ChronoDuration::minutes(10);
    let session = Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token("cooldown"),
        created_at: now,
        expires_at: now + ChronoDuration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: Some(active_until),
    };

    assert_eq!(
        session.active_recovery_cooldown_until(now),
        Some(active_until)
    );
    assert!(session.is_in_recovery_cooldown(now));

    let expired = Session {
        recovery_cooldown_until: Some(now - ChronoDuration::seconds(1)),
        ..session.clone()
    };
    assert_eq!(expired.active_recovery_cooldown_until(now), None);
    assert!(!expired.is_in_recovery_cooldown(now));

    let unrestricted = Session {
        recovery_cooldown_until: None,
        ..session
    };
    assert_eq!(unrestricted.active_recovery_cooldown_until(now), None);
    assert!(!unrestricted.is_in_recovery_cooldown(now));
}

#[tokio::test]
async fn create_then_validate_returns_same_session() {
    let (manager, sessions, audit) = fresh_manager();
    let user_id = UserId::new();

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
    let (manager, sessions, audit) = fresh_manager();
    let user_id = UserId::new();

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
async fn revoke_unknown_token_errors() {
    let (manager, _, _) = fresh_manager();
    let err = manager
        .revoke("not-a-real-token")
        .await
        .expect_err("revoke should fail");
    assert!(matches!(err, Error::SessionNotFound));
}

#[tokio::test]
async fn validate_unknown_token_errors() {
    let (manager, _, _) = fresh_manager();
    let err = manager
        .validate("not-a-real-token")
        .await
        .expect_err("validate should fail");
    assert!(matches!(err, Error::SessionNotFound));
}

#[tokio::test]
async fn expired_session_fails_validation_and_logs() {
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let clock = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60),
        },
    );

    let issued = manager
        .create(UserId::new(), SessionContext::default())
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
    let (manager, sessions, _) = fresh_manager();
    let issued = manager
        .create(UserId::new(), SessionContext::default())
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
    let (manager, sessions, _) = fresh_manager();
    let alice = UserId::new();
    let bob = UserId::new();

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
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let clock = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60),
        },
    );

    let alice = UserId::new();
    let bob = UserId::new();

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

    // Step past Alice's first session's expiry while keeping Bob's and
    // Alice's second session alive (re-issue Alice's second now to verify
    // the manager filters expired entries even though the storage adapter
    // still holds the row).
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
        "manager filters out expired sessions even when storage retains them"
    );
}

#[tokio::test]
async fn revoke_others_for_user_keeps_only_the_exception() {
    let (manager, sessions, _) = fresh_manager();
    let alice = UserId::new();
    let bob = UserId::new();

    let keep = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice keep");
    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice other 1");
    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice other 2");
    let bob_session = manager
        .create(bob, SessionContext::default())
        .await
        .expect("bob");

    let removed = manager
        .revoke_others_for_user(&user_with_id(alice, None), keep.session.id)
        .await
        .expect("revoke_others");
    assert_eq!(removed, 2);

    let remaining_alice: Vec<SessionId> = sessions
        .list_for_user(alice)
        .await
        .expect("list alice")
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(remaining_alice, vec![keep.session.id]);

    // Bob's session is untouched.
    assert!(
        sessions
            .find_session_by_id(bob_session.session.id)
            .await
            .expect("find bob")
            .is_some()
    );
}

#[tokio::test]
async fn revoke_others_for_user_notifies_user_hook_when_anything_removed() {
    let (manager, _, _) = fresh_manager();
    let hook: Arc<RecordingHook> = Arc::new(RecordingHook::default());
    let manager = manager.with_invalidation_hook(hook.clone() as Arc<dyn SessionInvalidationHook>);

    let alice = UserId::new();
    let keep = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice keep");
    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice other");

    let removed = manager
        .revoke_others_for_user(&user_with_id(alice, None), keep.session.id)
        .await
        .expect("revoke_others");
    assert_eq!(removed, 1);
    assert_eq!(*hook.users.lock().expect("read"), vec![alice]);
}

#[tokio::test]
async fn revoke_others_for_user_sends_notice_in_core() {
    // A non-axum host driving the manager directly must still get the
    // security notice — it originates in core, not in the HTTP layer.
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
    let notifier = SecurityEmailNotifier::new(
        email.clone() as Arc<dyn EmailSender>,
        Arc::new(DefaultBauthEmails),
    );
    let manager = SessionManager::new(
        sessions as Arc<dyn SessionStore>,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        audit as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    )
    .with_security_notifier(notifier);

    let alice = user_with_id(UserId::new(), Some("alice@example.com"));
    let keep = manager
        .create(alice.id, SessionContext::default())
        .await
        .expect("alice keep");
    manager
        .create(alice.id, SessionContext::default())
        .await
        .expect("alice other");

    manager
        .revoke_others_for_user(&alice, keep.session.id)
        .await
        .expect("revoke_others");

    let sent = email.sent();
    assert_eq!(sent.len(), 1, "one bulk-revocation notice queued in core");
    assert_eq!(sent[0].subject, "Security notice: other sessions revoked");
    assert_eq!(sent[0].to, "alice@example.com");
}

#[tokio::test]
async fn revoke_owned_session_notifies_only_for_other_sessions() {
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
    let notifier = SecurityEmailNotifier::new(
        email.clone() as Arc<dyn EmailSender>,
        Arc::new(DefaultBauthEmails),
    );
    let manager = SessionManager::new(
        sessions as Arc<dyn SessionStore>,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        audit as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    )
    .with_security_notifier(notifier);

    let alice = user_with_id(UserId::new(), Some("alice@example.com"));
    let current = manager
        .create(alice.id, SessionContext::default())
        .await
        .expect("current");
    let other = manager
        .create(alice.id, SessionContext::default())
        .await
        .expect("other");

    // Revoking the *other* session notifies.
    manager
        .revoke_owned_session(&alice, other.session.id, current.session.id)
        .await
        .expect("revoke other");
    assert_eq!(email.sent().len(), 1, "revoking another session notifies");

    // Revoking the caller's *own* current session stays silent.
    manager
        .revoke_owned_session(&alice, current.session.id, current.session.id)
        .await
        .expect("revoke self");
    assert_eq!(email.sent().len(), 1, "self-revocation sends no notice");

    // A session the caller does not own reads as not found.
    let bob = user_with_id(UserId::new(), Some("bob@example.com"));
    let bob_session = manager
        .create(bob.id, SessionContext::default())
        .await
        .expect("bob");
    let err = manager
        .revoke_owned_session(&alice, bob_session.session.id, current.session.id)
        .await
        .expect_err("alice cannot revoke bob's session");
    assert!(matches!(err, Error::SessionNotFound));
}

#[tokio::test]
async fn revoke_others_for_user_skips_hook_when_nothing_removed() {
    let (manager, _, _) = fresh_manager();
    let hook: Arc<RecordingHook> = Arc::new(RecordingHook::default());
    let manager = manager.with_invalidation_hook(hook.clone() as Arc<dyn SessionInvalidationHook>);

    let alice = UserId::new();
    let only = manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice only");

    let removed = manager
        .revoke_others_for_user(&user_with_id(alice, None), only.session.id)
        .await
        .expect("revoke_others");
    assert_eq!(removed, 0);
    assert!(
        hook.users.lock().expect("read").is_empty(),
        "no-op revoke must not spam the cache invalidator"
    );
}

#[tokio::test]
async fn purge_expired_deletes_only_expired() {
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let clock = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60),
        },
    );

    let short = manager
        .create(UserId::new(), SessionContext::default())
        .await
        .expect("short");

    clock.advance(ChronoDuration::seconds(30));
    let long = manager
        .create(UserId::new(), SessionContext::default())
        .await
        .expect("long");

    clock.advance(ChronoDuration::seconds(45));
    let removed = manager.purge_expired().await.expect("purge");
    assert_eq!(removed, 1);
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

#[tokio::test]
async fn user_store_round_trip() {
    let store = InMemoryUserStore::new();
    let user = User {
        id: UserId::new(),
        email: Some("alice@example.com".into()),
        email_verified_at: None,
        created_at: ts(2026, 1, 1),
        updated_at: ts(2026, 1, 1),
    };

    store.create_user(user.clone()).await.expect("create");
    assert_eq!(
        store.find_user_by_id(user.id).await.expect("find by id"),
        Some(user.clone())
    );
    assert_eq!(
        store
            .find_user_by_email("alice@example.com")
            .await
            .expect("find by email"),
        Some(user.clone())
    );

    store
        .create_user(user.clone())
        .await
        .expect_err("duplicate id should error");

    let other = User {
        id: UserId::new(),
        email: Some("alice@example.com".into()),
        email_verified_at: None,
        created_at: user.created_at,
        updated_at: user.updated_at,
    };
    store
        .create_user(other)
        .await
        .expect_err("duplicate email should error");

    store.delete_user(user.id).await.expect("delete");
    assert!(
        store
            .find_user_by_id(user.id)
            .await
            .expect("find after delete")
            .is_none()
    );
    assert!(
        store
            .find_user_by_email("alice@example.com")
            .await
            .expect("find email after delete")
            .is_none()
    );
}

#[tokio::test]
async fn email_sender_captures_messages() {
    let sender = CapturingEmailSender::new();
    let email = Email {
        to: "user@example.com".into(),
        subject: "Verify".into(),
        body_text: "click here".into(),
        body_html: None,
    };
    sender.send(email.clone()).await.expect("send");
    assert_eq!(sender.sent(), vec![email]);
}

#[derive(Debug, Default)]
struct RecordingHook {
    sessions: Mutex<Vec<SessionId>>,
    users: Mutex<Vec<UserId>>,
}

#[async_trait]
impl SessionInvalidationHook for RecordingHook {
    async fn on_session_invalidated(&self, session_id: SessionId) {
        self.sessions
            .lock()
            .expect("hook session lock")
            .push(session_id);
    }

    async fn on_user_sessions_invalidated(&self, user_id: UserId) {
        self.users.lock().expect("hook user lock").push(user_id);
    }
}

#[tokio::test]
async fn revoke_notifies_invalidation_hook_with_session_id() {
    let (manager, _, _) = fresh_manager();
    let hook: Arc<RecordingHook> = Arc::new(RecordingHook::default());
    let manager = manager.with_invalidation_hook(hook.clone() as Arc<dyn SessionInvalidationHook>);

    let issued = manager
        .create(UserId::new(), SessionContext::default())
        .await
        .expect("create");
    manager.revoke(&issued.token).await.expect("revoke");

    assert_eq!(
        *hook.sessions.lock().expect("read"),
        vec![issued.session.id],
        "revoke fires per-session hook"
    );
    assert!(
        hook.users.lock().expect("read").is_empty(),
        "no user-level hook on single revoke"
    );
}

#[tokio::test]
async fn revoke_by_id_notifies_invalidation_hook() {
    let (manager, _, _) = fresh_manager();
    let hook: Arc<RecordingHook> = Arc::new(RecordingHook::default());
    let manager = manager.with_invalidation_hook(hook.clone() as Arc<dyn SessionInvalidationHook>);

    let issued = manager
        .create(UserId::new(), SessionContext::default())
        .await
        .expect("create");
    manager
        .revoke_by_id(issued.session.id)
        .await
        .expect("revoke_by_id");

    assert_eq!(
        *hook.sessions.lock().expect("read"),
        vec![issued.session.id]
    );
}

#[tokio::test]
async fn revoke_all_for_user_notifies_user_hook() {
    let (manager, _, _) = fresh_manager();
    let hook: Arc<RecordingHook> = Arc::new(RecordingHook::default());
    let manager = manager.with_invalidation_hook(hook.clone() as Arc<dyn SessionInvalidationHook>);

    let alice = UserId::new();
    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 1");
    manager
        .create(alice, SessionContext::default())
        .await
        .expect("alice 2");

    let removed = manager
        .revoke_all_for_user(alice)
        .await
        .expect("revoke_all");
    assert_eq!(removed, 2);

    assert_eq!(
        *hook.users.lock().expect("read"),
        vec![alice],
        "delete_sessions_for_user fires user-level hook"
    );
    assert!(
        hook.sessions.lock().expect("read").is_empty(),
        "bulk revoke does not iterate per session"
    );
}

#[tokio::test]
async fn invalidation_hook_install_order_does_not_matter() {
    // The hook lives in a cell shared by every clone, so installing it is
    // visible to clones taken *before* the install as well as after. A
    // framework cache wired in after the dependent managers were cloned must
    // still be evicted on revoke — install order cannot break invalidation.
    let (manager, _, _) = fresh_manager();
    let early_clone = manager.clone();

    let hook: Arc<RecordingHook> = Arc::new(RecordingHook::default());
    // Install on the original *after* the clone was taken.
    manager.set_invalidation_hook(hook.clone() as Arc<dyn SessionInvalidationHook>);

    // Revoking through the clone taken before the install still fires the hook.
    let issued = early_clone
        .create(UserId::new(), SessionContext::default())
        .await
        .expect("create");
    early_clone
        .revoke(&issued.token)
        .await
        .expect("revoke via early clone");
    assert_eq!(
        *hook.sessions.lock().expect("read"),
        vec![issued.session.id],
        "clone taken before the hook was installed still observes invalidation"
    );

    // And a clone taken after the install shares the same hook.
    let late_clone = manager.clone();
    let issued = late_clone
        .create(UserId::new(), SessionContext::default())
        .await
        .expect("create");
    late_clone
        .revoke(&issued.token)
        .await
        .expect("revoke via late clone");
    assert_eq!(
        hook.sessions.lock().expect("read").len(),
        2,
        "clones taken after the install share the hook too"
    );
}

#[tokio::test]
async fn session_store_rejects_id_and_hash_collisions() {
    let store = InMemorySessionStore::new();
    let session = Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token("abc"),
        created_at: Utc::now(),
        expires_at: Utc::now() + ChronoDuration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    store.create_session(session.clone()).await.expect("first");

    let dup_id = Session {
        token_hash: hash_token("different"),
        ..session.clone()
    };
    store
        .create_session(dup_id)
        .await
        .expect_err("duplicate id should error");

    let dup_hash = Session {
        id: SessionId::new(),
        ..session
    };
    store
        .create_session(dup_hash)
        .await
        .expect_err("duplicate hash should error");
}
