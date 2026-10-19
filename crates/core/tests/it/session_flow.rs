use std::num::NonZeroU32;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::AuditEventKind;
use doorman_core::clock::Clock;
use doorman_core::destructive::{CurrentSession, DestructiveAction};
use doorman_core::error::Error;
use doorman_core::session::{
    IssuedSession, ResolvedSession, SessionConfig, SessionContext, hash_token,
};
use doorman_core::storage::{SessionId, SessionStore, User};

use crate::common::{
    Harness, RECOVERY_URL, SignedIn, authenticator, kinds, log_in, session_count,
    session_in_cool_down_for, sign_in, sign_in_from, token_from_email,
};

fn harness_with_lifetime(absolute_lifetime: Duration) -> Harness {
    Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime,
            ..SessionConfig::default()
        })
        .build()
}

async fn session_exists(h: &Harness, id: SessionId) -> bool {
    h.sessions
        .find_session_by_id(id)
        .await
        .expect("find session")
        .is_some()
}

async fn in_cool_down(h: &Harness, user: &User) -> ResolvedSession {
    session_in_cool_down_for(h, user, h.clock.now() + ChronoDuration::minutes(10)).await
}

#[derive(Debug, Clone, Copy)]
enum BulkRevocation {
    RevokeOthers,
    LogOutEverywhere,
}

impl BulkRevocation {
    const ALL: [Self; 2] = [Self::RevokeOthers, Self::LogOutEverywhere];

    async fn run(self, h: &Harness, session: &ResolvedSession) -> Result<CurrentSession, Error> {
        let action = match self {
            Self::RevokeOthers => DestructiveAction::RevokeOtherSessions,
            Self::LogOutEverywhere => DestructiveAction::LogOutEverywhere,
        };
        h.session_manager
            .perform(session, action, None, SessionContext::default())
            .await
    }
}

#[tokio::test]
async fn a_login_issues_a_session_bound_to_its_token() {
    let h = Harness::fresh();
    let context = SessionContext {
        ip: Some("1.2.3.4".into()),
        user_agent: Some("test-agent".into()),
    };
    let alice = sign_in_from(&h, "alice@example.com", context).await;
    let issued = &alice.session;

    assert_eq!(h.sessions.len(), 1);
    assert_eq!(issued.session.user_id, alice.user.id);
    assert_eq!(issued.session.ip.as_deref(), Some("1.2.3.4"));
    let stored = h
        .sessions
        .find_session_by_id(issued.session.id)
        .await
        .expect("find session")
        .expect("session stored");
    assert_eq!(hash_token(&issued.token), stored.token_hash);

    let resolved = h
        .session_manager
        .resolve(&issued.token)
        .await
        .expect("resolve")
        .expect("a live session");
    assert_eq!(resolved.id, issued.session.id);
    assert!(
        kinds(&h.audit.events()).contains(&AuditEventKind::SessionCreated {
            user_id: alice.user.id,
            session_id: issued.session.id,
        }),
        "the new session is audited",
    );
}

#[tokio::test]
async fn log_out_deletes_the_session_and_audits_it() {
    let h = Harness::fresh();
    let alice = sign_in(&h, "alice@example.com").await;
    let session = &alice.session.session;

    h.session_manager.log_out(session).await.expect("log out");
    assert!(h.sessions.is_empty());

    let resolved = h
        .session_manager
        .resolve(&alice.session.token)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
    assert_eq!(
        kinds(&h.audit.events()).last(),
        Some(&AuditEventKind::SessionRevoked {
            user_id: alice.user.id,
            session_id: session.id,
        }),
    );

    let err = h.session_manager.log_out(session).await.err();
    assert!(
        matches!(err, Some(Error::SessionNotFound)),
        "a session logs out once, got {err:?}"
    );
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

    let mut alice = sign_in(&h, "alice@example.com").await;
    let first = alice.session.clone();
    h.clock.advance(ChronoDuration::seconds(1));
    let bob = sign_in(&h, "bob@example.com").await;
    h.clock.advance(ChronoDuration::seconds(1));
    let second = alice.log_in_again(&h).await;
    h.clock.advance(ChronoDuration::seconds(1));
    let third = alice.log_in_again(&h).await;

    let mut alice_ids: Vec<SessionId> = h
        .session_manager
        .list_sessions(&third.session)
        .await
        .expect("list alice")
        .into_iter()
        .map(|s| s.id)
        .collect();
    alice_ids.sort_by_key(|id| id.0);
    let mut expected = vec![second.session.id, third.session.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(alice_ids, expected, "cap keeps the two newest sessions");

    let resolved = h
        .session_manager
        .resolve(&first.token)
        .await
        .expect("resolve");
    assert!(
        resolved.is_none(),
        "evicted session is gone, got {resolved:?}"
    );

    assert!(
        h.audit.events().iter().any(
            |e| matches!(e.kind, AuditEventKind::SessionRevoked { session_id, .. }
                if session_id == first.session.id)
        ),
        "evicting a capped-out session emits SessionRevoked",
    );

    assert!(session_exists(&h, bob.session.session.id).await);
}

#[tokio::test]
async fn session_cap_in_recovery_cool_down_evicts_only_sessions_in_it() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime: Duration::from_secs(60 * 60),
            max_sessions_per_user: NonZeroU32::new(2),
            ..SessionConfig::default()
        })
        .build();
    let mut alice = sign_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(1));
    let second = alice.log_in_again(&h).await;
    h.clock.advance(ChronoDuration::seconds(1));

    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("request recovery");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("link queued");
    let started = h
        .recovery
        .redeem_recovery_link(
            &token_from_email(&link.body_text, RECOVERY_URL),
            SessionContext::default(),
        )
        .await
        .expect("redeem");
    let mut recovered = authenticator();
    let attestation = recovered.do_registration(started.options);
    let recovery = h
        .recovery
        .finish_recovery(
            started.challenge_id,
            &attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect("finish recovery");
    h.clock.advance(ChronoDuration::seconds(1));
    let login = log_in(
        &h,
        &mut recovered,
        &recovery.passkey.credential_id,
        SessionContext::default(),
    )
    .await;
    assert!(login.session.is_in_recovery_cool_down());

    for (session, kept, case) in [
        (alice.session.session.id, true, "oldest outside cool-down"),
        (second.session.id, true, "newer outside cool-down"),
        (recovery.session.session.id, false, "recovery's own"),
        (login.session.id, true, "newest in cool-down"),
    ] {
        assert_eq!(session_exists(&h, session).await, kept, "{case}");
    }

    h.clock.advance(ChronoDuration::seconds(1));
    alice.log_in_again(&h).await;
    assert_eq!(
        session_count(&h, alice.user.id).await,
        2,
        "a session outside cool-down evicts down to the cap",
    );
}

#[tokio::test]
async fn list_returns_only_the_users_live_sessions() {
    let h = harness_with_lifetime(Duration::from_secs(60));

    let mut alice = sign_in(&h, "alice@example.com").await;
    let alice_second = alice.log_in_again(&h).await;
    sign_in(&h, "bob@example.com").await;

    let listed = h
        .session_manager
        .list_sessions(&alice.session.session)
        .await
        .expect("list");
    let mut ids: Vec<SessionId> = listed.iter().map(|s| s.id).collect();
    ids.sort_by_key(|id| id.0);
    let mut expected = vec![alice.session.session.id, alice_second.session.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(ids, expected, "list returns only Alice's sessions");

    h.clock.advance(ChronoDuration::seconds(120));
    let fresh = alice.log_in_again(&h).await;

    let listed_after = h
        .session_manager
        .list_sessions(&fresh.session)
        .await
        .expect("list after");
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

    let short = sign_in(&h, "short@example.com").await.session;
    h.clock.advance(ChronoDuration::seconds(30));
    let long = sign_in(&h, "long@example.com").await.session;

    h.clock.advance(ChronoDuration::seconds(45));
    let summary = h.storage.expiring.purge_all_expired(h.clock.now()).await;
    assert_eq!(summary.sessions.expect("purge sessions"), 1);
    assert!(!session_exists(&h, short.session.id).await);
    assert!(session_exists(&h, long.session.id).await);
}

#[tokio::test]
async fn revoke_others_keeps_only_the_acting_session_audits_and_notifies() {
    let h = Harness::fresh();
    let mut alice = sign_in(&h, "alice@example.com").await;
    let other_1 = alice.log_in_again(&h).await;
    let other_2 = alice.log_in_again(&h).await;
    let bob = sign_in(&h, "bob@example.com").await;
    let current = &alice.session.session;
    let mail_before = h.email.sent().len();

    h.session_manager
        .perform(
            current,
            DestructiveAction::RevokeOtherSessions,
            None,
            SessionContext::default(),
        )
        .await
        .expect("revoke other sessions");

    assert!(
        session_exists(&h, current.id).await,
        "the acting session stays"
    );
    assert!(!session_exists(&h, other_1.session.id).await);
    assert!(!session_exists(&h, other_2.session.id).await);
    assert!(
        session_exists(&h, bob.session.session.id).await,
        "another user is untouched"
    );
    assert_eq!(
        kinds(&h.audit.events()).last(),
        Some(&AuditEventKind::OtherSessionsRevoked {
            user_id: alice.user.id,
            revoked_count: 2,
        }),
    );
    let sent = &h.email.sent()[mail_before..];
    assert_eq!(sent.len(), 1, "one bulk-revocation notice");
    assert_eq!(sent[0].subject, "Security notice: other sessions revoked");
    assert_eq!(sent[0].to, "alice@example.com");
}

#[tokio::test]
async fn log_out_everywhere_ends_every_session_of_the_user_only() {
    let h = Harness::fresh();
    let mut alice = sign_in(&h, "alice@example.com").await;
    let other = alice.log_in_again(&h).await;
    let bob = sign_in(&h, "bob@example.com").await;
    let current = &alice.session.session;
    let mail_before = h.email.sent().len();
    let audited_before = h.audit.len();

    h.session_manager
        .perform(
            current,
            DestructiveAction::LogOutEverywhere,
            None,
            SessionContext::default(),
        )
        .await
        .expect("log out everywhere");

    assert!(!session_exists(&h, current.id).await);
    assert!(!session_exists(&h, other.session.id).await);
    assert!(
        session_exists(&h, bob.session.session.id).await,
        "another user is untouched"
    );
    assert_eq!(
        kinds(&h.audit.events()[audited_before..]),
        vec![
            AuditEventKind::OtherSessionsRevoked {
                user_id: alice.user.id,
                revoked_count: 1,
            },
            AuditEventKind::SessionRevoked {
                user_id: alice.user.id,
                session_id: current.id,
            },
        ],
    );
    let sent = &h.email.sent()[mail_before..];
    assert_eq!(sent.len(), 1, "one bulk-revocation notice");
    assert_eq!(sent[0].subject, "Security notice: other sessions revoked");
}

#[tokio::test]
async fn bulk_revocations_are_refused_during_recovery_cool_down() {
    for action in BulkRevocation::ALL {
        let h = Harness::fresh();
        let mut alice = sign_in(&h, "alice@example.com").await;
        let other = alice.log_in_again(&h).await;
        let current = in_cool_down(&h, &alice.user).await;
        let mail_before = h.email.sent().len();

        let err = action.run(&h, &current).await.err();
        assert!(
            matches!(err, Some(Error::RecoveryCoolDownActive)),
            "{action:?}: got {err:?}"
        );
        assert!(
            session_exists(&h, current.id).await,
            "{action:?}: nothing is revoked"
        );
        assert!(
            session_exists(&h, other.session.id).await,
            "{action:?}: nothing is revoked"
        );
        assert_eq!(h.email.sent().len(), mail_before, "{action:?}: no notice");

        h.clock.advance(ChronoDuration::minutes(11));
        action
            .run(&h, &current)
            .await
            .unwrap_or_else(|err| panic!("{action:?} allowed once the cool-down lapses: {err:?}"));
        assert!(!session_exists(&h, other.session.id).await, "{action:?}");
    }
}

type ActionFor = fn(&SignedIn, &IssuedSession) -> DestructiveAction;

#[tokio::test]
async fn a_destructive_action_reports_whether_it_ended_the_acting_session() {
    let cases: [(&str, ActionFor, CurrentSession); 7] = [
        (
            "delete user",
            |_, _| DestructiveAction::DeleteUser,
            CurrentSession::Ended,
        ),
        (
            "request email change",
            |_, _| DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            CurrentSession::Kept,
        ),
        (
            "remove passkey",
            |alice, _| DestructiveAction::RemovePasskey {
                credential_id: alice.credential_id.clone(),
            },
            CurrentSession::Kept,
        ),
        (
            "revoke the acting session",
            |alice, _| DestructiveAction::RevokeSession {
                id: alice.session.session.id,
            },
            CurrentSession::Ended,
        ),
        (
            "revoke another session",
            |_, other| DestructiveAction::RevokeSession {
                id: other.session.id,
            },
            CurrentSession::Kept,
        ),
        (
            "revoke other sessions",
            |_, _| DestructiveAction::RevokeOtherSessions,
            CurrentSession::Kept,
        ),
        (
            "log out everywhere",
            |_, _| DestructiveAction::LogOutEverywhere,
            CurrentSession::Ended,
        ),
    ];
    for (name, action, expected) in cases {
        let h = Harness::fresh();
        let mut alice = sign_in(&h, "alice@example.com").await;
        let other = alice.log_in_again(&h).await;
        let current = &alice.session.session;

        let reported = h
            .session_manager
            .perform(
                current,
                action(&alice, &other),
                None,
                SessionContext::default(),
            )
            .await
            .unwrap_or_else(|err| panic!("{name}: {err:?}"));

        assert_eq!(reported, expected, "{name}");
        assert_eq!(
            session_exists(&h, current.id).await,
            expected == CurrentSession::Kept,
            "{name}: the report matches the store"
        );
    }
}

#[tokio::test]
async fn revoke_notifies_only_for_another_session() {
    let h = Harness::fresh();
    let mut alice = sign_in(&h, "alice@example.com").await;
    let other = alice.log_in_again(&h).await;
    let current = &alice.session.session;
    let mail_before = h.email.sent().len();

    h.session_manager
        .perform(
            current,
            DestructiveAction::RevokeSession {
                id: other.session.id,
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("revoke other");
    assert!(!session_exists(&h, other.session.id).await);
    assert_eq!(
        h.email.sent().len(),
        mail_before + 1,
        "revoking another session notifies"
    );

    h.session_manager
        .perform(
            current,
            DestructiveAction::RevokeSession { id: current.id },
            None,
            SessionContext::default(),
        )
        .await
        .expect("revoke self");
    assert!(!session_exists(&h, current.id).await);
    assert_eq!(
        h.email.sent().len(),
        mail_before + 1,
        "self-revocation sends no notice"
    );
}

#[tokio::test]
async fn revoke_hides_another_users_session() {
    let h = Harness::fresh();
    let alice = sign_in(&h, "alice@example.com").await;
    let bob = sign_in(&h, "bob@example.com").await;

    let err = h
        .session_manager
        .perform(
            &alice.session.session,
            DestructiveAction::RevokeSession {
                id: bob.session.session.id,
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("alice cannot revoke bob's session");
    assert!(matches!(err, Error::SessionNotFound), "got: {err:?}");
    assert!(session_exists(&h, bob.session.session.id).await);
}

#[tokio::test]
async fn a_session_is_in_recovery_cool_down_only_before_its_deadline() {
    let h = Harness::fresh();
    let alice = sign_in(&h, "alice@example.com").await;
    let now = h.clock.now();
    for (until, in_cool_down) in [
        (now + ChronoDuration::minutes(10), true),
        (now, false),
        (now - ChronoDuration::seconds(1), false),
    ] {
        let session = session_in_cool_down_for(&h, &alice.user, until).await;
        assert_eq!(
            session.is_in_recovery_cool_down(),
            in_cool_down,
            "cool-down until {until}",
        );
    }
}
