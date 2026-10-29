use std::num::NonZeroU32;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::{Actor, AuditEventKind};
use doorman_core::clock::Clock;
use doorman_core::destructive::{CurrentSession, DestructiveAction};
use doorman_core::error::Error;
use doorman_core::session::{
    IssuedSession, ResolvedSession, SessionConfig, SessionContext, hash_token,
};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyStore, SessionId, SessionStore, SessionTransport, User, UserId,
    UserStore,
};
use doorman_test_support::request_context;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::common::{
    Harness, RECOVERY_URL, SignedIn, authenticator, kinds, log_in, register_passkey, session_count,
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
            .perform(session, action, None, request_context())
            .await
    }
}

#[tokio::test]
async fn a_login_issues_a_session_bound_to_its_token() {
    let h = Harness::fresh();
    let context = SessionContext::new("1.2.3.4".parse().expect("ip"), Some("test-agent"));
    let alice = sign_in_from(&h, "alice@example.com", context).await;
    let issued = &alice.session;

    assert_eq!(h.sessions.len(), 1);
    assert_eq!(issued.session.user_id, alice.user.id);
    assert_eq!(issued.session.ip.to_string(), "1.2.3.4");
    let stored = h
        .sessions
        .find_session_by_id(issued.session.id)
        .await
        .expect("find session")
        .expect("session stored");
    assert_eq!(hash_token(&issued.token), stored.token_hash);

    let resolved = h
        .session_manager
        .resolve(&issued.token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
    assert_eq!(resolved.id, issued.session.id);
    assert!(
        kinds(&h.audit.events()).contains(&AuditEventKind::SessionCreated {
            user_id: alice.user.id,
            session_id: issued.session.id,
            transport: SessionTransport::Cookie,
        }),
        "the new session is audited",
    );
}

#[tokio::test]
async fn log_out_deletes_the_session_and_audits_it() {
    let h = Harness::fresh();
    let alice = sign_in(&h, "alice@example.com").await;
    let session = &alice.session.session;

    h.session_manager
        .log_out(session, request_context())
        .await
        .expect("log out");
    assert!(h.sessions.is_empty());

    let resolved = h
        .session_manager
        .resolve(&alice.session.token, SessionTransport::Cookie)
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

    let err = h
        .session_manager
        .log_out(session, request_context())
        .await
        .err();
    assert!(
        matches!(err, Some(Error::SessionNotFound)),
        "a session logs out once, got {err:?}"
    );
}

#[derive(Debug, Clone, Copy)]
enum SessionEnd {
    LoggedOut,
    Expired,
}

impl SessionEnd {
    const ALL: [Self; 2] = [Self::LoggedOut, Self::Expired];

    async fn apply(self, h: &Harness, session: &ResolvedSession) {
        match self {
            Self::LoggedOut => h
                .session_manager
                .log_out(session, request_context())
                .await
                .expect("log out"),
            Self::Expired => h.clock.advance(ChronoDuration::hours(2)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SessionWrite {
    StartPasskeyRegistration,
    FinishPasskeyRegistration,
    RenamePasskey,
    StartReauth,
    Perform,
}

impl SessionWrite {
    const ALL: [Self; 5] = [
        Self::StartPasskeyRegistration,
        Self::FinishPasskeyRegistration,
        Self::RenamePasskey,
        Self::StartReauth,
        Self::Perform,
    ];

    async fn run(
        self,
        h: &Harness,
        signed_in: &mut SignedIn,
        session: &ResolvedSession,
        pending: (PasskeyChallengeId, CreationChallengeResponse),
    ) -> Result<(), Error> {
        let sessions = &h.session_manager;
        match self {
            Self::StartPasskeyRegistration => {
                sessions.start_passkey_registration(session).await.map(drop)
            }
            Self::FinishPasskeyRegistration => {
                let (challenge_id, options) = pending;
                let response = signed_in.authenticator.do_registration(options);
                sessions
                    .finish_passkey_registration(
                        session,
                        challenge_id,
                        &response,
                        None,
                        request_context(),
                    )
                    .await
                    .map(drop)
            }
            Self::RenamePasskey => sessions
                .rename_passkey(
                    session,
                    &signed_in.credential_id,
                    Some("renamed".into()),
                    request_context(),
                )
                .await
                .map(drop),
            Self::StartReauth => sessions.start_reauth(session).await.map(drop),
            Self::Perform => sessions
                .perform(
                    session,
                    DestructiveAction::DeleteUser,
                    None,
                    request_context(),
                )
                .await
                .map(drop),
        }
    }
}

async fn stored_state(
    h: &Harness,
    user_id: UserId,
) -> (Option<User>, Vec<(Vec<u8>, Option<String>)>, usize) {
    let user = h.users.find_user_by_id(user_id).await.expect("find user");
    let passkeys = h
        .passkeys
        .list_passkeys_for_user(user_id)
        .await
        .expect("list passkeys")
        .into_iter()
        .map(|p| (p.credential_id, p.name))
        .collect();
    (user, passkeys, h.challenges.len())
}

#[tokio::test]
async fn a_session_that_ended_after_it_was_resolved_writes_nothing() {
    for end in SessionEnd::ALL {
        for write in SessionWrite::ALL {
            let h = Harness::fresh();
            let mut alice = sign_in(&h, "alice@example.com").await;
            let session = alice.session.session.clone();
            let pending = h
                .session_manager
                .start_passkey_registration(&session)
                .await
                .expect("start while live");
            end.apply(&h, &session).await;
            let before = stored_state(&h, alice.user.id).await;

            let result = write.run(&h, &mut alice, &session, pending).await;
            assert!(
                matches!(result, Err(Error::SessionNotFound)),
                "{write:?} after {end:?}: got {result:?}",
            );
            assert_eq!(
                stored_state(&h, alice.user.id).await,
                before,
                "{write:?} after {end:?} changed what is stored",
            );
        }
    }
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
        .resolve(&first.token, SessionTransport::Cookie)
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
        .request_recovery("alice@example.com", request_context())
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
            request_context(),
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
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect("finish recovery");
    h.clock.advance(ChronoDuration::seconds(1));
    let login = log_in(
        &h,
        &mut recovered,
        &recovery.passkey.credential_id,
        request_context(),
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
            request_context(),
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

#[derive(Debug, Clone, Copy)]
enum ActingRequest {
    LogOut,
    RevokeAnotherSession,
    RevokeOtherSessions,
    LogOutEverywhere,
    LogInPastSessionCap,
    DeleteUser,
    RemovePasskey,
    RequestEmailChange,
}

impl ActingRequest {
    const ALL: [Self; 8] = [
        Self::LogOut,
        Self::RevokeAnotherSession,
        Self::RevokeOtherSessions,
        Self::LogOutEverywhere,
        Self::LogInPastSessionCap,
        Self::DeleteUser,
        Self::RemovePasskey,
        Self::RequestEmailChange,
    ];
}

#[tokio::test]
async fn revocations_and_destructive_actions_audit_the_request_not_the_login() {
    let login = SessionContext::new("198.51.100.1".parse().expect("ip"), Some("login"));
    let request = SessionContext::new("203.0.113.9".parse().expect("ip"), Some("request"));
    for acting in ActingRequest::ALL {
        let h = Harness::builder()
            .session_config(SessionConfig {
                absolute_lifetime: Duration::from_secs(60 * 60),
                max_sessions_per_user: NonZeroU32::new(2),
                ..SessionConfig::default()
            })
            .build();
        let mut alice = sign_in_from(&h, "alice@example.com", login.clone()).await;
        h.clock.advance(ChronoDuration::seconds(1));
        let other = log_in(
            &h,
            &mut alice.authenticator,
            &alice.credential_id,
            login.clone(),
        )
        .await;
        let spare = register_passkey(&h, alice.user.id, &mut authenticator(), None).await;
        h.clock.advance(ChronoDuration::seconds(1));
        let current = &alice.session.session;
        let audited_before = h.audit.len();

        let perform = |action| {
            h.session_manager
                .perform(current, action, None, request.clone())
        };
        match acting {
            ActingRequest::LogOut => h
                .session_manager
                .log_out(current, request.clone())
                .await
                .map(|()| CurrentSession::Ended),
            ActingRequest::RevokeAnotherSession => {
                perform(DestructiveAction::RevokeAnotherSession {
                    id: other.session.id,
                })
                .await
            }
            ActingRequest::RevokeOtherSessions => {
                perform(DestructiveAction::RevokeOtherSessions).await
            }
            ActingRequest::LogOutEverywhere => perform(DestructiveAction::LogOutEverywhere).await,
            ActingRequest::LogInPastSessionCap => {
                log_in(
                    &h,
                    &mut alice.authenticator,
                    &alice.credential_id,
                    request.clone(),
                )
                .await;
                Ok(CurrentSession::Kept)
            }
            ActingRequest::DeleteUser => perform(DestructiveAction::DeleteUser).await,
            ActingRequest::RemovePasskey => {
                perform(DestructiveAction::RemovePasskey {
                    credential_id: spare.credential_id.clone(),
                })
                .await
            }
            ActingRequest::RequestEmailChange => {
                perform(DestructiveAction::RequestEmailChange {
                    new_email: "alice@example.org".into(),
                })
                .await
            }
        }
        .unwrap_or_else(|error| panic!("{acting:?} failed: {error:?}"));

        let audited = &h.audit.events()[audited_before..];
        assert!(!audited.is_empty(), "{acting:?} audits nothing");
        for event in audited {
            assert_eq!(
                event.actor,
                Actor::from(&request),
                "{acting:?} audits {:?} as the wrong actor",
                event.kind,
            );
        }
    }
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
            request_context(),
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
    let cases: [(&str, ActionFor, CurrentSession); 6] = [
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
            "revoke another session",
            |_, other| DestructiveAction::RevokeAnotherSession {
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
            .perform(current, action(&alice, &other), None, request_context())
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
async fn revoking_another_session_sends_a_notice() {
    let h = Harness::fresh();
    let mut alice = sign_in(&h, "alice@example.com").await;
    let other = alice.log_in_again(&h).await;
    let current = &alice.session.session;
    let mail_before = h.email.sent().len();

    h.session_manager
        .perform(
            current,
            DestructiveAction::RevokeAnotherSession {
                id: other.session.id,
            },
            None,
            request_context(),
        )
        .await
        .expect("revoke another session");
    assert!(!session_exists(&h, other.session.id).await);
    assert!(session_exists(&h, current.id).await);
    let sent = &h.email.sent()[mail_before..];
    assert_eq!(sent.len(), 1, "one notice");
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
            DestructiveAction::RevokeAnotherSession {
                id: bob.session.session.id,
            },
            None,
            request_context(),
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
