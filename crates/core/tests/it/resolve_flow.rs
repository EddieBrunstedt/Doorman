use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::Error;
use doorman_core::assembly::AssemblyError;
use doorman_core::audit::{AuditEventKind, OperatorActor};
use doorman_core::clock::Clock;
use doorman_core::destructive::DestructiveAction;
use doorman_core::session::{SessionConfig, SessionContext, hash_token};
use doorman_core::storage::{SessionStore, User, UserId, UserStatus, UserStore};

use crate::common::{
    Harness, authenticator, last_email_change_token, make_user, register_passkey, session_count,
    sign_in, within_deadline,
};

fn sliding_config() -> SessionConfig {
    SessionConfig {
        absolute_lifetime: Duration::from_secs(60 * 60),
        idle_timeout: Some(Duration::from_secs(60 * 10)),
        ..SessionConfig::default()
    }
}

fn sliding_harness() -> Harness {
    Harness::builder().session_config(sliding_config()).build()
}

async fn signed_in(h: &Harness, email: &str) -> (User, String) {
    let signed_in = sign_in(h, email).await;
    (signed_in.user, signed_in.session.token)
}

#[tokio::test]
async fn a_request_reads_its_session_row_and_nothing_else() {
    let h = sliding_harness();
    let (user, token) = signed_in(&h, "alice@example.com").await;

    for advance in [0, 90] {
        h.clock.advance(ChronoDuration::seconds(advance));
        h.session_store.clear_reads();
        h.user_store.clear_reads();
        let resolved = h.session_manager.resolve(&token).await.expect("resolve");
        assert_eq!(resolved.user_id, user.id);
        assert_eq!(resolved.slid(), advance > 0);
        assert_eq!(h.session_store.reads(), 1, "one session read");
        assert_eq!(h.user_store.reads(), 0, "no user read");
    }
}

#[tokio::test]
async fn unknown_token_is_refused() {
    let h = Harness::fresh();
    let err = h.session_manager.resolve("not-a-session").await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn a_session_past_its_deadline_is_refused() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime: Duration::from_secs(30),
            ..SessionConfig::default()
        })
        .build();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.session_manager.resolve(&token).await.expect("resolve");

    h.clock.advance(ChronoDuration::seconds(30));
    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionExpired)), "got {err:?}");
}

#[tokio::test]
async fn a_revocation_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token)
        .await
        .expect("the other process resolves the session");

    let session = h.session_manager.resolve(&token).await.expect("resolve");
    h.session_manager.log_out(&session).await.expect("log out");
    let err = other.sessions.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn a_disable_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = signed_in(&h, "alice@example.com").await;
    other.sessions.resolve(&token).await.expect("resolve");

    h.operator
        .disable(user.id, operator())
        .await
        .expect("disable");
    let err = other.sessions.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn a_delete_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = signed_in(&h, "alice@example.com").await;
    other.sessions.resolve(&token).await.expect("resolve");

    h.operator
        .delete_user(user.id, operator())
        .await
        .expect("delete");
    let err = other.sessions.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn access_is_the_session_row_whatever_the_user_row_says() {
    let h = Harness::fresh();
    let (user, token) = signed_in(&h, "alice@example.com").await;
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable outside doorman");

    h.session_manager
        .resolve(&token)
        .await
        .expect("a status written outside doorman leaves the session in place");
}

#[tokio::test]
async fn the_user_read_is_fresh_in_every_process() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = signed_in(&h, "old@example.com").await;
    let session = h.session_manager.resolve(&token).await.expect("resolve");
    let found = other.sessions.find_user(&session).await.expect("find user");
    assert_eq!(found.email.as_deref(), Some("old@example.com"));

    h.destructive_actions
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    h.user
        .confirm_email_change(&last_email_change_token(&h), SessionContext::default())
        .await
        .expect("confirm email change");

    let found = other.sessions.find_user(&session).await.expect("find user");
    assert_eq!(found.id, user.id);
    assert_eq!(found.email.as_deref(), Some("new@example.com"));
}

#[tokio::test]
async fn a_security_notice_goes_to_the_address_changed_in_another_process() {
    let h = Harness::fresh();
    let other = h.another_process();
    let mut alice = sign_in(&h, "old@example.com").await;
    alice.log_in_again(&h).await;
    let session = alice.session.session;

    h.destructive_actions
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    h.user
        .confirm_email_change(&last_email_change_token(&h), SessionContext::default())
        .await
        .expect("confirm email change");

    other
        .destructive_actions
        .perform(
            &session,
            DestructiveAction::RevokeOtherSessions,
            None,
            SessionContext::default(),
        )
        .await
        .expect("revoke other sessions");
    let notice = h.email.sent().pop().expect("notice sent");
    assert_eq!(notice.to, "new@example.com");
}

#[tokio::test]
async fn a_request_after_the_slide_interval_slides_and_reports_it() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;

    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert!(resolved.slid(), "the deadline moved");
    assert_eq!(resolved.last_used_at, now);
    assert_eq!(resolved.expires_at, now + ChronoDuration::minutes(10));

    let stored = h
        .sessions
        .find_session_by_token_hash(&hash_token(&token))
        .await
        .expect("find")
        .expect("present");
    assert_eq!(stored.expires_at, resolved.expires_at, "persisted");
    assert_eq!(stored.last_used_at, now);
}

#[tokio::test]
async fn read_within_the_slide_interval_does_not_slide() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let first = h.session_manager.resolve(&token).await.expect("slide");

    h.clock.advance(ChronoDuration::seconds(30));
    let second = h.session_manager.resolve(&token).await.expect("read");
    assert!(!second.slid());
    assert_eq!(second.expires_at, first.expires_at);
    assert_eq!(second.last_used_at, first.last_used_at);
}

#[tokio::test]
async fn slide_is_clamped_at_the_absolute_cap() {
    let h = sliding_harness();
    let start = h.clock.now();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let cap = start + ChronoDuration::minutes(60);

    let mut last = None;
    for _ in 0..11 {
        h.clock.advance(ChronoDuration::minutes(5));
        let resolved = h.session_manager.resolve(&token).await.expect("resolve");
        assert!(resolved.expires_at <= cap);
        last = Some(resolved);
    }
    let last = last.expect("resolved at least once");
    assert_eq!(last.expires_at, cap);
}

#[tokio::test]
async fn without_an_idle_timeout_nothing_slides() {
    let h = Harness::fresh();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let issued = h
        .sessions
        .find_session_by_token_hash(&hash_token(&token))
        .await
        .expect("find")
        .expect("present");

    h.clock.advance(ChronoDuration::minutes(30));
    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert!(!resolved.slid());
    assert_eq!(resolved.expires_at, issued.expires_at);
    assert_eq!(resolved.last_used_at, issued.last_used_at);
}

#[test]
fn slide_interval_must_be_strictly_below_the_idle_timeout() {
    let idle = Duration::from_secs(60 * 10);
    let build = |slide_interval| {
        Harness::builder()
            .session_config(SessionConfig {
                slide_interval,
                ..sliding_config()
            })
            .try_build()
    };

    let err = build(idle).err();
    assert!(
        matches!(err, Some(AssemblyError::IdleTimeoutInvalid { idle_timeout, .. }) if idle_timeout == idle),
        "a slide interval equal to the idle timeout is rejected, got {err:?}",
    );
    assert!(build(idle - Duration::from_secs(1)).is_ok());
}

fn operator() -> OperatorActor {
    OperatorActor::new("support-agent-7", None, None, None).expect("operator actor")
}

async fn login_racing(
    h: &Harness,
    email: &str,
    lock_out: impl AsyncFnOnce(UserId),
) -> (UserId, Result<(), Error>) {
    let user = make_user(h, email).await;
    let mut wa = authenticator();
    let passkey = register_passkey(h, user.id, &mut wa, None).await;
    let (challenge, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start login");
    let assertion = wa.do_authentication(options, &passkey.credential_id);

    let held = h.user_store.hold_next_id_lookup();
    let (login, ()) = within_deadline(async {
        tokio::join!(
            h.passkey
                .finish_authentication(challenge, &assertion, SessionContext::default()),
            async {
                held.wait().await;
                lock_out(user.id).await;
                held.wait().await;
            },
        )
    })
    .await;
    (user.id, login.map(|_| ()))
}

#[tokio::test]
async fn a_login_racing_a_disable_leaves_no_session() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user_id, login) = login_racing(&h, "racer@example.com", async |user_id| {
        other
            .operator
            .disable(user_id, operator())
            .await
            .expect("disable");
    })
    .await;

    assert!(matches!(login, Err(Error::UserDisabled)), "got {login:?}");
    assert_eq!(session_count(&h, user_id).await, 0);
    assert!(
        !h.audit
            .events()
            .iter()
            .any(|e| matches!(e.kind, AuditEventKind::LoginSucceeded { .. })),
        "a refused login is not audited as a success",
    );
}

#[tokio::test]
async fn a_login_racing_a_delete_leaves_no_session() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user_id, login) = login_racing(&h, "racer@example.com", async |user_id| {
        other
            .operator
            .delete_user(user_id, operator())
            .await
            .expect("delete");
    })
    .await;

    assert!(login.is_err(), "got {login:?}");
    assert_eq!(session_count(&h, user_id).await, 0);
}
