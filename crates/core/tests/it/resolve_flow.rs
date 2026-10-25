use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::Error;
use doorman_core::assembly::AssemblyError;
use doorman_core::audit::AuditEventKind;
use doorman_core::clock::Clock;
use doorman_core::destructive::DestructiveAction;
use doorman_core::passkey::StartedRegistration;
use doorman_core::session::{IssuedSession, SessionConfig, SessionContext, hash_token};
use doorman_core::storage::{
    PasskeyChallengeId, SessionStore, SessionTransport, User, UserId, UserStatus, UserStore,
};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::common::{
    Harness, RECOVERY_URL, SIGNUP_URL, authenticator, kinds, last_email_change_token, make_user,
    operator, provision_user, register_passkey, session_count, sign_in, token_from_email,
    within_deadline,
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
        let resolved = h
            .session_manager
            .resolve(&token, SessionTransport::Cookie)
            .await
            .expect("resolve")
            .expect("a live session");
        assert_eq!(resolved.user_id, user.id);
        assert_eq!(h.session_store.reads(), 1, "one session read");
        assert_eq!(h.user_store.reads(), 0, "no user read");
    }
}

#[tokio::test]
async fn an_unknown_token_is_no_session() {
    let h = Harness::fresh();
    let resolved = h
        .session_manager
        .resolve("not-a-session", SessionTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_session_past_its_deadline_is_no_session_and_is_not_audited() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime: Duration::from_secs(30),
            ..SessionConfig::default()
        })
        .build();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.clock.advance(ChronoDuration::seconds(30));
    let audited = h.audit.len();
    let resolved = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
    assert_eq!(h.audit.len(), audited, "an expiry is not audited");
}

#[tokio::test]
async fn a_failing_session_store_is_an_error_not_no_session() {
    let h = Harness::fresh();
    let (_, token) = signed_in(&h, "alice@example.com").await;

    h.session_store.fail_reads();
    let err = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .err();
    assert!(matches!(err, Some(Error::Storage(_))), "got {err:?}");
}

#[tokio::test]
async fn a_revocation_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("the other process resolves the session");

    let session = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
    h.session_manager
        .log_out(&session, SessionContext::default())
        .await
        .expect("log out");
    let resolved = other
        .sessions
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_disable_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = signed_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.operator
        .disable(user.id, operator())
        .await
        .expect("disable");
    let resolved = other
        .sessions
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_delete_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = signed_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.operator
        .delete_user(user.id, operator())
        .await
        .expect("delete");
    let resolved = other
        .sessions
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
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
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a status written outside doorman leaves the session in place");
}

#[tokio::test]
async fn the_user_read_is_fresh_in_every_process() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = signed_in(&h, "old@example.com").await;
    let session = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
    let found = other.sessions.find_user(&session).await.expect("find user");
    assert_eq!(found.email.as_deref(), Some("old@example.com"));

    h.session_manager
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

    h.session_manager
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
        .sessions
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
async fn a_request_after_the_slide_interval_slides() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;

    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    let resolved = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
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
    let first = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.clock.advance(ChronoDuration::seconds(30));
    let second = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
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
        let resolved = h
            .session_manager
            .resolve(&token, SessionTransport::Cookie)
            .await
            .expect("resolve")
            .expect("a live session");
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
    let resolved = h
        .session_manager
        .resolve(&token, SessionTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
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

// Every flow that starts a session, driven up to its last call.
#[derive(Debug, Clone, Copy)]
enum Issuer {
    Login,
    Signup,
    Recovery,
}

#[derive(Clone)]
enum Finish {
    Login(PasskeyChallengeId, PublicKeyCredential),
    Registration(Issuer, PasskeyChallengeId, RegisterPublicKeyCredential),
}

#[derive(Debug, Clone, Copy)]
enum LockOut {
    Disable,
    Delete,
}

async fn redeem_emailed_link(h: &Harness, issuer: Issuer, token: &str) -> StartedRegistration {
    let context = SessionContext::default();
    match issuer {
        Issuer::Signup => h.signup.redeem_signup_link(token, context).await,
        _ => h.recovery.redeem_recovery_link(token, context).await,
    }
    .expect("redeem link")
}

async fn ready_to_finish(h: &Harness, issuer: Issuer, email: &str) -> (UserId, Finish) {
    let mut wa = authenticator();
    match issuer {
        Issuer::Login => {
            let user = make_user(h, email).await;
            let passkey = register_passkey(h, user.id, &mut wa, None).await;
            let (challenge, options) = h
                .passkey
                .start_authentication(SessionContext::default())
                .await
                .expect("start login");
            let assertion = wa.do_authentication(options, &passkey.credential_id);
            (user.id, Finish::Login(challenge, assertion))
        }
        Issuer::Signup | Issuer::Recovery => {
            let (url, subject) = if let Issuer::Signup = issuer {
                h.signup
                    .request_signup(email, None, SessionContext::default())
                    .await
                    .expect("request signup");
                (SIGNUP_URL, "Finish signing up")
            } else {
                provision_user(h, email).await;
                h.recovery
                    .request_recovery(email, SessionContext::default())
                    .await
                    .expect("request recovery");
                (RECOVERY_URL, "Recover access with a new passkey")
            };
            let link = h
                .email
                .sent()
                .into_iter()
                .rev()
                .find(|e| e.subject == subject)
                .expect("link queued");
            let started =
                redeem_emailed_link(h, issuer, &token_from_email(&link.body_text, url)).await;
            let user = h
                .users
                .find_user_by_email(email)
                .await
                .expect("find user")
                .expect("user exists");
            let attestation = wa.do_registration(started.options);
            (
                user.id,
                Finish::Registration(issuer, started.challenge_id, attestation),
            )
        }
    }
}

async fn finish(
    h: &Harness,
    finish: Finish,
    transport: SessionTransport,
) -> Result<IssuedSession, Error> {
    let context = SessionContext::default();
    match finish {
        Finish::Login(challenge, assertion) => h
            .passkey
            .finish_authentication(challenge, &assertion, transport, context)
            .await
            .map(|outcome| outcome.session),
        Finish::Registration(Issuer::Signup, challenge, attestation) => h
            .signup
            .finish_signup(challenge, &attestation, None, transport, context)
            .await
            .map(|outcome| outcome.session),
        Finish::Registration(_, challenge, attestation) => h
            .recovery
            .finish_recovery(challenge, &attestation, None, transport, context)
            .await
            .map(|outcome| outcome.session),
    }
}

#[tokio::test]
async fn a_session_issued_while_the_user_is_locked_out_does_not_survive() {
    for issuer in [Issuer::Login, Issuer::Signup, Issuer::Recovery] {
        for lock_out in [LockOut::Disable, LockOut::Delete] {
            let h = Harness::fresh();
            let other = h.another_process();
            let (user_id, ready) = ready_to_finish(&h, issuer, "racer@example.com").await;
            let audited_before = h.audit.events().len();

            // The lock-out lands while the new session is being written.
            let held = h.session_store.hold_next_session_write();
            let (issued, ()) = within_deadline(async {
                tokio::join!(finish(&h, ready, SessionTransport::Cookie), async {
                    held.wait().await;
                    match lock_out {
                        LockOut::Disable => other.operator.disable(user_id, operator()).await,
                        LockOut::Delete => other.operator.delete_user(user_id, operator()).await,
                    }
                    .expect("lock out");
                    held.wait().await;
                })
            })
            .await;

            let case = format!("{issuer:?} racing {lock_out:?}");
            match lock_out {
                LockOut::Disable => assert!(
                    matches!(issued, Err(Error::UserDisabled)),
                    "{case}: got {issued:?}"
                ),
                LockOut::Delete => assert!(
                    matches!(issued, Err(Error::UserNotFound)),
                    "{case}: got {issued:?}"
                ),
            }
            assert_eq!(session_count(&h, user_id).await, 0, "{case}");
            assert!(
                !h.audit.events()[audited_before..].iter().any(|e| matches!(
                    e.kind,
                    AuditEventKind::SessionCreated { .. } | AuditEventKind::LoginSucceeded { .. }
                )),
                "{case}: a refused session is not audited as issued",
            );
        }
    }
}

fn allowing_bearer_sessions() -> SessionConfig {
    SessionConfig {
        allow_bearer_sessions: true,
        ..SessionConfig::default()
    }
}

#[tokio::test]
async fn a_session_resolves_only_by_the_transport_it_started_with() {
    use SessionTransport::{Bearer, Cookie};
    for issuer in [Issuer::Login, Issuer::Signup, Issuer::Recovery] {
        for (transport, other) in [(Cookie, Bearer), (Bearer, Cookie)] {
            let h = Harness::builder()
                .session_config(allowing_bearer_sessions())
                .build();
            let (user_id, ready) = ready_to_finish(&h, issuer, "alice@example.com").await;
            let audited_before = h.audit.events().len();

            let issued = finish(&h, ready, transport).await.expect("session issued");

            let case = format!("{issuer:?} {transport:?}");
            assert_eq!(issued.session.transport, transport, "{case}");
            assert!(
                kinds(&h.audit.events()[audited_before..]).contains(
                    &AuditEventKind::SessionCreated {
                        user_id,
                        session_id: issued.session.id,
                        transport,
                    }
                ),
                "{case}: the audit names the transport",
            );
            let resolved = h
                .session_manager
                .resolve(&issued.token, transport)
                .await
                .expect("resolve");
            assert_eq!(resolved.map(|s| s.id), Some(issued.session.id), "{case}");
            let resolved = h
                .session_manager
                .resolve(&issued.token, other)
                .await
                .expect("resolve");
            assert!(resolved.is_none(), "{case}: resolved by {other:?}");
        }
    }
}

#[tokio::test]
async fn a_bearer_session_is_refused_before_the_ceremony_uses_anything_unless_the_host_allows_them()
{
    for issuer in [Issuer::Login, Issuer::Signup, Issuer::Recovery] {
        let h = Harness::fresh();
        let (user_id, ready) = ready_to_finish(&h, issuer, "alice@example.com").await;
        let sessions_before = session_count(&h, user_id).await;

        let refused = finish(&h, ready.clone(), SessionTransport::Bearer).await;

        assert!(
            matches!(refused, Err(Error::BearerSessionNotAllowed)),
            "{issuer:?}: got {refused:?}"
        );
        assert_eq!(
            session_count(&h, user_id).await,
            sessions_before,
            "{issuer:?}"
        );
        finish(&h, ready, SessionTransport::Cookie)
            .await
            .unwrap_or_else(|e| panic!("{issuer:?}: the refusal used up the ceremony: {e:?}"));
    }
}

#[tokio::test]
async fn a_host_that_stops_allowing_bearer_sessions_stops_honouring_them() {
    let h = Harness::builder()
        .session_config(allowing_bearer_sessions())
        .build();
    let (_, ready) = ready_to_finish(&h, Issuer::Login, "alice@example.com").await;
    let issued = finish(&h, ready, SessionTransport::Bearer)
        .await
        .expect("bearer session issued");

    let restarted = h.another_process_with(SessionConfig::default());
    let resolved = restarted
        .sessions
        .resolve(&issued.token, SessionTransport::Bearer)
        .await
        .expect("resolve");

    assert!(resolved.is_none(), "got {resolved:?}");
}
