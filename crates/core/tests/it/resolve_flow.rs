use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::Error;
use doorman_core::audit::AuditEventKind;
use doorman_core::clock::Clock;
use doorman_core::destructive::DestructiveAction;
use doorman_core::passkey::StartedRegistration;
use doorman_core::session::{
    IdleTimeout, IssuedSession, RequestTransport, SessionConfig, SessionExpiry, hash_token,
};
use doorman_core::storage::{
    PasskeyChallengeId, SessionStore, SessionTransport, User, UserId, UserStatus, UserStore,
};
use doorman_test_support::{DpopClient, dpop_origin, lifetime, request_context};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::common::{
    Harness, LOCK_OUTS, LockOut, RECOVERY_URL, SIGNUP_URL, authenticator, kinds,
    last_email_change_token, locked_out_during, logged_in_user, make_user, operator,
    provision_user, register_passkey, session_count, token_from_email,
};

fn sliding_config() -> SessionConfig {
    let idle_timeout = IdleTimeout::new(
        lifetime(Duration::from_secs(60 * 10)),
        IdleTimeout::DEFAULT_SLIDE_INTERVAL,
    )
    .expect("idle timeout");
    SessionConfig {
        expiry: SessionExpiry::sliding(lifetime(Duration::from_secs(60 * 60)), idle_timeout)
            .expect("session expiry"),
        ..SessionConfig::default()
    }
}

fn sliding_harness() -> Harness {
    Harness::builder().session_config(sliding_config()).build()
}

async fn logged_in(h: &Harness, email: &str) -> (User, String) {
    let logged_in = logged_in_user(h, email).await;
    (logged_in.user, logged_in.session.token)
}

#[tokio::test]
async fn a_request_reads_its_session_row_and_nothing_else() {
    let h = sliding_harness();
    let (user, token) = logged_in(&h, "alice@example.com").await;

    for advance in [0, 90] {
        h.clock.advance(ChronoDuration::seconds(advance));
        h.session_store.clear_reads();
        h.user_store.clear_reads();
        let resolved = h
            .session_manager
            .resolve(&token, &RequestTransport::Cookie)
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
        .resolve("not-a-session", &RequestTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_session_past_its_deadline_is_no_session_and_is_not_audited() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            expiry: SessionExpiry::absolute(lifetime(Duration::from_secs(30))),
            ..SessionConfig::default()
        })
        .build();
    let (_, token) = logged_in(&h, "alice@example.com").await;
    h.session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.clock.advance(ChronoDuration::seconds(30));
    let audited = h.audit.len();
    let resolved = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
    assert_eq!(h.audit.len(), audited, "an expiry is not audited");
}

#[tokio::test]
async fn a_failing_session_store_is_an_error_not_no_session() {
    let h = Harness::fresh();
    let (_, token) = logged_in(&h, "alice@example.com").await;

    h.session_store.fail_reads();
    let err = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .err();
    assert!(matches!(err, Some(Error::Storage(_))), "got {err:?}");
}

#[tokio::test]
async fn a_revocation_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (_, token) = logged_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("the other process resolves the session");

    let session = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
    h.session_manager
        .log_out(&session, request_context())
        .await
        .expect("log out");
    let resolved = other
        .sessions
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_disable_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = logged_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.operator
        .disable(user.id, operator())
        .await
        .expect("disable");
    let resolved = other
        .sessions
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_delete_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = logged_in(&h, "alice@example.com").await;
    other
        .sessions
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.operator
        .delete_user(user.id, operator())
        .await
        .expect("delete");
    let resolved = other
        .sessions
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn access_is_the_session_row_whatever_the_user_row_says() {
    let h = Harness::fresh();
    let (user, token) = logged_in(&h, "alice@example.com").await;
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable outside doorman");

    h.session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a status written outside doorman leaves the session in place");
}

#[tokio::test]
async fn the_user_read_is_fresh_in_every_process() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (user, token) = logged_in(&h, "old@example.com").await;
    let session = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
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
            request_context(),
        )
        .await
        .expect("request email change");
    h.user
        .confirm_email_change(&last_email_change_token(&h), request_context())
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
    let mut alice = logged_in_user(&h, "old@example.com").await;
    alice.log_in_again(&h).await;
    let session = alice.session.session;

    h.session_manager
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            request_context(),
        )
        .await
        .expect("request email change");
    h.user
        .confirm_email_change(&last_email_change_token(&h), request_context())
        .await
        .expect("confirm email change");

    other
        .sessions
        .perform(
            &session,
            DestructiveAction::RevokeOtherSessions,
            None,
            request_context(),
        )
        .await
        .expect("revoke other sessions");
    let notice = h.email.sent().pop().expect("notice sent");
    assert_eq!(notice.to, "new@example.com");
}

#[tokio::test]
async fn a_request_after_the_slide_interval_slides() {
    let h = sliding_harness();
    let (_, token) = logged_in(&h, "alice@example.com").await;

    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    let resolved = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
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
    let (_, token) = logged_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let first = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");

    h.clock.advance(ChronoDuration::seconds(30));
    let second = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
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
    let (_, token) = logged_in(&h, "alice@example.com").await;
    let cap = start + ChronoDuration::minutes(60);

    let mut last = None;
    for _ in 0..11 {
        h.clock.advance(ChronoDuration::minutes(5));
        let resolved = h
            .session_manager
            .resolve(&token, &RequestTransport::Cookie)
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
    let (_, token) = logged_in(&h, "alice@example.com").await;
    let issued = h
        .sessions
        .find_session_by_token_hash(&hash_token(&token))
        .await
        .expect("find")
        .expect("present");

    h.clock.advance(ChronoDuration::minutes(30));
    let resolved = h
        .session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
        .expect("a live session");
    assert_eq!(resolved.expires_at, issued.expires_at);
    assert_eq!(resolved.last_used_at, issued.last_used_at);
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

async fn redeem_emailed_link(h: &Harness, issuer: Issuer, token: &str) -> StartedRegistration {
    let context = request_context();
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
                .start_authentication(request_context())
                .await
                .expect("start login");
            let assertion = wa.do_authentication(options, &passkey.credential_id);
            (user.id, Finish::Login(challenge, assertion))
        }
        Issuer::Signup | Issuer::Recovery => {
            let (url, subject) = if let Issuer::Signup = issuer {
                h.signup
                    .request_signup(email, None, request_context())
                    .await
                    .expect("request signup");
                (SIGNUP_URL, "Finish signing up")
            } else {
                provision_user(h, email).await;
                h.recovery
                    .request_recovery(email, request_context())
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
    transport: RequestTransport,
) -> Result<IssuedSession, Error> {
    let context = request_context();
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
        for lock_out in LOCK_OUTS {
            let h = Harness::fresh();
            let (user_id, ready) = ready_to_finish(&h, issuer, "racer@example.com").await;
            let audited_before = h.audit.events().len();

            // The lock-out lands while the new session is being written.
            let held = h.session_store.hold_next_session_write();
            let issued = locked_out_during(
                &h,
                held,
                lock_out,
                user_id,
                finish(&h, ready, RequestTransport::Cookie),
            )
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
                // The owner was active when the session was confirmed, so it was issued before
                // the user was deleted.
                LockOut::DeleteEnabledMidway => {
                    assert!(issued.is_ok(), "{case}: got {issued:?}");
                }
            }
            assert_eq!(session_count(&h, user_id).await, 0, "{case}");
            if !matches!(lock_out, LockOut::DeleteEnabledMidway) {
                assert!(
                    !h.audit.events()[audited_before..].iter().any(|e| matches!(
                        e.kind,
                        AuditEventKind::SessionCreated { .. }
                            | AuditEventKind::LoginSucceeded { .. }
                    )),
                    "{case}: a refused session is not audited as issued",
                );
            }
        }
    }
}

const DPOP_ORIGIN: &str = "https://api.app.test";

fn allowing_dpop_sessions() -> SessionConfig {
    SessionConfig {
        dpop_origin: Some(dpop_origin(DPOP_ORIGIN)),
        ..SessionConfig::default()
    }
}

fn dpop_harness() -> Harness {
    Harness::builder()
        .session_config(allowing_dpop_sessions())
        .build()
}

// Core never sees the request, so the path only has to agree with the proof's `htu`.
async fn proven(h: &Harness, client: &DpopClient, token: Option<&str>) -> RequestTransport {
    let proof = client.presented("POST", "/request", token, h.clock.now());
    let key = h
        .session_manager
        .prove_dpop(&proof, token)
        .await
        .expect("a valid proof");
    RequestTransport::Dpop(key)
}

#[tokio::test]
async fn a_dpop_session_resolves_only_with_a_proof_from_the_key_it_started_with() {
    for issuer in [Issuer::Login, Issuer::Signup, Issuer::Recovery] {
        let h = dpop_harness();
        let client = DpopClient::new(DPOP_ORIGIN);
        let (user_id, ready) = ready_to_finish(&h, issuer, "alice@example.com").await;
        let audited_before = h.audit.events().len();

        let issued = finish(&h, ready, proven(&h, &client, None).await)
            .await
            .expect("session issued");

        let case = format!("{issuer:?}");
        let transport = SessionTransport::Dpop { jkt: client.jkt() };
        assert_eq!(issued.session.transport, transport, "{case}");
        assert!(
            kinds(&h.audit.events()[audited_before..]).contains(&AuditEventKind::SessionCreated {
                user_id,
                session_id: issued.session.id,
                transport,
            }),
            "{case}: the audit names the transport and its key",
        );
        let token = issued.token.as_str();
        let another_key = DpopClient::new(DPOP_ORIGIN);
        let cases = [
            (
                "its own key",
                proven(&h, &client, Some(token)).await,
                Some(issued.session.id),
            ),
            (
                "another key",
                proven(&h, &another_key, Some(token)).await,
                None,
            ),
            ("its cookie", RequestTransport::Cookie, None),
        ];
        for (presented, transport, expected) in cases {
            let resolved = h
                .session_manager
                .resolve(token, &transport)
                .await
                .expect("resolve");
            assert_eq!(resolved.map(|s| s.id), expected, "{case} by {presented}");
        }
    }
}

#[tokio::test]
async fn a_cookie_session_does_not_resolve_with_a_dpop_proof() {
    let h = dpop_harness();
    let (_, ready) = ready_to_finish(&h, Issuer::Login, "alice@example.com").await;
    let issued = finish(&h, ready, RequestTransport::Cookie)
        .await
        .expect("session issued");
    assert_eq!(issued.session.transport, SessionTransport::Cookie);

    let client = DpopClient::new(DPOP_ORIGIN);
    let resolved = h
        .session_manager
        .resolve(
            &issued.token,
            &proven(&h, &client, Some(&issued.token)).await,
        )
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "got {resolved:?}");
}

#[tokio::test]
async fn a_dpop_proof_is_proven_only_once() {
    let h = dpop_harness();
    let client = DpopClient::new(DPOP_ORIGIN);
    let proof = client.presented("GET", "/me", Some("a-token"), h.clock.now());

    h.session_manager
        .prove_dpop(&proof, Some("a-token"))
        .await
        .expect("first use");
    let replayed = h.session_manager.prove_dpop(&proof, Some("a-token")).await;
    assert!(
        matches!(replayed, Err(Error::InvalidDpopProof)),
        "got {replayed:?}"
    );
}

#[tokio::test]
async fn a_dpop_proof_signed_for_another_token_does_not_resolve_a_session() {
    let h = dpop_harness();
    let client = DpopClient::new(DPOP_ORIGIN);
    let (_, ready) = ready_to_finish(&h, Issuer::Login, "alice@example.com").await;
    let issued = finish(&h, ready, proven(&h, &client, None).await)
        .await
        .expect("session issued");

    for key in [
        proven(&h, &client, Some("another-token")).await,
        proven(&h, &client, None).await,
    ] {
        let refused = h.session_manager.resolve(&issued.token, &key).await;
        assert!(
            matches!(refused, Err(Error::InvalidDpopProof)),
            "got {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_request_carrying_a_dpop_session_can_start_another_with_the_same_proof() {
    let h = dpop_harness();
    let client = DpopClient::new(DPOP_ORIGIN);
    let (_, ready) = ready_to_finish(&h, Issuer::Login, "alice@example.com").await;
    let first = finish(&h, ready, proven(&h, &client, None).await)
        .await
        .expect("first session issued");

    let key = proven(&h, &client, Some(&first.token)).await;
    h.session_manager
        .resolve(&first.token, &key)
        .await
        .expect("resolve")
        .expect("the first session");
    let (_, ready) = ready_to_finish(&h, Issuer::Login, "bob@example.com").await;
    let second = finish(&h, ready, key).await.expect("second session issued");

    assert_eq!(
        second.session.transport,
        SessionTransport::Dpop { jkt: client.jkt() }
    );
}

#[tokio::test]
async fn a_dpop_session_is_refused_before_the_ceremony_uses_anything_unless_the_host_allows_them() {
    let allowing = dpop_harness();
    let client = DpopClient::new(DPOP_ORIGIN);
    let proof = client.presented("POST", "/request", None, allowing.clock.now());
    let refused = Harness::fresh()
        .session_manager
        .prove_dpop(&proof, None)
        .await;
    assert!(
        matches!(refused, Err(Error::DpopSessionNotAllowed)),
        "got {refused:?}"
    );

    for issuer in [Issuer::Login, Issuer::Signup, Issuer::Recovery] {
        let h = Harness::fresh();
        let (user_id, ready) = ready_to_finish(&h, issuer, "alice@example.com").await;
        let sessions_before = session_count(&h, user_id).await;

        let key = proven(&allowing, &client, None).await;
        let refused = finish(&h, ready.clone(), key).await;

        assert!(
            matches!(refused, Err(Error::DpopSessionNotAllowed)),
            "{issuer:?}: got {refused:?}"
        );
        assert_eq!(
            session_count(&h, user_id).await,
            sessions_before,
            "{issuer:?}"
        );
        finish(&h, ready, RequestTransport::Cookie)
            .await
            .unwrap_or_else(|e| panic!("{issuer:?}: the refusal used up the ceremony: {e:?}"));
    }
}

#[tokio::test]
async fn a_host_that_stops_allowing_dpop_sessions_stops_honouring_them() {
    let h = dpop_harness();
    let client = DpopClient::new(DPOP_ORIGIN);
    let (_, ready) = ready_to_finish(&h, Issuer::Login, "alice@example.com").await;
    let issued = finish(&h, ready, proven(&h, &client, None).await)
        .await
        .expect("DPoP session issued");

    let restarted = h.another_process_with(SessionConfig::default());
    let resolved = restarted
        .sessions
        .resolve(
            &issued.token,
            &proven(&h, &client, Some(&issued.token)).await,
        )
        .await
        .expect("resolve");

    assert!(resolved.is_none(), "got {resolved:?}");
}
