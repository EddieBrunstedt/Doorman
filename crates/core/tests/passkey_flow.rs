mod common;

use bauth_core::audit::{AuditEventKind, AuthFailureReason};
use bauth_core::clock::Clock;
use bauth_core::error::Error;
use bauth_core::session::SessionContext;
use bauth_core::storage::{PasskeyChallengeStore, PasskeyCredentialStore, UserId};
use chrono::Duration as ChronoDuration;

use common::{
    Harness, assert_discoverable_request_options, assert_resident_registration_options,
    authenticator, kinds, make_user, register_passkey,
};

#[tokio::test]
async fn register_then_discoverable_authenticate_round_trip() {
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();

    let credential = register_passkey(&h, user.id, &mut wa, Some("Alice's Mac")).await;
    assert_eq!(credential.user_id, user.id);
    assert_eq!(credential.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(credential.recovery_cooldown_until, None);
    assert_eq!(h.credentials.len(), 1);
    assert!(h.challenges.is_empty(), "challenge consumed");
    let sent = h.email.sent();
    assert_eq!(sent.len(), 1, "passkey registration notification sent");
    assert_eq!(sent[0].subject, "Security notice: passkey registered");
    assert!(sent[0].body_text.contains("Alice's Mac"));

    let (auth_challenge, rcr) = h
        .passkey
        .start_authentication()
        .await
        .expect("start_authentication");
    assert_discoverable_request_options(&rcr);
    let assertion = wa.do_authentication(rcr, &credential.credential_id);

    let issued = h
        .passkey
        .finish_authentication(
            auth_challenge,
            &assertion,
            SessionContext {
                ip: Some("1.2.3.4".into()),
                user_agent: Some("ua".into()),
            },
        )
        .await
        .expect("finish_authentication");
    assert_eq!(issued.session.user_id, user.id);
    assert_eq!(h.sessions.len(), 1);

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&credential.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    assert!(stored.last_used_at.is_some(), "last_used_at advanced");
    assert_eq!(stored.recovery_cooldown_until, None);

    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::CredentialAdded { .. }))
    );
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. }))
    );
}

#[tokio::test]
async fn registration_with_none_recovery_cooldown_stores_unrestricted_passkey() {
    let h = Harness::fresh();
    let user = make_user(&h, "none-cooldown@example.com").await;
    let mut wa = authenticator();

    let (challenge_id, ccr) = h
        .passkey
        .start_registration_with_recovery_cooldown(user.id, None)
        .await
        .expect("start_registration_with_recovery_cooldown");
    let response = wa.do_registration(ccr);
    let credential = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("finish_registration");

    assert_eq!(credential.recovery_cooldown_until, None);
    let stored = h
        .credentials
        .find_passkey_by_credential_id(&credential.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    assert_eq!(stored.recovery_cooldown_until, None);
}

#[tokio::test]
async fn registration_with_recovery_cooldown_stores_timestamp_on_passkey() {
    let h = Harness::fresh();
    let user = make_user(&h, "cooldown@example.com").await;
    let mut wa = authenticator();
    let cooldown_until = h.clock.now() + ChronoDuration::hours(24);

    let (challenge_id, ccr) = h
        .passkey
        .start_registration_with_recovery_cooldown(user.id, Some(cooldown_until))
        .await
        .expect("start_registration_with_recovery_cooldown");
    let response = wa.do_registration(ccr);
    let credential = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("finish_registration");

    assert_eq!(credential.recovery_cooldown_until, Some(cooldown_until));
    let stored = h
        .credentials
        .find_passkey_by_credential_id(&credential.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    assert_eq!(stored.recovery_cooldown_until, Some(cooldown_until));
}

#[tokio::test]
async fn finish_registration_recovery_cooldown_override_takes_precedence() {
    let h = Harness::fresh();
    let user = make_user(&h, "override-cooldown@example.com").await;
    let mut wa = authenticator();
    let challenge_cooldown_until = h.clock.now() + ChronoDuration::hours(1);
    let override_cooldown_until = h.clock.now() + ChronoDuration::hours(2);

    let (challenge_id, ccr) = h
        .passkey
        .start_registration_with_recovery_cooldown(user.id, Some(challenge_cooldown_until))
        .await
        .expect("start_registration_with_recovery_cooldown");
    let response = wa.do_registration(ccr);
    let credential = h
        .passkey
        .finish_registration_with_recovery_cooldown(
            challenge_id,
            &response,
            None,
            SessionContext::default(),
            override_cooldown_until,
        )
        .await
        .expect("finish_registration_with_recovery_cooldown");

    assert_eq!(
        credential.recovery_cooldown_until,
        Some(override_cooldown_until)
    );
}

#[tokio::test]
async fn discoverable_authentication_identifies_two_users_from_response() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();

    let alice_credential = register_passkey(&h, alice.id, &mut wa, Some("alice device")).await;
    let bob_credential = register_passkey(&h, bob.id, &mut wa, Some("bob device")).await;

    let (bob_challenge, bob_options) = h.passkey.start_authentication().await.expect("start bob");
    let bob_assertion = wa.do_authentication(bob_options, &bob_credential.credential_id);
    let bob_issued = h
        .passkey
        .finish_authentication(bob_challenge, &bob_assertion, SessionContext::default())
        .await
        .expect("finish bob");
    assert_eq!(bob_issued.session.user_id, bob.id);

    let (alice_challenge, alice_options) =
        h.passkey.start_authentication().await.expect("start alice");
    let alice_assertion = wa.do_authentication(alice_options, &alice_credential.credential_id);
    let alice_issued = h
        .passkey
        .finish_authentication(alice_challenge, &alice_assertion, SessionContext::default())
        .await
        .expect("finish alice");
    assert_eq!(alice_issued.session.user_id, alice.id);
}

#[tokio::test]
async fn authentication_without_user_handle_is_rejected() {
    // Discoverable auth must assert a user handle that maps to the
    // credential owner. An authenticator that omits it leaves the
    // credential-to-user binding unverified, so the login is refused even
    // though the credential id resolves.
    let h = Harness::fresh();
    let user = make_user(&h, "fallback@example.com").await;
    let mut wa = authenticator();
    let credential = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, options) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication_without_user_handle(options, &credential.credential_id);

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("missing user handle must be rejected");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(h.sessions.len(), 0, "no session minted");

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::UserHandleMismatch,
            } if *uid == user.id
        )),
        "missing handle audited as a user-handle mismatch"
    );
}

#[tokio::test]
async fn registration_links_passkey_to_existing_user() {
    let h = Harness::fresh();
    let user = make_user(&h, "linker@example.com").await;
    let mut wa = authenticator();

    let cred = register_passkey(&h, user.id, &mut wa, None).await;
    assert_eq!(cred.user_id, user.id, "passkey linked to same user");

    let listed = h.passkey.list_passkeys(user.id).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, cred.credential_id);
}

#[tokio::test]
async fn second_registration_excludes_existing_credentials() {
    let h = Harness::fresh();
    let user = make_user(&h, "two@example.com").await;
    let mut wa = authenticator();

    register_passkey(&h, user.id, &mut wa, None).await;

    let (_id2, ccr2) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("start second registration");
    assert_resident_registration_options(&ccr2);
    let excludes = ccr2
        .public_key
        .exclude_credentials
        .expect("previous credential excluded");
    assert_eq!(excludes.len(), 1, "previous credential excluded");
}

#[tokio::test]
async fn finish_registration_rejects_unknown_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "ghost@example.com").await;
    let mut wa = authenticator();
    let (challenge_id, ccr) = h.passkey.start_registration(user.id).await.expect("start");
    let response = wa.do_registration(ccr);
    h.passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("first finish ok");

    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect_err("replayed challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn finish_registration_rejects_expired_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "slow@example.com").await;
    let mut wa = authenticator();
    let (challenge_id, ccr) = h.passkey.start_registration(user.id).await.expect("start");
    let response = wa.do_registration(ccr);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn finish_authentication_rejects_unknown_credential() {
    let h = Harness::fresh();
    let user = make_user(&h, "vanish@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);

    h.credentials
        .delete_passkey(&cred.credential_id)
        .await
        .expect("delete credential");

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("missing credential");
    assert!(matches!(err, Error::PasskeyNotFound));
}

#[tokio::test]
async fn finish_authentication_rejects_mismatched_user_handle() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();
    let alice_credential = register_passkey(&h, alice.id, &mut wa, None).await;

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &alice_credential.credential_id);
    assertion.response.user_handle = Some(bob.id.0.as_bytes().as_slice().into());

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("ownership mismatch");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(h.sessions.len(), 0, "no session minted on mismatch");

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::UserHandleMismatch,
            } if *uid == alice.id
        )),
        "mismatch audited against the credential owner"
    );
}

#[tokio::test]
async fn finish_authentication_rejects_counter_regression_and_audits_it() {
    // A non-advancing signature counter is webauthn-rs's clone/rollback
    // signal. We simulate a credential whose recorded counter is already
    // ahead of what the authenticator will next assert by bumping the stored
    // blob's counter; the next assertion then presents a lower value.
    let h = Harness::fresh();
    let user = make_user(&h, "cloned@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let mut stored = h
        .credentials
        .find_passkey_by_credential_id(&cred.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    let mut blob: serde_json::Value =
        serde_json::from_slice(&stored.passkey).expect("blob is json");
    blob["cred"]["counter"] = serde_json::json!(1_000_000u32);
    stored.passkey = serde_json::to_vec(&blob).expect("reserialise blob");
    h.credentials
        .update_passkey(stored)
        .await
        .expect("persist bumped counter");

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("counter regression must be rejected");
    assert!(matches!(err, Error::PasskeyPossibleCompromise));
    assert_eq!(h.sessions.len(), 0, "no session minted on regression");

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::CounterRegression,
            } if *uid == user.id
        )),
        "counter regression emits a security audit event"
    );
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. })),
        "no login-succeeded event on regression"
    );
}

#[tokio::test]
async fn finish_authentication_audits_unknown_credential_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "gone@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    h.credentials
        .delete_passkey(&cred.credential_id)
        .await
        .expect("delete credential");

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("missing credential");
    assert!(matches!(err, Error::PasskeyNotFound));

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::AuthenticationFailed {
            user_id: None,
            reason: AuthFailureReason::UnknownCredential,
        }
    )));
}

#[tokio::test]
async fn finish_authentication_audits_expired_challenge_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "stale@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("expired challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::AuthenticationFailed {
            user_id: None,
            reason: AuthFailureReason::ExpiredChallenge,
        }
    )));
}

#[tokio::test]
async fn finish_authentication_audits_unknown_challenge_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "noghost@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    // Consume the challenge once, then replay against the now-empty store.
    h.passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("first finish");
    let audit_before = h.audit.events().len();

    let (auth_id2, rcr2) = h
        .passkey
        .start_authentication()
        .await
        .expect("start auth 2");
    let assertion2 = wa.do_authentication(rcr2, &cred.credential_id);
    // Drop the second challenge out from under the finish call.
    h.challenges
        .take_authentication(auth_id2)
        .await
        .expect("take challenge")
        .expect("challenge present");

    let err = h
        .passkey
        .finish_authentication(auth_id2, &assertion2, SessionContext::default())
        .await
        .expect_err("unknown challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));

    let events = kinds(&h.audit.events()[audit_before..]);
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::AuthenticationFailed {
            user_id: None,
            reason: AuthFailureReason::InvalidChallenge,
        }
    )));
}

#[tokio::test]
async fn start_authentication_is_usernameless_and_does_not_look_up_email() {
    let h = Harness::fresh();
    let (_id, rcr) = h
        .passkey
        .start_authentication()
        .await
        .expect("should succeed without an email");
    assert_discoverable_request_options(&rcr);
}

#[tokio::test]
async fn finish_authentication_rejects_expired_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "slow-auth@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("expired challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn remove_passkey_emits_audit_sends_notification_and_blocks_login() {
    let h = Harness::fresh();
    let user = make_user(&h, "remover@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, Some("old phone")).await;
    let mail_before = h.email.sent().len();

    h.passkey
        .remove_passkey(user.id, &cred.credential_id, SessionContext::default())
        .await
        .expect("remove");
    assert!(h.credentials.is_empty());
    let sent = h.email.sent();
    let removal_mail = &sent[mail_before..];
    assert_eq!(removal_mail.len(), 1, "passkey removal notification sent");
    assert_eq!(removal_mail[0].subject, "Security notice: passkey removed");
    assert!(removal_mail[0].body_text.contains("old phone"));
    assert!(removal_mail[0].body_text.contains("If this was not you"));

    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::CredentialRemoved { .. }))
    );
}

#[tokio::test]
async fn remove_passkey_refuses_other_users_credential_without_notification() {
    let h = Harness::fresh();
    let alice = make_user(&h, "a@example.com").await;
    let bob = make_user(&h, "b@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, alice.id, &mut wa, None).await;
    let mail_before = h.email.sent().len();

    let err = h
        .passkey
        .remove_passkey(bob.id, &cred.credential_id, SessionContext::default())
        .await
        .expect_err("ownership check");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(h.credentials.len(), 1, "alice's passkey untouched");
    assert_eq!(h.email.sent().len(), mail_before, "no removal email sent");
}

#[tokio::test]
async fn remove_missing_passkey_sends_no_notification() {
    let h = Harness::fresh();
    let user = make_user(&h, "missing@example.com").await;

    let err = h
        .passkey
        .remove_passkey(user.id, b"missing credential", SessionContext::default())
        .await
        .expect_err("missing credential");
    assert!(matches!(err, Error::PasskeyNotFound));
    assert_eq!(h.email.sent().len(), 0, "no removal email sent");
}

#[tokio::test]
async fn remove_passkey_notification_failure_does_not_undo_removal() {
    let h = Harness::fresh();
    let user = make_user(&h, "remove-failure@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, Some("old phone")).await;
    let mail_before = h.email.sent().len();
    h.email.fail_after_successful_sends(mail_before);

    h.passkey
        .remove_passkey(user.id, &cred.credential_id, SessionContext::default())
        .await
        .expect("remove succeeds despite notification failure");

    assert!(
        h.credentials
            .find_passkey_by_credential_id(&cred.credential_id)
            .await
            .expect("find credential")
            .is_none(),
        "credential was still removed"
    );
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "failed notification was not captured"
    );
}

#[tokio::test]
async fn start_registration_for_unknown_user_errors() {
    let h = Harness::fresh();
    let err = h
        .passkey
        .start_registration(UserId::new())
        .await
        .expect_err("unknown user");
    assert!(matches!(err, Error::UserNotFound));
}

#[tokio::test]
async fn challenge_store_purges_expired_entries() {
    let h = Harness::fresh();
    let user = make_user(&h, "exp@example.com").await;
    h.passkey
        .start_registration(user.id)
        .await
        .expect("start registration");
    h.passkey
        .start_authentication()
        .await
        .expect("start authentication");
    assert_eq!(h.challenges.len(), 2);

    h.clock.advance(ChronoDuration::seconds(600));
    let removed = h
        .challenges
        .purge_expired(h.clock.now())
        .await
        .expect("purge expired");
    assert_eq!(removed, 2);
    assert!(h.challenges.is_empty());
}
