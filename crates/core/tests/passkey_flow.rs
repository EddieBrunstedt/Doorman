mod common;

use bauth_core::audit::AuditEventKind;
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
async fn authentication_without_user_handle_falls_back_to_credential_id() {
    let h = Harness::fresh();
    let user = make_user(&h, "fallback@example.com").await;
    let mut wa = authenticator();
    let credential = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, options) = h.passkey.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication_without_user_handle(options, &credential.credential_id);

    let issued = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("finish via credential id fallback");
    assert_eq!(issued.session.user_id, user.id);
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
async fn remove_passkey_emits_audit_and_blocks_login() {
    let h = Harness::fresh();
    let user = make_user(&h, "remover@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    h.passkey
        .remove_passkey(user.id, &cred.credential_id, SessionContext::default())
        .await
        .expect("remove");
    assert!(h.credentials.is_empty());
    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::CredentialRemoved { .. }))
    );
}

#[tokio::test]
async fn remove_passkey_refuses_other_users_credential() {
    let h = Harness::fresh();
    let alice = make_user(&h, "a@example.com").await;
    let bob = make_user(&h, "b@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, alice.id, &mut wa, None).await;

    let err = h
        .passkey
        .remove_passkey(bob.id, &cred.credential_id, SessionContext::default())
        .await
        .expect_err("ownership check");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(h.credentials.len(), 1, "alice's passkey untouched");
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
