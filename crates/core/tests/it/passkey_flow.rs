use std::num::NonZeroU32;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::{AuditEventKind, AuthFailureReason, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::destructive::DestructiveAction;
use doorman_core::error::Error;
use doorman_core::passkey::{MAX_PASSKEY_NAME_LEN, PasskeyConfig};
use doorman_core::session::SessionContext;
use doorman_core::storage::{
    PasskeyChallengeStore, PasskeyStore, PasskeyUse, SessionTransport, UserStatus, UserStore,
};
use doorman_test_support::request_context;
use webauthn_rs_proto::AuthenticatorTransport;

use crate::common::{
    Harness, RP_ID, RP_NAME, assert_discoverable_request_options,
    assert_resident_registration_options, authenticator, kinds, last_email_change_token, make_user,
    passkey_count, register_passkey, rp_origin, session_count, session_for,
    session_in_cool_down_for,
};

fn base_passkey_config() -> PasskeyConfig {
    PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
}

#[tokio::test]
async fn register_then_discoverable_authenticate_round_trip() {
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();

    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let passkey = h
        .session_manager
        .finish_passkey_registration(
            &session,
            challenge_id,
            &response,
            Some("Alice's Mac".into()),
            request_context(),
        )
        .await
        .expect("finish_registration");
    assert_eq!(passkey.user_id, user.id);
    assert_eq!(passkey.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(passkey.recovery_cool_down_until, None);
    assert_eq!(passkey_count(&h, user.id).await, 1);
    let err = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect_err("challenge redeemed: the ceremony cannot be replayed");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    let sent = h.email.sent();
    assert_eq!(sent.len(), 1, "passkey registration notice sent");
    assert_eq!(sent[0].subject, "Security notice: passkey registered");
    assert!(sent[0].body_text.contains("Alice's Mac"));

    let (auth_challenge, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start_authentication");
    assert_discoverable_request_options(&rcr);
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    let sessions_before = session_count(&h, user.id).await;

    let issued = h
        .passkey
        .finish_authentication(
            auth_challenge,
            &assertion,
            SessionTransport::Cookie,
            SessionContext::new("1.2.3.4".parse().expect("ip"), Some("ua")),
        )
        .await
        .expect("finish_authentication");
    assert_eq!(
        issued.user.id, user.id,
        "the outcome carries the logged-in user"
    );
    let issued = issued.session;
    assert_eq!(issued.session.user_id, user.id);
    assert_eq!(session_count(&h, user.id).await, sessions_before + 1);

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    assert!(stored.last_used_at.is_some(), "last_used_at advanced");
    assert_eq!(stored.recovery_cool_down_until, None);

    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasskeyAdded { .. }))
    );
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. }))
    );
}

#[tokio::test]
async fn registration_captures_device_metadata_and_surfaces_it_in_summary() {
    let h = Harness::fresh();
    let user = make_user(&h, "metadata@example.com").await;
    let mut wa = authenticator();

    let passkey = register_passkey(&h, user.id, &mut wa, Some("Alice's Mac")).await;

    assert_eq!(passkey.aaguid, None, "passkey flow yields no AAGUID");

    let summaries = h
        .session_manager
        .list_passkeys(&session_for(&h, &user).await)
        .await
        .expect("list summaries");
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];

    assert_eq!(summary.aaguid, passkey.aaguid);
    assert_eq!(summary.transports, passkey.transports);
    assert_eq!(summary.backup_eligible, passkey.backup_eligible);
    assert_eq!(summary.backup_state, passkey.backup_state);
}

#[tokio::test]
async fn registration_stores_each_reported_transport_once() {
    let h = Harness::fresh();
    let user = make_user(&h, "transports@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start_registration");
    let mut response = wa.do_registration(ccr);
    // The client reports transports outside what the authenticator signs.
    let mut reported = vec![AuthenticatorTransport::Hybrid];
    reported.extend(std::iter::repeat_n(AuthenticatorTransport::Internal, 100));
    reported.push(AuthenticatorTransport::Hybrid);
    response.response.transports = Some(reported);

    let passkey = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect("finish_registration");
    assert_eq!(passkey.transports, ["hybrid", "internal"]);
}

#[tokio::test]
async fn discoverable_authentication_identifies_two_users_from_response() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();

    let alice_passkey = register_passkey(&h, alice.id, &mut wa, Some("alice device")).await;
    let bob_passkey = register_passkey(&h, bob.id, &mut wa, Some("bob device")).await;

    let (bob_challenge, bob_options) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start bob");
    let bob_assertion = wa.do_authentication(bob_options, &bob_passkey.credential_id);
    let bob_issued = h
        .passkey
        .finish_authentication(
            bob_challenge,
            &bob_assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect("finish bob")
        .session;
    assert_eq!(bob_issued.session.user_id, bob.id);

    let (alice_challenge, alice_options) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start alice");
    let alice_assertion = wa.do_authentication(alice_options, &alice_passkey.credential_id);
    let alice_issued = h
        .passkey
        .finish_authentication(
            alice_challenge,
            &alice_assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect("finish alice")
        .session;
    assert_eq!(alice_issued.session.user_id, alice.id);
}

#[tokio::test]
async fn authentication_without_user_handle_is_rejected() {
    let h = Harness::fresh();
    let user = make_user(&h, "fallback@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, options) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication_without_user_handle(options, &passkey.credential_id);

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("missing user handle must be rejected");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(session_count(&h, user.id).await, 0, "no session minted");

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

    let passkey = register_passkey(&h, user.id, &mut wa, None).await;
    assert_eq!(passkey.user_id, user.id, "passkey linked to same user");

    let listed = h
        .session_manager
        .list_passkeys(&session_for(&h, &user).await)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, passkey.credential_id);
}

#[tokio::test]
async fn second_registration_excludes_existing_passkeys() {
    let h = Harness::fresh();
    let user = make_user(&h, "two@example.com").await;
    let mut wa = authenticator();

    register_passkey(&h, user.id, &mut wa, None).await;

    let (_id2, ccr2) = h
        .session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect("start second registration");
    assert_resident_registration_options(&ccr2);
    let excludes = ccr2
        .public_key
        .exclude_credentials
        .expect("previous passkey excluded");
    assert_eq!(excludes.len(), 1, "previous passkey excluded");
}

#[tokio::test]
async fn finish_registration_rejects_unknown_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "ghost@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start");
    let response = wa.do_registration(ccr);
    h.session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect("first finish ok");

    let err = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect_err("replayed challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn an_added_passkey_finishes_only_in_the_session_that_started_it() {
    let h = Harness::fresh();
    let user = make_user(&h, "two-tabs@example.com").await;
    let mut wa = authenticator();
    let started_in = session_for(&h, &user).await;
    let other = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&started_in, request_context())
        .await
        .expect("start");
    let response = wa.do_registration(ccr);

    let err = h
        .session_manager
        .finish_passkey_registration(&other, challenge_id, &response, None, request_context())
        .await
        .expect_err("another session of the same user");
    assert!(
        matches!(err, Error::InvalidPasskeyChallenge),
        "got: {err:?}"
    );
    assert_eq!(passkey_count(&h, user.id).await, 0, "no passkey stored");
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::RegistrationChallenge,
            reason: RedemptionFailureReason::WrongSession,
        } if *id == user.id
    )));
}

#[tokio::test]
async fn finish_registration_rejects_expired_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "slow@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start");
    let response = wa.do_registration(ccr);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::RegistrationChallenge,
            reason: RedemptionFailureReason::Expired,
        } if *id == user.id
    )));
}

#[tokio::test]
async fn finish_registration_rejects_malformed_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "garbled@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start");
    let response = wa.do_registration(ccr);
    let mut stored = h
        .challenges
        .take_registration(challenge_id)
        .await
        .expect("take challenge")
        .expect("challenge present");
    stored.state = b"not a registration state".to_vec();
    h.challenges
        .put_registration(stored)
        .await
        .expect("put challenge");

    let err = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect_err("malformed");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    assert_eq!(passkey_count(&h, user.id).await, 0, "no passkey stored");
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::RegistrationChallenge,
            reason: RedemptionFailureReason::Malformed,
        } if *id == user.id
    )));
}

#[tokio::test]
async fn finish_registration_against_deleted_user_writes_no_orphan_passkey() {
    let h = Harness::fresh();
    let user = make_user(&h, "vanishing@example.com").await;
    let mut wa = authenticator();

    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start");
    let response = wa.do_registration(ccr);

    h.users.delete_user(user.id).await.expect("delete user");

    let err = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect_err("finishing against a deleted user must be rejected");
    assert!(
        matches!(err, Error::InvalidPasskeyChallenge),
        "got: {err:?}"
    );
    assert_eq!(
        passkey_count(&h, user.id).await,
        0,
        "no passkey written against the deleted user"
    );
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::RegistrationChallenge,
            reason: RedemptionFailureReason::UserNotFound,
        } if *id == user.id
    )));
}

#[tokio::test]
async fn finish_authentication_rejects_unknown_passkey() {
    let h = Harness::fresh();
    let user = make_user(&h, "vanish@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

    h.passkeys
        .delete_passkey(&passkey.credential_id)
        .await
        .expect("delete passkey");

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("missing passkey");
    assert!(matches!(err, Error::PasskeyNotFound));
}

#[tokio::test]
async fn finish_authentication_rejects_mismatched_user_handle() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();
    let alice_passkey = register_passkey(&h, alice.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &alice_passkey.credential_id);
    assertion.response.user_handle = Some(bob.id.0.as_bytes().as_slice().into());

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("ownership mismatch");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    for id in [alice.id, bob.id] {
        assert_eq!(
            session_count(&h, id).await,
            0,
            "no session minted on mismatch"
        );
    }

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::UserHandleMismatch,
            } if *uid == alice.id
        )),
        "mismatch audited against the passkey owner"
    );
}

#[tokio::test]
async fn finish_authentication_rejects_tampered_signature() {
    let h = Harness::fresh();
    let user = make_user(&h, "tamper@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &passkey.credential_id);

    let mut signature = assertion.response.signature.as_ref().to_vec();
    signature[0] ^= 0x01;
    assertion.response.signature = signature.as_slice().into();

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("tampered signature must be rejected");
    assert!(matches!(err, Error::Webauthn(_)));
    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "no session minted on a bad assertion"
    );

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::BadAssertion,
            } if *uid == user.id
        )),
        "tampered signature audited as a bad assertion against the owner"
    );
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. })),
        "no login-succeeded event on a tampered assertion"
    );
}

#[tokio::test]
async fn finish_registration_rejects_tampered_attestation() {
    let h = Harness::fresh();
    let user = make_user(&h, "tamper-reg@example.com").await;
    let mut wa = authenticator();

    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start");
    let mut response = wa.do_registration(ccr);

    let mut attestation = response.response.attestation_object.as_ref().to_vec();
    attestation[0] ^= 0x01;
    response.response.attestation_object = attestation.as_slice().into();

    let err = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect_err("tampered attestation must be rejected");
    assert!(matches!(err, Error::Webauthn(_)));
    assert_eq!(
        passkey_count(&h, user.id).await,
        0,
        "no passkey written for a tampered attestation"
    );
}

#[tokio::test]
async fn finish_authentication_rejects_counter_regression_and_audits_it() {
    let h = Harness::fresh();
    let user = make_user(&h, "cloned@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    let mut blob: serde_json::Value =
        serde_json::from_slice(&stored.passkey).expect("blob is json");
    blob["cred"]["counter"] = serde_json::json!(1_000_000u32);
    h.passkeys
        .record_passkey_use(
            &passkey.credential_id,
            PasskeyUse {
                passkey: serde_json::to_vec(&blob).expect("reserialise blob"),
                backup_eligible: stored.backup_eligible,
                backup_state: stored.backup_state,
                used_at: h.clock.now(),
            },
        )
        .await
        .expect("persist bumped counter");

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("counter regression must be rejected");
    assert!(matches!(err, Error::PasskeyPossibleCompromise));
    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "no session minted on regression"
    );

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
async fn finish_authentication_refuses_disabled_user() {
    let h = Harness::fresh();
    let user = make_user(&h, "disabled@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("disabled user must be refused");
    assert!(matches!(err, Error::UserDisabled));
    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "no session minted for a disabled user"
    );

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    assert_eq!(stored.last_used_at, None, "passkey not updated on refusal");

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::UserDisabled,
            } if *uid == user.id
        )),
        "refusal emits a user-disabled audit event"
    );
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. })),
        "no login-succeeded event for a disabled user"
    );

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("challenge redeemed: the refused login cannot be replayed");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn finish_authentication_audits_unknown_passkey_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "gone@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkeys
        .delete_passkey(&passkey.credential_id)
        .await
        .expect("delete passkey");

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("missing passkey");
    assert!(matches!(err, Error::PasskeyNotFound));

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::AuthenticationFailed {
            user_id: None,
            reason: AuthFailureReason::UnknownPasskey,
        }
    )));
}

#[tokio::test]
async fn finish_authentication_audits_expired_challenge_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "stale@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("expired challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: None,
            secret: SecretKind::LoginChallenge,
            reason: RedemptionFailureReason::Expired,
        }
    )));
}

#[tokio::test]
async fn finish_authentication_audits_unknown_challenge_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "noghost@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect("first finish");
    let audit_before = h.audit.events().len();

    let (auth_id2, rcr2) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth 2");
    let assertion2 = wa.do_authentication(rcr2, &passkey.credential_id);
    h.challenges
        .take_authentication(auth_id2)
        .await
        .expect("take challenge")
        .expect("challenge present");

    let err = h
        .passkey
        .finish_authentication(
            auth_id2,
            &assertion2,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("unknown challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));

    let events = kinds(&h.audit.events()[audit_before..]);
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: None,
            secret: SecretKind::LoginChallenge,
            reason: RedemptionFailureReason::Unknown,
        }
    )));
}

#[tokio::test]
async fn finish_authentication_rejects_a_reauth_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "mixup@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, None).await;
    let session = session_for(&h, &user).await;

    let (reauth_id, options) = h
        .session_manager
        .start_reauth(&session, request_context())
        .await
        .expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);
    let sessions_before = session_count(&h, user.id).await;

    let err = h
        .passkey
        .finish_authentication(
            reauth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("a re-authentication challenge cannot log in");
    assert!(
        matches!(err, Error::InvalidPasskeyChallenge),
        "got: {err:?}"
    );
    assert_eq!(
        session_count(&h, user.id).await,
        sessions_before,
        "no session minted"
    );

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: None,
            secret: SecretKind::LoginChallenge,
            reason: RedemptionFailureReason::WrongPurpose,
        }
    )));
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. })),
    );
}

#[tokio::test]
async fn start_authentication_is_usernameless_and_does_not_look_up_email() {
    let h = Harness::fresh();
    let (_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("should succeed without an email");
    assert_discoverable_request_options(&rcr);
}

#[tokio::test]
async fn finish_authentication_rejects_expired_challenge() {
    let h = Harness::fresh();
    let user = make_user(&h, "slow-auth@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("expired challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn remove_passkey_emits_audit_sends_notice_and_blocks_login() {
    let h = Harness::fresh();
    let user = make_user(&h, "remover@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("old phone")).await;
    let session = session_for(&h, &user).await;
    let mail_before = h.email.sent().len();

    h.session_manager
        .perform(
            &session,
            DestructiveAction::RemovePasskey {
                credential_id: passkey.credential_id.clone(),
            },
            None,
            request_context(),
        )
        .await
        .expect("remove");
    assert_eq!(passkey_count(&h, user.id).await, 0);
    let sent = h.email.sent();
    let removal_mail = &sent[mail_before..];
    assert_eq!(removal_mail.len(), 1, "passkey removal notice sent");
    assert_eq!(removal_mail[0].subject, "Security notice: passkey removed");
    assert!(removal_mail[0].body_text.contains("old phone"));
    assert!(removal_mail[0].body_text.contains("If this was not you"));

    let events = kinds(&h.audit.events());
    assert!(
        events
            .iter()
            .any(|k| matches!(k, AuditEventKind::PasskeyRemoved { .. }))
    );
}

#[tokio::test]
async fn remove_passkey_refuses_other_users_passkey_without_notice() {
    let h = Harness::fresh();
    let alice = make_user(&h, "a@example.com").await;
    let bob = make_user(&h, "b@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, alice.id, &mut wa, None).await;
    let bob_session = session_for(&h, &bob).await;
    let mail_before = h.email.sent().len();

    let err = h
        .session_manager
        .perform(
            &bob_session,
            DestructiveAction::RemovePasskey {
                credential_id: passkey.credential_id.clone(),
            },
            None,
            request_context(),
        )
        .await
        .expect_err("ownership check");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(
        passkey_count(&h, alice.id).await,
        1,
        "alice's passkey untouched"
    );
    assert_eq!(h.email.sent().len(), mail_before, "no removal email sent");
}

#[tokio::test]
async fn remove_missing_passkey_sends_no_notice() {
    let h = Harness::fresh();
    let user = make_user(&h, "missing@example.com").await;
    let session = session_for(&h, &user).await;

    let err = h
        .session_manager
        .perform(
            &session,
            DestructiveAction::RemovePasskey {
                credential_id: b"missing passkey".to_vec(),
            },
            None,
            request_context(),
        )
        .await
        .expect_err("missing passkey");
    assert!(matches!(err, Error::PasskeyNotFound));
    assert_eq!(h.email.sent().len(), 0, "no removal email sent");
}

#[tokio::test]
async fn remove_passkey_notice_failure_does_not_undo_removal() {
    let h = Harness::fresh();
    let user = make_user(&h, "remove-failure@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("old phone")).await;
    let session = session_for(&h, &user).await;
    let mail_before = h.email.sent().len();
    h.email.fail_after_successful_sends(mail_before);

    h.session_manager
        .perform(
            &session,
            DestructiveAction::RemovePasskey {
                credential_id: passkey.credential_id.clone(),
            },
            None,
            request_context(),
        )
        .await
        .expect("remove succeeds despite notice failure");

    assert!(
        h.passkeys
            .find_passkey_by_credential_id(&passkey.credential_id)
            .await
            .expect("find passkey")
            .is_none(),
        "passkey was still removed"
    );
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "failed notice was not captured"
    );
}

#[tokio::test]
async fn remove_passkey_refused_during_recovery_cool_down() {
    let h = Harness::fresh();
    let user = make_user(&h, "cool-down@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("only key")).await;
    let cool_down_until = h.clock.now() + ChronoDuration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until).await;
    let mail_before = h.email.sent().len();

    let err = h
        .session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::RemovePasskey {
                credential_id: passkey.credential_id.clone(),
            },
            None,
            request_context(),
        )
        .await
        .expect_err("removal must be refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCoolDownActive));
    assert_eq!(
        passkey_count(&h, user.id).await,
        1,
        "the passkey is left intact"
    );
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no removal notice is sent when the gate trips",
    );

    h.clock.advance(ChronoDuration::hours(25));
    h.session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::RemovePasskey {
                credential_id: passkey.credential_id.clone(),
            },
            None,
            request_context(),
        )
        .await
        .expect("removal allowed once the cool-down lapses");
    assert_eq!(passkey_count(&h, user.id).await, 0);
}

#[tokio::test]
async fn rename_passkey_updates_name_emits_audit_and_sends_no_notice() {
    let h = Harness::fresh();
    let user = make_user(&h, "renamer@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("old phone")).await;
    let session = session_for(&h, &user).await;
    let mail_before = h.email.sent().len();

    let updated = h
        .session_manager
        .rename_passkey(
            &session,
            &passkey.credential_id,
            Some("new phone".into()),
            request_context(),
        )
        .await
        .expect("rename");
    assert_eq!(updated.name.as_deref(), Some("new phone"));

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    assert_eq!(stored.name.as_deref(), Some("new phone"), "name persisted");
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "renaming is cosmetic and sends no notice",
    );

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(
            |k| matches!(k, AuditEventKind::PasskeyRenamed { user_id } if *user_id == user.id)
        )
    );
}

#[tokio::test]
async fn rename_passkey_clears_name_with_none() {
    let h = Harness::fresh();
    let user = make_user(&h, "clearer@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("labelled")).await;
    let session = session_for(&h, &user).await;

    let updated = h
        .session_manager
        .rename_passkey(&session, &passkey.credential_id, None, request_context())
        .await
        .expect("rename");
    assert_eq!(updated.name, None, "name cleared");
}

#[tokio::test]
async fn a_refused_passkey_name_leaves_the_registration_challenge_usable() {
    let h = Harness::fresh();
    let user = make_user(&h, "naming@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let finish = |name: &str| {
        h.session_manager.finish_passkey_registration(
            &session,
            challenge_id,
            &response,
            Some(name.to_owned()),
            request_context(),
        )
    };

    for name in [
        "n".repeat(MAX_PASSKEY_NAME_LEN + 1),
        "nul\u{0}name".to_owned(),
        "line\nbreak".to_owned(),
    ] {
        let err = finish(&name).await.expect_err("name refused");
        assert!(
            matches!(err, Error::InvalidPasskeyName),
            "{name:?}: {err:?}"
        );
    }
    assert_eq!(passkey_count(&h, user.id).await, 0);

    let passkey = finish("  Work laptop  ")
        .await
        .expect("a refused name redeems no challenge");
    assert_eq!(passkey.name.as_deref(), Some("Work laptop"));
}

#[tokio::test]
async fn rename_passkey_trims_the_name_and_refuses_an_invalid_one() {
    let h = Harness::fresh();
    let user = make_user(&h, "trimmer@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("labelled")).await;
    let session = session_for(&h, &user).await;
    let rename = |name: &str| {
        h.session_manager.rename_passkey(
            &session,
            &passkey.credential_id,
            Some(name.to_owned()),
            request_context(),
        )
    };
    let stored_name = || async {
        h.passkeys
            .find_passkey_by_credential_id(&passkey.credential_id)
            .await
            .expect("find passkey")
            .expect("passkey persisted")
            .name
    };

    let at_limit = "\u{e9}".repeat(MAX_PASSKEY_NAME_LEN / 2) + "n";
    assert_eq!(at_limit.len(), MAX_PASSKEY_NAME_LEN);
    let renamed = rename(&at_limit).await.expect("a name at the limit");
    assert_eq!(renamed.name.as_deref(), Some(at_limit.as_str()));

    for name in [format!("\u{e9}{at_limit}"), "bell\u{7}".to_owned()] {
        let err = rename(&name).await.expect_err("name refused");
        assert!(
            matches!(err, Error::InvalidPasskeyName),
            "{name:?}: {err:?}"
        );
        assert_eq!(stored_name().await.as_deref(), Some(at_limit.as_str()));
    }

    let cleared = rename("   ").await.expect("a blank name");
    assert_eq!(cleared.name, None, "a blank name clears it");
    assert_eq!(stored_name().await, None);
}

#[tokio::test]
async fn rename_passkey_refuses_other_users_passkey() {
    let h = Harness::fresh();
    let alice = make_user(&h, "a-rename@example.com").await;
    let bob = make_user(&h, "b-rename@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, alice.id, &mut wa, Some("alice key")).await;
    let bob_session = session_for(&h, &bob).await;

    let err = h
        .session_manager
        .rename_passkey(
            &bob_session,
            &passkey.credential_id,
            Some("pwned".into()),
            request_context(),
        )
        .await
        .expect_err("ownership check");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    assert_eq!(stored.name.as_deref(), Some("alice key"), "name untouched");
}

#[tokio::test]
async fn rename_missing_passkey_fails() {
    let h = Harness::fresh();
    let user = make_user(&h, "missing-rename@example.com").await;
    let session = session_for(&h, &user).await;

    let err = h
        .session_manager
        .rename_passkey(
            &session,
            b"missing passkey",
            Some("ghost".into()),
            request_context(),
        )
        .await
        .expect_err("missing passkey");
    assert!(matches!(err, Error::PasskeyNotFound));
}

#[tokio::test]
async fn rename_passkey_allowed_during_recovery_cool_down() {
    let h = Harness::fresh();
    let user = make_user(&h, "cool-down-rename@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("only key")).await;
    let cool_down_until = h.clock.now() + ChronoDuration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until).await;

    let updated = h
        .session_manager
        .rename_passkey(
            &in_cool_down,
            &passkey.credential_id,
            Some("renamed during cool-down".into()),
            request_context(),
        )
        .await
        .expect("rename allowed during the cool-down");
    assert_eq!(updated.name.as_deref(), Some("renamed during cool-down"));
}

#[tokio::test]
async fn start_registration_from_ordinary_session_carries_no_cool_down() {
    let h = Harness::fresh();
    let user = make_user(&h, "ordinary@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user).await;

    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let passkey = h
        .session_manager
        .finish_passkey_registration(&session, challenge_id, &response, None, request_context())
        .await
        .expect("finish_registration");

    assert_eq!(passkey.recovery_cool_down_until, None);
}

#[tokio::test]
async fn start_registration_for_deleted_user_errors() {
    let h = Harness::fresh();
    let user = make_user(&h, "deleted@example.com").await;
    h.users.delete_user(user.id).await.expect("delete user");
    let err = h
        .session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect_err("unknown user");
    assert!(matches!(err, Error::UserNotFound));
}

#[tokio::test]
async fn start_registration_refuses_disabled_user() {
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_pending_registrations_per_user: NonZeroU32::new(1),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "disabled@example.com").await;
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let err = h
        .session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect_err("disabled user must be refused");
    assert!(matches!(err, Error::UserDisabled));

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Active, now)
        .await
        .expect("re-enable user");
    h.session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect("no ceremony started: the pending budget is untouched");
}

#[tokio::test]
async fn registration_is_rejected_once_passkey_cap_is_reached() {
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_passkeys_per_user: NonZeroU32::new(1),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "cap@example.com").await;
    let mut wa = authenticator();

    register_passkey(&h, user.id, &mut wa, Some("first")).await;
    assert_eq!(passkey_count(&h, user.id).await, 1);

    let session = session_for(&h, &user).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("second start allowed");
    let response = wa.do_registration(ccr);
    let err = h
        .session_manager
        .finish_passkey_registration(
            &session,
            challenge_id,
            &response,
            Some("second".into()),
            request_context(),
        )
        .await
        .expect_err("passkey cap rejects the second registration");
    assert!(matches!(
        err,
        Error::ResourceLimitExceeded {
            resource: "passkeys",
            limit: 1
        }
    ));
    assert_eq!(passkey_count(&h, user.id).await, 1, "no passkey was stored");
}

#[tokio::test]
async fn start_registration_is_rejected_once_pending_challenge_cap_is_reached() {
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_pending_registrations_per_user: NonZeroU32::new(2),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "pending@example.com").await;
    let session = session_for(&h, &user).await;

    let (first_id, first_options) = h
        .session_manager
        .start_passkey_registration(&session, request_context())
        .await
        .expect("first pending allowed");
    h.session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect("second pending allowed");
    let err = h
        .session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect_err("third start rejected at the cap");
    assert!(matches!(
        err,
        Error::ResourceLimitExceeded {
            resource: "pending registrations",
            limit: 2
        }
    ));

    let response = authenticator().do_registration(first_options);
    h.session_manager
        .finish_passkey_registration(&session, first_id, &response, None, request_context())
        .await
        .expect("finish the first ceremony");
    h.session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect("no extra challenge was minted");

    let other = make_user(&h, "pending-other@example.com").await;
    h.session_manager
        .start_passkey_registration(&session_for(&h, &other).await, request_context())
        .await
        .expect("a different user has its own budget");
}

#[tokio::test]
async fn expired_registrations_do_not_count_toward_the_pending_cap() {
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_pending_registrations_per_user: NonZeroU32::new(1),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "abandoned@example.com").await;

    h.session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect("first pending allowed");
    h.clock.advance(ChronoDuration::seconds(301));

    h.session_manager
        .start_passkey_registration(&session_for(&h, &user).await, request_context())
        .await
        .expect("the expired registration no longer holds the only slot");
}

#[tokio::test]
async fn successful_login_records_login_and_latency_metrics() {
    use doorman_core::metrics::MetricEvent;

    let h = Harness::fresh();
    let user = make_user(&h, "metrics@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect("finish auth");

    assert_eq!(
        h.metrics.count(MetricEvent::LoginSucceeded),
        1,
        "one login recorded"
    );
    assert_eq!(
        h.metrics.count(MetricEvent::AuthFailed {
            reason: AuthFailureReason::BadAssertion,
        }),
        0,
        "no failure recorded on the success path"
    );
    assert!(
        h.metrics.has_latency(),
        "auth ceremony latency recorded on success"
    );
}

#[tokio::test]
async fn failed_login_records_auth_failure_and_latency_metrics() {
    use doorman_core::metrics::MetricEvent;

    let h = Harness::fresh();
    let user = make_user(&h, "gone@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkeys
        .delete_passkey(&passkey.credential_id)
        .await
        .expect("delete passkey");

    h.passkey
        .finish_authentication(
            auth_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect_err("missing passkey");

    assert_eq!(
        h.metrics.count(MetricEvent::AuthFailed {
            reason: AuthFailureReason::UnknownPasskey,
        }),
        1,
        "the unknown-passkey rejection is counted"
    );
    assert_eq!(
        h.metrics.count(MetricEvent::LoginSucceeded),
        0,
        "no login recorded on the failure path"
    );
    assert!(
        h.metrics.has_latency(),
        "auth ceremony latency recorded even on rejection"
    );
}

#[tokio::test]
async fn login_and_email_change_report_the_users_passkey_count() {
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();
    let first = register_passkey(&h, user.id, &mut wa, None).await;
    register_passkey(&h, user.id, &mut wa, Some("second")).await;

    let (challenge_id, options) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start login");
    let assertion = wa.do_authentication(options, &first.credential_id);
    let login = h
        .passkey
        .finish_authentication(
            challenge_id,
            &assertion,
            SessionTransport::Cookie,
            request_context(),
        )
        .await
        .expect("finish login");
    assert_eq!(login.passkey_count, 2);

    h.session_manager
        .perform(
            &login.session.session,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            request_context(),
        )
        .await
        .expect("request email change");
    let confirmed = h
        .user
        .confirm_email_change(&last_email_change_token(&h), request_context())
        .await
        .expect("confirm email change");
    assert_eq!(confirmed.passkey_count, 2);
}
