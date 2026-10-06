mod common;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::audit::{AuditEventKind, AuthFailureReason, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::error::Error;
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::passkey::{PasskeyConfig, PasskeyRateLimits};
use doorman_core::rate_limit::{RateLimitPolicy, RateLimiter};
use doorman_core::session::SessionContext;
use doorman_core::storage::{
    PasskeyChallengeStore, PasskeyStore, PasskeyUse, UserStatus, UserStore,
};
use doorman_test_support::MockClock;

use common::{
    Harness, RP_ID, RP_NAME, assert_discoverable_request_options,
    assert_resident_registration_options, authenticator, kinds, make_user, passkey_count,
    register_passkey, rp_origin, session_count, session_for, session_in_cool_down_for, ts,
};

fn base_passkey_config() -> PasskeyConfig {
    PasskeyConfig {
        rate_limits: PasskeyRateLimits::disabled(),
        ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
    }
}

#[tokio::test]
async fn register_then_discoverable_authenticate_round_trip() {
    let h = Harness::fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let passkey = h
        .passkey
        .finish_registration(
            challenge_id,
            &response,
            Some("Alice's Mac".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish_registration");
    assert_eq!(passkey.user_id, user.id);
    assert_eq!(passkey.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(passkey.recovery_cool_down_until, None);
    assert_eq!(passkey_count(&h, user.id).await, 1);
    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect_err("challenge redeemed: the ceremony cannot be replayed");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    let sent = h.email.sent();
    assert_eq!(sent.len(), 1, "passkey registration notice sent");
    assert_eq!(sent[0].subject, "Security notice: passkey registered");
    assert!(sent[0].body_text.contains("Alice's Mac"));

    let (auth_challenge, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start_authentication");
    assert_discoverable_request_options(&rcr);
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

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
    assert_eq!(
        issued.user.id, user.id,
        "the outcome carries the signed-in user"
    );
    let issued = issued.session;
    assert_eq!(issued.session.user_id, user.id);
    assert_eq!(session_count(&h, user.id).await, 1);

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
        .passkey
        .list_passkey_summaries(user.id)
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
async fn discoverable_authentication_identifies_two_users_from_response() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();

    let alice_passkey = register_passkey(&h, alice.id, &mut wa, Some("alice device")).await;
    let bob_passkey = register_passkey(&h, bob.id, &mut wa, Some("bob device")).await;

    let (bob_challenge, bob_options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start bob");
    let bob_assertion = wa.do_authentication(bob_options, &bob_passkey.credential_id);
    let bob_issued = h
        .passkey
        .finish_authentication(bob_challenge, &bob_assertion, SessionContext::default())
        .await
        .expect("finish bob")
        .session;
    assert_eq!(bob_issued.session.user_id, bob.id);

    let (alice_challenge, alice_options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start alice");
    let alice_assertion = wa.do_authentication(alice_options, &alice_passkey.credential_id);
    let alice_issued = h
        .passkey
        .finish_authentication(alice_challenge, &alice_assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication_without_user_handle(options, &passkey.credential_id);

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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

    let listed = h.passkey.list_passkeys(user.id).await.expect("list");
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
        .passkey
        .start_registration(&session_for(&h, &user))
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
    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("start");
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
    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("start");
    let response = wa.do_registration(ccr);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
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
    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
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
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
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

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("start");
    let response = wa.do_registration(ccr);

    h.users.delete_user(user.id).await.expect("delete user");

    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

    h.passkeys
        .delete_passkey(&passkey.credential_id)
        .await
        .expect("delete passkey");

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &alice_passkey.credential_id);
    assertion.response.user_handle = Some(bob.id.0.as_bytes().as_slice().into());

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &passkey.credential_id);

    let mut signature = assertion.response.signature.as_ref().to_vec();
    signature[0] ^= 0x01;
    assertion.response.signature = signature.as_slice().into();

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("start");
    let mut response = wa.do_registration(ccr);

    let mut attestation = response.response.attestation_object.as_ref().to_vec();
    attestation[0] ^= 0x01;
    response.response.attestation_object = attestation.as_slice().into();

    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkeys
        .delete_passkey(&passkey.credential_id)
        .await
        .expect("delete passkey");

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("first finish");
    let audit_before = h.audit.events().len();

    let (auth_id2, rcr2) = h
        .passkey
        .start_authentication(SessionContext::default())
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
        .finish_authentication(auth_id2, &assertion2, SessionContext::default())
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

    let (reauth_id, options) = h.reauth.start(user.id).await.expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);

    let err = h
        .passkey
        .finish_authentication(reauth_id, &assertion, SessionContext::default())
        .await
        .expect_err("a re-authentication challenge cannot log in");
    assert!(
        matches!(err, Error::InvalidPasskeyChallenge),
        "got: {err:?}"
    );
    assert_eq!(session_count(&h, user.id).await, 0, "no session minted");

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
        .start_authentication(SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();

    h.passkey
        .remove_passkey(
            &session,
            &passkey.credential_id,
            None,
            SessionContext::default(),
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
    let bob_session = session_for(&h, &bob);
    let mail_before = h.email.sent().len();

    let err = h
        .passkey
        .remove_passkey(
            &bob_session,
            &passkey.credential_id,
            None,
            SessionContext::default(),
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
    let session = session_for(&h, &user);

    let err = h
        .passkey
        .remove_passkey(
            &session,
            b"missing passkey",
            None,
            SessionContext::default(),
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
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();
    h.email.fail_after_successful_sends(mail_before);

    h.passkey
        .remove_passkey(
            &session,
            &passkey.credential_id,
            None,
            SessionContext::default(),
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
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until);
    let mail_before = h.email.sent().len();

    let err = h
        .passkey
        .remove_passkey(
            &in_cool_down,
            &passkey.credential_id,
            None,
            SessionContext::default(),
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
    h.passkey
        .remove_passkey(
            &in_cool_down,
            &passkey.credential_id,
            None,
            SessionContext::default(),
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
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();

    let updated = h
        .passkey
        .rename_passkey(
            &session,
            &passkey.credential_id,
            Some("new phone".into()),
            SessionContext::default(),
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
    let session = session_for(&h, &user);

    let updated = h
        .passkey
        .rename_passkey(
            &session,
            &passkey.credential_id,
            None,
            SessionContext::default(),
        )
        .await
        .expect("rename");
    assert_eq!(updated.name, None, "name cleared");
}

#[tokio::test]
async fn rename_passkey_refuses_other_users_passkey() {
    let h = Harness::fresh();
    let alice = make_user(&h, "a-rename@example.com").await;
    let bob = make_user(&h, "b-rename@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, alice.id, &mut wa, Some("alice key")).await;
    let bob_session = session_for(&h, &bob);

    let err = h
        .passkey
        .rename_passkey(
            &bob_session,
            &passkey.credential_id,
            Some("pwned".into()),
            SessionContext::default(),
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
    let session = session_for(&h, &user);

    let err = h
        .passkey
        .rename_passkey(
            &session,
            b"missing passkey",
            Some("ghost".into()),
            SessionContext::default(),
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
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until);

    let updated = h
        .passkey
        .rename_passkey(
            &in_cool_down,
            &passkey.credential_id,
            Some("renamed during cool-down".into()),
            SessionContext::default(),
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
    let session = session_for(&h, &user);

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session)
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let passkey = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
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
        .passkey
        .start_registration(&session_for(&h, &user))
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
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect_err("disabled user must be refused");
    assert!(matches!(err, Error::UserDisabled));

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Active, now)
        .await
        .expect("re-enable user");
    h.passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("no ceremony started: the pending budget is untouched");
}

#[tokio::test]
async fn challenge_store_purges_expired_entries() {
    let h = Harness::fresh();
    let user = make_user(&h, "exp@example.com").await;
    h.passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("start registration");
    h.passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start authentication");

    h.clock.advance(ChronoDuration::seconds(600));
    let removed = h
        .challenges
        .purge_expired(h.clock.now())
        .await
        .expect("purge expired");
    assert_eq!(removed, 2, "both ceremonies were stored, then swept");
    let removed_again = h
        .challenges
        .purge_expired(h.clock.now())
        .await
        .expect("purge expired again");
    assert_eq!(removed_again, 0, "nothing is left to sweep");
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

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("second start allowed");
    let response = wa.do_registration(ccr);
    let err = h
        .passkey
        .finish_registration(
            challenge_id,
            &response,
            Some("second".into()),
            SessionContext::default(),
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

    let (first_id, first_options) = h
        .passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("first pending allowed");
    h.passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("second pending allowed");
    let err = h
        .passkey
        .start_registration(&session_for(&h, &user))
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
    h.passkey
        .finish_registration(first_id, &response, None, SessionContext::default())
        .await
        .expect("finish the first ceremony");
    h.passkey
        .start_registration(&session_for(&h, &user))
        .await
        .expect("no extra challenge was minted");

    let other = make_user(&h, "pending-other@example.com").await;
    h.passkey
        .start_registration(&session_for(&h, &other))
        .await
        .expect("a different user has its own budget");
}

#[tokio::test]
async fn authenticate_start_is_rate_limited_per_ip() {
    let limiter = Arc::new(InMemoryRateLimiter::new(
        Arc::new(MockClock::new(ts(2026, 1, 1))) as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let h = Harness::builder()
        .signup_limiter(limiter)
        .passkey_config(PasskeyConfig {
            rate_limits: PasskeyRateLimits {
                authenticate_start_per_ip: Some(RateLimitPolicy::new(
                    1,
                    Duration::from_secs(60 * 60),
                )),
                ..PasskeyRateLimits::disabled()
            },
            ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
        })
        .build();

    let from = |ip: &str| SessionContext {
        ip: Some(ip.to_string()),
        user_agent: None,
    };

    h.passkey
        .start_authentication(from("1.2.3.4"))
        .await
        .expect("first attempt within budget");
    let err = h
        .passkey
        .start_authentication(from("1.2.3.4"))
        .await
        .expect_err("second attempt from same ip is limited");
    assert!(matches!(err, Error::RateLimited { .. }));

    h.passkey
        .start_authentication(from("5.6.7.8"))
        .await
        .expect("different ip is unaffected");
}

#[tokio::test]
async fn authenticate_finish_is_rate_limited_per_passkey() {
    let limiter = Arc::new(InMemoryRateLimiter::new(
        Arc::new(MockClock::new(ts(2026, 1, 1))) as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let h = Harness::builder()
        .signup_limiter(limiter)
        .passkey_config(PasskeyConfig {
            rate_limits: PasskeyRateLimits {
                authenticate_finish_per_passkey: Some(RateLimitPolicy::new(
                    1,
                    Duration::from_secs(60 * 60),
                )),
                ..PasskeyRateLimits::disabled()
            },
            ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
        })
        .build();
    let user = make_user(&h, "finish-rl@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("device")).await;

    let (id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start one");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkey
        .finish_authentication(id, &assertion, SessionContext::default())
        .await
        .expect("first finish within budget");

    let (id2, rcr2) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start two");
    let assertion2 = wa.do_authentication(rcr2, &passkey.credential_id);
    let err = h
        .passkey
        .finish_authentication(id2, &assertion2, SessionContext::default())
        .await
        .expect_err("second finish for the same passkey is limited");
    assert!(matches!(err, Error::RateLimited { .. }));
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &passkey.credential_id);
    h.passkeys
        .delete_passkey(&passkey.credential_id)
        .await
        .expect("delete passkey");

    h.passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
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
