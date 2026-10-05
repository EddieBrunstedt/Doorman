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
    AccountStatus, PasskeyChallengeStore, PasskeyCredentialStore, PasskeyUse, UserId, UserStore,
};
use doorman_test_support::MockClock;

use common::{
    Harness, RP_ID, RP_NAME, assert_discoverable_request_options,
    assert_resident_registration_options, authenticator, kinds, make_user, passkey_count,
    register_passkey, restricted_session_for, rp_origin, session_count, session_for, ts,
};

/// A [`PasskeyConfig`] matching the harness relying party but with the
/// authentication-ceremony rate limits off, so a cap / rate-limit test only
/// exercises the one knob it sets.
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
        .start_registration(user.id)
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let credential = h
        .passkey
        .finish_registration(
            challenge_id,
            &response,
            Some("Alice's Mac".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish_registration");
    assert_eq!(credential.user_id, user.id);
    assert_eq!(credential.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(credential.recovery_cooldown_until, None);
    assert_eq!(passkey_count(&h, user.id).await, 1);
    let err = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect_err("challenge consumed: the ceremony cannot be replayed");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    let sent = h.email.sent();
    assert_eq!(sent.len(), 1, "passkey registration notification sent");
    assert_eq!(sent[0].subject, "Security notice: passkey registered");
    assert!(sent[0].body_text.contains("Alice's Mac"));

    let (auth_challenge, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
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
    assert_eq!(
        issued.user.id, user.id,
        "the outcome carries the signed-in user"
    );
    let issued = issued.session;
    assert_eq!(issued.session.user_id, user.id);
    assert_eq!(session_count(&h, user.id).await, 1);

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
async fn registration_captures_device_metadata_and_surfaces_it_in_summary() {
    // The metadata a management UI needs (AAGUID, transports, and the
    // backup-eligibility/state flags) is captured at registration and
    // surfaced through the metadata-only summary projection without touching
    // the credential blob.
    let h = Harness::fresh();
    let user = make_user(&h, "metadata@example.com").await;
    let mut wa = authenticator();

    let credential = register_passkey(&h, user.id, &mut wa, Some("Alice's Mac")).await;

    // Passkey registration requests no attestation, so no AAGUID is produced.
    assert_eq!(credential.aaguid, None, "passkey flow yields no AAGUID");

    let summaries = h
        .passkey
        .list_passkey_summaries(user.id)
        .await
        .expect("list summaries");
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];

    // The summary carries the exact metadata captured on the stored credential
    // — proving it is both captured at registration and surfaced on the
    // listing path.
    assert_eq!(summary.aaguid, credential.aaguid);
    assert_eq!(summary.transports, credential.transports);
    assert_eq!(summary.backup_eligible, credential.backup_eligible);
    assert_eq!(summary.backup_state, credential.backup_state);
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

    let (bob_challenge, bob_options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start bob");
    let bob_assertion = wa.do_authentication(bob_options, &bob_credential.credential_id);
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
    let alice_assertion = wa.do_authentication(alice_options, &alice_credential.credential_id);
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
    // Discoverable auth must assert a user handle that maps to the
    // credential owner. An authenticator that omits it leaves the
    // credential-to-user binding unverified, so the login is refused even
    // though the credential id resolves.
    let h = Harness::fresh();
    let user = make_user(&h, "fallback@example.com").await;
    let mut wa = authenticator();
    let credential = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication_without_user_handle(options, &credential.credential_id);

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
async fn finish_registration_against_deleted_user_writes_no_orphan_credential() {
    // A user deleted after the ceremony began (e.g. a concurrent operator
    // delete) must not have a credential written against them: redeeming the
    // challenge re-checks the user still exists, and a challenge whose owner is
    // gone reads as invalid.
    let h = Harness::fresh();
    let user = make_user(&h, "vanishing@example.com").await;
    let mut wa = authenticator();

    let (challenge_id, ccr) = h.passkey.start_registration(user.id).await.expect("start");
    let response = wa.do_registration(ccr);

    // Delete the user out from under the in-flight ceremony.
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
        "no credential written against the deleted user"
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
async fn finish_authentication_rejects_unknown_credential() {
    let h = Harness::fresh();
    let user = make_user(&h, "vanish@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
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

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &alice_credential.credential_id);
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
        "mismatch audited against the credential owner"
    );
}

#[tokio::test]
async fn finish_authentication_rejects_tampered_signature() {
    // Flip a byte of the assertion signature after the authenticator produced
    // it: the user handle still resolves the owner, but webauthn-rs's signature
    // check fails, so no session is minted and the failure is audited against
    // the credential owner as a bad assertion.
    let h = Harness::fresh();
    let user = make_user(&h, "tamper@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &cred.credential_id);

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
    // Corrupting the attestation response after the authenticator signed it
    // must abort the ceremony: webauthn-rs rejects the credential and nothing
    // is written to the store.
    let h = Harness::fresh();
    let user = make_user(&h, "tamper-reg@example.com").await;
    let mut wa = authenticator();

    let (challenge_id, ccr) = h.passkey.start_registration(user.id).await.expect("start");
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
        "no credential written for a tampered attestation"
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

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&cred.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    let mut blob: serde_json::Value =
        serde_json::from_slice(&stored.passkey).expect("blob is json");
    blob["cred"]["counter"] = serde_json::json!(1_000_000u32);
    h.credentials
        .record_passkey_use(
            &cred.credential_id,
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
    let assertion = wa.do_authentication(rcr, &cred.credential_id);

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
async fn finish_authentication_refuses_disabled_account() {
    let h = Harness::fresh();
    let user = make_user(&h, "frozen@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("disabled account must be refused");
    assert!(matches!(err, Error::AccountDisabled));
    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "no session minted for a disabled account"
    );

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&cred.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    assert_eq!(
        stored.last_used_at, None,
        "credential not updated on refusal"
    );

    let events = kinds(&h.audit.events());
    assert!(
        events.iter().any(|k| matches!(
            k,
            AuditEventKind::AuthenticationFailed {
                user_id: Some(uid),
                reason: AuthFailureReason::AccountDisabled,
            } if *uid == user.id
        )),
        "refusal emits an account-disabled audit event"
    );
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, AuditEventKind::LoginSucceeded { .. })),
        "no login-succeeded event for a disabled account"
    );

    let err = h
        .passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("challenge consumed: the refused login cannot be replayed");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn finish_authentication_audits_unknown_credential_failure() {
    let h = Harness::fresh();
    let user = make_user(&h, "gone@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
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

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
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
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    // Consume the challenge once, then replay against the now-empty store.
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
        AuditEventKind::RedemptionFailed {
            user_id: None,
            secret: SecretKind::LoginChallenge,
            reason: RedemptionFailureReason::Unknown,
        }
    )));
}

#[tokio::test]
async fn finish_authentication_rejects_a_reauth_challenge() {
    // Sign-in and re-authentication share one challenge table. A
    // re-authentication challenge presented to sign-in is refused as an
    // invalid challenge — not an internal decode error — and mints nothing.
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
        .expect_err("a re-authentication challenge cannot sign in");
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
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
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
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();

    h.passkey
        .remove_passkey(
            &session,
            &cred.credential_id,
            None,
            SessionContext::default(),
        )
        .await
        .expect("remove");
    assert_eq!(passkey_count(&h, user.id).await, 0);
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
    let bob_session = session_for(&h, &bob);
    let mail_before = h.email.sent().len();

    let err = h
        .passkey
        .remove_passkey(
            &bob_session,
            &cred.credential_id,
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
async fn remove_missing_passkey_sends_no_notification() {
    let h = Harness::fresh();
    let user = make_user(&h, "missing@example.com").await;
    let session = session_for(&h, &user);

    let err = h
        .passkey
        .remove_passkey(
            &session,
            b"missing credential",
            None,
            SessionContext::default(),
        )
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
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();
    h.email.fail_after_successful_sends(mail_before);

    h.passkey
        .remove_passkey(
            &session,
            &cred.credential_id,
            None,
            SessionContext::default(),
        )
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
async fn remove_passkey_refused_during_recovery_cooldown() {
    // The cool-down gate lives in the manager, so a restricted session is
    // refused even when driving core directly — a phished recovery session
    // must not be able to strip the owner's remaining passkeys. (F1)
    let h = Harness::fresh();
    let user = make_user(&h, "locked@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, Some("only key")).await;
    let cooldown_until = h.clock.now() + ChronoDuration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);
    let mail_before = h.email.sent().len();

    let err = h
        .passkey
        .remove_passkey(
            &restricted,
            &cred.credential_id,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("removal must be refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive));
    assert_eq!(
        passkey_count(&h, user.id).await,
        1,
        "the passkey is left intact"
    );
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no removal notification is sent when the gate trips",
    );

    // Once the cool-down lapses, the same session can remove the passkey.
    h.clock.advance(ChronoDuration::hours(25));
    h.passkey
        .remove_passkey(
            &restricted,
            &cred.credential_id,
            None,
            SessionContext::default(),
        )
        .await
        .expect("removal allowed once the cool-down lapses");
    assert_eq!(passkey_count(&h, user.id).await, 0);
}

#[tokio::test]
async fn rename_passkey_updates_name_emits_audit_and_sends_no_notification() {
    let h = Harness::fresh();
    let user = make_user(&h, "renamer@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, Some("old phone")).await;
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();

    let updated = h
        .passkey
        .rename_passkey(
            &session,
            &cred.credential_id,
            Some("new phone".into()),
            SessionContext::default(),
        )
        .await
        .expect("rename");
    assert_eq!(updated.name.as_deref(), Some("new phone"));

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&cred.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    assert_eq!(stored.name.as_deref(), Some("new phone"), "name persisted");
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "renaming is cosmetic and sends no notification",
    );

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(
        |k| matches!(k, AuditEventKind::CredentialRenamed { user_id } if *user_id == user.id)
    ));
}

#[tokio::test]
async fn rename_passkey_clears_name_with_none() {
    let h = Harness::fresh();
    let user = make_user(&h, "clearer@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, Some("labelled")).await;
    let session = session_for(&h, &user);

    let updated = h
        .passkey
        .rename_passkey(
            &session,
            &cred.credential_id,
            None,
            SessionContext::default(),
        )
        .await
        .expect("rename");
    assert_eq!(updated.name, None, "name cleared");
}

#[tokio::test]
async fn rename_passkey_refuses_other_users_credential() {
    let h = Harness::fresh();
    let alice = make_user(&h, "a-rename@example.com").await;
    let bob = make_user(&h, "b-rename@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, alice.id, &mut wa, Some("alice key")).await;
    let bob_session = session_for(&h, &bob);

    let err = h
        .passkey
        .rename_passkey(
            &bob_session,
            &cred.credential_id,
            Some("pwned".into()),
            SessionContext::default(),
        )
        .await
        .expect_err("ownership check");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&cred.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
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
            b"missing credential",
            Some("ghost".into()),
            SessionContext::default(),
        )
        .await
        .expect_err("missing credential");
    assert!(matches!(err, Error::PasskeyNotFound));
}

#[tokio::test]
async fn rename_passkey_allowed_during_recovery_cooldown() {
    // Renaming is cosmetic, so unlike removal it is *not* gated by the
    // post-recovery cool-down: a relabel cannot lock the owner out or strip
    // access, so there is nothing for the gate to protect against.
    let h = Harness::fresh();
    let user = make_user(&h, "cooldown-rename@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, Some("only key")).await;
    let cooldown_until = h.clock.now() + ChronoDuration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    let updated = h
        .passkey
        .rename_passkey(
            &restricted,
            &cred.credential_id,
            Some("renamed during cooldown".into()),
            SessionContext::default(),
        )
        .await
        .expect("rename allowed during the cool-down");
    assert_eq!(updated.name.as_deref(), Some("renamed during cooldown"));
}

#[tokio::test]
async fn start_registration_for_session_propagates_active_cooldown() {
    // A passkey enrolled while the acting session is locked down must inherit
    // the same deadline, so it cannot be used to escape the cool-down. Deriving
    // this in core (not the transport) is the point of `for_session`. (F1)
    let h = Harness::fresh();
    let user = make_user(&h, "reenroll@example.com").await;
    let mut wa = authenticator();
    let cooldown_until = h.clock.now() + ChronoDuration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    let (challenge_id, ccr) = h
        .passkey
        .start_registration_for_session(&restricted)
        .await
        .expect("start_registration_for_session");
    let response = wa.do_registration(ccr);
    let credential = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("finish_registration");

    assert_eq!(
        credential.recovery_cooldown_until,
        Some(cooldown_until),
        "the new passkey inherits the session's active cool-down",
    );
}

#[tokio::test]
async fn start_registration_for_session_without_cooldown_is_unrestricted() {
    // An ordinary session carries no cool-down, so the registered passkey is
    // unrestricted — and an *expired* cool-down is likewise not propagated.
    let h = Harness::fresh();
    let user = make_user(&h, "ordinary@example.com").await;
    let mut wa = authenticator();
    let session = session_for(&h, &user);

    let (challenge_id, ccr) = h
        .passkey
        .start_registration_for_session(&session)
        .await
        .expect("start_registration_for_session");
    let response = wa.do_registration(ccr);
    let credential = h
        .passkey
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("finish_registration");

    assert_eq!(credential.recovery_cooldown_until, None);
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
async fn start_registration_refuses_disabled_account() {
    // A pending-registration cap of one makes a leftover ceremony observable:
    // had the refused start minted a challenge, the start after re-enabling
    // would hit the cap.
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_pending_registrations_per_user: NonZeroU32::new(1),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "frozen@example.com").await;
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let err = h
        .passkey
        .start_registration(user.id)
        .await
        .expect_err("disabled account must be refused");
    assert!(matches!(err, Error::AccountDisabled));

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Active, now)
        .await
        .expect("re-enable user");
    h.passkey
        .start_registration(user.id)
        .await
        .expect("no ceremony started: the pending budget is untouched");
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
async fn registration_is_rejected_once_credential_cap_is_reached() {
    // Cap of one credential: the first registration succeeds, the second is
    // rejected rather than silently dropping the existing passkey.
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_credentials_per_user: NonZeroU32::new(1),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "cap@example.com").await;
    let mut wa = authenticator();

    register_passkey(&h, user.id, &mut wa, Some("first")).await;
    assert_eq!(passkey_count(&h, user.id).await, 1);

    let (challenge_id, ccr) = h
        .passkey
        .start_registration(user.id)
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
        .expect_err("credential cap rejects the second registration");
    assert!(matches!(
        err,
        Error::ResourceLimitExceeded {
            resource: "credentials",
            limit: 1
        }
    ));
    assert_eq!(
        passkey_count(&h, user.id).await,
        1,
        "no credential was stored"
    );
}

#[tokio::test]
async fn start_registration_is_rejected_once_pending_challenge_cap_is_reached() {
    // Cap of two outstanding registration ceremonies: a foothold cannot grow
    // the challenge table without bound by repeatedly calling start.
    let h = Harness::builder()
        .passkey_config(PasskeyConfig {
            max_pending_registrations_per_user: NonZeroU32::new(2),
            ..base_passkey_config()
        })
        .build();
    let user = make_user(&h, "pending@example.com").await;

    let (first_id, first_options) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("first pending allowed");
    h.passkey
        .start_registration(user.id)
        .await
        .expect("second pending allowed");
    let err = h
        .passkey
        .start_registration(user.id)
        .await
        .expect_err("third start rejected at the cap");
    assert!(matches!(
        err,
        Error::ResourceLimitExceeded {
            resource: "pending registrations",
            limit: 2
        }
    ));

    // Finishing one ceremony frees exactly one slot. Had the rejected start
    // minted a challenge, two would still be pending and this start would fail.
    let response = authenticator().do_registration(first_options);
    h.passkey
        .finish_registration(first_id, &response, None, SessionContext::default())
        .await
        .expect("finish the first ceremony");
    h.passkey
        .start_registration(user.id)
        .await
        .expect("no extra challenge was minted");

    // The cap is per user: a different user is unaffected.
    let other = make_user(&h, "pending-other@example.com").await;
    h.passkey
        .start_registration(other.id)
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

    // A different source IP has its own budget.
    h.passkey
        .start_authentication(from("5.6.7.8"))
        .await
        .expect("different ip is unaffected");
}

#[tokio::test]
async fn authenticate_finish_is_rate_limited_per_credential() {
    // The per-credential finish limit applies even without a client IP: a
    // flood pounding one credential is throttled by the credential dimension.
    let limiter = Arc::new(InMemoryRateLimiter::new(
        Arc::new(MockClock::new(ts(2026, 1, 1))) as Arc<dyn Clock>,
    )) as Arc<dyn RateLimiter>;
    let h = Harness::builder()
        .signup_limiter(limiter)
        .passkey_config(PasskeyConfig {
            rate_limits: PasskeyRateLimits {
                authenticate_finish_per_credential: Some(RateLimitPolicy::new(
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
    let credential = register_passkey(&h, user.id, &mut wa, Some("device")).await;

    // First full ceremony: the finish charges the credential once and succeeds.
    let (id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start one");
    let assertion = wa.do_authentication(rcr, &credential.credential_id);
    h.passkey
        .finish_authentication(id, &assertion, SessionContext::default())
        .await
        .expect("first finish within budget");

    // Second ceremony: the per-credential budget is now exhausted, so the
    // finish is rejected before the single-use challenge is even consumed.
    let (id2, rcr2) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start two");
    let assertion2 = wa.do_authentication(rcr2, &credential.credential_id);
    let err = h
        .passkey
        .finish_authentication(id2, &assertion2, SessionContext::default())
        .await
        .expect_err("second finish for the same credential is limited");
    assert!(matches!(err, Error::RateLimited { .. }));
}

#[tokio::test]
async fn successful_login_records_login_and_latency_metrics() {
    use doorman_core::metrics::MetricEvent;

    let h = Harness::fresh();
    let user = make_user(&h, "metrics@example.com").await;
    let mut wa = authenticator();
    let credential = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &credential.credential_id);
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
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    h.credentials
        .delete_passkey(&cred.credential_id)
        .await
        .expect("delete credential");

    h.passkey
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("missing credential");

    assert_eq!(
        h.metrics.count(MetricEvent::AuthFailed {
            reason: AuthFailureReason::UnknownCredential,
        }),
        1,
        "the unknown-credential rejection is counted"
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
