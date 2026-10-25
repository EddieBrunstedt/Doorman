use crate::common;

use doorman_core::Error;
use doorman_core::audit::{AuditEventKind, AuthFailureReason, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::destructive::{CurrentSession, DestructiveAction};
use doorman_core::reauth::{ReauthAction, ReauthPolicy, ReauthProof};
use doorman_core::session::ResolvedSession;
use doorman_core::storage::{
    PasskeyStore, SessionId, SessionStore, StoredPasskey, UserStatus, UserStore,
};
use doorman_test_support::request_context;

use crate::common::{
    Harness, authenticator, kinds, make_user, register_passkey, session_for,
    session_in_cool_down_for, sign_in,
};

fn every_action(other_session: SessionId, spare_passkey: &[u8]) -> [DestructiveAction; 6] {
    let listed = |action: DestructiveAction| match action {
        DestructiveAction::DeleteUser
        | DestructiveAction::RequestEmailChange { .. }
        | DestructiveAction::RemovePasskey { .. }
        | DestructiveAction::RevokeSession { .. }
        | DestructiveAction::RevokeOtherSessions
        | DestructiveAction::LogOutEverywhere => action,
    };
    [
        DestructiveAction::DeleteUser,
        DestructiveAction::RequestEmailChange {
            new_email: "new@example.com".into(),
        },
        DestructiveAction::RemovePasskey {
            credential_id: spare_passkey.to_vec(),
        },
        DestructiveAction::RevokeSession { id: other_session },
        DestructiveAction::RevokeOtherSessions,
        DestructiveAction::LogOutEverywhere,
    ]
    .map(listed)
}

fn gated_harness() -> Harness {
    Harness::builder()
        .reauth_policy(ReauthPolicy::required_for([
            ReauthAction::DeleteUser,
            ReauthAction::RequestEmailChange,
            ReauthAction::RemovePasskey,
            ReauthAction::RevokeOtherSessions,
            ReauthAction::RevokeSession,
        ]))
        .build()
}

async fn perform(
    h: &Harness,
    session: &ResolvedSession,
    action: DestructiveAction,
    proof: Option<ReauthProof>,
) -> Result<CurrentSession, Error> {
    h.session_manager
        .perform(session, action, proof, request_context())
        .await
}

async fn fresh_proof(
    h: &Harness,
    session: &ResolvedSession,
    wa: &mut common::ResidentAuthenticator,
) -> ReauthProof {
    let (challenge_id, options) = h
        .session_manager
        .start_reauth(session)
        .await
        .expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);
    ReauthProof {
        challenge_id,
        assertion,
    }
}

#[tokio::test]
async fn every_destructive_action_refuses_cool_down_before_the_policy_asks_for_a_proof() {
    for gated in [false, true] {
        for index in 0..6 {
            let h = if gated {
                gated_harness()
            } else {
                Harness::fresh()
            };
            let mut alice = sign_in(&h, "owner@example.com").await;
            let other = alice.log_in_again(&h).await;
            let spare =
                register_passkey(&h, alice.user.id, &mut alice.authenticator, Some("spare")).await;
            let action = every_action(other.session.id, &spare.credential_id)[index].clone();
            let current = alice.session.session.clone();
            let policy = if gated { "gated" } else { "disabled" };

            let cool_down_until = h.clock.now() + chrono::Duration::hours(1);
            let in_cool_down = session_in_cool_down_for(&h, &alice.user, cool_down_until).await;
            let proof = fresh_proof(&h, &in_cool_down, &mut alice.authenticator).await;
            let refused = perform(&h, &in_cool_down, action.clone(), Some(proof)).await;
            assert!(
                matches!(refused, Err(Error::RecoveryCoolDownActive)),
                "{action:?} in cool-down under {policy} policy: got {refused:?}",
            );

            let proof = if gated {
                let refused = perform(&h, &current, action.clone(), None).await;
                assert!(
                    matches!(refused, Err(Error::ReauthRequired)),
                    "{action:?} without a proof under {policy} policy: got {refused:?}",
                );
                Some(fresh_proof(&h, &current, &mut alice.authenticator).await)
            } else {
                None
            };
            perform(&h, &current, action.clone(), proof)
                .await
                .unwrap_or_else(|err| panic!("{action:?} under {policy} policy: {err:?}"));
        }
    }
}

#[tokio::test]
async fn gated_action_with_fresh_proof_succeeds_and_audits() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user).await;

    let proof = fresh_proof(&h, &session, &mut wa).await;
    h.session_manager
        .perform(
            &session,
            DestructiveAction::DeleteUser,
            Some(proof),
            request_context(),
        )
        .await
        .expect("delete succeeds with a fresh proof");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_none(),
        "the user is deleted"
    );
    assert!(
        kinds(&h.audit.events()).iter().any(
            |k| matches!(k, AuditEventKind::ReauthSucceeded { user_id } if *user_id == user.id)
        ),
        "a ReauthSucceeded row is emitted"
    );
}

#[tokio::test]
async fn successful_reauth_records_the_passkey_use() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    let registered = register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user).await;
    h.clock.advance(chrono::Duration::minutes(1));

    let proof = fresh_proof(&h, &session, &mut wa).await;
    perform(
        &h,
        &session,
        DestructiveAction::RevokeOtherSessions,
        Some(proof),
    )
    .await
    .expect("a fresh proof passes");

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&registered.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    assert_eq!(
        stored.last_used_at,
        Some(h.clock.now()),
        "last_used_at advanced"
    );
    assert!(
        signature_counter(&stored) > signature_counter(&registered),
        "the stored signature counter advanced"
    );
}

#[tokio::test]
async fn reauth_refuses_a_disabled_users_passkey() {
    let h = gated_harness();
    let user = make_user(&h, "disabled@example.com").await;
    let mut wa = authenticator();
    let registered = register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user).await;
    let proof = fresh_proof(&h, &session, &mut wa).await;

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let err = perform(
        &h,
        &session,
        DestructiveAction::RevokeOtherSessions,
        Some(proof),
    )
    .await
    .expect_err("a disabled user cannot re-authenticate");
    assert!(matches!(err, Error::UserDisabled), "got: {err:?}");

    let stored = h
        .passkeys
        .find_passkey_by_credential_id(&registered.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted");
    assert_eq!(stored.last_used_at, None, "a refused proof records no use");
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::ReauthFailed {
            user_id,
            reason: AuthFailureReason::UserDisabled,
        } if *user_id == user.id
    )));
}

fn signature_counter(passkey: &StoredPasskey) -> u64 {
    let blob: serde_json::Value = serde_json::from_slice(&passkey.passkey).expect("blob is json");
    blob["cred"]["counter"]
        .as_u64()
        .expect("the stored passkey carries a counter")
}

#[tokio::test]
async fn challenge_is_single_use() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user).await;

    let proof = fresh_proof(&h, &session, &mut wa).await;
    register_passkey(&h, user.id, &mut wa, Some("second")).await;
    let passkeys = h
        .session_manager
        .list_passkeys(&session)
        .await
        .expect("list");
    let target = passkeys[0].credential_id.clone();

    h.session_manager
        .perform(
            &session,
            DestructiveAction::RemovePasskey {
                credential_id: target,
            },
            Some(proof.clone()),
            request_context(),
        )
        .await
        .expect("first use succeeds");

    let other = passkeys[1].credential_id.clone();
    let err = h
        .session_manager
        .perform(
            &session,
            DestructiveAction::RemovePasskey {
                credential_id: other,
            },
            Some(proof),
            request_context(),
        )
        .await
        .expect_err("replayed challenge must be rejected");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
}

#[tokio::test]
async fn login_challenge_is_not_a_reauth_proof() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    let passkey = register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user).await;

    let (challenge_id, options) = h
        .passkey
        .start_authentication(request_context())
        .await
        .expect("start login");
    let assertion = wa.do_authentication(options, &passkey.credential_id);

    let err = h
        .session_manager
        .perform(
            &session,
            DestructiveAction::DeleteUser,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            request_context(),
        )
        .await
        .expect_err("a login challenge cannot re-authenticate");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_some(),
        "the user survives"
    );
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::ReauthChallenge,
            reason: RedemptionFailureReason::WrongPurpose,
        } if *id == user.id
    )));
}

#[tokio::test]
async fn a_proof_started_in_another_session_is_refused() {
    let h = gated_harness();
    let mut alice = sign_in(&h, "owner@example.com").await;
    let other = alice.log_in_again(&h).await;
    let current = alice.session.session.clone();

    let proof = fresh_proof(&h, &other.session, &mut alice.authenticator).await;
    let err = perform(
        &h,
        &current,
        DestructiveAction::DeleteUser,
        Some(proof.clone()),
    )
    .await;
    assert!(matches!(err, Err(Error::ReauthRequired)), "got: {err:?}");
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::ReauthChallenge,
            reason: RedemptionFailureReason::WrongSession,
        } if *id == alice.user.id
    )));

    let err = perform(
        &h,
        &other.session,
        DestructiveAction::DeleteUser,
        Some(proof),
    )
    .await;
    assert!(
        matches!(err, Err(Error::ReauthRequired)),
        "the refused attempt redeemed the challenge: got {err:?}"
    );
    assert!(
        h.users
            .find_user_by_id(alice.user.id)
            .await
            .expect("lookup")
            .is_some(),
        "the user survives"
    );
}

#[tokio::test]
async fn expired_challenge_is_rejected() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user).await;

    let (challenge_id, options) = h
        .session_manager
        .start_reauth(&session)
        .await
        .expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);
    h.clock.advance(chrono::Duration::minutes(6));

    let err = h
        .session_manager
        .perform(
            &session,
            DestructiveAction::DeleteUser,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            request_context(),
        )
        .await
        .expect_err("expired challenge must be rejected");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
    assert!(
        kinds(&h.audit.events()).iter().any(|k| matches!(
            k,
            AuditEventKind::RedemptionFailed {
                user_id: Some(id),
                secret: SecretKind::ReauthChallenge,
                reason: RedemptionFailureReason::Expired,
            } if *id == user.id
        )),
        "an expired-challenge RedemptionFailed row is emitted"
    );
}

#[tokio::test]
async fn assertion_from_another_users_passkey_is_rejected() {
    let h = gated_harness();
    let owner = make_user(&h, "owner@example.com").await;
    let attacker = make_user(&h, "attacker@example.com").await;
    let mut owner_wa = authenticator();
    register_passkey(&h, owner.id, &mut owner_wa, Some("owner device")).await;
    let mut attacker_wa = authenticator();
    register_passkey(&h, attacker.id, &mut attacker_wa, Some("attacker device")).await;
    let owner_session = session_for(&h, &owner).await;

    let attacker_passkey = h
        .passkeys
        .list_passkeys_for_user(attacker.id)
        .await
        .expect("list")[0]
        .credential_id
        .clone();
    let (challenge_id, options) = h
        .session_manager
        .start_reauth(&owner_session)
        .await
        .expect("reauth start");
    let assertion = attacker_wa.do_scoped_authentication(scoped_to(options, &attacker_passkey));

    let err = h
        .session_manager
        .perform(
            &owner_session,
            DestructiveAction::DeleteUser,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            request_context(),
        )
        .await
        .expect_err("an assertion from another user's passkey must be rejected");
    assert!(
        matches!(err, Error::Webauthn(_) | Error::PasskeyOwnershipMismatch),
        "got: {err:?}"
    );
    assert!(
        h.users
            .find_user_by_id(owner.id)
            .await
            .expect("lookup")
            .is_some(),
        "the owner is untouched"
    );
    assert!(
        kinds(&h.audit.events())
            .iter()
            .any(|k| matches!(k, AuditEventKind::ReauthFailed { .. })),
        "a ReauthFailed row is emitted"
    );
}

fn scoped_to(
    mut options: webauthn_rs::prelude::RequestChallengeResponse,
    credential_id: &[u8],
) -> webauthn_rs::prelude::RequestChallengeResponse {
    use webauthn_rs_proto::AllowCredentials;
    options.public_key.allow_credentials = vec![AllowCredentials {
        type_: "public-key".to_string(),
        id: credential_id.to_vec().into(),
        transports: None,
    }];
    options
}

#[derive(Debug, Clone, Copy)]
enum EndActingSession {
    LogOut,
    RevokeIt,
}

#[tokio::test]
async fn ending_the_acting_session_passes_no_gate() {
    for way in [EndActingSession::LogOut, EndActingSession::RevokeIt] {
        for in_cool_down in [false, true] {
            let h = gated_harness();
            let alice = sign_in(&h, "owner@example.com").await;
            let current = if in_cool_down {
                let until = h.clock.now() + chrono::Duration::hours(1);
                session_in_cool_down_for(&h, &alice.user, until).await
            } else {
                alice.session.session.clone()
            };
            let mail_before = h.email.sent().len();

            let ended = match way {
                EndActingSession::LogOut => h
                    .session_manager
                    .log_out(&current, request_context())
                    .await
                    .map(|()| CurrentSession::Ended),
                EndActingSession::RevokeIt => {
                    let action = DestructiveAction::RevokeSession { id: current.id };
                    perform(&h, &current, action, None).await
                }
            };

            let case = format!("{way:?}, in cool-down: {in_cool_down}");
            assert!(
                matches!(ended, Ok(CurrentSession::Ended)),
                "{case}: {ended:?}"
            );
            assert!(
                h.sessions
                    .find_session_by_id(current.id)
                    .await
                    .expect("find session")
                    .is_none(),
                "{case}: the acting session is gone"
            );
            assert_eq!(
                h.email.sent().len(),
                mail_before,
                "{case}: no other-session notice"
            );
        }
    }
}

async fn register_passkey_in_cool_down(
    h: &Harness,
    user: &doorman_core::storage::User,
    wa: &mut common::ResidentAuthenticator,
    cool_down_until: chrono::DateTime<chrono::Utc>,
) -> StoredPasskey {
    let session = session_in_cool_down_for(h, user, cool_down_until).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session)
        .await
        .expect("start registration");
    let response = wa.do_registration(ccr);
    let registered = h
        .session_manager
        .finish_passkey_registration(
            &session,
            challenge_id,
            &response,
            Some("in cool-down".into()),
            request_context(),
        )
        .await
        .expect("finish registration");
    h.sessions
        .delete_session(session.id)
        .await
        .expect("drop registering session");
    h.passkeys
        .find_passkey_by_credential_id(&registered.credential_id)
        .await
        .expect("lookup")
        .expect("registered passkey stored")
}

#[tokio::test]
async fn a_passkey_in_recovery_cool_down_cannot_reauthenticate() {
    let h = gated_harness();
    let alice = sign_in(&h, "alice@example.com").await;
    let current = alice.session.session.clone();
    assert!(!current.is_in_recovery_cool_down());
    let mut recovered_wa = authenticator();
    let until = h.clock.now() + chrono::Duration::hours(1);
    let recovered = register_passkey_in_cool_down(&h, &alice.user, &mut recovered_wa, until).await;

    let (challenge_id, options) = h
        .session_manager
        .start_reauth(&current)
        .await
        .expect("reauth start");
    assert!(
        options
            .public_key
            .allow_credentials
            .iter()
            .all(|c| c.id.as_ref() != recovered.credential_id.as_slice()),
        "the challenge names the passkey in cool-down"
    );
    assert!(
        !options.public_key.allow_credentials.is_empty(),
        "the challenge names the user's other passkey"
    );

    let assertion =
        recovered_wa.do_scoped_authentication(scoped_to(options, &recovered.credential_id));
    let refused = perform(
        &h,
        &current,
        DestructiveAction::DeleteUser,
        Some(ReauthProof {
            challenge_id,
            assertion,
        }),
    )
    .await;
    assert!(
        matches!(refused, Err(Error::Webauthn(_))),
        "a passkey in cool-down cleared a destructive action: {refused:?}"
    );
    assert!(
        h.users
            .find_user_by_id(alice.user.id)
            .await
            .expect("lookup")
            .is_some(),
        "the user is untouched"
    );
}

#[tokio::test]
async fn reauth_start_is_refused_when_every_passkey_is_in_recovery_cool_down() {
    let h = gated_harness();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();
    let until = h.clock.now() + chrono::Duration::hours(1);
    register_passkey_in_cool_down(&h, &user, &mut wa, until).await;
    let current = session_for(&h, &user).await;

    let refused = h.session_manager.start_reauth(&current).await;
    assert!(
        matches!(refused, Err(Error::RecoveryCoolDownActive)),
        "got: {refused:?}"
    );
}

#[tokio::test]
async fn a_passkey_reauthenticates_once_its_recovery_cool_down_lapses() {
    let h = gated_harness();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();
    let until = h.clock.now() + chrono::Duration::hours(1);
    register_passkey_in_cool_down(&h, &user, &mut wa, until).await;
    let current = session_for(&h, &user).await;

    h.clock.advance(chrono::Duration::hours(1));
    let proof = fresh_proof(&h, &current, &mut wa).await;
    let performed = perform(&h, &current, DestructiveAction::DeleteUser, Some(proof)).await;
    assert!(
        matches!(performed, Ok(CurrentSession::Ended)),
        "got: {performed:?}"
    );
}
