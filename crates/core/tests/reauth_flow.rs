//! Integration tests for re-authentication: the `start` ceremony and the
//! `ensure` gate that fronts the destructive self-service actions.

mod common;

use doorman_core::Error;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::reauth::{ReauthAction, ReauthPolicy, ReauthProof};
use doorman_core::session::SessionContext;
use doorman_core::storage::UserStore;

use common::{
    Harness, authenticator, kinds, make_user, register_passkey, restricted_session_for, session_for,
};

/// Build a harness that gates every destructive action behind re-auth.
fn gated_harness() -> Harness {
    Harness::builder()
        .reauth_policy(ReauthPolicy::required_for([
            ReauthAction::DeleteAccount,
            ReauthAction::RequestEmailChange,
            ReauthAction::RemovePasskey,
        ]))
        .build()
}

/// Run the full ceremony and hand back a usable proof: register a passkey,
/// `start`, drive the authenticator, and assemble the `ReauthProof`.
async fn fresh_proof(
    h: &Harness,
    user: doorman_core::storage::UserId,
    wa: &mut common::ResidentTestAuthenticator,
) -> ReauthProof {
    let (challenge_id, options) = h.reauth.start(user).await.expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);
    ReauthProof {
        challenge_id,
        assertion,
    }
}

#[tokio::test]
async fn disabled_policy_lets_destructive_action_through_without_proof() {
    // The default harness policy is disabled, so a proof-less delete succeeds.
    let h = Harness::fresh();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    h.account
        .delete_account(&session, None, SessionContext::default())
        .await
        .expect("delete succeeds when reauth is disabled");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_none(),
        "the account is gone"
    );
}

#[tokio::test]
async fn gated_action_without_proof_is_reauth_required() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    let err = h
        .account
        .delete_account(&session, None, SessionContext::default())
        .await
        .expect_err("missing proof must be rejected");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_some(),
        "the account is untouched"
    );
    // A missing proof is the ordinary handshake, not a failed attempt — no
    // ReauthFailed row.
    assert!(
        !kinds(&h.audit.events())
            .iter()
            .any(|k| matches!(k, AuditEventKind::ReauthFailed { .. })),
        "absent proof must not emit ReauthFailed"
    );
}

#[tokio::test]
async fn gated_action_with_fresh_proof_succeeds_and_audits() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    h.account
        .delete_account(&session, Some(proof), SessionContext::default())
        .await
        .expect("delete succeeds with a fresh proof");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_none(),
        "the account is deleted"
    );
    assert!(
        kinds(&h.audit.events()).iter().any(
            |k| matches!(k, AuditEventKind::ReauthSucceeded { user_id } if *user_id == user.id)
        ),
        "a ReauthSucceeded row is emitted"
    );
}

#[tokio::test]
async fn challenge_is_single_use() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    // Remove one of two passkeys so the account survives the first success and
    // we can attempt a replay. Register a second so removal does not strip the
    // last credential mid-test.
    register_passkey(&h, user.id, &mut wa, Some("second")).await;
    let creds = h.passkey.list_passkeys(user.id).await.expect("list");
    let target = creds[0].credential_id.clone();

    h.passkey
        .remove_passkey(
            &session,
            &target,
            Some(proof.clone()),
            SessionContext::default(),
        )
        .await
        .expect("first use succeeds");

    // Replaying the same proof must fail: the challenge was consumed.
    let other = creds[1].credential_id.clone();
    let err = h
        .passkey
        .remove_passkey(&session, &other, Some(proof), SessionContext::default())
        .await
        .expect_err("replayed challenge must be rejected");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
}

#[tokio::test]
async fn login_challenge_is_not_a_reauth_proof() {
    // A sign-in challenge shares the table re-authentication uses, but it was
    // minted for another ceremony: presenting it as a proof is refused like
    // any other unusable challenge, and the gated action does not run.
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    let credential = register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    let (challenge_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start sign-in");
    let assertion = wa.do_authentication(options, &credential.credential_id);

    let err = h
        .account
        .delete_account(
            &session,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            SessionContext::default(),
        )
        .await
        .expect_err("a sign-in challenge cannot re-authenticate");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_some(),
        "the account survives"
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
async fn expired_challenge_is_rejected() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    let (challenge_id, options) = h.reauth.start(user.id).await.expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);
    // Step past the default 5-minute challenge lifetime before finishing.
    h.clock.advance(chrono::Duration::minutes(6));

    let err = h
        .account
        .delete_account(
            &session,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            SessionContext::default(),
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
async fn assertion_from_another_users_credential_is_rejected() {
    // The ceremony is scoped to the owner's credentials, so an assertion from a
    // different user's authenticator cannot verify against the owner-scoped
    // challenge state. The account is left untouched and a failure is recorded.
    let h = gated_harness();
    let owner = make_user(&h, "owner@example.com").await;
    let attacker = make_user(&h, "attacker@example.com").await;
    let mut owner_wa = authenticator();
    register_passkey(&h, owner.id, &mut owner_wa, Some("owner device")).await;
    let mut attacker_wa = authenticator();
    register_passkey(&h, attacker.id, &mut attacker_wa, Some("attacker device")).await;
    let owner_session = session_for(&h, &owner);

    // Mint an owner-scoped challenge, then answer it with the attacker's
    // authenticator over an allow-list re-pointed at the attacker credential.
    let attacker_cred = h.passkey.list_passkeys(attacker.id).await.expect("list")[0]
        .credential_id
        .clone();
    let (challenge_id, options) = h.reauth.start(owner.id).await.expect("reauth start");
    let assertion = attacker_wa.do_scoped_authentication(scoped_to(options, &attacker_cred));

    let err = h
        .account
        .delete_account(
            &owner_session,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            SessionContext::default(),
        )
        .await
        .expect_err("an assertion from another user's credential must be rejected");
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
        "the owner account is untouched"
    );
    assert!(
        kinds(&h.audit.events())
            .iter()
            .any(|k| matches!(k, AuditEventKind::ReauthFailed { .. })),
        "a ReauthFailed row is emitted"
    );
}

#[tokio::test]
async fn cooldown_beats_reauth() {
    // Precedence: even a valid proof cannot satisfy the post-recovery
    // cool-down, which is checked first.
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    let err = h
        .account
        .delete_account(&restricted, Some(proof), SessionContext::default())
        .await
        .expect_err("cool-down blocks even with a valid proof");
    assert!(matches!(err, Error::RecoveryCooldownActive), "got: {err:?}");
}

/// Re-point an allow-list-scoped challenge at `credential_id` so the
/// `SoftPasskey` answers with that specific resident credential.
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
