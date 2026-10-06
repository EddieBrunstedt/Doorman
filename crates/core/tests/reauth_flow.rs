mod common;

use doorman_core::Error;
use doorman_core::audit::{AuditEventKind, AuthFailureReason, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::reauth::{ReauthAction, ReauthPolicy, ReauthProof};
use doorman_core::session::SessionContext;
use doorman_core::storage::{PasskeyStore, StoredPasskey, UserStatus, UserStore};

use common::{
    Harness, authenticator, kinds, make_user, register_passkey, session_count, session_for,
    session_in_cool_down_for,
};

fn all_actions() -> [ReauthAction; 5] {
    let listed = |action: ReauthAction| match action {
        ReauthAction::DeleteUser
        | ReauthAction::RequestEmailChange
        | ReauthAction::RemovePasskey
        | ReauthAction::RevokeOtherSessions
        | ReauthAction::RevokeSession => action,
    };
    [
        ReauthAction::DeleteUser,
        ReauthAction::RequestEmailChange,
        ReauthAction::RemovePasskey,
        ReauthAction::RevokeOtherSessions,
        ReauthAction::RevokeSession,
    ]
    .map(listed)
}

fn gated_harness() -> Harness {
    Harness::builder()
        .reauth_policy(ReauthPolicy::required_for(all_actions()))
        .build()
}

#[tokio::test]
async fn ensure_matrix_cool_down_blocks_every_action_before_policy() {
    let cases = [(Harness::fresh(), "disabled"), (gated_harness(), "gated")];
    for (h, policy) in &cases {
        let user = make_user(h, "owner@example.com").await;
        let cool_down_until = h.clock.now() + chrono::Duration::hours(24);
        let in_cool_down = session_in_cool_down_for(h, &user, cool_down_until);
        let plain = session_for(h, &user);
        for action in all_actions() {
            let blocked = h
                .reauth
                .ensure(action, &in_cool_down, None, &SessionContext::default())
                .await;
            assert!(
                matches!(blocked, Err(Error::RecoveryCoolDownActive)),
                "{action:?} in cool-down under {policy} policy: got {blocked:?}",
            );

            let outside = h
                .reauth
                .ensure(action, &plain, None, &SessionContext::default())
                .await;
            match *policy {
                "disabled" => assert!(
                    outside.is_ok(),
                    "{action:?} outside cool-down under disabled policy: got {outside:?}",
                ),
                _ => assert!(
                    matches!(outside, Err(Error::ReauthRequired)),
                    "{action:?} outside cool-down under gated policy: got {outside:?}",
                ),
            }
        }
    }
}

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
    let h = Harness::fresh();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    h.user
        .delete_user(&session, None, SessionContext::default())
        .await
        .expect("delete succeeds when reauth is disabled");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_none(),
        "the user is gone"
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
        .user
        .delete_user(&session, None, SessionContext::default())
        .await
        .expect_err("missing proof must be rejected");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("lookup")
            .is_some(),
        "the user is untouched"
    );
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
    h.user
        .delete_user(&session, Some(proof), SessionContext::default())
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
    let session = session_for(&h, &user);
    h.clock.advance(chrono::Duration::minutes(1));

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    h.reauth
        .ensure(
            ReauthAction::RemovePasskey,
            &session,
            Some(&proof),
            &SessionContext::default(),
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
    let session = session_for(&h, &user);
    let proof = fresh_proof(&h, user.id, &mut wa).await;

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let err = h
        .reauth
        .ensure(
            ReauthAction::RemovePasskey,
            &session,
            Some(&proof),
            &SessionContext::default(),
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
    let session = session_for(&h, &user);

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    register_passkey(&h, user.id, &mut wa, Some("second")).await;
    let passkeys = h.passkey.list_passkeys(user.id).await.expect("list");
    let target = passkeys[0].credential_id.clone();

    h.passkey
        .remove_passkey(
            &session,
            &target,
            Some(proof.clone()),
            SessionContext::default(),
        )
        .await
        .expect("first use succeeds");

    let other = passkeys[1].credential_id.clone();
    let err = h
        .passkey
        .remove_passkey(&session, &other, Some(proof), SessionContext::default())
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
    let session = session_for(&h, &user);

    let (challenge_id, options) = h
        .passkey
        .start_authentication(SessionContext::default())
        .await
        .expect("start login");
    let assertion = wa.do_authentication(options, &passkey.credential_id);

    let err = h
        .user
        .delete_user(
            &session,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            SessionContext::default(),
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
async fn expired_challenge_is_rejected() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let session = session_for(&h, &user);

    let (challenge_id, options) = h.reauth.start(user.id).await.expect("reauth start");
    let assertion = wa.do_scoped_authentication(options);
    h.clock.advance(chrono::Duration::minutes(6));

    let err = h
        .user
        .delete_user(
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
async fn assertion_from_another_users_passkey_is_rejected() {
    let h = gated_harness();
    let owner = make_user(&h, "owner@example.com").await;
    let attacker = make_user(&h, "attacker@example.com").await;
    let mut owner_wa = authenticator();
    register_passkey(&h, owner.id, &mut owner_wa, Some("owner device")).await;
    let mut attacker_wa = authenticator();
    register_passkey(&h, attacker.id, &mut attacker_wa, Some("attacker device")).await;
    let owner_session = session_for(&h, &owner);

    let attacker_passkey = h.passkey.list_passkeys(attacker.id).await.expect("list")[0]
        .credential_id
        .clone();
    let (challenge_id, options) = h.reauth.start(owner.id).await.expect("reauth start");
    let assertion = attacker_wa.do_scoped_authentication(scoped_to(options, &attacker_passkey));

    let err = h
        .user
        .delete_user(
            &owner_session,
            Some(ReauthProof {
                challenge_id,
                assertion,
            }),
            SessionContext::default(),
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

#[tokio::test]
async fn cool_down_beats_reauth() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let cool_down_until = h.clock.now() + chrono::Duration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until);

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    let err = h
        .user
        .delete_user(&in_cool_down, Some(proof), SessionContext::default())
        .await
        .expect_err("cool-down blocks even with a valid proof");
    assert!(matches!(err, Error::RecoveryCoolDownActive), "got: {err:?}");
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

#[tokio::test]
async fn revoke_other_sessions_requires_proof_when_gated() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let current = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("current")
        .session;
    h.session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("other");

    let err = h
        .user
        .revoke_other_sessions(&current, None, SessionContext::default())
        .await
        .expect_err("missing proof must be rejected");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");
    assert_eq!(
        session_count(&h, user.id).await,
        2,
        "nothing is revoked without a proof"
    );

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    let removed = h
        .user
        .revoke_other_sessions(&current, Some(proof), SessionContext::default())
        .await
        .expect("revoke with a fresh proof");
    assert_eq!(removed, 1);
}

#[tokio::test]
async fn revoke_session_requires_proof_only_for_another_session() {
    let h = gated_harness();
    let user = make_user(&h, "owner@example.com").await;
    let mut wa = authenticator();
    register_passkey(&h, user.id, &mut wa, Some("device")).await;
    let current = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("current")
        .session;
    let other = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("other")
        .session;

    let err = h
        .user
        .revoke_session(&current, other.id, None, SessionContext::default())
        .await
        .expect_err("another session needs a proof");
    assert!(matches!(err, Error::ReauthRequired), "got: {err:?}");

    let proof = fresh_proof(&h, user.id, &mut wa).await;
    h.user
        .revoke_session(&current, other.id, Some(proof), SessionContext::default())
        .await
        .expect("revoke another session with a fresh proof");

    h.user
        .revoke_session(&current, current.id, None, SessionContext::default())
        .await
        .expect("self-revocation is never gated");
}
