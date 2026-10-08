use doorman_core::Error;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::destructive::DestructiveAction;
use doorman_core::session::SessionContext;
use doorman_core::storage::{UserStatus, UserStore};

use crate::common::{
    Harness, USER_URL, assert_last_redemption_unknown, authenticator, kinds,
    last_email_change_token, make_user, passkey_count, provision_user, session_count, session_for,
    session_in_cool_down_for, token_from_email, within_deadline,
};

#[tokio::test]
async fn email_change_happy_path() {
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user).await;
    let mail_before = h.email.sent().len();

    h.session_manager
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "New@Example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");

    let sent = h.email.sent();
    let new_mail = &sent[mail_before..];
    assert_eq!(new_mail.len(), 2, "confirmation + old-address notice");

    let confirmation = new_mail
        .iter()
        .find(|e| e.subject == "Confirm your new email address")
        .expect("confirmation email queued");
    assert_eq!(
        confirmation.to, "new@example.com",
        "confirmation goes to the normalized new address",
    );
    let notice = new_mail
        .iter()
        .find(|e| e.subject == "Security notice: email change requested")
        .expect("old-address notice queued");
    assert_eq!(
        notice.to, "old@example.com",
        "notice goes to the old address"
    );

    let pre = h
        .users
        .find_user_by_id(user.id)
        .await
        .expect("find user")
        .expect("user present");
    assert_eq!(pre.email.as_deref(), Some("old@example.com"));

    let token = token_from_email(&confirmation.body_text, USER_URL);
    let updated = h
        .user
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect("confirm email change");
    assert_eq!(updated.user.email.as_deref(), Some("new@example.com"));
    assert!(
        updated.user.email_verified_at.is_some(),
        "confirming the link verifies the new address",
    );

    let stored = h
        .users
        .find_user_by_id(user.id)
        .await
        .expect("find user")
        .expect("user present");
    assert_eq!(stored.email.as_deref(), Some("new@example.com"));

    assert!(matches!(
        h.user
            .confirm_email_change(&token, SessionContext::default())
            .await,
        Err(Error::InvalidEmailLink),
    ));

    let audit = kinds(&h.audit.events());
    assert!(
        audit
            .iter()
            .any(|k| matches!(k, AuditEventKind::EmailChangeRequested { .. })),
        "request emits an audit event",
    );
    assert!(
        audit
            .iter()
            .any(|k| matches!(k, AuditEventKind::EmailChangeCompleted { .. })),
        "confirm emits an audit event",
    );
}

#[tokio::test]
async fn email_change_confirm_refuses_address_claimed_since_request() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let session = session_for(&h, &user).await;
    h.session_manager
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "wanted@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let token = last_email_change_token(&h);
    let holder = make_user(&h, "wanted@example.com").await;

    let err = h
        .user
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect_err("an address claimed since the request is refused");
    assert!(matches!(err, Error::EmailAlreadyInUse), "got {err:?}");
    let owner = h
        .users
        .find_user_by_email("wanted@example.com")
        .await
        .expect("find holder")
        .expect("holder keeps the address");
    assert_eq!(owner.id, holder.id);
}

#[tokio::test]
async fn signup_losing_the_race_to_an_email_change_succeeds_silently() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let session = session_for(&h, &user).await;
    h.session_manager
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "wanted@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let token = last_email_change_token(&h);

    let release = h.user_store.hold_user_creates(1);
    let (signed_up, confirmed) = within_deadline(async {
        tokio::join!(
            h.signup
                .request_signup("wanted@example.com", None, SessionContext::default()),
            async {
                let confirmed = h
                    .user
                    .confirm_email_change(&token, SessionContext::default())
                    .await;
                release.wait().await;
                confirmed
            },
        )
    })
    .await;

    let updated = confirmed.expect("the confirm lands first");
    assert_eq!(updated.user.email.as_deref(), Some("wanted@example.com"));
    signed_up.expect("the signup that lost the race still succeeds");
    assert!(
        h.email
            .sent()
            .iter()
            .all(|e| e.to != "wanted@example.com" || e.subject == "Confirm your new email address"),
        "no signup link goes to the claimed address",
    );
    let owner = h
        .users
        .find_user_by_email("wanted@example.com")
        .await
        .expect("find holder")
        .expect("the confirmed user holds the address");
    assert_eq!(owner.id, user.id);
}

#[tokio::test]
async fn email_change_rejects_address_already_in_use() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let session = session_for(&h, &user).await;
    make_user(&h, "taken@example.com").await;
    let mail_before = h.email.sent().len();

    let err = h
        .session_manager
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "taken@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("address already in use must be rejected");
    assert!(matches!(err, Error::EmailAlreadyInUse));
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no email is sent when the target address is already registered",
    );
}

#[tokio::test]
async fn request_email_change_refused_during_recovery_cool_down() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let cool_down_until = h.clock.now() + chrono::Duration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until).await;
    let mail_before = h.email.sent().len();

    let err = h
        .session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("email change must be refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCoolDownActive));
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no confirmation link or notice is sent when the gate trips",
    );
}

#[tokio::test]
async fn delete_user_refused_during_recovery_cool_down() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let cool_down_until = h.clock.now() + chrono::Duration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until).await;

    let err = h
        .session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::DeleteUser,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("deletion must be refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCoolDownActive));
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user")
            .is_some(),
        "the user is untouched when the gate trips",
    );
    assert_eq!(
        session_count(&h, user.id).await,
        2,
        "the signup session and the one in cool-down are left intact"
    );
}

#[tokio::test]
async fn request_email_change_allowed_once_recovery_cool_down_lapses() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let cool_down_until = h.clock.now() + chrono::Duration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until).await;

    let err = h
        .session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("blocked during the cool-down");
    assert!(matches!(err, Error::RecoveryCoolDownActive));

    h.clock.advance(chrono::Duration::hours(25));
    let mail_before = h.email.sent().len();
    h.session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::RequestEmailChange {
                new_email: "new@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("email change allowed once the cool-down lapses");
    assert!(
        h.email.sent().len() > mail_before,
        "the confirmation email is sent after the cool-down lapses",
    );
    h.user
        .confirm_email_change(&last_email_change_token(&h), SessionContext::default())
        .await
        .expect("the confirmation link issued after the cool-down lapses redeems");
}

#[tokio::test]
async fn delete_user_allowed_once_recovery_cool_down_lapses() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let cool_down_until = h.clock.now() + chrono::Duration::hours(24);
    let in_cool_down = session_in_cool_down_for(&h, &user, cool_down_until).await;

    let err = h
        .session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::DeleteUser,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("blocked during the cool-down");
    assert!(matches!(err, Error::RecoveryCoolDownActive));

    h.clock.advance(chrono::Duration::hours(25));
    h.session_manager
        .perform(
            &in_cool_down,
            DestructiveAction::DeleteUser,
            None,
            SessionContext::default(),
        )
        .await
        .expect("deletion allowed once the cool-down lapses");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user")
            .is_none(),
        "the user is deleted after the cool-down lapses",
    );
}

#[tokio::test]
async fn confirm_refused_for_disabled_user() {
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user).await;
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
    let confirmation = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Confirm your new email address")
        .expect("confirmation email queued");
    let token = token_from_email(&confirmation.body_text, USER_URL);

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let err = h
        .user
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect_err("disabled user must be refused");
    assert!(matches!(err, Error::UserDisabled));

    let stored = h
        .users
        .find_user_by_id(user.id)
        .await
        .expect("find user")
        .expect("user present");
    assert_eq!(stored.email.as_deref(), Some("old@example.com"));
    assert!(
        !kinds(&h.audit.events())
            .iter()
            .any(|k| matches!(k, AuditEventKind::EmailChangeCompleted { .. })),
        "no completion is audited",
    );
}

#[tokio::test]
async fn delete_user_cascades_all_stores() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let session = session_for(&h, &user).await;

    h.session_manager
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "elsewhere@example.com".into(),
            },
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let email_change_token = last_email_change_token(&h);
    let (challenge_id, options) = h
        .session_manager
        .start_passkey_registration(&session)
        .await
        .expect("start a pending registration");
    let attestation = authenticator().do_registration(options);

    assert_eq!(
        session_count(&h, user.id).await,
        2,
        "signup and the test's own session are active"
    );
    assert_eq!(passkey_count(&h, user.id).await, 1, "signup left a passkey");

    h.session_manager
        .perform(
            &session,
            DestructiveAction::DeleteUser,
            None,
            SessionContext::default(),
        )
        .await
        .expect("delete user");

    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user")
            .is_none(),
        "the user row is gone",
    );
    assert_eq!(session_count(&h, user.id).await, 0, "sessions cascaded");
    assert_eq!(passkey_count(&h, user.id).await, 0, "passkeys cascaded");

    let audit = kinds(&h.audit.events());
    assert!(
        audit
            .iter()
            .any(|k| matches!(k, AuditEventKind::UserDeleted { .. })),
        "deletion emits an audit event",
    );

    let err = h
        .user
        .confirm_email_change(&email_change_token, SessionContext::default())
        .await
        .expect_err("the email-change link is gone");
    assert!(matches!(err, Error::InvalidEmailLink));
    assert_last_redemption_unknown(&h, SecretKind::EmailChangeLink);

    let err = h
        .session_manager
        .finish_passkey_registration(
            &session,
            challenge_id,
            &attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("the pending ceremony is gone");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    assert_last_redemption_unknown(&h, SecretKind::RegistrationChallenge);
}

#[tokio::test]
async fn registration_challenge_outliving_its_user_is_refused() {
    let h = Harness::fresh();
    let user = provision_user(&h, "racing@example.com").await;
    let session = session_for(&h, &user).await;
    let (challenge_id, options) = h
        .session_manager
        .start_passkey_registration(&session)
        .await
        .expect("start a pending registration");
    // Leaves the challenge behind, as a registration started while the delete runs can.
    h.users.delete_user(user.id).await.expect("delete user row");
    let attestation = authenticator().do_registration(options);
    let passkeys_before = passkey_count(&h, user.id).await;
    let audited_before = h.audit.events().len();

    let err = h
        .session_manager
        .finish_passkey_registration(
            &session,
            challenge_id,
            &attestation,
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("a challenge whose user is gone is refused");

    assert!(matches!(err, Error::InvalidPasskeyChallenge), "got {err:?}");
    assert_eq!(
        passkey_count(&h, user.id).await,
        passkeys_before,
        "no passkey stored"
    );
    assert_eq!(
        kinds(&h.audit.events()[audited_before..]),
        vec![AuditEventKind::RedemptionFailed {
            user_id: Some(user.id),
            secret: SecretKind::RegistrationChallenge,
            reason: RedemptionFailureReason::UserNotFound,
        }],
    );
}
