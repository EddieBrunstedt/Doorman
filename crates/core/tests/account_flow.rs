//! Integration tests for the account-lifecycle flows: verified email change
//! and account deletion.

mod common;

use doorman_core::Error;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::session::SessionContext;
use doorman_core::storage::{AccountStatus, UserStore};

use common::{
    ACCOUNT_URL, Harness, assert_last_redemption_unknown, authenticator, kinds,
    last_email_change_token, make_user, passkey_count, provision_user, restricted_session_for,
    session_count, session_for, token_from_email, within_deadline,
};

#[tokio::test]
async fn email_change_happy_path() {
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user);
    let mail_before = h.email.sent().len();

    h.account
        .request_email_change(
            &user,
            &session,
            "New@Example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");

    // Two emails: a confirmation to the new address and a notice to the old.
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

    // The account email is unchanged until the link is confirmed.
    let pre = h
        .users
        .find_user_by_id(user.id)
        .await
        .expect("find user")
        .expect("user present");
    assert_eq!(pre.email.as_deref(), Some("old@example.com"));

    let token = token_from_email(&confirmation.body_text, ACCOUNT_URL);
    let updated = h
        .account
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect("confirm email change");
    assert_eq!(updated.email.as_deref(), Some("new@example.com"));
    assert!(
        updated.email_verified_at.is_some(),
        "confirming the link verifies the new address",
    );

    let stored = h
        .users
        .find_user_by_id(user.id)
        .await
        .expect("find user")
        .expect("user present");
    assert_eq!(stored.email.as_deref(), Some("new@example.com"));

    // The token is single-use: a replay fails.
    assert!(matches!(
        h.account
            .confirm_email_change(&token, SessionContext::default())
            .await,
        Err(Error::InvalidVerificationToken),
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
    let session = session_for(&h, &user);
    h.account
        .request_email_change(
            &user,
            &session,
            "wanted@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let token = last_email_change_token(&h);
    let holder = make_user(&h, "wanted@example.com").await;

    let err = h
        .account
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
    let session = session_for(&h, &user);
    h.account
        .request_email_change(
            &user,
            &session,
            "wanted@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let token = last_email_change_token(&h);

    // The signup reads the address as free, then the confirm claims it
    // before the signup provisions it.
    let release = h.user_store.hold_email_lookups(1);
    let (signed_up, confirmed) = within_deadline(async {
        tokio::join!(
            h.signup
                .request_signup("wanted@example.com", None, SessionContext::default()),
            async {
                let confirmed = h
                    .account
                    .confirm_email_change(&token, SessionContext::default())
                    .await;
                release.wait().await;
                confirmed
            },
        )
    })
    .await;

    let updated = confirmed.expect("the confirm lands first");
    assert_eq!(updated.email.as_deref(), Some("wanted@example.com"));
    // The signup that lost the race answers as it would for an address that
    // was already registered: silent success, and no link.
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
        .expect("the confirmed account holds the address");
    assert_eq!(owner.id, user.id);
}

#[tokio::test]
async fn email_change_rejects_address_already_in_use() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let session = session_for(&h, &user);
    make_user(&h, "taken@example.com").await;
    let mail_before = h.email.sent().len();

    let err = h
        .account
        .request_email_change(
            &user,
            &session,
            "taken@example.com",
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
async fn request_email_change_refused_during_recovery_cooldown() {
    // The post-recovery cool-down gate lives in the manager, so a restricted
    // session is refused even when driving core directly — a phished recovery
    // session must not repoint the account's address. (F1)
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);
    let mail_before = h.email.sent().len();

    let err = h
        .account
        .request_email_change(
            &user,
            &restricted,
            "new@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("email change must be refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive));
    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "no confirmation link or notice is sent when the gate trips",
    );
}

#[tokio::test]
async fn delete_account_refused_during_recovery_cooldown() {
    // Account deletion is likewise gated in the manager: a phished recovery
    // session must not be able to delete the account before the owner reacts. (F1)
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    let err = h
        .account
        .delete_account(&restricted, None, SessionContext::default())
        .await
        .expect_err("deletion must be refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive));
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user")
            .is_some(),
        "the account is untouched when the gate trips",
    );
    assert_eq!(
        session_count(&h, user.id).await,
        1,
        "the signup session is left intact"
    );
}

#[tokio::test]
async fn request_email_change_allowed_once_recovery_cooldown_lapses() {
    // The cool-down releases: once the deadline passes, the same recovery
    // session can request the email change. A regression making the gate
    // permanent would lock the owner out of email changes forever. (F1)
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    // Blocked while the cool-down is active.
    let err = h
        .account
        .request_email_change(
            &user,
            &restricted,
            "new@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("blocked during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive));

    // After the deadline the request is allowed and issues the confirmation.
    h.clock.advance(chrono::Duration::hours(25));
    let mail_before = h.email.sent().len();
    h.account
        .request_email_change(
            &user,
            &restricted,
            "new@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("email change allowed once the cool-down lapses");
    assert!(
        h.email.sent().len() > mail_before,
        "the confirmation email is sent after the cool-down lapses",
    );
    h.account
        .confirm_email_change(&last_email_change_token(&h), SessionContext::default())
        .await
        .expect("the confirmation link issued after the cool-down lapses redeems");
}

#[tokio::test]
async fn delete_account_allowed_once_recovery_cooldown_lapses() {
    // Releasing the cool-down restores the ability to delete the account. (F1)
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    let err = h
        .account
        .delete_account(&restricted, None, SessionContext::default())
        .await
        .expect_err("blocked during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive));

    h.clock.advance(chrono::Duration::hours(25));
    h.account
        .delete_account(&restricted, None, SessionContext::default())
        .await
        .expect("deletion allowed once the cool-down lapses");
    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user")
            .is_none(),
        "the account is deleted after the cool-down lapses",
    );
}

#[tokio::test]
async fn confirm_rejects_expired_token() {
    // The email-change link expires like signup and recovery links do: a
    // confirm after `token_lifetime` is rejected and the address is unchanged.
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user);

    h.account
        .request_email_change(
            &user,
            &session,
            "new@example.com",
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
    let token = token_from_email(&confirmation.body_text, ACCOUNT_URL);

    // Step past the default 15-minute token lifetime before confirming.
    h.clock.advance(chrono::Duration::minutes(16));

    let err = h
        .account
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect_err("an expired token must be rejected");
    assert!(matches!(err, Error::InvalidVerificationToken));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: Some(id),
            secret: SecretKind::EmailChangeLink,
            reason: RedemptionFailureReason::Expired,
        } if *id == user.id
    )));

    let stored = h
        .users
        .find_user_by_id(user.id)
        .await
        .expect("find user")
        .expect("user present");
    assert_eq!(
        stored.email.as_deref(),
        Some("old@example.com"),
        "the address is unchanged when the link has expired",
    );
}

#[tokio::test]
async fn confirm_refused_for_disabled_account() {
    // A link requested while active must not repoint the address of an
    // account an operator has since disabled.
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user);
    h.account
        .request_email_change(
            &user,
            &session,
            "new@example.com",
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
    let token = token_from_email(&confirmation.body_text, ACCOUNT_URL);

    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Disabled { at: now }, now)
        .await
        .expect("disable user");

    let err = h
        .account
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect_err("disabled account must be refused");
    assert!(matches!(err, Error::AccountDisabled));

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
async fn confirm_rejects_unknown_token() {
    let h = Harness::fresh();
    let err = h
        .account
        .confirm_email_change("not-a-real-token", SessionContext::default())
        .await
        .expect_err("an unknown token must be rejected");
    assert!(matches!(err, Error::InvalidVerificationToken));
    assert!(kinds(&h.audit.events()).iter().any(|k| matches!(
        k,
        AuditEventKind::RedemptionFailed {
            user_id: None,
            secret: SecretKind::EmailChangeLink,
            reason: RedemptionFailureReason::Unknown,
        }
    )));
}

#[tokio::test]
async fn delete_account_cascades_all_stores() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let session = session_for(&h, &user);

    // Leave behind every kind of row that hangs off the user: a pending
    // email-change token, a pending registration ceremony, plus the session
    // and credential that signup already created.
    h.account
        .request_email_change(
            &user,
            &session,
            "elsewhere@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let email_change_token = last_email_change_token(&h);
    let (challenge_id, options) = h
        .passkey
        .start_registration(user.id)
        .await
        .expect("start a pending registration");
    let attestation = authenticator().do_registration(options);

    assert_eq!(
        session_count(&h, user.id).await,
        1,
        "signup left an active session"
    );
    assert_eq!(
        passkey_count(&h, user.id).await,
        1,
        "signup left a credential"
    );

    h.account
        .delete_account(&session, None, SessionContext::default())
        .await
        .expect("delete account");

    assert!(
        h.users
            .find_user_by_id(user.id)
            .await
            .expect("find user")
            .is_none(),
        "the user row is gone",
    );
    assert_eq!(session_count(&h, user.id).await, 0, "sessions cascaded");
    assert_eq!(passkey_count(&h, user.id).await, 0, "credentials cascaded");

    let audit = kinds(&h.audit.events());
    assert!(
        audit
            .iter()
            .any(|k| matches!(k, AuditEventKind::AccountDeleted { .. })),
        "deletion emits an audit event",
    );

    // The outstanding link and ceremony are refused as unknown, not as
    // belonging to a deleted user: their rows went with the account.
    let err = h
        .account
        .confirm_email_change(&email_change_token, SessionContext::default())
        .await
        .expect_err("the email-change link is gone");
    assert!(matches!(err, Error::InvalidVerificationToken));
    assert_last_redemption_unknown(&h, SecretKind::EmailChangeLink);

    let err = h
        .passkey
        .finish_registration(challenge_id, &attestation, None, SessionContext::default())
        .await
        .expect_err("the pending ceremony is gone");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    assert_last_redemption_unknown(&h, SecretKind::RegistrationChallenge);
}
