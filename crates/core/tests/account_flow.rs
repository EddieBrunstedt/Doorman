mod common;

use chrono::Duration as ChronoDuration;
use doorman_core::Error;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::session::SessionContext;
use doorman_core::storage::{AccountStatus, Session, SessionId, SessionStore, User, UserStore};

use common::{
    ACCOUNT_URL, Harness, SIGNUP_URL, assert_last_redemption_unknown, authenticator, kinds,
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
        .request_email_change(&session, "New@Example.com", None, SessionContext::default())
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
            &session,
            "wanted@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    let token = last_email_change_token(&h);

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
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);
    let mail_before = h.email.sent().len();

    let err = h
        .account
        .request_email_change(
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
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let cooldown_until = h.clock.now() + chrono::Duration::hours(24);
    let restricted = restricted_session_for(&h, &user, cooldown_until);

    let err = h
        .account
        .request_email_change(
            &restricted,
            "new@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect_err("blocked during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive));

    h.clock.advance(chrono::Duration::hours(25));
    let mail_before = h.email.sent().len();
    h.account
        .request_email_change(
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
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user);

    h.account
        .request_email_change(&session, "new@example.com", None, SessionContext::default())
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
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user);
    h.account
        .request_email_change(&session, "new@example.com", None, SessionContext::default())
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
async fn email_change_token_cannot_be_redeemed_by_another_flow() {
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let session = session_for(&h, &user);
    h.account
        .request_email_change(&session, "new@example.com", None, SessionContext::default())
        .await
        .expect("request email change");
    let token = last_email_change_token(&h);

    let err = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect_err("email-change token rejected on signup");
    assert!(matches!(err, Error::InvalidVerificationToken));
    let err = h
        .recovery
        .consume_recovery(&token, SessionContext::default())
        .await
        .expect_err("email-change token rejected on recovery");
    assert!(matches!(err, Error::InvalidVerificationToken));

    let updated = h
        .account
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect("email-change token still valid on its own flow");
    assert_eq!(updated.email.as_deref(), Some("new@example.com"));
}

#[tokio::test]
async fn signup_token_cannot_confirm_an_email_change() {
    let h = Harness::fresh();
    h.signup
        .request_signup("cross@example.com", None, SessionContext::default())
        .await
        .expect("request signup");
    let token = token_from_email(&h.email.sent()[0].body_text, SIGNUP_URL);

    let err = h
        .account
        .confirm_email_change(&token, SessionContext::default())
        .await
        .expect_err("signup token rejected on email change");
    assert!(matches!(err, Error::InvalidVerificationToken));

    h.signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("signup token still valid on its own flow");
}

#[tokio::test]
async fn delete_account_cascades_all_stores() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let session = session_for(&h, &user);

    h.account
        .request_email_change(
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
        .start_registration(&session_for(&h, &user))
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

async fn stored_session(
    h: &Harness,
    user: &User,
    cooldown_until: Option<ChronoDuration>,
) -> Session {
    let mut session = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session")
        .session;
    session.recovery_cooldown_until = cooldown_until.map(|span| h.clock.now() + span);
    session
}

async fn session_exists(h: &Harness, id: SessionId) -> bool {
    h.sessions
        .find_session_by_id(id)
        .await
        .expect("find session")
        .is_some()
}

#[tokio::test]
async fn revoke_other_sessions_keeps_only_the_acting_session_and_notifies() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let current = stored_session(&h, &alice, None).await;
    let other_1 = stored_session(&h, &alice, None).await;
    let other_2 = stored_session(&h, &alice, None).await;
    let bobs = stored_session(&h, &bob, None).await;
    let mail_before = h.email.sent().len();

    let removed = h
        .account
        .revoke_other_sessions(&current, None, SessionContext::default())
        .await
        .expect("revoke other sessions");

    assert_eq!(removed, 2);
    assert!(
        session_exists(&h, current.id).await,
        "the acting session stays"
    );
    assert!(!session_exists(&h, other_1.id).await);
    assert!(!session_exists(&h, other_2.id).await);
    assert!(
        session_exists(&h, bobs.id).await,
        "another user is untouched"
    );
    let sent = &h.email.sent()[mail_before..];
    assert_eq!(sent.len(), 1, "one bulk-revocation notice");
    assert_eq!(sent[0].subject, "Security notice: other sessions revoked");
    assert_eq!(sent[0].to, "alice@example.com");
}

#[tokio::test]
async fn revoke_session_notifies_only_for_other_sessions() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let current = stored_session(&h, &alice, None).await;
    let other = stored_session(&h, &alice, None).await;
    let mail_before = h.email.sent().len();

    h.account
        .revoke_session(&current, other.id, None, SessionContext::default())
        .await
        .expect("revoke other");
    assert!(!session_exists(&h, other.id).await);
    assert_eq!(
        h.email.sent().len(),
        mail_before + 1,
        "revoking another session notifies"
    );

    h.account
        .revoke_session(&current, current.id, None, SessionContext::default())
        .await
        .expect("revoke self");
    assert!(!session_exists(&h, current.id).await);
    assert_eq!(
        h.email.sent().len(),
        mail_before + 1,
        "self-revocation sends no notice"
    );
}

#[tokio::test]
async fn revoke_session_hides_another_users_session() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let current = stored_session(&h, &alice, None).await;
    let bobs = stored_session(&h, &bob, None).await;

    let err = h
        .account
        .revoke_session(&current, bobs.id, None, SessionContext::default())
        .await
        .expect_err("alice cannot revoke bob's session");
    assert!(matches!(err, Error::SessionNotFound), "got: {err:?}");
    assert!(session_exists(&h, bobs.id).await);
}

#[tokio::test]
async fn revoke_other_sessions_refused_during_recovery_cooldown() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let current = stored_session(&h, &alice, Some(ChronoDuration::minutes(10))).await;
    let other = stored_session(&h, &alice, None).await;
    let mail_before = h.email.sent().len();

    let err = h
        .account
        .revoke_other_sessions(&current, None, SessionContext::default())
        .await
        .expect_err("refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive), "got: {err:?}");
    assert!(session_exists(&h, other.id).await, "nothing is revoked");
    assert_eq!(h.email.sent().len(), mail_before, "no notice");

    h.clock.advance(ChronoDuration::minutes(11));
    let removed = h
        .account
        .revoke_other_sessions(&current, None, SessionContext::default())
        .await
        .expect("allowed once the cool-down lapses");
    assert_eq!(removed, 1);
    assert!(!session_exists(&h, other.id).await);
}

#[tokio::test]
async fn revoke_session_cooldown_blocks_others_but_allows_self() {
    let h = Harness::fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let current = stored_session(&h, &alice, Some(ChronoDuration::minutes(10))).await;
    let other = stored_session(&h, &alice, None).await;

    let err = h
        .account
        .revoke_session(&current, other.id, None, SessionContext::default())
        .await
        .expect_err("revoking another device is refused during the cool-down");
    assert!(matches!(err, Error::RecoveryCooldownActive), "got: {err:?}");
    assert!(
        session_exists(&h, other.id).await,
        "the other device is untouched"
    );

    h.clock.advance(ChronoDuration::minutes(11));
    h.account
        .revoke_session(&current, other.id, None, SessionContext::default())
        .await
        .expect("allowed once the cool-down lapses");
    assert!(!session_exists(&h, other.id).await);

    let restricted = stored_session(&h, &alice, Some(ChronoDuration::minutes(10))).await;
    h.account
        .revoke_session(&restricted, restricted.id, None, SessionContext::default())
        .await
        .expect("revoking the cool-down session itself stays allowed");
    assert!(!session_exists(&h, restricted.id).await);
}
