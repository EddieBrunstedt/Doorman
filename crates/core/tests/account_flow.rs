//! Integration tests for the account-lifecycle flows: verified email change
//! and account deletion.

mod common;

use bauth_core::Error;
use bauth_core::audit::AuditEventKind;
use bauth_core::session::SessionContext;
use bauth_core::storage::UserStore;

use common::{ACCOUNT_URL, Harness, kinds, make_user, provision_user, token_from_email};

#[tokio::test]
async fn email_change_happy_path() {
    let h = Harness::fresh();
    let user = provision_user(&h, "old@example.com").await;
    let mail_before = h.email.sent().len();

    h.account
        .request_email_change(&user, "New@Example.com", SessionContext::default())
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
async fn email_change_rejects_address_already_in_use() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    make_user(&h, "taken@example.com").await;
    let mail_before = h.email.sent().len();

    let err = h
        .account
        .request_email_change(&user, "taken@example.com", SessionContext::default())
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
async fn confirm_rejects_unknown_token() {
    let h = Harness::fresh();
    let err = h
        .account
        .confirm_email_change("not-a-real-token", SessionContext::default())
        .await
        .expect_err("an unknown token must be rejected");
    assert!(matches!(err, Error::InvalidVerificationToken));
}

#[tokio::test]
async fn delete_account_cascades_all_stores() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;

    // Leave behind every kind of row that hangs off the user: a pending
    // email-change token, a pending registration ceremony, plus the session
    // and credential that signup already created.
    h.account
        .request_email_change(&user, "elsewhere@example.com", SessionContext::default())
        .await
        .expect("request email change");
    h.passkey
        .start_registration(user.id)
        .await
        .expect("start a pending registration");

    assert_eq!(h.sessions.len(), 1, "signup left an active session");
    assert_eq!(h.credentials.len(), 1, "signup left a credential");
    assert_eq!(h.tokens.len(), 1, "email-change token outstanding");
    assert_eq!(h.challenges.len(), 1, "pending registration challenge");

    h.account
        .delete_account(&user, SessionContext::default())
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
    assert_eq!(h.sessions.len(), 0, "sessions cascaded");
    assert_eq!(h.credentials.len(), 0, "credentials cascaded");
    assert_eq!(h.tokens.len(), 0, "verification tokens cascaded");
    assert_eq!(h.challenges.len(), 0, "pending ceremonies cascaded");

    let audit = kinds(&h.audit.events());
    assert!(
        audit
            .iter()
            .any(|k| matches!(k, AuditEventKind::AccountDeleted { .. })),
        "deletion emits an audit event",
    );
}
