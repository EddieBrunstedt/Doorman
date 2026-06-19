//! Integration tests for the operator flows: host-driven operations acting on
//! a user _other_ than the acting one. The first flow is account deletion.

mod common;

use chrono::Utc;
use doorman_core::Error;
use doorman_core::audit::{Actor, AuditEvent, AuditEventKind, OperatorActor};
use doorman_core::operator::{NotificationPolicy, OperatorNotice};
use doorman_core::storage::{PasskeyCredentialStore, SessionId, SessionStore, UserId, UserStore};

use common::{Harness, HarnessBuilder, provision_user, session_for};

/// The first credential id registered for `user` by `provision_user`.
async fn first_credential_id(h: &Harness, user_id: UserId) -> Vec<u8> {
    let creds = h
        .credentials
        .list_passkeys_for_user(user_id)
        .await
        .expect("list passkeys");
    creds
        .first()
        .map(|c| c.credential_id.clone())
        .expect("user has a credential")
}

/// The id of `user`'s single active session.
async fn only_session_id(h: &Harness, user_id: UserId) -> SessionId {
    let sessions = h
        .sessions
        .list_for_user(user_id, Utc::now())
        .await
        .expect("list sessions");
    sessions.first().map(|s| s.id).expect("user has a session")
}

fn operator() -> OperatorActor {
    OperatorActor::new(
        "support-agent-7",
        Some("authz-log-42".to_string()),
        Some("198.51.100.7".to_string()),
        Some("admin-console/1.0".to_string()),
    )
    .expect("operator actor within bounds")
}

#[tokio::test]
async fn operator_delete_cascades_all_stores() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let session = session_for(&h, &user);

    // Leave behind every kind of row that hangs off the user.
    h.account
        .request_email_change(&user, &session, "elsewhere@example.com", Default::default())
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

    h.operator
        .delete_account(user.id, operator())
        .await
        .expect("operator delete");

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
}

#[tokio::test]
async fn operator_delete_emits_account_deleted_with_operator_actor() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;

    h.operator
        .delete_account(user.id, operator())
        .await
        .expect("operator delete");

    let deleted = h
        .audit
        .events()
        .into_iter()
        .find(
            |e| matches!(e.kind, AuditEventKind::AccountDeleted { user_id } if user_id == user.id),
        )
        .expect("an AccountDeleted event was emitted");

    let AuditEvent { actor, .. } = deleted;
    let Actor::Operator(recorded) = actor else {
        panic!("operator delete must attribute to Actor::Operator, got {actor:?}");
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");
    assert_eq!(recorded.correlation_id.as_deref(), Some("authz-log-42"));
    assert_eq!(recorded.ip.as_deref(), Some("198.51.100.7"));
    assert_eq!(recorded.user_agent.as_deref(), Some("admin-console/1.0"));
}

#[tokio::test]
async fn operator_delete_unknown_user_fails_before_touching_stores() {
    let h = Harness::fresh();
    // A surviving user so we can prove the cascade did not run against anyone.
    let bystander = provision_user(&h, "bystander@example.com").await;

    let err = h
        .operator
        .delete_account(UserId::new(), operator())
        .await
        .expect_err("a missing target must fail loudly");
    assert!(
        matches!(err, Error::UserNotFound),
        "expected UserNotFound, got {err:?}"
    );

    // No cascade ran: the bystander's session and credential are untouched and
    // no audit event was emitted.
    assert!(
        h.users
            .find_user_by_id(bystander.id)
            .await
            .expect("find bystander")
            .is_some(),
        "bystander survives",
    );
    assert_eq!(h.sessions.len(), 1, "bystander session untouched");
    assert_eq!(h.credentials.len(), 1, "bystander credential untouched");
    assert!(
        !h.audit
            .events()
            .iter()
            .any(|e| matches!(e.kind, AuditEventKind::AccountDeleted { .. })),
        "no deletion event for a missing target",
    );
}

// ---------------------------------------------------------------------------
// Operator passkey removal (F8 re-bind, D7 resolve-first, D3 operator copy).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn operator_remove_passkey_attributes_to_operator_and_sends_operator_copy() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let credential_id = first_credential_id(&h, user.id).await;

    h.operator
        .remove_passkey(user.id, &credential_id, operator())
        .await
        .expect("operator remove passkey");

    assert_eq!(h.credentials.len(), 0, "the credential was removed");

    // The removal is attributed to the operator, not the subject.
    let removed = h
        .audit
        .events()
        .into_iter()
        .find(|e| matches!(e.kind, AuditEventKind::CredentialRemoved { user_id } if user_id == user.id))
        .expect("a CredentialRemoved event was emitted");
    let Actor::Operator(recorded) = removed.actor else {
        panic!(
            "operator removal must attribute to Actor::Operator, got {:?}",
            removed.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");

    // The subject receives the operator-aware notice, never the self-service
    // "was this you?" copy.
    let notices = h.email.sent();
    assert!(
        notices
            .iter()
            .any(|e| e.subject == "Security notice: a passkey was removed by an administrator"),
        "operator-aware passkey-removed notice was sent",
    );
    assert!(
        !notices
            .iter()
            .any(|e| e.subject == "Security notice: passkey removed"),
        "the self-service passkey-removed copy must never fire on an operator action",
    );
}

#[tokio::test]
async fn operator_remove_passkey_refuses_cross_user_credential() {
    // F8: an operator names user X but hands a credential id that belongs to
    // user Y. The action must be refused, leave Y's credential intact, and emit
    // no mis-attributed audit row.
    let h = Harness::fresh();
    let victim = provision_user(&h, "victim@example.com").await;
    let named = provision_user(&h, "named@example.com").await;
    let victim_credential = first_credential_id(&h, victim.id).await;

    let before = h.audit.events().len();
    let err = h
        .operator
        .remove_passkey(named.id, &victim_credential, operator())
        .await
        .expect_err("cross-user credential must be refused");
    assert!(
        matches!(err, Error::PasskeyOwnershipMismatch),
        "expected PasskeyOwnershipMismatch, got {err:?}"
    );

    // The victim's credential survives and no removal event was recorded.
    assert!(
        h.credentials
            .find_passkey_by_credential_id(&victim_credential)
            .await
            .expect("find credential")
            .is_some(),
        "the victim's credential is untouched",
    );
    assert_eq!(
        h.audit.events().len(),
        before,
        "a refused cross-user removal emits no audit row",
    );
}

#[tokio::test]
async fn operator_remove_passkey_unknown_user_fails_loudly() {
    // D7: the subject is resolved before the credential store is touched.
    let h = Harness::fresh();
    let victim = provision_user(&h, "victim@example.com").await;
    let credential_id = first_credential_id(&h, victim.id).await;

    let err = h
        .operator
        .remove_passkey(UserId::new(), &credential_id, operator())
        .await
        .expect_err("a missing target must fail loudly");
    assert!(
        matches!(err, Error::UserNotFound),
        "expected UserNotFound, got {err:?}"
    );
    assert_eq!(
        h.credentials.len(),
        1,
        "no credential was removed for a missing target",
    );
}

#[tokio::test]
async fn operator_remove_passkey_suppresses_notice_when_policy_off() {
    let h = HarnessBuilder::new()
        .notification_policy(NotificationPolicy {
            passkey_removed: OperatorNotice::Suppress,
            ..NotificationPolicy::default()
        })
        .build();
    let user = provision_user(&h, "owner@example.com").await;
    let credential_id = first_credential_id(&h, user.id).await;

    h.operator
        .remove_passkey(user.id, &credential_id, operator())
        .await
        .expect("operator remove passkey");

    // Still removed and audited, but no subject notice was sent.
    assert_eq!(h.credentials.len(), 0, "the credential was removed");
    assert!(
        h.audit.events().iter().any(|e| matches!(
            e.kind,
            AuditEventKind::CredentialRemoved { user_id } if user_id == user.id
        )),
        "the removal is still audited under Suppress",
    );
    assert!(
        !h.email.sent().iter().any(|e| e
            .subject
            .starts_with("Security notice: a passkey was removed")),
        "Suppress sends no passkey-removed notice",
    );
}

// ---------------------------------------------------------------------------
// Operator single-session revoke (F8 re-bind, D7 resolve-first).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn operator_revoke_session_attributes_to_operator() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let session_id = only_session_id(&h, user.id).await;

    h.operator
        .revoke_session(user.id, session_id, operator())
        .await
        .expect("operator revoke session");

    assert_eq!(h.sessions.len(), 0, "the session was revoked");
    let revoked = h
        .audit
        .events()
        .into_iter()
        .find(|e| matches!(e.kind, AuditEventKind::SessionRevoked { session_id: id, .. } if id == session_id))
        .expect("a SessionRevoked event was emitted");
    let Actor::Operator(recorded) = revoked.actor else {
        panic!(
            "operator revoke must attribute to Actor::Operator, got {:?}",
            revoked.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7");
}

#[tokio::test]
async fn operator_revoke_session_refuses_cross_user_session() {
    // F8: an operator names user X but hands user Y's session id.
    let h = Harness::fresh();
    let victim = provision_user(&h, "victim@example.com").await;
    let named = provision_user(&h, "named@example.com").await;
    let victim_session = only_session_id(&h, victim.id).await;

    let before = h.audit.events().len();
    let err = h
        .operator
        .revoke_session(named.id, victim_session, operator())
        .await
        .expect_err("cross-user session must be refused");
    assert!(
        matches!(err, Error::SessionNotFound),
        "expected SessionNotFound, got {err:?}"
    );

    // The victim's session survives and no revoke event was recorded.
    assert!(
        h.sessions
            .find_session_by_id(victim_session)
            .await
            .expect("find session")
            .is_some(),
        "the victim's session is untouched",
    );
    assert_eq!(
        h.audit.events().len(),
        before,
        "a refused cross-user revoke emits no audit row",
    );
}

#[tokio::test]
async fn operator_revoke_session_unknown_user_fails_loudly() {
    // D7: the subject is resolved before the session store is touched.
    let h = Harness::fresh();
    let victim = provision_user(&h, "victim@example.com").await;
    let session_id = only_session_id(&h, victim.id).await;

    let err = h
        .operator
        .revoke_session(UserId::new(), session_id, operator())
        .await
        .expect_err("a missing target must fail loudly");
    assert!(
        matches!(err, Error::UserNotFound),
        "expected UserNotFound, got {err:?}"
    );
    assert_eq!(
        h.sessions.len(),
        1,
        "no session was revoked for a missing target"
    );
}

// ---------------------------------------------------------------------------
// Operator revoke-all (cache hook, D3 opt-in notice).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn operator_revoke_all_clears_sessions_and_suppresses_notice_by_default() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    assert_eq!(h.sessions.len(), 1, "user starts with a session");

    let count = h
        .operator
        .revoke_all_sessions(user.id, operator())
        .await
        .expect("operator revoke all");
    assert_eq!(count, 1, "the one active session was revoked");
    assert_eq!(h.sessions.len(), 0, "every session is gone");

    // sessions_revoked defaults to Suppress, so no notice goes out.
    assert!(
        !h.email.sent().iter().any(|e| e
            .subject
            .starts_with("Security notice: your account was signed out")),
        "revoke-all sends no notice under the default Suppress policy",
    );
}

#[tokio::test]
async fn operator_revoke_all_sends_operator_notice_when_opted_in() {
    let h = HarnessBuilder::new()
        .notification_policy(NotificationPolicy {
            sessions_revoked: OperatorNotice::Send,
            ..NotificationPolicy::default()
        })
        .build();
    let user = provision_user(&h, "owner@example.com").await;

    let count = h
        .operator
        .revoke_all_sessions(user.id, operator())
        .await
        .expect("operator revoke all");
    assert_eq!(count, 1);

    assert!(
        h.email.sent().iter().any(
            |e| e.subject == "Security notice: your account was signed out by an administrator"
        ),
        "opting in sends the operator-aware revoke-all notice",
    );
}

#[tokio::test]
async fn operator_revoke_all_unknown_user_fails_loudly() {
    let h = Harness::fresh();
    let bystander = provision_user(&h, "bystander@example.com").await;

    let err = h
        .operator
        .revoke_all_sessions(UserId::new(), operator())
        .await
        .expect_err("a missing target must fail loudly");
    assert!(
        matches!(err, Error::UserNotFound),
        "expected UserNotFound, got {err:?}"
    );
    assert_eq!(
        h.sessions.len(),
        1,
        "the bystander's session is untouched by a failed revoke-all",
    );
    let _ = bystander;
}
