//! Integration tests for the operator flows: host-driven operations acting on
//! a user _other_ than the acting one. The first flow is account deletion.

mod common;

use doorman_core::Error;
use doorman_core::audit::{Actor, AuditEvent, AuditEventKind, OperatorActor};
use doorman_core::storage::{UserId, UserStore};

use common::{Harness, provision_user, session_for};

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
