use doorman_core::Error;
use doorman_core::audit::RecoveryFailureReason;
use doorman_core::audit::{Actor, AuditEvent, AuditEventKind, OperatorActor, SecretKind};
use doorman_core::destructive::DestructiveAction;
use doorman_core::operator::{NoticePolicy, OperatorNotice};
use doorman_core::session::SessionContext;
use doorman_core::storage::{PasskeyStore, SessionId, SessionStore, UserId, UserStatus, UserStore};

use crate::common::{
    Harness, HarnessBuilder, RECOVERY_URL, assert_last_redemption_unknown, authenticator,
    last_email_change_token, passkey_count, provision_user, session_count, session_for,
    token_from_email,
};

async fn first_credential_id(h: &Harness, user_id: UserId) -> Vec<u8> {
    let passkeys = h
        .passkeys
        .list_passkeys_for_user(user_id)
        .await
        .expect("list passkeys");
    passkeys
        .first()
        .map(|c| c.credential_id.clone())
        .expect("user has a passkey")
}

async fn only_session_id(h: &Harness, user_id: UserId) -> SessionId {
    let sessions = h
        .sessions
        .list_for_user(user_id)
        .await
        .expect("list sessions");
    sessions.first().map(|s| s.id).expect("user has a session")
}

fn operator() -> OperatorActor {
    OperatorActor::new(
        "support-agent-7",
        Some("authz-log-42".to_string()),
        Some("198.51.100.7".to_string()),
        Some("operator-console/1.0".to_string()),
    )
    .expect("operator actor within bounds")
}

#[derive(Debug, Clone, Copy)]
enum OperatorAction {
    DeleteUser,
    RemovePasskey,
    RevokeSession,
    RevokeAllSessions,
    ListPasskeys,
    ListSessions,
    Disable,
    Enable,
}

#[tokio::test]
async fn every_operator_action_on_an_unknown_user_fails_and_touches_nothing() {
    for action in [
        OperatorAction::DeleteUser,
        OperatorAction::RemovePasskey,
        OperatorAction::RevokeSession,
        OperatorAction::RevokeAllSessions,
        OperatorAction::ListPasskeys,
        OperatorAction::ListSessions,
        OperatorAction::Disable,
        OperatorAction::Enable,
    ] {
        let h = Harness::fresh();
        let bystander = provision_user(&h, "bystander@example.com").await;
        let credential_id = first_credential_id(&h, bystander.id).await;
        let session_id = only_session_id(&h, bystander.id).await;
        let audit_before = h.audit.events().len();
        let unknown = UserId::new();

        let result = match action {
            OperatorAction::DeleteUser => h.operator.delete_user(unknown, operator()).await,
            OperatorAction::RemovePasskey => h
                .operator
                .remove_passkey(unknown, &credential_id, operator())
                .await
                .map(drop),
            OperatorAction::RevokeSession => {
                h.operator
                    .revoke_session(unknown, session_id, operator())
                    .await
            }
            OperatorAction::RevokeAllSessions => h
                .operator
                .revoke_all_sessions(unknown, operator())
                .await
                .map(drop),
            OperatorAction::ListPasskeys => h
                .operator
                .list_passkeys(unknown, operator())
                .await
                .map(drop),
            OperatorAction::ListSessions => h
                .operator
                .list_sessions(unknown, operator())
                .await
                .map(drop),
            OperatorAction::Disable => h.operator.disable(unknown, operator()).await,
            OperatorAction::Enable => h.operator.enable(unknown, operator()).await,
        };

        assert!(
            matches!(result, Err(Error::UserNotFound)),
            "{action:?}: {result:?}"
        );
        assert!(
            matches!(status_of(&h, bystander.id).await, UserStatus::Active),
            "{action:?}"
        );
        assert_eq!(session_count(&h, bystander.id).await, 1, "{action:?}");
        assert_eq!(passkey_count(&h, bystander.id).await, 1, "{action:?}");
        assert_eq!(h.audit.events().len(), audit_before, "{action:?}");
    }
}

#[tokio::test]
async fn operator_delete_cascades_all_stores() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;
    let session = session_for(&h, &user).await;

    h.destructive_actions
        .perform(
            &session,
            DestructiveAction::RequestEmailChange {
                new_email: "elsewhere@example.com".into(),
            },
            None,
            Default::default(),
        )
        .await
        .expect("request email change");
    let email_change_token = last_email_change_token(&h);
    let (challenge_id, options) = h
        .passkey
        .start_registration(&session)
        .await
        .expect("start a pending registration");
    let attestation = authenticator().do_registration(options);

    assert_eq!(
        session_count(&h, user.id).await,
        2,
        "signup and the test's own session are active"
    );
    assert_eq!(passkey_count(&h, user.id).await, 1, "signup left a passkey");

    h.operator
        .delete_user(user.id, operator())
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
    assert_eq!(session_count(&h, user.id).await, 0, "sessions cascaded");
    assert_eq!(passkey_count(&h, user.id).await, 0, "passkeys cascaded");

    let err = h
        .user
        .confirm_email_change(&email_change_token, SessionContext::default())
        .await
        .expect_err("the email-change link is gone");
    assert!(matches!(err, Error::InvalidEmailLink));
    assert_last_redemption_unknown(&h, SecretKind::EmailChangeLink);

    let err = h
        .passkey
        .finish_registration(challenge_id, &attestation, None, SessionContext::default())
        .await
        .expect_err("the pending ceremony is gone");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
    assert_last_redemption_unknown(&h, SecretKind::RegistrationChallenge);
}

#[tokio::test]
async fn operator_delete_emits_user_deleted_with_operator_actor() {
    let h = Harness::fresh();
    let user = provision_user(&h, "doomed@example.com").await;

    h.operator
        .delete_user(user.id, operator())
        .await
        .expect("operator delete");

    let deleted = h
        .audit
        .events()
        .into_iter()
        .find(|e| matches!(e.kind, AuditEventKind::UserDeleted { user_id } if user_id == user.id))
        .expect("an UserDeleted event was emitted");

    let AuditEvent { actor, .. } = deleted;
    let Actor::Operator(recorded) = actor else {
        panic!("operator delete must attribute to Actor::Operator, got {actor:?}");
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");
    assert_eq!(recorded.correlation_id.as_deref(), Some("authz-log-42"));
    assert_eq!(recorded.ip.as_deref(), Some("198.51.100.7"));
    assert_eq!(recorded.user_agent.as_deref(), Some("operator-console/1.0"));
}

#[tokio::test]
async fn operator_remove_passkey_attributes_to_operator_and_sends_operator_copy() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let credential_id = first_credential_id(&h, user.id).await;

    h.operator
        .remove_passkey(user.id, &credential_id, operator())
        .await
        .expect("operator remove passkey");

    assert_eq!(
        passkey_count(&h, user.id).await,
        0,
        "the passkey was removed"
    );

    let removed = h
        .audit
        .events()
        .into_iter()
        .find(
            |e| matches!(e.kind, AuditEventKind::PasskeyRemoved { user_id } if user_id == user.id),
        )
        .expect("a PasskeyRemoved event was emitted");
    let Actor::Operator(recorded) = removed.actor else {
        panic!(
            "operator removal must attribute to Actor::Operator, got {:?}",
            removed.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");

    let notices = h.email.sent();
    assert!(
        notices
            .iter()
            .any(|e| e.subject == "Security notice: a passkey was removed by an operator"),
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
async fn operator_remove_passkey_refuses_cross_user_passkey() {
    let h = Harness::fresh();
    let victim = provision_user(&h, "victim@example.com").await;
    let named = provision_user(&h, "named@example.com").await;
    let victim_passkey = first_credential_id(&h, victim.id).await;

    let before = h.audit.events().len();
    let err = h
        .operator
        .remove_passkey(named.id, &victim_passkey, operator())
        .await
        .expect_err("cross-user passkey must be refused");
    assert!(
        matches!(err, Error::PasskeyOwnershipMismatch),
        "expected PasskeyOwnershipMismatch, got {err:?}"
    );

    assert!(
        h.passkeys
            .find_passkey_by_credential_id(&victim_passkey)
            .await
            .expect("find passkey")
            .is_some(),
        "the victim's passkey is untouched",
    );
    assert_eq!(
        h.audit.events().len(),
        before,
        "a refused cross-user removal emits no audit row",
    );
}

#[tokio::test]
async fn operator_remove_passkey_suppresses_notice_when_policy_off() {
    let h = HarnessBuilder::new()
        .notice_policy(NoticePolicy {
            passkey_removed: OperatorNotice::Suppress,
            ..NoticePolicy::default()
        })
        .build();
    let user = provision_user(&h, "owner@example.com").await;
    let credential_id = first_credential_id(&h, user.id).await;

    h.operator
        .remove_passkey(user.id, &credential_id, operator())
        .await
        .expect("operator remove passkey");

    assert_eq!(
        passkey_count(&h, user.id).await,
        0,
        "the passkey was removed"
    );
    assert!(
        h.audit.events().iter().any(|e| matches!(
            e.kind,
            AuditEventKind::PasskeyRemoved { user_id } if user_id == user.id
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

#[tokio::test]
async fn operator_revoke_session_attributes_to_operator() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    let session_id = only_session_id(&h, user.id).await;

    h.operator
        .revoke_session(user.id, session_id, operator())
        .await
        .expect("operator revoke session");

    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "the session was revoked"
    );
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
async fn operator_revoke_all_clears_sessions_and_suppresses_notice_by_default() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;
    assert_eq!(
        session_count(&h, user.id).await,
        1,
        "user starts with a session"
    );

    let count = h
        .operator
        .revoke_all_sessions(user.id, operator())
        .await
        .expect("operator revoke all");
    assert_eq!(count, 1, "the one active session was revoked");
    assert_eq!(session_count(&h, user.id).await, 0, "every session is gone");

    assert!(
        !h.email.sent().iter().any(|e| e
            .subject
            .starts_with("Security notice: you were logged out")),
        "revoke-all sends no notice under the default Suppress policy",
    );
}

#[tokio::test]
async fn operator_revoke_all_sends_operator_notice_when_opted_in() {
    let h = HarnessBuilder::new()
        .notice_policy(NoticePolicy {
            sessions_revoked: OperatorNotice::Send,
            ..NoticePolicy::default()
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
        h.email
            .sent()
            .iter()
            .any(|e| e.subject == "Security notice: you were logged out by an operator"),
        "opting in sends the operator-aware revoke-all notice",
    );
}

#[tokio::test]
async fn operator_revoke_all_emits_audit_with_operator_actor() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;

    h.operator
        .revoke_all_sessions(user.id, operator())
        .await
        .expect("operator revoke all");

    let event = h
        .audit
        .events()
        .into_iter()
        .find(|e| {
            matches!(
                e.kind,
                AuditEventKind::OperatorRevokedAllSessions { user_id, .. } if user_id == user.id
            )
        })
        .expect("an OperatorRevokedAllSessions event was emitted");
    let Actor::Operator(recorded) = event.actor else {
        panic!(
            "revoke-all must attribute to Actor::Operator, got {:?}",
            event.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");
}

#[tokio::test]
async fn operator_list_passkeys_returns_summaries_and_audits() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;

    let summaries = h
        .operator
        .list_passkeys(user.id, operator())
        .await
        .expect("operator list passkeys");
    assert_eq!(summaries.len(), 1, "the provisioned passkey is listed");

    let listed = h
        .audit
        .events()
        .into_iter()
        .find(|e| {
            matches!(
                e.kind,
                AuditEventKind::OperatorListedPasskeys { user_id } if user_id == user.id
            )
        })
        .expect("an OperatorListedPasskeys event was emitted");
    let Actor::Operator(recorded) = listed.actor else {
        panic!(
            "operator read must attribute to Actor::Operator, got {:?}",
            listed.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");
}

#[tokio::test]
async fn operator_list_sessions_returns_summaries_without_token_hash_and_audits() {
    let h = Harness::fresh();
    let user = provision_user(&h, "owner@example.com").await;

    let summaries = h
        .operator
        .list_sessions(user.id, operator())
        .await
        .expect("operator list sessions");
    assert_eq!(summaries.len(), 1, "the active session is listed");

    let summary = &summaries[0];
    assert_eq!(summary.user_id, user.id, "summary is the subject's session");

    let listed = h
        .audit
        .events()
        .into_iter()
        .find(|e| {
            matches!(
                e.kind,
                AuditEventKind::OperatorListedSessions { user_id } if user_id == user.id
            )
        })
        .expect("an OperatorListedSessions event was emitted");
    let Actor::Operator(recorded) = listed.actor else {
        panic!(
            "operator read must attribute to Actor::Operator, got {:?}",
            listed.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");
}

async fn status_of(h: &Harness, user_id: UserId) -> UserStatus {
    h.users
        .find_user_by_id(user_id)
        .await
        .expect("find user")
        .expect("user exists")
        .status
}

#[tokio::test]
async fn operator_disable_bars_user_and_drops_live_sessions() {
    let h = Harness::fresh();
    let user = provision_user(&h, "disabled@example.com").await;
    assert_eq!(
        session_count(&h, user.id).await,
        1,
        "user starts with a live session"
    );

    h.operator
        .disable(user.id, operator())
        .await
        .expect("operator disable");

    assert!(
        matches!(status_of(&h, user.id).await, UserStatus::Disabled { .. }),
        "the user resolves as Disabled",
    );
    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "every live session was revoked"
    );
}

#[tokio::test]
async fn operator_disable_emits_status_and_revoke_audit_with_operator_actor() {
    let h = Harness::fresh();
    let user = provision_user(&h, "disabled@example.com").await;

    h.operator
        .disable(user.id, operator())
        .await
        .expect("operator disable");

    let disabled = h
        .audit
        .events()
        .into_iter()
        .find(|e| {
            matches!(
                e.kind,
                AuditEventKind::OperatorDisabledUser { user_id } if user_id == user.id
            )
        })
        .expect("an OperatorDisabledUser event was emitted");
    let Actor::Operator(recorded) = disabled.actor else {
        panic!(
            "disable must attribute to Actor::Operator, got {:?}",
            disabled.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");

    assert!(
        h.audit.events().iter().any(|e| matches!(
            e.kind,
            AuditEventKind::OperatorRevokedAllSessions { user_id, .. } if user_id == user.id
        )),
        "the session sweep emits OperatorRevokedAllSessions",
    );
}

#[tokio::test]
async fn operator_disable_suppresses_notice_by_default() {
    let h = Harness::fresh();
    let user = provision_user(&h, "disabled@example.com").await;

    h.operator
        .disable(user.id, operator())
        .await
        .expect("operator disable");

    assert!(
        !h.email.sent().iter().any(|e| e
            .subject
            .starts_with("Security notice: your access was disabled")),
        "disable sends no notice under the default Suppress policy",
    );
}

#[tokio::test]
async fn operator_disable_sends_operator_notice_when_opted_in() {
    let h = HarnessBuilder::new()
        .notice_policy(NoticePolicy {
            user_disabled: OperatorNotice::Send,
            ..NoticePolicy::default()
        })
        .build();
    let user = provision_user(&h, "disabled@example.com").await;

    h.operator
        .disable(user.id, operator())
        .await
        .expect("operator disable");

    assert!(
        h.email
            .sent()
            .iter()
            .any(|e| e.subject == "Security notice: your access was disabled by an operator"),
        "opting in sends the operator-aware disabled notice",
    );
}

#[tokio::test]
async fn operator_disable_is_idempotent() {
    let h = Harness::fresh();
    let user = provision_user(&h, "disabled@example.com").await;

    h.operator
        .disable(user.id, operator())
        .await
        .expect("first disable");
    h.operator
        .disable(user.id, operator())
        .await
        .expect("second disable is idempotent");

    assert!(
        matches!(status_of(&h, user.id).await, UserStatus::Disabled { .. }),
        "the user is still Disabled after a redundant disable",
    );
    assert_eq!(
        session_count(&h, user.id).await,
        0,
        "no live sessions reappear"
    );
}

#[tokio::test]
async fn operator_enable_returns_user_to_active_and_audits() {
    let h = Harness::fresh();
    let user = provision_user(&h, "thawed@example.com").await;
    h.operator
        .disable(user.id, operator())
        .await
        .expect("disable");
    assert!(matches!(
        status_of(&h, user.id).await,
        UserStatus::Disabled { .. }
    ));

    h.operator
        .enable(user.id, operator())
        .await
        .expect("operator enable");

    assert!(
        matches!(status_of(&h, user.id).await, UserStatus::Active),
        "the user is Active again",
    );
    let enabled = h
        .audit
        .events()
        .into_iter()
        .find(|e| {
            matches!(
                e.kind,
                AuditEventKind::OperatorEnabledUser { user_id } if user_id == user.id
            )
        })
        .expect("an OperatorEnabledUser event was emitted");
    let Actor::Operator(recorded) = enabled.actor else {
        panic!(
            "enable must attribute to Actor::Operator, got {:?}",
            enabled.actor
        );
    };
    assert_eq!(recorded.id, "support-agent-7", "actor id recorded verbatim");
}

#[tokio::test]
async fn disable_blocks_recovery_then_enable_restores_it() {
    let h = Harness::fresh();
    let user = provision_user(&h, "alice@example.com").await;

    h.operator
        .disable(user.id, operator())
        .await
        .expect("disable");

    let mail_before = h.email.sent().len();
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("silent ok for a disabled user");

    assert_eq!(
        h.email.sent().len(),
        mail_before,
        "a disabled user gets no recovery link",
    );
    assert!(
        h.audit.events().iter().any(|e| matches!(
            e.kind,
            AuditEventKind::RecoveryFailed {
                reason: RecoveryFailureReason::UserDisabled,
                user_id: Some(id),
            } if id == user.id,
        )),
        "the refusal is audited as UserDisabled",
    );

    h.operator
        .enable(user.id, operator())
        .await
        .expect("enable");
    h.recovery
        .request_recovery("alice@example.com", SessionContext::default())
        .await
        .expect("recovery request after enable");
    let link = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Recover access with a new passkey")
        .expect("an enabled user is sent a recovery link");
    h.recovery
        .redeem_recovery_link(
            &token_from_email(&link.body_text, RECOVERY_URL),
            SessionContext::default(),
        )
        .await
        .expect("an enabled user can recover again");
}
