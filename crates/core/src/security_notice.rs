use std::collections::BTreeSet;
use std::sync::Arc;

use crate::email::{EmailContent, EmailTemplates, Mailer};
use crate::storage::{User, UserId, UserStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperatorNotice {
    PasskeyRemoved,
    SessionsRevoked,
    UserDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticePolicy {
    sent: BTreeSet<OperatorNotice>,
}

impl Default for NoticePolicy {
    fn default() -> Self {
        Self {
            sent: BTreeSet::from([OperatorNotice::PasskeyRemoved]),
        }
    }
}

impl NoticePolicy {
    pub fn send(mut self, notice: OperatorNotice) -> Self {
        self.sent.insert(notice);
        self
    }

    pub fn suppress(mut self, notice: OperatorNotice) -> Self {
        self.sent.remove(&notice);
        self
    }

    pub fn sends(&self, notice: OperatorNotice) -> bool {
        self.sent.contains(&notice)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityNotice<'a> {
    RecoveryRequested,
    RecoveryCompleted,
    EmailChangeRequested { new_email: &'a str },
    PasskeyRegistered { passkey_name: Option<&'a str> },
    PasskeyRemoved { passkey_name: Option<&'a str> },
    OtherSessionRevoked,
    OtherSessionsRevoked,
    OperatorRemovedPasskey { passkey_name: Option<&'a str> },
    OperatorRevokedSessions,
    OperatorDisabledUser,
}

impl SecurityNotice<'_> {
    fn operator_notice(self) -> Option<OperatorNotice> {
        match self {
            Self::OperatorRemovedPasskey { .. } => Some(OperatorNotice::PasskeyRemoved),
            Self::OperatorRevokedSessions => Some(OperatorNotice::SessionsRevoked),
            Self::OperatorDisabledUser => Some(OperatorNotice::UserDisabled),
            Self::RecoveryRequested
            | Self::RecoveryCompleted
            | Self::EmailChangeRequested { .. }
            | Self::PasskeyRegistered { .. }
            | Self::PasskeyRemoved { .. }
            | Self::OtherSessionRevoked
            | Self::OtherSessionsRevoked => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::RecoveryRequested => "recovery requested notice",
            Self::RecoveryCompleted => "recovery completed notice",
            Self::EmailChangeRequested { .. } => "email change requested notice",
            Self::PasskeyRegistered { .. } => "passkey registered notice",
            Self::PasskeyRemoved { .. } => "passkey removed notice",
            Self::OtherSessionRevoked => "other-session revoked notice",
            Self::OtherSessionsRevoked => "other-sessions revoked notice",
            Self::OperatorRemovedPasskey { .. } => "operator passkey removed notice",
            Self::OperatorRevokedSessions => "operator sessions revoked notice",
            Self::OperatorDisabledUser => "operator user disabled notice",
        }
    }

    fn render(self, templates: &dyn EmailTemplates, user: &User) -> EmailContent {
        match self {
            Self::RecoveryRequested => templates.recovery_requested_notice_email(user),
            Self::RecoveryCompleted => templates.recovery_completed_notice_email(user),
            Self::EmailChangeRequested { new_email } => {
                templates.email_change_requested_notice_email(user, new_email)
            }
            Self::PasskeyRegistered { passkey_name } => {
                templates.passkey_registered_notice_email(user, passkey_name)
            }
            Self::PasskeyRemoved { passkey_name } => {
                templates.passkey_removed_notice_email(user, passkey_name)
            }
            Self::OtherSessionRevoked => templates.other_session_revoked_notice_email(user),
            Self::OtherSessionsRevoked => templates.other_sessions_revoked_notice_email(user),
            Self::OperatorRemovedPasskey { passkey_name } => {
                templates.operator_passkey_removed_notice_email(user, passkey_name)
            }
            Self::OperatorRevokedSessions => templates.operator_sessions_revoked_notice_email(user),
            Self::OperatorDisabledUser => templates.operator_user_disabled_notice_email(user),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SecurityNotices {
    mailer: Mailer,
    users: Arc<dyn UserStore>,
    policy: NoticePolicy,
}

impl SecurityNotices {
    pub(crate) fn new(mailer: Mailer, users: Arc<dyn UserStore>, policy: NoticePolicy) -> Self {
        Self {
            mailer,
            users,
            policy,
        }
    }

    pub(crate) fn policy(&self) -> &NoticePolicy {
        &self.policy
    }

    pub(crate) async fn send(&self, user: &User, notice: SecurityNotice<'_>) {
        if self.suppresses(notice) {
            return;
        }
        self.deliver(user, notice).await;
    }

    pub(crate) async fn send_to(&self, user_id: UserId, notice: SecurityNotice<'_>) {
        if self.suppresses(notice) {
            return;
        }
        match self.users.find_user_by_id(user_id).await {
            Ok(Some(user)) => self.deliver(&user, notice).await,
            Ok(None) => tracing::warn!(
                %user_id,
                "{} skipped because user was not found",
                notice.label()
            ),
            Err(err) => tracing::warn!(
                error = %err,
                %user_id,
                "{} skipped because user lookup failed",
                notice.label()
            ),
        }
    }

    fn suppresses(&self, notice: SecurityNotice<'_>) -> bool {
        notice
            .operator_notice()
            .is_some_and(|operator_notice| !self.policy.sends(operator_notice))
    }

    async fn deliver(&self, user: &User, notice: SecurityNotice<'_>) {
        self.mailer
            .send_best_effort(user, notice.label(), |templates| {
                notice.render(templates, user)
            })
            .await;
    }
}
