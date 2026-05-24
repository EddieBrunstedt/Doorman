use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::{SessionId, UserId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub kind: AuditEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    SessionCreated {
        user_id: UserId,
        session_id: SessionId,
    },
    SessionRevoked {
        user_id: UserId,
        session_id: SessionId,
    },
    SessionExpired {
        user_id: UserId,
        session_id: SessionId,
    },
    LoginSucceeded {
        user_id: UserId,
        method: AuthMethod,
    },
    LoginFailed {
        identifier: String,
        reason: LoginFailureReason,
    },
    LogoutSucceeded {
        user_id: UserId,
        session_id: SessionId,
    },
    PasswordChanged {
        user_id: UserId,
    },
    EmailVerified {
        user_id: UserId,
    },
    PasswordResetRequested {
        user_id: UserId,
    },
    PasswordResetCompleted {
        user_id: UserId,
    },
    CredentialAdded {
        user_id: UserId,
        credential_kind: CredentialKind,
    },
    CredentialRemoved {
        user_id: UserId,
        credential_kind: CredentialKind,
    },
    MagicLinkRequested {
        user_id: UserId,
    },
    MagicLinkConsumed {
        user_id: UserId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Passkey,
    OAuth,
    MagicLink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    Passkey,
    OAuth,
    MagicLink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginFailureReason {
    UserNotFound,
    InvalidCredential,
    AccountLocked,
    EmailNotVerified,
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn emit(&self, event: AuditEvent);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    async fn emit(&self, _event: AuditEvent) {}
}
