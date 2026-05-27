//! Audit-event model and sink abstraction.
//!
//! Managers emit these events for security-significant auth activity.
//! Hosts provide an [`AuditSink`] that persists or forwards them to a
//! durable log; [`NoopAuditSink`] exists only as a development default.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::{SessionId, UserId};

/// One audit record emitted by an auth flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub kind: AuditEventKind,
}

/// Specific security event captured in an [`AuditEvent`].
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

/// Authentication method that produced a successful login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Passkey,
    OAuth,
    MagicLink,
}

/// Credential family added to or removed from a user account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Passkey,
    OAuth,
    MagicLink,
}

/// Normalised reason for a failed login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginFailureReason {
    UserNotFound,
    InvalidCredential,
    AccountLocked,
    EmailNotVerified,
}

/// Destination for audit events emitted by the managers.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn emit(&self, event: AuditEvent);

    /// Used by the axum builder's startup sanity checks to detect that the
    /// host is running with no real audit sink wired up. Implementations
    /// other than [`NoopAuditSink`] should leave the default in place.
    #[doc(hidden)]
    fn is_noop_sink(&self) -> bool {
        false
    }
}

/// Audit sink that discards every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    async fn emit(&self, _event: AuditEvent) {}

    fn is_noop_sink(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn noop_sink_is_detected_as_noop() {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        assert!(sink.is_noop_sink());
    }

    #[test]
    fn custom_sink_default_is_not_noop() {
        struct MySink;
        #[async_trait]
        impl AuditSink for MySink {
            async fn emit(&self, _event: AuditEvent) {}
        }

        let sink: Arc<dyn AuditSink> = Arc::new(MySink);
        assert!(!sink.is_noop_sink());
    }
}
