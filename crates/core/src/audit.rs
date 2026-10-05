use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::storage::{SessionId, UserId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub actor: Actor,
    pub kind: AuditEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "actor_type", rename_all = "snake_case")]
pub enum Actor {
    Subject {
        ip: Option<String>,
        user_agent: Option<String>,
    },
    Operator(OperatorActor),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorActor {
    pub id: String,
    pub correlation_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl OperatorActor {
    pub const MAX_FIELD_LEN: usize = 1024;

    pub fn new(
        id: impl Into<String>,
        correlation_id: Option<String>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Self> {
        let id = id.into();
        if id.len() > Self::MAX_FIELD_LEN {
            return Err(Error::InvalidOperatorActor {
                field: "id",
                limit: Self::MAX_FIELD_LEN,
            });
        }
        if let Some(correlation_id) = &correlation_id
            && correlation_id.len() > Self::MAX_FIELD_LEN
        {
            return Err(Error::InvalidOperatorActor {
                field: "correlation_id",
                limit: Self::MAX_FIELD_LEN,
            });
        }
        Ok(Self {
            id,
            correlation_id,
            ip,
            user_agent,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
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
    },
    AuthenticationFailed {
        user_id: Option<UserId>,
        reason: AuthFailureReason,
    },
    CredentialAdded {
        user_id: UserId,
    },
    CredentialRemoved {
        user_id: UserId,
    },
    CredentialRenamed {
        user_id: UserId,
    },
    SignupRequested {
        user_id: UserId,
    },
    SignupDenied,
    SignupConsumed {
        user_id: UserId,
    },
    RecoveryRequested {
        user_id: Option<UserId>,
    },
    RecoveryConsumed {
        user_id: UserId,
    },
    RecoveryFailed {
        user_id: Option<UserId>,
        reason: RecoveryFailureReason,
    },
    EmailChangeRequested {
        user_id: UserId,
    },
    EmailChangeCompleted {
        user_id: UserId,
    },
    AccountDeleted {
        user_id: UserId,
    },
    ReauthSucceeded {
        user_id: UserId,
    },
    ReauthFailed {
        user_id: UserId,
        reason: AuthFailureReason,
    },
    OperatorRevokedAllSessions {
        user_id: UserId,
        revoked_count: u64,
    },
    OperatorDisabledAccount {
        user_id: UserId,
    },
    OperatorEnabledAccount {
        user_id: UserId,
    },
    OperatorListedPasskeys {
        user_id: UserId,
    },
    OperatorListedSessions {
        user_id: UserId,
    },
    RedemptionFailed {
        user_id: Option<UserId>,
        secret: SecretKind,
        reason: RedemptionFailureReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warn,
}

impl AuditEventKind {
    pub fn user_id(&self) -> Option<UserId> {
        match self {
            Self::SessionCreated { user_id, .. }
            | Self::SessionRevoked { user_id, .. }
            | Self::SessionExpired { user_id, .. }
            | Self::LoginSucceeded { user_id }
            | Self::CredentialAdded { user_id }
            | Self::CredentialRemoved { user_id }
            | Self::CredentialRenamed { user_id }
            | Self::SignupRequested { user_id }
            | Self::SignupConsumed { user_id }
            | Self::RecoveryConsumed { user_id }
            | Self::EmailChangeRequested { user_id }
            | Self::EmailChangeCompleted { user_id }
            | Self::AccountDeleted { user_id }
            | Self::ReauthSucceeded { user_id }
            | Self::ReauthFailed { user_id, .. }
            | Self::OperatorRevokedAllSessions { user_id, .. }
            | Self::OperatorDisabledAccount { user_id }
            | Self::OperatorEnabledAccount { user_id }
            | Self::OperatorListedPasskeys { user_id }
            | Self::OperatorListedSessions { user_id } => Some(*user_id),
            Self::AuthenticationFailed { user_id, .. }
            | Self::RecoveryRequested { user_id }
            | Self::RecoveryFailed { user_id, .. }
            | Self::RedemptionFailed { user_id, .. } => *user_id,
            Self::SignupDenied => None,
        }
    }

    pub fn severity(&self) -> AuditSeverity {
        match self {
            Self::AuthenticationFailed { .. }
            | Self::RecoveryFailed { .. }
            | Self::ReauthFailed { .. }
            | Self::RedemptionFailed { .. }
            | Self::SessionExpired { .. }
            | Self::SignupDenied => AuditSeverity::Warn,
            _ => AuditSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthFailureReason {
    UnknownCredential,
    UserHandleMismatch,
    OwnershipMismatch,
    CounterRegression,
    UserVerificationMissing,
    BadAssertion,
    AccountDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryFailureReason {
    UnknownEmail,
    RateLimited,
    AccountDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecretKind {
    RegistrationChallenge,
    LoginChallenge,
    ReauthChallenge,
    SignupLink,
    RecoveryLink,
    EmailChangeLink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RedemptionFailureReason {
    Unknown,
    WrongPurpose,
    Expired,
    Malformed,
    UserNotFound,
    AccountDisabled,
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

#[derive(Clone)]
pub struct AuditDispatch {
    sink: Arc<dyn AuditSink>,
}

impl AuditDispatch {
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    pub async fn emit(&self, event: AuditEvent) {
        let actor = ActorDisplay(&event.actor);
        let user_id = event.kind.user_id();
        match event.kind.severity() {
            AuditSeverity::Info => tracing::info!(
                target: "doorman::audit",
                kind = ?event.kind,
                user_id = ?user_id,
                %actor,
            ),
            AuditSeverity::Warn => tracing::warn!(
                target: "doorman::audit",
                kind = ?event.kind,
                user_id = ?user_id,
                %actor,
            ),
        }
        self.sink.emit(event).await;
    }
}

struct ActorDisplay<'a>(&'a Actor);

impl fmt::Display for ActorDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Actor::Subject { ip, user_agent } => {
                f.write_str("subject")?;
                if let Some(ip) = ip {
                    write!(f, " ip={}", Escaped(ip))?;
                }
                if let Some(user_agent) = user_agent {
                    write!(f, " ua={}", Escaped(user_agent))?;
                }
                Ok(())
            }
            Actor::Operator(op) => {
                write!(f, "operator id={}", Escaped(&op.id))?;
                if let Some(correlation_id) = &op.correlation_id {
                    write!(f, " correlation_id={}", Escaped(correlation_id))?;
                }
                if let Some(ip) = &op.ip {
                    write!(f, " ip={}", Escaped(ip))?;
                }
                if let Some(user_agent) = &op.user_agent {
                    write!(f, " ua={}", Escaped(user_agent))?;
                }
                Ok(())
            }
        }
    }
}

struct Escaped<'a>(&'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.chars() {
            if ch.is_control() {
                for escaped in ch.escape_default() {
                    f.write_char(escaped)?;
                }
            } else {
                f.write_char(ch)?;
            }
        }
        Ok(())
    }
}
