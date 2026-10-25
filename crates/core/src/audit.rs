use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::client_ip::ClientIp;
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::session::SessionContext;
use crate::storage::{SessionId, SessionTransport, UserId};

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
        ip: ClientIp,
        user_agent: Option<String>,
    },
    Operator(OperatorActor),
}

impl From<&SessionContext> for Actor {
    fn from(context: &SessionContext) -> Self {
        Self::Subject {
            ip: context.ip(),
            user_agent: context.user_agent().map(str::to_owned),
        }
    }
}

impl From<OperatorActor> for Actor {
    fn from(operator: OperatorActor) -> Self {
        Self::Operator(operator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OperatorActorFields")]
pub struct OperatorActor {
    id: String,
    correlation_id: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
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
        for (field, value) in [
            ("id", Some(id.as_str())),
            ("correlation_id", correlation_id.as_deref()),
            ("ip", ip.as_deref()),
            ("user_agent", user_agent.as_deref()),
        ] {
            if value.is_some_and(|value| value.len() > Self::MAX_FIELD_LEN) {
                return Err(Error::InvalidOperatorActor {
                    field,
                    limit: Self::MAX_FIELD_LEN,
                });
            }
        }
        Ok(Self {
            id,
            correlation_id,
            ip,
            user_agent,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }

    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

#[derive(Deserialize)]
struct OperatorActorFields {
    id: String,
    correlation_id: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
}

impl TryFrom<OperatorActorFields> for OperatorActor {
    type Error = Error;

    fn try_from(fields: OperatorActorFields) -> Result<Self> {
        Self::new(
            fields.id,
            fields.correlation_id,
            fields.ip,
            fields.user_agent,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditEventKind {
    SessionCreated {
        user_id: UserId,
        session_id: SessionId,
        transport: SessionTransport,
    },
    SessionRevoked {
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
    PasskeyAdded {
        user_id: UserId,
    },
    PasskeyRemoved {
        user_id: UserId,
    },
    PasskeyRenamed {
        user_id: UserId,
    },
    SignupRequested {
        user_id: UserId,
    },
    SignupDenied,
    SignupLinkRedeemed {
        user_id: UserId,
    },
    SignupFailed {
        user_id: UserId,
        reason: SignupFailureReason,
    },
    RecoveryRequested {
        user_id: Option<UserId>,
    },
    RecoveryLinkRedeemed {
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
    UserDeleted {
        user_id: UserId,
    },
    ReauthSucceeded {
        user_id: UserId,
    },
    ReauthFailed {
        user_id: UserId,
        reason: AuthFailureReason,
    },
    OtherSessionsRevoked {
        user_id: UserId,
        revoked_count: u64,
    },
    OperatorRevokedAllSessions {
        user_id: UserId,
        revoked_count: u64,
    },
    OperatorDisabledUser {
        user_id: UserId,
    },
    OperatorEnabledUser {
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
            | Self::LoginSucceeded { user_id }
            | Self::PasskeyAdded { user_id }
            | Self::PasskeyRemoved { user_id }
            | Self::PasskeyRenamed { user_id }
            | Self::SignupRequested { user_id }
            | Self::SignupLinkRedeemed { user_id }
            | Self::SignupFailed { user_id, .. }
            | Self::RecoveryLinkRedeemed { user_id }
            | Self::EmailChangeRequested { user_id }
            | Self::EmailChangeCompleted { user_id }
            | Self::UserDeleted { user_id }
            | Self::ReauthSucceeded { user_id }
            | Self::ReauthFailed { user_id, .. }
            | Self::OtherSessionsRevoked { user_id, .. }
            | Self::OperatorRevokedAllSessions { user_id, .. }
            | Self::OperatorDisabledUser { user_id }
            | Self::OperatorEnabledUser { user_id }
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
            | Self::SignupFailed { .. }
            | Self::RecoveryFailed { .. }
            | Self::ReauthFailed { .. }
            | Self::RedemptionFailed { .. }
            | Self::SignupDenied => AuditSeverity::Warn,
            _ => AuditSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthFailureReason {
    UnknownPasskey,
    UserHandleMismatch,
    OwnershipMismatch,
    CounterRegression,
    UserVerificationMissing,
    BadAssertion,
    UserDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignupFailureReason {
    UserDisabled,
    SignupFinished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryFailureReason {
    UnknownEmail,
    RateLimited,
    UserDisabled,
    SignupUnfinished,
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
    WrongSession,
    Expired,
    Malformed,
    UserNotFound,
    UserDisabled,
    SignupFinished,
    SignupUnfinished,
    EmailChanged,
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
pub(crate) struct AuditDispatch {
    sink: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
}

impl AuditDispatch {
    pub(crate) fn new(sink: Arc<dyn AuditSink>, clock: Arc<dyn Clock>) -> Self {
        Self { sink, clock }
    }

    pub(crate) async fn emit(&self, actor: impl Into<Actor>, kind: AuditEventKind) {
        let event = AuditEvent {
            timestamp: self.clock.now(),
            actor: actor.into(),
            kind,
        };
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
                write!(f, "subject ip={ip}")?;
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
