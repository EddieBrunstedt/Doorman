//! Audit-event model and sink abstraction.
//!
//! Managers emit these events for security-significant auth activity.
//! Hosts provide an [`AuditSink`] that persists or forwards them to a
//! durable log; [`NoopAuditSink`] exists only as a development default.

use std::any::Any;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::{SessionId, UserId};

/// One audit record emitted by an auth flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Client IP associated with the event, if known.
    pub ip: Option<String>,
    /// Client user-agent associated with the event, if known.
    pub user_agent: Option<String>,
    /// The specific event and its payload.
    pub kind: AuditEventKind,
}

/// Specific security event captured in an [`AuditEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A new session was minted for a user.
    SessionCreated {
        /// The user the session belongs to.
        user_id: UserId,
        /// The newly-created session.
        session_id: SessionId,
    },
    /// A session was explicitly revoked.
    SessionRevoked {
        /// The user the session belonged to.
        user_id: UserId,
        /// The revoked session.
        session_id: SessionId,
    },
    /// A session was rejected at resolution time because it had expired.
    SessionExpired {
        /// The user the session belonged to.
        user_id: UserId,
        /// The expired session.
        session_id: SessionId,
    },
    /// A passkey authentication succeeded and a session was minted.
    LoginSucceeded {
        /// The user that logged in.
        user_id: UserId,
    },
    /// Emitted on any passkey authentication failure — unknown or expired
    /// challenge, unknown credential, an unverifiable user-handle binding, a
    /// signature-counter regression (possible cloned authenticator), or a bad
    /// assertion. `user_id` is `Some` once the credential has been resolved
    /// and `None` for the pre-resolution failures (bad/expired challenge).
    /// The [`AuthFailureReason`] lets a host alert on the security-significant
    /// modes (counter regression, user-handle mismatch) without leaking which
    /// credential or secret was involved.
    AuthenticationFailed {
        /// The user, once the credential resolves; `None` for pre-resolution
        /// failures (bad/expired challenge).
        user_id: Option<UserId>,
        /// Why the attempt failed.
        reason: AuthFailureReason,
    },
    /// A passkey credential was registered for a user.
    CredentialAdded {
        /// The user the credential was added to.
        user_id: UserId,
    },
    /// A passkey credential was removed from a user.
    CredentialRemoved {
        /// The user the credential was removed from.
        user_id: UserId,
    },
    /// A signup link was requested for an address.
    SignupRequested {
        /// The provisioned user the link is bound to.
        user_id: UserId,
    },
    /// A signup token was consumed, starting first-passkey registration.
    SignupConsumed {
        /// The user whose signup token was consumed.
        user_id: UserId,
    },
    /// Emitted every time the recovery request endpoint is hit, including
    /// when the email does not resolve to a registered user (in which case
    /// `user_id` is `None`). The matching audit row makes a sustained
    /// enumeration probe visible even though the wire response is
    /// identical for known and unknown emails.
    RecoveryRequested {
        /// The matched user, or `None` when the address is unregistered.
        user_id: Option<UserId>,
    },
    /// Emitted when a recovery token is successfully consumed and a passkey
    /// registration ceremony is started against the user it identifies.
    RecoveryConsumed {
        /// The user whose recovery token was consumed.
        user_id: UserId,
    },
    /// Emitted on any recovery failure path — unknown email, rate-limit
    /// rejection, invalid token, expired token. Pairs with the
    /// [`RecoveryFailureReason`] for after-the-fact triage.
    RecoveryFailed {
        /// The matched user, when one was resolved before the failure.
        user_id: Option<UserId>,
        /// Why the recovery attempt failed.
        reason: RecoveryFailureReason,
    },
    /// Emitted when a verified email-change is requested: a confirmation link
    /// has been issued to the new address and the old address notified.
    EmailChangeRequested {
        /// The user requesting the change.
        user_id: UserId,
    },
    /// Emitted when an email-change confirmation token is redeemed and the
    /// account's address is updated.
    EmailChangeCompleted {
        /// The user whose address changed.
        user_id: UserId,
    },
    /// Emitted when an account and all of its sessions, credentials, tokens,
    /// and pending ceremonies are deleted.
    AccountDeleted {
        /// The deleted user.
        user_id: UserId,
    },
}

/// Why a passkey authentication attempt did not succeed. Pairs with
/// [`AuditEventKind::AuthenticationFailed`] for after-the-fact triage and
/// alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureReason {
    /// The presented challenge id did not resolve to an outstanding
    /// authentication ceremony (unknown or already consumed).
    InvalidChallenge,
    /// The authentication ceremony had expired before it was finished.
    ExpiredChallenge,
    /// The asserted credential id is not registered.
    UnknownCredential,
    /// The authenticator did not assert a user handle, or asserted one that
    /// does not map to the credential's stored owner. Either way the
    /// credential-to-user binding could not be confirmed, so no session is
    /// minted.
    UserHandleMismatch,
    /// The asserted signature counter did not advance past the stored value,
    /// which `webauthn-rs` flags as a possible cloned authenticator. The
    /// login is rejected and this event is emitted so the host can alert.
    CounterRegression,
    /// The assertion failed `webauthn-rs` verification for any other reason
    /// (bad signature, origin mismatch, malformed response, etc.).
    BadAssertion,
}

/// Why a recovery attempt did not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFailureReason {
    /// The request endpoint was asked to recover an email address that is
    /// not in the user table.
    UnknownEmail,
    /// A rate-limit policy rejected the request before any user lookup.
    RateLimited,
    /// A `recovery/consume` call presented a token the store did not
    /// recognise.
    InvalidToken,
    /// A `recovery/consume` call presented a token whose `expires_at` has
    /// already passed.
    ExpiredToken,
}

/// Destination for audit events emitted by the managers.
///
/// The [`Any`] supertrait lets a composition layer (e.g. the axum builder's
/// startup sanity checks) downcast a boxed sink to recognise the bundled
/// [`NoopAuditSink`]; host implementations get the blanket `Any` impl for
/// free and never have to think about it.
#[async_trait]
pub trait AuditSink: Send + Sync + Any {
    /// Persist or forward one audit event. Implementations should not block
    /// the auth flow on slow I/O; buffer or hand off as needed.
    async fn emit(&self, event: AuditEvent);
}

/// Audit sink that discards every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    async fn emit(&self, _event: AuditEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    #[test]
    fn noop_sink_downcasts_to_its_concrete_type() {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        assert!((sink.as_ref() as &dyn Any).is::<NoopAuditSink>());
    }

    #[test]
    fn custom_sink_does_not_masquerade_as_noop() {
        struct MySink;
        #[async_trait]
        impl AuditSink for MySink {
            async fn emit(&self, _event: AuditEvent) {}
        }

        let sink: Arc<dyn AuditSink> = Arc::new(MySink);
        assert!(!(sink.as_ref() as &dyn Any).is::<NoopAuditSink>());
    }
}
