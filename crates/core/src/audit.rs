//! Audit-event model and sink abstraction.
//!
//! Managers emit these events for security-significant auth activity.
//! Hosts provide an [`AuditSink`] that persists or forwards them to a
//! durable log; [`NoopAuditSink`] exists only as a development default.

use std::any::Any;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::storage::{SessionId, UserId};

/// One audit record emitted by an auth flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Who acted. The subject's or the operator's network metadata lives
    /// inside this descriptor so the two principals can never be confused.
    pub actor: Actor,
    /// The specific event and its payload. Its `user_id` always identifies
    /// the *subject* of the event, regardless of who acted.
    pub kind: AuditEventKind,
}

/// Who performed the action recorded by an [`AuditEvent`].
///
/// The event's [`AuditEventKind`] always names the *subject* (the account the
/// action targets). This descriptor names the *actor*, and carries that
/// actor's network metadata, so a self-service action and an operator action
/// against the same subject are no longer indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "actor_type", rename_all = "snake_case")]
pub enum Actor {
    /// The subject acted on themselves; doorman verified them via the session.
    /// The `ip` / `user_agent` are the subject's own request metadata.
    Subject {
        /// The subject's client IP, if known.
        ip: Option<String>,
        /// The subject's client user-agent, if known.
        user_agent: Option<String>,
    },
    /// A host-supplied operator acted on the subject. Recorded verbatim and
    /// never verified by doorman.
    Operator(OperatorActor),
}

/// A host-supplied operator that acted on a subject's behalf.
///
/// Every field is recorded verbatim and is **never verified** by doorman: the
/// audit row witnesses only that some caller asserted this identity. Because
/// the host may derive these values from attacker-influenceable input, doorman
/// stores them unmodified (fidelity) but consumers must neutralize them on
/// render (e.g. strip control characters before writing to a text log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorActor {
    /// The operator's identity, verbatim and unverified.
    pub id: String,
    /// An optional correlation id tying the action back to the host's own
    /// authorization log.
    pub correlation_id: Option<String>,
    /// The *operator's* client IP, if the host captured one.
    pub ip: Option<String>,
    /// The *operator's* client user-agent, if the host captured one.
    pub user_agent: Option<String>,
}

impl OperatorActor {
    /// Maximum byte length accepted for [`id`](Self::id) and
    /// [`correlation_id`](Self::correlation_id). A free-form, host-supplied
    /// value with no bound is an audit-store bloat / cost vector, so the
    /// constructor caps each at 1024 bytes.
    pub const MAX_FIELD_LEN: usize = 1024;

    /// Build an [`OperatorActor`], recording every field **verbatim** — no
    /// control-character stripping or other neutralization (that is the
    /// consumer's job on render).
    ///
    /// The `id` and `correlation_id` are each bounded to
    /// [`MAX_FIELD_LEN`](Self::MAX_FIELD_LEN) bytes. A value that exceeds the
    /// bound is **rejected** with [`Error::InvalidOperatorActor`] rather than
    /// silently truncated, so a caller never persists a quietly mangled
    /// identity.
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
    /// A passkey credential's friendly name was changed. Purely a relabel —
    /// the credential itself is untouched — but recorded so the credential
    /// inventory's change history stays complete alongside add / remove.
    CredentialRenamed {
        /// The user whose credential was renamed.
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
    /// An operator revoked **every** session belonging to a user at once
    /// (the bulk "sign the account out everywhere" operator flow). Carries
    /// only the subject's `user_id` — the flow is a set delete with no single
    /// `session_id` to name, mirroring [`AccountDeleted`](Self::AccountDeleted)
    /// rather than the per-session [`SessionRevoked`](Self::SessionRevoked).
    /// The self-service bulk revoke is silent; only the operator path records
    /// this row, so the [`Actor::Operator`] it carries is the accountability
    /// trail for the most consequential operator mutation.
    OperatorRevokedAllSessions {
        /// The user whose sessions were all revoked.
        user_id: UserId,
    },
    /// An operator disabled an account, freezing it: a reversible hold that
    /// both auth and recovery refuse until it is re-enabled. The disable flow
    /// also revokes every live session for immediate lockout — that bulk revoke
    /// emits its own [`OperatorRevokedAllSessions`](Self::OperatorRevokedAllSessions)
    /// row, so this kind records the *status change* itself rather than the
    /// session sweep. Carries only the subject's `user_id`, mirroring the other
    /// operator account-level kinds.
    OperatorDisabledAccount {
        /// The user whose account was disabled.
        user_id: UserId,
    },
    /// An operator re-enabled an account, lifting the disable hold and returning
    /// the account to `Active`. No session machinery runs — enabling only lifts
    /// the gate; the user logs in or recovers fresh.
    OperatorEnabledAccount {
        /// The user whose account was re-enabled.
        user_id: UserId,
    },
    /// An operator listed a user's passkeys. Operator read flows are audited
    /// (D8): inspecting another user's inventory is itself privacy-sensitive,
    /// so "who looked" lands in the same stream as "who changed what". The
    /// [`Actor::Operator`] is the point of the row. Self-service listings stay
    /// unaudited — a user reading their own inventory is not security-relevant.
    ///
    /// Split into distinct passkey / session variants (rather than one
    /// `OperatorRead { resource }`) to match the existing per-action kinds,
    /// each of which names its own operation directly.
    OperatorListedPasskeys {
        /// The user whose passkeys were listed.
        user_id: UserId,
    },
    /// An operator listed a user's sessions. The sessions are projected to
    /// `SessionSummary` (the `token_hash` never crosses into the operator
    /// view); this row records only that the listing happened and who ran it.
    /// See [`OperatorListedPasskeys`](Self::OperatorListedPasskeys) for why the
    /// read flows are audited and why the two reads are split.
    OperatorListedSessions {
        /// The user whose sessions were listed.
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
    /// The target account is disabled. Recovery refuses a disabled account at
    /// both the request seam (no link issued) and the consume seam (no token
    /// redeemed), so a disabled account cannot recover its way back in.
    AccountDisabled,
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
