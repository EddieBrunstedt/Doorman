//! Audit-event model and sink abstraction.
//!
//! Managers emit these events for security-significant auth activity.
//! Hosts provide an [`AuditSink`] that persists or forwards them to a
//! durable log; [`NoopAuditSink`] exists only as a development default.

use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

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
///
/// `#[non_exhaustive]` so new event kinds can be audited without breaking host
/// [`AuditSink`] implementations — match with a trailing `_ => {}` arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
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
    /// A signup request was rejected by the host's
    /// [`SignupPolicy`](crate::signup::SignupPolicy). Carries no user id —
    /// denial happens before any user is provisioned — and no email (PII).
    /// Emitted for both [`DenySilently`](crate::signup::SignupDecision::DenySilently)
    /// and [`Deny`](crate::signup::SignupDecision::Deny); the host's rejection
    /// reason, if any, is logged at the denial site rather than stored here.
    SignupDenied,
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
    /// A fresh passkey re-authentication succeeded immediately before a
    /// destructive action (account deletion, email-change request, passkey
    /// removal). Recency was proven by a user-verified assertion from one of
    /// the session user's own credentials; the action then proceeds. No
    /// ceremony email is sent — the destructive action keeps its own notice.
    ReauthSucceeded {
        /// The user that re-authenticated.
        user_id: UserId,
    },
    /// A passkey re-authentication attempt failed. Emitted only when a proof
    /// was supplied and rejected (bad/expired challenge, bad assertion,
    /// missing user verification, a credential not owned by the session user,
    /// or a signature-counter regression). A *missing* proof is the normal
    /// `reauth_required` handshake and is not recorded here. Pairs with the
    /// [`ReauthFailureReason`] for after-the-fact triage.
    ReauthFailed {
        /// The session user the re-authentication was attempted for.
        user_id: UserId,
        /// Why the attempt failed.
        reason: ReauthFailureReason,
    },
    /// An operator revoked **every** session belonging to a user at once
    /// (the bulk "sign the account out everywhere" operator flow). The flow is
    /// a set delete with no single `session_id` to name, mirroring
    /// [`AccountDeleted`](Self::AccountDeleted) rather than the per-session
    /// [`SessionRevoked`](Self::SessionRevoked); `revoked_count` records how
    /// many were swept so the row carries the scale of the action and not just
    /// that it happened. The self-service bulk revoke is silent; only the
    /// operator path records this row, so the [`Actor::Operator`] it carries is
    /// the accountability trail for the most consequential operator mutation.
    OperatorRevokedAllSessions {
        /// The user whose sessions were all revoked.
        user_id: UserId,
        /// How many live sessions the sweep deleted.
        revoked_count: u64,
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

/// Relative severity of an [`AuditEventKind`], used by [`AuditDispatch`] to
/// pick the tracing level for the event's log line: failed, rejected, or
/// expired attempts warn; everything else is informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    /// Routine or successful activity.
    Info,
    /// A failed, rejected, or expired attempt worth surfacing at `warn`.
    Warn,
}

impl AuditEventKind {
    /// The *subject* this event concerns, when one has been resolved. Lifted to
    /// a flat field on the `doorman::audit` tracing line so a log backend can
    /// filter by user without parsing the event payload. `None` for the
    /// pre-resolution failures and for [`SignupDenied`](Self::SignupDenied),
    /// which fires before any user is provisioned.
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
            | Self::RecoveryFailed { user_id, .. } => *user_id,
            Self::SignupDenied => None,
        }
    }

    /// Severity used to pick the tracing level for this event's audit log line.
    pub fn severity(&self) -> AuditSeverity {
        match self {
            Self::AuthenticationFailed { .. }
            | Self::RecoveryFailed { .. }
            | Self::ReauthFailed { .. }
            | Self::SessionExpired { .. }
            | Self::SignupDenied => AuditSeverity::Warn,
            _ => AuditSeverity::Info,
        }
    }
}

/// Why a passkey authentication attempt did not succeed. Pairs with
/// [`AuditEventKind::AuthenticationFailed`] for after-the-fact triage and
/// alerting.
///
/// `#[non_exhaustive]` so new rejection reasons can be added without breaking
/// host matches — include a trailing `_ => {}` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthFailureReason {
    /// The presented challenge id did not resolve to an outstanding
    /// authentication ceremony (unknown or already consumed).
    InvalidChallenge,
    /// The authentication ceremony had expired before it was finished.
    ExpiredChallenge,
    /// The asserted credential id is not registered, or its owner was deleted
    /// while the ceremony was in flight.
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
    /// The assertion verified but the authenticator did not set the
    /// user-verification flag. doorman requires user-verified passkeys, so the
    /// login is rejected and this event is emitted so the host can alert.
    UserVerificationMissing,
    /// The assertion failed `webauthn-rs` verification for any other reason
    /// (bad signature, origin mismatch, malformed response, etc.).
    BadAssertion,
    /// The assertion verified but the account is disabled by an operator, so
    /// no session is minted.
    AccountDisabled,
}

/// Why a passkey re-authentication attempt did not succeed. Pairs with
/// [`AuditEventKind::ReauthFailed`] for after-the-fact triage and alerting.
/// Mirrors the security-significant subset of [`AuthFailureReason`]; a missing
/// proof is not represented because it is the ordinary `reauth_required`
/// handshake rather than a failed attempt.
///
/// `#[non_exhaustive]` so new rejection reasons can be added without breaking
/// host matches — include a trailing `_ => {}` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReauthFailureReason {
    /// The presented challenge id did not resolve to an outstanding
    /// re-authentication ceremony, or it had already expired.
    InvalidChallenge,
    /// The assertion verified but the authenticator did not set the
    /// user-verification flag. Re-authentication always requires a deliberate
    /// user-verified gesture, so the attempt is rejected.
    UserVerificationMissing,
    /// The asserted credential is not registered to the session user, so the
    /// proof cannot stand in for *this* user's presence.
    OwnershipMismatch,
    /// The asserted signature counter did not advance past the stored value,
    /// which `webauthn-rs` flags as a possible cloned authenticator.
    CounterRegression,
    /// The assertion failed `webauthn-rs` verification for any other reason
    /// (bad signature, origin mismatch, malformed response, etc.).
    BadAssertion,
}

/// Why a recovery attempt did not succeed.
///
/// `#[non_exhaustive]` so new rejection reasons can be added without breaking
/// host matches — include a trailing `_ => {}` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
#[async_trait]
pub trait AuditSink: Send + Sync {
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

/// The single seam every audit event passes through.
///
/// Wrapping the [`AuditSink`] (kept private) makes *audit-without-tracing*
/// unrepresentable: [`emit`](Self::emit) always writes a structured line on the
/// `doorman::audit` tracing target **and** forwards the event to the sink, so
/// an audit event can never be recorded without a matching log line — even a
/// [`NoopAuditSink`] still leaves a tracing trail. Managers hold this rather
/// than a bare `Arc<dyn AuditSink>`, so no code path can reach the sink to emit
/// without the trace.
#[derive(Clone)]
pub struct AuditDispatch {
    sink: Arc<dyn AuditSink>,
}

impl AuditDispatch {
    /// Wrap a host [`AuditSink`] in the tracing-plus-emit dispatch.
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    /// Trace the event on the `doorman::audit` target, then forward it to the
    /// sink. The level comes from [`AuditEventKind::severity`]; the subject
    /// ([`user_id`](AuditEventKind::user_id)) and the actor are lifted to flat
    /// fields. The actor's host-supplied (and never doorman-verified) operator /
    /// network metadata is escaped before it is written, so it cannot forge log
    /// structure.
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

/// Renders an [`Actor`] for the `doorman::audit` tracing line with every
/// host-supplied field escaped. Both the operator descriptor and the subject's
/// network metadata are derived from attacker-influenceable input and are never
/// verified by doorman, so control characters (notably newlines) are escaped to
/// prevent log forging.
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

/// Writes a string with control characters (newlines, carriage returns, tabs,
/// and other C0/C1 controls) rendered via their escapes, leaving every other
/// character — including legitimate Unicode — verbatim. Keeps untrusted audit
/// metadata from injecting structure into a text log line.
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
