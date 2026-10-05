//! Operator flows: manager-level operations that act on _another_ user.
//!
//! Every destructive operation elsewhere in doorman is **self-service** — the
//! manager methods act on the acting user's own session. [`OperatorManager`]
//! is the path for someone _other than the account owner_ (a host operator,
//! support agent, CLI, or backend job) to act on a user, targeting them by
//! [`UserId`] rather than by an acting session.
//!
//! # Two principals, kept separate
//!
//! Every operator action involves two distinct identities:
//!
//! - the **subject** — the doorman user being acted on, identified by their
//!   [`UserId`];
//! - the **operator** — whoever is performing the action, an opaque,
//!   host-supplied [`OperatorActor`] recorded for attribution only and **never
//!   verified** by doorman.
//!
//! # Doorman provides the flow; the host owns authorization
//!
//! Doorman executes the action safely and records _that it happened and who
//! claimed to do it_. It makes **no decision about who is allowed** to invoke
//! an operator flow — authorization (roles, permissions, allowlists, SSO group
//! checks, network boundaries) is entirely the host's responsibility and lives
//! above doorman. The operator surface has no cool-down, no rate limit, and no
//! per-request ownership binding; the host's authorization decision is the
//! single load-bearing control in front of it.
//!
//! Because [`OperatorManager`] lives behind its own deliberate accessor, a
//! handler that does not hold one in scope cannot invoke an operator flow: the
//! "put your own authorization in front of this" rule is enforced by the type
//! system, not by convention.

use std::sync::Arc;

use crate::account::AccountManager;
use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind, OperatorActor};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::SecurityEmailNotifier;
use crate::error::{Error, Result};
use crate::passkey::{PasskeyManager, PasskeyRemovalNotice};
use crate::session::SessionManager;
use crate::storage::{
    AccountStatus, PasskeyChallengeStore, PasskeySummary, SessionId, SessionSummary, User, UserId,
    UserStore,
};

/// Whether an operator-initiated action notifies the subject.
///
/// Operator notices always use **operator-aware copy** ("an administrator
/// removed a passkey from your account") and never the self-service "was this
/// you?" copy, so suppression is the only thing this toggle governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorNotice {
    /// Send the operator-aware notice to the subject.
    Send,
    /// Send no notice. The action still emits an audit event; only the
    /// best-effort subject email is suppressed.
    Suppress,
}

/// Per-action toggles governing whether an operator flow notifies the subject.
///
/// A struct of independent toggles rather than one global switch, so a host can
/// send one class of operator notice while suppressing another. The choice is
/// made once when the [`OperatorManager`] is constructed; the flow call sites
/// stay free of per-call notification flags.
///
/// The defaults are deliberately **asymmetric**, matching the self-service
/// baseline each notice diverges from:
///
/// - [`passkey_removed`](Self::passkey_removed) defaults to
///   [`OperatorNotice::Send`] — self-service passkey removal already notifies,
///   so the operator path keeps that transparency by default.
/// - [`sessions_revoked`](Self::sessions_revoked) defaults to
///   [`OperatorNotice::Suppress`] — the underlying revoke-all primitive is
///   silent today, so an operator session-revoke notice is a *new* outbound
///   email that ships opt-in rather than forced-on.
/// - [`account_disabled`](Self::account_disabled) defaults to
///   [`OperatorNotice::Suppress`] — disabling is a deliberate "quiet hold", so
///   the subject notice ships opt-in: a host that wants the account owner told
///   turns it on explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPolicy {
    /// Whether operator-initiated passkey removal notifies the subject.
    pub passkey_removed: OperatorNotice,
    /// Whether operator-initiated session revocation notifies the subject.
    pub sessions_revoked: OperatorNotice,
    /// Whether operator-initiated account disable notifies the subject.
    pub account_disabled: OperatorNotice,
}

impl Default for NotificationPolicy {
    fn default() -> Self {
        Self {
            passkey_removed: OperatorNotice::Send,
            sessions_revoked: OperatorNotice::Suppress,
            account_disabled: OperatorNotice::Suppress,
        }
    }
}

/// Manager for operator flows — destructive and read-only operations a host
/// performs on a user _other_ than the acting one.
///
/// Reuses the same safe cascade, cache invalidation, and audit machinery the
/// self-service flows use by driving the existing manager cores rather than
/// re-issuing the raw store primitives. Built from the same [`CoreDeps`] bundle
/// the other managers read, plus a [`NotificationPolicy`] chosen at
/// construction.
///
/// Cheap to clone — every field is `Arc`-backed.
#[derive(Clone)]
pub struct OperatorManager {
    users: Arc<dyn UserStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    sessions: SessionManager,
    passkey: PasskeyManager,
    account: AccountManager,
    notifier: SecurityEmailNotifier,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    notifications: NotificationPolicy,
}

impl OperatorManager {
    /// Build an `OperatorManager` from the shared [`CoreDeps`] context, the
    /// already-constructed [`PasskeyManager`] and [`AccountManager`] (whose
    /// removal and deletion cascades the operator flows reuse), and the
    /// [`NotificationPolicy`] chosen at the composition root.
    ///
    /// The session manager and the best-effort security notifier are read from
    /// `deps`, so the operator flows share the one invalidation hook and the
    /// one configured email renderer with every other manager.
    pub fn new(
        deps: &CoreDeps,
        account: AccountManager,
        passkey: PasskeyManager,
        notifications: NotificationPolicy,
    ) -> Self {
        Self {
            users: deps.users.clone(),
            challenges: deps.passkey_challenges.clone(),
            sessions: deps.sessions.clone(),
            passkey,
            account,
            notifier: deps.notifier.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            notifications,
        }
    }

    /// The notification policy this manager was constructed with.
    pub fn notification_policy(&self) -> &NotificationPolicy {
        &self.notifications
    }

    /// Emit one audit event attributed to the supplied operator. The operator
    /// flows that go through a manager core (delete, single-session revoke,
    /// passkey removal) emit from inside that core; this helper covers the
    /// flows that have no core to ride on — the audited read listings (D8) and
    /// the bulk session revoke, whose underlying primitive is silent.
    async fn emit_operator(&self, actor: OperatorActor, kind: AuditEventKind) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor: Actor::Operator(actor),
                kind,
            })
            .await;
    }

    /// Irreversibly delete the account identified by `target_user_id` on an
    /// operator's behalf, running the same full cascade as self-service
    /// deletion: every session revoked first (evicting any framework-side
    /// session cache through the [`SessionManager`]'s invalidation hook), then
    /// credentials, verification tokens, pending registration ceremonies, and
    /// finally the user row.
    ///
    /// The subject is resolved up front: a missing or typo'd `target_user_id`
    /// fails with [`Error::UserNotFound`] *before* any store is touched, so an
    /// operator never receives an "OK" for a cascade that affected nothing.
    ///
    /// The action is attributed to `actor` as [`Actor::Operator`], recorded
    /// verbatim and never verified. No subject notice is sent regardless of
    /// policy — the mailbox owner is gone.
    ///
    /// After the user row is removed the cascade re-runs the pending-ceremony
    /// sweep, reclaiming any registration a concurrent finish slipped in during
    /// the cascade.
    ///
    /// [`SessionManager`]: crate::session::SessionManager
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn delete_account(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
        // Resolve the subject before mutating anything (D7): a stale or typo'd
        // id fails loudly rather than reporting success for an empty cascade.
        if self.users.find_user_by_id(target_user_id).await?.is_none() {
            tracing::warn!(outcome = "user_not_found", "operator delete failed");
            return Err(Error::UserNotFound);
        }

        self.account
            .delete_account_for(target_user_id, Actor::Operator(actor))
            .await?;

        // Re-sweep pending registration ceremonies after the user row is gone,
        // reclaiming any ceremony a concurrent finish slipped in during the
        // cascade (D9.2).
        self.challenges
            .delete_registrations_for_user(target_user_id)
            .await?;

        Ok(())
    }

    /// Disable (freeze) the account identified by `target_user_id` on an
    /// operator's behalf, putting it into a **reversible hold** that both auth
    /// and recovery refuse until [`enable`](Self::enable) lifts it.
    ///
    /// The subject is resolved up front (D7): a missing or typo'd
    /// `target_user_id` fails with [`Error::UserNotFound`] before any store is
    /// touched, and the resolved row is kept for the opt-in notice.
    ///
    /// The account's [`AccountStatus`] is set to
    /// [`AccountStatus::Disabled`] (stamped with the manager clock) and
    /// persisted with a bumped `updated_at`. The flow then **revokes every live
    /// session** through [`SessionManager::revoke_all_for_user`], firing the
    /// invalidation hook so any warm framework-side session cache is evicted and
    /// the lockout is immediate rather than waiting for sessions to expire — the
    /// write-side that makes the read-time disable gate bite at once.
    ///
    /// Disabling an **already-disabled** account is **idempotent**: the status
    /// is re-written (re-stamping `at` to now) and the session sweep re-runs, so
    /// the call always leaves the account disabled with no live sessions and
    /// never errors. It is not a no-op — re-disabling re-asserts the lockout.
    ///
    /// Two audit rows are emitted, both attributed to `actor` as
    /// [`Actor::Operator`]: an [`AuditEventKind::OperatorDisabledAccount`] for
    /// the status change and an
    /// [`AuditEventKind::OperatorRevokedAllSessions`] from the session sweep.
    ///
    /// The subject notice is **opt-in**: it is sent (with operator-aware copy)
    /// only when [`NotificationPolicy::account_disabled`] is
    /// [`OperatorNotice::Send`]; the default is [`OperatorNotice::Suppress`],
    /// the deliberate "quiet hold".
    ///
    /// [`SessionManager::revoke_all_for_user`]: crate::session::SessionManager::revoke_all_for_user
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn disable(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
        // Resolve the subject before mutating anything (D7); keep the row for
        // the opt-in notice.
        let user = self.resolve_subject(target_user_id).await?;

        let now = self.clock.now();
        self.users
            .set_user_status(target_user_id, AccountStatus::Disabled { at: now }, now)
            .await?;

        // Drop every live session so the lockout is immediate: this fires the
        // invalidation hook, flushing any warm framework-side session cache.
        // The underlying revoke-all primitive is silent, so the bulk-revoke
        // accountability row is emitted here, exactly as `revoke_all_sessions`
        // does for the standalone flow.
        let revoked_count = self.sessions.revoke_all_for_user(target_user_id).await?;
        self.emit_operator(
            actor.clone(),
            AuditEventKind::OperatorRevokedAllSessions {
                user_id: target_user_id,
                revoked_count,
            },
        )
        .await;

        self.emit_operator(
            actor,
            AuditEventKind::OperatorDisabledAccount {
                user_id: target_user_id,
            },
        )
        .await;

        if self.notifications.account_disabled == OperatorNotice::Send {
            self.notifier.operator_account_disabled(&user).await;
        }

        Ok(())
    }

    /// Re-enable the account identified by `target_user_id` on an operator's
    /// behalf, lifting a [`disable`](Self::disable) hold and returning the
    /// account to [`AccountStatus::Active`].
    ///
    /// The subject is resolved up front (D7): a missing or typo'd
    /// `target_user_id` fails with [`Error::UserNotFound`] before any store is
    /// touched. The status is set back to [`AccountStatus::Active`] and
    /// persisted with a bumped `updated_at`, then an
    /// [`AuditEventKind::OperatorEnabledAccount`] is emitted, attributed to
    /// `actor` as [`Actor::Operator`].
    ///
    /// Enabling lifts only the gate; there is **no session machinery** — disable
    /// already revoked the live sessions, and the user signs in (or recovers)
    /// fresh. Enabling an **already-active** account is **idempotent**: the
    /// status is re-written and the audit row still emitted; it never errors.
    /// No subject notice is sent for enable.
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn enable(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
        // Resolve the subject before mutating anything (D7).
        self.resolve_subject(target_user_id).await?;

        let now = self.clock.now();
        self.users
            .set_user_status(target_user_id, AccountStatus::Active, now)
            .await?;

        self.emit_operator(
            actor,
            AuditEventKind::OperatorEnabledAccount {
                user_id: target_user_id,
            },
        )
        .await;

        Ok(())
    }

    /// Resolve `target_user_id` to a [`User`], failing with
    /// [`Error::UserNotFound`] when it does not exist. Every operator flow
    /// resolves the subject up front (D7) so a stale or typo'd id fails loudly
    /// before any store is mutated, and so the resolved row is on hand for the
    /// best-effort subject notice.
    async fn resolve_subject(&self, target_user_id: UserId) -> Result<User> {
        match self.users.find_user_by_id(target_user_id).await? {
            Some(user) => Ok(user),
            None => {
                tracing::warn!(outcome = "user_not_found", "operator flow failed");
                Err(Error::UserNotFound)
            }
        }
    }

    /// Remove the passkey identified by `credential_id` from
    /// `target_user_id` on an operator's behalf.
    ///
    /// The subject is resolved up front (D7): a missing or typo'd
    /// `target_user_id` fails with [`Error::UserNotFound`] before any store is
    /// touched. The credential is then resolved and **re-bound** to the subject
    /// (F8): a missing credential is [`Error::PasskeyNotFound`] and one owned by
    /// a *different* user is [`Error::PasskeyOwnershipMismatch`], so an action
    /// named against user X handed a credential id belonging to user Y removes
    /// nothing and mis-attributes nothing.
    ///
    /// The removal runs through the same id-keyed core as self-service removal,
    /// so the audit event and any framework-side invalidation are identical;
    /// only the attribution ([`Actor::Operator`]) and the notice copy differ.
    /// When [`NotificationPolicy::passkey_removed`] is [`OperatorNotice::Send`]
    /// (the default) the subject receives the **operator-aware** notice ("an
    /// administrator removed a passkey"), never the self-service "was this you?"
    /// copy; when it is [`OperatorNotice::Suppress`] no notice is sent.
    ///
    /// Removing a user's *last* passkey is permitted and is a de-facto account
    /// lockout — the host owns whether that is desirable.
    #[tracing::instrument(skip(self, credential_id, actor), fields(target_user_id = %target_user_id))]
    pub async fn remove_passkey(
        &self,
        target_user_id: UserId,
        credential_id: &[u8],
        actor: OperatorActor,
    ) -> Result<()> {
        // Resolve the subject before touching the credential store (D7).
        self.resolve_subject(target_user_id).await?;

        let notice = match self.notifications.passkey_removed {
            OperatorNotice::Send => PasskeyRemovalNotice::Operator,
            OperatorNotice::Suppress => PasskeyRemovalNotice::Suppressed,
        };

        self.passkey
            .remove_passkey_for(
                target_user_id,
                credential_id,
                Actor::Operator(actor),
                notice,
            )
            .await?;

        Ok(())
    }

    /// Revoke **all** of `target_user_id`'s sessions on an operator's behalf,
    /// signing the user out everywhere.
    ///
    /// The subject is resolved up front (D7): a missing `target_user_id` fails
    /// with [`Error::UserNotFound`] before any store is touched. The revoke
    /// runs through [`SessionManager::revoke_all_for_user`], firing the
    /// invalidation hook (cache eviction) exactly as self-service revocation
    /// does.
    ///
    /// Unlike the self-service "sign out everywhere else" path this leaves
    /// **no** session behind — an operator holds none. It runs the bulk
    /// revoke-all primitive (a set delete plus the user-level invalidation
    /// hook), which records no *per-session* audit row.
    ///
    /// Because that primitive is otherwise silent, this flow emits a single
    /// [`AuditEventKind::OperatorRevokedAllSessions`] attributed to `actor`,
    /// closing the accountability gap on the most consequential operator
    /// mutation — the bulk revoke is the one mutation that would otherwise
    /// leave no trace of who ran it. The audit row is emitted whenever the
    /// subject resolved (even if nothing was revoked), so an operator firing a
    /// revoke-all at a live but session-less account still leaves a trace.
    ///
    /// The underlying revoke-all primitive is silent by default, so the subject
    /// *notice* here is an *opt-in* path: it is sent only when
    /// [`NotificationPolicy::sessions_revoked`] is [`OperatorNotice::Send`]
    /// (the default is [`OperatorNotice::Suppress`]), and always with
    /// operator-aware copy. Doing nothing sends nothing new. The notice is
    /// skipped when nothing was revoked.
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn revoke_all_sessions(
        &self,
        target_user_id: UserId,
        actor: OperatorActor,
    ) -> Result<u64> {
        // Resolve the subject before mutating anything (D7); keep the row for
        // the opt-in notice.
        let user = self.resolve_subject(target_user_id).await?;

        let count = self.sessions.revoke_all_for_user(target_user_id).await?;

        self.emit_operator(
            actor,
            AuditEventKind::OperatorRevokedAllSessions {
                user_id: target_user_id,
                revoked_count: count,
            },
        )
        .await;

        if count > 0 && self.notifications.sessions_revoked == OperatorNotice::Send {
            self.notifier.operator_sessions_revoked(&user).await;
        }

        Ok(count)
    }

    /// Revoke the single session identified by `session_id` from
    /// `target_user_id` on an operator's behalf.
    ///
    /// The subject is resolved up front (D7), and the session is **re-bound** to
    /// the subject (F8): a session that does not exist, or one owned by a
    /// *different* user, fails with [`Error::SessionNotFound`], so an action
    /// named against user X handed user Y's session id revokes nothing and
    /// mis-attributes nothing. The revoke fires the invalidation hook and emits
    /// the audit event through the same core the self-service single-session
    /// revoke uses; only the attribution differs.
    ///
    /// No subject notice is sent for a single-session operator revoke.
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id, session_id = %session_id))]
    pub async fn revoke_session(
        &self,
        target_user_id: UserId,
        session_id: SessionId,
        actor: OperatorActor,
    ) -> Result<()> {
        // Resolve the subject before touching the session store (D7).
        self.resolve_subject(target_user_id).await?;

        self.sessions
            .revoke_session_for_target(target_user_id, session_id, Actor::Operator(actor))
            .await?;

        Ok(())
    }

    /// List `target_user_id`'s passkeys as metadata-only [`PasskeySummary`]
    /// values for an operator UI.
    ///
    /// The subject is resolved up front (D7): a missing or typo'd
    /// `target_user_id` fails with [`Error::UserNotFound`] before anything is
    /// read. The summary projection already omits the credential blob, so no
    /// secret-equivalent material crosses into the operator view.
    ///
    /// Inspecting another user's inventory is itself privacy-sensitive, so the
    /// read is **audited** (D8): it emits an
    /// [`AuditEventKind::OperatorListedPasskeys`] attributed to `actor`, landing
    /// "who looked" in the same stream as "who changed what". Self-service
    /// listings stay unaudited. The audit row is emitted only after the subject
    /// resolves, so a failed lookup leaves no trace.
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn list_passkeys(
        &self,
        target_user_id: UserId,
        actor: OperatorActor,
    ) -> Result<Vec<PasskeySummary>> {
        // Resolve the subject before reading or auditing (D7).
        self.resolve_subject(target_user_id).await?;

        let summaries = self.passkey.list_passkey_summaries(target_user_id).await?;

        self.emit_operator(
            actor,
            AuditEventKind::OperatorListedPasskeys {
                user_id: target_user_id,
            },
        )
        .await;

        tracing::info!(
            count = summaries.len(),
            outcome = "listed",
            "operator list passkeys"
        );
        Ok(summaries)
    }

    /// List `target_user_id`'s active sessions as [`SessionSummary`] values for
    /// an operator UI.
    ///
    /// The subject is resolved up front (D7): a missing or typo'd
    /// `target_user_id` fails with [`Error::UserNotFound`] before anything is
    /// read. The projection happens in the [`SessionManager`], so the session
    /// `token_hash` never leaves the manager and cannot reach an operator view,
    /// its logs, or its JSON (F9).
    ///
    /// The read is **audited** (D8): it emits an
    /// [`AuditEventKind::OperatorListedSessions`] attributed to `actor`. As with
    /// the passkey listing, the audit row is emitted only after the subject
    /// resolves, and self-service listings stay unaudited.
    ///
    /// [`SessionManager`]: crate::session::SessionManager
    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn list_sessions(
        &self,
        target_user_id: UserId,
        actor: OperatorActor,
    ) -> Result<Vec<SessionSummary>> {
        // Resolve the subject before reading or auditing (D7).
        self.resolve_subject(target_user_id).await?;

        let summaries = self
            .sessions
            .list_summaries_for_user(target_user_id)
            .await?;

        self.emit_operator(
            actor,
            AuditEventKind::OperatorListedSessions {
                user_id: target_user_id,
            },
        )
        .await;

        tracing::info!(
            count = summaries.len(),
            outcome = "listed",
            "operator list sessions"
        );
        Ok(summaries)
    }
}
