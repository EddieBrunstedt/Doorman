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
use crate::audit::{Actor, OperatorActor};
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::storage::{PasskeyChallengeStore, UserId, UserStore};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPolicy {
    /// Whether operator-initiated passkey removal notifies the subject.
    pub passkey_removed: OperatorNotice,
    /// Whether operator-initiated session revocation notifies the subject.
    pub sessions_revoked: OperatorNotice,
}

impl Default for NotificationPolicy {
    fn default() -> Self {
        Self {
            passkey_removed: OperatorNotice::Send,
            sessions_revoked: OperatorNotice::Suppress,
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
    account: AccountManager,
    notifications: NotificationPolicy,
}

impl OperatorManager {
    /// Build an `OperatorManager` from the shared [`CoreDeps`] context, the
    /// already-constructed [`AccountManager`] (whose deletion cascade the
    /// operator delete reuses), and the [`NotificationPolicy`] chosen at the
    /// composition root.
    pub fn new(
        deps: &CoreDeps,
        account: AccountManager,
        notifications: NotificationPolicy,
    ) -> Self {
        Self {
            users: deps.users.clone(),
            challenges: deps.passkey_challenges.clone(),
            account,
            notifications,
        }
    }

    /// The notification policy this manager was constructed with.
    pub fn notification_policy(&self) -> &NotificationPolicy {
        &self.notifications
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

        tracing::info!(outcome = "deleted", "operator account delete");
        Ok(())
    }
}
