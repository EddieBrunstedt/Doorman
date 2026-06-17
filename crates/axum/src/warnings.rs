//! Startup sanity check for partial email branding.
//!
//! Both [`ManagerBuilder::build`](crate::manager_builder::ManagerBuilder::build)
//! and [`AuthServiceBuilder::build`](crate::builder::AuthServiceBuilder::build)
//! produce a [`Warnings`] snapshot and emit each applicable line via
//! [`tracing::warn!`] when a subscriber is attached or [`eprintln!`] when one
//! is not, so a host without `tracing` wired up still sees the message.
//!
//! Every other misconfiguration that used to surface here (insecure cookies,
//! a [`NoopAuditSink`], an [`InMemoryRateLimiter`], a dev email transport, a
//! placeholder URL, an undecided CSRF posture) is now a hard
//! [`BuilderError`](crate::manager_builder::BuilderError): the unsafe option
//! is an explicit, greppable call rather than a silent default the host has to
//! be warned about. Only partial email branding remains a warning, because the
//! safe choice is ambiguous — see [`Warnings::partial_email_branding`]. Hosts
//! that have made an informed choice silence it via `.silence_warnings()` on
//! either builder.
//!
//! [`NoopAuditSink`]: doorman_core::audit::NoopAuditSink
//! [`InMemoryRateLimiter`]: doorman_core::memory::InMemoryRateLimiter

/// Snapshot of the warning conditions detected at build time.
///
/// Public for tests; production code constructs and emits a snapshot in
/// the same call.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Warnings {
    /// A custom [`EmailTemplates`](doorman_core::email::EmailTemplates) renderer was
    /// set on one flow (signup or recovery) but no shared renderer was wired
    /// via [`AuthServiceBuilder::emails`](crate::AuthServiceBuilder::emails), so the other
    /// flow and the security notices still send the stock copy. Branding is
    /// partial; use `.emails(..)` for one consistent renderer.
    pub partial_email_branding: bool,
}

impl Warnings {
    /// Return the human-readable warning lines that apply, in the order
    /// the host should see them.
    pub fn messages(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.partial_email_branding {
            out.push(
                "A custom email renderer was set on only one flow. The other flow and the \
                 security notices still use the stock copy. Wire one renderer for every flow \
                 with AuthServiceBuilder::emails(..), or silence this with .silence_warnings() once \
                 you have made an informed choice.",
            );
        }
        out
    }

    /// `true` when no warning conditions were detected. Compares against the
    /// all-`false` default so a newly added flag is counted automatically.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Emit the warnings to the configured sink — `tracing::warn!` when a
    /// `tracing` subscriber is attached (global or thread-scoped),
    /// `eprintln!` otherwise so hosts without `tracing` wired still see
    /// the message.
    pub fn emit(&self) {
        // `has_been_set` only reports the global default. `with_default`
        // (used by tests and some hosts) installs a thread-scoped
        // subscriber instead. Inspect the *current* dispatcher to detect
        // both cases: the no-op default is `NoSubscriber`, anything else
        // means a host has wired up some subscriber.
        let has_subscriber =
            tracing::dispatcher::get_default(|d| !d.is::<tracing::subscriber::NoSubscriber>());
        for msg in self.messages() {
            if has_subscriber {
                tracing::warn!(target: "doorman", "{msg}");
            } else {
                eprintln!("doorman: warning: {msg}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_branding_yields_its_message() {
        let w = Warnings {
            partial_email_branding: true,
        };
        let lines = w.messages();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("custom email renderer"));
    }

    #[test]
    fn empty_snapshot_yields_no_messages() {
        let w = Warnings::default();
        assert!(w.is_empty());
        assert!(w.messages().is_empty());
    }
}
