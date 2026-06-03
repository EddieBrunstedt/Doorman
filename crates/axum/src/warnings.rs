//! Startup sanity checks.
//!
//! Both [`ManagerBuilder::build`](crate::manager_builder::ManagerBuilder::build)
//! and [`DoormanBuilder::build`](crate::builder::DoormanBuilder::build)
//! produce a [`Warnings`] snapshot describing apparent misconfigurations
//! (insecure cookies in apparent production, a [`NoopAuditSink`], an
//! [`InMemoryRateLimiter`] in a multi-replica-friendly deployment, etc.)
//! and emit each one via [`tracing::warn!`] when a subscriber is attached
//! or [`eprintln!`] when one is not, so a host without `tracing` wired up
//! still sees the message.
//!
//! Hosts that have made an informed choice silence the warnings via
//! `.silence_warnings()` on either builder.
//!
//! [`NoopAuditSink`]: doorman_core::audit::NoopAuditSink
//! [`InMemoryRateLimiter`]: doorman_core::memory::InMemoryRateLimiter

use std::any::Any;

use doorman_core::audit::{AuditSink, NoopAuditSink};
#[cfg(feature = "file-email")]
use doorman_core::email::FileEmailSender;
use doorman_core::email::{EmailSender, TerminalEmailSender};
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::rate_limit::{NoopRateLimiter, RateLimiter};

use crate::config::CookieConfig;

/// `true` if `sink` is the bundled [`NoopAuditSink`].
///
/// The collaborator traits no longer carry diagnostic methods; the bundled
/// dev/noop types are recognised here by downcasting through the traits'
/// [`Any`] supertrait, so a host implementing the trait writes nothing extra.
pub(crate) fn is_noop_audit(sink: &dyn AuditSink) -> bool {
    (sink as &dyn Any).is::<NoopAuditSink>()
}

/// `true` if `sender` is one of the bundled dev-only transports
/// ([`TerminalEmailSender`], or `FileEmailSender` under the `file-email`
/// feature) that never deliver mail.
pub(crate) fn is_dev_email_transport(sender: &dyn EmailSender) -> bool {
    let any = sender as &dyn Any;
    if any.is::<TerminalEmailSender>() {
        return true;
    }
    #[cfg(feature = "file-email")]
    if any.is::<FileEmailSender>() {
        return true;
    }
    false
}

/// Which bundled rate limiter (if any) `limiter` is, for the startup check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateLimiterFlavor {
    /// [`NoopRateLimiter`] — enforcement disabled.
    Noop,
    /// [`InMemoryRateLimiter`] — per-process only.
    InMemory,
    /// A host-supplied limiter; no warning.
    Custom,
}

pub(crate) fn rate_limiter_flavor(limiter: &dyn RateLimiter) -> RateLimiterFlavor {
    let any = limiter as &dyn Any;
    if any.is::<NoopRateLimiter>() {
        RateLimiterFlavor::Noop
    } else if any.is::<InMemoryRateLimiter>() {
        RateLimiterFlavor::InMemory
    } else {
        RateLimiterFlavor::Custom
    }
}

/// Snapshot of the warning conditions detected at build time.
///
/// Public for tests; production code constructs and emits a snapshot in
/// the same call.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Warnings {
    /// `cookie.secure = false` while the cookie has been scoped to an
    /// explicit non-`localhost` domain — suggests the host is running in
    /// apparent production over plaintext HTTP.
    pub cookie_insecure_in_production: bool,
    /// The wired-up [`AuditSink`] is a [`NoopAuditSink`] — security
    /// events are being discarded.
    pub noop_audit: bool,
    /// The wired-up [`RateLimiter`] is a [`NoopRateLimiter`]
    /// — enforcement is disabled.
    pub noop_rate_limiter: bool,
    /// The wired-up [`RateLimiter`] is the per-process
    /// [`InMemoryRateLimiter`].
    pub in_memory_rate_limiter: bool,
    /// The wired-up [`EmailSender`] is a dev-only transport
    /// ([`TerminalEmailSender`]
    /// or `FileEmailSender`) — mail
    /// is being printed to stdout or written to disk, not delivered to
    /// users.
    pub dev_email_transport: bool,
    /// A custom [`DoormanEmails`](doorman_core::email::DoormanEmails) renderer was
    /// set on one flow (signup or recovery) but no shared renderer was wired
    /// via [`DoormanBuilder::emails`](crate::DoormanBuilder::emails), so the other
    /// flow and the security notices still send the stock copy. Branding is
    /// partial; use `.emails(..)` for one consistent renderer.
    pub partial_email_branding: bool,
    /// A signup or recovery `url_template` is still the stock
    /// `example.invalid` placeholder. The link carries a valid token but
    /// points at a domain the host does not own, so the email is
    /// effectively dead. Set a real template via `.signup(..)` / `.recovery(..)`.
    pub placeholder_url_template: bool,
}

impl Warnings {
    /// Return the human-readable warning lines that apply, in the order
    /// the host should see them.
    pub fn messages(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.cookie_insecure_in_production {
            out.push(
                "cookie.secure = false with an explicit non-localhost domain. Session cookies \
                 will be sent over plaintext HTTP. Set cookie.secure = true in production.",
            );
        }
        if self.noop_audit {
            out.push(
                "Audit sink is NoopAuditSink. Audit events are being discarded. Wire a real \
                 AuditSink (file, syslog, your logging pipeline) in production.",
            );
        }
        if self.noop_rate_limiter {
            out.push(
                "Rate limiter is NoopRateLimiter. Rate limiting is disabled. Wire a real \
                 RateLimiter in production.",
            );
        }
        if self.in_memory_rate_limiter {
            out.push(
                "Rate limiter is InMemoryRateLimiter. The in-memory limiter is per-process; in \
                 a multi-replica deployment your effective rate budget is multiplied by the \
                 replica count. For single-process deployments this is fine; otherwise swap in \
                 a shared backend (e.g. a Redis-backed RateLimiter). Silence this with \
                 .silence_warnings() once you have made an informed choice.",
            );
        }
        if self.dev_email_transport {
            out.push(
                "Email transport is a dev-only sender (TerminalEmailSender or FileEmailSender). \
                 Recovery and signup links are being printed to stdout or written to disk, not \
                 delivered to users. Wire a real EmailSender (lettre, resend, SES, …) in \
                 production. Silence this with .silence_warnings() once you have made an \
                 informed choice.",
            );
        }
        if self.partial_email_branding {
            out.push(
                "A custom email renderer was set on only one flow. The other flow and the \
                 security notices still use the stock copy. Wire one renderer for every flow \
                 with DoormanBuilder::emails(..), or silence this with .silence_warnings() once \
                 you have made an informed choice.",
            );
        }
        if self.placeholder_url_template {
            out.push(
                "A signup, recovery, or account url_template is still the stock example.invalid \
                 placeholder. The emailed link points at a domain you do not own, so the link is \
                 dead. Set a real template via .signup(..) / .recovery(..) / .account(..).",
            );
        }
        out
    }

    /// `true` when no warning conditions were detected.
    pub fn is_empty(&self) -> bool {
        !self.cookie_insecure_in_production
            && !self.noop_audit
            && !self.noop_rate_limiter
            && !self.in_memory_rate_limiter
            && !self.dev_email_transport
            && !self.partial_email_branding
            && !self.placeholder_url_template
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

/// Inspect the cookie config for the insecure-in-production heuristic.
///
/// "Apparent production" is `secure = false` with an explicit domain that
/// is not `localhost`. `secure = false` with `domain = None` or
/// `domain = Some("localhost")` is treated as local dev and not flagged.
pub fn check_cookie(config: &CookieConfig) -> bool {
    if config.secure {
        return false;
    }
    match config.domain.as_deref() {
        None | Some("localhost") => false,
        Some(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(secure: bool, domain: Option<&str>) -> CookieConfig {
        CookieConfig {
            secure,
            domain: domain.map(str::to_owned),
            ..CookieConfig::default()
        }
    }

    #[test]
    fn secure_cookie_is_never_flagged() {
        assert!(!check_cookie(&cookie(true, None)));
        assert!(!check_cookie(&cookie(true, Some("example.com"))));
    }

    #[test]
    fn insecure_local_dev_is_not_flagged() {
        assert!(!check_cookie(&cookie(false, None)));
        assert!(!check_cookie(&cookie(false, Some("localhost"))));
    }

    #[test]
    fn insecure_with_production_domain_is_flagged() {
        assert!(check_cookie(&cookie(false, Some("example.com"))));
    }

    #[test]
    fn messages_returns_lines_in_order() {
        let w = Warnings {
            cookie_insecure_in_production: true,
            noop_audit: true,
            noop_rate_limiter: true,
            in_memory_rate_limiter: true,
            dev_email_transport: true,
            partial_email_branding: true,
            placeholder_url_template: true,
        };
        let lines = w.messages();
        assert_eq!(lines.len(), 7);
        assert!(lines[0].contains("cookie.secure"));
        assert!(lines[1].contains("AuditSink"));
        assert!(lines[2].contains("Rate limiting is disabled"));
        assert!(lines[3].contains("InMemoryRateLimiter"));
        assert!(lines[4].contains("dev-only sender"));
        assert!(lines[5].contains("custom email renderer"));
        assert!(lines[6].contains("example.invalid"));
    }

    #[test]
    fn empty_snapshot_yields_no_messages() {
        let w = Warnings::default();
        assert!(w.is_empty());
        assert!(w.messages().is_empty());
    }
}
