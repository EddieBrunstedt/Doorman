//! Startup sanity checks.
//!
//! Both [`BauthAxumBuilder::build`](crate::builder::BauthAxumBuilder::build)
//! and [`QuickstartBuilder::build`](crate::quickstart::QuickstartBuilder::build)
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
//! [`NoopAuditSink`]: bauth_core::audit::NoopAuditSink
//! [`InMemoryRateLimiter`]: bauth_core::memory::InMemoryRateLimiter

use crate::config::CookieConfig;

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
    /// The wired-up [`AuditSink`](bauth_core::audit::AuditSink) is a
    /// [`NoopAuditSink`](bauth_core::audit::NoopAuditSink) — security
    /// events are being discarded.
    pub noop_audit: bool,
    /// The wired-up [`RateLimiter`](bauth_core::rate_limit::RateLimiter)
    /// is a [`NoopRateLimiter`](bauth_core::rate_limit::NoopRateLimiter)
    /// — enforcement is disabled.
    pub noop_rate_limiter: bool,
    /// The wired-up [`RateLimiter`](bauth_core::rate_limit::RateLimiter)
    /// is the per-process
    /// [`InMemoryRateLimiter`](bauth_core::memory::InMemoryRateLimiter).
    pub in_memory_rate_limiter: bool,
    /// The wired-up [`EmailSender`](bauth_core::email::EmailSender) is a
    /// dev-only transport
    /// ([`TerminalEmailSender`](bauth_core::email::TerminalEmailSender)
    /// or [`FileEmailSender`](bauth_core::email::FileEmailSender)) — mail
    /// is being printed to stdout or written to disk, not delivered to
    /// users.
    pub dev_email_transport: bool,
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
        out
    }

    /// `true` when no warning conditions were detected.
    pub fn is_empty(&self) -> bool {
        !self.cookie_insecure_in_production
            && !self.noop_audit
            && !self.noop_rate_limiter
            && !self.in_memory_rate_limiter
            && !self.dev_email_transport
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
                tracing::warn!(target: "bauth", "{msg}");
            } else {
                eprintln!("bauth: warning: {msg}");
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
        };
        let lines = w.messages();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("cookie.secure"));
        assert!(lines[1].contains("AuditSink"));
        assert!(lines[2].contains("Rate limiting is disabled"));
        assert!(lines[3].contains("InMemoryRateLimiter"));
        assert!(lines[4].contains("dev-only sender"));
    }

    #[test]
    fn empty_snapshot_yields_no_messages() {
        let w = Warnings::default();
        assert!(w.is_empty());
        assert!(w.messages().is_empty());
    }
}
