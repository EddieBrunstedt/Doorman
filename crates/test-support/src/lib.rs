//! Test-only collaborators shared across the doorman test suites.
//!
//! These are deliberately kept out of `doorman-core` so they never compile
//! into a production build: [`MockClock`] makes expiry and rate-limit
//! behaviour deterministic, [`InMemoryAuditSink`] records emitted events
//! for assertions, and [`CapturingEmailSender`] captures sent mail instead
//! of delivering it. They implement the `doorman-core` collaborator traits
//! ([`Clock`], [`AuditSink`], [`EmailSender`]).
//!
//! The in-memory storage adapters and [`InMemoryRateLimiter`] are *not*
//! here — those live in [`doorman_core::memory`] because they back local
//! experiments and production single-process deployments, not just tests.
//!
//! [`Clock`]: doorman_core::clock::Clock
//! [`AuditSink`]: doorman_core::audit::AuditSink
//! [`EmailSender`]: doorman_core::email::EmailSender
//! [`InMemoryRateLimiter`]: doorman_core::memory::InMemoryRateLimiter

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use doorman_core::audit::{AuditEvent, AuditSink};
use doorman_core::clock::Clock;
use doorman_core::email::{Email, EmailSender};
use doorman_core::error::{EmailError, EmailResult};
use doorman_core::metrics::{MetricEvent, MetricSink};
use doorman_core::verification::TOKEN_PLACEHOLDER;

/// Recover the raw verification token from an email body whose link was
/// rendered from `template` (a URL containing [`TOKEN_PLACEHOLDER`], e.g. the
/// signup or recovery `url_template`).
///
/// Both the core and the axum integration suites mint links the same way and
/// then need to read the token back out of the captured mail; keeping the one
/// extractor here stops the two scaffolds from drifting on the URL convention.
pub fn token_from_email(body: &str, template: &str) -> String {
    let prefix = template
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has a prefix before the token placeholder");
    let start = body
        .find(prefix)
        .expect("email body contains the link prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("a token follows the link prefix")
        .to_string()
}

/// Mutable clock for deterministic tests.
#[derive(Debug)]
pub struct MockClock {
    inner: Mutex<DateTime<Utc>>,
}

impl MockClock {
    /// Create a clock frozen at `time`.
    pub fn new(time: DateTime<Utc>) -> Self {
        Self {
            inner: Mutex::new(time),
        }
    }

    /// Jump the clock to an absolute `time`.
    pub fn set(&self, time: DateTime<Utc>) {
        *self.inner.lock().expect("mock clock poisoned") = time;
    }

    /// Move the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut guard = self.inner.lock().expect("mock clock poisoned");
        *guard += by;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.inner.lock().expect("mock clock poisoned")
    }
}

/// Audit sink that records events in memory for tests.
#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every event emitted so far, in emission order.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .clone()
    }

    /// Number of events emitted so far.
    pub fn len(&self) -> usize {
        self.events.lock().expect("audit sink mutex poisoned").len()
    }

    /// Whether no events have been emitted yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn emit(&self, event: AuditEvent) {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .push(event);
    }
}

/// Email sender that records messages in memory instead of delivering them.
#[derive(Debug, Default)]
pub struct CapturingEmailSender {
    sent: Mutex<Vec<Email>>,
    fail_after_successful_sends: Mutex<Option<usize>>,
}

impl CapturingEmailSender {
    /// Create an empty sender.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every captured message, in send order.
    pub fn sent(&self) -> Vec<Email> {
        self.sent
            .lock()
            .expect("email sender mutex poisoned")
            .clone()
    }

    /// Cause future sends to fail once `sent().len()` has reached
    /// `successful_sends`. Existing captured messages are left untouched.
    pub fn fail_after_successful_sends(&self, successful_sends: usize) {
        *self
            .fail_after_successful_sends
            .lock()
            .expect("email sender failure mutex poisoned") = Some(successful_sends);
    }

    /// Undo [`fail_after_successful_sends`](Self::fail_after_successful_sends)
    /// so sends succeed again.
    pub fn clear_send_failure(&self) {
        *self
            .fail_after_successful_sends
            .lock()
            .expect("email sender failure mutex poisoned") = None;
    }
}

#[async_trait]
impl EmailSender for CapturingEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        let fail_after = *self
            .fail_after_successful_sends
            .lock()
            .expect("email sender failure mutex poisoned");
        let mut sent = self.sent.lock().expect("email sender mutex poisoned");
        if fail_after.is_some_and(|max| sent.len() >= max) {
            return Err(EmailError::msg("capturing email sender configured to fail"));
        }
        sent.push(email);
        Ok(())
    }
}

/// In-memory [`MetricSink`] that records every [`MetricEvent`] for tests.
#[derive(Debug, Default)]
pub struct CapturingMetrics {
    events: Mutex<Vec<MetricEvent>>,
}

impl CapturingMetrics {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every observation recorded so far, in order.
    pub fn events(&self) -> Vec<MetricEvent> {
        self.events.lock().expect("metrics mutex poisoned").clone()
    }

    /// Count the observations equal to `event`.
    pub fn count(&self, event: MetricEvent) -> usize {
        self.events
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .filter(|e| **e == event)
            .count()
    }

    /// Whether any recorded [`MetricEvent::AuthLatency`] observation exists.
    pub fn has_latency(&self) -> bool {
        self.events
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .any(|e| matches!(e, MetricEvent::AuthLatency(_)))
    }
}

impl MetricSink for CapturingMetrics {
    fn record(&self, event: MetricEvent) {
        self.events
            .lock()
            .expect("metrics mutex poisoned")
            .push(event);
    }
}
