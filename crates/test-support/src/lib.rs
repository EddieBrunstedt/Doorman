//! Test-only collaborators shared across the bauth test suites.
//!
//! These are deliberately kept out of `bauth-core` so they never compile
//! into a production build: [`MockClock`] makes expiry and rate-limit
//! behaviour deterministic, [`InMemoryAuditSink`] records emitted events
//! for assertions, and [`CapturingEmailSender`] captures sent mail instead
//! of delivering it. They implement the `bauth-core` collaborator traits
//! ([`Clock`], [`AuditSink`], [`EmailSender`]).
//!
//! The in-memory storage adapters and [`InMemoryRateLimiter`] are *not*
//! here — those live in [`bauth_core::memory`] because they back local
//! experiments and the quickstart default, not just tests.
//!
//! [`Clock`]: bauth_core::clock::Clock
//! [`AuditSink`]: bauth_core::audit::AuditSink
//! [`EmailSender`]: bauth_core::email::EmailSender
//! [`InMemoryRateLimiter`]: bauth_core::memory::InMemoryRateLimiter

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use bauth_core::audit::{AuditEvent, AuditSink};
use bauth_core::clock::Clock;
use bauth_core::email::{Email, EmailSender, EmailSenderKind};
use bauth_core::error::EmailResult;

/// Mutable clock for deterministic tests.
#[derive(Debug)]
pub struct MockClock {
    inner: Mutex<DateTime<Utc>>,
}

impl MockClock {
    pub fn new(time: DateTime<Utc>) -> Self {
        Self {
            inner: Mutex::new(time),
        }
    }

    pub fn set(&self, time: DateTime<Utc>) {
        *self.inner.lock().expect("mock clock poisoned") = time;
    }

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .clone()
    }

    pub fn len(&self) -> usize {
        self.events.lock().expect("audit sink mutex poisoned").len()
    }

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
}

impl CapturingEmailSender {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sent(&self) -> Vec<Email> {
        self.sent
            .lock()
            .expect("email sender mutex poisoned")
            .clone()
    }
}

#[async_trait]
impl EmailSender for CapturingEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        self.sent
            .lock()
            .expect("email sender mutex poisoned")
            .push(email);
        Ok(())
    }

    fn diagnostic_kind(&self) -> EmailSenderKind {
        EmailSenderKind::Capturing
    }
}
