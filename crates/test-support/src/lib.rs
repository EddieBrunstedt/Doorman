mod authenticator;
mod dpop;

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use doorman_core::audit::{AuditEvent, AuditSink};
use doorman_core::clock::Clock;
use doorman_core::dpop::DpopOrigin;
use doorman_core::email::{Email, EmailSender};
use doorman_core::email_link::TOKEN_PLACEHOLDER;
use doorman_core::error::{EmailError, EmailResult};
use doorman_core::lifetime::Lifetime;
use doorman_core::metrics::{MetricEvent, MetricSink};
use doorman_core::session::SessionContext;

pub use dpop::DpopClient;

pub use authenticator::{
    ResidentAuthenticator, assert_discoverable_request_options,
    assert_resident_registration_options,
};

pub const CLIENT_IP: &str = "192.0.2.1";

pub fn request_context() -> SessionContext {
    SessionContext::new(CLIENT_IP.parse().expect("client IP"), None)
}

pub fn lifetime(lifetime: std::time::Duration) -> Lifetime {
    Lifetime::new(lifetime).expect("a lifetime in bounds")
}

pub fn dpop_origin(origin: &str) -> DpopOrigin {
    DpopOrigin::new(url::Url::parse(origin).expect("a URL").origin()).expect("a tuple origin")
}

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

#[derive(Debug, Default)]
pub struct CapturingEmailSender {
    sent: Mutex<Vec<Email>>,
    bounced: Mutex<Vec<Email>>,
    fail_after_successful_sends: Mutex<Option<usize>>,
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

    pub fn bounced(&self) -> Vec<Email> {
        self.bounced
            .lock()
            .expect("email sender bounce mutex poisoned")
            .clone()
    }

    pub fn fail_after_successful_sends(&self, successful_sends: usize) {
        *self
            .fail_after_successful_sends
            .lock()
            .expect("email sender failure mutex poisoned") = Some(successful_sends);
    }

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
            self.bounced
                .lock()
                .expect("email sender bounce mutex poisoned")
                .push(email);
            return Err(EmailError::msg("capturing email sender configured to fail"));
        }
        sent.push(email);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct CapturingMetrics {
    events: Mutex<Vec<MetricEvent>>,
}

impl CapturingMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<MetricEvent> {
        self.events.lock().expect("metrics mutex poisoned").clone()
    }

    pub fn count(&self, event: MetricEvent) -> usize {
        self.events
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .filter(|e| **e == event)
            .count()
    }

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
