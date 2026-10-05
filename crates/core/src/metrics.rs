//! Optional metrics hooks for the key auth counters.
//!
//! A host that wants production telemetry implements [`MetricSink`] and wires it
//! in through [`AuthCoreBuilder::metrics`]. The
//! managers call [`MetricSink::record`] on the hot paths — successful logins,
//! authentication failures, and per-ceremony latency — and the session
//! resolver reports cache hits and misses through the same hook. The default
//! [`NoopMetricSink`] discards everything, so the hooks cost a single
//! non-inlined call when no host backend is attached.
//!
//! [`record`](MetricSink::record) is synchronous on purpose: a counter
//! increment or histogram observation should never await. Keep host
//! implementations cheap and non-blocking; do any I/O (scraping, flushing)
//! out of band.
//!
//! [`AuthCoreBuilder::metrics`]: crate::assembly::AuthCoreBuilder::metrics

use std::time::Duration;

use crate::audit::AuthFailureReason;

/// A single metric observation emitted from an auth hot path.
///
/// `#[non_exhaustive]` so new counters can be added without breaking host
/// implementations — match with a trailing `_ => {}` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetricEvent {
    /// A passkey authentication ceremony completed and a session was minted.
    LoginSucceeded,
    /// A passkey authentication ceremony was rejected. Carries the same
    /// [`AuthFailureReason`] as the matching audit event.
    AuthFailed {
        /// Why the authentication was rejected.
        reason: AuthFailureReason,
    },
    /// Wall-clock duration of a `finish_authentication` call, recorded on
    /// every outcome (success, rejection, or rate-limit). Feeds an
    /// auth-latency histogram.
    AuthLatency(Duration),
    /// A session-resolution cache lookup served the request without touching
    /// the session / user stores
    /// ([`SessionResolver`](crate::resolve::SessionResolver)).
    CacheHit,
    /// A session-resolution cache lookup missed and fell through to the
    /// stores ([`SessionResolver`](crate::resolve::SessionResolver)).
    CacheMiss,
}

/// Sink for [`MetricEvent`]s emitted by the auth hot paths.
///
/// Implementations bridge to whatever metrics backend the host runs
/// (Prometheus, statsd, OpenTelemetry, …). [`record`](Self::record) is called
/// inline on request-handling code paths, so it must return promptly.
pub trait MetricSink: Send + Sync {
    /// Record one observation. Must not block or await; increment a counter
    /// or observe a histogram and return.
    fn record(&self, event: MetricEvent);
}

/// [`MetricSink`] implementation that discards every observation. The default
/// when a host wires no metrics backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetricSink;

impl MetricSink for NoopMetricSink {
    fn record(&self, _event: MetricEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Test sink that records every event it receives behind a shared handle.
    #[derive(Clone, Default)]
    struct CapturingMetrics {
        events: Arc<Mutex<Vec<MetricEvent>>>,
    }

    impl CapturingMetrics {
        fn events(&self) -> Vec<MetricEvent> {
            self.events.lock().expect("metrics lock poisoned").clone()
        }
    }

    impl MetricSink for CapturingMetrics {
        fn record(&self, event: MetricEvent) {
            self.events
                .lock()
                .expect("metrics lock poisoned")
                .push(event);
        }
    }

    #[test]
    fn noop_metrics_discards() {
        let metrics = NoopMetricSink;
        metrics.record(MetricEvent::LoginSucceeded);
        metrics.record(MetricEvent::CacheHit);
    }

    #[test]
    fn capturing_sink_collects_events_through_trait_object() {
        let sink = CapturingMetrics::default();
        let metrics: Arc<dyn MetricSink> = Arc::new(sink.clone());
        metrics.record(MetricEvent::LoginSucceeded);
        metrics.record(MetricEvent::AuthFailed {
            reason: AuthFailureReason::UnknownCredential,
        });
        metrics.record(MetricEvent::AuthLatency(Duration::from_millis(7)));

        assert_eq!(
            sink.events(),
            vec![
                MetricEvent::LoginSucceeded,
                MetricEvent::AuthFailed {
                    reason: AuthFailureReason::UnknownCredential,
                },
                MetricEvent::AuthLatency(Duration::from_millis(7)),
            ]
        );
    }
}
