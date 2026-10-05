use std::time::Duration;

use crate::audit::AuthFailureReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetricEvent {
    LoginSucceeded,
    AuthFailed { reason: AuthFailureReason },
    AuthLatency(Duration),
    CacheHit,
    CacheMiss,
}

pub trait MetricSink: Send + Sync {
    fn record(&self, event: MetricEvent);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetricSink;

impl MetricSink for NoopMetricSink {
    fn record(&self, _event: MetricEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

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
