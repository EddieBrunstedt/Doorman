//! Clock abstraction used by managers and tests.
//!
//! Production code usually uses [`SystemClock`]. Tests can use
//! [`MockClock`] to make expiry and rate-limit behaviour deterministic.

use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};

/// Source of the current UTC time.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Clock implementation backed by [`Utc::now`](chrono::Utc::now).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

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
