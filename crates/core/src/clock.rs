//! Clock abstraction used by managers and tests.
//!
//! Production code usually uses [`SystemClock`]. Tests use the `MockClock`
//! from `bauth-test-support` to make expiry and rate-limit behaviour
//! deterministic.

use chrono::{DateTime, Utc};

/// Source of the current UTC time.
pub trait Clock: Send + Sync {
    /// Return the current UTC instant. A mock implementation drives
    /// deterministic time in tests.
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
