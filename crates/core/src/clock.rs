//! Clock abstraction used by managers and tests.
//!
//! Production code usually uses [`SystemClock`]. Tests use the `MockClock`
//! from `doorman-test-support` to make expiry and rate-limit behaviour
//! deterministic.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::{Error, Result};

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

/// The instant `lifetime` after `now`: when a token or ceremony challenge
/// minted at `now` expires. Assembly bounds every configured lifetime, so an
/// out-of-range one is a wiring bug; it fails the mint rather than yielding a
/// secret that never expires.
pub(crate) fn expiry(now: DateTime<Utc>, lifetime: Duration) -> Result<DateTime<Utc>> {
    chrono::Duration::from_std(lifetime)
        .ok()
        .and_then(|lifetime| now.checked_add_signed(lifetime))
        .ok_or_else(|| Error::Internal(format!("lifetime {lifetime:?} is out of range")))
}
