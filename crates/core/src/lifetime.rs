use std::time::Duration;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifetimeError {
    #[error("a lifetime must be greater than zero")]
    Zero,
    #[error("a lifetime ({0:?}) must be at most {max:?}", max = Lifetime::MAX.get())]
    TooLong(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lifetime(Duration);

impl Lifetime {
    // Far enough inside chrono's range that a deadline can always be computed from any real
    // clock reading.
    pub const MAX: Self = Self(Duration::from_secs(60 * 60 * 24 * 365 * 10));

    pub const fn new(lifetime: Duration) -> Result<Self, LifetimeError> {
        if lifetime.is_zero() {
            return Err(LifetimeError::Zero);
        }
        if Self::MAX.0.checked_sub(lifetime).is_none() {
            return Err(LifetimeError::TooLong(lifetime));
        }
        Ok(Self(lifetime))
    }

    // Only consts call this, so a lifetime out of bounds fails the build rather than panicking
    // in the host's process.
    #[allow(clippy::panic)]
    pub(crate) const fn from_secs(secs: u64) -> Self {
        match Self::new(Duration::from_secs(secs)) {
            Ok(lifetime) => lifetime,
            Err(_) => panic!("a lifetime const is out of bounds"),
        }
    }

    pub const fn get(self) -> Duration {
        self.0
    }

    pub(crate) fn ends(self, start: DateTime<Utc>) -> DateTime<Utc> {
        chrono::Duration::from_std(self.0)
            .ok()
            .and_then(|lifetime| start.checked_add_signed(lifetime))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_lifetime_ends_inside_chronos_range() {
        let now = Utc::now();
        assert!(Lifetime::MAX.ends(now) < DateTime::<Utc>::MAX_UTC);
    }

    #[test]
    fn a_lifetime_saturates_at_the_end_of_time() {
        let lifetime = Lifetime::from_secs(60 * 60);
        assert_eq!(
            lifetime.ends(DateTime::<Utc>::MAX_UTC),
            DateTime::<Utc>::MAX_UTC
        );
    }
}
