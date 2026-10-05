use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::{Error, Result};

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub(crate) fn expiry(now: DateTime<Utc>, lifetime: Duration) -> Result<DateTime<Utc>> {
    chrono::Duration::from_std(lifetime)
        .ok()
        .and_then(|lifetime| now.checked_add_signed(lifetime))
        .ok_or_else(|| Error::Internal(format!("lifetime {lifetime:?} is out of range")))
}
