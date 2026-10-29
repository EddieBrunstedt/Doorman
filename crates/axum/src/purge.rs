use std::sync::{Arc, Weak};
use std::time::Duration;

use doorman_core::assembly::AuthCore;
use tokio::runtime::Handle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::builder::BuilderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the purge interval ({0:?}) must be greater than zero and a reachable instant away")]
pub struct PurgeIntervalError(pub Duration);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeSchedule(Schedule);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Schedule {
    InProcess { every: Duration },
    External,
}

impl PurgeSchedule {
    pub fn in_process(every: Duration) -> Result<Self, PurgeIntervalError> {
        if every.is_zero() || Instant::now().checked_add(every).is_none() {
            return Err(PurgeIntervalError(every));
        }
        Ok(Self(Schedule::InProcess { every }))
    }

    pub const fn external() -> Self {
        Self(Schedule::External)
    }
}

pub(crate) struct Sweeper {
    runtime: Handle,
    every: Duration,
}

impl Sweeper {
    pub(crate) fn for_schedule(schedule: PurgeSchedule) -> Result<Option<Self>, BuilderError> {
        let PurgeSchedule(Schedule::InProcess { every }) = schedule else {
            return Ok(None);
        };
        let runtime = Handle::try_current().map_err(|_| BuilderError::PurgeNeedsRuntime)?;
        Ok(Some(Self { runtime, every }))
    }

    pub(crate) fn start(self, core: &Arc<AuthCore>) {
        self.runtime.spawn(sweep(Arc::downgrade(core), self.every));
    }
}

async fn sweep(core: Weak<AuthCore>, every: Duration) {
    let mut ticker = tokio::time::interval(every);
    // A sweep that overruns its period pushes the next one back, rather than leaving a backlog of
    // sweeps to run back to back.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // The task holds the core only while it sweeps, so dropping the service ends it.
        let Some(core) = core.upgrade() else {
            return;
        };
        let summary = core.purge_expired().await;
        for (store, error) in summary.failures() {
            tracing::warn!(store, %error, "purge sweep failed");
        }
        tracing::debug!(
            sessions = summary.sessions.as_ref().ok(),
            email_links = summary.email_links.as_ref().ok(),
            passkey_challenges = summary.passkey_challenges.as_ref().ok(),
            total = summary.total(),
            "purged expired rows",
        );
    }
}
