use chrono::{DateTime, Utc};

use crate::error::{Error, Result};
use crate::session::ResolvedSession;
use crate::storage::{SessionSummary, StoredPasskey, StoredPasskeyRegistration};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RecoveryCoolDown(Option<DateTime<Utc>>);

impl RecoveryCoolDown {
    pub(crate) const NONE: Self = Self(None);

    pub(crate) fn start(now: DateTime<Utc>, length: chrono::Duration) -> Self {
        Self(Some(
            now.checked_add_signed(length)
                .unwrap_or(DateTime::<Utc>::MAX_UTC),
        ))
    }

    pub(crate) fn of_session(session: &SessionSummary, now: DateTime<Utc>) -> Self {
        Self(session.recovery_cool_down_until).in_force(now)
    }

    pub(crate) fn of_passkey(passkey: &StoredPasskey, now: DateTime<Utc>) -> Self {
        Self(passkey.recovery_cool_down_until).in_force(now)
    }

    pub(crate) fn of_registration(registration: &StoredPasskeyRegistration) -> Self {
        Self(registration.recovery_cool_down_until)
    }

    pub(crate) fn extended_by(self, other: Self) -> Self {
        Self(self.0.max(other.0))
    }

    pub(crate) fn until(self) -> Option<DateTime<Utc>> {
        self.0
    }

    pub(crate) fn refuse_destructive_action(session: &ResolvedSession) -> Result<()> {
        if session.is_in_recovery_cool_down() {
            return Err(Error::RecoveryCoolDownActive);
        }
        Ok(())
    }

    // A passkey in cool-down would otherwise clear a destructive action for a session outside it.
    pub(crate) fn refuse_reauthentication(
        passkeys: Vec<StoredPasskey>,
        now: DateTime<Utc>,
    ) -> Result<Vec<StoredPasskey>> {
        let allowed: Vec<StoredPasskey> = passkeys
            .into_iter()
            .filter(|passkey| Self::of_passkey(passkey, now) == Self::NONE)
            .collect();
        if allowed.is_empty() {
            return Err(Error::RecoveryCoolDownActive);
        }
        Ok(allowed)
    }

    // A session in cool-down is refused revoking the user's sessions outside it, so starting one
    // must not evict them either.
    pub(crate) fn evictable_by(
        self,
        sessions: Vec<SessionSummary>,
        now: DateTime<Utc>,
    ) -> Vec<SessionSummary> {
        if self == Self::NONE {
            return sessions;
        }
        sessions
            .into_iter()
            .filter(|session| Self::of_session(session, now) != Self::NONE)
            .collect()
    }

    fn in_force(self, now: DateTime<Utc>) -> Self {
        Self(self.0.filter(|&until| now < until))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_saturates_instead_of_overflowing() {
        let started = RecoveryCoolDown::start(DateTime::<Utc>::MAX_UTC, chrono::Duration::hours(1));
        assert_eq!(started.until(), Some(DateTime::<Utc>::MAX_UTC));
    }
}
