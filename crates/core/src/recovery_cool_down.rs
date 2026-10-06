use chrono::{DateTime, Utc};

use crate::error::{Error, Result};
use crate::storage::{Session, StoredPasskey, StoredPasskeyRegistration};

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

    pub(crate) fn of_session(session: &Session, now: DateTime<Utc>) -> Self {
        Self(session.recovery_cool_down_until).in_force(now)
    }

    pub(crate) fn of_passkey(passkey: &StoredPasskey, now: DateTime<Utc>) -> Self {
        Self(passkey.recovery_cool_down_until).in_force(now)
    }

    pub(crate) fn of_registration(registration: &StoredPasskeyRegistration) -> Self {
        Self(registration.recovery_cool_down_until)
    }

    // A recovery stamps its challenge when the email link is redeemed and starts again when the
    // registration finishes; the later deadline wins, so a slow ceremony never eats into it.
    pub(crate) fn extended_by(self, other: Self) -> Self {
        Self(self.0.max(other.0))
    }

    pub(crate) fn until(self) -> Option<DateTime<Utc>> {
        self.0
    }

    pub(crate) fn refuse_destructive_action(session: &Session, now: DateTime<Utc>) -> Result<()> {
        if session.is_in_recovery_cool_down(now) {
            return Err(Error::RecoveryCoolDownActive);
        }
        Ok(())
    }

    fn in_force(self, now: DateTime<Utc>) -> Self {
        Self(self.0.filter(|&until| now < until))
    }
}

impl Session {
    pub fn is_in_recovery_cool_down(&self, now: DateTime<Utc>) -> bool {
        RecoveryCoolDown::of_session(self, now) != RecoveryCoolDown::NONE
    }
}

impl StoredPasskey {
    pub fn is_in_recovery_cool_down(&self, now: DateTime<Utc>) -> bool {
        RecoveryCoolDown::of_passkey(self, now) != RecoveryCoolDown::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn start_saturates_instead_of_overflowing() {
        let started = RecoveryCoolDown::start(DateTime::<Utc>::MAX_UTC, chrono::Duration::hours(1));
        assert_eq!(started.until(), Some(DateTime::<Utc>::MAX_UTC));
    }

    #[test]
    fn extended_by_keeps_the_later_deadline() {
        let earlier = RecoveryCoolDown::start(ts(0), chrono::Duration::hours(1));
        let later = RecoveryCoolDown::start(ts(0), chrono::Duration::hours(2));
        assert_eq!(earlier.extended_by(later), later);
        assert_eq!(later.extended_by(earlier), later);
        assert_eq!(RecoveryCoolDown::NONE.extended_by(earlier), earlier);
        assert_eq!(earlier.extended_by(RecoveryCoolDown::NONE), earlier);
    }
}
