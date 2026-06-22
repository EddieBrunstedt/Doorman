//! Expiry sweeping helpers.
//!
//! [`Storage::purge_all_expired`] runs every store's `purge_expired` in one
//! call so a host need not reimplement the per-table sweep by hand. With the
//! `background-purge` feature enabled, `spawn_purge_task` spawns a tokio
//! task that calls it on a fixed interval.

use chrono::{DateTime, Utc};

use crate::error::StorageResult;
use crate::storage::Storage;

/// Per-store counts from a [`Storage::purge_all_expired`] sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeSummary {
    /// Expired sessions removed.
    pub sessions: u64,
    /// Expired verification tokens removed.
    pub verification_tokens: u64,
    /// Expired passkey ceremony challenges removed (registrations and
    /// authentications combined).
    pub passkey_challenges: u64,
}

impl PurgeSummary {
    /// Total rows removed across every store.
    pub fn total(&self) -> u64 {
        self.sessions + self.verification_tokens + self.passkey_challenges
    }
}

impl Storage {
    /// Sweep every store of rows whose expiry is at or before `now`,
    /// returning the per-store counts.
    ///
    /// Covers the three stores that hold time-limited rows — sessions,
    /// verification tokens, and passkey ceremony challenges. User and
    /// credential records never expire and are left untouched. The sweeps run
    /// in sequence; if one store errors the call returns early and the
    /// remaining stores are not swept on that pass (the next pass retries
    /// them).
    pub async fn purge_all_expired(&self, now: DateTime<Utc>) -> StorageResult<PurgeSummary> {
        let sessions = self.sessions.purge_expired(now).await?;
        let verification_tokens = self.verification_tokens.purge_expired(now).await?;
        let passkey_challenges = self.passkey_challenges.purge_expired(now).await?;
        Ok(PurgeSummary {
            sessions,
            verification_tokens,
            passkey_challenges,
        })
    }
}

/// Spawn a background task that sweeps expired rows from `storage` every
/// `interval`, reading the current time from `clock`.
///
/// The first sweep runs immediately; subsequent sweeps run once per
/// `interval`. A sweep error is logged and the loop continues, so a transient
/// store failure does not kill the task. Drop or
/// [`abort`](tokio::task::JoinHandle::abort) the returned handle to stop it.
///
/// Gated behind the `background-purge` feature so the default core build does
/// not pull tokio's runtime/timer features.
#[cfg(feature = "background-purge")]
pub fn spawn_purge_task(
    storage: Storage,
    clock: std::sync::Arc<dyn crate::clock::Clock>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = clock.now();
            match storage.purge_all_expired(now).await {
                Ok(summary) => {
                    tracing::debug!(
                        sessions = summary.sessions,
                        verification_tokens = summary.verification_tokens,
                        passkey_challenges = summary.passkey_challenges,
                        total = summary.total(),
                        "purged expired rows",
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "background purge sweep failed");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::InMemoryStorage;
    use crate::storage::{
        PasskeyChallengeId, Session, SessionId, StoredPasskeyAuthentication,
        StoredPasskeyRegistration, TokenHash, UserId, VerificationPurpose, VerificationToken,
    };

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    /// Seed `storage` with one expired and one live row in each
    /// time-limited store. `now` is the sweep instant; "expired" rows have
    /// `expires_at <= now`, "live" rows expire after it.
    async fn seed(storage: &Storage, user_id: UserId, now: DateTime<Utc>) {
        let expired = now - chrono::Duration::hours(1);
        let live = now + chrono::Duration::hours(1);

        let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
            id: SessionId::new(),
            user_id,
            token_hash: TokenHash([tag; 32]),
            created_at: now - chrono::Duration::hours(2),
            last_used_at: now - chrono::Duration::hours(2),
            expires_at,
            ip: None,
            user_agent: None,
            recovery_cooldown_until: None,
        };
        storage
            .sessions
            .create_session(mk_session(1, expired))
            .await
            .expect("expired session");
        storage
            .sessions
            .create_session(mk_session(2, live))
            .await
            .expect("live session");

        let mk_token = |tag: u8, expires_at: DateTime<Utc>| VerificationToken {
            token_hash: TokenHash([tag; 32]),
            user_id,
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: now - chrono::Duration::hours(2),
            expires_at,
        };
        storage
            .verification_tokens
            .create_token(mk_token(3, expired))
            .await
            .expect("expired token");
        storage
            .verification_tokens
            .create_token(mk_token(4, live))
            .await
            .expect("live token");

        let mk_reg = |expires_at: DateTime<Utc>| StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            user_id,
            state: vec![1, 2, 3],
            created_at: now - chrono::Duration::hours(2),
            expires_at,
            recovery_cooldown_until: None,
        };
        storage
            .passkey_challenges
            .put_registration(mk_reg(expired))
            .await
            .expect("expired registration");
        storage
            .passkey_challenges
            .put_registration(mk_reg(live))
            .await
            .expect("live registration");

        let expired_auth = StoredPasskeyAuthentication {
            id: PasskeyChallengeId::new(),
            state: vec![4, 5, 6],
            created_at: now - chrono::Duration::hours(2),
            expires_at: expired,
        };
        storage
            .passkey_challenges
            .put_authentication(expired_auth)
            .await
            .expect("expired authentication");
    }

    #[tokio::test]
    async fn purge_all_expired_sweeps_every_store_and_reports_counts() {
        let now = ts(1_000_000);
        let storage = InMemoryStorage::new().all_stores();
        seed(&storage, UserId::new(), now).await;

        let summary = storage.purge_all_expired(now).await.expect("purge");

        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.verification_tokens, 1);
        // One expired registration + one expired authentication.
        assert_eq!(summary.passkey_challenges, 2);
        assert_eq!(summary.total(), 4);

        // The live rows survive: a second sweep removes nothing.
        let second = storage.purge_all_expired(now).await.expect("second purge");
        assert_eq!(second.total(), 0);
    }

    #[cfg(feature = "background-purge")]
    #[tokio::test(start_paused = true)]
    async fn spawn_purge_task_sweeps_on_its_interval() {
        use crate::clock::Clock;

        // A fixed clock whose `now` sits after the seeded expired rows but
        // before the live ones, so a sweep removes exactly the expired set.
        struct FixedClock(DateTime<Utc>);
        impl Clock for FixedClock {
            fn now(&self) -> DateTime<Utc> {
                self.0
            }
        }

        let now = ts(2_000_000);
        let user_id = UserId::new();
        let storage = InMemoryStorage::new().all_stores();
        seed(&storage, user_id, now).await;

        let handle = spawn_purge_task(
            storage.clone(),
            std::sync::Arc::new(FixedClock(now)),
            std::time::Duration::from_secs(3600),
        );

        // The first interval tick fires immediately; yield so the spawned
        // task runs its first sweep, then stop it.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        handle.abort();

        // The reference store returns rows unfiltered, so a non-empty list
        // that holds only the live session proves the task removed the
        // expired one (an un-run task would leave two rows).
        let remaining = storage
            .sessions
            .list_for_user(user_id, now)
            .await
            .expect("list");
        assert_eq!(remaining.len(), 1, "background task swept the expired row");
        assert!(remaining[0].expires_at > now);
    }
}
