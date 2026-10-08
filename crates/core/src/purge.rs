use chrono::{DateTime, Utc};

use crate::error::StorageResult;
use crate::storage::Storage;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeSummary {
    pub sessions: u64,
    pub email_links: u64,
    pub passkey_challenges: u64,
}

impl PurgeSummary {
    pub fn total(&self) -> u64 {
        self.sessions + self.email_links + self.passkey_challenges
    }
}

impl Storage {
    pub async fn purge_all_expired(&self, now: DateTime<Utc>) -> StorageResult<PurgeSummary> {
        let sessions = self.sessions.purge_expired(now).await?;
        let email_links = self.email_links.purge_expired(now).await?;
        let passkey_challenges = self.passkey_challenges.purge_expired(now).await?;
        Ok(PurgeSummary {
            sessions,
            email_links,
            passkey_challenges,
        })
    }
}

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
                        email_links = summary.email_links,
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
        AuthenticationPurpose, EmailLink, EmailLinkPurpose, PasskeyChallengeId,
        RegistrationPurpose, Session, SessionId, StoredPasskeyAuthentication,
        StoredPasskeyRegistration, TokenHash, UserId,
    };

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

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
            recovery_cool_down_until: None,
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

        let mk_token = |tag: u8, purpose, expires_at: DateTime<Utc>| EmailLink {
            token_hash: TokenHash([tag; 32]),
            user_id,
            purpose,
            new_email: None,
            created_at: now - chrono::Duration::hours(2),
            expires_at,
        };
        storage
            .email_links
            .replace_link(mk_token(3, EmailLinkPurpose::Signup, expired))
            .await
            .expect("expired token");
        storage
            .email_links
            .replace_link(mk_token(4, EmailLinkPurpose::Recovery, live))
            .await
            .expect("live token");

        let mk_reg = |expires_at: DateTime<Utc>| StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            purpose: RegistrationPurpose::AddPasskey,
            user_id,
            state: vec![1, 2, 3],
            created_at: now - chrono::Duration::hours(2),
            expires_at,
            recovery_cool_down_until: None,
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
            purpose: AuthenticationPurpose::Login,
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
        assert_eq!(summary.email_links, 1);
        assert_eq!(summary.passkey_challenges, 2);
        assert_eq!(summary.total(), 4);

        let second = storage.purge_all_expired(now).await.expect("second purge");
        assert_eq!(second.total(), 0);
    }

    #[cfg(feature = "background-purge")]
    #[tokio::test(start_paused = true)]
    async fn spawn_purge_task_sweeps_on_its_interval() {
        use crate::clock::Clock;

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

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        handle.abort();

        let remaining = storage.sessions.list_for_user(user_id).await.expect("list");
        assert_eq!(remaining.len(), 1, "background task swept the expired row");
        assert!(remaining[0].expires_at > now);
    }
}
