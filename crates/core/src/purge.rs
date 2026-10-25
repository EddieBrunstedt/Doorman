use chrono::{DateTime, Utc};

use crate::error::{StorageError, StorageResult};
use crate::storage::ExpiringStores;

#[derive(Debug)]
pub struct PurgeSummary {
    pub sessions: StorageResult<u64>,
    pub email_links: StorageResult<u64>,
    pub passkey_challenges: StorageResult<u64>,
}

impl PurgeSummary {
    pub fn total(&self) -> u64 {
        self.outcomes()
            .filter_map(|(_, outcome)| outcome.as_ref().ok())
            .sum()
    }

    pub fn failures(&self) -> impl Iterator<Item = (&'static str, &StorageError)> {
        self.outcomes()
            .filter_map(|(store, outcome)| outcome.as_ref().err().map(|error| (store, error)))
    }

    pub fn outcomes(&self) -> impl Iterator<Item = (&'static str, &StorageResult<u64>)> {
        [
            ("sessions", &self.sessions),
            ("email_links", &self.email_links),
            ("passkey_challenges", &self.passkey_challenges),
        ]
        .into_iter()
    }
}

impl ExpiringStores {
    pub async fn purge_all_expired(&self, now: DateTime<Utc>) -> PurgeSummary {
        // In sequence: SQLite and redb admit one writer at a time.
        PurgeSummary {
            sessions: self.sessions.purge_expired(now).await,
            email_links: self.email_links.purge_expired(now).await,
            passkey_challenges: self.passkey_challenges.purge_expired(now).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::memory::InMemoryStorage;
    use crate::storage::{
        AuthenticationPurpose, EmailLink, EmailLinkPurpose, PasskeyChallengeId,
        RegistrationPurpose, Session, SessionId, SessionStore, SessionTransport,
        StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, UserId,
    };

    struct UnavailableSessionStore;

    fn unavailable<T>() -> StorageResult<T> {
        Err(StorageError::msg("session store unavailable"))
    }

    #[async_trait]
    impl SessionStore for UnavailableSessionStore {
        async fn create_session(&self, _: Session) -> StorageResult<()> {
            unavailable()
        }

        async fn touch_session(
            &self,
            _: SessionId,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
        ) -> StorageResult<()> {
            unavailable()
        }

        async fn find_session_by_token_hash(
            &self,
            _: &TokenHash,
        ) -> StorageResult<Option<Session>> {
            unavailable()
        }

        async fn find_session_by_id(&self, _: SessionId) -> StorageResult<Option<Session>> {
            unavailable()
        }

        async fn list_for_user(&self, _: UserId) -> StorageResult<Vec<Session>> {
            unavailable()
        }

        async fn delete_session(&self, _: SessionId) -> StorageResult<()> {
            unavailable()
        }

        async fn delete_sessions_for_user(
            &self,
            _: UserId,
            _: Option<SessionId>,
        ) -> StorageResult<u64> {
            unavailable()
        }

        async fn purge_expired(&self, _: DateTime<Utc>) -> StorageResult<u64> {
            unavailable()
        }
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    async fn seed(stores: &ExpiringStores, user_id: UserId, now: DateTime<Utc>) {
        let expired = now - chrono::Duration::hours(1);
        let live = now + chrono::Duration::hours(1);

        let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
            id: SessionId::new(),
            user_id,
            token_hash: TokenHash([tag; 32]),
            transport: SessionTransport::Cookie,
            created_at: now - chrono::Duration::hours(2),
            last_used_at: now - chrono::Duration::hours(2),
            expires_at,
            ip: "192.0.2.1".parse().expect("ip"),
            user_agent: None,
            recovery_cool_down_until: None,
        };
        stores
            .sessions
            .create_session(mk_session(1, expired))
            .await
            .expect("expired session");
        stores
            .sessions
            .create_session(mk_session(2, live))
            .await
            .expect("live session");

        let mk_token = |tag: u8, purpose, expires_at: DateTime<Utc>| EmailLink {
            token_hash: TokenHash([tag; 32]),
            user_id,
            purpose,
            owner_email: None,
            new_email: None,
            created_at: now - chrono::Duration::hours(2),
            expires_at,
        };
        stores
            .email_links
            .replace_link(mk_token(3, EmailLinkPurpose::Signup, expired))
            .await
            .expect("expired token");
        stores
            .email_links
            .replace_link(mk_token(4, EmailLinkPurpose::Recovery, live))
            .await
            .expect("live token");

        let mk_reg = |expires_at: DateTime<Utc>| StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            purpose: RegistrationPurpose::AddPasskey,
            user_id,
            state: vec![1, 2, 3],
            owner_email: None,
            created_at: now - chrono::Duration::hours(2),
            expires_at,
            recovery_cool_down_until: None,
        };
        stores
            .passkey_challenges
            .put_registration(mk_reg(expired))
            .await
            .expect("expired registration");
        stores
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
        stores
            .passkey_challenges
            .put_authentication(expired_auth)
            .await
            .expect("expired authentication");
    }

    #[tokio::test]
    async fn purge_all_expired_sweeps_every_store_and_reports_counts() {
        let now = ts(1_000_000);
        let stores = InMemoryStorage::new().expiring();
        seed(&stores, UserId::new(), now).await;

        let summary = stores.purge_all_expired(now).await;

        assert_eq!(summary.sessions.expect("sessions"), 1);
        assert_eq!(summary.email_links.expect("email links"), 1);
        assert_eq!(summary.passkey_challenges.expect("passkey challenges"), 2);

        let second = stores.purge_all_expired(now).await;
        assert_eq!(second.failures().count(), 0);
        assert_eq!(second.total(), 0);
    }

    #[tokio::test]
    async fn purge_all_expired_sweeps_the_other_stores_when_one_fails() {
        let now = ts(1_000_000);
        let healthy = InMemoryStorage::new().expiring();
        seed(&healthy, UserId::new(), now).await;
        let stores = ExpiringStores {
            sessions: Arc::new(UnavailableSessionStore),
            ..healthy
        };

        let summary = stores.purge_all_expired(now).await;

        assert!(summary.sessions.is_err());
        assert_eq!(summary.email_links.as_ref().expect("email links"), &1);
        assert_eq!(
            summary
                .passkey_challenges
                .as_ref()
                .expect("passkey challenges"),
            &2
        );
        assert_eq!(summary.total(), 3);
        let failed: Vec<_> = summary.failures().map(|(store, _)| store).collect();
        assert_eq!(failed, ["sessions"]);
    }
}
