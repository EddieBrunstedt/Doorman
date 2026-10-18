use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::{ExpiringStores, Session, SessionId, SessionStore, TokenHash, UserId};

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

    async fn find_session_by_token_hash(&self, _: &TokenHash) -> StorageResult<Option<Session>> {
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

#[tokio::test]
#[should_panic(expected = "needs at least 2 runtime workers, got 1")]
async fn the_suite_refuses_a_runtime_that_cannot_race() {
    let storage = InMemoryStorage::new().all_stores();
    doorman_conformance::run(&storage).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_failing_check_is_reported_after_the_whole_suite_ran() {
    let stores = ExpiringStores {
        sessions: Arc::new(UnavailableSessionStore),
        ..InMemoryStorage::new().expiring()
    };

    let failure = tokio::spawn(async move { doorman_conformance::run_expiring(&stores).await })
        .await
        .expect_err("a broken session store fails the suite")
        .into_panic();
    let report = failure
        .downcast_ref::<String>()
        .expect("the suite reports in a formatted panic");

    assert!(
        report.starts_with("9 of 19 conformance checks failed:"),
        "{report}"
    );
    for failed in ["sessions_crud_and_queries", "inserts_refuse_duplicate_keys"] {
        assert!(
            report.contains(&format!("- {failed}: ")),
            "{failed} is reported: {report}",
        );
    }
    assert!(
        report.contains("session store unavailable"),
        "a check's own message is kept: {report}",
    );
    assert!(
        !report.contains("- email_link_single_use: "),
        "a passing check is not reported: {report}",
    );
}
