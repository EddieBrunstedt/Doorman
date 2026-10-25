use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::common::{Client, TestApp};

#[tokio::test]
async fn doormans_routes_are_checked_and_authenticated_without_the_hosts_layer() {
    let app = TestApp::without_host_layer(InMemoryStorage::new().all_stores());
    let session = app.session_as(Client::Browser, "alice@example.com").await;

    let listed = app.get("/auth/sessions").session(&session).send().await;
    let forged = app
        .post("/auth/logout")
        .header("cookie", &format!("doorman_session={}", session.token))
        .header("sec-fetch-site", "cross-site")
        .header("origin", "https://evil.test")
        .send()
        .await;

    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert_eq!(forged.error_code(), "csrf_origin_mismatch");
}

#[tokio::test]
async fn a_host_route_without_the_layer_is_refused_as_a_mistake_not_as_no_session() {
    let app = TestApp::without_host_layer(InMemoryStorage::new().all_stores());
    let session = app.session_for("alice@example.com").await;

    let me = app.get("/me").bearer(&session.token).send().await;

    assert_eq!(me.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(me.error_code(), "internal_error");
}

#[tokio::test]
async fn a_request_through_both_layers_looks_its_session_up_once() {
    let mut storage = InMemoryStorage::new().all_stores();
    let sessions = Arc::new(CountingSessionStore {
        inner: storage.expiring.sessions.clone(),
        lookups: AtomicUsize::new(0),
    });
    storage.expiring.sessions = sessions.clone();
    let app = TestApp::with_storage(storage, |b| b, |b| b);
    let session = app.session_for("alice@example.com").await;
    sessions.lookups.store(0, Ordering::SeqCst);

    let reply = app
        .get("/auth/sessions")
        .bearer(&session.token)
        .send()
        .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(sessions.lookups.load(Ordering::SeqCst), 1);
}

struct CountingSessionStore {
    inner: Arc<dyn SessionStore>,
    lookups: AtomicUsize,
}

#[async_trait]
impl SessionStore for CountingSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.inner.create_session(session).await
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.touch_session(id, last_used_at, expires_at).await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.find_session_by_token_hash(hash).await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.inner.find_session_by_id(id).await
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        self.inner.list_for_user(user_id).await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.inner.delete_session(id).await
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        self.inner.delete_sessions_for_user(user_id, except).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.inner.purge_expired(now).await
    }
}
