use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use doorman_axum::{AuthService, PurgeSchedule};
use doorman_core::clock::Clock;
use doorman_core::memory::InMemoryStorage;
use doorman_core::storage::{Session, SessionId, SessionTransport, Storage, TokenHash, UserId};
use doorman_test_support::{CapturingEmailSender, MockClock};

use crate::common::core_builder;

const EVERY: Duration = Duration::from_secs(3600);

fn start() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(2_000_000, 0).expect("timestamp")
}

fn in_process_service(storage: Storage, clock: Arc<MockClock>) -> AuthService {
    let core = core_builder(storage, Arc::new(CapturingEmailSender::new()))
        .clock(clock as Arc<dyn Clock>)
        .build();
    let purge = PurgeSchedule::in_process(EVERY).expect("purge schedule");
    AuthService::builder(core, purge).build().expect("build")
}

async fn session_expiring_at(storage: &Storage, tag: u8, expires_at: DateTime<Utc>) -> SessionId {
    let id = SessionId::new();
    storage
        .expiring
        .sessions
        .create_session(Session {
            id,
            user_id: UserId::new(),
            token_hash: TokenHash([tag; 32]),
            transport: SessionTransport::Cookie,
            created_at: start() - chrono::Duration::hours(2),
            last_used_at: start() - chrono::Duration::hours(2),
            expires_at,
            ip: "192.0.2.1".parse().expect("client IP"),
            user_agent: None,
            recovery_cool_down_until: None,
        })
        .await
        .expect("session");
    id
}

async fn session_exists(storage: &Storage, id: SessionId) -> bool {
    storage
        .expiring
        .sessions
        .find_session_by_id(id)
        .await
        .expect("get")
        .is_some()
}

async fn let_the_sweep_run() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn an_in_process_purge_schedule_sweeps_every_period_at_the_core_clock() {
    let storage = InMemoryStorage::new().all_stores();
    let clock = Arc::new(MockClock::new(start()));
    let expired = session_expiring_at(&storage, 1, start() - chrono::Duration::hours(1)).await;
    let live = session_expiring_at(&storage, 2, start() + chrono::Duration::minutes(30)).await;

    let _auth = in_process_service(storage.clone(), clock.clone());
    let_the_sweep_run().await;
    assert!(
        !session_exists(&storage, expired).await,
        "the first sweep runs at once"
    );
    assert!(session_exists(&storage, live).await, "a live row stays");

    clock.advance(chrono::Duration::hours(1));
    tokio::time::advance(EVERY).await;
    let_the_sweep_run().await;
    assert!(
        !session_exists(&storage, live).await,
        "the next sweep, a period later, purges the row that has since expired"
    );
}

#[tokio::test(start_paused = true)]
async fn the_in_process_purge_stops_once_the_service_is_dropped() {
    let storage = InMemoryStorage::new().all_stores();
    let clock = Arc::new(MockClock::new(start()));

    let auth = in_process_service(storage.clone(), clock.clone());
    let_the_sweep_run().await;
    drop(auth);

    let expired = session_expiring_at(&storage, 1, start() - chrono::Duration::hours(1)).await;
    tokio::time::advance(EVERY).await;
    let_the_sweep_run().await;
    assert!(session_exists(&storage, expired).await);
}
