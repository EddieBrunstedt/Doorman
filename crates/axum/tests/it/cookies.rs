use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Utc};
use doorman_axum::config::CookieConfig;
use doorman_axum::dto::AuthResponse;
use doorman_core::clock::Clock;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::memory::InMemoryStorage;
use doorman_core::session::{DEFAULT_SESSION_LIFETIME, SessionConfig};
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId, UserStatus};
use doorman_test_support::MockClock;

use crate::common::{ResidentAuthenticator, TestApp, rp_origin};

#[tokio::test]
async fn a_login_sets_a_session_cookie_that_authenticates() {
    let app = TestApp::new();
    let (_, mut authenticator) = app.signup("alice@example.com").await;
    let credential_id = authenticator.credential_ids()[0].clone();

    let login = app.log_in(&mut authenticator, &credential_id).await;
    assert_eq!(login.status, StatusCode::OK);
    let auth: AuthResponse = login.json();
    let set_cookie = login.set_cookie().expect("login sets the session cookie");
    assert!(set_cookie.contains(&format!("doorman_session={}", auth.token)));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(
        set_cookie.contains(&format!("Max-Age={}", DEFAULT_SESSION_LIFETIME.as_secs())),
        "the cookie lives as long as the session it carries: {set_cookie}",
    );

    let me = app.get("/me").cookie(&auth.token).send().await;
    assert_eq!(me.status, StatusCode::OK);
}

// Every request slides the session it carries, so each route below competes with a refresh of that
// cookie.
fn always_sliding_app() -> TestApp {
    TestApp::with(
        |b| {
            b.session(SessionConfig {
                idle_timeout: Some(IDLE),
                slide_interval: Duration::ZERO,
                ..SessionConfig::default()
            })
        },
        |b| b,
    )
}

#[tokio::test]
async fn ending_a_session_clears_its_cookie() {
    for (method, path) in [
        (Method::POST, "/auth/logout"),
        (Method::POST, "/auth/logout-all"),
        (Method::DELETE, "/auth/user"),
        (Method::DELETE, "/auth/sessions/{current}"),
    ] {
        let app = always_sliding_app();
        let session = app.session_for("alice@example.com").await;
        let target = path.replace("{current}", &session.session.id.0.to_string());

        let reply = app
            .call(method.clone(), &target)
            .cookie(&session.token)
            .send()
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{method} {path}");
        let set_cookie = reply.set_cookie().expect("the cookie is cleared");
        assert!(set_cookie.contains("doorman_session=;"), "{method} {path}");
        assert!(set_cookie.contains("Max-Age=0"), "{method} {path}");
        assert!(
            !app.is_authenticated(&session.token).await,
            "{method} {path}"
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum SessionStart {
    Login,
    Signup,
    Recovery,
}

#[tokio::test]
async fn starting_a_session_replaces_the_cookie_the_request_carried() {
    for (start, carried_live) in [
        SessionStart::Login,
        SessionStart::Signup,
        SessionStart::Recovery,
    ]
    .into_iter()
    .flat_map(|start| [(start, true), (start, false)])
    {
        let app = always_sliding_app();
        let (_, mut bob) = app.signup("bob@example.com").await;
        let alice = app.session_for("alice@example.com").await;
        if !carried_live {
            log_out(&app, &alice.token).await;
        }
        let app = app.default_header("cookie", &format!("doorman_session={}", alice.token));

        let reply = match start {
            SessionStart::Login => {
                let credential_id = bob.credential_ids()[0].clone();
                app.log_in(&mut bob, &credential_id).await
            }
            SessionStart::Signup => {
                let mut carol = ResidentAuthenticator::new(&rp_origin());
                app.finish_signup("carol@example.com", &mut carol).await
            }
            SessionStart::Recovery => app.finish_recovery("bob@example.com", &mut bob).await,
        };

        assert_eq!(reply.status, StatusCode::OK, "{start:?} {carried_live}");
        let started: AuthResponse = reply.json();
        let set_cookie = reply.set_cookie().expect("the new session's cookie is set");
        assert!(
            set_cookie.contains(&format!("doorman_session={};", started.token)),
            "{start:?} {carried_live}: {set_cookie}"
        );
    }
}

#[tokio::test]
async fn a_refused_login_sets_no_cookie() {
    let app = TestApp::new();
    let (auth, mut authenticator) = app.signup("alice@example.com").await;
    app.set_user_status(auth.user.id, UserStatus::Disabled { at: Utc::now() })
        .await;
    let credential_id = authenticator.credential_ids()[0].clone();

    let login = app.log_in(&mut authenticator, &credential_id).await;

    assert_eq!(login.status, StatusCode::FORBIDDEN);
    assert_eq!(login.error_code(), "user_disabled");
    assert!(login.set_cookie().is_none());
}

const IDLE: Duration = Duration::from_secs(60 * 60);

fn sliding_app(clock: Arc<MockClock>) -> TestApp {
    TestApp::with(
        move |b| {
            b.clock(clock as Arc<dyn Clock>).session(SessionConfig {
                absolute_lifetime: Duration::from_secs(60 * 60 * 24),
                idle_timeout: Some(IDLE),
                ..SessionConfig::default()
            })
        },
        |b| {
            b.cookie(CookieConfig {
                secure: false,
                ..CookieConfig::default()
            })
        },
    )
}

#[tokio::test]
async fn a_slid_session_refreshes_its_cookie() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app = sliding_app(clock.clone());
    let session = app.session_for("alice@example.com").await;

    let unslid = app.get("/me").cookie(&session.token).send().await;
    assert_eq!(unslid.status, StatusCode::OK);
    assert!(unslid.set_cookie().is_none(), "no slide, no refresh");

    clock.advance(chrono::Duration::minutes(2));
    let slid = app.get("/me").cookie(&session.token).send().await;
    assert_eq!(slid.status, StatusCode::OK);
    let set_cookie = slid.set_cookie().expect("a slide refreshes the cookie");
    assert!(set_cookie.contains(&format!("doorman_session={}", session.token)));
    assert!(set_cookie.contains(&format!("Max-Age={}", IDLE.as_secs())));
}

#[tokio::test]
async fn a_slid_bearer_session_sets_no_cookie() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app = sliding_app(clock.clone());
    let session = app.session_for("alice@example.com").await;

    clock.advance(chrono::Duration::minutes(2));
    let slid = app.get("/me").bearer(&session.token).send().await;

    assert_eq!(slid.status, StatusCode::OK);
    assert!(
        slid.set_cookie().is_none(),
        "bearer clients track expiry themselves"
    );
}

async fn log_out(app: &TestApp, token: &str) {
    let reply = app.post("/auth/logout").bearer(token).send().await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_cookie_without_a_live_session_is_cleared() {
    let clock = Arc::new(MockClock::new(Utc::now()));
    let app = sliding_app(clock.clone());
    let revoked = app.session_for("alice@example.com").await;
    log_out(&app, &revoked.token).await;
    let expired = app.session_for("bob@example.com").await;
    clock.advance(chrono::Duration::from_std(IDLE).expect("idle") + chrono::Duration::seconds(1));

    for (name, token) in [("revoked", &revoked.token), ("expired", &expired.token)] {
        let me = app.get("/me").cookie(token).send().await;
        assert_eq!(me.status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(me.error_code(), "session_not_found", "{name}");
        let set_cookie = me.set_cookie().expect("the dead cookie is cleared");
        assert!(
            set_cookie.contains("doorman_session=;"),
            "{name}: {set_cookie}"
        );
        assert!(set_cookie.contains("Max-Age=0"), "{name}: {set_cookie}");
    }
}

#[tokio::test]
async fn a_bearer_token_without_a_live_session_sets_no_cookie() {
    let app = TestApp::new();
    let session = app.session_for("alice@example.com").await;
    log_out(&app, &session.token).await;

    let me = app.get("/me").bearer(&session.token).send().await;

    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert!(me.set_cookie().is_none());
}

#[tokio::test]
async fn a_session_store_failure_refuses_the_request_and_keeps_its_cookie() {
    let memory = InMemoryStorage::new();
    let mut storage = memory.all_stores();
    storage.expiring.sessions = Arc::new(UnavailableSessionStore);
    let app = TestApp::with_storage(storage, |b| b, |b| b);

    let me = app.get("/me").cookie("a-session-token").send().await;

    assert_eq!(me.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(me.error_code(), "storage_error");
    assert!(me.set_cookie().is_none(), "the session may still be live");
}

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
