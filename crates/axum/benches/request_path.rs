use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use doorman_axum::AuthService;
use doorman_axum::SessionCache;
use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_axum::dto::UserDto;
use doorman_axum::extractors::AuthSession;
use doorman_core::account::AccountConfig;
use doorman_core::assembly::AuthCore;
use doorman_core::audit::NoopAuditSink;
use doorman_core::clock::SystemClock;
use doorman_core::email::EmailSender;
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::{SessionContext, SessionManager};
use doorman_core::signup::SignupConfig;
use doorman_core::storage::{
    AccountStatus, PasskeyCredentialStore, Storage, User, UserId, UserStore,
};
use doorman_test_support::CapturingEmailSender;
use tokio::runtime::Runtime;
use tower::ServiceExt;

struct Scaffold {
    router: Router,
    cache: SessionCache,
    token: String,
    user_id: UserId,
}

async fn build_scaffold() -> Scaffold {
    let email = Arc::new(CapturingEmailSender::new());
    let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let token_store: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let passkey_credentials: Arc<InMemoryPasskeyCredentialStore> =
        Arc::new(InMemoryPasskeyCredentialStore::new());
    let passkey_challenges: Arc<InMemoryPasskeyChallengeStore> =
        Arc::new(InMemoryPasskeyChallengeStore::new());

    let rp_origin = url::Url::parse("http://localhost:8080").expect("rp origin");
    let storage = Storage {
        users: user_store.clone(),
        sessions: session_store.clone(),
        verification_tokens: token_store,
        passkey_credentials: passkey_credentials.clone(),
        passkey_challenges,
    };

    let core = AuthCore::builder(storage)
        .email(email as Arc<dyn EmailSender>)
        .passkey(PasskeyConfig::new("localhost", rp_origin, "doorman bench"))
        .reauthentication(doorman_core::reauth::ReauthPolicy::disabled())
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig {
            url_template: "https://app.test/signup?token={token}".to_string(),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery?token={token}".to_string(),
            ..RecoveryConfig::default()
        })
        .account(AccountConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..AccountConfig::default()
        })
        .build()
        .expect("auth core built");
    let auth = AuthService::builder(core)
        .csrf(CsrfConfig::disabled())
        .cookie(CookieConfig {
            secure: false,
            ..CookieConfig::default()
        })
        .build()
        .expect("auth built");

    let session_manager: SessionManager = auth.state().session_manager().clone();
    let cache = auth.cache().clone();

    let now = chrono::Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("bench@example.com".into()),
        email_verified_at: Some(now),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    let user_id = user.id;
    user_store.create_user(user).await.expect("create user");
    let token = session_manager
        .create(user_id, SessionContext::default())
        .await
        .expect("create session")
        .token;

    let passkey_credentials_dyn: Arc<dyn PasskeyCredentialStore> = passkey_credentials;
    let router = Router::new()
        .merge(auth.router())
        .route("/me", get(me_handler))
        .route("/public", get(|| async { StatusCode::OK }))
        .layer(Extension(passkey_credentials_dyn))
        .layer(auth.session_layer());

    Scaffold {
        router,
        cache,
        token,
        user_id,
    }
}

async fn me_handler(
    auth: AuthSession,
    Extension(passkey_credentials): Extension<Arc<dyn PasskeyCredentialStore>>,
) -> Response {
    let passkey_count = passkey_credentials
        .count_passkeys_for_user(auth.user.id)
        .await
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(UserDto::from_user(&auth.user, passkey_count)),
    )
        .into_response()
}

fn me_request(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request")
}

fn request_path(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());

    runtime.block_on(async {
        let response = scaffold
            .router
            .clone()
            .oneshot(me_request(&scaffold.token))
            .await
            .expect("warm request");
        assert_eq!(response.status(), StatusCode::OK);
    });

    c.bench_function("me_cached", |b| {
        b.to_async(&runtime).iter(|| async {
            let response = scaffold
                .router
                .clone()
                .oneshot(me_request(&scaffold.token))
                .await
                .expect("request");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    c.bench_function("me_uncached", |b| {
        b.to_async(&runtime).iter_batched(
            || {
                scaffold.cache.invalidate_user(scaffold.user_id);
            },
            |_| async {
                let response = scaffold
                    .router
                    .clone()
                    .oneshot(me_request(&scaffold.token))
                    .await
                    .expect("request");
                assert_eq!(response.status(), StatusCode::OK);
            },
            BatchSize::PerIteration,
        );
    });

    c.bench_function("layer_no_auth", |b| {
        b.to_async(&runtime).iter(|| async {
            let request = Request::builder()
                .uri("/public")
                .body(Body::empty())
                .expect("build request");
            let response = scaffold
                .router
                .clone()
                .oneshot(request)
                .await
                .expect("request");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });
}

criterion_group!(benches, request_path);
criterion_main!(benches);
