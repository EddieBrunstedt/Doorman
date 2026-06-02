//! Shared test scaffolding.
//!
//! [`TestApp`] spins up an axum app backed by in-memory storage and a real
//! `bauth-axum` router, exposes a base URL for `reqwest`, and tears the
//! server down on drop. [`login`] mints a session directly via the
//! in-process `SessionManager` so the session-management tests can grab a
//! bearer token without driving the full passkey ceremony — tests that
//! specifically cover the signup flow drive it end-to-end themselves via
//! [`SignupClient`].

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::BauthAxum;
use bauth_axum::SessionCache;
use bauth_axum::config::CookieConfig;
use bauth_axum::dto::{
    AuthResponse, PasskeyChallenge, PasskeyDto, RegistrationFinishRequest, SignupConsumeRequest,
    SignupRequest, UserDto,
};
use bauth_axum::extractors::AuthSession;
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::passkey::PasskeyConfig;
use bauth_core::recovery::{RecoveryConfig, RecoveryRateLimits};
use bauth_core::session::{SessionContext, SessionManager};
use bauth_core::signup::{SignupConfig, SignupRateLimits};
use bauth_core::storage::{PasskeyCredentialStore, Storage, User, UserId, UserStore};
use bauth_core::verification::TOKEN_PLACEHOLDER;
use bauth_test_support::CapturingEmailSender;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url as ServerUrl;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::CreationChallengeResponse;

pub const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
pub const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";

pub struct TestApp {
    pub addr: SocketAddr,
    pub email: Arc<CapturingEmailSender>,
    pub rp_origin: ServerUrl,
    pub passkey_credentials: Arc<InMemoryPasskeyCredentialStore>,
    /// The session-resolution cache the running layer reads from, and the
    /// one the `session_manager` below evicts on revoke. Surfaced so the
    /// cache-invalidation tests can observe eviction directly.
    pub cache: SessionCache,
    /// The live, invalidation-hooked `SessionManager` the app runs on
    /// (cloned out of the built `BauthAxum`). `login` mints sessions
    /// through it, and revoking through it evicts [`Self::cache`].
    pub session_manager: SessionManager,
    user_store: Arc<InMemoryUserStore>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestApp {
    /// Start an app wired through [`BauthAxum::builder`] with the in-memory
    /// stores and the passkey + signup configs needed for full HTTP coverage.
    pub async fn start(host_routes: Router, secure_cookies: bool) -> Self {
        Self::start_with(host_routes, secure_cookies, |b| b).await
    }

    /// Start an app, letting the caller tweak the `BauthBuilder`
    /// (e.g. to set an `external_origin` for CSRF coverage).
    pub async fn start_with<F>(host_routes: Router, secure_cookies: bool, customise: F) -> Self
    where
        F: FnOnce(bauth_axum::BauthBuilder) -> bauth_axum::BauthBuilder,
    {
        let email = Arc::new(CapturingEmailSender::new());
        let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let token_store: Arc<InMemoryVerificationTokenStore> =
            Arc::new(InMemoryVerificationTokenStore::new());
        let passkey_credentials: Arc<InMemoryPasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::new());
        let passkey_challenges: Arc<InMemoryPasskeyChallengeStore> =
            Arc::new(InMemoryPasskeyChallengeStore::new());

        let rp_origin = ServerUrl::parse("http://localhost:8080").expect("rp origin");
        let storage = Storage {
            users: user_store.clone(),
            sessions: session_store.clone(),
            verification_tokens: token_store,
            passkey_credentials: passkey_credentials.clone(),
            passkey_challenges,
        };

        let builder = BauthAxum::builder(storage)
            .email(email.clone() as Arc<dyn EmailSender>)
            .passkey(PasskeyConfig::new(
                "localhost",
                rp_origin.clone(),
                "bauth tests",
            ))
            .signup(SignupConfig {
                url_template: SIGNUP_URL.to_string(),
                rate_limits: SignupRateLimits::disabled(),
                ..SignupConfig::default()
            })
            .recovery(RecoveryConfig {
                url_template: RECOVERY_URL.to_string(),
                rate_limits: RecoveryRateLimits::disabled(),
                ..RecoveryConfig::default()
            })
            .cookie(CookieConfig {
                secure: secure_cookies,
                ..CookieConfig::default()
            })
            .silence_warnings();

        let auth = customise(builder).build().expect("auth built");

        // `login` mints sessions directly through the same live,
        // invalidation-hooked `SessionManager` the app runs on, so a
        // revoke routed through it evicts the cache the layer reads. The
        // high-level builder wires the cache invalidator onto this manager,
        // so the cache-invalidation tests can drive it via `session_manager`.
        let session_manager = auth.state().session_manager().clone();
        let cache = auth.cache().clone();

        let passkey_credentials_dyn: Arc<dyn PasskeyCredentialStore> = passkey_credentials.clone();
        let app = Router::new()
            .merge(auth.router())
            .route("/me", get(me_handler))
            .merge(host_routes)
            .layer(Extension(passkey_credentials_dyn))
            .layer(auth.session_layer());

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });

        TestApp {
            addr,
            email,
            rp_origin,
            passkey_credentials,
            cache,
            session_manager,
            user_store,
            handle,
            shutdown: tx,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// Provision a user and mint a session directly via the in-process
/// `SessionManager`. Useful for tests that exercise the session-management
/// surface and don't need to cover the signup ceremony itself.
pub async fn login(_client: &reqwest::Client, app: &TestApp, email: &str) -> AuthResponse {
    let email_normalized = email.trim().to_ascii_lowercase();

    let user = if let Some(existing) = app
        .user_store
        .find_user_by_email(&email_normalized)
        .await
        .expect("find user")
    {
        existing
    } else {
        let now = chrono::Utc::now();
        let user = User {
            id: UserId::new(),
            email: Some(email_normalized),
            email_verified_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        app.user_store
            .create_user(user.clone())
            .await
            .expect("create user");
        user
    };

    let issued = app
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session");
    AuthResponse::from_issued(user, issued, 0)
}

/// Helper that drives the three-step signup flow over real HTTP, using a
/// `SoftPasskey` to satisfy the WebAuthn ceremony. Returns the response
/// JSON from `/auth/signup/finish` (cookies are picked up by the supplied
/// `reqwest::Client` automatically when its cookie store is enabled).
pub struct SignupClient {
    inner: WebauthnAuthenticator<SoftPasskey>,
    rp_origin: AuthUrl,
}

impl SignupClient {
    pub fn new(app: &TestApp) -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            rp_origin: AuthUrl::parse(app.rp_origin.as_str()).expect("rp origin"),
        }
    }

    /// Drive request → consume → finish, returning the parsed
    /// [`AuthResponse`] from `/auth/signup/finish`.
    pub async fn signup(
        &mut self,
        client: &reqwest::Client,
        app: &TestApp,
        email: &str,
    ) -> AuthResponse {
        let request = client
            .post(app.url("/auth/signup/request"))
            .json(&SignupRequest {
                email: email.into(),
            })
            .send()
            .await
            .expect("signup request");
        assert_eq!(request.status(), StatusCode::NO_CONTENT);

        let sent = app.email.sent();
        let token = token_from_email(&sent.last().expect("signup email queued").body_text.clone());

        let consume = client
            .post(app.url("/auth/signup/consume"))
            .json(&SignupConsumeRequest { token })
            .send()
            .await
            .expect("signup consume");
        assert_eq!(consume.status(), StatusCode::OK);
        let challenge: PasskeyChallenge<CreationChallengeResponse> =
            consume.json().await.expect("consume body");

        // Relax the resident-key flags so SoftPasskey accepts the ceremony.
        // bauth's server still emitted resident=required earlier; we
        // verified that elsewhere.
        let mut options = challenge.options;
        let selection = options
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("authenticator selection present");
        selection.require_resident_key = false;
        selection.resident_key = None;

        let attestation = self
            .inner
            .do_registration(self.rp_origin.clone(), options)
            .expect("authenticator register");

        let finish = client
            .post(app.url("/auth/signup/finish"))
            .json(&RegistrationFinishRequest {
                challenge_id: challenge.challenge_id,
                response: attestation,
                name: Some("test device".into()),
            })
            .send()
            .await
            .expect("signup finish");
        assert_eq!(finish.status(), StatusCode::OK);
        finish.json().await.expect("finish body")
    }

    /// Register an additional passkey for the authenticated session. The
    /// caller is expected to use a fresh [`SignupClient`] (a separate
    /// `SoftPasskey`) so the new credential is distinct from any existing
    /// one. The returned [`PasskeyDto::credential_id`] is the URL-safe
    /// base64 id usable with `DELETE /auth/passkey/{id}`.
    pub async fn register_additional_passkey(
        &mut self,
        client: &reqwest::Client,
        app: &TestApp,
        bearer: &str,
    ) -> PasskeyDto {
        let start = client
            .post(app.url("/auth/passkey/register/start"))
            .bearer_auth(bearer)
            .send()
            .await
            .expect("register start");
        assert_eq!(start.status(), StatusCode::OK);
        let challenge: PasskeyChallenge<CreationChallengeResponse> =
            start.json().await.expect("start body");

        let mut options = challenge.options;
        let selection = options
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("authenticator selection present");
        selection.require_resident_key = false;
        selection.resident_key = None;

        let attestation = self
            .inner
            .do_registration(self.rp_origin.clone(), options)
            .expect("authenticator register");

        let finish = client
            .post(app.url("/auth/passkey/register/finish"))
            .bearer_auth(bearer)
            .json(&serde_json::json!({
                "challenge_id": challenge.challenge_id,
                "response": attestation,
                "name": "backup device",
            }))
            .send()
            .await
            .expect("register finish");
        assert_eq!(finish.status(), StatusCode::OK);
        finish.json().await.expect("register finish body")
    }
}

/// Locate the raw signup token in an email body whose URL was rendered
/// from [`SIGNUP_URL`].
pub fn token_from_email(body: &str) -> String {
    token_from_email_with(body, SIGNUP_URL)
}

/// Locate the raw token in an email body whose URL was rendered from the
/// given template (signup or recovery).
pub fn token_from_email_with(body: &str, template: &str) -> String {
    let prefix = template
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("token follows prefix")
        .to_string()
}

async fn me_handler(
    auth: AuthSession,
    Extension(passkey_credentials): Extension<Arc<dyn PasskeyCredentialStore>>,
) -> Response {
    let passkey_count = passkey_credentials
        .list_passkeys_for_user(auth.user.id)
        .await
        .map(|list| list.len())
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(UserDto::from_user(&auth.user, passkey_count)),
    )
        .into_response()
}
