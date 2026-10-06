#![allow(
    dead_code,
    reason = "each test binary compiles this module, and not every binary uses every helper"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_axum::dto::{
    AuthResponse, PasskeyChallenge, PasskeyDto, Reauthentication, RegistrationFinishRequest,
    SignupConsumeRequest, SignupRequest, UserDto,
};
use doorman_axum::extractors::AuthSession;
use doorman_axum::{AuthService, AuthServiceBuilder};
use doorman_core::account::AccountConfig;
use doorman_core::assembly::{AuthCore, AuthCoreBuilder};
use doorman_core::audit::NoopAuditSink;
use doorman_core::cache::{SessionCacheConfig, SessionCachePolicy};
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::email::EmailSender;
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::operator::OperatorManager;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{RecoveryConfig, RecoveryRateLimits};
use doorman_core::session::{SessionContext, SessionManager};
use doorman_core::signup::{SignupConfig, SignupRateLimits};
use doorman_core::storage::{
    AccountStatus, PasskeyCredentialStore, Storage, User, UserId, UserStore,
};
use doorman_core::verification::normalize_email;
use doorman_test_support::CapturingEmailSender;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url as ServerUrl;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_proto::AllowCredentials;

pub const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
pub const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
pub const ACCOUNT_URL: &str = "https://app.test/email-change?token={token}";

pub struct TestApp {
    pub addr: SocketAddr,
    pub email: Arc<CapturingEmailSender>,
    pub rp_origin: ServerUrl,
    pub passkey_credentials: Arc<InMemoryPasskeyCredentialStore>,
    pub session_manager: SessionManager,
    pub operator: OperatorManager,
    user_store: Arc<InMemoryUserStore>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestApp {
    pub async fn start(host_routes: Router, secure_cookies: bool) -> Self {
        Self::start_with(host_routes, secure_cookies, |b| b).await
    }

    pub async fn start_with_clock(
        host_routes: Router,
        secure_cookies: bool,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::start_with(host_routes, secure_cookies, move |b| {
            b.clock(clock.clone())
                .limiter(Arc::new(InMemoryRateLimiter::new(clock.clone())))
        })
        .await
    }

    pub async fn start_with<F>(host_routes: Router, secure_cookies: bool, customise: F) -> Self
    where
        F: FnOnce(AuthCoreBuilder) -> AuthCoreBuilder,
    {
        Self::start_configured(host_routes, secure_cookies, customise, |b| b).await
    }

    pub async fn start_configured<C, H>(
        host_routes: Router,
        secure_cookies: bool,
        customise_core: C,
        customise_http: H,
    ) -> Self
    where
        C: FnOnce(AuthCoreBuilder) -> AuthCoreBuilder,
        H: FnOnce(AuthServiceBuilder) -> AuthServiceBuilder,
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

        let core_builder = AuthCore::builder(storage)
            .email(email.clone() as Arc<dyn EmailSender>)
            .passkey(PasskeyConfig::new(
                "localhost",
                rp_origin.clone(),
                "doorman tests",
            ))
            .audit(Arc::new(NoopAuditSink))
            .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
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
            .account(AccountConfig {
                url_template: ACCOUNT_URL.to_string(),
                ..AccountConfig::default()
            })
            .session_cache(SessionCachePolicy::users_only(SessionCacheConfig::default()))
            .reauthentication(ReauthPolicy::disabled());
        let core = customise_core(core_builder)
            .build()
            .expect("auth core built");

        let builder = AuthService::builder(core)
            .csrf(CsrfConfig::disabled())
            .cookie(CookieConfig {
                secure: secure_cookies,
                ..CookieConfig::default()
            });
        let auth = customise_http(builder).build().expect("auth built");

        let session_manager = auth.state().session_manager().clone();
        let operator = auth.state().operator().clone();

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
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
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
            session_manager,
            operator,
            user_store,
            handle,
            shutdown: tx,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn set_user_status(&self, user_id: UserId, status: AccountStatus) {
        self.user_store
            .set_user_status(user_id, status, chrono::Utc::now())
            .await
            .expect("update user status");
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

pub async fn login(_client: &reqwest::Client, app: &TestApp, email: &str) -> AuthResponse {
    let email_normalized = normalize_email(email);

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
            status: AccountStatus::Active,
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
                invite_token: None,
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

    pub async fn reauth(
        &mut self,
        client: &reqwest::Client,
        app: &TestApp,
        bearer: &str,
    ) -> Reauthentication {
        let start = client
            .post(app.url("/auth/reauth/start"))
            .bearer_auth(bearer)
            .send()
            .await
            .expect("reauth start");
        assert_eq!(start.status(), StatusCode::OK);
        let challenge: PasskeyChallenge<RequestChallengeResponse> =
            start.json().await.expect("reauth start body");
        let assertion = self
            .inner
            .do_authentication(self.rp_origin.clone(), challenge.options)
            .expect("authenticator scoped auth");
        Reauthentication {
            challenge_id: challenge.challenge_id,
            assertion,
        }
    }
}

#[derive(Clone)]
struct ResidentCredential {
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
}

pub struct ResidentHttpAuthenticator {
    inner: WebauthnAuthenticator<SoftPasskey>,
    rp_origin: AuthUrl,
    resident_credentials: Vec<ResidentCredential>,
}

impl ResidentHttpAuthenticator {
    pub fn new(rp_origin: &ServerUrl) -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            rp_origin: AuthUrl::parse(rp_origin.as_str()).expect("rp origin"),
            resident_credentials: Vec::new(),
        }
    }

    pub fn do_registration(
        &mut self,
        challenge: CreationChallengeResponse,
    ) -> RegisterPublicKeyCredential {
        let user_handle = challenge.public_key.user.id.as_ref().to_vec();
        let mut compatible = challenge;
        let selection = compatible
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("authenticator selection present");
        selection.require_resident_key = false;
        selection.resident_key = None;

        let response = self
            .inner
            .do_registration(self.rp_origin.clone(), compatible)
            .expect("authenticator register");
        self.resident_credentials.push(ResidentCredential {
            credential_id: response.raw_id.as_ref().to_vec(),
            user_handle,
        });
        response
    }

    pub fn do_authentication(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
    ) -> PublicKeyCredential {
        let resident = self
            .resident_credentials
            .iter()
            .find(|credential| credential.credential_id == credential_id)
            .cloned()
            .expect("credential is resident on test authenticator");

        let mut compatible = challenge;
        compatible.public_key.allow_credentials = vec![AllowCredentials {
            type_: "public-key".to_string(),
            id: resident.credential_id.clone().into(),
            transports: None,
        }];
        let mut assertion = self
            .inner
            .do_authentication(self.rp_origin.clone(), compatible)
            .expect("authenticator auth");
        assertion.response.user_handle = Some(resident.user_handle.into());
        assertion
    }
}

pub fn token_from_email(body: &str) -> String {
    token_from_email_with(body, SIGNUP_URL)
}

pub fn token_from_email_with(body: &str, template: &str) -> String {
    doorman_test_support::token_from_email(body, template)
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
