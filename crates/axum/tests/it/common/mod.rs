use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::routing::get;
use doorman_axum::config::CookieConfig;
use doorman_axum::dto::{
    AuthResponse, DpopAuthResponse, PasskeyAuthenticateFinishRequest, PasskeyChallenge, PasskeyDto,
    PasskeyRegisterFinishRequest, Reauthentication, RecoveryRedeemRequest, RecoveryRequest,
    RegistrationFinishRequest, SessionDto, SignupRedeemRequest, SignupRequest, UserDto,
};
use doorman_axum::extractors::AuthUser;
use doorman_axum::{AuthService, AuthServiceBuilder, PurgeSchedule};
use doorman_core::assembly::{AuthCore, AuthCoreBuilder, AuthCoreRequired};
use doorman_core::audit::NoopAuditSink;
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::email::EmailSender;
use doorman_core::email_link::{LinkTemplate, LinkTemplates};
use doorman_core::memory::{InMemoryRateLimiter, InMemoryStorage};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::{RateLimiting, RateLimits};
use doorman_core::reauth::ReauthPolicy;
use doorman_core::session::{SessionConfig, SessionManager};
use doorman_core::storage::{Storage, UserId, UserStatus, UserStore};
use doorman_test_support::{CapturingEmailSender, dpop_origin, relying_party, token_from_email};
pub use doorman_test_support::{DpopClient, ResidentAuthenticator};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::ServiceExt;
use url::Url;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

pub const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
pub const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
pub const USER_URL: &str = "https://app.test/email-change?token={token}";
pub const RP_ORIGIN: &str = "http://localhost:8080";
pub const PEER: &str = "127.0.0.1";
pub const DPOP_ORIGIN: &str = "https://api.app.test";

// How a test client keeps its session: a browser page, or a DPoP client such as a native app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Browser,
    Dpop,
}

// A session as its client holds it: a browser's token comes from the cookie it was set, and a
// DPoP client's comes with the key it is bound to.
#[derive(Debug, Clone)]
pub struct TestSession {
    pub user: UserDto,
    pub session: SessionDto,
    pub token: String,
    pub client: Client,
    pub key: Option<Arc<DpopClient>>,
}

impl TestSession {
    pub fn key(&self) -> &Arc<DpopClient> {
        self.key.as_ref().expect("a DPoP session's key")
    }
}

pub fn link_templates() -> LinkTemplates {
    LinkTemplates {
        signup: LinkTemplate::parse(SIGNUP_URL).expect("signup link template"),
        recovery: LinkTemplate::parse(RECOVERY_URL).expect("recovery link template"),
        email_change: LinkTemplate::parse(USER_URL).expect("email change link template"),
    }
}

pub fn core_required(storage: Storage, email: Arc<dyn EmailSender>) -> AuthCoreRequired {
    AuthCoreRequired {
        storage,
        email_sender: email,
        audit_sink: Arc::new(NoopAuditSink),
        passkey: PasskeyConfig::new(relying_party(rp_origin())),
        reauthentication: ReauthPolicy::disabled(),
        rate_limiting: RateLimiting::Disabled,
        links: link_templates(),
    }
}

pub fn core_builder(storage: Storage, email: Arc<dyn EmailSender>) -> AuthCoreBuilder {
    AuthCore::builder(core_required(storage, email))
}

// Lets the harness's DPoP clients start sessions; a test that sets its own config starts from it.
pub fn harness_core(required: AuthCoreRequired) -> AuthCoreBuilder {
    AuthCore::builder(required).session(session_config())
}

pub fn harness_rate_limiting(clock: Arc<dyn Clock>) -> RateLimiting {
    RateLimiting::Enforced {
        limiter: Arc::new(InMemoryRateLimiter::new(clock)),
        limits: RateLimits {
            signup_request_per_ip: None,
            signup_request_per_email: None,
            recovery_request_per_ip: None,
            recovery_request_per_email: None,
            recovery_request_per_email_daily: None,
            ..RateLimits::default()
        },
    }
}

pub fn session_config() -> SessionConfig {
    SessionConfig {
        dpop_origin: Some(dpop_origin(DPOP_ORIGIN)),
        ..SessionConfig::default()
    }
}

pub struct TestApp {
    router: Router,
    prefix: &'static str,
    // DPoP clients sign their proofs by the time the core keeps.
    clock: Arc<dyn Clock>,
    default_headers: HeaderMap,
    pub email: Arc<CapturingEmailSender>,
    pub sessions: SessionManager,
    users: Arc<dyn UserStore>,
    authenticators: Mutex<HashMap<String, ResidentAuthenticator>>,
}

impl TestApp {
    pub fn new() -> Self {
        Self::with(harness_core, |b| b)
    }

    pub fn with(
        customise_core: impl FnOnce(AuthCoreRequired) -> AuthCoreBuilder,
        customise_http: impl FnOnce(AuthServiceBuilder) -> AuthServiceBuilder,
    ) -> Self {
        Self::with_storage(
            InMemoryStorage::new().all_stores(),
            customise_core,
            customise_http,
        )
    }

    pub fn with_storage(
        storage: Storage,
        customise_core: impl FnOnce(AuthCoreRequired) -> AuthCoreBuilder,
        customise_http: impl FnOnce(AuthServiceBuilder) -> AuthServiceBuilder,
    ) -> Self {
        Self::assemble(storage, customise_core, customise_http, |auth| {
            host_routes(auth).layer(auth.session_layer())
        })
    }

    pub fn without_host_layer(storage: Storage) -> Self {
        Self::assemble(storage, harness_core, |b| b, host_routes)
    }

    // Every call's path is prefixed, as a client of a host that nests doorman sees it.
    pub fn nested_under(prefix: &'static str) -> Self {
        let mut app = Self::assemble(
            InMemoryStorage::new().all_stores(),
            harness_core,
            |b| b,
            |auth| Router::new().nest(prefix, host_routes(auth).layer(auth.session_layer())),
        );
        app.prefix = prefix;
        app
    }

    fn assemble(
        storage: Storage,
        customise_core: impl FnOnce(AuthCoreRequired) -> AuthCoreBuilder,
        customise_http: impl FnOnce(AuthServiceBuilder) -> AuthServiceBuilder,
        compose: impl FnOnce(&AuthService) -> Router,
    ) -> Self {
        let email = Arc::new(CapturingEmailSender::new());
        let users = storage.records.users.clone();
        let required = AuthCoreRequired {
            rate_limiting: harness_rate_limiting(Arc::new(SystemClock)),
            ..core_required(storage, email.clone() as Arc<dyn EmailSender>)
        };
        let core = customise_core(required).build();

        let http = AuthService::builder(core, PurgeSchedule::external()).cookie(insecure_cookie());
        let auth = customise_http(http).build().expect("auth built");
        let sessions = auth.state().sessions().clone();

        let router = compose(&auth);

        TestApp {
            router,
            prefix: "",
            clock: Arc::new(SystemClock),
            default_headers: HeaderMap::new(),
            email,
            sessions,
            users,
            authenticators: Mutex::default(),
        }
    }

    pub fn proofs_signed_by(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn default_header(mut self, name: &'static str, value: &str) -> Self {
        self.default_headers
            .insert(name, HeaderValue::from_str(value).expect("header value"));
        self
    }

    pub async fn serve(&self) -> Server {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let router = self.router.clone();
        let (shutdown, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .expect("serve");
        });
        Server {
            addr,
            handle,
            shutdown,
        }
    }

    pub fn get(&self, path: &str) -> Call<'_> {
        self.call(Method::GET, path)
    }

    pub fn post(&self, path: &str) -> Call<'_> {
        self.call(Method::POST, path)
    }

    pub fn patch(&self, path: &str) -> Call<'_> {
        self.call(Method::PATCH, path)
    }

    pub fn delete(&self, path: &str) -> Call<'_> {
        self.call(Method::DELETE, path)
    }

    pub fn call(&self, method: Method, path: &str) -> Call<'_> {
        let path = format!("{}{path}", self.prefix);
        let mut request = Request::builder().method(method.clone()).uri(&path);
        for (name, value) in &self.default_headers {
            request = request.header(name, value);
        }
        Call {
            app: self,
            request,
            body: Body::empty(),
            method,
            path: path.split('?').next().unwrap_or(&path).to_owned(),
            signer: None,
        }
    }

    pub async fn session_for(&self, email: &str) -> TestSession {
        self.session_as(Client::Dpop, email).await
    }

    pub async fn session_as(&self, client: Client, email: &str) -> TestSession {
        let stored = self
            .authenticators
            .lock()
            .expect("authenticators lock")
            .remove(email);
        let (session, authenticator) = match stored {
            Some(mut authenticator) => (
                self.log_in_again_as(client, &mut authenticator).await,
                authenticator,
            ),
            None => self.signup_as(client, email).await,
        };
        self.authenticators
            .lock()
            .expect("authenticators lock")
            .insert(email.to_owned(), authenticator);
        session
    }

    pub async fn log_in_again(&self, authenticator: &mut ResidentAuthenticator) -> TestSession {
        self.log_in_again_as(Client::Dpop, authenticator).await
    }

    pub async fn log_in_again_as(
        &self,
        client: Client,
        authenticator: &mut ResidentAuthenticator,
    ) -> TestSession {
        let credential_id = authenticator
            .credential_ids()
            .into_iter()
            .next()
            .expect("the authenticator holds a passkey");
        let reply = self.log_in_as(client, authenticator, &credential_id).await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.session(client)
    }

    pub async fn set_user_status(&self, user_id: UserId, status: UserStatus) {
        self.users
            .set_user_status(user_id, status, chrono::Utc::now())
            .await
            .expect("update user status");
    }

    pub fn last_link(&self, template: &str) -> String {
        let prefix = template.split('{').next().expect("template prefix");
        let email = self
            .email
            .sent()
            .into_iter()
            .rev()
            .find(|e| e.body_text.contains(prefix))
            .expect("an email carrying the link was sent");
        token_from_email(&email.body_text, template)
    }

    pub async fn signup(&self, email: &str) -> (TestSession, ResidentAuthenticator) {
        self.signup_as(Client::Dpop, email).await
    }

    pub async fn signup_as(
        &self,
        client: Client,
        email: &str,
    ) -> (TestSession, ResidentAuthenticator) {
        let mut authenticator = ResidentAuthenticator::new(&rp_origin());
        let finish = self.finish_signup(client, email, &mut authenticator).await;
        assert_eq!(finish.status, StatusCode::OK);
        (finish.session(client), authenticator)
    }

    pub async fn finish_signup(
        &self,
        client: Client,
        email: &str,
        authenticator: &mut ResidentAuthenticator,
    ) -> Reply {
        self.finish_signup_asking(client, client == Client::Dpop, email, authenticator)
            .await
    }

    pub async fn finish_signup_asking(
        &self,
        client: Client,
        asks_dpop: bool,
        email: &str,
        authenticator: &mut ResidentAuthenticator,
    ) -> Reply {
        let request = self
            .post("/auth/signup/request")
            .sent_by(client)
            .json(&SignupRequest {
                email: email.into(),
                invite_token: None,
            })
            .send()
            .await;
        assert_eq!(request.status, StatusCode::NO_CONTENT);

        let redeem = self
            .post("/auth/signup/redeem")
            .sent_by(client)
            .json(&SignupRedeemRequest {
                token: self.last_link(SIGNUP_URL),
            })
            .send()
            .await;
        assert_eq!(redeem.status, StatusCode::OK);
        let challenge: PasskeyChallenge<CreationChallengeResponse> = redeem.json();

        self.post("/auth/signup/finish")
            .sent_by(client)
            .asking_dpop(asks_dpop)
            .json(&RegistrationFinishRequest {
                challenge_id: challenge.challenge_id,
                response: authenticator.do_registration(challenge.options),
                name: Some("first device".into()),
            })
            .send()
            .await
    }

    pub async fn recover(
        &self,
        email: &str,
        authenticator: &mut ResidentAuthenticator,
    ) -> TestSession {
        let finish = self
            .finish_recovery(Client::Dpop, email, authenticator)
            .await;
        assert_eq!(finish.status, StatusCode::OK);
        finish.session(Client::Dpop)
    }

    pub async fn finish_recovery(
        &self,
        client: Client,
        email: &str,
        authenticator: &mut ResidentAuthenticator,
    ) -> Reply {
        self.finish_recovery_asking(client, client == Client::Dpop, email, authenticator)
            .await
    }

    pub async fn finish_recovery_asking(
        &self,
        client: Client,
        asks_dpop: bool,
        email: &str,
        authenticator: &mut ResidentAuthenticator,
    ) -> Reply {
        let request = self
            .post("/auth/recovery/request")
            .sent_by(client)
            .json(&RecoveryRequest {
                email: email.into(),
            })
            .send()
            .await;
        assert_eq!(request.status, StatusCode::NO_CONTENT);

        let redeem = self
            .post("/auth/recovery/redeem")
            .sent_by(client)
            .json(&RecoveryRedeemRequest {
                token: self.last_link(RECOVERY_URL),
            })
            .send()
            .await;
        assert_eq!(redeem.status, StatusCode::OK);
        let challenge: PasskeyChallenge<CreationChallengeResponse> = redeem.json();

        self.post("/auth/recovery/finish")
            .sent_by(client)
            .asking_dpop(asks_dpop)
            .json(&RegistrationFinishRequest {
                challenge_id: challenge.challenge_id,
                response: authenticator.do_registration(challenge.options),
                name: Some("recovery device".into()),
            })
            .send()
            .await
    }

    pub async fn register_passkey(
        &self,
        authenticator: &mut ResidentAuthenticator,
        session: &TestSession,
    ) -> PasskeyDto {
        let start = self
            .post("/auth/passkey/register/start")
            .session(session)
            .send()
            .await;
        assert_eq!(start.status, StatusCode::OK);
        let challenge: PasskeyChallenge<CreationChallengeResponse> = start.json();

        let finish = self
            .post("/auth/passkey/register/finish")
            .session(session)
            .json(&PasskeyRegisterFinishRequest {
                challenge_id: challenge.challenge_id,
                response: authenticator.do_registration(challenge.options),
                name: Some("backup device".into()),
            })
            .send()
            .await;
        assert_eq!(finish.status, StatusCode::OK);
        finish.json()
    }

    pub async fn log_in(
        &self,
        authenticator: &mut ResidentAuthenticator,
        credential_id: &[u8],
    ) -> Reply {
        self.log_in_as(Client::Dpop, authenticator, credential_id)
            .await
    }

    pub async fn log_in_as(
        &self,
        client: Client,
        authenticator: &mut ResidentAuthenticator,
        credential_id: &[u8],
    ) -> Reply {
        self.log_in_asking(client, client == Client::Dpop, authenticator, credential_id)
            .await
    }

    pub async fn log_in_asking(
        &self,
        client: Client,
        asks_dpop: bool,
        authenticator: &mut ResidentAuthenticator,
        credential_id: &[u8],
    ) -> Reply {
        let start = self
            .post("/auth/passkey/authenticate/start")
            .sent_by(client)
            .send()
            .await;
        assert_eq!(start.status, StatusCode::OK);
        let challenge: PasskeyChallenge<RequestChallengeResponse> = start.json();
        self.post("/auth/passkey/authenticate/finish")
            .sent_by(client)
            .asking_dpop(asks_dpop)
            .json(&PasskeyAuthenticateFinishRequest {
                challenge_id: challenge.challenge_id,
                response: authenticator.do_authentication(challenge.options, credential_id),
            })
            .send()
            .await
    }

    pub async fn reauth(
        &self,
        authenticator: &mut ResidentAuthenticator,
        session: &TestSession,
    ) -> Reauthentication {
        let start = self
            .post("/auth/reauth/start")
            .session(session)
            .send()
            .await;
        assert_eq!(start.status, StatusCode::OK);
        let challenge: PasskeyChallenge<RequestChallengeResponse> = start.json();
        Reauthentication {
            challenge_id: challenge.challenge_id,
            assertion: authenticator.do_scoped_authentication(challenge.options),
        }
    }

    pub async fn is_authenticated(&self, session: &TestSession) -> bool {
        let me = self.get("/me").session(session).send().await;
        match me.status {
            StatusCode::OK => true,
            StatusCode::UNAUTHORIZED => false,
            other => panic!("unexpected /me status {other}"),
        }
    }
}

// The tests' origin is plain http.
pub fn insecure_cookie() -> CookieConfig {
    CookieConfig::builder(CookieConfig::DEFAULT_NAME)
        .insecure()
        .build()
        .expect("an unprefixed cookie may be insecure")
}

pub fn rp_origin() -> Url {
    RP_ORIGIN.parse().expect("rp origin")
}

pub struct Call<'a> {
    app: &'a TestApp,
    request: axum::http::request::Builder,
    body: Body,
    method: Method,
    path: String,
    signer: Option<Signer>,
}

// Signs the call's proof when it is sent, for the call's own method and path.
struct Signer {
    key: Arc<DpopClient>,
    token: Option<String>,
}

impl Call<'_> {
    // Presents the token the way a DPoP client does, with a fresh proof from the key.
    pub fn dpop(self, key: &Arc<DpopClient>, token: &str) -> Self {
        self.header("authorization", &format!("DPoP {token}"))
            .signed_by(key, Some(token))
    }

    pub fn signed_by(mut self, key: &Arc<DpopClient>, token: Option<&str>) -> Self {
        self.signer = Some(Signer {
            key: key.clone(),
            token: token.map(str::to_owned),
        });
        self
    }

    // A DPoP client asks for a DPoP session by proving a key of its own as it finishes.
    pub fn asking_dpop(self, asks: bool) -> Self {
        if asks {
            self.signed_by(&Arc::new(DpopClient::new(DPOP_ORIGIN)), None)
        } else {
            self
        }
    }

    // A browser sends the session cookie from the application's own page with this header.
    pub fn cookie(self, token: &str) -> Self {
        self.header(COOKIE.as_str(), &format!("doorman_session={token}"))
            .sent_from_page()
    }

    pub fn sent_from_page(self) -> Self {
        self.header("sec-fetch-site", "same-origin")
    }

    pub fn sent_by(self, client: Client) -> Self {
        match client {
            Client::Browser => self.sent_from_page(),
            Client::Dpop => self,
        }
    }

    pub fn session(self, session: &TestSession) -> Self {
        match session.client {
            Client::Browser => self.cookie(&session.token),
            Client::Dpop => self.dpop(session.key(), &session.token),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.request = self.request.header(
            HeaderName::try_from(name).expect("header name"),
            HeaderValue::try_from(value).expect("header value"),
        );
        self
    }

    pub fn json(mut self, body: &impl Serialize) -> Self {
        self.request = self.request.header(CONTENT_TYPE, "application/json");
        self.body = Body::from(serde_json::to_vec(body).expect("json body"));
        self
    }

    pub async fn send(self) -> Reply {
        let mut builder = self.request;
        if let Some(signer) = &self.signer {
            let proof = signer.key.proof(
                self.method.as_str(),
                &self.path,
                signer.token.as_deref(),
                self.app.clock.now(),
            );
            builder = builder.header("dpop", proof);
        }
        let mut request = builder.body(self.body).expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                PEER.parse::<Ipv4Addr>().expect("peer"),
                40000,
            ))));
        let response = self
            .app
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("infallible router");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        Reply {
            status,
            headers,
            body,
            key: self.signer.map(|signer| signer.key),
        }
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    body: Bytes,
    key: Option<Arc<DpopClient>>,
}

impl Reply {
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "{} body is not the expected JSON ({e}): {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    // Each transport's token travels only its own way, so the reply is checked for the other.
    pub fn session(&self, client: Client) -> TestSession {
        match client {
            Client::Browser => {
                let body: serde_json::Value = self.json();
                assert!(
                    body.get("token").is_none(),
                    "a cookie session's token reached the body: {body}"
                );
                let auth: AuthResponse = self.json();
                TestSession {
                    user: auth.user,
                    session: auth.session,
                    token: self.session_cookie().expect("the session cookie is set"),
                    client,
                    key: None,
                }
            }
            Client::Dpop => {
                assert!(
                    self.set_cookie().is_none(),
                    "a DPoP session set a cookie: {:?}",
                    self.headers
                );
                let auth: DpopAuthResponse = self.json();
                TestSession {
                    user: auth.user,
                    session: auth.session,
                    token: auth.token,
                    client,
                    key: self.key.clone(),
                }
            }
        }
    }

    pub fn session_cookie(&self) -> Option<String> {
        let cookie = self.set_cookie()?;
        let value = cookie.strip_prefix("doorman_session=")?.split(';').next()?;
        (!value.is_empty()).then(|| value.to_owned())
    }

    pub fn error_code(&self) -> String {
        let body: serde_json::Value = self.json();
        body["error"]["code"]
            .as_str()
            .expect("error code")
            .to_owned()
    }

    // The browser keeps whichever session cookie comes last, so doorman sends at most one.
    pub fn set_cookie(&self) -> Option<&str> {
        let mut cookies = self.headers.get_all(SET_COOKIE).iter();
        let cookie = cookies.next()?;
        assert!(
            cookies.next().is_none(),
            "more than one Set-Cookie: {:?}",
            self.headers
        );
        Some(cookie.to_str().expect("ascii cookie"))
    }
}

pub struct Server {
    addr: SocketAddr,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

fn host_routes(auth: &AuthService) -> Router {
    Router::new().merge(auth.router()).route("/me", get(me))
}

async fn me(AuthUser(user): AuthUser) -> String {
    user.email.unwrap_or_default()
}
