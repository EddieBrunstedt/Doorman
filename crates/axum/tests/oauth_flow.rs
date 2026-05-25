//! End-to-end HTTP test for the OAuth callback flow.
//!
//! Uses a mock [`OAuthProvider`] so we exercise our state cookie + redirect
//! handling end-to-end without making real network calls. The mock returns
//! a fixed `ProviderUser` on every exchange so the assertions can focus on
//! the HTTP layer's behaviour: state cookie format, query-state validation,
//! session cookie issuance, and the `return_to` redirect target.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::http::StatusCode;
use bauth_axum::BauthAxum;
use bauth_axum::config::CookieConfig;
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::memory::{
    InMemoryOAuthIdentityStore, InMemoryOAuthStateStore, InMemorySessionStore, InMemoryUserStore,
};
use bauth_core::oauth::{
    AuthorizationRequest, ExchangeRequest, OAuthConfig, OAuthManager, OAuthProvider, ProviderError,
    ProviderUser,
};
use bauth_core::session::{SessionConfig, SessionManager};
use reqwest::redirect::Policy;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

struct MockProvider {
    user: ProviderUser,
    consent_url: Url,
}

#[async_trait]
impl OAuthProvider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    fn authorization_url(&self, request: AuthorizationRequest<'_>) -> Url {
        let mut url = self.consent_url.clone();
        url.query_pairs_mut()
            .append_pair("state", request.state)
            .append_pair("code_challenge", request.pkce_challenge)
            .append_pair("redirect_uri", request.redirect_uri);
        url
    }

    async fn exchange(&self, _request: ExchangeRequest<'_>) -> Result<ProviderUser, ProviderError> {
        Ok(self.user.clone())
    }
}

struct OAuthApp {
    addr: SocketAddr,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl OAuthApp {
    async fn start(provider_user: ProviderUser) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);

        let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let identity_store: Arc<InMemoryOAuthIdentityStore> =
            Arc::new(InMemoryOAuthIdentityStore::new());
        let state_store: Arc<InMemoryOAuthStateStore> = Arc::new(InMemoryOAuthStateStore::new());

        let session_manager = SessionManager::new(
            session_store,
            clock.clone(),
            audit.clone(),
            SessionConfig {
                lifetime: Duration::from_secs(60 * 60),
            },
        );

        let provider = Arc::new(MockProvider {
            user: provider_user,
            consent_url: Url::parse("https://idp.test/authorize").unwrap(),
        });

        let oauth = OAuthManager::new(
            vec![provider as Arc<dyn OAuthProvider>],
            user_store.clone(),
            identity_store,
            state_store,
            session_manager.clone(),
            clock,
            audit,
            OAuthConfig::default(),
        );

        // The external origin is what the OAuth manager should hand to
        // the provider as the registered callback URL. In a real app this
        // is the public hostname; in this test we use a placeholder
        // because the mock provider ignores the exchange entirely.
        let external_origin = Url::parse("https://app.test").unwrap();

        let auth = BauthAxum::builder()
            .session_manager(session_manager)
            .user_store(user_store)
            .oauth_manager(oauth)
            .external_origin(external_origin)
            .cookie_config(CookieConfig {
                secure: false,
                ..CookieConfig::default()
            })
            .build()
            .expect("auth built");

        let app = Router::new()
            .merge(auth.router())
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

        OAuthApp {
            addr,
            handle,
            shutdown: tx,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

fn provider_user() -> ProviderUser {
    ProviderUser {
        subject: "mock-subject-123".into(),
        email: Some("alice@example.com".into()),
        email_verified: true,
        display_name: Some("Alice".into()),
    }
}

#[tokio::test]
async fn start_sets_state_cookie_and_redirects_to_provider() {
    let app = OAuthApp::start(provider_user()).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let resp = client
        .get(app.url("/auth/oauth/mock/start?return_to=/dashboard"))
        .send()
        .await
        .expect("start");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap();
    assert!(location.starts_with("https://idp.test/authorize?"));
    let set_cookie = resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .unwrap();
    assert!(set_cookie.starts_with("bauth_oauth_state="));

    app.shutdown().await;
}

#[tokio::test]
async fn callback_with_matching_state_issues_session_and_redirects() {
    let app = OAuthApp::start(provider_user()).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .expect("client");

    // /start: capture the state cookie via the jar, capture the state
    // value from the provider URL the manager generated.
    let start = client
        .get(app.url("/auth/oauth/mock/start?return_to=/dashboard"))
        .send()
        .await
        .expect("start");
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let provider_url = start
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap()
        .to_owned();
    let parsed = Url::parse(&provider_url).expect("provider url");
    let state_param = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state param");

    // /callback: pass the same state echoed back as the provider would,
    // with any non-empty `code` (the mock provider ignores it).
    let callback = client
        .get(app.url(&format!(
            "/auth/oauth/mock/callback?code=mock_code&state={state_param}"
        )))
        .send()
        .await
        .expect("callback");
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let location = callback
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap();
    assert_eq!(location, "/dashboard");

    // The response should have set the session cookie and cleared the
    // OAuth state cookie.
    let set_cookies: Vec<String> = callback
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(set_cookies.iter().any(|c| c.starts_with("bauth_session=")));
    assert!(
        set_cookies
            .iter()
            .any(|c| c.starts_with("bauth_oauth_state=") && c.contains("Max-Age=0"))
    );

    app.shutdown().await;
}

#[tokio::test]
async fn callback_with_mismatched_state_redirects_with_error() {
    let app = OAuthApp::start(provider_user()).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .expect("client");

    client
        .get(app.url("/auth/oauth/mock/start?return_to=/dashboard"))
        .send()
        .await
        .expect("start");

    let callback = client
        .get(app.url("/auth/oauth/mock/callback?code=mock_code&state=tampered"))
        .send()
        .await
        .expect("callback");
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let location = callback
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap();
    assert!(location.starts_with("/dashboard?bauth_error=invalid_oauth_state"));

    app.shutdown().await;
}

#[tokio::test]
async fn callback_without_state_cookie_redirects_to_root() {
    let app = OAuthApp::start(provider_user()).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let callback = client
        .get(app.url("/auth/oauth/mock/callback?code=mock_code&state=anything"))
        .send()
        .await
        .expect("callback");
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let location = callback
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap();
    assert_eq!(location, "/?bauth_error=invalid_oauth_state");

    app.shutdown().await;
}

#[tokio::test]
async fn start_with_open_redirect_return_to_falls_back_to_root() {
    let app = OAuthApp::start(provider_user()).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .expect("client");

    let start = client
        .get(app.url("/auth/oauth/mock/start?return_to=https://evil.example.com/"))
        .send()
        .await
        .expect("start");
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let provider_url = start
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap()
        .to_owned();
    let parsed = Url::parse(&provider_url).expect("provider url");
    let state_param = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state param");

    let callback = client
        .get(app.url(&format!(
            "/auth/oauth/mock/callback?code=mock_code&state={state_param}"
        )))
        .send()
        .await
        .expect("callback");
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let location = callback
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("location")
        .to_str()
        .unwrap();
    assert_eq!(location, "/", "must not honour cross-origin return_to");

    app.shutdown().await;
}
