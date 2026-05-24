use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bauth_core::audit::{AuditEventKind, AuditSink, AuthMethod, CredentialKind};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::error::Error;
use bauth_core::memory::{
    InMemoryAuditSink, InMemoryOAuthIdentityStore, InMemoryOAuthStateStore, InMemorySessionStore,
    InMemoryUserStore,
};
use bauth_core::oauth::provider::{
    AuthorizationRequest, ExchangeRequest, OAuthProvider, ProviderError, ProviderUser,
};
use bauth_core::oauth::{OAuthConfig, OAuthManager};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{
    OAuthIdentityStore, OAuthStateId, OAuthStateStore, SessionStore, User, UserId, UserStore,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use url::Url;

/// Test double for an OAuth provider. Builds plausible authorization URLs
/// without hitting the network, and returns canned [`ProviderUser`] data
/// from a script of pre-loaded responses keyed by authorization code.
struct MockProvider {
    name: String,
    auth_endpoint: String,
    responses: Mutex<Vec<(String, Result<ProviderUser, ProviderError>)>>,
    exchanges: Mutex<Vec<ExchangeCall>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExchangeCall {
    code: String,
    pkce_verifier: String,
    redirect_uri: String,
}

impl MockProvider {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            auth_endpoint: format!("https://mock.test/{name}/authorize"),
            responses: Mutex::new(Vec::new()),
            exchanges: Mutex::new(Vec::new()),
        }
    }

    fn expect(&self, code: &str, user: ProviderUser) {
        self.responses
            .lock()
            .unwrap()
            .push((code.to_string(), Ok(user)));
    }

    fn expect_error(&self, code: &str, err: ProviderError) {
        self.responses
            .lock()
            .unwrap()
            .push((code.to_string(), Err(err)));
    }

    fn exchanges(&self) -> Vec<ExchangeCall> {
        self.exchanges.lock().unwrap().clone()
    }
}

#[async_trait]
impl OAuthProvider for MockProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorization_url(&self, request: AuthorizationRequest<'_>) -> Url {
        let mut url = Url::parse(&self.auth_endpoint).unwrap();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("state", request.state);
            q.append_pair("code_challenge", request.pkce_challenge);
            q.append_pair("redirect_uri", request.redirect_uri);
        }
        url
    }

    async fn exchange(&self, request: ExchangeRequest<'_>) -> Result<ProviderUser, ProviderError> {
        self.exchanges.lock().unwrap().push(ExchangeCall {
            code: request.code.to_string(),
            pkce_verifier: request.pkce_verifier.to_string(),
            redirect_uri: request.redirect_uri.to_string(),
        });
        let mut responses = self.responses.lock().unwrap();
        let idx = responses
            .iter()
            .position(|(c, _)| c == request.code)
            .unwrap_or_else(|| panic!("no canned response for code {}", request.code));
        responses.remove(idx).1
    }
}

struct Harness {
    manager: OAuthManager,
    users: Arc<InMemoryUserStore>,
    identities: Arc<InMemoryOAuthIdentityStore>,
    states: Arc<InMemoryOAuthStateStore>,
    sessions: Arc<InMemorySessionStore>,
    audit: Arc<InMemoryAuditSink>,
    clock: Arc<MockClock>,
    provider: Arc<MockProvider>,
}

const PROVIDER_NAME: &str = "mock";
const REDIRECT_URI: &str = "https://app.test/oauth/callback";

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn fresh(config: OAuthConfig) -> Harness {
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let identities: Arc<InMemoryOAuthIdentityStore> = Arc::new(InMemoryOAuthIdentityStore::new());
    let states: Arc<InMemoryOAuthStateStore> = Arc::new(InMemoryOAuthStateStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let provider: Arc<MockProvider> = Arc::new(MockProvider::new(PROVIDER_NAME));

    let session_manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );

    let manager = OAuthManager::new(
        vec![provider.clone() as Arc<dyn OAuthProvider>],
        users.clone() as Arc<dyn UserStore>,
        identities.clone() as Arc<dyn OAuthIdentityStore>,
        states.clone() as Arc<dyn OAuthStateStore>,
        session_manager,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        config,
    );

    Harness {
        manager,
        users,
        identities,
        states,
        sessions,
        audit,
        clock,
        provider,
    }
}

async fn make_user(h: &Harness, email: &str, verified: bool) -> User {
    let now = h.clock.now();
    let user = User {
        id: UserId::new(),
        email: Some(email.to_ascii_lowercase()),
        email_verified_at: verified.then_some(now),
        created_at: now,
        updated_at: now,
    };
    h.users.create_user(user.clone()).await.expect("create");
    user
}

fn kinds(events: &[bauth_core::audit::AuditEvent]) -> Vec<AuditEventKind> {
    events.iter().map(|e| e.kind.clone()).collect()
}

#[tokio::test]
async fn start_authorization_returns_state_and_persists_pending() {
    let h = fresh(OAuthConfig::default());
    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .expect("start");

    let state_param = started
        .authorize_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state in url");
    assert_eq!(state_param, started.state.0);
    assert_eq!(h.states.len(), 1);
}

#[tokio::test]
async fn start_authorization_rejects_unknown_provider() {
    let h = fresh(OAuthConfig::default());
    let err = h
        .manager
        .start_authorization("nope", REDIRECT_URI, None)
        .await
        .expect_err("unknown provider");
    assert!(matches!(err, Error::OAuthProviderNotConfigured(name) if name == "nope"));
}

#[tokio::test]
async fn finish_creates_new_user_when_no_match() {
    let h = fresh(OAuthConfig::default());
    h.provider.expect(
        "code-1",
        ProviderUser {
            subject: "sub-123".into(),
            email: Some("New@Example.com".into()),
            email_verified: true,
            display_name: Some("New User".into()),
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .expect("start");

    let outcome = h
        .manager
        .finish_authorization(
            &started.state,
            "code-1",
            SessionContext {
                ip: Some("1.1.1.1".into()),
                user_agent: Some("ua".into()),
            },
        )
        .await
        .expect("finish");

    assert!(outcome.is_new_user);
    assert!(outcome.link_was_added);
    assert_eq!(outcome.user.email.as_deref(), Some("new@example.com"));
    assert!(outcome.user.email_verified_at.is_some());
    assert_eq!(outcome.identity.provider, PROVIDER_NAME);
    assert_eq!(outcome.identity.subject, "sub-123");
    assert_eq!(outcome.identity.user_id, outcome.user.id);
    assert_eq!(outcome.session.session.user_id, outcome.user.id);
    assert_eq!(h.sessions.len(), 1);
    assert_eq!(h.identities.len(), 1);
    assert!(h.states.is_empty(), "state consumed");

    let exchange = h.provider.exchanges();
    assert_eq!(exchange.len(), 1);
    assert_eq!(exchange[0].code, "code-1");
    assert_eq!(exchange[0].redirect_uri, REDIRECT_URI);

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::CredentialAdded {
            credential_kind: CredentialKind::OAuth,
            ..
        }
    )));
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::LoginSucceeded {
            method: AuthMethod::OAuth,
            ..
        }
    )));
}

#[tokio::test]
async fn finish_logs_in_existing_identity_without_creating_user() {
    let h = fresh(OAuthConfig::default());
    h.provider.expect(
        "code-1",
        ProviderUser {
            subject: "sub-1".into(),
            email: Some("u@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );
    h.provider.expect(
        "code-2",
        ProviderUser {
            subject: "sub-1".into(),
            email: Some("u@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started_1 = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let first = h
        .manager
        .finish_authorization(&started_1.state, "code-1", SessionContext::default())
        .await
        .expect("first finish");

    let started_2 = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let second = h
        .manager
        .finish_authorization(&started_2.state, "code-2", SessionContext::default())
        .await
        .expect("second finish");

    assert!(!second.is_new_user);
    assert!(!second.link_was_added);
    assert_eq!(second.user.id, first.user.id);
    assert_eq!(h.identities.len(), 1, "no duplicate identity");
    assert_eq!(h.sessions.len(), 2, "second login creates a new session");
}

#[tokio::test]
async fn finish_links_to_existing_user_via_link_user_id() {
    let h = fresh(OAuthConfig::default());
    let user = make_user(&h, "owner@example.com", true).await;
    h.provider.expect(
        "code-link",
        ProviderUser {
            subject: "sub-link".into(),
            email: Some("different@example.com".into()),
            email_verified: false,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, Some(user.id))
        .await
        .unwrap();
    let outcome = h
        .manager
        .finish_authorization(&started.state, "code-link", SessionContext::default())
        .await
        .expect("finish");

    assert!(!outcome.is_new_user);
    assert!(outcome.link_was_added);
    assert_eq!(outcome.user.id, user.id);
    // Identity's email is the one the provider reported, not the user's.
    assert_eq!(
        outcome.identity.email.as_deref(),
        Some("different@example.com")
    );
}

#[tokio::test]
async fn finish_rejects_email_collision_without_linking_config() {
    let h = fresh(OAuthConfig::default());
    let _existing = make_user(&h, "taken@example.com", true).await;
    h.provider.expect(
        "code-collide",
        ProviderUser {
            subject: "sub-collide".into(),
            email: Some("taken@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let err = h
        .manager
        .finish_authorization(&started.state, "code-collide", SessionContext::default())
        .await
        .expect_err("email taken");
    assert!(matches!(err, Error::OAuthEmailTaken));
    assert!(h.identities.is_empty());
    assert_eq!(h.sessions.len(), 0);
}

#[tokio::test]
async fn finish_auto_links_when_email_linking_enabled_and_verified() {
    let h = fresh(OAuthConfig {
        allow_email_linking: true,
        ..OAuthConfig::default()
    });
    let user = make_user(&h, "owner@example.com", true).await;
    h.provider.expect(
        "code-auto",
        ProviderUser {
            subject: "sub-auto".into(),
            email: Some("owner@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let outcome = h
        .manager
        .finish_authorization(&started.state, "code-auto", SessionContext::default())
        .await
        .expect("finish");

    assert!(!outcome.is_new_user);
    assert!(outcome.link_was_added);
    assert_eq!(outcome.user.id, user.id);
}

#[tokio::test]
async fn finish_refuses_auto_link_when_provider_email_unverified() {
    let h = fresh(OAuthConfig {
        allow_email_linking: true,
        ..OAuthConfig::default()
    });
    let _user = make_user(&h, "owner@example.com", true).await;
    h.provider.expect(
        "code-noverify",
        ProviderUser {
            subject: "sub-noverify".into(),
            email: Some("owner@example.com".into()),
            email_verified: false,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let err = h
        .manager
        .finish_authorization(&started.state, "code-noverify", SessionContext::default())
        .await
        .expect_err("should refuse");
    assert!(matches!(err, Error::OAuthEmailTaken));
}

#[tokio::test]
async fn finish_rejects_unknown_state() {
    let h = fresh(OAuthConfig::default());
    let err = h
        .manager
        .finish_authorization(
            &OAuthStateId("not-real".into()),
            "code",
            SessionContext::default(),
        )
        .await
        .expect_err("unknown state");
    assert!(matches!(err, Error::InvalidOAuthState));
}

#[tokio::test]
async fn finish_rejects_replayed_state() {
    let h = fresh(OAuthConfig::default());
    h.provider.expect(
        "code-1",
        ProviderUser {
            subject: "sub-replay".into(),
            email: Some("r@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    h.manager
        .finish_authorization(&started.state, "code-1", SessionContext::default())
        .await
        .expect("first finish");

    let err = h
        .manager
        .finish_authorization(&started.state, "code-1", SessionContext::default())
        .await
        .expect_err("replayed");
    assert!(matches!(err, Error::InvalidOAuthState));
}

#[tokio::test]
async fn finish_rejects_expired_state() {
    let h = fresh(OAuthConfig {
        state_lifetime: Duration::from_secs(60),
        ..OAuthConfig::default()
    });
    h.provider.expect(
        "code-expired",
        ProviderUser {
            subject: "sub-x".into(),
            email: Some("x@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    h.clock.advance(ChronoDuration::seconds(120));

    let err = h
        .manager
        .finish_authorization(&started.state, "code-expired", SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidOAuthState));
}

#[tokio::test]
async fn finish_propagates_provider_error() {
    let h = fresh(OAuthConfig::default());
    h.provider.expect_error(
        "bad-code",
        ProviderError::Response {
            status: 400,
            message: "invalid_grant".into(),
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let err = h
        .manager
        .finish_authorization(&started.state, "bad-code", SessionContext::default())
        .await
        .expect_err("provider error");
    assert!(matches!(err, Error::OAuthProvider(_)));
    assert!(h.identities.is_empty());
    assert_eq!(h.sessions.len(), 0);
}

#[tokio::test]
async fn link_user_id_conflict_with_existing_identity_errors() {
    // Identity already linked to user A. User B is now logged in and
    // attempts to add the same external identity to their account.
    let h = fresh(OAuthConfig::default());
    let alice = make_user(&h, "alice@example.com", true).await;
    let bob = make_user(&h, "bob@example.com", true).await;

    h.provider.expect(
        "code-alice",
        ProviderUser {
            subject: "external-1".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );
    let started_alice = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, Some(alice.id))
        .await
        .unwrap();
    h.manager
        .finish_authorization(
            &started_alice.state,
            "code-alice",
            SessionContext::default(),
        )
        .await
        .expect("alice link");

    h.provider.expect(
        "code-bob",
        ProviderUser {
            subject: "external-1".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );
    let started_bob = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, Some(bob.id))
        .await
        .unwrap();
    let err = h
        .manager
        .finish_authorization(&started_bob.state, "code-bob", SessionContext::default())
        .await
        .expect_err("conflict");
    assert!(matches!(err, Error::OAuthIdentityAlreadyLinked));
}

#[tokio::test]
async fn unlink_removes_identity_and_emits_audit() {
    let h = fresh(OAuthConfig::default());
    h.provider.expect(
        "code-1",
        ProviderUser {
            subject: "sub-unlink".into(),
            email: Some("u@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    let outcome = h
        .manager
        .finish_authorization(&started.state, "code-1", SessionContext::default())
        .await
        .expect("finish");

    h.manager
        .unlink(
            outcome.user.id,
            PROVIDER_NAME,
            "sub-unlink",
            SessionContext::default(),
        )
        .await
        .expect("unlink");

    assert!(h.identities.is_empty());
    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::CredentialRemoved {
            credential_kind: CredentialKind::OAuth,
            ..
        }
    )));
}

#[tokio::test]
async fn unlink_refuses_other_users_identity() {
    let h = fresh(OAuthConfig::default());
    let alice = make_user(&h, "alice@example.com", true).await;
    let bob = make_user(&h, "bob@example.com", true).await;
    h.provider.expect(
        "code-alice",
        ProviderUser {
            subject: "sub-A".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );
    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, Some(alice.id))
        .await
        .unwrap();
    h.manager
        .finish_authorization(&started.state, "code-alice", SessionContext::default())
        .await
        .expect("link");

    let err = h
        .manager
        .unlink(bob.id, PROVIDER_NAME, "sub-A", SessionContext::default())
        .await
        .expect_err("wrong user");
    assert!(matches!(err, Error::OAuthIdentityAlreadyLinked));
    assert_eq!(h.identities.len(), 1, "alice's identity untouched");
}

#[tokio::test]
async fn state_store_purges_expired() {
    let h = fresh(OAuthConfig {
        state_lifetime: Duration::from_secs(60),
        ..OAuthConfig::default()
    });
    h.manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    assert_eq!(h.states.len(), 1);

    h.clock.advance(ChronoDuration::seconds(120));
    let removed = h.states.purge_expired(h.clock.now()).await.unwrap();
    assert_eq!(removed, 1);
    assert!(h.states.is_empty());
}

#[tokio::test]
async fn pkce_verifier_round_trips_to_provider() {
    let h = fresh(OAuthConfig::default());
    h.provider.expect(
        "code-pkce",
        ProviderUser {
            subject: "sub-pkce".into(),
            email: Some("p@example.com".into()),
            email_verified: true,
            display_name: None,
        },
    );

    let started = h
        .manager
        .start_authorization(PROVIDER_NAME, REDIRECT_URI, None)
        .await
        .unwrap();
    // The verifier itself is server-side; we observe it only through the
    // exchange call the provider sees.
    h.manager
        .finish_authorization(&started.state, "code-pkce", SessionContext::default())
        .await
        .expect("finish");

    let exchange = h.provider.exchanges();
    assert_eq!(exchange.len(), 1);
    assert!(
        !exchange[0].pkce_verifier.is_empty(),
        "verifier sent to provider"
    );
    assert_eq!(exchange[0].redirect_uri, REDIRECT_URI);
}
