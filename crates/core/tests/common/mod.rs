#![allow(
    dead_code,
    reason = "each test binary compiles this module, and not every binary uses every helper"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Barrier;

use chrono::{DateTime, TimeZone, Utc};
use doorman_core::account::{AccountConfig, AccountManager};
use doorman_core::assembly::{AssemblyError, AuthCore};
use doorman_core::audit::{
    AuditEvent, AuditEventKind, AuditSink, RedemptionFailureReason, SecretKind,
};
use doorman_core::cache::SessionCacheConfig;
use doorman_core::clock::Clock;
use doorman_core::email::{DefaultEmailTemplates, EmailSender, EmailTemplates};
use doorman_core::error::StorageResult;
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::metrics::MetricSink;
use doorman_core::operator::{NotificationPolicy, OperatorManager};
use doorman_core::passkey::{PasskeyConfig, PasskeyManager};
use doorman_core::rate_limit::{NoopRateLimiter, RateLimiter};
use doorman_core::reauth::{ReauthManager, ReauthPolicy};
use doorman_core::recovery::{RecoveryConfig, RecoveryManager, RecoveryRateLimits};
use doorman_core::resolve::SessionResolver;
use doorman_core::session::hash_token;
use doorman_core::session::{SessionConfig, SessionContext, SessionManager};
use doorman_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use doorman_core::storage::{
    AccountStatus, Session, SessionId, Storage, StoredPasskey, User, UserId, UserStore,
};
pub use doorman_test_support::token_from_email;
use doorman_test_support::{CapturingEmailSender, CapturingMetrics, InMemoryAuditSink, MockClock};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_proto::{AllowCredentials, ResidentKeyRequirement};

pub const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
pub const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
pub const ACCOUNT_URL: &str = "https://app.test/email-change?token={token}";
pub const RP_ID: &str = "localhost";
pub const RP_NAME: &str = "doorman tests";

pub fn rp_origin() -> Url {
    Url::parse("http://localhost:8080").expect("valid url")
}

pub fn auth_origin() -> AuthUrl {
    AuthUrl::parse("http://localhost:8080").expect("valid auth url")
}

pub fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

pub fn kinds(events: &[AuditEvent]) -> Vec<AuditEventKind> {
    events.iter().map(|e| e.kind.clone()).collect()
}

pub fn signup_config() -> SignupConfig {
    SignupConfig {
        url_template: SIGNUP_URL.to_string(),
        rate_limits: SignupRateLimits::disabled(),
        ..SignupConfig::default()
    }
}

pub fn recovery_config() -> RecoveryConfig {
    RecoveryConfig {
        url_template: RECOVERY_URL.to_string(),
        rate_limits: RecoveryRateLimits::disabled(),
        ..RecoveryConfig::default()
    }
}

pub struct CountingUserStore {
    inner: Arc<InMemoryUserStore>,
    reads_by_id: AtomicUsize,
    email_hold: Mutex<Option<(Arc<Barrier>, usize)>>,
}

impl CountingUserStore {
    pub fn reads_by_id(&self) -> usize {
        self.reads_by_id.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.reads_by_id.store(0, Ordering::SeqCst);
    }

    pub fn hold_email_lookups(&self, lookups: usize) -> Arc<Barrier> {
        let barrier = Arc::new(Barrier::new(lookups + 1));
        *self.email_hold.lock().expect("email hold lock") = Some((barrier.clone(), lookups));
        barrier
    }
}

#[async_trait]
impl UserStore for CountingUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        self.inner.create_user(user).await
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        self.reads_by_id.fetch_add(1, Ordering::SeqCst);
        self.inner.find_user_by_id(id).await
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let barrier = match &mut *self.email_hold.lock().expect("email hold lock") {
            Some((barrier, left)) if *left > 0 => {
                *left -= 1;
                Some(barrier.clone())
            }
            _ => None,
        };
        let found = self.inner.find_user_by_email(email).await;
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        found
    }

    async fn set_user_status(
        &self,
        id: UserId,
        status: AccountStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.set_user_status(id, status, at).await
    }

    async fn set_user_email(
        &self,
        id: UserId,
        email: &str,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.set_user_email(id, email, at).await
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        self.inner.mark_email_verified(id, at).await
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        self.inner.delete_user(id).await
    }
}

pub struct Harness {
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub account: AccountManager,
    pub reauth: ReauthManager,
    pub operator: OperatorManager,
    pub session_manager: SessionManager,
    pub resolver: SessionResolver,
    pub users: Arc<InMemoryUserStore>,
    pub user_store: Arc<CountingUserStore>,
    pub sessions: Arc<InMemorySessionStore>,
    pub tokens: Arc<InMemoryVerificationTokenStore>,
    pub credentials: Arc<InMemoryPasskeyCredentialStore>,
    pub challenges: Arc<InMemoryPasskeyChallengeStore>,
    pub storage: Storage,
    pub audit: Arc<InMemoryAuditSink>,
    pub email: Arc<CapturingEmailSender>,
    pub clock: Arc<MockClock>,
    pub metrics: Arc<CapturingMetrics>,
}

impl Harness {
    pub fn fresh() -> Harness {
        HarnessBuilder::new().build()
    }

    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::new()
    }
}

pub struct HarnessBuilder {
    signup: SignupConfig,
    recovery: RecoveryConfig,
    session_config: SessionConfig,
    cache_config: SessionCacheConfig,
    passkey: PasskeyConfig,
    signup_limiter: Arc<dyn RateLimiter>,
    recovery_limiter: Arc<dyn RateLimiter>,
    emails: Arc<dyn EmailTemplates>,
    notification_policy: NotificationPolicy,
    reauth_policy: ReauthPolicy,
}

impl HarnessBuilder {
    pub fn new() -> Self {
        Self {
            signup: signup_config(),
            recovery: recovery_config(),
            session_config: SessionConfig {
                absolute_lifetime: Duration::from_secs(60 * 60),
                ..SessionConfig::default()
            },
            cache_config: SessionCacheConfig::default(),
            passkey: PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
            signup_limiter: Arc::new(NoopRateLimiter),
            recovery_limiter: Arc::new(NoopRateLimiter),
            emails: Arc::new(DefaultEmailTemplates),
            notification_policy: NotificationPolicy::default(),
            reauth_policy: ReauthPolicy::disabled(),
        }
    }

    pub fn reauth_policy(mut self, policy: ReauthPolicy) -> Self {
        self.reauth_policy = policy;
        self
    }

    pub fn notification_policy(mut self, policy: NotificationPolicy) -> Self {
        self.notification_policy = policy;
        self
    }

    pub fn emails(mut self, emails: Arc<dyn EmailTemplates>) -> Self {
        self.emails = emails;
        self
    }

    pub fn signup_config(mut self, config: SignupConfig) -> Self {
        self.signup = config;
        self
    }

    pub fn recovery_config(mut self, config: RecoveryConfig) -> Self {
        self.recovery = config;
        self
    }

    pub fn signup_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.signup_limiter = limiter;
        self
    }

    pub fn recovery_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.recovery_limiter = limiter;
        self
    }

    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    pub fn cache_config(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = config;
        self
    }

    pub fn passkey_config(mut self, config: PasskeyConfig) -> Self {
        self.passkey = config;
        self
    }

    pub fn build(self) -> Harness {
        self.try_build().expect("harness assembles")
    }

    pub fn try_build(self) -> Result<Harness, AssemblyError> {
        let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let tokens: Arc<InMemoryVerificationTokenStore> =
            Arc::new(InMemoryVerificationTokenStore::new());
        let credentials: Arc<InMemoryPasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::new());
        let challenges: Arc<InMemoryPasskeyChallengeStore> =
            Arc::new(InMemoryPasskeyChallengeStore::new());
        let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
        let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
        let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
        let metrics: Arc<CapturingMetrics> = Arc::new(CapturingMetrics::new());

        let user_store = Arc::new(CountingUserStore {
            inner: users.clone(),
            reads_by_id: AtomicUsize::new(0),
            email_hold: Mutex::new(None),
        });

        let storage = Storage {
            users: user_store.clone(),
            sessions: sessions.clone(),
            verification_tokens: tokens.clone(),
            passkey_credentials: credentials.clone(),
            passkey_challenges: challenges.clone(),
        };

        let core = AuthCore::builder(storage.clone())
            .clock(clock.clone() as Arc<dyn Clock>)
            .audit(audit.clone() as Arc<dyn AuditSink>)
            .email(email.clone() as Arc<dyn EmailSender>)
            .emails(self.emails)
            .limiter(self.signup_limiter)
            .recovery_limiter(self.recovery_limiter)
            .metrics(metrics.clone() as Arc<dyn MetricSink>)
            .session(self.session_config)
            .cache(self.cache_config)
            .passkey(self.passkey)
            .signup(self.signup)
            .recovery(self.recovery)
            .account(AccountConfig {
                url_template: ACCOUNT_URL.to_string(),
                ..AccountConfig::default()
            })
            .reauthentication(self.reauth_policy)
            .notification_policy(self.notification_policy)
            .build()?;

        Ok(Harness {
            passkey: core.passkey,
            signup: core.signup,
            recovery: core.recovery,
            account: core.account,
            reauth: core.reauth,
            operator: core.operator,
            session_manager: core.session_manager,
            resolver: core.resolver,
            users,
            user_store,
            sessions,
            tokens,
            credentials,
            challenges,
            storage,
            audit,
            email,
            clock,
            metrics,
        })
    }
}

impl Default for HarnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn within_deadline<T>(race: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), race)
        .await
        .expect("the race finishes; is a held lookup never released?")
}

pub async fn session_count(h: &Harness, user_id: UserId) -> usize {
    h.session_manager
        .list_for_user(user_id)
        .await
        .expect("list sessions")
        .len()
}

pub async fn passkey_count(h: &Harness, user_id: UserId) -> u64 {
    h.passkey
        .count_passkeys(user_id)
        .await
        .expect("count passkeys")
}

pub fn last_email_change_token(h: &Harness) -> String {
    let confirmation = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Confirm your new email address")
        .expect("email-change link queued");
    token_from_email(&confirmation.body_text, ACCOUNT_URL)
}

pub fn assert_last_redemption_unknown(h: &Harness, secret: SecretKind) {
    let events = h.audit.events();
    let last = events.last().map(|e| &e.kind);
    assert!(
        matches!(
            last,
            Some(AuditEventKind::RedemptionFailed {
                user_id: None,
                secret: s,
                reason: RedemptionFailureReason::Unknown,
            }) if *s == secret
        ),
        "expected {secret:?} refused as unknown, got {last:?}",
    );
}

pub async fn make_user(h: &Harness, email: &str) -> User {
    let now = h.clock.now();
    let user = User {
        id: UserId::new(),
        email: Some(email.to_ascii_lowercase()),
        email_verified_at: Some(now),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    h.users.create_user(user.clone()).await.expect("create");
    user
}

pub fn session_for(h: &Harness, user: &User) -> Session {
    plain_session(h, user.id, None)
}

pub fn restricted_session_for(h: &Harness, user: &User, cooldown_until: DateTime<Utc>) -> Session {
    plain_session(h, user.id, Some(cooldown_until))
}

fn plain_session(h: &Harness, user_id: UserId, cooldown: Option<DateTime<Utc>>) -> Session {
    let now = h.clock.now();
    Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("test-session-token"),
        created_at: now,
        last_used_at: now,
        expires_at: now + chrono::Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: cooldown,
    }
}

pub async fn register_passkey(
    h: &Harness,
    user: UserId,
    wa: &mut ResidentTestAuthenticator,
    name: Option<&str>,
) -> StoredPasskey {
    let (challenge_id, ccr) = h
        .passkey
        .start_registration(&plain_session(h, user, None))
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    h.passkey
        .finish_registration(
            challenge_id,
            &response,
            name.map(ToOwned::to_owned),
            SessionContext::default(),
        )
        .await
        .expect("finish_registration")
}

pub async fn provision_user(h: &Harness, email: &str) -> User {
    h.signup
        .request_signup(email, None, SessionContext::default())
        .await
        .expect("signup request");
    let signup_email = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Finish setting up your account")
        .expect("signup link queued");
    let token = token_from_email(&signup_email.body_text, SIGNUP_URL);

    let consume = h
        .signup
        .consume_signup(&token, SessionContext::default())
        .await
        .expect("signup consume");

    let mut wa = ResidentTestAuthenticator::new();
    let attestation = wa.do_registration(consume.options);
    let outcome = h
        .signup
        .finish_signup(
            consume.challenge_id,
            &attestation,
            Some("initial device".into()),
            SessionContext::default(),
        )
        .await
        .expect("signup finish");
    outcome.user
}

#[derive(Clone)]
struct ResidentCredential {
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
}

pub struct ResidentTestAuthenticator {
    inner: WebauthnAuthenticator<SoftPasskey>,
    resident_credentials: Vec<ResidentCredential>,
}

impl ResidentTestAuthenticator {
    pub fn new() -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            resident_credentials: Vec::new(),
        }
    }

    pub fn do_registration(
        &mut self,
        challenge: CreationChallengeResponse,
    ) -> RegisterPublicKeyCredential {
        assert_resident_registration_options(&challenge);

        let user_handle = challenge.public_key.user.id.as_ref().to_vec();
        let mut compatible = challenge;
        let selection = compatible
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("passkey registration includes authenticator selection");
        selection.require_resident_key = false;
        selection.resident_key = None;

        let response = self
            .inner
            .do_registration(auth_origin(), compatible)
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
        self.do_authentication_inner(challenge, credential_id, true)
    }

    pub fn do_scoped_authentication(
        &mut self,
        challenge: RequestChallengeResponse,
    ) -> PublicKeyCredential {
        assert!(
            !challenge.public_key.allow_credentials.is_empty(),
            "re-auth challenge must be allow-list scoped"
        );
        self.inner
            .do_authentication(auth_origin(), challenge)
            .expect("authenticator auth")
    }

    pub fn do_authentication_without_user_handle(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
    ) -> PublicKeyCredential {
        self.do_authentication_inner(challenge, credential_id, false)
    }

    fn do_authentication_inner(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
        include_user_handle: bool,
    ) -> PublicKeyCredential {
        assert_discoverable_request_options(&challenge);
        let resident = self
            .resident_credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
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
            .do_authentication(auth_origin(), compatible)
            .expect("authenticator auth");
        assertion.response.user_handle = include_user_handle.then(|| resident.user_handle.into());
        assertion
    }
}

impl Default for ResidentTestAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn authenticator() -> ResidentTestAuthenticator {
    ResidentTestAuthenticator::new()
}

pub fn assert_resident_registration_options(challenge: &CreationChallengeResponse) {
    let selection = challenge
        .public_key
        .authenticator_selection
        .as_ref()
        .expect("registration includes authenticator selection");
    assert!(
        selection.require_resident_key,
        "registration must require resident keys"
    );
    assert_eq!(
        selection.resident_key,
        Some(ResidentKeyRequirement::Required),
        "registration must set residentKey=required"
    );
}

pub fn assert_discoverable_request_options(challenge: &RequestChallengeResponse) {
    assert!(
        challenge.public_key.allow_credentials.is_empty(),
        "discoverable auth must not send allowCredentials"
    );
}
