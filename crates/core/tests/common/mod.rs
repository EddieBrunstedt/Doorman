//! Shared scaffolding for the core flow integration tests.
//!
//! [`Harness`] wires the in-memory stores into one set of managers
//! (passkey / signup / recovery) sharing a single clock, audit sink, and
//! email sender, so the `signup_flow`, `recovery_flow`, and `passkey_flow`
//! suites build their world the same way. [`HarnessBuilder`] varies the
//! few knobs individual tests need (the signup / recovery configs and
//! per-flow rate limiters); everything else is fixed test defaults.
//!
//! [`ResidentTestAuthenticator`] is the one shared WebAuthn test client:
//! `SoftPasskey` cannot mint resident keys, so it verifies doorman's
//! server-issued options, then relaxes only the local input and records
//! the credential as if it were discoverable.
//!
//! `session_flow` is intentionally not built on this harness — it
//! exercises `SessionManager` in isolation with its own bespoke setup and
//! shares none of this scaffolding.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use doorman_core::account::{AccountConfig, AccountManager};
use doorman_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use doorman_core::cache::SessionCacheConfig;
use doorman_core::clock::Clock;
use doorman_core::context::CoreDeps;
use doorman_core::email::{
    DefaultEmailTemplates, EmailSender, EmailTemplates, SecurityEmailNotifier,
};
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
    AccountStatus, Session, SessionId, SessionStore, Storage, StoredPasskey, User, UserId,
    UserStore,
};
use doorman_core::verification::EnrollmentFlow;
use doorman_test_support::{CapturingEmailSender, CapturingMetrics, InMemoryAuditSink, MockClock};
// Re-export the shared token extractor so the flow suites can keep importing
// it from `common` while the one implementation lives in `doorman-test-support`.
use chrono::{DateTime, TimeZone, Utc};
pub use doorman_test_support::token_from_email;
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

/// The signup-flow [`SignupConfig`] used by the harness: a known URL
/// template (so [`token_from_email`] can recover the token) and disabled
/// rate limits. Tests override individual fields with `..signup_config()`.
pub fn signup_config() -> SignupConfig {
    SignupConfig {
        url_template: SIGNUP_URL.to_string(),
        rate_limits: SignupRateLimits::disabled(),
        ..SignupConfig::default()
    }
}

/// The recovery-flow [`RecoveryConfig`] counterpart to [`signup_config`].
pub fn recovery_config() -> RecoveryConfig {
    RecoveryConfig {
        url_template: RECOVERY_URL.to_string(),
        rate_limits: RecoveryRateLimits::disabled(),
        ..RecoveryConfig::default()
    }
}

/// In-memory stores plus the three flow managers, all sharing one clock,
/// audit sink, and email sender.
pub struct Harness {
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub account: AccountManager,
    pub reauth: ReauthManager,
    pub operator: OperatorManager,
    /// The session manager every other manager shares.
    pub session_manager: SessionManager,
    /// The request-time resolver over [`session_manager`](Self::session_manager),
    /// reporting cache hits and misses to [`metrics`](Self::metrics).
    pub resolver: SessionResolver,
    /// The recovery flow the harness built `recovery` from, kept so tests
    /// can construct another `RecoveryManager` (e.g. to exercise
    /// `RecoveryManager::new`'s cool-down validation) without re-wiring the
    /// stores.
    pub recovery_flow: EnrollmentFlow,
    pub users: Arc<InMemoryUserStore>,
    pub sessions: Arc<InMemorySessionStore>,
    pub tokens: Arc<InMemoryVerificationTokenStore>,
    pub credentials: Arc<InMemoryPasskeyCredentialStore>,
    pub challenges: Arc<InMemoryPasskeyChallengeStore>,
    pub audit: Arc<InMemoryAuditSink>,
    pub email: Arc<CapturingEmailSender>,
    pub clock: Arc<MockClock>,
    pub metrics: Arc<CapturingMetrics>,
}

impl Harness {
    /// Build with all defaults.
    pub fn fresh() -> Harness {
        HarnessBuilder::new().build()
    }

    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::new()
    }
}

/// Varies the knobs individual tests need; everything else is fixed.
pub struct HarnessBuilder {
    signup: SignupConfig,
    recovery: RecoveryConfig,
    session_config: SessionConfig,
    cache_config: SessionCacheConfig,
    /// Passkey config the [`PasskeyManager`] is built with. Defaults to the
    /// fixed test relying party; cap / rate-limit tests override it. The
    /// passkey manager reads the limiter from the signup [`CoreDeps`], so a
    /// passkey-ceremony rate-limit test pairs an override here with
    /// [`signup_limiter`](Self::signup_limiter).
    passkey: PasskeyConfig,
    /// Rate limiter for the signup manager (and, via the shared `CoreDeps`,
    /// the passkey manager). Kept separate from the recovery limiter so a
    /// recovery rate-limit test can provision users through signup without
    /// spending the budget it is measuring.
    signup_limiter: Arc<dyn RateLimiter>,
    recovery_limiter: Arc<dyn RateLimiter>,
    /// The single renderer threaded through `CoreDeps` and used for every
    /// flow's link copy and security notices. Defaults to the stock copy;
    /// branding tests override it.
    emails: Arc<dyn EmailTemplates>,
    /// The [`NotificationPolicy`] the [`OperatorManager`] is built with.
    /// Defaults to the asymmetric stock policy; the operator notice tests
    /// override it to exercise the send/suppress toggles.
    notification_policy: NotificationPolicy,
    /// The [`ReauthPolicy`] the destructive managers gate through. Defaults to
    /// [`ReauthPolicy::disabled`] so the account / passkey flow suites keep
    /// passing without supplying proofs; the reauth suite overrides it.
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

    /// Override the [`ReauthPolicy`] the harness gates destructive actions
    /// with. Defaults to [`ReauthPolicy::disabled`].
    pub fn reauth_policy(mut self, policy: ReauthPolicy) -> Self {
        self.reauth_policy = policy;
        self
    }

    /// Override the operator [`NotificationPolicy`] the harness builds its
    /// [`OperatorManager`] with.
    pub fn notification_policy(mut self, policy: NotificationPolicy) -> Self {
        self.notification_policy = policy;
        self
    }

    /// Override the renderer used for every flow's link copy and security
    /// notices.
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

        let notifier =
            SecurityEmailNotifier::new(email.clone() as Arc<dyn EmailSender>, self.emails.clone());
        let session_manager = SessionManager::new(
            sessions.clone() as Arc<dyn SessionStore>,
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            self.session_config,
        )
        .with_security_notifier(notifier.clone());
        let resolver = SessionResolver::new(
            session_manager.clone(),
            users.clone() as Arc<dyn UserStore>,
            self.cache_config,
        )
        .expect("cache ttl is below the idle timeout")
        .with_metrics(metrics.clone() as Arc<dyn MetricSink>);

        let storage = Storage {
            users: users.clone(),
            sessions: sessions.clone(),
            verification_tokens: tokens.clone(),
            passkey_credentials: credentials.clone(),
            passkey_challenges: challenges.clone(),
        };

        // The destructive managers gate through one shared re-auth manager.
        let reauth = ReauthManager::new(
            &self.passkey,
            credentials.clone(),
            challenges.clone(),
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            self.reauth_policy,
        )
        .expect("build reauth manager");

        // Signup and recovery hold their own EnrollmentFlow. The two flows
        // share every collaborator except the rate limiter, kept separate so
        // a recovery rate-limit test can provision users through signup
        // without spending the budget it is measuring — so we build one
        // `CoreDeps` and override just that field for recovery.
        let signup_deps = CoreDeps::new(
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            email.clone() as Arc<dyn EmailSender>,
            self.emails.clone(),
            notifier,
            self.signup_limiter,
            session_manager.clone(),
            reauth.clone(),
            storage,
        )
        .with_metrics(metrics.clone() as Arc<dyn MetricSink>);
        let recovery_deps = CoreDeps {
            rate_limiter: self.recovery_limiter,
            ..signup_deps.clone()
        };

        let passkey =
            PasskeyManager::new(&signup_deps, self.passkey).expect("build passkey manager");
        let signup_flow = EnrollmentFlow::new(&signup_deps, passkey.clone());
        let recovery_flow = EnrollmentFlow::new(&recovery_deps, passkey.clone());
        let signup = SignupManager::new(signup_flow, self.signup);
        let recovery = RecoveryManager::new(recovery_flow.clone(), self.recovery)
            .expect("recovery cooldown is at or above the floor");
        let account = AccountManager::new(
            &signup_deps,
            AccountConfig {
                url_template: ACCOUNT_URL.to_string(),
                ..AccountConfig::default()
            },
        );
        let operator = OperatorManager::new(
            &signup_deps,
            account.clone(),
            passkey.clone(),
            self.notification_policy,
        );

        Harness {
            passkey,
            signup,
            recovery,
            account,
            reauth,
            operator,
            session_manager,
            resolver,
            recovery_flow,
            users,
            sessions,
            tokens,
            credentials,
            challenges,
            audit,
            email,
            clock,
            metrics,
        }
    }
}

impl Default for HarnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a verified user directly in the store, bypassing the signup
/// ceremony. For passkey-flow tests that only need a user to attach
/// credentials to.
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

/// Build an ordinary (non-cool-down) session row for `user` at the harness
/// clock. The destructive managers read only the owning user and the
/// cool-down fields off the acting session, so a hand-built row is enough to
/// drive the cool-down gate in tests that don't go through a full login.
pub fn session_for(h: &Harness, user: &User) -> Session {
    plain_session(h, user.id, None)
}

/// Like [`session_for`] but restricted by a post-recovery cool-down ending at
/// `cooldown_until`, so the destructive managers treat it as locked down.
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

/// Register a passkey for `user` through the full ceremony and return the
/// stored credential.
pub async fn register_passkey(
    h: &Harness,
    user: UserId,
    wa: &mut ResidentTestAuthenticator,
    name: Option<&str>,
) -> StoredPasskey {
    let (challenge_id, ccr) = h
        .passkey
        .start_registration(user)
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

/// Drive a full signup flow against `h` so subsequent tests have a
/// registered user with a passkey.
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

/// Discoverable credential the test authenticator has "stored" so a later
/// usernameless authentication can claim residency.
#[derive(Clone)]
struct ResidentCredential {
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
}

/// Test authenticator wrapping a `SoftPasskey`. `SoftPasskey` cannot create
/// resident keys, so on registration it verifies doorman's server-issued
/// options, relaxes only the local input, and records the credential's
/// user handle as if it had been stored discoverably.
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

    /// Drive an allow-list-scoped authentication, as re-authentication issues.
    /// Unlike sign-in the challenge carries an `allow_credentials` list, so the
    /// `SoftPasskey` needs no compatibility shim — it picks the key straight
    /// from the server-issued list. A user handle is *not* attached: the
    /// scoped finish identifies the credential from the allow-list, and core's
    /// re-auth gate confirms ownership by looking the asserted credential up.
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

        // SoftPasskey still needs an allow-list to pick a key. This is
        // strictly a test-authenticator compatibility shim: the
        // server-issued challenge remains discoverable.
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
