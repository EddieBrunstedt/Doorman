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
//! `SoftPasskey` cannot mint resident keys, so it verifies bauth's
//! server-issued options, then relaxes only the local input and records
//! the credential as if it were discoverable.
//!
//! `session_flow` is intentionally not built on this harness — it
//! exercises `SessionManager` in isolation with its own bespoke setup and
//! shares none of this scaffolding.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use bauth_core::clock::Clock;
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::rate_limit::{NoopRateLimiter, RateLimiter};
use bauth_core::recovery::{RecoveryConfig, RecoveryManager, RecoveryRateLimits};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use bauth_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, StoredPasskey, User, UserId,
    UserStore, VerificationTokenStore,
};
use bauth_core::verification::EnrollmentFlow;
use bauth_core::verification::TOKEN_PLACEHOLDER;
use bauth_test_support::{CapturingEmailSender, InMemoryAuditSink, MockClock};
use chrono::{DateTime, TimeZone, Utc};
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
pub const RP_ID: &str = "localhost";
pub const RP_NAME: &str = "bauth tests";

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

/// Recover the raw token from an email body whose URL was rendered from
/// `template` (either [`SIGNUP_URL`] or [`RECOVERY_URL`]).
pub fn token_from_email(body: &str, template: &str) -> String {
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

/// In-memory stores plus the three flow managers, all sharing one clock,
/// audit sink, and email sender.
pub struct Harness {
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub users: Arc<InMemoryUserStore>,
    pub sessions: Arc<InMemorySessionStore>,
    pub tokens: Arc<InMemoryVerificationTokenStore>,
    pub credentials: Arc<InMemoryPasskeyCredentialStore>,
    pub challenges: Arc<InMemoryPasskeyChallengeStore>,
    pub audit: Arc<InMemoryAuditSink>,
    pub email: Arc<CapturingEmailSender>,
    pub clock: Arc<MockClock>,
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
    session_lifetime: Duration,
    /// Rate limiter for the signup manager. Kept separate from the
    /// recovery limiter so a recovery rate-limit test can provision users
    /// through signup without spending the budget it is measuring.
    signup_limiter: Arc<dyn RateLimiter>,
    recovery_limiter: Arc<dyn RateLimiter>,
}

impl HarnessBuilder {
    pub fn new() -> Self {
        Self {
            signup: signup_config(),
            recovery: recovery_config(),
            session_lifetime: Duration::from_secs(60 * 60),
            signup_limiter: Arc::new(NoopRateLimiter),
            recovery_limiter: Arc::new(NoopRateLimiter),
        }
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

        let session_manager = SessionManager::new(
            sessions.clone() as Arc<dyn SessionStore>,
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            SessionConfig {
                lifetime: self.session_lifetime,
            },
        );
        let passkey = PasskeyManager::new(
            users.clone() as Arc<dyn UserStore>,
            credentials.clone() as Arc<dyn PasskeyCredentialStore>,
            challenges.clone() as Arc<dyn PasskeyChallengeStore>,
            session_manager.clone(),
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            email.clone() as Arc<dyn EmailSender>,
            PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
        )
        .expect("build passkey manager");
        // Signup and recovery hold their own EnrollmentFlow. The two flows
        // differ only in their rate limiter, kept separate so a recovery
        // rate-limit test can provision users through signup without
        // spending the budget it is measuring.
        let signup_flow = EnrollmentFlow::new(
            users.clone() as Arc<dyn UserStore>,
            tokens.clone() as Arc<dyn VerificationTokenStore>,
            passkey.clone(),
            session_manager.clone(),
            email.clone() as Arc<dyn EmailSender>,
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            self.signup_limiter,
        );
        let recovery_flow = EnrollmentFlow::new(
            users.clone() as Arc<dyn UserStore>,
            tokens.clone() as Arc<dyn VerificationTokenStore>,
            passkey.clone(),
            session_manager,
            email.clone() as Arc<dyn EmailSender>,
            clock.clone() as Arc<dyn Clock>,
            audit.clone() as Arc<dyn AuditSink>,
            self.recovery_limiter,
        );
        let signup = SignupManager::new(signup_flow, self.signup);
        let recovery = RecoveryManager::new(recovery_flow, self.recovery);

        Harness {
            passkey,
            signup,
            recovery,
            users,
            sessions,
            tokens,
            credentials,
            challenges,
            audit,
            email,
            clock,
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
        created_at: now,
        updated_at: now,
    };
    h.users.create_user(user.clone()).await.expect("create");
    user
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
        .request_signup(email, SessionContext::default())
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
/// resident keys, so on registration it verifies bauth's server-issued
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
