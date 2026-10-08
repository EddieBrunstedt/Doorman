use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Barrier;

use chrono::{DateTime, TimeZone, Utc};
use doorman_core::assembly::{AssemblyError, AuthCore};
use doorman_core::audit::{
    AuditEvent, AuditEventKind, AuditSink, RedemptionFailureReason, SecretKind,
};
use doorman_core::clock::Clock;
use doorman_core::email::{DefaultEmailTemplates, EmailSender, EmailTemplates};
use doorman_core::error::StorageResult;
use doorman_core::memory::{
    InMemoryEmailLinkStore, InMemoryPasskeyChallengeStore, InMemoryPasskeyStore,
    InMemorySessionStore, InMemoryUserStore,
};
use doorman_core::metrics::MetricSink;
use doorman_core::operator::OperatorManager;
use doorman_core::passkey::{PasskeyConfig, PasskeyManager};
use doorman_core::rate_limit::{NoopRateLimiter, RateLimiter};
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{RecoveryConfig, RecoveryManager, RecoveryRateLimits};
use doorman_core::security_notice::NoticePolicy;
use doorman_core::session::hash_token;
use doorman_core::session::{
    IssuedSession, ResolvedSession, SessionConfig, SessionContext, SessionManager,
};
use doorman_core::signup::{SignupConfig, SignupManager, SignupRateLimits};
use doorman_core::storage::{
    PasskeyStore, Session, SessionId, SessionStore, Storage, StoredPasskey, TokenHash, User,
    UserId, UserStatus, UserStore,
};
use doorman_core::user::{UserConfig, UserManager};
pub use doorman_test_support::token_from_email;
use doorman_test_support::{CapturingEmailSender, CapturingMetrics, InMemoryAuditSink, MockClock};
pub use doorman_test_support::{
    ResidentAuthenticator, assert_discoverable_request_options,
    assert_resident_registration_options,
};
use url::Url;

pub const SIGNUP_URL: &str = "https://app.test/signup?token={token}";
pub const RECOVERY_URL: &str = "https://app.test/recovery?token={token}";
pub const USER_URL: &str = "https://app.test/email-change?token={token}";
pub const RP_ID: &str = "localhost";
pub const RP_NAME: &str = "doorman tests";

pub fn rp_origin() -> Url {
    Url::parse("http://localhost:8080").expect("valid url")
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
    reads: AtomicUsize,
    create_hold: Mutex<Option<(Arc<Barrier>, usize)>>,
}

impl CountingUserStore {
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    pub fn clear_reads(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }

    pub fn hold_user_creates(&self, creates: usize) -> Arc<Barrier> {
        let barrier = Arc::new(Barrier::new(creates + 1));
        *self.create_hold.lock().expect("create hold lock") = Some((barrier.clone(), creates));
        barrier
    }
}

#[async_trait]
impl UserStore for CountingUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let barrier = match &mut *self.create_hold.lock().expect("create hold lock") {
            Some((barrier, left)) if *left > 0 => {
                *left -= 1;
                Some(barrier.clone())
            }
            _ => None,
        };
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        self.inner.create_user(user).await
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.find_user_by_id(id).await
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.find_user_by_email(email).await
    }

    async fn set_user_status(
        &self,
        id: UserId,
        status: UserStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.set_user_status(id, status, at).await
    }

    async fn set_user_email(
        &self,
        id: UserId,
        email: &str,
        verified_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.set_user_email(id, email, verified_at).await
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        self.inner.mark_email_verified(id, at).await
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        self.inner.delete_user(id).await
    }
}

pub struct CountingSessionStore {
    inner: Arc<InMemorySessionStore>,
    reads: AtomicUsize,
    write_hold: Mutex<Option<Arc<Barrier>>>,
}

impl CountingSessionStore {
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    pub fn clear_reads(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }

    pub fn hold_next_session_write(&self) -> Arc<Barrier> {
        let barrier = Arc::new(Barrier::new(2));
        *self.write_hold.lock().expect("write hold lock") = Some(barrier.clone());
        barrier
    }

    fn read(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl SessionStore for CountingSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let barrier = self.write_hold.lock().expect("write hold lock").take();
        if let Some(barrier) = barrier {
            // The first wait tells the test the write is due; the second lets it through.
            barrier.wait().await;
            barrier.wait().await;
        }
        self.inner.create_session(session).await
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.touch_session(id, last_used_at, expires_at).await
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        self.read();
        self.inner.find_session_by_token_hash(hash).await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.read();
        self.inner.find_session_by_id(id).await
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        self.read();
        self.inner.list_for_user(user_id).await
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        self.inner.delete_session(id).await
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        self.inner.delete_sessions_for_user(user_id, except).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.inner.purge_expired(now).await
    }
}

pub struct Harness {
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub user: UserManager,
    pub operator: OperatorManager,
    pub session_manager: SessionManager,
    pub users: Arc<InMemoryUserStore>,
    pub user_store: Arc<CountingUserStore>,
    pub sessions: Arc<InMemorySessionStore>,
    pub session_store: Arc<CountingSessionStore>,
    pub passkeys: Arc<InMemoryPasskeyStore>,
    pub challenges: Arc<InMemoryPasskeyChallengeStore>,
    pub storage: Storage,
    pub audit: Arc<InMemoryAuditSink>,
    pub email: Arc<CapturingEmailSender>,
    pub clock: Arc<MockClock>,
    pub metrics: Arc<CapturingMetrics>,
    session_config: SessionConfig,
}

impl Harness {
    pub fn fresh() -> Harness {
        HarnessBuilder::new().build()
    }

    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::new()
    }

    pub fn another_process(&self) -> AuthCore {
        AuthCore::builder(self.storage.clone())
            .clock(self.clock.clone() as Arc<dyn Clock>)
            .audit(self.audit.clone() as Arc<dyn AuditSink>)
            .email(self.email.clone() as Arc<dyn EmailSender>)
            .limiter(Arc::new(NoopRateLimiter))
            .session(self.session_config.clone())
            .passkey(PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME))
            .signup(signup_config())
            .recovery(recovery_config())
            .user(UserConfig {
                url_template: USER_URL.to_string(),
                ..UserConfig::default()
            })
            .reauthentication(ReauthPolicy::disabled())
            .build()
            .expect("another process assembles")
    }
}

pub struct HarnessBuilder {
    signup: SignupConfig,
    recovery: RecoveryConfig,
    session_config: SessionConfig,
    passkey: PasskeyConfig,
    signup_limiter: Arc<dyn RateLimiter>,
    recovery_limiter: Arc<dyn RateLimiter>,
    emails: Arc<dyn EmailTemplates>,
    notice_policy: NoticePolicy,
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
            passkey: PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
            signup_limiter: Arc::new(NoopRateLimiter),
            recovery_limiter: Arc::new(NoopRateLimiter),
            emails: Arc::new(DefaultEmailTemplates),
            notice_policy: NoticePolicy::default(),
            reauth_policy: ReauthPolicy::disabled(),
        }
    }

    pub fn reauth_policy(mut self, policy: ReauthPolicy) -> Self {
        self.reauth_policy = policy;
        self
    }

    pub fn notice_policy(mut self, policy: NoticePolicy) -> Self {
        self.notice_policy = policy;
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
        let email_links: Arc<InMemoryEmailLinkStore> = Arc::new(InMemoryEmailLinkStore::new());
        let passkeys: Arc<InMemoryPasskeyStore> = Arc::new(InMemoryPasskeyStore::new());
        let challenges: Arc<InMemoryPasskeyChallengeStore> =
            Arc::new(InMemoryPasskeyChallengeStore::new());
        let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
        let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
        let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
        let metrics: Arc<CapturingMetrics> = Arc::new(CapturingMetrics::new());

        let user_store = Arc::new(CountingUserStore {
            inner: users.clone(),
            reads: AtomicUsize::new(0),
            create_hold: Mutex::new(None),
        });
        let session_store = Arc::new(CountingSessionStore {
            inner: sessions.clone(),
            reads: AtomicUsize::new(0),
            write_hold: Mutex::new(None),
        });

        let storage = Storage {
            users: user_store.clone(),
            sessions: session_store.clone(),
            email_links,
            passkeys: passkeys.clone(),
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
            .session(self.session_config.clone())
            .passkey(self.passkey)
            .signup(self.signup)
            .recovery(self.recovery)
            .user(UserConfig {
                url_template: USER_URL.to_string(),
                ..UserConfig::default()
            })
            .reauthentication(self.reauth_policy)
            .notice_policy(self.notice_policy)
            .build()?;

        Ok(Harness {
            passkey: core.passkey,
            signup: core.signup,
            recovery: core.recovery,
            user: core.user,
            operator: core.operator,
            session_manager: core.sessions,
            users,
            user_store,
            sessions,
            session_store,
            passkeys,
            challenges,
            storage,
            audit,
            email,
            clock,
            metrics,
            session_config: self.session_config,
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
    let now = h.clock.now();
    h.sessions
        .list_for_user(user_id)
        .await
        .expect("list sessions")
        .iter()
        .filter(|session| session.expires_at > now)
        .count()
}

pub async fn passkey_count(h: &Harness, user_id: UserId) -> u64 {
    h.passkeys
        .list_passkeys_for_user(user_id)
        .await
        .expect("list passkeys")
        .len() as u64
}

pub fn last_email_change_token(h: &Harness) -> String {
    let confirmation = h
        .email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Confirm your new email address")
        .expect("email-change link queued");
    token_from_email(&confirmation.body_text, USER_URL)
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
        status: UserStatus::Active,
        created_at: now,
        updated_at: now,
    };
    h.users.create_user(user.clone()).await.expect("create");
    user
}

pub async fn session_for(h: &Harness, user: &User) -> ResolvedSession {
    stored_session(h, user.id, None).await
}

pub async fn session_in_cool_down_for(
    h: &Harness,
    user: &User,
    cool_down_until: DateTime<Utc>,
) -> ResolvedSession {
    stored_session(h, user.id, Some(cool_down_until)).await
}

async fn stored_session(
    h: &Harness,
    user_id: UserId,
    cool_down: Option<DateTime<Utc>>,
) -> ResolvedSession {
    let now = h.clock.now();
    let id = SessionId::new();
    let token = format!("test-session-token-{id}");
    h.sessions
        .create_session(Session {
            id,
            user_id,
            token_hash: hash_token(&token),
            created_at: now,
            last_used_at: now,
            // Outlives any recovery cool-down a test sets, as a real session outlives the default one.
            expires_at: now + chrono::Duration::days(30),
            ip: None,
            user_agent: None,
            recovery_cool_down_until: cool_down,
        })
        .await
        .expect("store session");
    h.session_manager
        .resolve(&token)
        .await
        .expect("resolve stored session")
}

pub async fn register_passkey(
    h: &Harness,
    user: UserId,
    wa: &mut ResidentAuthenticator,
    name: Option<&str>,
) -> StoredPasskey {
    let session = stored_session(h, user, None).await;
    let (challenge_id, ccr) = h
        .session_manager
        .start_passkey_registration(&session)
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    let registered = h
        .session_manager
        .finish_passkey_registration(
            &session,
            challenge_id,
            &response,
            name.map(ToOwned::to_owned),
            SessionContext::default(),
        )
        .await
        .expect("finish_registration");
    // The registering session is scaffolding; leave the user's session count as the test made it.
    h.sessions
        .delete_session(session.id)
        .await
        .expect("drop registering session");
    h.passkeys
        .find_passkey_by_credential_id(&registered.credential_id)
        .await
        .expect("find passkey")
        .expect("passkey persisted")
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
        .find(|e| e.subject == "Finish signing up")
        .expect("signup link queued");
    let token = token_from_email(&signup_email.body_text, SIGNUP_URL);

    let started = h
        .signup
        .redeem_signup_link(&token, SessionContext::default())
        .await
        .expect("signup redeem");

    let mut wa = authenticator();
    let attestation = wa.do_registration(started.options);
    let outcome = h
        .signup
        .finish_signup(
            started.challenge_id,
            &attestation,
            Some("initial device".into()),
            SessionContext::default(),
        )
        .await
        .expect("signup finish");
    outcome.user
}

pub struct SignedIn {
    pub user: User,
    pub authenticator: ResidentAuthenticator,
    pub credential_id: Vec<u8>,
    pub session: IssuedSession,
}

impl SignedIn {
    pub async fn log_in_again(&mut self, h: &Harness) -> IssuedSession {
        log_in(
            h,
            &mut self.authenticator,
            &self.credential_id,
            SessionContext::default(),
        )
        .await
    }
}

pub async fn sign_in(h: &Harness, email: &str) -> SignedIn {
    sign_in_from(h, email, SessionContext::default()).await
}

pub async fn sign_in_from(h: &Harness, email: &str, context: SessionContext) -> SignedIn {
    let user = make_user(h, email).await;
    let mut authenticator = authenticator();
    let passkey = register_passkey(h, user.id, &mut authenticator, None).await;
    let session = log_in(h, &mut authenticator, &passkey.credential_id, context).await;
    SignedIn {
        user,
        authenticator,
        credential_id: passkey.credential_id,
        session,
    }
}

pub async fn log_in(
    h: &Harness,
    wa: &mut ResidentAuthenticator,
    credential_id: &[u8],
    context: SessionContext,
) -> IssuedSession {
    let (challenge_id, options) = h
        .passkey
        .start_authentication(context.clone())
        .await
        .expect("start login");
    let assertion = wa.do_authentication(options, credential_id);
    h.passkey
        .finish_authentication(challenge_id, &assertion, context)
        .await
        .expect("finish login")
        .session
}

pub fn authenticator() -> ResidentAuthenticator {
    ResidentAuthenticator::new(&rp_origin())
}
