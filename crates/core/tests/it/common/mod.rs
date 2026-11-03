use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Barrier;

use chrono::{DateTime, TimeZone, Utc};
use doorman_core::assembly::{AuthCore, AuthCoreRequired};
use doorman_core::audit::{
    AuditEvent, AuditEventKind, AuditSink, OperatorActor, RedemptionFailureReason, SecretKind,
};
use doorman_core::clock::Clock;
use doorman_core::email::{DefaultEmailTemplates, EmailSender, EmailTemplates};
use doorman_core::email_link::{LinkTemplate, LinkTemplates};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::memory::{
    InMemoryDpopProofStore, InMemoryEmailLinkStore, InMemoryPasskeyChallengeStore,
    InMemoryPasskeyStore, InMemorySessionStore, InMemoryUserStore,
};
use doorman_core::metrics::MetricSink;
use doorman_core::operator::OperatorManager;
use doorman_core::passkey::{PasskeyConfig, PasskeyManager};
use doorman_core::rate_limit::RateLimiting;
use doorman_core::reauth::ReauthPolicy;
use doorman_core::recovery::{RecoveryConfig, RecoveryManager};
use doorman_core::security_notice::NoticePolicy;
use doorman_core::session::hash_token;
use doorman_core::session::{
    IssuedSession, RequestTransport, ResolvedSession, SessionConfig, SessionContext, SessionExpiry,
    SessionManager,
};
use doorman_core::signup::{SignupConfig, SignupManager};
use doorman_core::storage::{
    EmailLink, EmailLinkStore, ExpiringStores, PasskeyChallengeId, PasskeyChallengeStore,
    PasskeyStore, PasskeyUse, RecordStores, Session, SessionId, SessionStore, SessionTransport,
    Storage, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash,
    User, UserId, UserStatus, UserStore,
};
use doorman_core::user::UserManager;
pub use doorman_test_support::token_from_email;
use doorman_test_support::{
    CLIENT_IP, CapturingEmailSender, CapturingMetrics, InMemoryAuditSink, MockClock, lifetime,
    request_context,
};
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

pub fn operator() -> OperatorActor {
    OperatorActor::new("support-agent-7", None, None, None).expect("operator actor")
}

pub fn link_templates() -> LinkTemplates {
    LinkTemplates {
        signup: LinkTemplate::parse(SIGNUP_URL).expect("signup link template"),
        recovery: LinkTemplate::parse(RECOVERY_URL).expect("recovery link template"),
        email_change: LinkTemplate::parse(USER_URL).expect("email change link template"),
    }
}

pub struct CountingUserStore {
    inner: Arc<InMemoryUserStore>,
    reads: AtomicUsize,
    create_hold: Mutex<Option<(Arc<Barrier>, usize)>>,
    signup_mark_hold: WriteHold,
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

    pub fn hold_next_signup_mark(&self) -> Arc<Barrier> {
        self.signup_mark_hold.hold_next()
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
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        self.inner.set_user_email(id, email, at).await
    }

    async fn mark_signed_up(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        self.signup_mark_hold.pass().await;
        self.inner.mark_signed_up(id, at).await
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        self.inner.delete_user(id).await
    }
}

// Holds the next write until the test has done something meanwhile.
#[derive(Default)]
pub struct WriteHold(Mutex<Option<Arc<Barrier>>>);

impl WriteHold {
    fn hold_next(&self) -> Arc<Barrier> {
        let barrier = Arc::new(Barrier::new(2));
        *self.0.lock().expect("write hold lock") = Some(barrier.clone());
        barrier
    }

    async fn pass(&self) {
        let barrier = self.0.lock().expect("write hold lock").take();
        if let Some(barrier) = barrier {
            // The first wait tells the test the write is due; the second lets it through.
            barrier.wait().await;
            barrier.wait().await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LockOut {
    Disable,
    Delete,
}

pub const LOCK_OUTS: [LockOut; 2] = [LockOut::Disable, LockOut::Delete];

// Runs `flow` with the lock-out landing, from another process, while the held write waits.
pub async fn locked_out_during<T>(
    h: &Harness,
    held: Arc<Barrier>,
    lock_out: LockOut,
    user_id: UserId,
    flow: impl Future<Output = T>,
) -> T {
    let other = h.another_process();
    let (out, ()) = within_deadline(async {
        tokio::join!(flow, async {
            held.wait().await;
            match lock_out {
                LockOut::Disable => other.operator.disable(user_id, operator()).await,
                LockOut::Delete => other.operator.delete_user(user_id, operator()).await,
            }
            .expect("lock out");
            held.wait().await;
        })
    })
    .await;
    out
}

pub struct CountingSessionStore {
    inner: Arc<InMemorySessionStore>,
    reads: AtomicUsize,
    failing_reads: AtomicBool,
    write_hold: WriteHold,
}

impl CountingSessionStore {
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    pub fn clear_reads(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }

    pub fn hold_next_session_write(&self) -> Arc<Barrier> {
        self.write_hold.hold_next()
    }

    pub fn fail_reads(&self) {
        self.failing_reads.store(true, Ordering::SeqCst);
    }

    fn read(&self) -> StorageResult<()> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.failing_reads.load(Ordering::SeqCst) {
            return Err(StorageError::msg("session store unavailable"));
        }
        Ok(())
    }
}

#[async_trait]
impl SessionStore for CountingSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.write_hold.pass().await;
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
        self.read()?;
        self.inner.find_session_by_token_hash(hash).await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        self.read()?;
        self.inner.find_session_by_id(id).await
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        self.read()?;
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

pub struct HeldEmailLinkStore {
    inner: Arc<InMemoryEmailLinkStore>,
    write_hold: WriteHold,
}

impl HeldEmailLinkStore {
    pub fn hold_next_link_write(&self) -> Arc<Barrier> {
        self.write_hold.hold_next()
    }
}

#[async_trait]
impl EmailLinkStore for HeldEmailLinkStore {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        self.write_hold.pass().await;
        self.inner.replace_link(link).await
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        self.inner.redeem_link(hash).await
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.inner.delete_links_for_user(user_id).await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        self.inner.purge_expired(now).await
    }
}

pub struct HeldPasskeyStore {
    inner: Arc<InMemoryPasskeyStore>,
    write_hold: WriteHold,
}

impl HeldPasskeyStore {
    pub fn hold_next_passkey_write(&self) -> Arc<Barrier> {
        self.write_hold.hold_next()
    }
}

#[async_trait]
impl PasskeyStore for HeldPasskeyStore {
    async fn add_passkey(&self, passkey: StoredPasskey) -> StorageResult<()> {
        self.write_hold.pass().await;
        self.inner.add_passkey(passkey).await
    }

    async fn record_passkey_use(
        &self,
        credential_id: &[u8],
        used: PasskeyUse,
    ) -> StorageResult<()> {
        self.inner.record_passkey_use(credential_id, used).await
    }

    async fn set_passkey_name(
        &self,
        credential_id: &[u8],
        name: Option<&str>,
    ) -> StorageResult<()> {
        self.inner.set_passkey_name(credential_id, name).await
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        self.inner.list_passkeys_for_user(user_id).await
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        self.inner
            .find_passkey_by_credential_id(credential_id)
            .await
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        self.inner.delete_passkey(credential_id).await
    }

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.inner.delete_passkeys_for_user(user_id).await
    }
}

pub struct HeldPasskeyChallengeStore {
    inner: Arc<InMemoryPasskeyChallengeStore>,
    write_hold: WriteHold,
}

impl HeldPasskeyChallengeStore {
    pub fn hold_next_registration_write(&self) -> Arc<Barrier> {
        self.write_hold.hold_next()
    }
}

#[async_trait]
impl PasskeyChallengeStore for HeldPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        self.write_hold.pass().await;
        self.inner.put_registration(value).await
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        self.inner.take_registration(id).await
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        self.inner.delete_registrations_for_user(user_id).await
    }

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>> {
        self.inner.list_registrations_for_user(user_id).await
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        self.inner.put_authentication(value).await
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        self.inner.take_authentication(id).await
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
    pub email_links: Arc<InMemoryEmailLinkStore>,
    pub email_link_store: Arc<HeldEmailLinkStore>,
    pub passkeys: Arc<InMemoryPasskeyStore>,
    pub passkey_store: Arc<HeldPasskeyStore>,
    pub challenges: Arc<InMemoryPasskeyChallengeStore>,
    pub challenge_store: Arc<HeldPasskeyChallengeStore>,
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
        self.another_process_with(self.session_config.clone())
    }

    pub fn another_process_with(&self, session_config: SessionConfig) -> AuthCore {
        AuthCore::builder(AuthCoreRequired {
            storage: self.storage.clone(),
            email_sender: self.email.clone() as Arc<dyn EmailSender>,
            audit_sink: self.audit.clone() as Arc<dyn AuditSink>,
            passkey: PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
            reauthentication: ReauthPolicy::disabled(),
            rate_limiting: RateLimiting::Disabled,
            links: link_templates(),
        })
        .clock(self.clock.clone() as Arc<dyn Clock>)
        .session(session_config)
        .build()
        .expect("another process assembles")
    }
}

pub struct HarnessBuilder {
    signup: SignupConfig,
    recovery: RecoveryConfig,
    session_config: SessionConfig,
    passkey: PasskeyConfig,
    rate_limiting: RateLimiting,
    email_templates: Arc<dyn EmailTemplates>,
    notice_policy: NoticePolicy,
    reauth_policy: ReauthPolicy,
}

impl HarnessBuilder {
    pub fn new() -> Self {
        Self {
            signup: SignupConfig::default(),
            recovery: RecoveryConfig::default(),
            session_config: SessionConfig {
                expiry: SessionExpiry::absolute(lifetime(Duration::from_secs(60 * 60))),
                ..SessionConfig::default()
            },
            passkey: PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
            rate_limiting: RateLimiting::Disabled,
            email_templates: Arc::new(DefaultEmailTemplates),
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

    pub fn email_templates(mut self, templates: Arc<dyn EmailTemplates>) -> Self {
        self.email_templates = templates;
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

    pub fn rate_limiting(mut self, rate_limiting: RateLimiting) -> Self {
        self.rate_limiting = rate_limiting;
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
        let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let email_links: Arc<InMemoryEmailLinkStore> = Arc::new(InMemoryEmailLinkStore::new());
        let passkeys: Arc<InMemoryPasskeyStore> = Arc::new(InMemoryPasskeyStore::new());
        let challenges: Arc<InMemoryPasskeyChallengeStore> =
            Arc::new(InMemoryPasskeyChallengeStore::new());
        let dpop_proofs: Arc<InMemoryDpopProofStore> = Arc::new(InMemoryDpopProofStore::new());
        let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
        let email: Arc<CapturingEmailSender> = Arc::new(CapturingEmailSender::new());
        let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
        let metrics: Arc<CapturingMetrics> = Arc::new(CapturingMetrics::new());

        let user_store = Arc::new(CountingUserStore {
            inner: users.clone(),
            reads: AtomicUsize::new(0),
            create_hold: Mutex::new(None),
            signup_mark_hold: WriteHold::default(),
        });
        let session_store = Arc::new(CountingSessionStore {
            inner: sessions.clone(),
            reads: AtomicUsize::new(0),
            failing_reads: AtomicBool::new(false),
            write_hold: WriteHold::default(),
        });
        let email_link_store = Arc::new(HeldEmailLinkStore {
            inner: email_links.clone(),
            write_hold: WriteHold::default(),
        });
        let passkey_store = Arc::new(HeldPasskeyStore {
            inner: passkeys.clone(),
            write_hold: WriteHold::default(),
        });
        let challenge_store = Arc::new(HeldPasskeyChallengeStore {
            inner: challenges.clone(),
            write_hold: WriteHold::default(),
        });

        let storage = Storage {
            records: RecordStores {
                users: user_store.clone(),
                passkeys: passkey_store.clone(),
            },
            expiring: ExpiringStores {
                sessions: session_store.clone(),
                email_links: email_link_store.clone(),
                passkey_challenges: challenge_store.clone(),
                dpop_proofs,
            },
        };

        let core = AuthCore::builder(AuthCoreRequired {
            storage: storage.clone(),
            email_sender: email.clone() as Arc<dyn EmailSender>,
            audit_sink: audit.clone() as Arc<dyn AuditSink>,
            passkey: self.passkey,
            reauthentication: self.reauth_policy,
            rate_limiting: self.rate_limiting,
            links: link_templates(),
        })
        .clock(clock.clone() as Arc<dyn Clock>)
        .email_templates(self.email_templates)
        .metrics(metrics.clone() as Arc<dyn MetricSink>)
        .session(self.session_config.clone())
        .signup(self.signup)
        .recovery(self.recovery)
        .notice_policy(self.notice_policy)
        .build()
        .expect("harness assembles");

        Harness {
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
            email_links,
            email_link_store,
            passkeys,
            passkey_store,
            challenges,
            challenge_store,
            storage,
            audit,
            email,
            clock,
            metrics,
            session_config: self.session_config,
        }
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
        signed_up_at: Some(now),
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
            transport: SessionTransport::Cookie,
            created_at: now,
            last_used_at: now,
            // Outlives any recovery cool-down a test sets, as a real session outlives the default one.
            expires_at: now + chrono::Duration::days(30),
            ip: CLIENT_IP.parse().expect("ip"),
            user_agent: None,
            recovery_cool_down_until: cool_down,
        })
        .await
        .expect("store session");
    h.session_manager
        .resolve(&token, &RequestTransport::Cookie)
        .await
        .expect("resolve")
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
        .start_passkey_registration(&session, request_context())
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
            request_context(),
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
        .request_signup(email, None, request_context())
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
        .redeem_signup_link(&token, request_context())
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
            RequestTransport::Cookie,
            request_context(),
        )
        .await
        .expect("signup finish");
    outcome.user
}

pub struct LoggedInUser {
    pub user: User,
    pub authenticator: ResidentAuthenticator,
    pub credential_id: Vec<u8>,
    pub session: IssuedSession,
}

impl LoggedInUser {
    pub async fn log_in_again(&mut self, h: &Harness) -> IssuedSession {
        log_in(
            h,
            &mut self.authenticator,
            &self.credential_id,
            request_context(),
        )
        .await
    }
}

pub async fn logged_in_user(h: &Harness, email: &str) -> LoggedInUser {
    logged_in_user_from(h, email, request_context()).await
}

pub async fn logged_in_user_from(
    h: &Harness,
    email: &str,
    context: SessionContext,
) -> LoggedInUser {
    let user = make_user(h, email).await;
    let mut authenticator = authenticator();
    let passkey = register_passkey(h, user.id, &mut authenticator, None).await;
    let session = log_in(h, &mut authenticator, &passkey.credential_id, context).await;
    LoggedInUser {
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
        .finish_authentication(challenge_id, &assertion, RequestTransport::Cookie, context)
        .await
        .expect("finish login")
        .session
}

pub fn authenticator() -> ResidentAuthenticator {
    ResidentAuthenticator::new(&rp_origin())
}
