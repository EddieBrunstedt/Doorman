use std::sync::Arc;

use crate::audit::{AuditDispatch, AuditSink};
use crate::clock::{Clock, SystemClock};
use crate::context::CoreDeps;
use crate::destructive::DestructiveActions;
use crate::email::{DefaultEmailTemplates, EmailSender, EmailTemplates, Mailer};
use crate::email_link::LinkTemplates;
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::operator::OperatorManager;
use crate::passkey::{PasskeyConfig, PasskeyManager, build_webauthn};
use crate::passkey_registration::PasskeyRegistrations;
use crate::purge::PurgeSummary;
use crate::rate_limit::{RateLimitEnforcer, RateLimiting};
use crate::reauth::{ReauthManager, ReauthPolicy};
use crate::recovery::{RecoveryConfig, RecoveryManager};
use crate::security_notice::{NoticePolicy, SecurityNotices};
use crate::session::{SessionConfig, SessionManager};
use crate::session_records::SessionRecords;
use crate::signup::{SignupConfig, SignupManager};
use crate::storage::{ExpiringStores, Storage};
use crate::user::{UserConfig, UserManager};

#[derive(Debug, thiserror::Error)]
pub enum AssemblyError {
    #[error("passkey manager construction failed: {0}")]
    Passkey(crate::error::Error),
}

#[derive(Clone)]
pub struct AuthCore {
    pub sessions: SessionManager,
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub user: UserManager,
    pub operator: OperatorManager,
    expiring: ExpiringStores,
    clock: Arc<dyn Clock>,
}

impl AuthCore {
    pub fn builder(required: AuthCoreRequired) -> AuthCoreBuilder {
        AuthCoreBuilder::new(required)
    }

    pub async fn purge_expired(&self) -> PurgeSummary {
        self.expiring.purge_all_expired(self.clock.now()).await
    }
}

// Everything a core can't be built without, as fields, so the compiler names whatever a host leaves
// out.
pub struct AuthCoreRequired {
    pub storage: Storage,
    pub email_sender: Arc<dyn EmailSender>,
    pub audit_sink: Arc<dyn AuditSink>,
    pub passkey: PasskeyConfig,
    pub reauthentication: ReauthPolicy,
    pub rate_limiting: RateLimiting,
    pub links: LinkTemplates,
}

pub struct AuthCoreBuilder {
    required: AuthCoreRequired,
    clock: Option<Arc<dyn Clock>>,
    email_templates: Option<Arc<dyn EmailTemplates>>,
    metrics: Option<Arc<dyn MetricSink>>,
    session_config: Option<SessionConfig>,
    signup: Option<SignupConfig>,
    recovery: Option<RecoveryConfig>,
    user: Option<UserConfig>,
    notice_policy: Option<NoticePolicy>,
}

impl AuthCoreBuilder {
    fn new(required: AuthCoreRequired) -> Self {
        Self {
            required,
            clock: None,
            email_templates: None,
            metrics: None,
            session_config: None,
            signup: None,
            recovery: None,
            user: None,
            notice_policy: None,
        }
    }

    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn email_templates(mut self, templates: Arc<dyn EmailTemplates>) -> Self {
        self.email_templates = Some(templates);
        self
    }

    pub fn metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn session(mut self, config: SessionConfig) -> Self {
        self.session_config = Some(config);
        self
    }

    pub fn signup(mut self, config: SignupConfig) -> Self {
        self.signup = Some(config);
        self
    }

    pub fn recovery(mut self, config: RecoveryConfig) -> Self {
        self.recovery = Some(config);
        self
    }

    pub fn user(mut self, config: UserConfig) -> Self {
        self.user = Some(config);
        self
    }

    pub fn notice_policy(mut self, policy: NoticePolicy) -> Self {
        self.notice_policy = Some(policy);
        self
    }

    pub fn build(self) -> Result<AuthCore, AssemblyError> {
        let AuthCoreRequired {
            storage,
            email_sender,
            audit_sink,
            passkey: passkey_config,
            reauthentication: reauth_policy,
            rate_limiting,
            links,
        } = self.required;
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let audit = AuditDispatch::new(audit_sink, clock.clone());
        let rate_limits = RateLimitEnforcer::new(rate_limiting, audit.clone());
        let metrics: Arc<dyn MetricSink> = self
            .metrics
            .unwrap_or_else(|| Arc::new(NoopMetricSink) as Arc<dyn MetricSink>);
        let session_config = self.session_config.unwrap_or_default();

        let email_templates: Arc<dyn EmailTemplates> = self
            .email_templates
            .unwrap_or_else(|| Arc::new(DefaultEmailTemplates));
        let signup_config = self.signup.unwrap_or_default();
        let recovery_config = self.recovery.unwrap_or_default();
        let user_config = self.user.unwrap_or_default();

        let mailer = Mailer::new(email_sender, email_templates);
        let notices = SecurityNotices::new(
            mailer.clone(),
            storage.records.users.clone(),
            self.notice_policy.unwrap_or_default(),
        );

        let session_records = SessionRecords::new(
            storage.expiring.sessions.clone(),
            storage.expiring.dpop_proofs.clone(),
            clock.clone(),
            audit.clone(),
            session_config,
        );

        let webauthn = Arc::new(build_webauthn(&passkey_config).map_err(AssemblyError::Passkey)?);

        let expiring = storage.expiring.clone();
        let deps = CoreDeps::new(
            clock.clone(),
            audit,
            mailer,
            notices,
            rate_limits,
            session_records,
            storage,
        )
        .with_metrics(metrics);

        let reauth = ReauthManager::new(&deps, &passkey_config, webauthn.clone());

        let registrations = PasskeyRegistrations::new(
            &deps,
            &passkey_config,
            webauthn.clone(),
            recovery_config.cool_down,
        );

        let passkey = PasskeyManager::new(&deps, registrations.clone(), passkey_config, webauthn);

        let signup = SignupManager::new(&deps, registrations.clone(), links.signup, signup_config);

        let recovery = RecoveryManager::new(&deps, registrations, links.recovery, &recovery_config);

        let user = UserManager::new(&deps, links.email_change, user_config);

        let operator = OperatorManager::new(&deps, passkey.clone());

        let destructive = DestructiveActions::new(
            &deps,
            reauth.clone(),
            reauth_policy,
            passkey.clone(),
            user.clone(),
        );

        let sessions = SessionManager::new(&deps, passkey.clone(), reauth, destructive);

        Ok(AuthCore {
            sessions,
            passkey,
            signup,
            recovery,
            user,
            operator,
            expiring,
            clock,
        })
    }
}
