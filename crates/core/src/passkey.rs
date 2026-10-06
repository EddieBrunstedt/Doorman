use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationMetadata, CreationChallengeResponse, Credential, Passkey, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::assertion::{AssertionVerifier, VerifiedAssertion};
use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::challenge::{Login, PasskeyChallenge, RedeemedRegistration, Registration};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::SecurityEmailNotifier;
use crate::error::{Error, Result};
use crate::metrics::{MetricEvent, MetricSink};
use crate::rate_limit::{RateLimitPolicy, RateLimiter, enforce_rate_limit};
use crate::reauth::{ReauthAction, ReauthManager, ReauthProof};
use crate::recovery_cooldown::RecoveryCooldown;
use crate::redeem::Redeemer;
use crate::session::{IssuedSession, SessionContext, SessionManager};
use crate::storage::{
    PasskeyChallengeId, PasskeyCredentialStore, PasskeySummary, RegistrationPurpose, Session,
    StoredPasskey, User, UserId,
};
use crate::user::UserRecords;

#[derive(Debug, Clone, Copy)]
pub struct PasskeyRateLimits {
    pub authenticate_start_per_ip: Option<RateLimitPolicy>,
    pub authenticate_finish_per_ip: Option<RateLimitPolicy>,
    pub authenticate_finish_per_credential: Option<RateLimitPolicy>,
}

impl PasskeyRateLimits {
    pub const DEFAULT_START_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(60, Duration::from_secs(60));
    pub const DEFAULT_FINISH_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(60, Duration::from_secs(60));
    pub const DEFAULT_FINISH_PER_CREDENTIAL: RateLimitPolicy =
        RateLimitPolicy::new(30, Duration::from_secs(60));

    pub const fn disabled() -> Self {
        Self {
            authenticate_start_per_ip: None,
            authenticate_finish_per_ip: None,
            authenticate_finish_per_credential: None,
        }
    }
}

impl Default for PasskeyRateLimits {
    fn default() -> Self {
        Self {
            authenticate_start_per_ip: Some(Self::DEFAULT_START_PER_IP),
            authenticate_finish_per_ip: Some(Self::DEFAULT_FINISH_PER_IP),
            authenticate_finish_per_credential: Some(Self::DEFAULT_FINISH_PER_CREDENTIAL),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum EmailLinkRegistration {
    Signup,
    Recovery { cooldown: chrono::Duration },
}

impl EmailLinkRegistration {
    fn purpose(self) -> RegistrationPurpose {
        match self {
            Self::Signup => RegistrationPurpose::Signup,
            Self::Recovery { .. } => RegistrationPurpose::Recovery,
        }
    }

    // A user who has lost their passkeys may still sit at the cap, and recovery is their way back.
    fn enforces_credential_cap(self) -> bool {
        matches!(self, Self::Signup)
    }

    fn started_cooldown(self, now: DateTime<Utc>) -> RecoveryCooldown {
        match self {
            Self::Signup => RecoveryCooldown::NONE,
            Self::Recovery { cooldown } => RecoveryCooldown::start(now, cooldown),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_origin: Url,
    pub rp_name: String,
    pub additional_origins: Vec<Url>,
    pub challenge_lifetime: Duration,
    pub rate_limits: PasskeyRateLimits,
    pub max_credentials_per_user: Option<NonZeroU32>,
    pub max_pending_registrations_per_user: Option<NonZeroU32>,
}

impl PasskeyConfig {
    pub const DEFAULT_CHALLENGE_LIFETIME: Duration = Duration::from_secs(300);

    pub fn new(rp_id: impl Into<String>, rp_origin: Url, rp_name: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_origin,
            rp_name: rp_name.into(),
            additional_origins: Vec::new(),
            challenge_lifetime: Self::DEFAULT_CHALLENGE_LIFETIME,
            rate_limits: PasskeyRateLimits::default(),
            max_credentials_per_user: None,
            max_pending_registrations_per_user: None,
        }
    }

    pub fn from_origin(rp_origin: Url, rp_name: impl Into<String>) -> Result<Self> {
        let rp_id = rp_origin.host_str().ok_or_else(|| {
            Error::InvalidRelyingParty(format!("origin {rp_origin} has no host to use as rp_id"))
        })?;
        Ok(Self::new(rp_id.to_owned(), rp_origin.clone(), rp_name))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticationOutcome {
    pub user: User,
    pub session: IssuedSession,
}

#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    pub user: User,
    pub session: IssuedSession,
    pub passkey: StoredPasskey,
}

#[derive(Clone)]
pub struct PasskeyManager {
    records: UserRecords,
    credentials: Arc<dyn PasskeyCredentialStore>,
    registrations: PasskeyChallenge<Registration>,
    logins: PasskeyChallenge<Login>,
    assertions: AssertionVerifier,
    sessions: SessionManager,
    reauth: ReauthManager,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    notifier: SecurityEmailNotifier,
    rate_limiter: Arc<dyn RateLimiter>,
    metrics: Arc<dyn MetricSink>,
    webauthn: Arc<Webauthn>,
    config: PasskeyConfig,
}

impl PasskeyManager {
    pub(crate) fn new(deps: &CoreDeps, config: PasskeyConfig, webauthn: Arc<Webauthn>) -> Self {
        fn challenge<P>(
            deps: &CoreDeps,
            config: &PasskeyConfig,
            webauthn: &Arc<Webauthn>,
        ) -> PasskeyChallenge<P> {
            PasskeyChallenge::new(
                config,
                webauthn.clone(),
                deps.passkey_challenges.clone(),
                deps.passkey_credentials.clone(),
                Redeemer::from_deps(deps),
                deps.clock.clone(),
            )
        }
        Self {
            records: UserRecords::new(deps),
            credentials: deps.passkey_credentials.clone(),
            registrations: challenge(deps, &config, &webauthn),
            logins: challenge(deps, &config, &webauthn),
            assertions: AssertionVerifier::new(
                webauthn.clone(),
                deps.users.clone(),
                deps.passkey_credentials.clone(),
                deps.clock.clone(),
            ),
            sessions: deps.sessions.clone(),
            reauth: deps.reauth.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            notifier: deps.notifier.clone(),
            rate_limiter: deps.rate_limiter.clone(),
            metrics: deps.metrics.clone(),
            webauthn,
            config,
        }
    }

    #[tracing::instrument(skip(self, session), fields(method = "passkey", user_id = %session.user_id))]
    pub async fn start_registration(
        &self,
        session: &Session,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let cooldown = RecoveryCooldown::of_session(session, self.clock.now());
        self.issue_registration(session.user_id, RegistrationPurpose::AddPasskey, cooldown)
            .await
    }

    async fn issue_registration(
        &self,
        user_id: UserId,
        purpose: RegistrationPurpose,
        cooldown: RecoveryCooldown,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let user = self.records.find_active(user_id).await?;
        let (id, ccr) = self.registrations.issue(&user, purpose, cooldown).await?;
        tracing::info!(outcome = "started", "passkey registration started");
        Ok((id, ccr))
    }

    #[tracing::instrument(
        skip(self, response, name, context),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub async fn finish_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<StoredPasskey> {
        let registration = self
            .redeem_registration(challenge_id, RegistrationPurpose::AddPasskey, &context)
            .await?;
        self.enforce_credential_cap(registration.user.id).await?;
        let credential =
            self.verify_registration(&registration, response, name, registration.cooldown)?;
        self.store_credential(&registration.user, credential, &context)
            .await
    }

    pub(crate) async fn start_email_link_registration(
        &self,
        user_id: UserId,
        registration: EmailLinkRegistration,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.registrations.invalidate_pending(user_id).await?;
        let cooldown = registration.started_cooldown(self.clock.now());
        self.issue_registration(user_id, registration.purpose(), cooldown)
            .await
    }

    pub(crate) async fn finish_email_link_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        registration: EmailLinkRegistration,
    ) -> Result<RegistrationOutcome> {
        let started = registration.started_cooldown(self.clock.now());

        let redeemed = self
            .redeem_registration(challenge_id, registration.purpose(), &context)
            .await?;
        let user = &redeemed.user;
        if registration.enforces_credential_cap() {
            self.enforce_credential_cap(user.id).await?;
        }
        let cooldown = redeemed.cooldown.extended_by(started);
        let credential = self.verify_registration(&redeemed, response, name, cooldown)?;
        // Registrations started before the recovery may belong to whoever holds the lost passkey.
        if let EmailLinkRegistration::Recovery { .. } = registration {
            self.registrations.invalidate_pending(user.id).await?;
        }
        let passkey = self.store_credential(user, credential, &context).await?;
        let session = self
            .sessions
            .issue(user.id, context.clone(), cooldown)
            .await?;
        self.audit
            .emit(
                &context,
                AuditEventKind::LoginSucceeded { user_id: user.id },
            )
            .await;

        Ok(RegistrationOutcome {
            user: redeemed.user,
            session,
            passkey,
        })
    }

    async fn redeem_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        purpose: RegistrationPurpose,
        context: &SessionContext,
    ) -> Result<RedeemedRegistration> {
        let registration = self
            .registrations
            .redeem(challenge_id, purpose, context)
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(registration.user.id));
        Ok(registration)
    }

    async fn enforce_credential_cap(&self, user_id: UserId) -> Result<()> {
        let Some(max) = self.config.max_credentials_per_user else {
            return Ok(());
        };
        let count = self.credentials.count_passkeys_for_user(user_id).await?;
        if count >= u64::from(max.get()) {
            tracing::warn!(%user_id, max = max.get(), "passkey registration rejected: credential cap reached");
            return Err(Error::ResourceLimitExceeded {
                resource: "credentials",
                limit: max.get(),
            });
        }
        Ok(())
    }

    fn verify_registration(
        &self,
        registration: &RedeemedRegistration,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        cooldown: RecoveryCooldown,
    ) -> Result<StoredPasskey> {
        let user_id = registration.user.id;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &registration.state)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let metadata = PasskeyMetadata::from_passkey(&passkey);
        if !metadata.user_verified {
            tracing::warn!(%user_id, outcome = "user_verification_missing", "passkey registration failed");
            return Err(Error::UserVerificationRequired);
        }
        Ok(StoredPasskey {
            credential_id: passkey.cred_id().to_vec(),
            user_id,
            passkey: encode_credential(&passkey)?,
            name,
            created_at: self.clock.now(),
            last_used_at: None,
            aaguid: metadata.aaguid,
            transports: metadata.transports,
            backup_eligible: metadata.backup_eligible,
            backup_state: metadata.backup_state,
            recovery_cooldown_until: cooldown.until(),
        })
    }

    async fn store_credential(
        &self,
        user: &User,
        credential: StoredPasskey,
        context: &SessionContext,
    ) -> Result<StoredPasskey> {
        self.credentials.add_passkey(credential.clone()).await?;

        self.audit
            .emit(
                context,
                AuditEventKind::CredentialAdded { user_id: user.id },
            )
            .await;
        self.notifier
            .passkey_registered(user, credential.name.as_deref())
            .await;
        Ok(credential)
    }

    #[tracing::instrument(skip(self, context), fields(method = "passkey"))]
    pub async fn start_authentication(
        &self,
        context: SessionContext,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        enforce_rate_limit(
            self.rate_limiter.as_ref(),
            self.config.rate_limits.authenticate_start_per_ip,
            "passkey/authenticate/start",
            "ip",
            context.ip.as_deref(),
        )
        .await?;

        let (id, rcr) = self.logins.issue().await?;
        tracing::info!(outcome = "started", "passkey authentication started");
        Ok((id, rcr))
    }

    #[tracing::instrument(
        skip(self, response, context),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub async fn finish_authentication(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &PublicKeyCredential,
        context: SessionContext,
    ) -> Result<AuthenticationOutcome> {
        let _latency = AuthLatencyGuard::start(self.metrics.clone());

        let credential_dim = URL_SAFE_NO_PAD.encode(response.raw_id.as_ref());
        enforce_rate_limit(
            self.rate_limiter.as_ref(),
            self.config.rate_limits.authenticate_finish_per_ip,
            "passkey/authenticate/finish",
            "ip",
            context.ip.as_deref(),
        )
        .await?;
        enforce_rate_limit(
            self.rate_limiter.as_ref(),
            self.config.rate_limits.authenticate_finish_per_credential,
            "passkey/authenticate/finish",
            "credential",
            Some(credential_dim.as_str()),
        )
        .await?;

        let pending = self.logins.redeem(challenge_id, &context).await?;

        let VerifiedAssertion { user, passkey } =
            match self.assertions.verify(pending, response).await? {
                Ok(verified) => verified,
                Err(refusal) => {
                    self.metrics.record(MetricEvent::AuthFailed {
                        reason: refusal.reason,
                    });
                    self.audit
                        .emit(
                            &context,
                            AuditEventKind::AuthenticationFailed {
                                user_id: refusal.user_id,
                                reason: refusal.reason,
                            },
                        )
                        .await;
                    return Err(refusal.error);
                }
            };
        let user_id = user.id;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));

        let cooldown = RecoveryCooldown::of_passkey(&passkey, self.clock.now());

        let session = self
            .sessions
            .issue(user_id, context.clone(), cooldown)
            .await?;
        self.metrics.record(MetricEvent::LoginSucceeded);
        self.audit
            .emit(&context, AuditEventKind::LoginSucceeded { user_id })
            .await;
        Ok(AuthenticationOutcome { user, session })
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_passkeys(&self, user_id: UserId) -> Result<Vec<StoredPasskey>> {
        Ok(self.credentials.list_passkeys_for_user(user_id).await?)
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn count_passkeys(&self, user_id: UserId) -> Result<u64> {
        Ok(self.credentials.count_passkeys_for_user(user_id).await?)
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_passkey_summaries(&self, user_id: UserId) -> Result<Vec<PasskeySummary>> {
        Ok(self
            .credentials
            .list_passkey_summaries_for_user(user_id)
            .await?)
    }

    #[tracing::instrument(skip(self, session, credential_id, reauth, context), fields(user_id = %session.user_id))]
    pub async fn remove_passkey(
        &self,
        session: &Session,
        credential_id: &[u8],
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        self.reauth
            .ensure(
                ReauthAction::RemovePasskey,
                session,
                reauth.as_ref(),
                &context,
            )
            .await?;
        let user_id = session.user_id;
        self.remove_passkey_for(
            user_id,
            credential_id,
            Actor::from(&context),
            PasskeyRemovalNotice::SelfService,
        )
        .await
    }

    #[tracing::instrument(skip(self, session, credential_id, name, context), fields(user_id = %session.user_id))]
    pub async fn rename_passkey(
        &self,
        session: &Session,
        credential_id: &[u8],
        name: Option<String>,
        context: SessionContext,
    ) -> Result<StoredPasskey> {
        let user_id = session.user_id;
        let mut credential =
            find_owned_passkey(self.credentials.as_ref(), user_id, credential_id).await?;
        self.credentials
            .set_passkey_name(credential_id, name.as_deref())
            .await?;
        credential.name = name;
        self.audit
            .emit(&context, AuditEventKind::CredentialRenamed { user_id })
            .await;
        Ok(credential)
    }

    pub(crate) async fn remove_passkey_for(
        &self,
        user_id: UserId,
        credential_id: &[u8],
        actor: Actor,
        notice: PasskeyRemovalNotice,
    ) -> Result<()> {
        let credential =
            find_owned_passkey(self.credentials.as_ref(), user_id, credential_id).await?;
        self.credentials.delete_passkey(credential_id).await?;
        self.audit
            .emit(actor, AuditEventKind::CredentialRemoved { user_id })
            .await;
        if notice.sends()
            && let Some(user) = self
                .records
                .find_for_notification(user_id, "passkey removed")
                .await
        {
            match notice {
                PasskeyRemovalNotice::SelfService => {
                    self.notifier
                        .passkey_removed(&user, credential.name.as_deref())
                        .await;
                }
                PasskeyRemovalNotice::Operator => {
                    self.notifier
                        .operator_passkey_removed(&user, credential.name.as_deref())
                        .await;
                }
                PasskeyRemovalNotice::Suppressed => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyRemovalNotice {
    SelfService,
    Operator,
    Suppressed,
}

impl PasskeyRemovalNotice {
    fn sends(self) -> bool {
        matches!(self, Self::SelfService | Self::Operator)
    }
}

pub(crate) async fn find_owned_passkey(
    credentials: &dyn PasskeyCredentialStore,
    user_id: UserId,
    credential_id: &[u8],
) -> Result<StoredPasskey> {
    let Some(credential) = credentials
        .find_passkey_by_credential_id(credential_id)
        .await?
    else {
        tracing::warn!(
            outcome = "credential_not_found",
            "passkey ownership check failed"
        );
        return Err(Error::PasskeyNotFound);
    };
    if credential.user_id != user_id {
        tracing::warn!(
            outcome = "ownership_mismatch",
            "passkey ownership check failed"
        );
        return Err(Error::PasskeyOwnershipMismatch);
    }
    Ok(credential)
}

struct AuthLatencyGuard {
    metrics: Arc<dyn MetricSink>,
    started: Instant,
}

impl AuthLatencyGuard {
    fn start(metrics: Arc<dyn MetricSink>) -> Self {
        Self {
            metrics,
            started: Instant::now(),
        }
    }
}

impl Drop for AuthLatencyGuard {
    fn drop(&mut self) {
        self.metrics
            .record(MetricEvent::AuthLatency(self.started.elapsed()));
    }
}

pub(crate) struct PasskeyMetadata {
    aaguid: Option<Uuid>,
    transports: Vec<String>,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    user_verified: bool,
}

impl PasskeyMetadata {
    pub(crate) fn from_passkey(passkey: &Passkey) -> Self {
        let cred: Credential = passkey.clone().into();
        let aaguid = match cred.attestation.metadata {
            AttestationMetadata::Packed { aaguid } | AttestationMetadata::Tpm { aaguid, .. } => {
                Some(aaguid)
            }
            _ => None,
        };
        let transports = cred
            .transports
            .unwrap_or_default()
            .iter()
            .map(|t| t.to_string())
            .collect();
        Self {
            aaguid,
            transports,
            backup_eligible: cred.backup_eligible,
            backup_state: cred.backup_state,
            user_verified: cred.user_verified,
        }
    }
}

pub(crate) fn build_webauthn(config: &PasskeyConfig) -> Result<Webauthn> {
    let mut builder = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
        .map_err(|e| Error::InvalidRelyingParty(e.to_string()))?
        .rp_name(&config.rp_name);
    for origin in &config.additional_origins {
        builder = builder.append_allowed_origin(origin);
    }
    builder
        .build()
        .map_err(|e| Error::InvalidRelyingParty(e.to_string()))
}

pub(crate) fn encode_credential(passkey: &Passkey) -> Result<Vec<u8>> {
    serde_json::to_vec(passkey).map_err(|e| Error::Internal(format!("serialise credential: {e}")))
}

pub(crate) fn decode_credential(bytes: &[u8]) -> Result<Passkey> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Internal(format!("deserialise credential: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn config_constructor_sets_default_lifetime() {
        let c = PasskeyConfig::new(
            "example.com",
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        );
        assert_eq!(c.challenge_lifetime, Duration::from_secs(300));
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.rp_name, "Example");
    }

    #[test]
    fn from_origin_derives_rp_id_from_host() {
        let c = PasskeyConfig::from_origin(
            Url::parse("https://app.example.com:8443/auth").expect("valid url"),
            "Example",
        )
        .expect("origin has a host");
        assert_eq!(c.rp_id, "app.example.com");
        assert_eq!(c.rp_name, "Example");
        assert_eq!(c.challenge_lifetime, Duration::from_secs(300));
    }

    #[test]
    fn config_defaults_to_no_additional_origins() {
        let c = PasskeyConfig::new(
            "example.com",
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        );
        assert!(c.additional_origins.is_empty());
    }

    #[test]
    fn build_webauthn_trusts_only_the_primary_origin_by_default() {
        let config = PasskeyConfig::from_origin(
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        )
        .expect("origin has a host");

        let webauthn = build_webauthn(&config).expect("webauthn builds");
        assert_eq!(webauthn.get_allowed_origins(), &[config.rp_origin]);
    }

    #[test]
    fn build_webauthn_trusts_additional_origins() {
        let mut config = PasskeyConfig::from_origin(
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        )
        .expect("origin has a host");
        let related = Url::parse("https://example.co.uk").expect("valid url");
        config.additional_origins = vec![related.clone()];

        let webauthn = build_webauthn(&config).expect("webauthn builds");
        let allowed = webauthn.get_allowed_origins();
        assert!(
            allowed.contains(&config.rp_origin),
            "the primary origin stays trusted"
        );
        assert!(
            allowed.contains(&related),
            "an additional origin becomes trusted"
        );
    }

    #[test]
    fn build_webauthn_trusts_a_native_app_origin() {
        let mut config = PasskeyConfig::from_origin(
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        )
        .expect("origin has a host");
        let android = Url::parse("android:apk-key-hash:pNxxqHowXQk").expect("valid url");
        assert_eq!(android.host_str(), None, "the app origin is hostless");
        config.additional_origins = vec![android.clone()];

        let webauthn = build_webauthn(&config).expect("webauthn builds");
        assert!(
            webauthn.get_allowed_origins().contains(&android),
            "the native-app origin becomes trusted"
        );
    }

    #[test]
    fn from_origin_rejects_hostless_origin() {
        let err = PasskeyConfig::from_origin(
            Url::parse("data:text/plain,hi").expect("valid url"),
            "Example",
        )
        .expect_err("hostless origin must be rejected");
        assert!(matches!(err, Error::InvalidRelyingParty(_)));
    }
}
