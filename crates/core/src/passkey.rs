use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationMetadata, CreationChallengeResponse, Credential, CredentialID,
    DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::assertion::{AssertionVerifier, PendingAssertion, VerifiedAssertion};
use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind, AuthFailureReason};
use crate::clock::{Clock, expiry};
use crate::context::CoreDeps;
use crate::email::SecurityEmailNotifier;
use crate::error::{Error, Result};
use crate::metrics::{MetricEvent, MetricSink};
use crate::rate_limit::{RateLimitPolicy, RateLimiter, enforce_rate_limit};
use crate::reauth::{ReauthAction, ReauthManager, ReauthProof};
use crate::redeem::{RedeemedRegistration, Redeemer};
use crate::session::{IssuedSession, SessionContext, SessionManager};
use crate::storage::{
    AuthenticationPurpose, PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore,
    PasskeySummary, Session, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration,
    User, UserId,
};
use crate::user::UserRecords;
use crate::verification::EnrollmentOutcome;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialCap {
    Enforce,
    Exempt,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EnrollmentPolicy {
    pub cooldown: Option<chrono::Duration>,
    pub credential_cap: CredentialCap,
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

#[derive(Clone)]
pub struct PasskeyManager {
    records: UserRecords,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    redeemer: Redeemer,
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
        Self {
            records: UserRecords::new(deps),
            credentials: deps.passkey_credentials.clone(),
            challenges: deps.passkey_challenges.clone(),
            redeemer: Redeemer::from_deps(deps),
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
        let cooldown_until = session.active_recovery_cooldown_until(self.clock.now());
        self.start_registration_inner(session.user_id, cooldown_until)
            .await
    }

    async fn start_registration_inner(
        &self,
        user_id: UserId,
        recovery_cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let user = self.records.find_active(user_id).await?;

        if let Some(max) = self.config.max_pending_registrations_per_user {
            let pending = self
                .challenges
                .count_registrations_for_user(user_id)
                .await?;
            if pending >= u64::from(max.get()) {
                tracing::warn!(%user_id, max = max.get(), "passkey registration rejected: too many pending challenges");
                return Err(Error::ResourceLimitExceeded {
                    resource: "pending registrations",
                    limit: max.get(),
                });
            }
        }

        let display_name = display_name_for(&user);

        let existing = self.credentials.list_passkeys_for_user(user_id).await?;
        let exclude = if existing.is_empty() {
            None
        } else {
            Some(
                existing
                    .iter()
                    .map(|c| CredentialID::from(c.credential_id.clone()))
                    .collect(),
            )
        };

        let (mut ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_id.0, &display_name, &display_name, exclude)
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        require_discoverable_credential(&mut ccr)?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        let stored = StoredPasskeyRegistration {
            id,
            user_id,
            state: encode_registration_state(&reg_state)?,
            created_at: now,
            expires_at: expiry(now, self.config.challenge_lifetime)?,
            recovery_cooldown_until,
        };
        self.challenges.put_registration(stored).await?;
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
        let registration = self.redeem_registration(challenge_id, &context).await?;
        self.enforce_credential_cap(registration.user.id).await?;
        let credential = self.verify_registration(&registration, response, name, None)?;
        self.store_credential(&registration.user, credential, &context)
            .await
    }

    pub(crate) async fn start_enrollment(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.invalidate_pending_registrations(user_id).await?;
        self.start_registration_inner(user_id, None).await
    }

    pub(crate) async fn enroll(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        policy: EnrollmentPolicy,
    ) -> Result<EnrollmentOutcome> {
        let cooldown_until = policy.cooldown.map(|cooldown| {
            self.clock
                .now()
                .checked_add_signed(cooldown)
                .unwrap_or(DateTime::<Utc>::MAX_UTC)
        });

        let registration = self.redeem_registration(challenge_id, &context).await?;
        let user = &registration.user;
        if policy.credential_cap == CredentialCap::Enforce {
            self.enforce_credential_cap(user.id).await?;
        }
        let credential = self.verify_registration(&registration, response, name, cooldown_until)?;
        if cooldown_until.is_some() {
            self.invalidate_pending_registrations(user.id).await?;
        }
        let passkey = self.store_credential(user, credential, &context).await?;
        let session = self
            .sessions
            .issue(user.id, context, cooldown_until)
            .await?;

        Ok(EnrollmentOutcome {
            user: registration.user,
            session,
            passkey,
        })
    }

    async fn redeem_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        context: &SessionContext,
    ) -> Result<RedeemedRegistration> {
        let registration = self.redeemer.registration(challenge_id, context).await?;
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
        recovery_cooldown_override: Option<DateTime<Utc>>,
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
            recovery_cooldown_until: recovery_cooldown_override
                .or(registration.recovery_cooldown_until),
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
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::CredentialAdded { user_id: user.id },
            })
            .await;
        self.notifier
            .passkey_registered(user, credential.name.as_deref())
            .await;
        Ok(credential)
    }

    async fn user_for_notification(&self, user_id: UserId, what: &'static str) -> Option<User> {
        match self.records.find(user_id).await {
            Ok(user) => Some(user),
            Err(Error::UserNotFound) => {
                tracing::warn!(
                    %user_id,
                    "{what} notification skipped because user was not found"
                );
                None
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %user_id,
                    "{what} notification skipped because user lookup failed"
                );
                None
            }
        }
    }

    async fn emit_auth_failure(
        &self,
        now: DateTime<Utc>,
        context: &SessionContext,
        user_id: Option<UserId>,
        reason: AuthFailureReason,
    ) {
        self.metrics.record(MetricEvent::AuthFailed { reason });
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::AuthenticationFailed { user_id, reason },
            })
            .await;
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

        let (rcr, auth_state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        let stored = StoredPasskeyAuthentication {
            id,
            purpose: AuthenticationPurpose::Login,
            state: encode_authentication_state(&auth_state)?,
            created_at: now,
            expires_at: expiry(now, self.config.challenge_lifetime)?,
        };
        self.challenges.put_authentication(stored).await?;
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

        let auth_state = self.redeemer.login(challenge_id, &context).await?;
        let now = self.clock.now();

        let VerifiedAssertion { user, passkey } = match self
            .assertions
            .verify(PendingAssertion::Login(auth_state), response)
            .await?
        {
            Ok(verified) => verified,
            Err(refusal) => {
                self.emit_auth_failure(now, &context, refusal.user_id, refusal.reason)
                    .await;
                return Err(refusal.error);
            }
        };
        let user_id = user.id;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));

        let active_recovery_cooldown_until = passkey.active_recovery_cooldown_until(now);

        self.metrics.record(MetricEvent::LoginSucceeded);
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::LoginSucceeded { user_id },
            })
            .await;

        let session = match active_recovery_cooldown_until {
            Some(cooldown_until) => {
                self.sessions
                    .create_restricted(user_id, context, cooldown_until)
                    .await?
            }
            None => self.sessions.create(user_id, context).await?,
        };
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

    async fn invalidate_pending_registrations(&self, user_id: UserId) -> Result<()> {
        let dropped = self
            .challenges
            .delete_registrations_for_user(user_id)
            .await?;
        if dropped > 0 {
            tracing::info!(%user_id, dropped, "pending passkey registrations invalidated");
        }
        Ok(())
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
            Actor::Subject {
                ip: context.ip,
                user_agent: context.user_agent,
            },
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
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor: Actor::Subject {
                    ip: context.ip,
                    user_agent: context.user_agent,
                },
                kind: AuditEventKind::CredentialRenamed { user_id },
            })
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
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor,
                kind: AuditEventKind::CredentialRemoved { user_id },
            })
            .await;
        if notice.sends()
            && let Some(user) = self.user_for_notification(user_id, "passkey removed").await
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

fn display_name_for(user: &User) -> String {
    user.email.clone().unwrap_or_else(|| user.id.to_string())
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

fn require_discoverable_credential(ccr: &mut CreationChallengeResponse) -> Result<()> {
    let selection = ccr
        .public_key
        .authenticator_selection
        .as_mut()
        .ok_or_else(|| {
            Error::Internal("passkey registration is missing authenticator selection".to_string())
        })?;
    selection.require_resident_key = true;
    selection.resident_key = Some(ResidentKeyRequirement::Required);
    Ok(())
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

fn encode_registration_state(state: &PasskeyRegistration) -> Result<Vec<u8>> {
    serde_json::to_vec(state)
        .map_err(|e| Error::Internal(format!("serialise registration state: {e}")))
}

pub(crate) fn decode_registration_state(bytes: &[u8]) -> Result<PasskeyRegistration> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Internal(format!("deserialise registration state: {e}")))
}

fn encode_authentication_state(state: &DiscoverableAuthentication) -> Result<Vec<u8>> {
    serde_json::to_vec(state)
        .map_err(|e| Error::Internal(format!("serialise authentication state: {e}")))
}

pub(crate) fn decode_authentication_state(bytes: &[u8]) -> Result<DiscoverableAuthentication> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Internal(format!("deserialise authentication state: {e}")))
}

pub(crate) fn encode_passkey_authentication_state(
    state: &PasskeyAuthentication,
) -> Result<Vec<u8>> {
    serde_json::to_vec(state).map_err(|e| Error::Internal(format!("serialise reauth state: {e}")))
}

pub(crate) fn decode_passkey_authentication_state(bytes: &[u8]) -> Result<PasskeyAuthentication> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Internal(format!("deserialise reauth state: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;
    use webauthn_rs_proto::UserVerificationPolicy;

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

    #[test]
    fn require_discoverable_forces_resident_key_when_selection_present() {
        let origin = Url::parse("https://example.com").expect("valid url");
        let webauthn = WebauthnBuilder::new("example.com", &origin)
            .expect("valid relying party")
            .build()
            .expect("webauthn builds");

        let (mut ccr, _state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "user", "user", None)
            .expect("registration starts");

        require_discoverable_credential(&mut ccr)
            .expect("authenticator selection present on fresh webauthn output");

        let selection = ccr
            .public_key
            .authenticator_selection
            .as_ref()
            .expect("authenticator selection present");
        assert!(selection.require_resident_key);
        assert_eq!(
            selection.resident_key,
            Some(ResidentKeyRequirement::Required)
        );
    }

    #[test]
    fn registration_requests_user_verification_required() {
        let origin = Url::parse("https://example.com").expect("valid url");
        let webauthn = WebauthnBuilder::new("example.com", &origin)
            .expect("valid relying party")
            .build()
            .expect("webauthn builds");

        let (ccr, _state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "user", "user", None)
            .expect("registration starts");
        let selection = ccr
            .public_key
            .authenticator_selection
            .as_ref()
            .expect("authenticator selection present");
        assert_eq!(
            selection.user_verification,
            UserVerificationPolicy::Required,
            "webauthn-rs changed its passkey registration UV default; doorman enforces \
             user verification at finish assuming Required — reconcile before bumping",
        );
    }

    #[test]
    fn discoverable_authentication_requests_user_verification_required() {
        let origin = Url::parse("https://example.com").expect("valid url");
        let webauthn = WebauthnBuilder::new("example.com", &origin)
            .expect("valid relying party")
            .build()
            .expect("webauthn builds");

        let (rcr, _state) = webauthn
            .start_discoverable_authentication()
            .expect("discoverable authentication starts");
        assert_eq!(
            rcr.public_key.user_verification,
            UserVerificationPolicy::Required,
            "webauthn-rs changed its discoverable-auth UV default; doorman enforces user \
             verification at finish assuming Required — reconcile before bumping",
        );
    }
}
