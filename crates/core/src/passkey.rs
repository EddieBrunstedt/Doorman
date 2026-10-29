use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationMetadata, CreationChallengeResponse, Credential, Passkey, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::assertion::{AssertionVerifier, VerifiedAssertion};
use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::challenge::PasskeyChallenges;
use crate::context::CoreDeps;
use crate::destructive::Cleared;
use crate::error::{Error, Result};
use crate::lifetime::Lifetime;
use crate::metrics::{MetricEvent, MetricSink};
use crate::passkey_registration::{
    PasskeyRegistrations, RegisteredPasskey, RegistrationFinish, RegistrationSource,
};
use crate::rate_limit::{Attempt, RateLimitEnforcer};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::{IssuedSession, RequestTransport, SessionContext};
use crate::session_records::LiveSession;
use crate::storage::{
    PasskeyChallengeId, PasskeyStore, PasskeySummary, StoredPasskey, User, UserId,
};
use crate::user_records::{OwnerRefusal, UserRecords};

pub const MAX_PASSKEY_NAME_LEN: usize = 255;

// WebAuthn's own limit, which webauthn-rs leaves to the relying party to enforce.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

// Only `parse` builds one, so storage never sees a name that skipped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasskeyName(String);

impl PasskeyName {
    pub(crate) fn parse(input: Option<&str>) -> Result<Option<Self>> {
        let Some(name) = input.map(str::trim).filter(|name| !name.is_empty()) else {
            return Ok(None);
        };
        // Security notices quote the name, so a control character could forge lines in one.
        if name.len() > MAX_PASSKEY_NAME_LEN || name.chars().any(char::is_control) {
            return Err(Error::InvalidPasskeyName);
        }
        Ok(Some(Self(name.to_owned())))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_origin: Url,
    pub rp_name: String,
    pub additional_origins: Vec<Url>,
    pub challenge_lifetime: Lifetime,
    pub max_passkeys_per_user: Option<NonZeroU32>,
    pub max_pending_registrations_per_user: Option<NonZeroU32>,
}

impl PasskeyConfig {
    pub const DEFAULT_CHALLENGE_LIFETIME: Lifetime = Lifetime::from_secs(300);

    pub fn new(rp_id: impl Into<String>, rp_origin: Url, rp_name: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_origin,
            rp_name: rp_name.into(),
            additional_origins: Vec::new(),
            challenge_lifetime: Self::DEFAULT_CHALLENGE_LIFETIME,
            max_passkeys_per_user: None,
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
    pub passkey_count: u64,
    pub session: IssuedSession,
}

#[derive(Debug)]
pub struct StartedRegistration {
    pub challenge_id: PasskeyChallengeId,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    pub user: User,
    pub passkey_count: u64,
    pub session: IssuedSession,
    pub passkey: PasskeySummary,
}

#[derive(Clone)]
pub struct PasskeyManager {
    passkeys: Arc<dyn PasskeyStore>,
    registrations: PasskeyRegistrations,
    challenges: PasskeyChallenges,
    assertions: AssertionVerifier,
    records: UserRecords,
    audit: AuditDispatch,
    notices: SecurityNotices,
    rate_limits: RateLimitEnforcer,
    metrics: Arc<dyn MetricSink>,
    config: PasskeyConfig,
}

impl PasskeyManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        config: PasskeyConfig,
        webauthn: Arc<Webauthn>,
    ) -> Self {
        Self {
            passkeys: deps.passkeys.clone(),
            registrations,
            challenges: PasskeyChallenges::from_deps(deps, &config, webauthn.clone()),
            assertions: AssertionVerifier::from_deps(deps, webauthn),
            records: UserRecords::new(deps),
            audit: deps.audit.clone(),
            notices: deps.notices.clone(),
            rate_limits: deps.rate_limits.clone(),
            metrics: deps.metrics.clone(),
            config,
        }
    }

    pub fn rp_origins(&self) -> impl Iterator<Item = &Url> {
        std::iter::once(&self.config.rp_origin).chain(&self.config.additional_origins)
    }

    #[tracing::instrument(skip(self, session), fields(method = "passkey", user_id = %session.user_id))]
    pub(crate) async fn start_registration(
        &self,
        session: &LiveSession,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let started = self
            .registrations
            .start(RegistrationSource::Session(session))
            .await?
            .map_err(OwnerRefusal::into_error)?;
        Ok((started.challenge_id, started.options))
    }

    #[tracing::instrument(
        skip(self, session, response, name),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub(crate) async fn finish_registration(
        &self,
        session: &LiveSession,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
    ) -> Result<PasskeySummary> {
        let RegisteredPasskey { user, passkey, .. } = self
            .registrations
            .finish(
                challenge_id,
                response,
                name,
                RegistrationFinish::Session(session),
            )
            .await?;
        self.notices
            .send(
                &user,
                SecurityNotice::PasskeyRegistered {
                    passkey_name: passkey.name.as_deref(),
                },
            )
            .await;
        Ok(PasskeySummary::from(passkey))
    }

    #[tracing::instrument(skip(self, context), fields(method = "passkey"))]
    pub async fn start_authentication(
        &self,
        context: SessionContext,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        self.rate_limits
            .enforce(&context, Attempt::LoginStart)
            .await?;

        let (id, rcr) = self.challenges.issue_login().await?;
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
        transport: RequestTransport,
        context: SessionContext,
    ) -> Result<AuthenticationOutcome> {
        let _latency = AuthLatencyGuard::start(self.metrics.clone());
        let transport = self.records.check_transport(&transport)?;

        self.rate_limits
            .enforce(
                &context,
                Attempt::LoginFinish {
                    passkey: response.raw_id.as_ref(),
                },
            )
            .await?;

        let pending = self.challenges.redeem_login(challenge_id, &context).await?;

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

        let session = self
            .records
            .issue_session(&passkey, transport, context.clone())
            .await?;
        let passkey_count = self.records.count_passkeys(user_id).await?;
        self.metrics.record(MetricEvent::LoginSucceeded);
        self.audit
            .emit(&context, AuditEventKind::LoginSucceeded { user_id })
            .await;
        Ok(AuthenticationOutcome {
            user,
            passkey_count,
            session,
        })
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub(crate) async fn list_passkeys(&self, user_id: UserId) -> Result<Vec<PasskeySummary>> {
        let passkeys = self.passkeys.list_passkeys_for_user(user_id).await?;
        Ok(passkeys.into_iter().map(PasskeySummary::from).collect())
    }

    pub(crate) async fn remove_passkey(
        &self,
        cleared: Cleared,
        credential_id: &[u8],
    ) -> Result<()> {
        self.remove_passkey_for(cleared.session().user_id, credential_id, cleared.actor())
            .await
    }

    #[tracing::instrument(skip(self, session, credential_id, name), fields(user_id = %session.user_id))]
    pub(crate) async fn rename_passkey(
        &self,
        session: &LiveSession,
        credential_id: &[u8],
        name: Option<String>,
    ) -> Result<PasskeySummary> {
        let name = PasskeyName::parse(name.as_deref())?;
        let user_id = session.user_id;
        let mut passkey =
            find_owned_passkey(self.passkeys.as_ref(), user_id, credential_id).await?;
        self.passkeys
            .set_passkey_name(credential_id, name.as_ref().map(PasskeyName::as_str))
            .await?;
        passkey.name = name.map(PasskeyName::into_string);
        self.audit
            .emit(session.actor(), AuditEventKind::PasskeyRenamed { user_id })
            .await;
        Ok(PasskeySummary::from(passkey))
    }

    pub(crate) async fn remove_passkey_for(
        &self,
        user_id: UserId,
        credential_id: &[u8],
        actor: Actor,
    ) -> Result<()> {
        let passkey = find_owned_passkey(self.passkeys.as_ref(), user_id, credential_id).await?;
        self.passkeys.delete_passkey(credential_id).await?;
        let passkey_name = passkey.name.as_deref();
        let notice = match actor {
            Actor::Session { .. } | Actor::Subject { .. } => {
                SecurityNotice::PasskeyRemoved { passkey_name }
            }
            Actor::Operator(_) => SecurityNotice::OperatorRemovedPasskey { passkey_name },
        };
        self.audit
            .emit(actor, AuditEventKind::PasskeyRemoved { user_id })
            .await;
        self.notices.send_to(user_id, notice).await;
        Ok(())
    }
}

pub(crate) async fn find_owned_passkey(
    passkeys: &dyn PasskeyStore,
    user_id: UserId,
    credential_id: &[u8],
) -> Result<StoredPasskey> {
    let Some(passkey) = passkeys
        .find_passkey_by_credential_id(credential_id)
        .await?
    else {
        tracing::warn!(
            outcome = "passkey_not_found",
            "passkey ownership check failed"
        );
        return Err(Error::PasskeyNotFound);
    };
    if passkey.user_id != user_id {
        tracing::warn!(
            outcome = "ownership_mismatch",
            "passkey ownership check failed"
        );
        return Err(Error::PasskeyOwnershipMismatch);
    }
    Ok(passkey)
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
    pub(crate) aaguid: Option<Uuid>,
    pub(crate) transports: Vec<String>,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    pub(crate) user_verified: bool,
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
        // The client reports transports unsigned, so a repeated one would grow the row unbounded.
        let mut transports: Vec<String> = Vec::new();
        for transport in cred.transports.unwrap_or_default() {
            let transport = transport.to_string();
            if !transports.contains(&transport) {
                transports.push(transport);
            }
        }
        Self {
            aaguid,
            transports,
            backup_eligible: cred.backup_eligible,
            backup_state: cred.backup_state,
            user_verified: cred.user_verified,
        }
    }
}

pub(crate) fn check_credential_id(credential_id: &[u8]) -> Result<()> {
    if credential_id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(Error::Webauthn(format!(
            "credential ID exceeds {MAX_CREDENTIAL_ID_LEN} bytes"
        )));
    }
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

pub(crate) fn encode_passkey(passkey: &Passkey) -> Result<Vec<u8>> {
    serde_json::to_vec(passkey).map_err(|e| Error::Internal(format!("serialise passkey: {e}")))
}

pub(crate) fn decode_passkey(bytes: &[u8]) -> Result<Passkey> {
    serde_json::from_slice(bytes).map_err(|e| Error::Internal(format!("deserialise passkey: {e}")))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use url::Url;

    #[test]
    fn credential_id_is_refused_past_the_webauthn_limit() {
        assert!(check_credential_id(&[0; MAX_CREDENTIAL_ID_LEN]).is_ok());
        assert!(matches!(
            check_credential_id(&[0; MAX_CREDENTIAL_ID_LEN + 1]),
            Err(Error::Webauthn(_))
        ));
    }

    #[test]
    fn config_constructor_sets_default_lifetime() {
        let c = PasskeyConfig::new(
            "example.com",
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        );
        assert_eq!(c.challenge_lifetime.get(), Duration::from_secs(300));
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
        assert_eq!(c.challenge_lifetime.get(), Duration::from_secs(300));
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
