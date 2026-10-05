//! Passkey (WebAuthn) registration and authentication ceremonies.
//!
//! The manager wraps a `webauthn-rs` [`Webauthn`] instance and composes
//! it with the user store, the passkey credential store, and a separate
//! challenge store that holds the per-ceremony server-side state between
//! the `start_*` and `finish_*` calls. Audit events are emitted at every
//! meaningful step, and successful passkey lifecycle changes send
//! best-effort security notifications after the credential store changes.
//!
//! Account linking falls out of the design for free: register a passkey
//! against any existing user id and that user now has a passkey credential.

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
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder, WebauthnError,
};
use webauthn_rs_proto::ResidentKeyRequirement;

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
    PasskeySummary, PasskeyUse, Session, StoredPasskey, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, User, UserId,
};
use crate::user::UserRecords;
use crate::verification::EnrollmentOutcome;

/// Rate-limit policies for the passkey authentication ceremony endpoints.
///
/// These throttle the discoverable-login `start` / `finish` calls so a
/// single source (or a single targeted credential) cannot hammer the
/// ceremony. They are enforced against the same [`RateLimiter`] the signup /
/// recovery request endpoints use. A `None` policy disables that axis; a
/// `None` IP on the request (no client address available) skips the per-IP
/// axes. The per-credential axis always applies on finish, since the
/// credential id is carried in the assertion.
///
/// Registration ceremonies are gated by an authenticated session and a
/// per-user pending-challenge cap
/// ([`PasskeyConfig::max_pending_registrations_per_user`]) rather than by
/// these limits.
#[derive(Debug, Clone, Copy)]
pub struct PasskeyRateLimits {
    /// Per source IP on `start_authentication`. Default 60 / minute.
    pub authenticate_start_per_ip: Option<RateLimitPolicy>,
    /// Per source IP on `finish_authentication`. Default 60 / minute.
    pub authenticate_finish_per_ip: Option<RateLimitPolicy>,
    /// Per asserted credential id on `finish_authentication`. Default
    /// 30 / minute. Bounds repeated assertions against one credential
    /// independent of source IP.
    pub authenticate_finish_per_credential: Option<RateLimitPolicy>,
}

impl PasskeyRateLimits {
    /// Default per-IP policy on `start_authentication`: 60 / minute.
    pub const DEFAULT_START_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(60, Duration::from_secs(60));
    /// Default per-IP policy on `finish_authentication`: 60 / minute.
    pub const DEFAULT_FINISH_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(60, Duration::from_secs(60));
    /// Default per-credential policy on `finish_authentication`: 30 / minute.
    /// Bounds repeated assertions against one credential independent of IP.
    pub const DEFAULT_FINISH_PER_CREDENTIAL: RateLimitPolicy =
        RateLimitPolicy::new(30, Duration::from_secs(60));

    /// Turn off every passkey-ceremony policy.
    pub const fn disabled() -> Self {
        Self {
            authenticate_start_per_ip: None,
            authenticate_finish_per_ip: None,
            authenticate_finish_per_credential: None,
        }
    }
}

impl Default for PasskeyRateLimits {
    /// Default: 60 / IP / minute on start ([`DEFAULT_START_PER_IP`]) and on
    /// finish ([`DEFAULT_FINISH_PER_IP`]), plus 30 / credential / minute on
    /// finish ([`DEFAULT_FINISH_PER_CREDENTIAL`]). Override any field via
    /// struct-update syntax, or pass [`disabled`] to turn every policy off.
    ///
    /// [`DEFAULT_START_PER_IP`]: PasskeyRateLimits::DEFAULT_START_PER_IP
    /// [`DEFAULT_FINISH_PER_IP`]: PasskeyRateLimits::DEFAULT_FINISH_PER_IP
    /// [`DEFAULT_FINISH_PER_CREDENTIAL`]: PasskeyRateLimits::DEFAULT_FINISH_PER_CREDENTIAL
    /// [`disabled`]: PasskeyRateLimits::disabled
    fn default() -> Self {
        Self {
            authenticate_start_per_ip: Some(Self::DEFAULT_START_PER_IP),
            authenticate_finish_per_ip: Some(Self::DEFAULT_FINISH_PER_IP),
            authenticate_finish_per_credential: Some(Self::DEFAULT_FINISH_PER_CREDENTIAL),
        }
    }
}

/// Whether an enrolment through [`PasskeyManager::enroll`] counts against
/// [`PasskeyConfig::max_credentials_per_user`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialCap {
    /// Refuse the enrolment once the user holds the configured maximum.
    Enforce,
    /// Enrol whatever the user already holds.
    Exempt,
}

/// The policy a flow enrols a passkey under through
/// [`PasskeyManager::enroll`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct EnrollmentPolicy {
    /// Post-recovery cool-down started at enrolment and stamped on both the
    /// new passkey and the new session, or `None` for an unrestricted
    /// enrolment.
    pub cooldown: Option<chrono::Duration>,
    /// Whether the per-user credential cap applies.
    pub credential_cap: CredentialCap,
}

/// WebAuthn relying-party configuration for passkey flows.
#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    /// Relying party identifier, typically the registrable suffix of
    /// the site origin (e.g. `"example.com"` for `https://app.example.com`).
    pub rp_id: String,
    /// The full origin the browser will see when calling `navigator
    /// .credentials.create` / `.get` (e.g. `https://app.example.com`).
    pub rp_origin: Url,
    /// Display name shown to users in the platform's passkey UI.
    pub rp_name: String,
    /// Extra origins to accept during passkey ceremonies, in addition to
    /// `rp_origin`.
    ///
    /// Every ceremony carries the origin the browser or app was at, and the
    /// server only completes one whose origin it trusts. By default that is
    /// just `rp_origin`. Adding an entry here is a deliberate statement that
    /// the origin is also you, and that your users' passkeys should be honored
    /// when a ceremony arrives from it. Two cases call for it:
    ///
    /// - **Native mobile apps**, whose platform WebAuthn APIs report an
    ///   app-specific origin (e.g. `android:apk-key-hash:...`) rather than your
    ///   `https://` web origin.
    /// - **Related Origin Requests**, where one relying party (a single
    ///   `rp_id`) spans genuinely different registrable domains (e.g.
    ///   `https://example.co.uk` alongside `https://example.com`).
    ///
    /// This is only doorman's half. The matching client-side setup — Android
    /// asset links / iOS associated domains, or a `/.well-known/webauthn`
    /// document for Related Origin Requests — is the host's to serve, and is
    /// what makes the client actually send the origin. Defaults to empty.
    pub additional_origins: Vec<Url>,
    /// How long an unfinished ceremony stays valid. Defaults to 5 minutes,
    /// matching the W3C recommended authenticator timeout.
    pub challenge_lifetime: Duration,
    /// Rate-limit policies for the authentication ceremony endpoints.
    /// Defaults to [`PasskeyRateLimits::default`].
    pub rate_limits: PasskeyRateLimits,
    /// Cap on registered credentials per user. When set, a registration that
    /// would exceed it is rejected with [`Error::ResourceLimitExceeded`]
    /// rather than silently evicting an existing passkey (losing a credential
    /// must be a deliberate user action). `None` (the default) is unbounded.
    pub max_credentials_per_user: Option<NonZeroU32>,
    /// Cap on outstanding (unfinished) registration ceremonies per user. When
    /// set, starting another beyond the cap is rejected with
    /// [`Error::ResourceLimitExceeded`], bounding how much challenge state an
    /// authenticated foothold can accumulate. `None` (the default) is
    /// unbounded.
    pub max_pending_registrations_per_user: Option<NonZeroU32>,
}

impl PasskeyConfig {
    /// Default ceremony challenge lifetime: 5 minutes, matching the W3C
    /// recommended authenticator timeout. See
    /// [`PasskeyConfig::challenge_lifetime`].
    pub const DEFAULT_CHALLENGE_LIFETIME: Duration = Duration::from_secs(300);

    /// Build a config from an explicit relying-party id, origin, and display
    /// name. Use [`from_origin`](Self::from_origin) when the rp_id is just the
    /// origin host; the rp_id must be a registrable suffix of that host.
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

    /// Derive the configuration from the site origin, using the origin's
    /// host as the relying-party id. This is the common case: a single
    /// origin (`https://app.example.com`) whose `rp_id` is just its host
    /// (`app.example.com`). Use [`new`](Self::new) directly when the
    /// `rp_id` must be a broader registrable suffix than the host (e.g.
    /// `example.com` so credentials work across `app.` and `id.`
    /// subdomains).
    ///
    /// Returns [`Error::InvalidRelyingParty`] when the origin has no host
    /// component (e.g. a `data:` or path-only URL), since WebAuthn requires
    /// a host-based relying-party id.
    pub fn from_origin(rp_origin: Url, rp_name: impl Into<String>) -> Result<Self> {
        let rp_id = rp_origin.host_str().ok_or_else(|| {
            Error::InvalidRelyingParty(format!("origin {rp_origin} has no host to use as rp_id"))
        })?;
        Ok(Self::new(rp_id.to_owned(), rp_origin.clone(), rp_name))
    }
}

/// Result of a successful
/// [`finish_authentication`](PasskeyManager::finish_authentication): the
/// signed-in user and the session minted for them.
#[derive(Debug, Clone)]
pub struct AuthenticationOutcome {
    /// The user the passkey belongs to, as read by the account-status check.
    pub user: User,
    /// The freshly-issued session.
    pub session: IssuedSession,
}

/// Manager for passkey registration, authentication, listing, and removal.
#[derive(Clone)]
pub struct PasskeyManager {
    records: UserRecords,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    redeemer: Redeemer,
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
    /// Construct a passkey manager from the shared [`CoreDeps`] context and
    /// the relying-party [`PasskeyConfig`]. The collaborators (clock, audit,
    /// email, session manager, and the user / credential / challenge stores)
    /// are read from `deps` so they are named once at the composition root
    /// rather than threaded through a long positional argument list.
    ///
    /// The security-notification helper is taken from
    /// [`CoreDeps::notifier`] — built once at the composition root — so the
    /// passkey lifecycle notices share the one configured sender and email
    /// renderer with every other bundled notice.
    pub fn new(deps: &CoreDeps, config: PasskeyConfig) -> Result<Self> {
        let webauthn = build_webauthn(&config)?;

        Ok(Self {
            records: UserRecords::new(deps),
            credentials: deps.passkey_credentials.clone(),
            challenges: deps.passkey_challenges.clone(),
            redeemer: Redeemer::from_deps(deps),
            sessions: deps.sessions.clone(),
            reauth: deps.reauth.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            notifier: deps.notifier.clone(),
            rate_limiter: deps.rate_limiter.clone(),
            metrics: deps.metrics.clone(),
            webauthn: Arc::new(webauthn),
            config,
        })
    }

    /// Begin registering a new passkey for `user_id`. The returned
    /// [`CreationChallengeResponse`] is the JSON payload to hand to
    /// `navigator.credentials.create` on the client; the
    /// [`PasskeyChallengeId`] is what the client must echo back to
    /// [`PasskeyManager::finish_registration`].
    ///
    /// Every `start_registration*` entry point refuses a missing user with
    /// [`Error::UserNotFound`] and a disabled account with
    /// [`Error::AccountDisabled`].
    #[tracing::instrument(skip(self), fields(method = "passkey", user_id = %user_id))]
    pub async fn start_registration(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.start_registration_inner(user_id, None).await
    }

    /// Begin registering a new passkey on behalf of an authenticated
    /// `session`, propagating that session's *active* post-recovery cool-down
    /// (if any) onto the in-progress ceremony. A passkey enrolled while the
    /// session is locked down therefore inherits the same deadline and cannot
    /// be turned into an unrestricted credential that escapes the cool-down; a
    /// session with no active cool-down registers an ordinary, unrestricted
    /// passkey.
    ///
    /// This is the session-aware entry point hosts should prefer for
    /// authenticated re-registration: it keeps the cool-down propagation in
    /// core (judged against this manager's clock, so expired cool-downs are
    /// not carried forward) rather than relying on each transport to read the
    /// deadline off the session and thread it through correctly. Use
    /// [`start_registration`](Self::start_registration) for flows with no
    /// acting session (e.g. signup), or
    /// [`start_registration_with_recovery_cooldown`](Self::start_registration_with_recovery_cooldown)
    /// to supply a deadline explicitly.
    #[tracing::instrument(skip(self, session), fields(method = "passkey", user_id = %session.user_id))]
    pub async fn start_registration_for_session(
        &self,
        session: &Session,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let cooldown_until = session.active_recovery_cooldown_until(self.clock.now());
        self.start_registration_inner(session.user_id, cooldown_until)
            .await
    }

    /// Begin registering a new passkey and associate optional recovery
    /// cool-down metadata with the in-progress ceremony. If the registration
    /// later finishes through [`PasskeyManager::finish_registration`], the
    /// stored credential receives the same timestamp. Prefer
    /// [`start_registration_for_session`](Self::start_registration_for_session)
    /// when the deadline comes from an authenticated session: it derives the
    /// *active* deadline from the session itself so an expired cool-down is
    /// not propagated by accident.
    #[tracing::instrument(skip(self), fields(method = "passkey", user_id = %user_id))]
    pub async fn start_registration_with_recovery_cooldown(
        &self,
        user_id: UserId,
        recovery_cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.start_registration_inner(user_id, recovery_cooldown_until)
            .await
    }

    async fn start_registration_inner(
        &self,
        user_id: UserId,
        recovery_cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        // A disabled account cannot start a ceremony; finish re-checks before
        // anything is persisted.
        let user = self.records.find_active(user_id).await?;

        // Bound how much challenge state one user can accumulate: an
        // authenticated foothold could otherwise call `start` repeatedly and
        // grow the registration table without ever finishing a ceremony.
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
            // The top-level credential id is enough to exclude already-registered
            // authenticators; no need to deserialise each opaque passkey blob.
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

    /// Complete a registration ceremony. On success the passkey is
    /// persisted and a [`CredentialAdded`](AuditEventKind::CredentialAdded)
    /// event is emitted. If the registration challenge was started with
    /// recovery cool-down metadata, the stored passkey receives that same
    /// timestamp.
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
        self.finish_registration_inner(challenge_id, response, name, context, None)
            .await
    }

    /// Complete a registration ceremony while overriding any cool-down stored
    /// on the challenge.
    #[tracing::instrument(
        skip(self, response, name, context),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub async fn finish_registration_with_recovery_cooldown(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        recovery_cooldown_until: DateTime<Utc>,
    ) -> Result<StoredPasskey> {
        self.finish_registration_inner(
            challenge_id,
            response,
            name,
            context,
            Some(recovery_cooldown_until),
        )
        .await
    }

    async fn finish_registration_inner(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        recovery_cooldown_override: Option<DateTime<Utc>>,
    ) -> Result<StoredPasskey> {
        let registration = self.redeem_registration(challenge_id, &context).await?;
        self.enforce_credential_cap(registration.user.id).await?;
        let credential =
            self.verify_registration(&registration, response, name, recovery_cooldown_override)?;
        self.store_credential(&registration.user, credential, &context)
            .await
    }

    /// Start the registration ceremony an emailed signup or recovery link
    /// leads to. The link is already consumed when this runs, so starting
    /// must not fail on
    /// [`max_pending_registrations_per_user`](PasskeyConfig::max_pending_registrations_per_user):
    /// the user's unfinished registration ceremonies are dropped first and
    /// the new one replaces them, the same way a fresh link supersedes older
    /// ones.
    pub(crate) async fn start_enrollment(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.invalidate_pending_registrations(user_id).await?;
        self.start_registration_inner(user_id, None).await
    }

    /// Finish the registration ceremony begun by
    /// [`start_enrollment`](Self::start_enrollment), enrol the passkey, and
    /// issue a session for its user.
    ///
    /// With a `policy.cooldown`, the new passkey and session share one
    /// deadline, bound to this instant, and the user's other unfinished
    /// registration ceremonies are dropped before anything is stored: they
    /// were started without the cool-down, so finishing one later would add
    /// a credential that escapes it.
    ///
    /// The passkey and session live in separate stores that may sit on
    /// different backends, so enrolment is not atomic. Every check that can
    /// refuse it runs before the passkey is stored, which leaves only session
    /// issue after it, and that fails only on a storage error (the session
    /// cap evicts rather than refuses). The passkey is then kept: the
    /// authenticator already holds the credential, so deleting it would
    /// strand a passkey the user can still sign in with.
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

    /// Redeem a registration challenge. Redeeming re-checks that the user the
    /// ceremony was started for still exists and is active: a concurrent
    /// delete or operator disable may have landed after the challenge was
    /// issued, and enrolling then would orphan a credential or re-credential
    /// a disabled account. This is the backstop that keeps recovery from
    /// re-credentialing its way back in even when the link was consumed
    /// before the disable landed. What remains is the window between this
    /// check and `add_passkey`.
    async fn redeem_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        context: &SessionContext,
    ) -> Result<RedeemedRegistration> {
        let registration = self.redeemer.registration(challenge_id, context).await?;
        tracing::Span::current().record("user_id", tracing::field::display(registration.user.id));
        Ok(registration)
    }

    /// Reject (never evict) a registration once the user holds
    /// [`max_credentials_per_user`](PasskeyConfig::max_credentials_per_user)
    /// passkeys: silently dropping an existing passkey would remove an
    /// authenticator the user still relies on.
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

    /// Verify the authenticator's response against the redeemed ceremony and
    /// build the credential to store. A `recovery_cooldown_override` takes
    /// precedence over the deadline the ceremony was started with.
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

    /// Store a verified credential for `user`, audit it, and send the
    /// best-effort passkey-registered notice.
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

    /// Resolve the user a best-effort passkey lifecycle notice is addressed
    /// to. A missing user or a lookup failure skips the notice with a warning
    /// rather than failing the operation that already succeeded.
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

    /// Emit an [`AuthenticationFailed`](AuditEventKind::AuthenticationFailed)
    /// audit event for a failed login attempt. Centralised so every
    /// `finish_authentication` rejection path records the same shape; the
    /// caller supplies the resolved `user_id` (or `None` when the failure
    /// happened before a credential was identified) and the
    /// [`AuthFailureReason`].
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

    /// Begin a discoverable passkey authentication ceremony. Returns the
    /// [`RequestChallengeResponse`] for `navigator.credentials.get` and a
    /// [`PasskeyChallengeId`] the client must echo back. No user input is
    /// accepted, so every caller receives the same challenge shape and the
    /// user is identified only at finish-time from the authenticator response.
    ///
    /// The request `context`'s IP, when present, is charged against the
    /// per-IP start policy ([`PasskeyRateLimits::authenticate_start_per_ip`])
    /// before any challenge state is minted.
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

    /// Complete an authentication ceremony, issuing a session on success and
    /// returning it with the signed-in user. If the authenticated passkey still carries an active recovery
    /// cool-down deadline, the issued session inherits that restriction.
    ///
    /// A disabled account is refused with [`Error::AccountDisabled`] after the
    /// assertion verifies: no session is minted and the credential is not
    /// updated.
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
        // Record the ceremony's wall-clock latency on every outcome: the
        // guard fires its `AuthLatency` observation when this scope unwinds,
        // whether through a rate-limit `?`, a rejection, or success — so the
        // histogram captures the full finish-endpoint cost without a record
        // call on each return path.
        let _latency = AuthLatencyGuard::start(self.metrics.clone());

        // Throttle before consuming the single-use challenge, keyed both by
        // source IP and by the asserted credential id, so a flood cannot burn
        // challenges or pound one credential. The credential id is the raw
        // assertion id (present before we resolve the credential), encoded for
        // a stable, log-safe dimension value.
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

        let cred_id_bytes: &[u8] = response.raw_id.as_ref();
        let Some(credential) = self
            .credentials
            .find_passkey_by_credential_id(cred_id_bytes)
            .await?
        else {
            self.emit_auth_failure(now, &context, None, AuthFailureReason::UnknownCredential)
                .await;
            return Err(Error::PasskeyNotFound);
        };

        let user_id = credential.user_id;

        // Discoverable-credential auth must assert a user handle that maps to
        // the credential's stored owner. A missing or malformed handle, or one
        // that names a different user, means the credential-to-user binding
        // cannot be confirmed — reject rather than mint a session for the owner
        // the credential lookup happened to return.
        match user_id_from_handle(response) {
            Ok(Some(asserted_user)) if asserted_user == user_id => {}
            _ => {
                self.emit_auth_failure(
                    now,
                    &context,
                    Some(user_id),
                    AuthFailureReason::UserHandleMismatch,
                )
                .await;
                return Err(Error::PasskeyOwnershipMismatch);
            }
        }
        tracing::Span::current().record("user_id", tracing::field::display(user_id));

        let mut passkey = decode_credential(&credential.passkey)?;
        let discoverable = [DiscoverableKey::from(&passkey)];
        let auth_result = match self.webauthn.finish_discoverable_authentication(
            response,
            auth_state,
            &discoverable,
        ) {
            Ok(result) => result,
            // `webauthn-rs` enforces the signature-counter regression check
            // inside the credential blob and flags a non-advancing counter as a
            // possible cloned authenticator. Surface it as a distinct security
            // event and reject the login. Authenticators that always report 0
            // never trip this — the check is skipped when both counters are 0.
            Err(WebauthnError::CredentialPossibleCompromise) => {
                self.emit_auth_failure(
                    now,
                    &context,
                    Some(user_id),
                    AuthFailureReason::CounterRegression,
                )
                .await;
                return Err(Error::PasskeyPossibleCompromise);
            }
            Err(e) => {
                self.emit_auth_failure(
                    now,
                    &context,
                    Some(user_id),
                    AuthFailureReason::BadAssertion,
                )
                .await;
                return Err(Error::Webauthn(e.to_string()));
            }
        };

        if !auth_result.user_verified() {
            self.emit_auth_failure(
                now,
                &context,
                Some(user_id),
                AuthFailureReason::UserVerificationMissing,
            )
            .await;
            return Err(Error::UserVerificationRequired);
        }

        // Refuse a disabled account (or one deleted while the ceremony was in
        // flight) before anything is persisted or minted. The check sits after
        // the assertion verifies so only the credential holder learns the
        // account is disabled; the single-use challenge stays consumed.
        // The gate is the one session resolution applies on every request.
        let user = match self.records.find_active(user_id).await {
            Ok(user) => user,
            Err(error) => {
                let reason = match error {
                    Error::UserNotFound => AuthFailureReason::UnknownCredential,
                    Error::AccountDisabled => AuthFailureReason::AccountDisabled,
                    _ => return Err(error),
                };
                self.emit_auth_failure(now, &context, Some(user_id), reason)
                    .await;
                return Err(error);
            }
        };

        let active_recovery_cooldown_until = credential.active_recovery_cooldown_until(now);

        // Counter / backup-state updates are advisory per webauthn-rs;
        // last_used_at always advances, so we record the use on every success.
        // The mutated passkey is re-serialised into the opaque blob, and the
        // backup flags are refreshed from it so the surfaced metadata tracks a
        // passkey that became backed up after registration. Only these fields
        // are written, so a concurrent rename survives.
        passkey.update_credential(&auth_result);
        let refreshed = PasskeyMetadata::from_passkey(&passkey);
        self.credentials
            .record_passkey_use(
                &credential.credential_id,
                PasskeyUse {
                    passkey: encode_credential(&passkey)?,
                    backup_eligible: refreshed.backup_eligible,
                    backup_state: refreshed.backup_state,
                    used_at: now,
                },
            )
            .await?;

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

    /// List a user's credentials, including the credential blob. Prefer the
    /// summary listing for UI that does not need the blob.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_passkeys(&self, user_id: UserId) -> Result<Vec<StoredPasskey>> {
        Ok(self.credentials.list_passkeys_for_user(user_id).await?)
    }

    /// Count the user's passkeys without loading them.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn count_passkeys(&self, user_id: UserId) -> Result<u64> {
        Ok(self.credentials.count_passkeys_for_user(user_id).await?)
    }

    /// List the user's passkeys as metadata-only [`PasskeySummary`] values.
    /// Backs the management listing without deserialising the credential
    /// blob.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_passkey_summaries(&self, user_id: UserId) -> Result<Vec<PasskeySummary>> {
        Ok(self
            .credentials
            .list_passkey_summaries_for_user(user_id)
            .await?)
    }

    /// Drop every unfinished registration ceremony for `user_id`.
    /// [`start_enrollment`](Self::start_enrollment) and
    /// [`enroll`](Self::enroll) say why each needs it.
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

    /// Remove a passkey on behalf of the authenticated `session`. The
    /// session's owning user is enforced server-side so a session for user A
    /// cannot delete user B's credential by guessing a credential id.
    ///
    /// Refused with [`Error::RecoveryCooldownActive`] while `session` is
    /// inside its post-recovery cool-down window: a phished recovery session
    /// must not be able to strip the legitimate owner's remaining passkeys.
    /// Pass a `session` resolved from storage for this request; the cool-down
    /// (and revocation) check trusts the supplied snapshot.
    ///
    /// Outside the cool-down this may remove the user's *last* credential.
    /// That is intentional: the email-based recovery flow is the designed
    /// backstop for the "lost every passkey" case, so self-service removal
    /// does not special-case the final credential.
    ///
    /// When the host's [`ReauthPolicy`](crate::reauth::ReauthPolicy) gates
    /// [`RemovePasskey`](ReauthAction::RemovePasskey), `reauth` must carry a
    /// fresh [`ReauthProof`]; an absent one is rejected with
    /// [`Error::ReauthRequired`]. The cool-down is checked **first** — it is a
    /// hard block re-auth cannot satisfy.
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

    /// Rename a passkey on behalf of the authenticated `session`, setting its
    /// friendly label to `name` (`None` clears it). The session's owning user
    /// is enforced server-side so a session for user A cannot rename user B's
    /// credential by guessing a credential id: a missing credential is
    /// [`Error::PasskeyNotFound`] and one owned by a different user is
    /// [`Error::PasskeyOwnershipMismatch`]. Writes only the name, and returns
    /// the credential as read with the new name applied.
    ///
    /// Unlike [`remove_passkey`](Self::remove_passkey) this is purely cosmetic
    /// — it neither adds nor removes an authenticator and cannot lock the
    /// legitimate owner out or strip their access — so it is **not** gated by
    /// the post-recovery cool-down and sends no security notification. The
    /// change is still recorded with a
    /// [`CredentialRenamed`](AuditEventKind::CredentialRenamed) audit event so
    /// the credential inventory's change history stays complete.
    ///
    /// The library does not interpret `name`; it is persisted verbatim,
    /// matching how a name supplied at registration is treated.
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

    /// Remove `credential_id` from `user_id`, attributing the audit event to
    /// `actor`. The id-keyed core both self-service
    /// [`remove_passkey`](Self::remove_passkey) and the operator removal flow
    /// drive, so the resolve-verify-ownership-delete cascade plus the audit
    /// emission are shared; the two paths diverge only on `notice`, which
    /// selects the notification copy (the self-service "was this you?" wording
    /// versus operator-aware copy) and whether a notice is sent at all.
    ///
    /// The core resolves the credential and verifies it belongs to `user_id`
    /// before deleting: a missing credential is [`Error::PasskeyNotFound`] and
    /// one owned by a different user is [`Error::PasskeyOwnershipMismatch`].
    /// Binding ownership to the passed `user_id` is what keeps a removal named
    /// against one user from touching another user's credential.
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

/// Which subject notice the shared passkey-removal core sends, the one thing
/// the self-service and operator removal paths diverge on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyRemovalNotice {
    /// The self-service "a passkey was removed — was this you?" copy. Always
    /// sent (self-service removal is transparent by default).
    SelfService,
    /// Operator-aware copy ("an administrator removed a passkey"). The operator
    /// path passes this when its
    /// [`NotificationPolicy`](crate::operator::NotificationPolicy) keeps the
    /// notice on.
    Operator,
    /// No subject notice. The operator path passes this when its policy
    /// suppresses the passkey-removal notice; the removal and its audit event
    /// still run.
    Suppressed,
}

impl PasskeyRemovalNotice {
    /// Whether this variant emits any subject notice.
    fn sends(self) -> bool {
        matches!(self, Self::SelfService | Self::Operator)
    }
}

/// Resolve `credential_id` and confirm it belongs to `user_id`. The one place
/// the "a user acts only on their own credential" rule lives: a missing
/// credential is [`Error::PasskeyNotFound`] and one owned by a different user
/// is [`Error::PasskeyOwnershipMismatch`].
///
/// Checking before a separate write is race-free because a credential's owner
/// is fixed when it is added: no [`PasskeyCredentialStore`] write moves it.
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

/// The label shown in the platform passkey UI. doorman uses the email when set
/// (the user id otherwise) for both the WebAuthn user name and display name —
/// the two are intentionally identical, so one value feeds both parameters.
fn display_name_for(user: &User) -> String {
    user.email.clone().unwrap_or_else(|| user.id.to_string())
}

/// RAII guard that records a `finish_authentication` ceremony's wall-clock
/// duration through the metrics sink on drop, so the [`MetricEvent::AuthLatency`]
/// observation fires on every return path without a record call threaded
/// through each early `?`. Uses [`Instant`] (monotonic) rather than the
/// domain [`Clock`] because this is elapsed real time, not a logical
/// timestamp.
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

/// Device metadata read out of a freshly finished or updated [`Passkey`].
///
/// `webauthn-rs` keeps these on the credential internals, reachable via the
/// `danger-credential-internals` feature; `doorman-core` is the only layer that
/// touches the `webauthn-rs` types, lowering them to the primitive fields the
/// storage traits persist so a host's store stays `webauthn-rs`-free.
struct PasskeyMetadata {
    aaguid: Option<Uuid>,
    transports: Vec<String>,
    backup_eligible: bool,
    backup_state: bool,
    user_verified: bool,
}

impl PasskeyMetadata {
    fn from_passkey(passkey: &Passkey) -> Self {
        let cred: Credential = passkey.clone().into();
        // AAGUID is only present when the authenticator volunteered packed or
        // TPM attestation metadata. Passkey registration requests no
        // attestation, so for the common discoverable-credential flow this is
        // `None`.
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

fn user_id_from_handle(response: &PublicKeyCredential) -> Result<Option<UserId>> {
    response
        .response
        .user_handle
        .as_ref()
        .map(|handle| {
            Uuid::from_slice(handle.as_ref())
                .map(UserId)
                .map_err(|_| Error::PasskeyNotFound)
        })
        .transpose()
}

// Opaque-blob (de)serialisation. The storage traits deal in `Vec<u8>` so a
// host's store needs no `webauthn-rs` dependency; `doorman-core` is the only
// layer that knows the blob is JSON-serialised `webauthn-rs` state.

/// Build the `webauthn-rs` [`Webauthn`] handle from the relying-party config.
/// Shared by [`PasskeyManager::new`] and
/// [`ReauthManager::new`](crate::reauth::ReauthManager::new): both need a
/// handle configured against the same `rp_id` / origin, so the construction
/// lives here once.
pub(crate) fn build_webauthn(config: &PasskeyConfig) -> Result<Webauthn> {
    let mut builder = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
        .map_err(|e| Error::InvalidRelyingParty(e.to_string()))?
        .rp_name(&config.rp_name);
    // Appended verbatim, with no scheme/host validation: native-app
    // (`android:`/app-specific) and Related-Origin entries are legitimately
    // non-`https`, so a "must be https" check here would reject valid input.
    // Keeping these correct and minimal is the host's responsibility.
    for origin in &config.additional_origins {
        builder = builder.append_allowed_origin(origin);
    }
    builder
        .build()
        .map_err(|e| Error::InvalidRelyingParty(e.to_string()))
}

fn encode_credential(passkey: &Passkey) -> Result<Vec<u8>> {
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

/// Encode the allow-list-scoped [`PasskeyAuthentication`] ceremony state used
/// by re-authentication. It rides the same opaque `state` blob and
/// [`PasskeyChallengeStore`] as the discoverable login state above; the
/// challenge's [`AuthenticationPurpose`] keeps the two apart.
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
        // The native-app case the docs call out: a non-`https`, hostless
        // `android:` origin must survive the `Url` round-trip and reach the
        // allowed set unchanged.
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
        // Canary: doorman's finish-side UV enforcement assumes webauthn-rs requests
        // UserVerificationPolicy::Required for passkey registration. If a future
        // webauthn-rs changes this default, this test fails on the version bump so the
        // change is handled deliberately instead of silently weakening the guarantee.
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
        // Canary, authentication side. Requires the `conditional-ui` feature, which is
        // enabled in the workspace Cargo.toml.
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
