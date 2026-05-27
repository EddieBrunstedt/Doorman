//! Magic-link authentication: email-the-link, click-to-sign-in.
//!
//! The [`MagicLinkManager`] mirrors the shape of the other auth managers:
//! a [`request_magic_link`](MagicLinkManager::request_magic_link) call
//! issues a single-use, time-limited token, embeds it in a URL via the
//! configured template, and hands the rendered email to the configured
//! [`EmailSender`]. A subsequent
//! [`consume_magic_link`](MagicLinkManager::consume_magic_link) call
//! redeems the token atomically and issues a session.
//!
//! Magic links pair best with another factor (e.g. passkeys) for sensitive
//! operations: anyone with access to the user's inbox can sign in. They
//! make sense either as an additional login option or as the only option
//! for apps where email already gates the security boundary.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, AuthMethod};
use crate::clock::Clock;
use crate::email::{BauthEmails, EmailSender, default_emails};
use crate::error::{Error, Result};
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::session::{IssuedSession, SessionContext, SessionManager, hash_token};
use crate::storage::{
    TokenHash, User, UserId, UserStore, VerificationPurpose, VerificationToken,
    VerificationTokenStore,
};

const MAGIC_LINK_TOKEN_BYTES: usize = 32;

/// Placeholder substituted with the generated token in URL templates.
pub const TOKEN_PLACEHOLDER: &str = "{token}";

/// Configuration for issuing and consuming magic-link login tokens.
#[derive(Clone)]
pub struct MagicLinkConfig {
    /// Token lifetime. Short by design — the link is the credential and a
    /// stale link sitting in an inbox is a takeover vector.
    pub token_lifetime: Duration,
    /// URL template used in magic-link emails. The literal substring
    /// `{token}` is replaced with the generated token at send time.
    pub url_template: String,
    /// When `true`, a request for an unknown email provisions a new user
    /// (email unverified until the link is consumed). When `false`, the
    /// request silently succeeds without sending mail — same shape as
    /// `request_password_reset` for unknown addresses, so the endpoint
    /// does not leak which emails are registered.
    pub allow_signup: bool,
    /// Rate-limit policies applied to the request endpoint. Both the
    /// per-IP and per-identifier policies are checked; both must clear
    /// for the request to proceed.
    pub rate_limits: MagicLinkRateLimits,
    /// Renderer for the magic-link email. Defaults to
    /// [`DefaultBauthEmails`](crate::email::DefaultBauthEmails); hosts that
    /// want branded copy override this with an [`Arc<dyn BauthEmails>`].
    pub emails: Arc<dyn BauthEmails>,
}

/// Rate-limit policies for the magic-link request endpoint.
#[derive(Debug, Clone, Copy)]
pub struct MagicLinkRateLimits {
    pub request_per_ip: Option<RateLimitPolicy>,
    pub request_per_identifier: Option<RateLimitPolicy>,
}

impl MagicLinkRateLimits {
    /// Turn off every policy. Equivalent to wiring a
    /// [`NoopRateLimiter`](crate::rate_limit::NoopRateLimiter) but keeps
    /// the limiter free of fan-out on hot paths.
    pub const fn disabled() -> Self {
        Self {
            request_per_ip: None,
            request_per_identifier: None,
        }
    }
}

impl Default for MagicLinkRateLimits {
    fn default() -> Self {
        Self {
            // Same posture as password reset: a legitimate user clicking
            // "send me a link" a couple of times is fine; an attacker
            // hammering an inbox is not.
            request_per_ip: Some(RateLimitPolicy::new(5, Duration::from_secs(60 * 60))),
            request_per_identifier: Some(RateLimitPolicy::new(3, Duration::from_secs(60 * 60))),
        }
    }
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(60 * 15),
            url_template: format!("https://example.invalid/magic-link?token={TOKEN_PLACEHOLDER}"),
            allow_signup: true,
            rate_limits: MagicLinkRateLimits::default(),
            emails: default_emails(),
        }
    }
}

/// Result of a successful [`MagicLinkManager::consume_magic_link`] call.
#[derive(Debug, Clone)]
pub struct MagicLinkOutcome {
    pub user: User,
    pub session: IssuedSession,
    /// `true` when this consume verified the user's email for the first
    /// time. In the common signup path this means the user was provisioned
    /// by the matching `request_magic_link` call.
    pub is_new_user: bool,
}

/// Manager for magic-link request and consume flows.
#[derive(Clone)]
pub struct MagicLinkManager {
    users: Arc<dyn UserStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    sessions: SessionManager,
    email: Arc<dyn EmailSender>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    rate_limiter: Arc<dyn RateLimiter>,
    config: MagicLinkConfig,
}

impl MagicLinkManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserStore>,
        tokens: Arc<dyn VerificationTokenStore>,
        sessions: SessionManager,
        email: Arc<dyn EmailSender>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        rate_limiter: Arc<dyn RateLimiter>,
        config: MagicLinkConfig,
    ) -> Self {
        Self {
            users,
            tokens,
            sessions,
            email,
            clock,
            audit,
            rate_limiter,
            config,
        }
    }

    /// Issue a magic link to `email`. Returns `Ok(())` regardless of
    /// whether the email is registered (or whether signup was triggered),
    /// matching the silent-success contract of
    /// [`PasswordAuthManager::request_password_reset`] so the endpoint
    /// cannot be used to enumerate accounts.
    ///
    /// [`PasswordAuthManager::request_password_reset`]: crate::password_auth::PasswordAuthManager::request_password_reset
    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "magic_link", user_id = tracing::field::Empty),
    )]
    pub async fn request_magic_link(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = normalize_email(email);
        validate_email(&email_normalized)?;

        self.enforce_rate_limit(
            self.config.rate_limits.request_per_ip,
            "magic_link/request/ip",
            context.ip.as_deref(),
        )
        .await?;
        self.enforce_rate_limit(
            self.config.rate_limits.request_per_identifier,
            "magic_link/request/email",
            Some(email_normalized.as_str()),
        )
        .await?;

        let now = self.clock.now();
        let existing = self.users.find_user_by_email(&email_normalized).await?;

        let user = match (existing, self.config.allow_signup) {
            (Some(user), _) => user,
            (None, true) => {
                let user = User {
                    id: UserId::new(),
                    email: Some(email_normalized.clone()),
                    email_verified_at: None,
                    created_at: now,
                    updated_at: now,
                };
                self.users.create_user(user.clone()).await?;
                user
            }
            (None, false) => {
                // Silent success: do not leak which addresses are registered.
                tracing::info!(outcome = "unknown_email", "magic link request (silent)");
                return Ok(());
            }
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        // Invalidate prior outstanding magic-link tokens so an attacker who
        // grabbed a stale link can't reuse it after a fresh request.
        self.tokens
            .delete_tokens_for_user(user.id, VerificationPurpose::MagicLink)
            .await?;

        let lifetime = chrono::Duration::from_std(self.config.token_lifetime)
            .expect("magic link lifetime overflows chrono::Duration; configure a smaller value");
        let (token, token_hash) = generate_token();
        self.tokens
            .create_token(VerificationToken {
                token_hash,
                user_id: user.id,
                purpose: VerificationPurpose::MagicLink,
                created_at: now,
                expires_at: now + lifetime,
            })
            .await?;

        if user.email.is_some() {
            let url = build_url(&self.config.url_template, &token);
            let email = self.config.emails.magic_link_email(&user, &url);
            self.email.send(email).await?;
        }

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::MagicLinkRequested { user_id: user.id },
            })
            .await;
        tracing::info!(outcome = "sent", "magic link email sent");
        Ok(())
    }

    /// Redeem a magic-link token. Atomically consumes the token (so the
    /// same link cannot be replayed), marks the user's email as verified
    /// if it was not already, and issues a session.
    #[tracing::instrument(
        skip(self, token, context),
        fields(method = "magic_link", user_id = tracing::field::Empty),
    )]
    pub async fn consume_magic_link(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<MagicLinkOutcome> {
        let hash = hash_token(token);
        let now = self.clock.now();
        let Some(record) = self
            .tokens
            .consume_token(&hash, VerificationPurpose::MagicLink)
            .await?
        else {
            tracing::warn!(outcome = "invalid_token", "magic link consume failed");
            return Err(Error::InvalidVerificationToken);
        };
        if record.expires_at <= now {
            tracing::warn!(outcome = "expired_token", "magic link consume failed");
            return Err(Error::InvalidVerificationToken);
        }
        let Some(mut user) = self.users.find_user_by_id(record.user_id).await? else {
            tracing::warn!(outcome = "user_not_found", "magic link consume failed");
            return Err(Error::UserNotFound);
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        let email_was_unverified = user.email_verified_at.is_none();
        if email_was_unverified {
            // Clicking a link sent to the address proves ownership; mark
            // the email verified so subsequent flows that check it (e.g.
            // OAuth linking, password login with `require_email_verification`)
            // see a verified account.
            user.email_verified_at = Some(now);
            user.updated_at = now;
            self.users.update_user(user.clone()).await?;
        }

        let session = self.sessions.create(user.id, context.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::MagicLinkConsumed { user_id: user.id },
            })
            .await;
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::LoginSucceeded {
                    user_id: user.id,
                    method: AuthMethod::MagicLink,
                },
            })
            .await;

        tracing::info!(
            outcome = "succeeded",
            is_new_user = email_was_unverified,
            "magic link login succeeded",
        );
        Ok(MagicLinkOutcome {
            user,
            session,
            is_new_user: email_was_unverified,
        })
    }

    async fn enforce_rate_limit(
        &self,
        policy: Option<RateLimitPolicy>,
        prefix: &str,
        scope: Option<&str>,
    ) -> Result<()> {
        let (Some(policy), Some(scope)) = (policy, scope) else {
            return Ok(());
        };
        let key = format!("{prefix}:{scope}");
        match self.rate_limiter.check(&key, policy).await? {
            RateLimitDecision::Allowed => Ok(()),
            RateLimitDecision::Limited { retry_after } => Err(Error::RateLimited { retry_after }),
        }
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

fn generate_token() -> (String, TokenHash) {
    let mut bytes = [0u8; MAGIC_LINK_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_substitutes_placeholder() {
        let url = build_url("https://x.test/m?token={token}", "abc");
        assert_eq!(url, "https://x.test/m?token=abc");
    }

    #[test]
    fn tokens_are_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
    }
}
