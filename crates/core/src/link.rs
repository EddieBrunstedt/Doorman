use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use crate::assembly::{AssemblyError, validate_lifetime};
use crate::audit::SecretKind;
use crate::clock::{Clock, expiry};
use crate::error::{Error, Result};
use crate::redeem::{Candidate, Redeemer};
use crate::session::SessionContext;
use crate::storage::{
    User, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use crate::token::{generate_token, hash_token};
use crate::verification::TOKEN_PLACEHOLDER;

const PLACEHOLDER_URL_HOST: &str = "example.invalid";

pub(crate) trait LinkPurpose {
    type Payload;
    const PURPOSE: VerificationPurpose;
    const SECRET: SecretKind;
    const FLOW: &'static str;
    const LIFETIME_FIELD: &'static str;
    fn store(payload: Self::Payload) -> Option<String>;
    fn load(token: &VerificationToken) -> Option<Self::Payload>;
}

pub(crate) enum Signup {}

pub(crate) enum Recovery {}

pub(crate) enum EmailChange {}

impl LinkPurpose for Signup {
    type Payload = ();
    const PURPOSE: VerificationPurpose = VerificationPurpose::Signup;
    const SECRET: SecretKind = SecretKind::SignupLink;
    const FLOW: &'static str = "signup";
    const LIFETIME_FIELD: &'static str = "signup token_lifetime";

    fn store((): ()) -> Option<String> {
        None
    }

    fn load(_: &VerificationToken) -> Option<()> {
        Some(())
    }
}

impl LinkPurpose for Recovery {
    type Payload = ();
    const PURPOSE: VerificationPurpose = VerificationPurpose::Recovery;
    const SECRET: SecretKind = SecretKind::RecoveryLink;
    const FLOW: &'static str = "recovery";
    const LIFETIME_FIELD: &'static str = "recovery token_lifetime";

    fn store((): ()) -> Option<String> {
        None
    }

    fn load(_: &VerificationToken) -> Option<()> {
        Some(())
    }
}

impl LinkPurpose for EmailChange {
    type Payload = String;
    const PURPOSE: VerificationPurpose = VerificationPurpose::EmailChange;
    const SECRET: SecretKind = SecretKind::EmailChangeLink;
    const FLOW: &'static str = "account email change";
    const LIFETIME_FIELD: &'static str = "account token_lifetime";

    fn store(new_email: String) -> Option<String> {
        Some(new_email)
    }

    fn load(token: &VerificationToken) -> Option<String> {
        token.new_email.clone()
    }
}

pub(crate) struct EmailedLink<P> {
    template: String,
    lifetime: Duration,
    tokens: Arc<dyn VerificationTokenStore>,
    redeemer: Redeemer,
    clock: Arc<dyn Clock>,
    purpose: PhantomData<fn() -> P>,
}

impl<P> Clone for EmailedLink<P> {
    fn clone(&self) -> Self {
        Self {
            template: self.template.clone(),
            lifetime: self.lifetime,
            tokens: self.tokens.clone(),
            redeemer: self.redeemer.clone(),
            clock: self.clock.clone(),
            purpose: PhantomData,
        }
    }
}

impl<P: LinkPurpose> EmailedLink<P> {
    pub(crate) fn new(
        tokens: Arc<dyn VerificationTokenStore>,
        redeemer: Redeemer,
        clock: Arc<dyn Clock>,
        template: &str,
        lifetime: Duration,
    ) -> std::result::Result<Self, AssemblyError> {
        if !template.contains(TOKEN_PLACEHOLDER) {
            return Err(AssemblyError::InvalidUrlTemplate {
                flow: P::FLOW,
                placeholder: TOKEN_PLACEHOLDER,
            });
        }
        if template.contains(PLACEHOLDER_URL_HOST) {
            return Err(AssemblyError::PlaceholderUrlTemplate {
                flow: P::FLOW,
                placeholder_host: PLACEHOLDER_URL_HOST,
            });
        }
        validate_lifetime(P::LIFETIME_FIELD, lifetime)?;
        Ok(Self {
            template: template.to_owned(),
            lifetime,
            tokens,
            redeemer,
            clock,
            purpose: PhantomData,
        })
    }

    pub(crate) async fn issue(&self, user_id: UserId, payload: P::Payload) -> Result<String> {
        self.tokens
            .delete_tokens_for_user(user_id, P::PURPOSE)
            .await?;

        let now = self.clock.now();
        let expires_at = expiry(now, self.lifetime)?;
        let (token, token_hash) = generate_token()?;
        self.tokens
            .create_token(VerificationToken {
                token_hash,
                user_id,
                purpose: P::PURPOSE,
                new_email: P::store(payload),
                created_at: now,
                expires_at,
            })
            .await?;

        Ok(self.template.replace(TOKEN_PLACEHOLDER, &token))
    }

    pub(crate) async fn redeem(
        &self,
        token: &str,
        context: &SessionContext,
    ) -> Result<(User, P::Payload)> {
        let record = self
            .tokens
            .consume_token(&hash_token(token), P::PURPOSE)
            .await?;
        let candidate = record.map(|record| Candidate {
            owner: Some(record.user_id),
            purpose_matches: record.purpose == P::PURPOSE,
            expires_at: record.expires_at,
            payload: P::load(&record)
                .map(|payload| (record.user_id, payload))
                .ok_or_else(|| Error::Internal("email link carries no payload".to_string())),
        });
        let (user_id, payload) = self
            .redeemer
            .check(P::SECRET, None, candidate, context)
            .await?;
        let user = self
            .redeemer
            .active_owner(P::SECRET, user_id, context)
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));
        Ok((user, payload))
    }
}
