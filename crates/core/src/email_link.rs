use std::sync::Arc;
use std::time::Duration;

use crate::assembly::{AssemblyError, validate_lifetime};
use crate::clock::{Clock, expiry};
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::redeem::Redeemer;
use crate::session::SessionContext;
use crate::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, User, UserId};
use crate::token::{generate_token, hash_token};

pub const TOKEN_PLACEHOLDER: &str = "{token}";

const PLACEHOLDER_URL_HOST: &str = "example.invalid";

#[derive(Clone)]
pub(crate) struct EmailLinks {
    purpose: EmailLinkPurpose,
    template: String,
    lifetime: Duration,
    tokens: Arc<dyn EmailLinkStore>,
    redeemer: Redeemer,
    clock: Arc<dyn Clock>,
}

impl EmailLinks {
    pub(crate) fn new(
        deps: &CoreDeps,
        purpose: EmailLinkPurpose,
        template: &str,
        lifetime: Duration,
    ) -> std::result::Result<Self, AssemblyError> {
        let (flow, lifetime_field) = match purpose {
            EmailLinkPurpose::Signup => ("signup", "signup token_lifetime"),
            EmailLinkPurpose::Recovery => ("recovery", "recovery token_lifetime"),
            EmailLinkPurpose::EmailChange => ("email change", "user token_lifetime"),
        };
        if !template.contains(TOKEN_PLACEHOLDER) {
            return Err(AssemblyError::InvalidUrlTemplate {
                flow,
                placeholder: TOKEN_PLACEHOLDER,
            });
        }
        if template.contains(PLACEHOLDER_URL_HOST) {
            return Err(AssemblyError::PlaceholderUrlTemplate {
                flow,
                placeholder_host: PLACEHOLDER_URL_HOST,
            });
        }
        validate_lifetime(lifetime_field, lifetime)?;
        Ok(Self {
            purpose,
            template: template.to_owned(),
            lifetime,
            tokens: deps.email_links.clone(),
            redeemer: Redeemer::from_deps(deps),
            clock: deps.clock.clone(),
        })
    }

    pub(crate) async fn issue(&self, user_id: UserId, new_email: Option<String>) -> Result<String> {
        self.tokens
            .delete_links_for_user(user_id, self.purpose)
            .await?;

        let now = self.clock.now();
        let expires_at = expiry(now, self.lifetime)?;
        let (token, token_hash) = generate_token()?;
        self.tokens
            .create_link(EmailLink {
                token_hash,
                user_id,
                purpose: self.purpose,
                new_email,
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
    ) -> Result<(User, Option<String>)> {
        let taken = self.tokens.redeem_link(&hash_token(token)).await?;
        let (user, new_email) = self
            .redeemer
            .check_owned(taken, self.purpose, carried_email, context)
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));
        Ok((user, new_email))
    }
}

// Only an email-change link carries an address: the one the user is changing to.
fn carried_email(link: EmailLink) -> Result<Option<String>> {
    match (link.purpose, link.new_email) {
        (EmailLinkPurpose::EmailChange, None) => Err(Error::Internal(
            "email-change link carries no new email".to_string(),
        )),
        (_, new_email) => Ok(new_email),
    }
}
