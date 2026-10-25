use std::sync::Arc;
use std::time::Duration;

use crate::assembly::{AssemblyError, validate_lifetime};
use crate::clock::{Clock, expiry};
use crate::context::CoreDeps;
use crate::email::EmailAddress;
use crate::error::{Error, Result};
use crate::redeem::{OwnedSecret, OwnerRefusal, Redeemer, owner_refusal};
use crate::session::SessionContext;
use crate::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, User};
use crate::token::{generate_token, hash_token};

pub const TOKEN_PLACEHOLDER: &str = "{token}";

const PLACEHOLDER_URL_HOST: &str = "example.invalid";

#[must_use]
#[derive(Debug)]
pub(crate) enum Issued {
    Link(String),
    Refused(OwnerRefusal),
}

#[derive(Clone)]
pub(crate) struct EmailLinks {
    purpose: EmailLinkPurpose,
    template: String,
    lifetime: Duration,
    links: Arc<dyn EmailLinkStore>,
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
            links: deps.email_links.clone(),
            redeemer: Redeemer::from_deps(deps),
            clock: deps.clock.clone(),
        })
    }

    pub(crate) async fn issue(
        &self,
        owner: &User,
        new_email: Option<&EmailAddress>,
    ) -> Result<Issued> {
        // Redemption checks the owner again, since they can change once the link is out; this
        // check only keeps a link that could never redeem from being sent.
        if let Some(refusal) = owner_refusal(owner, EmailLink::signup_stage(self.purpose)) {
            return Ok(Issued::Refused(refusal));
        }
        let now = self.clock.now();
        let expires_at = expiry(now, self.lifetime)?;
        let (token, token_hash) = generate_token()?;
        self.links
            .replace_link(EmailLink {
                token_hash,
                user_id: owner.id,
                purpose: self.purpose,
                owner_email: owner.email.clone(),
                new_email: new_email.map(|address| address.as_str().to_owned()),
                created_at: now,
                expires_at,
            })
            .await?;

        Ok(Issued::Link(
            self.template.replace(TOKEN_PLACEHOLDER, &token),
        ))
    }

    pub(crate) async fn redeem(
        &self,
        token: &str,
        context: &SessionContext,
    ) -> Result<(User, Option<EmailAddress>)> {
        let taken = self.links.redeem_link(&hash_token(token)).await?;
        let (user, new_email) = self
            .redeemer
            .check_owned(taken, self.purpose, carried_email, context)
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));
        Ok((user, new_email))
    }
}

// Only an email-change link carries an address: the one the user is changing to.
fn carried_email(link: EmailLink) -> Result<Option<EmailAddress>> {
    match (link.purpose, link.new_email) {
        (EmailLinkPurpose::EmailChange, None) => Err(Error::Internal(
            "email-change link carries no new email".to_string(),
        )),
        (_, new_email) => new_email.as_deref().map(EmailAddress::parse).transpose(),
    }
}
