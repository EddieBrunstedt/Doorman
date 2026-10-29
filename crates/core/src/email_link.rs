use std::sync::Arc;

use crate::audit::Actor;
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::EmailAddress;
use crate::error::{Error, Result};
use crate::lifetime::Lifetime;
use crate::redeem::{OwnedSecret, Redeemer};
use crate::session::SessionContext;
use crate::storage::{EmailLink, EmailLinkPurpose, EmailLinkStore, TokenHash, User, UserId};
use crate::token::{generate_token, hash_token};
use crate::user_records::{OwnerRefusal, UserRecords, owner_refusal};

pub const TOKEN_PLACEHOLDER: &str = "{token}";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkTemplateError {
    #[error(
        "a link template must contain the `{{token}}` placeholder, so the link carries the token"
    )]
    MissingToken,
    #[error("a link template must make an absolute URL: {0}")]
    NotAUrl(url::ParseError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTemplate(String);

impl LinkTemplate {
    pub fn parse(template: impl Into<String>) -> std::result::Result<Self, LinkTemplateError> {
        let template = template.into();
        if !template.contains(TOKEN_PLACEHOLDER) {
            return Err(LinkTemplateError::MissingToken);
        }
        // A token is URL-safe base64, so a link is a URL whenever one made with a stand-in is.
        url::Url::parse(&template.replace(TOKEN_PLACEHOLDER, "token"))
            .map_err(LinkTemplateError::NotAUrl)?;
        Ok(Self(template))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn link(&self, token: &str) -> String {
        self.0.replace(TOKEN_PLACEHOLDER, token)
    }
}

#[derive(Debug, Clone)]
pub struct LinkTemplates {
    pub signup: LinkTemplate,
    pub recovery: LinkTemplate,
    pub email_change: LinkTemplate,
}

#[must_use]
#[derive(Debug)]
pub(crate) enum Issued {
    Link(String),
    Refused(OwnerRefusal),
}

#[derive(Clone)]
pub(crate) struct EmailLinks {
    purpose: EmailLinkPurpose,
    template: LinkTemplate,
    lifetime: Lifetime,
    links: Arc<dyn EmailLinkStore>,
    records: UserRecords,
    redeemer: Redeemer,
    clock: Arc<dyn Clock>,
}

impl EmailLinks {
    pub(crate) fn new(
        deps: &CoreDeps,
        purpose: EmailLinkPurpose,
        template: LinkTemplate,
        lifetime: Lifetime,
    ) -> Self {
        Self {
            purpose,
            template,
            lifetime,
            links: deps.email_links.clone(),
            records: UserRecords::new(deps),
            redeemer: Redeemer::from_deps(deps),
            clock: deps.clock.clone(),
        }
    }

    pub(crate) async fn issue(
        &self,
        owner: &User,
        new_email: Option<&EmailAddress>,
    ) -> Result<Issued> {
        // Redemption checks the owner again, since they can change once the link is out; this
        // check only keeps a link that could never redeem from being written.
        if let Some(refusal) = owner_refusal(owner, EmailLink::signup_stage(self.purpose)) {
            return Ok(Issued::Refused(refusal));
        }
        let now = self.clock.now();
        let expires_at = self.lifetime.ends(now);
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
        match self
            .records
            .confirm_written(owner.id, self.discard(&token_hash))
            .await?
        {
            Ok(_) => Ok(Issued::Link(self.template.link(&token))),
            Err(refusal) => Ok(Issued::Refused(refusal)),
        }
    }

    async fn discard(&self, token_hash: &TokenHash) {
        if let Err(error) = self.links.redeem_link(token_hash).await {
            tracing::warn!(%error, "refused email link left behind; it was never sent");
        }
    }

    pub(crate) async fn redeem(
        &self,
        token: &str,
        context: &SessionContext,
    ) -> Result<(User, Option<EmailAddress>)> {
        let taken = self.links.redeem_link(&hash_token(token)).await?;
        let (user, new_email) = self
            .redeemer
            .check_owned(taken, self.purpose, carried_email, &Actor::from(context))
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));
        Ok((user, new_email))
    }

    // For a refusal that comes once the link is redeemed, so it is audited as the redemption's.
    pub(crate) async fn refuse_owner(
        &self,
        owner: UserId,
        refusal: OwnerRefusal,
        context: &SessionContext,
    ) -> Error {
        self.redeemer
            .refuse_owner::<EmailLink>(self.purpose, owner, refusal, &Actor::from(context))
            .await
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
