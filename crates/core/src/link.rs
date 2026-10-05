//! Emailed links: the single-use URLs the signup, recovery and email-change
//! flows send by email.
//!
//! An [`EmailedLink`] is built once per [`VerificationPurpose`], from that
//! purpose's URL template and lifetime. Its constructor validates both, so a
//! link that would carry no token, point at the stock placeholder host, or
//! never be valid fails assembly instead of reaching an inbox. After that it
//! owns every rule a link of its purpose follows:
//!
//! - [`issue`](EmailedLink::issue) supersedes the owner's earlier links of the
//!   same purpose, stores a fresh token by hash with its expiry and payload,
//!   and returns the URL. Only the URL carries the cleartext token.
//! - [`redeem`](EmailedLink::redeem) takes the token from its store, so it
//!   cannot be replayed, and refuses one issued for another purpose, one past
//!   its lifetime, or one whose owner is no longer active. [`Redeemer`] runs
//!   that sequence and audits every refusal.
//!
//! What a link carries besides its owner is typed per purpose by
//! [`LinkPurpose`]: nothing for signup and recovery, and the normalized new
//! address for an email change.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use crate::assembly::{AssemblyError, validate_lifetime};
use crate::clock::{Clock, expiry};
use crate::error::Result;
use crate::redeem::Redeemer;
use crate::session::SessionContext;
use crate::storage::{
    User, UserId, VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use crate::token::generate_token;
use crate::verification::TOKEN_PLACEHOLDER;

/// Host (DNS suffix) reserved for documentation/examples. A URL template
/// still pointing here is the stock default the host never replaced.
const PLACEHOLDER_URL_HOST: &str = "example.invalid";

/// What sets one kind of emailed link apart: the token purpose it is stored
/// under, the names assembly errors report, and its payload.
pub(crate) trait LinkPurpose {
    /// What a link carries besides its owner.
    type Payload;
    /// The token purpose links of this kind are stored and redeemed under.
    const PURPOSE: VerificationPurpose;
    /// The flow an [`AssemblyError`] names for a bad URL template.
    const FLOW: &'static str;
    /// The field an [`AssemblyError`] names for a bad lifetime.
    const LIFETIME_FIELD: &'static str;
    /// The token row's `new_email` column for `payload`.
    fn store(payload: Self::Payload) -> Option<String>;
    /// The payload read back from a redeemed token, or `None` when the row
    /// lacks it.
    fn load(token: &VerificationToken) -> Option<Self::Payload>;
}

/// A signup link: proves the visitor controls the address they signed up
/// with.
pub(crate) enum Signup {}

/// A recovery link: lets the address on file enrol a new passkey.
pub(crate) enum Recovery {}

/// An email-change link: proves the user controls the new address, which it
/// carries.
pub(crate) enum EmailChange {}

impl LinkPurpose for Signup {
    type Payload = ();
    const PURPOSE: VerificationPurpose = VerificationPurpose::Signup;
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
    /// The already-normalized address the account moves to.
    type Payload = String;
    const PURPOSE: VerificationPurpose = VerificationPurpose::EmailChange;
    const FLOW: &'static str = "account email change";
    const LIFETIME_FIELD: &'static str = "account token_lifetime";

    fn store(new_email: String) -> Option<String> {
        Some(new_email)
    }

    fn load(token: &VerificationToken) -> Option<String> {
        token.new_email.clone()
    }
}

/// Issues and redeems the emailed links of one purpose `P`.
///
/// Cheap to clone: every collaborator is `Arc`-backed.
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
    /// Build the links of purpose `P` from the host's `template` and
    /// `lifetime`.
    ///
    /// Returns [`AssemblyError::InvalidUrlTemplate`] when `template` lacks
    /// [`TOKEN_PLACEHOLDER`], [`AssemblyError::PlaceholderUrlTemplate`] when it
    /// still points at the stock `example.invalid` host, and
    /// [`AssemblyError::InvalidLifetime`] for a zero or implausibly long
    /// `lifetime`.
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

    /// Issue a link for `user_id` carrying `payload` and return its URL.
    /// Earlier links of this purpose for the same user stop redeeming, so a
    /// stale link left in an inbox is dead once a fresh one is requested.
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

    /// Redeem `token` and return its active owner and the link's payload, and
    /// record the owner on the current span's `user_id` field.
    ///
    /// A recognised token is consumed whether or not it redeems, so a link
    /// works at most once. Refusals are audited as
    /// [`RedemptionFailed`](crate::audit::AuditEventKind::RedemptionFailed) and
    /// return [`Error::InvalidVerificationToken`](crate::Error::InvalidVerificationToken),
    /// or [`Error::AccountDisabled`](crate::Error::AccountDisabled) for a
    /// disabled owner.
    pub(crate) async fn redeem(
        &self,
        token: &str,
        context: &SessionContext,
    ) -> Result<(User, P::Payload)> {
        let (user, payload) = self
            .redeemer
            .link(token, P::PURPOSE, context, P::load)
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));
        Ok((user, payload))
    }
}
