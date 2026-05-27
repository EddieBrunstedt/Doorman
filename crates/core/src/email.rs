//! Email transport and email-template customization.
//!
//! Managers build transactional emails through [`BauthEmails`] and hand
//! them to an [`EmailSender`]. Production hosts provide a real transport;
//! tests and local experiments can use [`NoopEmailSender`] or the
//! in-memory sender in [`crate::memory`].

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::EmailResult;
use crate::storage::User;

/// Transactional email ready to hand to a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
}

/// Transport for sending rendered transactional emails.
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, email: Email) -> EmailResult<()>;
}

/// Email sender that accepts mail and drops it.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEmailSender;

#[async_trait]
impl EmailSender for NoopEmailSender {
    async fn send(&self, _email: Email) -> EmailResult<()> {
        Ok(())
    }
}

/// Renders the subject and body for each transactional email the library
/// sends. Hosts implement this trait when they want to customise the copy
/// (brand name, language, HTML body, etc.) without rewriting the auth
/// flows that send them.
///
/// The default impl, [`DefaultBauthEmails`], ships with neutral copy that
/// matches what the library sent before this trait existed. Each method
/// has a default body so a host can override one method and inherit the
/// rest:
///
/// ```ignore
/// use bauth_core::email::{BauthEmails, Email};
/// use bauth_core::storage::User;
///
/// struct MyEmails {
///     brand: String,
/// }
///
/// impl BauthEmails for MyEmails {
///     fn magic_link_email(&self, user: &User, url: &str) -> Email {
///         Email {
///             to: user.email.clone().unwrap_or_default(),
///             subject: format!("Sign in to {}", self.brand),
///             body_text: format!("Visit {url} to sign in."),
///             body_html: None,
///         }
///     }
/// }
/// ```
///
/// The methods only run when [`User::email`] is `Some` — the auth flows
/// guard on that before calling. Default impls populate the `to` field
/// from `user.email.clone().unwrap_or_default()` for convenience; custom
/// impls should do the same.
pub trait BauthEmails: Send + Sync {
    fn magic_link_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Your sign-in link".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 Click the link below to sign in. The link can only be used once and expires shortly:\n\n\
                 {url}\n\n\
                 If you did not request this you can safely ignore this message.\n"
            ),
            body_html: None,
        }
    }
}

/// Stock [`BauthEmails`] impl. Produces the strings the library shipped
/// before email content was customisable. Used as the default when a
/// config does not specify its own.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultBauthEmails;

impl BauthEmails for DefaultBauthEmails {}

/// Convenience for the default [`Arc<dyn BauthEmails>`] handed to configs
/// that don't otherwise specify a renderer.
pub(crate) fn default_emails() -> Arc<dyn BauthEmails> {
    Arc::new(DefaultBauthEmails)
}
