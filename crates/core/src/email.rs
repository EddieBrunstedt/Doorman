//! Email transport and email-template customization.
//!
//! Managers build transactional emails through [`BauthEmails`] and hand
//! them to an [`EmailSender`]. The library does not ship a silent
//! transport — every host wires an explicit sender. First-party
//! implementations: [`TerminalEmailSender`] (prints rendered messages to
//! stdout) and [`FileEmailSender`] (writes RFC 822-shaped `.eml` files
//! into a directory). Tests use `CapturingEmailSender` from
//! `bauth-test-support`; hosts plug in real transports (lettre, resend,
//! SES, …) through the [`EmailSender`] trait.
//!
//! The library uses email purely as a side channel for **signup links**,
//! **recovery links**, and security notifications for recovery, passkey
//! lifecycle, and high-risk session revocation events. The default copy
//! describes a passkey-driven flow; hosts override [`BauthEmails`] to brand it.

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use chrono::Utc;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::error::{EmailError, EmailResult};
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
///
/// The [`Any`] supertrait lets a composition layer (e.g. the axum builder's
/// startup sanity checks) downcast a boxed sender to recognise the bundled
/// dev-only transports; it places no burden on host implementations, which
/// get the blanket `Any` impl for free.
#[async_trait]
pub trait EmailSender: Send + Sync + Any {
    async fn send(&self, email: Email) -> EmailResult<()>;
}

/// Prints every rendered email to stdout in a clearly-labelled block.
///
/// Intended for local development and the bundled example app. Does not
/// deliver mail. Detected at build time by the axum warnings module so
/// hosts who forget to swap in a real transport get a startup nudge.
#[derive(Debug, Default, Clone, Copy)]
pub struct TerminalEmailSender;

#[async_trait]
impl EmailSender for TerminalEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        println!(
            "\n--- bauth email ---\nTo: {}\nSubject: {}\n\n{}\n--- end bauth email ---\n",
            email.to, email.subject, email.body_text
        );
        Ok(())
    }
}

/// Writes each rendered email to `dir/<timestamp>-<seq>.eml` in an
/// RFC 822-shaped layout. Intended for local development and inspecting
/// flows without wiring a real SMTP / API transport.
///
/// The directory must already exist; the sender does not create it.
/// Filenames combine an RFC 3339 UTC timestamp with a per-process
/// counter so multiple emails sent in the same second do not collide.
#[derive(Debug)]
pub struct FileEmailSender {
    dir: PathBuf,
    seq: AtomicU64,
}

impl FileEmailSender {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            seq: AtomicU64::new(0),
        }
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }
}

#[async_trait]
impl EmailSender for FileEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let stamp = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
        let path = self.dir.join(format!("{stamp}-{seq:06}.eml"));

        let mut buf = String::new();
        buf.push_str("To: ");
        buf.push_str(&email.to);
        buf.push_str("\r\n");
        buf.push_str("Subject: ");
        buf.push_str(&email.subject);
        buf.push_str("\r\n");
        buf.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        buf.push_str("\r\n");
        buf.push_str(&email.body_text);
        if !buf.ends_with('\n') {
            buf.push_str("\r\n");
        }

        let mut file = fs::File::create(&path).await.map_err(EmailError::new)?;
        file.write_all(buf.as_bytes())
            .await
            .map_err(EmailError::new)?;
        file.flush().await.map_err(EmailError::new)?;
        Ok(())
    }
}

/// Renders the subject and body for each transactional email the library
/// sends. Hosts implement this trait when they want to customise the copy
/// (brand name, language, HTML body, etc.) without rewriting the auth
/// flows that send them.
///
/// The default impl, [`DefaultBauthEmails`], ships with neutral copy for
/// the built-in passkey-driven flows. Each method has a default body so a
/// host can override one method and inherit the rest:
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
///     fn signup_email(&self, user: &User, url: &str) -> Email {
///         Email {
///             to: user.email.clone().unwrap_or_default(),
///             subject: format!("Finish creating your {} account", self.brand),
///             body_text: format!("Visit {url} to finish setting up your account."),
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
    fn signup_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Finish setting up your account".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 Click the link below to finish creating your account by registering a passkey. \
                 The link can only be used once and expires shortly:\n\n\
                 {url}\n\n\
                 If you did not request this you can safely ignore this message.\n"
            ),
            body_html: None,
        }
    }

    /// Sent to a registered user when their address shows up at the
    /// recovery request endpoint. The link redeems for exactly one action:
    /// starting a passkey registration ceremony against the user. No
    /// session is issued from the click.
    fn recovery_email(&self, user: &User, url: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Recover access to your account".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 Someone — hopefully you — asked to recover access to your account. \
                 Click the link below to register a new passkey on this device:\n\n\
                 {url}\n\n\
                 The link can only be used once and expires shortly. \
                 If you did not request a recovery, ignore this message and \
                 sign in with one of your existing passkeys.\n"
            ),
            body_html: None,
        }
    }

    /// Sent to the registered user alongside the recovery link. The goal
    /// is to make every recovery request visible to the legitimate inbox
    /// owner before a new passkey can be enrolled.
    fn recovery_requested_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: account recovery requested".to_string(),
            body_text: "Hello,\n\n\
                 We received a request to recover access to your account. \
                 If this was you, use the recovery link we sent separately and continue by \
                 registering a new passkey.\n\n\
                 If this was not you, do not open or forward the recovery link. \
                 Sign in with one of your existing passkeys, review the passkeys registered \
                 to your account, and revoke any you do not recognise. Contact support if \
                 you cannot regain access.\n"
                .to_string(),
            body_html: None,
        }
    }

    /// Sent when a recovery completes successfully. The goal is to make the
    /// newly-enrolled passkey visible while the recovery cool-down still
    /// blocks destructive account changes.
    fn recovery_completed_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: account recovery completed".to_string(),
            body_text: "Hello,\n\n\
                 Account recovery just completed for your account, and a new passkey was \
                 registered. If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your existing passkeys \
                 immediately, review the passkeys and sessions on your account, and revoke \
                 anything you do not recognise. Contact support if you cannot regain \
                 access.\n"
                .to_string(),
            body_html: None,
        }
    }

    /// Sent whenever a passkey is successfully registered for the account.
    /// `passkey_name` is the optional user-supplied friendly label; raw
    /// credential ids, attestation data, tokens, and other secrets are not
    /// exposed to email templates.
    fn passkey_registered_notification_email(
        &self,
        user: &User,
        passkey_name: Option<&str>,
    ) -> Email {
        let detail = display_passkey_name(passkey_name)
            .map(|name| format!("A new passkey named \"{name}\" was just registered."))
            .unwrap_or_else(|| "A new passkey was just registered.".to_string());

        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: passkey registered".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 {detail} If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your existing passkeys \
                 immediately, review the passkeys and sessions on your account, and revoke \
                 anything you do not recognise. Contact support if you cannot regain \
                 access.\n"
            ),
            body_html: None,
        }
    }

    /// Sent whenever a passkey is successfully removed from the account.
    /// `passkey_name` is the optional user-supplied friendly label; raw
    /// credential ids and other credential material are not exposed to email
    /// templates.
    fn passkey_removed_notification_email(&self, user: &User, passkey_name: Option<&str>) -> Email {
        let detail = display_passkey_name(passkey_name)
            .map(|name| format!("The passkey named \"{name}\" was just removed from your account."))
            .unwrap_or_else(|| "A passkey was just removed from your account.".to_string());

        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: passkey removed".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 {detail} If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your remaining passkeys \
                 immediately, review the passkeys and sessions on your account, and revoke \
                 anything you do not recognise. Contact support if you cannot sign in or \
                 regain access.\n"
            ),
            body_html: None,
        }
    }

    /// Sent whenever a session other than the caller's current session is
    /// successfully revoked from the account.
    fn other_session_revoked_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: session revoked".to_string(),
            body_text: "Hello,\n\n\
                 A session other than the one you are currently using was just signed out of \
                 your account. If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your passkeys immediately, review the \
                 passkeys and sessions on your account, and revoke anything you do not \
                 recognise. Contact support if you cannot regain access.\n"
                .to_string(),
            body_html: None,
        }
    }

    /// Sent whenever the caller uses the "sign out everywhere else" action.
    fn other_sessions_revoked_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: other sessions revoked".to_string(),
            body_text: "Hello,\n\n\
                 The \"sign out everywhere else\" action just ran for your account. Any other \
                 active sessions were revoked while the session that requested it stayed signed \
                 in. If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your passkeys immediately, review the \
                 passkeys and sessions on your account, and revoke anything you do not \
                 recognise. Contact support if you cannot regain access.\n"
                .to_string(),
            body_html: None,
        }
    }
}

fn display_passkey_name(passkey_name: Option<&str>) -> Option<String> {
    let name = passkey_name?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.replace(['\r', '\n'], " "))
}

/// Stock [`BauthEmails`] impl. Produces neutral copy for the built-in
/// passkey-driven flows. Used as the default when a config does not
/// specify its own.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultBauthEmails;

impl BauthEmails for DefaultBauthEmails {}

/// Best-effort sender for security notifications.
///
/// Managers and bundled HTTP handlers call this only after the protected
/// action has already succeeded. Send failures are logged and deliberately
/// do not roll back the action. Link-delivery emails do not use this helper,
/// so they remain hard failures at the call sites that issue signup /
/// recovery links.
#[derive(Clone)]
pub struct SecurityEmailNotifier {
    sender: Arc<dyn EmailSender>,
    emails: Arc<dyn BauthEmails>,
}

impl SecurityEmailNotifier {
    pub fn new(sender: Arc<dyn EmailSender>, emails: Arc<dyn BauthEmails>) -> Self {
        Self { sender, emails }
    }

    pub async fn passkey_registered(&self, user: &User, passkey_name: Option<&str>) {
        if user.email.is_none() {
            tracing::debug!(
                user_id = %user.id,
                "passkey registered notification skipped because user has no email"
            );
            return;
        }

        let email = self
            .emails
            .passkey_registered_notification_email(user, passkey_name);
        if let Err(err) = self.sender.send(email).await {
            tracing::warn!(
                error = %err,
                user_id = %user.id,
                "passkey registered notification failed"
            );
        }
    }

    pub async fn passkey_removed(&self, user: &User, passkey_name: Option<&str>) {
        if user.email.is_none() {
            tracing::debug!(
                user_id = %user.id,
                "passkey removed notification skipped because user has no email"
            );
            return;
        }

        let email = self
            .emails
            .passkey_removed_notification_email(user, passkey_name);
        if let Err(err) = self.sender.send(email).await {
            tracing::warn!(
                error = %err,
                user_id = %user.id,
                "passkey removed notification failed"
            );
        }
    }

    /// Send the best-effort notification for revoking one other session.
    pub async fn other_session_revoked(&self, user: &User) {
        if user.email.is_none() {
            tracing::debug!(
                user_id = %user.id,
                "other-session revoked notification skipped because user has no email"
            );
            return;
        }

        let email = self.emails.other_session_revoked_notification_email(user);
        if let Err(err) = self.sender.send(email).await {
            tracing::warn!(
                error = %err,
                user_id = %user.id,
                "other-session revoked notification failed"
            );
        }
    }

    /// Send the best-effort notification for "sign out everywhere else".
    pub async fn other_sessions_revoked(&self, user: &User) {
        if user.email.is_none() {
            tracing::debug!(
                user_id = %user.id,
                "other-sessions revoked notification skipped because user has no email"
            );
            return;
        }

        let email = self.emails.other_sessions_revoked_notification_email(user);
        if let Err(err) = self.sender.send(email).await {
            tracing::warn!(
                error = %err,
                user_id = %user.id,
                "other-sessions revoked notification failed"
            );
        }
    }
}

/// Convenience for the default [`Arc<dyn BauthEmails>`] handed to configs
/// that don't otherwise specify a renderer.
pub(crate) fn default_emails() -> Arc<dyn BauthEmails> {
    Arc::new(DefaultBauthEmails)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn terminal_sender_does_not_panic() {
        let sender = TerminalEmailSender;
        sender
            .send(Email {
                to: "test@example.com".into(),
                subject: "hi".into(),
                body_text: "body".into(),
                body_html: None,
            })
            .await
            .expect("send");
    }

    #[tokio::test]
    async fn file_sender_writes_to_dir() {
        let dir = std::env::temp_dir().join(format!(
            "bauth-file-email-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        fs::create_dir_all(&dir).await.expect("mkdir");
        let sender = FileEmailSender::new(&dir);

        sender
            .send(Email {
                to: "user@example.com".into(),
                subject: "Hello".into(),
                body_text: "body line".into(),
                body_html: None,
            })
            .await
            .expect("send");

        let mut entries = fs::read_dir(&dir).await.expect("read_dir");
        let mut written = Vec::new();
        while let Some(entry) = entries.next_entry().await.expect("next") {
            written.push(entry.path());
        }
        assert_eq!(written.len(), 1, "exactly one .eml written");
        let body = fs::read_to_string(&written[0]).await.expect("read");
        assert!(body.contains("To: user@example.com"));
        assert!(body.contains("Subject: Hello"));
        assert!(body.contains("body line"));

        // Best-effort cleanup.
        let _ = fs::remove_dir_all(&dir).await;
    }
}
