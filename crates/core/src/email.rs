//! Email transport and email-template customization.
//!
//! Managers build transactional emails through [`BauthEmails`] and hand
//! them to an [`EmailSender`]. The library does not ship a silent
//! transport — every host wires an explicit sender. First-party
//! implementations: [`TerminalEmailSender`] (prints rendered messages to
//! stdout) and [`FileEmailSender`] (writes RFC 822-shaped `.eml` files
//! into a directory). Tests use `CapturingEmailSender` from
//! `crate::memory` behind the `testing` feature; hosts plug in real
//! transports (lettre, resend, SES, …) through the [`EmailSender`]
//! trait.
//!
//! The library uses email purely as a side channel for **signup links**
//! and **recovery links** (plus the recovery-notification email a
//! registered user receives whenever recovery is attempted against their
//! address). The default copy describes a passkey-driven flow; hosts
//! override [`BauthEmails`] to brand it.

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

/// Diagnostic tag returned by [`EmailSender::diagnostic_kind`]. Used by
/// the axum builder's startup sanity checks to surface transports that
/// are not safe in production. `Terminal` and `File` are convenient for
/// local development; both leave the user's recovery / signup links in
/// places that real users will never see.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailSenderKind {
    /// A host-supplied transport. The default for any third-party
    /// implementation; no warning is emitted at build time.
    Custom,
    /// [`TerminalEmailSender`] — prints to stdout, never delivers.
    Terminal,
    /// [`FileEmailSender`] — writes `.eml` files to disk, never
    /// delivers.
    File,
    /// `CapturingEmailSender` from the `testing` feature — for tests
    /// only.
    Capturing,
}

/// Transport for sending rendered transactional emails.
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, email: Email) -> EmailResult<()>;

    /// Used by the axum builder's startup sanity checks to detect
    /// dev-only transports. Third-party implementations should leave
    /// the default in place.
    #[doc(hidden)]
    fn diagnostic_kind(&self) -> EmailSenderKind {
        EmailSenderKind::Custom
    }
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

    fn diagnostic_kind(&self) -> EmailSenderKind {
        EmailSenderKind::Terminal
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

    fn diagnostic_kind(&self) -> EmailSenderKind {
        EmailSenderKind::File
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

    /// Sent to the registered user alongside the recovery link, and again
    /// when a recovery completes successfully. The goal is to make every
    /// recovery attempt visible to the legitimate inbox owner so they
    /// notice an attacker enrolling a new passkey before that passkey is
    /// out of cool-down. Hosts override the copy to point at their
    /// support / sign-out workflow.
    fn recovery_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: account recovery activity".to_string(),
            body_text: "Hello,\n\n\
                 We're letting you know that account recovery activity was just initiated \
                 or completed for your account. \
                 If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your existing passkeys, \
                 review the passkeys registered to your account, and revoke any you \
                 do not recognise. Contact support if you cannot regain access.\n"
                .to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_sender_reports_terminal_kind() {
        let sender: Arc<dyn EmailSender> = Arc::new(TerminalEmailSender);
        assert_eq!(sender.diagnostic_kind(), EmailSenderKind::Terminal);
    }

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
        assert_eq!(sender.diagnostic_kind(), EmailSenderKind::File);

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
