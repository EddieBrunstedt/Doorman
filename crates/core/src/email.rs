#[cfg(feature = "file-email")]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "file-email")]
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
#[cfg(feature = "file-email")]
use chrono::Utc;
#[cfg(feature = "file-email")]
use tokio::fs;
#[cfg(feature = "file-email")]
use tokio::io::AsyncWriteExt;

#[cfg(feature = "file-email")]
use crate::error::EmailError;
use crate::error::{EmailResult, Error, Result};
use crate::storage::User;

// The longest address SMTP can deliver to (RFC 5321's 256-byte path, less its angle brackets).
pub const MAX_EMAIL_ADDRESS_LEN: usize = 254;

// Only `parse` builds one, so storage never sees an address that skipped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmailAddress(String);

impl EmailAddress {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let address = input.trim().to_ascii_lowercase();
        if address.is_empty()
            || address.len() > MAX_EMAIL_ADDRESS_LEN
            || !address.contains('@')
            || address.chars().any(char::is_control)
        {
            return Err(Error::InvalidEmail);
        }
        Ok(Self(address))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailContent {
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
}

impl EmailContent {
    fn addressed_to(self, to: &str) -> Email {
        Email {
            to: to.to_owned(),
            subject: self.subject,
            body_text: self.body_text,
            body_html: self.body_html,
        }
    }
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, email: Email) -> EmailResult<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TerminalEmailSender;

#[async_trait]
impl EmailSender for TerminalEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        println!(
            "\n--- doorman email: start ---\nTo: {}\nSubject: {}\n\n{}\n--- doorman email: end ---\n",
            email.to, email.subject, email.body_text
        );
        Ok(())
    }
}

#[cfg(feature = "file-email")]
#[derive(Debug)]
pub struct FileEmailSender {
    dir: PathBuf,
    seq: AtomicU64,
}

#[cfg(feature = "file-email")]
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

#[cfg(feature = "file-email")]
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

pub trait EmailTemplates: Send + Sync {
    fn signup_email(&self, _user: &User, url: &str) -> EmailContent {
        EmailContent {
            subject: "Finish signing up".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 Click the link below to finish signing up by registering a passkey. \
                 The link can only be used once and expires shortly:\n\n\
                 {url}\n\n\
                 If you did not request this you can safely ignore this message.\n"
            ),
            body_html: None,
        }
    }

    fn recovery_email(&self, _user: &User, url: &str) -> EmailContent {
        EmailContent {
            subject: "Recover access with a new passkey".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 Someone — hopefully you — asked to recover your access. \
                 Click the link below to register a new passkey on this device:\n\n\
                 {url}\n\n\
                 The link can only be used once and expires shortly. \
                 If you did not request a recovery, ignore this message and \
                 log in with one of your existing passkeys.\n"
            ),
            body_html: None,
        }
    }

    fn recovery_requested_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Security notice: recovery requested".to_string(),
            body_text: "Hello,\n\n\
                 We received a request to recover your access. \
                 If this was you, use the recovery link we sent separately and continue by \
                 registering a new passkey.\n\n\
                 If this was not you, do not open or forward the recovery link. \
                 Log in with one of your existing passkeys, review your passkeys, and remove \
                 any you do not recognise. Contact support if you cannot regain access.\n"
                .to_string(),
            body_html: None,
        }
    }

    fn recovery_completed_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Security notice: recovery completed".to_string(),
            body_text: "Hello,\n\n\
                 A recovery just completed for you, and a new passkey was registered. \
                 If this was you, no action is needed.\n\n\
                 If this was not you, log in with one of your existing passkeys \
                 immediately, review your passkeys and sessions, and revoke anything you \
                 do not recognise. Contact support if you cannot regain \
                 access.\n"
                .to_string(),
            body_html: None,
        }
    }

    fn email_change_confirmation_email(
        &self,
        _user: &User,
        _new_email: &str,
        url: &str,
    ) -> EmailContent {
        EmailContent {
            subject: "Confirm your new email address".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 A request was made to use this email address in place of another one. \
                 Click the link below to confirm it:\n\n\
                 {url}\n\n\
                 The link can only be used once and expires shortly. \
                 If you did not request this, you can safely ignore this message.\n"
            ),
            body_html: None,
        }
    }

    fn email_change_requested_notice_email(&self, _user: &User, new_email: &str) -> EmailContent {
        EmailContent {
            subject: "Security notice: email change requested".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 We received a request to change your email address to \
                 {new_email}. The change does not take effect until it is confirmed from the \
                 new address. If this was you, no action is needed.\n\n\
                 If this was not you, log in with one of your passkeys immediately, review your \
                 sessions, and revoke anything you do not recognise. Contact support if you \
                 cannot regain access.\n"
            ),
            body_html: None,
        }
    }

    fn passkey_registered_notice_email(
        &self,
        _user: &User,
        passkey_name: Option<&str>,
    ) -> EmailContent {
        let detail = display_passkey_name(passkey_name)
            .map(|name| format!("A new passkey named \"{name}\" was just registered."))
            .unwrap_or_else(|| "A new passkey was just registered.".to_string());

        EmailContent {
            subject: "Security notice: passkey registered".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 {detail} If this was you, no action is needed.\n\n\
                 If this was not you, log in with one of your existing passkeys \
                 immediately, review your passkeys and sessions, and revoke anything you \
                 do not recognise. Contact support if you cannot regain access.\n"
            ),
            body_html: None,
        }
    }

    fn passkey_removed_notice_email(
        &self,
        _user: &User,
        passkey_name: Option<&str>,
    ) -> EmailContent {
        let detail = display_passkey_name(passkey_name)
            .map(|name| format!("The passkey named \"{name}\" was just removed."))
            .unwrap_or_else(|| "A passkey was just removed.".to_string());

        EmailContent {
            subject: "Security notice: passkey removed".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 {detail} If this was you, no action is needed.\n\n\
                 If this was not you, log in with one of your remaining passkeys \
                 immediately, review your passkeys and sessions, and revoke anything you \
                 do not recognise. Contact support if you cannot log in or regain access.\n"
            ),
            body_html: None,
        }
    }

    fn operator_passkey_removed_notice_email(
        &self,
        _user: &User,
        passkey_name: Option<&str>,
    ) -> EmailContent {
        let detail = display_passkey_name(passkey_name)
            .map(|name| format!("An operator removed the passkey named \"{name}\"."))
            .unwrap_or_else(|| "An operator removed one of your passkeys.".to_string());

        EmailContent {
            subject: "Security notice: a passkey was removed by an operator".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 {detail} This was done by an operator, not from one of your sessions.\n\n\
                 If you have questions about this change, contact support.\n"
            ),
            body_html: None,
        }
    }

    fn operator_sessions_revoked_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Security notice: you were logged out by an operator".to_string(),
            body_text: "Hello,\n\n\
                 An operator ended all of your active sessions. You will need to log in \
                 again with one of your passkeys.\n\n\
                 If you have questions about this change, contact support.\n"
                .to_string(),
            body_html: None,
        }
    }

    fn operator_user_disabled_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Security notice: your access was disabled by an operator".to_string(),
            body_text: "Hello,\n\n\
                 An operator disabled your access. Until an operator enables it again, you \
                 cannot log in or recover access, and your active sessions have ended.\n\n\
                 If you have questions about this change, contact support.\n"
                .to_string(),
            body_html: None,
        }
    }

    fn other_session_revoked_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Security notice: session revoked".to_string(),
            body_text: "Hello,\n\n\
                 A session other than the one you are using was just revoked. If this was \
                 you, no action is needed.\n\n\
                 If this was not you, log in with one of your passkeys immediately, review your \
                 passkeys and sessions, and revoke anything you do not recognise. Contact support if you cannot regain access.\n"
                .to_string(),
            body_html: None,
        }
    }

    fn other_sessions_revoked_notice_email(&self, _user: &User) -> EmailContent {
        EmailContent {
            subject: "Security notice: other sessions revoked".to_string(),
            body_text: "Hello,\n\n\
                 All of your sessions except the one that asked for it were just revoked. \
                 If this was you, no action is needed.\n\n\
                 If this was not you, log in with one of your passkeys immediately, review your \
                 passkeys and sessions, and revoke anything you do not recognise. Contact support if you cannot regain access.\n"
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

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEmailTemplates;

impl EmailTemplates for DefaultEmailTemplates {}

#[derive(Clone)]
pub(crate) struct Mailer {
    sender: Arc<dyn EmailSender>,
    templates: Arc<dyn EmailTemplates>,
}

impl Mailer {
    pub(crate) fn new(sender: Arc<dyn EmailSender>, templates: Arc<dyn EmailTemplates>) -> Self {
        Self { sender, templates }
    }

    pub(crate) async fn send(
        &self,
        to: &str,
        render: impl FnOnce(&dyn EmailTemplates) -> EmailContent,
    ) -> EmailResult<()> {
        let email = render(self.templates.as_ref()).addressed_to(to);
        self.sender.send(email).await
    }

    pub(crate) async fn send_best_effort(
        &self,
        user: &User,
        what: &'static str,
        render: impl FnOnce(&dyn EmailTemplates) -> EmailContent,
    ) {
        let Some(to) = user.email.as_deref() else {
            tracing::debug!(
                user_id = %user.id,
                "{what} email skipped because user has no email"
            );
            return;
        };

        if let Err(err) = self.send(to, render).await {
            tracing::warn!(
                error = %err,
                user_id = %user.id,
                "{what} email failed (best-effort)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_address_trims_and_lowercases_ascii_only() {
        let parsed = |input| EmailAddress::parse(input).expect("valid");
        assert_eq!(parsed("  USER@Example.COM ").as_str(), "user@example.com");
        assert_eq!(
            parsed("JOS\u{c9}@Example.com").as_str(),
            "jos\u{c9}@example.com"
        );
    }

    #[test]
    fn email_address_rejects_malformed() {
        assert!(EmailAddress::parse("nope").is_err());
        assert!(EmailAddress::parse("").is_err());
        assert!(EmailAddress::parse("   ").is_err());
        assert!(EmailAddress::parse("a@b").is_ok());
    }

    #[test]
    fn email_address_rejects_more_than_the_limit() {
        let local = |len| "\u{e9}".repeat(len / 2) + &"a".repeat(len % 2);
        let at_limit = local(MAX_EMAIL_ADDRESS_LEN - "@example.com".len()) + "@example.com";
        assert_eq!(at_limit.len(), MAX_EMAIL_ADDRESS_LEN);
        assert_eq!(
            EmailAddress::parse(&at_limit)
                .expect("at the limit")
                .as_str(),
            at_limit
        );
        let over_limit = format!("a{at_limit}");
        assert!(matches!(
            EmailAddress::parse(&over_limit),
            Err(Error::InvalidEmail)
        ));
    }

    #[test]
    fn email_address_rejects_embedded_control_characters() {
        assert!(EmailAddress::parse("a@b.com\r\nBcc: victim@evil.com").is_err());
        assert!(EmailAddress::parse("a@b.com\nSubject: spoofed").is_err());
        assert!(EmailAddress::parse("a@b.com\0").is_err());
        assert!(EmailAddress::parse("user@example.com").is_ok());
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

    #[cfg(feature = "file-email")]
    #[tokio::test]
    async fn file_sender_writes_to_dir() {
        let dir = std::env::temp_dir().join(format!(
            "doorman-file-email-{}-{}",
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

        let _ = fs::remove_dir_all(&dir).await;
    }
}
