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
use crate::error::EmailResult;
use crate::storage::User;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
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

    fn email_change_confirmation_email(&self, _user: &User, new_email: &str, url: &str) -> Email {
        Email {
            to: new_email.to_string(),
            subject: "Confirm your new email address".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 A request was made to change the email address on an account to this one. \
                 Click the link below to confirm it:\n\n\
                 {url}\n\n\
                 The link can only be used once and expires shortly. \
                 If you did not request this, you can safely ignore this message.\n"
            ),
            body_html: None,
        }
    }

    fn email_change_requested_notification_email(&self, user: &User, new_email: &str) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: email change requested".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 We received a request to change the email address on your account to \
                 {new_email}. The change does not take effect until it is confirmed from the \
                 new address. If this was you, no action is needed.\n\n\
                 If this was not you, sign in with one of your passkeys immediately, review the \
                 sessions on your account, and revoke anything you do not recognise. Contact \
                 support if you cannot regain access.\n"
            ),
            body_html: None,
        }
    }

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

    fn operator_passkey_removed_notification_email(
        &self,
        user: &User,
        passkey_name: Option<&str>,
    ) -> Email {
        let detail = display_passkey_name(passkey_name)
            .map(|name| {
                format!("An administrator removed the passkey named \"{name}\" from your account.")
            })
            .unwrap_or_else(|| "An administrator removed a passkey from your account.".to_string());

        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: a passkey was removed by an administrator".to_string(),
            body_text: format!(
                "Hello,\n\n\
                 {detail} This was an administrative action taken on your account.\n\n\
                 If you have questions about this change, contact support.\n"
            ),
            body_html: None,
        }
    }

    fn operator_sessions_revoked_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: your account was signed out by an administrator".to_string(),
            body_text: "Hello,\n\n\
                 An administrator signed your account out of all of its active sessions. \
                 This was an administrative action taken on your account; you will need to \
                 sign in again with one of your passkeys.\n\n\
                 If you have questions about this change, contact support.\n"
                .to_string(),
            body_html: None,
        }
    }

    fn operator_account_disabled_notification_email(&self, user: &User) -> Email {
        Email {
            to: user.email.clone().unwrap_or_default(),
            subject: "Security notice: your account was disabled by an administrator".to_string(),
            body_text: "Hello,\n\n\
                 An administrator disabled your account. While it is disabled you cannot \
                 sign in or recover access, and any active sessions have been signed out. \
                 This was an administrative action taken on your account; it can be reversed \
                 by an administrator.\n\n\
                 If you have questions about this change, contact support.\n"
                .to_string(),
            body_html: None,
        }
    }

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

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEmailTemplates;

impl EmailTemplates for DefaultEmailTemplates {}

#[derive(Clone)]
pub struct SecurityEmailNotifier {
    sender: Arc<dyn EmailSender>,
    emails: Arc<dyn EmailTemplates>,
}

impl SecurityEmailNotifier {
    pub fn new(sender: Arc<dyn EmailSender>, emails: Arc<dyn EmailTemplates>) -> Self {
        Self { sender, emails }
    }

    pub async fn passkey_registered(&self, user: &User, passkey_name: Option<&str>) {
        self.send_best_effort(user, "passkey registered notification", |emails| {
            emails.passkey_registered_notification_email(user, passkey_name)
        })
        .await;
    }

    pub async fn passkey_removed(&self, user: &User, passkey_name: Option<&str>) {
        self.send_best_effort(user, "passkey removed notification", |emails| {
            emails.passkey_removed_notification_email(user, passkey_name)
        })
        .await;
    }

    pub async fn operator_passkey_removed(&self, user: &User, passkey_name: Option<&str>) {
        self.send_best_effort(user, "operator passkey removed notification", |emails| {
            emails.operator_passkey_removed_notification_email(user, passkey_name)
        })
        .await;
    }

    pub async fn operator_sessions_revoked(&self, user: &User) {
        self.send_best_effort(user, "operator sessions revoked notification", |emails| {
            emails.operator_sessions_revoked_notification_email(user)
        })
        .await;
    }

    pub async fn operator_account_disabled(&self, user: &User) {
        self.send_best_effort(user, "operator account disabled notification", |emails| {
            emails.operator_account_disabled_notification_email(user)
        })
        .await;
    }

    pub async fn other_session_revoked(&self, user: &User) {
        self.send_best_effort(user, "other-session revoked notification", |emails| {
            emails.other_session_revoked_notification_email(user)
        })
        .await;
    }

    pub async fn other_sessions_revoked(&self, user: &User) {
        self.send_best_effort(user, "other-sessions revoked notification", |emails| {
            emails.other_sessions_revoked_notification_email(user)
        })
        .await;
    }

    pub async fn recovery_requested(&self, user: &User) {
        self.send_best_effort(user, "recovery requested notification", |emails| {
            emails.recovery_requested_notification_email(user)
        })
        .await;
    }

    pub async fn recovery_completed(&self, user: &User) {
        self.send_best_effort(user, "recovery completed notification", |emails| {
            emails.recovery_completed_notification_email(user)
        })
        .await;
    }

    pub async fn email_change_requested(&self, user: &User, new_email: &str) {
        self.send_best_effort(user, "email change requested notification", |emails| {
            emails.email_change_requested_notification_email(user, new_email)
        })
        .await;
    }

    pub(crate) async fn send_best_effort(
        &self,
        user: &User,
        what: &'static str,
        render: impl FnOnce(&dyn EmailTemplates) -> Email,
    ) {
        if user.email.is_none() {
            tracing::debug!(
                user_id = %user.id,
                "{what} email skipped because user has no email"
            );
            return;
        }

        let email = render(self.emails.as_ref());
        if let Err(err) = self.sender.send(email).await {
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
