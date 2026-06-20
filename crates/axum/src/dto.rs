//! Wire-shape data-transfer objects.
//!
//! These intentionally mirror the [`doorman_core`] types as a thin
//! conversion layer rather than re-exporting the core types directly:
//!
//! - The core types carry a richer surface (e.g. `User::updated_at`,
//!   the raw `StoredPasskey::passkey` blob) that we don't want to leak
//!   over the wire.
//! - JSON shape stability is part of the public API for the HTTP layer,
//!   while the storage shape inside the host's database is not.
//!
//! Hosts that want to ship richer responses on their own `/api/me` route
//! can ignore [`UserDto`] and serialize their own type — the extractors
//! and routes in this crate use the core types internally.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use doorman_core::session::IssuedSession;
use doorman_core::storage::{PasskeySummary, Session, SessionId, StoredPasskey, User, UserId};
use serde::{Deserialize, Serialize};

/// Public JSON representation of a user.
///
/// `passkey_count` is the number of passkeys the user currently has
/// registered. Frontends use it to decide whether to nudge the user to
/// enrol a backup credential (e.g. when the count is 1 right after
/// signup or recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    /// Stable user identifier.
    pub id: UserId,
    /// The user's email address, if set.
    pub email: Option<String>,
    /// Whether the email address has been verified.
    pub email_verified: bool,
    /// When the account was created.
    pub created_at: DateTime<Utc>,
    /// Number of passkeys currently registered to the user.
    pub passkey_count: usize,
}

impl UserDto {
    /// Build the DTO from a core [`User`] and a known passkey count.
    pub fn from_user(user: &User, passkey_count: usize) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            email_verified: user.email_verified_at.is_some(),
            created_at: user.created_at,
            passkey_count,
        }
    }
}

/// Public JSON representation of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDto {
    /// Stable session identifier.
    pub id: SessionId,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
    /// Best-effort client IP captured at session-issue time, mirroring the
    /// value the audit log records. `None` when the proxy chain stripped
    /// the headers we look for.
    pub ip: Option<String>,
    /// Browser/CLI `User-Agent` captured at session-issue time.
    pub user_agent: Option<String>,
    /// Best-effort human label derived from `user_agent` ("Chrome on macOS",
    /// "Safari on iOS", "Firefox on Windows"). Powers a friendly
    /// "your active sessions" list without the frontend re-parsing the raw
    /// UA. `None` when there is no UA or none of the known tokens match.
    pub device_label: Option<String>,
    /// `true` when this dto represents the session the request was made
    /// on. Set by the routes that build a session list via `from_session`.
    pub is_current: bool,
}

impl SessionDto {
    /// Build the DTO from a core [`Session`], flagging whether it is the
    /// session the current request was made on.
    pub fn from_session(value: &Session, is_current: bool) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            expires_at: value.expires_at,
            ip: value.ip.clone(),
            user_agent: value.user_agent.clone(),
            device_label: value.user_agent.as_deref().and_then(device_label),
            is_current,
        }
    }
}

/// Derive a coarse "Browser on OS" label from a `User-Agent` string.
///
/// Intentionally a small heuristic over the common desktop/mobile tokens, not
/// a full UA database: it gives the session list a readable device name and
/// returns `None` when nothing recognisable matches (the frontend can then
/// fall back to showing the raw UA or IP).
fn device_label(ua: &str) -> Option<String> {
    let lower = ua.to_ascii_lowercase();

    let os = if lower.contains("windows") {
        Some("Windows")
    } else if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ios") {
        Some("iOS")
    } else if lower.contains("mac os") || lower.contains("macos") || lower.contains("macintosh") {
        Some("macOS")
    } else if lower.contains("android") {
        Some("Android")
    } else if lower.contains("linux") {
        Some("Linux")
    } else {
        None
    };

    // Order matters: Edge/Chrome both carry "chrome", and Chrome carries
    // "safari", so test the more specific tokens first.
    let browser = if lower.contains("edg/") || lower.contains("edge") {
        Some("Edge")
    } else if lower.contains("firefox") {
        Some("Firefox")
    } else if lower.contains("chrome") || lower.contains("chromium") {
        Some("Chrome")
    } else if lower.contains("safari") {
        Some("Safari")
    } else {
        None
    };

    match (browser, os) {
        (Some(b), Some(o)) => Some(format!("{b} on {o}")),
        (Some(b), None) => Some(b.to_owned()),
        (None, Some(o)) => Some(o.to_owned()),
        (None, None) => None,
    }
}

/// Returned by every endpoint that issues a session: passkey sign-in,
/// signup finish, and recovery finish.
///
/// `token` is the raw bearer token. It is *also* set as an HttpOnly
/// session cookie on the same response, so browser clients can ignore
/// the body field; non-browser clients (mobile, CLI) read it instead
/// of trying to manage cookies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The authenticated user.
    pub user: UserDto,
    /// The newly-issued session.
    pub session: SessionDto,
    /// Raw bearer token, also set as an HttpOnly cookie on the same response.
    pub token: String,
}

impl AuthResponse {
    /// Build the response from the user, the issued session, and the user's
    /// passkey count.
    pub fn from_issued(user: User, issued: IssuedSession, passkey_count: usize) -> Self {
        Self {
            user: UserDto::from_user(&user, passkey_count),
            session: SessionDto::from_session(&issued.session, true),
            token: issued.token,
        }
    }
}

/// Public JSON representation of a registered passkey.
///
/// The device-metadata fields (`aaguid`, `transports`, `backup_eligible`,
/// `backup_state`) are captured at registration and let a management UI label
/// each credential ("synced passkey", "hardware security key") and nudge the
/// user to add a backup when every credential is single-device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyDto {
    /// Raw credential id encoded as URL-safe base64 (no padding). Matches
    /// the encoding the browser uses for `PublicKeyCredential.rawId` when
    /// serialised to JSON.
    pub credential_id: String,
    /// Friendly device name set at registration, if any.
    pub name: Option<String>,
    /// When the credential was registered.
    pub created_at: DateTime<Utc>,
    /// When the credential was last used to authenticate, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Authenticator AAGUID, when the ceremony produced one. Usually `null`
    /// for passkeys, which request no attestation.
    pub aaguid: Option<String>,
    /// Transport hints the authenticator advertised (`"usb"`, `"internal"`,
    /// `"hybrid"`, …). A UI hint, not a security property.
    pub transports: Vec<String>,
    /// `true` when the credential may be backed up or synced across devices.
    pub backup_eligible: bool,
    /// `true` when the credential is currently backed up or synced.
    pub backup_state: bool,
}

impl From<StoredPasskey> for PasskeyDto {
    /// Route through the metadata-only [`PasskeySummary`] projection: the
    /// wire shape never carries the credential blob, so the two conversions
    /// share one field mapping.
    fn from(value: StoredPasskey) -> Self {
        PasskeySummary::from(value).into()
    }
}

impl From<PasskeySummary> for PasskeyDto {
    fn from(value: PasskeySummary) -> Self {
        Self {
            credential_id: URL_SAFE_NO_PAD.encode(&value.credential_id),
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            aaguid: value.aaguid.map(|a| a.to_string()),
            transports: value.transports,
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
        }
    }
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/// Request body for `/auth/signup/request`. The response is always 204
/// regardless of whether the email is already registered, so the endpoint
/// is not an enumeration oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupRequest {
    /// Email address to send the signup link to.
    pub email: String,
}

/// Request body for `/auth/signup/consume`. The token comes from the
/// signup email link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupConsumeRequest {
    /// Single-use signup token from the email link.
    pub token: String,
}

/// Request body shared by the three registration-finish endpoints
/// (`/auth/signup/finish`, `/auth/recovery/finish`,
/// `/auth/passkey/register/finish`). Each echoes the `challenge_id` its
/// matching `start`/`consume` endpoint returned and carries the WebAuthn
/// attestation the browser produced from the embedded `options`; the field
/// shape is identical across all three, so they share one type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    /// The challenge id the matching `start`/`consume` endpoint returned.
    pub challenge_id: String,
    /// The WebAuthn attestation the browser produced.
    pub response: webauthn_rs::prelude::RegisterPublicKeyCredential,
    /// Optional friendly name for the new credential.
    #[serde(default)]
    pub name: Option<String>,
}

/// Request body for `/auth/recovery/request`. The response is always 204
/// regardless of whether the email resolves to a registered user, so the
/// endpoint is not an enumeration oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Email address to send the recovery link to.
    pub email: String,
}

/// Request body for `/auth/recovery/consume`. The token comes from the
/// recovery email link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConsumeRequest {
    /// Single-use recovery token from the email link.
    pub token: String,
}

/// Re-authentication proof a client attaches to a destructive request to
/// prove session recency. Obtained by running the `POST /auth/reauth/start`
/// ceremony and feeding its `options` to `navigator.credentials.get`.
/// Absent-but-required surfaces as `401 reauth_required`; the client then runs
/// the ceremony and retries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reauthentication {
    /// The challenge id the `reauth/start` response returned.
    pub challenge_id: String,
    /// The WebAuthn assertion the browser produced for the challenge.
    pub assertion: webauthn_rs::prelude::PublicKeyCredential,
}

/// Request body for `/auth/account/email`. Starts a verified email change:
/// a confirmation link is sent to `new_email` and the current address is
/// notified. The change only takes effect once the link is confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailChangeRequest {
    /// The address to move the account to once confirmed.
    pub new_email: String,
    /// Optional re-authentication proof, required when the host gates the
    /// email-change request behind re-auth.
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

/// Request body for `DELETE /auth/account`. The body is optional — a client
/// with no re-auth gate (or making its first, proof-less attempt) sends
/// none — so the only field is the optional re-authentication proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    /// Optional re-authentication proof, required when the host gates account
    /// deletion behind re-auth.
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

/// Request body for `DELETE /auth/passkey/{credential_id}`. Optional, like
/// [`DeleteAccountRequest`]: it carries only the re-authentication proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemovePasskeyRequest {
    /// Optional re-authentication proof, required when the host gates passkey
    /// removal behind re-auth.
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

/// Request body for `/auth/account/email/confirm`. The token comes from the
/// confirmation link sent to the new address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailChangeConfirmRequest {
    /// Single-use confirmation token from the new address's email link.
    pub token: String,
}

/// Request body for `PATCH /auth/passkey/{credential_id}`. Sets the
/// credential's friendly label; an absent or `null` `name` clears it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRenameRequest {
    /// The new friendly name for the credential, or `null` to clear it.
    #[serde(default)]
    pub name: Option<String>,
}

/// Returned by both passkey ceremony `start` endpoints. The `options`
/// field is the JSON `webauthn-rs` produces for
/// `navigator.credentials.{create,get}`; we wrap it so the response also
/// carries the `challenge_id` the client must echo back at `finish` time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge<T> {
    /// The challenge id the client must echo back at `finish` time.
    pub challenge_id: String,
    /// The `webauthn-rs` options to pass to the browser ceremony.
    pub options: T,
}

/// Request body for completing passkey authentication.
#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyAuthenticateFinishRequest {
    /// The challenge id the `start` endpoint returned.
    pub challenge_id: String,
    /// The WebAuthn assertion the browser produced.
    pub response: webauthn_rs::prelude::PublicKeyCredential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use doorman_core::storage::{Session, SessionId, TokenHash, UserId};

    fn session_with_ua(ua: Option<&str>) -> Session {
        let now = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        Session {
            id: SessionId::new(),
            user_id: UserId::new(),
            token_hash: TokenHash([0u8; 32]),
            created_at: now,
            expires_at: now,
            ip: None,
            user_agent: ua.map(ToOwned::to_owned),
            recovery_cooldown_until: None,
        }
    }

    #[test]
    fn device_label_recognises_common_user_agents() {
        let chrome_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(device_label(chrome_mac).as_deref(), Some("Chrome on macOS"));

        let safari_ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
             AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(device_label(safari_ios).as_deref(), Some("Safari on iOS"));

        let firefox_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) \
             Gecko/20100101 Firefox/121.0";
        assert_eq!(
            device_label(firefox_win).as_deref(),
            Some("Firefox on Windows")
        );

        // Edge carries "chrome" too; the more specific token wins.
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        assert_eq!(device_label(edge).as_deref(), Some("Edge on Windows"));
    }

    #[test]
    fn device_label_is_none_for_unrecognised_ua() {
        assert_eq!(device_label("curl/8.4.0"), None);
    }

    #[test]
    fn session_dto_populates_device_label_from_user_agent() {
        let chrome_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let dto = SessionDto::from_session(&session_with_ua(Some(chrome_mac)), true);
        assert_eq!(dto.device_label.as_deref(), Some("Chrome on macOS"));

        let dto = SessionDto::from_session(&session_with_ua(None), false);
        assert_eq!(dto.device_label, None);
    }
}
