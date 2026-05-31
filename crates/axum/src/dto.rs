//! Wire-shape data-transfer objects.
//!
//! These intentionally mirror the [`bauth_core`] types as a thin
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
use bauth_core::session::IssuedSession;
use bauth_core::storage::{PasskeySummary, Session, SessionId, StoredPasskey, User, UserId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Public JSON representation of a user.
///
/// `passkey_count` is the number of passkeys the user currently has
/// registered. Frontends use it to decide whether to nudge the user to
/// enrol a backup credential (e.g. when the count is 1 right after
/// signup or recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub passkey_count: usize,
}

impl UserDto {
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
    pub id: SessionId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Best-effort client IP captured at session-issue time, mirroring the
    /// value the audit log records. `None` when the proxy chain stripped
    /// the headers we look for.
    pub ip: Option<String>,
    /// Browser/CLI `User-Agent` captured at session-issue time.
    pub user_agent: Option<String>,
    /// `true` when this dto represents the session the request was made
    /// on. Set by the routes that build a session list via `from_session`.
    pub is_current: bool,
}

impl SessionDto {
    pub fn from_session(value: &Session, is_current: bool) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            expires_at: value.expires_at,
            ip: value.ip.clone(),
            user_agent: value.user_agent.clone(),
            is_current,
        }
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
    pub user: UserDto,
    pub session: SessionDto,
    pub token: String,
}

impl AuthResponse {
    pub fn from_issued(user: User, issued: IssuedSession, passkey_count: usize) -> Self {
        Self {
            user: UserDto::from_user(&user, passkey_count),
            session: SessionDto::from_session(&issued.session, true),
            token: issued.token,
        }
    }
}

/// Public JSON representation of a registered passkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyDto {
    /// Raw credential id encoded as URL-safe base64 (no padding). Matches
    /// the encoding the browser uses for `PublicKeyCredential.rawId` when
    /// serialised to JSON.
    pub credential_id: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<StoredPasskey> for PasskeyDto {
    fn from(value: StoredPasskey) -> Self {
        Self {
            credential_id: URL_SAFE_NO_PAD.encode(&value.credential_id),
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
        }
    }
}

impl From<PasskeySummary> for PasskeyDto {
    fn from(value: PasskeySummary) -> Self {
        Self {
            credential_id: URL_SAFE_NO_PAD.encode(&value.credential_id),
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
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
    pub email: String,
}

/// Request body for `/auth/signup/consume`. The token comes from the
/// signup email link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupConsumeRequest {
    pub token: String,
}

/// Request body for `/auth/signup/finish`. Echoes the `challenge_id` the
/// consume endpoint returned and carries the WebAuthn attestation the
/// browser produced from the embedded `options`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::RegisterPublicKeyCredential,
    #[serde(default)]
    pub name: Option<String>,
}

/// Request body for `/auth/recovery/request`. The response is always 204
/// regardless of whether the email resolves to a registered user, so the
/// endpoint is not an enumeration oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub email: String,
}

/// Request body for `/auth/recovery/consume`. The token comes from the
/// recovery email link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConsumeRequest {
    pub token: String,
}

/// Request body for `/auth/recovery/finish`. Echoes the `challenge_id`
/// the consume endpoint returned and carries the WebAuthn attestation the
/// browser produced from the embedded `options`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::RegisterPublicKeyCredential,
    #[serde(default)]
    pub name: Option<String>,
}

/// Returned by both passkey ceremony `start` endpoints. The `options`
/// field is the JSON `webauthn-rs` produces for
/// `navigator.credentials.{create,get}`; we wrap it so the response also
/// carries the `challenge_id` the client must echo back at `finish` time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge<T> {
    pub challenge_id: String,
    pub options: T,
}

/// Request body for completing passkey registration.
#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::RegisterPublicKeyCredential,
    #[serde(default)]
    pub name: Option<String>,
}

/// Request body for completing passkey authentication.
#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyAuthenticateFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::PublicKeyCredential,
}
