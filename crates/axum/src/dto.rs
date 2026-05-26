//! Wire-shape data-transfer objects.
//!
//! These intentionally mirror the [`bauth_core`] types as a thin
//! conversion layer rather than re-exporting the core types directly:
//!
//! - The core types carry a richer surface (e.g. `User::updated_at`,
//!   the raw `StoredPasskey::passkey` blob, the OAuth `pkce_verifier`)
//!   that we don't want to leak over the wire.
//! - JSON shape stability is part of the public API for the HTTP layer,
//!   while the storage shape inside the host's database is not.
//!
//! Hosts that want to ship richer responses on their own `/api/me` route
//! can ignore [`UserDto`] and serialize their own type — the extractors
//! and routes in this crate use the core types internally.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bauth_core::session::IssuedSession;
use bauth_core::storage::{OAuthIdentity, Session, SessionId, StoredPasskey, User, UserId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserDto {
    fn from(value: User) -> Self {
        Self {
            id: value.id,
            email: value.email,
            email_verified: value.email_verified_at.is_some(),
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDto {
    pub id: SessionId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl From<Session> for SessionDto {
    fn from(value: Session) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

/// Returned by every endpoint that issues a session: register, login,
/// passkey finish, magic-link consume, OAuth callback.
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
    pub fn from_issued(user: User, issued: IssuedSession) -> Self {
        Self {
            user: user.into(),
            session: issued.session.into(),
            token: issued.token,
        }
    }
}

/// Returned by an authenticated "who am I" endpoint. Includes the active
/// session id and its expiry so a host frontend can render a session-aware
/// header (and prompt re-auth before the cookie quietly stops working).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub user: UserDto,
    pub session: SessionDto,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthIdentityDto {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<OAuthIdentity> for OAuthIdentityDto {
    fn from(value: OAuthIdentity) -> Self {
        Self {
            provider: value.provider,
            subject: value.subject,
            email: value.email,
            created_at: value.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMagicLinkRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkConsumeRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthenticateStartRequest {
    pub email: String,
}

/// Returned by both passkey ceremony `start` endpoints. The `options`
/// field is the JSON `webauthn-rs` produces for
/// `navigator.credentials.{create,get}`; we wrap it so the response also
/// carries the `challenge_id` the client must echo back at `finish` time.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyChallenge<T> {
    pub challenge_id: String,
    pub options: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::RegisterPublicKeyCredential,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyAuthenticateFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::PublicKeyCredential,
}
