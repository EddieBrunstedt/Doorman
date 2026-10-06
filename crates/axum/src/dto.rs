use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use doorman_core::session::IssuedSession;
use doorman_core::storage::{PasskeySummary, Session, SessionId, StoredPasskey, User, UserId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub passkey_count: u64,
}

impl UserDto {
    pub fn from_user(user: &User, passkey_count: u64) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            email_verified: user.email_verified_at.is_some(),
            created_at: user.created_at,
            passkey_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDto {
    pub id: SessionId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_label: Option<String>,
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
            device_label: value.user_agent.as_deref().and_then(device_label),
            is_current,
        }
    }
}

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

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: UserDto,
    pub session: SessionDto,
    pub token: String,
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse")
            .field("user", &self.user)
            .field("session", &self.session)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AuthResponse {
    pub fn from_issued(user: User, issued: IssuedSession, passkey_count: u64) -> Self {
        Self {
            user: UserDto::from_user(&user, passkey_count),
            session: SessionDto::from_session(&issued.session, true),
            token: issued.token,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyDto {
    pub credential_id: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub aaguid: Option<String>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

impl From<StoredPasskey> for PasskeyDto {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    #[serde(default)]
    pub invite_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupRedeemRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::RegisterPublicKeyCredential,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRedeemRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reauthentication {
    pub challenge_id: String,
    pub assertion: webauthn_rs::prelude::PublicKeyCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailChangeRequest {
    pub new_email: String,
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeleteUserRequest {
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemovePasskeyRequest {
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevokeSessionRequest {
    #[serde(default)]
    pub reauthentication: Option<Reauthentication>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailChangeConfirmRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRenameRequest {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge<T> {
    pub challenge_id: String,
    pub options: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyAuthenticateFinishRequest {
    pub challenge_id: String,
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
            last_used_at: now,
            expires_at: now,
            ip: None,
            user_agent: ua.map(ToOwned::to_owned),
            recovery_cool_down_until: None,
        }
    }

    #[test]
    fn auth_response_debug_redacts_token() {
        let now = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let response = AuthResponse {
            user: UserDto {
                id: UserId::new(),
                email: Some("user@example.com".to_string()),
                email_verified: true,
                created_at: now,
                passkey_count: 1,
            },
            session: SessionDto::from_session(&session_with_ua(None), true),
            token: "super-secret-bearer-token".to_string(),
        };

        let rendered = format!("{response:?}");
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "Debug output leaked the cleartext token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
        let json = serde_json::to_string(&response).expect("serialize");
        assert!(json.contains("super-secret-bearer-token"));
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
