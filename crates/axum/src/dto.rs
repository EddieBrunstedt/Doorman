use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use doorman_core::session::{IssuedSession, ResolvedSession};
use doorman_core::storage::{
    ClientIp, PasskeySummary, SessionId, SessionSummary, SessionTransport, User, UserId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub id: UserId,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub passkey_count: u64,
}

impl UserDto {
    pub fn from_user(user: &User, passkey_count: u64) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            created_at: user.created_at,
            passkey_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDto {
    pub id: SessionId,
    pub transport: SessionTransport,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: ClientIp,
    pub user_agent: Option<String>,
    pub device_label: Option<String>,
    pub is_current: bool,
}

impl SessionDto {
    pub fn new(value: &SessionSummary, is_current: bool) -> Self {
        Self {
            id: value.id,
            transport: value.transport,
            created_at: value.created_at,
            expires_at: value.expires_at,
            ip: value.ip,
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

// A cookie session's token goes only in its cookie, so this response has no field that could
// carry it to a page script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: UserDto,
    pub session: SessionDto,
}

impl AuthResponse {
    pub fn new(user: &User, passkey_count: u64, session: &ResolvedSession) -> Self {
        Self {
            user: UserDto::from_user(user, passkey_count),
            session: SessionDto::new(session, true),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DpopAuthResponse {
    pub user: UserDto,
    pub session: SessionDto,
    pub token: String,
}

impl std::fmt::Debug for DpopAuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopAuthResponse")
            .field("user", &self.user)
            .field("session", &self.session)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl DpopAuthResponse {
    pub fn from_issued(user: &User, passkey_count: u64, issued: IssuedSession) -> Self {
        Self {
            user: UserDto::from_user(user, passkey_count),
            session: SessionDto::new(&issued.session, true),
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
pub struct PasskeyRegisterFinishRequest {
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
pub struct DestructiveActionRequest {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthenticateFinishRequest {
    pub challenge_id: String,
    pub response: webauthn_rs::prelude::PublicKeyCredential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    fn session_with_ua(ua: Option<&str>) -> SessionSummary {
        let now = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        SessionSummary {
            id: SessionId::new(),
            user_id: UserId::new(),
            transport: SessionTransport::Dpop {
                jkt: doorman_core::storage::JwkThumbprint([9u8; 32]),
            },
            created_at: now,
            last_used_at: now,
            expires_at: now,
            ip: "192.0.2.1".parse().expect("client IP"),
            user_agent: ua.map(ToOwned::to_owned),
            recovery_cool_down_until: None,
        }
    }

    fn user_dto() -> UserDto {
        UserDto {
            id: UserId::new(),
            email: Some("user@example.com".to_string()),
            created_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            passkey_count: 1,
        }
    }

    #[test]
    fn a_cookie_session_response_has_no_token() {
        let response = AuthResponse {
            user: user_dto(),
            session: SessionDto::new(&session_with_ua(None), true),
        };

        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(
            json.as_object().map(|body| body.keys().collect::<Vec<_>>()),
            Some(vec![&"session".to_owned(), &"user".to_owned()]),
        );
    }

    #[test]
    fn dpop_auth_response_debug_redacts_token() {
        let response = DpopAuthResponse {
            user: user_dto(),
            session: SessionDto::new(&session_with_ua(None), true),
            token: "super-secret-dpop-token".to_string(),
        };

        let rendered = format!("{response:?}");
        assert!(
            !rendered.contains("super-secret-dpop-token"),
            "Debug output leaked the cleartext token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
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
        let dto = SessionDto::new(&session_with_ua(Some(chrome_mac)), true);
        assert_eq!(dto.device_label.as_deref(), Some("Chrome on macOS"));

        let dto = SessionDto::new(&session_with_ua(None), false);
        assert_eq!(dto.device_label, None);
    }
}
