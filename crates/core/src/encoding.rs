use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::client_ip::ClientIp;
use crate::error::{StorageError, StorageResult};
use crate::storage::{
    AuthenticationPurpose, EmailLinkPurpose, JwkThumbprint, RegistrationPurpose, SessionTransport,
    UserStatus,
};

pub fn purpose_to_str(purpose: EmailLinkPurpose) -> &'static str {
    match purpose {
        EmailLinkPurpose::Signup => "signup",
        EmailLinkPurpose::Recovery => "recovery",
        EmailLinkPurpose::EmailChange => "email_change",
    }
}

pub fn purpose_from_str(raw: &str) -> StorageResult<EmailLinkPurpose> {
    match raw {
        "signup" => Ok(EmailLinkPurpose::Signup),
        "recovery" => Ok(EmailLinkPurpose::Recovery),
        "email_change" => Ok(EmailLinkPurpose::EmailChange),
        other => Err(StorageError::msg(format!(
            "unknown email link purpose `{other}` in storage"
        ))),
    }
}

pub fn authentication_purpose_to_str(purpose: AuthenticationPurpose) -> &'static str {
    match purpose {
        AuthenticationPurpose::Login => "login",
        AuthenticationPurpose::Reauth => "reauth",
    }
}

pub fn authentication_purpose_from_str(raw: &str) -> StorageResult<AuthenticationPurpose> {
    match raw {
        "login" => Ok(AuthenticationPurpose::Login),
        "reauth" => Ok(AuthenticationPurpose::Reauth),
        other => Err(StorageError::msg(format!(
            "unknown authentication purpose `{other}` in storage"
        ))),
    }
}

pub fn registration_purpose_to_str(purpose: RegistrationPurpose) -> &'static str {
    match purpose {
        RegistrationPurpose::Signup => "signup",
        RegistrationPurpose::Recovery => "recovery",
        RegistrationPurpose::AddPasskey => "add_passkey",
    }
}

pub fn registration_purpose_from_str(raw: &str) -> StorageResult<RegistrationPurpose> {
    match raw {
        "signup" => Ok(RegistrationPurpose::Signup),
        "recovery" => Ok(RegistrationPurpose::Recovery),
        "add_passkey" => Ok(RegistrationPurpose::AddPasskey),
        other => Err(StorageError::msg(format!(
            "unknown registration purpose `{other}` in storage"
        ))),
    }
}

pub fn session_transport_to_str(transport: &SessionTransport) -> &'static str {
    match transport {
        SessionTransport::Cookie => "cookie",
        SessionTransport::Dpop { .. } => "dpop",
    }
}

pub fn session_transport_from_parts(
    discriminant: &str,
    dpop_jkt: Option<&[u8]>,
) -> StorageResult<SessionTransport> {
    match (discriminant, dpop_jkt) {
        ("cookie", None) => Ok(SessionTransport::Cookie),
        ("dpop", Some(jkt)) => {
            let jkt = <[u8; 32]>::try_from(jkt).map_err(|_| {
                StorageError::msg("DPoP session's JWK thumbprint is not 32 bytes in storage")
            })?;
            Ok(SessionTransport::Dpop {
                jkt: JwkThumbprint(jkt),
            })
        }
        ("cookie", Some(_)) => Err(StorageError::msg(
            "cookie session carries a JWK thumbprint in storage",
        )),
        ("dpop", None) => Err(StorageError::msg(
            "DPoP session missing its JWK thumbprint in storage",
        )),
        (other, _) => Err(StorageError::msg(format!(
            "unknown session transport `{other}` in storage"
        ))),
    }
}

pub fn client_ip_from_str(raw: &str) -> StorageResult<ClientIp> {
    raw.parse()
        .map_err(|_| StorageError::msg(format!("invalid client IP `{raw}` in storage")))
}

pub fn user_status_to_str(status: &UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Disabled { .. } => "disabled",
    }
}

pub fn user_status_from_parts(
    discriminant: &str,
    disabled_at: Option<DateTime<Utc>>,
) -> StorageResult<UserStatus> {
    match discriminant {
        "active" => Ok(UserStatus::Active),
        "disabled" => {
            let at = disabled_at.ok_or_else(|| {
                StorageError::msg("disabled user status missing disabled_at timestamp in storage")
            })?;
            Ok(UserStatus::Disabled { at })
        }
        other => Err(StorageError::msg(format!(
            "unknown user status `{other}` in storage"
        ))),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn transports_to_str(transports: &[String]) -> String {
    transports.join(",")
}

pub fn transports_from_str(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|seg| !seg.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn aaguid_to_str(aaguid: Option<Uuid>) -> Option<String> {
    aaguid.map(|u| u.to_string())
}

pub fn aaguid_from_str(s: Option<String>) -> StorageResult<Option<Uuid>> {
    s.map(|raw| Uuid::parse_str(&raw).map_err(|e| StorageError::msg(e.to_string())))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn purpose_strings_are_stable() {
        assert_eq!(purpose_to_str(EmailLinkPurpose::Signup), "signup");
        assert_eq!(purpose_to_str(EmailLinkPurpose::Recovery), "recovery");
        assert_eq!(
            purpose_to_str(EmailLinkPurpose::EmailChange),
            "email_change"
        );
    }

    #[test]
    fn purpose_round_trips() {
        for p in [
            EmailLinkPurpose::Signup,
            EmailLinkPurpose::Recovery,
            EmailLinkPurpose::EmailChange,
        ] {
            assert_eq!(purpose_from_str(purpose_to_str(p)).unwrap(), p);
        }
    }

    #[test]
    fn purpose_from_str_rejects_unknown() {
        assert!(purpose_from_str("nope").is_err());
    }

    #[test]
    fn authentication_purpose_round_trips() {
        for p in [AuthenticationPurpose::Login, AuthenticationPurpose::Reauth] {
            let raw = authentication_purpose_to_str(p);
            assert_eq!(authentication_purpose_from_str(raw).unwrap(), p);
        }
        assert!(authentication_purpose_from_str("nope").is_err());
    }

    #[test]
    fn registration_purpose_round_trips() {
        for p in [
            RegistrationPurpose::Signup,
            RegistrationPurpose::Recovery,
            RegistrationPurpose::AddPasskey,
        ] {
            let raw = registration_purpose_to_str(p);
            assert_eq!(registration_purpose_from_str(raw).unwrap(), p);
        }
        assert!(registration_purpose_from_str("nope").is_err());
    }

    #[test]
    fn session_transport_round_trips() {
        let dpop = SessionTransport::Dpop {
            jkt: JwkThumbprint([7u8; 32]),
        };
        for t in [SessionTransport::Cookie, dpop] {
            let jkt = t.dpop_jkt().map(|jkt| jkt.0);
            let raw = session_transport_to_str(&t);
            assert_eq!(
                session_transport_from_parts(raw, jkt.as_ref().map(|j| j.as_slice())).unwrap(),
                t
            );
        }
    }

    #[test]
    fn session_transport_from_parts_rejects_bad_input() {
        let jkt = [7u8; 32];
        assert!(session_transport_from_parts("nope", None).is_err());
        assert!(session_transport_from_parts("cookie", Some(&jkt)).is_err());
        assert!(session_transport_from_parts("dpop", None).is_err());
        assert!(session_transport_from_parts("dpop", Some(&jkt[..31])).is_err());
    }

    #[test]
    fn client_ip_round_trips_and_refuses_garbage() {
        for raw in ["192.0.2.1", "2001:db8::1"] {
            assert_eq!(client_ip_from_str(raw).unwrap().to_string(), raw);
        }
        assert!(client_ip_from_str("nope").is_err());
    }

    #[test]
    fn user_status_round_trips() {
        let at = Utc
            .with_ymd_and_hms(2026, 2, 15, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        for status in [UserStatus::Active, UserStatus::Disabled { at }] {
            let disc = user_status_to_str(&status);
            let rebuilt = user_status_from_parts(disc, status.disabled_at()).unwrap();
            assert_eq!(rebuilt, status);
        }
    }

    #[test]
    fn user_status_from_parts_rejects_bad_input() {
        assert!(user_status_from_parts("banned", None).is_err());
        assert!(user_status_from_parts("disabled", None).is_err());
    }

    #[test]
    fn hex_is_lowercase_and_two_chars_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(hex(&[]), "");
        let h = hex(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn transports_round_trip() {
        let t = vec!["usb".to_string(), "nfc".to_string(), "internal".to_string()];
        assert_eq!(transports_to_str(&t), "usb,nfc,internal");
        assert_eq!(transports_from_str("usb,nfc,internal"), t);
    }

    #[test]
    fn transports_empty_round_trips_to_empty_vec() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(transports_to_str(&empty), "");
        assert_eq!(transports_from_str(""), empty);
    }

    #[test]
    fn transports_from_str_drops_empty_segments() {
        assert_eq!(
            transports_from_str(",usb,,nfc,"),
            vec!["usb".to_string(), "nfc".to_string()]
        );
    }

    #[test]
    fn aaguid_round_trips() {
        let id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let s = aaguid_to_str(Some(id));
        assert_eq!(s.as_deref(), Some("00000000-0000-0000-0000-000000000001"));
        assert_eq!(aaguid_from_str(s).unwrap(), Some(id));

        assert_eq!(aaguid_to_str(None), None);
        assert_eq!(aaguid_from_str(None).unwrap(), None);
    }

    #[test]
    fn aaguid_from_str_rejects_garbage() {
        assert!(aaguid_from_str(Some("not-a-uuid".to_string())).is_err());
    }
}
