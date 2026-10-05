use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{StorageError, StorageResult};
use crate::storage::{AccountStatus, AuthenticationPurpose, VerificationPurpose};

pub fn purpose_to_str(purpose: VerificationPurpose) -> &'static str {
    match purpose {
        VerificationPurpose::Signup => "signup",
        VerificationPurpose::Recovery => "recovery",
        VerificationPurpose::EmailChange => "email_change",
    }
}

pub fn purpose_from_str(raw: &str) -> StorageResult<VerificationPurpose> {
    match raw {
        "signup" => Ok(VerificationPurpose::Signup),
        "recovery" => Ok(VerificationPurpose::Recovery),
        "email_change" => Ok(VerificationPurpose::EmailChange),
        other => Err(StorageError::msg(format!(
            "unknown verification purpose `{other}` in storage"
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

pub fn account_status_to_str(status: &AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "active",
        AccountStatus::Disabled { .. } => "disabled",
    }
}

pub fn account_status_from_parts(
    discriminant: &str,
    disabled_at: Option<DateTime<Utc>>,
) -> StorageResult<AccountStatus> {
    match discriminant {
        "active" => Ok(AccountStatus::Active),
        "disabled" => {
            let at = disabled_at.ok_or_else(|| {
                StorageError::msg(
                    "disabled account status missing disabled_at timestamp in storage",
                )
            })?;
            Ok(AccountStatus::Disabled { at })
        }
        other => Err(StorageError::msg(format!(
            "unknown account status `{other}` in storage"
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
        assert_eq!(purpose_to_str(VerificationPurpose::Signup), "signup");
        assert_eq!(purpose_to_str(VerificationPurpose::Recovery), "recovery");
        assert_eq!(
            purpose_to_str(VerificationPurpose::EmailChange),
            "email_change"
        );
    }

    #[test]
    fn purpose_round_trips() {
        for p in [
            VerificationPurpose::Signup,
            VerificationPurpose::Recovery,
            VerificationPurpose::EmailChange,
        ] {
            assert_eq!(purpose_from_str(purpose_to_str(p)).unwrap(), p);
        }
    }

    #[test]
    fn purpose_from_str_rejects_unknown() {
        assert!(purpose_from_str("nope").is_err());
    }

    #[test]
    fn purpose_str_matches_serde_rename() {
        for p in [
            VerificationPurpose::Signup,
            VerificationPurpose::Recovery,
            VerificationPurpose::EmailChange,
        ] {
            let serde_form = serde_json::to_value(p).unwrap();
            assert_eq!(
                serde_form,
                serde_json::Value::String(purpose_to_str(p).to_string())
            );
        }
    }

    #[test]
    fn authentication_purpose_round_trips_and_matches_serde() {
        for p in [AuthenticationPurpose::Login, AuthenticationPurpose::Reauth] {
            let raw = authentication_purpose_to_str(p);
            assert_eq!(authentication_purpose_from_str(raw).unwrap(), p);
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                serde_json::Value::String(raw.to_string())
            );
        }
        assert!(authentication_purpose_from_str("nope").is_err());
    }

    #[test]
    fn account_status_round_trips() {
        let at = Utc
            .with_ymd_and_hms(2026, 2, 15, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        for status in [AccountStatus::Active, AccountStatus::Disabled { at }] {
            let disc = account_status_to_str(&status);
            let rebuilt = account_status_from_parts(disc, status.disabled_at()).unwrap();
            assert_eq!(rebuilt, status);
        }
    }

    #[test]
    fn account_status_from_parts_rejects_bad_input() {
        assert!(account_status_from_parts("banned", None).is_err());
        assert!(account_status_from_parts("disabled", None).is_err());
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
