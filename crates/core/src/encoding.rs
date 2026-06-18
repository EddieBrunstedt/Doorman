//! Value-formatting primitives shared by every storage adapter.
//!
//! These functions encode a domain value into the byte-identical string form an
//! adapter writes to a column or key, and decode it back. They are pure format
//! concerns, not storage concerns, and must stay identical across adapters so
//! data written by one version round-trips on the next. Keeping a single source
//! of truth here removes the lockstep-edit hazard of per-adapter copies.
//!
//! Key-layout strings (table prefixes, separators) stay in each adapter; only
//! the value primitives live here.

use std::fmt::Write as _;

use uuid::Uuid;

use crate::error::{StorageError, StorageResult};
use crate::storage::VerificationPurpose;

/// Stable lowercase string for a verification purpose, matching the
/// `snake_case` serde rename on [`VerificationPurpose`] so a stored value is
/// the same whichever side builds it.
pub fn purpose_to_str(purpose: VerificationPurpose) -> &'static str {
    match purpose {
        VerificationPurpose::Signup => "signup",
        VerificationPurpose::Recovery => "recovery",
        VerificationPurpose::EmailChange => "email_change",
    }
}

/// Parse a stored purpose string back into a [`VerificationPurpose`], the
/// inverse of [`purpose_to_str`]. An unknown value is a corrupt or
/// forward-incompatible record and surfaces as a [`StorageError`].
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

/// Lowercase hex rendering of opaque bytes (`{:02x}` per byte), used for keys
/// and column values that carry token hashes or credential ids.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Flatten passkey transport hints into a single comma-separated value.
/// Transport tokens (`usb`, `nfc`, `ble`, `internal`, `hybrid`) never contain
/// commas, so the join is unambiguous; an empty slice yields `""`.
pub fn transports_to_str(transports: &[String]) -> String {
    transports.join(",")
}

/// Split a comma-separated transports value back into the list. Empty segments
/// are dropped so a stored `""` round-trips to an empty `Vec`.
pub fn transports_from_str(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|seg| !seg.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Render an optional AAGUID for a (nullable) string column.
pub fn aaguid_to_str(aaguid: Option<Uuid>) -> Option<String> {
    aaguid.map(|u| u.to_string())
}

/// Parse a nullable AAGUID string column back into a [`Uuid`].
pub fn aaguid_from_str(s: Option<String>) -> StorageResult<Option<Uuid>> {
    s.map(|raw| Uuid::parse_str(&raw).map_err(|e| StorageError::msg(e.to_string())))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Locks [`purpose_to_str`] to the serde `snake_case` rename of
    /// [`VerificationPurpose`]: if the enum's serde form ever drifts from the
    /// hand-written match, this fails loudly.
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
