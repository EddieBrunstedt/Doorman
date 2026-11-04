use chrono::{DateTime, Utc};
use doorman_core::encoding::{
    authentication_purpose_from_str, authentication_purpose_to_str, client_ip_from_str,
    purpose_from_str, purpose_to_str, registration_purpose_from_str, registration_purpose_to_str,
    session_transport_from_parts, session_transport_to_str, user_status_from_parts,
    user_status_to_str,
};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    DpopProofId, EmailLink, JwkThumbprint, PasskeyChallengeId, Session, SessionId, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, UsedDpopProof, User, UserId,
};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::db::err;

// A core type as this adapter stores it. The row type, not core's, fixes the stored format, so a
// change to core's type breaks this crate's build instead of the rows already written.
pub(crate) trait Stored: Sized {
    type Row: Serialize + DeserializeOwned;

    fn to_row(&self) -> Self::Row;

    fn from_row(row: Self::Row) -> StorageResult<Self>;
}

pub(crate) fn encode<T: Stored>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(&value.to_row()).map_err(err)
}

pub(crate) fn decode<T: Stored>(bytes: &[u8]) -> StorageResult<T> {
    T::from_row(serde_json::from_slice(bytes).map_err(err)?)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// Bytes stored as lowercase hex text.
pub(crate) struct Hex<B>(B);

impl<B: AsRef<[u8]>> Serialize for Hex<B> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&doorman_core::encoding::hex(self.0.as_ref()))
    }
}

impl<'de, B: TryFrom<Vec<u8>>> Deserialize<'de> for Hex<B> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = unhex(&text).ok_or_else(|| D::Error::custom("not hex text"))?;
        B::try_from(bytes)
            .map(Self)
            .map_err(|_| D::Error::custom("hex text of the wrong length"))
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct UserRow {
    id: Uuid,
    email: Option<String>,
    signed_up_at: Option<DateTime<Utc>>,
    status: String,
    disabled_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Stored for User {
    type Row = UserRow;

    fn to_row(&self) -> UserRow {
        let User {
            id,
            email,
            signed_up_at,
            status,
            created_at,
            updated_at,
        } = self;
        UserRow {
            id: id.0,
            email: email.clone(),
            signed_up_at: *signed_up_at,
            status: user_status_to_str(status).to_owned(),
            disabled_at: status.disabled_at(),
            created_at: *created_at,
            updated_at: *updated_at,
        }
    }

    fn from_row(row: UserRow) -> StorageResult<Self> {
        Ok(User {
            id: UserId(row.id),
            email: row.email,
            signed_up_at: row.signed_up_at,
            status: user_status_from_parts(&row.status, row.disabled_at)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PasskeyRow {
    credential_id: Hex<Vec<u8>>,
    user_id: Uuid,
    passkey: Hex<Vec<u8>>,
    name: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    aaguid: Option<Uuid>,
    transports: Vec<String>,
    backup_eligible: bool,
    backup_state: bool,
    recovery_cool_down_until: Option<DateTime<Utc>>,
}

impl Stored for StoredPasskey {
    type Row = PasskeyRow;

    fn to_row(&self) -> PasskeyRow {
        let StoredPasskey {
            credential_id,
            user_id,
            passkey,
            name,
            created_at,
            last_used_at,
            aaguid,
            transports,
            backup_eligible,
            backup_state,
            recovery_cool_down_until,
        } = self;
        PasskeyRow {
            credential_id: Hex(credential_id.clone()),
            user_id: user_id.0,
            passkey: Hex(passkey.clone()),
            name: name.clone(),
            created_at: *created_at,
            last_used_at: *last_used_at,
            aaguid: *aaguid,
            transports: transports.clone(),
            backup_eligible: *backup_eligible,
            backup_state: *backup_state,
            recovery_cool_down_until: *recovery_cool_down_until,
        }
    }

    fn from_row(row: PasskeyRow) -> StorageResult<Self> {
        Ok(StoredPasskey {
            credential_id: row.credential_id.0,
            user_id: UserId(row.user_id),
            passkey: row.passkey.0,
            name: row.name,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            aaguid: row.aaguid,
            transports: row.transports,
            backup_eligible: row.backup_eligible,
            backup_state: row.backup_state,
            recovery_cool_down_until: row.recovery_cool_down_until,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: Hex<[u8; 32]>,
    transport: String,
    dpop_jkt: Option<Hex<[u8; 32]>>,
    created_at: DateTime<Utc>,
    last_used_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    ip: String,
    user_agent: Option<String>,
    recovery_cool_down_until: Option<DateTime<Utc>>,
}

impl Stored for Session {
    type Row = SessionRow;

    fn to_row(&self) -> SessionRow {
        let Session {
            id,
            user_id,
            token_hash,
            transport,
            created_at,
            last_used_at,
            expires_at,
            ip,
            user_agent,
            recovery_cool_down_until,
        } = self;
        SessionRow {
            id: id.0,
            user_id: user_id.0,
            token_hash: Hex(token_hash.0),
            transport: session_transport_to_str(transport).to_owned(),
            dpop_jkt: transport.dpop_jkt().map(|JwkThumbprint(jkt)| Hex(jkt)),
            created_at: *created_at,
            last_used_at: *last_used_at,
            expires_at: *expires_at,
            ip: ip.to_string(),
            user_agent: user_agent.clone(),
            recovery_cool_down_until: *recovery_cool_down_until,
        }
    }

    fn from_row(row: SessionRow) -> StorageResult<Self> {
        let jkt = row.dpop_jkt.as_ref().map(|Hex(jkt)| jkt.as_slice());
        Ok(Session {
            id: SessionId(row.id),
            user_id: UserId(row.user_id),
            token_hash: TokenHash(row.token_hash.0),
            transport: session_transport_from_parts(&row.transport, jkt)?,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            expires_at: row.expires_at,
            ip: client_ip_from_str(&row.ip)?,
            user_agent: row.user_agent,
            recovery_cool_down_until: row.recovery_cool_down_until,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct EmailLinkRow {
    token_hash: Hex<[u8; 32]>,
    user_id: Uuid,
    purpose: String,
    owner_email: Option<String>,
    new_email: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl Stored for EmailLink {
    type Row = EmailLinkRow;

    fn to_row(&self) -> EmailLinkRow {
        let EmailLink {
            token_hash,
            user_id,
            purpose,
            owner_email,
            new_email,
            created_at,
            expires_at,
        } = self;
        EmailLinkRow {
            token_hash: Hex(token_hash.0),
            user_id: user_id.0,
            purpose: purpose_to_str(*purpose).to_owned(),
            owner_email: owner_email.clone(),
            new_email: new_email.clone(),
            created_at: *created_at,
            expires_at: *expires_at,
        }
    }

    fn from_row(row: EmailLinkRow) -> StorageResult<Self> {
        Ok(EmailLink {
            token_hash: TokenHash(row.token_hash.0),
            user_id: UserId(row.user_id),
            purpose: purpose_from_str(&row.purpose)?,
            owner_email: row.owner_email,
            new_email: row.new_email,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PasskeyRegistrationRow {
    id: Uuid,
    purpose: String,
    user_id: Uuid,
    state: Hex<Vec<u8>>,
    owner_email: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    recovery_cool_down_until: Option<DateTime<Utc>>,
}

impl Stored for StoredPasskeyRegistration {
    type Row = PasskeyRegistrationRow;

    fn to_row(&self) -> PasskeyRegistrationRow {
        let StoredPasskeyRegistration {
            id,
            purpose,
            user_id,
            state,
            owner_email,
            created_at,
            expires_at,
            recovery_cool_down_until,
        } = self;
        PasskeyRegistrationRow {
            id: id.0,
            purpose: registration_purpose_to_str(*purpose).to_owned(),
            user_id: user_id.0,
            state: Hex(state.clone()),
            owner_email: owner_email.clone(),
            created_at: *created_at,
            expires_at: *expires_at,
            recovery_cool_down_until: *recovery_cool_down_until,
        }
    }

    fn from_row(row: PasskeyRegistrationRow) -> StorageResult<Self> {
        Ok(StoredPasskeyRegistration {
            id: PasskeyChallengeId(row.id),
            purpose: registration_purpose_from_str(&row.purpose)?,
            user_id: UserId(row.user_id),
            state: row.state.0,
            owner_email: row.owner_email,
            created_at: row.created_at,
            expires_at: row.expires_at,
            recovery_cool_down_until: row.recovery_cool_down_until,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PasskeyAuthenticationRow {
    id: Uuid,
    purpose: String,
    state: Hex<Vec<u8>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl Stored for StoredPasskeyAuthentication {
    type Row = PasskeyAuthenticationRow;

    fn to_row(&self) -> PasskeyAuthenticationRow {
        let StoredPasskeyAuthentication {
            id,
            purpose,
            state,
            created_at,
            expires_at,
        } = self;
        PasskeyAuthenticationRow {
            id: id.0,
            purpose: authentication_purpose_to_str(*purpose).to_owned(),
            state: Hex(state.clone()),
            created_at: *created_at,
            expires_at: *expires_at,
        }
    }

    fn from_row(row: PasskeyAuthenticationRow) -> StorageResult<Self> {
        Ok(StoredPasskeyAuthentication {
            id: PasskeyChallengeId(row.id),
            purpose: authentication_purpose_from_str(&row.purpose)?,
            state: row.state.0,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DpopProofRow {
    id: Hex<[u8; 32]>,
    expires_at: DateTime<Utc>,
}

impl Stored for UsedDpopProof {
    type Row = DpopProofRow;

    fn to_row(&self) -> DpopProofRow {
        let UsedDpopProof { id, expires_at } = self;
        DpopProofRow {
            id: Hex(id.0),
            expires_at: *expires_at,
        }
    }

    fn from_row(row: DpopProofRow) -> StorageResult<Self> {
        Ok(UsedDpopProof {
            id: DpopProofId(row.id.0),
            expires_at: row.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use doorman_core::storage::{
        AuthenticationPurpose, EmailLinkPurpose, RegistrationPurpose, SessionTransport, UserStatus,
    };
    use serde_json::{Value, json};

    use super::*;

    // Each fixture is a row as a release of this crate wrote it, so it must keep reading after any
    // change to core's types or to the row types. A new format gets fixtures of its own; the old
    // ones then only read.
    fn assert_format<T: Stored + PartialEq + Debug>(fixture: Value, value: T) {
        let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
        assert_eq!(
            decode::<T>(&bytes).expect("the fixture reads"),
            value,
            "a stored {} reads as written",
            std::any::type_name::<T>(),
        );
        let written: Value =
            serde_json::from_slice(&encode(&value).expect("encode")).expect("written JSON");
        assert_eq!(
            written,
            fixture,
            "a {} is written in the fixture's format",
            std::any::type_name::<T>(),
        );
    }

    fn at(rfc3339: &str) -> DateTime<Utc> {
        rfc3339.parse().expect("timestamp")
    }

    fn uuid(text: &str) -> Uuid {
        text.parse().expect("uuid")
    }

    const USER_ID: &str = "0b9d4a6e-2f7c-4a43-9d1e-5c6b7a8f9e01";
    const CHALLENGE_ID: &str = "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";
    const SESSION_ID: &str = "3a4b5c6d-7e8f-4a1b-9c2d-3e4f5a6b7c8d";
    const CREATED: &str = "2030-05-06T07:08:09.123456789Z";
    const USED: &str = "2030-05-06T08:00:00Z";
    const EXPIRES: &str = "2030-05-07T07:08:09.123456789Z";

    #[test]
    fn every_stored_row_kind_keeps_its_format() {
        assert_format(
            json!({
                "id": USER_ID,
                "email": "user@example.com",
                "signed_up_at": USED,
                "status": "active",
                "disabled_at": null,
                "created_at": CREATED,
                "updated_at": USED,
            }),
            User {
                id: UserId(uuid(USER_ID)),
                email: Some("user@example.com".to_owned()),
                signed_up_at: Some(at(USED)),
                status: UserStatus::Active,
                created_at: at(CREATED),
                updated_at: at(USED),
            },
        );
        assert_format(
            json!({
                "id": USER_ID,
                "email": null,
                "signed_up_at": null,
                "status": "disabled",
                "disabled_at": USED,
                "created_at": CREATED,
                "updated_at": USED,
            }),
            User {
                id: UserId(uuid(USER_ID)),
                email: None,
                signed_up_at: None,
                status: UserStatus::Disabled { at: at(USED) },
                created_at: at(CREATED),
                updated_at: at(USED),
            },
        );
        assert_format(
            json!({
                "credential_id": "c0ffee",
                "user_id": USER_ID,
                "passkey": "7b7d",
                "name": "Laptop",
                "created_at": CREATED,
                "last_used_at": USED,
                "aaguid": CHALLENGE_ID,
                "transports": ["internal", "hybrid"],
                "backup_eligible": true,
                "backup_state": false,
                "recovery_cool_down_until": EXPIRES,
            }),
            StoredPasskey {
                credential_id: vec![0xc0, 0xff, 0xee],
                user_id: UserId(uuid(USER_ID)),
                passkey: b"{}".to_vec(),
                name: Some("Laptop".to_owned()),
                created_at: at(CREATED),
                last_used_at: Some(at(USED)),
                aaguid: Some(uuid(CHALLENGE_ID)),
                transports: vec!["internal".to_owned(), "hybrid".to_owned()],
                backup_eligible: true,
                backup_state: false,
                recovery_cool_down_until: Some(at(EXPIRES)),
            },
        );
        assert_format(
            json!({
                "id": SESSION_ID,
                "user_id": USER_ID,
                "token_hash": "ab".repeat(32),
                "transport": "cookie",
                "dpop_jkt": null,
                "created_at": CREATED,
                "last_used_at": USED,
                "expires_at": EXPIRES,
                "ip": "192.0.2.1",
                "user_agent": "Mozilla/5.0",
                "recovery_cool_down_until": null,
            }),
            Session {
                id: SessionId(uuid(SESSION_ID)),
                user_id: UserId(uuid(USER_ID)),
                token_hash: TokenHash([0xab; 32]),
                transport: SessionTransport::Cookie,
                created_at: at(CREATED),
                last_used_at: at(USED),
                expires_at: at(EXPIRES),
                ip: "192.0.2.1".parse().expect("client IP"),
                user_agent: Some("Mozilla/5.0".to_owned()),
                recovery_cool_down_until: None,
            },
        );
        assert_format(
            json!({
                "id": SESSION_ID,
                "user_id": USER_ID,
                "token_hash": "ab".repeat(32),
                "transport": "dpop",
                "dpop_jkt": "cd".repeat(32),
                "created_at": CREATED,
                "last_used_at": USED,
                "expires_at": EXPIRES,
                "ip": "2001:db8::1",
                "user_agent": null,
                "recovery_cool_down_until": USED,
            }),
            Session {
                id: SessionId(uuid(SESSION_ID)),
                user_id: UserId(uuid(USER_ID)),
                token_hash: TokenHash([0xab; 32]),
                transport: SessionTransport::Dpop {
                    jkt: JwkThumbprint([0xcd; 32]),
                },
                created_at: at(CREATED),
                last_used_at: at(USED),
                expires_at: at(EXPIRES),
                ip: "2001:db8::1".parse().expect("client IP"),
                user_agent: None,
                recovery_cool_down_until: Some(at(USED)),
            },
        );
        assert_format(
            json!({
                "token_hash": "ef".repeat(32),
                "user_id": USER_ID,
                "purpose": "email_change",
                "owner_email": "old@example.com",
                "new_email": "new@example.com",
                "created_at": CREATED,
                "expires_at": EXPIRES,
            }),
            EmailLink {
                token_hash: TokenHash([0xef; 32]),
                user_id: UserId(uuid(USER_ID)),
                purpose: EmailLinkPurpose::EmailChange,
                owner_email: Some("old@example.com".to_owned()),
                new_email: Some("new@example.com".to_owned()),
                created_at: at(CREATED),
                expires_at: at(EXPIRES),
            },
        );
        assert_format(
            json!({
                "id": CHALLENGE_ID,
                "purpose": "add_passkey",
                "user_id": USER_ID,
                "state": "00017eff",
                "owner_email": "user@example.com",
                "created_at": CREATED,
                "expires_at": EXPIRES,
                "recovery_cool_down_until": USED,
            }),
            StoredPasskeyRegistration {
                id: PasskeyChallengeId(uuid(CHALLENGE_ID)),
                purpose: RegistrationPurpose::AddPasskey,
                user_id: UserId(uuid(USER_ID)),
                state: vec![0x00, 0x01, 0x7e, 0xff],
                owner_email: Some("user@example.com".to_owned()),
                created_at: at(CREATED),
                expires_at: at(EXPIRES),
                recovery_cool_down_until: Some(at(USED)),
            },
        );
        assert_format(
            json!({
                "id": CHALLENGE_ID,
                "purpose": "reauth",
                "state": "deadbeef",
                "created_at": CREATED,
                "expires_at": EXPIRES,
            }),
            StoredPasskeyAuthentication {
                id: PasskeyChallengeId(uuid(CHALLENGE_ID)),
                purpose: AuthenticationPurpose::Reauth,
                state: vec![0xde, 0xad, 0xbe, 0xef],
                created_at: at(CREATED),
                expires_at: at(EXPIRES),
            },
        );
        assert_format(
            json!({
                "id": "12".repeat(32),
                "expires_at": EXPIRES,
            }),
            UsedDpopProof {
                id: DpopProofId([0x12; 32]),
                expires_at: at(EXPIRES),
            },
        );
    }

    #[test]
    fn a_row_that_is_not_its_kinds_format_is_a_storage_error() {
        for (row, why) in [
            (
                json!({"id": "12".repeat(31), "expires_at": EXPIRES}),
                "short hex",
            ),
            (
                json!({"id": "zz".repeat(32), "expires_at": EXPIRES}),
                "not hex",
            ),
            (json!({"expires_at": EXPIRES}), "missing field"),
        ] {
            let bytes = serde_json::to_vec(&row).expect("row bytes");
            assert!(decode::<UsedDpopProof>(&bytes).is_err(), "{why}");
        }
    }
}
