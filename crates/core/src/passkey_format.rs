use std::fmt::Debug;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationFormat, AttestationMetadata, COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType,
    COSEOKPKey, COSERSAKey, Credential, ECDSACurve, EDDSACurve, ParsedAttestation,
    ParsedAttestationData, Passkey,
};
use webauthn_rs_proto::{
    AuthenticatorTransport, CredProps, CredentialProtectionPolicy, ExtnState, RegisteredExtensions,
    UserVerificationPolicy,
};

use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use crate::encoding::hex;
use crate::error::{Error, Result};

// Passkeys never expire, so the bytes core hands storage must outlive every webauthn-rs upgrade.
// The format is doorman's own: each conversion below names every field and variant of
// webauthn-rs's types, so a change to them breaks this module's build instead of the stored
// passkeys, and the row types here decide how older rows read.
pub(crate) fn encode(passkey: &Passkey) -> Result<Vec<u8>> {
    let row = PasskeyRow::from_credential(passkey.clone().into())?;
    serde_json::to_vec(&row).map_err(|e| Error::Internal(format!("serialise passkey: {e}")))
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Passkey> {
    let row: PasskeyRow = serde_json::from_slice(bytes)
        .map_err(|e| Error::Internal(format!("deserialise passkey: {e}")))?;
    Ok(Passkey::from(row.into_credential()?))
}

#[derive(Serialize, Deserialize)]
struct PasskeyRow {
    credential_id: Hex<Vec<u8>>,
    public_key: PublicKeyRow,
    counter: u32,
    transports: Option<Vec<TransportRow>>,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
    registration_policy: PolicyRow,
    extensions: ExtensionsRow,
    attestation: AttestationRow,
}

impl PasskeyRow {
    fn from_credential(credential: Credential) -> Result<Self> {
        let Credential {
            cred_id,
            cred,
            counter,
            transports,
            user_verified,
            backup_eligible,
            backup_state,
            registration_policy,
            extensions,
            attestation,
            attestation_format,
        } = credential;
        Ok(Self {
            credential_id: Hex(cred_id),
            public_key: PublicKeyRow::from_key(cred)?,
            counter,
            transports: transports.map(|transports| {
                transports
                    .into_iter()
                    .map(TransportRow::from_transport)
                    .collect()
            }),
            user_verified,
            backup_eligible,
            backup_state,
            registration_policy: PolicyRow::from_policy(registration_policy),
            extensions: ExtensionsRow::from_extensions(extensions),
            attestation: AttestationRow::from_attestation(attestation, attestation_format)?,
        })
    }

    fn into_credential(self) -> Result<Credential> {
        let (attestation, attestation_format) = self.attestation.into_attestation()?;
        Ok(Credential {
            cred_id: self.credential_id.0,
            cred: self.public_key.into_key(),
            counter: self.counter,
            transports: self.transports.map(|transports| {
                transports
                    .into_iter()
                    .map(TransportRow::into_transport)
                    .collect()
            }),
            user_verified: self.user_verified,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            registration_policy: self.registration_policy.into_policy(),
            extensions: self.extensions.into_extensions(),
            attestation,
            attestation_format,
        })
    }
}

// Shaped like a COSE key, with the IANA COSE registry's names for key types, curves and algorithms.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kty")]
enum PublicKeyRow {
    #[serde(rename = "EC2")]
    Ec2 {
        alg: AlgorithmRow,
        crv: Ec2CurveRow,
        x: Hex<Vec<u8>>,
        y: Hex<Vec<u8>>,
    },
    #[serde(rename = "OKP")]
    Okp {
        alg: AlgorithmRow,
        crv: OkpCurveRow,
        x: Hex<Vec<u8>>,
    },
    #[serde(rename = "RSA")]
    Rsa {
        alg: AlgorithmRow,
        n: Hex<Vec<u8>>,
        e: Hex<[u8; 3]>,
    },
}

impl PublicKeyRow {
    fn from_key(key: COSEKey) -> Result<Self> {
        let COSEKey { type_, key } = key;
        let alg = AlgorithmRow::from_algorithm(type_)?;
        Ok(match key {
            COSEKeyType::EC_EC2(COSEEC2Key { curve, x, y }) => Self::Ec2 {
                alg,
                crv: Ec2CurveRow::from_curve(curve),
                x: Hex(x),
                y: Hex(y),
            },
            COSEKeyType::EC_OKP(COSEOKPKey { curve, x }) => Self::Okp {
                alg,
                crv: OkpCurveRow::from_curve(curve),
                x: Hex(x),
            },
            COSEKeyType::RSA(COSERSAKey { n, e }) => Self::Rsa {
                alg,
                n: Hex(n),
                e: Hex(e),
            },
        })
    }

    fn into_key(self) -> COSEKey {
        let (alg, key) = match self {
            Self::Ec2 { alg, crv, x, y } => (
                alg,
                COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: crv.into_curve(),
                    x: x.0,
                    y: y.0,
                }),
            ),
            Self::Okp { alg, crv, x } => (
                alg,
                COSEKeyType::EC_OKP(COSEOKPKey {
                    curve: crv.into_curve(),
                    x: x.0,
                }),
            ),
            Self::Rsa { alg, n, e } => (alg, COSEKeyType::RSA(COSERSAKey { n: n.0, e: e.0 })),
        };
        COSEKey {
            type_: alg.into_algorithm(),
            key,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum AlgorithmRow {
    ES256,
    ES384,
    ES512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    EdDSA,
    RS1,
}

impl AlgorithmRow {
    fn from_algorithm(algorithm: COSEAlgorithm) -> Result<Self> {
        Ok(match algorithm {
            COSEAlgorithm::ES256 => Self::ES256,
            COSEAlgorithm::ES384 => Self::ES384,
            COSEAlgorithm::ES521 => Self::ES512,
            COSEAlgorithm::RS256 => Self::RS256,
            COSEAlgorithm::RS384 => Self::RS384,
            COSEAlgorithm::RS512 => Self::RS512,
            COSEAlgorithm::PS256 => Self::PS256,
            COSEAlgorithm::PS384 => Self::PS384,
            COSEAlgorithm::PS512 => Self::PS512,
            COSEAlgorithm::EDDSA => Self::EdDSA,
            COSEAlgorithm::INSECURE_RS1 => Self::RS1,
            // webauthn-rs uses it only for CTAP's PIN protocol; no credential's key has it.
            COSEAlgorithm::PinUvProtocol => {
                return Err(Error::Internal(
                    "passkey names the PIN/UV protocol as its key's algorithm".to_owned(),
                ));
            }
        })
    }

    fn into_algorithm(self) -> COSEAlgorithm {
        match self {
            Self::ES256 => COSEAlgorithm::ES256,
            Self::ES384 => COSEAlgorithm::ES384,
            Self::ES512 => COSEAlgorithm::ES521,
            Self::RS256 => COSEAlgorithm::RS256,
            Self::RS384 => COSEAlgorithm::RS384,
            Self::RS512 => COSEAlgorithm::RS512,
            Self::PS256 => COSEAlgorithm::PS256,
            Self::PS384 => COSEAlgorithm::PS384,
            Self::PS512 => COSEAlgorithm::PS512,
            Self::EdDSA => COSEAlgorithm::EDDSA,
            Self::RS1 => COSEAlgorithm::INSECURE_RS1,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum Ec2CurveRow {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

impl Ec2CurveRow {
    fn from_curve(curve: ECDSACurve) -> Self {
        match curve {
            ECDSACurve::SECP256R1 => Self::P256,
            ECDSACurve::SECP384R1 => Self::P384,
            ECDSACurve::SECP521R1 => Self::P521,
        }
    }

    fn into_curve(self) -> ECDSACurve {
        match self {
            Self::P256 => ECDSACurve::SECP256R1,
            Self::P384 => ECDSACurve::SECP384R1,
            Self::P521 => ECDSACurve::SECP521R1,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum OkpCurveRow {
    Ed25519,
    Ed448,
}

impl OkpCurveRow {
    fn from_curve(curve: EDDSACurve) -> Self {
        match curve {
            EDDSACurve::ED25519 => Self::Ed25519,
            EDDSACurve::ED448 => Self::Ed448,
        }
    }

    fn into_curve(self) -> EDDSACurve {
        match self {
            Self::Ed25519 => EDDSACurve::ED25519,
            Self::Ed448 => EDDSACurve::ED448,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TransportRow {
    Usb,
    Nfc,
    Ble,
    Internal,
    Hybrid,
    Test,
    Unknown,
}

impl TransportRow {
    fn from_transport(transport: AuthenticatorTransport) -> Self {
        match transport {
            AuthenticatorTransport::Usb => Self::Usb,
            AuthenticatorTransport::Nfc => Self::Nfc,
            AuthenticatorTransport::Ble => Self::Ble,
            AuthenticatorTransport::Internal => Self::Internal,
            AuthenticatorTransport::Hybrid => Self::Hybrid,
            AuthenticatorTransport::Test => Self::Test,
            AuthenticatorTransport::Unknown => Self::Unknown,
        }
    }

    fn into_transport(self) -> AuthenticatorTransport {
        match self {
            Self::Usb => AuthenticatorTransport::Usb,
            Self::Nfc => AuthenticatorTransport::Nfc,
            Self::Ble => AuthenticatorTransport::Ble,
            Self::Internal => AuthenticatorTransport::Internal,
            Self::Hybrid => AuthenticatorTransport::Hybrid,
            Self::Test => AuthenticatorTransport::Test,
            Self::Unknown => AuthenticatorTransport::Unknown,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PolicyRow {
    Required,
    Preferred,
    Discouraged,
}

impl PolicyRow {
    fn from_policy(policy: UserVerificationPolicy) -> Self {
        match policy {
            UserVerificationPolicy::Required => Self::Required,
            UserVerificationPolicy::Preferred => Self::Preferred,
            UserVerificationPolicy::Discouraged_DO_NOT_USE => Self::Discouraged,
        }
    }

    fn into_policy(self) -> UserVerificationPolicy {
        match self {
            Self::Required => UserVerificationPolicy::Required,
            Self::Preferred => UserVerificationPolicy::Preferred,
            Self::Discouraged => UserVerificationPolicy::Discouraged_DO_NOT_USE,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ExtensionsRow {
    cred_protect: ExtensionRow<CredProtectRow>,
    hmac_create_secret: ExtensionRow<bool>,
    appid: ExtensionRow<bool>,
    cred_props: ExtensionRow<CredPropsRow>,
}

impl ExtensionsRow {
    fn from_extensions(extensions: RegisteredExtensions) -> Self {
        let RegisteredExtensions {
            cred_protect,
            hmac_create_secret,
            appid,
            cred_props,
        } = extensions;
        Self {
            cred_protect: ExtensionRow::from_state(cred_protect, CredProtectRow::from_policy),
            hmac_create_secret: ExtensionRow::from_state(hmac_create_secret, |set| set),
            appid: ExtensionRow::from_state(appid, |used| used),
            cred_props: ExtensionRow::from_state(cred_props, |CredProps { rk }| CredPropsRow {
                rk,
            }),
        }
    }

    fn into_extensions(self) -> RegisteredExtensions {
        RegisteredExtensions {
            cred_protect: self.cred_protect.into_state(CredProtectRow::into_policy),
            hmac_create_secret: self.hmac_create_secret.into_state(|set| set),
            appid: self.appid.into_state(|used| used),
            cred_props: self
                .cred_props
                .into_state(|CredPropsRow { rk }| CredProps { rk }),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
enum ExtensionRow<T> {
    NotRequested,
    Ignored,
    Set(T),
    Unsolicited(T),
    Unsigned(T),
}

impl<T> ExtensionRow<T> {
    fn from_state<S: Clone + Debug>(state: ExtnState<S>, value: impl FnOnce(S) -> T) -> Self {
        match state {
            ExtnState::NotRequested => Self::NotRequested,
            ExtnState::Ignored => Self::Ignored,
            ExtnState::Set(set) => Self::Set(value(set)),
            ExtnState::Unsolicited(sent) => Self::Unsolicited(value(sent)),
            ExtnState::Unsigned(sent) => Self::Unsigned(value(sent)),
        }
    }

    fn into_state<S: Clone + Debug>(self, value: impl FnOnce(T) -> S) -> ExtnState<S> {
        match self {
            Self::NotRequested => ExtnState::NotRequested,
            Self::Ignored => ExtnState::Ignored,
            Self::Set(set) => ExtnState::Set(value(set)),
            Self::Unsolicited(sent) => ExtnState::Unsolicited(value(sent)),
            Self::Unsigned(sent) => ExtnState::Unsigned(value(sent)),
        }
    }
}

// WebAuthn's own names for the credProtect policies.
#[derive(Serialize, Deserialize)]
enum CredProtectRow {
    #[serde(rename = "userVerificationOptional")]
    Optional,
    #[serde(rename = "userVerificationOptionalWithCredentialIDList")]
    OptionalWithCredentialIdList,
    #[serde(rename = "userVerificationRequired")]
    Required,
}

impl CredProtectRow {
    fn from_policy(policy: CredentialProtectionPolicy) -> Self {
        match policy {
            CredentialProtectionPolicy::UserVerificationOptional => Self::Optional,
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => {
                Self::OptionalWithCredentialIdList
            }
            CredentialProtectionPolicy::UserVerificationRequired => Self::Required,
        }
    }

    fn into_policy(self) -> CredentialProtectionPolicy {
        match self {
            Self::Optional => CredentialProtectionPolicy::UserVerificationOptional,
            Self::OptionalWithCredentialIdList => {
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList
            }
            Self::Required => CredentialProtectionPolicy::UserVerificationRequired,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CredPropsRow {
    rk: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct AttestationRow {
    format: AttestationFormatRow,
    data: AttestationDataRow,
    metadata: AttestationMetadataRow,
}

impl AttestationRow {
    fn from_attestation(attestation: ParsedAttestation, format: AttestationFormat) -> Result<Self> {
        let ParsedAttestation { data, metadata } = attestation;
        Ok(Self {
            format: AttestationFormatRow::from_format(format),
            data: AttestationDataRow::from_data(data)?,
            metadata: AttestationMetadataRow::from_metadata(metadata),
        })
    }

    fn into_attestation(self) -> Result<(ParsedAttestation, AttestationFormat)> {
        Ok((
            ParsedAttestation {
                data: self.data.into_data()?,
                metadata: self.metadata.into_metadata(),
            },
            self.format.into_format(),
        ))
    }
}

// The attestation statement format identifiers of the IANA WebAuthn registry.
#[derive(Serialize, Deserialize)]
enum AttestationFormatRow {
    #[serde(rename = "packed")]
    Packed,
    #[serde(rename = "tpm")]
    Tpm,
    #[serde(rename = "android-key")]
    AndroidKey,
    #[serde(rename = "android-safetynet")]
    AndroidSafetyNet,
    #[serde(rename = "fido-u2f")]
    FidoU2f,
    #[serde(rename = "apple")]
    Apple,
    #[serde(rename = "none")]
    None,
}

impl AttestationFormatRow {
    fn from_format(format: AttestationFormat) -> Self {
        match format {
            AttestationFormat::Packed => Self::Packed,
            AttestationFormat::Tpm => Self::Tpm,
            AttestationFormat::AndroidKey => Self::AndroidKey,
            AttestationFormat::AndroidSafetyNet => Self::AndroidSafetyNet,
            AttestationFormat::FIDOU2F => Self::FidoU2f,
            AttestationFormat::AppleAnonymous => Self::Apple,
            AttestationFormat::None => Self::None,
        }
    }

    fn into_format(self) -> AttestationFormat {
        match self {
            Self::Packed => AttestationFormat::Packed,
            Self::Tpm => AttestationFormat::Tpm,
            Self::AndroidKey => AttestationFormat::AndroidKey,
            Self::AndroidSafetyNet => AttestationFormat::AndroidSafetyNet,
            Self::FidoU2f => AttestationFormat::FIDOU2F,
            Self::Apple => AttestationFormat::AppleAnonymous,
            Self::None => AttestationFormat::None,
        }
    }
}

// Each certificate chain is held as DER.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "chain", rename_all = "snake_case")]
enum AttestationDataRow {
    Basic(Vec<Hex<Vec<u8>>>),
    #[serde(rename = "self")]
    SelfAttested,
    AttCa(Vec<Hex<Vec<u8>>>),
    AnonCa(Vec<Hex<Vec<u8>>>),
    Ecdaa,
    None,
    Uncertain,
}

impl AttestationDataRow {
    fn from_data(data: ParsedAttestationData) -> Result<Self> {
        Ok(match data {
            ParsedAttestationData::Basic(chain) => Self::Basic(chain_to_der(&chain)?),
            ParsedAttestationData::Self_ => Self::SelfAttested,
            ParsedAttestationData::AttCa(chain) => Self::AttCa(chain_to_der(&chain)?),
            ParsedAttestationData::AnonCa(chain) => Self::AnonCa(chain_to_der(&chain)?),
            ParsedAttestationData::ECDAA => Self::Ecdaa,
            ParsedAttestationData::None => Self::None,
            ParsedAttestationData::Uncertain => Self::Uncertain,
        })
    }

    fn into_data(self) -> Result<ParsedAttestationData> {
        Ok(match self {
            Self::Basic(chain) => ParsedAttestationData::Basic(chain_from_der(chain)?),
            Self::SelfAttested => ParsedAttestationData::Self_,
            Self::AttCa(chain) => ParsedAttestationData::AttCa(chain_from_der(chain)?),
            Self::AnonCa(chain) => ParsedAttestationData::AnonCa(chain_from_der(chain)?),
            Self::Ecdaa => ParsedAttestationData::ECDAA,
            Self::None => ParsedAttestationData::None,
            Self::Uncertain => ParsedAttestationData::Uncertain,
        })
    }
}

fn chain_to_der(chain: &[Certificate]) -> Result<Vec<Hex<Vec<u8>>>> {
    chain
        .iter()
        .map(|certificate| {
            certificate.to_der().map(Hex).map_err(|e| {
                Error::Internal(format!("serialise passkey attestation certificate: {e}"))
            })
        })
        .collect()
}

fn chain_from_der(chain: Vec<Hex<Vec<u8>>>) -> Result<Vec<Certificate>> {
    chain
        .into_iter()
        .map(|Hex(der)| {
            Certificate::from_der(&der).map_err(|e| {
                Error::Internal(format!("deserialise passkey attestation certificate: {e}"))
            })
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AttestationMetadataRow {
    None,
    Packed {
        aaguid: Uuid,
    },
    Tpm {
        aaguid: Uuid,
        firmware_version: u64,
    },
    AndroidKey {
        is_km_tee: bool,
        is_attest_tee: bool,
    },
    AndroidSafetyNet {
        apk_package_name: String,
        apk_certificate_digest_sha256: Vec<Hex<Vec<u8>>>,
        cts_profile_match: bool,
        basic_integrity: bool,
        evaluation_type: Option<String>,
    },
}

impl AttestationMetadataRow {
    fn from_metadata(metadata: AttestationMetadata) -> Self {
        match metadata {
            AttestationMetadata::None => Self::None,
            AttestationMetadata::Packed { aaguid } => Self::Packed { aaguid },
            AttestationMetadata::Tpm {
                aaguid,
                firmware_version,
            } => Self::Tpm {
                aaguid,
                firmware_version,
            },
            AttestationMetadata::AndroidKey {
                is_km_tee,
                is_attest_tee,
            } => Self::AndroidKey {
                is_km_tee,
                is_attest_tee,
            },
            AttestationMetadata::AndroidSafetyNet {
                apk_package_name,
                apk_certificate_digest_sha256,
                cts_profile_match,
                basic_integrity,
                evaluation_type,
            } => Self::AndroidSafetyNet {
                apk_package_name,
                apk_certificate_digest_sha256: apk_certificate_digest_sha256
                    .into_iter()
                    .map(Hex)
                    .collect(),
                cts_profile_match,
                basic_integrity,
                evaluation_type,
            },
        }
    }

    fn into_metadata(self) -> AttestationMetadata {
        match self {
            Self::None => AttestationMetadata::None,
            Self::Packed { aaguid } => AttestationMetadata::Packed { aaguid },
            Self::Tpm {
                aaguid,
                firmware_version,
            } => AttestationMetadata::Tpm {
                aaguid,
                firmware_version,
            },
            Self::AndroidKey {
                is_km_tee,
                is_attest_tee,
            } => AttestationMetadata::AndroidKey {
                is_km_tee,
                is_attest_tee,
            },
            Self::AndroidSafetyNet {
                apk_package_name,
                apk_certificate_digest_sha256,
                cts_profile_match,
                basic_integrity,
                evaluation_type,
            } => AttestationMetadata::AndroidSafetyNet {
                apk_package_name,
                apk_certificate_digest_sha256: apk_certificate_digest_sha256
                    .into_iter()
                    .map(|Hex(digest)| digest)
                    .collect(),
                cts_profile_match,
                basic_integrity,
                evaluation_type,
            },
        }
    }
}

// Bytes held as lowercase hex text.
struct Hex<B>(B);

impl<B: AsRef<[u8]>> Serialize for Hex<B> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(self.0.as_ref()))
    }
}

impl<'de, B: TryFrom<Vec<u8>>> Deserialize<'de> for Hex<B> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = unhex(&text).ok_or_else(|| D::Error::custom("not hex text"))?;
        B::try_from(bytes)
            .map(Self)
            .map_err(|_| D::Error::custom("hex text of the wrong length"))
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    // `from_str_radix` alone would also take a sign or upper case, so one value could be
    // spelled several ways.
    if !text.len().is_multiple_of(2)
        || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::*;

    // A self-signed Ed25519 certificate, as DER.
    const CERTIFICATE: &str = "308201383081eba0030201020214623ce958421685de68c62228ddc986fa52e14644300506032b657030123110300e06035504030c07646f6f726d616e301e170d3236313130353136333731365a170d3236313130363136333731365a30123110300e06035504030c07646f6f726d616e302a300506032b65700321009c94dc781a4c8716a70db80d2acb61509e2371d79a493dfc8678cf7e0eb0bdc4a3533051301d0603551d0e04160414e589dd477ae49af06a16b88cdd1596c0db0e973f301f0603551d23041830168014e589dd477ae49af06a16b88cdd1596c0db0e973f300f0603551d130101ff040530030101ff300506032b657003410061e7302f0d7d189aea21df025798a21a1cb589f84edcfe1e8b7e55e590d9b9c51e5a226a342bbe14d838255064a1f43ef32ed110bd0ab39bd70dd1542342390c";

    const AAGUID: &str = "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";

    fn certificate() -> Certificate {
        Certificate::from_der(&unhex(CERTIFICATE).expect("hex")).expect("certificate")
    }

    // webauthn-rs's own serialization compares two credentials, which have no `PartialEq`.
    fn same(left: &Credential, right: &Credential) -> bool {
        serde_json::to_value(left).expect("credential JSON")
            == serde_json::to_value(right).expect("credential JSON")
    }

    // Each fixture is a passkey as a release of doorman stored it, so it must keep reading after
    // any change to webauthn-rs or to the row types. A new format gets fixtures of its own; the
    // old ones then only read.
    fn assert_format(fixture: Value, credential: Credential) {
        let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
        let read = Credential::from(decode(&bytes).expect("the fixture reads"));
        assert!(
            same(&read, &credential),
            "a stored passkey reads as written"
        );
        let written: Value =
            serde_json::from_slice(&encode(&Passkey::from(credential)).expect("encode"))
                .expect("written JSON");
        assert_eq!(
            written, fixture,
            "a passkey is written in the fixture's format"
        );
    }

    #[test]
    fn every_stored_passkey_kind_keeps_its_format() {
        assert_format(
            json!({
                "credential_id": "c0ffee",
                "public_key": {
                    "kty": "EC2",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "01".repeat(32),
                    "y": "02".repeat(32),
                },
                "counter": 7,
                "transports": ["internal", "hybrid"],
                "user_verified": true,
                "backup_eligible": true,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {
                    "cred_protect": {"state": "set", "value": "userVerificationRequired"},
                    "hmac_create_secret": {"state": "ignored"},
                    "appid": {"state": "not_requested"},
                    "cred_props": {"state": "unsigned", "value": {"rk": true}},
                },
                "attestation": {
                    "format": "packed",
                    "data": {"type": "basic", "chain": [CERTIFICATE]},
                    "metadata": {"kind": "packed", "aaguid": AAGUID},
                },
            }),
            Credential {
                cred_id: vec![0xc0, 0xff, 0xee],
                cred: COSEKey {
                    type_: COSEAlgorithm::ES256,
                    key: COSEKeyType::EC_EC2(COSEEC2Key {
                        curve: ECDSACurve::SECP256R1,
                        x: vec![1; 32],
                        y: vec![2; 32],
                    }),
                },
                counter: 7,
                transports: Some(vec![
                    AuthenticatorTransport::Internal,
                    AuthenticatorTransport::Hybrid,
                ]),
                user_verified: true,
                backup_eligible: true,
                backup_state: false,
                registration_policy: UserVerificationPolicy::Required,
                extensions: RegisteredExtensions {
                    cred_protect: ExtnState::Set(
                        CredentialProtectionPolicy::UserVerificationRequired,
                    ),
                    hmac_create_secret: ExtnState::Ignored,
                    appid: ExtnState::NotRequested,
                    cred_props: ExtnState::Unsigned(CredProps { rk: Some(true) }),
                },
                attestation: ParsedAttestation {
                    data: ParsedAttestationData::Basic(vec![certificate()]),
                    metadata: AttestationMetadata::Packed {
                        aaguid: AAGUID.parse().expect("uuid"),
                    },
                },
                attestation_format: AttestationFormat::Packed,
            },
        );
        assert_format(
            json!({
                "credential_id": "0102",
                "public_key": {"kty": "OKP", "alg": "EdDSA", "crv": "Ed25519", "x": "03".repeat(32)},
                "counter": 0,
                "transports": null,
                "user_verified": false,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "preferred",
                "extensions": {
                    "cred_protect": {"state": "not_requested"},
                    "hmac_create_secret": {"state": "set", "value": true},
                    "appid": {"state": "unsolicited", "value": false},
                    "cred_props": {"state": "not_requested"},
                },
                "attestation": {
                    "format": "none",
                    "data": {"type": "none"},
                    "metadata": {"kind": "none"},
                },
            }),
            Credential {
                cred_id: vec![1, 2],
                cred: COSEKey {
                    type_: COSEAlgorithm::EDDSA,
                    key: COSEKeyType::EC_OKP(COSEOKPKey {
                        curve: EDDSACurve::ED25519,
                        x: vec![3; 32],
                    }),
                },
                counter: 0,
                transports: None,
                user_verified: false,
                backup_eligible: false,
                backup_state: false,
                registration_policy: UserVerificationPolicy::Preferred,
                extensions: RegisteredExtensions {
                    cred_protect: ExtnState::NotRequested,
                    hmac_create_secret: ExtnState::Set(true),
                    appid: ExtnState::Unsolicited(false),
                    cred_props: ExtnState::NotRequested,
                },
                attestation: ParsedAttestation {
                    data: ParsedAttestationData::None,
                    metadata: AttestationMetadata::None,
                },
                attestation_format: AttestationFormat::None,
            },
        );
        assert_format(
            json!({
                "credential_id": "ff",
                "public_key": {"kty": "RSA", "alg": "RS256", "n": "04".repeat(256), "e": "010001"},
                "counter": 4294967295u32,
                "transports": [],
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {
                    "cred_protect": {"state": "not_requested"},
                    "hmac_create_secret": {"state": "not_requested"},
                    "appid": {"state": "not_requested"},
                    "cred_props": {"state": "not_requested"},
                },
                "attestation": {
                    "format": "tpm",
                    "data": {"type": "att_ca", "chain": [CERTIFICATE, CERTIFICATE]},
                    "metadata": {"kind": "tpm", "aaguid": AAGUID, "firmware_version": 42},
                },
            }),
            Credential {
                cred_id: vec![0xff],
                cred: COSEKey {
                    type_: COSEAlgorithm::RS256,
                    key: COSEKeyType::RSA(COSERSAKey {
                        n: vec![4; 256],
                        e: [1, 0, 1],
                    }),
                },
                counter: u32::MAX,
                transports: Some(Vec::new()),
                user_verified: true,
                backup_eligible: false,
                backup_state: false,
                registration_policy: UserVerificationPolicy::Required,
                extensions: RegisteredExtensions::none(),
                attestation: ParsedAttestation {
                    data: ParsedAttestationData::AttCa(vec![certificate(), certificate()]),
                    metadata: AttestationMetadata::Tpm {
                        aaguid: AAGUID.parse().expect("uuid"),
                        firmware_version: 42,
                    },
                },
                attestation_format: AttestationFormat::Tpm,
            },
        );
    }

    #[test]
    fn hex_reads_only_its_own_spelling() {
        assert_eq!(unhex("00ff"), Some(vec![0, 0xff]));
        for other in ["0", "0F", "+f", "-1", "zz", "0x"] {
            assert_eq!(unhex(other), None, "{other:?}");
        }
    }

    fn bytes(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), len)
    }

    fn extension<T: Clone + Debug + 'static>(
        value: impl Strategy<Value = T> + Clone + 'static,
    ) -> impl Strategy<Value = ExtnState<T>> {
        prop_oneof![
            Just(ExtnState::NotRequested),
            Just(ExtnState::Ignored),
            value.clone().prop_map(ExtnState::Set),
            value.clone().prop_map(ExtnState::Unsolicited),
            value.prop_map(ExtnState::Unsigned),
        ]
    }

    fn public_key() -> impl Strategy<Value = COSEKey> {
        let algorithm = prop::sample::select(vec![
            COSEAlgorithm::ES256,
            COSEAlgorithm::ES384,
            COSEAlgorithm::ES521,
            COSEAlgorithm::RS256,
            COSEAlgorithm::RS384,
            COSEAlgorithm::RS512,
            COSEAlgorithm::PS256,
            COSEAlgorithm::PS384,
            COSEAlgorithm::PS512,
            COSEAlgorithm::EDDSA,
            COSEAlgorithm::INSECURE_RS1,
        ]);
        let key = prop_oneof![
            (
                prop::sample::select(vec![
                    ECDSACurve::SECP256R1,
                    ECDSACurve::SECP384R1,
                    ECDSACurve::SECP521R1,
                ]),
                bytes(0..67),
                bytes(0..67),
            )
                .prop_map(|(curve, x, y)| COSEKeyType::EC_EC2(COSEEC2Key {
                    curve,
                    x,
                    y,
                })),
            (
                prop::sample::select(vec![EDDSACurve::ED25519, EDDSACurve::ED448]),
                bytes(0..58),
            )
                .prop_map(|(curve, x)| COSEKeyType::EC_OKP(COSEOKPKey { curve, x })),
            (bytes(0..513), any::<[u8; 3]>())
                .prop_map(|(n, e)| COSEKeyType::RSA(COSERSAKey { n, e })),
        ];
        (algorithm, key).prop_map(|(type_, key)| COSEKey { type_, key })
    }

    fn extensions() -> impl Strategy<Value = RegisteredExtensions> {
        (
            extension(prop::sample::select(vec![
                CredentialProtectionPolicy::UserVerificationOptional,
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
                CredentialProtectionPolicy::UserVerificationRequired,
            ])),
            extension(any::<bool>()),
            extension(any::<bool>()),
            extension(any::<Option<bool>>().prop_map(|rk| CredProps { rk })),
        )
            .prop_map(|(cred_protect, hmac_create_secret, appid, cred_props)| {
                RegisteredExtensions {
                    cred_protect,
                    hmac_create_secret,
                    appid,
                    cred_props,
                }
            })
    }

    fn attestation() -> impl Strategy<Value = ParsedAttestation> {
        let chain = (0..3usize).prop_map(|len| vec![certificate(); len]);
        let data = prop_oneof![
            chain.clone().prop_map(ParsedAttestationData::Basic),
            Just(ParsedAttestationData::Self_),
            chain.clone().prop_map(ParsedAttestationData::AttCa),
            chain.prop_map(ParsedAttestationData::AnonCa),
            Just(ParsedAttestationData::ECDAA),
            Just(ParsedAttestationData::None),
            Just(ParsedAttestationData::Uncertain),
        ];
        let aaguid = any::<[u8; 16]>().prop_map(Uuid::from_bytes);
        let metadata = prop_oneof![
            Just(AttestationMetadata::None),
            aaguid
                .clone()
                .prop_map(|aaguid| AttestationMetadata::Packed { aaguid }),
            (aaguid, any::<u64>()).prop_map(|(aaguid, firmware_version)| {
                AttestationMetadata::Tpm {
                    aaguid,
                    firmware_version,
                }
            }),
            (any::<bool>(), any::<bool>()).prop_map(|(is_km_tee, is_attest_tee)| {
                AttestationMetadata::AndroidKey {
                    is_km_tee,
                    is_attest_tee,
                }
            }),
            (
                ".*",
                prop::collection::vec(bytes(0..33), 0..3),
                any::<bool>(),
                any::<bool>(),
                any::<Option<String>>(),
            )
                .prop_map(
                    |(name, digests, cts_profile_match, basic_integrity, evaluation_type)| {
                        AttestationMetadata::AndroidSafetyNet {
                            apk_package_name: name,
                            apk_certificate_digest_sha256: digests.into_iter().collect(),
                            cts_profile_match,
                            basic_integrity,
                            evaluation_type,
                        }
                    },
                ),
        ];
        (data, metadata).prop_map(|(data, metadata)| ParsedAttestation { data, metadata })
    }

    fn credential() -> impl Strategy<Value = Credential> {
        let transports = prop::option::of(prop::collection::vec(
            prop::sample::select(vec![
                AuthenticatorTransport::Usb,
                AuthenticatorTransport::Nfc,
                AuthenticatorTransport::Ble,
                AuthenticatorTransport::Internal,
                AuthenticatorTransport::Hybrid,
                AuthenticatorTransport::Test,
                AuthenticatorTransport::Unknown,
            ]),
            0..4,
        ));
        let policy = prop::sample::select(vec![
            UserVerificationPolicy::Required,
            UserVerificationPolicy::Preferred,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
        ]);
        let format = prop::sample::select(vec![
            AttestationFormat::Packed,
            AttestationFormat::Tpm,
            AttestationFormat::AndroidKey,
            AttestationFormat::AndroidSafetyNet,
            AttestationFormat::FIDOU2F,
            AttestationFormat::AppleAnonymous,
            AttestationFormat::None,
        ]);
        (
            (bytes(1..64), public_key(), any::<u32>(), transports),
            any::<[bool; 3]>(),
            (policy, extensions(), attestation(), format),
        )
            .prop_map(
                |(
                    (cred_id, cred, counter, transports),
                    [user_verified, backup_eligible, backup_state],
                    (registration_policy, extensions, attestation, attestation_format),
                )| Credential {
                    cred_id,
                    cred,
                    counter,
                    transports,
                    user_verified,
                    backup_eligible,
                    backup_state,
                    registration_policy,
                    extensions,
                    attestation,
                    attestation_format,
                },
            )
    }

    proptest! {
        #[test]
        fn every_passkey_reads_back_as_written(credential in credential()) {
            let bytes = encode(&Passkey::from(credential.clone())).expect("encode");
            let read = Credential::from(decode(&bytes).expect("decode"));
            prop_assert!(same(&read, &credential));
        }
    }
}
