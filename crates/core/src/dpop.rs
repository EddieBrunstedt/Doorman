use std::fmt;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use url::{Origin, Url};

use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::storage::{DpopProofId, DpopProofStore, UsedDpopProof};
use crate::token::{TokenHash, hash_token};

// Every platform key store a DPoP client can keep its key in signs with P-256, so one algorithm
// leaves nothing to negotiate and no other verifier to get wrong.
pub const DPOP_ALGORITHM: &str = "ES256";

// Either side of `iat`, so a client whose clock drifts this far still works. A proof can be used
// only once, so the window bounds how long a used proof must be remembered, not how long a
// captured one can be replayed.
const PROOF_WINDOW: chrono::Duration = chrono::Duration::seconds(60);

// A P-256 key, a URL and the claims fit in well under this; anything longer is refused unread.
const MAX_PROOF_LEN: usize = 4096;

const COORDINATE_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwkThumbprint(pub [u8; 32]);

impl JwkThumbprint {
    fn of_p256(x: &[u8], y: &[u8]) -> Self {
        // RFC 7638: the required members only, in lexicographic order, with no whitespace.
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y),
        );
        Self(Sha256::digest(canonical.as_bytes()).into())
    }
}

impl fmt::Display for JwkThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for JwkThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JwkThumbprint({self})")
    }
}

impl Serialize for JwkThumbprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for JwkThumbprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("a JWK thumbprint is 32 base64url bytes"))
    }
}

// What a request presents as its DPoP proof: the JWT, and the method and path of the request it
// came with, which the proof must have been signed for.
#[derive(Clone)]
pub struct DpopProof {
    jwt: String,
    method: String,
    path: String,
}

impl DpopProof {
    pub fn new(jwt: impl Into<String>, method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            jwt: jwt.into(),
            method: method.into(),
            path: path.into(),
        }
    }
}

// The JWT is left out: whoever reads a log must not find a proof they could still use.
impl fmt::Debug for DpopProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopProof")
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

// A proof whose signature, request and age all checked out, and that is not yet used.
#[derive(Debug)]
struct CheckedProof {
    jkt: JwkThumbprint,
    used: UsedDpopProof,
}

// What one request's proof showed: that its sender holds the key, and which session token, if
// any, it was signed for. Only `DpopProofs::prove` builds one, after using the proof up, so the
// session layer can check a request's proof once and hand the result both to resolving the
// session it carries and to starting a new one.
#[derive(Debug, Clone)]
pub struct ProvenDpopKey {
    jkt: JwkThumbprint,
    token_hash: Option<TokenHash>,
}

impl ProvenDpopKey {
    pub fn jkt(&self) -> JwkThumbprint {
        self.jkt
    }

    pub(crate) fn signed_for(&self, token: &str) -> bool {
        self.token_hash == Some(hash_token(token))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofRefusal {
    Malformed,
    UnsupportedKey,
    BadSignature,
    WrongMethod,
    WrongUrl,
    OutsideWindow,
    WrongToken,
}

#[derive(Clone)]
pub(crate) struct DpopProofs {
    origin: Origin,
    store: Arc<dyn DpopProofStore>,
    clock: Arc<dyn Clock>,
}

impl DpopProofs {
    pub(crate) fn new(
        origin: Origin,
        store: Arc<dyn DpopProofStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            origin,
            store,
            clock,
        }
    }

    // A session's token is given only once the session starts, so a proof made to start one
    // carries none.
    pub(crate) async fn prove(
        &self,
        proof: &DpopProof,
        token: Option<&str>,
    ) -> Result<ProvenDpopKey> {
        let checked = check(proof, token, &self.origin, self.clock.now()).map_err(|refusal| {
            tracing::info!(?refusal, "refused a DPoP proof");
            Error::InvalidDpopProof
        })?;
        if !self.store.use_proof(checked.used).await? {
            tracing::warn!(outcome = "replayed", "refused a DPoP proof used before");
            return Err(Error::InvalidDpopProof);
        }
        Ok(ProvenDpopKey {
            jkt: checked.jkt,
            token_hash: token.map(hash_token),
        })
    }
}

#[derive(Deserialize)]
struct Header {
    typ: String,
    alg: String,
    jwk: Jwk,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    // A proof that carries its private key proves nothing about who holds it.
    #[serde(default)]
    d: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct Claims {
    jti: String,
    htm: String,
    htu: String,
    iat: f64,
    #[serde(default)]
    ath: Option<String>,
}

fn check(
    proof: &DpopProof,
    token: Option<&str>,
    origin: &Origin,
    now: DateTime<Utc>,
) -> std::result::Result<CheckedProof, ProofRefusal> {
    use ProofRefusal::*;

    if proof.jwt.len() > MAX_PROOF_LEN {
        return Err(Malformed);
    }
    let mut parts = proof.jwt.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Malformed);
    };
    let header: Header = decode_json(header)?;
    if header.typ != "dpop+jwt" {
        return Err(Malformed);
    }
    if header.alg != DPOP_ALGORITHM {
        return Err(UnsupportedKey);
    }
    let Jwk { kty, crv, x, y, d } = header.jwk;
    if kty != "EC" || crv != "P-256" || d.is_some() {
        return Err(UnsupportedKey);
    }
    let x = decode_coordinate(&x)?;
    let y = decode_coordinate(&y)?;
    let signing_input = &proof.jwt[..proof.jwt.len() - signature.len() - 1];
    verify_es256(&x, &y, signing_input.as_bytes(), signature)?;

    let claims: Claims = decode_json(claims)?;
    if claims.jti.is_empty() {
        return Err(Malformed);
    }
    if claims.htm != proof.method {
        return Err(WrongMethod);
    }
    if !same_url(&claims.htu, origin, &proof.path) {
        return Err(WrongUrl);
    }
    let issued_at = issued_at(claims.iat)?;
    let expires_at = issued_at
        .checked_add_signed(PROOF_WINDOW)
        .ok_or(Malformed)?;
    // Refused from the moment its deadline comes, when a purge may already have forgotten it.
    if expires_at <= now || issued_at > now + PROOF_WINDOW {
        return Err(OutsideWindow);
    }
    if let Some(token) = token {
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        if claims.ath.as_deref() != Some(expected.as_str()) {
            return Err(WrongToken);
        }
    }

    let jkt = JwkThumbprint::of_p256(&x, &y);
    // The id is scoped to the key, so two clients that happen to pick the same `jti` don't
    // refuse each other's proofs.
    let mut id = Sha256::new();
    id.update(jkt.0);
    id.update(claims.jti.as_bytes());
    Ok(CheckedProof {
        jkt,
        used: UsedDpopProof {
            id: DpopProofId(id.finalize().into()),
            expires_at,
        },
    })
}

fn decode_json<T: serde::de::DeserializeOwned>(part: &str) -> std::result::Result<T, ProofRefusal> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| ProofRefusal::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| ProofRefusal::Malformed)
}

fn decode_coordinate(encoded: &str) -> std::result::Result<Vec<u8>, ProofRefusal> {
    match URL_SAFE_NO_PAD.decode(encoded) {
        Ok(bytes) if bytes.len() == COORDINATE_LEN => Ok(bytes),
        _ => Err(ProofRefusal::UnsupportedKey),
    }
}

fn verify_es256(
    x: &[u8],
    y: &[u8],
    signing_input: &[u8],
    signature: &str,
) -> std::result::Result<(), ProofRefusal> {
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProofRefusal::BadSignature)?;
    if signature.len() != 2 * COORDINATE_LEN {
        return Err(ProofRefusal::BadSignature);
    }
    let (r, s) = signature.split_at(COORDINATE_LEN);
    let verified = (|| {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let (x, y) = (BigNum::from_slice(x)?, BigNum::from_slice(y)?);
        // Building the key checks the point lies on the curve.
        let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
        let signature =
            EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
        signature.verify(&Sha256::digest(signing_input), &key)
    })();
    match verified {
        Ok(true) => Ok(()),
        Ok(false) => Err(ProofRefusal::BadSignature),
        Err(_) => Err(ProofRefusal::UnsupportedKey),
    }
}

fn same_url(htu: &str, origin: &Origin, path: &str) -> bool {
    // Anything but an absolute path would join onto the origin's host.
    if !path.starts_with('/') {
        return false;
    }
    let (Ok(claimed), Ok(expected)) = (
        Url::parse(htu),
        Url::parse(&format!("{}{path}", origin.ascii_serialization())),
    ) else {
        return false;
    };
    claimed.origin() == expected.origin() && claimed.path() == expected.path()
}

fn issued_at(iat: f64) -> std::result::Result<DateTime<Utc>, ProofRefusal> {
    if !iat.is_finite() {
        return Err(ProofRefusal::Malformed);
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a finite float out of range saturates, and the window check then refuses it"
    )]
    let seconds = iat.floor() as i64;
    DateTime::from_timestamp(seconds, 0).ok_or(ProofRefusal::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::EcKeyRef;
    use openssl::pkey::Private;
    use serde_json::{Value, json};

    const ORIGIN: &str = "https://api.app.test";
    const TOKEN: &str = "the-session-token";

    fn origin() -> Origin {
        Url::parse(ORIGIN).expect("origin").origin()
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).expect("timestamp")
    }

    fn key() -> EcKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("group");
        EcKey::generate(&group).expect("key")
    }

    fn coordinates(key: &EcKeyRef<Private>) -> (Vec<u8>, Vec<u8>) {
        let group = key.group();
        let mut ctx = openssl::bn::BigNumContext::new().expect("context");
        let (mut x, mut y) = (BigNum::new().expect("x"), BigNum::new().expect("y"));
        key.public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .expect("coordinates");
        (
            x.to_vec_padded(32).expect("x bytes"),
            y.to_vec_padded(32).expect("y bytes"),
        )
    }

    fn jwk(key: &EcKeyRef<Private>) -> Value {
        let (x, y) = coordinates(key);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        })
    }

    fn sign(key: &EcKeyRef<Private>, header: &Value, claims: &Value) -> String {
        let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
        let input = format!("{}.{}", encode(header), encode(claims));
        let signature = EcdsaSig::sign(&Sha256::digest(input.as_bytes()), key).expect("signature");
        let mut raw = signature.r().to_vec_padded(32).expect("r");
        raw.extend(signature.s().to_vec_padded(32).expect("s"));
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw))
    }

    fn header(key: &EcKeyRef<Private>) -> Value {
        json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk(key) })
    }

    fn claims() -> Value {
        json!({
            "jti": "a-unique-id",
            "htm": "GET",
            "htu": format!("{ORIGIN}/auth/me"),
            "iat": now().timestamp(),
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(TOKEN.as_bytes())),
        })
    }

    fn presented(jwt: String) -> DpopProof {
        DpopProof::new(jwt, "GET", "/auth/me")
    }

    fn with(mut value: Value, field: &str, replacement: Value) -> Value {
        value[field] = replacement;
        value
    }

    fn without(mut value: Value, field: &str) -> Value {
        value.as_object_mut().expect("object").remove(field);
        value
    }

    #[test]
    fn a_proof_signed_for_this_request_names_its_key() {
        let key = key();
        let checked = check(
            &presented(sign(&key, &header(&key), &claims())),
            Some(TOKEN),
            &origin(),
            now(),
        )
        .expect("a valid proof");
        let (x, y) = coordinates(&key);
        assert_eq!(checked.jkt, JwkThumbprint::of_p256(&x, &y));
        assert_eq!(checked.used.expires_at, now() + PROOF_WINDOW);
    }

    #[test]
    fn a_proof_is_refused_unless_every_part_matches_the_request() {
        use ProofRefusal::*;
        let key = key();
        let other = self::key();
        let ok_header = header(&key);
        let ok_claims = claims();
        let iat = now().timestamp();
        let cases: Vec<(&str, String, Option<&str>, ProofRefusal)> = vec![
            ("not a jwt", "not-a-jwt".to_owned(), Some(TOKEN), Malformed),
            (
                "too long",
                format!("{}.e30.e30", "a".repeat(MAX_PROOF_LEN)),
                Some(TOKEN),
                Malformed,
            ),
            (
                "wrong typ",
                sign(
                    &key,
                    &with(ok_header.clone(), "typ", json!("jwt")),
                    &ok_claims,
                ),
                Some(TOKEN),
                Malformed,
            ),
            (
                "another alg",
                sign(
                    &key,
                    &with(ok_header.clone(), "alg", json!("RS256")),
                    &ok_claims,
                ),
                Some(TOKEN),
                UnsupportedKey,
            ),
            (
                "a private key in the header",
                sign(
                    &key,
                    &with(
                        ok_header.clone(),
                        "jwk",
                        with(jwk(&key), "d", json!("c2VjcmV0")),
                    ),
                    &ok_claims,
                ),
                Some(TOKEN),
                UnsupportedKey,
            ),
            (
                "signed by another key",
                sign(&other, &ok_header, &ok_claims),
                Some(TOKEN),
                BadSignature,
            ),
            (
                "another method",
                sign(
                    &key,
                    &ok_header,
                    &with(ok_claims.clone(), "htm", json!("POST")),
                ),
                Some(TOKEN),
                WrongMethod,
            ),
            (
                "another path",
                sign(
                    &key,
                    &ok_header,
                    &with(
                        ok_claims.clone(),
                        "htu",
                        json!(format!("{ORIGIN}/auth/sessions")),
                    ),
                ),
                Some(TOKEN),
                WrongUrl,
            ),
            (
                "another origin",
                sign(
                    &key,
                    &ok_header,
                    &with(ok_claims.clone(), "htu", json!("https://evil.test/auth/me")),
                ),
                Some(TOKEN),
                WrongUrl,
            ),
            (
                "too old",
                sign(
                    &key,
                    &ok_header,
                    &with(ok_claims.clone(), "iat", json!(iat - 61)),
                ),
                Some(TOKEN),
                OutsideWindow,
            ),
            (
                "from the future",
                sign(
                    &key,
                    &ok_header,
                    &with(ok_claims.clone(), "iat", json!(iat + 61)),
                ),
                Some(TOKEN),
                OutsideWindow,
            ),
            (
                "for another token",
                sign(&key, &ok_header, &ok_claims),
                Some("another-token"),
                WrongToken,
            ),
            (
                "naming no token",
                sign(&key, &ok_header, &without(ok_claims.clone(), "ath")),
                Some(TOKEN),
                WrongToken,
            ),
            (
                "issued at the end of time",
                sign(
                    &key,
                    &ok_header,
                    &with(ok_claims.clone(), "iat", json!(f64::MAX)),
                ),
                Some(TOKEN),
                Malformed,
            ),
            (
                "without a jti",
                sign(&key, &ok_header, &with(ok_claims.clone(), "jti", json!(""))),
                Some(TOKEN),
                Malformed,
            ),
        ];

        for (case, jwt, token, expected) in cases {
            let refusal = check(&presented(jwt), token, &origin(), now()).err();
            assert_eq!(refusal, Some(expected), "{case}");
        }
    }

    #[test]
    fn a_proof_that_starts_a_session_names_no_token() {
        let key = key();
        let jwt = sign(&key, &header(&key), &without(claims(), "ath"));
        assert!(check(&presented(jwt), None, &origin(), now()).is_ok());
    }

    #[test]
    fn the_url_matches_by_origin_and_path_alone() {
        let origin = origin();
        assert!(same_url(
            "https://api.app.test:443/auth/me?x=1#f",
            &origin,
            "/auth/me"
        ));
        assert!(same_url(
            "https://API.app.test/auth/./me",
            &origin,
            "/auth/me"
        ));
        assert!(!same_url(
            "http://api.app.test/auth/me",
            &origin,
            "/auth/me"
        ));
        assert!(!same_url(
            "https://api.app.test/auth/me",
            &origin,
            "auth/me"
        ));
        assert!(!same_url(
            "https://api.app.test@evil.test/auth/me",
            &origin,
            "/auth/me"
        ));
    }

    #[test]
    fn proofs_from_two_keys_with_one_jti_are_two_proofs() {
        let (a, b) = (key(), key());
        let proof = |key: &EcKey<Private>| {
            check(
                &presented(sign(key, &header(key), &claims())),
                Some(TOKEN),
                &origin(),
                now(),
            )
            .expect("a valid proof")
        };
        assert_ne!(proof(&a).used.id, proof(&b).used.id);
        assert_eq!(proof(&a).used.id, proof(&a).used.id);
    }

    #[test]
    fn a_thumbprint_matches_the_one_rfc_9449_gives_for_its_example_key() {
        let decode = |encoded: &str| URL_SAFE_NO_PAD.decode(encoded).expect("coordinate");
        let x = decode("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs");
        let y = decode("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA");
        let thumbprint = JwkThumbprint::of_p256(&x, &y);
        assert_eq!(
            thumbprint.to_string(),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );

        let json = serde_json::to_string(&thumbprint).expect("serialize");
        assert_eq!(json, format!("\"{thumbprint}\""));
        assert_eq!(
            serde_json::from_str::<JwkThumbprint>(&json).expect("deserialize"),
            thumbprint
        );
    }

    #[test]
    fn a_proofs_debug_output_leaves_out_the_jwt() {
        let rendered = format!("{:?}", DpopProof::new("secret.jwt.here", "GET", "/auth/me"));
        assert!(!rendered.contains("secret.jwt.here"), "{rendered}");
    }
}
