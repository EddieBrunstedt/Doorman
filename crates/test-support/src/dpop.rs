use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use doorman_core::dpop::DpopProof;
use doorman_core::storage::JwkThumbprint;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// A DPoP client's key, which signs a fresh proof for each request it makes.
pub struct DpopClient {
    key: EcKey<Private>,
    origin: String,
}

impl std::fmt::Debug for DpopClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopClient")
            .field("jkt", &self.jkt())
            .field("origin", &self.origin)
            .finish()
    }
}

impl DpopClient {
    pub fn new(origin: &str) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        Self {
            key: EcKey::generate(&group).expect("DPoP key"),
            origin: origin.trim_end_matches('/').to_owned(),
        }
    }

    // Worked out here from RFC 7638, not by doorman, so a test can check doorman's own.
    pub fn jkt(&self) -> JwkThumbprint {
        let (x, y) = self.coordinates();
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        JwkThumbprint(Sha256::digest(canonical.as_bytes()).into())
    }

    pub fn proof(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        issued_at: DateTime<Utc>,
    ) -> String {
        let mut jti = [0u8; 16];
        openssl::rand::rand_bytes(&mut jti).expect("jti");
        let mut claims = json!({
            "jti": URL_SAFE_NO_PAD.encode(jti),
            "htm": method,
            "htu": format!("{}{path}", self.origin),
            "iat": issued_at.timestamp(),
        });
        if let Some(token) = token {
            claims["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
        }
        self.sign(&claims)
    }

    pub fn presented(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        issued_at: DateTime<Utc>,
    ) -> DpopProof {
        DpopProof::new(self.proof(method, path, token, issued_at), method, path)
    }

    fn sign(&self, claims: &Value) -> String {
        let (x, y) = self.coordinates();
        let header = json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y },
        });
        let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
        let input = format!("{}.{}", encode(&header), encode(claims));
        let signature =
            EcdsaSig::sign(&Sha256::digest(input.as_bytes()), &self.key).expect("signature");
        let mut raw = signature.r().to_vec_padded(32).expect("r");
        raw.extend(signature.s().to_vec_padded(32).expect("s"));
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw))
    }

    fn coordinates(&self) -> (String, String) {
        let mut ctx = BigNumContext::new().expect("context");
        let (mut x, mut y) = (BigNum::new().expect("x"), BigNum::new().expect("y"));
        self.key
            .public_key()
            .affine_coordinates(self.key.group(), &mut x, &mut y, &mut ctx)
            .expect("coordinates");
        let encode = |n: &BigNum| URL_SAFE_NO_PAD.encode(n.to_vec_padded(32).expect("coordinate"));
        (encode(&x), encode(&y))
    }
}
