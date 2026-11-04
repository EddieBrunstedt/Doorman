use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

pub(crate) const TOKEN_BYTES: usize = 32;

#[allow(
    clippy::derived_hash_with_manual_eq,
    reason = "PartialEq is constant-time but byte-equivalent to a derived impl, so the Hash/Eq contract holds"
)]
#[derive(Clone, Copy, Hash)]
pub struct TokenHash(pub [u8; 32]);

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for TokenHash {}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenHash(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

pub fn hash_token(token: &str) -> TokenHash {
    TokenHash(Sha256::digest(token.as_bytes()).into())
}

pub(crate) fn generate_token() -> Result<(String, TokenHash)> {
    let mut bytes = [0u8; TOKEN_BYTES];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| Error::Internal(format!("OS random source failed: {e}")))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    Ok((token, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hash_token_is_deterministic(s in ".*") {
            prop_assert_eq!(hash_token(&s), hash_token(&s));
        }

        #[test]
        fn distinct_tokens_hash_distinctly(a in ".*", b in ".*") {
            prop_assume!(a != b);
            prop_assert_ne!(hash_token(&a), hash_token(&b));
        }

        #[test]
        fn token_hash_eq_matches_byte_compare(a in ".*", b in ".*") {
            let ha = hash_token(&a);
            let hb = hash_token(&b);
            prop_assert_eq!(ha == hb, ha.0 == hb.0);
        }

        #[test]
        fn generated_token_is_url_safe_and_hash_matches(_seed in any::<u8>()) {
            let (token, hash) = generate_token().expect("token");
            for ch in token.chars() {
                prop_assert!(
                    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                    "token contains non-url-safe char: {:?}",
                    ch
                );
            }
            prop_assert_eq!(hash, hash_token(&token));
        }
    }

    #[test]
    fn generated_tokens_are_url_safe_and_unique() {
        let (a, ha) = generate_token().expect("token");
        let (b, hb) = generate_token().expect("token");
        assert_ne!(a, b);
        assert_ne!(ha, hb);
        for ch in a.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "token contains non-url-safe char: {ch:?}"
            );
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_token("hello");
        let b = hash_token("hello");
        assert_eq!(a, b);
    }

    #[test]
    fn token_hash_eq_matches_constant_time_compare() {
        let base = TokenHash([7u8; 32]);
        let same = TokenHash([7u8; 32]);

        let mut first_differs_bytes = [7u8; 32];
        first_differs_bytes[0] = 8;
        let first_differs = TokenHash(first_differs_bytes);

        let mut last_differs_bytes = [7u8; 32];
        last_differs_bytes[31] = 8;
        let last_differs = TokenHash(last_differs_bytes);

        for other in [same, first_differs, last_differs] {
            assert_eq!(base == other, bool::from(base.0.ct_eq(&other.0)));
        }

        assert!(base == same);
        assert!(base != first_differs);
        assert!(base != last_differs);
    }
}
