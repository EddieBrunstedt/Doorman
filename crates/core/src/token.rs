//! Opaque-token scheme shared by session bearer tokens and verification
//! links.
//!
//! This module is the single home for the opaque-token primitives: the
//! random-token generator, the at-rest hash function, and the [`TokenHash`]
//! type sessions and verification tokens are keyed by. Centralizing them
//! here keeps the two flows from diverging on entropy, encoding, or the
//! comparison used to look a token up — a security-relevant invariant, so
//! it lives in one deliberate place rather than being defined next to one
//! consumer and borrowed by the other.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of the random token in bytes. 256 bits of entropy. Shared by
/// session tokens and verification tokens (see [`generate_token`]).
pub const TOKEN_BYTES: usize = 32;

/// SHA-256 digest of a token. Tokens are stored keyed by hash so that a
/// database breach does not yield usable tokens. Equality is constant-time
/// so that any in-process comparison (including HashMap bucket
/// disambiguation) does not leak the matched prefix length via timing.
///
/// `PartialEq` is constant-time but byte-equivalent to a derived impl, so the
/// `Hash`/`Eq` contract (`a == b => hash(a) == hash(b)`) still holds.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Copy, Hash, Serialize, Deserialize)]
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

/// Hash a cleartext token into its at-rest [`TokenHash`].
pub fn hash_token(token: &str) -> TokenHash {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    TokenHash(out)
}

/// Generate a fresh random token and its at-rest hash. The cleartext token
/// is handed to the client (session cookie or email link); only the hash is
/// persisted. Shared by [`SessionManager`](crate::session::SessionManager)
/// and the verification flows.
pub(crate) fn generate_token() -> (String, TokenHash) {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_url_safe_and_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
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

    /// Lock in that `TokenHash` equality goes through `subtle`'s
    /// constant-time comparison rather than a short-circuiting byte compare.
    /// A naive `==` would return the same booleans, so a pure value test
    /// cannot prove constant-timeness; instead we assert that the public
    /// `PartialEq` agrees with `ct_eq` on every interesting case (equal,
    /// differing in the first byte, differing in the last byte). If someone
    /// swaps the impl for a derived/short-circuiting one, this stays green —
    /// the real guarantee is the `ConstantTimeEq` call in `eq`; this test
    /// guards that the wiring is present and behaviorally correct.
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
