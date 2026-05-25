//! Password hashing primitives.
//!
//! Hashing is Argon2id with the `argon2` crate's default parameters, which
//! target roughly 100 ms of work on commodity hardware and align with the
//! current OWASP recommendation. The output is a self-describing PHC
//! string, so verification needs only the stored hash and the plaintext.
//!
//! Both the hash and verify routines are CPU-bound for ~100 ms by design.
//! [`hash_password_async`] and [`verify_password_async`] dispatch the
//! synchronous primitives through [`tokio::task::spawn_blocking`] so that
//! the runtime's worker threads stay free to drive other I/O while a login
//! is in flight; the surrounding `async fn` flows in
//! [`crate::password_auth`] use those wrappers.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash as Argon2Hash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};

use crate::error::{Error, Result};

/// Minimum requirements applied to plain-text passwords before hashing.
///
/// Kept intentionally small: hosts that need entropy classes, dictionary
/// checks, or breach-list lookups should layer those on top of this in
/// their own registration handler.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self { min_length: 12 }
    }
}

impl PasswordPolicy {
    pub fn validate(&self, plain: &str) -> Result<()> {
        if plain.chars().count() < self.min_length {
            return Err(Error::WeakPassword {
                min_length: self.min_length,
            });
        }
        Ok(())
    }
}

/// Hash a plain-text password into a PHC string suitable for storage.
pub fn hash_password(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| Error::PasswordHashing(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verify a plain-text password against a previously stored PHC hash.
///
/// Returns `Ok(true)` on a match, `Ok(false)` on a mismatch, and `Err`
/// only when the stored hash is unparsable or hashing fails for some
/// other reason.
pub fn verify_password(plain: &str, hash: &str) -> Result<bool> {
    let parsed = Argon2Hash::new(hash).map_err(|_| Error::PasswordHashCorrupt)?;
    match Argon2::default().verify_password(plain.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(Error::PasswordHashing(e.to_string())),
    }
}

/// Async wrapper around [`hash_password`] that offloads the Argon2 work
/// onto the blocking pool so the calling tokio worker is not pinned for
/// the ~100 ms hashing window.
pub async fn hash_password_async(plain: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&plain))
        .await
        .map_err(|e| Error::PasswordHashing(format!("hashing task panicked: {e}")))?
}

/// Async wrapper around [`verify_password`] that offloads the Argon2 work
/// onto the blocking pool. See [`hash_password_async`].
pub async fn verify_password_async(plain: String, hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || verify_password(&plain, &hash))
        .await
        .map_err(|e| Error::PasswordHashing(format!("hashing task panicked: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let hash = hash_password("correct horse battery staple").expect("hash");
        assert!(verify_password("correct horse battery staple", &hash).expect("verify"));
        assert!(!verify_password("wrong", &hash).expect("verify wrong"));
    }

    #[test]
    fn each_hash_is_unique() {
        let a = hash_password("hunter2hunter2").expect("a");
        let b = hash_password("hunter2hunter2").expect("b");
        assert_ne!(a, b, "salts should be random per hash");
    }

    #[test]
    fn policy_rejects_short_passwords() {
        let p = PasswordPolicy { min_length: 12 };
        assert!(p.validate("short").is_err());
        assert!(p.validate("twelve chars").is_ok());
    }

    #[test]
    fn corrupt_hash_errors() {
        let err = verify_password("anything", "not-a-phc-string").expect_err("err");
        assert!(matches!(err, Error::PasswordHashCorrupt));
    }
}
