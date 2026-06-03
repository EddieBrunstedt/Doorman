//! The three ephemeral storage traits, each in its own module.
//!
//! `doorman-redis` implements only the TTL-bearing, ephemeral stores
//! ([`SessionStore`](doorman_core::storage::SessionStore),
//! [`VerificationTokenStore`](doorman_core::storage::VerificationTokenStore),
//! [`PasskeyChallengeStore`](doorman_core::storage::PasskeyChallengeStore)).
//! The system-of-record stores (`UserStore`, `PasskeyCredentialStore`) stay in
//! a SQL backend; see the crate docs for the rationale.

pub(crate) mod passkey_chal;
pub(crate) mod session;
pub(crate) mod verification;
