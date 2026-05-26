//! Common imports for hosts using `bauth-core` directly.
//!
//! ```ignore
//! use bauth_core::prelude::*;
//! ```
//!
//! Brings the storage traits, manager types, configs, and the trait-shaped
//! collaborators (clock, audit, email, rate limiter) into scope in one
//! line. Hosts who want a narrower import surface should reach into the
//! individual modules instead.

pub use crate::audit::{
    AuditEvent, AuditEventKind, AuditSink, AuthMethod, CredentialKind, LoginFailureReason,
    NoopAuditSink,
};
pub use crate::clock::{Clock, SystemClock};
pub use crate::email::{BauthEmails, DefaultBauthEmails, Email, EmailSender, NoopEmailSender};
pub use crate::error::{Error, Result, StorageError, StorageResult};
pub use crate::magic_link::{
    MagicLinkConfig, MagicLinkManager, MagicLinkOutcome, MagicLinkRateLimits,
};
pub use crate::oauth::{
    OAuthConfig, OAuthManager, OAuthOutcome, OAuthProvider, ProviderError, ProviderUser,
    StartedAuthorization,
};
pub use crate::passkey::{PasskeyConfig, PasskeyManager};
pub use crate::password::PasswordPolicy;
pub use crate::password_auth::{
    PasswordAuthConfig, PasswordAuthManager, PasswordRateLimits, RegisterOutcome,
};
pub use crate::rate_limit::{NoopRateLimiter, RateLimitDecision, RateLimitPolicy, RateLimiter};
pub use crate::session::{
    IssuedSession, SessionConfig, SessionContext, SessionInvalidationHook, SessionManager,
};
pub use crate::storage::{
    OAuthIdentity, OAuthIdentityStore, OAuthStateId, OAuthStateStore, PasskeyChallengeId,
    PasskeyChallengeStore, PasskeyCredentialStore, PasswordCredential, PasswordCredentialStore,
    PendingOAuthAuthorization, Session, SessionId, SessionStore, Storage, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId, UserStore,
    VerificationPurpose, VerificationToken, VerificationTokenStore,
};
