//! Provider abstraction for OAuth 2.0 / OIDC login flows.
//!
//! A [`OAuthProvider`] knows how to build a consent URL and how to exchange
//! an authorization code for a normalised [`ProviderUser`]. Concrete
//! provider implementations (Google, GitHub) live alongside this module;
//! tests can also implement the trait directly with canned responses to
//! avoid standing up an HTTP server.

use std::fmt;

use async_trait::async_trait;
use url::Url;

/// What the manager hands to [`OAuthProvider::authorization_url`] when it
/// has finished generating per-request crypto material (state, PKCE).
#[derive(Debug, Clone)]
pub struct AuthorizationRequest<'a> {
    /// CSRF state; also doubles as our storage key for the pending
    /// authorization. Round-trips through the provider verbatim.
    pub state: &'a str,
    /// PKCE `code_challenge` (S256). Sent now; the verifier is sent at
    /// exchange time.
    pub pkce_challenge: &'a str,
    /// Where the provider should redirect the browser after consent.
    /// Must exactly match a redirect URI registered with the provider.
    pub redirect_uri: &'a str,
}

/// What the manager hands to [`OAuthProvider::exchange`] when the callback
/// is being processed.
#[derive(Debug, Clone)]
pub struct ExchangeRequest<'a> {
    pub code: &'a str,
    pub pkce_verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// Normalised end-user information returned by a provider after a
/// successful token exchange. The fields are the lowest-common-denominator
/// across providers; provider-specific extras are deliberately not
/// surfaced through this trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderUser {
    /// Stable, opaque, provider-side user identifier. For OIDC this is
    /// the `sub` claim; for GitHub it is the numeric `id`.
    pub subject: String,
    /// Email reported by the provider, lower-cased. May be absent (e.g.
    /// a GitHub user with no public address and no granted email scope).
    pub email: Option<String>,
    /// `true` if and only if the provider asserts the email is verified.
    /// Drives auto-linking decisions; never set this optimistically.
    pub email_verified: bool,
    /// Human display name reported by the provider, if any. Informational
    /// only — the library does not persist it.
    pub display_name: Option<String>,
}

#[derive(Debug)]
pub enum ProviderError {
    /// Transport-level failure (DNS, TLS, timeout, connection reset).
    Http(String),
    /// HTTP status indicated an error and/or the body could not be parsed.
    Response { status: u16, message: String },
    /// Response body parsed but a required field was absent or empty.
    MissingField(&'static str),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(msg) => write!(f, "transport error: {msg}"),
            Self::Response { status, message } => write!(f, "http {status}: {message}"),
            Self::MissingField(name) => write!(f, "missing field `{name}` in provider response"),
        }
    }
}

impl std::error::Error for ProviderError {}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Stable identifier used as the storage key for linked identities.
    /// Convention: lower-case, no spaces (e.g. `"google"`, `"github"`).
    /// Must be unique across providers registered with a manager.
    fn name(&self) -> &str;

    /// Build the consent URL to redirect the user-agent to. Synchronous
    /// because it is pure URL construction; no network is involved.
    fn authorization_url(&self, request: AuthorizationRequest<'_>) -> Url;

    /// Exchange `code` for tokens and fetch user info, returning the
    /// normalised end-user representation. Implementations MUST verify
    /// the provider's response indicates success before claiming the user
    /// is authenticated.
    async fn exchange(
        &self,
        request: ExchangeRequest<'_>,
    ) -> std::result::Result<ProviderUser, ProviderError>;
}
