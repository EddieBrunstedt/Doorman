//! Begin an OAuth authorization. Generates PKCE + CSRF state, stores
//! the per-flow record, and returns the URL to send the browser to.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::storage::{OAuthStateId, PendingOAuthAuthorization, UserId};

use super::{OAuthManager, StartedAuthorization, provider::AuthorizationRequest};

/// Random bytes for PKCE verifier and CSRF state. 32 bytes → 43-character
/// URL-safe base64 string, which sits inside the W3C-recommended 43..=128
/// PKCE verifier length window.
const RANDOM_BYTES: usize = 32;

impl OAuthManager {
    /// Begin an OAuth authorization. Generates PKCE + CSRF state, stores
    /// the per-flow record, and returns the URL to send the browser to.
    ///
    /// `link_user_id` is `Some` when an already-logged-in user wants to
    /// attach a federated identity to their existing account.
    pub async fn start_authorization(
        &self,
        provider_name: &str,
        redirect_uri: &str,
        link_user_id: Option<UserId>,
    ) -> Result<StartedAuthorization> {
        let provider = self.provider(provider_name)?;

        let state = OAuthStateId(random_base64url());
        let pkce_verifier = random_base64url();
        let pkce_challenge = pkce_s256(&pkce_verifier);

        let url = provider.authorization_url(AuthorizationRequest {
            state: &state.0,
            pkce_challenge: &pkce_challenge,
            redirect_uri,
        });

        let now = self.clock.now();
        let lifetime = chrono::Duration::from_std(self.config.state_lifetime)
            .expect("oauth state lifetime overflows chrono::Duration; configure a smaller value");
        self.states
            .put(PendingOAuthAuthorization {
                state_id: state.clone(),
                provider: provider_name.to_owned(),
                pkce_verifier,
                redirect_uri: redirect_uri.to_owned(),
                link_user_id,
                created_at: now,
                expires_at: now + lifetime,
            })
            .await?;

        Ok(StartedAuthorization {
            state,
            authorize_url: url,
        })
    }
}

fn random_base64url() -> String {
    let mut bytes = [0u8; RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_base64url_sha256() {
        // RFC 7636 §4.2 worked example: verifier
        // `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → challenge
        // `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
        let challenge = pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn random_state_unique() {
        let a = random_base64url();
        let b = random_base64url();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
    }
}
