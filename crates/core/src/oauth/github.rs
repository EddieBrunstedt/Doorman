//! GitHub OAuth provider.
//!
//! GitHub does not return email-verification status from `/user`; this
//! provider calls `/user/emails` (which requires the `user:email` scope)
//! and uses the primary verified address. That separate call is the only
//! reason this implementation is more involved than [`super::google`].

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::http::decode_json;
use super::provider::{
    AuthorizationRequest, ExchangeRequest, OAuthProvider, ProviderError, ProviderUser,
};

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const EMAILS_URL: &str = "https://api.github.com/user/emails";

/// `read:user` populates `/user`; `user:email` is required so we can read
/// `/user/emails` and identify the primary verified address.
pub const DEFAULT_SCOPES: &[&str] = &["read:user", "user:email"];

/// GitHub rejects API requests without a User-Agent header.
const USER_AGENT: &str = concat!("bauth/", env!("CARGO_PKG_VERSION"));

/// Built-in GitHub OAuth provider.
#[derive(Clone)]
pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    http: Client,
}

impl GitHubProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect(),
            http: Client::new(),
        }
    }

    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_http_client(mut self, http: Client) -> Self {
        self.http = http;
        self
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct UserResponse {
    id: u64,
    email: Option<String>,
    name: Option<String>,
    login: String,
}

#[derive(Debug, Deserialize)]
struct EmailEntry {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn authorization_url(&self, request: AuthorizationRequest<'_>) -> Url {
        let mut url = Url::parse(AUTH_URL).expect("static auth url parses");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.client_id);
            q.append_pair("redirect_uri", request.redirect_uri);
            q.append_pair("scope", &self.scopes.join(" "));
            q.append_pair("state", request.state);
            q.append_pair("code_challenge", request.pkce_challenge);
            q.append_pair("code_challenge_method", "S256");
            q.append_pair("response_type", "code");
        }
        url
    }

    async fn exchange(&self, request: ExchangeRequest<'_>) -> Result<ProviderUser, ProviderError> {
        let token_response = self
            .http
            .post(TOKEN_URL)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", request.code),
                ("redirect_uri", request.redirect_uri),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code_verifier", request.pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let token: TokenResponse = decode_json(token_response).await?;

        let user_response = self
            .http
            .get(USER_URL)
            .bearer_auth(&token.access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let user: UserResponse = decode_json(user_response).await?;

        // GitHub omits unverified or private emails from /user; ask
        // /user/emails directly so we know whether to trust the address.
        let emails_response = self
            .http
            .get(EMAILS_URL)
            .bearer_auth(&token.access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let emails: Vec<EmailEntry> = decode_json(emails_response).await?;

        let primary_verified = emails.iter().find(|e| e.primary && e.verified);
        let (email, email_verified) = match primary_verified {
            Some(entry) => (Some(entry.email.clone()), true),
            None => (user.email, false),
        };

        Ok(ProviderUser {
            subject: user.id.to_string(),
            email,
            email_verified,
            display_name: user.name.or(Some(user.login)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_includes_required_params() {
        let p = GitHubProvider::new("cid", "secret");
        let url = p.authorization_url(AuthorizationRequest {
            state: "STATE",
            pkce_challenge: "CHAL",
            redirect_uri: "https://app.test/cb",
        });
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("client_id").map(String::as_str), Some("cid"));
        assert_eq!(query.get("state").map(String::as_str), Some("STATE"));
        assert!(query.get("scope").unwrap().contains("user:email"));
    }
}
