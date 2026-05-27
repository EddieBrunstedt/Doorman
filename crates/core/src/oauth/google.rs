//! Google OAuth 2.0 / OpenID Connect provider.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::http::decode_json;
use super::provider::{
    AuthorizationRequest, ExchangeRequest, OAuthProvider, ProviderError, ProviderUser,
};

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// Default scopes requested. `openid` enables OIDC semantics; `email` and
/// `profile` populate the corresponding userinfo fields.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

/// Built-in Google OAuth / OpenID Connect provider.
#[derive(Clone)]
pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    http: Client,
}

impl GoogleProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect(),
            http: Client::new(),
        }
    }

    /// Override the default OAuth scopes.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Inject a pre-configured `reqwest` client (useful for custom timeouts
    /// or shared connection pools).
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
struct UserInfoResponse {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn name(&self) -> &str {
        "google"
    }

    fn authorization_url(&self, request: AuthorizationRequest<'_>) -> Url {
        let mut url = Url::parse(AUTH_URL).expect("static auth url parses");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", &self.client_id);
            q.append_pair("redirect_uri", request.redirect_uri);
            q.append_pair("scope", &self.scopes.join(" "));
            q.append_pair("state", request.state);
            q.append_pair("code_challenge", request.pkce_challenge);
            q.append_pair("code_challenge_method", "S256");
            q.append_pair("access_type", "online");
        }
        url
    }

    async fn exchange(&self, request: ExchangeRequest<'_>) -> Result<ProviderUser, ProviderError> {
        let token_response = self
            .http
            .post(TOKEN_URL)
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

        let userinfo_response = self
            .http
            .get(USERINFO_URL)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let info: UserInfoResponse = decode_json(userinfo_response).await?;

        Ok(ProviderUser {
            subject: info.sub,
            email: info.email,
            email_verified: info.email_verified.unwrap_or(false),
            display_name: info.name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_includes_required_params() {
        let p = GoogleProvider::new("cid", "secret");
        let url = p.authorization_url(AuthorizationRequest {
            state: "STATE",
            pkce_challenge: "CHAL",
            redirect_uri: "https://app.test/cb",
        });
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("client_id").map(String::as_str), Some("cid"));
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(query.get("state").map(String::as_str), Some("STATE"));
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some("CHAL")
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(query.get("scope").unwrap().contains("openid"));
    }
}
