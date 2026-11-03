use std::sync::Arc;

use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelyingPartyError {
    #[error("origin {0} has no domain name to take the relying party ID from")]
    NoDomain(Url),
    #[error("relying party ID `{id}` is neither the domain of origin {origin} nor a parent of it")]
    IdOutsideOrigin { id: String, origin: Url },
    #[error("webauthn-rs refused the relying party: {0}")]
    Refused(String),
}

// Holds the verifier webauthn-rs builds from it, so webauthn-rs's own check of the ID against the
// origin runs once, when the relying party is made.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    webauthn: Arc<Webauthn>,
}

impl RelyingParty {
    pub fn builder(origin: Url, name: impl Into<String>) -> RelyingPartyBuilder {
        RelyingPartyBuilder {
            origin,
            name: name.into(),
            id: None,
            additional_origins: Vec::new(),
        }
    }

    pub fn from_origin(origin: Url, name: impl Into<String>) -> Result<Self, RelyingPartyError> {
        Self::builder(origin, name).build()
    }

    pub fn origins(&self) -> &[Url] {
        self.webauthn.get_allowed_origins()
    }

    pub(crate) fn webauthn(&self) -> &Arc<Webauthn> {
        &self.webauthn
    }
}

#[derive(Debug, Clone)]
pub struct RelyingPartyBuilder {
    origin: Url,
    name: String,
    id: Option<String>,
    additional_origins: Vec<Url>,
}

impl RelyingPartyBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    // A native app's origin has no domain, so nothing checks it against the ID.
    pub fn additional_origin(mut self, origin: Url) -> Self {
        self.additional_origins.push(origin);
        self
    }

    pub fn build(self) -> Result<RelyingParty, RelyingPartyError> {
        let Some(domain) = self.origin.domain() else {
            return Err(RelyingPartyError::NoDomain(self.origin));
        };
        let id = self.id.unwrap_or_else(|| domain.to_owned());
        // `WebauthnBuilder::new` refuses only an ID that is neither the origin's domain nor a
        // parent of it.
        let mut builder = match WebauthnBuilder::new(&id, &self.origin) {
            Ok(builder) => builder.rp_name(&self.name),
            Err(_) => {
                return Err(RelyingPartyError::IdOutsideOrigin {
                    id,
                    origin: self.origin,
                });
            }
        };
        for origin in &self.additional_origins {
            builder = builder.append_allowed_origin(origin);
        }
        // Its `build` refuses nothing yet; whatever it refuses later still stops here.
        let webauthn = builder
            .build()
            .map_err(|e| RelyingPartyError::Refused(e.to_string()))?;
        Ok(RelyingParty {
            webauthn: Arc::new(webauthn),
        })
    }
}
