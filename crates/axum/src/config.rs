pub use cookie::SameSite;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CookieConfigError {
    #[error("cookie name `{0}` is not an RFC 6265 token")]
    InvalidName(String),
    #[error("cookie path `{0}` must start with `/` and hold only visible ASCII other than `;`")]
    InvalidPath(String),
    #[error("cookie domain `{0}` is not a domain name")]
    InvalidDomain(String),
    #[error("a cookie whose name carries the {0} prefix must be Secure")]
    PrefixNeedsSecure(&'static str),
    #[error("a cookie whose name carries the __Host- prefix must have the path `/`")]
    HostPrefixNeedsRootPath,
    #[error("a cookie whose name carries the __Host- prefix must not set a domain")]
    HostPrefixForbidsDomain,
    #[error("a cookie with SameSite=None must be Secure")]
    SameSiteNoneNeedsSecure,
}

#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub(crate) name: String,
    pub(crate) domain: Option<String>,
    pub(crate) path: String,
    pub(crate) secure: bool,
    pub(crate) same_site: SameSite,
}

impl CookieConfig {
    pub const DEFAULT_NAME: &'static str = "doorman_session";

    pub fn builder(name: impl Into<String>) -> CookieConfigBuilder {
        CookieConfigBuilder {
            config: Self {
                name: name.into(),
                ..Self::default()
            },
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> Result<(), CookieConfigError> {
        if !is_token(&self.name) {
            return Err(CookieConfigError::InvalidName(self.name.clone()));
        }
        if !self.path.starts_with('/') || !self.path.chars().all(is_attribute_char) {
            return Err(CookieConfigError::InvalidPath(self.path.clone()));
        }
        if let Some(domain) = &self.domain
            && !is_domain(domain)
        {
            return Err(CookieConfigError::InvalidDomain(domain.clone()));
        }
        // Browsers match the prefixes case-insensitively, and drop a cookie that breaks a rule.
        if has_prefix(&self.name, "__Host-") {
            if !self.secure {
                return Err(CookieConfigError::PrefixNeedsSecure("__Host-"));
            }
            if self.path != "/" {
                return Err(CookieConfigError::HostPrefixNeedsRootPath);
            }
            if self.domain.is_some() {
                return Err(CookieConfigError::HostPrefixForbidsDomain);
            }
        }
        if has_prefix(&self.name, "__Secure-") && !self.secure {
            return Err(CookieConfigError::PrefixNeedsSecure("__Secure-"));
        }
        if self.same_site == SameSite::None && !self.secure {
            return Err(CookieConfigError::SameSiteNoneNeedsSecure);
        }
        Ok(())
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: Self::DEFAULT_NAME.to_owned(),
            domain: None,
            path: "/".to_owned(),
            secure: true,
            same_site: SameSite::Lax,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CookieConfigBuilder {
    config: CookieConfig,
}

impl CookieConfigBuilder {
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.config.domain = Some(domain.into());
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.config.path = path.into();
        self
    }

    // Browsers drop a Secure cookie that a plain-http page other than localhost sets.
    pub fn insecure(mut self) -> Self {
        self.config.secure = false;
        self
    }

    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.config.same_site = same_site;
        self
    }

    pub fn build(self) -> Result<CookieConfig, CookieConfigError> {
        self.config.check()?;
        Ok(self.config)
    }
}

fn has_prefix(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

// RFC 6265's cookie-name: visible ASCII other than separators.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b))
}

// RFC 6265's av-octet: visible ASCII or a space, other than `;`.
fn is_attribute_char(c: char) -> bool {
    (c.is_ascii_graphic() || c == ' ') && c != ';'
}

// A host name in ASCII, so an internationalised domain is given in its punycode form. Browsers
// ignore one leading dot.
fn is_domain(domain: &str) -> bool {
    let domain = domain.strip_prefix('.').unwrap_or(domain);
    !domain.is_empty()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_passes_its_own_checks() {
        let config = CookieConfig::default();
        assert_eq!(config.check(), Ok(()));
        assert_eq!(config.name(), CookieConfig::DEFAULT_NAME);
    }
}
