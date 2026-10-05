use std::sync::Arc;
use std::time::Duration;

use doorman_core::assembly::AuthCore;

use url::Url;

use crate::AuthService;
use crate::config::CookieConfig;
use crate::cookies::clear_session_cookie;
use crate::csrf::CsrfConfig;
use crate::session::{SessionLayer, SessionLayerState};
use crate::state::AuthState;

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error(
        "a CSRF decision is required: set external_origin to enable origin checks, or pass CsrfConfig::disabled() to opt out"
    )]
    CsrfDecisionRequired,
    #[error("cookie name `{name}` carries a {prefix} prefix but {requirement}")]
    InvalidCookiePrefix {
        name: String,
        prefix: &'static str,
        requirement: &'static str,
    },
    #[error("the session cookie name, path or domain contains a control character")]
    InvalidCookieAttributes,
    #[error(
        "cookie Max-Age ({cookie_max_age:?}) exceeds the session lifetime ({session_lifetime:?})"
    )]
    CookieMaxAgeExceedsSessionLifetime {
        cookie_max_age: Duration,
        session_lifetime: Duration,
    },
}

pub struct AuthServiceBuilder {
    core: AuthCore,
    cookie_config: Option<CookieConfig>,
    csrf_config: Option<CsrfConfig>,
    external_origin: Option<Url>,
}

impl AuthServiceBuilder {
    pub(crate) fn new(core: AuthCore) -> Self {
        Self {
            core,
            cookie_config: None,
            csrf_config: None,
            external_origin: None,
        }
    }

    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    pub fn build(self) -> Result<AuthService, BuilderError> {
        let core = self.core;
        let cookie_config = self.cookie_config.unwrap_or_default();
        validate_cookie_prefix(&cookie_config)?;
        if clear_session_cookie(&cookie_config).is_err() {
            return Err(BuilderError::InvalidCookieAttributes);
        }

        let session_lifetime = core.session_manager.unused_lifetime();
        if cookie_config.session_max_age > session_lifetime {
            return Err(BuilderError::CookieMaxAgeExceedsSessionLifetime {
                cookie_max_age: cookie_config.session_max_age,
                session_lifetime,
            });
        }

        let csrf_config = match (self.csrf_config, self.external_origin) {
            (Some(config), _) => config,
            (None, Some(origin)) => CsrfConfig::new(origin),
            (None, None) => return Err(BuilderError::CsrfDecisionRequired),
        }
        .enabled_config();

        let layer_state = Arc::new(SessionLayerState {
            resolver: core.resolver.clone(),
            cookie: cookie_config.clone(),
            csrf: csrf_config,
        });

        let state = AuthState {
            core: Arc::new(core),
            cookie_config: Arc::new(cookie_config),
        };

        Ok(AuthService {
            state,
            session_layer: SessionLayer::new(layer_state),
        })
    }
}

fn validate_cookie_prefix(config: &CookieConfig) -> Result<(), BuilderError> {
    let name = config.session_cookie_name.as_str();
    let invalid = |prefix, requirement| BuilderError::InvalidCookiePrefix {
        name: name.to_string(),
        prefix,
        requirement,
    };
    if name.starts_with("__Host-") {
        if !config.secure {
            return Err(invalid("__Host-", "requires secure = true"));
        }
        if config.path != "/" {
            return Err(invalid("__Host-", "requires path = \"/\""));
        }
        if config.domain.is_some() {
            return Err(invalid("__Host-", "must not set a Domain attribute"));
        }
    } else if name.starts_with("__Secure-") && !config.secure {
        return Err(invalid("__Secure-", "requires secure = true"));
    }
    Ok(())
}
