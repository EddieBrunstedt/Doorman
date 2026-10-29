use std::sync::Arc;

use doorman_core::assembly::AuthCore;

use url::Url;

use crate::AuthService;
use crate::config::CookieConfig;
use crate::cookies::clear_session_cookie;
use crate::csrf::TrustedOrigins;
use crate::purge::{PurgeSchedule, Sweeper};
use crate::session::{SessionLayer, SessionLayerState};
use crate::state::AuthState;

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("cookie name `{name}` carries a {prefix} prefix but {requirement}")]
    InvalidCookiePrefix {
        name: String,
        prefix: &'static str,
        requirement: &'static str,
    },
    #[error("the session cookie name, path or domain contains a control character")]
    InvalidCookieAttributes,
    #[error(
        "PurgeSchedule::in_process sweeps on a tokio task, so the service must be built inside a tokio runtime"
    )]
    PurgeNeedsRuntime,
}

pub struct AuthServiceBuilder {
    core: AuthCore,
    cookie_config: Option<CookieConfig>,
    trusted_origins: Vec<Url>,
    purge: PurgeSchedule,
}

impl AuthServiceBuilder {
    pub(crate) fn new(core: AuthCore, purge: PurgeSchedule) -> Self {
        Self {
            core,
            cookie_config: None,
            trusted_origins: Vec::new(),
            purge,
        }
    }

    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    pub fn trusted_origin(mut self, origin: Url) -> Self {
        self.trusted_origins.push(origin);
        self
    }

    pub fn build(self) -> Result<AuthService, BuilderError> {
        let sweeper = Sweeper::for_schedule(self.purge)?;
        let core = self.core;
        let cookie_config = self.cookie_config.unwrap_or_default();
        validate_cookie_prefix(&cookie_config)?;
        if clear_session_cookie(&cookie_config).is_err() {
            return Err(BuilderError::InvalidCookieAttributes);
        }

        // The relying party's origins are where the application's pages run passkey ceremonies,
        // so they are the origins its requests come from.
        let trusted_origins = TrustedOrigins::new(
            core.passkey
                .rp_origins()
                .cloned()
                .chain(self.trusted_origins),
        );

        let layer_state = Arc::new(SessionLayerState {
            sessions: core.sessions.clone(),
            cookie: cookie_config.clone(),
            trusted_origins,
        });

        let core = Arc::new(core);
        // Started last, so a build that fails leaves no task behind.
        if let Some(sweeper) = sweeper {
            sweeper.start(&core);
        }

        let state = AuthState {
            core,
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
