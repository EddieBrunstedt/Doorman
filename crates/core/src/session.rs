use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

/// Length of the random token in bytes. 256 bits of entropy.
const TOKEN_BYTES: usize = 32;

/// A session that has just been issued, paired with the plaintext token to
/// hand back to the client. The token is never persisted in plaintext.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub session: Session,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub lifetime: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // 30 days
            lifetime: Duration::from_secs(60 * 60 * 24 * 30),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<dyn SessionStore>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    config: SessionConfig,
}

impl SessionManager {
    pub fn new(
        sessions: Arc<dyn SessionStore>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        config: SessionConfig,
    ) -> Self {
        Self {
            sessions,
            clock,
            audit,
            config,
        }
    }

    pub async fn create(&self, user_id: UserId, context: SessionContext) -> Result<IssuedSession> {
        let (token, token_hash) = generate_token();
        let now = self.clock.now();
        let expires_at = now
            + chrono::Duration::from_std(self.config.lifetime)
                .expect("session lifetime overflows chrono::Duration; configure a smaller value");

        let session = Session {
            id: SessionId::new(),
            user_id,
            token_hash,
            created_at: now,
            expires_at,
            ip: context.ip.clone(),
            user_agent: context.user_agent.clone(),
        };

        self.sessions.create_session(session.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::SessionCreated {
                    user_id,
                    session_id: session.id,
                },
            })
            .await;

        Ok(IssuedSession { session, token })
    }

    pub async fn validate(&self, token: &str) -> Result<Session> {
        let hash = hash_token(token);
        let Some(session) = self.sessions.find_session_by_token_hash(&hash).await? else {
            return Err(Error::SessionNotFound);
        };

        let now = self.clock.now();
        if session.expires_at <= now {
            self.audit
                .emit(AuditEvent {
                    timestamp: now,
                    ip: session.ip.clone(),
                    user_agent: session.user_agent.clone(),
                    kind: AuditEventKind::SessionExpired {
                        user_id: session.user_id,
                        session_id: session.id,
                    },
                })
                .await;
            return Err(Error::SessionExpired);
        }

        Ok(session)
    }

    pub async fn revoke(&self, token: &str) -> Result<()> {
        let hash = hash_token(token);
        let Some(session) = self.sessions.find_session_by_token_hash(&hash).await? else {
            return Err(Error::SessionNotFound);
        };
        self.revoke_session(session).await
    }

    pub async fn revoke_by_id(&self, session_id: SessionId) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            return Err(Error::SessionNotFound);
        };
        self.revoke_session(session).await
    }

    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<u64> {
        let count = self.sessions.delete_sessions_for_user(user_id).await?;
        Ok(count)
    }

    pub async fn purge_expired(&self) -> Result<u64> {
        let now = self.clock.now();
        let count = self.sessions.purge_expired(now).await?;
        Ok(count)
    }

    async fn revoke_session(&self, session: Session) -> Result<()> {
        self.sessions.delete_session(session.id).await?;
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: session.ip,
                user_agent: session.user_agent,
                kind: AuditEventKind::SessionRevoked {
                    user_id: session.user_id,
                    session_id: session.id,
                },
            })
            .await;
        Ok(())
    }
}

pub fn hash_token(token: &str) -> TokenHash {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    TokenHash(out)
}

fn generate_token() -> (String, TokenHash) {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_url_safe_and_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
        for ch in a.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "token contains non-url-safe char: {ch:?}"
            );
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_token("hello");
        let b = hash_token("hello");
        assert_eq!(a, b);
    }

    #[test]
    fn default_config_builds() {
        let _ = SessionConfig::default();
    }
}
