use doorman_core::storage::{PasskeyChallengeId, SessionId, TokenHash, UserId};

#[derive(Clone, Debug)]
pub(crate) struct KeySchema {
    prefix: String,
}

impl KeySchema {
    pub(crate) fn new(prefix: String) -> Self {
        Self { prefix }
    }

    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    pub(crate) fn session(&self, id: SessionId) -> String {
        self.session_key_for(&id.0.to_string())
    }

    pub(crate) fn session_key_for(&self, id: &str) -> String {
        format!("{}session:{}", self.prefix, id)
    }

    pub(crate) fn session_hash_index(&self, hash: &TokenHash) -> String {
        format!("{}session:hash:{}", self.prefix, token_hash_hex(hash))
    }

    pub(crate) fn user_sessions(&self, user_id: UserId) -> String {
        format!("{}user:{}:sessions", self.prefix, user_id.0)
    }

    pub(crate) fn user_sessions_pattern(&self) -> String {
        format!("{}user:*:sessions", self.prefix)
    }

    pub(crate) fn email_link(&self, hash: &TokenHash) -> String {
        self.email_link_key_for(&token_hash_hex(hash))
    }

    pub(crate) fn email_link_key_for(&self, hex_hash: &str) -> String {
        format!("{}email_link:{}", self.prefix, hex_hash)
    }

    pub(crate) fn user_email_links(&self, user_id: UserId) -> String {
        format!("{}user:{}:email_links", self.prefix, user_id.0)
    }

    pub(crate) fn user_email_links_pattern(&self) -> String {
        format!("{}user:*:email_links", self.prefix)
    }

    pub(crate) fn pkreg(&self, id: PasskeyChallengeId) -> String {
        self.pkreg_key_for(&id.0.to_string())
    }

    pub(crate) fn pkreg_key_for(&self, id: &str) -> String {
        format!("{}pkreg:{}", self.prefix, id)
    }

    pub(crate) fn user_pkregs(&self, user_id: UserId) -> String {
        format!("{}user:{}:pkregs", self.prefix, user_id.0)
    }

    pub(crate) fn user_pkregs_pattern(&self) -> String {
        format!("{}user:*:pkregs", self.prefix)
    }

    pub(crate) fn pkauth(&self, id: PasskeyChallengeId) -> String {
        format!("{}pkauth:{}", self.prefix, id.0)
    }

    pub(crate) fn pkauth_pattern(&self) -> String {
        format!("{}pkauth:*", self.prefix)
    }

    pub(crate) fn rate_limit(&self, canonical: &str, window_ms: u128) -> String {
        format!("{}ratelimit:{}:{}", self.prefix, window_ms, canonical)
    }
}

pub(crate) fn token_hash_hex(hash: &TokenHash) -> String {
    doorman_core::encoding::hex(&hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use doorman_core::session::hash_token;

    #[test]
    fn keys_are_prefixed() {
        let keys = KeySchema::new("doorman:".to_string());
        let hash = hash_token("a-token");
        let user = UserId::new();

        assert!(
            keys.session_hash_index(&hash)
                .starts_with("doorman:session:hash:")
        );
        assert_eq!(keys.prefix(), "doorman:");

        assert_eq!(
            keys.email_link(&hash),
            format!("doorman:email_link:{}", token_hash_hex(&hash))
        );

        assert_eq!(
            keys.user_email_links(user),
            format!("doorman:user:{}:email_links", user.0)
        );
    }

    #[test]
    fn hex_is_64_lowercase_chars() {
        let hash = hash_token("x");
        let h = token_hash_hex(&hash);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
