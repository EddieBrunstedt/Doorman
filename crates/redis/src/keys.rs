use std::fmt;

use doorman_core::storage::{TokenHash, UserId};
use redis::{RedisWrite, ToRedisArgs};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace(String);

impl Namespace {
    pub fn new(name: impl Into<String>) -> Result<Self, NamespaceError> {
        let name = name.into();
        if name.is_empty() {
            return Err(NamespaceError::Empty);
        }
        // Every key starts with the namespace as its hash tag; a brace inside it would end the tag
        // early or open another, and the keys would no longer share one hash slot.
        if name.contains(['{', '}']) {
            return Err(NamespaceError::Brace);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self("doorman".to_owned())
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NamespaceError {
    #[error("a Redis namespace must not be empty")]
    Empty,
    #[error("a Redis namespace must not contain `{{` or `}}`")]
    Brace,
}

// Deliberately neither `Display` nor a string accessor: a key reaches Redis only as a command's
// key or a script's declared key, never as text a script could take apart or rebuild.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Key(String);

impl ToRedisArgs for Key {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        out.write_arg(self.0.as_bytes());
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Ownership {
    None,
    // A sorted set of the owner's row ids, scored by deadline.
    Set,
    // A hash naming at most one row per field.
    Field,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Family {
    pub(crate) row: &'static str,
    pub(crate) rows: &'static str,
    pub(crate) ownership: Ownership,
}

#[derive(Clone, Debug)]
pub(crate) struct Keys {
    tag: String,
}

impl Keys {
    pub(crate) fn new(namespace: &Namespace) -> Self {
        Self {
            tag: format!("{{{namespace}}}"),
        }
    }

    pub(crate) fn row(&self, family: Family, id: &str) -> Key {
        Key(format!("{}:{}:{id}", self.tag, family.row))
    }

    pub(crate) fn deadlines(&self, family: Family) -> Key {
        Key(format!("{}:deadline:{}", self.tag, family.rows))
    }

    pub(crate) fn owned(&self, family: Family, owner: UserId) -> Key {
        Key(format!("{}:user:{}:{}", self.tag, owner.0, family.rows))
    }

    pub(crate) fn session_by_token_hash(&self, hash: &TokenHash) -> Key {
        Key(format!(
            "{}:session:hash:{}",
            self.tag,
            token_hash_hex(hash)
        ))
    }

    pub(crate) fn rate_limit(&self, canonical: &str, window_ms: u128) -> Key {
        Key(format!("{}:ratelimit:{window_ms}:{canonical}", self.tag))
    }
}

pub(crate) fn token_hash_hex(hash: &TokenHash) -> String {
    doorman_core::encoding::hex(&hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use doorman_core::session::hash_token;

    const SESSIONS: Family = Family {
        row: "session",
        rows: "sessions",
        ownership: Ownership::Set,
    };

    fn text(key: Key) -> String {
        key.0
    }

    #[test]
    fn a_namespace_must_be_a_non_empty_hash_tag() {
        assert_eq!(Namespace::new(""), Err(NamespaceError::Empty));
        for braced in ["{app", "app}", "a{b}c", "{}"] {
            assert_eq!(
                Namespace::new(braced),
                Err(NamespaceError::Brace),
                "{braced}"
            );
        }
        for plain in ["app", "app*:", "[x]", "a\\b", "doorman:v1"] {
            assert_eq!(
                Namespace::new(plain).map(|n| n.to_string()),
                Ok(plain.to_owned())
            );
        }
        assert_eq!(Namespace::default().as_str(), "doorman");
    }

    #[test]
    fn every_key_starts_with_the_namespace_hash_tag() {
        let keys = Keys::new(&Namespace::new("app").expect("namespace"));
        let hash = hash_token("a-token");
        let user = UserId::new();

        assert_eq!(text(keys.row(SESSIONS, "id")), "{app}:session:id");
        assert_eq!(text(keys.deadlines(SESSIONS)), "{app}:deadline:sessions");
        assert_eq!(
            text(keys.owned(SESSIONS, user)),
            format!("{{app}}:user:{}:sessions", user.0)
        );
        assert_eq!(
            text(keys.session_by_token_hash(&hash)),
            format!("{{app}}:session:hash:{}", token_hash_hex(&hash))
        );
        assert_eq!(
            text(keys.rate_limit("login:{x}", 60_000)),
            "{app}:ratelimit:60000:login:{x}"
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
