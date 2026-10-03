//! What's cached per isolate: each issuer's keys, and each verified token
//! until it expires. A Worker's isolate outlives its requests, so both carry
//! over from one request to the next.

use std::{cell::RefCell, collections::HashMap};

use sha2::{Digest, Sha256};
use worker::Date;

use crate::{Jwt, jwk::RsaKey};

/// How long a fetched JWK Set is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's JWK Set at most this often, so
/// tokens with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 30 * 1000;

thread_local! {
    /// Each issuer's keys, by issuer.
    static KEYS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
    static VERIFIED: RefCell<VerifiedCache> = RefCell::new(VerifiedCache::new());
}

/// Whether `issuer`'s key `kid` is cached, or its keys should be fetched.
pub(crate) fn key(issuer: &str, kid: Option<&str>, now_ms: u64) -> Lookup {
    KEYS.with_borrow(|sets| KeySet::lookup(sets.get(issuer), kid, now_ms))
}

/// Caches `keys`, `issuer`'s, fetched at `now_ms`. Returns the one `kid`
/// names.
pub(crate) fn store_keys(
    issuer: &str,
    keys: Vec<RsaKey>,
    kid: Option<&str>,
    now_ms: u64,
) -> Option<RsaKey> {
    let set = KeySet {
        keys,
        fetched_at: now_ms,
    };
    let key = set.find(kid).cloned();
    KEYS.with_borrow_mut(|sets| sets.insert(issuer.to_string(), set));
    key
}

/// `token`, verified, if it's cached and hasn't expired by `now_ms`.
pub(crate) fn jwt(token: &str, now_ms: u64) -> Option<Jwt> {
    let key = VerifiedCache::key(token);
    VERIFIED.with_borrow(|cache| cache.get(&key, now_ms))
}

/// Caches `jwt`, verified from `token`, until `expires_at`.
pub(crate) fn store_jwt(token: &str, jwt: Jwt, expires_at: u64, now_ms: u64) {
    let key = VerifiedCache::key(token);
    VERIFIED.with_borrow_mut(|cache| cache.insert(key, jwt, expires_at, now_ms));
}

/// `token`, if [`Providers::verify`](crate::Providers::verify) accepted it in
/// this isolate and it hasn't expired since.
pub fn verified(token: &str) -> Option<Jwt> {
    jwt(token, Date::now().as_millis())
}

/// An issuer's keys, cached per isolate.
struct KeySet {
    keys: Vec<RsaKey>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Lookup {
    Hit(RsaKey),
    Fetch,
    /// Unknown `kid`, and the JWK Set was fetched too recently to try again.
    Unknown,
}

impl KeySet {
    /// The key with this `kid`; without one, the only key there is.
    fn find(&self, kid: Option<&str>) -> Option<&RsaKey> {
        match kid {
            Some(kid) => self.keys.iter().find(|key| key.kid() == Some(kid)),
            None => match self.keys.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    fn lookup(set: Option<&KeySet>, kid: Option<&str>, now_ms: u64) -> Lookup {
        let Some(set) = set else {
            return Lookup::Fetch;
        };
        let age = now_ms.saturating_sub(set.fetched_at);
        match set.find(kid) {
            Some(key) if age < JWKS_TTL_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < JWKS_MIN_REFETCH_MS => Lookup::Unknown,
            None => Lookup::Fetch,
        }
    }
}

/// Per-isolate cache of verified tokens, keyed by the SHA-256 of the token
/// so raw tokens are never stored.
struct VerifiedCache {
    entries: HashMap<[u8; 32], (u64, Jwt)>,
}

impl VerifiedCache {
    /// Upper bound on entries, so a flood of distinct tokens can't grow the
    /// isolate's memory without limit.
    const MAX_ENTRIES: usize = 1024;

    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn key(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Jwt> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, jwt)| jwt.clone())
    }

    fn insert(&mut self, key: [u8; 32], jwt: Jwt, expires_at: u64, now_ms: u64) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, jwt));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Claims, Header, jwk::JwkSet};

    fn jwt() -> Jwt {
        Jwt {
            header: Header::default(),
            claims: Claims::default(),
        }
    }

    #[test]
    fn verified_tokens_expire() {
        let mut cache = VerifiedCache::new();
        let key = VerifiedCache::key("token");
        cache.insert(key, jwt(), 100, 0);
        assert_eq!(cache.get(&key, 99), Some(jwt()));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn verified_tokens_are_bounded() {
        let mut cache = VerifiedCache::new();
        for i in 0..=VerifiedCache::MAX_ENTRIES {
            cache.insert(VerifiedCache::key(&i.to_string()), jwt(), 100, 0);
        }
        assert!(cache.entries.len() <= VerifiedCache::MAX_ENTRIES);
    }

    #[test]
    fn refetches_sparingly() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
        ]}))
        .unwrap();
        let set = KeySet {
            keys: jwks.rs256_keys(),
            fetched_at: 0,
        };

        assert_eq!(KeySet::lookup(None, Some("key-1"), 0), Lookup::Fetch);
        assert!(matches!(
            KeySet::lookup(Some(&set), Some("key-1"), 1),
            Lookup::Hit(_)
        ));
        // Without a kid, the only key.
        assert!(matches!(
            KeySet::lookup(Some(&set), None, 1),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-1"), JWKS_TTL_MS),
            Lookup::Fetch
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), 1),
            Lookup::Unknown
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), JWKS_MIN_REFETCH_MS),
            Lookup::Fetch
        );
    }
}
