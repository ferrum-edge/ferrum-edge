use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct TokenKey {
    digest: [u8; 32],
}

impl TokenKey {
    pub fn from_token(token: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self { digest }
    }

    #[cfg(test)]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

enum Entry {
    Active {
        claims: Arc<Value>,
        expires_at: Instant,
    },
    Negative {
        expires_at: Instant,
    },
}

pub enum CacheLookup {
    Active(Arc<Value>),
    Negative,
    Miss,
}

pub struct IntrospectionCache {
    entries: DashMap<TokenKey, Entry>,
    max_entries: usize,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl IntrospectionCache {
    pub fn new(
        max_entries: usize,
        positive_ttl: Duration,
        negative_ttl: Duration,
        shard_amount: usize,
    ) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            max_entries,
            positive_ttl,
            negative_ttl,
        }
    }

    pub fn get(&self, token: &str, now: Instant) -> CacheLookup {
        let key = TokenKey::from_token(token);
        let expired = match self.entries.get(&key) {
            Some(entry) => match entry.value() {
                Entry::Active { claims, expires_at } if *expires_at > now => {
                    return CacheLookup::Active(claims.clone());
                }
                Entry::Negative { expires_at } if *expires_at > now => {
                    return CacheLookup::Negative;
                }
                _ => true,
            },
            None => false,
        };
        if expired {
            self.entries.remove(&key);
        }
        CacheLookup::Miss
    }

    pub fn insert_active(&self, token: &str, claims: Arc<Value>, now: Instant, exp: Option<i64>) {
        if self.positive_ttl.is_zero() {
            return;
        }
        let mut expires_at = now + self.positive_ttl;
        if let Some(exp) = exp {
            let unix_now = chrono::Utc::now().timestamp();
            if exp > unix_now {
                let exp_deadline = now + Duration::from_secs((exp - unix_now) as u64);
                expires_at = expires_at.min(exp_deadline);
            } else {
                return;
            }
        }
        self.insert(
            TokenKey::from_token(token),
            Entry::Active { claims, expires_at },
            now,
        );
    }

    pub fn insert_negative(&self, token: &str, now: Instant) {
        if self.negative_ttl.is_zero() {
            return;
        }
        self.insert(
            TokenKey::from_token(token),
            Entry::Negative {
                expires_at: now + self.negative_ttl,
            },
            now,
        );
    }

    fn insert(&self, key: TokenKey, entry: Entry, now: Instant) {
        if self.entries.len() >= self.max_entries {
            self.evict_expired(now);
        }
        if self.entries.len() >= self.max_entries
            && let Some(victim) = self.entries.iter().next().map(|entry| entry.key().clone())
        {
            self.entries.remove(&victim);
        }
        self.entries.insert(key, entry);
    }

    fn evict_expired(&self, now: Instant) {
        self.entries.retain(|_, entry| match entry {
            Entry::Active { expires_at, .. } | Entry::Negative { expires_at } => *expires_at > now,
        });
    }
}

static INTROSPECTION_CACHE: OnceLock<Arc<DashMap<String, Arc<IntrospectionCache>>>> =
    OnceLock::new();

fn global_cache() -> &'static Arc<DashMap<String, Arc<IntrospectionCache>>> {
    INTROSPECTION_CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

pub fn get_or_create_introspection_cache(
    cache_key: &str,
    max_entries: usize,
    positive_ttl: Duration,
    negative_ttl: Duration,
    shard_amount: usize,
) -> Arc<IntrospectionCache> {
    global_cache()
        .entry(cache_key.to_string())
        .or_insert_with(|| {
            Arc::new(IntrospectionCache::new(
                max_entries,
                positive_ttl,
                negative_ttl,
                shard_amount,
            ))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_key_hash_does_not_store_raw_token() {
        let key = TokenKey::from_token("secret-token");
        assert_ne!(key.digest().as_slice(), b"secret-token");
    }

    #[test]
    fn positive_cache_expires() {
        let cache = IntrospectionCache::new(10, Duration::from_secs(1), Duration::from_secs(1), 4);
        let now = Instant::now();
        cache.insert_active("token", Arc::new(json!({"active": true})), now, None);
        assert!(matches!(cache.get("token", now), CacheLookup::Active(_)));
        assert!(matches!(
            cache.get("token", now + Duration::from_secs(2)),
            CacheLookup::Miss
        ));
    }
}
