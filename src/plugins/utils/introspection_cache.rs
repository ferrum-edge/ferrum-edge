use crate::fips::approved::Sha256;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use serde_json::Value;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct TokenKey {
    digest: [u8; 32],
}

impl TokenKey {
    pub fn from_token(token: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest: [u8; 32] = hasher.finalize();
        Self { digest }
    }

    #[cfg(test)]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

enum Entry {
    Active {
        credential: Arc<CachedIntrospection>,
        expires_at: Instant,
    },
    Negative {
        expires_at: Instant,
    },
}

pub enum CacheLookup {
    Active(Arc<CachedIntrospection>),
    Negative,
    Miss,
}

/// Validated provider result retained without the raw bearer token. The
/// absolute expiry is derived once at provider response time so cache hits and
/// single-flight followers cannot extend an `expires_in` credential.
pub struct CachedIntrospection {
    pub claims: Arc<Value>,
    pub expires_at_unix: Option<i64>,
}

pub struct IntrospectionCache {
    entries: DashMap<TokenKey, Entry>,
    entry_count: AtomicUsize,
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
            entry_count: AtomicUsize::new(0),
            max_entries,
            positive_ttl,
            negative_ttl,
        }
    }

    pub fn get(&self, token: &str, now: Instant) -> CacheLookup {
        let key = TokenKey::from_token(token);
        let expired = match self.entries.get(&key) {
            Some(entry) => match entry.value() {
                Entry::Active {
                    credential,
                    expires_at,
                } if *expires_at > now => {
                    return CacheLookup::Active(credential.clone());
                }
                Entry::Negative { expires_at } if *expires_at > now => {
                    return CacheLookup::Negative;
                }
                _ => true,
            },
            None => false,
        };
        if expired {
            self.remove(&key);
        }
        CacheLookup::Miss
    }

    pub fn insert_active(
        &self,
        token: &str,
        credential: Arc<CachedIntrospection>,
        now: Instant,
    ) {
        if self.positive_ttl.is_zero() {
            return;
        }
        let Some(mut expires_at) = now.checked_add(self.positive_ttl) else {
            return;
        };
        if let Some(exp) = credential.expires_at_unix {
            let unix_now = chrono::Utc::now().timestamp();
            if exp > unix_now {
                let Some(exp_deadline) =
                    now.checked_add(Duration::from_secs((exp - unix_now) as u64))
                else {
                    return;
                };
                expires_at = expires_at.min(exp_deadline);
            } else {
                return;
            }
        }
        self.insert(
            TokenKey::from_token(token),
            Entry::Active {
                credential,
                expires_at,
            },
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
        if self.max_entries == 0 {
            return;
        }
        let mut entry = Some(entry);
        loop {
            match self.entries.entry(key.clone()) {
                DashEntry::Occupied(mut occupied) => {
                    if let Some(entry) = entry.take() {
                        occupied.insert(entry);
                    }
                    return;
                }
                DashEntry::Vacant(vacant) => {
                    let reserved = self
                        .entry_count
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < self.max_entries).then_some(count + 1)
                        })
                        .is_ok();
                    if reserved {
                        if let Some(entry) = entry.take() {
                            vacant.insert(entry);
                        } else {
                            self.release_slot();
                        }
                        return;
                    }
                    drop(vacant);
                }
            }

            self.evict_expired(now);
            if self.entry_count.load(Ordering::Acquire) >= self.max_entries {
                let victim = self.entries.iter().next().map(|entry| entry.key().clone());
                if let Some(victim) = victim {
                    self.remove(&victim);
                }
            }
        }
    }

    fn evict_expired(&self, now: Instant) {
        let expired: Vec<TokenKey> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let expired = match entry.value() {
                    Entry::Active { expires_at, .. } | Entry::Negative { expires_at } => {
                        *expires_at <= now
                    }
                };
                expired.then(|| entry.key().clone())
            })
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    fn remove(&self, key: &TokenKey) {
        if self.entries.remove(key).is_some() {
            self.release_slot();
        }
    }

    fn release_slot(&self) {
        let _ = self
            .entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }
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
        cache.insert_active(
            "token",
            Arc::new(CachedIntrospection {
                claims: Arc::new(json!({"active": true})),
                expires_at_unix: None,
            }),
            now,
        );
        assert!(matches!(cache.get("token", now), CacheLookup::Active(_)));
        assert!(matches!(
            cache.get("token", now + Duration::from_secs(2)),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn concurrent_inserts_never_exceed_capacity() {
        let cache = Arc::new(IntrospectionCache::new(
            100,
            Duration::from_secs(60),
            Duration::from_secs(60),
            4,
        ));
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let cache = Arc::clone(&cache);
                scope.spawn(move || {
                    for token in 0..100 {
                        cache.insert_negative(
                            &format!("worker-{worker}-token-{token}"),
                            Instant::now(),
                        );
                    }
                });
            }
        });
        assert!(cache.len() <= 100);
        assert_eq!(cache.len(), cache.entries.len());
    }
}
