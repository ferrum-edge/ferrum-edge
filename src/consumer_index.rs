use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::Consumer;

/// Pre-indexed consumer lookup for O(1) credential matching on the hot path.
///
/// Uses separate HashMaps per credential type to avoid `format!()` string
/// allocation on every lookup. Built once at config load time and atomically
/// swapped on config changes via ArcSwap — reads are lock-free.
pub struct ConsumerIndex {
    /// Separate indexes per credential type — avoids format!() allocation per lookup.
    keyauth_index: ArcSwap<HashMap<String, Arc<Consumer>>>,
    basic_index: ArcSwap<HashMap<String, Arc<Consumer>>>,
    identity_index: ArcSwap<HashMap<String, Arc<Consumer>>>,
    /// Full consumer list for plugins that need iteration (jwt_auth, oauth2_auth)
    all_consumers: ArcSwap<Vec<Arc<Consumer>>>,
}

struct IndexMaps {
    keyauth: HashMap<String, Arc<Consumer>>,
    basic: HashMap<String, Arc<Consumer>>,
    identity: HashMap<String, Arc<Consumer>>,
    all: Vec<Arc<Consumer>>,
}

impl ConsumerIndex {
    /// Build a new consumer index from the given consumer list.
    pub fn new(consumers: &[Consumer]) -> Self {
        let maps = Self::build_index(consumers);
        Self {
            keyauth_index: ArcSwap::new(Arc::new(maps.keyauth)),
            basic_index: ArcSwap::new(Arc::new(maps.basic)),
            identity_index: ArcSwap::new(Arc::new(maps.identity)),
            all_consumers: ArcSwap::new(Arc::new(maps.all)),
        }
    }

    /// Atomically rebuild the index when config changes.
    pub fn rebuild(&self, consumers: &[Consumer]) {
        let maps = Self::build_index(consumers);
        self.keyauth_index.store(Arc::new(maps.keyauth));
        self.basic_index.store(Arc::new(maps.basic));
        self.identity_index.store(Arc::new(maps.identity));
        self.all_consumers.store(Arc::new(maps.all));
    }

    /// O(1) lookup by API key (for key_auth plugin). No allocation.
    pub fn find_by_api_key(&self, api_key: &str) -> Option<Arc<Consumer>> {
        let idx = self.keyauth_index.load();
        idx.get(api_key).cloned()
    }

    /// O(1) lookup by username (for basic_auth plugin). No allocation.
    pub fn find_by_username(&self, username: &str) -> Option<Arc<Consumer>> {
        let idx = self.basic_index.load();
        idx.get(username).cloned()
    }

    /// O(1) lookup by username or ID (for jwt_auth/oauth2_auth claim matching). No allocation.
    pub fn find_by_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        let idx = self.identity_index.load();
        idx.get(identity).cloned()
    }

    /// Returns the full consumer list for plugins that need to iterate
    /// (e.g. jwt_auth trying multiple secrets).
    pub fn consumers(&self) -> Arc<Vec<Arc<Consumer>>> {
        self.all_consumers.load_full()
    }

    /// Incrementally update the consumer index by applying only the changes.
    ///
    /// Clones the current maps, removes deleted consumers' index entries,
    /// and inserts/overwrites added or modified consumers. Untouched
    /// consumers keep their existing Arc references — no reallocation.
    pub fn apply_delta(&self, added: &[Consumer], removed_ids: &[String], modified: &[Consumer]) {
        if added.is_empty() && removed_ids.is_empty() && modified.is_empty() {
            return;
        }

        // Clone current state for patching
        let mut keyauth = self.keyauth_index.load().as_ref().clone();
        let mut basic = self.basic_index.load().as_ref().clone();
        let mut identity = self.identity_index.load().as_ref().clone();
        let mut all: Vec<Arc<Consumer>> = self.all_consumers.load().as_ref().clone();

        // Remove deleted consumers from all indexes
        if !removed_ids.is_empty() {
            let removed_set: std::collections::HashSet<&str> =
                removed_ids.iter().map(|s| s.as_str()).collect();

            // Remove from all-consumers list
            all.retain(|c| !removed_set.contains(c.id.as_str()));

            // Remove from credential indexes (need to find their keys)
            keyauth.retain(|_, c| !removed_set.contains(c.id.as_str()));
            basic.retain(|_, c| !removed_set.contains(c.id.as_str()));
            identity.retain(|_, c| !removed_set.contains(c.id.as_str()));
        }

        // Upsert added and modified consumers
        for consumer in added.iter().chain(modified.iter()) {
            let arc_consumer = Arc::new(consumer.clone());

            // For modified: remove old entries first (username/custom_id may have changed)
            all.retain(|c| c.id != consumer.id);
            keyauth.retain(|_, c| c.id != consumer.id);
            basic.retain(|_, c| c.id != consumer.id);
            identity.retain(|_, c| c.id != consumer.id);

            // Insert new entries
            all.push(Arc::clone(&arc_consumer));

            if let Some(key_creds) = consumer.credentials.get("keyauth")
                && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
            {
                keyauth.insert(key.to_string(), Arc::clone(&arc_consumer));
            }

            basic.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            identity.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            identity.insert(consumer.id.clone(), Arc::clone(&arc_consumer));
            if let Some(ref custom_id) = consumer.custom_id {
                identity.insert(custom_id.clone(), Arc::clone(&arc_consumer));
            }
        }

        // Atomic swap all indexes
        self.keyauth_index.store(Arc::new(keyauth));
        self.basic_index.store(Arc::new(basic));
        self.identity_index.store(Arc::new(identity));
        self.all_consumers.store(Arc::new(all));
    }

    /// Number of indexed entries (for testing).
    #[allow(dead_code)]
    pub fn index_len(&self) -> usize {
        self.keyauth_index.load().len()
            + self.basic_index.load().len()
            + self.identity_index.load().len()
    }

    /// Number of consumers (for testing).
    #[allow(dead_code)]
    pub fn consumer_count(&self) -> usize {
        self.all_consumers.load().len()
    }

    fn build_index(consumers: &[Consumer]) -> IndexMaps {
        let mut keyauth = HashMap::with_capacity(consumers.len());
        let mut basic = HashMap::with_capacity(consumers.len());
        // identity has up to 3 entries per consumer (username, id, custom_id)
        let mut identity = HashMap::with_capacity(consumers.len() * 3);
        let mut all = Vec::with_capacity(consumers.len());

        for consumer in consumers {
            let arc_consumer = Arc::new(consumer.clone());
            all.push(Arc::clone(&arc_consumer));

            // Index by API key (keyauth credential)
            if let Some(key_creds) = consumer.credentials.get("keyauth")
                && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
            {
                keyauth.insert(key.to_string(), Arc::clone(&arc_consumer));
            }

            // Index by username (for basic_auth)
            basic.insert(consumer.username.clone(), Arc::clone(&arc_consumer));

            // Index by username and id (for jwt/oauth2 claim matching)
            identity.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            identity.insert(consumer.id.clone(), Arc::clone(&arc_consumer));
            if let Some(ref custom_id) = consumer.custom_id {
                identity.insert(custom_id.clone(), Arc::clone(&arc_consumer));
            }
        }

        IndexMaps {
            keyauth,
            basic,
            identity,
            all,
        }
    }
}
