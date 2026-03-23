use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, warn};

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
    /// Uses O(1) HashMap removal by pre-indexing old credential keys instead of
    /// O(n) `.retain()` loops per consumer. This keeps delta application fast even
    /// at 100k+ consumers with thousands of modifications per reload.
    pub fn apply_delta(&self, added: &[Consumer], removed_ids: &[String], modified: &[Consumer]) {
        if added.is_empty() && removed_ids.is_empty() && modified.is_empty() {
            return;
        }

        // Clone current state for patching
        let mut keyauth = self.keyauth_index.load().as_ref().clone();
        let mut basic = self.basic_index.load().as_ref().clone();
        let mut identity = self.identity_index.load().as_ref().clone();
        let mut all: Vec<Arc<Consumer>> = self.all_consumers.load().as_ref().clone();

        // Collect all IDs that need removal (deleted + modified consumers being re-inserted)
        let ids_to_remove: std::collections::HashSet<&str> = removed_ids
            .iter()
            .map(|s| s.as_str())
            .chain(modified.iter().map(|c| c.id.as_str()))
            .collect();

        if !ids_to_remove.is_empty() {
            // Build a reverse index: consumer_id → old credential keys, so we can
            // do O(1) HashMap::remove instead of O(n) retain loops.
            // Scan the all-consumers list once to find old entries for removed/modified IDs.
            let mut old_keyauth_keys: Vec<String> = Vec::new();
            let mut old_basic_keys: Vec<String> = Vec::new();
            let mut old_identity_keys: Vec<String> = Vec::new();

            for consumer in all.iter() {
                if !ids_to_remove.contains(consumer.id.as_str()) {
                    continue;
                }
                // Collect old keyauth credential key
                if let Some(key_creds) = consumer.credentials.get("keyauth")
                    && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
                {
                    old_keyauth_keys.push(key.to_string());
                }
                // Collect old basicauth username
                if consumer.credentials.contains_key("basicauth") {
                    old_basic_keys.push(consumer.username.clone());
                }
                // Collect old identity keys (username, id, custom_id)
                old_identity_keys.push(consumer.username.clone());
                old_identity_keys.push(consumer.id.clone());
                if let Some(ref custom_id) = consumer.custom_id {
                    old_identity_keys.push(custom_id.clone());
                }
            }

            // O(1) removals from credential indexes using collected keys
            for key in &old_keyauth_keys {
                // Only remove if the entry actually belongs to a consumer being removed
                if let Some(existing) = keyauth.get(key)
                    && ids_to_remove.contains(existing.id.as_str())
                {
                    keyauth.remove(key);
                }
            }
            for key in &old_basic_keys {
                if let Some(existing) = basic.get(key)
                    && ids_to_remove.contains(existing.id.as_str())
                {
                    basic.remove(key);
                }
            }
            for key in &old_identity_keys {
                if let Some(existing) = identity.get(key)
                    && ids_to_remove.contains(existing.id.as_str())
                {
                    identity.remove(key);
                }
            }

            // Remove from all-consumers list (single pass with HashSet lookup)
            all.retain(|c| !ids_to_remove.contains(c.id.as_str()));
        }

        // Insert added and modified consumers
        for consumer in added.iter().chain(modified.iter()) {
            let arc_consumer = Arc::new(consumer.clone());

            all.push(Arc::clone(&arc_consumer));

            if let Some(key_creds) = consumer.credentials.get("keyauth")
                && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
            {
                keyauth.insert(key.to_string(), Arc::clone(&arc_consumer));
            }

            // Index by username only if consumer has basic_auth credentials
            if consumer.credentials.contains_key("basicauth") {
                basic.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            }
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
                let prev = keyauth.insert(key.to_string(), Arc::clone(&arc_consumer));
                if let Some(existing) = prev {
                    warn!(
                        "Credential collision: keyauth key '{}' for consumer '{}' overwrites consumer '{}'",
                        key, consumer.id, existing.id
                    );
                }
            }

            // Index by username only if consumer has basic_auth credentials
            if consumer.credentials.contains_key("basicauth") {
                let prev = basic.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
                if let Some(existing) = prev {
                    warn!(
                        "Credential collision: basicauth username '{}' for consumer '{}' overwrites consumer '{}'",
                        consumer.username, consumer.id, existing.id
                    );
                }
            }

            // Index by username and id (for jwt/oauth2 claim matching)
            let prev = identity.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            if let Some(existing) = prev {
                warn!(
                    "Credential collision: identity '{}' for consumer '{}' overwrites consumer '{}'",
                    consumer.username, consumer.id, existing.id
                );
            }
            identity.insert(consumer.id.clone(), Arc::clone(&arc_consumer));
            if let Some(ref custom_id) = consumer.custom_id {
                let prev = identity.insert(custom_id.clone(), Arc::clone(&arc_consumer));
                if let Some(existing) = prev
                    && existing.id != consumer.id
                {
                    error!(
                        "IDENTITY COLLISION: custom_id '{}' for consumer '{}' overwrites consumer '{}'. \
                         This will cause incorrect OAuth2/JWT authentication. \
                         Ensure custom_id values are unique across all consumers.",
                        custom_id, consumer.id, existing.id
                    );
                }
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
