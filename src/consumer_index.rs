use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::Consumer;

/// Pre-indexed consumer lookup for O(1) credential matching on the hot path.
///
/// Built once at config load time and atomically swapped on config changes
/// via ArcSwap — reads are lock-free.
pub struct ConsumerIndex {
    /// Credential-keyed index: "keyauth:{api_key}" or "basic:{username}" → Consumer
    index: ArcSwap<HashMap<String, Arc<Consumer>>>,
    /// Full consumer list for plugins that need iteration (jwt_auth, oauth2_auth)
    all_consumers: ArcSwap<Vec<Arc<Consumer>>>,
}

impl ConsumerIndex {
    /// Build a new consumer index from the given consumer list.
    pub fn new(consumers: &[Consumer]) -> Self {
        let (index, all) = Self::build_index(consumers);
        Self {
            index: ArcSwap::new(Arc::new(index)),
            all_consumers: ArcSwap::new(Arc::new(all)),
        }
    }

    /// Atomically rebuild the index when config changes.
    pub fn rebuild(&self, consumers: &[Consumer]) {
        let (index, all) = Self::build_index(consumers);
        self.index.store(Arc::new(index));
        self.all_consumers.store(Arc::new(all));
    }

    /// O(1) lookup by API key (for key_auth plugin).
    pub fn find_by_api_key(&self, api_key: &str) -> Option<Arc<Consumer>> {
        let idx = self.index.load();
        let key = format!("keyauth:{}", api_key);
        idx.get(&key).cloned()
    }

    /// O(1) lookup by username (for basic_auth plugin).
    pub fn find_by_username(&self, username: &str) -> Option<Arc<Consumer>> {
        let idx = self.index.load();
        let key = format!("basic:{}", username);
        idx.get(&key).cloned()
    }

    /// O(1) lookup by username or ID (for jwt_auth/oauth2_auth claim matching).
    pub fn find_by_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        let idx = self.index.load();
        // Try username first, then id
        idx.get(&format!("identity:{}", identity)).cloned()
    }

    /// Returns the full consumer list for plugins that need to iterate
    /// (e.g. jwt_auth trying multiple secrets).
    pub fn consumers(&self) -> Arc<Vec<Arc<Consumer>>> {
        self.all_consumers.load_full()
    }

    /// Number of indexed entries (for testing).
    #[allow(dead_code)]
    pub fn index_len(&self) -> usize {
        self.index.load().len()
    }

    /// Number of consumers (for testing).
    #[allow(dead_code)]
    pub fn consumer_count(&self) -> usize {
        self.all_consumers.load().len()
    }

    fn build_index(consumers: &[Consumer]) -> (HashMap<String, Arc<Consumer>>, Vec<Arc<Consumer>>) {
        let mut index = HashMap::new();
        let mut all = Vec::with_capacity(consumers.len());

        for consumer in consumers {
            let arc_consumer = Arc::new(consumer.clone());
            all.push(Arc::clone(&arc_consumer));

            // Index by API key (keyauth credential)
            if let Some(key_creds) = consumer.credentials.get("keyauth")
                && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
            {
                index.insert(format!("keyauth:{}", key), Arc::clone(&arc_consumer));
            }

            // Index by username (for basic_auth)
            index.insert(
                format!("basic:{}", consumer.username),
                Arc::clone(&arc_consumer),
            );

            // Index by username and id (for jwt/oauth2 claim matching)
            index.insert(
                format!("identity:{}", consumer.username),
                Arc::clone(&arc_consumer),
            );
            index.insert(
                format!("identity:{}", consumer.id),
                Arc::clone(&arc_consumer),
            );
            if let Some(ref custom_id) = consumer.custom_id {
                index.insert(
                    format!("identity:{}", custom_id),
                    Arc::clone(&arc_consumer),
                );
            }
        }

        (index, all)
    }
}
