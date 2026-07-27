use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{error, warn};

use crate::config::types::Consumer;

/// All consumer-index data swapped as a single unit so readers never see a
/// mix of old and new credential mappings (e.g., a new keyauth entry paired
/// with a stale identity index).
pub(crate) struct ConsumerIndexInner {
    /// Separate indexes per credential type — avoids format!() allocation per lookup.
    keyauth_index: HashMap<String, Arc<Consumer>>,
    basic_index: HashMap<String, Arc<Consumer>>,
    identity_index: HashMap<String, Arc<Consumer>>,
    /// Namespace-scoped identity index for HMAC authentication. HMAC secrets
    /// may be reused across namespaces, so the verifier must never resolve a
    /// signed identity through the process-global JWT/JWKS identity map.
    hmac_identity_index: HashMap<String, HashMap<String, Arc<Consumer>>>,
    /// mTLS identity index: maps `mtls_auth.identity` -> Consumer for O(1) cert-based auth.
    mtls_index: HashMap<String, Arc<Consumer>>,
    /// DNS SAN identities use RFC case-insensitive matching. Keys are normalized at reload time.
    mtls_dns_index: HashMap<String, Arc<Consumer>>,
    /// Full consumer list for plugins that need iteration (jwt_auth, jwks_auth).
    /// Wrapped in `Arc` so `consumers()` can return a cheap clone without O(n) Vec cloning.
    all_consumers: Arc<Vec<Arc<Consumer>>>,
    /// Pre-computed credential counts for auth types that share the identity index.
    jwt_credential_count: usize,
    hmac_credential_count: usize,
}

/// Pre-indexed consumer lookup for O(1) credential matching on the hot path.
///
/// Uses separate HashMaps per credential type to avoid `format!()` string
/// allocation on every lookup. Built once at config load time and atomically
/// swapped on config changes via a single `ArcSwap` — reads are lock-free
/// and always see a consistent generation across all credential types.
pub struct ConsumerIndex {
    inner: ConsumerIndexStorage,
}

enum ConsumerIndexStorage {
    Shared(ArcSwap<ConsumerIndexInner>),
    Snapshot(Arc<ConsumerIndexInner>),
}

struct IndexMaps {
    keyauth: HashMap<String, Arc<Consumer>>,
    basic: HashMap<String, Arc<Consumer>>,
    identity: HashMap<String, Arc<Consumer>>,
    hmac_identity: HashMap<String, HashMap<String, Arc<Consumer>>>,
    mtls: HashMap<String, Arc<Consumer>>,
    mtls_dns: HashMap<String, Arc<Consumer>>,
    all: Vec<Arc<Consumer>>,
    jwt_count: usize,
    hmac_count: usize,
}

impl ConsumerIndex {
    /// Build a new consumer index from the given consumer list.
    pub fn new(consumers: &[Consumer]) -> Self {
        let maps = Self::build_index(consumers);
        Self {
            inner: ConsumerIndexStorage::Shared(ArcSwap::new(Arc::new(
                ConsumerIndexInner::from_maps(maps),
            ))),
        }
    }

    /// Build a lightweight facade over an already-published consumer snapshot.
    ///
    /// This avoids constructing an ArcSwap-backed wrapper on request paths that
    /// already loaded a RequestEpoch.
    pub(crate) fn from_inner(inner: Arc<ConsumerIndexInner>) -> Self {
        Self {
            inner: ConsumerIndexStorage::Snapshot(inner),
        }
    }

    pub(crate) fn build_inner(consumers: &[Consumer]) -> Arc<ConsumerIndexInner> {
        Arc::new(ConsumerIndexInner::from_maps(Self::build_index(consumers)))
    }

    pub(crate) fn store_inner(&self, inner: Arc<ConsumerIndexInner>) {
        match &self.inner {
            ConsumerIndexStorage::Shared(shared) => shared.store(inner),
            ConsumerIndexStorage::Snapshot(_) => {
                debug_assert!(
                    false,
                    "attempted to mutate a snapshot-backed ConsumerIndex facade"
                );
                error!("attempted to mutate a snapshot-backed ConsumerIndex facade");
            }
        }
    }

    pub(crate) fn load_inner(&self) -> Arc<ConsumerIndexInner> {
        match &self.inner {
            ConsumerIndexStorage::Shared(shared) => shared.load_full(),
            ConsumerIndexStorage::Snapshot(inner) => Arc::clone(inner),
        }
    }

    fn with_inner<R>(&self, f: impl FnOnce(&ConsumerIndexInner) -> R) -> R {
        match &self.inner {
            ConsumerIndexStorage::Shared(shared) => {
                let inner = shared.load();
                f(&inner)
            }
            ConsumerIndexStorage::Snapshot(inner) => f(inner),
        }
    }

    /// Atomically rebuild the index when config changes.
    pub fn rebuild(&self, consumers: &[Consumer]) {
        self.store_inner(Self::build_inner(consumers));
    }

    /// O(1) lookup by API key (for key_auth plugin). No allocation.
    pub fn find_by_api_key(&self, api_key: &str) -> Option<Arc<Consumer>> {
        self.with_inner(|inner| inner.find_by_api_key(api_key))
    }

    /// O(1) lookup by username (for basic_auth plugin). No allocation.
    pub fn find_by_username(&self, username: &str) -> Option<Arc<Consumer>> {
        self.with_inner(|inner| inner.find_by_username(username))
    }

    /// O(1) lookup by username or ID (for jwt_auth/jwks_auth claim matching). No allocation.
    pub fn find_by_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        self.with_inner(|inner| inner.find_by_identity(identity))
    }

    /// O(1) namespace-scoped HMAC lookup by Consumer username, ID, or custom ID.
    /// No composite-key allocation occurs on the request path.
    pub fn find_hmac_by_identity(&self, namespace: &str, identity: &str) -> Option<Arc<Consumer>> {
        self.with_inner(|inner| inner.find_hmac_by_identity(namespace, identity))
    }

    /// O(1) lookup by mTLS identity (for mtls_auth plugin). No allocation.
    pub fn find_by_mtls_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        self.with_inner(|inner| inner.find_by_mtls_identity(identity))
    }

    /// O(1) lookup by an already-lowercased DNS SAN identity. No allocation.
    pub fn find_by_mtls_dns_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        self.with_inner(|inner| inner.find_by_mtls_dns_identity(identity))
    }

    /// Returns the full consumer list for custom plugins that need to iterate.
    ///
    /// Returns `Arc<Vec<…>>` — cheap pointer clone, no O(n) Vec copy.
    pub fn consumers(&self) -> Arc<Vec<Arc<Consumer>>> {
        self.with_inner(|inner| inner.consumers())
    }

    /// Incrementally update the consumer index by applying only the changes.
    ///
    /// Uses O(1) HashMap removal by pre-indexing old credential keys instead of
    /// O(n) `.retain()` loops per consumer. This keeps delta application fast even
    /// at 100k+ consumers with thousands of modifications per reload.
    pub fn apply_delta(
        &self,
        added: &[Consumer],
        removed_ids: &[crate::config::db_backend::NamespacedResourceId],
        modified: &[Consumer],
    ) {
        if added.is_empty() && removed_ids.is_empty() && modified.is_empty() {
            return;
        }

        // Load the current snapshot and clone its fields for patching
        let current = match &self.inner {
            ConsumerIndexStorage::Shared(shared) => shared.load_full(),
            ConsumerIndexStorage::Snapshot(inner) => Arc::clone(inner),
        };
        let mut keyauth = current.keyauth_index.clone();
        let mut basic = current.basic_index.clone();
        let mut identity = current.identity_index.clone();
        let mut hmac_identity = current.hmac_identity_index.clone();
        let mut mtls = current.mtls_index.clone();
        let mut mtls_dns = current.mtls_dns_index.clone();
        let mut all: Vec<Arc<Consumer>> = current.all_consumers.as_ref().clone();

        // Collect all identities that need removal (deleted + modified consumers being re-inserted)
        let ids_to_remove: HashSet<(&str, &str)> = removed_ids
            .iter()
            .map(|key| key.as_key())
            .chain(
                modified
                    .iter()
                    .map(|c| (c.namespace.as_str(), c.id.as_str())),
            )
            .collect();

        // Track jwt/hmac credential count delta incrementally instead of
        // recomputing from the full consumer list (which would be O(n_total)).
        let mut jwt_delta: isize = 0;
        let mut hmac_delta: isize = 0;

        if !ids_to_remove.is_empty() {
            // Build a reverse index: consumer_id -> old credential keys, so we can
            // do O(1) HashMap::remove instead of O(n) retain loops.
            // Scan the all-consumers list once to find old entries for removed/modified IDs.
            let mut old_keyauth_keys: Vec<String> = Vec::new();
            let mut old_basic_keys: Vec<String> = Vec::new();
            let mut old_identity_keys: Vec<String> = Vec::new();
            let mut old_hmac_identity_keys: Vec<(String, String)> = Vec::new();
            let mut old_mtls_keys: Vec<String> = Vec::new();
            let mut old_mtls_dns_keys: Vec<String> = Vec::new();

            for consumer in all.iter() {
                if !ids_to_remove.contains(&(consumer.namespace.as_str(), consumer.id.as_str())) {
                    continue;
                }
                // Subtract old jwt/hmac counts for removed/modified consumers
                jwt_delta -= consumer.credential_entries("jwt").len() as isize;
                hmac_delta -= consumer.credential_entries("hmac_auth").len() as isize;
                // Collect old keyauth credential keys (supports array)
                for key_creds in consumer.credential_entries("keyauth") {
                    if let Some(key) = key_creds.get("key").and_then(|s| s.as_str()) {
                        old_keyauth_keys.push(key.to_string());
                    }
                }
                // Collect old basicauth username
                if consumer.has_credential("basicauth") {
                    old_basic_keys.push(consumer.username.clone());
                }
                // Collect old mtls_auth identities (supports array)
                for mtls_creds in consumer.credential_entries("mtls_auth") {
                    if let Some(id) = mtls_creds.get("identity").and_then(|s| s.as_str()) {
                        old_mtls_keys.push(id.to_string());
                        old_mtls_dns_keys.push(id.to_ascii_lowercase());
                    }
                }
                // Collect old identity keys (username, id, custom_id)
                old_identity_keys.push(consumer.username.clone());
                old_identity_keys.push(consumer.id.clone());
                if let Some(ref custom_id) = consumer.custom_id {
                    old_identity_keys.push(custom_id.clone());
                }
                if !consumer.credential_entries("hmac_auth").is_empty() {
                    old_hmac_identity_keys
                        .push((consumer.namespace.clone(), consumer.username.clone()));
                    old_hmac_identity_keys.push((consumer.namespace.clone(), consumer.id.clone()));
                    if let Some(custom_id) = consumer.custom_id.as_ref() {
                        old_hmac_identity_keys
                            .push((consumer.namespace.clone(), custom_id.clone()));
                    }
                }
            }

            // O(1) removals from credential indexes using collected keys
            for key in &old_keyauth_keys {
                // Only remove if the entry actually belongs to a consumer being removed
                if let Some(existing) = keyauth.get(key)
                    && ids_to_remove.contains(&(existing.namespace.as_str(), existing.id.as_str()))
                {
                    keyauth.remove(key);
                }
            }
            for key in &old_basic_keys {
                if let Some(existing) = basic.get(key)
                    && ids_to_remove.contains(&(existing.namespace.as_str(), existing.id.as_str()))
                {
                    basic.remove(key);
                }
            }
            for key in &old_identity_keys {
                if let Some(existing) = identity.get(key)
                    && ids_to_remove.contains(&(existing.namespace.as_str(), existing.id.as_str()))
                {
                    identity.remove(key);
                }
            }
            for (namespace, key) in &old_hmac_identity_keys {
                if let Some(namespace_index) = hmac_identity.get_mut(namespace)
                    && let Some(existing) = namespace_index.get(key)
                    && ids_to_remove.contains(&(existing.namespace.as_str(), existing.id.as_str()))
                {
                    namespace_index.remove(key);
                }
            }
            hmac_identity.retain(|_, namespace_index| !namespace_index.is_empty());
            for key in &old_mtls_keys {
                if let Some(existing) = mtls.get(key)
                    && ids_to_remove.contains(&(existing.namespace.as_str(), existing.id.as_str()))
                {
                    mtls.remove(key);
                }
            }
            for key in &old_mtls_dns_keys {
                if let Some(existing) = mtls_dns.get(key)
                    && ids_to_remove.contains(&(existing.namespace.as_str(), existing.id.as_str()))
                {
                    mtls_dns.remove(key);
                }
            }

            // Remove from all-consumers list (single pass with HashSet lookup)
            all.retain(|c| !ids_to_remove.contains(&(c.namespace.as_str(), c.id.as_str())));

            Self::restore_shadowed_entries(
                &all,
                &mut keyauth,
                &mut basic,
                &mut identity,
                &mut hmac_identity,
                &mut mtls,
                &mut mtls_dns,
                &old_keyauth_keys,
                &old_basic_keys,
                &old_identity_keys,
                &old_hmac_identity_keys,
                &old_mtls_keys,
                &old_mtls_dns_keys,
            );
        }

        // Insert added and modified consumers
        for consumer in added.iter().chain(modified.iter()) {
            let arc_consumer = Arc::new(consumer.clone());

            all.push(Arc::clone(&arc_consumer));

            // Add new jwt/hmac counts for added/modified consumers
            jwt_delta += consumer.credential_entries("jwt").len() as isize;
            hmac_delta += consumer.credential_entries("hmac_auth").len() as isize;

            // Index all keyauth keys (supports array)
            for key_creds in consumer.credential_entries("keyauth") {
                if let Some(key) = key_creds.get("key").and_then(|s| s.as_str()) {
                    keyauth.insert(key.to_string(), Arc::clone(&arc_consumer));
                }
            }

            // Index by username only if consumer has basic_auth credentials
            if consumer.has_credential("basicauth") {
                basic.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            }
            // Index all mTLS identities (supports array)
            for mtls_creds in consumer.credential_entries("mtls_auth") {
                if let Some(id) = mtls_creds.get("identity").and_then(|s| s.as_str()) {
                    mtls.insert(id.to_string(), Arc::clone(&arc_consumer));
                    mtls_dns.insert(id.to_ascii_lowercase(), Arc::clone(&arc_consumer));
                }
            }
            identity.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
            identity.insert(consumer.id.clone(), Arc::clone(&arc_consumer));
            if let Some(ref custom_id) = consumer.custom_id {
                identity.insert(custom_id.clone(), Arc::clone(&arc_consumer));
            }
            Self::insert_hmac_identities(&mut hmac_identity, &arc_consumer);
        }

        // Apply jwt/hmac credential count deltas
        let jwt_count = (current.jwt_credential_count as isize + jwt_delta).max(0) as usize;
        let hmac_count = (current.hmac_credential_count as isize + hmac_delta).max(0) as usize;

        // Single atomic swap — readers see old or new, never a partial state.
        self.store_inner(Arc::new(ConsumerIndexInner {
            keyauth_index: keyauth,
            basic_index: basic,
            identity_index: identity,
            hmac_identity_index: hmac_identity,
            mtls_index: mtls,
            mtls_dns_index: mtls_dns,
            all_consumers: Arc::new(all),
            jwt_credential_count: jwt_count,
            hmac_credential_count: hmac_count,
        }));
    }

    /// Number of indexed entries (for testing).
    pub fn index_len(&self) -> usize {
        self.with_inner(|inner| {
            inner.keyauth_index.len()
                + inner.basic_index.len()
                + inner.identity_index.len()
                + inner.mtls_index.len()
        })
    }

    /// Number of consumers (for testing).
    pub fn consumer_count(&self) -> usize {
        self.with_inner(|inner| inner.all_consumers.len())
    }

    /// Per-auth-type credential counts for metrics.
    ///
    /// Returns (keyauth, basic, mtls, jwt, hmac, identity, total_consumers).
    /// - keyauth/basic/mtls: index entry counts (O(1) lookup targets)
    /// - jwt/hmac: credential entry counts (consumers with those credential types)
    /// - identity: shared identity index size (serves jwt, jwks, hmac, ldap lookups)
    /// - total_consumers: total consumer count
    pub fn auth_type_counts(&self) -> (usize, usize, usize, usize, usize, usize, usize) {
        self.with_inner(|inner| inner.auth_type_counts())
    }

    fn build_index(consumers: &[Consumer]) -> IndexMaps {
        let mut keyauth = HashMap::with_capacity(consumers.len());
        let mut basic = HashMap::with_capacity(consumers.len());
        let mut mtls = HashMap::with_capacity(consumers.len());
        let mut mtls_dns = HashMap::with_capacity(consumers.len());
        // identity has up to 3 entries per consumer (username, id, custom_id)
        let mut identity = HashMap::with_capacity(consumers.len() * 3);
        let mut hmac_identity = HashMap::new();
        let mut all = Vec::with_capacity(consumers.len());
        let mut jwt_count: usize = 0;
        let mut hmac_count: usize = 0;

        for consumer in consumers {
            let arc_consumer = Arc::new(consumer.clone());
            all.push(Arc::clone(&arc_consumer));

            // Count JWT and HMAC credential entries for metrics
            jwt_count += consumer.credential_entries("jwt").len();
            hmac_count += consumer.credential_entries("hmac_auth").len();

            // Index by API key (keyauth credentials).
            for key_creds in consumer.credential_entries("keyauth") {
                if let Some(key) = key_creds.get("key").and_then(|s| s.as_str()) {
                    let prev = keyauth.insert(key.to_string(), Arc::clone(&arc_consumer));
                    if let Some(existing) = prev {
                        warn!(
                            "Credential collision: keyauth credential for consumer '{}' overwrites consumer '{}'",
                            consumer.id, existing.id
                        );
                    }
                }
            }

            // Index by username only if consumer has basic_auth credentials
            if consumer.has_credential("basicauth") {
                let prev = basic.insert(consumer.username.clone(), Arc::clone(&arc_consumer));
                if let Some(existing) = prev {
                    warn!(
                        "Credential collision: basicauth username '{}' for consumer '{}' overwrites consumer '{}'",
                        consumer.username, consumer.id, existing.id
                    );
                }
            }

            // Index by mTLS identity (mtls_auth credentials).
            for mtls_creds in consumer.credential_entries("mtls_auth") {
                if let Some(id) = mtls_creds.get("identity").and_then(|s| s.as_str()) {
                    let prev = mtls.insert(id.to_string(), Arc::clone(&arc_consumer));
                    if let Some(existing) = prev {
                        warn!(
                            "Credential collision: mtls_auth identity '{}' for consumer '{}' overwrites consumer '{}'",
                            id, consumer.id, existing.id
                        );
                    }
                    let normalized = id.to_ascii_lowercase();
                    let prev = mtls_dns.insert(normalized, Arc::clone(&arc_consumer));
                    if let Some(existing) = prev
                        && existing.id != consumer.id
                    {
                        warn!(
                            "Credential collision: case-insensitive mtls_auth DNS identity '{}' for consumer '{}' overwrites consumer '{}'",
                            id, consumer.id, existing.id
                        );
                    }
                }
            }

            // Index by username and id (for jwt/jwks claim matching)
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
                         This will cause incorrect JWKS/JWT authentication. \
                         Ensure custom_id values are unique across all consumers.",
                        custom_id, consumer.id, existing.id
                    );
                }
            }
            Self::insert_hmac_identities(&mut hmac_identity, &arc_consumer);
        }

        IndexMaps {
            keyauth,
            basic,
            identity,
            hmac_identity,
            mtls,
            mtls_dns,
            all,
            jwt_count,
            hmac_count,
        }
    }

    fn insert_hmac_identities(
        index: &mut HashMap<String, HashMap<String, Arc<Consumer>>>,
        consumer: &Arc<Consumer>,
    ) {
        if consumer.credential_entries("hmac_auth").is_empty() {
            return;
        }
        let namespace_index = index.entry(consumer.namespace.clone()).or_default();
        for identity in std::iter::once(consumer.username.as_str())
            .chain(std::iter::once(consumer.id.as_str()))
            .chain(consumer.custom_id.as_deref())
        {
            let previous = namespace_index.insert(identity.to_string(), Arc::clone(consumer));
            if let Some(existing) = previous
                && existing.id != consumer.id
            {
                warn!(
                    "Credential collision: hmac_auth identity '{}' for consumer '{}' overwrites consumer '{}' in namespace '{}'",
                    identity, consumer.id, existing.id, consumer.namespace
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_shadowed_entries(
        all: &[Arc<Consumer>],
        keyauth: &mut HashMap<String, Arc<Consumer>>,
        basic: &mut HashMap<String, Arc<Consumer>>,
        identity: &mut HashMap<String, Arc<Consumer>>,
        hmac_identity: &mut HashMap<String, HashMap<String, Arc<Consumer>>>,
        mtls: &mut HashMap<String, Arc<Consumer>>,
        mtls_dns: &mut HashMap<String, Arc<Consumer>>,
        keyauth_keys: &[String],
        basic_keys: &[String],
        identity_keys: &[String],
        hmac_identity_keys: &[(String, String)],
        mtls_keys: &[String],
        mtls_dns_keys: &[String],
    ) {
        let keyauth_keys: HashSet<&str> = keyauth_keys.iter().map(String::as_str).collect();
        let basic_keys: HashSet<&str> = basic_keys.iter().map(String::as_str).collect();
        let identity_keys: HashSet<&str> = identity_keys.iter().map(String::as_str).collect();
        let hmac_identity_keys: HashSet<(&str, &str)> = hmac_identity_keys
            .iter()
            .map(|(namespace, identity)| (namespace.as_str(), identity.as_str()))
            .collect();
        let mtls_keys: HashSet<&str> = mtls_keys.iter().map(String::as_str).collect();
        let mtls_dns_keys: HashSet<&str> = mtls_dns_keys.iter().map(String::as_str).collect();

        if keyauth_keys.is_empty()
            && basic_keys.is_empty()
            && identity_keys.is_empty()
            && hmac_identity_keys.is_empty()
            && mtls_keys.is_empty()
            && mtls_dns_keys.is_empty()
        {
            return;
        }

        for consumer in all {
            for key_creds in consumer.credential_entries("keyauth") {
                if let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
                    && keyauth_keys.contains(key)
                {
                    keyauth.insert(key.to_string(), Arc::clone(consumer));
                }
            }

            if consumer.has_credential("basicauth")
                && basic_keys.contains(consumer.username.as_str())
            {
                basic.insert(consumer.username.clone(), Arc::clone(consumer));
            }

            if identity_keys.contains(consumer.username.as_str()) {
                identity.insert(consumer.username.clone(), Arc::clone(consumer));
            }
            if identity_keys.contains(consumer.id.as_str()) {
                identity.insert(consumer.id.clone(), Arc::clone(consumer));
            }
            if let Some(custom_id) = consumer.custom_id.as_ref()
                && identity_keys.contains(custom_id.as_str())
            {
                identity.insert(custom_id.clone(), Arc::clone(consumer));
            }

            if !consumer.credential_entries("hmac_auth").is_empty() {
                for hmac_identity_value in std::iter::once(consumer.username.as_str())
                    .chain(std::iter::once(consumer.id.as_str()))
                    .chain(consumer.custom_id.as_deref())
                {
                    if hmac_identity_keys
                        .contains(&(consumer.namespace.as_str(), hmac_identity_value))
                    {
                        hmac_identity
                            .entry(consumer.namespace.clone())
                            .or_default()
                            .insert(hmac_identity_value.to_string(), Arc::clone(consumer));
                    }
                }
            }

            for mtls_creds in consumer.credential_entries("mtls_auth") {
                if let Some(id) = mtls_creds.get("identity").and_then(|s| s.as_str()) {
                    if mtls_keys.contains(id) {
                        mtls.insert(id.to_string(), Arc::clone(consumer));
                    }
                    let normalized = id.to_ascii_lowercase();
                    if mtls_dns_keys.contains(normalized.as_str()) {
                        mtls_dns.insert(normalized, Arc::clone(consumer));
                    }
                }
            }
        }
    }
}

impl ConsumerIndexInner {
    fn from_maps(maps: IndexMaps) -> Self {
        Self {
            keyauth_index: maps.keyauth,
            basic_index: maps.basic,
            identity_index: maps.identity,
            hmac_identity_index: maps.hmac_identity,
            mtls_index: maps.mtls,
            mtls_dns_index: maps.mtls_dns,
            all_consumers: Arc::new(maps.all),
            jwt_credential_count: maps.jwt_count,
            hmac_credential_count: maps.hmac_count,
        }
    }

    /// O(1) lookup by API key (for key_auth plugin). No allocation.
    pub fn find_by_api_key(&self, api_key: &str) -> Option<Arc<Consumer>> {
        self.keyauth_index.get(api_key).cloned()
    }

    /// O(1) lookup by username (for basic_auth plugin). No allocation.
    pub fn find_by_username(&self, username: &str) -> Option<Arc<Consumer>> {
        self.basic_index.get(username).cloned()
    }

    /// O(1) lookup by username or ID (for jwt_auth/jwks_auth claim matching). No allocation.
    pub fn find_by_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        self.identity_index.get(identity).cloned()
    }

    pub fn find_hmac_by_identity(&self, namespace: &str, identity: &str) -> Option<Arc<Consumer>> {
        self.hmac_identity_index
            .get(namespace)
            .and_then(|namespace_index| namespace_index.get(identity))
            .cloned()
    }

    /// O(1) lookup by mTLS identity (for mtls_auth plugin). No allocation.
    pub fn find_by_mtls_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        self.mtls_index.get(identity).cloned()
    }

    /// O(1) lookup by an already-lowercased DNS SAN identity. No allocation.
    pub fn find_by_mtls_dns_identity(&self, identity: &str) -> Option<Arc<Consumer>> {
        self.mtls_dns_index.get(identity).cloned()
    }

    pub fn consumers(&self) -> Arc<Vec<Arc<Consumer>>> {
        Arc::clone(&self.all_consumers)
    }

    pub fn auth_type_counts(&self) -> (usize, usize, usize, usize, usize, usize, usize) {
        (
            self.keyauth_index.len(),
            self.basic_index.len(),
            self.mtls_index.len(),
            self.jwt_credential_count,
            self.hmac_credential_count,
            self.identity_index.len(),
            self.all_consumers.len(),
        )
    }
}
