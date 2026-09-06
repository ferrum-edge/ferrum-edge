use std::cmp::Ordering as CmpOrdering;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kube::api::DynamicObject;
use kube::runtime::reflector;
use tokio::sync::watch;

use crate::config_sources::k8s::K8sObject;
use crate::k8s_controller::convert::dynamic_object_to_k8s_object;

pub struct CrdResourceStore {
    pub api_version: String,
    pub kind: String,
    pub scope: String,
    store: reflector::Store<DynamicObject>,
}

impl CrdResourceStore {
    pub fn new(api_version: String, kind: String, store: reflector::Store<DynamicObject>) -> Self {
        Self::new_scoped(api_version, kind, "all".to_string(), store)
    }

    pub fn new_scoped(
        api_version: String,
        kind: String,
        scope: String,
        store: reflector::Store<DynamicObject>,
    ) -> Self {
        Self {
            api_version,
            kind,
            scope,
            store,
        }
    }

    pub fn snapshot(&self) -> Vec<K8sObject> {
        self.store
            .state()
            .iter()
            .map(|obj| dynamic_object_to_k8s_object(obj.as_ref(), &self.api_version, &self.kind))
            .collect()
    }

    /// `(namespace, name)` of every object in the store — an empty namespace
    /// for cluster-scoped objects — read without converting the objects, so a
    /// relist divergence check stays cheap on large scopes (issue #4491).
    pub fn object_identities(&self) -> Vec<(String, String)> {
        self.store
            .state()
            .iter()
            .map(|object| {
                (
                    object.metadata.namespace.clone().unwrap_or_default(),
                    object.metadata.name.clone().unwrap_or_default(),
                )
            })
            .collect()
    }

    pub async fn wait_until_ready(&self) -> Result<(), String> {
        self.store.wait_until_ready().await.map_err(|e| {
            format!(
                "{} {} reflector store was dropped before ready: {e}",
                self.api_version, self.kind
            )
        })
    }

    /// Owned-`Arc` variant of `wait_until_ready` so callers can `.await` it
    /// without holding a `&CrdResourceStore` borrow across the suspension
    /// point. Holding such a borrow trips rustc's HRTB Send analysis when
    /// the outer future is `tokio::spawn`-ed (see `reconciler.rs`).
    pub async fn wait_until_ready_owned(self: Arc<Self>) -> Result<(), String> {
        self.wait_until_ready().await
    }

    pub fn len(&self) -> usize {
        self.store.state().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct ResourceStoreSet {
    stores: Vec<Arc<CrdResourceStore>>,
    notifier: ResourceChangeNotifier,
}

#[derive(Clone)]
pub struct ResourceChangeNotifier {
    change_tx: Arc<watch::Sender<u64>>,
    revision: Arc<AtomicU64>,
}

impl ResourceChangeNotifier {
    pub fn notify_change(&self) {
        let rev = self.revision.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.change_tx.send(rev);
    }
}

impl Default for ResourceStoreSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceStoreSet {
    pub fn new() -> Self {
        let (change_tx, _change_rx) = watch::channel(0);
        Self {
            stores: Vec::new(),
            notifier: ResourceChangeNotifier {
                change_tx: Arc::new(change_tx),
                revision: Arc::new(AtomicU64::new(0)),
            },
        }
    }

    pub fn add_store(&mut self, store: Arc<CrdResourceStore>) -> bool {
        if self.has_store_for_scope(&store.api_version, &store.kind, &store.scope) {
            return false;
        }
        self.stores.push(store);
        self.notify_change();
        true
    }

    pub fn remove_store(&mut self, api_version: &str, kind: &str) -> bool {
        let Some(index) = self
            .stores
            .iter()
            .position(|store| store.api_version == api_version && store.kind == kind)
        else {
            return false;
        };

        self.stores.remove(index);
        self.notify_change();
        true
    }

    pub fn remove_store_for_scope(&mut self, api_version: &str, kind: &str, scope: &str) -> bool {
        let Some(index) = self.stores.iter().position(|store| {
            store.api_version == api_version && store.kind == kind && store.scope == scope
        }) else {
            return false;
        };

        self.stores.remove(index);
        self.notify_change();
        true
    }

    /// Swap a fresh reflector store in for the one already registered under the
    /// same `(api_version, kind, scope)` triple, or add it when the old scope was
    /// concurrently deregistered. Does NOT notify subscribers.
    ///
    /// This is the make-before-break half of the idle relist in
    /// [`super::watcher`]: the previous generation's store keeps serving its
    /// last-known-good objects to `snapshot_all` until the replacement has
    /// finished its initial list, so a relist never opens a window in which the
    /// scope contributes zero objects. A gap there would look exactly like a
    /// mass deletion to the reconciler and would broadcast a config wipe.
    ///
    /// Deferring notification is load-bearing for the Kubernetes config
    /// revision tracker (issue #3611): the watcher must commit the replacement
    /// generation's convergence evidence under this same `ResourceStoreSet`
    /// lock and only then wake reconciliation. Otherwise a reconciler can pair
    /// the new store with the old scalar revision and permanently withhold the
    /// changed mesh when the relisted scope is quiet.
    ///
    /// Returns `true` when an existing store was replaced and `false` when the
    /// scope had to be re-added. The caller MUST invoke [`Self::notify_change`]
    /// after committing any state that describes this store and before
    /// releasing its outer lock.
    pub fn replace_or_add_store_for_scope_without_notify(
        &mut self,
        store: Arc<CrdResourceStore>,
    ) -> bool {
        let Some(index) = self.stores.iter().position(|existing| {
            existing.api_version == store.api_version
                && existing.kind == store.kind
                && existing.scope == store.scope
        }) else {
            self.stores.push(store);
            return false;
        };

        self.stores[index] = store;
        true
    }

    pub fn has_store(&self, api_version: &str, kind: &str) -> bool {
        self.stores
            .iter()
            .any(|store| store.api_version == api_version && store.kind == kind)
    }

    pub fn has_store_for_scope(&self, api_version: &str, kind: &str, scope: &str) -> bool {
        self.stores.iter().any(|store| {
            store.api_version == api_version && store.kind == kind && store.scope == scope
        })
    }

    pub fn stores(&self) -> Vec<Arc<CrdResourceStore>> {
        self.stores.clone()
    }

    /// The store currently registered for one `(api_version, kind, scope)`.
    pub fn store_for_scope(
        &self,
        api_version: &str,
        kind: &str,
        scope: &str,
    ) -> Option<Arc<CrdResourceStore>> {
        self.stores
            .iter()
            .find(|store| {
                store.api_version == api_version && store.kind == kind && store.scope == scope
            })
            .cloned()
    }

    /// Identity of every currently registered scope.
    ///
    /// The revision tracker's aggregation set (issue #3611). Callers pin it and
    /// read the watermark under the SAME lock they later call
    /// [`Self::snapshot_all`] under, and in that order: between the two the
    /// stores can only move forward, so the snapshot is never older than the
    /// watermark claims.
    pub fn scope_keys(&self) -> Vec<crate::k8s_controller::revision::K8sWatchScopeKey> {
        self.stores
            .iter()
            .map(|store| {
                crate::k8s_controller::revision::watch_scope_key(
                    &store.api_version,
                    &store.kind,
                    &store.scope,
                )
            })
            .collect()
    }

    /// Every object across every registered store, deduplicated and in a
    /// deterministic order (issue #4491).
    ///
    /// The reconciler translates this list, so it must not depend on anything
    /// incidental: a reflector store iterates a hash map, and a scope whose
    /// stream ended re-registers at the end of the store list. One Kubernetes
    /// object watched under several served API versions (`Gateway` v1 and
    /// v1beta1, `TLSRoute` v1 and v1alpha2) is kept once, under the preferred
    /// served version by Kubernetes version priority
    /// ([`served_version_rank`]: GA, then beta, then alpha, higher numbers
    /// first within a stability) — and the result is ordered by group, kind,
    /// namespace, and name. The same cluster state, including a stale store
    /// that still holds a deleted object, therefore always yields the same
    /// snapshot and the same translation. A deleted object survives here until
    /// EVERY alias scope that held it has relisted, since each scope's store
    /// is retired independently.
    pub fn snapshot_all(&self) -> Vec<K8sObject> {
        let mut chosen: HashMap<ResourceIdentity, K8sObject> = HashMap::new();
        for store in &self.stores {
            for object in store.snapshot() {
                match chosen.entry(resource_identity(&object)) {
                    Entry::Vacant(slot) => {
                        slot.insert(object);
                    }
                    Entry::Occupied(mut slot) => {
                        if served_version_rank(&object.api_version)
                            < served_version_rank(&slot.get().api_version)
                        {
                            slot.insert(object);
                        }
                    }
                }
            }
        }
        let mut objects: Vec<K8sObject> = chosen.into_values().collect();
        objects.sort_by(compare_resource_order);
        objects
    }

    pub fn notify_change(&self) {
        self.notifier.notify_change();
    }

    pub fn change_notifier(&self) -> ResourceChangeNotifier {
        self.notifier.clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.notifier.change_tx.subscribe()
    }

    pub fn total_resources(&self) -> usize {
        self.stores.iter().map(|s| s.len()).sum()
    }
}

/// `(group, kind, namespace, name)`: one Kubernetes object, whichever served
/// API version delivered it.
type ResourceIdentity = (String, String, String, String);

fn resource_identity(object: &K8sObject) -> ResourceIdentity {
    (
        api_group(&object.api_version).to_string(),
        object.kind.clone(),
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
    )
}

fn api_group(api_version: &str) -> &str {
    api_version
        .split_once('/')
        .map_or("", |(group, _version)| group)
}

/// Kubernetes version priority of one `apiVersion`, most preferred first,
/// mirroring `k8s.io/apimachinery`'s `CompareKubeAwareVersionStrings`: GA
/// before beta before alpha before anything not shaped `vN[(alpha|beta)M]`;
/// within one stability the higher `N`, then the higher `M`, comes first; the
/// unrecognized shapes sort last, lexicographically. So `v1` beats `v1beta1`,
/// `v2` beats `v1beta1` (where string order would not), `v1` beats `v2alpha1`,
/// and `v1beta2` beats `v1beta1`. Only the version segment is compared; the
/// caller has already matched group, kind, namespace, and name.
fn served_version_rank(api_version: &str) -> (u8, Reverse<u64>, Reverse<u64>, &str) {
    let version = api_version.rsplit('/').next().unwrap_or(api_version);
    match parse_kube_version(version) {
        Some((stability, major, minor)) => (stability, Reverse(major), Reverse(minor), ""),
        None => (3, Reverse(0), Reverse(0), version),
    }
}

/// `(stability, major, minor)` of a `vN`, `vNbetaM`, or `vNalphaM` version,
/// with stability `0`, `1`, `2` respectively; `None` for anything else,
/// including a missing `M` or a number that does not fit.
fn parse_kube_version(version: &str) -> Option<(u8, u64, u64)> {
    let rest = version.strip_prefix('v')?;
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let (major, rest) = rest.split_at(digits);
    let major: u64 = major.parse().ok()?;
    if rest.is_empty() {
        return Some((0, major, 0));
    }
    let (stability, minor) = match rest.strip_prefix("beta") {
        Some(minor) => (1, minor),
        None => (2, rest.strip_prefix("alpha")?),
    };
    let minor: u64 = minor.parse().ok()?;
    Some((stability, major, minor))
}

/// Deterministic reconcile order: group, kind, namespace, name. Identities are
/// unique after deduplication, so this is a total order over the snapshot.
fn compare_resource_order(left: &K8sObject, right: &K8sObject) -> CmpOrdering {
    api_group(&left.api_version)
        .cmp(api_group(&right.api_version))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.metadata.namespace.cmp(&right.metadata.namespace))
        .then_with(|| left.metadata.name.cmp(&right.metadata.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::{ApiResource, DynamicObject};
    use kube::runtime::watcher::Event;
    use serde_json::json;

    fn test_store(api_version: &str, kind: &str) -> Arc<CrdResourceStore> {
        let ar = ApiResource {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: format!("{}s", kind.to_ascii_lowercase()),
        };
        let writer = reflector::store::Writer::new(ar);
        let store = writer.as_reader();
        Arc::new(CrdResourceStore::new(
            api_version.to_string(),
            kind.to_string(),
            store,
        ))
    }

    fn test_scoped_store(api_version: &str, kind: &str, scope: &str) -> Arc<CrdResourceStore> {
        let ar = ApiResource {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: format!("{}s", kind.to_ascii_lowercase()),
        };
        let writer = reflector::store::Writer::new(ar);
        let store = writer.as_reader();
        Arc::new(CrdResourceStore::new_scoped(
            api_version.to_string(),
            kind.to_string(),
            scope.to_string(),
            store,
        ))
    }

    fn populated_test_store(
        api_version: &str,
        kind: &str,
        name: &str,
        namespace: &str,
    ) -> Arc<CrdResourceStore> {
        let (group, version) = api_version.split_once('/').unwrap_or(("", api_version));
        let ar = ApiResource {
            group: group.to_string(),
            version: version.to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: format!("{}s", kind.to_ascii_lowercase()),
        };
        let mut writer = reflector::store::Writer::new(ar.clone());
        let object = DynamicObject::new(name, &ar)
            .within(namespace)
            .data(json!({ "spec": {} }));
        writer.apply_watcher_event(&Event::Init);
        writer.apply_watcher_event(&Event::InitApply(object));
        writer.apply_watcher_event(&Event::InitDone);
        Arc::new(CrdResourceStore::new_scoped(
            api_version.to_string(),
            kind.to_string(),
            "all".to_string(),
            writer.as_reader(),
        ))
    }

    #[test]
    fn remove_store_deregisters_and_notifies() {
        let mut set = ResourceStoreSet::new();
        let rx = set.subscribe();
        let store = test_store("example.com/v1", "Widget");

        assert!(set.add_store(store));
        assert!(set.has_store("example.com/v1", "Widget"));
        assert_eq!(*rx.borrow(), 1);

        assert!(set.remove_store("example.com/v1", "Widget"));

        assert!(!set.has_store("example.com/v1", "Widget"));
        assert_eq!(*rx.borrow(), 2);
    }

    #[test]
    fn duplicate_detection_is_scope_aware() {
        let mut set = ResourceStoreSet::new();

        assert!(set.add_store(test_scoped_store(
            "example.com/v1",
            "Widget",
            "namespace:default",
        )));
        assert!(set.add_store(test_scoped_store(
            "example.com/v1",
            "Widget",
            "namespace:prod",
        )));
        assert!(!set.add_store(test_scoped_store(
            "example.com/v1",
            "Widget",
            "namespace:default",
        )));

        assert!(set.has_store("example.com/v1", "Widget"));
        assert!(set.has_store_for_scope("example.com/v1", "Widget", "namespace:prod",));
        assert!(set.remove_store_for_scope("example.com/v1", "Widget", "namespace:default",));
        assert!(set.has_store_for_scope("example.com/v1", "Widget", "namespace:prod",));
    }

    #[test]
    fn snapshot_all_deduplicates_served_version_aliases() {
        let mut set = ResourceStoreSet::new();
        assert!(set.add_store(populated_test_store(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "edge",
            "default",
        )));
        assert!(set.add_store(populated_test_store(
            "gateway.networking.k8s.io/v1beta1",
            "Gateway",
            "edge",
            "default",
        )));

        let objects = set.snapshot_all();

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].api_version, "gateway.networking.k8s.io/v1");
        assert_eq!(objects[0].kind, "Gateway");
        assert_eq!(objects[0].metadata.namespace, "default");
        assert_eq!(objects[0].metadata.name, "edge");
    }

    #[test]
    fn snapshot_all_deduplicates_tlsroute_v1_and_v1alpha2() {
        let mut set = ResourceStoreSet::new();
        assert!(set.add_store(populated_test_store(
            "gateway.networking.k8s.io/v1",
            "TLSRoute",
            "db",
            "default",
        )));
        assert!(set.add_store(populated_test_store(
            "gateway.networking.k8s.io/v1alpha2",
            "TLSRoute",
            "db",
            "default",
        )));

        assert!(set.has_store("gateway.networking.k8s.io/v1", "TLSRoute"));
        assert!(set.has_store("gateway.networking.k8s.io/v1alpha2", "TLSRoute",));

        let objects = set.snapshot_all();

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].api_version, "gateway.networking.k8s.io/v1");
        assert_eq!(objects[0].kind, "TLSRoute");
        assert_eq!(objects[0].metadata.namespace, "default");
        assert_eq!(objects[0].metadata.name, "db");
    }

    /// ProxyConfig rides the same scoped-store + remove-on-stream-end path as
    /// every other Istio CRD: a live store keeps last-known-good objects in
    /// `snapshot_all` until the watcher explicitly deregisters the scope
    /// (reprobe then restarts). This pins the store identity used by
    /// `start_crd_watchers` for `networking.istio.io/v1beta1` ProxyConfig.
    #[test]
    fn proxy_config_scoped_store_keeps_last_known_until_scope_removed() {
        let mut set = ResourceStoreSet::new();
        let api_version = "networking.istio.io/v1beta1";
        let kind = "ProxyConfig";
        let scope = "namespace:default";

        let ar = ApiResource {
            group: "networking.istio.io".to_string(),
            version: "v1beta1".to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: "proxyconfigs".to_string(),
        };
        let mut writer = reflector::store::Writer::new(ar.clone());
        let object = DynamicObject::new("pc-defaults", &ar)
            .within("default")
            .data(json!({
                "spec": { "concurrency": 4, "tracing": { "sampling": 42.0 } }
            }));
        writer.apply_watcher_event(&Event::Init);
        writer.apply_watcher_event(&Event::InitApply(object));
        writer.apply_watcher_event(&Event::InitDone);
        let store = Arc::new(CrdResourceStore::new_scoped(
            api_version.to_string(),
            kind.to_string(),
            scope.to_string(),
            writer.as_reader(),
        ));

        assert!(set.add_store(store));
        assert!(set.has_store_for_scope(api_version, kind, scope));
        let snap = set.snapshot_all();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kind, "ProxyConfig");
        assert_eq!(snap[0].metadata.name, "pc-defaults");
        assert_eq!(snap[0].api_version, api_version);

        // Stream-end path removes only this scope; last-known objects leave
        // with the store. Reprobe can re-add without clobbering other scopes.
        assert!(set.remove_store_for_scope(api_version, kind, scope));
        assert!(!set.has_store_for_scope(api_version, kind, scope));
        assert!(set.snapshot_all().is_empty());
    }
}
