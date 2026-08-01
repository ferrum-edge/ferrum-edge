use std::collections::HashSet;
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
    /// same `(api_version, kind, scope)` triple, in place and under one lock.
    ///
    /// This is the make-before-break half of the idle relist in
    /// [`super::watcher`]: the previous generation's store keeps serving its
    /// last-known-good objects to `snapshot_all` until the replacement has
    /// finished its initial list, so a relist never opens a window in which the
    /// scope contributes zero objects. A gap there would look exactly like a
    /// mass deletion to the reconciler and would broadcast a config wipe.
    ///
    /// Returns `false` when no store is registered for the triple; the caller
    /// then falls back to [`Self::add_store`] rather than dropping the scope.
    pub fn replace_store_for_scope(&mut self, store: Arc<CrdResourceStore>) -> bool {
        let Some(index) = self.stores.iter().position(|existing| {
            existing.api_version == store.api_version
                && existing.kind == store.kind
                && existing.scope == store.scope
        }) else {
            return false;
        };

        self.stores[index] = store;
        self.notify_change();
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

    pub fn snapshot_all(&self) -> Vec<K8sObject> {
        let mut objects = Vec::new();
        let mut seen = HashSet::new();
        for store in &self.stores {
            for object in store.snapshot() {
                if seen.insert(resource_identity(&object)) {
                    objects.push(object);
                }
            }
        }
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

fn resource_identity(object: &K8sObject) -> (String, String, String, String) {
    let group = object
        .api_version
        .split_once('/')
        .map_or("", |(group, _version)| group);
    (
        group.to_string(),
        object.kind.clone(),
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
    )
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
