//! Kubernetes mesh-overlay withdrawal (issue #2452).
//!
//! Deleting the last mesh-contributing Kubernetes object used to leave the
//! previously published mesh live forever: the translator represented a
//! managed-but-empty mesh as `GatewayConfig.mesh == None`, and the reconciler
//! read that same `None` as "Kubernetes has no mesh update, keep the active
//! mesh". `GatewayConfig.k8s_mesh_overlay` now separates the two states:
//!
//! * `NoAuthority` — this source is not a mesh owner; leave other sources'
//!   mesh state alone.
//! * `Authoritative` — the published mesh is a retained non-Kubernetes
//!   `base_mesh` plus a Kubernetes overlay layered on top, and an EMPTY overlay
//!   is a withdrawal.
//!
//! Ownership is keyed by OBJECT IDENTITY (collection + namespace + the
//! resource's own key), never by namespace: a namespace routinely holds
//! objects from several sources at once, so withdrawing a namespace would
//! erase mesh state Kubernetes never published.
//!
//! These tests cover both states end to end: real translations for Service /
//! Workload, AuthorizationPolicy / PeerAuthentication / RequestAuthentication,
//! ServiceEntry / WorkloadEntry, same-namespace mixed-source ownership,
//! same-name collisions, mesh-global blocks, drift (re-publication without
//! duplication), watch-scope shrink, CP full-reload composition, publication
//! atomicity, and repeated-empty idempotence.

use std::collections::{BTreeSet, HashMap};

use arc_swap::ArcSwap;
use ferrum_edge::_test_support::{
    compose_db_with_k8s_overlay, empty_k8s_overlay_slot, merge_k8s_translation,
    store_accepted_k8s_overlay, swap_merged_k8s_translation,
};
use ferrum_edge::config::types::{GatewayConfig, K8sMeshOverlay};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshCorsOriginMatch, MeshCorsPolicy, MeshDestinationRule, MeshPolicy,
    MeshProxyConfig, MeshRequestAuthentication, MeshService, MeshSidecar, MeshTelemetryConfig,
    MeshTelemetryResource, MeshVirtualServiceCorsPolicy, MeshWaypointBinding, MtlsMode,
    OutboundTrafficPolicy, PeerAuthentication, PolicyScope, ServiceEntry, Workload,
    WorkloadSelector,
};
use serde_json::{Value, json};

// ── Fixtures ──────────────────────────────────────────────────────────────

/// Translation options for a controller that DOES watch mesh-contributing
/// kinds, i.e. an authoritative mesh owner.
fn authoritative_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_pod_discovery_enabled(true)
    .with_mesh_overlay_authority(true)
}

/// Translation options for a controller that watches no mesh-contributing
/// kind and therefore owns nothing.
fn non_authoritative_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_mesh_overlay_authority(false)
}

fn object(api_version: &str, kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn service() -> K8sObject {
    object(
        "v1",
        "Service",
        "default",
        "reviews",
        json!({
            "ports": [{
                "name": "http",
                "port": 9080,
                "targetPort": 9080,
                "appProtocol": "http"
            }]
        }),
    )
}

fn ready_pod() -> K8sObject {
    let mut pod = object(
        "v1",
        "Pod",
        "default",
        "reviews-v1",
        json!({
            "serviceAccountName": "reviews",
            "nodeName": "node-a",
            "containers": [{
                "ports": [{"name": "http", "containerPort": 9080, "protocol": "TCP"}]
            }]
        }),
    );
    pod.metadata
        .labels
        .insert("app".to_string(), "reviews".to_string());
    pod.status = json!({
        "phase": "Running",
        "podIP": "10.1.0.10",
        "conditions": [{"type": "Ready", "status": "True"}]
    });
    pod
}

fn endpoint_slice() -> K8sObject {
    let mut slice = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "default",
        "reviews-abc",
        json!({
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["10.1.0.10"],
                "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
                "conditions": {"ready": true}
            }],
            "ports": [{"name": "http", "port": 9080}]
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        "reviews".to_string(),
    );
    slice
}

fn authorization_policy(namespace: &str) -> K8sObject {
    object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        namespace,
        "allow-reviews",
        json!({
            "action": "ALLOW",
            "rules": [{"to": [{"operation": {"ports": ["9080"]}}]}]
        }),
    )
}

fn peer_authentication(namespace: &str) -> K8sObject {
    object(
        "security.istio.io/v1",
        "PeerAuthentication",
        namespace,
        "strict-mtls",
        json!({"mtls": {"mode": "STRICT"}}),
    )
}

fn request_authentication(namespace: &str) -> K8sObject {
    object(
        "security.istio.io/v1",
        "RequestAuthentication",
        namespace,
        "jwt",
        json!({
            "jwtRules": [{
                "issuer": "https://issuer.example.com",
                "jwksUri": "https://issuer.example.com/certs"
            }]
        }),
    )
}

fn service_entry(namespace: &str, name: &str, host: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "ServiceEntry",
        namespace,
        name,
        json!({
            "hosts": [host],
            "resolution": "DNS",
            "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
        }),
    )
}

fn workload_entry(namespace: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "WorkloadEntry",
        namespace,
        "vm-api",
        json!({
            "address": "vm-api.example",
            "serviceAccount": "api",
            "service": "api",
            "labels": {"app": "api"},
            "ports": {"http": 8080}
        }),
    )
}

/// Translate an authoritative Kubernetes snapshot into a `GatewayConfig`.
fn authoritative_translation(objects: &[K8sObject]) -> GatewayConfig {
    translate_k8s_objects(objects, authoritative_options())
        .expect("translation succeeds")
        .config
}

/// The authoritative EMPTY snapshot: every mesh-contributing object deleted.
fn authoritative_empty_translation() -> GatewayConfig {
    authoritative_translation(&[])
}

/// A hand-built authoritative Kubernetes overlay, for coverage a real
/// translation cannot reach conveniently (every mesh collection at once).
fn authoritative_overlay(mesh: Option<MeshConfig>) -> GatewayConfig {
    GatewayConfig {
        mesh: mesh.map(Box::new),
        k8s_mesh_overlay: K8sMeshOverlay::authoritative_translation(),
        ..GatewayConfig::default()
    }
}

/// An active snapshot whose mesh is owned entirely by a non-Kubernetes source
/// (native / file / xDS).
fn other_source_config(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

fn managed(namespaces: &[&str]) -> BTreeSet<String> {
    namespaces.iter().map(|ns| ns.to_string()).collect()
}

fn native_mesh_service(namespace: &str, name: &str) -> MeshService {
    MeshService {
        cluster_ips: vec!["10.96.0.7".to_string()],
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
    }
}

fn mesh_of(config: &GatewayConfig) -> &MeshConfig {
    config.mesh.as_deref().expect("mesh must be published")
}

fn service_names(mesh: &MeshConfig, namespace: &str) -> Vec<String> {
    mesh.services
        .iter()
        .filter(|svc| svc.namespace == namespace)
        .map(|svc| svc.name.clone())
        .collect()
}

// ── Translator: authority marking ─────────────────────────────────────────

#[test]
fn authoritative_translator_marks_an_empty_snapshot_as_authoritative() {
    let empty = authoritative_empty_translation();

    assert!(
        empty.mesh.is_none(),
        "an empty mesh must still serialize as `mesh: None`"
    );
    assert_eq!(
        empty.k8s_mesh_overlay,
        K8sMeshOverlay::Authoritative { base_mesh: None },
        "an empty managed snapshot is an authoritative withdrawal, not a missing update"
    );
}

#[test]
fn a_translation_owns_its_whole_mesh_and_nothing_underneath_it() {
    let translation = authoritative_translation(&[
        service_entry("alpha", "api", "api.example.com"),
        service_entry("beta", "cdn", "cdn.example.com"),
    ]);

    assert_eq!(
        translation.k8s_mesh_overlay,
        K8sMeshOverlay::Authoritative { base_mesh: None },
        "a raw translation has no base layer: its whole mesh is Kubernetes-owned"
    );
    assert_eq!(mesh_of(&translation).service_entries.len(), 2);
}

#[test]
fn non_authoritative_translator_never_claims_mesh_ownership() {
    let translation = translate_k8s_objects(&[], non_authoritative_options())
        .expect("translation succeeds")
        .config;

    assert_eq!(translation.k8s_mesh_overlay, K8sMeshOverlay::NoAuthority);
    assert!(!translation.k8s_mesh_overlay.is_authoritative());
}

// ── Withdrawal by resource kind ───────────────────────────────────────────

#[test]
fn deleting_the_last_service_and_workload_withdraws_the_mesh_overlay() {
    let populated = authoritative_translation(&[service(), ready_pod(), endpoint_slice()]);
    let mesh = mesh_of(&populated);
    assert_eq!(mesh.services.len(), 1);
    assert_eq!(mesh.workloads.len(), 1);

    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    let active = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    assert!(active.mesh.is_some(), "the K8s mesh must publish first");

    let withdrawn = merge_k8s_translation(&active, &empty, &managed);

    assert!(
        withdrawn.mesh.is_none(),
        "deleting the last Service/Pod/EndpointSlice must withdraw the mesh overlay"
    );
}

#[test]
fn deleting_the_last_policies_withdraws_the_mesh_overlay() {
    let populated = authoritative_translation(&[
        authorization_policy("default"),
        peer_authentication("default"),
        request_authentication("default"),
    ]);
    let mesh = mesh_of(&populated);
    assert_eq!(mesh.mesh_policies.len(), 1);
    assert_eq!(mesh.peer_authentications.len(), 1);
    assert_eq!(mesh.request_authentications.len(), 1);

    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    let active = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    assert!(active.mesh.is_some());

    let withdrawn = merge_k8s_translation(&active, &empty, &managed);

    assert!(
        withdrawn.mesh.is_none(),
        "a deleted AuthorizationPolicy / PeerAuthentication / RequestAuthentication must not \
         keep governing traffic"
    );
}

#[test]
fn deleting_the_last_service_entry_and_workload_entry_withdraws_the_mesh_overlay() {
    let populated = authoritative_translation(&[
        service_entry("default", "api", "api.example.com"),
        workload_entry("default"),
    ]);
    let mesh = mesh_of(&populated);
    assert_eq!(mesh.service_entries.len(), 1);
    assert_eq!(mesh.workloads.len(), 1);

    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    let active = merge_k8s_translation(&GatewayConfig::default(), &populated, &managed);
    assert!(active.mesh.is_some());

    let withdrawn = merge_k8s_translation(&active, &empty, &managed);

    assert!(
        withdrawn.mesh.is_none(),
        "a deleted ServiceEntry / WorkloadEntry must stop being routable"
    );
}

// ── Ownership boundaries ──────────────────────────────────────────────────

#[test]
fn withdrawal_preserves_mesh_state_owned_by_another_source() {
    // A native/file/xDS source owns `native/native-svc`; Kubernetes owns
    // `default/*`. Kubernetes withdrawing everything it owns must not touch
    // the other source's object.
    let mut active = other_source_config(MeshConfig {
        services: vec![native_mesh_service("native", "native-svc")],
        ..MeshConfig::default()
    });
    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    active = merge_k8s_translation(
        &active,
        &authoritative_translation(&[service_entry("default", "api", "api.example.com")]),
        &managed,
    );
    let active_mesh = mesh_of(&active);
    assert_eq!(active_mesh.services.len(), 1);
    assert_eq!(active_mesh.service_entries.len(), 1);

    let withdrawn = merge_k8s_translation(&active, &empty, &managed);

    let mesh = withdrawn
        .mesh
        .as_deref()
        .expect("mesh owned by another source must survive a Kubernetes withdrawal");
    assert!(
        mesh.service_entries.is_empty(),
        "the Kubernetes-owned ServiceEntry must be withdrawn"
    );
    assert_eq!(
        mesh.services.len(),
        1,
        "the natively owned service must survive"
    );
    assert_eq!(mesh.services[0].namespace, "native");
}

#[test]
fn withdrawal_preserves_another_sources_mesh_state_in_the_same_namespace() {
    // The root-review case: the other source's object lives in the SAME
    // namespace Kubernetes owns objects in, and is of the same kind as one of
    // them. Namespace-scoped withdrawal would delete it; identity-scoped
    // withdrawal must not.
    let base = other_source_config(MeshConfig {
        services: vec![native_mesh_service("default", "native-svc")],
        ..MeshConfig::default()
    });
    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    let objects = [
        service(),
        ready_pod(),
        endpoint_slice(),
        service_entry("default", "api", "api.example.com"),
    ];
    let overlay = authoritative_translation(&objects);

    let published = merge_k8s_translation(&base, &overlay, &managed);

    let published_mesh = mesh_of(&published);
    assert_eq!(
        service_names(published_mesh, "default"),
        vec!["native-svc".to_string(), "reviews".to_string()],
        "a non-empty Kubernetes publish must add to, not replace, a shared namespace"
    );
    assert_eq!(published_mesh.service_entries.len(), 1);
    assert_eq!(published_mesh.workloads.len(), 1);

    let withdrawn = merge_k8s_translation(&published, &empty, &managed);

    let mesh = withdrawn
        .mesh
        .as_deref()
        .expect("the other source's same-namespace mesh state must survive the withdrawal");
    assert_eq!(
        service_names(mesh, "default"),
        vec!["native-svc".to_string()],
        "only the Kubernetes-owned service may be withdrawn"
    );
    assert_eq!(mesh.services[0].cluster_ips, vec!["10.96.0.7".to_string()]);
    assert!(mesh.service_entries.is_empty());
    assert!(mesh.workloads.is_empty());
}

#[test]
fn a_same_name_collision_gives_kubernetes_precedence_then_restores_the_base() {
    // Both sources author `default/reviews`. Kubernetes must win
    // deterministically while its overlay is present — ONE object, the
    // Kubernetes one — and the base object must come back when it withdraws.
    // Neither "keep both" nor "lose both" is acceptable.
    let base_service = MeshService {
        cluster_ips: vec!["10.96.0.7".to_string()],
        name: "reviews".to_string(),
        namespace: "default".to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
    };
    let base = other_source_config(MeshConfig {
        services: vec![base_service.clone()],
        ..MeshConfig::default()
    });
    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    let overlay = authoritative_translation(&[service()]);

    let published = merge_k8s_translation(&base, &overlay, &managed);

    let published_mesh = mesh_of(&published);
    assert_eq!(
        published_mesh.services.len(),
        1,
        "a same-key collision must resolve, not leave two ambiguous duplicates"
    );
    let winner = &published_mesh.services[0];
    assert!(
        winner.cluster_ips.is_empty() && !winner.ports.is_empty(),
        "Kubernetes must win the collision while its overlay is present, got {winner:?}"
    );

    let withdrawn = merge_k8s_translation(&published, &empty, &managed);

    let mesh = withdrawn
        .mesh
        .as_deref()
        .expect("the shadowed base object must be restored, not withdrawn with the overlay");
    assert_eq!(mesh.services, vec![base_service]);
}

#[test]
fn a_source_without_mesh_authority_never_withdraws_another_sources_mesh() {
    let active = other_source_config(MeshConfig {
        services: vec![native_mesh_service("default", "native-svc")],
        ..MeshConfig::default()
    });
    let no_authority = translate_k8s_objects(&[], non_authoritative_options())
        .expect("translation succeeds")
        .config;

    let merged = merge_k8s_translation(&active, &no_authority, &managed(&["default"]));

    let mesh = mesh_of(&merged);
    assert_eq!(
        mesh.services.len(),
        1,
        "a controller that watches no mesh kind owns nothing and may withdraw nothing"
    );
}

#[test]
fn mesh_global_blocks_owned_by_another_source_survive_the_overlay_lifecycle() {
    let base = other_source_config(MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        ..MeshConfig::default()
    });
    let managed = managed(&["default"]);
    let empty = authoritative_empty_translation();
    let overlay = authoritative_translation(&[service_entry("default", "api", "api.example.com")]);

    let published = merge_k8s_translation(&base, &overlay, &managed);

    assert_eq!(
        mesh_of(&published).outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "Kubernetes does not translate mesh-global blocks, so it must not own them"
    );

    let withdrawn = merge_k8s_translation(&published, &empty, &managed);

    assert_eq!(
        mesh_of(&withdrawn).outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "a Kubernetes withdrawal must not clear another source's mesh-global policy"
    );
    assert!(mesh_of(&withdrawn).service_entries.is_empty());
}

// ── Watch-scope shrink ────────────────────────────────────────────────────

#[test]
fn watch_scope_shrink_withdraws_kubernetes_objects_and_keeps_other_sources() {
    // `beta` is dropped from the watch scope between rounds. Its previously
    // published Kubernetes objects must still be withdrawn rather than
    // stranded — and the other source's object in the STILL-managed `alpha`
    // namespace must survive, because withdrawal keys on object identity, not
    // on whether a namespace is managed.
    let base = other_source_config(MeshConfig {
        services: vec![native_mesh_service("alpha", "native-svc")],
        ..MeshConfig::default()
    });
    let populated = authoritative_translation(&[
        service_entry("alpha", "api", "api.example.com"),
        service_entry("beta", "cdn", "cdn.example.com"),
    ]);
    let active = merge_k8s_translation(&base, &populated, &managed(&["alpha", "beta"]));
    assert_eq!(mesh_of(&active).service_entries.len(), 2);

    let withdrawn = merge_k8s_translation(
        &active,
        &authoritative_empty_translation(),
        &managed(&["alpha"]),
    );

    let mesh = mesh_of(&withdrawn);
    assert!(
        mesh.service_entries.is_empty(),
        "objects in a namespace that left the managed set must still be withdrawn"
    );
    assert_eq!(
        service_names(mesh, "alpha"),
        vec!["native-svc".to_string()],
        "shrinking the watch scope must not disturb another source's object"
    );
}

#[test]
fn watch_scope_shrink_withdraws_objects_outside_every_service_namespace() {
    // Waypoint bindings and root-namespace resources sit in a namespace of
    // their own. Withdrawal must not depend on that namespace still being
    // watched.
    let overlay = MeshConfig {
        waypoint_bindings: vec![MeshWaypointBinding {
            name: "shared-waypoint".to_string(),
            namespace: "mesh-system".to_string(),
            waypoint_for: "service".to_string(),
            services: Vec::new(),
        }],
        services: vec![native_mesh_service("payments", "checkout")],
        ..MeshConfig::default()
    };
    let active = merge_k8s_translation(
        &GatewayConfig::default(),
        &authoritative_overlay(Some(overlay)),
        &managed(&["payments", "mesh-system"]),
    );
    assert_eq!(mesh_of(&active).waypoint_bindings.len(), 1);

    let withdrawn = merge_k8s_translation(
        &active,
        &authoritative_overlay(None),
        &managed(&["payments"]),
    );

    assert!(
        withdrawn.mesh.is_none(),
        "a Kubernetes waypoint binding outside every service namespace must not be stranded"
    );
}

// ── Drift / idempotence ───────────────────────────────────────────────────

#[test]
fn republishing_the_same_snapshot_replaces_rather_than_duplicates() {
    let base = other_source_config(MeshConfig {
        services: vec![native_mesh_service("default", "native-svc")],
        ..MeshConfig::default()
    });
    let populated =
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]);
    let managed = managed(&["default"]);

    let first = merge_k8s_translation(&base, &populated, &managed);
    let second = merge_k8s_translation(&first, &populated, &managed);
    let third = merge_k8s_translation(&second, &populated, &managed);

    let mesh = mesh_of(&third);
    assert_eq!(
        mesh.service_entries.len(),
        1,
        "a re-published Kubernetes object must replace its predecessor, not stack on it"
    );
    assert_eq!(
        service_names(mesh, "default"),
        vec!["native-svc".to_string()],
        "repeated publishes must not duplicate or drop the other source's object"
    );
    assert_eq!(
        mesh_of(&first).services,
        mesh.services,
        "idempotent publishes must converge on one composed view"
    );
}

#[test]
fn repeated_empty_snapshots_are_idempotent_and_publish_once() {
    let populated =
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]);
    let empty = authoritative_empty_translation();
    let managed = managed(&["default"]);

    let config_arc = ArcSwap::from_pointee(GatewayConfig::default());
    assert!(
        swap_merged_k8s_translation(&config_arc, &populated, &managed).is_some(),
        "the first non-empty publication must commit"
    );

    let withdrawal = swap_merged_k8s_translation(&config_arc, &empty, &managed)
        .expect("the withdrawal must commit exactly once");
    assert!(withdrawal.mesh.is_none());

    assert!(
        swap_merged_k8s_translation(&config_arc, &empty, &managed).is_none(),
        "a repeated empty snapshot is a no-op — no re-publication, no broadcast"
    );
    assert!(config_arc.load().mesh.is_none());
}

#[test]
fn withdrawal_publishes_one_complete_snapshot() {
    let populated =
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]);
    let empty = authoritative_empty_translation();
    let managed = managed(&["default"]);
    let base = other_source_config(MeshConfig {
        services: vec![native_mesh_service("default", "native-svc")],
        ..MeshConfig::default()
    });

    let config_arc = ArcSwap::from_pointee(base);
    swap_merged_k8s_translation(&config_arc, &populated, &managed).expect("initial publication");

    // An in-flight consumer holding the pre-withdrawal snapshot.
    let in_flight = config_arc.load_full();
    assert_eq!(mesh_of(&in_flight).service_entries.len(), 1);

    swap_merged_k8s_translation(&config_arc, &empty, &managed).expect("withdrawal publication");

    assert_eq!(
        mesh_of(&in_flight).service_entries.len(),
        1,
        "the in-flight snapshot must stay complete — never partially withdrawn"
    );
    let published = config_arc.load_full();
    assert!(
        mesh_of(&published).service_entries.is_empty(),
        "the next load must see the complete post-withdrawal snapshot"
    );
    assert_eq!(
        service_names(mesh_of(&published), "default"),
        vec!["native-svc".to_string()],
        "the same-namespace object owned by another source must survive publication"
    );
}

// ── CP full-reload re-merge (overlay slot) ────────────────────────────────

#[test]
fn overlay_slot_does_not_resurrect_an_authoritatively_withdrawn_mesh() {
    let overlay_slot = empty_k8s_overlay_slot();
    let managed = managed(&["default"]);

    store_accepted_k8s_overlay(
        &overlay_slot,
        authoritative_translation(&[service_entry("default", "api", "api.example.com")]),
        managed.clone(),
    );
    assert!(
        compose_db_with_k8s_overlay(&GatewayConfig::default(), &overlay_slot)
            .mesh
            .is_some(),
        "the accepted overlay must supply mesh on a CP full reload"
    );

    store_accepted_k8s_overlay(&overlay_slot, authoritative_empty_translation(), managed);

    assert!(
        compose_db_with_k8s_overlay(&GatewayConfig::default(), &overlay_slot)
            .mesh
            .is_none(),
        "a CP full reload must not resurrect a withdrawn Kubernetes mesh overlay"
    );
}

#[test]
fn overlay_slot_compose_preserves_same_namespace_mesh_from_a_non_kubernetes_base() {
    // Production CP DB full loads clear `mesh` before overlay re-merge; this
    // exercises `compose_db_with_k8s_overlay` with a synthetic non-Kubernetes
    // mesh base to pin the helper's retained-base contract.
    let overlay_slot = empty_k8s_overlay_slot();
    let managed = managed(&["default"]);
    let non_kubernetes_base = other_source_config(MeshConfig {
        services: vec![native_mesh_service("default", "native-svc")],
        ..MeshConfig::default()
    });
    let objects = [
        service(),
        service_entry("default", "api", "api.example.com"),
    ];

    store_accepted_k8s_overlay(
        &overlay_slot,
        authoritative_translation(&objects),
        managed.clone(),
    );
    let composed = compose_db_with_k8s_overlay(&non_kubernetes_base, &overlay_slot);
    assert_eq!(
        service_names(mesh_of(&composed), "default"),
        vec!["native-svc".to_string(), "reviews".to_string()],
        "the overlay must layer onto the non-Kubernetes mesh base, not replace it"
    );

    store_accepted_k8s_overlay(&overlay_slot, authoritative_empty_translation(), managed);
    let withdrawn = compose_db_with_k8s_overlay(&non_kubernetes_base, &overlay_slot);

    let mesh = mesh_of(&withdrawn);
    assert_eq!(
        service_names(mesh, "default"),
        vec!["native-svc".to_string()],
        "a withdrawal after compose must keep the non-Kubernetes mesh base in that namespace"
    );
    assert!(mesh.service_entries.is_empty());
}

#[test]
fn overlay_slot_compose_restores_a_non_kubernetes_object_the_overlay_shadowed() {
    let overlay_slot = empty_k8s_overlay_slot();
    let managed = managed(&["default"]);
    let base_service = MeshService {
        cluster_ips: vec!["10.96.0.7".to_string()],
        name: "reviews".to_string(),
        namespace: "default".to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
    };
    let non_kubernetes_base = other_source_config(MeshConfig {
        services: vec![base_service.clone()],
        ..MeshConfig::default()
    });

    store_accepted_k8s_overlay(
        &overlay_slot,
        authoritative_translation(&[service()]),
        managed.clone(),
    );
    let composed = compose_db_with_k8s_overlay(&non_kubernetes_base, &overlay_slot);
    assert_eq!(mesh_of(&composed).services.len(), 1);
    assert!(mesh_of(&composed).services[0].cluster_ips.is_empty());

    store_accepted_k8s_overlay(&overlay_slot, authoritative_empty_translation(), managed);
    let withdrawn = compose_db_with_k8s_overlay(&non_kubernetes_base, &overlay_slot);

    assert_eq!(mesh_of(&withdrawn).services, vec![base_service]);
}

// ── Workload identity tiers ───────────────────────────────────────────────

/// A `Workload` whose identity-bearing fields are all set independently.
///
/// `pod_uid` is passed through VERBATIM — including `Some("")`, which the
/// native / file / xDS sources can deserialize — because an empty UID must
/// reach the FALLBACK identity tier rather than becoming a real pod identity.
fn workload(
    namespace: &str,
    service_account: &str,
    addresses: &[&str],
    pod_uid: Option<&str>,
    service_name: &str,
) -> Workload {
    let uri = format!("spiffe://cluster.local/ns/{namespace}/sa/{service_account}");
    Workload {
        spiffe_id: SpiffeId::new(uri).expect("test spiffe id"),
        selector: WorkloadSelector::default(),
        service_name: service_name.to_string(),
        addresses: addresses.iter().map(|addr| addr.to_string()).collect(),
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("test trust domain"),
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(service_account.to_string()),
        pod_uid: pod_uid.map(str::to_string),
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn mesh_with_workloads(workloads: Vec<Workload>) -> MeshConfig {
    MeshConfig {
        workloads,
        ..MeshConfig::default()
    }
}

/// Compose a non-Kubernetes base mesh with an authoritative Kubernetes overlay.
fn compose_workloads(base: &MeshConfig, overlay: Option<MeshConfig>) -> GatewayConfig {
    merge_k8s_translation(
        &other_source_config(base.clone()),
        &authoritative_overlay(overlay),
        &managed(&["default"]),
    )
}

fn workload_names(config: &GatewayConfig) -> Vec<&str> {
    mesh_of(config)
        .workloads
        .iter()
        .map(|workload| workload.service_name.as_str())
        .collect()
}

const POD_A: &str = "11111111-1111-4111-8111-111111111111";
const POD_B: &str = "22222222-2222-4222-8222-222222222222";

/// A Kubernetes Pod UID is the STABLE identity of that logical workload: its
/// addresses, SPIFFE id, service account and service name all legitimately
/// change while the same Pod object is reconciled. Folding any of those into
/// the identity key would stop the overlay from shadowing the base snapshot's
/// copy of the pod, leaving two logical copies of it in the composed mesh.
#[test]
fn a_pod_backed_workload_is_identified_by_its_pod_uid_alone() {
    let base_workload = workload(
        "default",
        "reviews",
        &["10.0.0.1"],
        Some(POD_A),
        "reviews-base-v1",
    );
    let base = mesh_with_workloads(vec![base_workload]);
    let k8s = workload(
        "default",
        "reviews-rotated",
        &["10.0.0.9", "fd00::9"],
        Some(POD_A),
        "reviews-k8s-v2",
    );
    let overlay = mesh_with_workloads(vec![k8s.clone()]);

    let composed = compose_workloads(&base, Some(overlay));

    assert_eq!(
        mesh_of(&composed).workloads,
        vec![k8s],
        "one pod UID is one logical workload: the Kubernetes copy must shadow \
         the base copy even though every other field changed"
    );
}

#[test]
fn withdrawing_a_pod_backed_overlay_restores_the_exact_base_workload() {
    let base_workload = workload(
        "default",
        "reviews",
        &["10.0.0.1"],
        Some(POD_A),
        "reviews-base-v1",
    );
    let base = mesh_with_workloads(vec![base_workload.clone()]);
    let k8s = workload(
        "default",
        "reviews-rotated",
        &["10.0.0.9"],
        Some(POD_A),
        "reviews-k8s-v2",
    );
    let overlay = mesh_with_workloads(vec![k8s]);

    let active = compose_workloads(&base, Some(overlay));
    assert_eq!(mesh_of(&active).workloads.len(), 1);

    let withdrawn = merge_k8s_translation(
        &active,
        &authoritative_overlay(None),
        &managed(&["default"]),
    );

    assert_eq!(
        mesh_of(&withdrawn).workloads,
        vec![base_workload],
        "withdrawal must restore the base workload the overlay had shadowed"
    );
}

#[test]
fn two_pod_backed_workloads_with_different_uids_coexist() {
    // Identical in every field EXCEPT the pod UID.
    let base_workload = workload(
        "default",
        "reviews",
        &["10.0.0.1"],
        Some(POD_A),
        "reviews-same-fields",
    );
    let base = mesh_with_workloads(vec![base_workload]);
    let k8s = workload(
        "default",
        "reviews",
        &["10.0.0.1"],
        Some(POD_B),
        "reviews-same-fields",
    );
    let overlay = mesh_with_workloads(vec![k8s]);

    let composed = compose_workloads(&base, Some(overlay));

    assert_eq!(
        mesh_of(&composed).workloads.len(),
        2,
        "two distinct pods must coexist even when every other field matches"
    );
}

/// WorkloadEntry / VM / native / xDS workloads carry no pod identity, and
/// `Workload` has no resource name to key on, so the fallback tier must keep
/// two workloads that share a service account — and therefore a SPIFFE id —
/// distinct.
#[test]
fn non_pod_workloads_sharing_a_spiffe_identity_coexist_when_addresses_differ() {
    let base_workload = workload("default", "vm-sa", &["10.1.0.1"], None, "legacy-vm-alpha");
    let base = mesh_with_workloads(vec![base_workload]);
    let k8s = workload("default", "vm-sa", &["10.1.0.2"], None, "legacy-vm-beta");
    let overlay = mesh_with_workloads(vec![k8s]);

    let composed = compose_workloads(&base, Some(overlay));

    assert_eq!(
        mesh_of(&composed).workloads.len(),
        2,
        "a shared service account must not collapse two distinct non-pod workloads"
    );
}

#[test]
fn an_empty_pod_uid_falls_back_instead_of_becoming_a_pod_identity() {
    // Two uid-less workloads differing only by address. Normalizing `Some("")`
    // into the pod tier would give both the same key and silently drop one.
    let empty_uid = workload(
        "default",
        "vm-sa",
        &["10.1.0.1"],
        Some(""),
        "legacy-empty-uid",
    );
    let absent_uid = workload("default", "vm-sa", &["10.1.0.2"], None, "legacy-absent-uid");
    let unrelated = mesh_with_workloads(vec![empty_uid, absent_uid]);
    assert_eq!(
        unrelated.object_identities().len(),
        2,
        "an empty pod UID must not collapse unrelated non-pod workloads"
    );

    let empty_base = mesh_with_workloads(Vec::new());
    let composed = compose_workloads(&empty_base, Some(unrelated.clone()));
    assert_eq!(mesh_of(&composed).workloads.len(), 2);

    // An absent and an explicitly empty UID are the SAME (fallback) tier, so a
    // matching SPIFFE id plus addresses still shadows.
    let reauthoring = workload("default", "vm-sa", &["10.1.0.1"], None, "legacy-reauthored");
    let shadowing = mesh_with_workloads(vec![reauthoring]);
    let reauthored = compose_workloads(&unrelated, Some(shadowing));
    assert_eq!(
        workload_names(&reauthored),
        vec!["legacy-absent-uid", "legacy-reauthored"],
        "an absent and an explicitly empty pod UID share one identity tier"
    );

    // A fallback identity must never collide with a pod identity.
    let twin = workload(
        "default",
        "vm-sa",
        &["10.1.0.1"],
        Some(POD_A),
        "pod-backed-twin",
    );
    let pod_backed = mesh_with_workloads(vec![twin]);
    let mixed = compose_workloads(&unrelated, Some(pod_backed));
    assert_eq!(
        mesh_of(&mixed).workloads.len(),
        3,
        "a pod-backed workload must never shadow a uid-less one that happens to \
         share its SPIFFE id and addresses"
    );
}

// ── Ownership-accounting coverage guard ───────────────────────────────────

/// One object in EVERY namespaced [`MeshConfig`] collection.
///
/// `key_suffix` varies the objects' IDENTITY (so base and overlay objects can
/// be made distinct or made to collide) while `marker` varies a NON-identity
/// field (so a collision's winner is observable). `waypoint_bindings` is
/// deliberately placed in a different namespace from everything else: a
/// waypoint binding's own namespace routinely differs from the namespaces of
/// the services it governs.
fn all_collections(key_suffix: &str, marker: &str) -> MeshConfig {
    let name = |kind: &str| format!("{kind}-{key_suffix}");
    let uri = format!("spiffe://cluster.local/ns/shared/sa/{key_suffix}");
    let spiffe_id = SpiffeId::new(uri).expect("test spiffe id");
    let trust_domain = TrustDomain::new("cluster.local").expect("test trust domain");
    let scope = PolicyScope::Namespace {
        namespace: marker.to_string(),
    };
    let origin = MeshCorsOriginMatch::Exact(format!("https://{marker}.example.com"));
    MeshConfig {
        workloads: vec![Workload {
            spiffe_id,
            selector: WorkloadSelector::default(),
            service_name: marker.to_string(),
            addresses: Vec::new(),
            ports: Vec::new(),
            trust_domain,
            namespace: "shared".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: vec![marker.to_string()],
            name: name("service"),
            namespace: "shared".to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }],
        mesh_policies: vec![MeshPolicy {
            name: name("policy"),
            namespace: "shared".to_string(),
            scope: scope.clone(),
            rules: Vec::new(),
        }],
        peer_authentications: vec![PeerAuthentication {
            name: name("peer-auth"),
            namespace: "shared".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::default(),
            port_overrides: HashMap::new(),
        }],
        service_entries: vec![ServiceEntry {
            name: name("service-entry"),
            namespace: "shared".to_string(),
            hosts: vec![format!("{marker}.example.com")],
            endpoints: Vec::new(),
            resolution: Default::default(),
            location: Default::default(),
            ports: Vec::new(),
            export_to: Vec::new(),
            workload_selector: None,
        }],
        request_authentications: vec![MeshRequestAuthentication {
            name: name("request-auth"),
            namespace: "shared".to_string(),
            scope: scope.clone(),
            jwt_rules: Vec::new(),
        }],
        telemetry_resources: vec![MeshTelemetryResource {
            name: name("telemetry"),
            namespace: "shared".to_string(),
            scope,
            config: MeshTelemetryConfig::default(),
        }],
        destination_rules: vec![MeshDestinationRule {
            name: name("destination-rule"),
            namespace: "shared".to_string(),
            host: "shared.example.com".to_string(),
            traffic_policy: None,
            port_level_settings: HashMap::new(),
            subsets: Vec::new(),
        }],
        virtual_service_cors_policies: vec![MeshVirtualServiceCorsPolicy {
            name: name("cors"),
            namespace: "shared".to_string(),
            host: "shared.example.com".to_string(),
            export_to: Vec::new(),
            cors: MeshCorsPolicy {
                allowed_origins: vec![origin],
                allowed_methods: Vec::new(),
                allowed_headers: Vec::new(),
                exposed_headers: Vec::new(),
                max_age_seconds: None,
                allow_credentials: None,
                unmatched_preflights: None,
            },
        }],
        proxy_configs: vec![MeshProxyConfig {
            name: name("proxy-config"),
            namespace: "shared".to_string(),
            image: Some(marker.to_string()),
            ..MeshProxyConfig::default()
        }],
        sidecars: vec![MeshSidecar {
            name: name("sidecar"),
            namespace: "shared".to_string(),
            workload_selector: None,
            egress_inherits_defaults: marker == "k8s",
            egress: Vec::new(),
            ingress_declared: false,
            ingress: Vec::new(),
        }],
        waypoint_bindings: vec![MeshWaypointBinding {
            name: name("waypoint"),
            namespace: "mesh-system".to_string(),
            waypoint_for: marker.to_string(),
            services: Vec::new(),
        }],
        ..MeshConfig::default()
    }
}

/// Per-collection object counts, in the order [`MeshConfig`] declares them.
fn collection_counts(mesh: &MeshConfig) -> [usize; 12] {
    [
        mesh.workloads.len(),
        mesh.services.len(),
        mesh.mesh_policies.len(),
        mesh.peer_authentications.len(),
        mesh.service_entries.len(),
        mesh.request_authentications.len(),
        mesh.telemetry_resources.len(),
        mesh.destination_rules.len(),
        mesh.virtual_service_cors_policies.len(),
        mesh.proxy_configs.len(),
        mesh.sidecars.len(),
        mesh.waypoint_bindings.len(),
    ]
}

/// Exhaustively destructures [`MeshConfig`] so a new field cannot be added
/// without deciding whether it participates in Kubernetes overlay ownership,
/// then proves every namespaced collection is actually wired in.
///
/// A new NAMESPACED collection must reach `MeshConfig::object_namespaces`,
/// `MeshConfig::object_identities`, and `MeshConfig::overlay_objects_from`, or
/// it will silently survive a Kubernetes withdrawal. A new mesh-GLOBAL block is
/// deliberately left alone by the merge (the Kubernetes translator produces
/// none).
#[test]
fn mesh_config_fields_are_accounted_for_in_overlay_ownership() {
    let MeshConfig {
        istio_root_namespace: _,
        // Namespaced, Kubernetes-ownable collections.
        workloads: _,
        services: _,
        mesh_policies: _,
        peer_authentications: _,
        service_entries: _,
        request_authentications: _,
        telemetry_resources: _,
        destination_rules: _,
        virtual_service_cors_policies: _,
        proxy_configs: _,
        sidecars: _,
        waypoint_bindings: _,
        // Mesh-global blocks: never produced by the Kubernetes translator and
        // therefore never withdrawn by it.
        trust_bundles: _,
        multi_cluster: _,
        outbound_traffic_policy: _,
        extension_configs: _,
        // Runtime-only back-projections: derived per slice, never source-owned,
        // always default on a control-plane snapshot.
        node_waypoint_assertors: _,
        node_waypoint_capture_destinations: _,
        node_waypoint_capture_peer_authentications: _,
        local_inbound_services: _,
        local_ingress_listeners: _,
        declared_ingress_http_ports: _,
        local_inbound_tcp_routes: _,
    } = MeshConfig::default();

    // Every namespaced collection is visible to the ownership accounting.
    let base = all_collections("base", "base");
    assert_eq!(
        base.object_identities().len(),
        12,
        "every namespaced collection must contribute exactly one identity"
    );
    assert_eq!(
        base.object_namespaces(),
        managed(&["mesh-system", "shared"]),
        "an object outside the service namespaces must still be accounted for"
    );

    // Distinct identities: the overlay ADDS to every collection. A collection
    // missing from `overlay_objects_from` would keep only its base object.
    let mut composed = base.clone();
    composed.overlay_objects_from(&all_collections("k8s", "k8s"));
    assert_eq!(
        collection_counts(&composed),
        [2; 12],
        "every namespaced collection must be layered, not skipped"
    );

    // Colliding identities: the overlay WINS in every collection.
    let overlay = all_collections("base", "k8s");
    let mut collided = base.clone();
    collided.overlay_objects_from(&overlay);
    assert_eq!(
        collection_counts(&collided),
        [1; 12],
        "a same-key collision must resolve to one object per collection"
    );
    assert_eq!(
        collided, overlay,
        "Kubernetes must deterministically win every same-key collision"
    );
}

#[test]
fn every_namespaced_collection_is_withdrawn_and_restores_its_base() {
    let base = all_collections("base", "base");
    let managed = managed(&["shared", "mesh-system"]);
    let active = merge_k8s_translation(
        &other_source_config(base.clone()),
        &authoritative_overlay(Some(all_collections("k8s", "k8s"))),
        &managed,
    );
    assert_eq!(collection_counts(mesh_of(&active)), [2; 12]);

    let withdrawn = merge_k8s_translation(&active, &authoritative_overlay(None), &managed);

    assert_eq!(
        mesh_of(&withdrawn),
        &base,
        "a Kubernetes withdrawal must restore every collection's base layer exactly"
    );
}
