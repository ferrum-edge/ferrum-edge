//! CP DB-poll / Kubernetes-overlay isolation (issues #2982–#2984) and CP
//! publication ordering.
//!
//! Covers overlay survival across full DB reload, per-namespace failure
//! isolation, concurrent poll/reconcile CAS publication, and the requirement
//! that the order in which snapshots are committed to `config_arc` is the order
//! in which DP and mesh subscribers observe them.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::{
    CpPublicationGate, K8sOverlaySlot, cas_publish_db_snapshot_with_k8s_overlay_for_test,
    cas_publish_incremental_partitions_for_test, compose_db_with_k8s_overlay,
    compose_incremental_partitions_for_test, empty_k8s_overlay_slot,
    publish_cp_full_reload_for_test, publish_cp_incremental_for_test, publish_k8s_reconcile,
    store_accepted_k8s_overlay, swap_merged_k8s_translation,
};
use ferrum_edge::config::db_backend::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy, ResponseBodyMode,
};
use ferrum_edge::grpc::cp_server::{CpScope, DpNodeRegistry, NamespaceBroadcasts};
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_server::MeshConfigBroadcast;
use ferrum_edge::grpc::proto::ConfigUpdate;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService};
use tokio::sync::broadcast;

fn empty_incremental() -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    }
}

fn make_proxy(id: &str, namespace: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: Some(id.to_string()),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 8080,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mesh_with_service(name: &str) -> Box<MeshConfig> {
    Box::new(MeshConfig {
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: "ferrum".to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }],
        ..Default::default()
    })
}

#[test]
fn full_db_reload_reapplies_k8s_overlay_and_mesh() {
    // #2982: DB-only snapshot must not wipe the independently owned overlay.
    let overlay_slot = empty_k8s_overlay_slot();
    let mut k8s = GatewayConfig::default();
    k8s.proxies
        .push(make_proxy("gwapi-route-httpbin", "ferrum"));
    k8s.mesh = Some(mesh_with_service("overlay-svc"));
    let managed = BTreeSet::from(["ferrum".to_string()]);
    store_accepted_k8s_overlay(&overlay_slot, k8s.clone(), managed);

    let mut db_reload = GatewayConfig::default();
    db_reload.proxies.push(make_proxy("db-proxy", "ferrum"));

    let config_arc = ArcSwap::from_pointee(GatewayConfig::default());
    let published =
        cas_publish_db_snapshot_with_k8s_overlay_for_test(&config_arc, &overlay_slot, db_reload);

    assert!(
        published.proxies.iter().any(|p| p.id == "db-proxy"),
        "DB resources must survive publication"
    );
    assert!(
        published
            .proxies
            .iter()
            .any(|p| p.id == "gwapi-route-httpbin"),
        "K8s overlay proxy must be re-merged across full reload"
    );
    assert!(
        published.mesh.is_some(),
        "mesh block from the overlay slot must survive full reload"
    );
    assert_eq!(
        compose_db_with_k8s_overlay(&GatewayConfig::default(), &overlay_slot)
            .proxies
            .len(),
        1,
        "compose helper must read the same slot"
    );
}

#[test]
fn overlay_slot_preserves_mesh_when_later_translate_omits_it() {
    // #2982: merge_k8s_translation keeps an existing mesh when a successful
    // translate omits mesh. The overlay slot must do the same — it is the only
    // mesh source on CP full-reload re-merge (DB snapshots clear mesh).
    let overlay_slot = empty_k8s_overlay_slot();
    let managed = BTreeSet::from(["ferrum".to_string()]);

    let mut with_mesh = GatewayConfig::default();
    with_mesh
        .proxies
        .push(make_proxy("gwapi-route-httpbin", "ferrum"));
    with_mesh.mesh = Some(mesh_with_service("overlay-svc"));
    store_accepted_k8s_overlay(&overlay_slot, with_mesh, managed.clone());

    let mut without_mesh = GatewayConfig::default();
    without_mesh
        .proxies
        .push(make_proxy("gwapi-route-httpbin", "ferrum"));
    store_accepted_k8s_overlay(&overlay_slot, without_mesh, managed);

    let mut db_reload = GatewayConfig::default();
    db_reload.proxies.push(make_proxy("db-proxy", "ferrum"));
    db_reload.mesh = None;

    let published = cas_publish_db_snapshot_with_k8s_overlay_for_test(
        &ArcSwap::from_pointee(GatewayConfig::default()),
        &overlay_slot,
        db_reload,
    );

    assert!(
        published.mesh.is_some(),
        "mesh accepted by an earlier translate must survive a later mesh-less \
         translate and the following DB full-reload re-merge"
    );
    let service_names = published.mesh.as_ref().map(|mesh| {
        mesh.services
            .iter()
            .map(|service| service.name.as_str())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        service_names,
        Some(vec!["overlay-svc"]),
        "preserved mesh must remain the previously accepted overlay mesh"
    );
}

#[test]
fn full_reload_with_no_refreshed_namespaces_leaves_subscribers_untouched() {
    // A full load whose every namespace was demoted (e.g. cursor reads failed)
    // must not CAS/broadcast: DPs and mesh keep last-known-good.
    let mut initial = GatewayConfig::default();
    initial.proxies.push(make_proxy("lkg", "ferrum"));
    let (harness, mut dp_rx) = PublicationHarness::new(initial.clone());
    let mut mesh_rx = harness.mesh_subscribe();

    let mut db_reload = GatewayConfig::default();
    db_reload
        .proxies
        .push(make_proxy("should-not-publish", "ferrum"));
    publish_cp_full_reload_for_test(
        &harness.gate,
        harness.config_arc.as_ref(),
        &harness.overlay_slot,
        db_reload,
        &[],
        harness.broadcasts.as_ref(),
        harness.dp_registry.as_ref(),
        &harness.cp_scope,
        &harness.mesh_tx,
        harness.mesh_registry.as_ref(),
    );

    assert_eq!(
        proxy_ids(&harness.config_arc.load_full()),
        proxy_ids(&initial),
        "empty refreshed set must not commit a DB snapshot"
    );
    assert!(
        drain(&mut dp_rx).is_empty(),
        "DP subscribers must see no emission"
    );
    assert!(
        drain(&mut mesh_rx).is_empty(),
        "mesh subscribers must see no emission"
    );
}

#[test]
fn per_namespace_incremental_rejection_keeps_sibling_lkg() {
    // #2983: invalid ns-b must not block ns-a refresh.
    let mut base = GatewayConfig::default();
    base.proxies.push(make_proxy("a-old", "ns-a"));
    base.proxies.push(make_proxy("b-old", "ns-b"));

    let mut ok_delta = empty_incremental();
    ok_delta.added_or_modified_proxies = vec![make_proxy("a-new", "ns-a")];
    ok_delta.removed_proxy_ids = vec![NamespacedResourceId::new("ns-a", "a-old")];

    let mut bad_delta = empty_incremental();
    let mut dangling = make_proxy("b-bad", "ns-b");
    dangling.upstream_id = Some("missing-upstream".to_string());
    bad_delta.added_or_modified_proxies = vec![dangling];
    bad_delta.removed_proxy_ids = vec![NamespacedResourceId::new("ns-b", "b-old")];

    let partitions = HashMap::from([
        ("ns-a".to_string(), ok_delta),
        ("ns-b".to_string(), bad_delta),
    ]);

    let (composed, accepted, rejected) =
        compose_incremental_partitions_for_test(&base, &partitions);

    assert_eq!(accepted, vec!["ns-a".to_string()]);
    assert_eq!(rejected, vec!["ns-b".to_string()]);
    assert!(
        composed.proxies.iter().any(|p| p.id == "a-new"),
        "valid namespace must refresh"
    );
    assert!(
        composed.proxies.iter().any(|p| p.id == "b-old"),
        "rejected namespace must retain last-known-good"
    );
    assert!(
        !composed.proxies.iter().any(|p| p.id == "b-bad"),
        "rejected namespace must not apply the invalid delta"
    );
}

#[test]
fn concurrent_poll_and_reconcile_cas_preserves_both_sources() {
    // #2984: poll CAS must not revert a concurrent reconciler overlay write.
    let mut db_base = GatewayConfig::default();
    db_base.proxies.push(make_proxy("db-base", "ferrum"));
    let config_arc = Arc::new(ArcSwap::from_pointee(db_base.clone()));

    let overlay_slot = empty_k8s_overlay_slot();
    let mut k8s = GatewayConfig::default();
    k8s.proxies
        .push(make_proxy("gwapi-route-overlay", "ferrum"));
    let managed = BTreeSet::from(["ferrum".to_string()]);
    store_accepted_k8s_overlay(&overlay_slot, k8s.clone(), managed.clone());

    let writer = {
        let config_arc = Arc::clone(&config_arc);
        let k8s = k8s.clone();
        let managed = managed.clone();
        thread::spawn(move || {
            for _ in 0..200 {
                let _ = swap_merged_k8s_translation(config_arc.as_ref(), &k8s, &managed);
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    let mut db_reload = db_base;
    db_reload.proxies.push(make_proxy("db-updated", "ferrum"));
    for _ in 0..50 {
        let _ = cas_publish_db_snapshot_with_k8s_overlay_for_test(
            config_arc.as_ref(),
            &overlay_slot,
            db_reload.clone(),
        );
        thread::sleep(Duration::from_micros(50));
    }

    writer.join().expect("reconciler thread");

    let final_config = config_arc.load_full();
    assert!(
        final_config
            .proxies
            .iter()
            .any(|p| p.id == "db-updated" || p.id == "db-base"),
        "DB-authored proxies must remain after concurrent publication"
    );
    assert!(
        final_config
            .proxies
            .iter()
            .any(|p| p.id == "gwapi-route-overlay"),
        "K8s overlay must not be lost to a concurrent poll store"
    );
}

#[test]
fn concurrent_incremental_cas_retains_reconciler_overlay() {
    let mut base = GatewayConfig::default();
    base.proxies.push(make_proxy("db-base", "ferrum"));
    let config_arc = Arc::new(ArcSwap::from_pointee(base));

    let mut k8s = GatewayConfig::default();
    k8s.proxies
        .push(make_proxy("gwapi-route-overlay", "ferrum"));
    let managed = BTreeSet::from(["ferrum".to_string()]);
    let _ = swap_merged_k8s_translation(config_arc.as_ref(), &k8s, &managed);

    let writer = {
        let config_arc = Arc::clone(&config_arc);
        let k8s = k8s.clone();
        let managed = managed.clone();
        thread::spawn(move || {
            for _ in 0..100 {
                let _ = swap_merged_k8s_translation(config_arc.as_ref(), &k8s, &managed);
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    let mut delta = empty_incremental();
    delta.added_or_modified_proxies = vec![make_proxy("db-delta", "ferrum")];
    let partitions = HashMap::from([("ferrum".to_string(), delta)]);

    for _ in 0..30 {
        let _ = cas_publish_incremental_partitions_for_test(config_arc.as_ref(), &partitions);
        thread::sleep(Duration::from_micros(50));
    }

    writer.join().expect("reconciler thread");

    let final_config = config_arc.load_full();
    assert!(
        final_config.proxies.iter().any(|p| p.id == "db-delta"),
        "incremental DB delta must commit"
    );
    assert!(
        final_config
            .proxies
            .iter()
            .any(|p| p.id == "gwapi-route-overlay"),
        "concurrent reconciler overlay must survive incremental CAS"
    );
}

// ── CP publication ordering ─────────────────────────────────────────────────
//
// CAS makes each commit atomic but says nothing about the emissions that follow
// it. The CP has two independent writers — the DB poll loop and the K8s
// reconciler — and both DP (`ConfigUpdate.version` is informational) and mesh
// (`MeshConfigBroadcast::Full` carries no generation) subscribers apply strictly
// in arrival order. So the only thing keeping a subscriber from ending on a
// snapshot older than `config_arc` is that commit order equals broadcast order,
// which is what `CpPublicationGate` enforces and what these tests assert.
//
// The assertions are interleaving-independent: they hold for EVERY schedule, so
// they never depend on sleeps or on winning a timing race.

const PUBLICATION_ROUNDS: usize = 150;
const TEST_BROADCAST_CAPACITY: usize = 8192;

/// Everything the two CP writers publish through, wired to real broadcast
/// channels so the tests observe exactly what a DP and a mesh node would.
struct PublicationHarness {
    gate: CpPublicationGate,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasts: Arc<NamespaceBroadcasts>,
    dp_registry: Arc<DpNodeRegistry>,
    cp_scope: CpScope,
    mesh_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
}

impl PublicationHarness {
    fn new(initial: GatewayConfig) -> (Self, broadcast::Receiver<ConfigUpdate>) {
        let broadcasts = Arc::new(NamespaceBroadcasts::new(TEST_BROADCAST_CAPACITY));
        // Subscribe before any publication: the broadcast helpers no-op when no
        // channel exists for the namespace yet.
        let dp_rx = broadcasts.sender_for("ferrum").subscribe();
        let (mesh_tx, _) = broadcast::channel(TEST_BROADCAST_CAPACITY);
        let harness = Self {
            gate: CpPublicationGate::new(),
            config_arc: Arc::new(ArcSwap::from_pointee(initial)),
            overlay_slot: empty_k8s_overlay_slot(),
            broadcasts,
            dp_registry: Arc::new(DpNodeRegistry::new()),
            cp_scope: CpScope::Single("ferrum".to_string()),
            mesh_tx,
            mesh_registry: Arc::new(MeshNodeRegistry::new()),
        };
        (harness, dp_rx)
    }

    fn mesh_subscribe(&self) -> broadcast::Receiver<MeshConfigBroadcast> {
        self.mesh_tx.subscribe()
    }

    fn publish_full_db_snapshot(&self, db_config: GatewayConfig) {
        publish_cp_full_reload_for_test(
            &self.gate,
            self.config_arc.as_ref(),
            &self.overlay_slot,
            db_config,
            &["ferrum".to_string()],
            self.broadcasts.as_ref(),
            self.dp_registry.as_ref(),
            &self.cp_scope,
            &self.mesh_tx,
            self.mesh_registry.as_ref(),
        );
    }

    fn publish_incremental(&self, partitions: &HashMap<String, IncrementalResult>, round: usize) {
        publish_cp_incremental_for_test(
            &self.gate,
            self.config_arc.as_ref(),
            partitions,
            &format!("delta-{round}"),
            round as u64,
            Utc::now(),
            self.broadcasts.as_ref(),
            self.dp_registry.as_ref(),
            &self.cp_scope,
            &self.mesh_tx,
            self.mesh_registry.as_ref(),
        );
    }

    fn publish_reconcile(&self, translation: &GatewayConfig, managed: &BTreeSet<String>) {
        publish_k8s_reconcile(
            &self.gate,
            self.config_arc.as_ref(),
            &self.overlay_slot,
            translation,
            managed,
            "ferrum",
            self.broadcasts.as_ref(),
            self.dp_registry.as_ref(),
            &self.cp_scope,
            &self.mesh_tx,
            self.mesh_registry.as_ref(),
        );
    }
}

fn proxy_ids(config: &GatewayConfig) -> BTreeSet<String> {
    config.proxies.iter().map(|p| p.id.clone()).collect()
}

fn json_ids(payload: &serde_json::Value, field: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let Some(items) = payload.get(field).and_then(|value| value.as_array()) else {
        return ids;
    };
    for item in items {
        if let Some(id) = item.get("id").and_then(|id| id.as_str()) {
            ids.push(id.to_string());
        }
    }
    ids
}

fn json_strings(payload: &serde_json::Value, field: &str) -> Vec<String> {
    let mut values = Vec::new();
    let Some(items) = payload.get(field).and_then(|value| value.as_array()) else {
        return values;
    };
    for item in items {
        if let Some(value) = item.as_str() {
            values.push(value.to_string());
        }
    }
    values
}

/// Fold a mesh broadcast into the state a mesh node would hold, exactly as a
/// subscriber does: `Full` replaces, `Delta` applies on top, arrival order only.
fn apply_mesh_event(state: &mut BTreeSet<String>, event: &MeshConfigBroadcast) {
    match event {
        MeshConfigBroadcast::Full(config) => *state = proxy_ids(config),
        MeshConfigBroadcast::Delta { result, .. } => {
            for proxy in &result.added_or_modified_proxies {
                state.insert(proxy.id.clone());
            }
            for key in &result.removed_proxy_ids {
                state.remove(&key.id);
            }
        }
    }
}

/// The same fold over the wire payload the CP actually sends to a DP.
fn apply_dp_event(state: &mut BTreeSet<String>, update: &ConfigUpdate) {
    let payload: serde_json::Value =
        serde_json::from_str(&update.config_json).expect("CP payload must be JSON");
    if update.update_type == 0 {
        *state = json_ids(&payload, "proxies").into_iter().collect();
        return;
    }
    for id in json_ids(&payload, "added_or_modified_proxies") {
        state.insert(id);
    }
    for id in json_strings(&payload, "removed_proxy_ids") {
        state.remove(&id);
    }
}

fn drain<T: Clone>(rx: &mut broadcast::Receiver<T>) -> Vec<T> {
    let mut events = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(event) => events.push(event),
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                panic!("test subscriber lagged by {skipped}; raise the capacity")
            }
            Err(_) => break,
        }
    }
    events
}

fn k8s_translation(round: usize) -> GatewayConfig {
    let mut translation = GatewayConfig::default();
    let proxy = make_proxy(&format!("gwapi-route-{round}"), "ferrum");
    translation.proxies.push(proxy);
    translation
}

#[test]
fn publication_gate_orders_a_second_publisher_after_the_first() {
    // The primitive contract: no publication may begin while another is in
    // flight, so a commit can never be separated from its own broadcasts.
    let gate = CpPublicationGate::new();
    let entered = Arc::new(std::sync::Barrier::new(2));
    let (order_tx, order_rx) = mpsc::channel::<&'static str>();

    let second = {
        let gate = gate.clone();
        let entered = Arc::clone(&entered);
        let order_tx = order_tx.clone();
        thread::spawn(move || {
            entered.wait();
            gate.publish(|| {
                let _ = order_tx.send("second");
            });
        })
    };

    gate.publish(|| {
        // Release the second publisher only once this section is open. It can
        // record itself only from inside its own section, which cannot begin
        // until this one ends, so "first" is always recorded first.
        entered.wait();
        let _ = order_tx.send("first");
    });

    second.join().expect("second publisher thread");
    drop(order_tx);
    let observed: Vec<&'static str> = order_rx.iter().collect();
    assert_eq!(
        observed,
        vec!["first", "second"],
        "sections must not overlap"
    );
}

#[test]
fn competing_full_publications_never_end_on_a_stale_snapshot() {
    // Full-vs-full: the poller commits a DB snapshot while the reconciler
    // commits DB+overlay. Without shared ordering the poller can broadcast its
    // older snapshot after the reconciler broadcast the newer one, leaving
    // every DP and mesh node permanently behind `config_arc`.
    let mut initial = GatewayConfig::default();
    initial.proxies.push(make_proxy("db-0", "ferrum"));
    let (harness, mut dp_rx) = PublicationHarness::new(initial);
    let mut mesh_rx = harness.mesh_subscribe();
    let harness = Arc::new(harness);
    let managed = BTreeSet::from(["ferrum".to_string()]);

    let reconciler = {
        let harness = Arc::clone(&harness);
        let managed = managed.clone();
        thread::spawn(move || {
            for round in 1..=PUBLICATION_ROUNDS {
                harness.publish_reconcile(&k8s_translation(round), &managed);
            }
        })
    };

    for round in 1..=PUBLICATION_ROUNDS {
        let proxy = make_proxy(&format!("db-{round}"), "ferrum");
        let mut db_config = GatewayConfig::default();
        db_config.proxies.push(proxy);
        harness.publish_full_db_snapshot(db_config);
    }
    reconciler.join().expect("reconciler thread");

    let committed = proxy_ids(&harness.config_arc.load_full());

    let mesh_events = drain(&mut mesh_rx);
    assert!(!mesh_events.is_empty(), "mesh subscribers must see traffic");
    let mut mesh_state = BTreeSet::new();
    for event in &mesh_events {
        apply_mesh_event(&mut mesh_state, event);
    }
    assert_eq!(
        mesh_state, committed,
        "mesh must end on the committed snapshot"
    );

    let dp_events = drain(&mut dp_rx);
    assert!(!dp_events.is_empty(), "DP subscribers must see traffic");
    let mut dp_state = BTreeSet::new();
    for event in &dp_events {
        apply_dp_event(&mut dp_state, event);
    }
    assert_eq!(dp_state, committed, "DP must end on the committed snapshot");
}

#[test]
fn reconcile_full_never_erases_a_newer_committed_poll_delta() {
    // Reconcile-full vs poll-delta — the dangerous direction. A full snapshot
    // computed before a delta commits but emitted after it would silently roll
    // that delta back in every subscriber while `config_arc` still holds it.
    let mut initial = GatewayConfig::default();
    initial.proxies.push(make_proxy("db-base", "ferrum"));
    let (harness, mut dp_rx) = PublicationHarness::new(initial.clone());
    let mut mesh_rx = harness.mesh_subscribe();
    let harness = Arc::new(harness);
    let managed = BTreeSet::from(["ferrum".to_string()]);

    let reconciler = {
        let harness = Arc::clone(&harness);
        let managed = managed.clone();
        thread::spawn(move || {
            for round in 1..=PUBLICATION_ROUNDS {
                harness.publish_reconcile(&k8s_translation(round), &managed);
            }
        })
    };

    for round in 1..=PUBLICATION_ROUNDS {
        let mut delta = empty_incremental();
        delta.added_or_modified_proxies = vec![make_proxy(&format!("db-delta-{round}"), "ferrum")];
        let partitions = HashMap::from([("ferrum".to_string(), delta)]);
        harness.publish_incremental(&partitions, round);
    }
    reconciler.join().expect("reconciler thread");

    let committed = proxy_ids(&harness.config_arc.load_full());
    for round in 1..=PUBLICATION_ROUNDS {
        let id = format!("db-delta-{round}");
        assert!(committed.contains(&id), "accepted deltas must be committed");
    }

    // Replaying the emissions in arrival order must land exactly on the
    // committed snapshot: no full may have overwritten a delta that was already
    // committed when that full was emitted.
    let mesh_events = drain(&mut mesh_rx);
    let mut mesh_state = proxy_ids(&initial);
    for event in &mesh_events {
        apply_mesh_event(&mut mesh_state, event);
    }
    assert_eq!(mesh_state, committed, "a stale full must not erase a delta");

    let dp_events = drain(&mut dp_rx);
    let mut dp_state = proxy_ids(&initial);
    for event in &dp_events {
        apply_dp_event(&mut dp_state, event);
    }
    assert_eq!(dp_state, committed, "the DP stream must not roll back");
}
