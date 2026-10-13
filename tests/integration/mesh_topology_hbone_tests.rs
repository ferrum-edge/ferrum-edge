//! Topology-level mesh tests: listener plan + plugin-injection
//! differences across `Ambient`, `NodeWaypoint`, `ServiceWaypoint`,
//! `EastWestGateway`, and `EgressGateway`, plus HBONE baggage parsing
//! semantics.
//!
//! End-to-end CONNECT-relay behaviour for HBONE is already covered in
//! `mesh_hbone_tests.rs`; the focus here is the topology contract
//! (which listeners get spawned, which auto-injected plugins differ)
//! and the baggage-identity boundary that mesh_authz / spiffe_identity
//! depend on.

use std::collections::HashMap;

use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::OutboundTrafficPolicy;
use ferrum_edge::modes::mesh::hbone::{
    BAGGAGE_HEADER, HboneIdentity, baggage_header_for_source, is_authenticated_hbone_connect,
    is_hbone_connect,
};
use ferrum_edge::modes::mesh::{
    MESH_ACCESS_LOG_PLUGIN_ID, MESH_AUTHZ_PLUGIN_ID, MESH_BPF_METRICS_PLUGIN_ID,
    MESH_OUTBOUND_REGISTRY_PLUGIN_ID, MESH_REQUEST_AUTH_PLUGIN_ID, MESH_SPIFFE_IDENTITY_PLUGIN_ID,
    MESH_WORKLOAD_METRICS_PLUGIN_ID, MeshListenerKind, MeshTopology, MeshTrafficDirection,
    prepare_gateway_config_for_mesh,
};
use http::{HeaderMap, HeaderValue, Method, Version};

use super::mesh_test_support::{
    gateway_config_with_mesh, mesh_config_with, runtime_for_topology, service_for, workload_for,
};
use ferrum_edge::identity::SpiffeId;

// ── Topology listener plans ───────────────────────────────────────────────

#[test]
fn ambient_topology_runs_outbound_capture_and_hbone_inbound() {
    let plan = runtime_for_topology(MeshTopology::Ambient).listener_plan();
    assert_eq!(plan.len(), 2);
    let outbound = plan
        .iter()
        .find(|l| l.direction == MeshTrafficDirection::Outbound)
        .expect("ambient still keeps outbound capture");
    assert_eq!(outbound.kind, MeshListenerKind::PlaintextCapture);
    let inbound = plan
        .iter()
        .find(|l| l.direction == MeshTrafficDirection::Inbound)
        .expect("ambient terminates HBONE inbound");
    assert_eq!(inbound.kind, MeshListenerKind::HboneTermination);
}

#[test]
fn node_waypoint_topology_only_runs_hbone_inbound() {
    // Node-waypoint is shared by every pod on the node — no outbound
    // capture (those are per-pod sidecar/ambient concerns), only the
    // HBONE inbound listener that accepts ztunnel traffic.
    let plan = runtime_for_topology(MeshTopology::NodeWaypoint).listener_plan();
    assert_eq!(plan.len(), 1);
    let listener = &plan[0];
    assert_eq!(listener.direction, MeshTrafficDirection::Inbound);
    assert_eq!(listener.kind, MeshListenerKind::HboneTermination);
}

#[test]
fn service_waypoint_topology_only_runs_hbone_inbound() {
    let plan = runtime_for_topology(MeshTopology::ServiceWaypoint).listener_plan();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].direction, MeshTrafficDirection::Inbound);
    assert_eq!(plan[0].kind, MeshListenerKind::HboneTermination);
}

#[test]
fn east_west_gateway_topology_runs_no_listeners_from_plan() {
    // East-west gateway materialises its listeners from the slice's
    // EastWestGateway resource via `materialize_east_west_gateway_proxies`
    // — the static listener plan returns nothing. Locks in the
    // separation so a refactor doesn't accidentally double-bind.
    let plan = runtime_for_topology(MeshTopology::EastWestGateway).listener_plan();
    assert!(
        plan.is_empty(),
        "east-west gateway listeners come from materialise path, not listener_plan, got {plan:?}"
    );
}

#[test]
fn egress_gateway_topology_runs_mesh_internal_mtls_inbound() {
    let plan = runtime_for_topology(MeshTopology::EgressGateway).listener_plan();
    assert_eq!(plan.len(), 1);
    let listener = &plan[0];
    assert_eq!(listener.direction, MeshTrafficDirection::Inbound);
    assert_eq!(
        listener.kind,
        MeshListenerKind::MtlsTermination,
        "egress gateway terminates mTLS from sidecars on its internal port"
    );
}

#[test]
fn topology_predicates_match_listener_plan_shape() {
    // The convenience predicates on `MeshTopology` are used by listener
    // spawning and admin endpoints — guard against a future drift
    // where a topology starts terminating HBONE but `terminates_hbone()`
    // still returns false.
    for topology in [
        MeshTopology::Sidecar,
        MeshTopology::Ambient,
        MeshTopology::NodeWaypoint,
        MeshTopology::ServiceWaypoint,
        MeshTopology::EastWestGateway,
        MeshTopology::EgressGateway,
    ] {
        let plan = runtime_for_topology(topology).listener_plan();
        let has_hbone = plan
            .iter()
            .any(|l| l.kind == MeshListenerKind::HboneTermination);
        assert_eq!(
            topology.terminates_hbone(),
            has_hbone,
            "terminates_hbone() should align with listener plan for {topology:?}"
        );
        assert_eq!(
            topology.is_waypoint(),
            matches!(
                topology,
                MeshTopology::NodeWaypoint | MeshTopology::ServiceWaypoint
            )
        );
    }
}

// ── Plugin injection differences by topology ──────────────────────────────

#[test]
fn ambient_topology_injects_same_core_plugins_as_sidecar() {
    // Ambient and sidecar share the same core plugin chain (identity,
    // authz, workload metrics, access log). The transport differs (HBONE
    // vs sidecar inbound mTLS) but the L7 enforcement is identical.
    let runtime = runtime_for_topology(MeshTopology::Ambient);
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
    let mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("ambient prepared");
    let ids: std::collections::HashSet<_> = prepared
        .plugin_configs
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    for required in [
        MESH_SPIFFE_IDENTITY_PLUGIN_ID,
        MESH_AUTHZ_PLUGIN_ID,
        MESH_WORKLOAD_METRICS_PLUGIN_ID,
        MESH_ACCESS_LOG_PLUGIN_ID,
    ] {
        assert!(
            ids.contains(required),
            "ambient must inject {required}, got {ids:?}"
        );
    }
    assert!(
        !ids.contains(MESH_BPF_METRICS_PLUGIN_ID),
        "ambient must NOT inject bpf_metrics — only NodeWaypoint runs the SOCK_OPS BPF program"
    );
}

#[test]
fn node_waypoint_topology_injects_bpf_metrics() {
    // NodeWaypoint is the only topology that runs the SOCK_OPS BPF
    // program; auto-injecting bpf_metrics anywhere else would emit
    // always-zero counters and mislead operator dashboards.
    let runtime = runtime_for_topology(MeshTopology::NodeWaypoint);
    let workload = workload_for(
        "shared-waypoint",
        "default",
        [("app", "waypoint")],
        ["10.0.0.1"],
    );
    let mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("node-waypoint prepared");
    let ids: std::collections::HashSet<_> = prepared
        .plugin_configs
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert!(
        ids.contains(MESH_BPF_METRICS_PLUGIN_ID),
        "NodeWaypoint must auto-inject bpf_metrics, got {ids:?}"
    );
}

#[test]
fn registry_only_outbound_policy_injects_outbound_registry_plugin_for_sidecar() {
    // When the runtime requests `REGISTRY_ONLY` outbound traffic, the
    // slice-apply path must inject `mesh_outbound_registry` so the
    // sidecar rejects unknown destinations with `reject_status`.
    //
    // Note: `runtime_for_topology` uses `outbound_listen_addr: 127.0.0.1:0`
    // for ephemeral binding in tests that spawn real listeners. The mesh
    // injection path correctly skips the plugin when the outbound listener
    // port is 0 (no listener to enforce against — see
    // `inject_mesh_global_plugins_skips_outbound_registry_when_outbound_port_is_zero`).
    // Override to a concrete production-shaped port so the projection path
    // injects the plugin.
    let mut runtime = runtime_for_topology(MeshTopology::Sidecar);
    runtime.outbound_traffic_policy = OutboundTrafficPolicy::RegistryOnly;
    runtime.outbound_listen_addr = "127.0.0.1:15001".parse().expect("addr");
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
    let registry_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
    assert!(
        registry_plugin.is_some(),
        "REGISTRY_ONLY outbound policy must inject mesh_outbound_registry, got {:?}",
        prepared
            .plugin_configs
            .iter()
            .map(|p| &p.id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn allow_any_outbound_policy_omits_outbound_registry_plugin() {
    // AllowAny is the default and must NOT inject the registry plugin
    // (keeps the per-request hot path allocation-free for permissive
    // deployments).
    let mut runtime = runtime_for_topology(MeshTopology::Sidecar);
    runtime.outbound_traffic_policy = OutboundTrafficPolicy::AllowAny;
    let mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
    assert!(
        prepared
            .plugin_configs
            .iter()
            .all(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID),
        "AllowAny outbound must not inject outbound registry plugin"
    );
}

#[test]
fn request_authentication_plugin_only_injected_when_jwt_rules_present() {
    // The `__mesh_request_auth` plugin is opt-in: it must appear only
    // when at least one `MeshRequestAuthentication` resource declares a
    // JWT rule. Plugin chains in deployments without JWT requirements
    // should not pay the per-request cost.
    use ferrum_edge::modes::mesh::config::{MeshJwtRule, MeshRequestAuthentication, PolicyScope};

    // Case 1: no request_authentications → plugin absent.
    {
        let runtime = runtime_for_topology(MeshTopology::Sidecar);
        let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
        let mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
        let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
        let plugin_ids: std::collections::HashSet<_> = prepared
            .plugin_configs
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert!(
            !plugin_ids.contains(MESH_REQUEST_AUTH_PLUGIN_ID),
            "no JWT rules → request_auth plugin should NOT be injected, got {plugin_ids:?}"
        );
    }

    // Case 2: a MeshRequestAuthentication carries a JWT rule → plugin
    // present.
    {
        let runtime = runtime_for_topology(MeshTopology::Sidecar);
        let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
        let mut mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
        mesh.request_authentications
            .push(MeshRequestAuthentication {
                name: "issuer".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                jwt_rules: vec![MeshJwtRule {
                    issuer: "https://issuer.example.com".to_string(),
                    audiences: vec!["api".to_string()],
                    jwks_uri: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
                    jwks: None,
                    from_headers: Vec::new(),
                    from_params: Vec::new(),
                    forward_original_token: false,
                    output_claim_to_headers: Vec::new(),
                }],
            });
        let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
        let plugin_ids: std::collections::HashSet<_> = prepared
            .plugin_configs
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert!(
            plugin_ids.contains(MESH_REQUEST_AUTH_PLUGIN_ID),
            "JWT rule present → request_auth plugin must be injected, got {plugin_ids:?}"
        );
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");
        assert_eq!(
            jwks.config["providers"][0]["issuer"].as_str(),
            Some("https://issuer.example.com")
        );
        assert_eq!(
            jwks.config["providers"][0]["audiences"],
            serde_json::json!(["api"])
        );
        assert_eq!(
            jwks.config["emit_mesh_request_principal_metadata"],
            serde_json::json!(true)
        );
        // Permissive missing-token handling is an explicit opt-in on the
        // mesh-generated instance, never implied by the metadata flag.
        assert_eq!(jwks.config["allow_missing_token"], serde_json::json!(true));
        // Mesh injection carries no cooldown knob, so the injected generation
        // inherits the shared store's default unknown-`kid` refetch: an IdP
        // rotation recovers for mesh workloads exactly as it does for a
        // directly configured `jwks_auth` (issue #4508).
        assert!(
            jwks.config
                .get("kid_miss_refresh_cooldown_seconds")
                .is_none(),
            "mesh must not invent a cooldown knob"
        );
        let injected = ferrum_edge::plugins::jwks_auth::JwksAuth::new(
            &jwks.config,
            ferrum_edge::plugins::PluginHttpClient::default(),
        )
        .expect("injected mesh request-auth config must construct");
        let store = injected
            .remote_jwks_stores_for_test()
            .first()
            .cloned()
            .expect("the injected provider has a remote JWKS store");
        assert_eq!(
            store.kid_miss_cooldown(),
            std::time::Duration::from_secs(
                ferrum_edge::plugins::jwks_auth::DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS
            )
        );
        store.request_refresh_on_kid_miss();
        assert_eq!(
            store.kid_miss_refresh_requests(),
            1,
            "the on-demand refetch path must be reachable from mesh RequestAuthentication"
        );
    }
}

// ── HBONE baggage parsing ─────────────────────────────────────────────────

fn baggage_header(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(BAGGAGE_HEADER, HeaderValue::from_str(value).expect("hdr"));
    headers
}

#[test]
fn baggage_header_round_trips_through_parser() {
    // The encoder produces a header value that the decoder reads back
    // into the same SPIFFE id. Locks in the contract that
    // `baggage_header_for_source` produces is decodable by
    // `HboneIdentity::from_headers`.
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("id");
    let header_value = baggage_header_for_source(&id);
    let headers = baggage_header(&header_value);
    let identity = HboneIdentity::from_headers(&headers);
    assert_eq!(
        identity.source_principal.as_ref(),
        Some(&id),
        "round-tripped baggage should parse back to the original SPIFFE id"
    );
}

#[test]
fn baggage_parser_accepts_alternate_key_names_for_source_principal() {
    // Istio + downstream OpenTelemetry contributors use a few aliases
    // for the source-principal key. The parser must accept the
    // documented set so we don't depend on one implementation's
    // spelling.
    for key in [
        "source.principal",
        "source_principal",
        "source.identity",
        "source_identity",
        "src.identity",
        "src_identity",
    ] {
        let raw = format!("{key}=spiffe%3A%2F%2Fcluster.local%2Fns%2Fdefault%2Fsa%2Fclient");
        let headers = baggage_header(&raw);
        let identity = HboneIdentity::from_headers(&headers);
        assert!(
            identity.source_principal.is_some(),
            "baggage key {key} should parse the source principal, got {:?}",
            identity.source_principal
        );
    }
}

#[test]
fn baggage_parser_ignores_keys_outside_the_documented_principal_alias_set() {
    // A baggage entry that happens to look like a SPIFFE id under a
    // foreign key must NOT be promoted to source_principal —
    // otherwise an attacker could inject a different baggage key and
    // bypass identity checks.
    let raw = "user.principal=spiffe%3A%2F%2Ftd%2Fns%2Fa%2Fsa%2Fb";
    let headers = baggage_header(raw);
    let identity = HboneIdentity::from_headers(&headers);
    assert!(
        identity.source_principal.is_none(),
        "non-canonical baggage key must NOT populate source_principal, got {:?}",
        identity.source_principal
    );
}

#[test]
fn is_hbone_connect_accepts_plain_http2_connect_without_marker_header() {
    // `is_hbone_connect` is the wire-*shape* detector: Istio's HBONE
    // definition is "HTTP/2 CONNECT over mTLS", so a plain H2 CONNECT is
    // HBONE-shaped without an `x-ferrum-mesh-protocol` marker. Shape alone
    // does NOT authorize relaying — that requires an authenticated peer via
    // `is_authenticated_hbone_connect` (see below).
    let headers = HeaderMap::new();
    assert!(is_hbone_connect(
        &Method::CONNECT,
        Version::HTTP_2,
        &headers
    ));
}

#[test]
fn is_hbone_connect_rejects_non_connect_methods_and_non_h2() {
    let headers = HeaderMap::new();
    assert!(
        !is_hbone_connect(&Method::GET, Version::HTTP_2, &headers),
        "GET is not HBONE"
    );
    assert!(
        !is_hbone_connect(&Method::CONNECT, Version::HTTP_11, &headers),
        "H1 CONNECT is not HBONE — HBONE requires H2 framing for the inner stream"
    );
}

#[test]
fn is_hbone_connect_rejects_explicit_non_hbone_protocol_marker() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-istio-protocol",
        HeaderValue::from_static("connect-tunnel"),
    );
    assert!(!is_hbone_connect(
        &Method::CONNECT,
        Version::HTTP_2,
        &headers
    ));
}

#[test]
fn is_hbone_connect_accepts_explicit_marker_when_value_is_hbone() {
    let mut headers = HeaderMap::new();
    headers.insert("x-istio-protocol", HeaderValue::from_static("hbone"));
    assert!(is_hbone_connect(
        &Method::CONNECT,
        Version::HTTP_2,
        &headers
    ));
}

// ── HBONE relay trust boundary (mesh audit finding #2) ──────────────────

#[test]
fn is_authenticated_hbone_connect_rejects_bare_connect_without_peer() {
    // The finding: a marker-less HTTP/2 CONNECT with no authenticated peer is
    // HBONE-shaped but must NOT be authorized for relay as a transparent TCP
    // tunnel.
    let headers = HeaderMap::new();
    assert!(
        is_hbone_connect(&Method::CONNECT, Version::HTTP_2, &headers),
        "precondition: bare H2 CONNECT is HBONE-shaped"
    );
    assert!(
        !is_authenticated_hbone_connect(&Method::CONNECT, Version::HTTP_2, &headers, None),
        "bare CONNECT with no authenticated peer must not be relayed as HBONE"
    );
}

#[test]
fn is_authenticated_hbone_connect_admits_authenticated_peer() {
    // A verified mTLS peer (the steady state for real ztunnel/waypoint HBONE)
    // is authorized for relay, with or without an explicit marker header.
    let peer = SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("spiffe id");

    let bare = HeaderMap::new();
    assert!(is_authenticated_hbone_connect(
        &Method::CONNECT,
        Version::HTTP_2,
        &bare,
        Some(&peer),
    ));

    let mut marker = HeaderMap::new();
    marker.insert("x-istio-protocol", HeaderValue::from_static("hbone"));
    assert!(is_authenticated_hbone_connect(
        &Method::CONNECT,
        Version::HTTP_2,
        &marker,
        Some(&peer),
    ));
}

#[test]
fn is_authenticated_hbone_connect_marker_does_not_bypass_peer_requirement() {
    // The explicit-marker path is not a back door: a CONNECT that merely
    // asserts `x-istio-protocol: hbone` without a verified peer is rejected.
    let mut headers = HeaderMap::new();
    headers.insert("x-istio-protocol", HeaderValue::from_static("hbone"));
    assert!(
        !is_authenticated_hbone_connect(&Method::CONNECT, Version::HTTP_2, &headers, None),
        "marker header must not authorize an unauthenticated peer"
    );
}

// ── Trust-domain alias plumbing on MeshRuntimeConfig ─────────────────────

#[test]
fn trust_domain_aliases_round_trip_through_runtime_config() {
    let mut runtime = runtime_for_topology(MeshTopology::Ambient);
    runtime
        .trust_domain_aliases
        .push(TrustDomain::new("aliased.local").expect("td"));
    runtime
        .trust_domain_aliases
        .push(TrustDomain::new("aliased.global").expect("td"));
    assert_eq!(runtime.trust_domain_aliases.len(), 2);
    assert_eq!(
        runtime.trust_domain_aliases[0].as_str(),
        "aliased.local",
        "aliases preserved in insertion order"
    );
}

#[test]
fn workload_labels_round_trip_through_runtime_config() {
    // The slice projection reads `MeshRuntimeConfig.workload_labels`
    // and stamps them onto the slice for downstream scope filtering.
    // Verify the field carries the env-var-shaped data unchanged.
    let mut runtime = runtime_for_topology(MeshTopology::Sidecar);
    runtime
        .workload_labels
        .extend([("app".to_string(), "reviews".to_string())]);
    assert_eq!(
        runtime.workload_labels.get("app").map(String::as_str),
        Some("reviews")
    );

    let mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
    let authz = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected");
    let labels = authz
        .config
        .get("mesh_slice")
        .and_then(|v| v.get("labels"))
        .and_then(|v| v.as_object())
        .expect("slice carries labels");
    assert_eq!(
        labels.get("app").and_then(|v| v.as_str()),
        Some("reviews"),
        "runtime workload_labels must propagate into mesh_slice.labels for mesh_authz scope filter"
    );
}

#[test]
fn unsupported_topology_string_parses_with_error_not_panic() {
    // Defensive: an unknown FERRUM_MESH_TOPOLOGY value should produce
    // a clean error, not panic. Locks in the operator-friendly
    // surface; if MeshTopology::parse ever changes shape this test
    // catches the regression.
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::modes::mesh::MeshRuntimeConfig;

    // Build a clean EnvConfig with bogus FERRUM_MESH_TOPOLOGY via a
    // direct env var override — the `MeshRuntimeConfig::from_env_config`
    // path reads from `FERRUM_MESH_TOPOLOGY`.
    let prev = std::env::var("FERRUM_MESH_TOPOLOGY").ok();
    // Safe in a single-threaded test: from_env_config is the only
    // path that reads it here.
    // SAFETY: `set_var` is called only from this test; no other thread reads
    // FERRUM_MESH_TOPOLOGY for the duration of this test.
    unsafe {
        std::env::set_var("FERRUM_MESH_TOPOLOGY", "definitely-not-a-topology");
    }
    let env_config = EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        // Provide the required CP-gRPC URL list so we get past the
        // initial "required-field" guard and reach topology parsing.
        dp_cp_grpc_urls: vec!["http://127.0.0.1:1".to_string()],
        ..EnvConfig::default()
    };
    let result = MeshRuntimeConfig::from_env_config(&env_config);
    // Restore env var before asserting so a failure doesn't pollute
    // the rest of the test binary's env.
    // SAFETY: same as above; single-threaded restore.
    unsafe {
        match prev {
            Some(value) => std::env::set_var("FERRUM_MESH_TOPOLOGY", value),
            None => std::env::remove_var("FERRUM_MESH_TOPOLOGY"),
        }
    }
    let err = result.expect_err("unknown topology must produce an error");
    assert!(
        err.contains("FERRUM_MESH_TOPOLOGY"),
        "error should name the offending env var, got {err:?}"
    );
}

// Use HashMap to keep the import resolved in case future tests need it.
#[allow(dead_code)]
fn _unused_label_anchor() -> HashMap<String, String> {
    HashMap::new()
}
