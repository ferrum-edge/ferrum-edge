//! East-West gateway + Egress gateway materialization coverage.
//!
//! Locks in the cold-path proxy/upstream materialization that
//! `prepare_gateway_config_for_mesh` performs only on the relevant
//! topology:
//!
//! - `EastWestGateway`: SNI-passthrough TCP proxies from
//!   `MultiClusterConfig.east_west_gateways` AND per-service
//!   passthrough proxies for local mesh services.
//! - `EgressGateway`: HTTP-family proxies AND stream-family TCP proxies
//!   (T5-A) from `ServiceEntry` resources with `location: MESH_EXTERNAL`.
//!
//! The materialisation is topology-gated — running on any other
//! topology must be a no-op so a flag flip doesn't accidentally double-
//! bind. The tests also verify the materialisation correctly skips
//! resources that should not be projected (wrong location, empty
//! hosts, no exported scope, no reachable workloads).

use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, MultiClusterConfig, Resolution, ServiceEntry,
    ServiceEntryLocation, ServicePort,
};
use ferrum_edge::modes::mesh::prepare_gateway_config_for_mesh;
use ferrum_edge::modes::mesh::{MeshTopology, runtime::MeshRuntimeState};

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, default_mesh_runtime, gateway_config_with_mesh, mesh_config_with,
    runtime_for_topology, service_for, workload_for,
};

// ── East-West gateway materialization ─────────────────────────────────────

fn east_west_gateway(name: &str, sni_hosts: Vec<&str>) -> EastWestGateway {
    EastWestGateway {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        host: "10.0.0.42".to_string(),
        port: 15443,
        sni_hosts: sni_hosts.into_iter().map(String::from).collect(),
        trust_domain: Some(TrustDomain::new("cluster.local").expect("td")),
        network: Some("network-1".to_string()),
    }
}

fn east_west_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::EastWestGateway);
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    runtime.east_west_listen_port = 15443;
    runtime
}

#[test]
fn east_west_gateway_materializes_sni_passthrough_proxy_from_remote_gateway_config() {
    // Explicit EastWestGateway entry in MultiClusterConfig produces a
    // passthrough TCP proxy on the east-west listen port. This is the
    // "remote gateway backend" flow — operators declare a remote
    // cluster's external east-west gateway and we materialise a
    // passthrough proxy that fronts it.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![east_west_gateway(
            "remote-cluster-gw",
            vec!["remote-svc.default.svc.cluster.local"],
        )],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("east-west prepared");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id.starts_with("__mesh-east-west-"))
        .expect("east-west gateway proxy materialised");
    assert_eq!(
        proxy.listen_port,
        Some(15443),
        "proxy must bind east-west listen port"
    );
    assert!(
        proxy.passthrough,
        "east-west proxy is SNI passthrough (no TLS termination)"
    );
    assert_eq!(
        proxy.hosts,
        vec!["remote-svc.default.svc.cluster.local".to_string()],
        "SNI hosts copied onto the proxy.hosts list"
    );
    assert_eq!(proxy.backend_host, "10.0.0.42");
    assert_eq!(proxy.backend_port, 15443);
}

#[test]
fn east_west_gateway_materializes_local_service_proxies_for_sni_routing() {
    // Workloads + services in the mesh slice produce per-service
    // passthrough proxies so inbound cross-cluster traffic SNI-routes
    // to the right local workload. The SNI host is the service FQDN.
    let workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.5", "10.0.0.6"],
    );
    let service = service_for("reviews", DEFAULT_NAMESPACE, &[&workload]);
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("east-west prepared");

    // One proxy per service, materialised with the FQDN SNI host.
    let service_proxy = prepared
        .proxies
        .iter()
        .find(|p| {
            p.hosts
                .iter()
                .any(|h| h.contains("reviews.default.svc.cluster.local"))
        })
        .expect("east-west service proxy materialised");
    assert!(service_proxy.passthrough);
    assert_eq!(service_proxy.listen_port, Some(15443));

    // One upstream per service with the workload addresses as targets.
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id.contains("reviews"))
        .expect("east-west upstream materialised");
    assert!(
        upstream.targets.len() >= 2,
        "upstream must carry both workload addresses, got {:?}",
        upstream.targets.iter().map(|t| &t.host).collect::<Vec<_>>()
    );
}

/// Multi-port east-west (issue #2010 phase 3): a service with two HTTP ports
/// materializes ONE SNI-passthrough proxy PER port — the first on the base
/// service FQDN, the second on the deterministic `p<port>.<fqdn>` alias — each
/// backed by that port's container port. This is the gateway (destination) side
/// of the per-port SNI scheme the client materializers dial.
#[test]
fn east_west_gateway_materializes_per_port_proxies_for_multiport_service() {
    let workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.5"],
    );
    let mut service = service_for("reviews", DEFAULT_NAMESPACE, &[&workload]);
    service.ports = vec![
        ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        },
        ServicePort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
            target_port: None,
        },
    ];
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("east-west prepared");

    // First port → base FQDN passthrough proxy → backend container port 8080.
    let first = prepared
        .proxies
        .iter()
        .find(|p| {
            p.hosts
                .iter()
                .any(|h| h == "reviews.default.svc.cluster.local")
        })
        .expect("first-port east-west proxy (base FQDN) must materialise");
    assert!(first.passthrough);
    assert_eq!(first.listen_port, Some(15443));
    let first_upstream = prepared
        .upstreams
        .iter()
        .find(|u| Some(&u.id) == first.upstream_id.as_ref())
        .expect("first-port upstream");
    assert!(
        first_upstream.targets.iter().all(|t| t.port == 8080),
        "first-port upstream backends the 8080 container port, got {:?}",
        first_upstream
            .targets
            .iter()
            .map(|t| t.port)
            .collect::<Vec<_>>()
    );

    // Second port → `p9090.<fqdn>` alias passthrough proxy → container port 9090.
    let second = prepared
        .proxies
        .iter()
        .find(|p| {
            p.hosts
                .iter()
                .any(|h| h == "p9090.reviews.default.svc.cluster.local")
        })
        .expect("second-port east-west proxy (p9090 alias) must materialise");
    assert!(second.passthrough);
    assert_eq!(second.listen_port, Some(15443));
    let second_upstream = prepared
        .upstreams
        .iter()
        .find(|u| Some(&u.id) == second.upstream_id.as_ref())
        .expect("second-port upstream");
    assert!(
        second_upstream.targets.iter().all(|t| t.port == 9090),
        "second-port upstream backends the 9090 container port, got {:?}",
        second_upstream
            .targets
            .iter()
            .map(|t| t.port)
            .collect::<Vec<_>>()
    );

    // The two ports are DISTINCT proxies (distinct ids, distinct SNI hosts) on the
    // shared east-west listen port.
    assert_ne!(first.id, second.id);
}

#[test]
fn east_west_materialisation_is_a_no_op_on_other_topologies() {
    // Sidecar topology should NOT materialise the east-west gateway
    // even if the MultiClusterConfig is present — verifies the
    // topology-gated short-circuit.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![east_west_gateway("ghost-gw", vec!["a.example.com"])],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("sidecar prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.id.starts_with("__mesh-east-west-")),
        "east-west proxies must not be materialised under non-EW topology, got {:?}",
        prepared.proxies.iter().map(|p| &p.id).collect::<Vec<_>>()
    );
}

#[test]
fn east_west_gateway_skips_remote_gateway_from_other_namespace() {
    // An EastWestGateway whose namespace doesn't match the runtime
    // namespace must be ignored — operators rely on this for
    // namespace isolation across federated clusters.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let mut foreign_gw = east_west_gateway("foreign", vec!["foreign.example.com"]);
    foreign_gw.namespace = "other-ns".to_string();
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![foreign_gw],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("prepared");
    assert!(
        prepared.proxies.iter().all(|p| !p.id.contains("foreign")),
        "foreign-namespace east-west gateway must be filtered out"
    );
}

#[test]
fn east_west_explicit_sni_override_suppresses_auto_local_service_proxy() {
    // An explicit EastWestGateway that owns a local service's FQDN SNI host
    // must win over the automatic local-service proxy: materializing both
    // would emit two passthrough proxies claiming the same SNI on the shared
    // listen port, which `validate_stream_proxies` rejects as overlapping —
    // silently dropping the operator's explicit route. The auto proxy for the
    // overlapping FQDN is suppressed so exactly one (the explicit) survives.
    let workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.5"],
    );
    let service = service_for("reviews", DEFAULT_NAMESPACE, &[&workload]);
    let mut mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![east_west_gateway(
            "explicit-reviews",
            vec!["reviews.default.svc.cluster.local"],
        )],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("prepared");

    // The explicit gateway proxy is present...
    assert!(
        prepared
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-east-west-")
                && p.hosts
                    .iter()
                    .any(|h| h == "reviews.default.svc.cluster.local")),
        "explicit east-west gateway proxy must own the reviews SNI"
    );
    // ...and the auto local-service proxy for the same FQDN is suppressed, so
    // only one proxy claims that SNI on the shared listen port.
    let claimants = prepared
        .proxies
        .iter()
        .filter(|p| {
            p.listen_port == Some(15443)
                && p.hosts
                    .iter()
                    .any(|h| h == "reviews.default.svc.cluster.local")
        })
        .count();
    assert_eq!(
        claimants, 1,
        "explicit override must suppress the auto proxy so exactly one proxy claims the SNI"
    );
}

#[test]
fn east_west_overwritten_duplicate_gateway_does_not_suppress_auto_proxy() {
    // Two EastWestGateway entries in the same namespace that reuse the same
    // `name` collapse onto one generated proxy id (last wins). The override
    // set must reflect only the surviving gateway's SNI hosts: an overwritten
    // entry that claimed `reviews.default.svc.cluster.local` must NOT suppress
    // the auto local-service proxy for `reviews`, or that service silently
    // disappears from east-west routing. The surviving entry claims `ratings`.
    let reviews_wl = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.5"],
    );
    let reviews_svc = service_for("reviews", DEFAULT_NAMESPACE, &[&reviews_wl]);
    let mut mesh = mesh_config_with(vec![reviews_wl], vec![reviews_svc], Vec::new());
    // Both gateways share name "dup" → same generated proxy id; only the last
    // (claiming `ratings`) materializes a proxy. The first (claiming `reviews`)
    // is overwritten and owns no surviving explicit proxy.
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            east_west_gateway("dup", vec!["reviews.default.svc.cluster.local"]),
            east_west_gateway("dup", vec!["ratings.default.svc.cluster.local"]),
        ],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("prepared");

    // The auto local-service proxy for `reviews` must still be materialized
    // because the overwritten duplicate-name entry never produced a surviving
    // explicit proxy that owns the SNI.
    assert!(
        prepared
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-ew-svc-")
                && p.hosts
                    .iter()
                    .any(|h| h == "reviews.default.svc.cluster.local")),
        "auto local-service proxy for reviews must survive when only an overwritten duplicate-name gateway claimed it, got {:?}",
        prepared
            .proxies
            .iter()
            .map(|p| (&p.id, &p.hosts))
            .collect::<Vec<_>>()
    );
}

// ── Egress gateway materialization ────────────────────────────────────────

fn egress_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::EgressGateway);
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    runtime.egress_stream_enabled = true;
    runtime
}

fn external_service_entry(name: &str, host: &str, port: u16) -> ServiceEntry {
    ServiceEntry {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        hosts: vec![host.to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        export_to: vec![".".to_string()],
        workload_selector: None,
    }
}

#[test]
fn egress_gateway_materializes_proxy_for_external_service_entry() {
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_service_entry(
        "payments",
        "payments.example.com",
        443,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h.contains("payments.example.com")))
        .expect("egress proxy materialised for payments.example.com");
    assert!(
        !proxy.passthrough,
        "egress proxy terminates HTTP, not passthrough"
    );
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id.contains("payments"))
        .expect("egress upstream materialised");
    assert!(
        !upstream.targets.is_empty(),
        "egress upstream must carry at least one target"
    );
}

#[test]
fn egress_gateway_skips_mesh_internal_service_entries() {
    // MESH_INTERNAL ServiceEntries are used for VM workload
    // registration, NOT egress targets. Materialisation must skip
    // them.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let mut internal_entry = external_service_entry("vm-app", "vm.internal.example.com", 80);
    internal_entry.location = ServiceEntryLocation::MeshInternal;
    mesh.service_entries.push(internal_entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.hosts.iter().any(|h| h.contains("vm.internal"))),
        "MESH_INTERNAL ServiceEntry must not produce an egress proxy"
    );
}

#[test]
fn egress_gateway_skips_service_entries_without_export_scope_for_namespace() {
    // A ServiceEntry whose namespace doesn't match and whose export
    // doesn't include `*` or our namespace must not produce a proxy.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let mut entry = external_service_entry("blocked", "blocked.example.com", 443);
    entry.namespace = "private-ns".to_string();
    entry.export_to = vec!["private-ns".to_string()];
    mesh.service_entries.push(entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.hosts.iter().any(|h| h.contains("blocked.example.com"))),
        "non-exported ServiceEntry must not produce an egress proxy"
    );
}

#[test]
fn egress_materialisation_is_a_no_op_on_other_topologies() {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries
        .push(external_service_entry("ghost", "ghost.example.com", 443));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("sidecar prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.hosts.iter().any(|h| h.contains("ghost.example.com"))),
        "egress proxies must not be materialised under non-egress topology"
    );
}

#[test]
fn egress_gateway_materialises_distinct_proxies_per_external_entry() {
    // Multiple ServiceEntries → multiple proxies. Verify each gets a
    // distinct proxy/upstream.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries
        .push(external_service_entry("a", "a.example.com", 443));
    mesh.service_entries
        .push(external_service_entry("b", "b.example.com", 443));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("prepared");
    let a_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h.contains("a.example.com")))
        .expect("a proxy");
    let b_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h.contains("b.example.com")))
        .expect("b proxy");
    assert_ne!(a_proxy.id, b_proxy.id, "distinct proxy IDs per entry");
}

// ── T5-A: stream-family egress materialization ───────────────────────────

fn external_stream_service_entry(
    name: &str,
    host: &str,
    port: u16,
    protocol: AppProtocol,
) -> ServiceEntry {
    ServiceEntry {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        hosts: vec![host.to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port,
            protocol,
            name: Some("stream".to_string()),
            target_port: None,
        }],
        export_to: vec![".".to_string()],
        workload_selector: None,
    }
}

#[test]
fn egress_gateway_materialises_tcp_stream_proxy_for_external_tcp_service_entry() {
    // T5-A: a `ServiceEntry` for `redis.external.io:6379/TCP` admitted under
    // `location: mesh_external` materializes a TCP stream proxy on the egress
    // gateway. The proxy listens on the SE's own port (6379) and routes by
    // listen_port, not hosts.
    use ferrum_edge::config::types::BackendScheme;

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "redis-ext",
        "redis.external.io",
        6379,
        AppProtocol::Redis,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");

    let stream_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(6379))
        .expect("stream egress proxy materialised on the SE's port");
    assert!(
        stream_proxy.hosts.is_empty(),
        "stream proxies route by listen_port, not host"
    );
    assert!(stream_proxy.listen_path.is_none());
    assert_eq!(stream_proxy.backend_scheme, Some(BackendScheme::Tcp));
    assert!(!stream_proxy.passthrough, "egress is NOT SNI passthrough");
    assert!(
        stream_proxy.dispatch_kind.is_stream(),
        "dispatch_kind must resolve to a stream variant"
    );

    let upstream = prepared
        .upstreams
        .iter()
        // The SE name "redis-ext" is encoded into the egress id with the
        // injective, `-`-free scheme (#1727), so its `-` becomes the `_dash_`
        // token and the name segment is "redis_dash_ext".
        .find(|u| u.id.contains("redis_dash_ext"))
        .expect("stream egress upstream materialised");
    assert!(
        !upstream.targets.is_empty(),
        "stream egress upstream must carry at least one target"
    );
    assert_eq!(upstream.targets[0].host, "redis.external.io");
    assert_eq!(upstream.targets[0].port, 6379);
}

#[test]
fn egress_gateway_materialises_database_protocols_as_tcp_stream_proxies() {
    // All five TCP-based AppProtocols (Tcp, Mongo, Redis, Mysql, Postgres)
    // produce TCP stream proxies. Protocol-aware mediation is T5-C.
    use ferrum_edge::config::types::BackendScheme;

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "ext-mongo",
        "mongo.external.io",
        27017,
        AppProtocol::Mongo,
    ));
    mesh.service_entries.push(external_stream_service_entry(
        "ext-pg",
        "pg.external.io",
        5432,
        AppProtocol::Postgres,
    ));
    mesh.service_entries.push(external_stream_service_entry(
        "ext-mysql",
        "mysql.external.io",
        3306,
        AppProtocol::Mysql,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");

    for (host, port) in [
        ("mongo.external.io", 27017_u16),
        ("pg.external.io", 5432),
        ("mysql.external.io", 3306),
    ] {
        let proxy = prepared
            .proxies
            .iter()
            .find(|p| p.listen_port == Some(port))
            .unwrap_or_else(|| panic!("stream proxy for {host}:{port} should exist"));
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
        let upstream = prepared
            .upstreams
            .iter()
            .find(|u| u.targets.iter().any(|t| t.host == host && t.port == port))
            .unwrap_or_else(|| panic!("upstream for {host}:{port} should exist"));
        assert!(!upstream.targets.is_empty());
    }
}

#[test]
fn egress_gateway_materialises_http_and_stream_entries_side_by_side() {
    // Mixed manifest: an HTTPS SE and a TCP SE coexist. HTTP-family uses
    // host-routed listener at 15090; stream-family binds its own listen_port.
    // Both must materialize without interference.
    use ferrum_edge::config::types::BackendScheme;

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries
        .push(external_service_entry("ext-api", "api.example.com", 443));
    mesh.service_entries.push(external_stream_service_entry(
        "ext-postgres",
        "pg.example.com",
        5432,
        AppProtocol::Postgres,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");

    // HTTP-family: host-routed, listen_port is None.
    let http_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h == "api.example.com"))
        .expect("http egress proxy materialized");
    assert!(http_proxy.listen_port.is_none());
    assert!(http_proxy.dispatch_kind.is_http_family());

    // Stream-family: port-routed, hosts is empty.
    let stream_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(5432))
        .expect("stream egress proxy materialized");
    assert!(stream_proxy.hosts.is_empty());
    assert_eq!(stream_proxy.backend_scheme, Some(BackendScheme::Tcp));
}

#[test]
fn egress_gateway_skips_stream_service_entries_under_non_egress_topology() {
    // Topology gate must apply to stream-family materialization the same
    // way it applies to HTTP-family materialization.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "ghost-tcp",
        "ghost.example.com",
        9000,
        AppProtocol::Tcp,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("sidecar prepared");

    assert!(
        prepared.proxies.iter().all(|p| p.listen_port != Some(9000)),
        "stream egress proxies must not materialize under non-egress topology"
    );
}

#[test]
fn egress_gateway_stream_port_collision_skips_second_entry() {
    // Two SEs requesting the same listen_port: the materializer must skip
    // the second one (only one stream proxy per port). Non-fatal — keeps
    // the first proxy live and emits a warning for the second.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "primary",
        "primary.example.com",
        6379,
        AppProtocol::Redis,
    ));
    mesh.service_entries.push(external_stream_service_entry(
        "secondary",
        "secondary.example.com",
        6379,
        AppProtocol::Redis,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("prepared");

    let stream_proxies: Vec<_> = prepared
        .proxies
        .iter()
        .filter(|p| p.listen_port == Some(6379))
        .collect();
    assert_eq!(
        stream_proxies.len(),
        1,
        "port-collision policy: only the first SE wins on the same listen_port"
    );

    // The first SE in config order must be the surviving one.
    let primary_upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.targets.iter().any(|t| t.host == "primary.example.com"))
        .expect("primary upstream materialized");
    assert!(!primary_upstream.targets.is_empty());
}

#[test]
fn egress_gateway_stream_skips_service_entries_that_collide_with_egress_listener_port() {
    // A ServiceEntry whose port matches the egress gateway's own mTLS-
    // termination listener (`egress_listen_addr.port()`) would fail to bind
    // at runtime (EADDRINUSE on the listener manager reconcile). The
    // materializer skips these with a warning. Without the skip, the stream
    // listener would crash the slice apply pipeline rather than degrade
    // gracefully.
    let mut runtime = egress_runtime();
    runtime.egress_listen_addr = "127.0.0.1:15090".parse().expect("addr");

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "colliding",
        "external.io",
        15090,
        AppProtocol::Tcp,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");

    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| p.listen_port != Some(15090)),
        "stream proxies must not collide with the egress gateway's own listener"
    );
}

// ── F6 §6.1: stream egress SVID-mTLS termination ─────────────────────────

#[test]
fn egress_gateway_stream_proxies_terminate_mtls_by_default() {
    // F6 §6.1: with stream egress enabled (and the plaintext opt-out NOT set),
    // every materialized per-port stream egress proxy is `frontend_tls: true`.
    // The stream listener then terminates SVID-mTLS using the shared mesh-
    // inbound `ServerConfig` and runs `__mesh_spiffe_identity` + `__mesh_authz`
    // at accept — parity with HTTP egress. (`egress_runtime()` sets
    // `egress_stream_enabled = true` and leaves `egress_stream_allow_plaintext`
    // at its secure default `false`.)
    let runtime = egress_runtime();
    assert!(
        !runtime.egress_stream_allow_plaintext,
        "default posture must keep plaintext disabled"
    );

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "redis-ext",
        "redis.external.io",
        6379,
        AppProtocol::Redis,
    ));
    mesh.service_entries.push(external_stream_service_entry(
        "pg-ext",
        "pg.external.io",
        5432,
        AppProtocol::Postgres,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("egress prepared");

    let stream_proxies: Vec<_> = prepared
        .proxies
        .iter()
        .filter(|p| p.listen_port.is_some())
        .collect();
    assert_eq!(
        stream_proxies.len(),
        2,
        "both stream ServiceEntries should materialize a stream proxy"
    );
    for proxy in stream_proxies {
        assert!(
            proxy.frontend_tls,
            "stream egress proxy on port {:?} must terminate SVID-mTLS by default",
            proxy.listen_port
        );
        // mTLS termination is NOT raw SNI passthrough: the bytes flow through
        // the normal TCP pipeline so the on_stream_connect mesh_authz hook runs.
        assert!(
            !proxy.passthrough,
            "stream egress must terminate (not passthrough) so mesh_authz runs"
        );
    }
}

#[test]
fn egress_gateway_stream_proxies_allow_plaintext_opt_out() {
    // The explicit opt-out `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true`
    // restores the legacy plaintext + unauthenticated listener
    // (`frontend_tls: false`) for operators who genuinely need it.
    let mut runtime = egress_runtime();
    runtime.egress_stream_allow_plaintext = true;

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "redis-ext",
        "redis.external.io",
        6379,
        AppProtocol::Redis,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("egress prepared");

    let stream_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(6379))
        .expect("stream egress proxy materialised");
    assert!(
        !stream_proxy.frontend_tls,
        "plaintext opt-out must produce a plaintext (frontend_tls: false) stream listener"
    );
}

#[test]
fn egress_gateway_stream_allow_plaintext_is_noop_without_stream_enabled() {
    // `egress_stream_allow_plaintext` only matters when stream egress is
    // enabled. With stream egress OFF, stream ServiceEntries are skipped
    // regardless of the plaintext flag, so HTTP egress alone materializes.
    let mut runtime = runtime_for_topology(MeshTopology::EgressGateway);
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    runtime.egress_stream_enabled = false;
    runtime.egress_stream_allow_plaintext = true;

    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_stream_service_entry(
        "redis-ext",
        "redis.external.io",
        6379,
        AppProtocol::Redis,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("egress prepared");

    assert!(
        prepared.proxies.iter().all(|p| p.listen_port.is_none()),
        "stream egress must not materialize when FERRUM_MESH_EGRESS_STREAM_ENABLED is off"
    );
}

// ── MeshRuntimeState smoke ────────────────────────────────────────────────

#[test]
fn mesh_runtime_state_install_and_snapshot_round_trip() {
    let state = MeshRuntimeState::new();
    assert!(
        !state.has_first_slice(),
        "fresh state has no installed slice"
    );
    let slice = ferrum_edge::modes::mesh::slice::MeshSlice {
        version: "v-test".to_string(),
        node_id: "node-1".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        ..Default::default()
    };
    state.install_slice(slice);
    assert!(state.has_first_slice());
    let snapshot = state.snapshot();
    let slice_ref = snapshot.as_ref().as_ref().expect("snapshot has slice");
    assert_eq!(slice_ref.version, "v-test");
    assert_eq!(slice_ref.namespace, DEFAULT_NAMESPACE);
}
