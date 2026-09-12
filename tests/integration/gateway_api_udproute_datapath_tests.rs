//! Live UDP data-path coverage for Gateway API `UDPRoute` (issue #3275).
//!
//! The unit suite proves what a `UDPRoute` translates *into*. This suite runs
//! that translated snapshot through the real UDP runtime: `start_udp_listener`
//! binds the Gateway listener port the translator chose, a client datagram
//! traverses the generated stream proxy, and the reply comes back from the
//! backend the route actually named.
//!
//! Determinism rules this file follows:
//!
//! * Every backend socket is bound once and owned for the whole run, so no
//!   backend port is released and re-bound mid-test.
//! * Gateway listener ports come from `reserve_udp_port`. A listener that
//!   never reports `started` voids the entire attempt — fresh ports and fresh
//!   runtime state — instead of being retried in place, and every assertion
//!   below is made exactly once against a healthy data plane.
//! * No assertion depends on wall-clock latency, on sleeping for a state
//!   transition, or on which leg of a weighted set the load balancer picks.
//!   The only deadlines are an upper bound on a reply that must arrive and a
//!   short window for a datagram that must never be answered.
//! * The one test-side substitution is DNS: the generated
//!   `<service>.<namespace>.svc.cluster.local` backend names are pointed at
//!   loopback through `DnsConfig::global_overrides`. Listen ports, backend
//!   ports, backend hosts, upstream identity, and weights all come from the
//!   translator.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{BackendScheme, GatewayConfig, Proxy, Upstream};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::FERRUM_GATEWAY_CONTROLLER_NAME;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::modes::mesh::outbound_enforcement::empty_slot;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::ports::reserve_udp_port;

const GW_V1: &str = "gateway.networking.k8s.io/v1";
const GW_V1ALPHA2: &str = "gateway.networking.k8s.io/v1alpha2";
const ROUTE_NS: &str = "default";
const CLUSTER_DOMAIN: &str = "cluster.local";

/// Upper bound on a reply that must arrive. Generous on purpose: it bounds a
/// hang, it is not a latency assertion.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// Window for a datagram that must never be answered. Any reply at all is a
/// real fail-open, so a short window cannot produce a false failure.
const NO_REPLY_WINDOW: Duration = Duration::from_millis(750);
const LISTENER_STARTED_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LAB_ATTEMPTS: u32 = 3;

// ---------------------------------------------------------------------------
// Pre-bound tagged backends
// ---------------------------------------------------------------------------

/// A UDP backend that answers every datagram with `<tag>:<payload>`.
///
/// The socket is bound once and moved into a detached task, so the port stays
/// held for the whole test. Nothing here drops and re-binds, which is what
/// keeps a parallel test from stealing a backend port mid-run. The tag is what
/// makes "the reply came from the backend this route named" an assertion
/// rather than an assumption.
struct TaggedBackend {
    tag: &'static str,
    port: u16,
    _join: tokio::task::JoinHandle<()>,
}

impl TaggedBackend {
    async fn start(tag: &'static str) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("backend bind");
        let port = socket.local_addr().expect("backend addr").port();
        let join = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let mut reply = Vec::with_capacity(tag.len() + 1 + len);
                        reply.extend_from_slice(tag.as_bytes());
                        reply.push(b':');
                        reply.extend_from_slice(&buf[..len]);
                        let _ = socket.send_to(&reply, peer).await;
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            tag,
            port,
            _join: join,
        }
    }

    /// Kubernetes `Service` name this backend is published as.
    fn service(&self) -> String {
        let tag = self.tag;
        format!("udp-echo-{tag}")
    }

    /// The name the translator puts in `Proxy::backend_host` for it.
    fn dns_name(&self) -> String {
        let service = self.service();
        format!("{service}.{ROUTE_NS}.svc.{CLUSTER_DOMAIN}")
    }
}

/// Point every named backend's generated cluster DNS name at loopback.
fn dns_overrides(backends: &[&TaggedBackend]) -> HashMap<String, String> {
    let mut overrides = HashMap::new();
    for backend in backends {
        overrides.insert(backend.dns_name(), "127.0.0.1".to_string());
    }
    overrides
}

// ---------------------------------------------------------------------------
// Kubernetes snapshot builders
// ---------------------------------------------------------------------------

fn object(kind: &str, api_version: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    let spec = json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME});
    object("GatewayClass", GW_V1, "", "ferrum", spec)
}

fn udp_service(name: &str, port: u16) -> K8sObject {
    let ports = json!([{"name": "udp", "protocol": "UDP", "port": port}]);
    let spec = json!({"ports": ports});
    object("Service", "v1", ROUTE_NS, name, spec)
}

/// One Gateway listener plus the `UDPRoute` attached to it.
#[derive(Clone)]
struct RouteSpec {
    gateway: &'static str,
    section: &'static str,
    route: &'static str,
    /// `backendRefs` exactly as the route declares them.
    backend_refs: Value,
}

fn udp_gateway_object(route: &RouteSpec, port: u16) -> K8sObject {
    let spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": route.section,
            "port": port,
            "protocol": "UDP",
            "allowedRoutes": {
                "kinds": [{"kind": "UDPRoute"}],
                "namespaces": {"from": "Same"}
            }
        }]
    });
    object("Gateway", GW_V1, ROUTE_NS, route.gateway, spec)
}

fn udp_route_object(route: &RouteSpec) -> K8sObject {
    let parent = json!([{"name": route.gateway, "sectionName": route.section}]);
    let spec = json!({
        "parentRefs": parent,
        "rules": [{"backendRefs": route.backend_refs.clone()}]
    });
    object("UDPRoute", GW_V1ALPHA2, ROUTE_NS, route.route, spec)
}

/// Everything a lab attempt needs besides the listener ports it reserves.
///
/// Held as data rather than a closure so one attempt's snapshot is rebuilt
/// verbatim on the next attempt's fresh ports.
struct LabSnapshot {
    /// `(Service name, Service port)` pairs published in `ROUTE_NS`.
    services: Vec<(String, u16)>,
    /// One entry per Gateway listener; index N takes reserved port N.
    routes: Vec<RouteSpec>,
    extra_objects: Vec<K8sObject>,
}

impl LabSnapshot {
    fn objects(&self, listen_ports: &[u16]) -> Vec<K8sObject> {
        let mut objects = vec![gateway_class()];
        for (name, port) in &self.services {
            objects.push(udp_service(name, *port));
        }
        for (index, route) in self.routes.iter().enumerate() {
            let port = listen_ports[index];
            objects.push(udp_gateway_object(route, port));
            objects.push(udp_route_object(route));
        }
        objects.extend(self.extra_objects.clone());
        objects
    }
}

fn translation_options() -> K8sTranslationOptions {
    let trust_domain = TrustDomain::new(CLUSTER_DOMAIN).expect("trust domain");
    K8sTranslationOptions::new(ROUTE_NS.to_string(), trust_domain)
}

// ---------------------------------------------------------------------------
// Translated data plane
// ---------------------------------------------------------------------------

/// A running data plane whose every listener came out of the translator.
struct TranslatedUdpLab {
    /// The translated snapshot the listeners are serving.
    config: GatewayConfig,
    /// Reserved Gateway listener ports, in `LabSnapshot::routes` order.
    listen_ports: Vec<u16>,
    shutdown_tx: watch::Sender<bool>,
    joins: Vec<tokio::task::JoinHandle<()>>,
}

impl TranslatedUdpLab {
    fn gateway_addr(&self, index: usize) -> SocketAddr {
        let port = self.listen_ports[index];
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn udp_proxies(&self) -> Vec<&Proxy> {
        let is_udp = |proxy: &&Proxy| proxy.backend_scheme == Some(BackendScheme::Udp);
        self.config.proxies.iter().filter(is_udp).collect()
    }

    /// The one materialized UDP proxy, asserting there is exactly one.
    fn sole_udp_proxy(&self) -> &Proxy {
        let proxies = self.udp_proxies();
        assert_eq!(proxies.len(), 1, "expected exactly one UDP proxy");
        proxies[0]
    }

    /// The proxy bound to reserved listener port `index`.
    fn proxy_on_listener(&self, index: usize) -> &Proxy {
        let port = self.listen_ports[index];
        let on_port = |proxy: &&Proxy| proxy.listen_port == Some(port);
        let found = self.udp_proxies().into_iter().find(on_port);
        found.unwrap_or_else(|| panic!("no UDP proxy on listener port {port}"))
    }

    fn upstream(&self, id: &str) -> &Upstream {
        let found = self.config.upstreams.iter().find(|up| up.id == id);
        found.unwrap_or_else(|| panic!("translated upstream {id} is missing"))
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        for join in self.joins {
            let _ = tokio::time::timeout(REPLY_TIMEOUT, join).await;
        }
    }
}

/// Translate `snapshot` onto freshly reserved listener ports and serve it.
///
/// A bind that loses a reserved port is not an observation: the whole attempt
/// is torn down and replayed on new ports, so no assertion ever runs against a
/// half-started data plane.
async fn start_translated_udp_lab(
    snapshot: &LabSnapshot,
    overrides: HashMap<String, String>,
) -> TranslatedUdpLab {
    for attempt in 1..=MAX_LAB_ATTEMPTS {
        let mut reservations = Vec::new();
        for _ in 0..snapshot.routes.len() {
            let reserved = reserve_udp_port().await.expect("reserve listener port");
            reservations.push(reserved);
        }
        let mut listen_ports = Vec::new();
        for reservation in reservations {
            listen_ports.push(reservation.drop_and_take_port());
        }

        let objects = snapshot.objects(&listen_ports);
        let options = translation_options();
        let translated = translate_k8s_objects(&objects, options);
        let config = translated.expect("UDPRoute snapshot translates").config;
        let served = try_serve_translated_config(config, listen_ports, &overrides);
        if let Some(lab) = served.await {
            return lab;
        }
        eprintln!("translated UDPRoute lab attempt {attempt} lost a listener port");
    }
    panic!("no translated UDP listener started after {MAX_LAB_ATTEMPTS} attempts");
}

async fn try_serve_translated_config(
    config: GatewayConfig,
    listen_ports: Vec<u16>,
    overrides: &HashMap<String, String>,
) -> Option<TranslatedUdpLab> {
    let is_udp = |proxy: &&Proxy| proxy.backend_scheme == Some(BackendScheme::Udp);
    let selected = config.proxies.iter().filter(is_udp);
    let udp_proxies: Vec<Proxy> = selected.cloned().collect();
    assert!(
        !udp_proxies.is_empty(),
        "translation must materialize at least one UDP stream proxy"
    );

    let plugin_cache = Arc::new(PluginCache::new(&config).expect("plugin cache"));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let load_balancer_cache = Arc::new(LoadBalancerCache::new(&config));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        config.clone(),
        &plugin_cache,
        &consumer_index,
        &load_balancer_cache,
    ));
    let dns_config = DnsConfig {
        global_overrides: overrides.clone(),
        ..DnsConfig::default()
    };
    let dns_cache = DnsCache::new(dns_config);
    let circuit_breaker_cache = Arc::new(CircuitBreakerCache::new());
    let health_checker = Arc::new(HealthChecker::new());
    let adaptive_buffer = Arc::new(AdaptiveBufferTracker::new(
        true, true, 300, 8192, 262_144, 65_536, 6000,
    ));
    let overload = Arc::new(OverloadState::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut started_flags = Vec::new();
    let mut joins = Vec::new();
    for proxy in &udp_proxies {
        let started = Arc::new(AtomicBool::new(false));
        started_flags.push(Arc::clone(&started));
        let cfg = UdpListenerConfig {
            port: proxy.listen_port.expect("translated proxy has a port"),
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            proxy_id: proxy.id.clone(),
            proxy_namespace: proxy.namespace.clone(),
            dns_cache: dns_cache.clone(),
            request_epoch: Arc::clone(&request_epoch),
            health_checker: Arc::clone(&health_checker),
            shutdown: shutdown_rx.clone(),
            global_shutdown: None,
            metrics: Arc::new(UdpProxyMetrics::default()),
            frontend_dtls_config: None,
            dtls_server_tx: None,
            tls_no_verify: false,
            tls_ca_bundle_path: None,
            max_sessions: 1024,
            frontend_tls_handshake_timeout_seconds: 10,
            cleanup_interval_seconds: 10,
            session_shard_amount: 0,
            circuit_breaker_cache: Arc::clone(&circuit_breaker_cache),
            crls: Arc::new(Vec::new()),
            backend_tls_reload_epoch: Arc::new(AtomicU64::new(0)),
            tls_policy: None,
            started,
            sni_proxy_ids: None,
            adaptive_buffer: Arc::clone(&adaptive_buffer),
            recvmmsg_batch_size: 64,
            overload: Arc::clone(&overload),
            so_busy_poll_us: 0,
            udp_gro_enabled: false,
            udp_gso_enabled: false,
            udp_pktinfo_enabled: false,
            mesh_outbound_enforcement: empty_slot(),
            node_waypoint_udp_source_scoping: None,
            node_waypoint_udp_owner: false,
            node_waypoint_udp_destinations: None,
            datagram_client_address: None,
        };
        let join = tokio::spawn(async move {
            let _ = start_udp_listener(cfg).await;
        });
        joins.push(join);
    }

    // `started` is the only readiness signal the listener exposes, so this
    // polls that flag under a hard deadline instead of sleeping a guessed
    // startup budget. A task that already exited lost its port.
    let deadline = Instant::now() + LISTENER_STARTED_TIMEOUT;
    let mut ready = false;
    while Instant::now() <= deadline {
        if started_flags
            .iter()
            .all(|flag| flag.load(Ordering::Acquire))
        {
            ready = true;
            break;
        }
        if joins.iter().any(|join| join.is_finished()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if !ready {
        let _ = shutdown_tx.send(true);
        for join in joins {
            join.abort();
            let _ = join.await;
        }
        return None;
    }

    Some(TranslatedUdpLab {
        config,
        listen_ports,
        shutdown_tx,
        joins,
    })
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

/// Send `payload` through the gateway and return the tagged backend reply.
async fn round_trip(client: &UdpSocket, gateway: SocketAddr, payload: &[u8]) -> String {
    client.send_to(payload, gateway).await.expect("send");
    let mut buf = vec![0u8; 65535];
    let received = tokio::time::timeout(REPLY_TIMEOUT, client.recv_from(&mut buf)).await;
    let (len, _) = received.expect("backend reply").expect("recv reply");
    String::from_utf8(buf[..len].to_vec()).expect("tagged reply is UTF-8")
}

/// Split a `<tag>:<payload>` reply, asserting the payload round-tripped whole.
fn responder_tag(reply: &str, sent: &str) -> String {
    let (tag, echoed) = reply.split_once(':').expect("tagged reply");
    assert_eq!(echoed, sent, "backend must echo the datagram unchanged");
    tag.to_string()
}

/// Assert the gateway never answers `payload`.
///
/// Only an actually received datagram fails this: a socket error (an ICMP
/// unreachable surfacing, say) is not a reply, so the assertion has no
/// false-failure path and the short window is safe.
async fn expect_no_reply(client: &UdpSocket, gateway: SocketAddr, payload: &[u8]) {
    client.send_to(payload, gateway).await.expect("send");
    let mut buf = vec![0u8; 65535];
    let recv = client.recv_from(&mut buf);
    let outcome = tokio::time::timeout(NO_REPLY_WINDOW, recv).await;
    let answered = matches!(outcome, Ok(Ok(_)));
    assert!(
        !answered,
        "a UDPRoute leg with no resolvable Service must drop the datagram"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The core acceptance criterion of issue #3275: a Gateway API `UDPRoute`
/// becomes a real UDP listener and carries a datagram to the backend it named.
#[tokio::test]
async fn translated_udp_route_carries_a_datagram_to_its_declared_backend() {
    let backend = TaggedBackend::start("alpha").await;
    let service = backend.service();
    let backend_port = backend.port;
    let snapshot = LabSnapshot {
        services: vec![(service.clone(), backend_port)],
        routes: vec![RouteSpec {
            gateway: "edge",
            section: "dns",
            route: "dns",
            backend_refs: json!([{"name": service.as_str(), "port": backend_port}]),
        }],
        extra_objects: Vec::new(),
    };

    let overrides = dns_overrides(&[&backend]);
    let lab = start_translated_udp_lab(&snapshot, overrides).await;

    let proxy = lab.sole_udp_proxy();
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Udp));
    assert_eq!(proxy.listen_port, Some(lab.listen_ports[0]));
    assert_eq!(proxy.backend_host, backend.dns_name());
    assert_eq!(proxy.backend_port, backend_port);
    assert_eq!(proxy.upstream_id, None);
    assert_eq!(
        proxy.udp_max_response_amplification_factor,
        Some(8.0),
        "Gateway API UDPRoute must never program an unlimited amplification relay"
    );

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let reply = round_trip(&client, lab.gateway_addr(0), b"gwapi-udp").await;
    assert_eq!(reply, "alpha:gwapi-udp");

    lab.shutdown().await;
}

/// Two `UDPRoute`s on two `protocol: UDP` listeners must not cross-talk: the
/// listener port a datagram arrives on decides which backend serves it, which
/// is the whole match a matchless L4 route has.
#[tokio::test]
async fn each_translated_udp_route_reaches_only_its_own_declared_backend() {
    let alpha = TaggedBackend::start("alpha").await;
    let beta = TaggedBackend::start("beta").await;
    let alpha_service = alpha.service();
    let beta_service = beta.service();
    let alpha_port = alpha.port;
    let beta_port = beta.port;
    let snapshot = LabSnapshot {
        services: vec![
            (alpha_service.clone(), alpha_port),
            (beta_service.clone(), beta_port),
        ],
        routes: vec![
            RouteSpec {
                gateway: "edge-alpha",
                section: "dns-alpha",
                route: "route-alpha",
                backend_refs: json!([{"name": alpha_service.as_str(), "port": alpha_port}]),
            },
            RouteSpec {
                gateway: "edge-beta",
                section: "dns-beta",
                route: "route-beta",
                backend_refs: json!([{"name": beta_service.as_str(), "port": beta_port}]),
            },
        ],
        extra_objects: Vec::new(),
    };

    let overrides = dns_overrides(&[&alpha, &beta]);
    let lab = start_translated_udp_lab(&snapshot, overrides).await;

    assert_eq!(lab.udp_proxies().len(), 2);
    assert_eq!(lab.proxy_on_listener(0).backend_port, alpha_port);
    assert_eq!(lab.proxy_on_listener(1).backend_port, beta_port);

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let to_alpha = round_trip(&client, lab.gateway_addr(0), b"one").await;
    let to_beta = round_trip(&client, lab.gateway_addr(1), b"two").await;
    assert_eq!(to_alpha, "alpha:one");
    assert_eq!(to_beta, "beta:two");

    lab.shutdown().await;
}

/// A weighted `backendRefs` set materializes a generated upstream, and the
/// live UDP path serves from it. The assertion is deliberately not a split
/// ratio: Gateway API weights converge over *sessions* here, so what is
/// deterministic — and what is asserted — is that every session is served by a
/// declared leg and stays on the one leg it selected for its whole lifetime.
#[tokio::test]
async fn translated_weighted_udp_route_serves_each_session_from_one_leg() {
    let alpha = TaggedBackend::start("alpha").await;
    let beta = TaggedBackend::start("beta").await;
    let alpha_service = alpha.service();
    let beta_service = beta.service();
    let alpha_port = alpha.port;
    let beta_port = beta.port;
    let legs = json!([
        {"name": alpha_service.as_str(), "port": alpha_port, "weight": 3},
        {"name": beta_service.as_str(), "port": beta_port, "weight": 1}
    ]);
    let snapshot = LabSnapshot {
        services: vec![
            (alpha_service.clone(), alpha_port),
            (beta_service.clone(), beta_port),
        ],
        routes: vec![RouteSpec {
            gateway: "edge",
            section: "dns",
            route: "split",
            backend_refs: legs,
        }],
        extra_objects: Vec::new(),
    };

    let overrides = dns_overrides(&[&alpha, &beta]);
    let lab = start_translated_udp_lab(&snapshot, overrides).await;

    let proxy = lab.sole_udp_proxy();
    let upstream_id = proxy.upstream_id.clone().expect("weighted set upstream");
    let upstream = lab.upstream(&upstream_id);
    let mut declared: Vec<(String, u16, u32)> = Vec::new();
    for target in &upstream.targets {
        declared.push((target.host.clone(), target.port, target.weight));
    }
    declared.sort();
    assert_eq!(
        declared,
        vec![
            (alpha.dns_name(), alpha_port, 3),
            (beta.dns_name(), beta_port, 1),
        ],
        "the live upstream must carry both legs at their declared weights"
    );

    let allowed = BTreeSet::from(["alpha".to_string(), "beta".to_string()]);
    for session in 0..4u8 {
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let mut tags = BTreeSet::new();
        for datagram in 0..3u8 {
            let sent = format!("s{session}-d{datagram}");
            let addr = lab.gateway_addr(0);
            let reply = round_trip(&client, addr, sent.as_bytes()).await;
            tags.insert(responder_tag(&reply, &sent));
        }
        assert!(
            tags.is_subset(&allowed),
            "every datagram must be served by a declared leg, saw {tags:?}"
        );
        assert_eq!(
            tags.len(),
            1,
            "a UDP session must stay on the leg it selected, saw {tags:?}"
        );
    }

    lab.shutdown().await;
}

/// A leg whose `Service` does not exist keeps its weight and is pointed at an
/// unresolvable blackhole, so its traffic is dropped rather than silently
/// steered somewhere else. Proven on the live path: the listener still binds,
/// and the datagram is never answered.
#[tokio::test]
async fn translated_udp_route_with_an_unresolved_backend_drops_the_datagram() {
    // A published Service keeps the translator's service cache warm; the route
    // deliberately names a different, absent one.
    let observed = TaggedBackend::start("alpha").await;
    let observed_service = observed.service();
    let observed_port = observed.port;
    let snapshot = LabSnapshot {
        services: vec![(observed_service, observed_port)],
        routes: vec![RouteSpec {
            gateway: "edge",
            section: "dns",
            route: "absent",
            backend_refs: json!([{"name": "udp-echo-absent", "port": 5353}]),
        }],
        extra_objects: Vec::new(),
    };

    let overrides = dns_overrides(&[&observed]);
    let lab = start_translated_udp_lab(&snapshot, overrides).await;

    let proxy = lab.sole_udp_proxy();
    assert_eq!(proxy.listen_port, Some(lab.listen_ports[0]));
    assert_eq!(proxy.backend_host, "ferrum-zero-weight.invalid.");
    assert_eq!(proxy.backend_port, 65535);

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    expect_no_reply(&client, lab.gateway_addr(0), b"dropped").await;

    lab.shutdown().await;
}

/// A backend that replies `count` times with a fixed payload for every request.
/// Used to prove cumulative multi-datagram amplification accounting.
struct BurstBackend {
    port: u16,
    _join: tokio::task::JoinHandle<()>,
}

impl BurstBackend {
    async fn start(payload: Vec<u8>, count: usize) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("backend bind");
        let port = socket.local_addr().expect("backend addr").port();
        let join = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((_, peer)) => {
                        for _ in 0..count {
                            let _ = socket.send_to(&payload, peer).await;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Self { port, _join: join }
    }

    fn service() -> String {
        "udp-burst".to_string()
    }

    fn dns_name() -> String {
        format!("{}.{ROUTE_NS}.svc.{CLUSTER_DOMAIN}", Self::service())
    }
}

fn amp_policy(route: &str, factor: f64) -> K8sObject {
    object(
        "UDPResponseAmplificationPolicy",
        "gateway.ferrum.io/v1alpha1",
        ROUTE_NS,
        "tight",
        json!({
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "UDPRoute",
                "name": route
            }],
            "mode": "Finite",
            "maxResponseAmplificationFactor": factor
        }),
    )
}

async fn recv_n(client: &UdpSocket, max: usize, window: Duration) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let deadline = Instant::now() + window;
    let mut buf = vec![0u8; 65535];
    while out.len() < max {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => out.push(buf[..n].to_vec()),
            _ => break,
        }
    }
    out
}

#[tokio::test]
async fn default_factor_drops_a_single_over_budget_reply() {
    let backend = BurstBackend::start(vec![b'x'; 900], 1).await;
    let service = BurstBackend::service();
    let snapshot = LabSnapshot {
        services: vec![(service.clone(), backend.port)],
        routes: vec![RouteSpec {
            gateway: "edge",
            section: "dns",
            route: "dns",
            backend_refs: json!([{"name": service.as_str(), "port": backend.port}]),
        }],
        extra_objects: Vec::new(),
    };
    let mut overrides = HashMap::new();
    overrides.insert(BurstBackend::dns_name(), "127.0.0.1".to_string());
    let lab = start_translated_udp_lab(&snapshot, overrides).await;
    assert_eq!(
        lab.sole_udp_proxy().udp_max_response_amplification_factor,
        Some(8.0)
    );

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let request = vec![b'r'; 100];
    client
        .send_to(&request, lab.gateway_addr(0))
        .await
        .expect("send");
    let replies = recv_n(&client, 4, NO_REPLY_WINDOW).await;
    assert!(
        replies.is_empty(),
        "900-byte reply must exceed the default 800-byte budget"
    );
    lab.shutdown().await;
}

#[tokio::test]
async fn cumulative_multi_datagram_replies_share_one_request_budget() {
    let backend = BurstBackend::start(vec![b'y'; 300], 3).await;
    let service = BurstBackend::service();
    let snapshot = LabSnapshot {
        services: vec![(service.clone(), backend.port)],
        routes: vec![RouteSpec {
            gateway: "edge",
            section: "dns",
            route: "dns",
            backend_refs: json!([{"name": service.as_str(), "port": backend.port}]),
        }],
        extra_objects: Vec::new(),
    };
    let mut overrides = HashMap::new();
    overrides.insert(BurstBackend::dns_name(), "127.0.0.1".to_string());
    let lab = start_translated_udp_lab(&snapshot, overrides).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let request = vec![b'r'; 100];
    client
        .send_to(&request, lab.gateway_addr(0))
        .await
        .expect("send");
    // Each 300-byte reply is under the 800-byte per-datagram product; the
    // third must still drop once 600 bytes have been charged.
    let replies = recv_n(&client, 4, REPLY_TIMEOUT).await;
    assert_eq!(replies.len(), 2, "third 300-byte reply must be dropped");
    assert!(replies.iter().all(|reply| reply.len() == 300));
    lab.shutdown().await;
}

#[tokio::test]
async fn exhausted_exchange_does_not_fund_the_next_requests_reply() {
    let backend = BurstBackend::start(vec![b'x'; 800], 1).await;
    let service = BurstBackend::service();
    let snapshot = LabSnapshot {
        services: vec![(service.clone(), backend.port)],
        routes: vec![RouteSpec {
            gateway: "edge",
            section: "dns",
            route: "dns",
            backend_refs: json!([{"name": service.as_str(), "port": backend.port}]),
        }],
        extra_objects: Vec::new(),
    };
    let mut overrides = HashMap::new();
    overrides.insert(BurstBackend::dns_name(), "127.0.0.1".to_string());
    let lab = start_translated_udp_lab(&snapshot, overrides).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

    client
        .send_to(&[b'r'; 100], lab.gateway_addr(0))
        .await
        .expect("send first request");
    let replies = recv_n(&client, 1, REPLY_TIMEOUT).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].len(), 800);

    // Reuse the session after consuming the entire first request's credit.
    // The next 800-byte reply exceeds this request's 792-byte allowance.
    client
        .send_to(&[b'r'; 99], lab.gateway_addr(0))
        .await
        .expect("send second request");
    assert!(recv_n(&client, 1, NO_REPLY_WINDOW).await.is_empty());
    lab.shutdown().await;
}

#[tokio::test]
async fn route_policy_tightens_then_delete_restores_default() {
    let backend = BurstBackend::start(vec![b'z'; 200], 1).await;
    let service = BurstBackend::service();
    let route = RouteSpec {
        gateway: "edge",
        section: "dns",
        route: "dns",
        backend_refs: json!([{"name": service.as_str(), "port": backend.port}]),
    };
    let with_policy = LabSnapshot {
        services: vec![(service.clone(), backend.port)],
        routes: vec![route.clone()],
        extra_objects: vec![amp_policy("dns", 1.0)],
    };
    let without_policy = LabSnapshot {
        services: vec![(service.clone(), backend.port)],
        routes: vec![route],
        extra_objects: Vec::new(),
    };
    let mut overrides = HashMap::new();
    overrides.insert(BurstBackend::dns_name(), "127.0.0.1".to_string());

    let tight = start_translated_udp_lab(&with_policy, overrides.clone()).await;
    assert_eq!(
        tight.sole_udp_proxy().udp_max_response_amplification_factor,
        Some(1.0)
    );
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let request = vec![b'r'; 100];
    client
        .send_to(&request, tight.gateway_addr(0))
        .await
        .expect("send");
    let dropped = recv_n(&client, 2, NO_REPLY_WINDOW).await;
    assert!(dropped.is_empty(), "factor 1 must drop a 200-byte reply");
    tight.shutdown().await;

    let restored = start_translated_udp_lab(&without_policy, overrides).await;
    assert_eq!(
        restored
            .sole_udp_proxy()
            .udp_max_response_amplification_factor,
        Some(8.0)
    );
    client
        .send_to(&request, restored.gateway_addr(0))
        .await
        .expect("send");
    let replies = recv_n(&client, 2, REPLY_TIMEOUT).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].len(), 200);
    restored.shutdown().await;
}
