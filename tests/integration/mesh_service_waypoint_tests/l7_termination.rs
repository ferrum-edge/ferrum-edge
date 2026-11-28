//! ServiceWaypoint L7 termination on HBONE `:15008` (issue #7501).
//!
//! Every test here drives a REAL HBONE tunnel: a mutually authenticated
//! HTTP/2 `CONNECT` to the production listener and dispatcher
//! (`start_proxy_listener_with_bound_listener_and_mesh_direction`, inbound
//! direction), whose upgraded stream then carries inner HTTP/1.1 or HTTP/2
//! requests that the waypoint terminates and dispatches through the bound
//! Service's route partition to real HTTP backends.
//!
//! The configuration is built the way production builds it: the Kubernetes
//! translator writes the VirtualServices, the control plane filters and
//! projects the ServiceWaypoint slice, and the data plane materializes it
//! (`prepare_gateway_config_from_mesh_slice`). The waypoint runs the explicit
//! no-identity development posture, so it dials its backing workloads (real
//! loopback HTTP servers) in plaintext; the tunnel itself is always mTLS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::_test_support::{
    cp_filter_config_to_mesh_request_for_test, publish_prepared_mesh_config_for_test,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshPolicy, MeshRule, MeshService, MeshWaypointBinding, MeshWaypointServiceRef,
    PolicyAction, PolicyScope, PolicyTargetAttachment, PrincipalMatch, ServicePort,
    ServiceTargetPort, Workload, WorkloadPort, WorkloadRef,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, MeshTrafficDirection, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::proxy::hbone_admission_fence::HboneRevocationReason;
use ferrum_edge::proxy::service_waypoint_l7_proxy::{
    ServiceWaypointL7TunnelTermination, ServiceWaypointRouteRefusal, l7_tunnel_terminations,
    l7_tunnels_active, route_refusals,
};
use ferrum_edge::proxy::{
    ConfigApplyOutcome, ProxyState, start_proxy_listener_with_bound_listener_and_mesh_direction,
};
use serde_json::json;

use super::super::mesh_hbone_tests::{
    HboneMtlsCerts, connect_hbone_h2_mtls, frame_datagram, generate_hbone_mtls_certs,
    hbone_client_config, hbone_server_config, read_framed_datagram, start_external_udp_echo,
    udp_connect_request,
};
use super::super::mesh_test_support::{
    BackendCaptureLog, BackendResponder, runtime_for_topology, start_http_backend, workload_for,
};

const NAMESPACE: &str = "default";
const WAYPOINT_NAME: &str = "waypoint";
const CLIENT_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/client";
/// A peer the waypoint trusts to assert a source principal over HBONE baggage
/// (`trusted_hbone_assertors: ["ztunnel"]`, same-namespace grant).
const ZTUNNEL_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/ztunnel";
const FRONTEND_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/frontend";
const SERVICE_PORT: u16 = 8080;
const STREAM_SERVICE_PORT: u16 = 9000;
const UDP_SERVICE_PORT: u16 = 5353;
const REVIEWS_VIP: &str = "10.96.0.11";
const RATINGS_VIP: &str = "10.96.0.12";
const DEADLINE: Duration = Duration::from_secs(10);
/// The Istio root namespace of the fixture mesh (where a `GatewayClass`
/// `targetRef` policy lives).
const ROOT_NAMESPACE: &str = "istio-system";

fn host(service: &str) -> String {
    format!("{service}.{NAMESPACE}.svc.cluster.local")
}

// ── Configuration ──────────────────────────────────────────────────────────

fn virtual_service(name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "VirtualService".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: NAMESPACE.to_string(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// The reviews VirtualService most tests use: a 90/10 split between the two
/// bound Services.
fn split_90_10() -> serde_json::Value {
    json!({
        "hosts": [host("reviews")],
        "http": [{
            "route": [
                {"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}, "weight": 90},
                {"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}, "weight": 10}
            ]
        }]
    })
}

/// Header, URI and method match dispatch plus a rewrite and a fault on the
/// reviews host.
fn match_dispatch_spec() -> serde_json::Value {
    json!({
        "hosts": [host("reviews")],
        "http": [
            {
                "match": [{"headers": {"x-canary": {"exact": "true"}}}],
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "match": [{"uri": {"prefix": "/legacy"}}],
                "rewrite": {"uri": "/modern"},
                "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "match": [{"uri": {"prefix": "/teapot"}}],
                "fault": {"abort": {"httpStatus": 418, "percentage": {"value": 100}}},
                "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "match": [{"method": {"exact": "DELETE"}}],
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "match": [{"sourceNamespace": "default", "uri": {"prefix": "/same-namespace"}}],
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
            }
        ]
    })
}

/// Standalone CORS policy on the reviews host. Kept separate from
/// [`match_dispatch_spec`] because proxy-scoped route-local plugins (such as
/// `cors`) fail closed when a route must collapse with sibling guarded routes.
fn cors_policy_spec() -> serde_json::Value {
    json!({
        "hosts": [host("reviews")],
        "http": [{
            "corsPolicy": {
                "allowOrigins": [{"exact": "https://ui.example"}],
                "allowMethods": ["GET"]
            },
            "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
        }]
    })
}

#[test]
fn route_local_cors_is_refused_when_dispatch_requires_collapse() {
    let mut spec = match_dispatch_spec();
    let fallback = spec["http"]
        .as_array_mut()
        .and_then(|routes| routes.last_mut())
        .expect("fixture: default route");
    fallback["corsPolicy"] = cors_policy_spec()["http"][0]["corsPolicy"].clone();

    let error = translate_k8s_objects(
        &[virtual_service("reviews-merged-cors", spec)],
        K8sTranslationOptions::new(
            NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .expect_err("route-local CORS must not leak onto sibling routes");
    assert!(
        error.to_string().contains("merged with another route"),
        "unexpected collapse error: {error}"
    );
}

fn translate(config: &mut GatewayConfig, objects: &[K8sObject]) {
    if objects.is_empty() {
        return;
    }
    let translated = translate_k8s_objects(
        objects,
        K8sTranslationOptions::new(
            NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .expect("VirtualService translates")
    .config;
    config.proxies.extend(translated.proxies);
    config.upstreams.extend(translated.upstreams);
    config.plugin_configs.extend(translated.plugin_configs);
    if let Some(mesh) = translated.mesh {
        let target = config.mesh.get_or_insert_with(Box::default);
        target
            .virtual_service_http_routes
            .extend(mesh.virtual_service_http_routes);
        target.destination_rules.extend(mesh.destination_rules);
    }
}

fn destination_rule(name: &str, spec: serde_json::Value) -> K8sObject {
    let mut object = virtual_service(name, spec);
    object.kind = "DestinationRule".to_string();
    object
}

fn workload_port(port: u16, protocol: AppProtocol, name: &str) -> WorkloadPort {
    WorkloadPort {
        port,
        protocol,
        name: Some(name.to_string()),
    }
}

fn service_port(port: u16, protocol: AppProtocol, name: &str, target: u16) -> ServicePort {
    ServicePort {
        port,
        protocol,
        name: Some(name.to_string()),
        target_port: Some(ServiceTargetPort::Number(target)),
    }
}

fn mesh_service(
    name: &str,
    cluster_ip: &str,
    ports: Vec<ServicePort>,
    workload: &Workload,
) -> MeshService {
    MeshService {
        cluster_ips: vec![cluster_ip.to_string()],
        name: name.to_string(),
        namespace: NAMESPACE.to_string(),
        ports,
        workloads: vec![WorkloadRef {
            spiffe_id: workload.spiffe_id.clone(),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
        allow_path_parameters: false,
    }
}

/// The real loopback backends behind the bound Services.
struct Backends {
    reviews: SocketAddr,
    reviews_log: BackendCaptureLog,
    ratings: SocketAddr,
    ratings_log: BackendCaptureLog,
    /// Raw TCP echo on the reviews workload's stream-family port.
    tcp_echo: SocketAddr,
    /// UDP echo on the reviews workload's datagram port.
    udp_echo: SocketAddr,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Answers `<marker>\n<request head>` so a test can see which Service served
/// a request and the request line and headers it received.
fn marker_responder(marker: &'static str) -> (BackendResponder, BackendCaptureLog) {
    let log: BackendCaptureLog = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = Arc::clone(&log);
    let responder: BackendResponder = Arc::new(move |request: &str| {
        if let Ok(mut guard) = captured.lock() {
            guard.push(request.to_string());
        }
        format!("{marker}\n{request}").into_bytes()
    });
    (responder, log)
}

async fn start_tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind tcp echo");
    let addr = listener.local_addr().expect("tcp echo addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

async fn start_backends() -> Backends {
    let (reviews_responder, reviews_log) = marker_responder("reviews");
    let (ratings_responder, ratings_log) = marker_responder("ratings");
    let (reviews, reviews_handle) = start_http_backend(reviews_responder).await;
    let (ratings, ratings_handle) = start_http_backend(ratings_responder).await;
    let (tcp_echo, tcp_handle) = start_tcp_echo().await;
    let (udp_echo, udp_handle) = start_external_udp_echo().await;
    Backends {
        reviews,
        reviews_log,
        ratings,
        ratings_log,
        tcp_echo,
        udp_echo,
        handles: vec![reviews_handle, ratings_handle, tcp_handle, udp_handle],
    }
}

impl Backends {
    fn requests_to(&self, log: &BackendCaptureLog) -> Vec<String> {
        let _ = self;
        log.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    fn stop(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

/// What a fixture binds and attaches.
#[derive(Default)]
struct Scenario {
    virtual_services: Vec<K8sObject>,
    policies: Vec<MeshPolicy>,
    ext_authz_providers: Vec<ferrum_edge::modes::mesh::config::MeshExtAuthzProvider>,
    request_authentications: Vec<ferrum_edge::modes::mesh::config::MeshRequestAuthentication>,
    /// Hostnames the waypoint's DNS cache resolves to loopback.
    dns_overrides: Vec<String>,
    /// Bind `ratings` to the waypoint too (it is always modeled).
    unbind_ratings: bool,
    /// A second bound Service sharing the reviews workload's HTTP endpoint,
    /// making that backing endpoint ambiguous.
    ambiguous_alias: bool,
    /// The waypoint's tunnel idle timeout (`FERRUM_TCP_IDLE_TIMEOUT_SECONDS`).
    tcp_idle_timeout_seconds: Option<u64>,
    /// A `trusted_hbone_assertors` value written onto the mesh-managed
    /// `mesh_authz` instance (object grants exist only on a plugin override).
    assertor_grants: Option<serde_json::Value>,
}

fn cp_config(backends: &Backends, scenario: &Scenario) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    translate(&mut config, &scenario.virtual_services);
    let mut reviews = workload_for("reviews", NAMESPACE, [("app", "reviews")], ["127.0.0.1"]);
    reviews.ports = vec![
        workload_port(backends.reviews.port(), AppProtocol::Http, "http"),
        workload_port(backends.tcp_echo.port(), AppProtocol::Tcp, "tcp"),
        workload_port(backends.udp_echo.port(), AppProtocol::Udp, "udp"),
    ];
    let mut ratings = workload_for("ratings", NAMESPACE, [("app", "ratings")], ["127.0.0.1"]);
    ratings.ports = vec![workload_port(
        backends.ratings.port(),
        AppProtocol::Http,
        "http",
    )];
    let mut services = vec![
        mesh_service(
            "reviews",
            REVIEWS_VIP,
            vec![
                service_port(
                    SERVICE_PORT,
                    AppProtocol::Http,
                    "http",
                    backends.reviews.port(),
                ),
                service_port(
                    STREAM_SERVICE_PORT,
                    AppProtocol::Tcp,
                    "tcp",
                    backends.tcp_echo.port(),
                ),
                service_port(
                    UDP_SERVICE_PORT,
                    AppProtocol::Udp,
                    "udp",
                    backends.udp_echo.port(),
                ),
            ],
            &reviews,
        ),
        mesh_service(
            "ratings",
            RATINGS_VIP,
            vec![service_port(
                SERVICE_PORT,
                AppProtocol::Http,
                "http",
                backends.ratings.port(),
            )],
            &ratings,
        ),
    ];
    let mut bound = vec!["reviews".to_string()];
    if !scenario.unbind_ratings {
        bound.push("ratings".to_string());
    }
    if scenario.ambiguous_alias {
        services.push(mesh_service(
            "reviews-alias",
            "10.96.0.13",
            vec![service_port(
                SERVICE_PORT,
                AppProtocol::Http,
                "http",
                backends.reviews.port(),
            )],
            &reviews,
        ));
        bound.push("reviews-alias".to_string());
    }
    let mut workloads = vec![reviews, ratings];
    if scenario.ambiguous_alias {
        // The alias Service's own backing record: the SAME pod (identity,
        // address and port) attached to `reviews-alias`, so both bound
        // Services materialize an L7 binding on one backing endpoint.
        let mut alias = workloads[0].clone();
        alias.service_name = "reviews-alias".to_string();
        workloads.push(alias);
    }
    let mesh = config.mesh.get_or_insert_with(Box::default);
    mesh.services = services;
    mesh.workloads = workloads;
    mesh.waypoint_bindings = vec![MeshWaypointBinding {
        name: WAYPOINT_NAME.to_string(),
        namespace: NAMESPACE.to_string(),
        waypoint_for: "service".to_string(),
        gateway_class_name: Some("istio-waypoint".to_string()),
        services: bound
            .into_iter()
            .map(|name| MeshWaypointServiceRef {
                namespace: NAMESPACE.to_string(),
                name,
            })
            .collect(),
    }];
    mesh.mesh_policies = scenario.policies.clone();
    mesh.ext_authz_providers = scenario.ext_authz_providers.clone();
    mesh.request_authentications = scenario.request_authentications.clone();
    mesh.istio_root_namespace = ROOT_NAMESPACE.to_string();
    config.normalize_fields();
    config.normalize_mesh_fields();
    config
}

fn waypoint_runtime() -> MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::ServiceWaypoint);
    runtime.namespace = NAMESPACE.to_string();
    runtime.waypoint_name = Some(WAYPOINT_NAME.to_string());
    runtime.trusted_hbone_assertors = vec!["ztunnel".to_string()];
    runtime
}

fn prepared(backends: &Backends, scenario: &Scenario) -> GatewayConfig {
    let runtime = waypoint_runtime();
    let request = runtime.mesh_slice_request();
    let filtered =
        cp_filter_config_to_mesh_request_for_test(&cp_config(backends, scenario), &request);
    let slice = MeshSlice::from_gateway_config(&filtered, request);
    let mut prepared =
        prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes");
    // The kind suites relay to pod IPs; these backends listen on loopback, so
    // the L4 relay is given the own-namespace loopback privilege a Sidecar
    // holds. The L7 path never consults it (it dials materialized upstreams).
    if let Some(mesh) = prepared.mesh.as_deref_mut() {
        mesh.inbound_relay_admits_loopback_namespace = true;
    }
    if let Some(grants) = scenario.assertor_grants.as_ref() {
        let authz = prepared
            .plugin_configs
            .iter_mut()
            .find(|plugin| plugin.id == "__mesh_authz")
            .expect("fixture: the mesh-managed mesh_authz instance");
        authz.config["trusted_hbone_assertors"] = grants.clone();
    }
    prepared
}

fn build_state(prepared: GatewayConfig) -> ProxyState {
    build_state_with_dns(prepared, &[], None)
}

fn build_state_with_dns(
    prepared: GatewayConfig,
    loopback_hosts: &[String],
    tcp_idle_timeout_seconds: Option<u64>,
) -> ProxyState {
    let dns = DnsConfig {
        global_overrides: loopback_hosts
            .iter()
            .map(|host| (host.clone(), "127.0.0.1".to_string()))
            .collect(),
        ..DnsConfig::default()
    };
    let mut env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    if let Some(seconds) = tcp_idle_timeout_seconds {
        env_config.tcp_idle_timeout_seconds = seconds;
    }
    ProxyState::new(prepared, DnsCache::new(dns), env_config, None, None)
        .expect("the ServiceWaypoint generation is accepted by the proxy runtime")
        .0
}

/// A running ServiceWaypoint and the client side of one mTLS HTTP/2 session.
struct Waypoint {
    state: ProxyState,
    backends: Backends,
    sender: h2::client::SendRequest<Bytes>,
    conn_task: tokio::task::JoinHandle<Result<(), h2::Error>>,
    shutdown_tx: watch::Sender<bool>,
    certs: HboneMtlsCerts,
    addr: SocketAddr,
}

impl Waypoint {
    async fn start(scenario: Scenario) -> Self {
        Self::start_as(scenario, CLIENT_SPIFFE).await
    }

    async fn start_as(scenario: Scenario, client_spiffe: &str) -> Self {
        Self::start_with(start_backends().await, scenario, client_spiffe).await
    }

    /// Start a waypoint over caller-supplied backends.
    async fn start_with(backends: Backends, scenario: Scenario, client_spiffe: &str) -> Self {
        let state = build_state_with_dns(
            prepared(&backends, &scenario),
            &scenario.dns_overrides,
            scenario.tcp_idle_timeout_seconds,
        );
        assert!(
            !state.router_cache.service_waypoint_l7_routes().is_empty(),
            "fixture: the waypoint builds bound-Service partitions"
        );
        let certs = generate_hbone_mtls_certs(client_spiffe);
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind waypoint");
        let addr = listener.local_addr().expect("waypoint addr");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_state = state.clone();
        let server_config = hbone_server_config(&certs);
        tokio::spawn(async move {
            let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
                listener,
                serve_state,
                shutdown_rx,
                Some(server_config),
                Some(MeshTrafficDirection::Inbound),
            )
            .await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (sender, conn_task) = connect_hbone_h2_mtls(addr, hbone_client_config(&certs)).await;
        Self {
            state,
            backends,
            sender,
            conn_task,
            shutdown_tx,
            certs,
            addr,
        }
    }

    /// Send an HBONE CONNECT for `authority` with optional extra headers.
    async fn connect_with(
        &mut self,
        authority: &str,
        headers: &[(&str, &str)],
    ) -> (hyper::Response<h2::RecvStream>, h2::SendStream<Bytes>) {
        let mut builder = Request::builder().method(Method::CONNECT).uri(authority);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(()).expect("CONNECT request");
        let (response, send) = self
            .sender
            .send_request(request, false)
            .expect("send CONNECT");
        let response = tokio::time::timeout(DEADLINE, response)
            .await
            .expect("CONNECT answered within the deadline")
            .expect("CONNECT response");
        (response, send)
    }

    /// Open an admitted L7 tunnel to `authority`.
    async fn tunnel(&mut self, authority: &str, headers: &[(&str, &str)]) -> TunnelStream {
        let (response, send) = self.connect_with(authority, headers).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an authenticated CONNECT to a bound Service HTTP port is admitted"
        );
        TunnelStream {
            send,
            recv: response.into_body(),
            buffered: Bytes::new(),
        }
    }

    async fn teardown(self) {
        let _ = self.shutdown_tx.send(true);
        self.conn_task.abort();
        self.backends.stop();
    }
}

// ── The tunnel as an inner-HTTP transport ──────────────────────────────────

/// One HBONE CONNECT stream as a byte transport for an inner HTTP client.
struct TunnelStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    buffered: Bytes,
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.buffered.is_empty() {
                let n = buf.remaining().min(this.buffered.len());
                let chunk = this.buffered.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match ready!(this.recv.poll_data(cx)) {
                None => return Poll::Ready(Ok(())),
                Some(Ok(chunk)) => {
                    let _ = this.recv.flow_control().release_capacity(chunk.len());
                    this.buffered = chunk;
                }
                Some(Err(error)) => return Poll::Ready(Err(std::io::Error::other(error))),
            }
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(buf.len());
        match ready!(this.send.poll_capacity(cx)) {
            None => Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))),
            Some(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
            Some(Ok(capacity)) => {
                let n = capacity.min(buf.len());
                this.send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(std::io::Error::other)?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self.get_mut().send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

type InnerH1 = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

async fn inner_http1(tunnel: TunnelStream) -> InnerH1 {
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tunnel))
        .await
        .expect("inner HTTP/1.1 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

/// An inner response: status, headers and body text.
struct InnerResponse {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: String,
}

impl InnerResponse {
    /// The serving backend's marker (first body line).
    fn served_by(&self) -> &str {
        self.body.lines().next().unwrap_or_default()
    }
}

async fn send_h1(sender: &mut InnerH1, request: Request<Empty<Bytes>>) -> InnerResponse {
    sender.ready().await.expect("inner HTTP/1.1 sender ready");
    let response = tokio::time::timeout(DEADLINE, sender.send_request(request))
        .await
        .expect("inner response within the deadline")
        .expect("inner response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("inner body")
        .to_bytes();
    InnerResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn get(path: &str, host_header: &str) -> Request<Empty<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", host_header)
        .body(Empty::new())
        .expect("inner request")
}

/// The peer must see its CONNECT stream reset with `RST_STREAM(CONNECT_ERROR)`,
/// never a clean `END_STREAM`. Bytes buffered before the reset are drained.
async fn assert_reset_with_connect_error(recv: &mut h2::RecvStream) {
    let error = tokio::time::timeout(DEADLINE, async {
        loop {
            match recv.data().await {
                None => return None,
                Some(Err(error)) => return Some(error),
                Some(Ok(chunk)) => {
                    let _ = recv.flow_control().release_capacity(chunk.len());
                }
            }
        }
    })
    .await
    .expect("the tunnel ends toward the peer")
    .expect("the tunnel is reset, not ended with END_STREAM");
    assert_eq!(error.reason(), Some(h2::Reason::CONNECT_ERROR));
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    tokio::time::timeout(DEADLINE, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Acceptance: a 90/10 weighted split checked over 1000 selections, through
/// one real HBONE tunnel carrying 1000 inner HTTP/1.1 keep-alive requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_http1_requests_follow_the_bound_services_90_10_split_over_1000_selections() {
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-split", split_90_10())],
        ..Scenario::default()
    })
    .await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let mut reviews = 0usize;
    let mut ratings = 0usize;
    for _ in 0..1000 {
        let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        match response.served_by() {
            "reviews" => reviews += 1,
            "ratings" => ratings += 1,
            other => panic!("unexpected backend marker {other:?}"),
        }
    }
    assert_eq!(reviews + ratings, 1000);
    assert!(
        (850..=950).contains(&reviews),
        "the 90/10 split holds over 1000 selections: reviews={reviews} ratings={ratings}"
    );
    assert!(ratings > 0, "the 10% leg is selected");
    assert_eq!(
        l7_tunnels_active(),
        1,
        "the live tunnel holds one active-tunnel gauge slot"
    );
    waypoint.teardown().await;
}

/// Acceptance: URI, header, method and `sourceNamespace` match dispatch, a
/// URI rewrite and a fault, served at L7 inside the tunnel over inner HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_http2_requests_apply_match_dispatch_rewrite_and_fault() {
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-matches", match_dispatch_spec())],
        ..Scenario::default()
    })
    .await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let (mut inner, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tunnel))
            .await
            .expect("inner HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let authority = format!("http://{}:{SERVICE_PORT}", host("reviews"));
    let mut send = |method: Method, path: &str, headers: &[(&str, &str)]| {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{authority}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(Empty::<Bytes>::new()).expect("inner request");
        inner.send_request(request)
    };
    let collect = |response: hyper::Response<hyper::body::Incoming>| async move {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        InnerResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    };

    let plain = collect(send(Method::GET, "/", &[]).await.expect("plain")).await;
    assert_eq!(plain.status, StatusCode::OK);
    assert_eq!(plain.served_by(), "reviews");

    let canary = collect(
        send(Method::GET, "/", &[("x-canary", "true")])
            .await
            .expect("canary"),
    )
    .await;
    assert_eq!(canary.served_by(), "ratings", "header match dispatches");

    let deleted = collect(send(Method::DELETE, "/item", &[]).await.expect("delete")).await;
    assert_eq!(deleted.served_by(), "ratings", "method match dispatches");

    let same_namespace = collect(
        send(Method::GET, "/same-namespace", &[])
            .await
            .expect("source namespace"),
    )
    .await;
    assert_eq!(
        same_namespace.served_by(),
        "ratings",
        "sourceNamespace is matched on the tunnel's verified source principal"
    );

    let legacy = collect(
        send(Method::GET, "/legacy/page", &[])
            .await
            .expect("rewrite"),
    )
    .await;
    assert_eq!(legacy.served_by(), "reviews");
    assert!(
        legacy.body.contains("GET /modern"),
        "the URI rewrite reaches the backend: {}",
        legacy.body
    );

    let teapot = collect(send(Method::GET, "/teapot", &[]).await.expect("fault")).await;
    assert_eq!(teapot.status.as_u16(), 418, "the fault abort answers");
    waypoint.teardown().await;
}

/// Acceptance: a standalone `http[].corsPolicy` on the reviews host answers
/// preflight requests at L7 inside the tunnel over inner HTTP/2 without
/// collapsing onto sibling routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_http2_requests_apply_cors_policy() {
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-cors", cors_policy_spec())],
        ..Scenario::default()
    })
    .await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let (mut inner, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tunnel))
            .await
            .expect("inner HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let authority = format!("http://{}:{SERVICE_PORT}", host("reviews"));
    let mut send = |method: Method, path: &str, headers: &[(&str, &str)]| {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{authority}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(Empty::<Bytes>::new()).expect("inner request");
        inner.send_request(request)
    };
    let collect = |response: hyper::Response<hyper::body::Incoming>| async move {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        InnerResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    };

    let preflight = collect(
        send(
            Method::OPTIONS,
            "/",
            &[
                ("origin", "https://ui.example"),
                ("access-control-request-method", "GET"),
            ],
        )
        .await
        .expect("preflight"),
    )
    .await;
    assert_eq!(
        preflight
            .headers
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://ui.example"),
        "the CORS policy answers the preflight"
    );

    let plain = collect(send(Method::GET, "/", &[]).await.expect("plain")).await;
    assert_eq!(plain.status, StatusCode::OK);
    assert_eq!(plain.served_by(), "reviews");
    waypoint.teardown().await;
}

/// Acceptance: an inner `Host` naming another bound Service (or any other
/// host) inside a tunnel admitted for reviews is refused `403
/// service_waypoint_host_mismatch` and never reaches another Service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_host_spoofing_is_refused_403_and_never_reaches_another_bound_service() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let cutoff = ferrum_edge::time_compat::UtcTimestamp::now();
    for spoofed in [
        host("ratings"),
        "ratings".to_string(),
        format!("{}:{SERVICE_PORT}", host("ratings")),
        "attacker.example.com".to_string(),
        // The bound host on a port the tunnel was not admitted for.
        format!("{}:9999", host("reviews")),
    ] {
        let response = send_h1(&mut inner, get("/", &spoofed)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "inner Host {spoofed:?} is refused"
        );
        assert!(
            response.body.contains("does not match"),
            "the refusal names the host mismatch: {}",
            response.body
        );
    }
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.ratings_log)
            .is_empty(),
        "a spoofed host never reaches the other bound Service"
    );
    assert_eq!(route_refusals(ServiceWaypointRouteRefusal::HostMismatch), 5);
    let denies = ferrum_edge::modes::mesh::policy_deny_log::global().aggregate_recent(cutoff, 50);
    assert!(
        denies
            .grouped
            .iter()
            .any(|group| group.rule == "service_waypoint_host_mismatch"
                && group.source.as_deref() == Some(CLIENT_SPIFFE)),
        "the refusal is on /mesh/policy-denies/recent with the tunnel's principal"
    );
    // The bound Service itself, short name included, still answers.
    for admitted in [host("reviews"), "reviews".to_string()] {
        let response = send_h1(&mut inner, get("/", &admitted)).await;
        assert_eq!(response.status, StatusCode::OK, "{admitted}");
        assert_eq!(response.served_by(), "reviews");
    }
    waypoint.teardown().await;
}

/// Acceptance: non-HTTP bytes inside an HTTP-port CONNECT reset the tunnel
/// with `CONNECT_ERROR` and are never relayed at L4.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_http_bytes_inside_an_http_port_connect_reset_with_connect_error() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    let (response, mut send) = waypoint
        .connect_with(&format!("{REVIEWS_VIP}:{SERVICE_PORT}"), &[])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the ClusterIP authority of a bound Service HTTP port is terminated"
    );
    let mut recv = response.into_body();
    // A TLS ClientHello prefix: not HTTP/1.1, not the HTTP/2 preface.
    send.send_data(
        Bytes::from_static(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\xd4\xfe\x81\x07"),
        false,
    )
    .expect("send non-HTTP bytes");
    assert_reset_with_connect_error(&mut recv).await;
    wait_until(
        || l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::InnerProtocolError) == 1,
        "the inner protocol error termination",
    )
    .await;
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.reviews_log)
            .is_empty(),
        "nothing reached the backing workload: the bytes were never relayed"
    );
    assert_eq!(l7_tunnels_active(), 0);
    waypoint.teardown().await;
}

/// Acceptance: removing the Service's waypoint binding revokes the live L7
/// tunnel through the admission fence and cuts it with `CONNECT_ERROR`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withdrawing_the_binding_revokes_the_live_l7_tunnel_with_connect_error() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    let (response, send) = waypoint
        .connect_with(&format!("{}:{SERVICE_PORT}", host("ratings")), &[])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut tunnel = TunnelStream {
        send,
        recv: response.into_body(),
        buffered: Bytes::new(),
    };
    tunnel
        .write_all(b"GET / HTTP/1.1\r\nhost: ratings\r\n\r\n")
        .await
        .expect("inner request");
    let mut head = vec![0_u8; 12];
    tokio::time::timeout(DEADLINE, tunnel.read_exact(&mut head))
        .await
        .expect("inner response within the deadline")
        .expect("inner response head");
    assert_eq!(&head, b"HTTP/1.1 200");
    assert_eq!(waypoint.state.hbone_admission_fence.live_tunnels(), 1);

    // `istio.io/use-waypoint` is removed from ratings.
    let withdrawn = prepared(
        &waypoint.backends,
        &Scenario {
            unbind_ratings: true,
            ..Scenario::default()
        },
    );
    assert_eq!(
        publish_prepared_mesh_config_for_test(&waypoint.state, withdrawn),
        ConfigApplyOutcome::Applied
    );
    assert_reset_with_connect_error(&mut tunnel.recv).await;
    wait_until(
        || {
            waypoint
                .state
                .hbone_admission_fence
                .revocations(HboneRevocationReason::RelayDestination)
                == 1
        },
        "the relay_destination revocation",
    )
    .await;
    wait_until(
        || l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::FenceRevoked) == 1,
        "the fence_revoked termination",
    )
    .await;
    // The next CONNECT for the unbound Service is no longer terminated.
    let (refused, _send) = waypoint
        .connect_with(&format!("{}:{SERVICE_PORT}", host("ratings")), &[])
        .await;
    assert_ne!(refused.status(), StatusCode::OK);
    waypoint.teardown().await;
}

/// Acceptance: live peer-trust revocation (the enforced CRL now revokes the
/// peer's leaf) cuts the outer L7 tunnel with `CONNECT_ERROR`, and the
/// revoked peer's next CONNECT is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_the_peer_credential_cuts_the_live_l7_tunnel() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    // The inbound admission trust the peer's chain anchors in, so the
    // tunnel's credential is judged by the fence for its whole life.
    let slot = ferrum_edge::tls::shared_bundle_slot(Some(inbound_trust_bundle(&waypoint.certs)));
    waypoint.state.install_mesh_inbound_admission_trust(&slot);

    let (response, _send) = waypoint
        .connect_with(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    assert_eq!(waypoint.state.hbone_admission_fence.live_tunnels(), 1);

    assert!(
        waypoint.state.publish_mesh_inbound_crls(Arc::new(vec![
            waypoint
                .certs
                .signed_crl(&[super::super::mesh_hbone_tests::HBONE_CLIENT_LEAF_SERIAL])
        ])),
        "the enforced CRL set changes"
    );
    assert_reset_with_connect_error(&mut recv).await;
    wait_until(
        || {
            waypoint
                .state
                .hbone_admission_fence
                .revocations(HboneRevocationReason::PeerRevoked)
                == 1
        },
        "the peer_revoked revocation",
    )
    .await;
    wait_until(
        || l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::FenceRevoked) == 1,
        "the fence_revoked termination",
    )
    .await;
    let (refused, _send) = waypoint
        .connect_with(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "the revoked peer's next CONNECT is refused"
    );
    waypoint.teardown().await;
}

/// The inbound admission trust for the fixture CA: the peer's own trust
/// domain anchored on the CA that issued its leaf.
fn inbound_trust_bundle(certs: &HboneMtlsCerts) -> ferrum_edge::identity::SvidBundle {
    use ferrum_edge::identity::{SpiffeId, SvidBundle, TrustBundle, TrustBundleSet};
    SvidBundle {
        spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/waypoint")
            .expect("waypoint spiffe id"),
        cert_chain_der: vec![certs.client_leaf_der()],
        private_key_pkcs8_der: vec![8, 8, 8].into(),
        trust_bundles: TrustBundleSet {
            local: TrustBundle {
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                x509_authorities: vec![certs.ca_der()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Default::default(),
        },
    }
}

/// Acceptance: a CONNECT authority that two bound Services own on the same
/// backing endpoint is refused before any upgrade, never guessed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ambiguous_backing_endpoint_authority_is_refused_before_any_upgrade() {
    let mut waypoint = Waypoint::start(Scenario {
        ambiguous_alias: true,
        ..Scenario::default()
    })
    .await;
    // Both bound Services materialized an L7 binding on the one backing
    // endpoint, so the ambiguity under test is real.
    let reviews_port = waypoint.backends.reviews.port();
    {
        let config = waypoint.state.config.load();
        let bindings = &config
            .mesh
            .as_ref()
            .expect("prepared mesh config")
            .service_waypoint_l7_bindings;
        for service in ["reviews", "reviews-alias"] {
            assert!(
                bindings
                    .iter()
                    .any(|binding| binding.target.service == service
                        && binding.backing_endpoints.iter().any(|(address, port)| {
                            address.is_loopback() && *port == reviews_port
                        })),
                "fixture: {service} materializes an L7 binding on the shared endpoint"
            );
        }
    }
    let reviews_endpoint = format!("127.0.0.1:{reviews_port}");
    let (response, _send) = waypoint.connect_with(&reviews_endpoint, &[]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(l7_tunnels_active(), 0);
    // Each Service's own host stays unambiguous.
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    assert_eq!(
        send_h1(&mut inner, get("/", &host("reviews"))).await.status,
        StatusCode::OK
    );
    waypoint.teardown().await;
}

/// Acceptance: stream-family ports and `connect-udp` on bound Services stay
/// on the L4 relay: the bytes are relayed verbatim, nothing is terminated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_family_ports_and_connect_udp_stay_on_the_l4_relay() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    // A raw TCP stream to the reviews workload's stream-family port.
    let tcp_endpoint = format!("127.0.0.1:{}", waypoint.backends.tcp_echo.port());
    let (response, mut send) = waypoint.connect_with(&tcp_endpoint, &[]).await;
    assert_eq!(response.status(), StatusCode::OK, "the L4 relay admits it");
    let mut recv = response.into_body();
    send.send_data(Bytes::from_static(b"not-http\x00\x01"), false)
        .expect("send raw bytes");
    let echoed = tokio::time::timeout(DEADLINE, recv.data())
        .await
        .expect("echo within the deadline")
        .expect("echo chunk")
        .expect("echo bytes");
    assert_eq!(&echoed[..], b"not-http\x00\x01", "relayed verbatim at L4");

    // A connect-udp tunnel naming the reviews workload's UDP port.
    let udp_endpoint = format!("127.0.0.1:{}", waypoint.backends.udp_echo.port());
    let (udp_response, mut udp_send) = {
        let (response, send) = waypoint
            .sender
            .send_request(udp_connect_request(&udp_endpoint), false)
            .expect("send connect-udp");
        (
            tokio::time::timeout(DEADLINE, response)
                .await
                .expect("connect-udp answered")
                .expect("connect-udp response"),
            send,
        )
    };
    assert_eq!(udp_response.status(), StatusCode::OK);
    let mut udp_recv = udp_response.into_body();
    udp_send
        .send_data(frame_datagram(b"datagram"), false)
        .expect("send datagram");
    let reply = tokio::time::timeout(DEADLINE, read_framed_datagram(&mut udp_recv))
        .await
        .expect("datagram reply within the deadline");
    assert_eq!(reply, b"datagram");

    // Neither tunnel was terminated at L7.
    assert_eq!(l7_tunnels_active(), 0);
    for reason in ServiceWaypointL7TunnelTermination::ALL {
        assert_eq!(l7_tunnel_terminations(reason), 0, "{}", reason.as_str());
    }
    waypoint.teardown().await;
}

/// Acceptance: per-branch AuthorizationPolicy. A DENY attached to the
/// ratings Service (`targetRefs`) refuses the header-dispatched branch to
/// ratings while the route's own destination keeps serving; an ALLOW
/// attached to the waypoint's Gateway admits only the client principal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_branch_authorization_policy_judges_the_selected_branch() {
    let deny_ratings = MeshPolicy {
        name: "deny-ratings".to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::Service {
                namespace: NAMESPACE.to_string(),
                name: "ratings".to_string(),
            }],
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    };
    let allow_client_at_gateway = MeshPolicy {
        name: "allow-client-at-waypoint".to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::Gateway {
                namespace: NAMESPACE.to_string(),
                name: WAYPOINT_NAME.to_string(),
            }],
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-matches", match_dispatch_spec())],
        policies: vec![deny_ratings, allow_client_at_gateway],
        ..Scenario::default()
    })
    .await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let own = send_h1(&mut inner, get("/", &host("reviews"))).await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
    assert_eq!(own.served_by(), "reviews");

    let mut canary = get("/", &host("reviews"));
    canary
        .headers_mut()
        .insert("x-canary", hyper::header::HeaderValue::from_static("true"));
    let branch = send_h1(&mut inner, canary).await;
    assert_eq!(
        branch.status,
        StatusCode::FORBIDDEN,
        "the ratings branch is judged on ratings' own DENY: {}",
        branch.body
    );
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.ratings_log)
            .is_empty(),
        "the denied branch is never dialed"
    );
    waypoint.teardown().await;
}

/// Acceptance: the verified outer peer identity and an honored outer baggage
/// `source.principal` reach every inner request; an inner request's own
/// `baggage` header can never assert an identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outer_baggage_principal_is_honored_and_inner_baggage_is_ignored() {
    let allow_frontend = MeshPolicy {
        name: "allow-frontend".to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::Service {
                namespace: NAMESPACE.to_string(),
                name: "reviews".to_string(),
            }],
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(FRONTEND_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let mut waypoint = Waypoint::start_as(
        Scenario {
            policies: vec![allow_frontend],
            ..Scenario::default()
        },
        ZTUNNEL_SPIFFE,
    )
    .await;
    let authority = format!("{}:{SERVICE_PORT}", host("reviews"));
    let baggage = format!("source.principal={FRONTEND_SPIFFE}");

    // The trusted assertor asserts frontend on the OUTER CONNECT.
    let asserted = waypoint
        .tunnel(&authority, &[("baggage", baggage.as_str())])
        .await;
    let mut inner = inner_http1(asserted).await;
    let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "the honored outer assertion authorizes the inner request: {}",
        response.body
    );

    // No outer assertion: an inner `baggage` header asserting frontend is
    // application data, never an identity.
    let plain = waypoint.tunnel(&authority, &[]).await;
    let mut inner = inner_http1(plain).await;
    let mut forged = get("/", &host("reviews"));
    forged.headers_mut().insert(
        "baggage",
        hyper::header::HeaderValue::from_str(&baggage).expect("baggage value"),
    );
    let response = send_h1(&mut inner, forged).await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "an inner baggage header cannot assert the principal"
    );
    waypoint.teardown().await;
}

/// Hop-limit loop prevention applies to every inner request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inner_request_at_the_hop_limit_is_refused_loop_detected() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    let limit = waypoint.state.env_config.max_proxy_hops;
    assert!(limit > 0, "fixture: the hop limit is enabled by default");
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let mut looping = get("/", &host("reviews"));
    looping.headers_mut().insert(
        "x-ferrum-hops",
        hyper::header::HeaderValue::from_str(&limit.to_string()).expect("hop value"),
    );
    let response = send_h1(&mut inner, looping).await;
    assert_eq!(response.status, StatusCode::LOOP_DETECTED);
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.reviews_log)
            .is_empty()
    );
    waypoint.teardown().await;
}

/// Acceptance: a direct (non-CONNECT) request on the ServiceWaypoint `:15008`
/// listener never reaches a carried `istio-vs-*` route or a default L7 route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_requests_on_the_waypoint_listener_never_reach_l7_routes() {
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-split", split_90_10())],
        ..Scenario::default()
    })
    .await;
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{}:{SERVICE_PORT}/", host("reviews")))
        .body(())
        .expect("direct request");
    let (response, _send) = waypoint
        .sender
        .send_request(request, true)
        .expect("send direct request");
    let response = tokio::time::timeout(DEADLINE, response)
        .await
        .expect("direct request answered")
        .expect("direct response");
    assert_ne!(response.status(), StatusCode::OK);
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.reviews_log)
            .is_empty()
            && waypoint
                .backends
                .requests_to(&waypoint.backends.ratings_log)
                .is_empty(),
        "a direct request reaches no bound Service"
    );
    let _ = waypoint.addr;
    waypoint.teardown().await;
}

/// A peer that closes its tunnel ends it cleanly (`END_STREAM`), and the
/// active-tunnel gauge follows the tunnel's life.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tunnel_the_peer_closes_ends_cleanly_and_releases_its_gauge_slot() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let (mut inner, connection): (InnerH1, _) =
        hyper::client::conn::http1::handshake(TokioIo::new(tunnel))
            .await
            .expect("inner HTTP/1.1 handshake");
    // Recover the open CONNECT transport so the peer explicitly sends END_STREAM.
    let driver = tokio::spawn(connection.without_shutdown());
    assert_eq!(
        send_h1(&mut inner, get("/", &host("reviews"))).await.status,
        StatusCode::OK
    );
    assert_eq!(l7_tunnels_active(), 1);
    drop(inner);
    let parts = tokio::time::timeout(DEADLINE, driver)
        .await
        .expect("inner HTTP/1.1 driver timed out")
        .expect("inner HTTP/1.1 driver panicked")
        .expect("inner HTTP/1.1 connection failed");
    let mut tunnel = parts.io.into_inner();
    tunnel
        .send
        .send_data(Bytes::new(), true)
        .expect("send outer H2 END_STREAM");
    wait_until(
        || l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::CleanClose) == 1,
        "the clean_close termination",
    )
    .await;
    wait_until(|| l7_tunnels_active() == 0, "the gauge release").await;
    assert_eq!(waypoint.state.hbone_admission_fence.live_tunnels(), 0);
    drop(tunnel);
    waypoint.teardown().await;
}

/// Acceptance: the 90/10 split is checked over 1000 selections when a
/// DestinationRule governs a leg, so the split is dispatched leg by leg, each
/// leg through its own rule-bearing upstream and judged on its own verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_rule_governed_split_is_dispatched_leg_by_leg_90_10() {
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![
            virtual_service("reviews-split", split_90_10()),
            destination_rule(
                "ratings-pool",
                json!({
                    "host": host("ratings"),
                    "trafficPolicy": {"connectionPool": {"tcp": {"connectTimeout": "2s"}}}
                }),
            ),
        ],
        ..Scenario::default()
    })
    .await;
    let leg_dispatched = waypoint
        .state
        .config
        .load()
        .plugin_configs
        .iter()
        .any(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin
                    .config
                    .get("weighted_splits")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|splits| !splits.is_empty())
        });
    assert!(
        leg_dispatched,
        "fixture: the split is dispatched leg by leg"
    );
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let mut reviews = 0usize;
    for _ in 0..1000 {
        let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        if response.served_by() == "reviews" {
            reviews += 1;
        }
    }
    assert!(
        (850..=950).contains(&reviews),
        "the leg-dispatched 90/10 split holds: reviews={reviews}"
    );
    waypoint.teardown().await;
}

/// A scripted loopback backend: answers each request with the status, delay
/// and body `respond` picks from the request head.
type ScriptedResponder = Arc<dyn Fn(&str) -> (u16, Duration, String) + Send + Sync>;

async fn start_scripted_backend(
    respond: ScriptedResponder,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind scripted backend");
    let addr = listener.local_addr().expect("scripted backend addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let respond = Arc::clone(&respond);
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (status, delay, body) = respond(&request);
                tokio::time::sleep(delay).await;
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, handle)
}

/// Acceptance: retries, timeouts and loopback mirrors of a carried route
/// apply to inner requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_requests_apply_retries_timeouts_and_loopback_mirrors() {
    // The mirror target: a loopback listener the translator admits.
    let (mirror_responder, mirror_log) = marker_responder("mirror");
    let (mirror_addr, mirror_handle) = start_http_backend(mirror_responder).await;
    // A flaky / slow path on its own backend, reached through a second
    // route on the reviews host.
    let flaky_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts = Arc::clone(&flaky_attempts);
    let (scripted_addr, scripted_handle) =
        start_scripted_backend(Arc::new(move |request: &str| {
            if request.starts_with("GET /flaky") {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if attempt == 0 {
                    return (503, Duration::ZERO, "flaky-first".to_string());
                }
                return (200, Duration::ZERO, "flaky-recovered".to_string());
            }
            if request.starts_with("GET /slow") {
                return (200, Duration::from_secs(3), "too-late".to_string());
            }
            (200, Duration::ZERO, "scripted".to_string())
        }))
        .await;
    let spec = json!({
        "hosts": [host("reviews")],
        "http": [
            {
                "match": [{"uri": {"prefix": "/flaky"}}],
                "retries": {"attempts": 2, "retryOn": "5xx"},
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "match": [{"uri": {"prefix": "/slow"}}],
                "timeout": "0.3s",
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "mirror": {"host": "127.0.0.1", "port": {"number": mirror_addr.port()}},
                "mirrorPercentage": {"value": 100},
                "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
            }
        ]
    });
    let backends = start_backends().await;
    // Ratings is served by the scripted backend in this scenario.
    let mut scripted = Backends {
        ratings: scripted_addr,
        ..backends
    };
    scripted.handles.push(scripted_handle);
    scripted.handles.push(mirror_handle);
    let state = build_state(prepared(
        &scripted,
        &Scenario {
            virtual_services: vec![virtual_service("reviews-policies", spec)],
            ..Scenario::default()
        },
    ));
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind waypoint");
    let addr = listener.local_addr().expect("waypoint addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let serve_state = state.clone();
    let server_config = hbone_server_config(&certs);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            serve_state,
            shutdown_rx,
            Some(server_config),
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (sender, conn_task) = connect_hbone_h2_mtls(addr, hbone_client_config(&certs)).await;
    let mut waypoint = Waypoint {
        state,
        backends: scripted,
        sender,
        conn_task,
        shutdown_tx,
        certs,
        addr,
    };
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;

    let flaky = send_h1(&mut inner, get("/flaky", &host("reviews"))).await;
    assert_eq!(
        flaky.status,
        StatusCode::OK,
        "the retry recovers: {}",
        flaky.body
    );
    assert_eq!(flaky.body, "flaky-recovered");
    assert_eq!(
        flaky_attempts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "exactly one retry"
    );

    let slow = send_h1(&mut inner, get("/slow", &host("reviews"))).await;
    assert_eq!(
        slow.status,
        StatusCode::GATEWAY_TIMEOUT,
        "the route timeout fires"
    );

    let mirrored = send_h1(&mut inner, get("/mirrored", &host("reviews"))).await;
    assert_eq!(mirrored.status, StatusCode::OK);
    assert_eq!(mirrored.served_by(), "reviews");
    wait_until(
        || {
            mirror_log
                .lock()
                .map(|log| {
                    log.iter()
                        .any(|request| request.starts_with("GET /mirrored"))
                })
                .unwrap_or(false)
        },
        "the loopback mirror copy",
    )
    .await;
    waypoint.teardown().await;
}

/// A loopback ext_authz stub that denies every check and counts them.
async fn start_denying_ext_authz() -> (
    SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&checks);
    let (addr, handle) = start_scripted_backend(Arc::new(move |_request: &str| {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        (403, Duration::ZERO, "denied-by-provider".to_string())
    }))
    .await;
    (addr, checks, handle)
}

fn ext_authz_provider(port: u16) -> ferrum_edge::modes::mesh::config::MeshExtAuthzProvider {
    ferrum_edge::modes::mesh::config::MeshExtAuthzProvider {
        name: "branch-authz".to_string(),
        service: "127.0.0.1".to_string(),
        port,
        tls: false,
        path_prefix: Some("/check".to_string()),
        timeout_ms: 2_000,
        fail_open: false,
        status_on_error: 403,
        include_request_headers_in_check: Vec::new(),
        include_additional_headers_in_check: Vec::new(),
        include_request_body_in_check: None,
        headers_to_upstream_on_allow: Vec::new(),
        headers_to_downstream_on_deny: Vec::new(),
        headers_to_downstream_on_allow: Vec::new(),
    }
}

/// Acceptance: per-branch CUSTOM AuthorizationPolicy. A CUSTOM delegation
/// attached to ratings runs ONLY when route dispatch selects the ratings
/// branch, and its provider's denial refuses that request; the route's own
/// destination never consults the provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_custom_policy_runs_only_for_the_selected_branch() {
    let (provider_addr, checks, provider_handle) = start_denying_ext_authz().await;
    let custom_on_ratings = MeshPolicy {
        name: "custom-ratings".to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::Service {
                namespace: NAMESPACE.to_string(),
                name: "ratings".to_string(),
            }],
        },
        rules: vec![MeshRule {
            to: vec![ferrum_edge::modes::mesh::config::RequestMatch {
                paths: vec!["/*".to_string()],
                ..Default::default()
            }],
            action: PolicyAction::Custom {
                provider: "branch-authz".to_string(),
            },
            ..MeshRule::default()
        }],
    };
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-matches", match_dispatch_spec())],
        policies: vec![custom_on_ratings],
        ext_authz_providers: vec![ext_authz_provider(provider_addr.port())],
        ..Scenario::default()
    })
    .await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;

    let own = send_h1(&mut inner, get("/", &host("reviews"))).await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
    assert_eq!(own.served_by(), "reviews");
    assert_eq!(
        checks.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the unselected ratings branch's CUSTOM check never runs"
    );

    let mut canary = get("/", &host("reviews"));
    canary
        .headers_mut()
        .insert("x-canary", hyper::header::HeaderValue::from_static("true"));
    let branch = send_h1(&mut inner, canary).await;
    assert_eq!(
        branch.status,
        StatusCode::FORBIDDEN,
        "the selected branch's provider denies: {}",
        branch.body
    );
    assert_eq!(
        checks.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one check, for the selected branch"
    );
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.ratings_log)
            .is_empty()
    );
    provider_handle.abort();
    waypoint.teardown().await;
}

/// Acceptance: an AuthorizationPolicy attached to the waypoint's
/// `GatewayClass` (from the root namespace) applies to every destination the
/// waypoint serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gateway_class_target_ref_policy_applies_at_the_waypoint() {
    let deny_admin = MeshPolicy {
        name: "deny-admin-on-waypoints".to_string(),
        namespace: ROOT_NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::GatewayClass {
                name: "istio-waypoint".to_string(),
            }],
        },
        rules: vec![MeshRule {
            to: vec![ferrum_edge::modes::mesh::config::RequestMatch {
                paths: vec!["/admin*".to_string()],
                ..Default::default()
            }],
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    };
    let mut waypoint = Waypoint::start(Scenario {
        policies: vec![deny_admin],
        ..Scenario::default()
    })
    .await;
    for service in ["reviews", "ratings"] {
        let tunnel = waypoint
            .tunnel(&format!("{}:{SERVICE_PORT}", host(service)), &[])
            .await;
        let mut inner = inner_http1(tunnel).await;
        let public = send_h1(&mut inner, get("/public", &host(service))).await;
        assert_eq!(public.status, StatusCode::OK, "{service}: {}", public.body);
        let admin = send_h1(&mut inner, get("/admin/keys", &host(service))).await;
        assert_eq!(
            admin.status,
            StatusCode::FORBIDDEN,
            "{service}: the GatewayClass-attached DENY applies at L7"
        );
    }
    waypoint.teardown().await;
}

/// Acceptance: destination-scoped RequestAuthentication. The JWT providers
/// of a RequestAuthentication selecting the reviews workloads validate inner
/// requests to reviews, and never apply to ratings on the same waypoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_authentication_follows_the_destination_service() {
    use ferrum_edge::modes::mesh::config::{
        MeshJwtRule, MeshRequestAuthentication, WorkloadSelector,
    };
    // RFC 7517 Appendix A.1 EC P-256 public key, used for signatures here.
    let jwks = json!({"keys": [{
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "use": "sig",
        "alg": "ES256",
        "kid": "1"
    }]})
    .to_string();
    let reviews_jwt = MeshRequestAuthentication {
        name: "reviews-jwt".to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: [("app".to_string(), "reviews".to_string())]
                    .into_iter()
                    .collect(),
                namespace: Some(NAMESPACE.to_string()),
            },
        },
        jwt_rules: vec![MeshJwtRule {
            issuer: "https://issuer.example".to_string(),
            audiences: Vec::new(),
            jwks_uri: None,
            jwks: Some(jwks),
            from_headers: Vec::new(),
            from_params: Vec::new(),
            forward_original_token: false,
            output_claim_to_headers: Vec::new(),
        }],
        refused: false,
    };
    let mut waypoint = Waypoint::start(Scenario {
        request_authentications: vec![reviews_jwt],
        ..Scenario::default()
    })
    .await;
    let forged = "Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.c2lnbmF0dXJl";
    let with_token = |service: &str| {
        let mut request = get("/", &host(service));
        request.headers_mut().insert(
            hyper::header::AUTHORIZATION,
            hyper::header::HeaderValue::from_static(forged),
        );
        request
    };

    let reviews_tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut reviews = inner_http1(reviews_tunnel).await;
    let refused = send_h1(&mut reviews, with_token("reviews")).await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "reviews' RequestAuthentication rejects a token it cannot verify: {}",
        refused.body
    );
    let anonymous = send_h1(&mut reviews, get("/", &host("reviews"))).await;
    assert_eq!(
        anonymous.status,
        StatusCode::OK,
        "a request without a token is not refused by RequestAuthentication alone"
    );

    let ratings_tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("ratings")), &[])
        .await;
    let mut ratings = inner_http1(ratings_tunnel).await;
    let untouched = send_h1(&mut ratings, with_token("ratings")).await;
    assert_eq!(
        untouched.status,
        StatusCode::OK,
        "reviews' providers never apply to ratings: {}",
        untouched.body
    );
    waypoint.teardown().await;
}

/// A loopback HTTPS backend with a self-signed certificate for `hostname`.
async fn start_tls_backend(hostname: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().expect("tls backend key");
    let params = rcgen::CertificateParams::new(vec![hostname.to_string()]).expect("params");
    let cert = params
        .self_signed(&key)
        .expect("self-signed tls backend cert");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
        .expect("tls backend config");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind tls backend");
    let addr = listener.local_addr().expect("tls backend addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0_u8; 4096];
                if matches!(tls.read(&mut buf).await, Ok(0) | Err(_)) {
                    return;
                }
                let body = "tls-external\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, handle)
}

/// Acceptance: a 90/10 split with an external residual leg whose
/// DestinationRule originates TLS, checked over 1000 selections: the
/// external leg is dialed over TLS, the Service leg keeps its transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_external_residual_leg_originates_the_tls_its_destination_rule_requires() {
    // Three labels: a two-label host is a Service alias (`<svc>.<ns>`).
    const EXTERNAL_HOST: &str = "api.tls-external.test";
    let (tls_addr, tls_handle) = start_tls_backend(EXTERNAL_HOST).await;
    let split = json!({
        "hosts": [host("reviews")],
        "http": [{
            "route": [
                {"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}, "weight": 90},
                {"destination": {"host": EXTERNAL_HOST, "port": {"number": tls_addr.port()}}, "weight": 10}
            ]
        }]
    });
    let originate = json!({
        "host": EXTERNAL_HOST,
        "trafficPolicy": {"tls": {"mode": "SIMPLE", "sni": EXTERNAL_HOST, "insecureSkipVerify": true}}
    });
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![
            virtual_service("reviews-external-split", split),
            destination_rule("external-tls", originate),
        ],
        dns_overrides: vec![EXTERNAL_HOST.to_string()],
        ..Scenario::default()
    })
    .await;
    let originating_leg = waypoint
        .state
        .config
        .load()
        .plugin_configs
        .iter()
        .any(|plugin| {
            plugin
                .config
                .get("weighted_splits")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .flat_map(|split| {
                    split
                        .get("legs")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .any(|leg| {
                    leg.get("originate_tls")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                })
        });
    assert!(
        originating_leg,
        "fixture: the external residual leg originates TLS"
    );
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let mut external = 0usize;
    let mut reviews = 0usize;
    for _ in 0..1000 {
        let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        match response.served_by() {
            "tls-external" => external += 1,
            "reviews" => reviews += 1,
            other => panic!("unexpected backend marker {other:?}"),
        }
    }
    assert!(
        (850..=950).contains(&reviews) && (50..=150).contains(&external),
        "90/10 across the Service leg and the TLS-originating external leg: \
         reviews={reviews} external={external}"
    );
    tls_handle.abort();
    waypoint.teardown().await;
}

// ── Review findings (#7545) ────────────────────────────────────────────────

/// The reviews VirtualService of the identity-matrix tests: a header-matched
/// branch to the bound ratings Service, every other request to an external
/// host (whose destination is judged on waypoint-wide policies only and
/// stamps no authorized destination).
fn external_fallback_spec(external_host: &str, external_port: u16) -> serde_json::Value {
    json!({
        "hosts": [host("reviews")],
        "http": [
            {
                "match": [{"headers": {"x-canary": {"exact": "true"}}}],
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "route": [{"destination": {"host": external_host, "port": {"number": external_port}}}]
            }
        ]
    })
}

fn principal_policy(name: &str, service: &str, action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::Service {
                namespace: NAMESPACE.to_string(),
                name: service.to_string(),
            }],
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(FRONTEND_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            action,
            ..MeshRule::default()
        }],
    }
}

fn canary_request() -> Request<Empty<Bytes>> {
    let mut request = get("/", &host("reviews"));
    request
        .headers_mut()
        .insert("x-canary", hyper::header::HeaderValue::from_static("true"));
    request
}

/// Review F1: every outer identity case (an allowed assertor, a disallowed
/// assertor, no baggage, malformed baggage) against an ALLOW and a DENY on
/// the ratings branch of a route whose own destination is external. The
/// branch is always judged on its own verdict for the principal the tunnel
/// actually carries (a discarded assertion leaves the verified certificate
/// principal), never admitted for lack of one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_outer_identity_case_is_judged_on_the_selected_branch_verdict() {
    const EXTERNAL_HOST: &str = "api.plain-external.test";
    let frontend = format!("source.principal={FRONTEND_SPIFFE}");
    // (case, peer, outer baggage, ALLOW-frontend outcome, DENY-frontend outcome)
    let cases: [(&str, &str, Option<&str>, StatusCode, StatusCode); 4] = [
        (
            "allowed assertor",
            ZTUNNEL_SPIFFE,
            Some(frontend.as_str()),
            StatusCode::OK,
            StatusCode::FORBIDDEN,
        ),
        (
            "disallowed assertor",
            CLIENT_SPIFFE,
            Some(frontend.as_str()),
            StatusCode::FORBIDDEN,
            StatusCode::OK,
        ),
        (
            "absent baggage",
            ZTUNNEL_SPIFFE,
            None,
            StatusCode::FORBIDDEN,
            StatusCode::OK,
        ),
        (
            "malformed baggage",
            ZTUNNEL_SPIFFE,
            Some("source.principal=%%not-a-spiffe-id%%"),
            StatusCode::FORBIDDEN,
            StatusCode::OK,
        ),
    ];
    for action in [PolicyAction::Allow, PolicyAction::Deny] {
        let allow = matches!(action, PolicyAction::Allow);
        for (case, peer, baggage, allow_status, deny_status) in &cases {
            let (external_responder, _external_log) = marker_responder("external");
            let (external_addr, external_handle) = start_http_backend(external_responder).await;
            let mut waypoint = Waypoint::start_as(
                Scenario {
                    virtual_services: vec![virtual_service(
                        "reviews-external-fallback",
                        external_fallback_spec(EXTERNAL_HOST, external_addr.port()),
                    )],
                    policies: vec![principal_policy(
                        "ratings-frontend",
                        "ratings",
                        action.clone(),
                    )],
                    dns_overrides: vec![EXTERNAL_HOST.to_string()],
                    ..Scenario::default()
                },
                peer,
            )
            .await;
            let headers: Vec<(&str, &str)> = baggage
                .map(|value| vec![("baggage", value)])
                .unwrap_or_default();
            let tunnel = waypoint
                .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &headers)
                .await;
            let mut inner = inner_http1(tunnel).await;
            let own = send_h1(&mut inner, get("/", &host("reviews"))).await;
            assert_eq!(
                own.status,
                StatusCode::OK,
                "{case}: the external own destination serves: {}",
                own.body
            );
            assert_eq!(own.served_by(), "external", "{case}");
            let branch = send_h1(&mut inner, canary_request()).await;
            let expected = if allow { *allow_status } else { *deny_status };
            assert_eq!(
                branch.status,
                expected,
                "{case} with {} on ratings: {}",
                if allow { "ALLOW" } else { "DENY" },
                branch.body
            );
            if expected == StatusCode::OK {
                assert_eq!(branch.served_by(), "ratings", "{case}");
            } else {
                assert!(
                    waypoint
                        .backends
                        .requests_to(&waypoint.backends.ratings_log)
                        .is_empty(),
                    "{case}: a refused branch is never dialed"
                );
            }
            external_handle.abort();
            waypoint.teardown().await;
        }
    }
}

/// Review F2: a 90/10 split between two bound Services with NO
/// DestinationRule is still dispatched leg by leg on a ServiceWaypoint, so a
/// DENY attached to the 10% Service refuses only that leg and the 90% leg
/// keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_split_without_a_destination_rule_is_authorized_leg_by_leg() {
    let deny_ratings = MeshPolicy {
        name: "deny-ratings".to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::Service {
                namespace: NAMESPACE.to_string(),
                name: "ratings".to_string(),
            }],
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    };
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-split", split_90_10())],
        policies: vec![deny_ratings],
        ..Scenario::default()
    })
    .await;
    let leg_dispatched = waypoint
        .state
        .config
        .load()
        .plugin_configs
        .iter()
        .any(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin
                    .config
                    .get("weighted_splits")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|splits| !splits.is_empty())
        });
    assert!(
        leg_dispatched,
        "a ServiceWaypoint split is dispatched leg by leg without a DestinationRule"
    );
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let (mut served, mut refused) = (0usize, 0usize);
    for _ in 0..200 {
        let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
        match response.status {
            StatusCode::OK => {
                assert_eq!(response.served_by(), "reviews");
                served += 1;
            }
            StatusCode::FORBIDDEN => refused += 1,
            other => panic!("unexpected status {other}: {}", response.body),
        }
    }
    assert!(
        (160..=195).contains(&served) && refused > 0,
        "only the denied 10% leg is refused: served={served} refused={refused}"
    );
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.ratings_log)
            .is_empty(),
        "the denied leg is never dialed"
    );
    waypoint.teardown().await;
}

/// Review F3: an inner HTTP/1 head the framing guard refuses (conflicting
/// `Content-Length`) ends the inner connection "cleanly" for hyper, yet the
/// outer stream is reset with `CONNECT_ERROR`, never ended with `END_STREAM`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_framing_guard_reject_inside_the_tunnel_resets_with_connect_error() {
    let mut waypoint = Waypoint::start(Scenario::default()).await;
    let (response, mut send) = waypoint
        .connect_with(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
        host("reviews")
    );
    send.send_data(Bytes::from(head), false)
        .expect("send the conflicting head");
    assert_reset_with_connect_error(&mut recv).await;
    wait_until(
        || l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::InnerProtocolError) == 1,
        "the inner protocol error termination",
    )
    .await;
    assert_eq!(
        l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::CleanClose),
        0
    );
    assert!(
        waypoint
            .backends
            .requests_to(&waypoint.backends.reviews_log)
            .is_empty(),
        "the refused head never reached the backend"
    );
    waypoint.teardown().await;
}

/// Review F4: `match.sourceNamespace` follows the caller the tunnel's trusted
/// outer assertion names, not the asserting transport peer, when the two are
/// in different namespaces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_namespace_matches_the_honored_caller_not_the_asserting_peer() {
    const INFRA_ZTUNNEL: &str = "spiffe://cluster.local/ns/infra/sa/ztunnel";
    const TENANT_CALLER: &str = "spiffe://cluster.local/ns/tenant/sa/app";
    let spec = json!({
        "hosts": [host("reviews")],
        "http": [
            {
                "match": [{"sourceNamespace": "tenant"}],
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
            }
        ]
    });
    let mut waypoint = Waypoint::start_as(
        Scenario {
            virtual_services: vec![virtual_service("reviews-by-source", spec)],
            assertor_grants: Some(json!([
                {"assertor": INFRA_ZTUNNEL, "asserts": [TENANT_CALLER]}
            ])),
            ..Scenario::default()
        },
        INFRA_ZTUNNEL,
    )
    .await;
    let authority = format!("{}:{SERVICE_PORT}", host("reviews"));
    let baggage = format!("source.principal={TENANT_CALLER}");
    let asserted = waypoint
        .tunnel(&authority, &[("baggage", baggage.as_str())])
        .await;
    let mut inner = inner_http1(asserted).await;
    let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(
        response.served_by(),
        "ratings",
        "the honored tenant caller matches sourceNamespace: tenant"
    );
    // The peer alone (infra) does not match.
    let plain = waypoint.tunnel(&authority, &[]).await;
    let mut inner = inner_http1(plain).await;
    let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.served_by(), "reviews");
    waypoint.teardown().await;
}

/// Review F5: `match.port` and a `FROM_REQUEST_PORT` redirect read the bound
/// Service port the tunnel was admitted for, never the HBONE listener port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn match_port_and_request_port_redirects_use_the_bound_service_port() {
    let spec = json!({
        "hosts": [host("reviews")],
        "http": [
            {
                "match": [{"uri": {"prefix": "/moved"}}],
                "redirect": {"uri": "/new", "derivePort": "FROM_REQUEST_PORT"}
            },
            {
                "match": [{"port": SERVICE_PORT, "uri": {"prefix": "/by-port"}}],
                "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
            },
            {
                "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
            }
        ]
    });
    let mut waypoint = Waypoint::start(Scenario {
        virtual_services: vec![virtual_service("reviews-ports", spec)],
        ..Scenario::default()
    })
    .await;
    let listener_port = waypoint.addr.port();
    assert_ne!(listener_port, SERVICE_PORT, "fixture: distinct ports");
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let by_port = send_h1(&mut inner, get("/by-port", &host("reviews"))).await;
    assert_eq!(by_port.status, StatusCode::OK, "{}", by_port.body);
    assert_eq!(
        by_port.served_by(),
        "ratings",
        "match.port {SERVICE_PORT} matches the bound Service port"
    );
    let moved = send_h1(&mut inner, get("/moved", &host("reviews"))).await;
    assert!(
        moved.status.is_redirection(),
        "the redirect answers: {}",
        moved.status
    );
    let location = moved
        .headers
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("redirect Location")
        .to_string();
    assert!(
        location.contains(&format!(":{SERVICE_PORT}/new")),
        "FROM_REQUEST_PORT advertises the bound Service port: {location}"
    );
    assert!(
        !location.contains(&format!(":{listener_port}")),
        "never the HBONE listener port: {location}"
    );
    waypoint.teardown().await;
}

/// A backend that answers with a chunked body: one chunk, a pause of
/// `pause`, then a final chunk.
async fn start_pausing_backend(pause: Duration) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind pausing backend");
    let addr = listener.local_addr().expect("pausing backend addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                if matches!(stream.read(&mut buf).await, Ok(0) | Err(_)) {
                    return;
                }
                let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
                            Content-Type: text/plain\r\nConnection: close\r\n\r\n";
                if stream.write_all(head.as_bytes()).await.is_err()
                    || stream.write_all(b"8\r\nreviews\n\r\n").await.is_err()
                {
                    return;
                }
                let _ = stream.flush().await;
                tokio::time::sleep(pause).await;
                let _ = stream.write_all(b"6\r\nlater\n\r\n0\r\n\r\n").await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, handle)
}

/// Review F6: a streaming response body that pauses longer than the tunnel
/// idle timeout is still an active request, so the tunnel is not cut and the
/// whole body arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_response_body_pausing_past_the_idle_timeout_is_not_cut() {
    let (pausing_addr, pausing_handle) = start_pausing_backend(Duration::from_millis(2_500)).await;
    let mut backends = start_backends().await;
    backends.reviews = pausing_addr;
    backends.handles.push(pausing_handle);
    let mut waypoint = Waypoint::start_with(
        backends,
        Scenario {
            tcp_idle_timeout_seconds: Some(1),
            ..Scenario::default()
        },
        CLIENT_SPIFFE,
    )
    .await;
    let tunnel = waypoint
        .tunnel(&format!("{}:{SERVICE_PORT}", host("reviews")), &[])
        .await;
    let mut inner = inner_http1(tunnel).await;
    let response = send_h1(&mut inner, get("/", &host("reviews"))).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.body, "reviews\nlater\n",
        "the body survives a pause past the idle timeout"
    );
    assert_eq!(
        l7_tunnel_terminations(ServiceWaypointL7TunnelTermination::IdleTimeout),
        0,
        "the idle timer did not fire during the active body"
    );
    waypoint.teardown().await;
}

/// The prepared configuration of a SECURED ServiceWaypoint whose bound
/// Services are Sidecar-backed, so their default upstreams dial over Sidecar
/// mTLS with the destination Service authority stamped on every target.
fn prepared_secured_sidecar_waypoint(virtual_services: Vec<K8sObject>) -> GatewayConfig {
    use ferrum_edge::modes::mesh::config::WorkloadMeshTransport;
    let backends = Backends {
        reviews: "127.0.0.1:18080".parse().expect("addr"),
        reviews_log: Arc::new(std::sync::Mutex::new(Vec::new())),
        ratings: "127.0.0.1:18081".parse().expect("addr"),
        ratings_log: Arc::new(std::sync::Mutex::new(Vec::new())),
        tcp_echo: "127.0.0.1:18082".parse().expect("addr"),
        udp_echo: "127.0.0.1:18083".parse().expect("addr"),
        handles: Vec::new(),
    };
    let mut cp = cp_config(
        &backends,
        &Scenario {
            virtual_services,
            ..Scenario::default()
        },
    );
    for workload in &mut cp.mesh.as_deref_mut().expect("mesh").workloads {
        workload.mesh_transport = Some(WorkloadMeshTransport::SidecarMtls);
    }
    let mut runtime = waypoint_runtime();
    runtime.workload_svid_cert_path = Some("/fixture/svid.pem".to_string());
    runtime.workload_svid_key_path = Some("/fixture/svid.key".to_string());
    runtime.workload_svid_trust_bundle_path = Some("/fixture/bundle.pem".to_string());
    let request = runtime.mesh_slice_request();
    let filtered = cp_filter_config_to_mesh_request_for_test(&cp, &request);
    let slice = MeshSlice::from_gateway_config(&filtered, request);
    prepare_gateway_config_from_mesh_slice(&slice, &runtime).expect("slice materializes")
}

/// Review F7: on a ServiceWaypoint, a carried rule's `rewrite.authority` to a
/// Sidecar-backed destination is validated like a Sidecar's (it must name the
/// selected Service) and dials a route-scoped clone with no stamped
/// authority, so the rewritten authority is forwarded; ordinary dispatch
/// keeps the stamped Service authority.
#[test]
fn a_service_waypoint_authority_rewrite_to_a_sidecar_destination_is_forwarded() {
    use ferrum_edge::proxy::mesh_mtls_pool::{
        MESH_MTLS_AUTHORITY_HOST_TAG, MESH_MTLS_AUTHORITY_PORT_TAG,
    };
    let rewrite = |authority: &str| {
        virtual_service(
            "reviews-rewrite",
            json!({
                "hosts": [host("reviews")],
                "http": [
                    {
                        "match": [{"headers": {"x-alias": {"exact": "true"}}}],
                        "rewrite": {"authority": authority},
                        "route": [{"destination": {"host": host("ratings"), "port": {"number": SERVICE_PORT}}}]
                    },
                    {
                        "route": [{"destination": {"host": host("reviews"), "port": {"number": SERVICE_PORT}}}]
                    }
                ]
            }),
        )
    };
    let carried_routes = |config: &GatewayConfig| {
        config
            .proxies
            .iter()
            .filter(|proxy| proxy.id.starts_with("istio-vs-"))
            .count()
    };

    // An alias of the selected destination (ratings) is admitted.
    let admitted = prepared_secured_sidecar_waypoint(vec![rewrite("ratings.default.svc")]);
    assert!(carried_routes(&admitted) > 0, "the rewriting route is kept");
    let default_upstream =
        ferrum_edge::modes::mesh::service_waypoint_l7::service_waypoint_l7_upstream_id(
            NAMESPACE,
            "ratings",
            SERVICE_PORT,
        );
    let rewrite_upstream =
        ferrum_edge::modes::mesh::service_waypoint_l7::service_waypoint_l7_rewrite_upstream_id(
            NAMESPACE,
            "ratings",
            SERVICE_PORT,
        );
    let rule_destinations: Vec<String> = admitted
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .flat_map(|plugin| {
            plugin
                .config
                .get("rules")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|rule| {
            rule.get("destination")
                .and_then(|destination| destination.get("upstream_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect();
    assert!(
        rule_destinations.contains(&rewrite_upstream),
        "the rewriting rule dials the tag-free clone: {rule_destinations:?}"
    );
    let upstream = |id: &str| {
        admitted
            .upstreams
            .iter()
            .find(|upstream| upstream.id == id)
            .unwrap_or_else(|| panic!("upstream {id} materialized"))
    };
    let clone = upstream(&rewrite_upstream);
    assert!(!clone.targets.is_empty());
    for target in &clone.targets {
        assert!(
            ferrum_edge::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(target),
            "the clone still dials over Sidecar mTLS"
        );
        assert!(
            !target.tags.contains_key(MESH_MTLS_AUTHORITY_HOST_TAG)
                && !target.tags.contains_key(MESH_MTLS_AUTHORITY_PORT_TAG),
            "the clone carries no stamped authority"
        );
    }
    assert_eq!(
        clone.admission_upstream_id.as_deref(),
        Some(default_upstream.as_str()),
        "the clone shares the Service upstream's admission lanes"
    );
    for target in &upstream(&default_upstream).targets {
        assert!(
            target.tags.contains_key(MESH_MTLS_AUTHORITY_HOST_TAG),
            "ordinary dispatch keeps the stamped Service authority"
        );
    }

    // A rewrite naming something the destination Sidecar cannot route is
    // refused with its route.
    let before = route_refusals(ServiceWaypointRouteRefusal::AuthorityRewriteRefused);
    let refused = prepared_secured_sidecar_waypoint(vec![rewrite("attacker.example.com")]);
    assert_eq!(
        carried_routes(&refused),
        0,
        "a rewrite that does not name the selected Service refuses its route"
    );
    assert!(route_refusals(ServiceWaypointRouteRefusal::AuthorityRewriteRefused) > before);
}
