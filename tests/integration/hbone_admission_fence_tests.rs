//! Receiver-side HBONE admission fence (issue #5042 step 1).
//!
//! An HBONE CONNECT is judged once, at admission; the relay then byte-copies
//! for as long as the tunnel lives. These tests pin the fence that re-applies
//! the admission gates to LIVE tunnels on every request-epoch publication and
//! every inbound PeerAuthentication swap:
//!
//! * a tightened authorize chain revokes the tunnel and denies the same
//!   principal's next CONNECT (parity between the sweep and the request path);
//! * an unrelated publication re-evaluates but keeps the tunnel flowing;
//! * withdrawing the admitting proxy revokes the tunnel;
//! * a PeerAuthentication swap the tunnel's transport no longer satisfies
//!   revokes it, on both the byte-stream and the datagram relay, while a
//!   swap it does satisfy leaves it alone;
//! * an admission that RACED a publication is re-swept when it registers, so a
//!   CONNECT in flight across a tightening apply cannot escape the fence;
//! * the relay-destination gate revokes a synthesized inbound relay whose
//!   destination left this terminator's inventory, and one whose dialled
//!   address is loopback after the own-namespace privilege is withdrawn;
//! * a side-effecting operator authorize plugin is NOT re-run by a sweep — no
//!   consumed budget, no spurious revocation;
//! * publications coalesce and revoke every live tunnel exactly once;
//! * a revocation never lands on `ferrum_mesh_hbone_relay_failures_total`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshInboundRelayDestination, MeshInboundRelayHost, MeshPolicy,
    MeshRelayEnrollmentEvidence, MtlsMode, PolicyScope,
};
use ferrum_edge::modes::mesh::{MeshTrafficDirection, prepare_gateway_config_for_mesh};
use ferrum_edge::plugins::{ProxyProtocol, RequestContext};
use ferrum_edge::proxy::hbone_admission_fence::{
    AdmittedHboneTunnel, HboneAdmissionSnapshot, HboneRelayDestinationGate, HboneRevocationReason,
};
use ferrum_edge::proxy::{
    ConfigApplyOutcome, MeshInboundTlsPolicy, ProxyState,
    start_proxy_listener_with_bound_listener_and_mesh_direction,
};

use super::mesh_hbone_tests::{
    connect_hbone_h2_mtls, create_egress_udp_gateway_state, create_mesh_proxy,
    egress_udp_mesh_config, frame_datagram, generate_hbone_mtls_certs, hbone_client_config,
    hbone_server_config, read_framed_datagram, start_external_udp_echo, udp_connect_request,
};
use super::mesh_test_support::{
    DEFAULT_NAMESPACE, default_mesh_runtime, gateway_config_with_mesh, mesh_config_with,
    policy_allow_principal, policy_deny_principal,
};

const CLIENT_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/client";
const OTHER_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/other";
const CONNECT_AUTHORITY: &str = "orders.default.svc.cluster.local:8080";
const DEADLINE: Duration = Duration::from_secs(5);
/// Mesh synthesis builds the ordinary transparent inbound relay under this
/// reserved id. The constant itself is crate-private, so the literal is pinned
/// here exactly as the other mesh suites pin it.
const MESH_INBOUND_HBONE_RELAY_PROXY_ID: &str = "__mesh-inbound-hbone-relay";
const RELAY_APP_HOST: &str = "orders.default.svc.cluster.local";
const RELAY_APP_PORT: u16 = 8080;

fn namespace_scope() -> PolicyScope {
    PolicyScope::Namespace {
        namespace: DEFAULT_NAMESPACE.to_string(),
    }
}

fn allow_client() -> MeshPolicy {
    policy_allow_principal(
        "allow-client",
        DEFAULT_NAMESPACE,
        namespace_scope(),
        CLIENT_SPIFFE,
    )
}

fn allow_other() -> MeshPolicy {
    policy_allow_principal(
        "allow-other",
        DEFAULT_NAMESPACE,
        namespace_scope(),
        OTHER_SPIFFE,
    )
}

fn deny_client() -> MeshPolicy {
    policy_deny_principal(
        "deny-client",
        DEFAULT_NAMESPACE,
        namespace_scope(),
        CLIENT_SPIFFE,
    )
}

/// Production materializes the mesh-managed `spiffe_identity` / `mesh_authz`
/// rows under reserved `__mesh_*` ids and republishes them through the
/// crate-private `ProxyState::update_mesh_config`. These tests publish through
/// the public `update_config`, whose resource-id grammar refuses the reserved
/// prefix, so the injected rows are retagged as ordinary operator globals. On
/// the Sidecar topology `mesh_authz` reads only its config JSON, never its row
/// id, so the retag changes nothing about enforcement.
fn retag_mesh_managed_plugins(config: &mut GatewayConfig) {
    let retag = |id: &str| {
        id.strip_prefix("__mesh_")
            .map(|rest| format!("mesh-managed-{}", rest.replace('_', "-")))
    };
    for plugin in &mut config.plugin_configs {
        if let Some(public) = retag(&plugin.id) {
            plugin.id = public;
        }
    }
    for proxy in &mut config.proxies {
        for association in &mut proxy.plugins {
            if let Some(public) = retag(&association.plugin_config_id) {
                association.plugin_config_id = public;
            }
        }
    }
    assert!(
        config.proxies.iter().all(|p| !p.id.starts_with("__mesh"))
            && config.upstreams.iter().all(|u| !u.id.starts_with("__mesh")),
        "fixture must not depend on reserved mesh-generated proxies or upstreams"
    );
}

/// Sidecar mesh config with one configured HBONE proxy (or none) and the
/// supplied AuthorizationPolicies, run through the production mesh preparation
/// so `spiffe_identity` and `mesh_authz` are injected exactly as at runtime.
fn prepared_config(proxy_backend_port: Option<u16>, policies: Vec<MeshPolicy>) -> GatewayConfig {
    prepared_config_with(proxy_backend_port, None, policies, Vec::new())
}

/// [`prepared_config`] with an optional proxy-id override (so one test can own a
/// metric series no other test can touch) and operator-global plugin rows.
fn prepared_config_with(
    proxy_backend_port: Option<u16>,
    proxy_id: Option<&str>,
    policies: Vec<MeshPolicy>,
    plugin_configs: Vec<PluginConfig>,
) -> GatewayConfig {
    let runtime = default_mesh_runtime();
    let proxies = proxy_backend_port
        .map(|port| {
            let mut proxy = create_mesh_proxy(port);
            if let Some(id) = proxy_id {
                proxy.id = id.to_string();
            }
            proxy
        })
        .into_iter()
        .collect();
    let mut config = gateway_config_with_mesh(
        proxies,
        Vec::new(),
        mesh_config_with(Vec::new(), Vec::new(), policies),
    );
    config.plugin_configs = plugin_configs;
    let mut prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared config");
    retag_mesh_managed_plugins(&mut prepared);
    prepared
}

/// A globally scoped `rate_limiting` instance keyed by the peer's SPIFFE
/// identity — an operator authorize plugin whose `authorize` CONSUMES a token.
/// The fence must never re-run it for a live tunnel.
fn spiffe_rate_limit_plugin(max_requests: u32) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: "operator-spiffe-rate-limit".to_string(),
        plugin_name: "rate_limiting".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        config: json!({
            "window_seconds": 60,
            "max_requests": max_requests,
            "limit_by": "spiffe_identity"
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// One entry in this terminator's inbound-relay destination inventory, declared
/// by NAME so the guard matches the CONNECT authority verbatim (an IP authority
/// would take the address arm instead).
fn relay_destination(host: &str, port: u16) -> MeshInboundRelayDestination {
    MeshInboundRelayDestination {
        host: MeshInboundRelayHost::Name(host.to_string()),
        ports: vec![port],
        enrollment: MeshRelayEnrollmentEvidence::default(),
        registry_uncontested: true,
    }
}

/// A generation carrying exactly the inbound-relay inventory a test needs. The
/// configured proxy differs per `generation_tag` so the config delta always
/// publishes; the gate under test reads only `config.mesh`.
fn relay_destination_config(
    destinations: Vec<MeshInboundRelayDestination>,
    admits_loopback_namespace: bool,
    generation_tag: u16,
) -> GatewayConfig {
    let mut config = gateway_config_with_mesh(
        vec![create_mesh_proxy(generation_tag)],
        Vec::new(),
        MeshConfig {
            inbound_relay_destinations: destinations,
            inbound_relay_admits_loopback_namespace: admits_loopback_namespace,
            ..MeshConfig::default()
        },
    );
    config.version = format!("relay-destination-{generation_tag}");
    config
}

/// The synthesized ordinary inbound relay, as mesh synthesis builds it for one
/// application destination.
fn inbound_relay_proxy(app_host: &str, app_port: u16) -> Proxy {
    let mut proxy = create_mesh_proxy(app_port);
    proxy.id = MESH_INBOUND_HBONE_RELAY_PROXY_ID.to_string();
    proxy.backend_host = app_host.to_string();
    proxy.backend_port = app_port;
    proxy
}

/// An admission snapshot for a gate the live-gateway fixtures cannot reach.
///
/// Every field is what the CONNECT path would have captured. `mesh_direction`
/// stays `None`, which leaves the post-route PeerAuthentication gate
/// inapplicable, and the synthesized relay carries no lifecycle generation, so
/// each test isolates exactly the gate it names.
fn synthetic_snapshot(
    proxy: Proxy,
    destination_gate: HboneRelayDestinationGate,
    resolved_ip: Option<IpAddr>,
    admission_sweep_epoch: u64,
) -> HboneAdmissionSnapshot {
    HboneAdmissionSnapshot {
        ctx: RequestContext::new(
            "127.0.0.1".to_string(),
            "CONNECT".to_string(),
            "/".to_string(),
        ),
        proxy: Arc::new(proxy),
        upstream_target: None,
        is_tls: true,
        has_verified_peer_certificate: true,
        mesh_inbound_pre_handshake_app_port: None,
        destination_gate,
        resolved_ip,
        proxy_lifecycle_generation: None,
        request_protocol: ProxyProtocol::Http,
        grpc_web_request: false,
        admission_sweep_epoch,
    }
}

fn build_state(prepared: GatewayConfig) -> ProxyState {
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: DEFAULT_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    ProxyState::new(
        prepared,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("mesh proxy state")
    .0
}

/// Inbound-direction mTLS gateway. The direction is what arms the post-route
/// PeerAuthentication transport gate and marks the authorize chain's inbound
/// leg, so both fence gates under test are live.
async fn start_inbound_gateway(
    state: ProxyState,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> (SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            state,
            shutdown_rx,
            Some(server_config),
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

/// Echoes every chunk back as it arrives, so a tunnel's liveness can be probed
/// mid-flight (the classic `read_to_end` echo only answers at EOF). Accepts in a
/// loop: several concurrent tunnels each dial their own backend connection.
async fn start_interactive_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("echo backend local addr");
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

struct Tunnel {
    request_body: h2::SendStream<Bytes>,
    response_body: h2::RecvStream,
}

async fn open_tunnel(sender: &mut h2::client::SendRequest<Bytes>) -> Result<Tunnel, StatusCode> {
    open_tunnel_with_content_type(sender, None).await
}

/// Send a CONNECT and hand back the response head plus the request-body handle.
/// The caller decides what the head means — a gRPC-classified refusal is shaped
/// as trailers-only (`200` + `grpc-status`), not as an HTTP error status.
async fn send_connect(
    sender: &mut h2::client::SendRequest<Bytes>,
    content_type: Option<&str>,
) -> (hyper::Response<h2::RecvStream>, h2::SendStream<Bytes>) {
    let mut builder = Request::builder()
        .method(Method::CONNECT)
        .uri(CONNECT_AUTHORITY);
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    let req = builder.body(()).expect("connect request");
    let (response_fut, request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = tokio::time::timeout(DEADLINE, response_fut)
        .await
        .expect("CONNECT response within deadline")
        .expect("CONNECT response");
    (resp, request_body)
}

/// [`open_tunnel`] carrying an optional `content-type`. A CONNECT declaring
/// `application/grpc` is classified as `HttpFlavor::Grpc`, so the request path
/// resolves the gRPC authorize view for it — a peer-selectable choice the fence
/// must mirror rather than assume plain HTTP.
async fn open_tunnel_with_content_type(
    sender: &mut h2::client::SendRequest<Bytes>,
    content_type: Option<&str>,
) -> Result<Tunnel, StatusCode> {
    let (resp, request_body) = send_connect(sender, content_type).await;
    if resp.status() != StatusCode::OK {
        return Err(resp.status());
    }
    Ok(Tunnel {
        request_body,
        response_body: resp.into_body(),
    })
}

/// The `grpc-status` a trailers-only refusal carries, if any. An admitted HBONE
/// CONNECT's `200` carries none.
fn grpc_status_of(response: &hyper::Response<h2::RecvStream>) -> Option<String> {
    response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

async fn read_exact_from_body(body: &mut h2::RecvStream, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let chunk = body
            .data()
            .await
            .expect("tunnel closed before the echo arrived")
            .expect("tunnel chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    out
}

async fn echo_round_trip(tunnel: &mut Tunnel, payload: &'static [u8]) {
    tunnel
        .request_body
        .send_data(Bytes::from_static(payload), false)
        .expect("send tunnel bytes");
    let echoed = tokio::time::timeout(
        DEADLINE,
        read_exact_from_body(&mut tunnel.response_body, payload.len()),
    )
    .await
    .expect("echo within deadline");
    assert_eq!(echoed, payload);
}

/// A revoked tunnel ends from the peer's point of view: the CONNECT response
/// body reaches END_STREAM or the stream is reset. Anything still buffered
/// before the cut is drained and ignored.
async fn assert_tunnel_closed(body: &mut h2::RecvStream) {
    tokio::time::timeout(DEADLINE, async {
        loop {
            match body.data().await {
                None | Some(Err(_)) => return,
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
            }
        }
    })
    .await
    .expect("revoked tunnel must close toward the peer");
}

async fn wait_for_sweep_after(state: &ProxyState, completed_before: u64) {
    tokio::time::timeout(DEADLINE, async {
        while state.hbone_admission_fence.sweeps_completed() <= completed_before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fence sweep completes after publication");
}

async fn wait_for_no_live_tunnels(state: &ProxyState) {
    tokio::time::timeout(DEADLINE, async {
        while state.hbone_admission_fence.live_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("revoked tunnel deregisters once its relay task ends");
}

/// Every requested sweep has settled. Coalescing folds concurrent requests into
/// one pass, so `completed` catches up to `requested` rather than matching it
/// one request per pass.
async fn wait_for_settled_sweeps(state: &ProxyState) {
    let fence = &state.hbone_admission_fence;
    tokio::time::timeout(DEADLINE, async {
        while fence.sweeps_completed() < fence.sweep_epoch() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every requested fence sweep settles");
}

async fn wait_for_revocation(tunnel: &AdmittedHboneTunnel) {
    tokio::time::timeout(DEADLINE, tunnel.revocation_token().cancelled_owned())
        .await
        .expect("the fence must revoke the tunnel within the deadline");
}

fn revocation_counts(state: &ProxyState) -> [u64; 5] {
    let fence = &state.hbone_admission_fence;
    [
        fence.revocations(HboneRevocationReason::ProxyWithdrawn),
        fence.revocations(HboneRevocationReason::PeerAuthTransport),
        fence.revocations(HboneRevocationReason::RelayDestination),
        fence.revocations(HboneRevocationReason::AuthorizationDenied),
        fence.revocations(HboneRevocationReason::ReevaluationFailed),
    ]
}

/// One admitted byte-stream tunnel plus the handles a test needs to publish
/// against it and to tear it down.
struct AdmittedFixture {
    state: ProxyState,
    tunnel: Tunnel,
    sender: h2::client::SendRequest<Bytes>,
    conn_task: tokio::task::JoinHandle<Result<(), h2::Error>>,
    backend_handle: tokio::task::JoinHandle<()>,
    backend_port: u16,
    shutdown_tx: watch::Sender<bool>,
}

async fn admit_client_tunnel(policies: Vec<MeshPolicy>) -> AdmittedFixture {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(Some(backend_addr.port()), policies));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("admitted CONNECT under the initial policy generation");
    echo_round_trip(&mut tunnel, b"before-publish").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0]);

    AdmittedFixture {
        state,
        tunnel,
        sender,
        conn_task,
        backend_handle,
        backend_port: backend_addr.port(),
        shutdown_tx,
    }
}

impl AdmittedFixture {
    async fn teardown(self) {
        let _ = self.shutdown_tx.send(true);
        self.backend_handle.abort();
        self.conn_task.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tightened_authorization_policy_revokes_live_tunnel_and_denies_the_next_connect() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    // Operator replaces the ALLOW with a DENY for the admitted principal.
    let outcome = fx
        .state
        .update_config(prepared_config(Some(fx.backend_port), vec![deny_client()]));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 1, 0],
        "exactly one authorization_denied revocation"
    );
    assert!(
        fx.state.hbone_admission_fence.reevaluations() >= 1,
        "the sweep must have re-run the authorize chain for the live tunnel"
    );

    // Request-path parity: the same principal's fresh CONNECT is now refused
    // at admission, so the fence and the gate agree on the new generation.
    let denied = open_tunnel(&mut fx.sender).await.err();
    assert_eq!(
        denied,
        Some(StatusCode::FORBIDDEN),
        "a new CONNECT from the denied principal must be refused at admission"
    );
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 1, 0],
        "a refused CONNECT is never a revocation"
    );

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unrelated_policy_publication_reevaluates_but_keeps_the_tunnel() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;
    let completed_before = fx.state.hbone_admission_fence.sweeps_completed();
    let reevaluations_before = fx.state.hbone_admission_fence.reevaluations();

    // A second ALLOW for a different principal: a real generation change that
    // still admits the live tunnel's CONNECT.
    let outcome = fx.state.update_config(prepared_config(
        Some(fx.backend_port),
        vec![allow_client(), allow_other()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_sweep_after(&fx.state, completed_before).await;

    assert!(
        fx.state.hbone_admission_fence.reevaluations() > reevaluations_before,
        "the publication must re-judge the live tunnel, not skip it"
    );
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0]);
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 1);
    echo_round_trip(&mut fx.tunnel, b"after-unrelated-publish").await;

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_admitting_proxy_revokes_live_tunnel() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    // The configured proxy disappears from the published generation.
    let outcome = fx
        .state
        .update_config(prepared_config(None, vec![allow_client()]));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [1, 0, 0, 0, 0],
        "exactly one proxy_withdrawn revocation"
    );

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_authentication_swap_revokes_only_a_non_compliant_tunnel() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    // STRICT is satisfied by this mTLS tunnel: re-judged, kept.
    let completed_before = fx.state.hbone_admission_fence.sweeps_completed();
    fx.state
        .publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
            default_mode: MtlsMode::Strict,
            ..MeshInboundTlsPolicy::default()
        });
    wait_for_sweep_after(&fx.state, completed_before).await;
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0]);
    echo_round_trip(&mut fx.tunnel, b"still-admitted-under-strict").await;

    // DISABLE refuses TLS transport for the app port: the same tunnel is now
    // non-compliant and must not outlive the swap.
    fx.state
        .publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
            default_mode: MtlsMode::Disable,
            ..MeshInboundTlsPolicy::default()
        });
    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 1, 0, 0, 0],
        "exactly one peer_auth_transport revocation"
    );

    fx.teardown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_authentication_swap_revokes_a_live_datagram_tunnel() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response_fut, mut request_body) = sender
        .send_request(
            udp_connect_request(&format!("127.0.0.1:{}", external_addr.port())),
            false,
        )
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(DEADLINE, response_fut)
        .await
        .expect("udp CONNECT response within deadline")
        .expect("udp CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);
    let mut response_body = resp.into_body();

    request_body
        .send_data(frame_datagram(b"ping"), false)
        .expect("send framed datagram");
    let echoed = tokio::time::timeout(DEADLINE, read_framed_datagram(&mut response_body))
        .await
        .expect("external udp reply");
    assert_eq!(echoed, b"pong:ping".to_vec());
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);

    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
        default_mode: MtlsMode::Disable,
        ..MeshInboundTlsPolicy::default()
    });
    assert_tunnel_closed(&mut response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert_eq!(
        revocation_counts(&state),
        [0, 1, 0, 0, 0],
        "the datagram relay honors the same revocation as the byte-stream relay"
    );

    let _ = shutdown_tx.send(true);
    external_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admission_that_raced_a_publication_is_reswept_when_it_registers() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9301));
    let fence = &state.hbone_admission_fence;

    // Captured exactly where the request path captures it: BEFORE the epoch the
    // admission gates judge.
    let captured = fence.sweep_epoch();

    // The operator applies while this CONNECT is still in the authorize chain /
    // backend dial. The publication's own sweep reads the registry — which the
    // tunnel has not reached yet — and settles.
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9302));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&state).await;
    assert!(
        fence.sweep_epoch() > captured,
        "the publication must have advanced the fence's sweep-request counter"
    );

    // Only publish-then-recheck can revoke this: the superseded generation
    // admitted it, and on a quiet mesh no further publication is coming.
    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        captured,
    ));
    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the re-sweep must judge the tunnel against the CURRENT generation"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admission_under_the_current_generation_schedules_no_sweep() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9401));
    let fence = &state.hbone_admission_fence;
    let completed_before = fence.sweeps_completed();

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        fence.sweeps_completed(),
        completed_before,
        "an uncontested admission must not schedule a sweep of its own"
    );
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(fence.live_tunnels(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_relay_destination_revokes_a_live_inbound_relay_tunnel() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9101));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(tunnel.revoked_reason(), None);

    // The workload leaves this terminator's inventory.
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9102));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the synthesized inbound relay's ownership guard is what revoked it"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_pinned_inbound_relay_is_revoked_when_the_namespace_privilege_is_withdrawn() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    // Sidecar posture: the terminator shares the application pod's network
    // namespace, so a declared name that resolves to loopback is admitted.
    let state = build_state(relay_destination_config(
        vec![destination.clone()],
        true,
        9201,
    ));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        Some("127.0.0.1".parse::<IpAddr>().expect("loopback literal")),
        fence.sweep_epoch(),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The authority is STILL in the inventory — only the own-namespace loopback
    // privilege is gone, which a fresh CONNECT's post-DNS screen would refuse.
    let outcome = state.update_config(relay_destination_config(vec![destination], false, 9202));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the sweep must re-apply the post-DNS loopback screen to the dialled address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grpc_classified_connect_is_fenced_on_the_admitting_plugin_view() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    // `content-type: application/grpc` is peer-chosen and makes the request path
    // resolve the gRPC authorize view rather than the plain-HTTP one.
    let mut tunnel = open_tunnel_with_content_type(&mut sender, Some("application/grpc"))
        .await
        .expect("gRPC-classified CONNECT admitted under the initial generation");
    echo_round_trip(&mut tunnel, b"grpc-classified").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    let reevaluations_before = state.hbone_admission_fence.reevaluations();

    let outcome = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut tunnel.response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert!(
        state.hbone_admission_fence.reevaluations() > reevaluations_before,
        "the sweep must have resolved a non-empty authorize chain for the gRPC view"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 1, 0]);

    // Request-path parity on the same peer-selected view. A gRPC-classified
    // rejection is shaped as trailers-only (`200` + a non-zero `grpc-status`),
    // NOT as an HTTP 403 — which is precisely why the sweep must resolve the
    // view the CONNECT was admitted with instead of assuming plain HTTP.
    let (refused, _refused_body) = send_connect(&mut sender, Some("application/grpc")).await;
    assert_eq!(refused.status(), StatusCode::OK);
    let refused_grpc_status = grpc_status_of(&refused);
    assert!(
        refused_grpc_status
            .as_deref()
            .is_some_and(|status| status != "0"),
        "the sweep and the request path must judge the same chain; got grpc-status \
         {refused_grpc_status:?}"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_side_effecting_operator_authorize_plugin_is_never_re_run_by_a_sweep() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    // Budget of two CONNECTs for this peer identity, for the whole window.
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![spiffe_rate_limit_plugin(2)],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    // Token 1 of 2.
    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("first CONNECT admitted under the operator rate limit");
    echo_round_trip(&mut tunnel, b"before-sweeps").await;

    // PeerAuthentication publications the tunnel still satisfies. They do NOT
    // rebuild the plugin cache, so the limiter instance — and its remaining
    // budget — is exactly the one the CONNECT charged.
    for _ in 0..3 {
        let completed_before = state.hbone_admission_fence.sweeps_completed();
        state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
            default_mode: MtlsMode::Strict,
            ..MeshInboundTlsPolicy::default()
        });
        wait_for_sweep_after(&state, completed_before).await;
    }

    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0],
        "a sweep must not revoke a compliant tunnel over a plugin it may not re-run"
    );
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    echo_round_trip(&mut tunnel, b"after-sweeps").await;

    // Token 2 of 2 is still there: the sweeps spent none of the peer's budget.
    let second = open_tunnel(&mut sender).await;
    assert!(
        second.is_ok(),
        "the sweeps must not have consumed the peer's rate-limit budget: {:?}",
        second.err()
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn close_publications_coalesce_and_revoke_every_live_tunnel_exactly_once() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnels = Vec::new();
    for _ in 0..3 {
        let mut tunnel = open_tunnel(&mut sender).await.expect("CONNECT admitted");
        echo_round_trip(&mut tunnel, b"live").await;
        tunnels.push(tunnel);
    }
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 3);

    let requested_before = state.hbone_admission_fence.sweep_epoch();
    let reevaluations_before = state.hbone_admission_fence.reevaluations();

    // Two publications back to back: the first still admits every tunnel, the
    // second denies the principal.
    let first = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client(), allow_other()],
    ));
    assert_eq!(first, ConfigApplyOutcome::Applied);
    let second = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    assert_eq!(second, ConfigApplyOutcome::Applied);

    for tunnel in tunnels.iter_mut() {
        assert_tunnel_closed(&mut tunnel.response_body).await;
    }
    wait_for_no_live_tunnels(&state).await;
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 3, 0],
        "each live tunnel is revoked exactly once"
    );
    let fence = &state.hbone_admission_fence;
    assert!(
        fence.sweep_epoch() >= requested_before + 2,
        "both publications must be counted as sweep requests"
    );
    let reevaluations = fence.reevaluations() - reevaluations_before;
    assert!(
        (3..=6).contains(&reevaluations),
        "coalescing bounds the work at one pass per publication over three \
         tunnels, and at least one full pass must have run; got {reevaluations}"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_tunnel_never_counts_as_an_hbone_relay_failure() {
    // A proxy id no other test publishes, so the assertions below read exactly
    // this test's series out of the process-wide registry.
    const METRICS_PROXY_ID: &str = "mesh-hbone-revocation-metrics";

    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        Some(METRICS_PROXY_ID),
        vec![allow_client()],
        Vec::new(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnel = open_tunnel(&mut sender).await.expect("CONNECT admitted");
    echo_round_trip(&mut tunnel, b"before-revocation").await;

    let outcome = state.update_config(prepared_config_with(
        Some(backend_addr.port()),
        Some(METRICS_PROXY_ID),
        vec![deny_client()],
        Vec::new(),
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut tunnel.response_body).await;
    wait_for_no_live_tunnels(&state).await;
    // The relay records its outcome just after deregistering; give that tail a
    // moment so an incorrectly classified failure would be visible below.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let rendered = ferrum_edge::plugins::prometheus_metrics::global_registry().render_uncached();
    assert!(
        rendered.contains(&format!(
            "ferrum_mesh_hbone_tunnel_revocations_total{{proxy_id=\"{METRICS_PROXY_ID}\",\
             reason=\"authorization_denied\""
        )),
        "the revocation must be counted on the fence's own family: {rendered}"
    );
    assert!(
        !rendered.contains(&format!(
            "ferrum_mesh_hbone_relay_failures_total{{proxy_id=\"{METRICS_PROXY_ID}\""
        )),
        "a policy revocation must never increment the relay-failure family: {rendered}"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}
