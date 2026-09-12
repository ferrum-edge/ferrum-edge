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
//!   swap it does satisfy leaves it alone.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use hyper::{Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::config::{MeshPolicy, MtlsMode, PolicyScope};
use ferrum_edge::modes::mesh::{MeshTrafficDirection, prepare_gateway_config_for_mesh};
use ferrum_edge::proxy::hbone_admission_fence::HboneRevocationReason;
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
    let runtime = default_mesh_runtime();
    let proxies = proxy_backend_port
        .map(create_mesh_proxy)
        .into_iter()
        .collect();
    let config = gateway_config_with_mesh(
        proxies,
        Vec::new(),
        mesh_config_with(Vec::new(), Vec::new(), policies),
    );
    let mut prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared config");
    retag_mesh_managed_plugins(&mut prepared);
    prepared
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
    let listener = TcpListener::bind("127.0.0.1:0")
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
/// mid-flight (the classic `read_to_end` echo only answers at EOF).
async fn start_interactive_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("echo backend local addr");
    let handle = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
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
    (addr, handle)
}

struct Tunnel {
    request_body: h2::SendStream<Bytes>,
    response_body: h2::RecvStream,
}

async fn open_tunnel(sender: &mut h2::client::SendRequest<Bytes>) -> Result<Tunnel, StatusCode> {
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(CONNECT_AUTHORITY)
        .body(())
        .expect("connect request");
    let (response_fut, request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = tokio::time::timeout(DEADLINE, response_fut)
        .await
        .expect("CONNECT response within deadline")
        .expect("CONNECT response");
    if resp.status() != StatusCode::OK {
        return Err(resp.status());
    }
    Ok(Tunnel {
        request_body,
        response_body: resp.into_body(),
    })
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

fn revocation_counts(state: &ProxyState) -> [u64; 4] {
    let fence = &state.hbone_admission_fence;
    [
        fence.revocations(HboneRevocationReason::ProxyWithdrawn),
        fence.revocations(HboneRevocationReason::PeerAuthTransport),
        fence.revocations(HboneRevocationReason::RelayDestination),
        fence.revocations(HboneRevocationReason::AuthorizationDenied),
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0]);

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
        [0, 0, 0, 1],
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
        [0, 0, 0, 1],
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
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0]);
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
        [1, 0, 0, 0],
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
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0]);
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
        [0, 1, 0, 0],
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
        [0, 1, 0, 0],
        "the datagram relay honors the same revocation as the byte-stream relay"
    );

    let _ = shutdown_tx.send(true);
    external_handle.abort();
    conn_task.abort();
}
