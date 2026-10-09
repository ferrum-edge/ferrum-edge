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
//! * the same gate revokes a Sidecar `ingress[]` CONNECT remap once a reload
//!   adds an HTTP listener on its `defaultEndpoint` port, and keeps it across
//!   an `ingress[]` reload that leaves its mapping intact;
//! * a CONNECT declaring a gRPC content type is refused before it can become a
//!   tunnel, so a peer cannot steer the fence onto a view it was never admitted
//!   with;
//! * a side-effecting operator authorize plugin is NOT re-run by a sweep — no
//!   consumed budget, no spurious revocation;
//! * a tunnel failing BOTH the authorize gate and the transport gate is
//!   attributed `authorization_denied`, because that is the gate order the
//!   CONNECT path applies and the `reason` label is the operator's only
//!   attribution;
//! * retirement and revocation are one atomic transition: a relay that ends
//!   first is never counted or classified as revoked, and a sweep that wins
//!   first leaves its reason readable after the relay retires;
//! * publications coalesce and revoke every live tunnel exactly once;
//! * a revocation never lands on `ferrum_mesh_hbone_relay_failures_total`;
//! * a revoked tunnel was cut short, so the peer sees its CONNECT stream reset
//!   with `RST_STREAM(CONNECT_ERROR)`, not a clean `END_STREAM`, on both the
//!   byte-stream and the datagram relay (issue #5858).
//!
//! and the CREDENTIAL dimension (issue #5568), which a sweep re-decides because
//! an established inbound mTLS session is never re-handshaked. Its trust input
//! is the INBOUND ADMISSION SLOT — the `tls::SharedBundleSlot` the mesh SPIFFE
//! client-certificate verifier reads — not the request epoch's gateway trust,
//! because the fence's verdict means "this peer's next CONNECT would be
//! refused" and that is the verifier which would refuse it:
//!
//! * a trust rotation that still anchors the peer revokes nothing, and costs
//!   exactly one certificate path build per tunnel;
//! * a root rotation the inbound verifier ACCEPTED keeps live tunnels, even
//!   while the request epoch's separately-built bundles never carried that root
//!   — the false-mass-revocation regression the independent review found;
//! * withdrawing the peer's trust domain (local or federated), and rotating
//!   away the authority that issued its leaf, each revoke with `peer_trust`;
//! * an unchanged republish — including one beneath a rotated gateway leaf —
//!   revokes nothing and does NO certificate path building, and a tunnel
//!   already verified against the current revision never rebuilds its path;
//! * an admitted SVID past its `notAfter` is revoked by the fence's own expiry
//!   watcher with NO publication of any kind, an unparseable retained leaf
//!   fails closed as `reevaluation_failed` rather than as `peer_expired`, and
//!   an unbounded one is not revoked at all;
//! * a published trust bundle that cannot be compiled into a verifier fails
//!   closed with `reevaluation_failed`;
//! * a peer the admitting inbound trust never anchored — the chain-only inbound
//!   posture — is never revoked for trust;
//! * and the production capture itself runs end to end over a REAL mTLS
//!   handshake: what `HbonePeerCredential::from_admitted_connect` retained is
//!   read back out of the fence's registry, including the case where the slot's
//!   local trust domain is the SVID's own and the slice's differs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::{
    SpiffeId, SvidBundle, TrustBundle as RuntimeTrustBundle,
    TrustBundleSet as RuntimeTrustBundleSet, TrustDomain,
};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshExtAuthzProvider, MeshInboundRelayDestination,
    MeshInboundRelayHost, MeshPolicy, MeshRelayEnrollmentEvidence, MeshRule, MtlsMode,
    OutboundTrafficPolicy, PolicyAction, PolicyScope, RequestMatch, ResolvedIngressListener,
};
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, MeshTrafficDirection, prepare_gateway_config_for_mesh,
};
use ferrum_edge::plugins::{HboneReuseContext, ProxyProtocol, RequestContext};
use ferrum_edge::proxy::hbone_admission_fence::{
    AdmittedHboneTunnel, AdmittedLeafExpiry, HboneAdmissionSnapshot, HbonePeerCredential,
    HboneRelayDestinationGate, HboneRevocationReason,
};
use ferrum_edge::proxy::{
    ConfigApplyOutcome, MeshInboundTlsPolicy, ProxyState,
    start_proxy_listener_with_bound_listener_and_mesh_direction,
};
use ferrum_edge::tls::{self, SharedBundleSlot};

use super::mesh_hbone_tests::{
    HBONE_CLIENT_LEAF_SERIAL, HboneMtlsCerts, connect_hbone_h2_mtls,
    create_egress_udp_gateway_state, create_mesh_proxy, egress_udp_mesh_config, frame_datagram,
    generate_hbone_mtls_certs, hbone_client_config, hbone_server_config,
    hbone_server_config_with_client_verifier, read_framed_datagram, start_external_udp_echo,
    udp_connect_request,
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
/// prefix, so the injected rows are retagged as ordinary operator globals.
/// Outside the NodeWaypoint topology `mesh_authz` reads only its config JSON,
/// never its row id, so the retag changes nothing about enforcement.
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

/// The mesh runtime every prepared fixture is built for: the Ambient HBONE
/// terminator.
///
/// The live fixtures send a bare CONNECT that MATCHES the configured HTTP
/// proxy, so the tunnel is admitted through the configured-route
/// (`HboneRelayDestinationGate::Configured`) dispatch with its own lifecycle
/// generation and plugin chain, which is what the fence's gates are pinned
/// against. A Sidecar refuses exactly that CONNECT before the plugin chain
/// runs (issue #6110: on its inbound listener it would relay HTTP past the
/// route's chain), and a stream proxy is never an HTTP route match, so the
/// fence fixtures use the topology whose matched-route CONNECT dispatch is
/// still served. The Sidecar refusal itself is pinned by
/// `sidecar_connect_http_port_tests.rs` and by
/// `a_reload_that_refuses_matched_http_connects_revokes_a_configured_route_tunnel`.
fn fence_mesh_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        topology: MeshTopology::Ambient,
        ..default_mesh_runtime()
    }
}

/// Ambient mesh config with one configured HBONE proxy (or none) and the
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
    prepared_config_from_mesh(
        proxy_backend_port,
        proxy_id,
        mesh_config_with(Vec::new(), Vec::new(), policies),
        plugin_configs,
    )
}

/// [`prepared_config_with`] over a fully-built [`MeshConfig`], for the cases
/// that need slice state the policy list alone cannot express (the external
/// authorization provider registry, for one).
fn prepared_config_from_mesh(
    proxy_backend_port: Option<u16>,
    proxy_id: Option<&str>,
    mesh: MeshConfig,
    plugin_configs: Vec<PluginConfig>,
) -> GatewayConfig {
    prepared_config_from_mesh_with_runtime(
        proxy_backend_port,
        proxy_id,
        mesh,
        plugin_configs,
        fence_mesh_runtime(),
    )
}

/// [`prepared_config_from_mesh`] over an explicit [`MeshRuntimeConfig`], for
/// the cases whose injected plugin set depends on the LISTENER PLAN rather than
/// on the slice — `mesh_outbound_registry` is scoped to the outbound-direction
/// capture ports, and `fence_mesh_runtime` binds that listener on `:0`, which
/// yields no ports at all.
fn prepared_config_from_mesh_with_runtime(
    proxy_backend_port: Option<u16>,
    proxy_id: Option<&str>,
    mesh: MeshConfig,
    plugin_configs: Vec<PluginConfig>,
    runtime: MeshRuntimeConfig,
) -> GatewayConfig {
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
    let mut config = gateway_config_with_mesh(proxies, Vec::new(), mesh);
    config.plugin_configs = plugin_configs;
    let mut prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared config");
    retag_mesh_managed_plugins(&mut prepared);
    prepared
}

/// The `meshConfig.extensionProviders` entry a CUSTOM policy delegates to.
/// Loopback so the provider validator accepts plaintext; nothing ever dials it
/// in these tests.
const FENCE_EXT_AUTHZ_PROVIDER: &str = "fence-ext-authz";

fn ext_authz_provider() -> MeshExtAuthzProvider {
    MeshExtAuthzProvider {
        name: FENCE_EXT_AUTHZ_PROVIDER.to_string(),
        service: "127.0.0.1".to_string(),
        port: 9999,
        tls: false,
        path_prefix: Some("/check".to_string()),
        timeout_ms: 500,
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

/// An `action: CUSTOM` policy that binds the provider above but whose rule can
/// never match this suite's client — it names a DIFFERENT principal.
///
/// That is deliberate. `MeshAuthz` binds its executor per GENERATION, from the
/// CUSTOM actions present in the slice, not per request; so this generation is
/// one whose CONNECT is decided entirely by the local ALLOW tier and for which
/// no external check is ever issued. It must STILL refuse reuse: the refusal is
/// a property of the generation, because a sweep never re-consults a provider
/// and the classification cannot depend on which rules a particular CONNECT
/// happened to match.
fn custom_policy_for_other_principal() -> MeshPolicy {
    let mut policy = allow_other();
    policy.name = "delegate-other".to_string();
    policy.rules[0].action = PolicyAction::Custom {
        provider: FENCE_EXT_AUTHZ_PROVIDER.to_string(),
    };
    policy
}

/// A globally scoped plugin row the reuse classification has never looked at.
///
/// `correlation_id` takes no authorization decision of any kind and never
/// rejects, so it is the sharpest possible statement of the fail-closed rule:
/// `Plugin::allows_hbone_inner_reuse` defaults to a literal `false`, so ANY
/// plugin nobody has classified — built-in or custom — refuses reuse, whatever
/// else it declares about itself.
fn unclassified_plugin() -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: "operator-correlation-id".to_string(),
        plugin_name: "correlation_id".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        config: json!({}),
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

/// A globally scoped `access_control` row that admits any authenticated
/// external identity. See
/// `an_access_control_chain_refuses_the_connect_it_would_have_let_reuse` for
/// why this never reaches the advertisement.
fn access_control_plugin() -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: "operator-access-control".to_string(),
        plugin_name: "access_control".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        config: json!({ "allow_authenticated_identity": true }),
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

/// A globally scoped `rate_limiting` instance keyed by the peer's SPIFFE
/// identity — an operator authorize plugin whose `authorize` CONSUMES a token.
/// The fence must never re-run it for a live tunnel.
///
/// The windows live inside a `limits` rule: `rate_limiting` rejects the legacy
/// top-level `window_seconds` / `max_requests` spelling outright, so a fixture
/// using it would abort gateway startup instead of exercising the budget.
fn spiffe_rate_limit_plugin(max_requests: u32) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: "operator-spiffe-rate-limit".to_string(),
        plugin_name: "rate_limiting".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        config: json!({
            "limit_by": "spiffe_identity",
            "limits": [
                {
                    "scope": "default",
                    "window_seconds": 60,
                    "max_requests": max_requests
                }
            ]
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
        // No peer credential: these fixtures isolate a POLICY gate, and a
        // credential-less snapshot leaves the credential gate (and the expiry
        // watcher) inapplicable. `credential_snapshot` is the fixture for that
        // dimension.
        peer_credential: None,
        // Likewise for the reuse gate (issue #5583): a synthetic tunnel that
        // never advertised the capability is never judged for it, so these
        // fixtures see exactly the gate they are about. The reuse dimension is
        // exercised end to end through the production dispatcher instead —
        // there is no synthetic fixture for it, because the thing under test is
        // the chain the dispatcher itself resolves.
        advertised_inner_reuse: false,
        reuse_context: HboneReuseContext {
            mesh_direction: None,
            frontend_listen_port: None,
        },
    }
}

/// An admission snapshot that arms BOTH the authorize gate and the post-route
/// PeerAuthentication transport gate, so one sweep sees two failing gates and
/// has to choose which one it attributes the revocation to.
///
/// `mesh_direction: Inbound` is what arms the transport gate at all; the peer
/// SPIFFE id is what the authorize chain judges; and plaintext transport
/// (`is_tls: false`) satisfies the default PERMISSIVE posture while failing
/// STRICT, so the transport gate can be armed by a later publication without
/// touching the authorize side. The proxy is a CONFIGURED one, so the
/// destination gate does not apply and no lifecycle generation is recorded —
/// exactly two gates are live.
fn dual_gate_snapshot(proxy: Arc<Proxy>, admission_sweep_epoch: u64) -> HboneAdmissionSnapshot {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "CONNECT".to_string(),
        "/".to_string(),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx.peer_spiffe_id = Some(SpiffeId::new(CLIENT_SPIFFE).expect("client spiffe id"));
    ctx.matched_proxy = Some(Arc::clone(&proxy));
    HboneAdmissionSnapshot {
        reuse_context: HboneReuseContext::from(&ctx),
        ctx,
        proxy,
        upstream_target: None,
        is_tls: false,
        has_verified_peer_certificate: false,
        mesh_inbound_pre_handshake_app_port: None,
        destination_gate: HboneRelayDestinationGate::Configured,
        resolved_ip: None,
        proxy_lifecycle_generation: None,
        request_protocol: ProxyProtocol::Http,
        grpc_web_request: false,
        admission_sweep_epoch,
        peer_credential: None,
        advertised_inner_reuse: false,
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
    start_gateway_with_direction(state, server_config, MeshTrafficDirection::Inbound).await
}

/// The real accept loop and dispatcher with an explicit listener stamp. An
/// Outbound listener can terminate a matching authenticated CONNECT too.
async fn start_gateway_with_direction(
    state: ProxyState,
    server_config: std::sync::Arc<rustls::ServerConfig>,
    direction: MeshTrafficDirection,
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
            Some(direction),
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

/// Send a plain HBONE CONNECT and, on a `200`, hand back both halves of the
/// live tunnel. A non-`200` head is the admission refusal.
///
/// Deliberately plain: a CONNECT carrying a gRPC `content-type` classifies as
/// gRPC before the HBONE branch is reached and is refused as a trailers-only
/// `200`, which this helper could not tell from an admitted tunnel. Tests that
/// want that shape use [`send_connect`] and read the `grpc-status` themselves.
async fn open_tunnel(sender: &mut h2::client::SendRequest<Bytes>) -> Result<Tunnel, StatusCode> {
    let (resp, request_body) = send_connect(sender, None).await;
    if resp.status() != StatusCode::OK {
        return Err(resp.status());
    }
    Ok(Tunnel {
        request_body,
        response_body: resp.into_body(),
    })
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

/// A revoked tunnel was cut short, so the peer must see its CONNECT stream
/// reset with `RST_STREAM(CONNECT_ERROR)` rather than the clean `END_STREAM`
/// that reads as a completed relay (issue #5858). Anything still buffered
/// before the cut is drained and ignored.
async fn assert_tunnel_reset_with_connect_error(body: &mut h2::RecvStream) {
    let err = tokio::time::timeout(DEADLINE, async {
        loop {
            match body.data().await {
                None => return None,
                Some(Err(err)) => return Some(err),
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
            }
        }
    })
    .await
    .expect("revoked tunnel must close toward the peer")
    .expect("a revoked tunnel must be reset, not ended with END_STREAM");
    assert_eq!(err.reason(), Some(h2::Reason::CONNECT_ERROR));
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

/// Every revocation reason, in the fence's own GATE ORDER, so an assertion
/// reads the same way the sweep decides:
/// `[proxy_withdrawn, peer_expired, peer_trust, peer_revoked,
///   authorization_denied, peer_auth_transport, relay_destination,
///   reuse_withdrawn, reevaluation_failed]`.
///
/// The three credential arms are ordered by webpki's own error precedence —
/// `notAfter` before any anchor, `UnknownIssuer` before revocation — so this
/// array is also the pin on that derivation (issue #5574). `reuse_withdrawn`
/// (issue #5583) sits after every gate that is a refusal, because it is the
/// only reason whose tunnel would still have been ADMITTED.
fn revocation_counts(state: &ProxyState) -> [u64; HboneRevocationReason::ALL.len()] {
    let fence = &state.hbone_admission_fence;
    [
        fence.revocations(HboneRevocationReason::ProxyWithdrawn),
        fence.revocations(HboneRevocationReason::PeerExpired),
        fence.revocations(HboneRevocationReason::PeerTrust),
        fence.revocations(HboneRevocationReason::PeerRevoked),
        fence.revocations(HboneRevocationReason::AuthorizationDenied),
        fence.revocations(HboneRevocationReason::PeerAuthTransport),
        fence.revocations(HboneRevocationReason::RelayDestination),
        fence.revocations(HboneRevocationReason::ReuseWithdrawn),
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
    /// The inbound SPIFFE verifier's trust slot, when this fixture installed
    /// one. `None` is the chain-only inbound posture: peers are verified
    /// against the operator client-CA bundle and the fence's trust half is
    /// inapplicable.
    inbound_trust_slot: Option<SharedBundleSlot>,
    /// The mTLS material the handshake used, retained so a revocation test can
    /// sign a CRL with the very CA that issued the client SVID this connection
    /// presented (issue #5574).
    certs: HboneMtlsCerts,
}

async fn admit_client_tunnel(policies: Vec<MeshPolicy>) -> AdmittedFixture {
    admit_client_tunnel_with_inbound_trust(policies, false).await
}

/// One admitted byte-stream tunnel over a REAL inbound mTLS handshake.
///
/// With `install_inbound_trust`, the fence is additionally given an inbound
/// SPIFFE trust slot whose LOCAL bundle is the fixture CA's trust domain — the
/// peer's — and whose federated map carries the slice's differing local domain.
/// That is the exact shape `merge_trust_overlay_into_svid_bundle` produces, and
/// it is the shape under which the request epoch's separately-built bundles
/// would have reported the peer as unanchored.
async fn admit_client_tunnel_with_inbound_trust(
    policies: Vec<MeshPolicy>,
    install_inbound: bool,
) -> AdmittedFixture {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(Some(backend_addr.port()), policies));
    let inbound_trust_slot = install_inbound.then(|| {
        let gateway = mint_peer_chain(GATEWAY_SPIFFE);
        let mut federated = std::collections::HashMap::new();
        federated.insert(
            TrustDomain::new(SLICE_TRUST_DOMAIN).expect("slice trust domain"),
            trust_bundle(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
        );
        install_inbound_trust(
            &state,
            &gateway,
            RuntimeTrustBundleSet {
                local: trust_bundle(PEER_TRUST_DOMAIN, vec![certs.ca_der()]),
                federated,
            },
        )
    });
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("admitted CONNECT under the initial policy generation");
    echo_round_trip(&mut tunnel, b"before-publish").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    AdmittedFixture {
        state,
        tunnel,
        sender,
        conn_task,
        backend_handle,
        backend_port: backend_addr.port(),
        shutdown_tx,
        inbound_trust_slot,
        certs,
    }
}

impl AdmittedFixture {
    async fn teardown(self) {
        let _ = self.shutdown_tx.send(true);
        self.backend_handle.abort();
        self.conn_task.abort();
    }
}

/// An `action: DENY` rule whose only match constraint is an L7 path. A relayed
/// tunnel carries no parsed request, so the rule can only be satisfied through
/// the relay's Layer-4 authorization: a DENY ignores HTTP-only fields and
/// matches on its remaining constraints.
fn deny_l7_path() -> MeshPolicy {
    MeshPolicy {
        name: "deny-l7-path".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: namespace_scope(),
        rules: vec![MeshRule {
            to: vec![RequestMatch {
                paths: vec!["/admin/*".to_string()],
                ..RequestMatch::default()
            }],
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

/// A real authenticated HBONE CONNECT through the production handler chain is
/// refused at admission by an L7 DENY, and never becomes a tunnel.
///
/// The ALLOW admits the peer and the DENY carries only a path, so this only
/// holds because the proxy marks the CONNECT as an opaque relay before the
/// plugin chain runs. Without that mark the CONNECT would be judged as an HTTP
/// request whose path does not reach the rule, and the ALLOW would admit it.
#[tokio::test(flavor = "multi_thread")]
async fn an_l7_deny_refuses_a_real_hbone_connect_at_admission() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client(), deny_l7_path()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an L7 DENY must refuse the relayed CONNECT at admission"
    );
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        0,
        "a refused CONNECT must never become a tunnel"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// The datagram tag has no live-policy fixture in this suite, so this pins that
/// BOTH HBONE tag entry points mark the relay before they record it as HBONE.
/// The end-to-end test above proves the byte-stream mark is reached through the
/// production handler chain.
#[test]
fn both_hbone_tag_entry_points_mark_the_connect_relay() {
    let proxy = include_str!("../../src/proxy/hbone_proxy.rs");
    for function in ["fn tag_request_metadata", "fn tag_udp_request_metadata"] {
        let start = proxy
            .find(function)
            .unwrap_or_else(|| panic!("{function} must exist"));
        let body = &proxy[start..];
        let mark = body
            .find("ctx.mark_hbone_connect_relay();")
            .unwrap_or_else(|| panic!("{function} must mark the relay"));
        let protocol_tag = body
            .find(".insert(\"request_protocol\"")
            .unwrap_or_else(|| panic!("{function} must tag the request protocol"));
        assert!(
            mark < protocol_tag,
            "{function} must mark the relay before it records HBONE metadata"
        );
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

    assert_tunnel_reset_with_connect_error(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 0, 1, 0, 0, 0, 0],
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
        [0, 0, 0, 0, 1, 0, 0, 0, 0],
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
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        [1, 0, 0, 0, 0, 0, 0, 0, 0],
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
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        [0, 0, 0, 0, 0, 1, 0, 0, 0],
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
    assert_tunnel_reset_with_connect_error(&mut response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0, 1, 0, 0, 0],
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
    // Read at the cancellation edge, deliberately: the accounting is published
    // before the token is cancelled, so anything woken by the cancellation
    // already sees the revocation counted.
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0, 0]);
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
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0, 0]);
}

/// [`relay_destination_config`] carrying the markers a materialized Sidecar
/// publishes for its inbound HTTP routes (issue #6110).
fn sidecar_http_route_config(
    destinations: Vec<MeshInboundRelayDestination>,
    http_app_ports: Vec<u16>,
    refuses_matched_http_connect: bool,
    generation_tag: u16,
) -> GatewayConfig {
    let mut config = relay_destination_config(destinations, false, generation_tag);
    let mesh = config.mesh.as_deref_mut().expect("mesh block");
    mesh.sidecar_inbound_http_app_ports = http_app_ports;
    mesh.sidecar_inbound_refuses_matched_http_connect = refuses_matched_http_connect;
    config
}

/// A live relay to a port that a reload turns into a Sidecar HTTP application
/// port is revoked: the peer's next CONNECT to it would be refused
/// `http_application_port`, so the tunnel must not keep relaying bytes past
/// the HTTP route's plugin chain (issue #6110).
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_makes_the_relayed_port_an_http_application_port_revokes_the_tunnel() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let initial = sidecar_http_route_config(vec![destination.clone()], Vec::new(), true, 9501);
    let state = build_state(initial);
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The destination stays owned; only its port now serves an HTTP route.
    let reloaded = sidecar_http_route_config(vec![destination], vec![RELAY_APP_PORT], true, 9502);
    let outcome = state.update_config(reloaded);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the stream relay guard must re-apply the HTTP application port refusal"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0, 0]);
}

/// A live tunnel admitted through a configured HTTP route on the inbound
/// listener is revoked once a reload makes that listener a materializing
/// Sidecar's, where the peer's next bare CONNECT matching the route would be
/// refused (issue #6110). A tunnel through the same route on a listener of
/// another direction is not judged by that rule and survives.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_refuses_matched_http_connects_revokes_a_configured_route_tunnel() {
    let initial = sidecar_http_route_config(Vec::new(), Vec::new(), false, 9601);
    let state = build_state(initial);
    let fence = &state.hbone_admission_fence;
    let configured = |direction: MeshTrafficDirection| {
        let mut snapshot = synthetic_snapshot(
            create_mesh_proxy(RELAY_APP_PORT),
            HboneRelayDestinationGate::Configured,
            None,
            fence.sweep_epoch(),
        );
        snapshot.ctx.mesh_direction = Some(direction);
        fence.admit(snapshot)
    };
    let inbound = configured(MeshTrafficDirection::Inbound);
    let outbound = configured(MeshTrafficDirection::Outbound);
    assert_eq!(inbound.revoked_reason(), None);
    assert_eq!(outbound.revoked_reason(), None);

    let reloaded = sidecar_http_route_config(Vec::new(), Vec::new(), true, 9602);
    let outcome = state.update_config(reloaded);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&inbound).await;
    assert_eq!(
        inbound.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "a bare CONNECT matching a Sidecar inbound HTTP route is no longer admitted"
    );
    wait_for_settled_sweeps(&state).await;
    assert_eq!(outbound.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0, 0]);
}

/// Mesh synthesis builds the Sidecar `ingress[]` CONNECT remap under this
/// reserved id. Pinned as a literal for the same reason as
/// `MESH_INBOUND_HBONE_RELAY_PROXY_ID`.
const MESH_INGRESS_HBONE_RELAY_PROXY_ID: &str = "__mesh-ingress-connect-relay";
const INGRESS_ENDPOINT_HOST: &str = "127.0.0.1";
/// The declared stream-family `ingress[]` listener port a peer's CONNECT names,
/// and the loopback `defaultEndpoint` port the remap dials for it.
const REMAP_LISTENER_PORT: u16 = 16379;
const REMAP_ENDPOINT_PORT: u16 = 6379;
/// A second stream listener with an endpoint port of its own.
const KEPT_LISTENER_PORT: u16 = 16380;
const KEPT_ENDPOINT_PORT: u16 = 6380;
/// An HTTP-family `ingress[]` listener a reload adds, and an endpoint port it
/// can forward to without sharing a remap's.
const HTTP_LISTENER_PORT: u16 = 9080;
const HTTP_ENDPOINT_PORT: u16 = 8080;

/// A resolved Sidecar `ingress[]` listener on `port` forwarding to loopback
/// `endpoint_port`, owned by a local service so the remap guard can admit it.
fn ingress_listener(
    port: u16,
    endpoint_port: u16,
    protocol: AppProtocol,
) -> ResolvedIngressListener {
    ResolvedIngressListener {
        port,
        endpoint_host: INGRESS_ENDPOINT_HOST.to_string(),
        endpoint_port,
        protocol,
        endpoint_unix_path: None,
        endpoint_unix_h2c: false,
        owner_namespace: DEFAULT_NAMESPACE.to_string(),
        owner_service: "orders".to_string(),
        bind: None,
    }
}

/// [`relay_destination_config`] carrying a DECLARED Sidecar `ingress[]` block
/// whose admitted listeners are `listeners`, as the Sidecar inbound
/// materializer back-projects them onto the prepared mesh block.
fn ingress_remap_config(
    listeners: Vec<ResolvedIngressListener>,
    generation_tag: u16,
) -> GatewayConfig {
    let mut config = relay_destination_config(Vec::new(), false, generation_tag);
    let mesh = config.mesh.as_deref_mut().expect("mesh block");
    mesh.sidecar_ingress_declared = true;
    mesh.local_ingress_listeners = listeners;
    config
}

/// Whether `config` still maps a CONNECT to `listener_port` onto loopback
/// `endpoint_port`: the predicate the sweep's ingress-remap gate re-applies.
/// Asserting it on each generation proves a test's verdict comes from the
/// mapping it names, not from a fixture the guard never admitted.
fn remap_admitted(config: &GatewayConfig, listener_port: u16, endpoint_port: u16) -> bool {
    let mesh = config.mesh.as_deref().expect("mesh block");
    mesh.sidecar_ingress_connect_relay_endpoint_matches(
        listener_port,
        INGRESS_ENDPOINT_HOST,
        endpoint_port,
    )
}

/// Registers what the CONNECT path records for a remapped tunnel: the reserved
/// remap proxy dialling the listener's loopback `defaultEndpoint`, the
/// `IngressRelay` gate, and the DECLARED listener port the remap stamps as the
/// listener authz port, which is the key the sweep re-judges the mapping on.
fn admit_ingress_remap(
    state: &ProxyState,
    listener_port: u16,
    endpoint_port: u16,
) -> AdmittedHboneTunnel {
    let fence = &state.hbone_admission_fence;
    let mut proxy = create_mesh_proxy(endpoint_port);
    proxy.id = MESH_INGRESS_HBONE_RELAY_PROXY_ID.to_string();
    proxy.backend_host = INGRESS_ENDPOINT_HOST.to_string();
    let mut snapshot = synthetic_snapshot(
        proxy,
        HboneRelayDestinationGate::IngressRelay,
        Some(IpAddr::from([127, 0, 0, 1])),
        fence.sweep_epoch(),
    );
    snapshot.ctx.mesh_inbound_listener_authz_port = Some(listener_port);
    fence.admit(snapshot)
}

/// A live Sidecar `ingress[]` CONNECT remap is revoked once a reload adds an
/// HTTP-family `ingress[]` listener forwarding to the same `defaultEndpoint`
/// port. HTTP wins a shared port (issue #6110), so the peer's next CONNECT to
/// the stream listener would be refused `http_application_port`, and the live
/// tunnel must not keep relaying opaque bytes past the HTTP route's plugin
/// chain. A remap to a different endpoint port survives the same reload.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_adds_an_http_ingress_listener_on_the_endpoint_port_revokes_the_remap() {
    let remap = ingress_listener(REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT, AppProtocol::Tcp);
    let kept = ingress_listener(KEPT_LISTENER_PORT, KEPT_ENDPOINT_PORT, AppProtocol::Tcp);
    let initial = ingress_remap_config(vec![remap.clone(), kept.clone()], 9701);
    assert!(remap_admitted(&initial, REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT));
    assert!(remap_admitted(&initial, KEPT_LISTENER_PORT, KEPT_ENDPOINT_PORT));
    let state = build_state(initial);

    let shared_tunnel = admit_ingress_remap(&state, REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT);
    let kept_tunnel = admit_ingress_remap(&state, KEPT_LISTENER_PORT, KEPT_ENDPOINT_PORT);
    assert_eq!(shared_tunnel.revoked_reason(), None);
    assert_eq!(kept_tunnel.revoked_reason(), None);

    // Both stream listeners stay declared; only the remap's endpoint port is
    // now one an HTTP listener also forwards to.
    let http = ingress_listener(HTTP_LISTENER_PORT, REMAP_ENDPOINT_PORT, AppProtocol::Http);
    let reloaded = ingress_remap_config(vec![remap, kept, http], 9702);
    assert!(!remap_admitted(&reloaded, REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT));
    assert!(remap_admitted(&reloaded, KEPT_LISTENER_PORT, KEPT_ENDPOINT_PORT));
    let outcome = state.update_config(reloaded);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&shared_tunnel).await;
    assert_eq!(
        shared_tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the ingress remap guard must re-apply the HTTP-wins-a-shared-port rule"
    );
    wait_for_settled_sweeps(&state).await;
    assert_eq!(kept_tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0, 0]);
}

/// A reload that changes the Sidecar `ingress[]` block without touching a live
/// remap's mapping re-judges the tunnel and keeps it: the added HTTP listener
/// forwards to an endpoint port of its own, so the peer's next CONNECT to the
/// declared stream listener would still be remapped exactly as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_ingress_reload_that_leaves_the_mapping_intact_keeps_a_live_remap() {
    let remap = ingress_listener(REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT, AppProtocol::Tcp);
    let initial = ingress_remap_config(vec![remap.clone()], 9711);
    assert!(remap_admitted(&initial, REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT));
    let state = build_state(initial);
    let fence = &state.hbone_admission_fence;

    let tunnel = admit_ingress_remap(&state, REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT);
    assert_eq!(tunnel.revoked_reason(), None);
    let completed_before = fence.sweeps_completed();
    let reevaluations_before = fence.reevaluations();

    // A real generation change to the same `ingress[]` block whose shared-port
    // rule does not reach the remap's endpoint.
    let http = ingress_listener(HTTP_LISTENER_PORT, HTTP_ENDPOINT_PORT, AppProtocol::Http);
    let reloaded = ingress_remap_config(vec![remap, http], 9712);
    assert!(remap_admitted(&reloaded, REMAP_LISTENER_PORT, REMAP_ENDPOINT_PORT));
    let outcome = state.update_config(reloaded);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_sweep_after(&state, completed_before).await;
    wait_for_settled_sweeps(&state).await;

    assert!(
        fence.reevaluations() > reevaluations_before,
        "the publication must re-judge the live remap, not skip it"
    );
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
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

/// A peer cannot steer the fence onto a plugin view the tunnel was never
/// admitted with, because a CONNECT that declares a gRPC content type is not
/// admitted at all.
///
/// `content-type: application/grpc` classifies the request as
/// `HttpFlavor::Grpc` well before the HBONE branch, and the gRPC spec's POST
/// requirement then refuses any other method as trailers-only (`200` + a
/// non-zero `grpc-status`, END_STREAM) — a refusal, not a tunnel. Every
/// admitted HBONE tunnel is therefore admitted on the plain-HTTP view, which is
/// the view a sweep re-resolves. The snapshot still records whichever view the
/// request path actually used
/// (`HboneAdmissionSnapshot::request_protocol` / `grpc_web_request`, pinned by
/// `the_fence_sweep_resolves_the_admitting_plugin_view`) instead of hardcoding
/// plain HTTP, so the sweep cannot drift from the request path if that gate
/// ever moves.
#[tokio::test(flavor = "multi_thread")]
async fn a_grpc_classified_connect_is_refused_before_it_can_become_a_fenced_tunnel() {
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

    // This generation ALLOWS the principal, so the refusal below is the
    // protocol gate rather than authorization.
    let (refused, _refused_request) = send_connect(&mut sender, Some("application/grpc")).await;
    assert_eq!(
        refused.status(),
        StatusCode::OK,
        "a gRPC-classified refusal is trailers-only, not an HTTP error status"
    );
    let refused_grpc_status = grpc_status_of(&refused);
    assert!(
        refused_grpc_status
            .as_deref()
            .is_some_and(|status| status != "0"),
        "a gRPC-classified CONNECT must be refused, never admitted as a tunnel; got \
         grpc-status {refused_grpc_status:?}"
    );
    let mut refused_body = refused.into_body();
    assert_tunnel_closed(&mut refused_body).await;
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        0,
        "a refused CONNECT must not register a sweepable tunnel"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    // The same peer's plain CONNECT IS admitted, on the plain-HTTP view, and
    // the fence judges it against exactly that view.
    let mut tunnel = open_tunnel(&mut sender)
        .await
        .expect("a plain CONNECT is admitted under the same generation");
    echo_round_trip(&mut tunnel, b"admitting-view").await;
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
        "the sweep must have resolved a non-empty authorize chain for the admitting view"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 1, 0, 0, 0, 0]);

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
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
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
        [0, 0, 0, 0, 3, 0, 0, 0, 0],
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

/// Gate ORDER, not just gate coverage: the sweep's `reason` label and the
/// operator log line are the only attribution a revocation carries, so a tunnel
/// that fails two gates must be attributed the one its peer's next CONNECT
/// would actually be refused with. The request path authorizes in
/// `handle_proxy_request_inner` BEFORE it branches into `handle_hbone_request`,
/// which only then checks the PeerAuthentication transport mode — so
/// `authorization_denied` outranks `peer_auth_transport`, and a rollout
/// dashboard watching `ferrum_mesh_hbone_tunnel_revocations_total` by `reason`
/// agrees with what the client sees on its next CONNECT.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorization_denial_outranks_a_transport_mismatch_in_one_sweep() {
    const APP_PORT: u16 = 8080;
    // The published generation already DENIES this principal, so the authorize
    // gate is armed before the tunnel is ever registered.
    let state = build_state(prepared_config(Some(APP_PORT), vec![deny_client()]));
    let fence = &state.hbone_admission_fence;
    let proxy = Arc::new(create_mesh_proxy(APP_PORT));

    let tunnel = fence.admit(dual_gate_snapshot(proxy, fence.sweep_epoch()));
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    // STRICT arms the transport gate for this plaintext tunnel AND is what
    // schedules the single sweep that now sees both gates failing.
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy {
        default_mode: MtlsMode::Strict,
        ..MeshInboundTlsPolicy::default()
    });

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::AuthorizationDenied),
        "a tunnel failing both gates must carry the reason the CONNECT path would refuse it \
         with, not the reason the sweep happened to evaluate first"
    );
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 1, 0, 0, 0, 0],
        "exactly one authorization_denied revocation, and no peer_auth_transport one"
    );
    assert!(
        fence.reevaluations() >= 1,
        "the authorize chain must actually have run for the live tunnel"
    );
}

/// A globally scoped, timestamp-only `soap_ws_security` row: HTTP-only
/// admission policy that is not an auth plugin.
fn http_only_admission_plugin() -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: "operator-soap-freshness".to_string(),
        plugin_name: "soap_ws_security".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        config: json!({
            "timestamp": {
                "require": true,
                "max_age_seconds": 300,
                "clock_skew_seconds": 300
            },
            "reject_missing_security_header": true
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

/// The request path refuses a client-selected flavor whose plugin view omits
/// the route's admission policy before any plugin runs. A reload that adds an
/// HTTP-only admission plugin therefore refuses the peer's next CONNECT on a
/// gRPC-classified view, so a live tunnel admitted on that view is revoked
/// rather than outliving the policy, under the authorize gate's reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_omits_admission_policy_from_the_admitting_view_revokes_the_tunnel() {
    const APP_PORT: u16 = 8080;
    let state = build_state(prepared_config(Some(APP_PORT), vec![allow_client()]));
    let fence = &state.hbone_admission_fence;
    let proxy = Arc::new(create_mesh_proxy(APP_PORT));
    let mut snapshot = dual_gate_snapshot(proxy, fence.sweep_epoch());
    snapshot.request_protocol = ProxyProtocol::Grpc;
    let tunnel = fence.admit(snapshot);
    assert_eq!(tunnel.revoked_reason(), None);

    // Negative control: a generation that still admits the principal and adds
    // no admission policy leaves the gRPC-classified tunnel live.
    let completed_before = fence.sweeps_completed();
    let outcome = state.update_config(prepared_config(
        Some(APP_PORT),
        vec![allow_client(), allow_other()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_sweep_after(&state, completed_before).await;
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let outcome = state.update_config(prepared_config_with(
        Some(APP_PORT),
        None,
        vec![allow_client()],
        vec![http_only_admission_plugin()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::AuthorizationDenied)
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 1, 0, 0, 0, 0]);
}

/// Retirement and revocation are ONE compare-exchange against the same terminal
/// state, so exactly one wins. When the relay wins, the tunnel is neither
/// counted, metered, nor classified as revoked: two separate atomics let a
/// sweep that read "not retired" microseconds before the relay ended still
/// increment `revocations[..]` and log a revocation for a tunnel carrying no
/// bytes — and the datagram relay, which reads `revoked_reason()` AFTER
/// `retire()` and has no `first_failure` to cross-check against, then reported
/// an ordinary idle/EOF close as an admission revocation.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_the_relay_retired_first_is_never_counted_or_classified_as_revoked() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9501));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    assert!(
        tunnel.retire(),
        "the relay ended first, so it owns the terminal transition"
    );
    assert!(!tunnel.retire(), "the terminal transition is one-shot");
    assert_eq!(fence.live_tunnels(), 0);

    // Exactly the publication that WOULD have revoked this tunnel.
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9502));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a retired tunnel must never be classified as revoked"
    );
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
        "a retired tunnel must never be counted as a revocation"
    );
    assert!(
        !tunnel.revocation_token().is_cancelled(),
        "a retired tunnel's relay must not be told the fence cut it"
    );
}

/// The other side of the same transition. Once a sweep has claimed a tunnel,
/// the relay's `retire()` loses and the recorded reason stays readable — which
/// is exactly what the datagram relay depends on, because it calls `retire()`
/// and THEN reads `revoked_reason()` to classify its own close.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_tunnels_reason_survives_the_relays_retire() {
    let destination = relay_destination(RELAY_APP_HOST, RELAY_APP_PORT);
    let state = build_state(relay_destination_config(vec![destination], false, 9601));
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(synthetic_snapshot(
        inbound_relay_proxy(RELAY_APP_HOST, RELAY_APP_PORT),
        HboneRelayDestinationGate::InboundRelay,
        None,
        fence.sweep_epoch(),
    ));
    let outcome = state.update_config(relay_destination_config(Vec::new(), false, 9602));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_revocation(&tunnel).await;

    assert!(
        !tunnel.retire(),
        "a sweep already owns the terminal transition for this tunnel"
    );
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::RelayDestination),
        "the reason must outlive the relay's retire(), or the datagram relay misreports it"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 1, 0, 0]);
}

// ── Credential dimension (issue #5568) ────────────────────────────────────

/// The peer's trust domain, as it appears in [`CLIENT_SPIFFE`].
const PEER_TRUST_DOMAIN: &str = "cluster.local";
/// A second trust domain, used as the domain a slice declares locally when it
/// differs from the gateway SVID's own.
const SLICE_TRUST_DOMAIN: &str = "partner.local";
/// The gateway's own workload identity. Never consulted by the fence, which
/// reads only the trust bundles, but a real SVID keeps the published slot the
/// shape every other consumer expects.
const GATEWAY_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/gateway";
/// `backend_port` on the configured proxy the credential fixtures name.
///
/// No socket is ever bound to it and nothing dials it: these fixtures register
/// a snapshot with the fence directly and assert on the sweep's verdict, so the
/// value is only a field on a `Proxy` struct — the same way the relay-
/// destination fixtures above use their generation tag.
const CREDENTIAL_BACKEND_PORT: u16 = 9600;

/// The serial every minted leaf carries, so a CRL fixture can name it without
/// re-parsing the certificate (issue #5574). Fixed rather than random because
/// the revocation tests turn on "this serial versus another one", and the other
/// one is [`UNRELATED_LEAF_SERIAL`].
const PEER_LEAF_SERIAL: u64 = 0x5574;
/// A serial no minted leaf carries. A CRL listing only this must revoke nothing.
const UNRELATED_LEAF_SERIAL: u64 = 0x5575;

/// The issuing intermediate's serial, so a root-signed CRL can revoke the
/// ISSUER rather than the leaf and prove the policy really is full-chain.
const INTERMEDIATE_SERIAL: u64 = 0x5576;

/// The leaf under that intermediate. Deliberately never named by any CRL in
/// the full-chain test: revoking the issuer has to be enough.
const INTERMEDIATE_LEAF_SERIAL: u64 = 0x5577;

/// A self-signed CA plus one SPIFFE leaf it issued, both DER.
///
/// Minted here rather than borrowed from `mesh_hbone_tests` so these tests own
/// the issuing root they assert about: several of them turn on one chain
/// anchoring in one bundle and not in another.
///
/// The issuer is retained (issue #5574) because the revocation tests have to
/// sign a CRL with the very key that issued the leaf — a CRL signed by anything
/// else is not the authority for that chain and webpki would ignore it, which
/// would make a revocation test pass for the wrong reason.
struct PeerChain {
    ca_der: Vec<u8>,
    leaf_der: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn mint_peer_chain(spiffe: &str) -> PeerChain {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, SerialNumber, string::Ia5String,
    };

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("{spiffe} issuing CA"));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");
    let ca_der = ca_cert.der().to_vec();
    // `Issuer::new` consumes the params + key, so capture the CA DER first.
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.serial_number = Some(SerialNumber::from(PEER_LEAF_SERIAL));
    leaf_params.subject_alt_names.push(SanType::URI(
        Ia5String::try_from(spiffe.to_string()).expect("spiffe uri san"),
    ));
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    PeerChain {
        ca_der,
        leaf_der: leaf.der().to_vec(),
        issuer,
    }
}

/// A properly signed, in-window CRL from `chain`'s CA revoking `serials`.
///
/// Signed by the chain's own issuer so it is authoritative for that chain; the
/// window brackets now, so `enforce_revocation_expiration()` — which the shared
/// CRL policy always sets — accepts it.
fn signed_crl(chain: &PeerChain, serials: &[u64]) -> CertificateRevocationListDer<'static> {
    signed_crl_in_window(
        chain,
        serials,
        time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        time::OffsetDateTime::now_utc() + time::Duration::days(30),
    )
}

fn signed_crl_in_window(
    chain: &PeerChain,
    serials: &[u64],
    this_update: time::OffsetDateTime,
    next_update: time::OffsetDateTime,
) -> CertificateRevocationListDer<'static> {
    signed_crl_by_issuer(&chain.issuer, serials, this_update, next_update)
}

/// [`signed_crl_in_window`] against an arbitrary issuer.
///
/// Separate because a full-chain revocation test has to sign with the ROOT — a
/// CRL revoking an issuing intermediate is authoritative only when the
/// authority that ISSUED that intermediate signed it, and webpki ignores one
/// signed by anything else.
fn signed_crl_by_issuer(
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    serials: &[u64],
    this_update: time::OffsetDateTime,
    next_update: time::OffsetDateTime,
) -> CertificateRevocationListDer<'static> {
    let revoked_certs = serials
        .iter()
        .map(|serial| rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from(*serial),
            revocation_time: this_update,
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = rcgen::CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    CertificateRevocationListDer::from(params.signed_by(issuer).expect("sign CRL").der().to_vec())
}

/// Publish `records` as the enforced mesh inbound CRL set, through the one
/// writer production uses. Returns whether the enforced set actually changed.
fn publish_crls(state: &ProxyState, records: Vec<CertificateRevocationListDer<'static>>) -> bool {
    state.publish_mesh_inbound_crls(Arc::new(records))
}

/// The inbound SPIFFE peer verifier the mesh listener builds, reading `state`'s
/// LIVE enforced CRL slot.
///
/// Built ONCE per test and reused across publications on purpose: the listener
/// is not rebound when an operator rotates a CRL, so reusing one verifier is
/// what pins the half of issue #5574 that lives in the verifier cache — its
/// identity has to include the enforced set's generation, not just the SVID
/// source.
fn inbound_verifier(
    state: &ProxyState,
    slot: &SharedBundleSlot,
) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
    tls::build_spiffe_client_cert_verifier_for_inbound_admission(
        slot.clone(),
        true,
        Arc::clone(&state.mesh_inbound_admission),
    )
}

/// Whether `verifier` still accepts `peer`'s leaf — the "next handshake" half
/// of issue #5574: the fence cuts the live tunnel, and the same published CRL
/// must also refuse the peer's next handshake, or a revoked workload simply
/// reconnects.
fn handshake_admits(
    verifier: &Arc<dyn rustls::server::danger::ClientCertVerifier>,
    peer: &PeerChain,
) -> bool {
    handshake_admits_leaf(verifier, &peer.leaf_der)
}

/// [`handshake_admits`] for a leaf whose fixture is not a [`PeerChain`] — the
/// live HBONE mTLS fixture's own client SVID, so one test can drive the
/// production `verify_client_cert` for exactly the peer whose tunnel the fence
/// is judging.
fn handshake_admits_leaf(
    verifier: &Arc<dyn rustls::server::danger::ClientCertVerifier>,
    leaf_der: &[u8],
) -> bool {
    use rustls::server::danger::ClientCertVerifier;

    let leaf = rustls::pki_types::CertificateDer::from(leaf_der.to_vec());
    let now = rustls::pki_types::UnixTime::now();
    let verified = ClientCertVerifier::verify_client_cert(verifier.as_ref(), &leaf, &[], now);
    verified.is_ok()
}

/// One trust domain's bundle.
fn trust_bundle(trust_domain: &str, authorities: Vec<Vec<u8>>) -> RuntimeTrustBundle {
    RuntimeTrustBundle {
        trust_domain: TrustDomain::new(trust_domain).expect("trust domain"),
        x509_authorities: authorities,
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }
}

/// A trust set whose local bundle is `trust_domain` and which federates
/// nothing.
fn local_trust(trust_domain: &str, authorities: Vec<Vec<u8>>) -> RuntimeTrustBundleSet {
    RuntimeTrustBundleSet {
        local: trust_bundle(trust_domain, authorities),
        federated: Default::default(),
    }
}

/// An SVID bundle in the shape the mesh inbound SPIFFE verifier's slot carries.
fn inbound_bundle(gateway: &PeerChain, trust_bundles: RuntimeTrustBundleSet) -> SvidBundle {
    SvidBundle {
        spiffe_id: SpiffeId::new(GATEWAY_SPIFFE).expect("gateway spiffe id"),
        cert_chain_der: vec![gateway.leaf_der.clone()],
        private_key_pkcs8_der: vec![8, 8, 8].into(),
        trust_bundles,
    }
}

/// Install the inbound mTLS verifier's trust slot — the slot the fence judges
/// live tunnels against — carrying `trust_bundles`.
///
/// Production wires the ONE slot `mesh_inbound_spiffe_verifier` reads; these
/// fixtures wire an equivalent one, because the fence's contract is defined by
/// what that verifier would accept on the peer's next handshake.
fn install_inbound_trust(
    state: &ProxyState,
    gateway: &PeerChain,
    trust_bundles: RuntimeTrustBundleSet,
) -> SharedBundleSlot {
    let slot = ferrum_edge::tls::shared_bundle_slot(Some(inbound_bundle(gateway, trust_bundles)));
    state.install_mesh_inbound_admission_trust(&slot);
    slot
}

/// Republish the inbound verifier's trust slot through the one production
/// writer, which advances the slot's trust revision when the X.509 material
/// changed and then requests a fence sweep.
fn publish_inbound_trust(
    state: &ProxyState,
    slot: &SharedBundleSlot,
    gateway: &PeerChain,
    trust_bundles: RuntimeTrustBundleSet,
) {
    state.publish_mesh_inbound_trust_bundle(
        slot,
        Arc::new(Some(inbound_bundle(gateway, trust_bundles))),
    );
}

/// Publish one REQUEST-EPOCH gateway trust generation carrying exactly
/// `authorities` for `trust_domain`.
///
/// Goes through `install_gateway_runtime_svid_bundle`, the production SVID
/// source-rotation entry point, so the publication really is the complete
/// fence → install → retire → commit transaction that ends at
/// `publish_live_gateway_trust`.
///
/// Deliberately separate from [`publish_inbound_trust`]: the two really are
/// different material written by different code, which is the whole point of
/// the divergence tests below. The epoch's bundles are the CP/database
/// override; the inbound slot's are what a peer handshake is checked against.
fn publish_gateway_trust(
    state: &ProxyState,
    gateway: &PeerChain,
    trust_domain: &str,
    authorities: Vec<Vec<u8>>,
) {
    let _withdrew = state.install_gateway_runtime_svid_bundle(inbound_bundle(
        gateway,
        local_trust(trust_domain, authorities),
    ));
}

fn gateway_trust_generation(state: &ProxyState) -> u64 {
    state.request_epoch.load().gateway_trust().generation()
}

/// The trust revision the fence's installed inbound slot currently publishes.
fn inbound_trust_revision(state: &ProxyState) -> u64 {
    state
        .hbone_admission_fence
        .inbound_trust_revision()
        .expect("the credential fixtures install an inbound admission trust slot")
}

/// A credential deadline far enough out that the expiry half of the gate never
/// fires, so a test isolates the trust half.
fn live_expiry() -> AdmittedLeafExpiry {
    AdmittedLeafExpiry::At(tokio::time::Instant::now() + Duration::from_secs(3600))
}

fn peer_credential(
    chain: &PeerChain,
    leaf_expiry: AdmittedLeafExpiry,
    anchored_at_admission: bool,
    admitted_trust_revision: u64,
) -> HbonePeerCredential {
    HbonePeerCredential {
        spiffe_id: SpiffeId::new(CLIENT_SPIFFE).expect("client spiffe id"),
        leaf_der: Arc::new(chain.leaf_der.clone()),
        intermediates_der: None,
        leaf_expiry,
        anchored_at_admission,
        admitted_trust_revision,
    }
}

/// An admission snapshot whose ONLY live gate is the credential one.
///
/// A configured proxy (so the relay-destination guard does not apply and no
/// lifecycle generation is recorded), no mesh direction (so the transport gate
/// is inapplicable), and a published generation carrying no authorize plugins
/// at all — see [`relay_destination_config`], which does not run mesh
/// preparation.
fn credential_snapshot(
    admission_sweep_epoch: u64,
    peer_credential: HbonePeerCredential,
) -> HboneAdmissionSnapshot {
    let mut snapshot = synthetic_snapshot(
        create_mesh_proxy(CREDENTIAL_BACKEND_PORT),
        HboneRelayDestinationGate::Configured,
        None,
        admission_sweep_epoch,
    );
    snapshot.peer_credential = Some(peer_credential);
    snapshot
}

/// A state whose published generation exercises nothing but the credential
/// gate: no relay inventory, no policies, no injected plugins.
fn credential_state(generation_tag: u16) -> ProxyState {
    build_state(relay_destination_config(Vec::new(), false, generation_tag))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trust_rotation_that_keeps_the_peer_anchored_revokes_nothing() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let joining = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9601);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let admitted_revision = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, admitted_revision),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // A CA rotation that ADDS a root: a real new revision, and the authority
    // that issued this peer's leaf is still in it.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );
    assert!(
        inbound_trust_revision(&state) > admitted_revision,
        "the rotation must advance the inbound trust revision, or the sweep would \
         legitimately skip the chain re-verification and prove nothing"
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(
        fence.trust_rechecks(),
        1,
        "a trust change costs exactly ONE certificate path build per tunnel"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_peers_trust_domain_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9602);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The trust domain is retired. The peer's own issuing root is still in the
    // published material — it simply no longer names a trust domain this
    // gateway accepts, which is exactly what a fresh handshake would refuse.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust),
        "a retired trust domain is a credential withdrawal, not a policy denial"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

/// Withdrawing a FEDERATED trust domain is the same withdrawal as withdrawing
/// the local one, and reaches the peer whose chain anchored there.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_a_federated_trust_domain_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9608);

    // The gateway SVID's own domain is the slice's; the peer's domain rides the
    // set as a federated entry, exactly as `merge_trust_overlay_into_svid_bundle`
    // files a cross-domain bundle.
    let mut federated = std::collections::HashMap::new();
    federated.insert(
        TrustDomain::new(PEER_TRUST_DOMAIN).expect("peer trust domain"),
        trust_bundle(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let slot = install_inbound_trust(
        &state,
        &gateway,
        RuntimeTrustBundleSet {
            local: trust_bundle(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
            federated,
        },
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // The federation is dropped; the local domain is untouched.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust)
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_away_the_issuing_authority_revokes_its_live_tunnel() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let replacement = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9603);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // Same trust domain, different root: the retained chain no longer builds a
    // path. Only re-verifying the chain can see this — the trust domain is
    // still present, so a membership check alone would keep the tunnel.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![replacement.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust)
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

/// The regression the independent review of #5573 found, in its own words: a
/// SPIRE CA rotation arrives through the SVID installer, the INBOUND verifier
/// gains the new root and keeps admitting, and the request epoch's gateway
/// trust — which a CP/database override replaces wholesale — does not describe
/// that root at all.
///
/// Judging the tunnel by the epoch revoked every such peer as `peer_trust` and
/// then immediately re-admitted its reconnect, a self-inflicted reconnect storm
/// that contradicted the fence's own "no false mass revocation" claim. Judging
/// it by the slot the handshake reads is the fix, and this pins it: the epoch
/// generation moves twice and never anchors the peer, while the tunnel stays
/// live because the verifier it would be re-handshaked against still does.
#[tokio::test(flavor = "multi_thread")]
async fn a_root_rotation_the_inbound_verifier_accepted_keeps_live_tunnels() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let joining = mint_peer_chain(OTHER_SPIFFE);
    let cp_override = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9607);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    // The request epoch carries the CP/database override for the SAME trust
    // domain, and that override never carried the peer's issuing root.
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![cp_override.ca_der.clone()],
    );
    let admitted_epoch_generation = gateway_trust_generation(&state);

    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // SPIRE rotates: the installer merges the joining root into the inbound
    // slot additively, and publishes its own (masked) epoch generation.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );
    publish_gateway_trust(
        &state,
        &gateway,
        PEER_TRUST_DOMAIN,
        vec![cp_override.ca_der.clone(), joining.ca_der.clone()],
    );
    assert!(
        gateway_trust_generation(&state) > admitted_epoch_generation,
        "the epoch generation must move, or this proves nothing about which trust the \
         fence reads"
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a peer the inbound verifier still admits must not be revoked because the request \
         epoch's separately-built bundles never carried its root"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
}

/// An ordinary publication is free. A slice apply republishes the inbound slot
/// from unchanged inputs and a pure leaf/key SVID rotation replaces the slot's
/// bundle without touching a single anchor; neither may cost a certificate path
/// build, and a tunnel that has already been verified against the current
/// revision must not be re-verified by every later sweep.
#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_republish_revokes_nothing_and_builds_no_certificate_path() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let rotated_leaf = mint_peer_chain(GATEWAY_SPIFFE);
    let state = credential_state(9609);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let admitted_revision = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, admitted_revision),
    ));

    // Byte-identical trust material, republished twice, plus a gateway SVID
    // whose LEAF rotated while its anchors did not.
    for _ in 0..2 {
        publish_inbound_trust(
            &state,
            &slot,
            &gateway,
            local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
        );
    }
    publish_inbound_trust(
        &state,
        &slot,
        &rotated_leaf,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        inbound_trust_revision(&state),
        admitted_revision,
        "republishing the same anchors — even beneath a rotated leaf — must not advance \
         the trust revision"
    );
    assert_eq!(
        fence.trust_rechecks(),
        0,
        "an ordinary publication must do no certificate path building at all"
    );

    // And a real trust change costs exactly one path build per tunnel, not one
    // per sweep for the rest of the tunnel's life.
    let joining = mint_peer_chain(OTHER_SPIFFE);
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );
    wait_for_settled_sweeps(&state).await;
    assert_eq!(fence.trust_rechecks(), 1);

    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());
    wait_for_settled_sweeps(&state).await;
    assert_eq!(
        fence.trust_rechecks(),
        1,
        "a tunnel re-verified against the current revision must not rebuild its path on \
         every later sweep"
    );
    assert_eq!(tunnel.revoked_reason(), None);
}

/// The one revocation nothing publishes. An established inbound mTLS session is
/// never re-handshaked, so a peer SVID that simply ages out on an otherwise
/// quiet mesh is ended by the fence's own expiry watcher or by nothing at all.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_peer_svid_is_revoked_with_no_publication_at_all() {
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9604);
    let fence = &state.hbone_admission_fence;
    let sweep_epoch_before = fence.sweep_epoch();

    // `Instant::now()` is monotonic and non-decreasing and the gate compares
    // `>=`, so this deadline is already elapsed for every later clock read —
    // without the panic risk of subtracting from a fresh monotonic instant.
    let tunnel = fence.admit(credential_snapshot(
        sweep_epoch_before,
        peer_credential(
            &peer,
            AdmittedLeafExpiry::At(tokio::time::Instant::now()),
            false,
            0,
        ),
    ));

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerExpired),
        "an aged-out leaf is `peer_expired`, never folded into the trust verdict"
    );
    assert_eq!(revocation_counts(&state), [0, 1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        fence.sweep_epoch(),
        sweep_epoch_before,
        "the expiry watcher must sweep directly, not through the coalescing \
         publication counter"
    );
}

/// A leaf the fence cannot parse is a FENCE failure, not a statement about the
/// peer's SVID lifetime. The `reason` label is the operator's only attribution,
/// so it must not point at rotation when the problem is a parser.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_retained_leaf_fails_closed_as_a_reevaluation_failure() {
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9610);
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, AdmittedLeafExpiry::Unparseable, false, 0),
    ));
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::ReevaluationFailed),
        "an unparseable leaf must not be attributed to the peer's SVID lifetime"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 1]);
}

/// A leaf whose `notAfter` outruns the representable monotonic range carries no
/// upper bound of its own (issue #5396). It is an admission, not a refusal, and
/// the expiry half simply has nothing to decide.
#[tokio::test(flavor = "multi_thread")]
async fn an_unbounded_leaf_is_not_revoked_by_the_expiry_half() {
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9611);
    let fence = &state.hbone_admission_fence;

    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, AdmittedLeafExpiry::Unbounded, false, 0),
    ));
    state.publish_mesh_inbound_tls_policy(MeshInboundTlsPolicy::default());
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

/// Parity with the inbound verifier, which is what "would still be admitted"
/// has to mean (issue #5568 review).
///
/// `SpiffePeerVerifierCache::build` compiles a candidate trust set ATOMICALLY
/// and, when it fails, keeps its last-known-good set and carries on admitting
/// peers. A candidate the fence cannot compile must therefore not replace what
/// the fence judges against either — classifying per trust domain cut tunnels in
/// the domains that DID compile while the verifier was still admitting their
/// peers, and judged every other domain against material the verifier never
/// adopted. It is reachable without malformed input: a federated trust domain
/// carrying only `jwtAuthorities` passes mesh config validation and is merged
/// verbatim into the inbound slot.
#[tokio::test(flavor = "multi_thread")]
async fn a_trust_publication_that_does_not_compile_never_takes_force() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9605);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let in_force = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let compilations = fence.trust_anchor_builds();
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, in_force),
    ));
    assert_eq!(tunnel.revoked_reason(), None);

    // A federated trust domain declaring no X.509 authority at all: the inbound
    // verifier refuses the WHOLE candidate on an empty root store.
    let mut jwt_only = std::collections::HashMap::new();
    jwt_only.insert(
        TrustDomain::new(SLICE_TRUST_DOMAIN).expect("slice trust domain"),
        trust_bundle(SLICE_TRUST_DOMAIN, Vec::new()),
    );
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        RuntimeTrustBundleSet {
            local: trust_bundle(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
            federated: jwt_only,
        },
    );
    // ...and authorities that are not usable trust roots at all.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![b"not-a-certificate".to_vec()]),
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        inbound_trust_revision(&state),
        in_force,
        "a publication the inbound verifier would reject must not advance the trust in force"
    );
    assert_eq!(
        fence.trust_anchor_builds(),
        compilations,
        "a refused candidate must not replace the cached anchors either"
    );
    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "the verifier is still admitting this peer under its last-known-good set, so the \
         fence must not cut its tunnel"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.trust_rechecks(), 0);

    // A withdrawal that DOES compile is still a withdrawal: the fence has not
    // been turned off, only aligned with what is in force.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerTrust),
        "a trust set that IS in force and no longer anchors the peer still revokes"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert!(inbound_trust_revision(&state) > in_force);
}

/// The guard against a false mass revocation: a mesh inbound listener with no
/// gateway SVID material verifies peers chain-only against the operator client
/// CA bundle, which the inbound SPIFFE slot does not describe at all. Such a
/// tunnel was never anchored by the inbound admission trust, so the trust half
/// of the gate must never judge it.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_the_admitting_trust_never_anchored_is_not_revoked_for_trust() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let unrelated = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9606);

    // The admitting slot carries a bundle for an unrelated trust domain, so it
    // never anchored this peer.
    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![unrelated.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), false, inbound_trust_revision(&state)),
    ));

    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust("other.local", vec![unrelated.ca_der.clone()]),
    );
    wait_for_settled_sweeps(&state).await;

    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(fence.trust_rechecks(), 0);
}

// ── End-to-end admission capture (issue #5568) ────────────────────────────

/// `HbonePeerCredential::from_admitted_connect` runs on the real CONNECT path,
/// against a real mTLS handshake, so what it captured is asserted from the
/// fence's own registry rather than reconstructed by a fixture.
///
/// This is the coverage whose absence let the trust-source divergence ship:
/// every other credential fixture passes `anchored_at_admission` as a literal,
/// and the production constructor — the one that decides which trust the tunnel
/// is judged by — was never executed at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_connect_captures_its_peer_credential_from_the_inbound_trust() {
    let mut fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;

    let captured = fx
        .state
        .hbone_admission_fence
        .inspect_live_tunnels(|snapshot| {
            snapshot.peer_credential.as_ref().map(|credential| {
                (
                    credential.spiffe_id.to_string(),
                    credential.anchored_at_admission,
                    matches!(credential.leaf_expiry, AdmittedLeafExpiry::At(_)),
                )
            })
        });
    assert_eq!(
        captured,
        vec![Some((CLIENT_SPIFFE.to_string(), true, true))],
        "a certificate-authenticated CONNECT must retain its peer SPIFFE id, a finite leaf \
         deadline, and the anchoring the INBOUND verifier's trust implies"
    );

    echo_round_trip(&mut fx.tunnel, b"still-flowing").await;
    fx.teardown().await;
}

/// The chain-only inbound posture, end to end: no inbound admission trust is
/// installed, so the credential is still captured — the expiry half applies —
/// but the trust half stays inapplicable for the tunnel's whole life.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_connect_with_no_inbound_trust_installed_is_never_anchored() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;

    let captured = fx
        .state
        .hbone_admission_fence
        .inspect_live_tunnels(|snapshot| {
            snapshot
                .peer_credential
                .as_ref()
                .map(|credential| credential.anchored_at_admission)
        });
    assert_eq!(
        captured,
        vec![Some(false)],
        "with no inbound SPIFFE slot installed, peers are verified chain-only against the \
         operator client-CA bundle and must never be judged by the trust gate"
    );

    echo_round_trip(&mut fx.tunnel, b"still-flowing").await;
    fx.teardown().await;
}

/// Scenario B of the independent review, end to end.
///
/// The inbound slot's LOCAL domain is the gateway SVID's own — the peer's — and
/// the slice's differing local domain is filed beside it as federated, which is
/// exactly what `merge_trust_overlay_into_svid_bundle` produces. Reading the
/// request epoch instead would find no bundle for the peer's domain at all,
/// mark the tunnel unanchored, and then never judge it again: withdrawing that
/// domain would revoke nothing, silently, for the tunnel's whole life.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_the_svids_own_trust_domain_revokes_a_real_tunnel() {
    let fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;
    let slot = fx
        .inbound_trust_slot
        .clone()
        .expect("the fixture installed an inbound admission trust slot");
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);

    // The peer's trust domain — the SVID's own local domain — loses its
    // authorities; the slice's domain is untouched.
    publish_inbound_trust(
        &fx.state,
        &slot,
        &gateway,
        local_trust(SLICE_TRUST_DOMAIN, vec![gateway.ca_der.clone()]),
    );

    tokio::time::timeout(DEADLINE, async {
        while fx
            .state
            .hbone_admission_fence
            .revocations(HboneRevocationReason::PeerTrust)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("withdrawing the peer's trust domain must revoke its live tunnel");

    assert_eq!(revocation_counts(&fx.state), [0, 0, 1, 0, 0, 0, 0, 0, 0]);
    fx.teardown().await;
}

/// The pooled-session hole the verification re-review of PR #5573 found.
///
/// An established inbound HBONE mTLS session is NEVER re-handshaked and many
/// CONNECTs multiplex over it, so a peer the fence just revoked simply re-opens
/// a tunnel on the same connection. Seeding the replacement tunnel's
/// last-verified revision from the revision its CONNECT merely READ admitted it
/// under trust that had already refused its chain, and then short-circuited
/// every later sweep for that tunnel's whole life — the fence defeated in its
/// own primary scenario. The CONNECT now re-verifies the retained chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_connect_after_a_trust_withdrawal_is_refused_not_reseeded() {
    let mut fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;
    let slot = fx
        .inbound_trust_slot
        .clone()
        .expect("the fixture installed an inbound admission trust slot");
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let compilations_before = fx.state.hbone_admission_fence.trust_anchor_builds();

    // R2 still declares the peer's trust domain and still compiles; only the
    // root that issued the live peer's leaf is retired. A membership check
    // alone would see nothing.
    let replacement = mint_peer_chain(OTHER_SPIFFE);
    publish_inbound_trust(
        &fx.state,
        &slot,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![replacement.ca_der.clone()]),
    );

    // (i) the live tunnel is revoked for trust...
    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 1, 0, 0, 0, 0, 0, 0],
        "exactly one peer_trust revocation"
    );

    // (ii) ...and the peer's immediate retry, on the SAME never-re-handshaked
    // inbound mTLS connection, is refused at admission rather than admitted and
    // never checked again.
    let refused = open_tunnel(&mut fx.sender).await.err();
    assert_eq!(
        refused,
        Some(StatusCode::FORBIDDEN),
        "a CONNECT whose chain no longer anchors must be refused, not re-admitted"
    );
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 0);
    assert_eq!(fx.state.hbone_admission_fence.connect_trust_refusals(), 1);
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 1, 0, 0, 0, 0, 0, 0],
        "a refused CONNECT is never a revocation"
    );
    assert_eq!(
        fx.state.hbone_admission_fence.trust_anchor_builds(),
        compilations_before + 1,
        "the publication compiles the anchors once; the CONNECT validates a path against \
         them and compiles nothing"
    );

    fx.teardown().await;
}

/// The chain-only inbound posture must be untouched by the CONNECT-time trust
/// gate. With no inbound admission trust installed there is nothing in force to
/// verify against — peers are verified against the operator client-CA bundle,
/// which `tls::client_trust` bounds separately (issue #3857) — so refusing
/// would be an outage rather than a fence.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_only_posture_still_admits_a_pooled_second_connect() {
    let mut fx = admit_client_tunnel(vec![allow_client()]).await;
    let fence = &fx.state.hbone_admission_fence;
    assert!(
        fence.inbound_trust_revision().is_none(),
        "this posture installs no inbound admission trust at all"
    );

    let mut second = open_tunnel(&mut fx.sender)
        .await
        .expect("a chain-only posture admits a second CONNECT on the same connection");
    echo_round_trip(&mut second, b"chain-only").await;

    assert_eq!(fence.live_tunnels(), 2);
    assert_eq!(fence.connect_trust_refusals(), 0);
    assert_eq!(fence.trust_anchor_builds(), 0);
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    fx.teardown().await;
}

/// The credential gate is only as good as the publications that schedule it.
/// Two writers must each store first and sweep second: the inbound admission
/// trust (which decides the trust verdict) and the request-facing gateway trust
/// generation (retained as the defence-in-depth half of the two-publication
/// step). Pinning both in source is what keeps a future publisher from growing
/// its own path and silently leaving live tunnels judged against retired trust.
#[test]
fn every_trust_publisher_stores_before_it_requests_a_sweep() {
    fn body<'a>(source: &'a str, signature: &str, end: &str) -> &'a str {
        let start = source.find(signature).expect("publisher must exist");
        let rest = &source[start..];
        let end = rest.find(end).expect("publisher body must terminate");
        &rest[..end]
    }

    fn assert_store_then_sweep(func: &str, store: &str, sweep: &str, what: &str) {
        let store = func.find(store).unwrap_or_else(|| {
            panic!("{what}: the store is what publishes the material a sweep judges")
        });
        let sweep = func
            .find(sweep)
            .unwrap_or_else(|| panic!("{what}: every publication must schedule a fence sweep"));
        assert!(
            store < sweep,
            "{what}: publish-then-recheck — the sweep must be requested AFTER the store, or a \
             CONNECT that read the superseded state could register between them and never be \
             re-judged"
        );
    }

    let proxy = include_str!("../../src/proxy/mod.rs");
    assert_store_then_sweep(
        body(
            proxy,
            "fn publish_live_gateway_trust(&self) {",
            "\n    /// Whether request paths may authenticate gateway-to-mesh peers",
        ),
        "self.request_epoch.update_gateway_trust(",
        "self.hbone_admission_fence.request_sweep()",
        "publish_live_gateway_trust",
    );

    let fence = include_str!("../../src/proxy/hbone_admission_fence.rs");
    let publish_inbound = body(
        fence,
        "pub fn publish_inbound_admission_trust(",
        "\n    /// Publish the CRL records the mesh inbound SPIFFE verifier enforces",
    );
    assert_store_then_sweep(
        publish_inbound,
        "slot.store(Arc::clone(&bundle));",
        "self.request_sweep()",
        "publish_inbound_admission_trust",
    );
    // The store is the CALLER's slot, never the binding's. They are the same
    // object in the ordinary case, but a rebind the fence refuses keeps the
    // previous binding in force — and publishing this bundle into THAT slot
    // would hand one listener's server identity to another's.
    assert!(
        !publish_inbound.contains("trust.slot.store("),
        "the SVID bundle must be stored into the slot it was published for"
    );

    // A publication that does not take force is the one failure mode an
    // operator cannot see from the outside — the verifier keeps admitting and
    // the fence keeps judging, both against the previous set — so it must reach
    // the sampled operator warning rather than being silently dropped.
    assert!(
        publish_inbound.contains("self.warn_trust_not_in_force("),
        "a publication the fence refuses to put in force must not do so silently"
    );

    // The enforced CRL records are the OTHER input to the same compiled anchors
    // (issue #5574), so their publisher owes the same two guarantees: the
    // records reach the verifier's slot before the sweep that judges live
    // tunnels against them, and a candidate that takes no force says so.
    //
    // That publisher is split in two — the outer function does the lock-free
    // pre-checks and the sweep, the locked half decides what goes in force — so
    // the ordering is pinned ACROSS the split: the locked half stores and the
    // caller sweeps only once it has returned, which is also what keeps the
    // sweep from being requested while the publication lock is held.
    let publish_crls = body(
        fence,
        "pub fn publish_inbound_admission_crls(",
        "\n    /// The locked half of",
    );
    assert_store_then_sweep(
        publish_crls,
        "self.publish_usable_inbound_admission_crls(crls)",
        "self.request_sweep()",
        "publish_inbound_admission_crls",
    );
    assert!(
        publish_crls.contains("self.warn_crls_not_in_force("),
        "an unusable CRL candidate must not take no force silently"
    );
    let publish_crls_locked = body(
        fence,
        "fn publish_usable_inbound_admission_crls(",
        "\n    /// The enforced CRL slot inside the shared inbound admission artifact.",
    );
    assert!(
        publish_crls_locked.contains("publish_enforced_crl_set(slot, crls)"),
        "the locked half is what stores the records into the verifier's slot"
    );
    assert!(
        !publish_crls_locked.contains("self.request_sweep()"),
        "and it must never sweep while it holds the publication lock"
    );

    // All three publishers take the ONE fence-owned lock, and the install is
    // inside it: production arms the backend CRL watcher before mesh installs
    // the inbound slot, so an installer that overtakes a publisher's
    // no-trust-installed check is a startup interleaving rather than a misuse.
    for publisher in [
        "pub fn install_inbound_admission_trust(&self, slot: &crate::tls::SharedBundleSlot) {",
        "pub fn publish_inbound_admission_trust(",
        "fn publish_usable_inbound_admission_crls(",
    ] {
        // Delimited by the next doc comment rather than a byte budget: the
        // source is full of multi-byte punctuation and a fixed-width slice can
        // land mid-character.
        let taken = body(fence, publisher, "\n    /// ");
        assert!(
            taken.contains("self.publication_lock()"),
            "{publisher} must serialize on the fence's own publication lock"
        );
    }
    assert_eq!(
        fence.matches("publish_lock: std::sync::Mutex<()>").count(),
        1,
        "exactly ONE lock, owned by the fence itself — a per-installed-trust lock cannot \
         cover the install that creates it"
    );

    // A REBIND can never leave the shared artifact with nothing in force while
    // the fence has anchors (issue #5574 verification re-review). Installing a
    // different slot does not reach an inbound verifier that already exists —
    // that verifier keeps reading the slot it was built with — so clearing the
    // artifact would drop the handshake onto its own compile of the OLD slot
    // while the fence lost its anchors entirely and every arriving CONNECT took
    // the unanchored path.
    //
    // Pinned structurally rather than behaviourally: the artifact cell takes
    // the anchors themselves, so "clear it" is not expressible at all.
    let spiffe = include_str!("../../src/tls/spiffe.rs");
    assert_eq!(
        spiffe
            .matches("pub(crate) fn put_in_force(&self, anchors: Arc<AdmittedPeerTrustAnchors>)")
            .count(),
        1,
        "the in-force cell must take the anchors themselves; an `Option` parameter is what \
         makes clearing it — and stranding both surfaces — representable"
    );
    assert_eq!(
        fence.matches("put_in_force(None)").count(),
        0,
        "nothing may clear the anchors in force"
    );
    // ...and the installer takes the same last-known-good posture a rejected
    // trust or CRL candidate takes, rather than binding a slot that compiles
    // nothing over one that does.
    let install_locked = body(
        fence,
        "fn install_inbound_admission_trust_locked(",
        "\n    /// The one publication lock,",
    );
    assert!(
        install_locked.contains("bound.filter(|installed| installed.has_anchors_in_force())"),
        "a rebind must ask whether anchors are already in force before replacing the binding"
    );
    assert!(
        install_locked.contains("self.warn_rebind_not_in_force(trust_domain_class);"),
        "a refused rebind must not be silent"
    );

    // And `ProxyState` must route through it rather than storing the slot.
    let publish_state_crls = body(
        proxy,
        "pub fn publish_mesh_inbound_crls(&self, crls: crate::tls::CrlList) -> bool {",
        "\n    /// Republish only the captured-listener-port",
    );
    assert!(
        publish_state_crls.contains(".publish_inbound_admission_crls("),
        "the enforced mesh inbound CRL slot must be published through the fence's one \
         publisher, which recompiles the anchors it is an input to"
    );
    assert!(
        !publish_state_crls.contains(".store("),
        "a direct store leaves the verifier and the fence's cached anchors policing \
         different records"
    );

    // And the mesh writers must reach that publisher rather than storing into
    // the verifier's slot themselves. Every `.store(` inside each publisher's
    // own body is enumerated, because the two writers bind the inbound slot
    // under DIFFERENT names (`inbound_slot` and, in `publish_staged_spiffe_
    // bundle`'s `DirectSlot` arm, plain `slot`): pinning one variable name
    // leaves the other free to regress, and only the sibling call-count
    // assertion would notice — and only because the call disappeared.
    let mesh = include_str!("../../src/modes/mesh/mod.rs");
    for (what, publisher, permitted_stores) in [
        (
            "publish_runtime_svid_to_inbound_slot",
            body(
                mesh,
                "fn publish_runtime_svid_to_inbound_slot(",
                "\nfn start_mesh_inbound_svid_rotation_republisher(",
            ),
            &[][..],
        ),
        (
            "publish_staged_spiffe_bundle",
            body(
                mesh,
                "fn publish_staged_spiffe_bundle(",
                "\n/// Stage the exact effective mesh/federation gateway trust decision",
            ),
            // The accepted trust OVERLAY is a different slot with no fence
            // binding; publishing it is this writer's own job.
            &["trust_overlay_slot.store(Arc::new(trust_overlay));"][..],
        ),
    ] {
        assert_eq!(
            publisher.matches(".store(").count(),
            permitted_stores.len(),
            "{what}: the mesh inbound SPIFFE slot must be published through \
             ProxyState::publish_mesh_inbound_trust_bundle, never stored into directly"
        );
        for permitted in permitted_stores {
            assert!(
                publisher.contains(permitted),
                "{what}: expected store `{permitted}` is gone; re-derive what this publisher \
                 is allowed to write before relaxing the count above"
            );
        }
        assert!(
            publisher.contains("publish_mesh_inbound_trust_bundle(")
                || publisher.contains("publish_runtime_svid_to_inbound_slot("),
            "{what}: every inbound-slot publisher must reach the one writer"
        );
    }
    assert_eq!(
        mesh.matches("publish_mesh_inbound_trust_bundle(").count(),
        2,
        "exactly the two inbound-slot writers — the runtime SVID republisher and the staged \
         slice publisher — may publish inbound trust"
    );
}

// ---------------------------------------------------------------------------
// Issue #5042 step 2: the fence's CAPABILITY ADVERTISEMENT, and issue #5583:
// the PLUGIN CLASSIFICATION that qualifies it.
//
// Source-side reuse of the application connection inside a tunnel is
// admissible only because a later policy or credential generation can still
// reach that tunnel and cut it. The destination therefore SAYS so, on the
// CONNECT `200`, and only while the fence really holds the tunnel.
//
// The fence re-issues two things and no more: the local authorize verdict, on
// every publication, and the peer's mTLS credential. Reuse elides CONNECTs
// whose request attributes would have been IDENTICAL, so the ONLY thing those
// elided runs could have decided differently is time-varying state — and any
// plugin whose time-varying state the fence does not re-issue must force a
// fresh CONNECT per operation. `Plugin::allows_hbone_inner_reuse` is that
// classification, fail-closed by default; these tests pin it end to end over a
// real mTLS CONNECT. The static table of who classifies what lives in
// `tests/unit/gateway_core/hbone_inner_reuse_classification_tests.rs`, and the
// source-side half — what a peer does with the header — in
// `hbone_inner_pool_tests.rs`.
// ---------------------------------------------------------------------------

/// The advertised value, read off the CONNECT response head.
fn tunnel_reuse_advertisement(response: &hyper::Response<h2::RecvStream>) -> Option<String> {
    response
        .headers()
        .get(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// The ordinary mesh inbound chain is reusable end to end.
///
/// `prepare_gateway_config_for_mesh` injects `spiffe_identity`, `mesh_authz`,
/// `workload_metrics`, and the `stdout_logging` access log, so this is not a
/// one-plugin assertion: EVERY member of the production chain must classify
/// itself reusable for the header to appear at all. Demoting any one of them —
/// or adding a fifth injected plugin without classifying it — turns this
/// advertisement off, which is the fail-closed direction and exactly what this
/// test is here to notice.
#[tokio::test(flavor = "multi_thread")]
async fn an_admitted_connect_advertises_the_fence_capability_on_its_200() {
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

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response).as_deref(),
        Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
        "an admitted tunnel the fence holds must advertise that the receiver \
         re-evaluates it, so the source may reuse the application connection"
    );
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        1,
        "the advertisement must describe a tunnel that is actually registered"
    );
    // The advertisement is a capability flag, never an authorization: the
    // admission counters are untouched by it.
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// A rate limit is a per-operation CHARGE, so it must not be spent once and
/// then honoured for an unbounded number of operations.
///
/// The tunnel is still admitted and still fenced — the classification governs
/// the CAPABILITY, never the admission — so the only observable difference is
/// the absent header, and with it one CONNECT (and one charge) per operation.
#[tokio::test(flavor = "multi_thread")]
async fn a_connect_with_per_request_rate_limiting_does_not_advertise_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
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

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "a chain that charges a token per operation must force one CONNECT per operation"
    );
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        1,
        "the classification withholds the capability, it does not refuse the tunnel"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// `mesh_authz` with an external authorization provider bound is not reusable,
/// because a sweep deliberately never re-consults that provider: the
/// admission-time verdict stands for the tunnel's whole life
/// (`MESH_AUTHZ_REEVALUATION_METADATA_KEY`). Reuse would therefore buy one
/// external `allow` and honour it indefinitely.
///
/// The CUSTOM rule here matches a principal this client never presents, so the
/// CONNECT is decided purely by the local ALLOW tier and no check is ever
/// issued. The refusal must hold anyway — it is a property of the GENERATION,
/// not of which rules one CONNECT happened to match.
#[tokio::test(flavor = "multi_thread")]
async fn a_connect_whose_mesh_authz_binds_an_external_authorizer_does_not_advertise_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let mesh = MeshConfig {
        mesh_policies: vec![allow_client(), custom_policy_for_other_principal()],
        ext_authz_providers: vec![ext_authz_provider()],
        ..MeshConfig::default()
    };
    let state = build_state(prepared_config_from_mesh(
        Some(backend_addr.port()),
        None,
        mesh,
        Vec::new(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the local ALLOW tier still admits this CONNECT; only the capability is withheld"
    );
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "a generation whose mesh_authz can delegate externally must force a fresh CONNECT, and \
         a fresh external verdict, per operation"
    );
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// An UNCLASSIFIED plugin in the admitting chain withholds the capability, even
/// when it takes no authorization decision at all.
///
/// `correlation_id` only stamps a header and never rejects, but nobody has
/// declared it reuse-safe, so the literal `false` default refuses it — and one
/// refusal anywhere in the chain is the whole chain's answer. That is the
/// intended direction: a new built-in, or any custom plugin, must be looked at
/// before it can ride a reused tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn a_connect_whose_chain_carries_an_unclassified_plugin_does_not_advertise_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![unclassified_plugin()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "an unclassified plugin must fail closed, whatever it actually does"
    );
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// `access_control` IS classified reusable — its verdict is a pure function of
/// the request's identity inputs and immutable allow/deny sets, and every
/// published generation requests a sweep that re-runs exactly that hook
/// (`reevaluates_live_admission`). The classification is pinned statically in
/// `hbone_inner_reuse_classification_tests.rs`.
///
/// It cannot be pinned end to end in the ADVERTISING direction, and this test
/// records why rather than leaving a silent gap: an HBONE CONNECT carries no
/// mapped gateway Consumer and no `authenticated_identity` — `spiffe_identity`
/// admits a certificate PRINCIPAL, which is a different field — so
/// `access_control` refuses every such CONNECT before a tunnel can exist. Its
/// reuse classification is therefore unreachable on this path today, and the
/// refusal below is what would have to change first.
#[tokio::test(flavor = "multi_thread")]
async fn an_access_control_chain_refuses_the_connect_it_would_have_let_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![access_control_plugin()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the no-consumer arm of `AccessControl::authorize_identity` is what refuses this CONNECT, \
         and it rejects `401`: `allow_authenticated_identity` needs an `authenticated_identity`, \
         and `spiffe_identity` publishes a certificate PRINCIPAL (`peer_spiffe_id`) instead, so \
         neither the Consumer nor the external-identity arm is reached"
    );
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "a refused CONNECT advertises nothing"
    );
    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        0,
        "no tunnel was admitted, so none can be reused"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// The datagram CONNECT path never advertises reuse, whatever its admitting
/// chain classified.
///
/// A datagram tunnel unframes into a local `UdpSocket` and carries no inner
/// request/response exchange the source could pool, so the capability does not
/// exist on that surface at all.
///
/// The distinction matters, and this fixture is what makes it observable: the
/// egress-UDP gateway carries no plugin that refuses reuse — its only
/// configured global is `spiffe_identity`, which IS classified reusable — so
/// the classification would have said yes here. The absent header is therefore
/// the SURFACE refusing unconditionally, not a plugin declining, which is
/// exactly the property that must survive someone later "fixing" the datagram
/// path to consult its chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_connect_never_advertises_reuse() {
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
    let response = tokio::time::timeout(DEADLINE, response_fut)
        .await
        .expect("udp CONNECT response within deadline")
        .expect("udp CONNECT response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "a datagram tunnel has no inner application connection to keep"
    );
    let mut response_body = response.into_body();

    // The tunnel is genuinely live and fenced — the absent header is the
    // surface having no such capability, not a failed admission.
    request_body
        .send_data(frame_datagram(b"ping"), false)
        .expect("send framed datagram");
    let echoed = tokio::time::timeout(DEADLINE, read_framed_datagram(&mut response_body))
        .await
        .expect("external udp reply");
    assert_eq!(echoed, b"pong:ping".to_vec());
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);

    let _ = shutdown_tx.send(true);
    external_handle.abort();
    conn_task.abort();
}

// ---------------------------------------------------------------------------
// Issue #5583, second half: the advertisement is an OBLIGATION, not a one-time
// statement.
//
// A tunnel admitted with the capability advertised keeps carrying application
// operations its source will not re-CONNECT for. So a chain that stops
// permitting reuse — a CUSTOM `mesh_authz` policy is published, `rate_limiting`
// is attached, an unclassified plugin appears — would never see them: the sweep
// re-issues opted-in `authorize` verdicts and the peer credential, and NOTHING
// else. Every sweep therefore re-folds the classification over the CURRENT
// chain and revokes `reuse_withdrawn`, which is what restores per-operation
// admission: the source's next operation performs a fresh CONNECT under the new
// chain and is charged, mirrored, or externally authorized exactly as it asks.
//
// These run through the production dispatcher over real mTLS, like the
// advertisement tests above. The static side — who classifies what, and that the
// default is a literal `false` no other marker can move — is in
// `tests/unit/gateway_core/hbone_inner_reuse_classification_tests.rs`.
// ---------------------------------------------------------------------------

/// One admitted byte-stream tunnel over a REAL inbound mTLS CONNECT, with the
/// response head's reuse advertisement recorded.
///
/// [`admit_client_tunnel`] cannot serve these tests: it discards the response
/// head, and the advertisement on it is the whole premise here — a tunnel that
/// never advertised took on no obligation, which is itself one of the cases
/// below.
struct ReuseFixture {
    state: ProxyState,
    tunnel: Tunnel,
    sender: h2::client::SendRequest<Bytes>,
    conn_task: tokio::task::JoinHandle<Result<(), h2::Error>>,
    backend_handle: tokio::task::JoinHandle<()>,
    backend_port: u16,
    shutdown_tx: watch::Sender<bool>,
    /// Whether the admitted CONNECT's `200` carried the capability.
    advertised: bool,
}

impl ReuseFixture {
    async fn teardown(self) {
        let _ = self.shutdown_tx.send(true);
        self.backend_handle.abort();
        self.conn_task.abort();
    }
}

async fn admit_tunnel_with_plugins(plugin_configs: Vec<PluginConfig>) -> ReuseFixture {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        plugin_configs,
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the reuse classification governs the CAPABILITY, never the admission"
    );
    let fenced = Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED);
    let advertised = tunnel_reuse_advertisement(&response).as_deref() == fenced;
    let mut tunnel = Tunnel {
        request_body,
        response_body: response.into_body(),
    };
    echo_round_trip(&mut tunnel, b"before-publish").await;
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);

    ReuseFixture {
        state,
        tunnel,
        sender,
        conn_task,
        backend_handle,
        backend_port: backend_addr.port(),
        shutdown_tx,
        advertised,
    }
}

/// The generation that binds an external authorization executor: the same mesh
/// shape `a_connect_whose_mesh_authz_binds_an_external_authorizer_does_not_advertise_reuse`
/// admits a CONNECT under, so the CONNECT itself is unaffected and only the
/// capability moves.
fn custom_delegating_mesh() -> MeshConfig {
    MeshConfig {
        mesh_policies: vec![allow_client(), custom_policy_for_other_principal()],
        ext_authz_providers: vec![ext_authz_provider()],
        ..MeshConfig::default()
    }
}

/// Publishing a `CUSTOM` `mesh_authz` policy revokes a tunnel that was already
/// advertised reusable.
///
/// A sweep deliberately never re-consults an external authorizer
/// (`MESH_AUTHZ_REEVALUATION_METADATA_KEY`), so without this gate the source
/// would keep eliding CONNECTs the destination now wants an external verdict
/// for — one `allow` bought at admission and honoured indefinitely. The tunnel's
/// own CONNECT is still admitted by the local ALLOW tier, which is exactly why
/// the reason has to be its own: nothing was refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_published_custom_authorization_policy_withdraws_reuse_from_a_live_tunnel() {
    let mut fx = admit_tunnel_with_plugins(Vec::new()).await;
    assert!(
        fx.advertised,
        "the ordinary mesh inbound chain must be reusable, or this test proves nothing"
    );

    let outcome = fx.state.update_config(prepared_config_from_mesh(
        Some(fx.backend_port),
        None,
        custom_delegating_mesh(),
        Vec::new(),
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 0, 0, 0, 0, 1, 0],
        "exactly one reuse_withdrawn revocation, and no authorization_denied one: the local \
         ALLOW tier still admits this principal, so nothing about the tunnel was REFUSED"
    );

    // The peer re-CONNECTs on the same pooled mTLS connection, which is what the
    // revocation exists to provoke. It is admitted — and it is that fresh
    // CONNECT, not a reused tunnel, that a CUSTOM policy can now decide.
    let (response, _request_body) = send_connect(&mut fx.sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "and the replacement tunnel must not be granted the capability that was just withdrawn"
    );

    fx.teardown().await;
}

/// Attaching a plugin that CHARGES an operation revokes a tunnel that was
/// already advertised reusable.
///
/// `rate_limiting` consumes a token per operation. Left alone, the tunnel
/// admitted before the publication would carry an unbounded number of
/// operations against the single token its CONNECT paid — the budget bypass the
/// classification exists to prevent, arrived at by a routine config apply
/// instead of by a CONNECT.
#[tokio::test(flavor = "multi_thread")]
async fn attaching_a_per_operation_charge_withdraws_reuse_from_a_live_tunnel() {
    let mut fx = admit_tunnel_with_plugins(Vec::new()).await;
    assert!(fx.advertised);

    // Generous limit: this test is about the CLASSIFICATION, and a budget small
    // enough to refuse the follow-up CONNECT would confuse the two.
    let outcome = fx.state.update_config(prepared_config_with(
        Some(fx.backend_port),
        None,
        vec![allow_client()],
        vec![spiffe_rate_limit_plugin(64)],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 0, 0, 0, 0, 1, 0],
        "exactly one reuse_withdrawn revocation; the sweep must not have RE-RUN the limiter, \
         which would have charged a real client's budget per live tunnel"
    );

    let (response, _request_body) = send_connect(&mut fx.sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the replacement CONNECT is inside the budget and is charged one token, which is the \
         per-operation admission the withdrawal restored"
    );
    assert_eq!(tunnel_reuse_advertisement(&response), None);

    fx.teardown().await;
}

/// The SAME publication leaves a tunnel that never advertised alone.
///
/// Such a tunnel already performs one full destination admission per operation,
/// so there is nothing for the newly attached policy to miss and cutting it
/// would be a gratuitous connection reset on every config apply.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_that_never_advertised_survives_the_same_withdrawal_publication() {
    let mut fx = admit_tunnel_with_plugins(vec![unclassified_plugin()]).await;
    assert!(
        !fx.advertised,
        "an unclassified plugin in the chain must have withheld the capability at admission"
    );

    let outcome = fx.state.update_config(prepared_config_from_mesh(
        Some(fx.backend_port),
        None,
        custom_delegating_mesh(),
        vec![unclassified_plugin()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&fx.state).await;

    assert_eq!(
        fx.state.hbone_admission_fence.live_tunnels(),
        1,
        "a tunnel that was never granted the capability cannot lose it"
    );
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // Still carrying bytes, not merely still registered.
    echo_round_trip(&mut fx.tunnel, b"after-publish").await;

    fx.teardown().await;
}

/// A chain that BECOMES reusable does not disturb live tunnels either.
///
/// The gate is one-directional by construction: it judges only tunnels whose
/// snapshot recorded the advertisement. A tunnel admitted without it keeps
/// doing what it was admitted to do — one CONNECT per operation — and only the
/// NEXT CONNECT is granted the capability.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_that_becomes_reusable_leaves_live_tunnels_untouched() {
    let mut fx = admit_tunnel_with_plugins(vec![unclassified_plugin()]).await;
    assert!(!fx.advertised);

    // The unclassified plugin is withdrawn: the chain is now the ordinary
    // reusable mesh inbound one.
    let outcome = fx.state.update_config(prepared_config_with(
        Some(fx.backend_port),
        None,
        vec![allow_client()],
        Vec::new(),
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&fx.state).await;

    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 1);
    assert_eq!(revocation_counts(&fx.state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    echo_round_trip(&mut fx.tunnel, b"after-publish").await;

    let (response, _request_body) = send_connect(&mut fx.sender, None).await;
    assert_eq!(
        tunnel_reuse_advertisement(&response).as_deref(),
        Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
        "the capability follows the chain, so the next CONNECT does get it"
    );

    fx.teardown().await;
}

/// The outbound capture listener port the REGISTRY_ONLY fixture below gives its
/// mesh runtime.
///
/// Nothing in this suite BINDS it: the only listener these tests open is the
/// inbound gateway, on a registry-allocated ephemeral port. The number exists
/// so `MeshRuntimeConfig::listener_plan()` yields one nonzero
/// OUTBOUND-direction entry, which is what `inject_mesh_global_plugins` stamps
/// onto the injected gate as `outbound_listen_ports`. With
/// `fence_mesh_runtime`'s `127.0.0.1:0` that set is empty and injection
/// removes the plugin outright, so a REGISTRY_ONLY fixture built on it would
/// prove nothing at all.
const REGISTRY_ONLY_OUTBOUND_CAPTURE_PORT: u16 = 15001;

fn registry_only_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        outbound_listen_addr: SocketAddr::from((
            IpAddr::from([127, 0, 0, 1]),
            REGISTRY_ONLY_OUTBOUND_CAPTURE_PORT,
        )),
        ..fence_mesh_runtime()
    }
}

/// `outboundTrafficPolicy: REGISTRY_ONLY` over an EMPTY slice, so the derived
/// known-destinations registry admits NOTHING.
///
/// That is deliberate and is what makes the test below a real pin: if the
/// injected gate ever decided on the inbound HBONE listener, this CONNECT would
/// be REJECTED outright rather than merely losing its capability.
fn registry_only_mesh() -> MeshConfig {
    MeshConfig {
        mesh_policies: vec![allow_client()],
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        ..MeshConfig::default()
    }
}

/// Prove the fixture installs what it claims before anything is asserted
/// through it.
fn assert_registry_only_gate_is_injected(config: &GatewayConfig) {
    let row = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_outbound_registry")
        .expect("REGISTRY_ONLY must inject the outbound registry gate");
    assert!(row.enabled, "the injected gate must be enabled");
    assert_eq!(
        row.scope,
        PluginScope::Global,
        "the gate is a GLOBAL row, which is exactly why it enters the inbound chain"
    );
    assert_eq!(
        row.config["outbound_listen_ports"],
        json!([REGISTRY_ONLY_OUTBOUND_CAPTURE_PORT]),
        "the injected gate must be scoped to the OUTBOUND capture port; an unscoped instance \
         keeps the fail-closed reuse classification because it enforces on non-mesh listeners"
    );
    assert_eq!(
        row.config["registry"],
        json!([]),
        "an empty registry is what makes an inbound enforcement regression loud: it admits no \
         destination at all"
    );
}

/// `REGISTRY_ONLY` must neither withhold inbound reuse nor revoke the tunnels
/// that already have it.
///
/// The Global registry row enters the inbound admitting chain, but its first
/// hook statement skips the Inbound direction before any registry lookup.
/// A blanket `false` would withhold reuse and revoke live advertised tunnels
/// even on disjoint ports. Both halves run through the production dispatcher:
/// the live tunnel survives publication carrying bytes, and a fresh CONNECT is
/// admitted AND advertised. The next test covers a colliding numeric scope.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_only_publication_neither_revokes_nor_withholds_inbound_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;

    // ALLOW_ANY start, on the SAME runtime the publication uses, so the only
    // delta between the two generations is the outbound traffic policy.
    let state = build_state(prepared_config_from_mesh_with_runtime(
        Some(backend_addr.port()),
        None,
        MeshConfig {
            mesh_policies: vec![allow_client()],
            ..MeshConfig::default()
        },
        Vec::new(),
        registry_only_runtime(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    assert_ne!(gateway_addr.port(), REGISTRY_ONLY_OUTBOUND_CAPTURE_PORT);
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response).as_deref(),
        Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
        "the ALLOW_ANY chain is the ordinary reusable one, or this test proves nothing"
    );
    let mut tunnel = Tunnel {
        request_body,
        response_body: response.into_body(),
    };
    echo_round_trip(&mut tunnel, b"before-registry-only").await;

    let registry_only = prepared_config_from_mesh_with_runtime(
        Some(backend_addr.port()),
        None,
        registry_only_mesh(),
        Vec::new(),
        registry_only_runtime(),
    );
    assert_registry_only_gate_is_injected(&registry_only);
    assert_eq!(
        state.update_config(registry_only),
        ConfigApplyOutcome::Applied
    );

    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        state.hbone_admission_fence.live_tunnels(),
        1,
        "arming REGISTRY_ONLY must not revoke an inbound tunnel: the gate it installs answers \
         `Continue` on the listener that terminated this CONNECT"
    );
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
        "no reuse_withdrawn, and no refusal either"
    );
    // Still carrying bytes, not merely still registered.
    echo_round_trip(&mut tunnel, b"after-registry-only").await;

    // And the capability survives into the new generation. The empty registry
    // would refuse every destination if this gate decided inbound at all, so a
    // 200 here is itself the proof that it did not.
    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an outbound egress policy must not refuse an inbound CONNECT"
    );
    assert_eq!(
        tunnel_reuse_advertisement(&response).as_deref(),
        Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
        "and it must not cost the new tunnel its capability either"
    );

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// A numeric scope that CONTAINS the actual HBONE listener port must still
/// leave inbound CONNECTs admitted and reusable. No second socket is needed:
/// the production gate sees exactly the colliding scope and stamped direction
/// that same-port binds on distinct addresses used to produce. Startup now
/// rejects that listener plan; this independently proves the request boundary.
#[tokio::test(flavor = "multi_thread")]
async fn a_colliding_registry_scope_skips_inbound_connects_and_advertises_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let mut runtime = registry_only_runtime();
    runtime.outbound_listen_addr.set_port(gateway_addr.port());
    let registry_only = prepared_config_from_mesh_with_runtime(
        Some(backend_addr.port()),
        None,
        registry_only_mesh(),
        Vec::new(),
        runtime,
    );
    let row = registry_only
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_outbound_registry")
        .expect("a nonzero outbound scope must inject the registry");
    assert!(row.enabled);
    assert_eq!(row.scope, PluginScope::Global);
    assert_eq!(
        row.config["outbound_listen_ports"],
        json!([gateway_addr.port()])
    );
    assert_eq!(row.config["registry"], json!([]));

    // Re-publish the same collision as an operator-managed global as well.
    // This proves the boundary does not depend on an auto-injected row id.
    let mut operator_row = row.clone();
    operator_row.id = "operator-colliding-outbound-registry".to_string();
    let operator_config = prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![operator_row],
    );
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;
    for config in [registry_only, operator_config] {
        assert_eq!(state.update_config(config), ConfigApplyOutcome::Applied);
        wait_for_settled_sweeps(&state).await;
        let (response, request_body) = send_connect(&mut sender, None).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an empty registry would reject this CONNECT if the matching port armed enforcement"
        );
        assert_eq!(
            tunnel_reuse_advertisement(&response).as_deref(),
            Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
            "the Inbound direction gate makes a colliding scoped instance reusable"
        );
        let mut tunnel = Tunnel {
            request_body,
            response_body: response.into_body(),
        };
        echo_round_trip(&mut tunnel, b"inbound-with-colliding-registry-port").await;
        assert_eq!(revocation_counts(&state), [0; 9]);
    }

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// An operator registry with a priority override deliberately exercises
/// `PluginInstanceWrapper` as well as the registry's context-aware answer.
fn operator_registry_plugin(port: u16) -> PluginConfig {
    let mut row = unclassified_plugin();
    row.id = "operator-outbound-registry".to_string();
    row.plugin_name = "mesh_outbound_registry".to_string();
    row.config = json!({
        "registry": [CONNECT_AUTHORITY],
        "outbound_listen_ports": [port],
    });
    row.priority_override = Some(ferrum_edge::plugins::priority::MESH_OUTBOUND_REGISTRY);
    row
}

/// NodeWaypoint capture also stamps Outbound and supplies an authenticated
/// principal. This fixture uses mTLS to supply that principal without eBPF or
/// netns setup, then runs the production dispatcher and CONNECT terminator.
/// Only registry membership changes: route and authorization remain identical.
#[tokio::test(flavor = "multi_thread")]
async fn an_outbound_terminated_connect_decided_by_the_registry_never_advertises_reuse() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) = start_gateway_with_direction(
        state.clone(),
        hbone_server_config(&certs),
        MeshTrafficDirection::Outbound,
    )
    .await;
    let mut config = prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![operator_registry_plugin(gateway_addr.port())],
    );
    assert_eq!(
        state.update_config(config.clone()),
        ConfigApplyOutcome::Applied
    );
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "this CONNECT spent a registry verdict that no fence sweep re-issues"
    );
    assert_eq!(
        state
            .hbone_admission_fence
            .inspect_live_tunnels(|snapshot| {
                (
                    snapshot.reuse_context,
                    snapshot.advertised_inner_reuse,
                    snapshot
                        .ctx
                        .peer_spiffe_id
                        .as_ref()
                        .map(ToString::to_string),
                )
            }),
        vec![(
            HboneReuseContext {
                mesh_direction: Some(MeshTrafficDirection::Outbound),
                frontend_listen_port: Some(gateway_addr.port()),
            },
            false,
            Some(CLIENT_SPIFFE.to_string()),
        )]
    );
    let mut tunnel = Tunnel {
        request_body,
        response_body: response.into_body(),
    };
    echo_round_trip(&mut tunnel, b"registered-outbound-connect").await;

    let registry = config
        .plugin_configs
        .iter_mut()
        .find(|row| row.id == "operator-outbound-registry")
        .expect("operator registry");
    registry.config["registry"] = json!([]);
    registry.updated_at += chrono::Duration::seconds(1);
    assert_eq!(state.update_config(config), ConfigApplyOutcome::Applied);
    wait_for_settled_sweeps(&state).await;

    // This unadvertised tunnel may finish its original operation; the source
    // must make a fresh CONNECT for the next one, on the same outer H2 session.
    echo_round_trip(&mut tunnel, b"finish-original-operation").await;
    assert_eq!(revocation_counts(&state), [0; 9]);
    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "withdrawing only the registry entry must refuse the next CONNECT"
    );
    assert_eq!(tunnel_reuse_advertisement(&response), None);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// A scoped instance initially skips this Outbound listener. Expanding its
/// scope must withdraw the capability using the ORIGINAL listener facts,
/// even though sweeps have no live request to obtain those facts from.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_scope_change_refolds_the_recorded_outbound_admission_facts() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![allow_client()],
    ));
    let (gateway_addr, shutdown_tx) = start_gateway_with_direction(
        state.clone(),
        hbone_server_config(&certs),
        MeshTrafficDirection::Outbound,
    )
    .await;
    let other_port = if gateway_addr.port() == 1 { 2 } else { 1 };
    let mut config = prepared_config_with(
        Some(backend_addr.port()),
        None,
        vec![allow_client()],
        vec![operator_registry_plugin(other_port)],
    );
    assert_eq!(
        state.update_config(config.clone()),
        ConfigApplyOutcome::Applied
    );
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;
    let (response, request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        tunnel_reuse_advertisement(&response).as_deref(),
        Some(ferrum_edge::modes::mesh::hbone::TUNNEL_REUSE_FENCED),
        "the nonmatching scope skipped this CONNECT, including through the instance wrapper"
    );
    let mut tunnel = Tunnel {
        request_body,
        response_body: response.into_body(),
    };
    echo_round_trip(&mut tunnel, b"before-outbound-scope-expansion").await;

    let registry = config
        .plugin_configs
        .iter_mut()
        .find(|row| row.id == "operator-outbound-registry")
        .expect("operator registry");
    registry.config["outbound_listen_ports"] = json!([gateway_addr.port()]);
    registry.updated_at += chrono::Duration::seconds(1);
    assert_eq!(state.update_config(config), ConfigApplyOutcome::Applied);
    assert_tunnel_closed(&mut tunnel.response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 1, 0]);

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the destination is still registered, so a fresh per-operation CONNECT is admitted"
    );
    assert_eq!(tunnel_reuse_advertisement(&response), None);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// A CONNECT released simultaneously with the withdrawing publication ends in
/// one of exactly three states, and never in the fourth.
///
/// What this test CAN force: both sides start at the same instant, from a
/// barrier, on a multi-threaded runtime. What it CANNOT force is which one wins
/// — nor should it, because the contract is that no order leaves a reusable
/// tunnel under a chain that no longer permits reuse. So the assertion is on
/// the terminal state, not on the interleaving. Three of them are correct:
///
/// 1. the CONNECT was admitted under the OLD generation and its response read
///    `fence_in_force()` while the tunnel was still held, so it carries the
///    advertisement and the tunnel is revoked `reuse_withdrawn` — this is the
///    ordering publish-then-recheck exists for, since the publication's own
///    sweep may have read the registry before the insert;
/// 2. it was admitted under the NEW generation, never recorded the
///    advertisement, and is left alone;
/// 3. it recorded OLD-generation eligibility and the sweep the publication
///    requested revoked the tunnel BEFORE the response read `fence_in_force()`
///    — so the header is ABSENT even though the tunnel had it. The result is
///    unadvertised, revoked `reuse_withdrawn`, and closed, which is correct
///    twice over.
///
/// (3) is why the header alone cannot stand in for the admitting generation:
/// absent means "not advertised", never "admitted under the new chain". The
/// safety statement is therefore taken from the SURVIVING snapshots plus the
/// revocation and closure evidence — nothing still live may hold the capability
/// the new chain withdrew, and anything that lost it lost it to
/// `reuse_withdrawn` rather than to a refusal.
///
/// The fourth state — a live tunnel whose snapshot recorded the advertisement —
/// is the failure. A run that always took the same branch would still be a
/// correct run of this test, and the sibling tests above pin the deterministic
/// branches; this one exists for the window between them.
#[tokio::test(flavor = "multi_thread")]
async fn a_connect_racing_the_withdrawing_publication_is_never_left_reusable() {
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

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let connect_barrier = Arc::clone(&barrier);
    let connecting = tokio::spawn(async move {
        connect_barrier.wait().await;
        let (response, request_body) = send_connect(&mut sender, None).await;
        let status = response.status();
        let advertised = tunnel_reuse_advertisement(&response).is_some();
        (status, advertised, request_body, response.into_body())
    });

    // Built BEFORE the barrier: mesh preparation is not cheap, and doing it
    // after the release would hand the CONNECT a head start this test has no
    // business granting it.
    let withdrawing = prepared_config_from_mesh(
        Some(backend_addr.port()),
        None,
        custom_delegating_mesh(),
        Vec::new(),
    );
    let publishing_state = state.clone();
    let publishing = tokio::spawn(async move {
        barrier.wait().await;
        publishing_state.update_config(withdrawing)
    });

    let (status, advertised, _request_body, mut response_body) =
        connecting.await.expect("the CONNECT task must not panic");
    let outcome = publishing
        .await
        .expect("the publication task must not panic");
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert_eq!(
        status,
        StatusCode::OK,
        "neither ordering refuses this principal; only the capability is at stake"
    );

    wait_for_settled_sweeps(&state).await;

    // The safety statement, taken from the terminal state rather than from the
    // interleaving: nothing STILL LIVE may hold the capability the published
    // chain withdrew. This is the one assertion that holds in all three correct
    // orderings, including the one where the sweep beat the response to
    // `fence_in_force()` and the header is absent on a tunnel that had it.
    let surviving: Vec<bool> = state
        .hbone_admission_fence
        .inspect_live_tunnels(|snapshot| snapshot.advertised_inner_reuse);
    assert!(
        !surviving.contains(&true),
        "a live tunnel still carrying inner-reuse eligibility under a chain that no longer \
         permits it is exactly the state this gate exists to prevent (surviving snapshots: \
         {surviving:?})"
    );

    // Whatever was revoked was revoked for losing the CAPABILITY. Neither
    // ordering refuses this principal, so any other reason would be a real
    // regression hiding behind the race.
    let counts = revocation_counts(&state);
    let reasons = HboneRevocationReason::ALL;
    for (reason, count) in reasons.into_iter().zip(counts) {
        if reason != HboneRevocationReason::ReuseWithdrawn {
            assert_eq!(
                count,
                0,
                "nothing may be revoked for `{}` in either ordering",
                reason.as_str()
            );
        }
    }

    let reuse_withdrawn = counts[HboneRevocationReason::ReuseWithdrawn.index()];
    if advertised {
        // The response SAW the fence holding the tunnel, so the tunnel had the
        // capability and must have lost it. `admit()`'s own sweep-epoch recheck
        // is what closes the window when the publication's sweep read the
        // registry before the insert.
        assert_eq!(
            reuse_withdrawn, 1,
            "a tunnel whose 200 advertised reuse across a withdrawing publication must be \
             revoked by the sweep that publication requested"
        );
        assert_tunnel_closed(&mut response_body).await;
        wait_for_no_live_tunnels(&state).await;
    } else if reuse_withdrawn == 1 {
        // State (3): eligibility was recorded, then revoked before the response
        // read `fence_in_force()`. Unadvertised AND cut — safe twice over.
        assert_tunnel_closed(&mut response_body).await;
        wait_for_no_live_tunnels(&state).await;
    } else {
        // State (2): admitted under the new generation, so there was never
        // anything to withdraw and nothing to cut.
        assert_eq!(
            reuse_withdrawn, 0,
            "a tunnel that never recorded the advertisement cannot lose it"
        );
        assert_eq!(
            state.hbone_admission_fence.live_tunnels(),
            1,
            "and it must not be cut for anything else either"
        );
    }

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_connect_never_advertises_the_fence_capability() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let (backend_addr, backend_handle) = start_interactive_echo_backend().await;
    // DENY for the connecting principal: the CONNECT is refused at admission,
    // so no tunnel is ever registered and nothing may be advertised.
    let state = build_state(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response, _request_body) = send_connect(&mut sender, None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        tunnel_reuse_advertisement(&response),
        None,
        "a refusal must carry no capability: there is no tunnel for a later \
         generation to reach, so there is nothing a source may reuse"
    );
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 0);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_capability_is_not_advertised_once_the_fence_has_revoked_the_tunnel() {
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

    let (admitted, _first_body) = send_connect(&mut sender, None).await;
    assert_eq!(admitted.status(), StatusCode::OK);
    assert!(tunnel_reuse_advertisement(&admitted).is_some());

    // Tighten: the live tunnel is revoked and the same principal's next CONNECT
    // is refused. The refusal carries no advertisement, which is exactly what
    // stops a source from re-establishing a reusable lease under a policy that
    // no longer admits it.
    let outcome = state.update_config(prepared_config(
        Some(backend_addr.port()),
        vec![deny_client()],
    ));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    wait_for_no_live_tunnels(&state).await;

    let (refused, _second_body) = send_connect(&mut sender, None).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(tunnel_reuse_advertisement(&refused), None);

    let _ = shutdown_tx.send(true);
    backend_handle.abort();
    conn_task.abort();
}

/// The residual risk the re-review named: nothing proved that production wires
/// the SAME slot into the rustls inbound verifier and into the fence. Those
/// constructors are private to `modes::mesh`, so the chain of custody is pinned
/// in source instead — every link of it, so a new slot binding cannot quietly
/// appear between them.
#[test]
fn the_inbound_spiffe_verifier_and_the_fence_share_one_trust_slot() {
    // Collapse runs of whitespace so an assertion survives rustfmt reflow.
    fn flat(source: &str) -> String {
        source.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // The serving path's ONE inbound SPIFFE slot binding.
    const SLOT_BINDING: &str =
        "let mesh_inbound_spiffe_slot = build_mesh_inbound_spiffe_slot_with_federation(";
    // The install that binds exactly that value to the admission fence.
    const SLOT_INSTALL: &str = "if let Some(slot) = mesh_inbound_spiffe_slot.as_ref() { \
                                proxy_state.install_mesh_inbound_admission_trust(slot); }";
    // That same binding is what the inbound TLS state hands every verifier build.
    const VERIFIER_SLOT: &str = "spiffe_bundle_slot: mesh_inbound_spiffe_slot";
    const VERIFIER_CALL: &str = "mesh_inbound_spiffe_verifier(spiffe_bundle_slot";
    // The shared-artifact builder, not the snapshot one: the mesh inbound
    // listener has to read the enforced set on every handshake AND verify
    // against the anchors the fence put in force (issue #5574), while the
    // snapshot form pins a list for the verifier's lifetime and compiles its
    // own anchors.
    const VERIFIER_BUILD: &str = "tls::build_spiffe_client_cert_verifier_for_inbound_admission(";
    const PINNED_CRL_BUILD: &str = "tls::build_spiffe_client_cert_verifier(";
    // The CA-backend slot origin, and the carry-through that keeps it the SAME
    // `Arc` rather than a second slot the fence never saw.
    const CA_INSTALL: &str = "proxy_state.install_mesh_inbound_admission_trust(&inbound_slot);";
    const CARRY_THROUGH: &str =
        "if let Some(slot) = runtime_svid_slot { return Some(slot.clone()); }";
    const ANY_INSTALL: &str = "install_mesh_inbound_admission_trust(";

    let mesh = flat(include_str!("../../src/modes/mesh/mod.rs"));

    // One slot binding in the serving path, and it is installed on the fence.
    assert_eq!(
        mesh.matches(SLOT_BINDING).count(),
        1,
        "the serving path must derive its inbound SPIFFE slot exactly once"
    );
    assert!(
        mesh.contains(&flat(SLOT_INSTALL)),
        "that binding must be the slot installed on the admission fence"
    );

    // ...and the SAME binding is what every inbound-TLS verifier build reads.
    assert_eq!(
        mesh.matches(VERIFIER_SLOT).count(),
        1,
        "the inbound TLS state's verifier slot must be that same binding"
    );
    assert_eq!(
        mesh.matches(VERIFIER_CALL).count(),
        1,
        "exactly one production site may build the inbound peer verifier"
    );
    assert_eq!(
        mesh.matches(VERIFIER_BUILD).count(),
        1,
        "exactly one production site — `mesh_inbound_spiffe_verifier` — may build it, and the \
         mTLS mode selects `peer_required` rather than forking the call"
    );
    assert_eq!(
        mesh.matches(PINNED_CRL_BUILD).count(),
        0,
        "the mesh inbound verifier must read the SHARED admission artifact; the snapshot form \
         pins a revocation list for the verifier's lifetime and compiles its own anchors, so \
         neither a rotation nor the fence's accepted set can ever reach it"
    );

    // The CA-backend slot reaches that binding as the SAME `Arc`: the builder
    // returns the runtime slot it was handed rather than constructing a second
    // one, and it is installed before the first SVID can be published into it.
    assert!(
        mesh.contains(CA_INSTALL),
        "the CA-backend slot must be installed before its first SVID fetch"
    );
    assert!(
        mesh.contains(CARRY_THROUGH),
        "a runtime SVID slot must be carried through, never rebuilt — a second slot would \
         give the verifier and the fence different trust"
    );
    assert_eq!(
        mesh.matches(ANY_INSTALL).count(),
        2,
        "exactly the two slot origins may bind the fence's inbound admission trust"
    );
}

// ── Revocation dimension: the mesh inbound CRL (issue #5574) ──────────────

/// The gap #5574 closes, end to end over a REAL inbound mTLS handshake. A CRL
/// that revokes an already-admitted peer's leaf must cut the live tunnel — an
/// established mTLS session is never re-handshaked, so nothing else would — and
/// must also refuse that peer's immediate retry on the SAME pooled connection,
/// or a revoked workload simply reconnects and keeps serving.
///
/// No trust material moves here at all: the assertion that the in-force
/// revision advanced by exactly one, driven by the CRL publication alone, is
/// what proves the revocation came from the records rather than from a trust
/// change.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_revoking_the_admitted_leaf_revokes_the_tunnel_and_refuses_the_next_connect() {
    let mut fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;
    // The fixture owns the CA that issued the client SVID this handshake
    // presented, so the CRL it signs is authoritative for that chain. A CRL
    // signed by anything else is ignored by webpki, which would make this test
    // pass for the wrong reason.
    let revoking = fx.certs.signed_crl(&[HBONE_CLIENT_LEAF_SERIAL]);
    let fence = &fx.state.hbone_admission_fence;
    let admitted_revision = inbound_trust_revision(&fx.state);
    let compilations_before = fence.trust_anchor_builds();

    assert!(
        publish_crls(&fx.state, vec![revoking]),
        "records the enforced set did not carry are a real publication"
    );
    assert_eq!(
        inbound_trust_revision(&fx.state),
        admitted_revision + 1,
        "a CRL publication advances the ONE in-force revision, which is the sweep's only \
         skip key — without that the fast path would skip the very tunnel it was published for"
    );
    assert_eq!(
        fence.trust_anchor_builds(),
        compilations_before + 1,
        "the records are attached to the anchors ONCE, at publication"
    );

    // (i) the live tunnel is cut, attributed to revocation rather than to a
    // trust withdrawal...
    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 1, 0, 0, 0, 0, 0],
        "a chain that still anchors but whose leaf the enforced CRL lists is `peer_revoked`"
    );

    // (ii) ...and the peer's immediate retry, on the same never-re-handshaked
    // inbound mTLS connection, is refused at admission.
    let refused = open_tunnel(&mut fx.sender).await.err();
    assert_eq!(
        refused,
        Some(StatusCode::FORBIDDEN),
        "a CONNECT whose chain the enforced CRL revokes must be refused, not re-admitted"
    );
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 0);
    assert_eq!(fx.state.hbone_admission_fence.connect_trust_refusals(), 1);
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 1, 0, 0, 0, 0, 0],
        "a refused CONNECT is never a revocation"
    );
    assert_eq!(
        fx.state.hbone_admission_fence.trust_anchor_builds(),
        compilations_before + 1,
        "the CONNECT validates a path against the cached anchors and compiles nothing"
    );

    fx.teardown().await;
}

/// The other side of the gate: a CRL is not a blanket re-admission event. One
/// that lists a serial no live peer carries leaves every tunnel alone, so an
/// operator publishing an unrelated revocation does not churn the mesh.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_revoking_a_different_serial_revokes_nothing() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9641);

    let _slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, inbound_trust_revision(&state)),
    ));

    let unrelated = signed_crl(&peer, &[UNRELATED_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![unrelated]));
    wait_for_settled_sweeps(&state).await;

    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a CRL that does not list this leaf's serial must not revoke it"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fence.live_tunnels(), 1);
    assert_eq!(
        fence.trust_rechecks(),
        1,
        "the publication costs exactly ONE certificate path build per tunnel, and the \
         verdict is that the peer is still admissible"
    );
}

/// ONE revision covers both halves. Nothing about the trust MATERIAL changes
/// here, so a fast path keyed on trust alone — which is exactly what the fence
/// did before #5574 — would never look at the chain and the revoked peer would
/// keep its tunnel. The revision must advance exactly once, and republishing
/// the identical records must be a complete no-op.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_publication_with_unchanged_trust_material_advances_the_revision_exactly_once() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9642);

    let _slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let admitted_revision = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, admitted_revision),
    ));
    wait_for_settled_sweeps(&state).await;
    let sweeps_before = fence.sweeps_completed();
    let compilations_before = fence.trust_anchor_builds();

    let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking.clone()]));
    assert_eq!(
        inbound_trust_revision(&state),
        admitted_revision + 1,
        "exactly one revision, drawn from the same fence-wide sequence a trust publication \
         draws from"
    );
    assert_eq!(
        fence.trust_anchor_builds(),
        compilations_before + 1,
        "the anchors are recompiled once, with the new records"
    );
    wait_for_revocation(&tunnel).await;
    // The revocation is published from inside the pass; the completed counter
    // advances only when the pass returns. Let it settle before reading it.
    wait_for_sweep_after(&state, sweeps_before).await;

    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerRevoked)
    );
    assert!(
        fence.sweeps_completed() > sweeps_before,
        "the CRL publication must schedule a sweep of its own"
    );

    // Republishing the identical records is not a rotation: no revision bump,
    // no recompilation, and no sweep, so a periodic reload of an unchanged CRL
    // file is free.
    let settled = fence.sweeps_completed();
    let revision = inbound_trust_revision(&state);
    let compilations = fence.trust_anchor_builds();
    assert!(
        !publish_crls(&state, vec![revoking]),
        "byte-identical records are not a new enforced set"
    );
    assert_eq!(inbound_trust_revision(&state), revision);
    assert_eq!(fence.trust_anchor_builds(), compilations);
    wait_for_settled_sweeps(&state).await;
    assert_eq!(
        fence.sweeps_completed(),
        settled,
        "an unchanged republication must schedule no sweep at all"
    );
}

/// All-or-nothing, applied to the records. A candidate the inbound verifier
/// could not use must not become the list the fence judges by: it takes NO
/// force, so the revision does not move, nothing is recompiled, and — the point
/// — no healthy tunnel is revoked as un-judgeable. That is the same rule a
/// trust candidate that does not compile already follows.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_crl_never_takes_force() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9643);

    let _slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let admitted_revision = inbound_trust_revision(&state);
    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, admitted_revision),
    ));
    let compilations_before = fence.trust_anchor_builds();

    // Every class `crl_policy::classify_crl_window` refuses, each reached
    // through the fence's own `usable_crl_records`: not a CRL at all, a
    // `thisUpdate` in the future, a record declaring no `nextUpdate`, and one
    // whose `nextUpdate` has already passed. The same rule
    // `crl_policy::validate_crl_windows` applies everywhere else.
    let now = time::OffsetDateTime::now_utc();
    let garbage = CertificateRevocationListDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    let not_yet_valid = signed_crl_in_window(
        &peer,
        &[PEER_LEAF_SERIAL],
        now + time::Duration::days(1),
        now + time::Duration::days(30),
    );
    let no_next_update = crl_without_next_update(&signed_crl(&peer, &[PEER_LEAF_SERIAL]));
    let expired = signed_crl_in_window(
        &peer,
        &[PEER_LEAF_SERIAL],
        now - time::Duration::days(30),
        now - time::Duration::days(1),
    );
    let usable = signed_crl(&peer, &[UNRELATED_LEAF_SERIAL]);
    // The last candidate is a partially invalid multi-record source: the usable
    // subset must not be published either, or an issuer the operator listed
    // would silently stop being policed.
    let candidates = vec![
        vec![garbage],
        vec![not_yet_valid],
        vec![no_next_update],
        vec![expired.clone()],
        vec![usable, expired],
    ];

    for candidate in candidates {
        assert!(
            !publish_crls(&state, candidate),
            "an unusable candidate publishes nothing"
        );
        assert_eq!(
            state.mesh_inbound_admission.crls().load().crls().len(),
            0,
            "the verifier keeps enforcing the records already published"
        );
        assert_eq!(inbound_trust_revision(&state), admitted_revision);
        assert_eq!(fence.trust_anchor_builds(), compilations_before);
    }

    wait_for_settled_sweeps(&state).await;
    assert_eq!(
        tunnel.revoked_reason(),
        None,
        "a candidate that never took force must not revoke the tunnels it was never \
         judged against"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        fence.trust_rechecks(),
        0,
        "nothing moved, so no tunnel rebuilt a certificate path"
    );
}

/// A CRL rotation must reach the HANDSHAKE too, not only the fence. The
/// inbound SPIFFE verifier reads the enforced slot live and keys its cached
/// per-domain verifiers on the set's generation, so a peer whose leaf a
/// published CRL revokes is refused on its next handshake without rebinding the
/// listener — and a peer the records do not name is still admitted.
#[tokio::test(flavor = "multi_thread")]
async fn a_published_crl_refuses_the_peers_next_handshake() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9645);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    // ONE verifier for the whole test: the listener is never rebound when an
    // operator rotates a CRL, so this is the object that has to notice.
    let verifier = inbound_verifier(&state, &slot);
    assert!(
        handshake_admits(&verifier, &peer),
        "the peer's credential must be admissible before anything revokes it"
    );

    let unrelated = signed_crl(&peer, &[UNRELATED_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![unrelated]));
    assert!(
        handshake_admits(&verifier, &peer),
        "a CRL that does not name this leaf leaves the handshake admitting it"
    );

    let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking]));
    assert!(
        !handshake_admits(&verifier, &peer),
        "the published CRL must refuse the peer's next handshake, or a revoked workload \
         just reconnects — the verifier cache identity has to include the CRL generation"
    );
}

/// The `reason` label is an operator's only attribution, so its order is a
/// contract, not a detail: a tunnel failing several gates carries the one its
/// peer's next CONNECT would actually be refused with.
///
/// The three credential arms follow webpki's own path-building sequence:
/// `notAfter` is validated before any trust anchor is considered, the
/// trust-anchor loop defaults to `UnknownIssuer`, and revocation is consulted
/// only inside the signed-chain check — i.e. only once a candidate anchor has
/// matched. So expiry wins over anchoring, and anchoring wins over revocation.
///
/// `reuse_withdrawn` (issue #5583) is the one reason that is NOT a refusal —
/// that tunnel's CONNECT would still be admitted, only without the reuse
/// capability — so it sits after every gate that is one, and before the
/// fail-closed arm.
#[test]
fn the_revocation_reason_order_is_pinned() {
    // Read out of `ALL` rather than a handwritten copy of it. A copy silently
    // stops describing the enum the moment a reason is inserted — it would keep
    // asserting the order of the variants someone remembered — whereas `ALL` is
    // the array the per-reason counters are indexed into, so pinning THAT pins
    // what the metric actually emits.
    let labels: Vec<&'static str> = HboneRevocationReason::ALL
        .iter()
        .map(|reason| reason.as_str())
        .collect();

    assert_eq!(
        labels,
        vec![
            "proxy_withdrawn",
            "peer_expired",
            "peer_trust",
            "peer_revoked",
            "authorization_denied",
            "peer_auth_transport",
            "relay_destination",
            "reuse_withdrawn",
            "reevaluation_failed",
        ],
        "the closed `reason` set and its gate order are pinned by docs/mesh.md, \
         docs/prometheus_metrics.md, and docs/prometheus_metric_contract.json"
    );

    // `index()` is the counter slot, so it must agree with `ALL`'s order or a
    // revocation would be metered under a neighbouring reason's label.
    for (position, reason) in HboneRevocationReason::ALL.iter().enumerate() {
        assert_eq!(
            reason.index(),
            position,
            "{} must index its own slot in ALL",
            reason.as_str()
        );
    }

    // And the same array sizes the counter fixture: `revocation_counts` returns
    // `[u64; HboneRevocationReason::ALL.len()]`, so a new reason breaks the
    // build rather than slipping in unasserted.
    assert_eq!(
        labels.len(),
        HboneRevocationReason::ALL.len(),
        "every declared reason must render exactly one label"
    );
}

// ── Fixtures for the re-review's coverage gaps (issue #5574) ──────────────

/// A three-level chain: a root CA, an issuing intermediate, and a SPIFFE leaf.
///
/// The shared CRL policy is FULL-CHAIN, so revoking the intermediate has to
/// stop every leaf it signed even though no record names a leaf serial. The
/// two-level [`PeerChain`] above cannot express that case at all.
struct IssuedChain {
    root_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    leaf_der: Vec<u8>,
    /// The ROOT's issuer, retained so a CRL revoking the intermediate is signed
    /// by the authority that issued it.
    root_issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn mint_peer_chain_via_intermediate(spiffe: &str) -> IssuedChain {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, SerialNumber, string::Ia5String,
    };

    let root_key = KeyPair::generate().expect("root key");
    let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params
        .distinguished_name
        .push(DnType::CommonName, format!("{spiffe} root CA"));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("self-signed root");
    let root_der = root_cert.der().to_vec();
    // `Issuer::new` consumes the params + key, so capture the DER first.
    let root_issuer = Issuer::new(root_params, root_key);

    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let mut intermediate_params =
        CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.serial_number = Some(SerialNumber::from(INTERMEDIATE_SERIAL));
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, format!("{spiffe} issuing CA"));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .expect("intermediate");
    let intermediate_der = intermediate_cert.der().to_vec();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.serial_number = Some(SerialNumber::from(INTERMEDIATE_LEAF_SERIAL));
    leaf_params.subject_alt_names.push(SanType::URI(
        Ia5String::try_from(spiffe.to_string()).expect("spiffe uri san"),
    ));
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf_params
        .signed_by(&leaf_key, &intermediate_issuer)
        .expect("leaf");

    IssuedChain {
        root_der,
        intermediate_der,
        leaf_der: leaf.der().to_vec(),
        root_issuer,
    }
}

/// [`handshake_admits`] for a chain that presents an intermediate, so the
/// verifier is asked the same full-chain question the fence's re-check is.
fn handshake_admits_chain(
    verifier: &Arc<dyn rustls::server::danger::ClientCertVerifier>,
    chain: &IssuedChain,
) -> bool {
    use rustls::server::danger::ClientCertVerifier;

    let leaf = rustls::pki_types::CertificateDer::from(chain.leaf_der.clone());
    let intermediates = [rustls::pki_types::CertificateDer::from(
        chain.intermediate_der.clone(),
    )];
    let now = rustls::pki_types::UnixTime::now();
    ClientCertVerifier::verify_client_cert(verifier.as_ref(), &leaf, &intermediates, now).is_ok()
}

/// [`peer_credential`] retaining the intermediate, exactly as the accept path
/// retains `ctx.tls_client_cert_chain_der`.
fn intermediate_peer_credential(
    chain: &IssuedChain,
    admitted_trust_revision: u64,
) -> HbonePeerCredential {
    HbonePeerCredential {
        spiffe_id: SpiffeId::new(CLIENT_SPIFFE).expect("client spiffe id"),
        leaf_der: Arc::new(chain.leaf_der.clone()),
        intermediates_der: Some(Arc::new(vec![chain.intermediate_der.clone()])),
        leaf_expiry: live_expiry(),
        anchored_at_admission: true,
        admitted_trust_revision,
    }
}

/// Whether a peer can still establish a usable mTLS session with the gateway.
///
/// Not just "did `connect` return": under TLS 1.3 the CLIENT finishes its
/// handshake before the server has looked at the client certificate, so a
/// refusal arrives as an alert on the first exchange. The question an operator
/// actually asks is whether the peer got a working session, so this drives a
/// real HTTP/2 handshake and one CONNECT and reports whether a response came
/// back at all. The response STATUS is deliberately not inspected — a `403`
/// from a later gate still means the mTLS session was established.
async fn mtls_session_is_established(
    gateway_addr: SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
) -> bool {
    let Ok(tcp) = tokio::net::TcpStream::connect(gateway_addr).await else {
        return false;
    };
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let server_name = rustls::pki_types::ServerName::IpAddress(
        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
    );
    let Ok(Ok(tls)) = tokio::time::timeout(DEADLINE, connector.connect(server_name, tcp)).await
    else {
        return false;
    };
    let Ok(Ok((mut sender, conn))) =
        tokio::time::timeout(DEADLINE, h2::client::handshake(tls)).await
    else {
        return false;
    };
    let conn_task = tokio::spawn(conn);
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(CONNECT_AUTHORITY)
        .body(())
        .expect("connect request");
    let established = match sender.send_request(request, false) {
        Ok((response_fut, _request_body)) => tokio::time::timeout(DEADLINE, response_fut)
            .await
            .is_ok_and(|response| response.is_ok()),
        Err(_) => false,
    };
    conn_task.abort();
    established
}

// ── DER surgery: the one CRL shape rcgen cannot emit ──────────────────────

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        panic!("test CRL is unexpectedly large");
    }
}

/// Split one DER TLV off the front of `input`, returning `(tag, content, rest)`.
fn read_tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
    assert!(input.len() >= 2, "truncated DER");
    let tag = input[0];
    let first = input[1] as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        assert!(count > 0 && count <= 4, "unsupported DER length form");
        let mut len = 0usize;
        for byte in &input[2..2 + count] {
            len = (len << 8) | *byte as usize;
        }
        (len, 2 + count)
    };
    assert!(input.len() >= header + len, "truncated DER value");
    (tag, &input[header..header + len], &input[header + len..])
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Rebuild `crl` with its `nextUpdate` field DROPPED.
///
/// The one shape rcgen cannot emit, and the shape RFC 5280 §5.1.2.5 forbids a
/// conforming issuer from emitting — which is why the fence has to refuse it
/// rather than let a verifier build fail later with an opaque DER error. Only
/// the second `Time` of `tbsCertList` is removed; every other field and the
/// signature are carried through byte for byte. The signature no longer matches
/// the rewritten body, which is exactly right here: the fence classifies the
/// temporal window before any signer is known.
fn crl_without_next_update(
    crl: &CertificateRevocationListDer<'static>,
) -> CertificateRevocationListDer<'static> {
    let (outer_tag, outer, outer_rest) = read_tlv(crl.as_ref());
    assert_eq!(outer_tag, 0x30, "a CRL is a SEQUENCE");
    assert!(outer_rest.is_empty(), "trailing bytes after the CRL");
    let (tbs_tag, tbs, after_tbs) = read_tlv(outer);
    assert_eq!(tbs_tag, 0x30, "tbsCertList is a SEQUENCE");

    let mut rebuilt: Vec<u8> = Vec::new();
    let mut rest = tbs;
    let mut times_seen = 0;
    while !rest.is_empty() {
        let (tag, _content, next) = read_tlv(rest);
        let element = &rest[..rest.len() - next.len()];
        if tag == 0x17 || tag == 0x18 {
            times_seen += 1;
            if times_seen != 2 {
                rebuilt.extend_from_slice(element);
            }
        } else {
            rebuilt.extend_from_slice(element);
        }
        rest = next;
    }
    assert_eq!(
        times_seen, 2,
        "an rcgen CRL carries exactly thisUpdate and nextUpdate at the top level"
    );

    let mut outer_content = der_wrap(0x30, &rebuilt);
    outer_content.extend_from_slice(after_tbs);
    CertificateRevocationListDer::from(der_wrap(0x30, &outer_content))
}

// ── One accepted artifact, and one publication order (issue #5574 re-review) ──

/// The divergence the independent review found, in the direction that lets a
/// REVOKED peer keep handshaking.
///
/// A trust candidate the fence refuses to put in force is still STORED in the
/// SVID slot — the same slot backs the inbound listener's server identity — so
/// a handshake verifier that compiles its own anchors keeps failing to build
/// from that candidate and keeps returning its own previous set. It therefore
/// never adopts a CRL published afterwards, even though the fence has already
/// compiled that CRL into the anchors it judges live tunnels and arriving
/// CONNECTs with. The fence cut the tunnel and refused the CONNECT while the
/// very next handshake re-admitted the revoked leaf.
///
/// ONE verifier for the whole test, warmed before anything is rejected: a cold
/// verifier fails outright on a rejected candidate, so only a warmed one can
/// show the stale retained set.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_trust_candidate_never_strands_the_handshake_on_stale_records() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9660);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let verifier = inbound_verifier(&state, &slot);
    assert!(
        handshake_admits(&verifier, &peer),
        "the peer must be admissible before anything is rejected or revoked"
    );

    // A federated trust domain declaring only JWT authorities: entirely valid
    // configuration, and a candidate the inbound verifier compiles ATOMICALLY
    // and therefore refuses as a whole.
    let mut jwt_only = std::collections::HashMap::new();
    jwt_only.insert(
        TrustDomain::new(SLICE_TRUST_DOMAIN).expect("slice trust domain"),
        trust_bundle(SLICE_TRUST_DOMAIN, Vec::new()),
    );
    let in_force = inbound_trust_revision(&state);
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        RuntimeTrustBundleSet {
            local: trust_bundle(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
            federated: jwt_only,
        },
    );
    assert_eq!(
        inbound_trust_revision(&state),
        in_force,
        "a candidate the verifier would reject must take no force"
    );
    assert!(
        handshake_admits(&verifier, &peer),
        "and the peer is still admitted, exactly as the last-known-good posture promises"
    );

    // NOW the operator revokes that peer's leaf.
    let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking]));
    assert!(
        !handshake_admits(&verifier, &peer),
        "a CRL published while a trust candidate stands rejected must still reach the \
         handshake; otherwise the fence revokes the tunnel and refuses the CONNECT while the \
         peer's very next handshake re-admits the revoked leaf"
    );

    // ...and the mirror image: withdrawing the revocation must re-admit it, or
    // a rescinded revocation never takes effect on the surface the peer retries
    // against.
    assert!(publish_crls(&state, Vec::new()));
    assert!(
        handshake_admits(&verifier, &peer),
        "removing the records must reach the handshake too"
    );
    assert_eq!(
        state.mesh_inbound_admission.crls().load().crls().len(),
        0,
        "an empty publication is a real publication, not a no-op"
    );
}

/// The rebind half of the same last-known-good rule (issue #5574 verification
/// re-review). Installing a DIFFERENT trust slot whose material does not
/// compile must keep the binding already in force rather than replacing it.
///
/// Installation does not reach an inbound verifier that already exists — that
/// verifier keeps reading the slot it was built with — so clearing the shared
/// anchors would drop the handshake onto its own last-known-good compile of the
/// OLD slot while the fence lost its anchors entirely: arriving CONNECTs would
/// take the unanchored path and every credential admitted that way skips trust
/// reevaluation for the rest of its tunnel's life.
///
/// ONE verifier is built here and reused, exactly as a live listener does, and
/// the peer is the fixture's real client SVID, so the handshake assertions run
/// through the production `verify_client_cert` for the same peer whose tunnel
/// the fence is judging. The discriminator is the CRL: a rebind that had
/// replaced the binding would leave the publisher with no material in force to
/// recompile, so the records would reach the verifier while the revision never
/// moved and the live tunnels were never cut.
#[tokio::test(flavor = "multi_thread")]
async fn a_rebind_to_an_uncompilable_slot_keeps_the_accepted_anchors_in_force() {
    let mut fx = admit_client_tunnel_with_inbound_trust(vec![allow_client()], true).await;
    let slot_a = fx.inbound_trust_slot.clone().expect("fixture inbound slot");
    let verifier = inbound_verifier(&fx.state, &slot_a);
    let peer_leaf = fx.certs.client_leaf_der();
    assert!(
        handshake_admits_leaf(&verifier, &peer_leaf),
        "the peer must be admissible before anything is rebound"
    );

    let accepted_revision = inbound_trust_revision(&fx.state);
    let compilations = fx.state.hbone_admission_fence.trust_anchor_builds();

    // A different slot carrying a federated trust domain that declares only JWT
    // authorities: entirely valid configuration, and a candidate the inbound
    // verifier compiles ATOMICALLY and therefore refuses as a whole.
    let rebind_gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let mut jwt_only = std::collections::HashMap::new();
    jwt_only.insert(
        TrustDomain::new(SLICE_TRUST_DOMAIN).expect("slice trust domain"),
        trust_bundle(SLICE_TRUST_DOMAIN, Vec::new()),
    );
    let slot_b = tls::shared_bundle_slot(Some(inbound_bundle(
        &rebind_gateway,
        RuntimeTrustBundleSet {
            local: trust_bundle(PEER_TRUST_DOMAIN, vec![fx.certs.ca_der()]),
            federated: jwt_only,
        },
    )));
    fx.state.install_mesh_inbound_admission_trust(&slot_b);

    assert_eq!(
        inbound_trust_revision(&fx.state),
        accepted_revision,
        "a rebind that compiles nothing must not advance the in-force revision"
    );
    assert_eq!(
        fx.state.hbone_admission_fence.trust_anchor_builds(),
        compilations,
        "and a refused compile builds no anchors, so the only cost is the failed attempt"
    );
    assert!(
        handshake_admits_leaf(&verifier, &peer_leaf),
        "the handshake must still verify against the anchors that ARE in force"
    );
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 1);

    // The CONNECT gate is still judging against those anchors: a second CONNECT
    // on the same never-re-handshaked session is admitted and relays.
    let mut second = open_tunnel(&mut fx.sender)
        .await
        .expect("a CONNECT judged against the anchors still in force is admitted");
    echo_round_trip(&mut second, b"after-rebind").await;
    assert_eq!(fx.state.hbone_admission_fence.live_tunnels(), 2);
    assert_eq!(fx.state.hbone_admission_fence.connect_trust_refusals(), 0);

    // Now the discriminator. The records are compiled into the material still
    // in force — slot A's. Had the rebind replaced the binding with one that
    // compiles nothing, there would be no material to recompile, no revision to
    // advance, and no tunnel to cut.
    let revoking = fx.certs.signed_crl(&[HBONE_CLIENT_LEAF_SERIAL]);
    assert!(publish_crls(&fx.state, vec![revoking]));
    assert_eq!(
        inbound_trust_revision(&fx.state),
        accepted_revision + 1,
        "the publication recompiles the anchors the refused rebind left in force"
    );
    assert_eq!(
        fx.state.hbone_admission_fence.trust_anchor_builds(),
        compilations + 1
    );
    assert!(
        !handshake_admits_leaf(&verifier, &peer_leaf),
        "and the same records reach the handshake through the anchors in force"
    );
    assert_tunnel_closed(&mut fx.tunnel.response_body).await;
    assert_tunnel_closed(&mut second.response_body).await;
    wait_for_no_live_tunnels(&fx.state).await;
    assert_eq!(
        revocation_counts(&fx.state),
        [0, 0, 0, 2, 0, 0, 0, 0, 0],
        "both tunnels are cut as `peer_revoked`, judged by slot A's anchors"
    );
    let refused = open_tunnel(&mut fx.sender).await.err();
    assert_eq!(refused, Some(StatusCode::FORBIDDEN));
    assert_eq!(fx.state.hbone_admission_fence.connect_trust_refusals(), 1);

    // Withdrawing the records restores admission, so the next assertion cannot
    // pass for the wrong reason.
    assert!(publish_crls(&fx.state, Vec::new()));
    assert_eq!(
        inbound_trust_revision(&fx.state),
        accepted_revision + 2,
        "an empty publication is a real publication"
    );
    assert!(handshake_admits_leaf(&verifier, &peer_leaf));

    // A publication through the REBOUND slot that DOES compile replaces the
    // binding atomically, with a fresh revision drawn from the same fence-wide
    // sequence. Its trust set deliberately does not anchor this peer, so the
    // handshake flipping back to a refusal is what proves slot B's material —
    // not slot A's — is now what both surfaces verify against.
    let elsewhere = mint_peer_chain(OTHER_SPIFFE);
    fx.state.publish_mesh_inbound_trust_bundle(
        &slot_b,
        Arc::new(Some(inbound_bundle(
            &rebind_gateway,
            local_trust(PEER_TRUST_DOMAIN, vec![elsewhere.ca_der.clone()]),
        ))),
    );
    assert_eq!(
        inbound_trust_revision(&fx.state),
        accepted_revision + 3,
        "a compilable rebind takes a fresh revision"
    );
    assert!(
        !handshake_admits_leaf(&verifier, &peer_leaf),
        "the rebound slot's material is what verifies now"
    );

    fx.teardown().await;
}

/// Removing the enforced records restores admission on BOTH surfaces at once:
/// the peer's next CONNECT is admitted again and no live tunnel is revoked for
/// revocation. An empty list is the operator's "revocation rescinded", not an
/// absence of publication.
#[tokio::test(flavor = "multi_thread")]
async fn removing_the_enforced_records_readmits_the_peer() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let state = credential_state(9661);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let verifier = inbound_verifier(&state, &slot);
    let fence = &state.hbone_admission_fence;

    let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking]));
    assert!(!handshake_admits(&verifier, &peer));

    let revision_while_revoked = inbound_trust_revision(&state);
    assert!(
        publish_crls(&state, Vec::new()),
        "withdrawing every record is a publication in its own right"
    );
    assert_eq!(
        inbound_trust_revision(&state),
        revision_while_revoked + 1,
        "the withdrawal advances the ONE in-force revision, so every live tunnel re-verifies"
    );
    assert!(
        handshake_admits(&verifier, &peer),
        "with no records enforced, revocation checking is off again"
    );

    // A tunnel admitted under the revoked generation is not revoked by the
    // withdrawal: the sweep re-verifies and finds the peer admissible.
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, revision_while_revoked),
    ));
    fence.request_sweep();
    wait_for_settled_sweeps(&state).await;
    assert_eq!(tunnel.revoked_reason(), None);
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

/// The shared CRL policy is FULL-CHAIN, so revoking the ISSUING INTERMEDIATE
/// must stop every leaf it signed even though no record names a leaf serial. A
/// two-level fixture cannot show that at all, and an operator revoking a
/// compromised issuing CA is the case that matters most.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_issuing_intermediate_revokes_the_tunnel_and_the_handshake() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let chain = mint_peer_chain_via_intermediate(CLIENT_SPIFFE);
    let state = credential_state(9662);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![chain.root_der.clone()]),
    );
    let verifier = inbound_verifier(&state, &slot);
    assert!(
        handshake_admits_chain(&verifier, &chain),
        "the three-level chain must be admissible before anything revokes it"
    );

    let fence = &state.hbone_admission_fence;
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        intermediate_peer_credential(&chain, inbound_trust_revision(&state)),
    ));

    // Signed by the ROOT, which is the authority that issued the intermediate;
    // a CRL from anything else is not authoritative and webpki ignores it.
    let revoking = signed_crl_by_issuer(
        &chain.root_issuer,
        &[INTERMEDIATE_SERIAL],
        time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        time::OffsetDateTime::now_utc() + time::Duration::days(30),
    );
    assert!(publish_crls(&state, vec![revoking]));

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::PeerRevoked),
        "a revoked issuing CA revokes the leaves it signed, and it is a revocation rather \
         than a trust withdrawal: the chain still anchors in the root"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 1, 0, 0, 0, 0, 0]);
    assert!(
        !handshake_admits_chain(&verifier, &chain),
        "and the same record refuses the peer's next handshake"
    );
}

/// A CRL that ages out AFTER it took force is a fence failure, not a statement
/// about the peer: the revocation question can no longer be answered, so the
/// tunnel is cut as `reevaluation_failed` rather than left serving or filed
/// under `peer_expired`. Bounded by the skip key, deliberately — it is observed
/// on the next publication that moves the revision, not at the instant the
/// record expires — so this test publishes a trust change to move it.
///
/// **Timing budget.** There is no injectable verification clock: `UnixTime::now`
/// and `OffsetDateTime::now_utc` are read directly by rustls/webpki and by the
/// record minting, and the repository forbids adding a test-only one to a main
/// source module. So the record is minted with a generous `nextUpdate` — eight
/// seconds, far more than signing and publication can plausibly take even on a
/// loaded runner, where a two-second window left roughly one second after
/// `nextUpdate`'s second-resolution encoding — and the wait afterwards is
/// computed FROM that minted instant plus a one-second guard rather than being a
/// fixed sleep. Total wall time is therefore about nine seconds, and it cannot
/// race its own setup: the publication assertion is made while the record is
/// still comfortably in window.
///
/// A POSITIVE verification is established before the clock is allowed to run
/// out, so the final refusal is a state change rather than a first observation:
/// the tunnel is admitted carrying the revision that was in force BEFORE the
/// publication, which makes the first sweep genuinely re-verify (asserted
/// through `trust_rechecks`) and find the peer admissible.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_that_ages_out_after_taking_force_fails_closed_on_the_next_revision() {
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let peer = mint_peer_chain(CLIENT_SPIFFE);
    let joining = mint_peer_chain(OTHER_SPIFFE);
    let state = credential_state(9664);

    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
    );
    let fence = &state.hbone_admission_fence;
    let revision_before_records = inbound_trust_revision(&state);

    // In window now, expired shortly. Naming an unrelated serial on purpose:
    // the tunnel is cut because the list can no longer be evaluated, not
    // because it revokes this peer.
    let now = time::OffsetDateTime::now_utc();
    let next_update = now + time::Duration::seconds(8);
    let short_lived = signed_crl_in_window(
        &peer,
        &[UNRELATED_LEAF_SERIAL],
        now - time::Duration::hours(1),
        next_update,
    );
    assert!(
        publish_crls(&state, vec![short_lived]),
        "the record is usable at publication, so it takes force"
    );
    assert_eq!(
        inbound_trust_revision(&state),
        revision_before_records + 1,
        "and taking force is what advances the one in-force revision"
    );

    // Admitted under the PREVIOUS revision, so the first sweep cannot take the
    // skip path: it rebuilds the certificate path against the in-force anchors
    // — with the record still in window — and finds the peer admissible.
    let tunnel = fence.admit(credential_snapshot(
        fence.sweep_epoch(),
        peer_credential(&peer, live_expiry(), true, revision_before_records),
    ));
    fence.request_sweep();
    wait_for_settled_sweeps(&state).await;
    assert_eq!(tunnel.revoked_reason(), None);
    assert!(
        fence.trust_rechecks() > 0,
        "the tunnel must actually have been re-verified while the record was live, or the \
         refusal below would be its first verification rather than a state change"
    );

    // Wait past the minted `nextUpdate` itself, plus a guard — never a fixed
    // sleep, which would race a runner that was slow to get here.
    let remaining = next_update - time::OffsetDateTime::now_utc();
    let past_expiry = tokio::time::Instant::now()
        + Duration::try_from(remaining).unwrap_or_default()
        + Duration::from_secs(1);
    tokio::time::sleep_until(past_expiry).await;

    // A trust change that still anchors the peer. It recompiles with the SAME,
    // now-expired records and moves the revision, which is what makes the
    // tunnel re-verify.
    publish_inbound_trust(
        &state,
        &slot,
        &gateway,
        local_trust(
            PEER_TRUST_DOMAIN,
            vec![peer.ca_der.clone(), joining.ca_der.clone()],
        ),
    );

    wait_for_revocation(&tunnel).await;
    assert_eq!(
        tunnel.revoked_reason(),
        Some(HboneRevocationReason::ReevaluationFailed),
        "an in-force CRL past its nextUpdate makes the chain un-judgeable; the fence fails \
         closed and must NOT file it as peer_expired, which describes the peer's own SVID"
    );
    assert_eq!(revocation_counts(&state), [0, 0, 0, 0, 0, 0, 0, 0, 1]);
}

/// The datagram relay shares the credential gate with the byte-stream relay, so
/// a published CRL must cut a live `CONNECT-UDP` tunnel and refuse the peer's
/// next datagram CONNECT on the same never-re-handshaked mTLS session.
#[tokio::test(flavor = "multi_thread")]
async fn a_crl_revoking_the_peer_cuts_a_live_datagram_tunnel_and_refuses_its_retry() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let _slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![certs.ca_der()]),
    );
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state.clone(), hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let authority = format!("127.0.0.1:{}", external_addr.port());
    let (response_fut, mut request_body) = sender
        .send_request(udp_connect_request(&authority), false)
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

    let revoking = certs.signed_crl(&[HBONE_CLIENT_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking]));

    assert_tunnel_closed(&mut response_body).await;
    wait_for_no_live_tunnels(&state).await;
    assert_eq!(
        revocation_counts(&state),
        [0, 0, 0, 1, 0, 0, 0, 0, 0],
        "the datagram relay honors the revocation exactly as the byte-stream relay does"
    );

    // The retry on the same pooled connection is refused at admission.
    let (retry_fut, _retry_body) = sender
        .send_request(udp_connect_request(&authority), false)
        .expect("send retry udp CONNECT");
    let retry = tokio::time::timeout(DEADLINE, retry_fut)
        .await
        .expect("retry response within deadline")
        .expect("retry response");
    assert_eq!(
        retry.status(),
        StatusCode::FORBIDDEN,
        "a datagram CONNECT whose chain the enforced records revoke must be refused"
    );
    assert_eq!(state.hbone_admission_fence.connect_trust_refusals(), 1);
    assert_eq!(state.hbone_admission_fence.live_tunnels(), 0);

    let _ = shutdown_tx.send(true);
    external_handle.abort();
    conn_task.abort();
}

/// A rotation must reach a REAL TLS handshake on a live listener, not only a
/// direct `verify_client_cert` call. The listener here is built with the
/// production SPIFFE peer verifier bound to the shared admission artifact, and
/// is never rebound: the assertion is that the peer's next mTLS session simply
/// stops working once its leaf is revoked, and keeps working for a record that
/// names a different serial.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_spiffe_mtls_session_stops_being_established_after_a_crl_rotation() {
    let certs = generate_hbone_mtls_certs(CLIENT_SPIFFE);
    let gateway = mint_peer_chain(GATEWAY_SPIFFE);
    let state = credential_state(9665);
    let slot = install_inbound_trust(
        &state,
        &gateway,
        local_trust(PEER_TRUST_DOMAIN, vec![certs.ca_der()]),
    );
    let server_config =
        hbone_server_config_with_client_verifier(&certs, inbound_verifier(&state, &slot));
    let (gateway_addr, shutdown_tx) = start_inbound_gateway(state.clone(), server_config).await;

    assert!(
        mtls_session_is_established(gateway_addr, hbone_client_config(&certs)).await,
        "the peer must complete mTLS and exchange one request before anything revokes it"
    );

    let unrelated = certs.signed_crl(&[UNRELATED_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![unrelated]));
    assert!(
        mtls_session_is_established(gateway_addr, hbone_client_config(&certs)).await,
        "a record naming a different serial must leave this peer connecting"
    );

    let revoking = certs.signed_crl(&[HBONE_CLIENT_LEAF_SERIAL]);
    assert!(publish_crls(&state, vec![revoking]));
    assert!(
        !mtls_session_is_established(gateway_addr, hbone_client_config(&certs)).await,
        "the rotation must end the peer's next session on the LIVE listener, with no rebind \
         and no ServerConfig rebuild"
    );

    let _ = shutdown_tx.send(true);
}

/// Both publication orderings the concurrent smoke test below can only sample,
/// driven DETERMINISTICALLY through the public API.
///
/// Production arms the backend CRL watcher before mesh installs its inbound
/// slot, so a CRL publication really can land BEFORE any trust is installed:
/// the publisher stores the records with nothing to recompile, and the install
/// that follows must compile WITH them. The reverse is the ordinary order.
/// Either way exactly ONE set ends up in force on both surfaces — observable as
/// the peer the records revoke being cut by the fence, not only refused by the
/// handshake.
///
/// The third case the concurrent tests touch — a byte-identical republish after
/// a publication compiling nothing and advancing nothing — is already covered
/// sequentially by
/// `a_crl_publication_with_unchanged_trust_material_advances_the_revision_exactly_once`,
/// and is deliberately not duplicated here.
#[tokio::test(flavor = "multi_thread")]
async fn either_publication_order_leaves_one_set_in_force_on_both_surfaces() {
    for crls_first in [true, false] {
        let gateway = mint_peer_chain(GATEWAY_SPIFFE);
        let peer = mint_peer_chain(CLIENT_SPIFFE);
        let state = credential_state(if crls_first { 9666 } else { 9667 });
        let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
        let slot = tls::shared_bundle_slot(Some(inbound_bundle(
            &gateway,
            local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
        )));

        if crls_first {
            assert!(
                state.publish_mesh_inbound_crls(Arc::new(vec![revoking])),
                "records publish with no trust installed; there is simply nothing to recompile"
            );
            state.install_mesh_inbound_admission_trust(&slot);
        } else {
            state.install_mesh_inbound_admission_trust(&slot);
            assert!(state.publish_mesh_inbound_crls(Arc::new(vec![revoking])));
        }

        assert_eq!(
            state.mesh_inbound_admission.crls().load().crls().len(),
            1,
            "the records are enforced in either order"
        );
        let verifier = inbound_verifier(&state, &slot);
        assert!(
            !handshake_admits(&verifier, &peer),
            "the handshake polices the published records in either order"
        );

        // ...and so does the fence. `admitted_trust_revision` 0 never matches a
        // real revision, so the sweep always re-verifies rather than skipping.
        let fence = &state.hbone_admission_fence;
        let tunnel = fence.admit(credential_snapshot(
            fence.sweep_epoch(),
            peer_credential(&peer, live_expiry(), true, 0),
        ));
        fence.request_sweep();
        wait_for_revocation(&tunnel).await;
        assert_eq!(
            tunnel.revoked_reason(),
            Some(HboneRevocationReason::PeerRevoked),
            "the anchors in force must have been compiled WITH the published records; an \
             install that runs after a publication must not leave the fence judging by an \
             empty list"
        );
        assert_eq!(revocation_counts(&state), [0, 0, 0, 1, 0, 0, 0, 0, 0]);
    }
}

/// A SMOKE test for the same invariant under real concurrency, not a proof of
/// any particular interleaving.
///
/// Production arms the backend CRL watcher before mesh installs its inbound
/// slot, so a CRL publisher really can read "no trust installed" and be
/// overtaken by the install. Before the fence-owned lock, the publisher then
/// stored its records with nothing recompiled: the verifier enforced one list
/// and the fence's anchors policed another, permanently, because a
/// byte-identical republish returns early and can never repair it.
///
/// What this test CANNOT do is force that interleaving. The barrier releases
/// both threads immediately before their public calls; it cannot suspend the
/// publisher between its "no trust installed" decision and its store, and there
/// are no test-only hooks in the fence to do so with (the repository forbids
/// test-only runtime branches in main source modules). Every iteration may well
/// execute in a safe order, and the loop is a sampling budget, not a guarantee.
/// The deterministic coverage of both orders is
/// `either_publication_order_leaves_one_set_in_force_on_both_surfaces` above.
///
/// The final assertions are still worth running under concurrency: whichever
/// order lands, ONE set must be in force on both surfaces — observable as the
/// peer the records revoke being cut by the fence, not only refused by the
/// handshake — and that is what fails if the serialization or the locked
/// re-check is removed and an unsafe interleaving does occur.
#[tokio::test(flavor = "multi_thread")]
async fn an_install_that_races_a_crl_publication_leaves_one_set_in_force() {
    for iteration in 0..12u16 {
        let gateway = mint_peer_chain(GATEWAY_SPIFFE);
        let peer = mint_peer_chain(CLIENT_SPIFFE);
        let state = credential_state(9670 + iteration);
        let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
        let slot = tls::shared_bundle_slot(Some(inbound_bundle(
            &gateway,
            local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
        )));

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let installer = {
            let handle = tokio::runtime::Handle::current();
            let barrier = Arc::clone(&barrier);
            let state = state.clone();
            let slot = slot.clone();
            std::thread::spawn(move || {
                let _runtime = handle.enter();
                barrier.wait();
                state.install_mesh_inbound_admission_trust(&slot);
            })
        };
        let publisher = {
            let handle = tokio::runtime::Handle::current();
            let barrier = Arc::clone(&barrier);
            let state = state.clone();
            std::thread::spawn(move || {
                let _runtime = handle.enter();
                barrier.wait();
                state.publish_mesh_inbound_crls(Arc::new(vec![revoking]));
            })
        };
        installer.join().expect("installer thread");
        publisher.join().expect("publisher thread");

        assert_eq!(
            state.mesh_inbound_admission.crls().load().crls().len(),
            1,
            "the records are enforced whichever thread won"
        );
        let verifier = inbound_verifier(&state, &slot);
        assert!(
            !handshake_admits(&verifier, &peer),
            "the handshake polices the published records"
        );

        // ...and so does the fence. `admitted_trust_revision` 0 never matches a
        // real revision, so the sweep always re-verifies rather than skipping.
        let fence = &state.hbone_admission_fence;
        let tunnel = fence.admit(credential_snapshot(
            fence.sweep_epoch(),
            peer_credential(&peer, live_expiry(), true, 0),
        ));
        fence.request_sweep();
        wait_for_revocation(&tunnel).await;
        assert_eq!(
            tunnel.revoked_reason(),
            Some(HboneRevocationReason::PeerRevoked),
            "the anchors in force must have been compiled WITH the published records; an \
             install that overtook the publisher's 'no trust installed' check must not leave \
             the fence judging by an empty list"
        );
    }
}

/// Two publishers can pass the outer equality check with the SAME candidate.
/// The loser must recompile nothing and advance nothing: an identical
/// publication that moved the in-force revision would charge every live tunnel
/// a certificate path build for a decision that did not change, which is
/// exactly what the skip key exists to prevent.
///
/// A SMOKE test, like its sibling above: the barrier releases both threads
/// immediately before `publish_mesh_inbound_crls`, so it cannot force both of
/// them past the outer equality check before either takes the lock, and no
/// iteration is guaranteed to reach that interleaving. The
/// exactly-one-publication, exactly-one-revision and exactly-one-compilation
/// assertions are what detect removal of the locked re-check or of the
/// `publish_enforced_crl_set`-gated advance WHEN the interleaving does occur;
/// the sequential no-op guarantee itself is pinned by
/// `a_crl_publication_with_unchanged_trust_material_advances_the_revision_exactly_once`.
#[tokio::test(flavor = "multi_thread")]
async fn two_identical_concurrent_crl_publications_compile_and_advance_once() {
    for iteration in 0..12u16 {
        let gateway = mint_peer_chain(GATEWAY_SPIFFE);
        let peer = mint_peer_chain(CLIENT_SPIFFE);
        let state = credential_state(9690 + iteration);
        let _slot = install_inbound_trust(
            &state,
            &gateway,
            local_trust(PEER_TRUST_DOMAIN, vec![peer.ca_der.clone()]),
        );
        let revoking = signed_crl(&peer, &[PEER_LEAF_SERIAL]);
        let revision_before = inbound_trust_revision(&state);
        let compilations_before = state.hbone_admission_fence.trust_anchor_builds();

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let racers: Vec<std::thread::JoinHandle<bool>> = (0..2)
            .map(|_| {
                let handle = tokio::runtime::Handle::current();
                let barrier = Arc::clone(&barrier);
                let state = state.clone();
                let records = vec![revoking.clone()];
                std::thread::spawn(move || {
                    let _runtime = handle.enter();
                    barrier.wait();
                    state.publish_mesh_inbound_crls(Arc::new(records))
                })
            })
            .collect();
        let published: Vec<bool> = racers
            .into_iter()
            .map(|racer| racer.join().expect("publisher thread"))
            .collect();

        assert_eq!(
            published.iter().filter(|changed| **changed).count(),
            1,
            "exactly one of two identical publications changes the enforced set"
        );
        assert_eq!(
            inbound_trust_revision(&state),
            revision_before + 1,
            "and it moves the ONE in-force revision exactly once"
        );
        assert_eq!(
            state.hbone_admission_fence.trust_anchor_builds(),
            compilations_before + 1,
            "the loser must not recompile the anchors either"
        );
    }
}

/// The CONNECT refusal's operator attribution is a closed four-value set, and
/// the same literal has to reach BOTH surfaces an operator reads: the
/// `mesh_authz.deny_policy` request metadata and the rejected-request reason.
///
/// `HboneConnectRefusal` is crate-private and the metadata never leaves the
/// gateway, so the wiring is pinned in source — the technique the sibling
/// chain-of-custody test above already uses. The runtime half (a `403` with the
/// byte-identical unauthenticated body, and one `connect_trust_refusals`) is
/// asserted by the TCP and datagram revocation tests.
#[test]
fn the_connect_refusal_attribution_is_one_closed_set_on_both_surfaces() {
    // Collapse runs of whitespace so an assertion survives rustfmt reflow.
    fn flat(source: &str) -> String {
        source.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    let proxy = flat(include_str!("../../src/proxy/hbone_proxy.rs"));
    let fence = flat(include_str!("../../src/proxy/hbone_admission_fence.rs"));

    // Each relay derives its attribution from the refusal itself, never from a
    // literal at the call site that can drift from the gate that produced it.
    let byte_stream = "let deny_reason = refusal.connect_reason();";
    let datagram = "let deny_reason = refusal.udp_connect_reason();";
    assert_eq!(proxy.matches(byte_stream).count(), 1);
    assert_eq!(proxy.matches(datagram).count(), 1);

    // Both stamp the SAME metadata key from that reason...
    let stamp = ".insert(\"mesh_authz.deny_policy\".to_string(), deny_policy);";
    assert_eq!(
        proxy.matches(stamp).count(),
        2,
        "the byte-stream and datagram relays must stamp one metadata key"
    );
    // ...and log the rejected request with the very same value.
    assert_eq!(
        proxy.matches("start_time, deny_reason,").count(),
        2,
        "the logged reason and the metadata must never be two different strings"
    );

    // The set itself is closed: four literals, each declared exactly once, on
    // the renderer rather than scattered across the relays.
    for reason in [
        "hbone_peer_trust_withdrawn",
        "hbone_peer_revoked",
        "hbone_udp_peer_trust_withdrawn",
        "hbone_udp_peer_revoked",
    ] {
        let literal = format!("\"{reason}\"");
        assert_eq!(
            fence.matches(&literal).count(),
            1,
            "{reason} must be declared exactly once, on HboneConnectRefusal"
        );
        assert_eq!(
            proxy.matches(&literal).count(),
            0,
            "{reason} must not be re-spelled at a relay call site"
        );
    }
    assert_eq!(fence.matches("fn connect_reason(self)").count(), 1);
    assert_eq!(fence.matches("fn udp_connect_reason(self)").count(), 1);
}
