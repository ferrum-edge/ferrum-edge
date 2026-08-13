//! Black-box regression coverage for advisory GHSA-3f2j-wwqw-grmg —
//! "Fleet-wide CP/DP HS256 secret lets a compromised tenant forge namespace
//! authorization".
//!
//! The attacker model is a fully compromised tenant-A node: it holds every
//! credential actually installed in tenant A and may write anything it likes
//! into the token it presents. The invariant under test is that such a node
//! cannot reach tenant B on **any** configuration surface — `ConfigSync`
//! (`Subscribe` and `GetFullConfig`), native `MeshConfigSync.MeshSubscribe`,
//! or xDS ADS — and that the refusal happens before a single byte of tenant-B
//! gateway config, mesh inventory, trust material, or xDS resource is
//! serialized.
//!
//! These tests drive the real gRPC services over a real loopback socket with
//! hand-minted tokens, so they exercise the wire path rather than the
//! resolver in isolation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation, decode, encode};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::auth::{
    AuthorizedResponseStream, MESH_LOCAL_SUBSCRIBE_AUDIENCE, StreamAuthSurface,
    StreamAuthorizationLease, remote_discovery_audience,
};
use ferrum_edge::grpc::cp_server::{CpGrpcServer, CpScope, DpNodeRegistry};
use ferrum_edge::grpc::cp_trust::{
    CpDpTrustBundle, CpDpVerifier, CpDpVerifierStore, CpGrpcConnectInfo, PeerNamespaceScope,
    PinnedTrustBundleSource, TrustBundleRejectReason,
};
use ferrum_edge::grpc::cp_trust_health::{CpDpTrustReloadStatus, TrustReloadFailure};
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_server::MeshGrpcServer;
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshService, TrustBundle, TrustBundleSet};
use ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use ferrum_edge::xds::proto::{DeltaDiscoveryRequest, DiscoveryRequest, Node};
use ferrum_edge::xds::{LDS_TYPE_URL, XdsAdsServer};

const TEST_ISSUER: &str = "ferrum-edge-cp-dp";

/// The secret actually installed on tenant A's data planes. Under the
/// pre-advisory design this was the *fleet* secret; the whole point of the fix
/// is that holding it now buys tenant A nothing outside tenant A.
const TENANT_A_SECRET: &str = "tenant-a-cp-dp-secret-2026-ferrum-edge";
const TENANT_B_SECRET: &str = "tenant-b-cp-dp-secret-2026-ferrum-edge";

const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";

// ── Trust bundle fixtures ────────────────────────────────────────────────

/// A two-tenant symmetric trust bundle: each `kid` is bound, by control-plane
/// configuration, to exactly one namespace.
fn two_tenant_verifier() -> CpDpVerifier {
    let document = json!({
        "version": 1,
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
            { "kid": TENANT_B, "algorithm": "HS256", "secret": TENANT_B_SECRET,
              "namespaces": [TENANT_B] },
        ]
    })
    .to_string();
    let bundle = CpDpTrustBundle::from_document_str(&document, "test-bundle", None)
        .expect("two-tenant bundle must load");
    CpDpVerifier::TrustBundle(bundle)
}

fn two_tenant_bundle() -> Arc<CpDpVerifier> {
    Arc::new(two_tenant_verifier())
}

fn tenant_b_only_verifier() -> CpDpVerifier {
    let document = json!({
        "version": 1,
        "keys": [
            { "kid": TENANT_B, "algorithm": "HS256", "secret": TENANT_B_SECRET,
              "namespaces": [TENANT_B] },
        ]
    })
    .to_string();
    CpDpVerifier::TrustBundle(
        CpDpTrustBundle::from_document_str(&document, "tenant-b-only", None)
            .expect("tenant B verifier must load"),
    )
}

fn tenant_a_broad_verifier() -> CpDpVerifier {
    let document = json!({
        "version": 1,
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A, TENANT_B] },
            { "kid": TENANT_B, "algorithm": "HS256", "secret": TENANT_B_SECRET,
              "namespaces": [TENANT_B] },
        ]
    })
    .to_string();
    CpDpVerifier::TrustBundle(
        CpDpTrustBundle::from_document_str(&document, "tenant-a-broad", None)
            .expect("broad tenant A verifier must load"),
    )
}

/// Mint a token exactly as a compromised node would: arbitrary claims, signed
/// with whatever key that node actually holds, and stamped with whatever `kid`
/// the attacker chooses.
fn mint(
    secret: &str,
    kid: Option<&str>,
    node_id: &str,
    ns: Option<serde_json::Value>,
    audience: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();
    mint_with_exp(secret, kid, node_id, ns, audience, now + 600)
}

fn mint_with_exp(
    secret: &str,
    kid: Option<&str>,
    node_id: &str,
    ns: Option<serde_json::Value>,
    audience: Option<&str>,
    exp: i64,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "sub": node_id,
        "iat": now,
        "exp": exp,
        "iss": TEST_ISSUER,
        "role": "data_plane",
    });
    if let Some(ns) = ns {
        claims["ns"] = ns;
    }
    if let Some(audience) = audience {
        claims["aud"] = json!(audience);
    }
    let mut header = Header::new(Algorithm::HS256);
    header.kid = kid.map(str::to_string);
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("test JWT must encode")
}

// ── Config fixtures ──────────────────────────────────────────────────────

fn tenant_marked_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        known_namespaces: vec![TENANT_A.to_string(), TENANT_B.to_string()],
        mesh: Some(Box::new(MeshConfig {
            services: vec![
                mesh_service("svc-tenant-a-marker", TENANT_A),
                mesh_service("svc-tenant-b-marker", TENANT_B),
            ],
            trust_bundles: Some(test_trust_bundles()),
            ..MeshConfig::default()
        })),
        ..Default::default()
    }
}

fn mesh_service(name: &str, namespace: &str) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
    }
}

fn test_trust_bundles() -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
            x509_authorities: vec!["AQIDBA==".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }
}

fn multi_tenant_scope() -> CpScope {
    CpScope::Set(
        [TENANT_A.to_string(), TENANT_B.to_string()]
            .into_iter()
            .collect(),
    )
}

fn fixed_verifier_store(verifier: Arc<CpDpVerifier>) -> Arc<CpDpVerifierStore> {
    Arc::new(CpDpVerifierStore::from_arc(verifier))
}

// ── Server harnesses ─────────────────────────────────────────────────────

async fn start_configsync(
    verifier: Arc<CpDpVerifier>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (server, _tx) = CpGrpcServer::builder(cfg_arc, TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(DpNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier_store(fixed_verifier_store(verifier))
        .scope(multi_tenant_scope())
        .real_ip_header(None)
        .build();
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("ConfigSync server failed");
    });
    settle().await;
    (addr, handle)
}

async fn start_mesh(verifier: Arc<CpDpVerifier>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (server, _tx) = MeshGrpcServer::builder(cfg_arc, TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(MeshNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier_store(fixed_verifier_store(verifier))
        .scope(multi_tenant_scope())
        .build();
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("mesh gRPC server failed");
    });
    settle().await;
    (addr, handle)
}

async fn start_xds(verifier: Arc<CpDpVerifier>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (_cp, update_tx) = CpGrpcServer::builder(cfg_arc.clone(), TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .scope(multi_tenant_scope())
        .build();
    let server = XdsAdsServer::new(
        cfg_arc,
        update_tx,
        TENANT_A_SECRET.to_string(),
        TEST_ISSUER.to_string(),
        TENANT_A.to_string(),
        32,
    )
    .with_verifier_store(fixed_verifier_store(verifier))
    .with_scope(multi_tenant_scope());
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("xDS server failed");
    });
    settle().await;
    (addr, handle)
}

async fn start_all_stream_surfaces(
    verifier: Arc<CpDpVerifierStore>,
    max_lifetime: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (cp, update_tx) = CpGrpcServer::builder(cfg_arc.clone(), TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(DpNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier_store(verifier.clone())
        .max_stream_lifetime(max_lifetime)
        .scope(multi_tenant_scope())
        .real_ip_header(None)
        .build();
    let (mesh, _mesh_tx) = MeshGrpcServer::builder(cfg_arc.clone(), TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(MeshNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier_store(verifier.clone())
        .max_stream_lifetime(max_lifetime)
        .scope(multi_tenant_scope())
        .cluster_audience(Some("test-cluster".to_string()))
        .build();
    let xds = XdsAdsServer::new(
        cfg_arc,
        update_tx,
        TENANT_A_SECRET.to_string(),
        TEST_ISSUER.to_string(),
        TENANT_A.to_string(),
        32,
    )
    .with_verifier_store(verifier)
    .with_max_stream_lifetime(max_lifetime)
    .with_scope(multi_tenant_scope());

    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(cp.into_service())
            .add_service(mesh.into_service())
            .add_service(xds.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("combined configuration stream server failed");
    });
    settle().await;
    (addr, handle)
}

async fn bind_loopback() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Give the spawned server a moment to start accepting before the client
/// dials, matching the surrounding integration suites.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

macro_rules! configsync_client {
    ($addr:expr, $token:expr) => {{
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", $addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        )
    }};
}

macro_rules! mesh_client {
    ($addr:expr, $token:expr) => {{
        let token_meta: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", $token).parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(format!("http://{}", $addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        ferrum_edge::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                req.metadata_mut()
                    .insert("authorization", token_meta.clone());
                Ok(req)
            },
        )
    }};
}

fn subscribe_request(node_id: &str, namespace: &str) -> ferrum_edge::grpc::proto::SubscribeRequest {
    ferrum_edge::grpc::proto::SubscribeRequest {
        node_id: node_id.to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: namespace.to_string(),
        real_ip_header: Some(String::new()),
        supports_heartbeat: true,
    }
}

fn mesh_subscribe_request(
    node_id: &str,
    namespace: &str,
    remote_discovery: bool,
) -> ferrum_edge::grpc::proto::MeshSubscribeRequest {
    ferrum_edge::grpc::proto::MeshSubscribeRequest {
        node_id: node_id.to_string(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: namespace.to_string(),
        workload_spiffe_id: String::new(),
        labels: HashMap::new(),
        waypoint_name: String::new(),
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
        remote_discovery,
    }
}

async fn wait_for_terminal_status<T>(stream: &mut tonic::Streaming<T>) -> tonic::Code {
    timeout(Duration::from_secs(3), async {
        loop {
            match stream.message().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("configuration stream closed without terminal status"),
                Err(status) => return status.code(),
            }
        }
    })
    .await
    .expect("configuration stream must terminate within the bounded lease window")
}

async fn xds_channel(addr: SocketAddr) -> tonic::transport::Channel {
    tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

fn authorize<T>(mut request: tonic::Request<T>, token: &str) -> tonic::Request<T> {
    request.metadata_mut().insert(
        "authorization",
        tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

/// Admission must bind to the generation carried by the exact immutable
/// verifier snapshot used for signature and claims verification. Re-reading
/// generation from the current store would accept here because tenant A's
/// opaque credential identity is present again after the remove/re-add.
#[test]
fn captured_old_verifier_snapshot_cannot_bind_after_remove_then_readd() {
    let verifier = CpDpVerifierStore::from_arc(two_tenant_bundle());
    let captured = verifier.load();
    let token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "captured-snapshot-node",
        Some(json!(TENANT_A)),
        None,
    );
    let request = authorize(tonic::Request::new(()), &token);

    verifier.replace(tenant_b_only_verifier());
    verifier.replace(two_tenant_verifier());

    let status = match captured.verify_and_bind_grpc_identity(
        request.metadata(),
        TEST_ISSUER,
        None,
        &verifier,
    ) {
        Ok(_) => panic!("an identity verified by the removed generation must not bind"),
        Err(status) => status,
    };
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test(start_paused = true)]
async fn finite_server_lease_closes_every_bearer_configuration_stream() {
    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    let (addr, handle) = start_all_stream_surfaces(verifier, Duration::from_millis(150)).await;

    let config_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "config-node",
        Some(json!(TENANT_A)),
        None,
    );
    let mut config_client = configsync_client!(addr, config_token);
    let mut config_stream = config_client
        .subscribe(tonic::Request::new(subscribe_request(
            "config-node",
            TENANT_A,
        )))
        .await
        .expect("ConfigSync admission")
        .into_inner();
    assert_eq!(
        wait_for_terminal_status(&mut config_stream).await,
        tonic::Code::Unauthenticated
    );

    for (node_id, remote, audience) in [
        (
            "mesh-local-node",
            false,
            MESH_LOCAL_SUBSCRIBE_AUDIENCE.to_string(),
        ),
        (
            "mesh-remote-node",
            true,
            remote_discovery_audience("test-cluster"),
        ),
    ] {
        let mesh_token = mint(
            TENANT_A_SECRET,
            Some(TENANT_A),
            node_id,
            Some(json!(TENANT_A)),
            Some(&audience),
        );
        let mut mesh_client = mesh_client!(addr, mesh_token);
        let mut mesh_stream = mesh_client
            .mesh_subscribe(tonic::Request::new(mesh_subscribe_request(
                node_id, TENANT_A, remote,
            )))
            .await
            .expect("MeshSubscribe admission")
            .into_inner();
        assert_eq!(
            wait_for_terminal_status(&mut mesh_stream).await,
            tonic::Code::Unauthenticated
        );
    }

    let sotw_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "xds-sotw-node",
        Some(json!(TENANT_A)),
        None,
    );
    let mut sotw_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (sotw_tx, sotw_rx) = mpsc::channel(2);
    sotw_tx
        .send(DiscoveryRequest {
            node: Some(Node {
                id: "xds-sotw-node".to_string(),
                ..Node::default()
            }),
            resource_names: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DiscoveryRequest::default()
        })
        .await
        .unwrap();
    let mut sotw_stream = sotw_client
        .stream_aggregated_resources(authorize(
            tonic::Request::new(ReceiverStream::new(sotw_rx)),
            &sotw_token,
        ))
        .await
        .expect("SotW ADS admission")
        .into_inner();
    assert_eq!(
        wait_for_terminal_status(&mut sotw_stream).await,
        tonic::Code::Unauthenticated
    );
    drop(sotw_tx);

    let delta_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "xds-delta-node",
        Some(json!(TENANT_A)),
        None,
    );
    let mut delta_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (delta_tx, delta_rx) = mpsc::channel(2);
    delta_tx
        .send(DeltaDiscoveryRequest {
            node: Some(Node {
                id: "xds-delta-node".to_string(),
                ..Node::default()
            }),
            resource_names_subscribe: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DeltaDiscoveryRequest::default()
        })
        .await
        .unwrap();
    let mut delta_stream = delta_client
        .delta_aggregated_resources(authorize(
            tonic::Request::new(ReceiverStream::new(delta_rx)),
            &delta_token,
        ))
        .await
        .expect("delta ADS admission")
        .into_inner();
    assert_eq!(
        wait_for_terminal_status(&mut delta_stream).await,
        tonic::Code::Unauthenticated
    );
    drop(delta_tx);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_rotation_revokes_only_streams_bound_to_removed_credentials() {
    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    // Keep the independent server lease well beyond the client-side terminal
    // wait so this test isolates verifier rotation.
    let (addr, handle) =
        start_all_stream_surfaces(verifier.clone(), Duration::from_secs(300)).await;

    let token_a = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a-rotation",
        Some(json!(TENANT_A)),
        None,
    );
    let token_b = mint(
        TENANT_B_SECRET,
        Some(TENANT_B),
        "dp-b-rotation",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client_a = configsync_client!(addr, token_a);
    let mut stream_a = client_a
        .subscribe(tonic::Request::new(subscribe_request(
            "dp-a-rotation",
            TENANT_A,
        )))
        .await
        .expect("tenant A stream admission")
        .into_inner();
    let mut client_b = configsync_client!(addr, token_b);
    let mut stream_b = client_b
        .subscribe(tonic::Request::new(subscribe_request(
            "dp-b-rotation",
            TENANT_B,
        )))
        .await
        .expect("tenant B stream admission")
        .into_inner();
    stream_a
        .message()
        .await
        .unwrap()
        .expect("tenant A initial snapshot");
    stream_b
        .message()
        .await
        .unwrap()
        .expect("tenant B initial snapshot");

    verifier.replace(tenant_b_only_verifier());
    // Re-add the exact tenant-A key before either stream observes the watch
    // revision. Its new generation must not resurrect a stream admitted by
    // the removed generation, while tenant B remains continuously accepted.
    verifier.replace(two_tenant_verifier());
    assert_eq!(
        wait_for_terminal_status(&mut stream_a).await,
        tonic::Code::PermissionDenied
    );
    assert!(
        timeout(Duration::from_millis(600), stream_b.message())
            .await
            .is_err(),
        "an overlapping retained credential must not churn its live stream"
    );

    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn revocation_preempts_buffered_delivery_on_every_configuration_surface() {
    for surface in [
        StreamAuthSurface::ConfigSync,
        StreamAuthSurface::MeshSubscribeLocal,
        StreamAuthSurface::MeshSubscribeRemote,
        StreamAuthSurface::XdsSotw,
        StreamAuthSurface::XdsDelta,
    ] {
        let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
        let snapshot = verifier.load();
        let token = mint(
            TENANT_A_SECRET,
            Some(TENANT_A),
            "buffered-delivery-node",
            Some(json!(TENANT_A)),
            None,
        );
        let request = authorize(tonic::Request::new(()), &token);
        let identity = snapshot
            .verify_and_bind_grpc_identity(request.metadata(), TEST_ISSUER, None, verifier.as_ref())
            .expect("test identity must bind to the active generation");
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok::<_, tonic::Status>(()))
            .await
            .expect("buffered response must enqueue");
        let mut stream = AuthorizedResponseStream::new(
            ReceiverStream::new(rx),
            &identity,
            verifier.clone(),
            Duration::from_secs(300),
            surface,
        );

        verifier.replace(tenant_b_only_verifier());
        let status = stream
            .next()
            .await
            .expect("authorization closure must emit one terminal item")
            .expect_err("authorization closure must preempt buffered configuration output");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            status.message(),
            "Stream verification credential is no longer trusted"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn retained_reload_cannot_mask_the_next_revocation_on_an_idle_stream() {
    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    let snapshot = verifier.load();
    let token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "idle-reload-node",
        Some(json!(TENANT_A)),
        None,
    );
    let request = authorize(tonic::Request::new(()), &token);
    let identity = snapshot
        .verify_and_bind_grpc_identity(request.metadata(), TEST_ISSUER, None, verifier.as_ref())
        .expect("test identity must bind to the active generation");
    let (_tx, rx) = mpsc::channel::<Result<(), tonic::Status>>(1);
    let mut stream = AuthorizedResponseStream::new(
        ReceiverStream::new(rx),
        &identity,
        verifier.clone(),
        Duration::from_secs(300),
        StreamAuthSurface::ConfigSync,
    );
    let waiter = tokio::spawn(async move { stream.next().await });
    tokio::task::yield_now().await;

    // This replacement retains tenant A's exact credential generation. The
    // authorization watch must re-arm after observing it so the following
    // removal still wakes an otherwise idle response stream.
    verifier.replace(two_tenant_verifier());
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    verifier.replace(tenant_b_only_verifier());

    let status = waiter
        .await
        .expect("idle response waiter must not panic")
        .expect("revocation must emit one terminal item")
        .expect_err("revocation must terminate the idle stream");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test(start_paused = true)]
async fn deadlines_preempt_buffered_configuration_output() {
    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    let snapshot = verifier.load();
    let token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "server-deadline-buffered-node",
        Some(json!(TENANT_A)),
        None,
    );
    let request = authorize(tonic::Request::new(()), &token);
    let identity = snapshot
        .verify_and_bind_grpc_identity(request.metadata(), TEST_ISSUER, None, verifier.as_ref())
        .expect("test identity must bind to the active generation");
    let (tx, rx) = mpsc::channel(1);
    tx.send(Ok::<_, tonic::Status>(()))
        .await
        .expect("buffered response must enqueue");
    let mut stream = AuthorizedResponseStream::new(
        ReceiverStream::new(rx),
        &identity,
        verifier,
        Duration::ZERO,
        StreamAuthSurface::ConfigSync,
    );
    let status = stream
        .next()
        .await
        .expect("server deadline must emit one terminal item")
        .expect_err("server deadline must preempt buffered configuration output");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        status.message(),
        "Authenticated stream reached server maximum lifetime"
    );

    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    let snapshot = verifier.load();
    let token = mint_with_exp(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "token-deadline-buffered-node",
        Some(json!(TENANT_A)),
        None,
        Utc::now().timestamp() - 59,
    );
    let request = authorize(tonic::Request::new(()), &token);
    let identity = snapshot
        .verify_and_bind_grpc_identity(request.metadata(), TEST_ISSUER, None, verifier.as_ref())
        .expect("token inside verification leeway must bind");
    let (tx, rx) = mpsc::channel(1);
    tx.send(Ok::<_, tonic::Status>(()))
        .await
        .expect("buffered response must enqueue");
    let mut stream = AuthorizedResponseStream::new(
        ReceiverStream::new(rx),
        &identity,
        verifier,
        Duration::from_secs(300),
        StreamAuthSurface::ConfigSync,
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let status = stream
        .next()
        .await
        .expect("token deadline must emit one terminal item")
        .expect_err("token deadline must preempt buffered configuration output");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "Stream authorization expired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xds_revocation_terminates_sotw_and_delta_with_buffered_transport_data() {
    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    // This test isolates credential revocation with the independent server
    // lease well beyond the client-side terminal wait.
    let (addr, handle) =
        start_all_stream_surfaces(verifier.clone(), Duration::from_secs(300)).await;

    let sotw_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "buffered-xds-sotw-node",
        Some(json!(TENANT_A)),
        None,
    );
    let mut sotw_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (sotw_tx, sotw_rx) = mpsc::channel(2);
    sotw_tx
        .send(DiscoveryRequest {
            node: Some(Node {
                id: "buffered-xds-sotw-node".to_string(),
                ..Node::default()
            }),
            resource_names: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DiscoveryRequest::default()
        })
        .await
        .unwrap();
    let mut sotw_stream = sotw_client
        .stream_aggregated_resources(authorize(
            tonic::Request::new(ReceiverStream::new(sotw_rx)),
            &sotw_token,
        ))
        .await
        .expect("SotW ADS admission")
        .into_inner();

    let delta_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "buffered-xds-delta-node",
        Some(json!(TENANT_A)),
        None,
    );
    let mut delta_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (delta_tx, delta_rx) = mpsc::channel(2);
    delta_tx
        .send(DeltaDiscoveryRequest {
            node: Some(Node {
                id: "buffered-xds-delta-node".to_string(),
                ..Node::default()
            }),
            resource_names_subscribe: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DeltaDiscoveryRequest::default()
        })
        .await
        .unwrap();
    let mut delta_stream = delta_client
        .delta_aggregated_resources(authorize(
            tonic::Request::new(ReceiverStream::new(delta_rx)),
            &delta_token,
        ))
        .await
        .expect("delta ADS admission")
        .into_inner();

    // Let both producer tasks enqueue their initial response. Tonic may already
    // have placed that authorized-at-delivery response on the wire; regardless
    // of client-side buffering, revocation must be the terminal stream status.
    settle().await;
    verifier.replace(tenant_b_only_verifier());
    assert_eq!(
        wait_for_terminal_status(&mut sotw_stream).await,
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        wait_for_terminal_status(&mut delta_stream).await,
        tonic::Code::PermissionDenied
    );

    drop(sotw_tx);
    drop(delta_tx);
    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn namespace_binding_narrowing_revokes_stream_using_the_old_ceiling() {
    let verifier = Arc::new(CpDpVerifierStore::new(tenant_a_broad_verifier()));
    let (addr, handle) = start_all_stream_surfaces(verifier.clone(), Duration::from_secs(5)).await;
    let token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a-old-ceiling",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, token);
    let mut stream = client
        .subscribe(tonic::Request::new(subscribe_request(
            "dp-a-old-ceiling",
            TENANT_B,
        )))
        .await
        .expect("the original broad namespace policy must admit the stream")
        .into_inner();
    stream
        .message()
        .await
        .expect("initial response must be readable")
        .expect("initial snapshot must be present");

    verifier.replace(two_tenant_verifier());
    assert_eq!(
        wait_for_terminal_status(&mut stream).await,
        tonic::Code::PermissionDenied
    );

    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn accepted_token_expiry_closes_stream_without_heartbeat_extension() {
    let verifier = Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()));
    let (addr, handle) = start_all_stream_surfaces(verifier, Duration::from_secs(5)).await;
    let config_token = mint_with_exp(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "expiring-config-node",
        Some(json!(TENANT_A)),
        None,
        Utc::now().timestamp() - 58,
    );
    let mut config_client = configsync_client!(addr, config_token);
    let mut config_stream = config_client
        .subscribe(tonic::Request::new(subscribe_request(
            "expiring-config-node",
            TENANT_A,
        )))
        .await
        .expect("token inside verifier leeway must be admitted")
        .into_inner();
    assert_eq!(
        wait_for_terminal_status(&mut config_stream).await,
        tonic::Code::Unauthenticated
    );

    for (node_id, remote, audience) in [
        (
            "expiring-mesh-local-node",
            false,
            MESH_LOCAL_SUBSCRIBE_AUDIENCE.to_string(),
        ),
        (
            "expiring-mesh-remote-node",
            true,
            remote_discovery_audience("test-cluster"),
        ),
    ] {
        let mesh_token = mint_with_exp(
            TENANT_A_SECRET,
            Some(TENANT_A),
            node_id,
            Some(json!(TENANT_A)),
            Some(&audience),
            Utc::now().timestamp() - 58,
        );
        let mut mesh_client = mesh_client!(addr, mesh_token);
        let mut mesh_stream = mesh_client
            .mesh_subscribe(tonic::Request::new(mesh_subscribe_request(
                node_id, TENANT_A, remote,
            )))
            .await
            .expect("mesh token inside verifier leeway must be admitted")
            .into_inner();
        assert_eq!(
            wait_for_terminal_status(&mut mesh_stream).await,
            tonic::Code::Unauthenticated
        );
    }

    let sotw_token = mint_with_exp(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "expiring-xds-sotw-node",
        Some(json!(TENANT_A)),
        None,
        Utc::now().timestamp() - 58,
    );
    let mut sotw_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (sotw_tx, sotw_rx) = mpsc::channel(2);
    sotw_tx
        .send(DiscoveryRequest {
            node: Some(Node {
                id: "expiring-xds-sotw-node".to_string(),
                ..Node::default()
            }),
            resource_names: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DiscoveryRequest::default()
        })
        .await
        .unwrap();
    let mut sotw_stream = sotw_client
        .stream_aggregated_resources(authorize(
            tonic::Request::new(ReceiverStream::new(sotw_rx)),
            &sotw_token,
        ))
        .await
        .expect("SotW token inside verifier leeway must be admitted")
        .into_inner();
    assert_eq!(
        wait_for_terminal_status(&mut sotw_stream).await,
        tonic::Code::Unauthenticated
    );
    drop(sotw_tx);

    let delta_token = mint_with_exp(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "expiring-xds-delta-node",
        Some(json!(TENANT_A)),
        None,
        Utc::now().timestamp() - 58,
    );
    let mut delta_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (delta_tx, delta_rx) = mpsc::channel(2);
    delta_tx
        .send(DeltaDiscoveryRequest {
            node: Some(Node {
                id: "expiring-xds-delta-node".to_string(),
                ..Node::default()
            }),
            resource_names_subscribe: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DeltaDiscoveryRequest::default()
        })
        .await
        .unwrap();
    let mut delta_stream = delta_client
        .delta_aggregated_resources(authorize(
            tonic::Request::new(ReceiverStream::new(delta_rx)),
            &delta_token,
        ))
        .await
        .expect("delta token inside verifier leeway must be admitted")
        .into_inner();
    assert_eq!(
        wait_for_terminal_status(&mut delta_stream).await,
        tonic::Code::Unauthenticated
    );
    drop(delta_tx);

    handle.abort();
}

// ── The core cross-tenant forgery, per surface ───────────────────────────

/// ConfigSync `Subscribe`: tenant A signs an otherwise-valid tenant-B token
/// with the credential it actually holds. The CP must refuse before any
/// snapshot is serialized.
#[tokio::test(flavor = "multi_thread")]
async fn configsync_refuses_tenant_a_credential_signing_a_tenant_b_claim() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    // Sanity: the same credential works for its OWN tenant, so the refusal
    // below is about the namespace binding and not a broken fixture.
    let own = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_A)),
        None,
    );
    let mut client = configsync_client!(addr, own);
    let mut stream = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect("tenant A must reach its own namespace")
        .into_inner();
    let first = timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("snapshot within 5s")
        .expect("stream ok")
        .expect("snapshot present");
    assert!(
        !first.config_json.contains("tenant-b"),
        "tenant A's own snapshot must not carry tenant B state"
    );

    // The attack: same installed secret, `ns` rewritten to tenant B. The
    // signature is valid — that was never the boundary.
    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, forged);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("forged tenant-B subscription must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // Naming tenant B's `kid` does not help either: selection is not a grant,
    // and tenant A does not hold tenant B's key.
    let wrong_kid = mint(
        TENANT_A_SECRET,
        Some(TENANT_B),
        "dp-a",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, wrong_kid);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("selecting tenant B's kid without its key must fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    handle.abort();
}

/// `GetFullConfig` shares the authorization seam with `Subscribe`; pin it
/// separately so a future refactor cannot leave the unary surface behind.
#[tokio::test(flavor = "multi_thread")]
async fn get_full_config_refuses_cross_tenant_forgery() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_B)),
        None,
    );
    let mut client = configsync_client!(addr, forged);
    let err = client
        .get_full_config(tonic::Request::new(
            ferrum_edge::grpc::proto::FullConfigRequest {
                node_id: "dp-a".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: TENANT_B.to_string(),
                real_ip_header: Some(String::new()),
            },
        ))
        .await
        .expect_err("forged tenant-B GetFullConfig must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// Native `MeshSubscribe`: same forgery, same refusal — and specifically
/// before any mesh slice (which carries the tenant's service inventory and
/// trust bundle) is serialized.
#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_refuses_tenant_a_credential_signing_a_tenant_b_claim() {
    let (addr, handle) = start_mesh(two_tenant_bundle()).await;

    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "mesh-a",
        Some(json!(TENANT_B)),
        Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
    );
    let mut client = mesh_client!(addr, forged);
    let err = client
        .mesh_subscribe(tonic::Request::new(
            ferrum_edge::grpc::proto::MeshSubscribeRequest {
                node_id: "mesh-a".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: TENANT_B.to_string(),
                workload_spiffe_id: String::new(),
                labels: HashMap::new(),
                waypoint_name: String::new(),
                ambient_udp_source_scoping: false,
                node_waypoint_capture_scoping: false,
                remote_discovery: false,
            },
        ))
        .await
        .expect_err("forged tenant-B MeshSubscribe must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// xDS ADS has no namespace request field, so the tenant identity comes purely
/// from the resolved namespace set. A tenant-A credential asserting tenant B
/// must never produce a tenant-B snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn xds_refuses_tenant_a_credential_signing_a_tenant_b_claim() {
    let (addr, handle) = start_xds(two_tenant_bundle()).await;

    let forged = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "xds-a",
        Some(json!(TENANT_B)),
        None,
    );
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(
            channel,
        );
    let requests = tokio_stream::iter(vec![ferrum_edge::xds::proto::DiscoveryRequest {
        version_info: String::new(),
        node: Some(ferrum_edge::xds::proto::Node {
            id: "xds-a".to_string(),
            cluster: String::new(),
            metadata: Vec::new(),
        }),
        resource_names: vec!["*".to_string()],
        type_url: LDS_TYPE_URL.to_string(),
        response_nonce: String::new(),
        error_detail: None,
    }]);
    let mut request = tonic::Request::new(requests);
    request.metadata_mut().insert(
        "authorization",
        tonic::metadata::MetadataValue::try_from(format!("Bearer {forged}")).unwrap(),
    );
    let err = client
        .stream_aggregated_resources(request)
        .await
        .expect_err("forged tenant-B ADS stream must be refused before serialization");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

// ── Shared-CA mTLS: a valid certificate is not namespace authorization ───

/// A certificate issued by the CA both tenants share proves the peer is
/// *some* member of the mesh. It must not, on its own, authorize a namespace,
/// and it must never widen what a credential permits.
///
/// Driven at the authorization seam rather than over a real TLS handshake:
/// the peer scope is exactly what the CP gRPC listener derives from a verified
/// leaf, so injecting it directly is the same input with less ceremony.
#[test]
fn shared_ca_peer_identity_cannot_widen_or_authorize_alone() {
    use ferrum_edge::grpc::cp_trust::resolve_authorized_namespaces;
    use std::collections::HashSet;

    let bound: HashSet<String> = [TENANT_A.to_string()].into_iter().collect();
    let peer_b = PeerNamespaceScope::single(TENANT_B);
    let claim_b: HashSet<String> = [TENANT_B.to_string()].into_iter().collect();

    // Tenant A's credential + a (mis-issued or stolen) tenant-B SPIFFE peer:
    // the intersection is empty, so this is refused rather than granted.
    assert!(
        resolve_authorized_namespaces(Some(&bound), Some(&peer_b), Some(&claim_b)).is_err(),
        "a peer certificate must not widen a credential's namespace binding"
    );

    // Tenant A's credential + tenant A's peer identity + no claim: authorized
    // for exactly tenant A.
    let peer_a = PeerNamespaceScope::single(TENANT_A);
    let resolved = resolve_authorized_namespaces(Some(&bound), Some(&peer_a), None)
        .expect("matching peer identity resolves")
        .expect("bundle mode always resolves a set");
    assert_eq!(resolved, bound);

    // A peer identity NARROWS a broader credential.
    let broad: HashSet<String> = [TENANT_A.to_string(), TENANT_B.to_string()]
        .into_iter()
        .collect();
    let narrowed = resolve_authorized_namespaces(Some(&broad), Some(&peer_a), None)
        .expect("peer narrows")
        .expect("set present");
    assert_eq!(narrowed, bound);

    // A peer whose certificate encodes no SPIFFE namespace contributes
    // nothing — it cannot widen, and it cannot substitute for a credential.
    let unchanged = resolve_authorized_namespaces(Some(&broad), None, None)
        .expect("no peer evidence")
        .expect("set present");
    assert_eq!(unchanged, broad);
}

/// The connect-info the listener attaches defaults to "no evidence", so a
/// plaintext or non-SPIFFE connection can never be mistaken for authorization.
#[test]
fn default_connect_info_carries_no_namespace_evidence() {
    let info = CpGrpcConnectInfo::default();
    assert!(info.peer_namespace_scope.is_none());
}

// ── Key selection, malformed, and ambiguous bundles ──────────────────────

/// A token with no `kid` cannot select a credential deterministically, so a
/// trust-bundle CP refuses it rather than guessing.
#[tokio::test(flavor = "multi_thread")]
async fn trust_bundle_cp_refuses_a_token_with_no_key_id() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let no_kid = mint(TENANT_A_SECRET, None, "dp-a", Some(json!(TENANT_A)), None);
    let mut client = configsync_client!(addr, no_kid);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect_err("a kid-less token must be refused by a trust-bundle CP");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(
        !err.message().contains(TENANT_A_SECRET),
        "rejection must never echo credential material"
    );

    handle.abort();
}

/// An unknown `kid` is refused, and the refusal discloses nothing about which
/// credentials the control plane actually trusts.
#[tokio::test(flavor = "multi_thread")]
async fn trust_bundle_cp_refuses_an_unknown_key_id_without_disclosure() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let unknown = mint(
        TENANT_A_SECRET,
        Some("tenant-z"),
        "dp-a",
        Some(json!(TENANT_A)),
        None,
    );
    let mut client = configsync_client!(addr, unknown);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect_err("an unknown kid must be refused");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let message = err.message();
    assert!(
        !message.contains(TENANT_A) && !message.contains(TENANT_B),
        "rejection must not enumerate the trusted key inventory, got: {message}"
    );

    handle.abort();
}

/// The bearer may only narrow: an array claim listing both tenants resolves to
/// the credential's single bound namespace, not to both.
#[tokio::test(flavor = "multi_thread")]
async fn multi_namespace_claim_cannot_widen_a_single_namespace_credential() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let greedy = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "dp-a",
        Some(json!([TENANT_A, TENANT_B])),
        None,
    );
    let mut client = configsync_client!(addr, greedy.clone());
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("a widened claim must not reach tenant B");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // The same token still works for the namespace it is genuinely bound to.
    let mut client = configsync_client!(addr, greedy);
    client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect("the bound namespace remains reachable");

    handle.abort();
}

/// A claim disjoint from the credential's binding resolves to nothing, and is
/// refused at authentication rather than producing a silently empty allow-set.
#[test]
fn disjoint_claim_resolves_to_no_authorized_namespace() {
    use ferrum_edge::grpc::cp_trust::resolve_authorized_namespaces;
    use std::collections::HashSet;

    let bound: HashSet<String> = [TENANT_A.to_string()].into_iter().collect();
    let claim: HashSet<String> = ["tenant-c".to_string()].into_iter().collect();
    let reason = resolve_authorized_namespaces(Some(&bound), None, Some(&claim))
        .expect_err("a disjoint claim must fail closed");
    assert_eq!(reason.as_metric_label(), "no_authorized_namespace");
}

// ── Trust-bundle document validation (fail-closed configuration) ─────────

#[test]
fn duplicate_key_ids_are_refused_as_ambiguous_selection() {
    let document = json!({
        "keys": [
            { "kid": "dup", "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
            { "kid": "dup", "algorithm": "HS256", "secret": TENANT_B_SECRET,
              "namespaces": [TENANT_B] },
        ]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "dup-bundle", None)
        .expect_err("duplicate kids must be refused");
    assert!(error.contains("duplicate kid"), "got: {error}");
}

#[test]
fn malformed_bundles_are_refused_without_echoing_material() {
    let cases: Vec<(serde_json::Value, &str)> = vec![
        (json!({ "keys": [] }), "declares no keys"),
        (
            json!({ "keys": [{ "kid": "", "algorithm": "HS256", "secret": TENANT_A_SECRET,
                               "namespaces": [TENANT_A] }] }),
            "non-empty `kid`",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "NOPE", "secret": TENANT_A_SECRET,
                               "namespaces": [TENANT_A] }] }),
            "unsupported algorithm",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256", "secret": TENANT_A_SECRET,
                               "namespaces": [] }] }),
            "at least one namespace",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256", "secret": "too-short",
                               "namespaces": [TENANT_A] }] }),
            "at least 32 bytes",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256",
                               "namespaces": [TENANT_A] }] }),
            "exactly one of",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "HS256", "secret": TENANT_A_SECRET,
                               "public_key_pem": "x", "namespaces": [TENANT_A] }] }),
            "exactly one of",
        ),
        (
            json!({ "keys": [{ "kid": "k", "algorithm": "ES256", "secret": TENANT_A_SECRET,
                               "namespaces": [TENANT_A] }] }),
            "symmetric secret material",
        ),
        (
            json!({ "version": 99, "keys": [{ "kid": "k", "algorithm": "HS256",
                    "secret": TENANT_A_SECRET, "namespaces": [TENANT_A] }] }),
            "unsupported version",
        ),
    ];

    for (document, expected) in cases {
        let raw = document.to_string();
        let error = CpDpTrustBundle::from_document_str(&raw, "bad-bundle", None)
            .expect_err("malformed bundle must be refused");
        assert!(
            error.contains(expected),
            "expected {expected:?} in error, got: {error}"
        );
        assert!(
            !error.contains(TENANT_A_SECRET) && !error.contains("too-short"),
            "startup errors must not echo secret material, got: {error}"
        );
    }
}

#[test]
fn trust_bundle_and_file_backed_material_reads_are_bounded_regular_files() {
    const FILE_LIMIT: usize = 1024 * 1024;

    let dir = tempfile::tempdir().expect("create bounded-read fixture directory");
    let oversized = vec![b'x'; FILE_LIMIT + 1];

    let bundle_path = dir.path().join("oversized-bundle.json");
    std::fs::write(&bundle_path, &oversized).expect("write oversized bundle fixture");
    let error = CpDpTrustBundle::load_from_path(
        bundle_path.to_str().expect("UTF-8 bundle fixture path"),
        None,
    )
    .expect_err("an oversized trust bundle must be refused before parsing");
    assert!(error.contains("above the 1048576-byte limit"), "{error}");

    let secret_path = dir.path().join("oversized-secret");
    std::fs::write(&secret_path, &oversized).expect("write oversized secret fixture");
    // A syntactically valid digest: the bounded read must reject the file
    // before integrity verification ever gets the chance to allocate it.
    let document = json!({
        "keys": [{
            "kid": "bounded-secret",
            "algorithm": "HS256",
            "secret_path": secret_path.display().to_string(),
            "material_sha256": sha256_hex(b"never-read"),
            "namespaces": [TENANT_A]
        }]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "bounded-material-test", None)
        .expect_err("oversized file-backed material must be refused");
    assert!(error.contains("above the 1048576-byte limit"), "{error}");

    let non_file_path = dir.path().join("material-directory");
    std::fs::create_dir(&non_file_path).expect("create non-file material fixture");
    let document = json!({
        "keys": [{
            "kid": "regular-file-only",
            "algorithm": "HS256",
            "secret_path": non_file_path.display().to_string(),
            "material_sha256": sha256_hex(b"never-read"),
            "namespaces": [TENANT_A]
        }]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "regular-material-test", None)
        .expect_err("non-regular file-backed material must be refused");
    assert!(error.contains("is not a regular file"), "{error}");
}

#[tokio::test]
async fn trust_bundle_reload_times_out_without_accumulating_detached_readers() {
    let dir = tempfile::tempdir().expect("create reload-reader fixture directory");
    let bundle_path = dir.path().join("trust-bundle.json");
    std::fs::write(
        &bundle_path,
        json!({
            "version": 1,
            "keys": [{
                "kid": TENANT_A,
                "algorithm": "HS256",
                "secret": TENANT_A_SECRET,
                "namespaces": [TENANT_A]
            }]
        })
        .to_string(),
    )
    .expect("write valid trust-bundle fixture");

    let permit =
        ferrum_edge::_test_support::acquire_cp_dp_trust_bundle_read_permit_for_test().await;
    assert_eq!(
        ferrum_edge::_test_support::load_cp_dp_trust_bundle_for_reload_for_test(
            bundle_path.to_string_lossy().into_owned(),
            Duration::from_millis(50),
        )
        .await
        .expect_err("the occupied reader must time out"),
        "reload_read_timed_out"
    );

    drop(permit);
    ferrum_edge::_test_support::load_cp_dp_trust_bundle_for_reload_for_test(
        bundle_path.to_string_lossy().into_owned(),
        Duration::from_secs(1),
    )
    .await
    .expect("valid trust bundle must load after the detached-reader slot is released");
}

/// A bound credential backed by the fleet-wide `FERRUM_CP_DP_GRPC_JWT_SECRET`
/// is structurally valid but semantically identical to the pre-advisory
/// posture: every data plane already holds that value, so any of them could
/// name this `kid` and reach its namespaces. Loading must refuse it — by
/// variable name for `secret_env`, and by resolved bytes for `secret` /
/// `secret_path`.
#[test]
fn fleet_secret_backed_credentials_are_refused() {
    const FLEET: &str = "fleet-wide-cp-dp-secret-2026-ferrum-edge";

    // Inline material equal to the effective fleet secret.
    let document = json!({
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": FLEET,
              "namespaces": [TENANT_A] },
        ]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "fleet-bundle", Some(FLEET))
        .expect_err("a credential backed by the fleet secret must be refused");
    assert!(error.contains("GHSA-3f2j-wwqw-grmg"), "got: {error}");
    assert!(
        !error.contains(FLEET),
        "the refusal must not echo the secret, got: {error}"
    );

    // `secret_env` naming the fleet variable is refused by name, even when the
    // effective fleet secret was configured through `ferrum.conf` and is not
    // available for a by-value comparison.
    let document = json!({
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256",
              "secret_env": "FERRUM_CP_DP_GRPC_JWT_SECRET",
              "namespaces": [TENANT_A] },
        ]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "fleet-env-bundle", None)
        .expect_err("secret_env naming the fleet variable must be refused");
    assert!(error.contains("GHSA-3f2j-wwqw-grmg"), "got: {error}");

    // File-backed material is compared after the loader trims the customary
    // trailing newline. A copied or symlinked fleet secret must not evade the
    // same by-value refusal merely because it came from `secret_path`.
    let dir = tempfile::tempdir().expect("temporary trust-bundle material");
    let secret_path = dir.path().join("fleet-secret");
    std::fs::write(&secret_path, format!("{FLEET}\n")).expect("write fleet-secret fixture");
    let document = json!({
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256",
              "secret_path": secret_path.display().to_string(),
              "material_sha256": sha256_hex(format!("{FLEET}\n").as_bytes()),
              "namespaces": [TENANT_A] },
        ]
    })
    .to_string();
    let error = CpDpTrustBundle::from_document_str(&document, "fleet-path-bundle", Some(FLEET))
        .expect_err("secret_path carrying the fleet secret must be refused");
    assert!(error.contains("GHSA-3f2j-wwqw-grmg"), "got: {error}");
    assert!(
        !error.contains(FLEET),
        "the file-backed refusal must not echo the secret, got: {error}"
    );

    // A distinct per-tenant secret still loads with the fleet secret present.
    let document = json!({
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
        ]
    })
    .to_string();
    CpDpTrustBundle::from_document_str(&document, "distinct-bundle", Some(FLEET))
        .expect("a per-tenant secret distinct from the fleet secret must load");
}

// ── Fail-closed startup ──────────────────────────────────────────────────

/// A multi-namespace control plane must refuse the fleet-wide self-minting
/// secret outright. There is no unsafe override.
#[test]
fn multi_namespace_startup_refuses_the_fleet_wide_secret() {
    let legacy = CpDpVerifier::SharedSecret(TENANT_A_SECRET.to_string());
    let error = legacy
        .validate_for_scope(true)
        .expect_err("multi-namespace CP must refuse the fleet-wide secret");
    assert!(error.contains("GHSA-3f2j-wwqw-grmg"), "got: {error}");
    assert!(
        !error.contains(TENANT_A_SECRET),
        "startup refusal must not echo the secret"
    );

    // Single-namespace stays usable: there is no second tenant to cross into.
    legacy
        .validate_for_scope(false)
        .expect("single-namespace CP keeps the legacy secret");

    // A trust bundle satisfies both.
    let bundle = two_tenant_bundle();
    bundle
        .validate_for_scope(true)
        .expect("a trust bundle is accepted for multi-namespace scope");
    assert!(bundle.has_namespace_binding());
    assert!(
        !bundle.describe().contains(TENANT_A_SECRET),
        "the startup description must not render material"
    );
}

/// `Debug` on the verifier is a disclosure surface (panics, `{:#?}` in
/// diagnostics). It must never render key material.
#[test]
fn verifier_debug_never_renders_material() {
    let legacy = CpDpVerifier::SharedSecret(TENANT_A_SECRET.to_string());
    let rendered = format!("{legacy:#?}");
    assert!(!rendered.contains(TENANT_A_SECRET), "got: {rendered}");

    let bundle = two_tenant_bundle();
    let rendered = format!("{bundle:#?}");
    assert!(
        !rendered.contains(TENANT_A_SECRET) && !rendered.contains(TENANT_B_SECRET),
        "got: {rendered}"
    );
}

/// An empty shared secret must never verify anything.
///
/// Every CP gRPC server builder seeds itself with
/// `CpDpVerifier::SharedSecret(jwt_secret)` before the caller overrides it, and
/// a trust-bundle control plane threads
/// `cp_dp_grpc_jwt_secret.unwrap_or_default()` — an empty string — into those
/// builders so cross-cluster remote discovery can still mint. A call site that
/// forgot `.verifier_store(..)` would then verify against the empty HS256 key,
/// which every caller can reproduce. The verifier itself refuses instead.
#[test]
fn empty_shared_secret_never_verifies() {
    let empty = CpDpVerifier::SharedSecret(String::new());
    assert!(
        empty
            .with_decoding_key(None, Algorithm::HS256, |_, _, _, _| ())
            .is_err(),
        "an empty shared secret must not produce a usable decoding key"
    );

    // The non-empty secret still works, so this is a guard and not a
    // regression of the supported single-namespace legacy posture.
    let legacy = CpDpVerifier::SharedSecret(TENANT_A_SECRET.to_string());
    assert!(
        legacy
            .with_decoding_key(None, Algorithm::HS256, |_, _, _, _| ())
            .is_ok(),
        "a configured shared secret must still verify"
    );
}

// ── Claim presence vs server-derived effective set ───────────────────────

/// A trust-bundle credential with `kid` but no `ns` claim must not satisfy the
/// automatic multi-namespace claim requirement on ConfigSync — even though the
/// credential binding alone would produce a non-empty effective set.
#[tokio::test(flavor = "multi_thread")]
async fn configsync_rejects_trust_bundle_token_with_kid_but_no_ns_claim() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let no_ns = mint(TENANT_A_SECRET, Some(TENANT_A), "dp-a", None, None);
    let mut client = configsync_client!(addr, no_ns);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect_err("missing ns claim must be refused on multi-namespace ConfigSync");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(
        err.message().contains("ns"),
        "refusal should name the missing claim, got: {}",
        err.message()
    );

    handle.abort();
}

/// Native MeshSubscribe shares the same claim-presence contract.
#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_rejects_trust_bundle_token_with_kid_but_no_ns_claim() {
    let (addr, handle) = start_mesh(two_tenant_bundle()).await;

    let no_ns = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "mesh-a",
        None,
        Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
    );
    let mut client = mesh_client!(addr, no_ns);
    let err = client
        .mesh_subscribe(tonic::Request::new(
            ferrum_edge::grpc::proto::MeshSubscribeRequest {
                node_id: "mesh-a".to_string(),
                ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
                namespace: TENANT_A.to_string(),
                workload_spiffe_id: String::new(),
                labels: HashMap::new(),
                waypoint_name: String::new(),
                ambient_udp_source_scoping: false,
                node_waypoint_capture_scoping: false,
                remote_discovery: false,
            },
        ))
        .await
        .expect_err("missing ns claim must be refused on multi-namespace MeshSubscribe");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// xDS ADS under `CpScope::All` with a single-namespace-bound credential and no
/// `ns` claim: the effective set is a sole namespace, which the pre-fix model
/// misread as a present claim. Must stay PermissionDenied.
#[tokio::test(flavor = "multi_thread")]
async fn xds_all_scope_rejects_bound_credential_without_ns_claim() {
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (_cp, update_tx) = CpGrpcServer::builder(cfg_arc.clone(), TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .scope(CpScope::All)
        .build();
    let server = XdsAdsServer::new(
        cfg_arc,
        update_tx,
        TENANT_A_SECRET.to_string(),
        TEST_ISSUER.to_string(),
        TENANT_A.to_string(),
        32,
    )
    .with_verifier_store(fixed_verifier_store(two_tenant_bundle()))
    .with_scope(CpScope::All);
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("xDS server failed");
    });
    settle().await;

    let no_ns = mint(TENANT_A_SECRET, Some(TENANT_A), "xds-a", None, None);
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        ferrum_edge::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(
            channel,
        );
    let requests = tokio_stream::iter(vec![ferrum_edge::xds::proto::DiscoveryRequest {
        version_info: String::new(),
        node: Some(ferrum_edge::xds::proto::Node {
            id: "xds-a".to_string(),
            cluster: String::new(),
            metadata: Vec::new(),
        }),
        resource_names: vec!["*".to_string()],
        type_url: LDS_TYPE_URL.to_string(),
        response_nonce: String::new(),
        error_detail: None,
    }]);
    let mut request = tonic::Request::new(requests);
    request.metadata_mut().insert(
        "authorization",
        tonic::metadata::MetadataValue::try_from(format!("Bearer {no_ns}")).unwrap(),
    );
    let err = client
        .stream_aggregated_resources(request)
        .await
        .expect_err("missing ns claim must not be satisfied by a sole bound namespace");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    handle.abort();
}

/// Single-scope CP with `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` rejects a
/// trust-bound token that carries `kid` but no `ns`, even though the effective
/// set would otherwise authorize the sole namespace.
#[tokio::test(flavor = "multi_thread")]
async fn single_scope_require_ns_claim_rejects_token_without_ns() {
    let verifier = single_tenant_bundle();
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (server, _tx) = CpGrpcServer::builder(cfg_arc, TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(DpNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier_store(fixed_verifier_store(verifier))
        .scope(CpScope::Single(TENANT_A.to_string()))
        .require_ns_claim(true)
        .real_ip_header(None)
        .build();
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("ConfigSync server failed");
    });
    settle().await;

    let no_ns = mint(TENANT_A_SECRET, Some(TENANT_A), "dp-a", None, None);
    let mut client = configsync_client!(addr, no_ns);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect_err("require_ns_claim=true must refuse a missing claim");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(
        err.message().contains("FERRUM_CP_REQUIRE_NAMESPACE_CLAIM"),
        "got: {}",
        err.message()
    );

    handle.abort();
}

/// Single-scope + `require_ns_claim=false` keeps the compatible path: a token
/// with `kid` and no `ns` is accepted, but the credential bound still applies
/// (the bearer cannot reach a namespace outside the intersected set).
#[tokio::test(flavor = "multi_thread")]
async fn single_scope_without_require_accepts_no_ns_but_applies_bound() {
    let verifier = single_tenant_bundle();
    let cfg_arc = Arc::new(ArcSwap::new(Arc::new(tenant_marked_config())));
    let (server, _tx) = CpGrpcServer::builder(cfg_arc, TENANT_A_SECRET.to_string())
        .channel_capacity(64)
        .registry(Arc::new(DpNodeRegistry::new()))
        .expected_issuer(TEST_ISSUER.to_string())
        .verifier_store(fixed_verifier_store(verifier))
        .scope(CpScope::Single(TENANT_A.to_string()))
        .require_ns_claim(false)
        .real_ip_header(None)
        .build();
    let (listener, addr) = bind_loopback().await;
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("ConfigSync server failed");
    });
    settle().await;

    let no_ns = mint(TENANT_A_SECRET, Some(TENANT_A), "dp-a", None, None);
    let mut client = configsync_client!(addr, no_ns.clone());
    client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
        .await
        .expect("single-scope require=false accepts a missing claim for the bound namespace");

    // Asking for a namespace outside the credential bound (and outside the
    // single CP scope) remains refused.
    let mut client = configsync_client!(addr, no_ns);
    let err = client
        .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_B)))
        .await
        .expect_err("bound/scope must still refuse an out-of-scope namespace");
    assert!(
        err.code() == tonic::Code::PermissionDenied
            || err.code() == tonic::Code::FailedPrecondition,
        "got {:?}",
        err.code()
    );

    handle.abort();
}

/// Admin JWT `AllowedNamespaces::is_present()` tracks claim presence only —
/// unchanged by the CP/DP server-derived ceiling split.
#[test]
fn admin_allowed_namespaces_is_present_tracks_claim_only() {
    use ferrum_edge::grpc::auth::AllowedNamespaces;
    use std::collections::HashSet;

    // Admin has no server-derived ceiling: empty == missing claim.
    assert!(!AllowedNamespaces::empty().is_present());
    assert!(!AllowedNamespaces::empty().allows("prod"));

    // Claimed (including present-but-empty) keeps is_present == true.
    let mut set = HashSet::new();
    set.insert("prod".to_string());
    let claimed = AllowedNamespaces::claimed(set);
    assert!(claimed.is_present());
    assert!(claimed.allows("prod"));
    assert!(!claimed.allows("staging"));

    let empty_claim = AllowedNamespaces::claimed(HashSet::new());
    assert!(empty_claim.is_present());
    assert!(!empty_claim.allows("prod"));
}

// ── Outward authentication failure non-disclosure ────────────────────────

/// Unknown `kid`, known `kid` with a wrong signature, and known `kid` with a
/// wrong algorithm must produce identical public Status messages so an
/// unauthenticated caller cannot enumerate the trusted key inventory.
#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_failures_do_not_disclose_key_inventory() {
    let (addr, handle) = start_configsync(two_tenant_bundle()).await;

    let unknown_kid = mint(
        TENANT_A_SECRET,
        Some("tenant-z"),
        "dp-a",
        Some(json!(TENANT_A)),
        None,
    );
    let wrong_sig = mint(
        "wrong-secret-that-is-long-enough-32b!",
        Some(TENANT_A),
        "dp-a",
        Some(json!(TENANT_A)),
        None,
    );
    let wrong_alg = {
        let now = Utc::now().timestamp();
        let claims = json!({
            "sub": "dp-a",
            "iat": now,
            "exp": now + 600,
            "iss": TEST_ISSUER,
            "role": "data_plane",
            "ns": TENANT_A,
        });
        // Header claims HS384 while the trust-bundle credential is HS256.
        let mut header = Header::new(Algorithm::HS384);
        header.kid = Some(TENANT_A.to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(TENANT_A_SECRET.as_bytes()),
        )
        .expect("test JWT must encode")
    };

    let mut messages = Vec::new();
    for token in [unknown_kid, wrong_sig, wrong_alg] {
        let mut client = configsync_client!(addr, token);
        let err = client
            .subscribe(tonic::Request::new(subscribe_request("dp-a", TENANT_A)))
            .await
            .expect_err("forged/unknown credential must be unauthenticated");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        let message = err.message().to_string();
        assert!(
            !message.contains(TENANT_A)
                && !message.contains(TENANT_B)
                && !message.contains(TENANT_A_SECRET)
                && !message.contains("HS256")
                && !message.contains("HS384")
                && !message.contains("tenant-z"),
            "public rejection must not echo kid/alg/secret inventory, got: {message}"
        );
        messages.push(message);
    }

    assert_eq!(
        messages[0], messages[1],
        "unknown kid and wrong signature must share one public message"
    );
    assert_eq!(
        messages[0], messages[2],
        "unknown kid and wrong algorithm must share one public message"
    );
    assert_eq!(messages[0], "Invalid token: authentication failed");

    // Internal labels remain distinct (closed fixed-cardinality set).
    use ferrum_edge::grpc::cp_trust::TenantAuthRejectReason;
    assert_eq!(
        TenantAuthRejectReason::UnknownKeyId.as_status_message(),
        TenantAuthRejectReason::AlgorithmMismatch.as_status_message()
    );
    assert_eq!(
        TenantAuthRejectReason::UnknownKeyId.as_status_message(),
        TenantAuthRejectReason::TokenValidation.as_status_message()
    );
    assert_ne!(
        TenantAuthRejectReason::UnknownKeyId.as_metric_label(),
        TenantAuthRejectReason::AlgorithmMismatch.as_metric_label()
    );
    assert_ne!(
        TenantAuthRejectReason::UnknownKeyId.as_metric_label(),
        TenantAuthRejectReason::TokenValidation.as_metric_label()
    );

    handle.abort();
}

fn single_tenant_bundle() -> Arc<CpDpVerifier> {
    let document = json!({
        "version": 1,
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
        ]
    })
    .to_string();
    let bundle = CpDpTrustBundle::from_document_str(&document, "single-tenant-bundle", None)
        .expect("single-tenant bundle must load");
    Arc::new(CpDpVerifier::TrustBundle(bundle))
}

// ── Coherent source-generation loading (issue #3814) ─────────────────────
//
// The trust bundle is the server-derived multi-tenant authorization boundary.
// Reading the document from one filesystem generation and then independently
// re-resolving each `secret_path` / `public_key_path` let a Kubernetes
// projected-Secret rotation pair one generation's namespace ceiling with
// another generation's key material. Both halves are individually valid, so the
// mixed result is internally self-consistent — neither the semantic fingerprint
// nor last-known-good retention could ever see it.

/// Lowercase hex SHA-256, exactly as `sha256sum` prints it and exactly what
/// `material_sha256` must contain.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// What a loaded bundle actually accepts for one `kid`: the namespace ceiling
/// it is bound to, and whether `secret` verifies under it.
///
/// A mixed generation is precisely a bundle whose two halves disagree, so both
/// values have to be asserted together — a namespace list alone cannot tell an
/// old policy paired with a new key from an honest old generation.
fn accepted_binding(verifier: &CpDpVerifier, kid: &str, secret: &str) -> (bool, Vec<String>) {
    let token = mint(secret, Some(kid), "coherence-probe", None, None);
    verifier
        .with_decoding_key(Some(kid), Algorithm::HS256, |key, alg, namespaces, _| {
            let mut validation = Validation::new(alg);
            validation.validate_exp = true;
            validation.validate_aud = false;
            validation.set_issuer(&[TEST_ISSUER]);
            let verified = decode::<serde_json::Value>(&token, key, &validation).is_ok();
            let mut bound: Vec<String> = namespaces
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default();
            bound.sort();
            (verified, bound)
        })
        .expect("the bundle must select the probed kid")
}

fn load_verifier(path: &str) -> CpDpVerifier {
    CpDpVerifier::TrustBundle(
        CpDpTrustBundle::load_from_path(path, None).expect("bundle must load"),
    )
}

/// An external (non-projected) trust-bundle fixture: an ordinary directory
/// where nothing can be pinned, so every referenced file must be bound by
/// `material_sha256`.
fn external_bundle(dir: &std::path::Path, document: serde_json::Value) -> String {
    let path = dir.join("trust-bundle.json");
    std::fs::write(&path, document.to_string()).expect("write external bundle fixture");
    path.to_str().expect("UTF-8 fixture path").to_string()
}

// ── Manifest-bound integrity for unpinnable sources ──────────────────────

/// A `secret_path` on an ordinary filesystem has no generation to be pinned
/// to. Without a manifest-bound digest nothing proves the bytes read belong to
/// the generation the document itself came from, so it is refused outright —
/// there is deliberately no unsafe compatibility opt-in.
#[test]
fn unpinnable_path_material_without_a_manifest_digest_is_refused() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let secret_path = dir.path().join("tenant-a.secret");
    std::fs::write(&secret_path, TENANT_A_SECRET).expect("write secret fixture");

    for (source, algorithm) in [("secret_path", "HS256"), ("public_key_path", "ES256")] {
        let mut entry = json!({
            "kid": TENANT_A,
            "algorithm": algorithm,
            "namespaces": [TENANT_A],
        });
        entry[source] = json!(secret_path.display().to_string());
        let path = external_bundle(dir.path(), json!({ "version": 1, "keys": [entry] }));

        let error = CpDpTrustBundle::load_coherent_from_path(&path, None)
            .expect_err("unbound path-backed material must be refused");
        assert_eq!(
            error.reason(),
            TrustBundleRejectReason::MaterialIntegrityUnbound,
            "{source}: {error}"
        );
        assert!(
            !error.to_string().contains(TENANT_A_SECRET),
            "the refusal must not echo material"
        );
    }
}

/// The digest is the binding, and it is checked for both material shapes.
#[test]
fn manifest_bound_digests_admit_matching_material_and_refuse_mismatches() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let secret_path = dir.path().join("tenant-a.secret");
    std::fs::write(&secret_path, TENANT_A_SECRET).expect("write secret fixture");
    let public_key = es256_public_key_pem();
    let public_key_path = dir.path().join("tenant-b.pub");
    std::fs::write(&public_key_path, &public_key).expect("write public key fixture");

    let document = json!({
        "version": 1,
        "keys": [
            { "kid": TENANT_A, "algorithm": "HS256",
              "secret_path": secret_path.display().to_string(),
              "material_sha256": sha256_hex(TENANT_A_SECRET.as_bytes()),
              "namespaces": [TENANT_A] },
            { "kid": TENANT_B, "algorithm": "ES256",
              "public_key_path": public_key_path.display().to_string(),
              "material_sha256": sha256_hex(public_key.as_bytes()),
              "namespaces": [TENANT_B] },
        ]
    });
    let path = external_bundle(dir.path(), document);
    let bundle = CpDpTrustBundle::load_coherent_from_path(&path, None)
        .expect("digest-bound external material must load");
    assert_eq!(bundle.key_count(), 2);
    let verifier = CpDpVerifier::TrustBundle(bundle);
    assert_eq!(
        accepted_binding(&verifier, TENANT_A, TENANT_A_SECRET),
        (true, vec![TENANT_A.to_string()])
    );

    // Rotating the file without rotating the digest the document binds it to
    // is exactly the incoherent state the digest exists to catch.
    std::fs::write(&secret_path, TENANT_B_SECRET).expect("rewrite secret fixture");
    let error = CpDpTrustBundle::load_coherent_from_path(&path, None)
        .expect_err("material that does not match its bound digest must be refused");
    assert_eq!(
        error.reason(),
        TrustBundleRejectReason::MaterialIntegrityMismatch
    );
    let rendered = error.to_string();
    assert!(
        !rendered.contains(TENANT_A_SECRET)
            && !rendered.contains(TENANT_B_SECRET)
            && !rendered.contains(&sha256_hex(TENANT_A_SECRET.as_bytes())),
        "a mismatch must reveal neither the material nor either digest: {rendered}"
    );
}

/// The digest is parsed strictly. A binding that quietly accepts near-misses is
/// not a binding, and a permissive parse is an easy way to ship an inert one.
#[test]
fn manifest_bound_digests_are_parsed_strictly() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let secret_path = dir.path().join("tenant-a.secret");
    std::fs::write(&secret_path, TENANT_A_SECRET).expect("write secret fixture");
    let valid = sha256_hex(TENANT_A_SECRET.as_bytes());

    let malformed = [
        valid.to_uppercase(),
        format!("sha256:{valid}"),
        format!(" {valid}"),
        format!("{valid}\n"),
        valid[..63].to_string(),
        format!("{valid}0"),
        String::new(),
        "z".repeat(64),
    ];
    for digest in malformed {
        let path = external_bundle(
            dir.path(),
            json!({ "version": 1, "keys": [{
                "kid": TENANT_A, "algorithm": "HS256",
                "secret_path": secret_path.display().to_string(),
                "material_sha256": digest,
                "namespaces": [TENANT_A],
            }]}),
        );
        let error = CpDpTrustBundle::load_coherent_from_path(&path, None)
            .expect_err("a non-canonical digest must be refused");
        assert_eq!(
            error.reason(),
            TrustBundleRejectReason::MaterialIntegrityMalformed,
            "digest {digest:?} was not refused as malformed"
        );
    }
}

/// Inline and environment-backed material is read atomically with the document
/// (or from the process environment) and keeps its documented behavior: no
/// digest is required, and declaring one is a configuration error rather than a
/// silently ignored field.
#[test]
fn inline_and_environment_sources_retain_their_documented_behavior() {
    let dir = tempfile::tempdir().expect("fixture directory");

    let path = external_bundle(
        dir.path(),
        json!({ "version": 1, "keys": [
            { "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
              "namespaces": [TENANT_A] },
            { "kid": TENANT_B, "algorithm": "ES256",
              "public_key_pem": es256_public_key_pem(), "namespaces": [TENANT_B] },
        ]}),
    );
    let bundle = CpDpTrustBundle::load_coherent_from_path(&path, None)
        .expect("inline material must load with no digest");
    assert_eq!(bundle.key_count(), 2);

    let path = external_bundle(
        dir.path(),
        json!({ "version": 1, "keys": [{
            "kid": TENANT_A, "algorithm": "HS256", "secret": TENANT_A_SECRET,
            "material_sha256": sha256_hex(TENANT_A_SECRET.as_bytes()),
            "namespaces": [TENANT_A],
        }]}),
    );
    let error = CpDpTrustBundle::load_coherent_from_path(&path, None)
        .expect_err("a digest on inline material must be refused, not ignored");
    assert_eq!(error.reason(), TrustBundleRejectReason::DocumentInvalid);
}

/// Every coherence rejection reason is a distinct, bounded label. #3813
/// consumes this set; nothing here may be derived from file contents.
#[test]
fn trust_bundle_reject_reasons_are_a_closed_bounded_label_set() {
    let reasons = [
        TrustBundleRejectReason::DocumentUnreadable,
        TrustBundleRejectReason::DocumentInvalid,
        TrustBundleRejectReason::MaterialUnreadable,
        TrustBundleRejectReason::MaterialIntegrityUnbound,
        TrustBundleRejectReason::MaterialIntegrityMalformed,
        TrustBundleRejectReason::MaterialIntegrityMismatch,
        TrustBundleRejectReason::SourceGenerationEscape,
        TrustBundleRejectReason::SourceGenerationUnstable,
        TrustBundleRejectReason::SourceGenerationUnsupported,
    ];
    let labels: std::collections::HashSet<&str> = reasons
        .iter()
        .map(|reason| TrustReloadFailure::from_reject_reason(*reason).as_str())
        .collect();
    assert_eq!(labels.len(), reasons.len(), "labels must be distinct");
    for label in labels {
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{label} is not a metric-safe label"
        );
    }
}

/// A generated ES256 SPKI PEM, so `public_key_path` coverage exercises real
/// asymmetric parsing rather than a placeholder string.
fn es256_public_key_pem() -> String {
    use base64::Engine as _;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("ring generates a P-256 key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("generated PKCS#8 parses");
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key_pair.public_key().as_ref());

    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(&spki);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

// ── Kubernetes projected-generation coherence ────────────────────────────

#[cfg(unix)]
mod projected_generation {
    use super::*;

    /// A faithful replica of a Kubernetes projected ConfigMap/Secret volume.
    ///
    /// Per-file entries are stable symlinks `<name> -> ..data/<name>`; `..data`
    /// is itself a symlink to a per-generation directory, replaced by
    /// `rename(2)` so a rotation is atomic and never partially written. No
    /// partial write is needed to produce a mixed bundle — that is exactly why
    /// bounded reads and stability checks cannot see this defect.
    struct ProjectedMount {
        dir: tempfile::TempDir,
    }

    impl ProjectedMount {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().expect("projected mount fixture"),
            }
        }

        fn root(&self) -> &std::path::Path {
            self.dir.path()
        }

        /// The mount-visible path of a projected entry — what an operator
        /// writes into the bundle document.
        fn entry_path(&self, name: &str) -> String {
            self.root()
                .join(name)
                .to_str()
                .expect("UTF-8 mount path")
                .to_string()
        }

        fn bundle_path(&self) -> String {
            self.entry_path("bundle.json")
        }

        fn write_generation(&self, label: &str, files: &[(&str, String)]) {
            let dir = self.root().join(format!("..{label}"));
            std::fs::create_dir_all(&dir).expect("create generation directory");
            for (name, contents) in files {
                std::fs::write(dir.join(name), contents).expect("write generation file");
            }
        }

        /// Atomically point `..data` at one generation, exactly as the kubelet
        /// does: stage the replacement link under a scratch name and
        /// `rename(2)` it over the live one.
        fn activate(&self, label: &str) {
            let staged = self.root().join("..data_tmp");
            let _ = std::fs::remove_file(&staged);
            std::os::unix::fs::symlink(format!("..{label}"), &staged).expect("stage ..data");
            std::fs::rename(&staged, self.root().join("..data")).expect("swap ..data");
        }

        /// Publish the stable per-file entries. Written once; a rotation never
        /// rewrites them, it only moves `..data` underneath them.
        fn publish(&self, names: &[&str]) {
            for name in names {
                let link = self.root().join(name);
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(format!("..data/{name}"), &link)
                    .expect("publish projected entry");
            }
        }

        fn reclaim_generation(&self, label: &str) {
            std::fs::remove_dir_all(self.root().join(format!("..{label}")))
                .expect("reclaim generation directory");
        }
    }

    /// One credential slot whose namespace binding and key material rotate
    /// together — the issue's cross-tenant scenario verbatim.
    fn slot_document(mount: &ProjectedMount, namespace: &str) -> String {
        json!({
            "version": 1,
            "keys": [{
                "kid": "shared-slot",
                "algorithm": "HS256",
                "secret_path": mount.entry_path("tenant.secret"),
                "namespaces": [namespace],
            }]
        })
        .to_string()
    }

    /// Stage both generations of the shared slot and publish the mount.
    fn shared_slot_mount() -> ProjectedMount {
        let mount = ProjectedMount::new();
        mount.write_generation(
            "gen-a",
            &[
                ("bundle.json", slot_document(&mount, TENANT_A)),
                ("tenant.secret", TENANT_A_SECRET.to_string()),
            ],
        );
        mount.write_generation(
            "gen-b",
            &[
                ("bundle.json", slot_document(&mount, TENANT_B)),
                ("tenant.secret", TENANT_B_SECRET.to_string()),
            ],
        );
        mount.activate("gen-a");
        mount.publish(&["bundle.json", "tenant.secret"]);
        mount
    }

    /// The issue's primary race: the document is read through the old
    /// generation, `..data` is atomically swapped, and the key is resolved
    /// afterwards. The old namespace ceiling must never be paired with the new
    /// generation's key — that state existed in neither operator configuration.
    #[test]
    fn old_manifest_with_a_swapped_in_new_key_stays_on_the_pinned_generation() {
        let mount = shared_slot_mount();

        let pinned = PinnedTrustBundleSource::pin(&mount.bundle_path())
            .expect("the old generation's document must read");
        // The swap lands in the exact window the defect lived in.
        mount.activate("gen-b");
        let bundle = CpDpTrustBundle::from_pinned_source(pinned, None)
            .expect("the pinned generation must still resolve coherently");

        let verifier = CpDpVerifier::TrustBundle(bundle);
        assert_eq!(
            accepted_binding(&verifier, "shared-slot", TENANT_A_SECRET),
            (true, vec![TENANT_A.to_string()]),
            "the pinned generation's own key and ceiling must be what loads"
        );
        assert!(
            !accepted_binding(&verifier, "shared-slot", TENANT_B_SECRET).0,
            "generation B's key must never verify under generation A's namespace ceiling"
        );
    }

    /// The inverse ordering is the same defect: a retired key inheriting the
    /// new document's namespace grant.
    #[test]
    fn new_manifest_with_a_swapped_back_old_key_stays_on_the_pinned_generation() {
        let mount = shared_slot_mount();
        mount.activate("gen-b");

        let pinned = PinnedTrustBundleSource::pin(&mount.bundle_path())
            .expect("the new generation's document must read");
        mount.activate("gen-a");
        let bundle = CpDpTrustBundle::from_pinned_source(pinned, None)
            .expect("the pinned generation must still resolve coherently");

        let verifier = CpDpVerifier::TrustBundle(bundle);
        assert_eq!(
            accepted_binding(&verifier, "shared-slot", TENANT_B_SECRET),
            (true, vec![TENANT_B.to_string()]),
            "the pinned generation's own key and ceiling must be what loads"
        );
        assert!(
            !accepted_binding(&verifier, "shared-slot", TENANT_A_SECRET).0,
            "the retired key must never inherit the new document's namespace grant"
        );
    }

    /// A double-read stability check is not a coherence proof: A→B→A restores
    /// byte-identical document observations while the material in between came
    /// from B. The pin is a descriptor for one inode, so the sequence cannot
    /// redirect anything.
    #[test]
    fn rapid_aba_generation_swaps_cannot_smuggle_foreign_material() {
        let mount = ProjectedMount::new();
        let document = slot_document(&mount, TENANT_A);
        mount.write_generation(
            "gen-a1",
            &[
                ("bundle.json", document.clone()),
                ("tenant.secret", TENANT_A_SECRET.to_string()),
            ],
        );
        mount.write_generation(
            "gen-b",
            &[
                ("bundle.json", slot_document(&mount, TENANT_B)),
                ("tenant.secret", TENANT_B_SECRET.to_string()),
            ],
        );
        // Byte-identical document, foreign key: a loader that only re-read the
        // document to check stability would see no change at all.
        mount.write_generation(
            "gen-a2",
            &[
                ("bundle.json", document),
                ("tenant.secret", TENANT_B_SECRET.to_string()),
            ],
        );
        mount.activate("gen-a1");
        mount.publish(&["bundle.json", "tenant.secret"]);

        let pinned = PinnedTrustBundleSource::pin(&mount.bundle_path()).expect("document reads");
        mount.activate("gen-b");
        mount.activate("gen-a2");
        let bundle = CpDpTrustBundle::from_pinned_source(pinned, None)
            .expect("the pinned generation must still resolve coherently");

        let verifier = CpDpVerifier::TrustBundle(bundle);
        assert_eq!(
            accepted_binding(&verifier, "shared-slot", TENANT_A_SECRET),
            (true, vec![TENANT_A.to_string()])
        );
        assert!(
            !accepted_binding(&verifier, "shared-slot", TENANT_B_SECRET).0,
            "an A→B→A sequence must not substitute material a stability check cannot see"
        );
    }

    /// Several referenced files, of both material shapes, all resolve through
    /// the one pinned generation. Generation B deliberately holds an unusable
    /// public key: if any single reference re-resolved live, the load would
    /// fail instead of quietly succeeding on the pinned bytes.
    #[test]
    fn every_referenced_file_resolves_through_one_pinned_generation() {
        let mount = ProjectedMount::new();
        let public_key = es256_public_key_pem();
        let document = json!({
            "version": 1,
            "keys": [
                { "kid": TENANT_A, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-a.secret"),
                  "namespaces": [TENANT_A] },
                { "kid": TENANT_B, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-b.secret"),
                  "namespaces": [TENANT_B] },
                { "kid": "tenant-c", "algorithm": "ES256",
                  "public_key_path": mount.entry_path("tenant-c.pub"),
                  "namespaces": ["tenant-c"] },
            ]
        })
        .to_string();

        mount.write_generation(
            "gen-a",
            &[
                ("bundle.json", document.clone()),
                ("tenant-a.secret", TENANT_A_SECRET.to_string()),
                ("tenant-b.secret", TENANT_B_SECRET.to_string()),
                ("tenant-c.pub", public_key),
            ],
        );
        mount.write_generation(
            "gen-b",
            &[
                ("bundle.json", document),
                ("tenant-a.secret", TENANT_B_SECRET.to_string()),
                ("tenant-b.secret", TENANT_A_SECRET.to_string()),
                ("tenant-c.pub", "not a public key at all".to_string()),
            ],
        );
        mount.activate("gen-a");
        mount.publish(&[
            "bundle.json",
            "tenant-a.secret",
            "tenant-b.secret",
            "tenant-c.pub",
        ]);

        let pinned = PinnedTrustBundleSource::pin(&mount.bundle_path()).expect("document reads");
        mount.activate("gen-b");
        let bundle = CpDpTrustBundle::from_pinned_source(pinned, None)
            .expect("every reference must resolve inside the pinned generation");
        assert_eq!(bundle.key_count(), 3);

        let verifier = CpDpVerifier::TrustBundle(bundle);
        assert_eq!(
            accepted_binding(&verifier, TENANT_A, TENANT_A_SECRET),
            (true, vec![TENANT_A.to_string()])
        );
        assert_eq!(
            accepted_binding(&verifier, TENANT_B, TENANT_B_SECRET),
            (true, vec![TENANT_B.to_string()])
        );
        assert!(
            !accepted_binding(&verifier, TENANT_A, TENANT_B_SECRET).0
                && !accepted_binding(&verifier, TENANT_B, TENANT_A_SECRET).0,
            "no entry may be assembled from generation B"
        );
    }

    /// A digest remains load-bearing even when the path also belongs to the
    /// pinned generation. The pin proves generation membership; the digest
    /// independently proves the manifest named these exact bytes.
    #[test]
    fn a_digest_is_verified_in_addition_to_the_generation_pin() {
        let mount = ProjectedMount::new();
        let document = |digest: String| {
            json!({
                "version": 1,
                "keys": [{
                    "kid": TENANT_A,
                    "algorithm": "HS256",
                    "secret_path": mount.entry_path("tenant.secret"),
                    "material_sha256": digest,
                    "namespaces": [TENANT_A],
                }]
            })
            .to_string()
        };
        mount.write_generation(
            "gen-a",
            &[
                (
                    "bundle.json",
                    document(sha256_hex(TENANT_A_SECRET.as_bytes())),
                ),
                ("tenant.secret", TENANT_A_SECRET.to_string()),
            ],
        );
        mount.write_generation(
            "gen-b",
            &[
                (
                    "bundle.json",
                    document(sha256_hex(TENANT_B_SECRET.as_bytes())),
                ),
                ("tenant.secret", TENANT_A_SECRET.to_string()),
            ],
        );
        mount.activate("gen-a");
        mount.publish(&["bundle.json", "tenant.secret"]);
        CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
            .expect("matching digest and pin must load");

        mount.activate("gen-b");
        let error = CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
            .expect_err("a pinned entry with the wrong digest must still be refused");
        assert_eq!(
            error.reason(),
            TrustBundleRejectReason::MaterialIntegrityMismatch
        );
    }

    /// A regular file that is not an entry in the pinned projection can still
    /// be used when the manifest binds it by digest. Exercise both a sibling
    /// path (the pinned open returns ENOENT) and a path in another directory.
    #[test]
    fn digest_bound_external_files_can_accompany_a_pinned_document() {
        let mount = ProjectedMount::new();
        let outside = tempfile::tempdir().expect("outside material directory");
        let sibling_path = mount.root().join("sibling.secret");
        let outside_path = outside.path().join("outside.secret");
        std::fs::write(&sibling_path, TENANT_A_SECRET).expect("write sibling material");
        std::fs::write(&outside_path, TENANT_B_SECRET).expect("write outside material");
        let document = json!({
            "version": 1,
            "keys": [
                {
                    "kid": TENANT_A,
                    "algorithm": "HS256",
                    "secret_path": sibling_path,
                    "material_sha256": sha256_hex(TENANT_A_SECRET.as_bytes()),
                    "namespaces": [TENANT_A],
                },
                {
                    "kid": TENANT_B,
                    "algorithm": "HS256",
                    "secret_path": outside_path,
                    "material_sha256": sha256_hex(TENANT_B_SECRET.as_bytes()),
                    "namespaces": [TENANT_B],
                },
            ]
        })
        .to_string();
        mount.write_generation("gen-a", &[("bundle.json", document)]);
        mount.activate("gen-a");
        mount.publish(&["bundle.json"]);

        let verifier = CpDpVerifier::TrustBundle(
            CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
                .expect("digest-bound external material must load"),
        );
        assert_eq!(
            accepted_binding(&verifier, TENANT_A, TENANT_A_SECRET),
            (true, vec![TENANT_A.to_string()])
        );
        assert_eq!(
            accepted_binding(&verifier, TENANT_B, TENANT_B_SECRET),
            (true, vec![TENANT_B.to_string()])
        );
    }

    /// The per-file ceiling also has an aggregate counterpart. Phase one holds
    /// every resolved source until the candidate is coherent, so two individually
    /// bounded files must not multiply retained memory beyond the candidate cap.
    #[test]
    fn aggregate_path_backed_material_is_bounded() {
        let mount = ProjectedMount::new();
        let document = json!({
            "version": 1,
            "keys": [
                { "kid": TENANT_A, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-a.secret"),
                  "namespaces": [TENANT_A] },
                { "kid": TENANT_B, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-b.secret"),
                  "namespaces": [TENANT_B] },
            ]
        })
        .to_string();
        let large_a = "a".repeat(600 * 1024);
        let large_b = "b".repeat(600 * 1024);
        mount.write_generation(
            "gen-a",
            &[
                ("bundle.json", document),
                ("tenant-a.secret", large_a),
                ("tenant-b.secret", large_b),
            ],
        );
        mount.activate("gen-a");
        mount.publish(&["bundle.json", "tenant-a.secret", "tenant-b.secret"]);

        let error = CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
            .expect_err("aggregate path-backed material must stay bounded");
        assert_eq!(error.reason(), TrustBundleRejectReason::MaterialUnreadable);
    }

    /// A symlink planted inside the pinned generation would resolve against the
    /// live filesystem, which is the escape the whole pin exists to prevent.
    #[test]
    fn a_symlink_inside_the_pinned_generation_is_refused() {
        let mount = ProjectedMount::new();
        let outside = tempfile::tempdir().expect("outside directory");
        std::fs::write(outside.path().join("planted"), TENANT_B_SECRET)
            .expect("write planted material");

        mount.write_generation("gen-a", &[("bundle.json", slot_document(&mount, TENANT_A))]);
        std::os::unix::fs::symlink(
            outside.path().join("planted"),
            mount.root().join("..gen-a").join("tenant.secret"),
        )
        .expect("plant a symlink inside the generation");
        mount.activate("gen-a");
        mount.publish(&["bundle.json", "tenant.secret"]);

        let error = CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
            .expect_err("a symlinked entry inside the pinned generation must be refused");
        assert_eq!(
            error.reason(),
            TrustBundleRejectReason::SourceGenerationEscape
        );
    }

    /// `..` is refused outright rather than normalized: it can climb out of the
    /// pinned generation between the directory comparison and the open.
    #[test]
    fn a_traversing_reference_is_refused() {
        let mount = ProjectedMount::new();
        let document = json!({
            "version": 1,
            "keys": [{
                "kid": "shared-slot",
                "algorithm": "HS256",
                "secret_path": mount
                    .root()
                    .join("..")
                    .join(mount.root().file_name().expect("fixture directory name"))
                    .join("tenant.secret")
                    .display()
                    .to_string(),
                "namespaces": [TENANT_A],
            }]
        })
        .to_string();
        mount.write_generation(
            "gen-a",
            &[
                ("bundle.json", document),
                ("tenant.secret", TENANT_A_SECRET.to_string()),
            ],
        );
        mount.activate("gen-a");
        mount.publish(&["bundle.json", "tenant.secret"]);

        let error = CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
            .expect_err("a `..` component must be refused");
        assert_eq!(
            error.reason(),
            TrustBundleRejectReason::SourceGenerationEscape
        );
    }

    /// A rotation that reclaims the pinned generation mid-load is unstable, not
    /// an invitation to re-resolve live. It is refused; the caller retains its
    /// last accepted verifier and the next poll succeeds on the new generation.
    #[test]
    fn a_reclaimed_pinned_generation_is_refused_rather_than_re_resolved() {
        let mount = shared_slot_mount();

        let pinned = PinnedTrustBundleSource::pin(&mount.bundle_path()).expect("document reads");
        mount.activate("gen-b");
        mount.reclaim_generation("gen-a");
        let error = CpDpTrustBundle::from_pinned_source(pinned, None)
            .expect_err("a reclaimed pinned generation must be refused");
        assert_eq!(
            error.reason(),
            TrustBundleRejectReason::SourceGenerationUnstable
        );

        // The new generation is coherent on its own and loads normally.
        let verifier = load_verifier(&mount.bundle_path());
        assert_eq!(
            accepted_binding(&verifier, "shared-slot", TENANT_B_SECRET),
            (true, vec![TENANT_B.to_string()])
        );
    }

    /// Startup (`load_from_path`) and the periodic reload worker must go
    /// through the same coherent-generation loader — a mixed candidate must be
    /// able to become neither the initial authorization root nor a live
    /// replacement.
    #[tokio::test]
    async fn startup_and_reload_share_the_coherent_generation_loader() {
        let mount = shared_slot_mount();

        // Coherent: both accept.
        CpDpTrustBundle::load_from_path(&mount.bundle_path(), None)
            .expect("startup must accept a coherent generation");
        ferrum_edge::_test_support::load_cp_dp_trust_bundle_for_reload_for_test(
            mount.bundle_path(),
            Duration::from_secs(5),
        )
        .await
        .expect("reload must accept a coherent generation");

        // Unbound: the referenced entry is absent from the live pinned
        // generation. Without a digest it cannot fall back to an external
        // regular file, and both surfaces refuse with the same closed
        // classification rather than calling a permanent omission a transient
        // rotation race.
        mount.write_generation("gen-c", &[("bundle.json", slot_document(&mount, TENANT_A))]);
        mount.activate("gen-c");

        let startup = CpDpTrustBundle::load_coherent_from_path(&mount.bundle_path(), None)
            .expect_err("startup must fail closed on an incoherent generation");
        assert_eq!(
            startup.reason(),
            TrustBundleRejectReason::MaterialIntegrityUnbound
        );
        assert_eq!(
            ferrum_edge::_test_support::load_cp_dp_trust_bundle_for_reload_for_test(
                mount.bundle_path(),
                Duration::from_secs(5),
            )
            .await
            .expect_err("reload must fail closed on an incoherent generation"),
            TrustReloadFailure::from_reject_reason(startup.reason()).as_str(),
            "startup and reload must classify identically"
        );
    }

    /// A coherent atomic rotation publishes exactly once, closes only the
    /// streams whose credential was actually removed, and a later incoherent
    /// generation retains the entire last-good verifier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coherent_rotation_publishes_once_and_retains_last_good() {
        let mount = ProjectedMount::new();
        let two_tenant = json!({
            "version": 1,
            "keys": [
                { "kid": TENANT_A, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-a.secret"),
                  "namespaces": [TENANT_A] },
                { "kid": TENANT_B, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-b.secret"),
                  "namespaces": [TENANT_B] },
            ]
        })
        .to_string();
        let tenant_a_only = json!({
            "version": 1,
            "keys": [
                { "kid": TENANT_A, "algorithm": "HS256",
                  "secret_path": mount.entry_path("tenant-a.secret"),
                  "namespaces": [TENANT_A] },
            ]
        })
        .to_string();

        mount.write_generation(
            "gen-a",
            &[
                ("bundle.json", two_tenant),
                ("tenant-a.secret", TENANT_A_SECRET.to_string()),
                ("tenant-b.secret", TENANT_B_SECRET.to_string()),
            ],
        );
        mount.activate("gen-a");
        mount.publish(&["bundle.json", "tenant-a.secret", "tenant-b.secret"]);

        let store = Arc::new(CpDpVerifierStore::new(load_verifier(&mount.bundle_path())));
        let (addr, handle) =
            start_all_stream_surfaces(store.clone(), Duration::from_secs(300)).await;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let reload = ferrum_edge::grpc::cp_trust::spawn_trust_bundle_reload(
            mount.bundle_path(),
            None,
            store.clone(),
            true,
            Duration::from_secs(1),
            Arc::new(CpDpTrustReloadStatus::disabled()),
            shutdown_rx,
        );

        let token_a = mint(
            TENANT_A_SECRET,
            Some(TENANT_A),
            "dp-a-coherent",
            Some(json!(TENANT_A)),
            None,
        );
        let token_b = mint(
            TENANT_B_SECRET,
            Some(TENANT_B),
            "dp-b-coherent",
            Some(json!(TENANT_B)),
            None,
        );
        let mut client_a = configsync_client!(addr, token_a);
        let mut stream_a = client_a
            .subscribe(tonic::Request::new(subscribe_request(
                "dp-a-coherent",
                TENANT_A,
            )))
            .await
            .expect("tenant A stream admission")
            .into_inner();
        let mut client_b = configsync_client!(addr, token_b);
        let mut stream_b = client_b
            .subscribe(tonic::Request::new(subscribe_request(
                "dp-b-coherent",
                TENANT_B,
            )))
            .await
            .expect("tenant B stream admission")
            .into_inner();
        stream_a
            .message()
            .await
            .unwrap()
            .expect("tenant A initial snapshot");
        stream_b
            .message()
            .await
            .unwrap()
            .expect("tenant B initial snapshot");

        // One coherent rotation: tenant A's credential is byte-identical, and
        // tenant B's is removed together with its material.
        mount.write_generation(
            "gen-b",
            &[
                ("bundle.json", tenant_a_only),
                ("tenant-a.secret", TENANT_A_SECRET.to_string()),
            ],
        );
        mount.activate("gen-b");

        assert_eq!(
            wait_for_terminal_status(&mut stream_b).await,
            tonic::Code::PermissionDenied,
            "the removed credential's stream must close"
        );
        assert!(
            timeout(Duration::from_millis(600), stream_a.message())
                .await
                .is_err(),
            "a retained credential must not churn its live stream"
        );
        assert_eq!(
            *store.subscribe().borrow(),
            1,
            "a coherent rotation must publish exactly once"
        );

        // An incoherent generation lands next: the document is fine, but the
        // material it names is not in the generation it was read from. The
        // entire last-good verifier is retained — no partial replacement, no
        // extra publication.
        mount.write_generation(
            "gen-c",
            &[(
                "bundle.json",
                json!({
                    "version": 1,
                    "keys": [{ "kid": TENANT_A, "algorithm": "HS256",
                               "secret_path": mount.entry_path("tenant-a.secret"),
                               "namespaces": [TENANT_A, TENANT_B] }]
                })
                .to_string(),
            )],
        );
        mount.activate("gen-c");
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(
            *store.subscribe().borrow(),
            1,
            "an incoherent candidate must not replace the accepted verifier"
        );
        // The rejected generation would have widened tenant A's ceiling to
        // include tenant B. The retained verifier must still refuse it — the
        // whole prior generation is kept, ceilings included, with no partial
        // replacement.
        let widened = mint(
            TENANT_A_SECRET,
            Some(TENANT_A),
            "dp-a-widened",
            Some(json!(TENANT_B)),
            None,
        );
        let mut widened_client = configsync_client!(addr, widened);
        let status = widened_client
            .subscribe(tonic::Request::new(subscribe_request(
                "dp-a-widened",
                TENANT_B,
            )))
            .await
            .expect_err("a rejected candidate's widened ceiling must never be in force");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let _ = shutdown_tx.send(true);
        reload.abort();
        handle.abort();
    }
}

/// Non-Unix hosts have no `openat`, so no generation can ever be pinned. That
/// is a fail-closed downgrade, not a silent one: a projected `..data` mount is
/// refused with the unsupported classification, and ordinary path-backed
/// material falls to the digest-bound contract exactly as it does on Unix when
/// nothing could be pinned.
#[cfg(not(unix))]
#[test]
fn non_unix_hosts_fail_closed_instead_of_re_resolving_live_symlinks() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let secret_path = dir.path().join("tenant-a.secret");
    std::fs::write(&secret_path, TENANT_A_SECRET).expect("write secret fixture");

    let unbound = external_bundle(
        dir.path(),
        json!({ "version": 1, "keys": [{
            "kid": TENANT_A, "algorithm": "HS256",
            "secret_path": secret_path.display().to_string(),
            "namespaces": [TENANT_A],
        }]}),
    );
    assert_eq!(
        CpDpTrustBundle::load_coherent_from_path(&unbound, None)
            .expect_err("unbound path-backed material must be refused")
            .reason(),
        TrustBundleRejectReason::MaterialIntegrityUnbound
    );

    let bound = external_bundle(
        dir.path(),
        json!({ "version": 1, "keys": [{
            "kid": TENANT_A, "algorithm": "HS256",
            "secret_path": secret_path.display().to_string(),
            "material_sha256": sha256_hex(TENANT_A_SECRET.as_bytes()),
            "namespaces": [TENANT_A],
        }]}),
    );
    CpDpTrustBundle::load_coherent_from_path(&bound, None)
        .expect("digest-bound material must load on any platform");
}

// ── Stale-trust boundary across every configuration surface (issue #3813) ──

fn watching_status_at(
    max_stale: Duration,
    unbounded_allowed: bool,
    interval: Duration,
    now: tokio::time::Instant,
) -> CpDpTrustReloadStatus {
    CpDpTrustReloadStatus::watching_at(
        max_stale,
        unbounded_allowed,
        interval,
        now,
        b"ferrum-test-status-hmac-key-32b!",
        &[0x11; 32],
    )
}

/// A verifier store whose trust source has already aged past its bound.
///
/// The bound is the boundary and nothing else: no failure needs to be recorded
/// for the age to grow, because only an *accepted* reload resets it.
fn stale_trust_store() -> Arc<CpDpVerifierStore> {
    let status = watching_status_at(
        // A millisecond bound keeps this test on real time without a sleep
        // long enough to slow the suite; the boundary semantics are identical
        // and are pinned exactly in `cp_trust_reload_health_tests.rs`.
        Duration::from_millis(1),
        false,
        Duration::from_secs(30),
        tokio::time::Instant::now(),
    );
    let status = Arc::new(status);
    status.record_rejected(TrustReloadFailure::DocumentUnreadable);
    Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()).with_trust_status(status))
}

async fn admission_outcome<T>(
    result: Result<tonic::Response<tonic::Streaming<T>>, tonic::Status>,
) -> tonic::Code {
    match result {
        Ok(response) => wait_for_terminal_status(&mut response.into_inner()).await,
        Err(status) => status.code(),
    }
}

/// Past the bound, a credential the operator tried to remove must not be able
/// to open a *new* stream on any configuration surface — the retained verifier
/// is no longer an admission authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_trust_refuses_new_streams_on_every_configuration_surface() {
    let verifier = stale_trust_store();
    let (addr, handle) = start_all_stream_surfaces(verifier, Duration::from_secs(300)).await;
    // Cross the bound. Only an accepted reload could have moved it.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let config_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "stale-config-node",
        Some(json!(TENANT_A)),
        None,
    );
    let mut config_client = configsync_client!(addr, config_token);
    assert_eq!(
        admission_outcome(
            config_client
                .subscribe(tonic::Request::new(subscribe_request(
                    "stale-config-node",
                    TENANT_A,
                )))
                .await
        )
        .await,
        tonic::Code::Unavailable
    );

    for (node_id, remote, audience) in [
        (
            "stale-mesh-local",
            false,
            MESH_LOCAL_SUBSCRIBE_AUDIENCE.to_string(),
        ),
        (
            "stale-mesh-remote",
            true,
            remote_discovery_audience("test-cluster"),
        ),
    ] {
        let mesh_token = mint(
            TENANT_A_SECRET,
            Some(TENANT_A),
            node_id,
            Some(json!(TENANT_A)),
            Some(&audience),
        );
        let mut mesh_client = mesh_client!(addr, mesh_token);
        assert_eq!(
            admission_outcome(
                mesh_client
                    .mesh_subscribe(tonic::Request::new(mesh_subscribe_request(
                        node_id, TENANT_A, remote,
                    )))
                    .await
            )
            .await,
            tonic::Code::Unavailable,
            "MeshSubscribe (remote_discovery={remote}) must refuse under stale trust"
        );
    }

    let sotw_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "stale-xds-sotw",
        Some(json!(TENANT_A)),
        None,
    );
    let mut sotw_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (sotw_tx, sotw_rx) = mpsc::channel(2);
    sotw_tx
        .send(DiscoveryRequest {
            node: Some(Node {
                id: "stale-xds-sotw".to_string(),
                ..Node::default()
            }),
            resource_names: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DiscoveryRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(
        admission_outcome(
            sotw_client
                .stream_aggregated_resources(authorize(
                    tonic::Request::new(ReceiverStream::new(sotw_rx)),
                    &sotw_token,
                ))
                .await
        )
        .await,
        tonic::Code::Unavailable
    );
    drop(sotw_tx);

    let delta_token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "stale-xds-delta",
        Some(json!(TENANT_A)),
        None,
    );
    let mut delta_client = AggregatedDiscoveryServiceClient::new(xds_channel(addr).await);
    let (delta_tx, delta_rx) = mpsc::channel(2);
    delta_tx
        .send(DeltaDiscoveryRequest {
            node: Some(Node {
                id: "stale-xds-delta".to_string(),
                ..Node::default()
            }),
            resource_names_subscribe: vec!["*".to_string()],
            type_url: LDS_TYPE_URL.to_string(),
            ..DeltaDiscoveryRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(
        admission_outcome(
            delta_client
                .delta_aggregated_resources(authorize(
                    tonic::Request::new(ReceiverStream::new(delta_rx)),
                    &delta_token,
                ))
                .await
        )
        .await,
        tonic::Code::Unavailable
    );
    drop(delta_tx);

    handle.abort();
}

/// Refusing only new streams would leave the longest-lived sessions as the ones
/// the bound never reaches. Established streams on every surface must end at
/// the boundary through the shared authorization lifecycle.
#[tokio::test(start_paused = true)]
async fn stale_trust_terminates_established_streams_on_every_surface() {
    for surface in [
        StreamAuthSurface::ConfigSync,
        StreamAuthSurface::MeshSubscribeLocal,
        StreamAuthSurface::MeshSubscribeRemote,
        StreamAuthSurface::XdsSotw,
        StreamAuthSurface::XdsDelta,
    ] {
        let bound = Duration::from_secs(60);
        let status = Arc::new(watching_status_at(
            bound,
            false,
            Duration::from_secs(30),
            tokio::time::Instant::now(),
        ));
        let verifier =
            Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()).with_trust_status(status));
        let snapshot = verifier.load();
        let token = mint(
            TENANT_A_SECRET,
            Some(TENANT_A),
            "stale-established-node",
            Some(json!(TENANT_A)),
            None,
        );
        let request = authorize(tonic::Request::new(()), &token);
        let identity = snapshot
            .verify_and_bind_grpc_identity(request.metadata(), TEST_ISSUER, None, verifier.as_ref())
            .expect("admission inside the bound must still succeed");
        let (_tx, rx) = mpsc::channel::<Result<(), tonic::Status>>(1);
        let mut stream = AuthorizedResponseStream::new(
            ReceiverStream::new(rx),
            &identity,
            verifier.clone(),
            // Far beyond the trust bound, so this proves the trust boundary
            // rather than the independent server lifetime.
            Duration::from_secs(86_400),
            surface,
        );
        let waiter = tokio::spawn(async move { stream.next().await });
        tokio::task::yield_now().await;
        tokio::time::advance(bound).await;

        let status = waiter
            .await
            .expect("stale-trust waiter must not panic")
            .expect("the stale boundary must emit one terminal item")
            .expect_err("the stale boundary must terminate the stream");
        assert_eq!(
            status.code(),
            tonic::Code::Unavailable,
            "surface {surface:?}"
        );
        assert_eq!(
            status.message(),
            "This control plane cannot currently revalidate its verification trust source"
        );
    }
}

/// The task-owned ADS loops wait on the shared lease rather than the response
/// stream, so the boundary has to hold there too.
#[tokio::test(start_paused = true)]
async fn stale_trust_ends_the_shared_authorization_lease() {
    let bound = Duration::from_secs(120);
    let status = Arc::new(watching_status_at(
        bound,
        false,
        Duration::from_secs(30),
        tokio::time::Instant::now(),
    ));
    let verifier =
        Arc::new(CpDpVerifierStore::from_arc(two_tenant_bundle()).with_trust_status(status));
    let snapshot = verifier.load();
    let token = mint(
        TENANT_A_SECRET,
        Some(TENANT_A),
        "stale-lease-node",
        Some(json!(TENANT_A)),
        None,
    );
    let request = authorize(tonic::Request::new(()), &token);
    let identity = snapshot
        .verify_and_bind_grpc_identity(request.metadata(), TEST_ISSUER, None, verifier.as_ref())
        .expect("admission inside the bound must still succeed");
    let lease = StreamAuthorizationLease::new(&identity, verifier, Duration::from_secs(86_400));
    let waiter = tokio::spawn(async move { lease.wait_for_end().await });
    tokio::task::yield_now().await;
    tokio::time::advance(bound).await;

    let reason = waiter.await.expect("lease waiter must not panic");
    assert_eq!(reason.label(), "trust_stale");
}
