//! Live data-path coverage for the stock Envoy / third-party Istio xDS
//! interoperability profile (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`, issue
//! #3317).
//!
//! Everything here runs against a **scripted third-party ADS server** — a bare
//! `envoy.service.discovery.v3.AggregatedDiscoveryService` implementation that
//! puts standard v3 `Cluster` / `ClusterLoadAssignment` / `Listener` /
//! `RouteConfiguration` resources on the wire. It is deliberately NOT Ferrum's
//! own `XdsAdsServer`: nothing in this file can be satisfied by the
//! Ferrum-private carrier protocol.
//!
//! The datapath is the real one:
//!
//! ```text
//!   scripted stock ADS server ──(production stock_xds client)──▶ gateway A
//!   plaintext app request ──▶ A's outbound capture listener
//!                        ──▶ materialized egress route (discovered service)
//!                        ──▶ SVID-mTLS to gateway B's inbound listener
//!                        ──▶ B's materialized loopback route ──▶ echo backend
//! ```
//!
//! Gateway A consumes **discovery only** from the stock server; its enforcement
//! posture (STRICT PeerAuthentication) comes from the mandatory local policy
//! document. Gateway B is an ordinary native-CP sidecar and is what proves the
//! request really traversed mesh mTLS: it terminates the mTLS, verifies A's
//! SVID, and only then relays to the labelled echo backend whose body the test
//! asserts.
//!
//! Phases (one fixture, in order). Fail-closed arms that can be represented as
//! a reachable service first are proven by a *change* in reachability on that
//! same host after the exact ACK of the refusal generation. Arms that cannot
//! have a same-host representable pre-state (foreign-namespace narrowing;
//! capability refusals of RBAC / weighted routes, which do not themselves
//! program a dialable CDS/EDS cluster) are proven by the exact ACK of the
//! generation that carried them, the field-specific diagnostic, accepted-service
//! continuity, and — for foreign-namespace narrowing — that a later
//! withdrawal still applies rather than freezing on an invalid projected slice.
//!
//! 1. CDS+EDS+LDS+RDS converge and the discovered service routes live traffic.
//! 2. Unpinned-peer and subset clusters: first prove the exact host is routable
//!    under a representable resource, then change only the refusal-causing
//!    field, wait for the matching ACK nonce/version, and prove it stops
//!    routing. A foreign-namespace cluster is ACKed into the same generation;
//!    it cannot be made reachable in this namespace, so the applied-generation
//!    proof is that exact ACK plus phases 4–7 still taking effect.
//! 3. A structurally invalid response is NACKed with a field-specific
//!    `error_detail` re-asserting the last accepted version, and the last-good
//!    view keeps serving real traffic.
//! 4. EDS endpoint withdrawal removes reachability.
//! 5. A replacement EDS assignment restores it.
//! 6. A state-of-the-world CDS withdrawal removes reachability.
//! 7. Re-publishing the cluster restores it.
//! 8. A listener carrying `envoy.filters.http.rbac` and a route using
//!    `weighted_clusters` are ACKed (not NACKed) with field-specific refusal
//!    diagnostics. The accepted service keeps serving. Semantic coverage that
//!    those constructs contribute no route lives in the unit/integration
//!    suites; this phase does not claim a live widening proof for a host that
//!    was never dialable.
//! 9. Re-pinning the cluster's peer identity to an impostor SPIFFE removes
//!    reachability — the control plane's SAN pin is a real verification input,
//!    not decoration.
//!
//! Run with:
//!   cargo test --test functional_tests functional_mesh_stock_xds -- --ignored --nocapture

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use prost::Message;
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MtlsMode, PeerAuthentication, ServicePort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::xds::proto::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use ferrum_edge::xds::proto::{
    Any, DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use ferrum_edge::xds::stock_proto as sp;
use ferrum_edge::xds::{CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL};

use crate::common::ensure_gateway_built;
use crate::functional::functional_mesh_mode_test::{
    MeshGatewaySpawnOptions, RETRY_ATTEMPTS, STARTUP_TIMEOUT, bind_fixture_listener,
    captured_output, exited_gateway_diagnostic, generate_two_gateway_svids, kill_child,
    loopback_ephemeral, plaintext_http_get, reserve_mesh_ports, spawn_mesh_gateway,
    start_static_mesh_cp, wait_for_gateway_listener,
};

const A_SPIFFE: &str = "spiffe://cluster.local/ns/ferrum/sa/client-app";
const B_SPIFFE: &str = "spiffe://cluster.local/ns/ferrum/sa/svc-b";
/// A SPIFFE identity nothing in the mesh actually holds. Used to prove the
/// control plane's SAN pin is verified rather than decorative.
const IMPOSTOR_SPIFFE: &str = "spiffe://cluster.local/ns/ferrum/sa/impostor";

const BACKEND_LABEL: &str = "stock-xds-backend-ok";
const SERVICE_HOST: &str = "svc-b.ferrum.svc.cluster.local";
const NO_PIN_HOST: &str = "svc-nopin.ferrum.svc.cluster.local";
const SUBSET_HOST: &str = "svc-subset.ferrum.svc.cluster.local";
const FOREIGN_NAMESPACE_HOST: &str = "svc-other.other.svc.cluster.local";
/// Synthetic Kubernetes pod UID for the one destination pod. Every Service
/// that pod backs carries this same non-empty UID so inbound can prove they
/// are one pod (addresses are not identity).
const DESTINATION_POD_UID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";

/// Bound for one discovery transition to show up on the data path.
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// Bound for the gateway's own ADS request (ACK / NACK) to reach the fixture.
const ADS_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

// ── scripted third-party ADS server ──────────────────────────────────────

#[derive(Clone, Default)]
struct AdsRecorder {
    requests: Arc<Mutex<Vec<DiscoveryRequest>>>,
}

impl AdsRecorder {
    fn record(&self, request: DiscoveryRequest) {
        self.requests
            .lock()
            .expect("ADS recorder mutex is never held across a panic")
            .push(request);
    }

    fn snapshot(&self) -> Vec<DiscoveryRequest> {
        self.requests
            .lock()
            .expect("ADS recorder mutex is never held across a panic")
            .clone()
    }
}

type SeedMap = Arc<Mutex<HashMap<String, DiscoveryResponse>>>;

/// A stock control plane the test scripts directly.
///
/// Each type's CURRENT state-of-the-world response is held in `seeds` and sent
/// when that type is first subscribed on a stream; pushing a new response both
/// broadcasts it to live streams and replaces the seed, so a reconnect resumes
/// from the newest state rather than rewinding to the first one.
struct ScriptedThirdPartyAds {
    recorder: AdsRecorder,
    seeds: SeedMap,
    pushes: broadcast::Sender<DiscoveryResponse>,
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for ScriptedThirdPartyAds {
    type StreamAggregatedResourcesStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<DiscoveryResponse, Status>> + Send>,
    >;
    type DeltaAggregatedResourcesStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>,
    >;

    async fn stream_aggregated_resources(
        &self,
        request: Request<Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        let mut inbound = request.into_inner();
        let recorder = self.recorder.clone();
        let seeds = Arc::clone(&self.seeds);
        // Subscribed before the response stream is returned so no push made
        // after the gateway connects can be missed.
        let mut pushes = self.pushes.subscribe();
        let (tx, rx) = mpsc::channel(64);

        let push_tx = tx.clone();
        tokio::spawn(async move {
            while let Ok(response) = pushes.recv().await {
                if push_tx.send(Ok(response)).await.is_err() {
                    return;
                }
            }
        });

        tokio::spawn(async move {
            let mut seeded: HashSet<String> = HashSet::new();
            while let Ok(Some(discovery_request)) = inbound.message().await {
                let type_url = discovery_request.type_url.clone();
                recorder.record(discovery_request);
                if !seeded.insert(type_url.clone()) {
                    continue;
                }
                let seed = seeds
                    .lock()
                    .expect("ADS seed mutex is never held across a panic")
                    .get(&type_url)
                    .cloned();
                if let Some(seed) = seed
                    && tx.send(Ok(seed)).await.is_err()
                {
                    return;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn delta_aggregated_resources(
        &self,
        _request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        // Delta xDS is explicitly out of scope for the stock profile.
        Err(Status::unimplemented(
            "delta xDS is not part of the Ferrum stock xDS profile",
        ))
    }
}

struct StockAdsHandle {
    addr: SocketAddr,
    recorder: AdsRecorder,
    seeds: SeedMap,
    pushes: broadcast::Sender<DiscoveryResponse>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl StockAdsHandle {
    async fn start(seeds: HashMap<String, DiscoveryResponse>) -> Result<Self, String> {
        let listener = bind_fixture_listener(loopback_ephemeral())
            .await
            .map_err(|e| format!("bind scripted ADS listener: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("scripted ADS listener addr: {e}"))?;
        let recorder = AdsRecorder::default();
        let seeds: SeedMap = Arc::new(Mutex::new(seeds));
        let (pushes, _) = broadcast::channel(64);
        let server = ScriptedThirdPartyAds {
            recorder: recorder.clone(),
            seeds: Arc::clone(&seeds),
            pushes: pushes.clone(),
        };
        let incoming = TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(server))
                .serve_with_incoming(incoming)
                .await
        });
        Ok(Self {
            addr,
            recorder,
            seeds,
            pushes,
            task,
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Publish one state-of-the-world response, and make it the state a
    /// reconnecting client would resume from.
    ///
    /// Returns the recorder length at the moment of the push so a subsequent
    /// ACK/NACK wait can ignore requests that arrived before this response.
    fn push(&self, response: DiscoveryResponse) -> usize {
        let watermark = self.recorder.snapshot().len();
        self.seeds
            .lock()
            .expect("ADS seed mutex is never held across a panic")
            .insert(response.type_url.clone(), response.clone());
        let _ = self.pushes.send(response);
        watermark
    }

    fn matching_request(
        &self,
        after: usize,
        type_url: &str,
        nonce: &str,
        version: Option<&str>,
        nack: bool,
    ) -> Option<DiscoveryRequest> {
        self.recorder
            .snapshot()
            .into_iter()
            .skip(after)
            .find(|request| {
                request.type_url == type_url
                    && request.response_nonce == nonce
                    && !request.response_nonce.is_empty()
                    && request.error_detail.is_some() == nack
                    && version.is_none_or(|expected| request.version_info == expected)
            })
    }

    /// Wait for the gateway to ACK this exact response (`version` + `nonce`)
    /// with a request recorded after `after`. Reconnects after the push still
    /// append, so a replayed ACK of the same nonce is accepted; an earlier
    /// ACK of a different generation is not.
    async fn wait_for_ack(
        &self,
        after: usize,
        type_url: &str,
        version: &str,
        nonce: &str,
    ) -> Result<(), String> {
        let deadline = Instant::now() + ADS_EXCHANGE_TIMEOUT;
        loop {
            if self
                .matching_request(after, type_url, nonce, Some(version), false)
                .is_some()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the gateway never ACKed '{type_url}' version '{version}' nonce '{nonce}' \
                     after request index {after}"
                ));
            }
            tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
        }
    }

    /// Wait for a NACK of this exact response nonce, recorded after `after`.
    /// `version_info` on a NACK is the last *accepted* version, not the refused
    /// one, so only the nonce identifies the response under test.
    async fn wait_for_nack(
        &self,
        after: usize,
        type_url: &str,
        nonce: &str,
    ) -> Result<DiscoveryRequest, String> {
        let deadline = Instant::now() + ADS_EXCHANGE_TIMEOUT;
        loop {
            if let Some(nack) = self.matching_request(after, type_url, nonce, None, true) {
                return Ok(nack);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the gateway never NACKed '{type_url}' nonce '{nonce}' after request index \
                     {after}"
                ));
            }
            tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
        }
    }

    /// True when a request recorded after `after` NACKed this exact nonce.
    fn nacked_after(&self, after: usize, type_url: &str, nonce: &str) -> bool {
        self.matching_request(after, type_url, nonce, None, true)
            .is_some()
    }

    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

// ── standard Envoy v3 resource fixtures ──────────────────────────────────

fn any_resource(type_url: &str, message: &impl Message) -> Any {
    Any {
        type_url: type_url.to_string(),
        value: message.encode_to_vec(),
    }
}

fn response(type_url: &str, version: &str, nonce: &str, resources: Vec<Any>) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        resources,
        canary: false,
        type_url: type_url.to_string(),
        nonce: nonce.to_string(),
        control_plane: None,
    }
}

fn ads_source() -> sp::ConfigSource {
    sp::ConfigSource {
        // `AggregatedConfigSource` is an empty upstream message, so presence is
        // the whole signal.
        ads: vec![Vec::new()],
        ..Default::default()
    }
}

/// The control plane's own statement of who may answer for a cluster: a URI SAN
/// matcher on the cluster's `UpstreamTlsContext`.
fn pinned_tls_socket(san: &str) -> sp::TransportSocket {
    let context = sp::UpstreamTlsContext {
        common_tls_context: Some(sp::CommonTlsContext {
            combined_validation_context: Some(sp::CombinedCertificateValidationContext {
                default_validation_context: Some(sp::CertificateValidationContext {
                    match_typed_subject_alt_names: vec![sp::SubjectAltNameMatcher {
                        // SanType::URI
                        san_type: 3,
                        matcher: Some(sp::StringMatcher {
                            exact: san.to_string(),
                            ..Default::default()
                        }),
                        oid: String::new(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    sp::TransportSocket {
        name: "envoy.transport_sockets.tls".to_string(),
        typed_config: Some(sp::Any {
            type_url: UPSTREAM_TLS_TYPE_URL.to_string(),
            value: context.encode_to_vec(),
        }),
    }
}

fn cluster_name(port: u16, subset: &str, host: &str) -> String {
    format!("outbound|{port}|{subset}|{host}")
}

/// A plain Istio outbound EDS cluster, optionally carrying the CP's SAN pin.
fn eds_cluster(name: &str, san: Option<&str>) -> sp::Cluster {
    sp::Cluster {
        name: name.to_string(),
        // DiscoveryType::EDS
        r#type: 3,
        eds_cluster_config: Some(sp::EdsClusterConfig {
            eds_config: Some(ads_source()),
            service_name: String::new(),
        }),
        transport_socket: san.map(pinned_tls_socket),
        ..Default::default()
    }
}

fn assignment(cluster: &str, endpoints: &[(&str, u16)]) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: endpoints
                .iter()
                .map(|(address, port)| sp::LbEndpoint {
                    endpoint: Some(sp::Endpoint {
                        address: Some(sp::Address {
                            socket_address: Some(sp::SocketAddress {
                                address: (*address).to_string(),
                                port_value: u32::from(*port),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    // HealthStatus::HEALTHY
                    health_status: 1,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }],
    }
}

/// A wildcard-bind HCM listener whose only HTTP filter is the terminal router,
/// plus the extra `filters` the caller wants in front of it. An enforcement
/// filter here must refuse the whole listener.
fn hcm_listener(name: &str, port: u16, route_config_name: &str, filters: &[&str]) -> sp::Listener {
    let mut http_filters: Vec<sp::HttpFilter> = filters
        .iter()
        .map(|filter| sp::HttpFilter {
            name: (*filter).to_string(),
            ..Default::default()
        })
        .collect();
    http_filters.push(sp::HttpFilter {
        name: "envoy.filters.http.router".to_string(),
        ..Default::default()
    });
    let hcm = sp::HttpConnectionManager {
        stat_prefix: "outbound".to_string(),
        rds: Some(sp::Rds {
            config_source: Some(ads_source()),
            route_config_name: route_config_name.to_string(),
        }),
        http_filters,
        ..Default::default()
    };
    sp::Listener {
        name: name.to_string(),
        address: Some(sp::Address {
            socket_address: Some(sp::SocketAddress {
                address: "0.0.0.0".to_string(),
                port_value: u32::from(port),
                ..Default::default()
            }),
            ..Default::default()
        }),
        filter_chains: vec![sp::FilterChain {
            filters: vec![sp::NetworkFilter {
                name: "envoy.filters.network.http_connection_manager".to_string(),
                typed_config: Some(sp::Any {
                    type_url: HCM_TYPE_URL.to_string(),
                    value: hcm.encode_to_vec(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        // TrafficDirection::OUTBOUND
        traffic_direction: 2,
        ..Default::default()
    }
}

fn route_config(name: &str, domains: &[&str], cluster: &str) -> sp::RouteConfiguration {
    sp::RouteConfiguration {
        name: name.to_string(),
        virtual_hosts: vec![sp::VirtualHost {
            name: format!("{name}-vhost"),
            domains: domains.iter().map(|d| (*d).to_string()).collect(),
            routes: vec![sp::Route {
                r#match: Some(sp::RouteMatch {
                    prefix: "/".to_string(),
                    ..Default::default()
                }),
                route: Some(sp::RouteAction {
                    cluster: cluster.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// A route configuration whose action splits traffic with `weighted_clusters` —
/// a traffic-shaping construct the stock profile refuses rather than
/// approximating. Presence of the field is the refusal signal; this fixture
/// replaces the accepted service's route so the live phase can prove the
/// response is ACKed (not NACKed) without claiming a host that was never
/// dialable became unreachable.
fn weighted_route_config(name: &str, domains: &[&str]) -> sp::RouteConfiguration {
    sp::RouteConfiguration {
        name: name.to_string(),
        virtual_hosts: vec![sp::VirtualHost {
            name: format!("{name}-weighted-vhost"),
            domains: domains.iter().map(|d| (*d).to_string()).collect(),
            routes: vec![sp::Route {
                r#match: Some(sp::RouteMatch {
                    prefix: "/".to_string(),
                    ..Default::default()
                }),
                route: Some(sp::RouteAction {
                    // Presence-only in the decode projection; a non-empty
                    // `weighted_clusters` is what must be refused.
                    weighted_clusters: vec![Vec::new()],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

// ── local fixtures (policy half, destination sidecar, backend) ───────────

/// The MANDATORY local policy document for the stock profile. It carries the
/// enforcement posture (STRICT mTLS) and deliberately declares no `services`
/// and no `workloads` — those are the control plane's half.
fn stock_policy_document() -> String {
    let mesh = MeshConfig {
        peer_authentications: vec![PeerAuthentication {
            name: "stock-xds-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        ..MeshConfig::default()
    };
    serde_json::to_string(&serde_json::json!({ "mesh": mesh }))
        .expect("mesh policy document serializes")
}

/// One local Service this destination pod backs, plus the per-service workload
/// record stock xDS also emits for a shared endpoint (same SPIFFE, same
/// synthetic pod UID, distinct `service_name`).
fn destination_local_service(
    name: &str,
    backend_port: u16,
    b_id: &SpiffeId,
    trust_domain: &TrustDomain,
) -> (Workload, MeshService) {
    let workload = Workload {
        spiffe_id: b_id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "svc-b".to_string())]),
            namespace: Some("ferrum".to_string()),
        },
        service_name: name.to_string(),
        service_namespace: None,
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port: backend_port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: trust_domain.clone(),
        namespace: "ferrum".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("svc-b".to_string()),
        pod_uid: Some(DESTINATION_POD_UID.to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: "ferrum".to_string(),
        ports: vec![ServicePort {
            port: backend_port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: b_id.clone(),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    };
    (workload, service)
}

/// Gateway B's slice: the destination sidecar's own view of the in-mesh
/// services this pod backs. B is an ordinary native-CP sidecar — the stock
/// control plane drives only gateway A.
///
/// Phase 2a publishes additional representable clusters (`svc-nopin`,
/// `svc-subset`) that share this pod's endpoint, SAN pin, and synthetic pod
/// UID. A's outbound preserves the client Host, so B must materialize inbound
/// Host routes for those Services or the pre-state probe 404s at B after a
/// successful mTLS hop. The shared non-empty UID is the same-pod proof;
/// matching addresses alone are not.
fn destination_slice(node_id: &str, backend_port: u16) -> MeshSlice {
    let b_id = SpiffeId::new(B_SPIFFE).expect("destination SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let (workloads, services): (Vec<Workload>, Vec<MeshService>) =
        ["svc-b", "svc-nopin", "svc-subset"]
            .into_iter()
            .map(|name| destination_local_service(name, backend_port, &b_id, &trust_domain))
            .unzip();
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: chrono::Utc::now().to_rfc3339(),
        workloads,
        services,
        peer_authentications: vec![PeerAuthentication {
            name: "stock-xds-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Echo backend behind gateway B. Its body is the only reliable "the request
/// reached the application" signal: every fail-closed outcome in this file is
/// asserted as "no 200 AND no backend body".
async fn start_stock_echo_backend() -> Result<u16, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .map_err(|e| format!("bind stock echo backend: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("stock echo backend addr: {e}"))?
        .port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    BACKEND_LABEL.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(BACKEND_LABEL.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    Ok(port)
}

// ── observed phase outcomes ──────────────────────────────────────────────

/// One HTTP observation at gateway A's outbound capture listener.
///
/// A transport-level failure is a first-class outcome, not an error: when a
/// discovered service is withdrawn or refused the client can legitimately see a
/// reset instead of a status line, and either way no backend body reached it.
#[derive(Debug)]
enum Probe {
    Answered { status: u16, body: String },
    TransportFailure(String),
}

impl Probe {
    fn reached_backend(&self) -> bool {
        matches!(
            self,
            Probe::Answered { status: 200, body } if body.contains(BACKEND_LABEL)
        )
    }

    fn describe(&self, what: &str) -> String {
        match self {
            Probe::Answered { status, body } => {
                format!("{what}: status={status} body={body:?}")
            }
            Probe::TransportFailure(error) => format!("{what}: transport failure ({error})"),
        }
    }
}

/// Everything the driver observed, asserted by the test so a single fixture
/// bring-up covers the whole live matrix.
struct StockLiveObservations {
    converged: Probe,
    unpinned_peer_before: Probe,
    unpinned_peer: Probe,
    subset_cluster_before: Probe,
    subset_cluster: Probe,
    good_service_after_refusals: Probe,
    nack_version_info: String,
    nack_message: String,
    good_service_after_nack: Probe,
    endpoints_withdrawn: Probe,
    endpoints_restored: Probe,
    cluster_withdrawn: Probe,
    cluster_restored: Probe,
    lds_nacked: bool,
    rds_nacked: bool,
    good_service_after_capability_refusal: Probe,
    impostor_pin: Probe,
    logs: String,
}

// ── the driver ───────────────────────────────────────────────────────────

async fn probe(outbound_port: u16, host: &str) -> Probe {
    match plaintext_http_get(outbound_port, host, "/").await {
        Ok((status, body)) => Probe::Answered { status, body },
        Err(e) => Probe::TransportFailure(format!("GET http://{host}/ : {e}")),
    }
}

/// Poll until the host is routed all the way to the backend, or fail.
async fn wait_until_reachable(outbound_port: u16, host: &str) -> Result<Probe, String> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let observed = probe(outbound_port, host).await;
        if observed.reached_backend() {
            return Ok(observed);
        }
        let last = observed.describe("last non-routed response");
        if Instant::now() >= deadline {
            return Err(format!(
                "'{host}' never became reachable within {CONVERGENCE_TIMEOUT:?}; {last}"
            ));
        }
        tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
    }
}

/// Poll until the host stops reaching the backend, then make ONE authoritative
/// confirming observation.
///
/// A withdrawal is a *transition*, so the poll bounds how long convergence may
/// take; the returned probe is the single post-convergence observation the test
/// asserts on. Polling never turns a reachable service into an unreachable
/// verdict — it only waits for the state the control plane just published, and
/// the confirming probe is issued exactly once afterwards.
async fn wait_until_unreachable(outbound_port: u16, host: &str) -> Result<Probe, String> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        if !probe(outbound_port, host).await.reached_backend() {
            return Ok(probe(outbound_port, host).await);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "'{host}' still reaches the backend {CONVERGENCE_TIMEOUT:?} after the control \
                 plane withdrew it"
            ));
        }
        tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
    }
}

/// Bring up the scripted stock control plane, the stock-driven sidecar (A), the
/// destination sidecar (B) and its backend, then walk the live phase matrix.
///
/// Bounded retries cover fixture bring-up races only: an attempt whose gateway
/// died mid-run is VOID (its ports were never owned by the process the driver
/// believed it was driving), so it is retried with fresh ports, temp dirs,
/// control planes, and ADS server rather than reported as a datapath result.
async fn drive_stock_xds_live_datapath() -> Result<StockLiveObservations, String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_a = format!("functional-stock-xds-a-{attempt}");
        let node_b = format!("functional-stock-xds-b-{attempt}");
        let temp_a = TempDir::new().map_err(|e| format!("temp dir a: {e}"))?;
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let svids = generate_two_gateway_svids(temp_b.path(), A_SPIFFE, B_SPIFFE);
        let backend_port = start_stock_echo_backend().await?;

        let good_cluster = cluster_name(backend_port, "", SERVICE_HOST);
        let nopin_cluster = cluster_name(backend_port, "", NO_PIN_HOST);
        let subset_cluster = cluster_name(backend_port, "v1", SUBSET_HOST);
        let subset_cluster_representable = cluster_name(backend_port, "", SUBSET_HOST);
        let foreign_cluster = cluster_name(backend_port, "", FOREIGN_NAMESPACE_HOST);
        // Istio names an outbound route configuration after the port.
        let route_config_name = backend_port.to_string();

        // The converged initial state a stock control plane would program:
        // one outbound cluster, its endpoint assignment, the listener that
        // classifies the port as HTTP, and the route configuration naming it.
        let ads = StockAdsHandle::start(HashMap::from([
            (
                CDS_TYPE_URL.to_string(),
                response(
                    CDS_TYPE_URL,
                    "cds-1",
                    "cds-n1",
                    vec![any_resource(
                        CDS_TYPE_URL,
                        &eds_cluster(&good_cluster, Some(B_SPIFFE)),
                    )],
                ),
            ),
            (
                EDS_TYPE_URL.to_string(),
                response(
                    EDS_TYPE_URL,
                    "eds-1",
                    "eds-n1",
                    vec![any_resource(
                        EDS_TYPE_URL,
                        &assignment(&good_cluster, &[("127.0.0.1", backend_port)]),
                    )],
                ),
            ),
            (
                LDS_TYPE_URL.to_string(),
                response(
                    LDS_TYPE_URL,
                    "lds-1",
                    "lds-n1",
                    vec![any_resource(
                        LDS_TYPE_URL,
                        &hcm_listener(
                            &format!("0.0.0.0_{backend_port}"),
                            backend_port,
                            &route_config_name,
                            &["istio.metadata_exchange"],
                        ),
                    )],
                ),
            ),
            (
                RDS_TYPE_URL.to_string(),
                response(
                    RDS_TYPE_URL,
                    "rds-1",
                    "rds-n1",
                    vec![any_resource(
                        RDS_TYPE_URL,
                        &route_config(
                            &route_config_name,
                            &[SERVICE_HOST, &format!("{SERVICE_HOST}:{backend_port}")],
                            &good_cluster,
                        ),
                    )],
                ),
            ),
        ]))
        .await?;

        let policy_path = temp_a.path().join("stock-mesh-policy.json");
        std::fs::write(&policy_path, stock_policy_document())
            .map_err(|e| format!("write stock policy document: {e}"))?;
        let policy_path = policy_path
            .to_str()
            .ok_or("stock policy path is not UTF-8")?
            .to_string();

        let cp_b = start_static_mesh_cp(destination_slice(&node_b, backend_port)).await;
        let ports_a = reserve_mesh_ports().await;
        let ports_b = reserve_mesh_ports().await;
        let a_outbound_port = ports_a.outbound;
        let b_inbound_port = ports_b.inbound;

        // Gateway B: the destination sidecar. Its workload identity makes the
        // local services this pod backs (svc-b plus the phase-2a representable
        // extra hosts) inbound-routable, so :inbound Host matching reaches the
        // backend.
        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", B_SPIFFE.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.b.trust_bundle_path.clone(),
                    ),
                ],
            },
        );
        let readiness =
            wait_for_gateway_listener(&mut child_b, b_inbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway B inbound listener", b_inbound_port),
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            cp_b.shutdown().await;
            ads.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Gateway A: the stock-xDS-driven sidecar. Discovery comes from the
        // scripted third-party ADS server; the enforcement posture comes from
        // the local policy document, which is mandatory for this profile.
        let mut child_a = spawn_mesh_gateway(
            &temp_a,
            MeshGatewaySpawnOptions {
                // A stock control plane is dialled through
                // FERRUM_MESH_STOCK_XDS_URLS; the harness's Ferrum CP URL is
                // deliberately unused by this profile.
                cp_addr: cp_b.addr,
                ports: ports_a,
                node_id: &node_a,
                config_protocol: "stock_xds",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    // Refusal diagnostics are warnings; debug level also keeps
                    // the discovery/apply trail in the captured output.
                    ("FERRUM_LOG_LEVEL", "debug".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_STOCK_XDS_URLS", ads.url()),
                    (
                        "FERRUM_MESH_STOCK_XDS_NODE_ID",
                        "sidecar~127.0.0.1~client-app.ferrum~ferrum.svc.cluster.local".to_string(),
                    ),
                    ("FERRUM_MESH_FILE_CONFIG_PATH", policy_path.clone()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", A_SPIFFE.to_string()),
                    ("FERRUM_MESH_EGRESS_MTLS_PORT", b_inbound_port.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.a.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.a.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.a.trust_bundle_path.clone(),
                    ),
                ],
            },
        );
        let readiness =
            wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway A outbound listener", a_outbound_port),
                captured_output(&temp_a)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_b.shutdown().await;
            ads.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let outcome = run_stock_live_phases(
            &ads,
            a_outbound_port,
            backend_port,
            &good_cluster,
            &nopin_cluster,
            &subset_cluster,
            &subset_cluster_representable,
            &foreign_cluster,
            &route_config_name,
        )
        .await;

        // A gateway that exited during the run never owned the ports the driver
        // drove, so every observation above proves nothing about the mesh
        // datapath (issue #2132). Void the attempt and retry with fresh
        // fixtures instead of reporting the resulting transport errors.
        let exited = exited_gateway_diagnostic(&mut [
            ("gateway A", &mut child_a),
            ("gateway B", &mut child_b),
        ]);
        let logs = format!(
            "--- gateway A (stock_xds) ---\n{}\n--- gateway B (destination) ---\n{}",
            captured_output(&temp_a),
            captured_output(&temp_b)
        );
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        cp_b.shutdown().await;
        ads.shutdown().await;

        if let Some(exited) = exited {
            last_failure = format!("attempt {attempt}: {exited}\n{logs}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        return match outcome {
            Ok(mut observations) => {
                observations.logs = logs;
                Ok(observations)
            }
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "the stock xDS live fixture never came up after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// The live phase matrix, run once against a healthy fixture.
#[allow(clippy::too_many_arguments)]
async fn run_stock_live_phases(
    ads: &StockAdsHandle,
    outbound_port: u16,
    backend_port: u16,
    good_cluster: &str,
    nopin_cluster: &str,
    subset_cluster: &str,
    subset_cluster_representable: &str,
    foreign_cluster: &str,
    route_config_name: &str,
) -> Result<StockLiveObservations, String> {
    let endpoint = [("127.0.0.1", backend_port)];

    // ── Phase 1: the converged stock resources route real traffic ──
    let converged = wait_until_reachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 2a: representable pre-state for the hosts we will later refuse ──
    // Unpinned-peer and subset refusals can only be a reachability *change* if
    // the exact host was first routed under a representable resource. The
    // foreign-namespace cluster is included in the same generation so a later
    // withdrawal can prove that generation applied (the namespace itself
    // prevents a same-host representable pre-state).
    let cds_2 = ads.push(response(
        CDS_TYPE_URL,
        "cds-2",
        "cds-n2",
        vec![
            any_resource(CDS_TYPE_URL, &eds_cluster(good_cluster, Some(B_SPIFFE))),
            any_resource(CDS_TYPE_URL, &eds_cluster(nopin_cluster, Some(B_SPIFFE))),
            any_resource(
                CDS_TYPE_URL,
                &eds_cluster(subset_cluster_representable, Some(B_SPIFFE)),
            ),
            any_resource(CDS_TYPE_URL, &eds_cluster(foreign_cluster, Some(B_SPIFFE))),
        ],
    ));
    let eds_2 = ads.push(response(
        EDS_TYPE_URL,
        "eds-2",
        "eds-n2",
        vec![
            any_resource(EDS_TYPE_URL, &assignment(good_cluster, &endpoint)),
            any_resource(EDS_TYPE_URL, &assignment(nopin_cluster, &endpoint)),
            any_resource(
                EDS_TYPE_URL,
                &assignment(subset_cluster_representable, &endpoint),
            ),
            any_resource(EDS_TYPE_URL, &assignment(foreign_cluster, &endpoint)),
        ],
    ));
    ads.wait_for_ack(cds_2, CDS_TYPE_URL, "cds-2", "cds-n2")
        .await?;
    ads.wait_for_ack(eds_2, EDS_TYPE_URL, "eds-2", "eds-n2")
        .await?;
    let unpinned_peer_before = wait_until_reachable(outbound_port, NO_PIN_HOST).await?;
    let subset_cluster_before = wait_until_reachable(outbound_port, SUBSET_HOST).await?;

    // ── Phase 2b: change only the refusal-causing field / shape ──
    let cds_3 = ads.push(response(
        CDS_TYPE_URL,
        "cds-3",
        "cds-n3",
        vec![
            any_resource(CDS_TYPE_URL, &eds_cluster(good_cluster, Some(B_SPIFFE))),
            // Same cluster name as 2a; only the SAN pin is removed.
            any_resource(CDS_TYPE_URL, &eds_cluster(nopin_cluster, None)),
            // Same host as 2a; only the Istio subset name is introduced.
            any_resource(CDS_TYPE_URL, &eds_cluster(subset_cluster, Some(B_SPIFFE))),
            any_resource(CDS_TYPE_URL, &eds_cluster(foreign_cluster, Some(B_SPIFFE))),
        ],
    ));
    let eds_3 = ads.push(response(
        EDS_TYPE_URL,
        "eds-3",
        "eds-n3",
        vec![
            any_resource(EDS_TYPE_URL, &assignment(good_cluster, &endpoint)),
            any_resource(EDS_TYPE_URL, &assignment(nopin_cluster, &endpoint)),
            any_resource(EDS_TYPE_URL, &assignment(subset_cluster, &endpoint)),
            any_resource(EDS_TYPE_URL, &assignment(foreign_cluster, &endpoint)),
        ],
    ));
    ads.wait_for_ack(cds_3, CDS_TYPE_URL, "cds-3", "cds-n3")
        .await?;
    ads.wait_for_ack(eds_3, EDS_TYPE_URL, "eds-3", "eds-n3")
        .await?;
    let good_service_after_refusals = wait_until_reachable(outbound_port, SERVICE_HOST).await?;
    let unpinned_peer = wait_until_unreachable(outbound_port, NO_PIN_HOST).await?;
    let subset_cluster_probe = wait_until_unreachable(outbound_port, SUBSET_HOST).await?;

    // ── Phase 3: a structural error NACKs; the last-good view keeps serving ──
    let cds_4 = ads.push(response(
        CDS_TYPE_URL,
        "cds-4",
        "cds-n4",
        vec![
            any_resource(CDS_TYPE_URL, &eds_cluster(good_cluster, Some(B_SPIFFE))),
            any_resource(CDS_TYPE_URL, &eds_cluster(good_cluster, Some(B_SPIFFE))),
        ],
    ));
    let nack = ads.wait_for_nack(cds_4, CDS_TYPE_URL, "cds-n4").await?;
    let nack_message = nack
        .error_detail
        .as_ref()
        .map(|status| status.message.clone())
        .ok_or("the NACK request carried no error_detail")?;
    let nack_version_info = nack.version_info.clone();
    let good_service_after_nack = wait_until_reachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 4: withdrawing the endpoints removes reachability ──
    // The cluster stays, so this isolates endpoint deletion. It is also the
    // proof that the foreign-namespace generation applied as a valid slice:
    // an unauthorizable leftover attachment would freeze apply on the last
    // good generation and this withdrawal would never land.
    let eds_4 = ads.push(response(
        EDS_TYPE_URL,
        "eds-4",
        "eds-n4",
        vec![any_resource(EDS_TYPE_URL, &assignment(good_cluster, &[]))],
    ));
    ads.wait_for_ack(eds_4, EDS_TYPE_URL, "eds-4", "eds-n4")
        .await?;
    let endpoints_withdrawn = wait_until_unreachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 5: a replacement assignment restores it ──
    let eds_5 = ads.push(response(
        EDS_TYPE_URL,
        "eds-5",
        "eds-n5",
        vec![any_resource(
            EDS_TYPE_URL,
            &assignment(good_cluster, &endpoint),
        )],
    ));
    ads.wait_for_ack(eds_5, EDS_TYPE_URL, "eds-5", "eds-n5")
        .await?;
    let endpoints_restored = wait_until_reachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 6: state-of-the-world CDS withdrawal removes reachability ──
    // `cds-5` no longer names the service's cluster. Under SotW that IS the
    // deletion, and it must take the endpoints with it.
    let cds_5 = ads.push(response(
        CDS_TYPE_URL,
        "cds-5",
        "cds-n5",
        vec![any_resource(
            CDS_TYPE_URL,
            &eds_cluster(nopin_cluster, Some(B_SPIFFE)),
        )],
    ));
    ads.wait_for_ack(cds_5, CDS_TYPE_URL, "cds-5", "cds-n5")
        .await?;
    let cluster_withdrawn = wait_until_unreachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 7: re-publishing the cluster restores it ──
    let cds_6 = ads.push(response(
        CDS_TYPE_URL,
        "cds-6",
        "cds-n6",
        vec![any_resource(
            CDS_TYPE_URL,
            &eds_cluster(good_cluster, Some(B_SPIFFE)),
        )],
    ));
    ads.wait_for_ack(cds_6, CDS_TYPE_URL, "cds-6", "cds-n6")
        .await?;
    let eds_6 = ads.push(response(
        EDS_TYPE_URL,
        "eds-6",
        "eds-n6",
        vec![any_resource(
            EDS_TYPE_URL,
            &assignment(good_cluster, &endpoint),
        )],
    ));
    ads.wait_for_ack(eds_6, EDS_TYPE_URL, "eds-6", "eds-n6")
        .await?;
    let cluster_restored = wait_until_reachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 8: unsupported enforcement + routing constructs are refused ──
    // An RBAC HTTP filter refuses the whole listener (reducing it to plain
    // routing would turn the control plane's DENY into an ALLOW), and a
    // `weighted_clusters` route action is refused rather than approximated.
    // Both are CAPABILITY refusals: the response is ACKed, not NACKed, with a
    // field-specific diagnostic. FQDN routing comes from CDS, so this phase
    // does not claim a live widening proof for a host that was never dialable;
    // it proves the exact ACK, the diagnostic, and accepted-service continuity.
    let lds_2 = ads.push(response(
        LDS_TYPE_URL,
        "lds-2",
        "lds-n2",
        vec![any_resource(
            LDS_TYPE_URL,
            &hcm_listener(
                &format!("0.0.0.0_{backend_port}"),
                backend_port,
                route_config_name,
                &["envoy.filters.http.rbac"],
            ),
        )],
    ));
    ads.wait_for_ack(lds_2, LDS_TYPE_URL, "lds-2", "lds-n2")
        .await?;
    let rds_2 = ads.push(response(
        RDS_TYPE_URL,
        "rds-2",
        "rds-n2",
        vec![any_resource(
            RDS_TYPE_URL,
            &weighted_route_config(route_config_name, &[SERVICE_HOST]),
        )],
    ));
    ads.wait_for_ack(rds_2, RDS_TYPE_URL, "rds-2", "rds-n2")
        .await?;
    let lds_nacked = ads.nacked_after(lds_2, LDS_TYPE_URL, "lds-n2");
    let rds_nacked = ads.nacked_after(rds_2, RDS_TYPE_URL, "rds-n2");
    let good_service_after_capability_refusal =
        wait_until_reachable(outbound_port, SERVICE_HOST).await?;

    // ── Phase 9: the CP's SAN pin is a verification input ──
    // Same cluster, same endpoint, only the pinned peer identity changes — so
    // losing reachability here can only come from the mTLS peer check.
    let cds_7 = ads.push(response(
        CDS_TYPE_URL,
        "cds-7",
        "cds-n7",
        vec![any_resource(
            CDS_TYPE_URL,
            &eds_cluster(good_cluster, Some(IMPOSTOR_SPIFFE)),
        )],
    ));
    ads.wait_for_ack(cds_7, CDS_TYPE_URL, "cds-7", "cds-n7")
        .await?;
    let eds_7 = ads.push(response(
        EDS_TYPE_URL,
        "eds-7",
        "eds-n7",
        vec![any_resource(
            EDS_TYPE_URL,
            &assignment(good_cluster, &endpoint),
        )],
    ));
    ads.wait_for_ack(eds_7, EDS_TYPE_URL, "eds-7", "eds-n7")
        .await?;
    let impostor_pin = wait_until_unreachable(outbound_port, SERVICE_HOST).await?;

    Ok(StockLiveObservations {
        converged,
        unpinned_peer_before,
        unpinned_peer,
        subset_cluster_before,
        subset_cluster: subset_cluster_probe,
        good_service_after_refusals,
        nack_version_info,
        nack_message,
        good_service_after_nack,
        endpoints_withdrawn,
        endpoints_restored,
        cluster_withdrawn,
        cluster_restored,
        lds_nacked,
        rds_nacked,
        good_service_after_capability_refusal,
        impostor_pin,
        logs: String::new(),
    })
}

// ── the test ─────────────────────────────────────────────────────────────

/// Live keystone for issue #3317: standard v3 resources from a **third-party**
/// ADS server, consumed by the production `stock_xds` client, routing real
/// traffic through a real Ferrum proxy listener to a real backend — and every
/// update, deletion, NACK, and refusal asserted on that same data path.
#[ignore]
#[tokio::test]
async fn functional_mesh_stock_xds_live_datapath_matrix() {
    let observed = drive_stock_xds_live_datapath()
        .await
        .expect("stock xDS live datapath drive");
    let logs = &observed.logs;

    // Phase 1.
    assert!(
        observed.converged.reached_backend(),
        "a service discovered from standard CDS/EDS/LDS/RDS must route captured traffic through \
         the mesh transport to its backend — {}\n{logs}",
        observed.converged.describe("converged probe")
    );

    // Phase 2 — unpinned/subset are transition proofs; foreign-namespace
    // narrowing is proven by the exact ACK of cds-3 plus phases 4–7 still
    // applying (an invalid leftover attachment would freeze those updates).
    assert!(
        observed.unpinned_peer_before.reached_backend(),
        "the unpinned-peer host must first be routable under a representable pin — {}\n{logs}",
        observed.unpinned_peer_before.describe("unpinned pre-state")
    );
    assert!(
        observed.subset_cluster_before.reached_backend(),
        "the subset host must first be routable as a non-subset cluster — {}\n{logs}",
        observed.subset_cluster_before.describe("subset pre-state")
    );
    assert!(
        observed.good_service_after_refusals.reached_backend(),
        "the accepted service must keep serving while other resources are refused — {}\n{logs}",
        observed
            .good_service_after_refusals
            .describe("good service")
    );
    for (probe, what, reason) in [
        (
            &observed.unpinned_peer,
            "a cluster whose control plane pinned NO peer identity",
            "no_pinned_peer_identity",
        ),
        (
            &observed.subset_cluster,
            "a DestinationRule subset cluster",
            "subset_cluster_unsupported",
        ),
    ] {
        assert!(
            !probe.reached_backend(),
            "{what} must lose reachability after only the refusal-causing field changed — \
             {}\n{logs}",
            probe.describe("refused probe")
        );
        assert!(
            logs.contains(reason),
            "the refusal diagnostic '{reason}' must appear for {what}\n{logs}"
        );
    }

    // Phase 3 — a structural error NACKs and the last-good view keeps serving.
    assert!(
        observed
            .nack_message
            .contains("duplicate Cluster resource name"),
        "the NACK must carry a field-specific diagnostic, got: {:?}\n{logs}",
        observed.nack_message
    );
    assert_eq!(
        observed.nack_version_info, "cds-3",
        "a NACK re-asserts the last version the client actually accepted\n{logs}"
    );
    assert!(
        observed.good_service_after_nack.reached_backend(),
        "a NACKed response must leave the last good slice serving live traffic — {}\n{logs}",
        observed.good_service_after_nack.describe("post-NACK probe")
    );

    // Phases 4–7 — update / delete take effect on the live data path. Phase 4
    // is also the applied-generation proof for foreign-namespace narrowing:
    // an invalid leftover attachment would freeze apply and this withdrawal
    // would never land.
    assert!(
        !observed.endpoints_withdrawn.reached_backend(),
        "withdrawing a cluster's endpoints must remove reachability — {}\n{logs}",
        observed
            .endpoints_withdrawn
            .describe("withdrawn-endpoints probe")
    );
    assert!(
        observed.endpoints_restored.reached_backend(),
        "a replacement endpoint assignment must restore reachability — {}\n{logs}",
        observed
            .endpoints_restored
            .describe("restored-endpoints probe")
    );
    assert!(
        !observed.cluster_withdrawn.reached_backend(),
        "a state-of-the-world CDS response that omits the cluster must remove reachability — \
         {}\n{logs}",
        observed
            .cluster_withdrawn
            .describe("withdrawn-cluster probe")
    );
    assert!(
        observed.cluster_restored.reached_backend(),
        "re-publishing the cluster must restore reachability — {}\n{logs}",
        observed.cluster_restored.describe("restored-cluster probe")
    );

    // Phase 8 — capability refusals ACK with a field-specific diagnostic and
    // leave the accepted service serving. Semantic coverage that RBAC / weighted
    // routes contribute no listener or virtual host lives in the unit suite;
    // this phase does not claim a live widening proof for a never-dialable host.
    assert!(
        !observed.lds_nacked,
        "a well-formed listener carrying an unsupported enforcement filter is a CAPABILITY \
         refusal of lds-n2, not a structural NACK\n{logs}"
    );
    assert!(
        !observed.rds_nacked,
        "a well-formed route using an unsupported action is a CAPABILITY refusal of rds-n2, \
         not a structural NACK\n{logs}"
    );
    assert!(
        logs.contains("unsupported_http_filter") && logs.contains("envoy.filters.http.rbac"),
        "the enforcement-filter refusal must name the offending filter field\n{logs}"
    );
    assert!(
        logs.contains("unsupported_route_action")
            && logs.contains("routes[].route.weighted_clusters"),
        "the traffic-shaping refusal must name the offending route field\n{logs}"
    );
    assert!(
        observed
            .good_service_after_capability_refusal
            .reached_backend(),
        "refusing an unsupported listener/route must not disturb the accepted service — {}\n{logs}",
        observed
            .good_service_after_capability_refusal
            .describe("post-refusal probe")
    );

    // Phase 9 — the control plane's SAN pin is enforced, not decorative.
    assert!(
        !observed.impostor_pin.reached_backend(),
        "re-pinning the cluster's peer identity to an impostor SPIFFE must fail the mesh mTLS \
         dial closed — {}\n{logs}",
        observed.impostor_pin.describe("impostor-pin probe")
    );
}
