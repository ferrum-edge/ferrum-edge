//! Live stock-xDS ADS stream behaviour (issue #3317).
//!
//! Drives `start_stock_xds_client_with_shutdown` against a **scripted
//! third-party ADS server** — not Ferrum's own `XdsAdsServer` — so the test
//! exercises exactly what a stock Envoy / Istio control plane puts on the wire:
//! standard v3 `Cluster` / `ClusterLoadAssignment` / `Listener` /
//! `RouteConfiguration` resources with per-type versions and nonces.
//!
//! Asserted here (the decode/mapping half lives in
//! `tests/unit/gateway_core/stock_xds_tests.rs`):
//!
//! * a converged CDS+EDS stream installs a real `MeshSlice` whose policy half
//!   came from the local document and whose discovery half came from the CP,
//! * every response is ACKed with the received version + nonce echoed back,
//! * the EDS subscription is dependency-ordered by resource NAME rather than
//!   wildcarded,
//! * a structurally invalid response is NACKed with an `error_detail` and the
//!   previously installed slice keeps serving (last-good),
//! * a state-of-the-world CDS response that drops a cluster deletes it,
//! * a PARTIAL EDS push (the by-name types may carry a subset) leaves the
//!   assignments it did not mention dialable, and
//! * a reconnect re-subscribes with an empty nonce and the last ACCEPTED
//!   version, never the NACKed one.

use crate::scaffolding::port_registry::TestSocket;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
    StockPolicySnapshot, StockXdsClientConfig, load_stock_policy_baseline,
    start_stock_xds_client_with_shutdown,
};
use ferrum_edge::modes::mesh::config_consumer::stock_xds_credential::{
    StockCredentialInvalidReason, StockCredentialLifetimePolicy, StockCredentialState,
    StockCredentialWatch, StockXdsCredentialSource,
};
use ferrum_edge::modes::mesh::config_consumer::stream_lifecycle::{
    MeshConfigStreamStatus, MeshStreamTimings,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::xds::proto::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use ferrum_edge::xds::proto::{
    Any, DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use ferrum_edge::xds::stock::StockXdsLimits;
use ferrum_edge::xds::stock_proto as sp;
use ferrum_edge::xds::{CDS_TYPE_URL, EDS_TYPE_URL, SDS_TYPE_URL};
use std::sync::atomic::AtomicBool;

const REVIEWS_CLUSTER: &str = "outbound|9080||reviews.default.svc.cluster.local";
const RATINGS_CLUSTER: &str = "outbound|9080||ratings.default.svc.cluster.local";
const REVIEWS_SAN: &str = "spiffe://cluster.local/ns/default/sa/bookinfo-reviews";
/// A cluster for a service in ANOTHER namespace, endpointed by an identity in
/// THIS one. Ferrum's namespace narrowing keeps it out of this workload's view.
const FOREIGN_CLUSTER: &str = "outbound|9080||payments.other.svc.cluster.local";
/// Same shared-endpoint shape as `FOREIGN_CLUSTER`, but the foreign namespace
/// sorts *before* the local `default` namespace. A projection that stamped the
/// first BTree owner onto a shared (SPIFFE, address) workload would drop the
/// local endpoint when this foreign service later narrowed away.
const EARLIER_FOREIGN_CLUSTER: &str = "outbound|9080||payments.aaa.svc.cluster.local";
const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";

// ── scripted third-party ADS server ──────────────────────────────────────

/// One scripted response, keyed by the type URL whose FIRST subscription
/// request triggers it. Later entries for the same type are sent in order on
/// each subsequent request for that type, which is how the delete/NACK steps
/// are staged.
#[derive(Clone)]
struct ScriptedResponse {
    type_url: String,
    version: String,
    nonce: String,
    resources: Vec<Any>,
}

#[derive(Clone, Default)]
struct AdsRecorder {
    requests: Arc<Mutex<Vec<DiscoveryRequest>>>,
}

impl AdsRecorder {
    fn snapshot(&self) -> Vec<DiscoveryRequest> {
        self.requests
            .lock()
            .expect("ADS recorder mutex is never held across a panic")
            .clone()
    }

    /// Requests carrying a `type_url`, in arrival order.
    fn for_type(&self, type_url: &str) -> Vec<DiscoveryRequest> {
        self.snapshot()
            .into_iter()
            .filter(|request| request.type_url == type_url)
            .collect()
    }
}

struct ScriptedAdsServer {
    recorder: AdsRecorder,
    /// Per-type queue of scripted responses.
    script: Arc<Mutex<HashMap<String, Vec<ScriptedResponse>>>>,
    /// When set, the server closes the response stream as soon as it sees a
    /// request carrying an `error_detail`. Dropping the response sender ends
    /// the RPC cleanly, which is exactly the reconnect path the client takes
    /// after a control plane hangs up — and the only way to observe what the
    /// FIRST request on a fresh stream asserts.
    close_on_nack: bool,
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for ScriptedAdsServer {
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
        let script = self.script.clone();
        let close_on_nack = self.close_on_nack;
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            while let Ok(Some(discovery_request)) = inbound.message().await {
                let type_url = discovery_request.type_url.clone();
                let nacked = discovery_request.error_detail.is_some();
                recorder
                    .requests
                    .lock()
                    .expect("recorder mutex")
                    .push(discovery_request);
                if close_on_nack && nacked {
                    // Dropping `tx` completes the response stream, so the
                    // client observes a clean stream end and reconnects.
                    return;
                }
                // Every inbound request — initial subscription, subscription
                // update, ACK, or NACK — releases the next queued response for
                // that type. The queue is finite, so the exchange terminates.
                let next = {
                    let mut script = script.lock().expect("script mutex");
                    script.get_mut(&type_url).and_then(|queue| {
                        if queue.is_empty() {
                            None
                        } else {
                            Some(queue.remove(0))
                        }
                    })
                };
                if let Some(scripted) = next {
                    let response = DiscoveryResponse {
                        version_info: scripted.version,
                        resources: scripted.resources,
                        canary: false,
                        type_url: scripted.type_url,
                        nonce: scripted.nonce,
                        control_plane: None,
                    };
                    if tx.send(Ok(response)).await.is_err() {
                        return;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn delta_aggregated_resources(
        &self,
        _request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented(
            "delta xDS is not part of this fixture",
        ))
    }
}

// ── resource fixtures ────────────────────────────────────────────────────

fn any_resource(type_url: &str, message: &impl Message) -> Any {
    Any {
        type_url: type_url.to_string(),
        value: message.encode_to_vec(),
    }
}

fn tls_socket(san: &str) -> sp::TransportSocket {
    let context = sp::UpstreamTlsContext {
        common_tls_context: Some(sp::CommonTlsContext {
            combined_validation_context: Some(sp::CombinedCertificateValidationContext {
                default_validation_context: Some(sp::CertificateValidationContext {
                    match_typed_subject_alt_names: vec![sp::SubjectAltNameMatcher {
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

fn eds_cluster(name: &str, san: &str) -> sp::Cluster {
    sp::Cluster {
        name: name.to_string(),
        r#type: 3,
        eds_cluster_config: Some(sp::EdsClusterConfig {
            eds_config: Some(sp::ConfigSource {
                ads: vec![Vec::new()],
                ..Default::default()
            }),
            service_name: String::new(),
        }),
        transport_socket: Some(tls_socket(san)),
        ..Default::default()
    }
}

fn cla(cluster_name: &str, address: &str, port: u16) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: vec![sp::LbEndpoint {
                endpoint: Some(sp::Endpoint {
                    address: Some(sp::Address {
                        socket_address: Some(sp::SocketAddress {
                            address: address.to_string(),
                            port_value: u32::from(port),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                health_status: 1,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// A state-of-the-world assignment that withdraws every endpoint of `cluster`.
fn empty_cla(cluster_name: &str) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: Vec::new(),
            ..Default::default()
        }],
    }
}

// ── harness ──────────────────────────────────────────────────────────────

/// The local mesh POLICY document. It deliberately carries no `services` and no
/// `workloads` — those are the control plane's half — and one
/// PeerAuthentication so the test can prove the policy survived the merge.
const POLICY_DOCUMENT: &str = r#"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: default
      mtls_mode: strict
"#;

struct StockHarness {
    state: MeshRuntimeState,
    recorder: AdsRecorder,
    shutdown_tx: watch::Sender<bool>,
    _policy_dir: tempfile::TempDir,
}

impl StockHarness {
    async fn start(script: HashMap<String, Vec<ScriptedResponse>>) -> Self {
        Self::start_with(script, false).await
    }

    async fn start_with(
        script: HashMap<String, Vec<ScriptedResponse>>,
        close_on_nack: bool,
    ) -> Self {
        let policy_dir = tempfile::tempdir().expect("temp dir");
        let policy_path = policy_dir.path().join("mesh-policy.yaml");
        std::fs::write(&policy_path, POLICY_DOCUMENT).expect("write policy document");
        let baseline: MeshConfig =
            load_stock_policy_baseline(&policy_path).expect("policy document is valid");

        let recorder = AdsRecorder::default();
        let script = Arc::new(Mutex::new(script));
        let server = ScriptedAdsServer {
            recorder: recorder.clone(),
            script: script.clone(),
            close_on_nack,
        };

        let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind scripted ADS listener");
        let addr = listener.local_addr().expect("listener addr");
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(server))
                .serve_with_incoming(incoming)
                .await;
        });

        let state = MeshRuntimeState::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_policy_tx, policy_rx) =
            watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));

        let config = StockXdsClientConfig {
            xds_urls: vec![format!("http://127.0.0.1:{}", addr.port())],
            node_id: "sidecar~10.1.2.3~reviews.default~default.svc.cluster.local".to_string(),
            cluster: "default".to_string(),
            namespace: "default".to_string(),
            node_metadata: Default::default(),
            credential: StockXdsCredentialSource::unauthenticated(),
            // Loopback h2c with no bearer, outside production mode: exactly the
            // development posture issue #3853 keeps admissible.
            allow_loopback_plaintext: true,
            stream_channel_capacity: 32,
            primary_retry_secs: 0,
            connect_timeout_seconds: 5,
            limits: StockXdsLimits::default(),
            timings: MeshStreamTimings::production(),
        };
        let request = MeshSliceRequest {
            node_id: config.node_id.clone(),
            namespace: "default".to_string(),
            cluster_domain: "cluster.local".to_string(),
            ..MeshSliceRequest::default()
        };

        tokio::spawn(start_stock_xds_client_with_shutdown(
            config,
            request,
            state.clone(),
            shutdown_rx,
            None,
            None,
            policy_rx,
            MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false))),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
        ));

        Self {
            state,
            recorder,
            shutdown_tx,
            _policy_dir: policy_dir,
        }
    }

    /// Poll the installed slice until `predicate` holds, or fail after ~5s.
    async fn wait_for_slice(
        &self,
        label: &str,
        predicate: impl Fn(&MeshSlice) -> bool,
    ) -> MeshSlice {
        for _ in 0..250 {
            if let Some(slice) = self.state.snapshot().as_ref().clone()
                && predicate(&slice)
            {
                return slice;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for the installed mesh slice: {label}");
    }

    async fn wait_for_requests(&self, type_url: &str, count: usize) -> Vec<DiscoveryRequest> {
        for _ in 0..250 {
            let requests = self.recorder.for_type(type_url);
            if requests.len() >= count {
                return requests;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {count} '{type_url}' request(s)");
    }
}

impl Drop for StockHarness {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

fn converged_script() -> HashMap<String, Vec<ScriptedResponse>> {
    HashMap::from([
        (
            CDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: CDS_TYPE_URL.to_string(),
                version: "cds-v1".to_string(),
                nonce: "cds-n1".to_string(),
                resources: vec![
                    any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                    any_resource(CDS_TYPE_URL, &eds_cluster(RATINGS_CLUSTER, REVIEWS_SAN)),
                ],
            }],
        ),
        (
            EDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: EDS_TYPE_URL.to_string(),
                version: "eds-v1".to_string(),
                nonce: "eds-n1".to_string(),
                resources: vec![
                    any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                    any_resource(EDS_TYPE_URL, &cla(RATINGS_CLUSTER, "10.1.2.4", 9080)),
                ],
            }],
        ),
    ])
}

// ── tests ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn stock_ads_stream_installs_a_slice_merging_cp_discovery_with_local_policy() {
    let harness = StockHarness::start(converged_script()).await;
    let slice = harness
        .wait_for_slice("two discovered services", |slice| slice.services.len() == 2)
        .await;

    let mut names: Vec<&str> = slice
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["ratings", "reviews"]);

    let mut addresses: Vec<String> = slice
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.clone())
        .collect();
    addresses.sort();
    assert_eq!(
        addresses,
        vec!["10.1.2.3".to_string(), "10.1.2.4".to_string()],
        "EDS endpoints become dialable workloads under the CP's own SAN pin"
    );

    assert_eq!(
        slice.peer_authentications.len(),
        1,
        "the local policy document is the enforcement authority and must survive the merge"
    );
    assert_eq!(slice.peer_authentications[0].name, "strict-default");
    assert!(
        slice.revision.is_none(),
        "a stock control plane supplies no Ferrum ordering revision"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_ads_client_acks_with_the_received_version_and_nonce() {
    let harness = StockHarness::start(converged_script()).await;
    harness
        .wait_for_slice("first slice", |slice| !slice.services.is_empty())
        .await;

    let cds_requests = harness.wait_for_requests(CDS_TYPE_URL, 2).await;
    let initial = &cds_requests[0];
    assert!(
        initial.version_info.is_empty() && initial.response_nonce.is_empty(),
        "the initial subscription carries no version or nonce"
    );
    assert!(
        initial.node.is_some(),
        "the first request on a stream must carry Node so the CP can identify the proxy"
    );

    let ack = cds_requests
        .iter()
        .find(|request| !request.response_nonce.is_empty())
        .expect("an ACK follows the CDS response");
    assert_eq!(ack.version_info, "cds-v1");
    assert_eq!(ack.response_nonce, "cds-n1");
    assert!(
        ack.error_detail.is_none(),
        "a valid response is ACKed without an error_detail"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_eds_subscription_is_dependency_ordered_by_resource_name() {
    let harness = StockHarness::start(converged_script()).await;
    harness
        .wait_for_slice("first slice", |slice| !slice.services.is_empty())
        .await;

    let eds_requests = harness.wait_for_requests(EDS_TYPE_URL, 1).await;
    let subscription = eds_requests
        .iter()
        .find(|request| !request.resource_names.is_empty())
        .expect("EDS is subscribed by explicit resource name after CDS lands");
    let mut names = subscription.resource_names.clone();
    names.sort();
    assert_eq!(
        names,
        vec![RATINGS_CLUSTER.to_string(), REVIEWS_CLUSTER.to_string()],
        "Ferrum asks only for the assignments its accepted clusters reference"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_invalid_response_is_nacked_and_the_last_good_slice_keeps_serving() {
    let mut script = converged_script();
    // The ACK for the first CDS response releases this structurally invalid one
    // (two resources sharing a name), so the exchange is deterministic without
    // needing a reconnect.
    script
        .get_mut(CDS_TYPE_URL)
        .expect("CDS queue")
        .push(ScriptedResponse {
            type_url: CDS_TYPE_URL.to_string(),
            version: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
            ],
        });
    let harness = StockHarness::start(script).await;

    let nack = {
        let mut found = None;
        for _ in 0..250 {
            if let Some(request) = harness
                .recorder
                .for_type(CDS_TYPE_URL)
                .into_iter()
                .find(|request| request.error_detail.is_some())
            {
                found = Some(request);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        found.expect("the invalid CDS response is NACKed")
    };

    assert_eq!(nack.response_nonce, "cds-n2");
    assert_eq!(
        nack.version_info, "cds-v1",
        "a NACK re-asserts the last version the client actually accepted"
    );
    let detail = nack.error_detail.expect("a NACK carries error_detail");
    assert!(
        detail.message.contains("duplicate Cluster resource name"),
        "the NACK must carry a field-specific diagnostic, got: {}",
        detail.message
    );

    // The rolled-back accumulator still holds the first (valid) CDS response,
    // so the slice converges to the last good view rather than to the rejected
    // one — a NACK never shrinks or replaces what is serving.
    let slice = harness
        .wait_for_slice("last-good view survives the NACK", |slice| {
            slice.services.len() == 2
        })
        .await;
    let mut names: Vec<&str> = slice
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["ratings", "reviews"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_partial_eds_push_keeps_the_untouched_clusters_dialable() {
    // EDS is subscribed BY NAME, so a state-of-the-world response for it may
    // legitimately carry only the assignments a push touched — istiod skips
    // recomputing a cluster its update did not change. Treating the omission as
    // a deletion would blackhole every other service in the mesh.
    let mut script = converged_script();
    script
        .get_mut(EDS_TYPE_URL)
        .expect("EDS queue")
        .push(ScriptedResponse {
            type_url: EDS_TYPE_URL.to_string(),
            version: "eds-v2".to_string(),
            nonce: "eds-n2".to_string(),
            resources: vec![any_resource(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, "10.1.2.9", 9080),
            )],
        });

    let harness = StockHarness::start(script).await;
    let slice = harness
        .wait_for_slice("partial EDS push applied", |slice| {
            let addresses: Vec<&str> = slice
                .workloads
                .iter()
                .flat_map(|workload| workload.addresses.iter().map(String::as_str))
                .collect();
            addresses.contains(&"10.1.2.9") && addresses.contains(&"10.1.2.4")
        })
        .await;

    let mut addresses: Vec<String> = slice
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.clone())
        .collect();
    addresses.sort();
    assert_eq!(
        addresses,
        vec!["10.1.2.4".to_string(), "10.1.2.9".to_string()],
        "the pushed assignment is replaced; the untouched one keeps its endpoint"
    );
    assert_eq!(slice.services.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_reconnect_after_a_nack_reasserts_the_accepted_version_with_no_nonce() {
    // xDS nonces are stream-scoped and a NACKed version was never accepted, so
    // the first request on a fresh stream must carry an EMPTY response_nonce
    // and the last ACCEPTED version. Re-asserting the rejected version would
    // let a version-comparing control plane withhold the resource it already
    // sent, wedging the data plane permanently unconverged.
    let mut script = converged_script();
    script
        .get_mut(CDS_TYPE_URL)
        .expect("CDS queue")
        .push(ScriptedResponse {
            type_url: CDS_TYPE_URL.to_string(),
            version: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
            ],
        });
    let harness = StockHarness::start_with(script, true).await;

    // `Node` rides only the FIRST request per type on a stream, so the second
    // node-bearing CDS request is the subscription that opened the new stream.
    let resubscribe = {
        let mut found = None;
        for _ in 0..250 {
            let with_node: Vec<DiscoveryRequest> = harness
                .recorder
                .for_type(CDS_TYPE_URL)
                .into_iter()
                .filter(|request| request.node.is_some())
                .collect();
            if with_node.len() >= 2 {
                found = Some(with_node[1].clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        found.expect("the client reconnects and re-subscribes")
    };

    assert!(
        resubscribe.response_nonce.is_empty(),
        "a nonce from a previous stream is expired; a new stream must start clean, got '{}'",
        resubscribe.response_nonce
    );
    assert_eq!(
        resubscribe.version_info, "cds-v1",
        "the re-subscription asserts the last ACCEPTED version, never the NACKed one"
    );
    assert!(resubscribe.error_detail.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_unsolicited_sds_closes_the_stream_without_subscribing_to_sds() {
    let mut script = HashMap::new();
    script.insert(
        CDS_TYPE_URL.to_string(),
        vec![ScriptedResponse {
            // The server violates the subscription by replying to the initial
            // CDS request with SDS. Ferrum must close this stream without
            // emitting a DiscoveryRequest for SDS: in SotW, even a NACK with
            // empty resource_names would create a wildcard SDS subscription.
            type_url: SDS_TYPE_URL.to_string(),
            version: "sds-v1".to_string(),
            nonce: "sds-n1".to_string(),
            resources: vec![Any {
                type_url: SDS_TYPE_URL.to_string(),
                value: vec![0x0a, 0x07, b'd', b'e', b'f', b'a', b'u', b'l', b't'],
            }],
        }],
    );
    let harness = StockHarness::start(script).await;

    let mut reconnected = false;
    for _ in 0..250 {
        if harness.recorder.for_type(CDS_TYPE_URL).len() >= 2 {
            reconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        reconnected,
        "an unsolicited unsupported type must terminate the stream and reconnect"
    );
    assert!(
        harness
            .recorder
            .snapshot()
            .iter()
            .all(|request| request.type_url != SDS_TYPE_URL),
        "Ferrum must never turn an unsolicited SDS push into an SDS subscription"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_state_of_the_world_replacement_deletes_a_withdrawn_cluster() {
    let mut script = converged_script();
    // Released by the ACK for the first CDS response: `ratings` is withdrawn.
    script
        .get_mut(CDS_TYPE_URL)
        .expect("CDS queue")
        .push(ScriptedResponse {
            type_url: CDS_TYPE_URL.to_string(),
            version: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![any_resource(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN),
            )],
        });
    script
        .get_mut(EDS_TYPE_URL)
        .expect("EDS queue")
        .push(ScriptedResponse {
            type_url: EDS_TYPE_URL.to_string(),
            version: "eds-v2".to_string(),
            nonce: "eds-n2".to_string(),
            resources: vec![any_resource(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080),
            )],
        });

    let harness = StockHarness::start(script).await;
    let slice = harness
        .wait_for_slice("ratings withdrawn", |slice| {
            slice.services.len() == 1 && slice.services[0].name == "reviews"
        })
        .await;
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.addresses != vec!["10.1.2.4".to_string()]),
        "the withdrawn cluster's endpoints must not linger as a stale route"
    );
}

/// Every installed slice must still validate as a mesh configuration.
///
/// This is the contract the proxy apply path enforces before it swaps a slice
/// in (`prepare_normalized_gateway_config_for_mesh`). A slice that fails it is
/// rejected and the runtime rolls back to the last applied generation, so a
/// slice that carries a self-inconsistent projection does not merely lose one
/// resource — it freezes the data plane on stale config.
fn assert_slice_validates_as_mesh_config(slice: &MeshSlice, label: &str) {
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: slice.workloads.clone(),
            services: slice.services.clone(),
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let errors = config.validate_mesh_fields();
    assert!(
        errors.is_empty(),
        "{label}: the projected slice must validate as a mesh config, got {errors:?}"
    );
}

/// Does the slice carry a dialable workload at `address`?
fn has_endpoint(slice: &MeshSlice, address: &str) -> bool {
    slice
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.iter())
        .any(|candidate| candidate == address)
}

/// CDS/EDS in which the local `reviews` service and a service in ANOTHER
/// namespace both carry the SAME reachable endpoint, pinned to an identity in
/// THIS namespace.
fn shared_endpoint_with_foreign_namespace_script(
    foreign_cluster: &str,
) -> HashMap<String, Vec<ScriptedResponse>> {
    HashMap::from([
        (
            CDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: CDS_TYPE_URL.to_string(),
                version: "cds-v1".to_string(),
                nonce: "cds-n1".to_string(),
                resources: vec![
                    any_resource(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN)),
                    any_resource(CDS_TYPE_URL, &eds_cluster(foreign_cluster, REVIEWS_SAN)),
                ],
            }],
        ),
        (
            EDS_TYPE_URL.to_string(),
            vec![ScriptedResponse {
                type_url: EDS_TYPE_URL.to_string(),
                version: "eds-v1".to_string(),
                nonce: "eds-n1".to_string(),
                resources: vec![
                    any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                    any_resource(EDS_TYPE_URL, &cla(foreign_cluster, "10.1.2.3", 9080)),
                ],
            }],
        ),
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_foreign_namespace_cluster_narrows_while_the_local_service_stays_dialable() {
    // The foreign service is discovered with a genuinely REACHABLE endpoint, so
    // only Ferrum's own narrowing can keep it off this workload's data path.
    // The local service sharing that endpoint must be unaffected — which is what
    // makes the narrowing above a real observation rather than an empty slice.
    let harness = StockHarness::start(shared_endpoint_with_foreign_namespace_script(
        FOREIGN_CLUSTER,
    ))
    .await;
    let slice = harness
        .wait_for_slice("converged", |slice| has_endpoint(slice, "10.1.2.3"))
        .await;

    assert!(
        slice
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "a service in another namespace stays outside this workload's view: {:?}",
        slice
            .services
            .iter()
            .map(|service| format!("{}/{}", service.namespace, service.name))
            .collect::<Vec<_>>()
    );
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.attached_service_namespace() == "default"),
        "the shared endpoint belongs to the local service, not the narrowed-away one"
    );
    assert_slice_validates_as_mesh_config(&slice, "converged");
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_shared_endpoint_survives_when_the_foreign_namespace_sorts_first() {
    // `aaa` < `default`. A (SPIFFE, address) collapse would stamp the foreign
    // service as the owner, and namespace narrowing would then drop the local
    // reviews endpoint with it. Per-service workload records keep reviews
    // dialable while the foreign attachment narrows.
    assert!(
        "aaa" < "default",
        "this regression is the reverse-lexicographic owner order"
    );
    let harness = StockHarness::start(shared_endpoint_with_foreign_namespace_script(
        EARLIER_FOREIGN_CLUSTER,
    ))
    .await;
    let slice = harness
        .wait_for_slice("converged", |slice| has_endpoint(slice, "10.1.2.3"))
        .await;

    assert!(
        slice
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "a lexicographically-earlier foreign service still stays outside this view: {:?}",
        slice
            .services
            .iter()
            .map(|service| format!("{}/{}", service.namespace, service.name))
            .collect::<Vec<_>>()
    );
    assert!(
        slice.workloads.iter().any(|workload| {
            workload.service_name == "reviews"
                && workload.attached_service_namespace() == "default"
                && workload
                    .addresses
                    .iter()
                    .any(|address| address == "10.1.2.3")
        }),
        "the visible service must keep the shared endpoint after the earlier foreign owner narrows"
    );
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.attached_service_namespace() == "default"),
        "the foreign attachment must not survive as the owner of the shared endpoint"
    );
    assert_slice_validates_as_mesh_config(&slice, "reverse-lex shared endpoint");
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_foreign_namespace_cluster_does_not_block_a_later_endpoint_withdrawal() {
    // Once `reviews` loses its endpoint, the shared address is claimed by the
    // foreign-namespace service alone. Its endpoint must narrow WITH that
    // service rather than surviving as a workload whose cross-namespace
    // attachment nothing in the view can authorize: such a slice is refused at
    // proxy apply, and the rollback to the last applied generation would keep
    // this withdrawal — and every later change — from ever being applied.
    let mut script = shared_endpoint_with_foreign_namespace_script(FOREIGN_CLUSTER);
    // Released by the ACK for the first EDS response.
    script
        .get_mut(EDS_TYPE_URL)
        .expect("EDS queue")
        .push(ScriptedResponse {
            type_url: EDS_TYPE_URL.to_string(),
            version: "eds-v2".to_string(),
            nonce: "eds-n2".to_string(),
            resources: vec![any_resource(EDS_TYPE_URL, &empty_cla(REVIEWS_CLUSTER))],
        });

    let harness = StockHarness::start(script).await;
    let withdrawn = harness
        .wait_for_slice("endpoints withdrawn", |slice| slice.workloads.is_empty())
        .await;
    assert!(
        withdrawn
            .services
            .iter()
            .any(|service| service.name == "reviews"),
        "the cluster itself is still published; only its endpoints were withdrawn"
    );
    assert!(
        withdrawn
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "the foreign-namespace service must not reappear once it owns the shared endpoint"
    );
    assert_slice_validates_as_mesh_config(&withdrawn, "endpoints withdrawn");
}

// ── issues #3852 / #3853 / #3854: stream lifecycle and credential fixtures ──
//
// A second, self-contained harness. The fixtures above script ONE endpoint and
// assert discovery mapping; these script a primary/fallback PAIR (and, for the
// credential cases, a TLS endpoint) and assert what the stream lifecycle does
// when the peer misbehaves or the credential rotates.

mod stream_lifecycle {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// How the scripted endpoint behaves once the client subscribes.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum EndpointBehaviour {
        /// Accept the streaming RPC and immediately close it cleanly, forever.
        /// This is the shape that used to pin the client on the primary.
        CleanEofImmediately,
        /// ACK the first CDS request, then close cleanly without ever sending
        /// EDS. The accumulator's required-type gate is unsatisfied, so no
        /// slice may be published.
        PartialThenCleanEof,
        /// Accept the RPC and never send anything at all.
        Mute,
        /// Accept the authenticated streaming request and never return
        /// response headers. The RPC-open future stays pending until the
        /// first-frame bound cancels it.
        WithholdHeaders,
        /// Keep sending CDS-only frames so `message()` stays ready, without
        /// ever completing a generation. First-slice must still fire.
        IncompleteForever,
        /// Serve the converged CDS+EDS script.
        Converged,
    }

    /// The loopback h2c fixture. It carries NO credential machinery on
    /// purpose: a bearer is never admissible over plaintext, so everything
    /// credential-related is proven over real TLS in `super::tls_lifecycle`.
    #[derive(Clone)]
    pub(super) struct LifecycleAds {
        recorder: AdsRecorder,
        streams: Arc<AtomicUsize>,
        behaviour: EndpointBehaviour,
    }

    impl LifecycleAds {
        fn new(behaviour: EndpointBehaviour) -> Self {
            Self {
                recorder: AdsRecorder::default(),
                streams: Arc::new(AtomicUsize::new(0)),
                behaviour,
            }
        }

        pub(super) fn stream_count(&self) -> usize {
            self.streams.load(Ordering::SeqCst)
        }
    }

    #[tonic::async_trait]
    impl AggregatedDiscoveryService for LifecycleAds {
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
            self.streams.fetch_add(1, Ordering::SeqCst);
            let behaviour = self.behaviour;
            if behaviour == EndpointBehaviour::WithholdHeaders {
                let _held = request.into_inner();
                return std::future::pending().await;
            }
            let mut inbound = request.into_inner();
            let recorder = self.recorder.clone();
            let (tx, rx) = mpsc::channel(32);

            tokio::spawn(async move {
                if behaviour == EndpointBehaviour::CleanEofImmediately {
                    // Drain one request so the client's subscription is
                    // recorded, then drop `tx`: a clean gRPC OK / EOF.
                    if let Ok(Some(discovery_request)) = inbound.message().await {
                        recorder
                            .requests
                            .lock()
                            .expect("recorder mutex")
                            .push(discovery_request);
                    }
                    return;
                }
                if behaviour == EndpointBehaviour::Mute {
                    if let Ok(Some(discovery_request)) = inbound.message().await {
                        recorder
                            .requests
                            .lock()
                            .expect("recorder mutex")
                            .push(discovery_request);
                    }
                    // Hold the response stream open forever without a frame.
                    std::future::pending::<()>().await;
                }
                if behaviour == EndpointBehaviour::IncompleteForever {
                    tokio::spawn(async move {
                        while inbound.message().await.ok().flatten().is_some() {}
                    });
                    let mut nonce = 0u64;
                    loop {
                        nonce = nonce.saturating_add(1);
                        let response = DiscoveryResponse {
                            version_info: format!("cds-v{nonce}"),
                            resources: vec![
                                any_resource(
                                    CDS_TYPE_URL,
                                    &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN),
                                ),
                                any_resource(
                                    CDS_TYPE_URL,
                                    &eds_cluster(RATINGS_CLUSTER, REVIEWS_SAN),
                                ),
                            ],
                            canary: false,
                            type_url: CDS_TYPE_URL.to_string(),
                            nonce: format!("cds-n{nonce}"),
                            control_plane: None,
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }

                let mut sent_cds = false;
                let mut sent_eds = false;
                while let Ok(Some(discovery_request)) = inbound.message().await {
                    let type_url = discovery_request.type_url.clone();
                    let has_resource_names = !discovery_request.resource_names.is_empty();
                    recorder
                        .requests
                        .lock()
                        .expect("recorder mutex")
                        .push(discovery_request);
                    if type_url == CDS_TYPE_URL && !sent_cds {
                        sent_cds = true;
                        let response = DiscoveryResponse {
                            version_info: "cds-v1".to_string(),
                            resources: vec![
                                any_resource(
                                    CDS_TYPE_URL,
                                    &eds_cluster(REVIEWS_CLUSTER, REVIEWS_SAN),
                                ),
                                any_resource(
                                    CDS_TYPE_URL,
                                    &eds_cluster(RATINGS_CLUSTER, REVIEWS_SAN),
                                ),
                            ],
                            canary: false,
                            type_url: CDS_TYPE_URL.to_string(),
                            nonce: "cds-n1".to_string(),
                            control_plane: None,
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                        if behaviour == EndpointBehaviour::PartialThenCleanEof {
                            // Let the ACK land, then hang up mid-convergence.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            return;
                        }
                        continue;
                    }
                    if type_url == EDS_TYPE_URL
                        && behaviour == EndpointBehaviour::Converged
                        && !sent_eds
                        && has_resource_names
                    {
                        sent_eds = true;
                        let response = DiscoveryResponse {
                            version_info: "eds-v1".to_string(),
                            resources: vec![
                                any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                                any_resource(EDS_TYPE_URL, &cla(RATINGS_CLUSTER, "10.1.2.4", 9080)),
                            ],
                            canary: false,
                            type_url: EDS_TYPE_URL.to_string(),
                            nonce: "eds-n1".to_string(),
                            control_plane: None,
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                }
            });

            Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
        }

        async fn delta_aggregated_resources(
            &self,
            _request: Request<Streaming<DeltaDiscoveryRequest>>,
        ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
            Err(Status::unimplemented(
                "delta xDS is not part of this fixture",
            ))
        }
    }

    /// Boot one scripted endpoint. Returns its handle and its `scheme://host:port`.
    pub(super) async fn serve(behaviour: EndpointBehaviour) -> (LifecycleAds, String) {
        let handle = LifecycleAds::new(behaviour);
        let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind lifecycle ADS listener");
        let addr = listener.local_addr().expect("listener addr");
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let served = handle.clone();
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(served))
                .serve_with_incoming(incoming)
                .await;
        });
        (handle, format!("http://127.0.0.1:{}", addr.port()))
    }

    pub(super) struct LifecycleHarness {
        pub(super) state: MeshRuntimeState,
        shutdown_tx: watch::Sender<bool>,
        client: tokio::task::JoinHandle<()>,
        /// Held so the client's policy-watch arm stays open for the whole test;
        /// a closed channel is not what these fixtures are exercising.
        _policy_tx: watch::Sender<StockPolicySnapshot>,
        _policy_dir: tempfile::TempDir,
    }

    impl LifecycleHarness {
        pub(super) async fn start(
            urls: Vec<String>,
            credential: StockXdsCredentialSource,
            credential_watch: StockCredentialWatch,
            timings: MeshStreamTimings,
        ) -> Self {
            let policy_dir = tempfile::tempdir().expect("temp dir");
            let policy_path = policy_dir.path().join("mesh-policy.yaml");
            std::fs::write(&policy_path, POLICY_DOCUMENT).expect("write policy document");
            let baseline =
                load_stock_policy_baseline(&policy_path).expect("policy document is valid");

            let state = MeshRuntimeState::new();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (policy_tx, policy_rx) =
                watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));

            let config = StockXdsClientConfig {
                xds_urls: urls,
                node_id: "sidecar~10.1.2.3~reviews.default~default.svc.cluster.local".to_string(),
                cluster: "default".to_string(),
                namespace: "default".to_string(),
                node_metadata: Default::default(),
                credential,
                allow_loopback_plaintext: true,
                stream_channel_capacity: 32,
                primary_retry_secs: 0,
                connect_timeout_seconds: 5,
                limits: StockXdsLimits::default(),
                timings,
            };
            let request = MeshSliceRequest {
                node_id: config.node_id.clone(),
                namespace: "default".to_string(),
                cluster_domain: "cluster.local".to_string(),
                ..MeshSliceRequest::default()
            };

            let client = tokio::spawn(start_stock_xds_client_with_shutdown(
                config,
                request,
                state.clone(),
                shutdown_rx,
                None,
                None,
                policy_rx,
                MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false))),
                credential_watch,
            ));

            Self {
                state,
                shutdown_tx,
                client,
                _policy_tx: policy_tx,
                _policy_dir: policy_dir,
            }
        }

        pub(super) async fn wait_for_services(&self, expected: usize) -> MeshSlice {
            for _ in 0..400 {
                if let Some(slice) = self.state.snapshot().as_ref().clone()
                    && slice.services.len() == expected
                {
                    return slice;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("timed out waiting for {expected} discovered services");
        }

        fn config_stream_state(&self) -> Option<&'static str> {
            self.state.config_stream_status().map(|status| status.state)
        }

        fn last_outcome(&self) -> Option<&'static str> {
            self.state
                .config_stream_status()
                .map(|status| status.last_attempt_outcome)
        }

        /// Prove the client task actually joins on shutdown rather than being
        /// left detached with a live stream.
        pub(super) async fn shutdown_and_join(self) {
            let _ = self.shutdown_tx.send(true);
            tokio::time::timeout(Duration::from_secs(10), self.client)
                .await
                .expect("the stock xDS client must observe shutdown and return")
                .expect("the stock xDS client task must not panic");
        }
    }

    /// Issue #3854, acceptance criterion 1. Before the shared policy, a primary
    /// that returned a clean EOF was recorded as a SUCCESSFUL attempt: backoff
    /// reset and the client stayed on index 0 forever, so the configured
    /// fallback never received the subscription.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_clean_eof_primary_hands_the_subscription_to_the_fallback() {
        let (primary, primary_url) = serve(EndpointBehaviour::CleanEofImmediately).await;
        let (fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![primary_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings::production(),
        )
        .await;

        let slice = harness.wait_for_services(2).await;
        assert_eq!(slice.services.len(), 2);
        assert!(
            fallback.stream_count() >= 1,
            "the fallback must actually have been dialed"
        );
        assert!(
            primary.stream_count() >= 1,
            "the primary must have been tried first"
        );
        harness.shutdown_and_join().await;
    }

    /// Issue #3854, acceptance criterion 2. A primary that ACKs only some of
    /// the required ADS types and then closes must publish NOTHING — a mixed
    /// generation is worse than no generation — and the fallback must converge
    /// a complete one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_partial_generation_followed_by_eof_publishes_no_mixed_state() {
        let (primary, primary_url) = serve(EndpointBehaviour::PartialThenCleanEof).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![primary_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings::production(),
        )
        .await;

        // The primary delivers CDS only. `accumulator.ready()` is false without
        // EDS, so nothing may be installed from it.
        for _ in 0..20 {
            // The CDS-only generation carries clusters but no endpoints, so any
            // slice observed here with empty `workloads` would be exactly the
            // mixed state that must never be published.
            if let Some(slice) = harness.state.snapshot().as_ref().clone() {
                assert!(
                    !slice.workloads.is_empty(),
                    "a CDS-only generation must never be published"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let slice = harness.wait_for_services(2).await;
        assert!(
            !slice.workloads.is_empty(),
            "the fallback's complete generation carries endpoints"
        );
        assert!(primary.stream_count() >= 1);
        harness.shutdown_and_join().await;
    }

    /// Issue #3854. A control plane that accepts the RPC and then supplies no
    /// frame at all must not hold startup: the first-frame bound fires and the
    /// fallback delivers the first usable slice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mute_primary_cannot_hold_startup_indefinitely() {
        let (mute, mute_url) = serve(EndpointBehaviour::Mute).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![mute_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings {
                first_frame: Duration::from_millis(300),
                // Generous on purpose: the mute primary is meant to fail on the
                // FIRST-FRAME bound, and the fallback must not race a tight
                // first-slice deadline in hosted CI.
                first_slice: Duration::from_secs(15),
                ..MeshStreamTimings::production()
            },
        )
        .await;

        let slice = harness.wait_for_services(2).await;
        assert_eq!(slice.services.len(), 2);
        assert!(mute.stream_count() >= 1);
        harness.shutdown_and_join().await;
    }

    /// A control plane that accepts the streaming RPC and never returns
    /// response headers — with no stock bearer configured — must still lose
    /// to the first-frame bound. The RPC-open await is inside that absolute
    /// clock; headers do not have to arrive before it starts.
    #[tokio::test(flavor = "multi_thread")]
    async fn withholding_headers_without_a_bearer_cannot_hold_startup() {
        let (withholding, withholding_url) = serve(EndpointBehaviour::WithholdHeaders).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![withholding_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings {
                first_frame: Duration::from_millis(300),
                first_slice: Duration::from_secs(15),
                ..MeshStreamTimings::production()
            },
        )
        .await;

        let slice = harness.wait_for_services(2).await;
        assert_eq!(slice.services.len(), 2);
        assert!(withholding.stream_count() >= 1);
        assert_eq!(
            harness.last_outcome(),
            Some("first_frame_timeout"),
            "header withholding must be classified as first-frame, not a hang"
        );
        harness.shutdown_and_join().await;
    }

    /// Incomplete CDS-only frames that keep `message()` ready must not starve
    /// the first-slice clock. The fallback delivers the first usable slice.
    #[tokio::test(flavor = "multi_thread")]
    async fn incomplete_frames_cannot_outrun_first_slice() {
        let (incomplete, incomplete_url) = serve(EndpointBehaviour::IncompleteForever).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![incomplete_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings {
                first_frame: Duration::from_secs(5),
                first_slice: Duration::from_millis(400),
                ..MeshStreamTimings::production()
            },
        )
        .await;

        let slice = harness.wait_for_services(2).await;
        assert_eq!(slice.services.len(), 2);
        assert!(incomplete.stream_count() >= 1);
        assert_eq!(
            harness.last_outcome(),
            Some("first_slice_timeout"),
            "a continuously ready incomplete generation must still hit first-slice"
        );
        harness.shutdown_and_join().await;
    }

    /// Issue #3854. The closed-set readiness projection must reach
    /// `/health` — `never_received_slice` while startup is blocked, then
    /// `connected` once a generation is serving.
    #[tokio::test(flavor = "multi_thread")]
    async fn health_reports_closed_set_stream_reasons() {
        let (_primary, primary_url) = serve(EndpointBehaviour::CleanEofImmediately).await;
        let (_fallback, fallback_url) = serve(EndpointBehaviour::Converged).await;

        let harness = LifecycleHarness::start(
            vec![primary_url, fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            MeshStreamTimings::production(),
        )
        .await;

        // Before any slice, readiness must say so explicitly. The client
        // publishes its first status as it starts, so wait for the publication
        // rather than racing the spawn.
        let mut startup_state = None;
        for _ in 0..200 {
            if let Some(state) = harness.config_stream_state() {
                startup_state = Some(state);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            startup_state,
            Some("never_received_slice"),
            "startup readiness must be distinguishable from serving-last-good"
        );

        harness.wait_for_services(2).await;
        // The clean-EOF attempt is what produced the failover, and it must be
        // reported by its own reason rather than as a success.
        let outcome = harness.last_outcome().expect("an attempt was recorded");
        assert_eq!(outcome, "remote_clean_eof", "{outcome}");
        harness.shutdown_and_join().await;
    }

    /// Issue #3852. An invalid credential source must PREVENT reconnection —
    /// not merely fail one read and fall back to the previously seen token.
    ///
    /// The endpoint is addressed over `https://` so the transport gate admits
    /// it and the credential gate is unambiguously what stops the dial. The
    /// proof is `last_attempt_outcome == "none"`: had the client attempted the
    /// connection, that field would carry `transport_failure` instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invalid_credential_source_prevents_reconnection() {
        let (endpoint, plain_url) = serve(EndpointBehaviour::Converged).await;
        let secure_url = plain_url.replacen("http://", "https://", 1);
        let temp = tempfile::tempdir().expect("temp dir");
        let absent = temp.path().join("never-written-token");

        let credential = StockXdsCredentialSource::new(
            Some(absent.to_string_lossy().into_owned()),
            StockCredentialLifetimePolicy::default(),
        );
        let credential_watch = StockCredentialWatch::new(StockCredentialState::Invalid {
            reason: StockCredentialInvalidReason::Missing,
        });

        let harness = LifecycleHarness::start(
            vec![secure_url],
            credential,
            credential_watch,
            MeshStreamTimings::production(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(750)).await;
        assert_eq!(
            endpoint.stream_count(),
            0,
            "an invalid credential source must block the connection attempt entirely"
        );
        assert!(!harness.state.has_first_slice());
        let status = harness
            .state
            .config_stream_status()
            .expect("status is published even while blocked");
        assert_eq!(status.credential, "source_invalid");
        assert_eq!(status.state, "never_received_slice");
        assert_eq!(
            status.last_attempt_outcome, "none",
            "no connection attempt may be made while the credential source is invalid"
        );
        harness.shutdown_and_join().await;
    }
}

// ── issues #3852 / #3853 / #3854: LIVE TLS ADS lifecycle ─────────────────
//
// The fixtures above run the production stock client over loopback h2c, which
// is the only posture issue #3853 still admits without a bearer. Everything a
// BEARER touches has to be proven over real authenticated TLS, because that is
// the only transport the client will attach one to. This module therefore
// stands up an actual TLS ADS server (rcgen CA + tonic `ServerTlsConfig`),
// drives `start_stock_xds_client_with_shutdown` against it with the real
// credential watcher running, and asserts what the *server* observed on the
// wire — per-RPC `authorization` metadata — rather than re-testing the
// materialization primitives in isolation.
mod tls_lifecycle {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // The two transport-liveness proofs below (blackhole and healthy-idle) are
    // protocol-agnostic and reuse the loopback h2c fixtures rather than paying
    // for TLS they do not exercise.
    use super::stream_lifecycle::{EndpointBehaviour, LifecycleHarness, serve};

    use ferrum_edge::config::env_config::EnvConfig;
    use ferrum_edge::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload};
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_credential::{
        StockCredentialWatch as CredentialWatch, start_stock_credential_watcher_with_shutdown,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tonic::transport::{Certificate, Identity, ServerTlsConfig};

    const THIRD_CLUSTER: &str = "outbound|9080||poison.default.svc.cluster.local";

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    }

    /// One CA plus a server leaf and a client leaf issued from it.
    ///
    /// Everything is issued in one call so the `rcgen::Issuer` never has to be
    /// named in a struct field, which keeps this fixture insensitive to rcgen's
    /// issuer lifetime parameterization.
    struct IssuedMaterial {
        ca_pem: Vec<u8>,
        server_cert_pem: Vec<u8>,
        server_key_pem: Vec<u8>,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
    }

    /// `server_dns` are the leaf's dNSName SANs. `server_expired` backdates the
    /// leaf's validity window so the negative expired-certificate case uses a
    /// genuinely expired certificate rather than a mocked verifier.
    fn issue_material(server_dns: &[&str], server_expired: bool) -> IssuedMaterial {
        ensure_crypto_provider();
        let ca_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["Ferrum Stock xDS Test CA".to_string()])
                .expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
        let ca_pem = ca_cert.pem().into_bytes();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let server_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
        let mut server_params = rcgen::CertificateParams::new(
            server_dns
                .iter()
                .map(|d| (*d).to_string())
                .collect::<Vec<_>>(),
        )
        .expect("server params");
        // The loopback iPAddress SAN is what the client actually verifies
        // against; it is added only for leaves that are meant to be valid for
        // this fixture, so a `wrong.example`-only leaf is a real mismatch.
        if server_dns.contains(&"localhost") {
            server_params
                .subject_alt_names
                .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
                    std::net::Ipv4Addr::LOCALHOST,
                )));
        }
        if server_expired {
            server_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
            server_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        }
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server leaf");

        let client_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
        let client_params =
            rcgen::CertificateParams::new(vec!["ferrum-dp".to_string()]).expect("client params");
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client leaf");

        IssuedMaterial {
            ca_pem,
            server_cert_pem: server_cert.pem().into_bytes(),
            server_key_pem: server_key.serialize_pem().into_bytes(),
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
        }
    }

    /// What a scripted TLS ADS endpoint does once the streaming RPC is open.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TlsBehaviour {
        /// Serve CDS then EDS for two services and hold the stream open.
        Converged,
        /// Accept the RPC and neither read the request stream nor answer it.
        /// This is the "stalled consumer" shape: the client must still reach a
        /// bounded retirement instead of parking on an awaited send.
        StallRequests,
        /// Receive/accept the authenticated streaming request (the bearer is
        /// on the inbound metadata) and never return response headers. The
        /// client's RPC-open future stays pending until a local credential
        /// retirement cancels it.
        WithholdHeaders,
    }

    #[derive(Clone)]
    struct TlsAds {
        /// `authorization` metadata observed on each accepted RPC, in order.
        authorizations: Arc<Mutex<Vec<String>>>,
        streams: Arc<AtomicUsize>,
        behaviour: TlsBehaviour,
        /// Flipped by the test to make the FIRST stream push an extra cluster
        /// after the credential has already been observed as rotated.
        poison: watch::Receiver<bool>,
        /// Set when that extra push was actually written to the first stream.
        poison_written: Arc<AtomicBool>,
    }

    impl TlsAds {
        fn stream_count(&self) -> usize {
            self.streams.load(Ordering::SeqCst)
        }

        fn authorization_snapshot(&self) -> Vec<String> {
            self.authorizations
                .lock()
                .expect("authorization mutex is never held across a panic")
                .clone()
        }
    }

    fn cds_response(clusters: &[&str], version: &str, nonce: &str) -> DiscoveryResponse {
        DiscoveryResponse {
            version_info: version.to_string(),
            resources: clusters
                .iter()
                .map(|name| any_resource(CDS_TYPE_URL, &eds_cluster(name, REVIEWS_SAN)))
                .collect(),
            canary: false,
            type_url: CDS_TYPE_URL.to_string(),
            nonce: nonce.to_string(),
            control_plane: None,
        }
    }

    fn eds_response() -> DiscoveryResponse {
        DiscoveryResponse {
            version_info: "eds-v1".to_string(),
            resources: vec![
                any_resource(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, "10.1.2.3", 9080)),
                any_resource(EDS_TYPE_URL, &cla(RATINGS_CLUSTER, "10.1.2.4", 9080)),
            ],
            canary: false,
            type_url: EDS_TYPE_URL.to_string(),
            nonce: "eds-n1".to_string(),
            control_plane: None,
        }
    }

    #[tonic::async_trait]
    impl AggregatedDiscoveryService for TlsAds {
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
            let stream_index = self.streams.fetch_add(1, Ordering::SeqCst);
            let observed = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<none>")
                .to_string();
            self.authorizations
                .lock()
                .expect("authorization mutex")
                .push(observed);

            let behaviour = self.behaviour;
            if behaviour == TlsBehaviour::WithholdHeaders {
                // The handler has accepted the authenticated request. Parking
                // here never returns `Ok(Response)`, so tonic never writes
                // response headers. Hold the inbound stream so the RPC stays
                // accepted until the client cancels the pending open.
                let _held = request.into_inner();
                return std::future::pending().await;
            }

            let mut inbound = request.into_inner();
            // `Option` + `take()`: the inner spawn moves the receiver, and the
            // compiler cannot see that the `sent_eds` guard makes that happen at
            // most once per stream.
            let mut poison = Some(self.poison.clone());
            let poison_written = self.poison_written.clone();
            let (tx, rx) = mpsc::channel(32);

            tokio::spawn(async move {
                if behaviour == TlsBehaviour::StallRequests {
                    // Never read `inbound`, never send: hold both halves open.
                    // `inbound` and `tx` stay alive for the whole park, so the
                    // client sees an established, silent, non-consuming peer.
                    let _held = (inbound, tx);
                    std::future::pending::<()>().await;
                    return;
                }

                let mut sent_cds = false;
                let mut sent_eds = false;
                while let Ok(Some(discovery_request)) = inbound.message().await {
                    let type_url = discovery_request.type_url.clone();
                    let has_resource_names = !discovery_request.resource_names.is_empty();
                    if type_url == CDS_TYPE_URL && !sent_cds {
                        sent_cds = true;
                        if tx
                            .send(Ok(cds_response(
                                &[REVIEWS_CLUSTER, RATINGS_CLUSTER],
                                "cds-v1",
                                "cds-n1",
                            )))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                    if type_url == EDS_TYPE_URL && !sent_eds && has_resource_names {
                        sent_eds = true;
                        if tx.send(Ok(eds_response())).await.is_err() {
                            return;
                        }
                        // Only the FIRST stream can be poisoned: every later
                        // stream serves the same two services, so a slice that
                        // ever shows three could only have come from the stream
                        // the credential rotation retired.
                        if stream_index == 0
                            && let Some(mut poison) = poison.take()
                        {
                            let poison_tx = tx.clone();
                            let written = poison_written.clone();
                            tokio::spawn(async move {
                                while poison.changed().await.is_ok() {
                                    if !*poison.borrow() {
                                        continue;
                                    }
                                    let sent = poison_tx
                                        .send(Ok(cds_response(
                                            &[REVIEWS_CLUSTER, RATINGS_CLUSTER, THIRD_CLUSTER],
                                            "cds-v2",
                                            "cds-n2",
                                        )))
                                        .await
                                        .is_ok();
                                    written.store(sent, Ordering::SeqCst);
                                    return;
                                }
                            });
                        }
                    }
                }
            });

            Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
        }

        async fn delta_aggregated_resources(
            &self,
            _request: Request<Streaming<DeltaDiscoveryRequest>>,
        ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
            Err(Status::unimplemented(
                "delta xDS is not part of this fixture",
            ))
        }
    }

    /// A live TLS ADS endpoint plus the handle needed to join its task.
    struct TlsEndpoint {
        ads: TlsAds,
        url: String,
        poison_tx: watch::Sender<bool>,
        shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl TlsEndpoint {
        async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            // A parked handler holds its connection task, so the graceful wait
            // is bounded and then the accept loop is torn down explicitly.
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
            self.task.abort();
        }
    }

    /// Bind a TLS ADS endpoint. `require_client_cert` makes it mTLS.
    async fn serve_tls(
        behaviour: TlsBehaviour,
        material: &IssuedMaterial,
        require_client_cert: bool,
    ) -> TlsEndpoint {
        let (poison_tx, poison_rx) = watch::channel(false);
        let ads = TlsAds {
            authorizations: Arc::new(Mutex::new(Vec::new())),
            streams: Arc::new(AtomicUsize::new(0)),
            behaviour,
            poison: poison_rx,
            poison_written: Arc::new(AtomicBool::new(false)),
        };

        let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind TLS ADS listener");
        let port = listener.local_addr().expect("listener addr").port();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(
            &material.server_cert_pem,
            &material.server_key_pem,
        ));
        if require_client_cert {
            tls = tls.client_ca_root(Certificate::from_pem(&material.ca_pem));
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let served = ads.clone();
        let task = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .expect("server TLS configuration")
                .add_service(AggregatedDiscoveryServiceServer::new(served))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        TlsEndpoint {
            ads,
            // The literal loopback IP, matched against the leaf's iPAddress
            // SAN. A `localhost` authority would depend on the host's
            // resolver preferring A over AAAA, which hosted runners do not
            // guarantee — and the SAN-mismatch case below proves hostname
            // verification is genuinely enforced either way.
            url: format!("https://127.0.0.1:{port}"),
            poison_tx,
            shutdown_tx: Some(shutdown_tx),
            task,
        }
    }

    /// Everything a live TLS attempt needs, so each test states only what it
    /// varies.
    struct TlsClientSpec {
        urls: Vec<String>,
        token_path: Option<std::path::PathBuf>,
        policy: StockCredentialLifetimePolicy,
        tls_config: Option<DpGrpcTlsConfig>,
        tls_reload: Option<DpGrpcTlsReload>,
        timings: MeshStreamTimings,
        /// Run the production credential watcher alongside the client.
        watch_credential: bool,
    }

    struct TlsHarness {
        state: MeshRuntimeState,
        credential_watch: CredentialWatch,
        shutdown_tx: watch::Sender<bool>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
        _policy_dir: tempfile::TempDir,
        _policy_tx: watch::Sender<StockPolicySnapshot>,
    }

    impl TlsHarness {
        async fn start(spec: TlsClientSpec) -> Self {
            let policy_dir = tempfile::tempdir().expect("temp dir");
            let policy_path = policy_dir.path().join("mesh-policy.yaml");
            std::fs::write(&policy_path, POLICY_DOCUMENT).expect("write policy document");
            let baseline =
                load_stock_policy_baseline(&policy_path).expect("policy document is valid");

            let credential = StockXdsCredentialSource::new(
                spec.token_path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                spec.policy,
            );
            let credential_watch = CredentialWatch::new(credential.initial_state());

            let state = MeshRuntimeState::new();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (policy_tx, policy_rx) =
                watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));

            let config = StockXdsClientConfig {
                xds_urls: spec.urls,
                node_id: "sidecar~10.1.2.3~reviews.default~default.svc.cluster.local".to_string(),
                cluster: "default".to_string(),
                namespace: "default".to_string(),
                node_metadata: Default::default(),
                credential: credential.clone(),
                // Irrelevant here: every endpoint is `https://`, which is the
                // only posture a bearer may ride.
                allow_loopback_plaintext: false,
                stream_channel_capacity: 32,
                primary_retry_secs: 0,
                connect_timeout_seconds: 5,
                limits: StockXdsLimits::default(),
                timings: spec.timings,
            };
            let request = MeshSliceRequest {
                node_id: config.node_id.clone(),
                namespace: "default".to_string(),
                cluster_domain: "cluster.local".to_string(),
                ..MeshSliceRequest::default()
            };

            let mut tasks = Vec::new();
            if spec.watch_credential {
                tasks.push(tokio::spawn(start_stock_credential_watcher_with_shutdown(
                    credential,
                    credential_watch.clone(),
                    shutdown_rx.clone(),
                )));
            }
            tasks.push(tokio::spawn(start_stock_xds_client_with_shutdown(
                config,
                request,
                state.clone(),
                shutdown_rx,
                spec.tls_config,
                spec.tls_reload,
                policy_rx,
                MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false))),
                credential_watch.clone(),
            )));

            Self {
                state,
                credential_watch,
                shutdown_tx,
                tasks,
                _policy_dir: policy_dir,
                _policy_tx: policy_tx,
            }
        }

        fn services(&self) -> Option<usize> {
            self.state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.services.len())
        }

        async fn wait_for_services(&self, expected: usize, what: &str) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                if self.services() == Some(expected) {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for {expected} services ({what}); observed {:?}",
                    self.services()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        fn status_field<T>(&self, pick: impl Fn(&MeshConfigStreamStatus) -> T) -> Option<T> {
            self.state.config_stream_status().as_ref().map(pick)
        }

        /// Prove every spawned task joins on shutdown rather than being left
        /// detached with a live stream or a live credential watcher.
        async fn shutdown_and_join(self) {
            let _ = self.shutdown_tx.send(true);
            for task in self.tasks {
                tokio::time::timeout(Duration::from_secs(15), task)
                    .await
                    .expect("every mesh background task must observe shutdown and return")
                    .expect("no mesh background task may panic");
            }
        }
    }

    fn dp_tls(material: &IssuedMaterial, with_client_cert: bool) -> DpGrpcTlsConfig {
        DpGrpcTlsConfig {
            ca_cert_pem: Some(material.ca_pem.clone()),
            client_cert_pem: with_client_cert.then(|| material.client_cert_pem.clone()),
            client_key_pem: with_client_cert.then(|| material.client_key_pem.clone()),
        }
    }

    fn write_token(dir: &tempfile::TempDir, name: &str, value: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, value.as_bytes()).expect("write token");
        path
    }

    /// A JWT-shaped token whose `exp` is `secs_from_now` in the future. The
    /// signature is never verified — the client uses `exp` only as a local
    /// reconnect-scheduling hint that may never schedule past expiry.
    fn jwt_expiring_in(secs_from_now: i64) -> String {
        use base64::Engine as _;
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs() as i64
            + secs_from_now;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
            r#"{{"exp":{exp},"sub":"system:serviceaccount:default:reviews"}}"#
        ));
        format!("{header}.{payload}.c2ln")
    }

    fn fast_timings() -> MeshStreamTimings {
        MeshStreamTimings {
            first_frame: Duration::from_secs(10),
            first_slice: Duration::from_secs(20),
            ..MeshStreamTimings::production()
        }
    }

    fn fast_policy(max_stream_lifetime: Duration) -> StockCredentialLifetimePolicy {
        StockCredentialLifetimePolicy {
            max_stream_lifetime,
            refresh_skew: Duration::from_secs(0),
            // Compressed so a rotation is observed inside a hosted test rather
            // than after the shipped 10s cadence.
            watch_interval: Duration::from_millis(100),
        }
    }

    // ── issue #3852: live rotation, invalidation, and deadlines ──────────

    /// Issue #3852, acceptance criteria 1 and 5, proven against a real
    /// authenticated TLS ADS server driving the production client.
    ///
    /// A healthy stream is established with token one; the projected token is
    /// then replaced. The production credential watcher observes it, the stream
    /// is retired, and the NEXT RPC carries only token two. A response the
    /// retired stream emits after that observation must never be installed:
    /// only the first stream can push a third cluster, so a slice that ever
    /// shows three services could only have come from the retired credential.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rotated_projected_token_retires_the_live_stream_and_only_the_new_token_is_presented()
    {
        let material = issue_material(&["localhost"], false);
        let endpoint = serve_tls(TlsBehaviour::Converged, &material, false).await;
        let tokens = tempfile::tempdir().expect("temp dir");
        let token_path = write_token(&tokens, "projected-token", "projected-token-one");

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![endpoint.url.clone()],
            token_path: Some(token_path.clone()),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(dp_tls(&material, false)),
            tls_reload: None,
            timings: fast_timings(),
            watch_credential: true,
        })
        .await;

        harness
            .wait_for_services(2, "the first authenticated stream")
            .await;
        assert_eq!(endpoint.ads.stream_count(), 1);
        assert_eq!(
            endpoint.ads.authorization_snapshot(),
            vec!["Bearer projected-token-one".to_string()],
            "the ADS server must receive the bearer over the authenticated TLS channel"
        );
        assert_eq!(
            harness.status_field(|status| status.state),
            Some("connected"),
            "a live stream serving usable configuration is `connected`"
        );
        assert_eq!(
            harness.status_field(|status| status.credential),
            Some("valid")
        );

        // A continuous sampler: the retired stream's push must never become
        // visible, not merely be absent at the end.
        let sampler_state = harness.state.clone();
        let sampler_stop = Arc::new(AtomicBool::new(false));
        let stop = sampler_stop.clone();
        let sampler = tokio::spawn(async move {
            let mut worst = 0usize;
            while !stop.load(Ordering::SeqCst) {
                if let Some(slice) = sampler_state.snapshot().as_ref().as_ref() {
                    worst = worst.max(slice.services.len());
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            worst
        });

        let generation_before = harness.credential_watch.latest().generation;
        std::fs::write(&token_path, b"projected-token-two").expect("rotate token");

        // Wait until the PRODUCTION watcher has observed the rotation, then
        // make the retired stream push its poison frame.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while harness.credential_watch.latest().generation == generation_before {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the credential watcher must observe the rotation"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = endpoint.poison_tx.send(true);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while endpoint.ads.stream_count() < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the rotation must retire the stream and open a new one"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        harness.wait_for_services(2, "the replacement stream").await;

        let observed = endpoint.ads.authorization_snapshot();
        assert!(observed.len() >= 2, "{observed:?}");
        assert_eq!(observed[0], "Bearer projected-token-one");
        for (index, value) in observed.iter().enumerate().skip(1) {
            assert_eq!(
                value, "Bearer projected-token-two",
                "RPC #{index} must carry only the replacement token: {observed:?}"
            );
        }

        sampler_stop.store(true, Ordering::SeqCst);
        let worst = sampler.await.expect("sampler task");
        assert_eq!(
            worst,
            2,
            "a response from the retired credential's stream must never be installed \
             (poison_written={})",
            endpoint.ads.poison_written.load(Ordering::SeqCst)
        );

        harness.shutdown_and_join().await;
        endpoint.shutdown().await;
    }

    /// Issue #3852, acceptance criterion 2: invalidating a previously HEALTHY
    /// source retires the stream and blocks reconnection until valid material
    /// returns.
    ///
    /// The live case is exercised through the real reader with the
    /// representative shapes a projected secret actually reaches — deleted,
    /// then empty — and recovery is proven by writing valid material back. The
    /// exhaustive boundary matrix (non-regular, oversized, invalid UTF-8,
    /// non-ASCII metadata, unreadable-where-portable, expired) runs through the
    /// same `StockXdsCredentialSource::materialize` boundary in
    /// `tests/unit/gateway_core/mesh_stream_lifecycle_tests.rs`, because a
    /// live server cannot distinguish them: they all produce the identical
    /// closed `SourceInvalid` posture and the identical refusal to dial.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn invalidating_a_healthy_credential_source_blocks_reconnect_until_it_returns() {
        let material = issue_material(&["localhost"], false);
        let endpoint = serve_tls(TlsBehaviour::Converged, &material, false).await;
        let tokens = tempfile::tempdir().expect("temp dir");
        let token_path = write_token(&tokens, "projected-token", "projected-token-one");

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![endpoint.url.clone()],
            token_path: Some(token_path.clone()),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(dp_tls(&material, false)),
            tls_reload: None,
            timings: fast_timings(),
            watch_credential: true,
        })
        .await;

        harness.wait_for_services(2, "the healthy stream").await;
        let healthy_streams = endpoint.ads.stream_count();
        assert_eq!(healthy_streams, 1);

        // Delete it, then leave an empty replacement: both are unusable, and
        // neither may permit a reconnect.
        std::fs::remove_file(&token_path).expect("delete token");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if harness.status_field(|status| status.credential) == Some("source_invalid") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the deleted source must be observed as invalid"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        std::fs::write(&token_path, b"   \n").expect("write empty token");

        // The last-good slice keeps serving while reconnection is refused.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            endpoint.ads.stream_count(),
            healthy_streams,
            "an invalid credential source must PREVENT reconnection, not merely fail one read"
        );
        assert_eq!(
            harness.services(),
            Some(2),
            "the already-installed slice keeps serving"
        );
        assert_eq!(
            harness.status_field(|status| status.credential),
            Some("source_invalid")
        );

        // Valid material returns: the client reconnects and presents it.
        std::fs::write(&token_path, b"projected-token-three").expect("restore token");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while endpoint.ads.stream_count() <= healthy_streams {
            assert!(
                tokio::time::Instant::now() < deadline,
                "valid replacement material must reopen the stream"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let observed = endpoint.ads.authorization_snapshot();
        assert_eq!(
            observed.last().map(String::as_str),
            Some("Bearer projected-token-three")
        );

        harness.shutdown_and_join().await;
        endpoint.shutdown().await;
    }

    /// Issue #3852, acceptance criterion 5: an unchanged token must not churn
    /// the ADS stream, even though the watcher re-reads it ten times a second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unchanged_token_does_not_churn_the_stream() {
        let material = issue_material(&["localhost"], false);
        let endpoint = serve_tls(TlsBehaviour::Converged, &material, false).await;
        let tokens = tempfile::tempdir().expect("temp dir");
        let token_path = write_token(&tokens, "projected-token", "projected-token-stable");

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![endpoint.url.clone()],
            token_path: Some(token_path.clone()),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(dp_tls(&material, false)),
            tls_reload: None,
            timings: fast_timings(),
            watch_credential: true,
        })
        .await;

        harness.wait_for_services(2, "the stable stream").await;
        let generation = harness.credential_watch.latest().generation;

        // Rewrite the SAME bytes: content-based detection must not see a change.
        for _ in 0..5 {
            std::fs::write(&token_path, b"projected-token-stable").expect("rewrite token");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        assert_eq!(
            endpoint.ads.stream_count(),
            1,
            "an unchanged credential must not retire a healthy stream"
        );
        assert_eq!(harness.credential_watch.latest().generation, generation);
        assert_eq!(
            harness.status_field(|status| status.state),
            Some("connected")
        );

        harness.shutdown_and_join().await;
        endpoint.shutdown().await;
    }

    /// Issue #3852, acceptance criteria 3 and 4.
    ///
    /// A short-lived JWT reconnects strictly BEFORE `exp` even though the peer
    /// would happily keep the stream open, and an opaque token reconnects at
    /// the finite maximum stream lifetime even though the file never changes.
    /// The two cases share one fixture because the observable is identical: a
    /// second RPC with no external stimulus at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_finite_authorization_deadline_reconnects_without_any_external_stimulus() {
        for (label, jwt_lifetime_secs, policy, must_reconnect_within) in [
            (
                "opaque",
                None,
                // Below the operator-facing 60s minimum on purpose: that floor
                // is enforced where an operator can set it, so a programmatic
                // policy can prove the deadline live without a production wait.
                fast_policy(Duration::from_secs(2)),
                Duration::from_secs(25),
            ),
            (
                "short-lived JWT",
                Some(3),
                fast_policy(Duration::from_secs(3600)),
                Duration::from_secs(25),
            ),
        ] {
            // Mint each credential only when its case starts. Constructing the
            // whole table eagerly lets the opaque case consume the JWT case's
            // intentionally short wall-clock lifetime before it is admitted.
            let token = jwt_lifetime_secs
                .map_or_else(|| "an-opaque-projected-token".to_string(), jwt_expiring_in);
            let material = issue_material(&["localhost"], false);
            let endpoint = serve_tls(TlsBehaviour::Converged, &material, false).await;
            let tokens = tempfile::tempdir().expect("temp dir");
            let token_path = write_token(&tokens, "projected-token", &token);

            let harness = TlsHarness::start(TlsClientSpec {
                urls: vec![endpoint.url.clone()],
                token_path: Some(token_path),
                policy,
                tls_config: Some(dp_tls(&material, false)),
                tls_reload: None,
                timings: fast_timings(),
                // No watcher: nothing about the SOURCE changes, so only the
                // authorization deadline can produce a second RPC.
                watch_credential: false,
            })
            .await;

            harness
                .wait_for_services(2, "the first deadline-bounded stream")
                .await;
            let started = tokio::time::Instant::now();
            let deadline = started + must_reconnect_within;
            while endpoint.ads.stream_count() < 2 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{label}: the credential deadline must retire the stream with no external \
                     stimulus"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            harness.shutdown_and_join().await;
            endpoint.shutdown().await;
        }
    }

    /// The stock bearer fence must cover the ADS RPC-open await itself: a
    /// control plane can accept the authenticated streaming request (bearer
    /// already attached) and then withhold response headers, leaving
    /// `stream_aggregated_resources(...).await` pending past rotation,
    /// invalidation, or the absolute deadline. The established-stream fence
    /// loop cannot save that case because it starts only after headers return.
    ///
    /// Production first-frame timing is used so this proof is about the
    /// credential fence, not the first-frame bound: a 2s credential deadline
    /// still wins over a 60s first-frame clock, including when both become
    /// ready in the same poll. An already-ready or simultaneous credential
    /// retirement must reset retired-credential discovery state as today.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn withholding_rpc_open_headers_cannot_outlive_credential_retirement() {
        struct Case {
            label: &'static str,
            expected_outcome: &'static str,
            watch_credential: bool,
            token: String,
            policy: StockCredentialLifetimePolicy,
            after_accept: AfterAccept,
        }
        enum AfterAccept {
            WaitForDeadline,
            Rotate,
            Invalidate,
        }

        for case in [
            Case {
                label: "absolute deadline",
                expected_outcome: "credential_deadline",
                watch_credential: false,
                token: "an-opaque-projected-token".to_string(),
                policy: fast_policy(Duration::from_secs(2)),
                after_accept: AfterAccept::WaitForDeadline,
            },
            Case {
                label: "credential rotation",
                expected_outcome: "credential_rotated",
                watch_credential: true,
                token: "projected-token-one".to_string(),
                policy: fast_policy(Duration::from_secs(3600)),
                after_accept: AfterAccept::Rotate,
            },
            Case {
                label: "source invalidation",
                expected_outcome: "credential_source_invalid",
                watch_credential: true,
                token: "projected-token-one".to_string(),
                policy: fast_policy(Duration::from_secs(3600)),
                after_accept: AfterAccept::Invalidate,
            },
        ] {
            let material = issue_material(&["localhost"], false);
            let endpoint = serve_tls(TlsBehaviour::WithholdHeaders, &material, false).await;
            let tokens = tempfile::tempdir().expect("temp dir");
            let token_path = write_token(&tokens, "projected-token", &case.token);

            let harness = TlsHarness::start(TlsClientSpec {
                urls: vec![endpoint.url.clone()],
                token_path: Some(token_path.clone()),
                policy: case.policy,
                tls_config: Some(dp_tls(&material, false)),
                tls_reload: None,
                timings: MeshStreamTimings::production(),
                watch_credential: case.watch_credential,
            })
            .await;

            let sampler_state = harness.state.clone();
            let sampler_stop = Arc::new(AtomicBool::new(false));
            let stop = sampler_stop.clone();
            let sampler = tokio::spawn(async move {
                let mut saw_slice = false;
                while !stop.load(Ordering::SeqCst) {
                    if sampler_state.snapshot().as_ref().as_ref().is_some() {
                        saw_slice = true;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                saw_slice
            });

            let accepted = tokio::time::Instant::now() + Duration::from_secs(20);
            while endpoint.ads.stream_count() == 0 {
                assert!(
                    tokio::time::Instant::now() < accepted,
                    "{}: the ADS server must accept the authenticated streaming request",
                    case.label
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let expected_bearer = format!("Bearer {}", case.token);
            assert_eq!(
                endpoint.ads.authorization_snapshot().first(),
                Some(&expected_bearer),
                "{}: the withheld-headers RPC must have carried the bearer",
                case.label
            );
            let streams_at_accept = endpoint.ads.stream_count();

            match case.after_accept {
                AfterAccept::WaitForDeadline => {}
                AfterAccept::Rotate => {
                    std::fs::write(&token_path, b"projected-token-two").expect("rotate token");
                }
                AfterAccept::Invalidate => {
                    std::fs::remove_file(&token_path).expect("delete token");
                }
            }

            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                if harness.status_field(|status| status.last_attempt_outcome)
                    == Some(case.expected_outcome)
                {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{}: pending RPC-open must retire as {} within a bounded time; last={:?} \
                     services={:?}",
                    case.label,
                    case.expected_outcome,
                    harness.status_field(|status| status.last_attempt_outcome),
                    harness.services()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            assert!(
                harness.services().is_none(),
                "{}: no discovery response can commit while headers are withheld",
                case.label
            );

            match case.after_accept {
                AfterAccept::WaitForDeadline => {
                    // Opaque material is still valid, so the client reconnects
                    // immediately. The replacement open is also withheld.
                    let reconnect = tokio::time::Instant::now() + Duration::from_secs(10);
                    while endpoint.ads.stream_count() <= streams_at_accept {
                        assert!(
                            tokio::time::Instant::now() < reconnect,
                            "{}: a deadline retirement must reconnect without charging backoff",
                            case.label
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                AfterAccept::Rotate => {
                    let reconnect = tokio::time::Instant::now() + Duration::from_secs(20);
                    while endpoint.ads.stream_count() <= streams_at_accept {
                        assert!(
                            tokio::time::Instant::now() < reconnect,
                            "{}: rotation must cancel the pending open and start a replacement",
                            case.label
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    let observed = endpoint.ads.authorization_snapshot();
                    assert!(observed.len() >= 2, "{}: {observed:?}", case.label);
                    assert_eq!(observed[0], "Bearer projected-token-one");
                    for (index, value) in observed.iter().enumerate().skip(1) {
                        assert_eq!(
                            value, "Bearer projected-token-two",
                            "{}: RPC #{index} must carry only the replacement token: {observed:?}",
                            case.label
                        );
                    }
                }
                AfterAccept::Invalidate => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    assert_eq!(
                        endpoint.ads.stream_count(),
                        streams_at_accept,
                        "{}: an invalid source must prevent reconnection",
                        case.label
                    );
                    assert_eq!(
                        harness.status_field(|status| status.credential),
                        Some("source_invalid"),
                        "{}",
                        case.label
                    );
                }
            }

            sampler_stop.store(true, Ordering::SeqCst);
            let saw_slice = sampler.await.expect("sampler task");
            assert!(
                !saw_slice,
                "{}: a withheld-headers RPC must never install a slice",
                case.label
            );

            harness.shutdown_and_join().await;
            endpoint.shutdown().await;
        }
    }

    /// Issue #3852, acceptance criterion 7: failover and failback always
    /// materialize the LATEST token rather than replaying the value captured by
    /// an earlier endpoint's interceptor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failover_presents_the_newest_token_to_the_fallback_endpoint() {
        let material = issue_material(&["localhost"], false);
        // The primary accepts the RPC and then neither reads nor answers, so
        // the bounded first-frame policy rotates to the fallback.
        let primary = serve_tls(TlsBehaviour::StallRequests, &material, false).await;
        let fallback = serve_tls(TlsBehaviour::Converged, &material, false).await;
        let tokens = tempfile::tempdir().expect("temp dir");
        let token_path = write_token(&tokens, "projected-token", "projected-token-one");

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![primary.url.clone(), fallback.url.clone()],
            token_path: Some(token_path.clone()),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(dp_tls(&material, false)),
            tls_reload: None,
            timings: MeshStreamTimings {
                first_frame: Duration::from_millis(400),
                first_slice: Duration::from_secs(20),
                ..MeshStreamTimings::production()
            },
            watch_credential: true,
        })
        .await;

        // Rotate while the client is still stuck on the stalled primary, so the
        // fallback's very first RPC must carry the replacement.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while primary.ads.stream_count() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the primary must be dialed first"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::write(&token_path, b"projected-token-two").expect("rotate token");

        harness
            .wait_for_services(2, "the fallback after a stalled primary")
            .await;

        let observed = fallback.ads.authorization_snapshot();
        assert!(!observed.is_empty());
        assert_eq!(
            observed.last().map(String::as_str),
            Some("Bearer projected-token-two"),
            "the fallback must present the newest material: {observed:?}"
        );
        assert_eq!(
            harness.status_field(|status| status.fallback_active),
            Some(true),
            "the client is attached to a non-primary endpoint"
        );

        harness.shutdown_and_join().await;
        primary.shutdown().await;
        fallback.shutdown().await;
    }

    /// Issue #3852, acceptance criterion 6: simultaneous TLS and token rotation
    /// produces ONE bounded reconnect that uses the newest values for both.
    ///
    /// The client first establishes a healthy stream with token one over a
    /// trusted CA so old-credential discovery state actually exists. The CA
    /// file and token are then replaced together and the TLS revision is
    /// bumped. The outer lifecycle must not let the TLS-reload arm mask the
    /// credential retirement: the replacement RPC carries only token two over
    /// the newly loaded CA, and a poison push from the retired stream must
    /// never be installed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn simultaneous_tls_and_token_rotation_yields_one_reconnect_with_the_newest_material() {
        let serving = issue_material(&["localhost"], false);
        let endpoint = serve_tls(TlsBehaviour::Converged, &serving, false).await;

        let dir = tempfile::tempdir().expect("temp dir");
        let ca_path = dir.path().join("cp-ca.pem");
        std::fs::write(&ca_path, &serving.ca_pem).expect("write serving CA");
        let token_path = write_token(&dir, "projected-token", "projected-token-one");

        let env_config = Arc::new(EnvConfig {
            dp_grpc_tls_ca_cert_path: Some(ca_path.to_string_lossy().into_owned()),
            ..EnvConfig::default()
        });
        let (revision_tx, revision_rx) = watch::channel(0u64);

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![endpoint.url.clone()],
            token_path: Some(token_path.clone()),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(DpGrpcTlsConfig {
                ca_cert_pem: Some(serving.ca_pem.clone()),
                client_cert_pem: None,
                client_key_pem: None,
            }),
            tls_reload: Some(DpGrpcTlsReload {
                env_config,
                label: "Mesh",
                revision_rx,
            }),
            timings: fast_timings(),
            watch_credential: true,
        })
        .await;

        harness
            .wait_for_services(2, "the established old-credential stream")
            .await;
        assert_eq!(endpoint.ads.stream_count(), 1);
        assert_eq!(
            endpoint.ads.authorization_snapshot(),
            vec!["Bearer projected-token-one".to_string()],
            "the first stream must present the original token over the original CA"
        );
        assert_eq!(
            harness.status_field(|status| status.state),
            Some("connected")
        );

        let sampler_state = harness.state.clone();
        let sampler_stop = Arc::new(AtomicBool::new(false));
        let stop = sampler_stop.clone();
        let sampler = tokio::spawn(async move {
            let mut worst = 0usize;
            while !stop.load(Ordering::SeqCst) {
                if let Some(slice) = sampler_state.snapshot().as_ref().as_ref() {
                    worst = worst.max(slice.services.len());
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            worst
        });

        let generation_before = harness.credential_watch.latest().generation;
        std::fs::write(&ca_path, &serving.ca_pem).expect("reload serving CA from disk");
        std::fs::write(&token_path, b"projected-token-two").expect("rotate token");
        revision_tx.send_replace(1);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while harness.credential_watch.latest().generation == generation_before {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the credential watcher must observe the rotation"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = endpoint.poison_tx.send(true);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while endpoint.ads.stream_count() < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the simultaneous TLS + token events must retire the established stream \
                 and open a replacement"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        harness
            .wait_for_services(2, "the coalesced TLS + token rotation")
            .await;
        let observed = endpoint.ads.authorization_snapshot();
        assert!(observed.len() >= 2, "{observed:?}");
        assert_eq!(observed[0], "Bearer projected-token-one");
        assert_eq!(
            endpoint.ads.stream_count(),
            2,
            "the two simultaneous lifecycle events must coalesce into ONE replacement stream; \
             observed {observed:?}"
        );
        for (index, value) in observed.iter().enumerate().skip(1) {
            assert_eq!(
                value, "Bearer projected-token-two",
                "RPC #{index} must carry only the replacement token over the newest TLS: \
                 {observed:?}"
            );
        }

        sampler_stop.store(true, Ordering::SeqCst);
        let worst = sampler.await.expect("sampler task");
        assert_eq!(
            worst,
            2,
            "old-credential discovery state and the retired stream's poison push must not \
             carry across the simultaneous TLS + token event (poison_written={})",
            endpoint.ads.poison_written.load(Ordering::SeqCst)
        );

        harness.shutdown_and_join().await;
        endpoint.shutdown().await;
    }

    // ── issue #3853: negative TLS acceptance ─────────────────────────────

    /// Issue #3853, acceptance criterion 7. Each case must fail closed BEFORE a
    /// slice — or any authorization-bearing discovery update — is accepted.
    /// A bearer is configured throughout, so these also prove the credential
    /// never rides a session whose server identity was not established.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn untrusted_mismatched_expired_and_mtls_less_servers_all_fail_closed() {
        // (label, server material, client TLS, server requires a client cert)
        let good = issue_material(&["localhost"], false);
        let other = issue_material(&["localhost"], false);
        let mismatched = issue_material(&["wrong.example"], false);
        let expired = issue_material(&["localhost"], true);

        let cases: Vec<(&str, &IssuedMaterial, DpGrpcTlsConfig, bool)> = vec![
            (
                "wrong/untrusted CA",
                &good,
                DpGrpcTlsConfig {
                    ca_cert_pem: Some(other.ca_pem.clone()),
                    client_cert_pem: None,
                    client_key_pem: None,
                },
                false,
            ),
            (
                "hostname/SAN mismatch",
                &mismatched,
                dp_tls(&mismatched, false),
                false,
            ),
            (
                "expired server certificate",
                &expired,
                dp_tls(&expired, false),
                false,
            ),
            (
                "missing required client certificate",
                &good,
                // Trusts the server, but presents no client identity to a
                // server that requires one.
                dp_tls(&good, false),
                true,
            ),
        ];

        for (label, material, client_tls, require_client_cert) in cases {
            let endpoint = serve_tls(TlsBehaviour::Converged, material, require_client_cert).await;
            let tokens = tempfile::tempdir().expect("temp dir");
            let token_path = write_token(&tokens, "projected-token", "projected-token-one");

            let harness = TlsHarness::start(TlsClientSpec {
                urls: vec![endpoint.url.clone()],
                token_path: Some(token_path),
                policy: fast_policy(Duration::from_secs(3600)),
                tls_config: Some(client_tls),
                tls_reload: None,
                timings: fast_timings(),
                watch_credential: false,
            })
            .await;

            // A two-second sleep can end before the five-second connection
            // attempt completes (#4744). Keep that minimum observation window,
            // but require a real completed failure before accepting the case.
            let started = tokio::time::Instant::now();
            let observe_until = started + Duration::from_secs(2);
            let deadline = started + Duration::from_secs(15);
            loop {
                assert_eq!(
                    harness.services(),
                    None,
                    "{label}: no slice may be accepted over a session that failed TLS admission"
                );
                assert!(
                    !harness.state.has_first_slice(),
                    "{label}: startup must stay blocked"
                );
                assert_eq!(
                    endpoint.ads.stream_count(),
                    0,
                    "{label}: the ADS handler must never be reached"
                );
                assert!(
                    endpoint.ads.authorization_snapshot().is_empty(),
                    "{label}: the bearer must never reach a server whose identity was not established"
                );

                // Check admission continuously, including while the outcome
                // remains pending. Any other completed outcome fails at once.
                let outcome = harness.status_field(|status| status.last_attempt_outcome);
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{label}: no completed transport failure within the observation bound; last={outcome:?}"
                );
                match outcome {
                    Some("transport_failure") => {
                        if tokio::time::Instant::now() >= observe_until {
                            break;
                        }
                    }
                    None | Some("none") => {}
                    other => panic!("{label}: unexpected completed TLS attempt: {other:?}"),
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            harness.shutdown_and_join().await;
            endpoint.shutdown().await;
        }
    }

    /// A mutually authenticated server DOES admit the client once it presents
    /// the required certificate, so the negative cases above are proving a real
    /// gate rather than a broken fixture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_mtls_server_admits_the_client_that_presents_its_certificate() {
        let material = issue_material(&["localhost"], false);
        let endpoint = serve_tls(TlsBehaviour::Converged, &material, true).await;
        let tokens = tempfile::tempdir().expect("temp dir");
        let token_path = write_token(&tokens, "projected-token", "projected-token-one");

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![endpoint.url.clone()],
            token_path: Some(token_path),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(dp_tls(&material, true)),
            tls_reload: None,
            timings: fast_timings(),
            watch_credential: false,
        })
        .await;

        harness.wait_for_services(2, "the mTLS stream").await;
        assert_eq!(
            endpoint.ads.authorization_snapshot(),
            vec!["Bearer projected-token-one".to_string()]
        );

        harness.shutdown_and_join().await;
        endpoint.shutdown().await;
    }

    // ── issue #3854: established-transport liveness ──────────────────────

    /// A TCP relay that forwards to the real ADS endpoint until told to stop,
    /// then holds BOTH sockets open and forwards nothing — no FIN, no RST.
    ///
    /// This is the half-open shape no connect timeout can see: the client's
    /// `message()` stays pending forever unless an HTTP/2 PING is emitted and
    /// its ack is bounded.
    struct Blackhole {
        port: u16,
        stop: Arc<AtomicBool>,
        task: tokio::task::JoinHandle<()>,
        /// Every per-connection relay task, so nothing is left parked when the
        /// fixture is torn down.
        pumps: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }

    impl Blackhole {
        async fn start(upstream_port: u16) -> Self {
            let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
                .await
                .expect("bind blackhole listener");
            let port = listener.local_addr().expect("blackhole addr").port();
            let stop = Arc::new(AtomicBool::new(false));
            let pumps: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> =
                Arc::new(Mutex::new(Vec::new()));
            let accept_stop = stop.clone();
            let accept_pumps = pumps.clone();
            let task = tokio::spawn(async move {
                while let Ok((downstream, _)) = listener.accept().await {
                    let Ok(upstream) =
                        tokio::net::TcpStream::connect(("127.0.0.1", upstream_port)).await
                    else {
                        continue;
                    };
                    let _ = downstream.set_nodelay(true);
                    let _ = upstream.set_nodelay(true);
                    let (down_read, down_write) = downstream.into_split();
                    let (up_read, up_write) = upstream.into_split();
                    let mut registered = accept_pumps
                        .lock()
                        .expect("blackhole pump registry is never held across a panic");
                    registered.push(tokio::spawn(pump(down_read, up_write, accept_stop.clone())));
                    registered.push(tokio::spawn(pump(up_read, down_write, accept_stop.clone())));
                }
            });
            Self {
                port,
                stop,
                task,
                pumps,
            }
        }

        fn blackhole(&self) {
            self.stop.store(true, Ordering::SeqCst);
        }

        /// A parked relay half is holding sockets open on purpose, so it can
        /// only be cancelled — but it IS cancelled, and awaited, so no task
        /// outlives the fixture.
        async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
            let pumps = std::mem::take(
                &mut *self
                    .pumps
                    .lock()
                    .expect("blackhole pump registry is never held across a panic"),
            );
            for pump in pumps {
                pump.abort();
                let _ = pump.await;
            }
        }
    }

    /// Copy one direction until `stop` is set, then park forever while HOLDING
    /// both halves. Dropping them would close the socket and produce a FIN,
    /// which is precisely the signal a blackhole does not give.
    async fn pump(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        stop: Arc<AtomicBool>,
    ) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if stop.load(Ordering::SeqCst) {
                let _held = (from, to);
                std::future::pending::<()>().await;
                return;
            }
            // The tick lets the blackhole engage even while the link is idle.
            // `AsyncReadExt::read` is cancel-safe, so dropping it here loses no
            // bytes that were already delivered to userspace.
            let read = tokio::select! {
                read = from.read(&mut buf) => read,
                _ = tokio::time::sleep(Duration::from_millis(20)) => continue,
            };
            match read {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if stop.load(Ordering::SeqCst) {
                        let _held = (from, to);
                        std::future::pending::<()>().await;
                        return;
                    }
                    if to.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Issue #3854, acceptance criterion 3 — the half-open proof.
    ///
    /// The client first ESTABLISHES a stream and installs a slice through the
    /// relay. The relay then stops forwarding while holding both sockets open,
    /// so no FIN or RST ever reaches the client. Only the HTTP/2 PING policy
    /// can detect this, and the client must fail over to the direct fallback
    /// within the documented bound for the timing policy it is running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_blackholed_established_transport_fails_over_within_the_documented_bound() {
        let (primary_ads, primary_url) = serve(EndpointBehaviour::Converged).await;
        let primary_port: u16 = primary_url
            .rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .expect("primary port");
        let blackhole = Blackhole::start(primary_port).await;
        let (fallback_ads, fallback_url) = serve(EndpointBehaviour::Converged).await;

        // Compressed, per-invocation stack state with production defaults for
        // everything else. There is no env or global path into these values.
        let timings = MeshStreamTimings {
            keepalive_interval: Duration::from_millis(300),
            keepalive_timeout: Duration::from_millis(300),
            first_frame: Duration::from_secs(20),
            first_slice: Duration::from_secs(30),
            ..MeshStreamTimings::production()
        };
        let harness = LifecycleHarness::start(
            vec![format!("http://127.0.0.1:{}", blackhole.port), fallback_url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            timings,
        )
        .await;

        // The stream must be genuinely ESTABLISHED and serving before the
        // blackhole engages; otherwise this would only re-prove connect
        // timeouts.
        harness.wait_for_services(2).await;
        assert_eq!(primary_ads.stream_count(), 1);
        assert_eq!(fallback_ads.stream_count(), 0);

        let engaged = tokio::time::Instant::now();
        blackhole.blackhole();

        let deadline = engaged + Duration::from_secs(20);
        while fallback_ads.stream_count() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a blackholed established transport must be detected by the HTTP/2 keepalive \
                 policy and fail over"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let detected = engaged.elapsed();
        assert!(
            detected < Duration::from_secs(15),
            "detection must stay bounded, took {detected:?}"
        );

        harness.shutdown_and_join().await;
        blackhole.shutdown().await;
    }

    /// The other half of the same policy: a healthy but application-IDLE
    /// standard-xDS stream must stay connected while PING acks succeed. Without
    /// `keep_alive_while_idle`, tonic stops pinging exactly when a blackhole
    /// would be invisible — and with a naive silence watchdog this stream would
    /// be torn down for being legitimately quiet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_healthy_application_idle_stream_stays_connected_while_pings_succeed() {
        let (ads, url) = serve(EndpointBehaviour::Converged).await;
        let timings = MeshStreamTimings {
            keepalive_interval: Duration::from_millis(200),
            keepalive_timeout: Duration::from_millis(200),
            ..MeshStreamTimings::production()
        };
        let harness = LifecycleHarness::start(
            vec![url],
            StockXdsCredentialSource::unauthenticated(),
            StockCredentialWatch::new(StockCredentialState::NotConfigured),
            timings,
        )
        .await;

        harness.wait_for_services(2).await;
        // Many keepalive periods with zero application frames.
        tokio::time::sleep(Duration::from_secs(3)).await;

        assert_eq!(
            ads.stream_count(),
            1,
            "an idle stream whose PINGs are acked must not be retired"
        );
        let status = harness
            .state
            .config_stream_status()
            .expect("status is published");
        assert_eq!(status.state, "connected");
        assert_eq!(status.consecutive_failures, 0);
        assert_eq!(
            status.liveness_bound_seconds, 1,
            "the reported bound follows the compressed policy actually in force"
        );

        harness.shutdown_and_join().await;
    }

    /// Issue #3854 round two: a control plane that accepts the streaming RPC
    /// and then neither reads its request stream nor answers it must not be
    /// able to park the client. The bounded first-frame policy retires the
    /// attempt and the fallback converges; every task joins.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_control_plane_that_never_consumes_requests_reaches_a_bounded_retirement() {
        let material = issue_material(&["localhost"], false);
        let stalling = serve_tls(TlsBehaviour::StallRequests, &material, false).await;
        let healthy = serve_tls(TlsBehaviour::Converged, &material, false).await;
        let tokens = tempfile::tempdir().expect("temp dir");
        let token_path = write_token(&tokens, "projected-token", "projected-token-one");

        let harness = TlsHarness::start(TlsClientSpec {
            urls: vec![stalling.url.clone(), healthy.url.clone()],
            token_path: Some(token_path),
            policy: fast_policy(Duration::from_secs(3600)),
            tls_config: Some(dp_tls(&material, false)),
            tls_reload: None,
            timings: MeshStreamTimings {
                first_frame: Duration::from_millis(400),
                first_slice: Duration::from_secs(20),
                outbound: Duration::from_millis(400),
                ..MeshStreamTimings::production()
            },
            watch_credential: false,
        })
        .await;

        harness
            .wait_for_services(2, "the fallback after a non-consuming primary")
            .await;
        assert_eq!(stalling.ads.stream_count(), 1);
        assert!(healthy.ads.stream_count() >= 1);

        harness.shutdown_and_join().await;
        stalling.shutdown().await;
        healthy.shutdown().await;
    }
}
