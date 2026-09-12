//! Live Ferrum-private ADS stream lifecycle (issue #3854 follow-up).
//!
//! Drives `start_xds_client_with_shutdown` against a scripted ADS server so
//! RPC-open header withholding, incomplete-frame starvation, revision-gate
//! refusal, and NACK-breaker refusal are classified on the production path.

use crate::scaffolding::port_registry::TestSocket;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use prost::Message;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use ferrum_edge::grpc::dp_client::GrpcJwtSecret;
use ferrum_edge::modes::mesh::config_consumer::stream_lifecycle::MeshStreamTimings;
use ferrum_edge::modes::mesh::config_consumer::xds_client::{
    XdsClientConfig, start_xds_client_with_shutdown,
};
use ferrum_edge::modes::mesh::revision::MeshConfigRevision;
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::xds::proto::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use ferrum_edge::xds::proto::{
    Any, Cluster, ClusterLoadAssignment, DeltaDiscoveryRequest, DeltaDiscoveryResponse,
    DiscoveryRequest, DiscoveryResponse, Listener, RouteConfiguration, TypedExtensionConfig,
};
use ferrum_edge::xds::{CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL};

const JWT_SECRET: &str = "mesh-xds-stream-lifecycle-secret-0000";
const NODE_ID: &str = "node-a";
const NAMESPACE: &str = "default";

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdsBehaviour {
    WithholdHeaders,
    IncompleteForever,
    CoherentUnversioned,
    InvalidRdsForever,
}

#[derive(Clone)]
struct ScriptedPrivateAds {
    streams: Arc<AtomicUsize>,
    behaviour: AdsBehaviour,
}

impl ScriptedPrivateAds {
    fn new(behaviour: AdsBehaviour) -> Self {
        Self {
            streams: Arc::new(AtomicUsize::new(0)),
            behaviour,
        }
    }

    fn stream_count(&self) -> usize {
        self.streams.load(Ordering::SeqCst)
    }
}

fn ferrum_resource(type_url: &str, name: &str) -> Any {
    let value = match type_url {
        CDS_TYPE_URL => Cluster {
            name: name.to_string(),
        }
        .encode_to_vec(),
        EDS_TYPE_URL => ClusterLoadAssignment {
            cluster_name: name.to_string(),
        }
        .encode_to_vec(),
        LDS_TYPE_URL => Listener {
            name: name.to_string(),
        }
        .encode_to_vec(),
        RDS_TYPE_URL => RouteConfiguration {
            name: name.to_string(),
        }
        .encode_to_vec(),
        ECDS_TYPE_URL => TypedExtensionConfig {
            name: name.to_string(),
            typed_config: Some(Any {
                type_url: "type.googleapis.com/ferrum.test.Ecds".to_string(),
                value: b"opaque".to_vec(),
            }),
        }
        .encode_to_vec(),
        other => panic!("unexpected private-xDS test type {other}"),
    };
    Any {
        type_url: type_url.to_string(),
        value,
    }
}

fn typed_response(type_url: &str, version: &str, nonce: &str, names: &[&str]) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        resources: names
            .iter()
            .map(|name| ferrum_resource(type_url, name))
            .collect(),
        canary: false,
        type_url: type_url.to_string(),
        nonce: nonce.to_string(),
        control_plane: None,
    }
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for ScriptedPrivateAds {
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
        if behaviour == AdsBehaviour::WithholdHeaders {
            let _held = request.into_inner();
            return std::future::pending().await;
        }

        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            match behaviour {
                AdsBehaviour::WithholdHeaders => unreachable!("handled before spawn"),
                AdsBehaviour::IncompleteForever => {
                    tokio::spawn(async move {
                        while inbound.message().await.ok().flatten().is_some() {}
                    });
                    let mut nonce = 0u64;
                    loop {
                        nonce = nonce.saturating_add(1);
                        let response = typed_response(
                            CDS_TYPE_URL,
                            &format!("v{nonce}"),
                            &format!("n{nonce}"),
                            &["cluster/default/api/8080"],
                        );
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                AdsBehaviour::CoherentUnversioned => {
                    let mut sent_cds = false;
                    let mut sent_eds = false;
                    let mut sent_lds = false;
                    let mut sent_rds = false;
                    let mut sent_ecds = false;
                    while let Ok(Some(discovery_request)) = inbound.message().await {
                        let type_url = discovery_request.type_url.clone();
                        let response = if type_url == CDS_TYPE_URL && !sent_cds {
                            sent_cds = true;
                            typed_response(
                                CDS_TYPE_URL,
                                "v1",
                                "cds-n1",
                                &["cluster/default/api/8080"],
                            )
                        } else if type_url == EDS_TYPE_URL && !sent_eds {
                            sent_eds = true;
                            typed_response(
                                EDS_TYPE_URL,
                                "v1",
                                "eds-n1",
                                &["cluster/default/api/8080"],
                            )
                        } else if type_url == LDS_TYPE_URL && !sent_lds {
                            sent_lds = true;
                            typed_response(
                                LDS_TYPE_URL,
                                "v1",
                                "lds-n1",
                                &["listener/default/api/8080"],
                            )
                        } else if type_url == RDS_TYPE_URL && !sent_rds {
                            sent_rds = true;
                            typed_response(RDS_TYPE_URL, "v1", "rds-n1", &["route/default/api"])
                        } else if type_url == ECDS_TYPE_URL && !sent_ecds {
                            sent_ecds = true;
                            DiscoveryResponse {
                                version_info: "v1".to_string(),
                                resources: Vec::new(),
                                canary: false,
                                type_url: ECDS_TYPE_URL.to_string(),
                                nonce: "ecds-n1".to_string(),
                                control_plane: None,
                            }
                        } else {
                            continue;
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                }
                AdsBehaviour::InvalidRdsForever => {
                    let mut nonce = 0u64;
                    while let Ok(Some(discovery_request)) = inbound.message().await {
                        if discovery_request.type_url != RDS_TYPE_URL {
                            continue;
                        }
                        nonce = nonce.saturating_add(1);
                        let response = typed_response(
                            RDS_TYPE_URL,
                            &format!("v{nonce}"),
                            &format!("n{nonce}"),
                            &["route/default"],
                        );
                        if tx.send(Ok(response)).await.is_err() {
                            return;
                        }
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

async fn serve(behaviour: AdsBehaviour) -> (ScriptedPrivateAds, String) {
    let handle = ScriptedPrivateAds::new(behaviour);
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind private ADS listener");
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

struct XdsHarness {
    state: MeshRuntimeState,
    shutdown_tx: watch::Sender<bool>,
    client: tokio::task::JoinHandle<()>,
}

impl XdsHarness {
    fn start(urls: Vec<String>, state: MeshRuntimeState, timings: MeshStreamTimings) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let config = XdsClientConfig {
            cp_urls: urls,
            node_id: NODE_ID.to_string(),
            cluster: "default".to_string(),
            namespace: NAMESPACE.to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
            stream_channel_capacity: 32,
            primary_retry_secs: 0,
            connect_timeout_seconds: 5,
            labels: Default::default(),
        };
        let client = tokio::spawn(start_xds_client_with_shutdown(
            GrpcJwtSecret::new(JWT_SECRET.to_string()),
            config,
            state.clone(),
            shutdown_rx,
            None,
            None,
            timings,
        ));
        Self {
            state,
            shutdown_tx,
            client,
        }
    }

    async fn wait_for_outcome(&self, expected: &'static str, deadline: Duration) {
        let until = tokio::time::Instant::now() + deadline;
        loop {
            if let Some(status) = self.state.config_stream_status()
                && status.last_attempt_outcome == expected
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "timed out waiting for xDS outcome {expected}; status={:?}",
                self.state.config_stream_status()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn shutdown_and_join(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(10), self.client)
            .await
            .expect("the private xDS client must observe shutdown and return")
            .expect("the private xDS client task must not panic");
    }
}

fn compressed_first_frame() -> MeshStreamTimings {
    MeshStreamTimings {
        first_frame: Duration::from_millis(300),
        first_slice: Duration::from_secs(15),
        ..MeshStreamTimings::production()
    }
}

fn compressed_first_slice() -> MeshStreamTimings {
    MeshStreamTimings {
        first_frame: Duration::from_secs(5),
        first_slice: Duration::from_millis(400),
        ..MeshStreamTimings::production()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn withholding_private_ads_headers_cannot_outrun_first_frame() {
    let (withholding, withholding_url) = serve(AdsBehaviour::WithholdHeaders).await;
    let harness = XdsHarness::start(
        vec![withholding_url],
        MeshRuntimeState::new(),
        compressed_first_frame(),
    );

    harness
        .wait_for_outcome("first_frame_timeout", Duration::from_secs(15))
        .await;
    assert!(withholding.stream_count() >= 1);
    let status = harness
        .state
        .config_stream_status()
        .expect("private xDS publishes stream status");
    assert_eq!(status.protocol, "xds");
    assert_eq!(status.last_attempt_outcome, "first_frame_timeout");
    harness.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn incomplete_private_ads_frames_cannot_outrun_first_slice() {
    let (incomplete, incomplete_url) = serve(AdsBehaviour::IncompleteForever).await;
    let harness = XdsHarness::start(
        vec![incomplete_url],
        MeshRuntimeState::new(),
        compressed_first_slice(),
    );

    harness
        .wait_for_outcome("first_slice_timeout", Duration::from_secs(15))
        .await;
    assert!(incomplete.stream_count() >= 1);
    let status = harness
        .state
        .config_stream_status()
        .expect("private xDS publishes stream status");
    assert_eq!(status.last_attempt_outcome, "first_slice_timeout");
    harness.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn private_xds_revision_rejection_is_policy_rejected_not_liveness() {
    let (_primary, primary_url) = serve(AdsBehaviour::CoherentUnversioned).await;
    let state = MeshRuntimeState::new();
    assert!(
        state
            .install_slice(MeshSlice {
                node_id: NODE_ID.to_string(),
                namespace: NAMESPACE.to_string(),
                version: "seed".to_string(),
                revision: Some(MeshConfigRevision::new("db", 100)),
                ..MeshSlice::default()
            })
            .installed()
    );

    let harness = XdsHarness::start(
        vec![primary_url],
        state,
        MeshStreamTimings {
            first_frame: Duration::from_secs(10),
            first_slice: Duration::from_secs(15),
            ..MeshStreamTimings::production()
        },
    );

    harness
        .wait_for_outcome("policy_rejected", Duration::from_secs(20))
        .await;
    let status = harness
        .state
        .config_stream_status()
        .expect("private xDS publishes stream status");
    assert_eq!(status.protocol, "xds");
    assert_eq!(status.last_attempt_outcome, "policy_rejected");
    assert_eq!(
        status.state, "serving_last_good",
        "revision refusal is policy, not an established-transport liveness failure"
    );
    assert_eq!(
        harness
            .state
            .snapshot()
            .as_ref()
            .as_ref()
            .map(|slice| slice.version.as_str()),
        Some("seed")
    );
    harness.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn private_xds_nack_breaker_is_policy_rejected_not_liveness() {
    let (primary, primary_url) = serve(AdsBehaviour::InvalidRdsForever).await;
    let harness = XdsHarness::start(
        vec![primary_url],
        MeshRuntimeState::new(),
        MeshStreamTimings {
            first_frame: Duration::from_secs(10),
            first_slice: Duration::from_secs(15),
            ..MeshStreamTimings::production()
        },
    );

    harness
        .wait_for_outcome("policy_rejected", Duration::from_secs(20))
        .await;
    assert!(primary.stream_count() >= 1);
    let status = harness
        .state
        .config_stream_status()
        .expect("private xDS publishes stream status");
    assert_eq!(status.protocol, "xds");
    assert_eq!(status.last_attempt_outcome, "policy_rejected");
    assert_eq!(
        status.state, "never_received_slice",
        "NACK-breaker refusal must not be labelled stream_liveness_failed"
    );
    harness.shutdown_and_join().await;
}
