//! Live-path functional coverage for Istio
//! `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting.failoverPriority`.
//!
//! Builds policy through the K8s DestinationRule translator → mesh prepare /
//! materialization path, then sends real HTTP traffic through an in-process
//! gateway against scripted backends that identify themselves in responses.
//!
//! Run with:
//!   cargo test --test functional_tests functional_failover_priority -- --ignored --nocapture

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::file::ServeOptions;
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use reqwest::StatusCode;
use serde_json::json;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::clients::{ClientResponse, Http1Client};
use crate::scaffolding::ports::reserve_port;

const NAMESPACE: &str = "default";
const UPSTREAM_ID: &str = "fp-reviews-u";
const PROXY_ID: &str = "fp-reviews-p";
const LISTEN_PATH: &str = "/fp-failover";
const JWT_SECRET: &str = "ferrum-edge-fp-failover-secret-00000000";
const JWT_ISSUER: &str = "ferrum-edge-fp-failover";
const PREFERRED: &str = "preferred";
const SECONDARY: &str = "secondary";
/// Healthy preferred hits that prove ordered failoverPriority selection before
/// the scripted backend flips to 503 and ejects via outlierDetection.
const PREFERRED_HEALTHY_HITS: usize = 4;

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_failover_priority_prefers_label_match_then_fails_over_on_outlier() {
    let preferred_res = reserve_port().await.expect("reserve preferred backend");
    let secondary_res = reserve_port().await.expect("reserve secondary backend");
    let preferred_port = preferred_res.port;
    let secondary_port = secondary_res.port;

    // Preferred returns 200 for the first PREFERRED_HEALTHY_HITS connections,
    // then 503 forever so a single consecutive5xxErrors=1 outlier ejects it.
    let mut preferred_scripts = Vec::with_capacity(PREFERRED_HEALTHY_HITS + 1);
    for _ in 0..PREFERRED_HEALTHY_HITS {
        preferred_scripts.push(identity_script(PREFERRED, 200, "OK"));
    }
    preferred_scripts.push(identity_script(PREFERRED, 503, "Service Unavailable"));
    let preferred = ScriptedHttp1Backend::builder(preferred_res.into_listener())
        .connection_scripts(preferred_scripts)
        .spawn()
        .expect("spawn preferred backend");

    // Secondary is always healthy and is listed FIRST in the upstream target
    // list so round-robin would otherwise select it before the preferred peer.
    let secondary = ScriptedHttp1Backend::builder(secondary_res.into_listener())
        .steps(identity_script(SECONDARY, 200, "OK"))
        .spawn()
        .expect("spawn secondary backend");

    let (prepared, proxy_port, shutdown_tx, gateway_join) =
        start_gateway(preferred_port, secondary_port)
            .await
            .expect("start failoverPriority gateway");

    // Projection assertions: DR translation + mesh prepare must stamp
    // failoverPriority, source labels, and the outlier→passive health signal
    // before any live traffic runs.
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == UPSTREAM_ID)
        .expect("upstream survived mesh prepare");
    let setting = upstream
        .locality_lb_setting
        .as_ref()
        .expect("failoverPriority projected onto upstream");
    assert_eq!(
        setting.failover_priority,
        vec![
            "topology.kubernetes.io/region".to_string(),
            "topology.kubernetes.io/zone".to_string(),
        ]
    );
    assert_eq!(
        upstream.source_labels.get("topology.kubernetes.io/region"),
        Some(&"us-west".to_string()),
        "source workload labels must drive failoverPriority ranking"
    );
    assert_eq!(
        upstream.source_labels.get("topology.kubernetes.io/zone"),
        Some(&"us-west-1".to_string())
    );
    let passive = upstream
        .health_checks
        .as_ref()
        .and_then(|h| h.passive.as_ref())
        .expect("outlierDetection must project passive health (failover enablement)");
    assert_eq!(passive.unhealthy_threshold, 1);
    assert_eq!(passive.healthy_after_seconds, 3600);
    assert_eq!(passive.max_ejection_percent, Some(100));

    let client = Http1Client::insecure().expect("http client");
    let base = format!("http://127.0.0.1:{proxy_port}{LISTEN_PATH}");

    // Phase 1: ordered failoverPriority must pin every healthy request onto
    // the full region+zone match even though secondary is listed first.
    for i in 0..PREFERRED_HEALTHY_HITS {
        let resp = retry_get(&client, &format!("{base}/healthy-{i}")).await;
        assert_eq!(
            resp.status,
            StatusCode::OK,
            "healthy preferred request {i} must succeed: {:?}",
            resp.body_text()
        );
        assert_backend_identity(&resp, PREFERRED, i);
    }
    assert_eq!(
        preferred.accepted_connections() as usize,
        PREFERRED_HEALTHY_HITS,
        "preferred must have served every healthy request"
    );
    assert_eq!(
        secondary.accepted_connections(),
        0,
        "secondary must not participate while preferred remains healthy"
    );

    // Phase 2: preferred returns 503 once → outlier ejects it on the live path.
    let eject = retry_get(&client, &format!("{base}/eject")).await;
    assert_eq!(
        eject.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "ejection probe must surface the preferred backend's 503: {:?}",
        eject.body_text()
    );
    assert_backend_identity(&eject, PREFERRED, PREFERRED_HEALTHY_HITS);

    // Phase 3: subsequent real traffic must land on the next-ranked healthy
    // backend (region-only match), proven by response body/header identity.
    let failover = retry_get(&client, &format!("{base}/failover")).await;
    assert_eq!(
        failover.status,
        StatusCode::OK,
        "post-ejection request must reach secondary: {:?}",
        failover.body_text()
    );
    assert_backend_identity(&failover, SECONDARY, 0);
    assert!(
        secondary.accepted_connections() >= 1,
        "secondary backend must have accepted the failover request"
    );

    preferred.assert_no_step_errors().await;
    secondary.assert_no_step_errors().await;

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), gateway_join)
        .await
        .expect("gateway shutdown timed out")
        .expect("gateway join task panicked");
    drop(preferred);
    drop(secondary);
    drop(prepared);
}

fn identity_script(name: &str, status: u16, reason: &str) -> Vec<HttpStep> {
    let body = format!(r#"{{"server":"{name}"}}"#);
    vec![
        HttpStep::ExpectRequest(RequestMatcher::any()),
        HttpStep::RespondStatus {
            status,
            reason: reason.to_string(),
        },
        HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "application/json".into(),
        },
        HttpStep::RespondHeader {
            name: "X-Backend".into(),
            value: name.to_string(),
        },
        HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        },
        HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: body.len().to_string(),
        },
        HttpStep::RespondBodyChunk(body.into_bytes()),
        HttpStep::RespondBodyEnd,
    ]
}

fn assert_backend_identity(resp: &ClientResponse, expected: &str, idx: usize) {
    let header = resp
        .headers
        .get("x-backend")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = resp.body_text();
    assert_eq!(
        header, expected,
        "request {idx}: X-Backend header must identify {expected}, got {header:?}; body={body}"
    );
    assert!(
        body.contains(&format!(r#""server":"{expected}""#)),
        "request {idx}: body must identify {expected}, got {body}"
    );
}

async fn retry_get(client: &Http1Client, url: &str) -> ClientResponse {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.get(url).await {
            Ok(resp) => return resp,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => {
                panic!(
                    "GET {url} did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}

async fn start_gateway(
    preferred_port: u16,
    secondary_port: u16,
) -> Result<
    (GatewayConfig, u16, watch::Sender<bool>, JoinHandle<()>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let proxy = reserve_port().await?;
    let admin = reserve_port().await?;
    let proxy_port = proxy.port;
    let admin_port = admin.port;

    let config = build_config_via_destination_rule(preferred_port, secondary_port)?;
    let runtime = mesh_runtime();
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("mesh preparation failed: {e}").into()
        },
    )?;

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: proxy_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(JWT_SECRET.to_string()),
        admin_jwt_issuer: JWT_ISSUER.to_string(),
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    let jwt_manager = JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let opts = ServeOptions {
        proxy_http: Some(proxy.into_listener()),
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = watch::channel(false);
    let handles =
        ferrum_edge::modes::file::serve(env_config, prepared.clone(), opts, shutdown_tx.clone())
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("file::serve failed: {e}").into()
            })?;
    let join = tokio::spawn(async move {
        if let Err(err) = handles.join().await {
            eprintln!("failoverPriority gateway listener panicked: {err}");
        }
    });

    Ok((prepared, proxy_port, shutdown_tx, join))
}

fn build_config_via_destination_rule(
    preferred_port: u16,
    secondary_port: u16,
) -> Result<GatewayConfig, Box<dyn std::error::Error + Send + Sync>> {
    let dr = K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "DestinationRule".to_string(),
        metadata: K8sMetadata {
            name: "fp-reviews".to_string(),
            uid: String::new(),
            namespace: NAMESPACE.to_string(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({
            "host": UPSTREAM_ID,
            "trafficPolicy": {
                "loadBalancer": {
                    "simple": "ROUND_ROBIN",
                    "localityLbSetting": {
                        "failoverPriority": [
                            "topology.kubernetes.io/region",
                            "topology.kubernetes.io/zone"
                        ]
                    }
                },
                "outlierDetection": {
                    "consecutive5xxErrors": 1,
                    "interval": "60s",
                    "baseEjectionTime": "3600s",
                    "maxEjectionPercent": 100
                }
            }
        }),
        status: json!({}),
    };
    let translated = translate_k8s_objects(
        &[dr],
        K8sTranslationOptions::new(
            NAMESPACE.to_string(),
            TrustDomain::new("cluster.local").expect("trust domain"),
        ),
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("DestinationRule translate failed: {e}").into()
    })?;

    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": PROXY_ID,
            "namespace": NAMESPACE,
            "listen_path": LISTEN_PATH,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": preferred_port,
            "strip_listen_path": true,
            "upstream_id": UPSTREAM_ID
        }],
        "upstreams": [{
            "id": UPSTREAM_ID,
            "namespace": NAMESPACE,
            "name": "failoverPriority live upstream",
            "algorithm": "round_robin",
            "targets": [
                {
                    "host": "127.0.0.1",
                    "port": secondary_port,
                    "weight": 1,
                    "locality": "us-west/us-west-2/a",
                    "tags": {
                        "topology.kubernetes.io/region": "us-west",
                        "topology.kubernetes.io/zone": "us-west-2",
                        "backend": SECONDARY
                    }
                },
                {
                    "host": "127.0.0.1",
                    "port": preferred_port,
                    "weight": 1,
                    "locality": "us-west/us-west-1/a",
                    "tags": {
                        "topology.kubernetes.io/region": "us-west",
                        "topology.kubernetes.io/zone": "us-west-1",
                        "backend": PREFERRED
                    }
                }
            ]
        }],
        "consumers": [],
        "plugin_configs": []
    }))
    .expect("base gateway config is valid");

    // Carry the translated DestinationRule into the gateway mesh block so
    // prepare_gateway_config_for_mesh projects it onto the upstream.
    config.mesh = translated.config.mesh;
    Ok(config)
}

fn mesh_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "fp-failover-node".to_string(),
        namespace: NAMESPACE.to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        stock_xds_urls: Vec::new(),
        stock_xds_node_id: None,
        stock_xds_node_metadata: Default::default(),
        stock_xds_token_file: None,
        stock_xds_limits: Default::default(),
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        egress_gateway: None,
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        xds_node_cluster: NAMESPACE.to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        unix_socket_allowed_roots: Vec::new(),
        unix_socket_allowed_uids: Vec::new(),
        workload_labels: HashMap::from([
            (
                "topology.kubernetes.io/region".to_string(),
                "us-west".to_string(),
            ),
            (
                "topology.kubernetes.io/zone".to_string(),
                "us-west-1".to_string(),
            ),
        ]),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}
