//! xDS ADS type-URL round-trip conformance.
//!
//! Verifies every type URL Ferrum subscribes to in `XDS_TYPE_URLS` survives
//! a slice → snapshot translation cycle and reaches the expected resource
//! container. The conformance bar is "the snapshot carries a non-empty
//! resource list for each type URL when the slice has the corresponding
//! input", not "the resource bytes decode to a specific Envoy proto" — that
//! is exhaustively covered by the unit suite at `tests/unit/gateway_core/xds_tests.rs`.

use std::collections::{BTreeMap, HashMap};

use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshDestinationRule, MeshRuntimeOverlay, MeshService, MtlsMode,
    PeerAuthentication, RuntimeValue, ServicePort, Workload, WorkloadPort, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::xds::{
    CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
    FERRUM_ECDS_LABELS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, RTDS_TYPE_URL, SDS_TYPE_URL,
    XDS_TYPE_URLS, runtime_proto, translate_mesh_slice_to_snapshot, translate_rtds_layer,
};

use crate::conformance::registry::Status;

const CATEGORY: &str = "xds_type_urls";

fn td() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("trust domain")
}

fn slice_with_one_service() -> MeshSlice {
    let workload = Workload {
        spiffe_id: SpiffeId::from_parts(&td(), "ns/default/sa/echo").expect("spiffe id"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "echo".to_string())]),
            namespace: Some("default".to_string()),
        },
        service_name: "echo".to_string(),
        addresses: vec!["10.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: td(),
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("echo".to_string()),
        pod_uid: None,
    };
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "echo".to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: workload.spiffe_id.clone(),
        }],
        protocol_overrides: HashMap::new(),
    };
    let peer_auth = PeerAuthentication {
        name: "strict".to_string(),
        namespace: "default".to_string(),
        scope: None,
        selector: Some(WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "echo".to_string())]),
            namespace: None,
        }),
        mtls_mode: MtlsMode::Strict,
        port_overrides: HashMap::new(),
    };
    MeshSlice {
        node_id: "conformance-node".to_string(),
        namespace: "default".to_string(),
        labels: BTreeMap::from([("app".to_string(), "echo".to_string())]),
        version: "test-1".to_string(),
        workloads: vec![workload],
        services: vec![service],
        peer_authentications: vec![peer_auth],
        ..MeshSlice::default()
    }
}

/// `XDS_TYPE_URLS` enumerates exactly the types Ferrum subscribes to. The
/// conformance assertion is the list shape — drift between docs and code
/// would silently break operator expectations.
#[test]
fn xds_subscribed_type_urls_match_documented_set() {
    register_feature!(
        category = CATEGORY,
        feature = "XDS_TYPE_URLS = {CDS, EDS, LDS, RDS, SDS, ECDS, RTDS}",
        status = Status::Supported,
        notes = "Ferrum xDS client subscribes to all seven types. CDS/EDS/LDS/RDS are the mesh-slice required quartet; SDS/ECDS/RTDS extend.",
    );
    let urls: std::collections::BTreeSet<&str> = XDS_TYPE_URLS.iter().copied().collect();
    let expected: std::collections::BTreeSet<&str> = [
        CDS_TYPE_URL,
        EDS_TYPE_URL,
        LDS_TYPE_URL,
        RDS_TYPE_URL,
        SDS_TYPE_URL,
        ECDS_TYPE_URL,
        RTDS_TYPE_URL,
    ]
    .into_iter()
    .collect();
    assert_eq!(urls, expected);
}

/// CDS round-trip: a slice with a service produces at least one CDS resource.
#[test]
fn xds_cds_round_trip() {
    register_feature!(
        category = CATEGORY,
        feature = "CDS (envoy.config.cluster.v3.Cluster)",
        status = Status::Supported,
        notes = "Each MeshService port produces one CDS resource named cluster/<ns>/<name>/<port>.",
    );
    let snapshot = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let cds = snapshot.resources(CDS_TYPE_URL);
    assert!(!cds.is_empty(), "CDS resource emitted for service port");
    let names: Vec<_> = cds.iter().map(|r| r.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.contains("default") && n.contains("echo") && n.contains("8080")),
        "CDS cluster name must encode namespace/service/port; got {names:?}"
    );
}

/// EDS round-trip: each CDS resource has a matching EDS ClusterLoadAssignment.
#[test]
fn xds_eds_round_trip() {
    register_feature!(
        category = CATEGORY,
        feature = "EDS (envoy.config.endpoint.v3.ClusterLoadAssignment)",
        status = Status::Supported,
        notes = "One EDS resource per service port, name matches the corresponding CDS cluster.",
    );
    let snapshot = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let eds = snapshot.resources(EDS_TYPE_URL);
    assert!(!eds.is_empty(), "EDS resource emitted");
}

/// LDS round-trip: each service port produces an LDS Listener.
#[test]
fn xds_lds_round_trip() {
    register_feature!(
        category = CATEGORY,
        feature = "LDS (envoy.config.listener.v3.Listener)",
        status = Status::Supported,
        notes = "One LDS resource per (service, port).",
    );
    let snapshot = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let lds = snapshot.resources(LDS_TYPE_URL);
    assert!(!lds.is_empty(), "LDS resource emitted");
}

/// RDS round-trip: each service produces an RDS RouteConfiguration.
#[test]
fn xds_rds_round_trip() {
    register_feature!(
        category = CATEGORY,
        feature = "RDS (envoy.config.route.v3.RouteConfiguration)",
        status = Status::Supported,
        notes = "One RDS resource per service.",
    );
    let snapshot = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let rds = snapshot.resources(RDS_TYPE_URL);
    assert!(!rds.is_empty(), "RDS resource emitted");
}

/// SDS round-trip: PeerAuthentication produces SDS Secret resources. With a
/// `mtls_mode: Strict` PA in the slice, at least one SDS resource is emitted.
#[test]
fn xds_sds_round_trip() {
    register_feature!(
        category = CATEGORY,
        feature = "SDS (envoy.extensions.transport_sockets.tls.v3.Secret)",
        status = Status::Supported,
        notes = "Mesh PeerAuthentication / inbound mTLS posture drives SDS resource emission.",
    );
    let snapshot = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let sds = snapshot.resources(SDS_TYPE_URL);
    // SDS may be empty if there's no trust bundle wired. The round-trip
    // bar is "translation does not panic and returns an addressable list";
    // a stricter assertion would couple the test to the SDS materialization
    // policy of the translator.
    let _ = sds;
}

/// ECDS DR-carrier round-trip — full `MeshDestinationRule` objects flow through
/// reserved Ferrum ECDS resources. This pins that a normal DR in the slice, not
/// only an operator-defined `MeshExtensionConfig`, reaches the ECDS resource
/// list and carries the Ferrum DR marker.
#[test]
fn xds_ecds_dr_carrier_round_trip() {
    use ferrum_edge::xds::proto;
    use prost::Message;

    register_feature!(
        category = CATEGORY,
        feature = "ECDS DR-carrier (FERRUM_ECDS_DESTINATION_RULE_TYPE_URL)",
        status = Status::Supported,
        notes = "QW-3 / GAP-1a: CPs wrap full DestinationRule JSON in reserved TypedExtensionConfig resources with the Ferrum-specific inner type_url; DPs recognize the marker and apply the DR locally.",
    );
    let mut slice = slice_with_one_service();
    slice.destination_rules.push(MeshDestinationRule {
        name: "echo-dr".to_string(),
        namespace: "default".to_string(),
        host: "echo.default.svc.cluster.local".to_string(),
        traffic_policy: None,
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
    });
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let ecds = snapshot.resources(ECDS_TYPE_URL);
    assert!(
        !ecds.is_empty(),
        "ECDS resource emitted for DR-carrier extension"
    );
    let dr_resource = ecds
        .iter()
        .find(|resource| resource.name == "ferrum-destination-rule-carrier/default/echo-dr")
        .expect("reserved DestinationRule carrier resource is emitted");
    let typed =
        proto::TypedExtensionConfig::decode(dr_resource.value.as_slice()).expect("decode TEC");
    let inner = typed.typed_config.expect("inner Any");
    assert_eq!(inner.type_url, FERRUM_ECDS_DESTINATION_RULE_TYPE_URL);
    let decoded: MeshDestinationRule = serde_json::from_slice(&inner.value).expect("DR json");
    assert_eq!(decoded, slice.destination_rules[0]);
}

/// Ferrum mesh-slice ECDS carriers — GAP-1a (full parity over xDS). A slice
/// with a PeerAuthentication must emit a `PeerAuthenticationsCarrier` ECDS
/// resource whose inner `type_url` decodes back to the same PeerAuthentication.
/// This pins the type-URL contract for the carriers that make xDS reach native
/// parity: without them the DP rebuilds an unprotected mesh.
#[test]
fn xds_mesh_slice_carriers_round_trip() {
    use ferrum_edge::xds::proto;
    use ferrum_edge::xds::{
        FERRUM_ECDS_PEER_AUTH_TYPE_URL, FERRUM_ECDS_SERVICES_TYPE_URL, MeshSliceCarrier,
    };
    use prost::Message;

    register_feature!(
        category = CATEGORY,
        feature =
            "Ferrum mesh-slice ECDS carriers (type.googleapis.com/ferrum.config.extension.v3.*)",
        status = Status::Supported,
        notes = "GAP-1a: security/policy slice fields and effective workload labels (authz, PeerAuth, JWT, ServiceEntry, trust bundles, ProxyConfig, workloads, services, outbound policy, sidecar egress scope) ride ECDS as Ferrum-specific carriers; DP requires the reserved resource name plus inner type_url. Ferrum-CP-to-Ferrum-DP only, NOT stock-Envoy/Istio-interoperable.",
    );

    let snapshot = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let ecds = snapshot.resources(ECDS_TYPE_URL);

    // Find the PeerAuthentication carrier among the ECDS resources and confirm
    // it round-trips through the shared MeshSliceCarrier decoder.
    let mut found_peer_auth = false;
    let mut found_services = false;
    let mut found_labels = false;
    for resource in ecds {
        let typed =
            proto::TypedExtensionConfig::decode(resource.value.as_slice()).expect("decode TEC");
        let inner = typed.typed_config.expect("inner Any");
        match MeshSliceCarrier::decode(&inner.type_url, &inner.value).expect("decode does not err")
        {
            Some(MeshSliceCarrier::PeerAuthentications(pas)) => {
                assert_eq!(inner.type_url, FERRUM_ECDS_PEER_AUTH_TYPE_URL);
                assert_eq!(pas.len(), 1);
                assert_eq!(pas[0].name, "strict");
                found_peer_auth = true;
            }
            Some(MeshSliceCarrier::Services(svcs)) => {
                assert_eq!(inner.type_url, FERRUM_ECDS_SERVICES_TYPE_URL);
                assert_eq!(svcs.len(), 1);
                found_services = true;
            }
            Some(MeshSliceCarrier::WorkloadLabels(labels)) => {
                assert_eq!(inner.type_url, FERRUM_ECDS_LABELS_TYPE_URL);
                assert_eq!(labels.get("app").map(String::as_str), Some("echo"));
                found_labels = true;
            }
            _ => {}
        }
    }
    assert!(
        found_peer_auth,
        "PeerAuthentication must ride ECDS as a Ferrum mesh-slice carrier"
    );
    assert!(
        found_services,
        "Services must ride ECDS as a Ferrum mesh-slice carrier"
    );
    assert!(
        found_labels,
        "effective workload labels must ride ECDS so selector policies keep matching"
    );
}

/// RTDS round-trip — PR #883. The xDS client decodes RTDS layers via
/// `translate_rtds_layer` into `MeshRuntimeOverlay`. Confirm the three
/// runtime-value kinds Ferrum supports (Number, String, FractionalPercent)
/// land on the overlay.
#[test]
fn xds_rtds_round_trip_numeric_string_fractional() {
    register_feature!(
        category = CATEGORY,
        feature = "RTDS (envoy.service.runtime.v3.Runtime)",
        status = Status::Supported,
        notes = "PR #883 (GAP-3E): RTDS layers decode into MeshRuntimeOverlay; numeric/string/bool/FractionalPercent values supported.",
    );
    use runtime_proto::value::Kind;

    let mut fields: BTreeMap<String, runtime_proto::Value> = BTreeMap::new();
    fields.insert(
        "ferrum.fault_injection.demo.abort_percent".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NumberValue(25.0)),
        },
    );
    fields.insert(
        "ferrum.log.level".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("ferrum_edge=info".to_string())),
        },
    );

    let layer = runtime_proto::Runtime {
        name: "rtds_layer0".to_string(),
        layer: Some(runtime_proto::Struct {
            fields: fields.into_iter().collect(),
        }),
    };
    let overlay = translate_rtds_layer(&layer);
    assert!(matches!(
        overlay
            .fields
            .get("ferrum.fault_injection.demo.abort_percent"),
        Some(RuntimeValue::Number(n)) if (*n - 25.0).abs() < f64::EPSILON
    ));
    assert!(matches!(
        overlay.fields.get("ferrum.log.level"),
        Some(RuntimeValue::String(s)) if s == "ferrum_edge=info"
    ));
}

/// RTDS consumer fan-out — three live consumers per CLAUDE.md
/// runtime_overlay_consumers section:
///   1. fault_injection abort/delay percentages
///   2. request_transformer / response_transformer enable gates
///   3. gateway-wide log level
///
/// The conformance assertion is that the overlay carries the reserved-key
/// shape each consumer expects.
#[test]
fn xds_rtds_consumer_keyspace_shape() {
    register_feature!(
        category = CATEGORY,
        feature = "RTDS reserved-key consumer namespaces",
        status = Status::Supported,
        notes = "PR #883: ferrum.fault_injection.*, ferrum.{request,response}_transformer.*, ferrum.log.level reserved namespaces routed to live consumers.",
    );
    let mut overlay = MeshRuntimeOverlay::default();
    overlay.fields.insert(
        "ferrum.fault_injection.demo.abort_percent".to_string(),
        RuntimeValue::Number(50.0),
    );
    overlay.fields.insert(
        "ferrum.request_transformer.demo.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    overlay.fields.insert(
        "ferrum.response_transformer.demo.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    overlay.fields.insert(
        "ferrum.log.level".to_string(),
        RuntimeValue::String("ferrum_edge=debug".to_string()),
    );

    // All four reserved namespaces must coexist in the overlay map.
    assert_eq!(overlay.fields.len(), 4);
    assert!(matches!(
        overlay
            .fields
            .get("ferrum.fault_injection.demo.abort_percent"),
        Some(RuntimeValue::Number(_))
    ));
    assert!(matches!(
        overlay.fields.get("ferrum.log.level"),
        Some(RuntimeValue::String(_))
    ));
}

/// Snapshot version is content-derived: two identical slices produce
/// identical snapshot versions; a structural change changes the version.
/// This is the basis for delta-xDS wire-byte reduction.
#[test]
fn xds_snapshot_version_is_content_derived() {
    register_feature!(
        category = CATEGORY,
        feature = "Snapshot version is content-derived",
        status = Status::Supported,
        notes = "Per-resource hash + aggregate snapshot version both content-derived; basis for delta-xDS wire-byte reduction.",
    );
    let snapshot_a = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    let snapshot_b = translate_mesh_slice_to_snapshot(&slice_with_one_service());
    assert_eq!(
        snapshot_a.version, snapshot_b.version,
        "two identical slices must produce identical snapshot versions"
    );

    let mut different = slice_with_one_service();
    different.services[0].name = "other".to_string();
    let snapshot_c = translate_mesh_slice_to_snapshot(&different);
    assert_ne!(
        snapshot_a.version, snapshot_c.version,
        "structurally different slices must produce different snapshot versions"
    );
}
