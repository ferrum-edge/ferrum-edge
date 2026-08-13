//! Stock Envoy / third-party Istio xDS interoperability profile (issue #3317).
//!
//! Enrols the capability boundary of `FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`
//! into the conformance matrix: what a stock control plane CAN drive, and —
//! just as important for an operator reading the matrix — what it explicitly
//! cannot. The behavioural depth lives in
//! `tests/unit/gateway_core/stock_xds_tests.rs` and
//! `tests/integration/mesh_stock_xds_tests.rs`, and the live traffic proof in
//! `tests/functional/functional_mesh_stock_xds_test.rs` (a scripted third-party
//! ADS server driving a real sidecar's data path through update, deletion,
//! NACK, and refusal — unpinned-peer and subset refusals as reachability
//! transitions; foreign-namespace narrowing and RBAC / weighted-route
//! capability refusals as exact ACK + diagnostic + accepted-service continuity);
//! these rows are the product contract.

use prost::Message;

use ferrum_edge::modes::mesh::config::AppProtocol;
use ferrum_edge::xds::stock::{
    STOCK_XDS_TYPE_URLS, StockXdsAccumulator, parse_istio_cluster_name,
    parse_kubernetes_service_host, refusal,
};
use ferrum_edge::xds::stock_proto as sp;
use ferrum_edge::xds::{
    CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, RTDS_TYPE_URL,
    SDS_TYPE_URL, XDS_TYPE_URLS,
};

use crate::conformance::registry::Status;

const CATEGORY: &str = "stock_xds_interop";

const REVIEWS_CLUSTER: &str = "outbound|9080||reviews.default.svc.cluster.local";
const REVIEWS_SAN: &str = "spiffe://cluster.local/ns/default/sa/bookinfo-reviews";
const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";

fn resource(type_url: &str, message: &impl Message) -> (String, Vec<u8>) {
    (type_url.to_string(), message.encode_to_vec())
}

fn cluster_with_pinned_identity(name: &str, san: &str) -> sp::Cluster {
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
        transport_socket: Some(sp::TransportSocket {
            name: "envoy.transport_sockets.tls".to_string(),
            typed_config: Some(sp::Any {
                type_url: UPSTREAM_TLS_TYPE_URL.to_string(),
                value: context.encode_to_vec(),
            }),
        }),
        ..Default::default()
    }
}

fn assignment(cluster: &str, address: &str, port: u16) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster.to_string(),
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

fn converged() -> StockXdsAccumulator {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[resource(
                CDS_TYPE_URL,
                &cluster_with_pinned_identity(REVIEWS_CLUSTER, REVIEWS_SAN),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[resource(
                EDS_TYPE_URL,
                &assignment(REVIEWS_CLUSTER, "10.1.2.3", 9080),
            )],
            "eds-1",
        )
        .expect("EDS applies");
    accumulator
}

/// The stock profile is a DISTINCT protocol name from the Ferrum-private xDS
/// profile. This is the acceptance criterion the issue names first: either
/// consume standard semantics, or clearly separate the private protocol.
#[test]
fn stock_profile_is_separate_from_the_ferrum_private_xds_profile() {
    register_feature!(
        category = CATEGORY,
        feature = "FERRUM_MESH_CONFIG_PROTOCOL=stock_xds (separate from =xds)",
        status = Status::Supported,
        notes = "Issue #3317: `stock_xds` consumes standard v3 CDS/EDS/LDS/RDS from a stock \
                 Envoy / third-party Istio control plane. `xds` keeps its Ferrum-private \
                 name-only resources and ferrum.config.extension.v3.* ECDS carriers, unchanged.",
    );
    let stock: std::collections::BTreeSet<&str> = STOCK_XDS_TYPE_URLS.iter().copied().collect();
    let expected: std::collections::BTreeSet<&str> =
        [CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL]
            .into_iter()
            .collect();
    assert_eq!(stock, expected);

    for private_only in [ECDS_TYPE_URL, RTDS_TYPE_URL] {
        assert!(
            !stock.contains(private_only),
            "the Ferrum-private carrier transport must never be accepted from a stock CP"
        );
        assert!(
            XDS_TYPE_URLS.contains(&private_only),
            "the Ferrum-private profile keeps its subscription set unchanged"
        );
    }
}

#[test]
fn stock_cds_eds_discovery_maps_to_the_typed_mesh_model() {
    register_feature!(
        category = CATEGORY,
        feature = "CDS + EDS → MeshService / Workload discovery",
        status = Status::Supported,
        notes = "An `outbound|<port>||<svc>.<ns>.svc.<domain>` cluster becomes a MeshService \
                 port; its EDS endpoints become Workloads carrying the SPIFFE identity the \
                 control plane itself pins in the cluster's UpstreamTlsContext SAN matcher. \
                 Proven on the live data path in \
                 tests/functional/functional_mesh_stock_xds_test.rs: a service discovered from a \
                 scripted third-party ADS server routes captured traffic through the mesh \
                 transport to its backend, and re-pinning the identity to an impostor SPIFFE \
                 fails the dial closed.",
    );
    let discovery = converged().discovery();
    assert_eq!(discovery.services.len(), 1);
    assert_eq!(discovery.services[0].name, "reviews");
    assert_eq!(discovery.services[0].namespace, "default");
    assert_eq!(discovery.workloads.len(), 1);
    assert_eq!(discovery.workloads[0].spiffe_id.as_str(), REVIEWS_SAN);
}

#[test]
fn stock_lds_filter_chains_classify_the_port_protocol() {
    register_feature!(
        category = CATEGORY,
        feature = "LDS filter chains → per-port protocol classification",
        status = Status::Supported,
        notes = "An HttpConnectionManager chain classifies the port HTTP (HTTP2 for a HTTP2 \
                 codec); a TcpProxy chain classifies it TCP. Two chains that disagree leave \
                 the port Unknown rather than guessing.",
    );
    let hcm = sp::HttpConnectionManager {
        stat_prefix: "outbound".to_string(),
        rds: Some(sp::Rds {
            config_source: Some(sp::ConfigSource {
                ads: vec![Vec::new()],
                ..Default::default()
            }),
            route_config_name: "9080".to_string(),
        }),
        http_filters: vec![sp::HttpFilter {
            name: "envoy.filters.http.router".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let listener = sp::Listener {
        name: "0.0.0.0_9080".to_string(),
        address: Some(sp::Address {
            socket_address: Some(sp::SocketAddress {
                address: "0.0.0.0".to_string(),
                port_value: 9080,
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
        traffic_direction: 2,
        ..Default::default()
    };

    let mut accumulator = converged();
    accumulator
        .apply_sotw(LDS_TYPE_URL, &[resource(LDS_TYPE_URL, &listener)], "lds-1")
        .expect("LDS applies");
    assert_eq!(
        accumulator.discovery().services[0].ports[0].protocol,
        AppProtocol::Http
    );
    assert_eq!(
        accumulator.rds_subscriptions(),
        vec!["9080".to_string()],
        "RDS is subscribed by the names the accepted listeners reference"
    );
}

#[test]
fn stock_dependency_ordering_and_deletion_follow_state_of_the_world() {
    register_feature!(
        category = CATEGORY,
        feature = "Dependency-ordered EDS/RDS subscription + SotW deletion",
        status = Status::Supported,
        notes = "EDS is subscribed by the accepted clusters' resource names and RDS by the \
                 accepted listeners' route-config names, rather than wildcarded. CDS and LDS are \
                 the complete-state types: a cluster absent from a new state-of-the-world CDS \
                 response is deleted, taking its endpoints with it. EDS/RDS responses may be \
                 partial, so they are merged and pruned against the subscription set instead — \
                 an omitted assignment is not a deletion. Both the endpoint withdrawal and the \
                 state-of-the-world cluster withdrawal are asserted on live traffic (and their \
                 replacements asserted to restore it) in \
                 tests/functional/functional_mesh_stock_xds_test.rs.",
    );
    let mut accumulator = converged();
    assert_eq!(
        accumulator.eds_subscriptions(),
        vec![REVIEWS_CLUSTER.to_string()]
    );
    assert!(accumulator.ready());

    accumulator
        .apply_sotw(CDS_TYPE_URL, &[], "cds-2")
        .expect("an empty SotW response applies");
    let discovery = accumulator.discovery();
    assert!(discovery.services.is_empty());
    assert!(discovery.workloads.is_empty());
}

#[test]
fn stock_enforcement_filters_fail_closed_rather_than_degrading_to_plain_routing() {
    register_feature!(
        category = CATEGORY,
        feature = "Enforcement HTTP/network filters refuse the listener",
        status = Status::Supported,
        notes = "envoy.filters.http.{rbac,jwt_authn,ext_authz,cors,local_ratelimit,lua,wasm} \
                 and every non-allowlisted network/listener filter refuse the whole listener \
                 with a field-specific diagnostic. Reducing an Istio listener that carries an \
                 RBAC or JWT filter to plain routing would turn the control plane's DENY into \
                 an ALLOW, so the listener contributes no protocol classification and no VIP. \
                 The live matrix asserts the exact ACK of that generation, the field-specific \
                 diagnostic, and accepted-service continuity; it does not claim a traffic-effect \
                 proof for a host that was never dialable.",
    );
    let hcm = sp::HttpConnectionManager {
        stat_prefix: "outbound".to_string(),
        rds: Some(sp::Rds {
            config_source: Some(sp::ConfigSource {
                ads: vec![Vec::new()],
                ..Default::default()
            }),
            route_config_name: "9080".to_string(),
        }),
        http_filters: vec![
            sp::HttpFilter {
                name: "envoy.filters.http.rbac".to_string(),
                ..Default::default()
            },
            sp::HttpFilter {
                name: "envoy.filters.http.router".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let listener = sp::Listener {
        name: "0.0.0.0_9080".to_string(),
        address: Some(sp::Address {
            socket_address: Some(sp::SocketAddress {
                address: "0.0.0.0".to_string(),
                port_value: 9080,
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
        traffic_direction: 2,
        ..Default::default()
    };

    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(LDS_TYPE_URL, &[resource(LDS_TYPE_URL, &listener)], "lds-1")
        .expect("a well-formed but unsupported listener is ACKed, not NACKed");
    assert!(accumulator.listeners().is_empty());
    let refusals = accumulator.refusals();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].reason, refusal::UNSUPPORTED_HTTP_FILTER);
}

#[test]
fn stock_extension_escapes_are_refused_across_clusters_listeners_and_routes() {
    register_feature!(
        category = CATEGORY,
        feature = "Extension-escape closure refused (cluster/listener/route)",
        status = Status::Supported,
        notes = "Cluster cluster_type / filters / load_balancing_policy / lb_subset_config / \
                 unknown typed_extension_protocol_options, listener api_listener / \
                 filter_chain_matcher, HCM scoped_routes, route typed_per_filter_config / \
                 regex matchers / weighted clusters / cluster specifier plugins, non-ADS \
                 ConfigSources, filesystem DataSources, and inline TLS certificates are all \
                 refused. A refused resource contributes no route, endpoint, or identity.",
    );
    let mut accumulator = StockXdsAccumulator::default();
    let escaping = sp::Cluster {
        filters: vec![vec![0x0a, 0x01, 0x61]],
        ..cluster_with_pinned_identity(REVIEWS_CLUSTER, REVIEWS_SAN)
    };
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[resource(CDS_TYPE_URL, &escaping)], "cds-1")
        .expect("a well-formed but unsupported cluster is ACKed, not NACKed");
    assert!(accumulator.clusters().is_empty());
    assert_eq!(
        accumulator.refusals()[0].reason,
        refusal::CLUSTER_EXTENSION_ESCAPE
    );
}

#[test]
fn stock_profile_never_ingests_control_plane_key_material() {
    register_feature!(
        category = CATEGORY,
        feature = "SDS secrets refused (no CP-delivered key or trust material)",
        status = Status::Supported,
        notes = "The stock profile does not subscribe to SDS. Workload identity and trust \
                 anchors come from Ferrum's own SPIFFE/SVID configuration. An unsolicited \
                 SDS push closes the stream without emitting an SDS request, and every \
                 key-bearing variant is refused by field name without being decoded, stored, \
                 or logged.",
    );
    assert!(!STOCK_XDS_TYPE_URLS.contains(&SDS_TYPE_URL));
    let secret = sp::Secret {
        name: "default".to_string(),
        tls_certificate: vec![vec![0x0a, 0x02, 0x61, 0x62]],
        ..Default::default()
    };
    let refused = ferrum_edge::xds::stock::refuse_stock_secret(&secret.encode_to_vec());
    assert_eq!(refused.reason, refusal::SDS_SECRET_REFUSED);
    assert_eq!(refused.detail, "tls_certificate");
}

#[test]
fn stock_peer_identity_comes_from_the_control_planes_own_san_pin() {
    register_feature!(
        category = CATEGORY,
        feature = "Peer identity from UpstreamTlsContext URI SAN pin",
        status = Status::Supported,
        notes = "A cluster with no pinned SPIFFE, or with more than one candidate, yields a \
                 service shape with NO dialable endpoint plus an explicit \
                 no_pinned_peer_identity / ambiguous_peer_identity diagnostic. Ferrum never \
                 invents a peer identity from endpoint metadata.",
    );
    let mut accumulator = StockXdsAccumulator::default();
    let mut unpinned = cluster_with_pinned_identity(REVIEWS_CLUSTER, REVIEWS_SAN);
    unpinned.transport_socket = None;
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[resource(CDS_TYPE_URL, &unpinned)], "cds-1")
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[resource(
                EDS_TYPE_URL,
                &assignment(REVIEWS_CLUSTER, "10.1.2.3", 9080),
            )],
            "eds-1",
        )
        .expect("EDS applies");
    let discovery = accumulator.discovery();
    assert_eq!(discovery.services.len(), 1);
    assert!(discovery.workloads.is_empty());
    assert!(
        discovery
            .refusals
            .iter()
            .any(|refused| refused.reason == refusal::NO_PINNED_PEER_IDENTITY)
    );
}

#[test]
fn stock_istio_naming_conventions_are_parsed_not_guessed() {
    register_feature!(
        category = CATEGORY,
        feature = "Istio cluster-name and Kubernetes service-host grammar",
        status = Status::Supported,
        notes = "`<direction>|<port>|<subset>|<host>` is parsed strictly; a subset cluster, an \
                 inbound cluster, a non-Kubernetes host, and an unparsable name each get their \
                 own refusal reason rather than a generic rejection.",
    );
    let parsed = parse_istio_cluster_name(REVIEWS_CLUSTER).expect("valid Istio cluster name");
    assert_eq!(parsed.direction, "outbound");
    assert_eq!(parsed.port, 9080);
    assert!(parsed.subset.is_empty());
    assert_eq!(parsed.host, "reviews.default.svc.cluster.local");

    assert_eq!(
        parse_kubernetes_service_host("reviews.default.svc.cluster.local"),
        Some(("reviews".to_string(), "default".to_string()))
    );
    assert_eq!(parse_kubernetes_service_host("api.example.com"), None);
    assert!(parse_istio_cluster_name("BlackHoleCluster").is_none());
}

/// Capabilities a stock control plane cannot drive through this profile. Kept
/// as an explicit `OutOfScope` row so the generated coverage matrix states the
/// boundary instead of leaving it to be inferred from silence.
#[test]
fn stock_profile_residuals_are_declared_not_inferred() {
    register_feature!(
        category = CATEGORY,
        feature = "Declared residuals of the stock profile",
        status = Status::OutOfScope,
        notes = "Not driven by a stock control plane: VirtualService-equivalent traffic \
                 shaping (weighted clusters, header/regex matching, retries, timeouts, fault, \
                 mirroring), DestinationRule subsets and traffic policy, external \
                 STRICT_DNS/LOGICAL_DNS/ORIGINAL_DST clusters, SDS secrets, ECDS/RTDS, delta \
                 xDS, and all enforcement policy (authorization, PeerAuthentication, JWT, \
                 trust bundles) which is supplied by the local FERRUM_MESH_FILE_CONFIG_PATH \
                 document instead. See docs/mesh.md and docs/mesh_supported_matrix.md.",
    );
    // The residual list is a documentation contract; the machine-checkable part
    // is that the profile subscribes to exactly four types and no more.
    assert_eq!(STOCK_XDS_TYPE_URLS.len(), 4);
}
