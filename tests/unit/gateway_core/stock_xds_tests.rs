//! Stock Envoy / third-party Istio xDS interoperability profile (issue #3317).
//!
//! These tests drive `ferrum_edge::xds::stock` with real, field-exact Envoy v3
//! wire bytes (built through the decode-only projections in
//! `proto/envoy/stock/v3/stock_xds.proto`) and assert the two properties the
//! profile exists to guarantee:
//!
//! 1. A standard `outbound|<port>||<svc>.<ns>.svc.<domain>` cluster plus its
//!    EDS assignment becomes a real `MeshService` + `Workload` pair, with the
//!    peer identity taken from the control plane's own `UpstreamTlsContext` SAN
//!    pin rather than invented.
//! 2. Every capability Ferrum does not model is refused with a field-specific
//!    diagnostic and contributes NOTHING — no route, no endpoint, no identity.
//!    In particular an Istio listener carrying an enforcement HTTP filter
//!    (`rbac`, `jwt_authn`, `ext_authz`, `lua`, `wasm`) is refused outright
//!    rather than silently reduced to plain routing.

use std::collections::HashMap;

use prost::Message;

use ferrum_edge::modes::mesh::config::{AppProtocol, ServiceTargetPort};
use ferrum_edge::xds::stock::{StockXdsAccumulator, StockXdsLimits, refusal};
use ferrum_edge::xds::stock_proto as sp;
use ferrum_edge::xds::{CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL};

const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const TCP_PROXY_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";

const REVIEWS_CLUSTER: &str = "outbound|9080||reviews.default.svc.cluster.local";
const REVIEWS_SAN: &str = "spiffe://cluster.local/ns/default/sa/bookinfo-reviews";

// ── fixture builders ─────────────────────────────────────────────────────

fn any(type_url: &str, message: &impl Message) -> (String, Vec<u8>) {
    (type_url.to_string(), message.encode_to_vec())
}

fn ads_source() -> sp::ConfigSource {
    sp::ConfigSource {
        // `AggregatedConfigSource` is an empty upstream message, so presence is
        // the whole signal: one zero-length element.
        ads: vec![Vec::new()],
        ..Default::default()
    }
}

fn san_matcher(san: &str) -> sp::SubjectAltNameMatcher {
    sp::SubjectAltNameMatcher {
        // SanType::URI
        san_type: 3,
        matcher: Some(sp::StringMatcher {
            exact: san.to_string(),
            ..Default::default()
        }),
        oid: String::new(),
    }
}

fn tls_socket(sans: &[&str]) -> sp::TransportSocket {
    let context = sp::UpstreamTlsContext {
        common_tls_context: Some(sp::CommonTlsContext {
            combined_validation_context: Some(sp::CombinedCertificateValidationContext {
                default_validation_context: Some(sp::CertificateValidationContext {
                    match_typed_subject_alt_names: sans
                        .iter()
                        .map(|san| san_matcher(san))
                        .collect(),
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

fn eds_cluster(name: &str, sans: &[&str]) -> sp::Cluster {
    sp::Cluster {
        name: name.to_string(),
        // DiscoveryType::EDS
        r#type: 3,
        eds_cluster_config: Some(sp::EdsClusterConfig {
            eds_config: Some(ads_source()),
            service_name: String::new(),
        }),
        transport_socket: Some(tls_socket(sans)),
        ..Default::default()
    }
}

fn socket_address(address: &str, port: u16) -> sp::Address {
    sp::Address {
        socket_address: Some(sp::SocketAddress {
            address: address.to_string(),
            port_value: u32::from(port),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn lb_endpoint(address: &str, port: u16, health_status: i32) -> sp::LbEndpoint {
    sp::LbEndpoint {
        endpoint: Some(sp::Endpoint {
            address: Some(socket_address(address, port)),
            ..Default::default()
        }),
        health_status,
        ..Default::default()
    }
}

fn cla(cluster_name: &str, endpoints: Vec<sp::LbEndpoint>) -> sp::ClusterLoadAssignment {
    sp::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: endpoints,
            ..Default::default()
        }],
    }
}

fn http_filters(names: &[&str]) -> Vec<sp::HttpFilter> {
    names
        .iter()
        .map(|name| sp::HttpFilter {
            name: (*name).to_string(),
            ..Default::default()
        })
        .collect()
}

fn hcm_listener(
    name: &str,
    bind: &str,
    port: u16,
    route_config_name: &str,
    filters: &[&str],
) -> sp::Listener {
    let hcm = sp::HttpConnectionManager {
        stat_prefix: "outbound".to_string(),
        rds: Some(sp::Rds {
            config_source: Some(ads_source()),
            route_config_name: route_config_name.to_string(),
        }),
        http_filters: http_filters(filters),
        ..Default::default()
    };
    sp::Listener {
        name: name.to_string(),
        address: Some(socket_address(bind, port)),
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

fn tcp_listener(name: &str, bind: &str, port: u16, cluster: &str) -> sp::Listener {
    let tcp = sp::TcpProxy {
        stat_prefix: "outbound".to_string(),
        cluster: cluster.to_string(),
        ..Default::default()
    };
    sp::Listener {
        name: name.to_string(),
        address: Some(socket_address(bind, port)),
        filter_chains: vec![sp::FilterChain {
            filters: vec![sp::NetworkFilter {
                name: "envoy.filters.network.tcp_proxy".to_string(),
                typed_config: Some(sp::Any {
                    type_url: TCP_PROXY_TYPE_URL.to_string(),
                    value: tcp.encode_to_vec(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
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

/// The canonical happy-path accumulator: one EDS cluster with a pinned peer
/// SPIFFE, one endpoint, one HTTP listener, one route configuration.
fn converged_accumulator() -> StockXdsAccumulator {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.3", 9080, 1)]),
            )],
            "eds-1",
        )
        .expect("EDS applies");
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[any(
                LDS_TYPE_URL,
                &hcm_listener(
                    "10.96.0.5_9080",
                    "10.96.0.5",
                    9080,
                    "9080",
                    &["istio.metadata_exchange", "envoy.filters.http.router"],
                ),
            )],
            "lds-1",
        )
        .expect("LDS applies");
    accumulator
        .apply_sotw(
            RDS_TYPE_URL,
            &[any(
                RDS_TYPE_URL,
                &route_config(
                    "9080",
                    &[
                        "reviews.default.svc.cluster.local",
                        "reviews.default.svc.cluster.local:9080",
                        "10.96.0.5:9080",
                    ],
                    REVIEWS_CLUSTER,
                ),
            )],
            "rds-1",
        )
        .expect("RDS applies");
    accumulator
}

// ── happy path ───────────────────────────────────────────────────────────

#[test]
fn stock_cds_eds_lds_rds_produce_a_routable_mesh_service() {
    let accumulator = converged_accumulator();
    assert!(accumulator.ready(), "CDS + EDS present means ready");
    assert!(accumulator.pending_types().is_empty());

    let discovery = accumulator.discovery();
    assert!(
        discovery.refusals.is_empty(),
        "a plain Istio outbound cluster must be accepted whole: {:?}",
        discovery.refusals
    );
    assert_eq!(discovery.services.len(), 1);
    let service = &discovery.services[0];
    assert_eq!(service.name, "reviews");
    assert_eq!(service.namespace, "default");
    assert_eq!(service.ports.len(), 1);
    assert_eq!(service.ports[0].port, 9080);
    assert_eq!(
        service.ports[0].protocol,
        AppProtocol::Http,
        "the HCM filter chain on the VIP listener classifies 9080 as HTTP"
    );
    assert_eq!(
        service.cluster_ips,
        vec!["10.96.0.5".to_string()],
        "the IP-literal virtual-host domain is the service VIP"
    );

    assert_eq!(discovery.workloads.len(), 1);
    let workload = &discovery.workloads[0];
    assert_eq!(workload.spiffe_id.as_str(), REVIEWS_SAN);
    assert_eq!(workload.addresses, vec!["10.1.2.3".to_string()]);
    assert_eq!(workload.namespace, "default");
    assert_eq!(workload.service_name, "reviews");
    assert_eq!(
        workload.service_account.as_deref(),
        Some("bookinfo-reviews"),
        "the service account comes from the CP's own SAN pin, not from a guess"
    );
    assert_eq!(service.workloads.len(), 1);
    assert_eq!(service.workloads[0].spiffe_id.as_str(), REVIEWS_SAN);
}

#[test]
fn stock_tcp_proxy_listener_classifies_the_port_as_tcp_and_names_the_vip() {
    let mut accumulator = StockXdsAccumulator::default();
    let cluster = "outbound|3306||mysql.data.svc.cluster.local";
    let san = "spiffe://cluster.local/ns/data/sa/mysql";
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(CDS_TYPE_URL, &eds_cluster(cluster, &[san]))],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(cluster, vec![lb_endpoint("10.2.0.7", 3306, 1)]),
            )],
            "eds-1",
        )
        .expect("EDS applies");
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[any(
                LDS_TYPE_URL,
                &tcp_listener("10.96.9.9_3306", "10.96.9.9", 3306, cluster),
            )],
            "lds-1",
        )
        .expect("LDS applies");

    let discovery = accumulator.discovery();
    assert_eq!(discovery.services.len(), 1);
    let service = &discovery.services[0];
    assert_eq!(service.ports[0].protocol, AppProtocol::Tcp);
    assert_eq!(
        service.cluster_ips,
        vec!["10.96.9.9".to_string()],
        "a concrete-bind TcpProxy listener attributes its bind address as the service VIP"
    );
}

#[test]
fn stock_endpoint_container_port_becomes_the_service_target_port() {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                // Service port 9080, container port 8080.
                &cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.3", 8080, 1)]),
            )],
            "eds-1",
        )
        .expect("EDS applies");

    let discovery = accumulator.discovery();
    assert_eq!(
        discovery.services[0].ports[0].target_port,
        Some(ServiceTargetPort::Number(8080)),
        "a single distinct endpoint container port is the service targetPort"
    );
    assert_eq!(discovery.workloads[0].ports[0].port, 8080);
}

// ── dependency ordering, warming, deletion ───────────────────────────────

#[test]
fn stock_eds_subscription_follows_the_accepted_clusters() {
    let mut accumulator = StockXdsAccumulator::default();
    assert!(accumulator.eds_subscriptions().is_empty());
    assert!(!accumulator.ready(), "no CDS response yet");
    assert_eq!(accumulator.pending_types(), vec!["cds"]);

    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    assert_eq!(
        accumulator.eds_subscriptions(),
        vec![REVIEWS_CLUSTER.to_string()],
        "the EDS subscription is derived from the accepted clusters, not wildcarded"
    );
    assert!(
        !accumulator.ready(),
        "an EDS-discovered cluster must wait for its assignment"
    );
    assert_eq!(accumulator.pending_types(), vec!["eds"]);
}

#[test]
fn stock_static_only_cluster_set_is_ready_without_eds() {
    let mut accumulator = StockXdsAccumulator::default();
    let cluster = sp::Cluster {
        name: REVIEWS_CLUSTER.to_string(),
        // DiscoveryType::STATIC
        r#type: 0,
        load_assignment: Some(cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.3", 9080, 1)])),
        transport_socket: Some(tls_socket(&[REVIEWS_SAN])),
        ..Default::default()
    };
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[any(CDS_TYPE_URL, &cluster)], "cds-1")
        .expect("CDS applies");

    assert!(accumulator.eds_subscriptions().is_empty());
    assert!(
        accumulator.ready(),
        "a mesh with no EDS-discovered cluster must not block on an EDS response that will \
         never arrive"
    );
    let discovery = accumulator.discovery();
    assert_eq!(discovery.workloads.len(), 1);
    assert_eq!(
        discovery.workloads[0].addresses,
        vec!["10.1.2.3".to_string()]
    );
}

#[test]
fn stock_rds_subscription_follows_the_accepted_listeners() {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[any(
                LDS_TYPE_URL,
                &hcm_listener(
                    "0.0.0.0_9080",
                    "0.0.0.0",
                    9080,
                    "9080",
                    &["envoy.filters.http.router"],
                ),
            )],
            "lds-1",
        )
        .expect("LDS applies");
    assert_eq!(accumulator.rds_subscriptions(), vec!["9080".to_string()]);
}

#[test]
fn stock_sotw_replacement_deletes_a_removed_cluster_and_its_endpoints() {
    let mut accumulator = converged_accumulator();
    assert_eq!(accumulator.discovery().services.len(), 1);

    // The CP re-sends CDS without the cluster: state-of-the-world semantics
    // mean the service disappears rather than lingering as a stale route.
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[], "cds-2")
        .expect("empty CDS applies");
    let discovery = accumulator.discovery();
    assert!(
        discovery.services.is_empty(),
        "a cluster absent from the new SotW response must be deleted"
    );
    assert!(discovery.workloads.is_empty());
    assert!(
        accumulator.eds_subscriptions().is_empty(),
        "the dependency-ordered EDS subscription shrinks with the cluster set"
    );
}

#[test]
fn stock_removed_endpoints_leave_the_service_without_dialable_workloads() {
    let mut accumulator = converged_accumulator();
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(EDS_TYPE_URL, &cla(REVIEWS_CLUSTER, Vec::new()))],
            "eds-2",
        )
        .expect("empty assignment applies");
    let discovery = accumulator.discovery();
    assert_eq!(
        discovery.services.len(),
        1,
        "the service shape survives so policy and the registry gate still see the port"
    );
    assert!(
        discovery.workloads.is_empty(),
        "an emptied assignment must remove every dialable endpoint"
    );
}

#[test]
fn stock_partial_eds_response_keeps_the_assignments_it_did_not_mention() {
    // Only CDS/LDS are complete state under SotW. istiod pushes EDS for just
    // the clusters a change touched ("Cluster was not updated, skip
    // recomputing"), so an omitted assignment is NOT a deletion — reading it as
    // one would blackhole every service the update never mentioned.
    const RATINGS_CLUSTER: &str = "outbound|9080||ratings.default.svc.cluster.local";
    const RATINGS_SAN: &str = "spiffe://cluster.local/ns/default/sa/bookinfo-ratings";

    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[
                any(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])),
                any(CDS_TYPE_URL, &eds_cluster(RATINGS_CLUSTER, &[RATINGS_SAN])),
            ],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[
                any(
                    EDS_TYPE_URL,
                    &cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.3", 9080, 1)]),
                ),
                any(
                    EDS_TYPE_URL,
                    &cla(RATINGS_CLUSTER, vec![lb_endpoint("10.1.2.4", 9080, 1)]),
                ),
            ],
            "eds-1",
        )
        .expect("EDS applies");

    // A partial push naming only `reviews`.
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.9", 9080, 1)]),
            )],
            "eds-2",
        )
        .expect("partial EDS applies");

    let mut addresses: Vec<String> = accumulator
        .discovery()
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.clone())
        .collect();
    addresses.sort();
    assert_eq!(
        addresses,
        vec!["10.1.2.4".to_string(), "10.1.2.9".to_string()],
        "the untouched cluster keeps its endpoints; only the pushed one is replaced"
    );
}

#[test]
fn stock_withdrawing_a_cluster_still_deletes_its_merged_endpoints() {
    // Merging EDS must not make deletion inert: CDS is the complete-state type,
    // so an assignment no accepted cluster references any more is pruned.
    let mut accumulator = converged_accumulator();
    assert_eq!(accumulator.discovery().workloads.len(), 1);

    accumulator
        .apply_sotw(CDS_TYPE_URL, &[], "cds-2")
        .expect("empty CDS applies");
    assert!(accumulator.eds_subscriptions().is_empty());
    assert!(
        accumulator.discovery().workloads.is_empty(),
        "the withdrawn cluster's merged endpoints must not survive as a stale route"
    );

    // Re-advertising the same cluster must not resurrect the pruned assignment.
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-3",
        )
        .expect("CDS re-applies");
    assert!(
        accumulator.discovery().workloads.is_empty(),
        "endpoints come back only when the control plane re-sends the assignment"
    );
}

#[test]
fn stock_partial_rds_response_keeps_the_route_configs_it_did_not_mention() {
    let mut accumulator = converged_accumulator();
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[
                any(
                    LDS_TYPE_URL,
                    &hcm_listener(
                        "10.96.0.5_9080",
                        "10.96.0.5",
                        9080,
                        "9080",
                        &["envoy.filters.http.router"],
                    ),
                ),
                any(
                    LDS_TYPE_URL,
                    &hcm_listener(
                        "10.96.0.6_8080",
                        "10.96.0.6",
                        8080,
                        "8080",
                        &["envoy.filters.http.router"],
                    ),
                ),
            ],
            "lds-2",
        )
        .expect("LDS applies");
    accumulator
        .apply_sotw(
            RDS_TYPE_URL,
            &[
                any(
                    RDS_TYPE_URL,
                    &route_config("9080", &["10.96.0.5:9080"], REVIEWS_CLUSTER),
                ),
                any(
                    RDS_TYPE_URL,
                    &route_config("8080", &["10.96.0.6:8080"], REVIEWS_CLUSTER),
                ),
            ],
            "rds-2",
        )
        .expect("RDS applies");
    assert_eq!(accumulator.route_configs().len(), 2);

    // A partial push naming only `9080`.
    accumulator
        .apply_sotw(
            RDS_TYPE_URL,
            &[any(
                RDS_TYPE_URL,
                &route_config("9080", &["10.96.0.5:9080"], REVIEWS_CLUSTER),
            )],
            "rds-3",
        )
        .expect("partial RDS applies");
    let mut names: Vec<&str> = accumulator
        .route_configs()
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["8080", "9080"],
        "an omitted RouteConfiguration is not a deletion on a by-name subscription"
    );

    // Withdrawing the listener that referenced it IS the deletion.
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[any(
                LDS_TYPE_URL,
                &hcm_listener(
                    "10.96.0.5_9080",
                    "10.96.0.5",
                    9080,
                    "9080",
                    &["envoy.filters.http.router"],
                ),
            )],
            "lds-3",
        )
        .expect("LDS applies");
    let names: Vec<&str> = accumulator
        .route_configs()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        names,
        vec!["9080"],
        "a route configuration no accepted listener references any more is pruned"
    );
}

#[test]
fn stock_refusal_diagnostics_are_bounded_and_free_of_control_characters() {
    // Resource names are control-plane-chosen and bounded only by
    // `max_resource_bytes`, and they land verbatim in operator log lines.
    let hostile = format!(
        "outbound|9080||{}\nWARN forged-log-line\r.example.com",
        "a".repeat(4096)
    );
    let mut cluster = eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]);
    cluster.name = hostile;
    let accumulator = cds_with(cluster);

    let refusals = accumulator.refusals();
    assert_eq!(
        refusals.len(),
        1,
        "the hostile cluster name is refused exactly once: {refusals:?}"
    );
    let refusal = &refusals[0];
    assert!(
        refusal.resource.chars().count() <= 200,
        "a refusal diagnostic must be length-bounded, got {} chars",
        refusal.resource.chars().count()
    );
    assert!(
        !refusal.resource.chars().any(char::is_control),
        "a refusal diagnostic must not carry control characters (log-line forgery)"
    );
    assert!(refusal.resource.ends_with("(truncated)"));
}

#[test]
fn stock_observability_versions_are_bounded_and_free_of_control_characters() {
    let hostile_version = format!("{}\nWARN forged-log-line\r", "v".repeat(4096));
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[], &hostile_version)
        .expect("opaque version applies");

    let version = accumulator
        .per_type_versions()
        .remove("cds")
        .expect("CDS version");
    assert!(version.chars().count() <= 200, "{version}");
    assert!(!version.chars().any(char::is_control), "{version}");
    assert!(version.ends_with("(truncated)"), "{version}");
}

#[test]
fn stock_unhealthy_and_draining_endpoints_are_excluded() {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(
                    REVIEWS_CLUSTER,
                    vec![
                        lb_endpoint("10.1.2.3", 9080, 1), // HEALTHY
                        lb_endpoint("10.1.2.4", 9080, 2), // UNHEALTHY
                        lb_endpoint("10.1.2.5", 9080, 3), // DRAINING
                        lb_endpoint("10.1.2.6", 9080, 5), // DEGRADED
                    ],
                ),
            )],
            "eds-1",
        )
        .expect("EDS applies");

    let addresses: Vec<String> = accumulator
        .discovery()
        .workloads
        .iter()
        .flat_map(|workload| workload.addresses.clone())
        .collect();
    assert_eq!(
        addresses,
        vec!["10.1.2.3".to_string(), "10.1.2.6".to_string()],
        "UNHEALTHY and DRAINING endpoints must not be dialable"
    );
}

// ── structural errors (NACK-worthy) ──────────────────────────────────────

#[test]
fn stock_empty_version_info_is_a_structural_error() {
    let mut accumulator = StockXdsAccumulator::default();
    let error = accumulator
        .apply_sotw(CDS_TYPE_URL, &[], "")
        .expect_err("an unversioned response is not acknowledgeable");
    assert!(error.contains("empty version_info"), "{error}");
}

#[test]
fn stock_duplicate_resource_name_is_a_structural_error() {
    let mut accumulator = StockXdsAccumulator::default();
    let cluster = eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]);
    let error = accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(CDS_TYPE_URL, &cluster), any(CDS_TYPE_URL, &cluster)],
            "cds-1",
        )
        .expect_err("duplicate names make the SotW set ambiguous");
    assert!(error.contains("duplicate Cluster resource name"), "{error}");
}

#[test]
fn stock_mismatched_resource_type_url_is_a_structural_error() {
    let mut accumulator = StockXdsAccumulator::default();
    let error = accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect_err("a resource must match its response type");
    assert!(
        error.contains("does not match response type_url"),
        "{error}"
    );
}

#[test]
fn stock_empty_resource_name_is_a_structural_error() {
    let mut accumulator = StockXdsAccumulator::default();
    let error = accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(CDS_TYPE_URL, &eds_cluster("", &[REVIEWS_SAN]))],
            "cds-1",
        )
        .expect_err("an unnamed cluster has no identity");
    assert!(error.contains("empty name"), "{error}");
}

#[test]
fn stock_resource_count_bound_is_a_structural_error() {
    let limits = StockXdsLimits {
        max_resources_per_type: 1,
        ..StockXdsLimits::default()
    };
    let mut accumulator = StockXdsAccumulator::new(limits);
    let error = accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[
                any(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])),
                any(
                    CDS_TYPE_URL,
                    &eds_cluster(
                        "outbound|80||other.default.svc.cluster.local",
                        &[REVIEWS_SAN],
                    ),
                ),
            ],
            "cds-1",
        )
        .expect_err("an oversized response is refused before it is decoded into the model");
    assert!(
        error.contains("over the configured stock-profile bound"),
        "{error}"
    );
}

#[test]
fn stock_resource_byte_bound_is_a_structural_error() {
    let limits = StockXdsLimits {
        max_resource_bytes: 8,
        ..StockXdsLimits::default()
    };
    let mut accumulator = StockXdsAccumulator::new(limits);
    let error = accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect_err("an oversized resource is refused before decode");
    assert!(error.contains("bytes, over the configured"), "{error}");
}

#[test]
fn stock_unsupported_type_url_is_a_structural_error() {
    let mut accumulator = StockXdsAccumulator::default();
    let error = accumulator
        .apply_sotw(
            "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig",
            &[],
            "ecds-1",
        )
        .expect_err("ECDS is the Ferrum-private carrier transport and must never be accepted here");
    assert!(error.contains("stock profile"), "{error}");
}

// ── capability refusals (ACKed, but contribute nothing) ──────────────────

fn refusal_reasons(accumulator: &StockXdsAccumulator) -> Vec<&'static str> {
    let mut reasons: Vec<&'static str> = accumulator
        .refusals()
        .iter()
        .map(|refused| refused.reason)
        .collect();
    reasons.sort_unstable();
    reasons.dedup();
    reasons
}

fn cds_with(cluster: sp::Cluster) -> StockXdsAccumulator {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[any(CDS_TYPE_URL, &cluster)], "cds-1")
        .expect("a well-formed but unsupported cluster is ACKed, not NACKed");
    accumulator
}

#[test]
fn stock_cluster_upstream_filters_are_an_extension_escape() {
    let accumulator = cds_with(sp::Cluster {
        filters: vec![vec![0x0a, 0x01, 0x61]],
        ..eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])
    });
    assert_eq!(
        refusal_reasons(&accumulator),
        vec![refusal::CLUSTER_EXTENSION_ESCAPE]
    );
    assert!(
        accumulator.clusters().is_empty(),
        "a refused cluster contributes no service"
    );
    assert_eq!(accumulator.refusals()[0].detail, "filters");
}

#[test]
fn stock_cluster_custom_type_and_lb_policy_extensions_are_refused() {
    for (label, cluster) in [
        (
            "cluster_type",
            sp::Cluster {
                cluster_type: vec![Vec::new()],
                ..eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])
            },
        ),
        (
            "load_balancing_policy",
            sp::Cluster {
                load_balancing_policy: vec![Vec::new()],
                ..eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])
            },
        ),
        (
            "lb_subset_config",
            sp::Cluster {
                lb_subset_config: vec![Vec::new()],
                ..eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])
            },
        ),
    ] {
        let accumulator = cds_with(cluster);
        assert!(
            accumulator.clusters().is_empty(),
            "{label} must refuse the cluster"
        );
        assert_eq!(accumulator.refusals()[0].detail, label);
    }
}

#[test]
fn stock_unknown_typed_extension_protocol_option_is_refused_but_http_options_are_allowed() {
    let mut allowed = eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]);
    allowed.typed_extension_protocol_options = HashMap::from([(
        "envoy.extensions.upstreams.http.v3.HttpProtocolOptions".to_string(),
        sp::Any::default(),
    )]);
    assert_eq!(
        cds_with(allowed).clusters().len(),
        1,
        "the standard HTTP protocol options key is not an escape"
    );

    let mut refused = eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]);
    refused.typed_extension_protocol_options = HashMap::from([(
        "envoy.extensions.upstreams.tcp.generic.v3.GenericConnectionPoolProto".to_string(),
        sp::Any::default(),
    )]);
    let accumulator = cds_with(refused);
    assert!(accumulator.clusters().is_empty());
    assert!(
        accumulator.refusals()[0]
            .detail
            .starts_with("typed_extension_protocol_options["),
        "the diagnostic must name the offending extension key: {:?}",
        accumulator.refusals()[0]
    );
}

#[test]
fn stock_dns_and_original_dst_clusters_are_refused() {
    for discovery_type in [1, 2, 4] {
        let accumulator = cds_with(sp::Cluster {
            r#type: discovery_type,
            eds_cluster_config: None,
            ..eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])
        });
        assert_eq!(
            refusal_reasons(&accumulator),
            vec![refusal::UNSUPPORTED_DISCOVERY_TYPE],
            "discovery type {discovery_type} has no endpoint inventory Ferrum can pin"
        );
    }
}

#[test]
fn stock_non_ads_eds_config_source_is_refused() {
    let accumulator = cds_with(sp::Cluster {
        eds_cluster_config: Some(sp::EdsClusterConfig {
            eds_config: Some(sp::ConfigSource {
                api_config_source: vec![Vec::new()],
                ..Default::default()
            }),
            service_name: String::new(),
        }),
        ..eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])
    });
    assert_eq!(
        refusal_reasons(&accumulator),
        vec![refusal::NON_ADS_CONFIG_SOURCE],
        "Ferrum holds one aggregated stream and cannot open a second delivery channel"
    );
}

#[test]
fn stock_inbound_subset_and_non_kubernetes_clusters_are_refused_with_distinct_reasons() {
    for (name, expected) in [
        ("inbound|9080||", refusal::INBOUND_CLUSTER_NOT_MAPPED),
        (
            "outbound|9080|v1|reviews.default.svc.cluster.local",
            refusal::SUBSET_CLUSTER_UNSUPPORTED,
        ),
        (
            "outbound|443||api.example.com",
            refusal::NON_KUBERNETES_SERVICE_HOST,
        ),
        ("some-operator-cluster", refusal::UNPARSABLE_CLUSTER_NAME),
    ] {
        let accumulator = cds_with(eds_cluster(name, &[REVIEWS_SAN]));
        assert_eq!(
            refusal_reasons(&accumulator),
            vec![expected],
            "cluster '{name}' must be refused as {expected}"
        );
    }
}

#[test]
fn stock_reserved_envoy_clusters_are_ignored_without_a_refusal() {
    for name in [
        "BlackHoleCluster",
        "PassthroughCluster",
        "InboundPassthroughClusterIpv4",
        "prometheus_stats",
    ] {
        let accumulator = cds_with(eds_cluster(name, &[REVIEWS_SAN]));
        assert!(accumulator.clusters().is_empty());
        assert!(
            accumulator.refusals().is_empty(),
            "'{name}' is ordinary Envoy plumbing, not a capability gap"
        );
    }
}

#[test]
fn stock_cluster_without_a_pinned_peer_identity_yields_no_dialable_workload() {
    let mut accumulator = StockXdsAccumulator::default();
    let mut cluster = eds_cluster(REVIEWS_CLUSTER, &[]);
    cluster.transport_socket = None;
    accumulator
        .apply_sotw(CDS_TYPE_URL, &[any(CDS_TYPE_URL, &cluster)], "cds-1")
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.3", 9080, 1)]),
            )],
            "eds-1",
        )
        .expect("EDS applies");

    let discovery = accumulator.discovery();
    assert_eq!(
        discovery.services.len(),
        1,
        "the service shape is still useful for policy and the registry gate"
    );
    assert!(
        discovery.workloads.is_empty(),
        "Ferrum must never dial a peer whose identity the control plane did not pin"
    );
    assert!(
        discovery
            .refusals
            .iter()
            .any(|refused| refused.reason == refusal::NO_PINNED_PEER_IDENTITY),
        "the missing pin must be surfaced, not silent: {:?}",
        discovery.refusals
    );
}

#[test]
fn stock_ambiguous_peer_identity_yields_no_dialable_workload() {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(
                    REVIEWS_CLUSTER,
                    &[REVIEWS_SAN, "spiffe://cluster.local/ns/default/sa/other"],
                ),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(REVIEWS_CLUSTER, vec![lb_endpoint("10.1.2.3", 9080, 1)]),
            )],
            "eds-1",
        )
        .expect("EDS applies");

    let discovery = accumulator.discovery();
    assert!(
        discovery.workloads.is_empty(),
        "two candidate identities means Ferrum cannot pin one; it must not pick"
    );
    assert!(
        discovery
            .refusals
            .iter()
            .any(|refused| refused.reason == refusal::AMBIGUOUS_PEER_IDENTITY)
    );
}

#[test]
fn stock_regex_peer_identity_matcher_is_refused() {
    let mut cluster = eds_cluster(REVIEWS_CLUSTER, &[]);
    cluster.transport_socket = Some(sp::TransportSocket {
        name: "envoy.transport_sockets.tls".to_string(),
        typed_config: Some(sp::Any {
            type_url: UPSTREAM_TLS_TYPE_URL.to_string(),
            value: sp::UpstreamTlsContext {
                common_tls_context: Some(sp::CommonTlsContext {
                    validation_context: Some(sp::CertificateValidationContext {
                        match_typed_subject_alt_names: vec![sp::SubjectAltNameMatcher {
                            san_type: 3,
                            matcher: Some(sp::StringMatcher {
                                safe_regex: vec![vec![0x0a, 0x02, 0x2e, 0x2a]],
                                ..Default::default()
                            }),
                            oid: String::new(),
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        }),
    });
    let accumulator = cds_with(cluster);
    assert_eq!(
        refusal_reasons(&accumulator),
        vec![refusal::UNSUPPORTED_PEER_IDENTITY_MATCHER],
        "an unbounded regex must never reach Ferrum's matcher engine"
    );
}

#[test]
fn stock_filesystem_trusted_ca_and_inline_certificates_are_refused() {
    let filesystem = sp::UpstreamTlsContext {
        common_tls_context: Some(sp::CommonTlsContext {
            validation_context: Some(sp::CertificateValidationContext {
                trusted_ca: Some(sp::DataSource {
                    filename: "/etc/certs/root-cert.pem".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut cluster = eds_cluster(REVIEWS_CLUSTER, &[]);
    cluster.transport_socket = Some(sp::TransportSocket {
        name: "envoy.transport_sockets.tls".to_string(),
        typed_config: Some(sp::Any {
            type_url: UPSTREAM_TLS_TYPE_URL.to_string(),
            value: filesystem.encode_to_vec(),
        }),
    });
    assert_eq!(
        refusal_reasons(&cds_with(cluster)),
        vec![refusal::FILESYSTEM_DATA_SOURCE],
        "a stock control plane must not steer Ferrum at a local file path"
    );

    let inline = sp::UpstreamTlsContext {
        common_tls_context: Some(sp::CommonTlsContext {
            tls_certificates: vec![Vec::new()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut cluster = eds_cluster(REVIEWS_CLUSTER, &[]);
    cluster.transport_socket = Some(sp::TransportSocket {
        name: "envoy.transport_sockets.tls".to_string(),
        typed_config: Some(sp::Any {
            type_url: UPSTREAM_TLS_TYPE_URL.to_string(),
            value: inline.encode_to_vec(),
        }),
    });
    assert_eq!(
        refusal_reasons(&cds_with(cluster)),
        vec![refusal::INLINE_CREDENTIAL_MATERIAL],
        "Ferrum never ingests control-plane-delivered client credentials"
    );
}

#[test]
fn stock_unknown_transport_socket_is_refused() {
    let mut cluster = eds_cluster(REVIEWS_CLUSTER, &[]);
    cluster.transport_socket = Some(sp::TransportSocket {
        name: "envoy.transport_sockets.starttls".to_string(),
        typed_config: Some(sp::Any {
            type_url: "type.googleapis.com/envoy.extensions.transport_sockets.starttls.v3.UpstreamStartTlsConfig"
                .to_string(),
            value: Vec::new(),
        }),
    });
    assert_eq!(
        refusal_reasons(&cds_with(cluster)),
        vec![refusal::UNSUPPORTED_TRANSPORT_SOCKET]
    );
}

// ── the enforcement-filter boundary ──────────────────────────────────────

fn lds_with(listener: sp::Listener) -> StockXdsAccumulator {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(LDS_TYPE_URL, &[any(LDS_TYPE_URL, &listener)], "lds-1")
        .expect("a well-formed but unsupported listener is ACKed, not NACKed");
    accumulator
}

#[test]
fn stock_enforcement_http_filters_refuse_the_whole_listener() {
    for filter in [
        "envoy.filters.http.rbac",
        "envoy.filters.http.jwt_authn",
        "envoy.filters.http.ext_authz",
        "envoy.filters.http.cors",
        "envoy.filters.http.local_ratelimit",
        "envoy.filters.http.lua",
        "envoy.filters.http.wasm",
    ] {
        let accumulator = lds_with(hcm_listener(
            "0.0.0.0_9080",
            "0.0.0.0",
            9080,
            "9080",
            &[filter, "envoy.filters.http.router"],
        ));
        assert!(
            accumulator.listeners().is_empty(),
            "'{filter}' enforces something Ferrum cannot express; silently reducing the \
             listener to plain routing would turn the control plane's DENY into an ALLOW"
        );
        let refusals = accumulator.refusals();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].reason, refusal::UNSUPPORTED_HTTP_FILTER);
        assert!(
            refusals[0].detail.contains(filter),
            "the diagnostic must name the filter: {:?}",
            refusals[0]
        );
    }
}

#[test]
fn stock_a_disabled_enforcement_filter_still_refuses_the_listener() {
    let mut listener = hcm_listener(
        "0.0.0.0_9080",
        "0.0.0.0",
        9080,
        "9080",
        &["envoy.filters.http.router"],
    );
    let hcm = sp::HttpConnectionManager {
        stat_prefix: "outbound".to_string(),
        rds: Some(sp::Rds {
            config_source: Some(ads_source()),
            route_config_name: "9080".to_string(),
        }),
        http_filters: vec![
            sp::HttpFilter {
                name: "envoy.filters.http.rbac".to_string(),
                disabled: true,
                is_optional: true,
                ..Default::default()
            },
            sp::HttpFilter {
                name: "envoy.filters.http.router".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    listener.filter_chains[0].filters[0].typed_config = Some(sp::Any {
        type_url: HCM_TYPE_URL.to_string(),
        value: hcm.encode_to_vec(),
    });

    let accumulator = lds_with(listener);
    assert!(
        accumulator.listeners().is_empty(),
        "a disabled RBAC filter can be re-enabled per route, and Ferrum honours neither state"
    );
}

#[test]
fn stock_telemetry_http_filters_are_ignored_not_refused() {
    let accumulator = lds_with(hcm_listener(
        "0.0.0.0_9080",
        "0.0.0.0",
        9080,
        "9080",
        &[
            "istio.metadata_exchange",
            "istio.stats",
            "envoy.filters.http.grpc_stats",
            "envoy.filters.http.fault",
            "envoy.filters.http.router",
        ],
    ));
    assert_eq!(accumulator.listeners().len(), 1);
    assert!(accumulator.refusals().is_empty());
}

#[test]
fn stock_unknown_network_and_listener_filters_refuse_the_listener() {
    let mut listener = hcm_listener(
        "0.0.0.0_9080",
        "0.0.0.0",
        9080,
        "9080",
        &["envoy.filters.http.router"],
    );
    listener.filter_chains[0].filters[0].name = "envoy.filters.network.rbac".to_string();
    listener.filter_chains[0].filters[0].typed_config = Some(sp::Any {
        type_url: "type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC".to_string(),
        value: Vec::new(),
    });
    let accumulator = lds_with(listener);
    assert_eq!(
        refusal_reasons(&accumulator),
        vec![refusal::UNSUPPORTED_NETWORK_FILTER]
    );

    let mut listener = hcm_listener(
        "0.0.0.0_9080",
        "0.0.0.0",
        9080,
        "9080",
        &["envoy.filters.http.router"],
    );
    listener.listener_filters = vec![sp::ListenerFilter {
        // A source-address rewrite is an authorization input.
        name: "envoy.filters.listener.proxy_protocol".to_string(),
        ..Default::default()
    }];
    assert_eq!(
        refusal_reasons(&lds_with(listener)),
        vec![refusal::UNSUPPORTED_LISTENER_FILTER]
    );
}

#[test]
fn stock_api_listener_and_scoped_routes_are_extension_escapes() {
    let mut listener = hcm_listener(
        "0.0.0.0_9080",
        "0.0.0.0",
        9080,
        "9080",
        &["envoy.filters.http.router"],
    );
    listener.api_listener = vec![Vec::new()];
    assert_eq!(
        refusal_reasons(&lds_with(listener)),
        vec![refusal::LISTENER_EXTENSION_ESCAPE]
    );

    let mut listener = hcm_listener(
        "0.0.0.0_9080",
        "0.0.0.0",
        9080,
        "9080",
        &["envoy.filters.http.router"],
    );
    let hcm = sp::HttpConnectionManager {
        stat_prefix: "outbound".to_string(),
        scoped_routes: vec![Vec::new()],
        rds: Some(sp::Rds {
            config_source: Some(ads_source()),
            route_config_name: "9080".to_string(),
        }),
        http_filters: http_filters(&["envoy.filters.http.router"]),
        ..Default::default()
    };
    listener.filter_chains[0].filters[0].typed_config = Some(sp::Any {
        type_url: HCM_TYPE_URL.to_string(),
        value: hcm.encode_to_vec(),
    });
    assert_eq!(
        refusal_reasons(&lds_with(listener)),
        vec![refusal::LISTENER_EXTENSION_ESCAPE]
    );
}

#[test]
fn stock_filter_chain_constraints_and_transport_socket_are_refused() {
    let constrained_matches = [
        sp::FilterChainMatch {
            prefix_ranges: vec![vec![1]],
            ..Default::default()
        },
        sp::FilterChainMatch {
            address_suffix: "127.0.0.1".to_string(),
            ..Default::default()
        },
        sp::FilterChainMatch {
            suffix_len: Some(sp::UInt32Value { value: 8 }),
            ..Default::default()
        },
        sp::FilterChainMatch {
            source_prefix_ranges: vec![vec![1]],
            ..Default::default()
        },
        sp::FilterChainMatch {
            source_ports: vec![15001],
            ..Default::default()
        },
        sp::FilterChainMatch {
            destination_port: Some(sp::UInt32Value { value: 443 }),
            ..Default::default()
        },
        sp::FilterChainMatch {
            transport_protocol: "tls".to_string(),
            ..Default::default()
        },
        sp::FilterChainMatch {
            application_protocols: vec![b"h2".to_vec()],
            ..Default::default()
        },
        sp::FilterChainMatch {
            server_names: vec![b"admin.example.test".to_vec()],
            ..Default::default()
        },
        sp::FilterChainMatch {
            source_type: 1,
            ..Default::default()
        },
        sp::FilterChainMatch {
            direct_source_prefix_ranges: vec![vec![1]],
            ..Default::default()
        },
    ];
    for filter_chain_match in constrained_matches {
        let mut listener = hcm_listener(
            "0.0.0.0_9080",
            "0.0.0.0",
            9080,
            "9080",
            &["envoy.filters.http.router"],
        );
        listener.filter_chains[0].filter_chain_match = Some(filter_chain_match);
        assert_eq!(
            refusal_reasons(&lds_with(listener)),
            vec![refusal::LISTENER_EXTENSION_ESCAPE]
        );
    }

    let mut listener = tcp_listener("0.0.0.0_9080", "0.0.0.0", 9080, REVIEWS_CLUSTER);
    listener.filter_chains[0].transport_socket = Some(sp::TransportSocket::default());
    assert_eq!(
        refusal_reasons(&lds_with(listener)),
        vec![refusal::UNSUPPORTED_TRANSPORT_SOCKET]
    );
}

// ── route refusals ───────────────────────────────────────────────────────

fn rds_with(config: sp::RouteConfiguration) -> StockXdsAccumulator {
    let mut accumulator = StockXdsAccumulator::default();
    // RDS SotW merges and then prunes against listener subscriptions: without
    // an LDS that names this route config, the accumulator would drop it
    // immediately and refusal fixtures could not observe the retained shape.
    let route_name = config.name.clone();
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[any(
                LDS_TYPE_URL,
                &hcm_listener(
                    &format!("{route_name}_listener"),
                    "10.96.0.5",
                    9080,
                    &route_name,
                    &["envoy.filters.http.router"],
                ),
            )],
            "lds-1",
        )
        .expect("LDS applies so the route config stays subscribed");
    accumulator
        .apply_sotw(RDS_TYPE_URL, &[any(RDS_TYPE_URL, &config)], "rds-1")
        .expect("a well-formed but unsupported route config is ACKed, not NACKed");
    accumulator
}

#[test]
fn stock_regex_route_match_refuses_the_virtual_host() {
    let mut config = route_config("9080", &["reviews"], REVIEWS_CLUSTER);
    config.virtual_hosts[0].routes[0].r#match = Some(sp::RouteMatch {
        safe_regex: vec![vec![0x0a, 0x02, 0x2e, 0x2a]],
        ..Default::default()
    });
    let accumulator = rds_with(config);
    assert_eq!(
        refusal_reasons(&accumulator),
        vec![refusal::UNSUPPORTED_ROUTE_MATCH]
    );
    assert!(
        accumulator.route_configs()["9080"].virtual_hosts.is_empty(),
        "a refused virtual host contributes no host alias"
    );
}

#[test]
fn stock_route_match_constraints_refuse_the_virtual_host() {
    let constrained_matches = [
        (
            sp::RouteMatch {
                prefix: "/admin-only".to_string(),
                ..Default::default()
            },
            "routes[].match.prefix",
        ),
        (
            sp::RouteMatch {
                path: "/admin-only".to_string(),
                ..Default::default()
            },
            "routes[].match.path",
        ),
        (
            sp::RouteMatch {
                path_separated_prefix: "/admin".to_string(),
                ..Default::default()
            },
            "routes[].match.path_separated_prefix",
        ),
        (
            sp::RouteMatch {
                prefix: "/".to_string(),
                tls_context: vec![vec![1]],
                ..Default::default()
            },
            "routes[].match.tls_context",
        ),
    ];
    for (route_match, expected_detail) in constrained_matches {
        let mut config = route_config("9080", &["10.96.0.5"], REVIEWS_CLUSTER);
        config.virtual_hosts[0].routes[0].r#match = Some(route_match);
        let accumulator = rds_with(config);
        assert_eq!(
            refusal_reasons(&accumulator),
            vec![refusal::UNSUPPORTED_ROUTE_MATCH]
        );
        assert_eq!(accumulator.refusals()[0].detail, expected_detail);
        assert!(
            accumulator.route_configs()["9080"].virtual_hosts.is_empty(),
            "a path-constrained virtual host must not contribute a VIP"
        );
    }
}

#[test]
fn stock_weighted_clusters_and_per_filter_overrides_refuse_the_virtual_host() {
    let mut config = route_config("9080", &["reviews"], REVIEWS_CLUSTER);
    config.virtual_hosts[0].routes[0].route = Some(sp::RouteAction {
        weighted_clusters: vec![Vec::new()],
        ..Default::default()
    });
    assert_eq!(
        refusal_reasons(&rds_with(config)),
        vec![refusal::UNSUPPORTED_ROUTE_ACTION],
        "traffic shifting has no representation in Ferrum's stock projection"
    );

    let mut config = route_config("9080", &["reviews"], REVIEWS_CLUSTER);
    config.virtual_hosts[0].routes[0].typed_per_filter_config =
        HashMap::from([("envoy.filters.http.rbac".to_string(), sp::Any::default())]);
    assert_eq!(
        refusal_reasons(&rds_with(config)),
        vec![refusal::ROUTE_EXTENSION_ESCAPE],
        "a per-route filter override can re-enable enforcement Ferrum cannot honour"
    );
}

#[test]
fn stock_require_tls_virtual_host_is_refused() {
    let mut config = route_config("9080", &["reviews"], REVIEWS_CLUSTER);
    // TlsRequirementType::ALL
    config.virtual_hosts[0].require_tls = 2;
    assert_eq!(
        refusal_reasons(&rds_with(config)),
        vec![refusal::ROUTE_EXTENSION_ESCAPE],
        "dropping require_tls would downgrade the control plane's enforcement to an allow"
    );
}

#[test]
fn stock_vhds_refuses_the_whole_route_configuration() {
    let mut config = route_config("9080", &["reviews"], REVIEWS_CLUSTER);
    config.vhds = vec![Vec::new()];
    let accumulator = rds_with(config);
    assert_eq!(
        refusal_reasons(&accumulator),
        vec![refusal::ROUTE_EXTENSION_ESCAPE]
    );
    assert!(accumulator.route_configs().is_empty());
}

#[test]
fn stock_path_constrained_multi_service_virtual_host_is_refused_before_attribution() {
    let mut accumulator = StockXdsAccumulator::default();
    let other = "outbound|9080||ratings.default.svc.cluster.local";
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[
                any(CDS_TYPE_URL, &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN])),
                any(CDS_TYPE_URL, &eds_cluster(other, &[REVIEWS_SAN])),
            ],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(EDS_TYPE_URL, &[], "eds-1")
        .expect("EDS applies");
    // Subscribe the route config via LDS before RDS: prune_unsubscribed_route_configs
    // drops CP-delivered RDS that no accepted listener references.
    accumulator
        .apply_sotw(
            LDS_TYPE_URL,
            &[any(
                LDS_TYPE_URL,
                &hcm_listener(
                    "10.96.0.5_9080",
                    "10.96.0.5",
                    9080,
                    "9080",
                    &["envoy.filters.http.router"],
                ),
            )],
            "lds-1",
        )
        .expect("LDS applies");

    let mut config = route_config("9080", &["10.96.0.5"], REVIEWS_CLUSTER);
    config.virtual_hosts[0].routes.push(sp::Route {
        r#match: Some(sp::RouteMatch {
            prefix: "/ratings".to_string(),
            ..Default::default()
        }),
        route: Some(sp::RouteAction {
            cluster: other.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    });
    accumulator
        .apply_sotw(RDS_TYPE_URL, &[any(RDS_TYPE_URL, &config)], "rds-1")
        .expect("RDS applies");

    let discovery = accumulator.discovery();
    assert!(
        discovery
            .refusals
            .iter()
            .any(|refused| refused.reason == refusal::UNSUPPORTED_ROUTE_MATCH)
    );
    assert!(
        discovery
            .services
            .iter()
            .all(|service| service.cluster_ips.is_empty()),
        "a path-constrained virtual host must not attribute its VIP to either service"
    );
}

// ── endpoint refusals ────────────────────────────────────────────────────

#[test]
fn stock_pipe_and_internal_endpoint_addresses_are_refused() {
    let mut accumulator = StockXdsAccumulator::default();
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect("CDS applies");

    let assignment = sp::ClusterLoadAssignment {
        cluster_name: REVIEWS_CLUSTER.to_string(),
        endpoints: vec![sp::LocalityLbEndpoints {
            lb_endpoints: vec![
                sp::LbEndpoint {
                    endpoint: Some(sp::Endpoint {
                        address: Some(sp::Address {
                            pipe: vec![Vec::new()],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    health_status: 1,
                    ..Default::default()
                },
                lb_endpoint("10.1.2.3", 9080, 1),
            ],
            ..Default::default()
        }],
    };
    accumulator
        .apply_sotw(EDS_TYPE_URL, &[any(EDS_TYPE_URL, &assignment)], "eds-1")
        .expect("a refused endpoint does not NACK the assignment");

    let discovery = accumulator.discovery();
    assert_eq!(discovery.workloads.len(), 1);
    assert_eq!(
        discovery.workloads[0].addresses,
        vec!["10.1.2.3".to_string()]
    );
    assert!(
        discovery
            .refusals
            .iter()
            .any(|refused| refused.reason == refusal::ENDPOINT_ADDRESS_UNSUPPORTED)
    );
}

#[test]
fn stock_endpoint_bound_refuses_the_assignment_without_keeping_stale_endpoints() {
    let limits = StockXdsLimits {
        max_endpoints_per_cluster: 1,
        ..StockXdsLimits::default()
    };
    let mut accumulator = StockXdsAccumulator::new(limits);
    accumulator
        .apply_sotw(
            CDS_TYPE_URL,
            &[any(
                CDS_TYPE_URL,
                &eds_cluster(REVIEWS_CLUSTER, &[REVIEWS_SAN]),
            )],
            "cds-1",
        )
        .expect("CDS applies");
    accumulator
        .apply_sotw(
            EDS_TYPE_URL,
            &[any(
                EDS_TYPE_URL,
                &cla(
                    REVIEWS_CLUSTER,
                    vec![
                        lb_endpoint("10.1.2.3", 9080, 1),
                        lb_endpoint("10.1.2.4", 9080, 1),
                    ],
                ),
            )],
            "eds-1",
        )
        .expect("an over-bound assignment is refused, not NACKed");

    let discovery = accumulator.discovery();
    assert!(
        discovery.workloads.is_empty(),
        "an over-bound assignment fails closed to zero endpoints"
    );
    assert!(
        discovery
            .refusals
            .iter()
            .any(|refused| refused.reason == refusal::ENDPOINT_LIMIT_EXCEEDED)
    );
}

// ── SDS refusal ──────────────────────────────────────────────────────────

#[test]
fn stock_sds_secret_is_refused_and_names_the_key_bearing_field() {
    let secret = sp::Secret {
        name: "default".to_string(),
        tls_certificate: vec![vec![0x0a, 0x02, 0x61, 0x62]],
        ..Default::default()
    };
    let refused = ferrum_edge::xds::stock::refuse_stock_secret(&secret.encode_to_vec());
    assert_eq!(refused.reason, refusal::SDS_SECRET_REFUSED);
    assert_eq!(refused.resource, "default");
    assert_eq!(
        refused.detail, "tls_certificate",
        "the diagnostic names the field without decoding or echoing key material"
    );
}

// ── the Ferrum-private profile is untouched ──────────────────────────────

#[test]
fn stock_profile_never_subscribes_the_ferrum_private_carrier_types() {
    use ferrum_edge::xds::stock::STOCK_XDS_TYPE_URLS;
    use ferrum_edge::xds::{ECDS_TYPE_URL, RTDS_TYPE_URL, SDS_TYPE_URL, XDS_TYPE_URLS};

    for private_only in [ECDS_TYPE_URL, RTDS_TYPE_URL, SDS_TYPE_URL] {
        assert!(
            !STOCK_XDS_TYPE_URLS.contains(&private_only),
            "'{private_only}' must stay off the stock subscription: ECDS/RTDS are the \
             Ferrum-private carrier transport, and SDS would mean ingesting third-party key \
             material"
        );
        assert!(
            XDS_TYPE_URLS.contains(&private_only),
            "the Ferrum-private profile must keep subscribing '{private_only}' unchanged"
        );
    }
    assert_eq!(
        XDS_TYPE_URLS.len(),
        7,
        "the Ferrum-private subscription set is unchanged by the stock profile"
    );
    assert_eq!(STOCK_XDS_TYPE_URLS.len(), 4);
}
