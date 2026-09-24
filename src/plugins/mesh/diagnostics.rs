//! Scoped typed-admission diagnostics. These tables describe diagnostic
//! provenance only: serde still makes every admission/default decision.
//!
//! A serde Map/Enum path segment is document content until the current schema
//! node recognizes it. Never use a global field-name allowlist: a label named
//! `namespace` is still a document key. Unknown subtrees retain the trusted
//! parent and the rejection class, never a guessed schema path.

use serde::de::DeserializeOwned;
use serde_path_to_error::Segment;

#[derive(Clone, Copy)]
pub(crate) enum Schema {
    Slice,
    Policy,
    Route,
    Registry,
    Direction,
    Provider,
    Fields(&'static str),
    MapFields(&'static str),
    Leaf,
}

impl Schema {
    fn fields(self) -> &'static str {
        match self {
            Self::Slice => SLICE,
            Self::Policy => "name namespace scope rules",
            Self::Route => "rules reject_unmatched",
            Self::Registry => "registry reject_status outbound_listen_ports namespace",
            Self::Direction => "server client",
            Self::Provider => "kind config",
            Self::Fields(fields) => fields,
            Self::Leaf | Self::MapFields(_) => "",
        }
    }

    fn child(self, field: &str) -> Self {
        match (self, field) {
            (Self::Slice, "mesh_policies") => Self::Policy,
            (Self::Slice, "revision") => Self::Fields("authority sequence"),
            (Self::Slice, "service_waypoint_bound_services") => Self::Fields("namespace name"),
            (Self::Slice, "node_waypoint_assertors") => Self::Fields("spiffe_id asserts"),
            (Self::Slice, "extension_configs") => Self::Fields("name namespace type_url value"),
            (
                Self::Slice,
                "workloads"
                | "ambient_udp_source_workloads"
                | "node_waypoint_capture_destinations"
                | "local_inbound_workloads",
            ) => Self::Fields(WORKLOAD),
            (Self::Slice, "services" | "local_inbound_services") => Self::Fields(SERVICE),
            (Self::Slice, "ext_authz_providers") => Self::Fields(EXT_AUTHZ),
            (
                Self::Slice,
                "peer_authentications" | "node_waypoint_capture_peer_authentications",
            ) => Self::Fields(PEER_AUTH),
            (Self::Slice, "request_authentications") => Self::Fields(REQUEST_AUTH),
            (Self::Slice, "telemetry_resources") => Self::Fields(TELEMETRY),
            (Self::Slice, "proxy_configs") => Self::Fields(PROXY_CONFIG),
            (Self::Slice, "service_entries") => Self::Fields(SERVICE_ENTRY),
            (Self::Slice, "destination_rules") => Self::Fields(DESTINATION_RULE),
            (Self::Slice, "trust_bundles") => Self::Fields("local federated"),
            (Self::Slice, "multi_cluster") => Self::Fields(MULTI_CLUSTER),
            (Self::Slice, "runtime_overlay") => Self::Fields("fields"),
            (Self::Fields("fields"), "fields") => Self::MapFields("kind value"),
            (Self::Fields("kind value"), "value") => Self::Fields("numerator denominator"),
            (Self::Slice, "local_ingress_listeners") => Self::Fields(
                "port endpoint_host endpoint_port protocol endpoint_unix_path endpoint_unix_h2c owner_namespace owner_service bind",
            ),
            (Self::Slice, "sidecar_egress_scope") => Self::Fields(EGRESS_SCOPE),
            (Self::Fields(EGRESS_SCOPE), "services" | "service_entries" | "destination_rules") => {
                Self::Fields("namespace name hosts ports")
            }
            (Self::Slice, "virtual_service_cors_policies") => Self::Fields(CORS_RESOURCE),
            (Self::Fields(CORS_RESOURCE), "cors") => Self::Fields(CORS),
            (Self::Fields(CORS), "allowed_origins") => Self::Fields("exact prefix regex"),
            (Self::Policy, "scope")
            | (Self::Fields(PEER_AUTH | REQUEST_AUTH | TELEMETRY | PROXY_CONFIG), "scope") => {
                Self::Fields("kind selector namespace attachments")
            }
            (Self::Fields(PEER_AUTH), "selector")
            | (Self::Fields(SERVICE_ENTRY), "workload_selector") => {
                Self::Fields("namespace labels")
            }
            (Self::Fields(EXT_AUTHZ), "include_additional_headers_in_check") => {
                Self::Fields("name value")
            }
            (Self::Fields(EXT_AUTHZ), "include_request_body_in_check") => {
                Self::Fields("max_request_bytes allow_partial_message")
            }
            (Self::Fields(REQUEST_AUTH), "jwt_rules") => Self::Fields(JWT_RULE),
            (Self::Fields(JWT_RULE), "from_headers") => Self::Fields("name prefix"),
            (Self::Fields(JWT_RULE), "output_claim_to_headers") => Self::Fields("header claim"),
            (Self::Fields(TELEMETRY), "config") => Self::Fields("tracing metrics access_logging"),
            (Self::Fields("tracing metrics access_logging"), "tracing") => Self::Fields(TRACING),
            (Self::Fields(TRACING), "providers" | "provider") => Self::Provider,
            (Self::Fields("tracing metrics access_logging"), "metrics") => {
                Self::Fields("tag_overrides disabled_metrics")
            }
            (Self::Fields("tag_overrides disabled_metrics"), "tag_overrides") => {
                Self::Fields("metric name operation")
            }
            (Self::Fields("metric name operation"), "operation") => {
                Self::Fields("type new_name value expression")
            }
            (Self::Fields("type new_name value expression"), "expression")
            | (Self::Fields(CEL), "then_expr" | "else_expr") => Self::Fields(CEL),
            (Self::Fields("tracing metrics access_logging"), "access_logging") => {
                Self::Fields("enabled filter")
            }
            (Self::Fields("enabled filter"), "filter") => Self::Fields(ACCESS_FILTER),
            (Self::Fields(ACCESS_FILTER), "expression")
            | (Self::Fields("op left right value"), "left" | "right") => {
                Self::Fields("op left right value")
            }
            (Self::Fields(SERVICE_ENTRY), "endpoints") => {
                Self::Fields("address ports labels network")
            }
            (Self::Fields("local federated"), "local" | "federated") => Self::Fields(TRUST_BUNDLE),
            (Self::Fields(TRUST_BUNDLE), "jwt_authorities") => {
                Self::Fields("key_id public_key_pem")
            }
            (Self::Fields(MULTI_CLUSTER), "remote_clusters") => Self::Fields(
                "name trust_domain network control_plane_url federation_endpoint discovery_credential_ref",
            ),
            (Self::Fields(MULTI_CLUSTER), "east_west_gateways") => {
                Self::Fields("name namespace host port sni_hosts trust_domain network")
            }
            (Self::Fields(DESTINATION_RULE), "port_level_settings") => {
                Self::MapFields(TRAFFIC_POLICY)
            }
            (Self::Fields(DESTINATION_RULE), "subsets") => {
                Self::Fields("name labels traffic_policy")
            }
            (Self::Fields(DESTINATION_RULE | "name labels traffic_policy"), "traffic_policy") => {
                Self::Fields(TRAFFIC_POLICY)
            }
            (Self::Fields(TRAFFIC_POLICY), "tls") => Self::Fields(
                "mode sni ca_certificates client_certificate private_key subject_alt_names insecure_skip_verify",
            ),
            (Self::Fields(TRAFFIC_POLICY), "outlier_detection") => Self::Fields(
                "consecutive_errors interval_seconds base_ejection_seconds max_ejection_percent",
            ),
            (Self::Fields(TRAFFIC_POLICY), "tcp_keepalive") => {
                Self::Fields("time_seconds interval_seconds probes")
            }
            (Self::Fields(TRAFFIC_POLICY), "connection_pool_http") => Self::Fields(
                "max_requests_per_connection idle_timeout_ms http2_max_requests max_concurrent_streams h2_upgrade_policy max_retries http1_max_pending_requests",
            ),
            (Self::Fields(TRAFFIC_POLICY), "load_balancer") => {
                Self::Fields("simple consistent_hash")
            }
            (Self::Fields("simple consistent_hash"), "consistent_hash") => {
                Self::Fields("http_header_name http_cookie_name use_source_ip")
            }
            (Self::Fields(TRAFFIC_POLICY), "locality_lb_setting") => Self::Fields(LOCALITY),
            (Self::Fields(LOCALITY), "distribute" | "failover") => Self::Fields("from to"),
            (Self::Policy, "rules") => Self::Fields(POLICY_RULE),
            (Self::Fields("kind selector namespace attachments"), "selector")
            | (Self::Fields(WORKLOAD), "selector") => Self::Fields("namespace labels"),
            (Self::Fields("kind selector namespace attachments"), "attachments") => {
                Self::Fields("kind namespace name")
            }
            (Self::Fields(POLICY_RULE), "from") => Self::Fields(
                "spiffe_id_pattern namespace_pattern trust_domain trust_domain_pattern",
            ),
            (Self::Fields(POLICY_RULE), "to") => Self::Fields(
                "methods paths hosts ports not_methods not_paths not_hosts not_ports not_port_patterns",
            ),
            (Self::Fields(POLICY_RULE), "when") => Self::Fields("key values not_values"),
            (Self::Fields(POLICY_RULE), "source_negation") => Self::Fields(
                "not_spiffe_id_patterns not_namespace_patterns not_trust_domain_patterns ip_blocks not_ip_blocks remote_ip_blocks not_remote_ip_blocks",
            ),
            (Self::Fields(POLICY_RULE), "action") => Self::Fields("custom"),
            (Self::Fields("custom"), "custom") => Self::Fields("provider"),
            (Self::Fields(WORKLOAD), "ports") => Self::Fields("port protocol name"),
            (Self::Fields(SERVICE | SERVICE_ENTRY), "ports") => {
                Self::Fields("port protocol name target_port")
            }
            (Self::Fields(WORKLOAD), "node_waypoint") => {
                Self::Fields("address hbone_port spiffe_id node_name node_uid network cluster")
            }
            (Self::Fields(SERVICE), "workloads") => Self::Fields("spiffe_id"),
            (Self::Route, "rules") => Self::Fields(ROUTE_RULE),
            (Self::Fields(ROUTE_RULE), "match") => Self::Fields(
                "methods headers query_params source_namespace authority uri ignore_uri_case",
            ),
            (
                Self::Fields(
                    "methods headers query_params source_namespace authority uri ignore_uri_case",
                ),
                "methods" | "authority" | "uri",
            ) => Self::Fields("exact prefix regex"),
            (Self::Fields(ROUTE_RULE), "destination") => Self::Fields(DESTINATION),
            (Self::Fields(DESTINATION), "backend_tls") => Self::Fields(
                "client_cert_path client_key_path server_ca_cert_path verify_server_cert sni san_allow_list",
            ),
            (Self::Fields(ROUTE_RULE), "retry") => Self::Fields(RETRY),
            (Self::Fields(RETRY), "backoff") => Self::Fields("fixed exponential"),
            (Self::Fields("fixed exponential"), "fixed") => Self::Fields("delay_ms"),
            (Self::Fields("fixed exponential"), "exponential") => Self::Fields("base_ms max_ms"),
            (Self::Fields(ROUTE_RULE), "request_transform" | "response_transform") => {
                Self::Fields("operation target key value")
            }
            (Self::Fields(ROUTE_RULE), "fault") => Self::Fields("delay abort"),
            (Self::Fields("delay abort"), "delay") => Self::Fields("duration_ms percentage"),
            (Self::Fields("delay abort"), "abort") => {
                Self::Fields("status_code percentage grpc_status body")
            }
            (Self::Fields(ROUTE_RULE), "rewrite") => Self::Fields("uri authority match_prefix"),
            (Self::Fields(ROUTE_RULE), "redirect") => {
                Self::Fields("uri authority match_prefix port derive_port scheme redirect_code")
            }
            (Self::Provider, "config") => Self::Fields(
                "url agent_url service collector_url access_token_env accessTokenEnv endpoint",
            ),
            _ => Self::Leaf,
        }
    }
}

const SLICE: &str = "node_id namespace istio_root_namespace workload_spiffe_id waypoint_name \
    waypoint_gateway_class service_waypoint_bound_services labels labels_ambiguous \
    virtual_service_l4_proxies virtual_service_l4_upstreams version revision workloads \
    ambient_udp_source_workloads node_waypoint_assertors node_waypoint_capture_destinations \
    node_waypoint_capture_peer_authentications services local_inbound_services \
    local_inbound_workloads local_ingress_listeners sidecar_ingress_declared \
    declared_ingress_http_ports mesh_policies ext_authz_providers peer_authentications \
    service_entries request_authentications telemetry_resources destination_rules \
    virtual_service_cors_policies proxy_configs trust_bundles multi_cluster \
    outbound_traffic_policy sidecar_outbound_traffic_policy sidecar_egress_scope \
    extension_configs runtime_overlay";
const WORKLOAD: &str = "spiffe_id selector service_name service_namespace addresses ports \
    trust_domain namespace network cluster weight locality service_account pod_uid \
    node_waypoint";
const SERVICE: &str = "name namespace ports workloads protocol_overrides cluster_ips uid";
const POLICY_RULE: &str = "from to when request_principals not_request_principals \
    source_negation never_matches action";
const ROUTE_RULE: &str = "match destination timeout_ms timeout_disabled request_timeout_ms \
    retry retry_disabled request_transform response_transform fault rewrite redirect";
const DESTINATION: &str = "upstream_id backend_host backend_port backend_tls \
    requires_node_waypoint_authz";
const RETRY: &str = "max_retries retryable_status_codes retryable_methods backoff \
    retry_on_connect_failure";
const EXT_AUTHZ: &str = "name service port tls path_prefix timeout_ms fail_open status_on_error \
    include_request_headers_in_check include_additional_headers_in_check \
    include_request_body_in_check headers_to_upstream_on_allow headers_to_downstream_on_deny \
    headers_to_downstream_on_allow";
const PEER_AUTH: &str = "name namespace scope selector mtls_mode port_overrides";
const REQUEST_AUTH: &str = "name namespace scope jwt_rules";
const JWT_RULE: &str = "issuer audiences jwks_uri jwks from_headers from_params \
    forward_original_token output_claim_to_headers";
const TELEMETRY: &str = "name namespace scope config";
const TRACING: &str = "mode sampling_percentage disable_span_reporting disableSpanReporting custom_tags \
    custom_header_tags custom_env_tags providers provider";
const CEL: &str = "op value name attribute then_expr else_expr";
const ACCESS_FILTER: &str = "status_code_min status_code_max min_latency_ms errors_only expression";
const PROXY_CONFIG: &str = "name namespace scope concurrency image environment tracing_sampling";
const SERVICE_ENTRY: &str = "name namespace hosts endpoints resolution location ports \
    export_to workload_selector";
const TRUST_BUNDLE: &str = "trust_domain x509_authorities jwt_authorities refresh_hint_seconds";
const MULTI_CLUSTER: &str = "local_cluster federation_endpoint remote_clusters east_west_gateways";
const DESTINATION_RULE: &str =
    "name namespace host traffic_policy port_level_settings subsets export_to";
const TRAFFIC_POLICY: &str = "connect_timeout_ms outlier_detection load_balancer tls \
    locality_lb_setting max_connections tcp_keepalive tcp_idle_timeout_seconds connection_pool_http";
const LOCALITY: &str = "enabled distribute failover failover_priority";
const CORS_RESOURCE: &str = "name namespace host export_to cors";
const CORS: &str = "allowed_origins allowed_methods allowed_headers exposed_headers \
    max_age_seconds allow_credentials unmatched_preflights";
const EGRESS_SCOPE: &str = "sidecar_enforced dry_run sidecar_applied sidecar_admitted_services \
    sidecar_denied_services destination_rules sidecar_admitted_destination_rules \
    sidecar_denied_destination_rules services service_entries known_destinations";

pub(crate) fn from_value<T: DeserializeOwned>(
    input: serde_json::Value,
    schema: Schema,
) -> Result<T, String> {
    serde_path_to_error::deserialize(input).map_err(|error| decode_error(error, schema))
}

fn decode_error(
    error: serde_path_to_error::Error<serde_json::Error>,
    mut schema: Schema,
) -> String {
    let mut path = String::new();
    for segment in error.path() {
        match segment {
            Segment::Seq { index } => path.push_str(&format!("[{index}]")),
            Segment::Map { key } | Segment::Enum { variant: key } => {
                if let Schema::MapFields(fields) = schema {
                    path.push_str("[<redacted key>]");
                    schema = Schema::Fields(fields);
                    continue;
                }
                let Some(field) = schema
                    .fields()
                    .split_ascii_whitespace()
                    .find(|field| *field == key)
                else {
                    if path.is_empty() {
                        path.push_str("config");
                    }
                    path.push_str("[<redacted key>]");
                    break;
                };
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(field);
                schema = schema.child(field);
            }
            Segment::Unknown => break,
        }
    }
    let inner = error.into_inner().to_string();
    // Unknown/duplicate field names originate in the document, unlike serde's
    // missing-field and expected-type metadata. Classify ONLY the bare error.
    let reason = if inner.starts_with("unknown field ") {
        let fields = schema
            .fields()
            .split_ascii_whitespace()
            .map(|field| format!("`{field}`"))
            .collect::<Vec<_>>();
        if fields.is_empty() {
            "unknown field".to_string()
        } else {
            format!("unknown field; expected one of {}", fields.join(", "))
        }
    } else if inner.starts_with("duplicate field ") {
        "duplicate field".to_string()
    } else {
        crate::util::deserialization::sanitize_message(&inner)
    };
    if path.is_empty() {
        format!("`config`: {reason}")
    } else {
        format!("`{path}`: {reason}")
    }
}
