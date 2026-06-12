//! Mesh runtime mode scaffolding.
//!
//! `FERRUM_MODE=mesh` data-plane mode.
//!
//! This module owns the mesh-specific runtime knobs and the config-consumer
//! boundary. It deliberately keeps the generic proxy/plugin chain unchanged so
//! existing plugins work in mesh context.

pub mod config;
pub mod config_consumer;
pub mod dns_proxy;
pub mod federation;
pub mod hbone;
pub mod multicluster;
pub mod node_waypoint;
pub mod outbound_enforcement;
pub mod policy;
pub mod policy_deny_log;
pub mod runtime;
pub mod runtime_overlay_consumers;
pub mod slice;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Context as _;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::config::types::{
    BackendScheme, BackendTlsConfig, GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm,
    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
    PassiveHealthCheck, PluginAssociation, PluginConfig, PluginScope, Proxy,
    ResolvedSubsetTrafficPolicy, ResponseBodyMode, SubsetDefinition, SubsetTrafficPolicy, Upstream,
    UpstreamPortOverride, UpstreamTarget,
};
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::dp_client::{DpGrpcTlsReload, GrpcJwtSecret, build_dp_grpc_tls_config};
use crate::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshDestinationRule, MeshJwtRule, MeshLoadBalancer,
    MeshLocalityLbSetting, MeshOutlierDetection, MeshRequestAuthentication, MeshSimpleLb,
    MeshTelemetryConfig, MeshTrafficPolicy, MeshTrafficPolicyTls, MtlsMode, PolicyScope,
    Resolution, ServiceEntry, ServiceEntryLocation, ServiceTargetPort, resolve_target_port,
    service_entry_exported_to_namespace,
};
use crate::modes::mesh::config_consumer::native_client::NativeMeshClientConfig;
use crate::modes::mesh::config_consumer::xds_client::XdsClientConfig;
use crate::modes::mesh::dns_proxy::MeshDnsProxy;
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::tls::{self, TlsPolicy};

const DEFAULT_INBOUND_LISTEN_ADDR: &str = "0.0.0.0:15006";
const DEFAULT_OUTBOUND_LISTEN_ADDR: &str = "127.0.0.1:15001";
const DEFAULT_HBONE_LISTEN_ADDR: &str = "0.0.0.0:15008";
const DEFAULT_EAST_WEST_LISTEN_PORT: u16 = 15443;
const DEFAULT_DNS_LISTEN_ADDR: &str = "127.0.0.1:15053";
const DEFAULT_DNS_UPSTREAM_ADDR: &str = "127.0.0.53:53";
const DEFAULT_DNS_TTL_SECONDS: u32 = 60;
const DEFAULT_DNS_ENABLED: bool = false;
const DEFAULT_DNS_MAX_CONCURRENT_QUERIES: usize = 1024;
const DEFAULT_EGRESS_LISTEN_ADDR: &str = "0.0.0.0:15090";

pub const MESH_SPIFFE_IDENTITY_PLUGIN_ID: &str = "__mesh_spiffe_identity";
pub const MESH_AUTHZ_PLUGIN_ID: &str = "__mesh_authz";
pub const MESH_WORKLOAD_METRICS_PLUGIN_ID: &str = "__mesh_workload_metrics";
pub const MESH_REQUEST_AUTH_PLUGIN_ID: &str = "__mesh_request_auth";
pub const MESH_ACCESS_LOG_PLUGIN_ID: &str = "__mesh_access_log";
pub const MESH_OUTBOUND_REGISTRY_PLUGIN_ID: &str = "__mesh_outbound_registry";
pub const MESH_BPF_METRICS_PLUGIN_ID: &str = "__mesh_bpf_metrics";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTrafficDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshListenerKind {
    PlaintextCapture,
    MtlsTermination,
    HboneTermination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshListener {
    pub direction: MeshTrafficDirection,
    pub kind: MeshListenerKind,
    pub addr: SocketAddr,
}

/// Mesh data-plane topology. Sidecar and ambient share the same runtime path;
/// ambient selects HBONE termination instead of sidecar inbound mTLS,
/// node-waypoint uses one HBONE listener for multiple node-local pods,
/// east-west gateway delegates SNI passthrough to the stream listener manager,
/// and egress gateway materializes HTTP-family proxies from external
/// `ServiceEntry` resources for controlled mesh-to-external routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTopology {
    Sidecar,
    Ambient,
    NodeWaypoint,
    /// Istio Ambient GAMMA service-scoped waypoint. One process serves L7
    /// policy for a specific set of services bound to a named waypoint via
    /// `istio.io/use-waypoint` Service label/annotation (or the equivalent
    /// Gateway-API `parentRefs` flow). HBONE inbound on the same port as
    /// `NodeWaypoint`/`Ambient`; the slice filter narrows services to those
    /// bound to this waypoint instead of admitting every service on this node.
    ServiceWaypoint,
    EastWestGateway,
    EgressGateway,
}

impl MeshTopology {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sidecar" => Ok(Self::Sidecar),
            "ambient" => Ok(Self::Ambient),
            "node_waypoint" | "node-waypoint" => Ok(Self::NodeWaypoint),
            "service_waypoint" | "service-waypoint" => Ok(Self::ServiceWaypoint),
            "east_west_gateway" | "east-west-gateway" => Ok(Self::EastWestGateway),
            "egress_gateway" | "egress-gateway" => Ok(Self::EgressGateway),
            other => Err(format!(
                "Invalid FERRUM_MESH_TOPOLOGY '{other}'. Expected: sidecar, ambient, node_waypoint, service_waypoint, east_west_gateway, or egress_gateway"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::Ambient => "ambient",
            Self::NodeWaypoint => "node_waypoint",
            Self::ServiceWaypoint => "service_waypoint",
            Self::EastWestGateway => "east_west_gateway",
            Self::EgressGateway => "egress_gateway",
        }
    }

    /// Whether this topology terminates HBONE inbound on the shared waypoint
    /// listener (port 15008 by default). True for `Ambient`, `NodeWaypoint`,
    /// and `ServiceWaypoint`. Used by listener spawning and by validation
    /// paths that require HBONE-specific config.
    #[inline]
    #[allow(dead_code)]
    pub fn terminates_hbone(self) -> bool {
        matches!(
            self,
            Self::Ambient | Self::NodeWaypoint | Self::ServiceWaypoint
        )
    }

    /// Whether this topology is a waypoint flavor (node or service scope).
    /// Used by slice-filter and admin-endpoint dispatch to identify the
    /// shared-listener topologies that need extra scoping beyond Ambient's
    /// single-workload identity.
    #[inline]
    #[allow(dead_code)]
    pub fn is_waypoint(self) -> bool {
        matches!(self, Self::NodeWaypoint | Self::ServiceWaypoint)
    }
}

/// Control-protocol source for mesh runtime config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigProtocol {
    Native,
    Xds,
    /// Localized file source: the mesh slice is built DP-side from a local
    /// YAML/JSON document (`FERRUM_MESH_FILE_CONFIG_PATH`), no control plane.
    File,
}

impl MeshConfigProtocol {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "xds" => Ok(Self::Xds),
            "file" => Ok(Self::File),
            other => Err(format!(
                "Invalid FERRUM_MESH_CONFIG_PROTOCOL '{other}'. Expected: native, xds, or file"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xds => "xds",
            Self::File => "file",
        }
    }

    /// Whether this protocol consumes config from a control plane over gRPC
    /// (and therefore needs CP URLs, the CP/DP JWT secret, and gRPC TLS).
    fn requires_control_plane(self) -> bool {
        matches!(self, Self::Native | Self::Xds)
    }
}

/// Parsed mesh runtime settings kept separate from `EnvConfig` so mesh mode
/// stays strictly additive and non-mesh deployments do not carry new fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRuntimeConfig {
    pub node_id: String,
    pub namespace: String,
    pub cp_urls: Vec<String>,
    pub config_protocol: MeshConfigProtocol,
    /// Localized mesh config document consumed when `config_protocol` is
    /// [`MeshConfigProtocol::File`]. Required for that protocol, `None`
    /// otherwise. Sourced from `FERRUM_MESH_FILE_CONFIG_PATH`.
    pub file_config_path: Option<String>,
    pub topology: MeshTopology,
    pub inbound_listen_addr: SocketAddr,
    pub outbound_listen_addr: SocketAddr,
    pub hbone_listen_addr: SocketAddr,
    pub east_west_listen_port: u16,
    /// Port dialed on DESTINATION workloads for Ambient egress HBONE
    /// (`FERRUM_MESH_EGRESS_HBONE_PORT`, default Istio's 15008). Stamped as the
    /// `mesh.hbone_port` target tag when non-default so heterogeneous meshes —
    /// and the two-gateways-on-one-host functional harness — can address peers
    /// off the convention port.
    pub egress_hbone_port: u16,
    /// Port dialed on DESTINATION sidecars for Sidecar egress SVID-mTLS
    /// (`FERRUM_MESH_EGRESS_MTLS_PORT`, default Istio's 15006). Stamped as the
    /// `mesh.mtls_port` target tag when non-default.
    pub egress_mtls_port: u16,
    /// Address the egress gateway listens on for mesh-internal mTLS traffic
    /// from sidecars. Only used when `topology == EgressGateway`. Parsed from
    /// `FERRUM_MESH_EGRESS_LISTEN_ADDR`, default `0.0.0.0:15090`.
    pub egress_listen_addr: SocketAddr,
    pub workload_spiffe_id: Option<String>,
    /// Name of the GAMMA Waypoint this process serves. Required when
    /// `topology == ServiceWaypoint`; ignored for every other topology.
    /// Sourced from `FERRUM_MESH_WAYPOINT_NAME`. The K8s translator records
    /// service→waypoint bindings (via `istio.io/use-waypoint` Service
    /// label/annotation or `gatewayClassName: istio-waypoint` Gateway resources),
    /// and the slice builder narrows admitted services to those bound to
    /// this name at slice-projection time.
    pub waypoint_name: Option<String>,
    /// xDS node cluster identity sent in DiscoveryRequest.node.cluster.
    /// Defaults to the Ferrum namespace when `FERRUM_MESH_XDS_NODE_CLUSTER`
    /// is unset.
    pub xds_node_cluster: String,
    /// Client-side ADS request channel capacity.
    pub xds_stream_channel_capacity: usize,
    /// How often a mesh xDS client retries the primary CP while connected to a
    /// fallback CP. `0` disables the timer.
    pub xds_primary_retry_secs: u64,
    /// Mesh xDS client connect timeout in seconds. `0` disables tonic's
    /// explicit connect timeout.
    pub xds_connect_timeout_seconds: u64,
    /// Operator-configured trust-domain aliases — additional SPIFFE trust
    /// domains accepted as equivalent to the peer cert's trust domain when
    /// validating HBONE baggage `source.principal`. Default empty: strict
    /// same-trust-domain match. Mirror of Istio
    /// `MeshConfig.trustDomainAliases`.
    pub trust_domain_aliases: Vec<crate::identity::TrustDomain>,
    /// Identity-asserting infrastructure SVIDs trusted to rewrite the authz
    /// principal via HBONE baggage `source.principal`. Empty means
    /// `mesh_authz`'s built-in defaults of `["ztunnel", "waypoint"]` apply.
    /// Operator-configured entries replace the defaults. Sourced from
    /// `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS`. Each entry is either a bare
    /// Kubernetes service-account name or a full SPIFFE id.
    pub trusted_hbone_assertors: Vec<String>,
    /// Workload labels for this mesh data plane. Used by `mesh_authz`'s
    /// PolicyScope filter (and by `MeshSlice::from_gateway_config`'s
    /// WorkloadSelector matching) to decide which policies apply to this
    /// proxy's workload. Sourced from `FERRUM_MESH_WORKLOAD_LABELS`
    /// (`key1=val1,key2=val2`); empty when unset. The Kubernetes injector
    /// (Phase D) can populate this from pod labels via the downward API.
    pub workload_labels: std::collections::HashMap<String, String>,
    /// Workload X.509-SVID certificate chain used for mesh-originated backend
    /// mTLS when DestinationRule `ISTIO_MUTUAL` is projected onto an upstream.
    /// Sourced from `FERRUM_GATEWAY_SVID_CERT_PATH`.
    pub workload_svid_cert_path: Option<String>,
    /// Workload X.509-SVID private key used with `workload_svid_cert_path`.
    /// Sourced from `FERRUM_GATEWAY_SVID_KEY_PATH`.
    pub workload_svid_key_path: Option<String>,
    /// Trust bundle for backend server SVID verification when DestinationRule
    /// `ISTIO_MUTUAL` is projected onto an upstream.
    /// Sourced from `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`.
    pub workload_svid_trust_bundle_path: Option<String>,
    /// Whether the transparent DNS proxy is enabled. Opt-in because it
    /// requires iptables/eBPF redirect to be useful.
    /// Sourced from `FERRUM_MESH_DNS_PROXY_ENABLED` (default false).
    pub dns_enabled: bool,
    /// Listen address for the mesh DNS proxy.
    /// Sourced from `FERRUM_MESH_DNS_LISTEN_ADDR` (default `127.0.0.1:15053`).
    pub dns_listen_addr: SocketAddr,
    /// Upstream DNS resolver for non-mesh queries.
    /// Sourced from `FERRUM_MESH_DNS_UPSTREAM_ADDR` (default `127.0.0.53:53`).
    pub dns_upstream_addr: SocketAddr,
    /// TTL (seconds) for DNS responses served from the mesh resolution table.
    /// Sourced from `FERRUM_MESH_DNS_TTL_SECONDS` (default 60).
    pub dns_ttl_seconds: u32,
    /// Maximum concurrent mesh DNS queries / upstream forwards.
    /// Sourced from `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` (default 1024).
    pub dns_max_concurrent_queries: usize,
    /// Maximum per-slice cached mesh DNS response templates.
    /// Sourced from `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` (default 4096).
    pub dns_response_cache_max_entries: usize,
    /// Kubernetes cluster DNS domain used for synthetic mesh service names.
    /// Sourced from `FERRUM_MESH_CLUSTER_DOMAIN` (default `cluster.local`).
    pub cluster_domain: String,
    /// Traffic capture mode for observability/logging. Does not change proxy
    /// behavior — listeners are topology-driven. Sourced from
    /// `FERRUM_MESH_CAPTURE_MODE` (default `explicit`).
    pub capture_mode: crate::capture::CaptureMode,
    /// Operator-set outbound traffic policy. Sourced from
    /// `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY`. When `RegistryOnly`, the
    /// slice-apply path injects the `mesh_outbound_registry` plugin with a
    /// registry built from the slice's known destinations.
    pub outbound_traffic_policy: crate::modes::mesh::config::OutboundTrafficPolicy,
    /// HTTP status returned by the auto-injected outbound registry plugin for
    /// unknown destinations. Sourced from
    /// `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` (default 502).
    pub outbound_registry_reject_status: u16,
    /// When `true`, the slice builder applies Istio `Sidecar` egress scope
    /// narrowing. Sourced from `FERRUM_MESH_SIDECAR_ENFORCED` (default
    /// `false`). When disabled, `Sidecar` resources are parsed and persisted
    /// in `MeshConfig` but the slice projection ignores them — behavior is
    /// identical to today, preserving safe-rollout semantics.
    pub sidecar_enforced: bool,
    /// When `true`, compute Sidecar egress diagnostics while keeping the
    /// unenforced slice output. Sourced from
    /// `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` (default `false`).
    pub sidecar_enforced_dry_run: bool,
    /// When `true`, and only when `sidecar_enforced` is also true, per-workload
    /// slices filter `workloads` down to identities referenced by admitted
    /// services. Sourced from `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING`
    /// (default `false`).
    pub sidecar_identity_narrowing: bool,
    /// Opt-in for stream-family (TCP/UDP) egress proxy materialization.
    /// Default `false` because stream egress proxies bind plaintext listeners
    /// (frontend_tls: false) and mesh_authz cannot authenticate connections
    /// without TLS client certs. Operators must explicitly enable via
    /// `FERRUM_MESH_EGRESS_STREAM_ENABLED=true` after configuring alternative
    /// authentication for stream listeners.
    pub egress_stream_enabled: bool,
    /// Whether the auto-injected mesh `RequestAuthentication` (`jwks_auth`)
    /// plugin requires the JWT `exp` claim. Defaults to `true` (secure):
    /// `exp`-less tokens are rejected so they cannot live forever. Sourced
    /// from `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP`. Present-but-expired tokens
    /// are always rejected regardless of this flag.
    pub request_auth_require_exp: bool,
}

impl MeshRuntimeConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let config_protocol = MeshConfigProtocol::parse(&env_config.mesh_config_protocol)?;
        let cp_urls = env_config.resolved_dp_cp_grpc_urls();
        if config_protocol.requires_control_plane() && cp_urls.is_empty() {
            return Err("FERRUM_DP_CP_GRPC_URLS is required in mesh mode".into());
        }
        let file_config_path = env_config
            .mesh_file_config_path
            .clone()
            .filter(|value| !value.trim().is_empty());
        if config_protocol == MeshConfigProtocol::File && file_config_path.is_none() {
            return Err(
                "FERRUM_MESH_FILE_CONFIG_PATH is required when FERRUM_MESH_CONFIG_PROTOCOL=file"
                    .into(),
            );
        }

        let node_id = resolve_ferrum_var("FERRUM_MESH_NODE_ID")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "ferrum-mesh-node".to_string());
        let topology = MeshTopology::parse(
            &resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").unwrap_or_else(|| "sidecar".to_string()),
        )?;
        let inbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_INBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_INBOUND_LISTEN_ADDR),
        )?;
        let outbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_OUTBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_OUTBOUND_LISTEN_ADDR),
        )?;
        let hbone_listen_addr = parse_socket_addr(
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_HBONE_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_HBONE_LISTEN_ADDR),
        )?;
        let east_west_port_raw = resolve_ferrum_var("FERRUM_MESH_EAST_WEST_LISTEN_PORT")
            .unwrap_or_else(|| DEFAULT_EAST_WEST_LISTEN_PORT.to_string());
        let east_west_listen_port =
            parse_port("FERRUM_MESH_EAST_WEST_LISTEN_PORT", &east_west_port_raw)?;
        let egress_hbone_port_raw = resolve_ferrum_var("FERRUM_MESH_EGRESS_HBONE_PORT")
            .unwrap_or_else(|| hbone::ISTIO_HBONE_PORT.to_string());
        let egress_hbone_port =
            parse_port("FERRUM_MESH_EGRESS_HBONE_PORT", &egress_hbone_port_raw)?;
        let egress_mtls_port_raw = resolve_ferrum_var("FERRUM_MESH_EGRESS_MTLS_PORT")
            .unwrap_or_else(|| {
                crate::proxy::mesh_mtls_pool::ISTIO_SIDECAR_INBOUND_PORT.to_string()
            });
        let egress_mtls_port = parse_port("FERRUM_MESH_EGRESS_MTLS_PORT", &egress_mtls_port_raw)?;
        let egress_listen_addr = parse_socket_addr(
            "FERRUM_MESH_EGRESS_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_EGRESS_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_EGRESS_LISTEN_ADDR),
        )?;
        let workload_spiffe_id = resolve_ferrum_var("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
            .filter(|value| !value.trim().is_empty());
        let waypoint_name = resolve_ferrum_var("FERRUM_MESH_WAYPOINT_NAME")
            .filter(|value| !value.trim().is_empty());
        if matches!(topology, MeshTopology::ServiceWaypoint) && waypoint_name.is_none() {
            return Err(
                "FERRUM_MESH_WAYPOINT_NAME is required when FERRUM_MESH_TOPOLOGY=service_waypoint \
                 (names the GAMMA Waypoint this process serves; bound services match via the \
                 istio.io/use-waypoint Service label/annotation or a Gateway resource with \
                 gatewayClassName=istio-waypoint)"
                    .into(),
            );
        }
        let workload_svid_cert_path = env_config.gateway_svid_cert_path.clone();
        let workload_svid_key_path = env_config.gateway_svid_key_path.clone();
        let workload_svid_trust_bundle_path = env_config.gateway_svid_trust_bundle_path.clone();
        let xds_node_cluster = resolve_ferrum_var("FERRUM_MESH_XDS_NODE_CLUSTER")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| env_config.namespace.clone());
        let xds_connect_timeout_raw = resolve_ferrum_var("FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "10".to_string());
        let xds_connect_timeout_seconds = parse_duration_seconds(
            "FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS",
            &xds_connect_timeout_raw,
        )?;
        let workload_labels =
            parse_workload_labels(resolve_ferrum_var("FERRUM_MESH_WORKLOAD_LABELS").as_deref())?;

        let trust_domain_aliases = env_config
            .mesh_trust_domain_aliases
            .iter()
            .map(|raw| crate::identity::TrustDomain::new(raw.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("FERRUM_MESH_TRUST_DOMAIN_ALIASES: {e}"))?;

        // Validate each entry early so a typo in the env var fails startup
        // with a clear message instead of failing later inside the plugin
        // constructor. We keep the raw strings here and let mesh_authz do the
        // real parsing — this is just an admission gate.
        for raw in &env_config.mesh_trusted_hbone_assertors {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(
                    "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS: entries must not be empty".to_string(),
                );
            }
            if let Some(rest) = trimmed.strip_prefix("spiffe://") {
                let _ = rest;
                crate::identity::SpiffeId::new(trimmed).map_err(|e| {
                    format!(
                        "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS: invalid SPIFFE id '{trimmed}': {e}"
                    )
                })?;
            } else if trimmed.contains("://") {
                return Err(format!(
                    "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS: entry '{trimmed}' looks like a URI \
                     but is not a 'spiffe://' SPIFFE id"
                ));
            }
        }
        let trusted_hbone_assertors = env_config.mesh_trusted_hbone_assertors.clone();

        let dns_enabled = resolve_ferrum_var("FERRUM_MESH_DNS_PROXY_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(DEFAULT_DNS_ENABLED);
        let dns_listen_addr = parse_socket_addr(
            "FERRUM_MESH_DNS_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_DNS_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_DNS_LISTEN_ADDR),
        )?;
        let dns_upstream_addr = parse_socket_addr(
            "FERRUM_MESH_DNS_UPSTREAM_ADDR",
            resolve_ferrum_var("FERRUM_MESH_DNS_UPSTREAM_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_DNS_UPSTREAM_ADDR),
        )?;
        let dns_ttl_seconds = resolve_ferrum_var("FERRUM_MESH_DNS_TTL_SECONDS")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_DNS_TTL_SECONDS);
        let dns_max_concurrent_queries =
            resolve_ferrum_var("FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_DNS_MAX_CONCURRENT_QUERIES);
        let dns_response_cache_max_entries =
            resolve_ferrum_var("FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES);
        let cluster_domain = resolve_ferrum_var("FERRUM_MESH_CLUSTER_DOMAIN")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string());
        let capture_mode = crate::capture::CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let outbound_traffic_policy = match env_config
            .mesh_outbound_traffic_policy
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "allow_any" => crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            "registry_only" => crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly,
            other => {
                return Err(format!(
                    "Invalid FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY '{other}'. Expected: \
                     allow_any or registry_only"
                ));
            }
        };
        let outbound_registry_reject_status = env_config.mesh_outbound_registry_reject_status;
        if !(400..=599).contains(&outbound_registry_reject_status) {
            return Err(format!(
                "Invalid FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS \
                 '{outbound_registry_reject_status}'. Expected: 400..=599"
            ));
        }

        Ok(Self {
            node_id,
            namespace: env_config.namespace.clone(),
            cp_urls,
            config_protocol,
            file_config_path,
            topology,
            inbound_listen_addr,
            outbound_listen_addr,
            hbone_listen_addr,
            east_west_listen_port,
            egress_hbone_port,
            egress_mtls_port,
            egress_listen_addr,
            workload_spiffe_id,
            waypoint_name,
            xds_node_cluster,
            xds_stream_channel_capacity: env_config.xds_stream_channel_capacity,
            xds_primary_retry_secs: env_config.dp_cp_failover_primary_retry_secs,
            xds_connect_timeout_seconds,
            trust_domain_aliases,
            trusted_hbone_assertors,
            workload_labels,
            workload_svid_cert_path,
            workload_svid_key_path,
            workload_svid_trust_bundle_path,
            dns_enabled,
            dns_listen_addr,
            dns_upstream_addr,
            dns_ttl_seconds,
            dns_max_concurrent_queries,
            dns_response_cache_max_entries,
            cluster_domain,
            capture_mode,
            outbound_traffic_policy,
            outbound_registry_reject_status,
            sidecar_enforced: env_config.mesh_sidecar_enforced,
            sidecar_enforced_dry_run: env_config.mesh_sidecar_enforced_dry_run,
            sidecar_identity_narrowing: env_config.mesh_sidecar_identity_narrowing,
            egress_stream_enabled: env_config.mesh_egress_stream_enabled,
            request_auth_require_exp: env_config.mesh_request_auth_require_exp,
        })
    }

    fn native_client_config(&self) -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            waypoint_name: self.service_waypoint_name(),
            labels: self.workload_labels.clone(),
            // Same `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` interval the xDS
            // client uses — the knob is protocol-agnostic failover/failback.
            primary_retry_secs: self.xds_primary_retry_secs,
        }
    }

    fn xds_client_config(&self) -> XdsClientConfig {
        XdsClientConfig {
            cp_urls: self.cp_urls.clone(),
            node_id: self.node_id.clone(),
            cluster: self.xds_node_cluster.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            waypoint_name: self.service_waypoint_name(),
            stream_channel_capacity: self.xds_stream_channel_capacity,
            primary_retry_secs: self.xds_primary_retry_secs,
            connect_timeout_seconds: self.xds_connect_timeout_seconds,
            labels: self
                .workload_labels
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    pub fn listener_plan(&self) -> Vec<MeshListener> {
        match self.topology {
            MeshTopology::Sidecar => vec![
                MeshListener {
                    direction: MeshTrafficDirection::Outbound,
                    kind: MeshListenerKind::PlaintextCapture,
                    addr: self.outbound_listen_addr,
                },
                MeshListener {
                    direction: MeshTrafficDirection::Inbound,
                    kind: MeshListenerKind::MtlsTermination,
                    addr: self.inbound_listen_addr,
                },
            ],
            MeshTopology::Ambient => vec![
                MeshListener {
                    direction: MeshTrafficDirection::Outbound,
                    kind: MeshListenerKind::PlaintextCapture,
                    addr: self.outbound_listen_addr,
                },
                MeshListener {
                    direction: MeshTrafficDirection::Inbound,
                    kind: MeshListenerKind::HboneTermination,
                    addr: self.hbone_listen_addr,
                },
            ],
            MeshTopology::NodeWaypoint | MeshTopology::ServiceWaypoint => {
                vec![MeshListener {
                    direction: MeshTrafficDirection::Inbound,
                    kind: MeshListenerKind::HboneTermination,
                    addr: self.hbone_listen_addr,
                }]
            }
            MeshTopology::EastWestGateway => Vec::new(),
            MeshTopology::EgressGateway => vec![MeshListener {
                direction: MeshTrafficDirection::Inbound,
                kind: MeshListenerKind::MtlsTermination,
                addr: self.egress_listen_addr,
            }],
        }
    }

    /// Whether this topology runs an inbound **TLS-terminating** listener (mTLS
    /// or HBONE). EastWestGateway does SNI passthrough — it forwards encrypted
    /// bytes without terminating — so it has no plaintext-inbound posture and is
    /// the single topology this returns `false` for. This is the one source of
    /// truth for the runtime inbound fail-closed exemption (issue #1523): both
    /// the startup gate (`enforce_mesh_inbound_fail_closed`) and the live-reload
    /// apply task key their "is there anything to fail closed on?" check off it,
    /// so the exempt set can never drift between the two.
    fn has_inbound_tls_termination_listener(&self) -> bool {
        self.listener_plan().iter().any(|listener| {
            matches!(
                listener.kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            )
        })
    }

    pub fn mesh_slice_request(&self) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            waypoint_name: self.service_waypoint_name(),
            labels: self
                .workload_labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            cluster_domain: self.cluster_domain.clone(),
            enforce_sidecar_egress: self.sidecar_enforced,
            sidecar_egress_dry_run: self.sidecar_enforced_dry_run,
            enforce_sidecar_identity_narrowing: self.sidecar_identity_narrowing,
        }
    }

    fn service_waypoint_name(&self) -> Option<String> {
        if self.topology == MeshTopology::ServiceWaypoint {
            self.waypoint_name.clone()
        } else {
            None
        }
    }
}

/// Prepare a gateway snapshot for mesh-mode serving.
///
/// Mesh mode is the only caller. The mutation is cold-path: it runs before
/// `ProxyState` builds router/plugin caches, so non-mesh modes and ordinary
/// requests never pay for mesh plugin injection.
#[allow(dead_code)] // Used by tests and future xDS bootstrap wiring.
pub fn prepare_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.normalize_mesh_fields();
    let mesh_slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
    // Back-project the slice's narrowed `services` view BEFORE preparation so
    // every consumer of the prepared config sees exactly what materialization
    // consumes — CP parity: on the CP-driven paths `gateway_config_from_mesh_slice`
    // builds `config.mesh` FROM the slice, so a DP never carries un-narrowed
    // services. Without this, a Sidecar egress scope that narrows a
    // multi-port service's ports would leave the raw declaration in
    // `config.mesh.services`, and the router's outbound sibling grouping
    // (declared-HTTP-port fail-closed) would demand orig-dst for a service
    // the slice narrowed to a single port.
    if let Some(mesh) = config.mesh.as_deref_mut() {
        mesh.services = mesh_slice.services.clone();
    }
    prepare_normalized_gateway_config_for_mesh(config, runtime, &mesh_slice)
}

fn prepare_gateway_config_for_native_slice(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.normalize_mesh_fields();
    prepare_normalized_gateway_config_for_mesh(config, runtime, mesh_slice)
}

fn prepare_normalized_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<GatewayConfig, anyhow::Error> {
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        ));
    }

    inject_mesh_global_plugins(&mut config, runtime, mesh_slice);
    materialize_east_west_gateway_proxies(&mut config, runtime, mesh_slice);
    materialize_egress_gateway_proxies(&mut config, runtime, mesh_slice);
    materialize_sidecar_inbound_proxies(&mut config, runtime, mesh_slice);
    // Outbound (egress) runs after inbound and before `apply_destination_rules`
    // so the materialized outbound upstreams pick up port-level DR policy
    // (re-keyed there to the resolved dial port). Topology-aware: Ambient emits
    // HBONE routes; Sidecar (SVID-mTLS) lands in a follow-up.
    materialize_mesh_outbound_proxies(&mut config, runtime, mesh_slice);
    apply_destination_rules(&mut config, runtime, mesh_slice)?;
    project_mesh_source_locality(&mut config, mesh_slice);
    // Project slice-filtered ServiceEntries back into the prepared mesh
    // block so introspection consumers (admin diagnostics, projected-config
    // snapshots, future helpers) see the same `export_to` / sidecar-narrowed
    // view the runtime serves. The slice has already applied namespace
    // visibility (`service_entry_exported_to_namespace`), sidecar egress
    // port narrowing, and ServiceWaypoint binding scoping; without this
    // back-projection, `config.mesh.service_entries` still carries the
    // unfiltered set even though DNS rebuild and egress materialization
    // consume the filtered slice directly. Closes Gap #2.
    if let Some(mesh) = config.mesh.as_deref_mut() {
        mesh.service_entries = mesh_slice.service_entries.clone();
    }
    config.normalize_fields();
    config.resolve_upstream_tls();

    // Warn once per config-apply when all three conditions hold:
    // (1) node-waypoint per-pod scoping is active,
    // (2) at least one stream proxy listener (TCP/TcpTls/UDP/DTLS) exists, and
    // (3) the loaded policies include at least one namespace- or
    //     selector-scoped entry.
    // TCP/TcpTls stream accept loops now resolve the connection's source pod
    // identity and stamp the per-pod `PolicyScopeCache`, putting TCP into
    // parity with the HBONE/HTTP path: once the GAP-2M accept-side cookie
    // bridge ships, scoped DENY/ALLOW rules start enforcing on TCP without
    // further proxy-side changes. Pre-GAP-2M both paths resolve `None`, and
    // mesh_authz's stream hook fails closed (Reject 403) whenever scoped
    // policies exist and per-pod scope is missing — see authz.rs and
    // docs/mesh.md.
    //
    // UDP/DTLS is structurally different: node-waypoint capture is keyed by
    // the per-connection TCP socket cookie that the eBPF `connect4`/`connect6`
    // cgroup hooks stamp with the source pod, there are no UDP capture hooks,
    // and a shared UDP frontend socket carries one cookie for all clients —
    // so per-pod scope cannot be wired without a new capture path. UDP/DTLS
    // therefore stays mesh-wide-only and likewise fails closed at mesh_authz
    // whenever scoped policies exist.
    //
    // The predicate covers both TCP and UDP stream listeners because the
    // operator-visible effect today is identical (mesh_authz fail-closed 403)
    // even though the underlying causes differ. Limiting the warning to UDP
    // would silently swallow pre-GAP-2M TCP-only deployments where every
    // scoped-policy connection 403s with no startup signal.
    if runtime.topology == MeshTopology::NodeWaypoint
        && config.proxies.iter().any(|p| p.dispatch_kind.is_stream())
        && mesh_slice
            .mesh_policies
            .iter()
            .any(|p| !matches!(p.scope, PolicyScope::MeshWide))
    {
        let has_tcp_stream = config.proxies.iter().any(|p| {
            matches!(
                p.dispatch_kind,
                crate::config::types::DispatchKind::TcpRaw
                    | crate::config::types::DispatchKind::TcpTls
            )
        });
        let has_udp_stream = config.proxies.iter().any(|p| p.dispatch_kind.is_udp());
        warn!(
            topology = "node_waypoint",
            has_tcp_stream,
            has_udp_stream,
            "Node-waypoint stream connections cannot resolve per-pod scope today: TCP/TcpTls \
             shares the HBONE/HTTP wiring and is gated on the GAP-2M accept-side cookie bridge \
             (until it lands, the accept-side `SO_COOKIE` is not registered in the resolver and \
             scope resolves `None`); UDP/DTLS is permanently mesh-wide-only (a shared UDP \
             frontend socket has no per-source-pod cookie, and node-waypoint capture is \
             TCP-connection scoped). mesh_authz REJECTS these connections (fail-closed, 403) \
             while namespace/selector-scoped policies are configured. MeshWide policies still \
             apply. See docs/mesh.md for details."
        );
    }

    Ok(config)
}

fn project_mesh_source_locality(config: &mut GatewayConfig, mesh_slice: &MeshSlice) {
    let Some(locality) = mesh_source_workload_locality(mesh_slice) else {
        return;
    };
    let loaded_at = config.loaded_at;
    for upstream in &mut config.upstreams {
        if upstream.source_locality.as_deref() != Some(locality) {
            upstream.source_locality = Some(locality.to_string());
            upstream.updated_at = loaded_at;
        }
    }
}

fn mesh_source_workload_locality(mesh_slice: &MeshSlice) -> Option<&str> {
    // SPIFFE-matched workload is authoritative: if the configured workload
    // identity matches a known workload, that workload's locality is the
    // answer — even when it is `None`. Falling through to the label-based
    // heuristic here would pick up a different pod's metadata and silently
    // disagree with the SPIFFE source of truth.
    if let Some(spiffe_id) = mesh_slice.workload_spiffe_id.as_deref()
        && let Some(workload) = mesh_slice
            .workloads
            .iter()
            .find(|workload| workload.spiffe_id.as_str() == spiffe_id)
    {
        return workload.locality.as_deref();
    }

    // Label-based fallback for native-discovery / non-SPIFFE deployments.
    // Multi-replica Deployments commonly produce N workloads with identical
    // labels and identical locality — accept those as a single answer.
    // Bail out only when two label-matched workloads disagree on locality.
    let mut matched_locality: Option<&str> = None;
    for workload in &mesh_slice.workloads {
        if workload.namespace != mesh_slice.namespace {
            continue;
        }
        let labels_match = mesh_slice.labels.iter().all(|(key, value)| {
            workload
                .selector
                .labels
                .get(key)
                .is_some_and(|candidate| candidate == value)
        });
        if !labels_match {
            continue;
        }
        let Some(locality) = workload.locality.as_deref() else {
            continue;
        };
        match matched_locality {
            None => matched_locality = Some(locality),
            Some(prev) if prev == locality => {}
            Some(_) => return None,
        }
    }
    matched_locality
}

fn gateway_config_from_mesh_slice(
    slice: &MeshSlice,
    runtime: &MeshRuntimeConfig,
    federation: Option<&federation::FederationSnapshot>,
    remote_endpoints: Option<&multicluster::RemoteEndpointSnapshot>,
) -> Result<GatewayConfig, anyhow::Error> {
    let loaded_at = chrono::DateTime::parse_from_rfc3339(&slice.version)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    // Overlay live-polled federation bundles on top of the CP-provided
    // [`TrustBundleSet.federated`] so cross-cluster mTLS verifies against the
    // freshest bundle the gateway has fetched. Empty snapshots are a no-op.
    let trust_bundles = match federation {
        Some(snapshot) if !snapshot.bundles.is_empty() => {
            federation::merge_federation_into_trust_bundles(slice.trust_bundles.clone(), snapshot)
        }
        _ => slice.trust_bundles.clone(),
    };
    // Aggregate cross-cluster endpoints (Tier 3b): merge remote-cluster
    // workloads / services discovered from `RemoteCluster.control_plane_url`
    // into the local registry. Remote workloads carry a distinct (remote)
    // locality so the locality-aware priority-tier load balancer fails over
    // local → remote at the endpoint level. Empty snapshots are a no-op.
    let (workloads, services) = match remote_endpoints {
        Some(snapshot) if !snapshot.is_empty() => multicluster::merge_remote_endpoints_into_mesh(
            &slice.workloads,
            &slice.services,
            snapshot,
        ),
        _ => (slice.workloads.clone(), slice.services.clone()),
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads,
            services,
            mesh_policies: slice.mesh_policies.clone(),
            peer_authentications: slice.peer_authentications.clone(),
            service_entries: slice.service_entries.clone(),
            request_authentications: slice.request_authentications.clone(),
            telemetry_resources: slice.telemetry_resources.clone(),
            destination_rules: slice.destination_rules.clone(),
            proxy_configs: slice.proxy_configs.clone(),
            // Slice-narrowing is applied CP-side at `MeshSlice::from_gateway_config`.
            // DPs receive the already-narrowed set of services / service-entries /
            // destination-rules; `MeshSidecar` resources are not echoed back.
            sidecars: Vec::new(),
            trust_bundles,
            multi_cluster: slice.multi_cluster.clone(),
            outbound_traffic_policy: slice.outbound_traffic_policy,
            ..MeshConfig::default()
        })),
        loaded_at,
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_native_slice(config, runtime, slice)
}

async fn wait_for_initial_mesh_config(
    mesh_state: &MeshRuntimeState,
    runtime: &MeshRuntimeConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(GatewayConfig, Arc<MeshSlice>), anyhow::Error> {
    let mut updates = mesh_state.subscribe();
    loop {
        let snapshot = mesh_state.snapshot();
        if let Some(slice) = snapshot.as_ref().as_ref() {
            let federation_snapshot = mesh_state.federation_store().snapshot();
            let remote_snapshot = mesh_state.remote_endpoint_store().snapshot();
            match gateway_config_from_mesh_slice(
                slice,
                runtime,
                Some(&federation_snapshot),
                Some(&remote_snapshot),
            ) {
                Ok(config) => return Ok((config, Arc::new(slice.clone()))),
                Err(e) => {
                    warn!(
                        mesh_slice_version = %slice.version,
                        error = %e,
                        "Ignoring invalid initial mesh slice"
                    );
                }
            }
        }

        tokio::select! {
            changed = updates.changed() => {
                if changed.is_err() {
                    return Err(anyhow::anyhow!(
                        "mesh slice update channel closed before a valid initial slice arrived"
                    ));
                }
            }
            _ = wait_for_mesh_shutdown(&mut shutdown_rx) => {
                return Err(anyhow::anyhow!("shutdown requested"));
            }
        }
    }
}

async fn wait_for_mesh_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn materialize_east_west_gateway_proxies(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    if runtime.topology != MeshTopology::EastWestGateway {
        return;
    }

    // Materialize proxies from explicit EastWestGateway config entries (remote
    // gateway backends).
    if let Some(mesh) = config.mesh.as_ref()
        && let Some(multi_cluster) = mesh.multi_cluster.as_ref()
    {
        for gateway in &multi_cluster.east_west_gateways {
            if gateway.namespace != runtime.namespace {
                continue;
            }

            let proxy = east_west_gateway_proxy(gateway, runtime.east_west_listen_port);

            if let Some(existing) = config
                .proxies
                .iter_mut()
                .find(|candidate| candidate.id == proxy.id)
            {
                *existing = proxy;
            } else {
                config.proxies.push(proxy);
            }
        }
    }

    // Materialize SNI-routed TCP passthrough proxies for each local mesh
    // service so that inbound cross-cluster traffic on the east-west listen
    // port reaches the correct workload. Each service gets one proxy (SNI host
    // = service FQDN) and one upstream (targets = workload addresses).
    let (proxies, upstreams) = build_east_west_service_proxies_and_upstreams(
        mesh_slice,
        runtime.east_west_listen_port,
        &runtime.namespace,
        &runtime.cluster_domain,
    );

    if !proxies.is_empty() {
        info!(
            east_west_service_proxies = proxies.len(),
            east_west_service_upstreams = upstreams.len(),
            "Materializing east-west gateway proxies for local mesh services"
        );
    }

    for upstream in upstreams {
        if let Some(existing) = config
            .upstreams
            .iter_mut()
            .find(|candidate| candidate.id == upstream.id)
        {
            *existing = upstream;
        } else {
            config.upstreams.push(upstream);
        }
    }

    for proxy in proxies {
        if let Some(existing) = config
            .proxies
            .iter_mut()
            .find(|candidate| candidate.id == proxy.id)
        {
            *existing = proxy;
        } else {
            config.proxies.push(proxy);
        }
    }
}

fn east_west_gateway_proxy(gateway: &EastWestGateway, listen_port: u16) -> Proxy {
    let now = chrono::Utc::now();
    Proxy {
        id: mesh_east_west_proxy_id(&gateway.namespace, &gateway.name),
        name: Some(format!("mesh east-west {}", gateway.name)),
        namespace: gateway.namespace.clone(),
        hosts: gateway.sni_hosts.clone(),
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: Default::default(),
        backend_host: gateway.host.clone(),
        backend_port: gateway.port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: true,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_east_west_proxy_id(namespace: &str, name: &str) -> String {
    format!("__mesh-east-west-{namespace}-{name}").replace(['/', '.'], "-")
}

// ── East-west service proxy materialization ──────────────────────────────

/// Build TCP passthrough proxies and upstreams for local mesh services so that
/// inbound cross-cluster traffic on the east-west listen port is SNI-routed to
/// the correct local workload.
///
/// For each service in the mesh slice:
///   - SNI hostname = `{name}.{namespace}.svc.{cluster_domain}`
///   - One upstream with targets from workload addresses
///   - One TCP passthrough proxy on the east-west listen port
fn build_east_west_service_proxies_and_upstreams(
    mesh_slice: &MeshSlice,
    listen_port: u16,
    namespace: &str,
    cluster_domain: &str,
) -> (Vec<Proxy>, Vec<Upstream>) {
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();
    let now = chrono::Utc::now();

    for service in &mesh_slice.services {
        // Build upstream targets from workloads that belong to this service.
        let targets = build_east_west_service_targets(
            service,
            &mesh_slice.workloads,
            mesh_slice
                .multi_cluster
                .as_ref()
                .and_then(|multi_cluster| multi_cluster.local_cluster.as_deref()),
        );
        if targets.is_empty() {
            debug!(
                service = %service.name,
                namespace = %service.namespace,
                "Skipping east-west service with no reachable workload targets"
            );
            continue;
        }

        let sni_hostname = format!(
            "{}.{}.svc.{}",
            service.name, service.namespace, cluster_domain
        );
        let upstream_id = mesh_east_west_service_upstream_id(&service.namespace, &service.name);

        let upstream = Upstream {
            id: upstream_id.clone(),
            name: Some(upstream_id.clone()),
            namespace: namespace.to_string(),
            targets,
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: Some(HealthCheckConfig {
                active: None,
                passive: Some(PassiveHealthCheck::default()),
            }),
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        upstreams.push(upstream);

        let proxy_id = mesh_east_west_service_proxy_id(&service.namespace, &service.name);
        let proxy = east_west_service_proxy(
            &proxy_id,
            &sni_hostname,
            namespace,
            &upstream_id,
            listen_port,
            now,
        );
        proxies.push(proxy);
    }

    (proxies, upstreams)
}

/// Match a service's `WorkloadRef`s to slice `Workload`s one-to-one by index (so
/// replicas sharing a SPIFFE id yield distinct workloads), then drop
/// remote-cluster endpoints. Shared scaffold for the east-west and Ambient
/// outbound target builders, which differ only in per-target port/tag policy. A
/// remote-cluster match still consumes its index (mirroring the original inline
/// loops) so a local replica isn't pulled into a remote ref's slot.
fn matched_local_service_workloads<'a>(
    service: &crate::modes::mesh::config::MeshService,
    workloads: &'a [crate::modes::mesh::config::Workload],
    local_cluster: Option<&str>,
) -> Vec<&'a crate::modes::mesh::config::Workload> {
    let mut matched = Vec::new();
    let mut used_workload_indices = std::collections::HashSet::new();

    for workload_ref in &service.workloads {
        let has_matching_service_metadata = workloads.iter().any(|workload| {
            workload.spiffe_id == workload_ref.spiffe_id
                && workload.namespace == service.namespace
                && workload.service_name == service.name
        });
        let Some((workload_index, workload)) =
            workloads.iter().enumerate().find(|(idx, workload)| {
                !used_workload_indices.contains(idx)
                    && workload.spiffe_id == workload_ref.spiffe_id
                    && workload.namespace == service.namespace
                    && (workload.service_name == service.name || !has_matching_service_metadata)
            })
        else {
            continue;
        };
        used_workload_indices.insert(workload_index);
        if local_cluster.is_some_and(|local_cluster| {
            workload
                .cluster
                .as_deref()
                .is_some_and(|cluster| cluster != local_cluster)
        }) {
            continue;
        }
        matched.push(workload);
    }

    matched
}

/// Build upstream targets from workloads that belong to the given service.
///
/// Matches workloads by SPIFFE ID against the service's `WorkloadRef` list.
/// Each workload address + first port produces one `UpstreamTarget`. When a
/// workload has no addresses, it is skipped (pod IP not yet assigned).
fn build_east_west_service_targets(
    service: &crate::modes::mesh::config::MeshService,
    workloads: &[crate::modes::mesh::config::Workload],
    local_cluster: Option<&str>,
) -> Vec<UpstreamTarget> {
    let mut targets = Vec::new();
    for workload in matched_local_service_workloads(service, workloads, local_cluster) {
        // Backend (container) port for this workload address: honor the first
        // service port's `targetPort` (Kubernetes' authoritative
        // service-port→container-port binding). A DECLARED targetPort is
        // authoritative — resolve it, or SKIP this target (fail closed) rather
        // than fall back to the Service port, so an unresolved named targetPort
        // (rollout skew / typo like `targetPort: "http"` with no matching
        // container port) doesn't silently publish a target on the wrong port.
        // Only an ABSENT targetPort falls back to the service port; a service
        // with no ports at all uses the workload's first port.
        let target_port = match service.ports.first() {
            Some(sp) => match sp.target_port.as_ref() {
                Some(_) => match resolve_target_port(sp.target_port.as_ref(), &workload.ports) {
                    Some(p) if p != 0 => p,
                    _ => continue,
                },
                None => sp.port,
            },
            None => workload.ports.first().map(|p| p.port).unwrap_or(80),
        };

        for address in &workload.addresses {
            targets.push(UpstreamTarget {
                host: address.clone(),
                port: target_port,
                weight: 1,
                tags: workload.selector.labels.clone(),
                locality: workload.locality.clone(),
                path: None,
            });
        }
    }

    targets
}

/// Construct a TCP passthrough proxy for east-west service routing.
fn east_west_service_proxy(
    id: &str,
    sni_hostname: &str,
    namespace: &str,
    upstream_id: &str,
    listen_port: u16,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("mesh east-west svc {sni_hostname}")),
        namespace: namespace.to_string(),
        hosts: vec![sni_hostname.to_string()],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: Default::default(),
        backend_host: String::new(),
        backend_port: 0,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: true,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_east_west_service_proxy_id(namespace: &str, name: &str) -> String {
    format!("__mesh-ew-svc-{namespace}-{name}").replace(['/', '.'], "-")
}

fn mesh_east_west_service_upstream_id(namespace: &str, name: &str) -> String {
    format!("__mesh-ew-upstream-{namespace}-{name}").replace(['/', '.'], "-")
}

// ── Sidecar inbound route materialization ─────────────────────────────────

/// True for application protocols routed through the HTTP-family proxy chain.
/// Stream protocols (raw TCP/TLS and the DB protocols) need an L4 stream proxy
/// and are materialized by a later stage.
fn is_http_family_mesh_protocol(protocol: AppProtocol) -> bool {
    matches!(
        protocol,
        AppProtocol::Http | AppProtocol::Http2 | AppProtocol::Grpc | AppProtocol::Unknown
    )
}

/// Host header variants a peer may use to reach a mesh service, in the form the
/// router matches (the listener strips the port before routing): the bare
/// service name (local-namespace short form) plus the `.ns`, `.ns.svc`, and
/// `.ns.svc.<cluster_domain>` Kubernetes forms.
fn mesh_service_host_variants(name: &str, namespace: &str, cluster_domain: &str) -> Vec<String> {
    let domain = cluster_domain.trim_matches('.');
    vec![
        name.to_string(),
        format!("{name}.{namespace}"),
        format!("{name}.{namespace}.svc"),
        format!("{name}.{namespace}.svc.{domain}"),
    ]
}

/// Reserved id prefix for materialized sidecar inbound routes. These routes are
/// **direction-scoped**: only the inbound listener may serve them. The inbound
/// and outbound capture listeners share one route table, so the request path
/// uses [`is_mesh_inbound_route_id`] to keep these loopback routes off the
/// outbound listener (where they would shortcut an app's own-service traffic to
/// loopback instead of the mesh).
pub(crate) const MESH_INBOUND_PROXY_ID_PREFIX: &str = "__mesh-inbound-";

/// Whether a proxy id names a materialized sidecar inbound route.
pub(crate) fn is_mesh_inbound_route_id(id: &str) -> bool {
    id.starts_with(MESH_INBOUND_PROXY_ID_PREFIX)
}

fn mesh_inbound_proxy_id(namespace: &str, name: &str, port: u16) -> String {
    format!("{MESH_INBOUND_PROXY_ID_PREFIX}{namespace}-{name}-{port}").replace(['/', '.'], "-")
}

/// Reserved id prefix for materialized mesh OUTBOUND (egress) routes. Like the
/// inbound prefix, these are **direction-scoped**: only the outbound capture
/// listener (`:15001`) may serve them. The inbound and outbound capture
/// listeners share one route table, so the request path uses
/// [`mesh_route_direction`] to keep an outbound route off the inbound listener
/// (where a peer's request for the local service would otherwise be re-tunnelled
/// back out to the mesh instead of delivered locally).
pub(crate) const MESH_OUTBOUND_PROXY_ID_PREFIX: &str = "__mesh-outbound-";

/// Whether a proxy id names a materialized mesh outbound route.
pub(crate) fn is_mesh_outbound_route_id(id: &str) -> bool {
    id.starts_with(MESH_OUTBOUND_PROXY_ID_PREFIX)
}

/// The mesh traffic direction a materialized route serves, or `None` when the id
/// does not name a direction-scoped mesh route. The request path uses this to
/// keep inbound routes off the outbound listener and outbound routes off the
/// inbound listener (the two capture listeners share one route table).
///
/// Only ever called on **proxy (route) ids** — request path, operator-yield,
/// authz — never on upstream ids. `mesh_outbound_upstream_id` deliberately uses a
/// non-overlapping `__mesh-out-upstream-` prefix (not `__mesh-outbound-`) so an
/// upstream id can never be misclassified as an Outbound route here.
pub(crate) fn mesh_route_direction(id: &str) -> Option<MeshTrafficDirection> {
    if is_mesh_inbound_route_id(id) {
        Some(MeshTrafficDirection::Inbound)
    } else if is_mesh_outbound_route_id(id) {
        Some(MeshTrafficDirection::Outbound)
    } else {
        None
    }
}

fn mesh_outbound_proxy_id(namespace: &str, name: &str, port: u16) -> String {
    format!("{MESH_OUTBOUND_PROXY_ID_PREFIX}{namespace}-{name}-{port}").replace(['/', '.'], "-")
}

/// HTTP-family service ports of an in-mesh service, with `protocol_overrides`
/// applied — the canonical "which ports does outbound materialization route"
/// predicate, shared by the materializer, the router's sibling grouping, and
/// the listen-path uniqueness exemption so the three can never drift.
pub(crate) fn service_http_family_ports(
    service: &crate::modes::mesh::config::MeshService,
) -> Vec<&crate::modes::mesh::config::ServicePort> {
    service
        .ports
        .iter()
        .filter(|sp| {
            is_http_family_mesh_protocol(
                service
                    .protocol_overrides
                    .get(&sp.port)
                    .copied()
                    .unwrap_or(sp.protocol),
            )
        })
        .collect()
}

/// Expected per-port outbound sibling routes of one in-mesh service.
///
/// **Single source of truth for per-port sibling identity.** Derived
/// *forward* from the mesh service (the exact ids [`mesh_outbound_proxy_id`]
/// emits), never by parsing ids backwards — `{namespace}-{name}` joining is
/// lossy (`ns "a" / svc "b-c"` and `ns "a-b" / svc "c"` collide), so id
/// parsing could conflate distinct services. Consumers:
/// `RouterCache::build_route_table` groups a service's materialized siblings
/// under one lowest-port tier representative, and
/// `validate_unique_listen_paths` exempts same-service sibling pairs from the
/// host+path uniqueness conflict (they intentionally share hosts + `/` and
/// are disambiguated post-match by the captured original-destination port).
/// Operator configs cannot reach either consumer's special-casing:
/// resource-id validation rejects ids starting with `_`, so
/// `__mesh-outbound-*` ids exist only via mesh materialization, and both
/// consumers key strictly off the `mesh` block the slice carried.
pub(crate) struct MeshOutboundServiceGroup {
    /// How many HTTP-family ports the service DECLARES — which can exceed the
    /// materialized sibling count (e.g. an unresolved named `targetPort`
    /// produced no targets for one port). Orig-dst-less requests must fail
    /// closed whenever this is > 1, even if only one sibling materialized:
    /// without the captured port, traffic meant for a skipped port is
    /// indistinguishable from the surviving one.
    pub declared_http_ports: usize,
    /// `(service_port, expected proxy id)` for every declared HTTP-family
    /// port, whether or not it materialized.
    pub siblings: Vec<(u16, String)>,
}

/// Compute [`MeshOutboundServiceGroup`]s for every in-mesh service carried by
/// the prepared config's `mesh` block. Empty outside mesh mode.
pub(crate) fn mesh_outbound_service_groups(
    mesh: &crate::modes::mesh::config::MeshConfig,
) -> Vec<MeshOutboundServiceGroup> {
    mesh.services
        .iter()
        .filter_map(|service| {
            let http_ports = service_http_family_ports(service);
            if http_ports.is_empty() {
                return None;
            }
            Some(MeshOutboundServiceGroup {
                declared_http_ports: http_ports.len(),
                siblings: http_ports
                    .iter()
                    .map(|sp| {
                        (
                            sp.port,
                            mesh_outbound_proxy_id(&service.namespace, &service.name, sp.port),
                        )
                    })
                    .collect(),
            })
        })
        .collect()
}

/// Upstream id for a materialized mesh outbound route, one per HTTP-family
/// service port (per-port upstreams keep LB counters, hash rings, passive
/// health, and pool keys isolated per app port). Deliberately
/// does NOT start with [`MESH_OUTBOUND_PROXY_ID_PREFIX`] (`__mesh-outbound-`) so
/// it is never misclassified as a direction-scoped *route* by
/// [`mesh_route_direction`] / [`is_mesh_outbound_route_id`] — those predicates
/// run on proxy ids, and a shared prefix would be a latent footgun if one were
/// ever handed an upstream id. Parallels the east-west `__mesh-ew-upstream-` id.
fn mesh_outbound_upstream_id(namespace: &str, name: &str, port: u16) -> String {
    format!("__mesh-out-upstream-{namespace}-{name}-{port}").replace(['/', '.'], "-")
}

/// Materialize inbound routes for the sidecar's **local** workload so that
/// mTLS-terminated traffic on the inbound listener (`:15006`) reaches the
/// co-located application on loopback. `docs/mesh.md` documents this ("the
/// inbound listener … forwards plaintext to the local application"), but nothing
/// implemented it: the slice's services/workloads were never turned into
/// routable inbound proxies, so an inbound request found no proxy and returned
/// 404. (The existing integration tests passed only because they hand-supplied a
/// `Proxy`.) This closes that gap for the sidecar inbound direction.
///
/// Driven by the **local workload(s)** — this sidecar's own pods, matched by the
/// SPIFFE identity in `runtime.workload_spiffe_id`. Each route is keyed by the
/// workload's own service FQDN (`service_name`/`namespace`) — never another
/// service that merely shares the SPIFFE id — and targets the workload's own
/// listening port (the app/target port, which may differ from the K8s service
/// port). For each HTTP-family workload port, one loopback proxy is emitted.
/// Stream (TCP) inbound and multi-port disambiguation by original destination
/// land in later stages. The emitted proxies carry the
/// [`MESH_INBOUND_PROXY_ID_PREFIX`] so the request path keeps them off the
/// outbound listener.
fn materialize_sidecar_inbound_proxies(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    if runtime.topology != MeshTopology::Sidecar {
        return;
    }
    let Some(local_spiffe) = runtime.workload_spiffe_id.as_deref() else {
        debug!("Sidecar inbound route materialization skipped: no workload SPIFFE identity");
        return;
    };

    let now = chrono::Utc::now();
    // The local workload(s) are this sidecar's own pods. A SPIFFE id alone is not
    // a unique key — multiple workloads can share a service account / SPIFFE id —
    // so when the sidecar's own labels are known (the slice carries them), also
    // require the workload's selector labels to **non-vacuously** match this pod
    // (an empty selector matches "any" and would reintroduce the shared-SPIFFE
    // leak). Without labels at all, fall back to SPIFFE-only.
    let sidecar_labels = &mesh_slice.labels;
    // Name of this sidecar's own cluster, when the slice declares one. Used to
    // tell a remote endpoint apart from a legitimately cluster-tagged local
    // workload (see the cluster check below).
    let local_cluster = mesh_slice
        .multi_cluster
        .as_ref()
        .and_then(|mc| mc.local_cluster.as_deref());
    // `local_inbound_workloads` is `Some` exactly when the slice builder resolved
    // the local-inbound view under Sidecar narrowing — it is then AUTHORITATIVE
    // for BOTH the workload and service sources: an empty `Some` means the local
    // identity was ambiguous, so materialize nothing and do NOT fall back to the
    // narrowed `workloads`/`services` (that could collapse the ambiguity to one
    // wrong service). `None` means no narrowing applied, so fall back to the full
    // sets. Reading the separate views keeps the egress/outbound-registry
    // `services`/`workloads` untouched. `resolve_local_workloads` re-applies the
    // precise match + shared-SPIFFE ambiguity guard so CP and DP cannot drift.
    let (inbound_services, local_workload_src) = match mesh_slice.local_inbound_workloads.as_deref()
    {
        Some(local) => (mesh_slice.local_inbound_services.as_slice(), local),
        None => (
            mesh_slice.services.as_slice(),
            mesh_slice.workloads.as_slice(),
        ),
    };
    let mut materialized = 0usize;
    for workload in crate::modes::mesh::slice::resolve_local_workloads(
        local_workload_src,
        local_spiffe,
        sidecar_labels,
        local_cluster,
    ) {
        // Route inbound traffic for the service(s) this workload backs — its own
        // service (matched by name + namespace), never a service that merely
        // shares its SPIFFE id. HTTP-family routability is read from the SERVICE
        // port: Kubernetes container ports carry only the transport protocol
        // (e.g. TCP), while the application protocol (HTTP/gRPC) is declared on
        // the Service. The backend targets the workload's own app port.
        for service in inbound_services.iter().filter(|s| {
            s.name == workload.service_name
                && s.namespace == workload.namespace
                // Require the Service to actually back the local workload. Other
                // mesh resolution paths treat `MeshService.workloads[]` as the
                // authoritative backing set, so a service whose refs omit this
                // SPIFFE id (config typo, EndpointSlice lag) must not be routed
                // to the local app merely because the names line up.
                && s.workloads.iter().any(|w| w.spiffe_id.as_str() == local_spiffe)
        }) {
            let http_ports: Vec<_> = service
                .ports
                .iter()
                .filter(|sp| {
                    is_http_family_mesh_protocol(
                        service
                            .protocol_overrides
                            .get(&sp.port)
                            .copied()
                            .unwrap_or(sp.protocol),
                    )
                })
                .collect();
            // Host-only routing can't disambiguate multiple service ports: the
            // router strips the request port from `Host`/`:authority`, so a
            // single `/` route on the shared service host matches traffic to
            // EVERY service port and would silently forward it to the FIRST
            // port's backend (e.g. `Host: reviews:90` -> the port-80 backend).
            // That is a cross-port misroute, not the clean "unsupported"
            // rejection callers expect. OUTBOUND multi-port disambiguation has
            // landed (captured original destination — `SO_ORIGINAL_DST` — picks
            // the per-port sibling), but INBOUND `:15006` dials are direct
            // (never NATed), so the inbound side will instead disambiguate by
            // the pre-strip `Host`/`:authority` port the egress side preserves
            // (a later stage). Until then, fail closed: materialize NOTHING for
            // a local service exposing more than one HTTP-family port, and
            // warn. Operators who need a specific port routed sooner can define
            // an explicit proxy (which this materializer yields to).
            // Single-HTTP-port services — the common case — are unaffected.
            if http_ports.len() > 1 {
                warn!(
                    service = %service.name,
                    namespace = %service.namespace,
                    http_ports = http_ports.len(),
                    "Local service exposes multiple HTTP-family ports; inbound host-only routing \
                     cannot disambiguate them yet (inbound port disambiguation lands in a later \
                     stage). Skipping inbound materialization for this service to avoid \
                     forwarding one port's traffic to another port's backend; define an explicit \
                     proxy to route a specific port."
                );
                continue;
            }
            let Some(service_port) = http_ports.first() else {
                continue;
            };
            // Backend = the workload's app (container) port this service port
            // forwards to. A declared `targetPort` is Kubernetes' AUTHORITATIVE
            // service-port→container-port binding, so honor it exclusively — no
            // heuristic fallback: a numeric targetPort IS the container port; a
            // named one resolves against the workload's container-port names, and
            // an unresolved name (typo / rollout skew) SKIPS rather than guessing
            // a different port. Only when NO targetPort is declared do we fall
            // back to the heuristic over the signals we have, in declining order
            // of confidence:
            //   1. a shared port NAME — the canonical Service↔container linkage,
            //   2. an equal port NUMBER — `targetPort` defaulting to the port,
            //   3. the workload's sole container port — single-port pod.
            // A workload that declares no ports defaults to the service port
            // (Kubernetes' `targetPort`-defaults-to-`port` rule). Otherwise the
            // target is genuinely ambiguous: skip and warn rather than misroute.
            let backend_port = match service_port.target_port.as_ref() {
                Some(ServiceTargetPort::Number(n)) => Some(*n),
                Some(ServiceTargetPort::Name(name)) => workload
                    .ports
                    .iter()
                    .find(|wp| wp.name.as_deref() == Some(name.as_str()))
                    .map(|wp| wp.port),
                None if workload.ports.is_empty() => Some(service_port.port),
                None => workload
                    .ports
                    .iter()
                    .find(|wp| wp.name.is_some() && wp.name == service_port.name)
                    .or_else(|| {
                        workload
                            .ports
                            .iter()
                            .find(|wp| wp.port == service_port.port)
                    })
                    .or(match workload.ports.as_slice() {
                        [only] => Some(only),
                        _ => None,
                    })
                    .map(|wp| wp.port),
            };
            // Reject a 0 backend (invalid targetPort/port; config validation also
            // rejects it for non-xDS slices) defensively rather than route to :0.
            let Some(backend_port) = backend_port.filter(|&p| p != 0) else {
                warn!(
                    service = %service.name,
                    namespace = %service.namespace,
                    service_port = service_port.port,
                    target_port = ?service_port.target_port,
                    "Cannot resolve a usable local backend port for an inbound mesh route \
                     (no resolvable Service targetPort, and no port name/number match among \
                     multiple container ports). Set targetPort, name the ports consistently, \
                     or define an explicit proxy. Skipping this route."
                );
                continue;
            };
            let proxy = mesh_inbound_loopback_proxy(
                &mesh_inbound_proxy_id(&service.namespace, &service.name, service_port.port),
                mesh_service_host_variants(
                    &service.name,
                    &service.namespace,
                    &runtime.cluster_domain,
                ),
                &service.namespace,
                backend_port,
                now,
            );
            // Don't collide with or shadow an explicit operator proxy (e.g. the
            // documented file-mode pre-materialization workaround) already
            // routing this host. Our route is the greediest HTTP match for the
            // host — a `/` prefix — and the router searches exact → prefix →
            // regex → host-only, so it shadows any same-host regex (`~...`) or
            // host-only (`listen_path: None`) route and collides with an equal
            // `/` prefix. (Exact and longer-prefix operator routes still win for
            // their own paths, so they coexist.) Only HTTP-family proxies share
            // this routing space: stream proxies route by `listen_port` and carry
            // empty hosts + null `listen_path` that would otherwise read as a
            // host-only catch-all here, so skip them exactly as
            // `validate_unique_listen_paths` does. Either way the operator wins.
            if config.proxies.iter().any(|p| {
                if p.id == proxy.id || p.dispatch_kind.is_stream() {
                    return false;
                }
                let shadows_or_collides = p.listen_path == proxy.listen_path
                    || p.listen_path.is_none()
                    || p.listen_path
                        .as_deref()
                        .is_some_and(|lp| lp.starts_with('~'));
                shadows_or_collides && crate::config::types::hosts_overlap(&p.hosts, &proxy.hosts)
            }) {
                debug!(
                    proxy_id = %proxy.id,
                    "Skipping inbound route materialization; an existing proxy already routes this host/path"
                );
                continue;
            }
            if let Some(existing) = config.proxies.iter_mut().find(|p| p.id == proxy.id) {
                *existing = proxy;
            } else {
                config.proxies.push(proxy);
            }
            materialized += 1;
        }
    }

    if materialized > 0 {
        info!(
            inbound_proxies = materialized,
            local_spiffe, "Materialized sidecar inbound routes to the local application"
        );
    }
}

/// A loopback-backend HTTP proxy: inbound mesh traffic matching `hosts` is
/// forwarded in plaintext to the co-located application at `127.0.0.1:<port>`.
fn mesh_inbound_loopback_proxy(
    id: &str,
    hosts: Vec<String>,
    namespace: &str,
    port: u16,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("mesh inbound {id}")),
        namespace: namespace.to_string(),
        hosts,
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: Default::default(),
        backend_host: "127.0.0.1".to_string(),
        backend_port: port,
        backend_path: None,
        strip_listen_path: false,
        // The local app expects its own service Host, not 127.0.0.1.
        preserve_host_header: true,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// Reserved id for a synthesized transparent INBOUND HBONE relay proxy.
/// Ambient / Waypoint terminators materialize NO inbound routes (the relay is
/// transparent — it dials the CONNECT `:authority`, the original destination
/// the mesh peer asked for), so an authenticated HBONE CONNECT that matches no
/// route is relayed through a proxy built on the fly with this id. Carries the
/// `MESH_INBOUND_PROXY_ID_PREFIX` so `mesh_authz`'s `mesh_inbound_app_port`
/// reads the relay's `backend_port` (the destination app port) when evaluating
/// port-scoped policy, exactly as for a materialized sidecar inbound route.
pub(crate) const MESH_INBOUND_HBONE_RELAY_PROXY_ID: &str = "__mesh-inbound-hbone-relay";

/// Build the transparent inbound HBONE relay proxy that dials `host:port` — the
/// CONNECT `:authority` of an authenticated mesh peer. The caller
/// (`proxy::mod`) gates this on the destination being a safe local target
/// (loopback or a slice-known in-mesh workload address), so the terminator can
/// never be used as an open proxy to arbitrary hosts. No upstreams / circuit
/// breaker / retry: it is a transparent TCP tunnel, and the mesh global plugin
/// chain (incl. `mesh_authz`) still runs on the outer CONNECT before the relay.
pub(crate) fn mesh_inbound_hbone_relay_proxy(host: &str, port: u16) -> Proxy {
    let now = chrono::Utc::now();
    Proxy {
        id: MESH_INBOUND_HBONE_RELAY_PROXY_ID.to_string(),
        name: Some("mesh inbound hbone relay".to_string()),
        namespace: String::new(),
        hosts: Vec::new(),
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: Default::default(),
        backend_host: host.to_string(),
        backend_port: port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: true,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// Which egress transport an outbound-materialized target dispatches over.
/// Mesh transports are PER-TOPOLOGY (see `.claude/rules/mesh.md` "Datapath
/// Layering"): Ambient/Waypoint speak HBONE on `:15008`; Sidecar speaks plain
/// SVID-mTLS HTTP on `:15006`. A target carries exactly one transport tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MeshEgressTransport {
    /// HBONE: HTTP/2 CONNECT over mTLS to the destination's `:15008`
    /// (`mesh.hbone`-tagged targets → `HboneConnectionPool`).
    Hbone,
    /// Plain SVID-mTLS HTTP/2 to the destination sidecar's inbound `:15006`
    /// (`mesh.mtls`-tagged targets → `MeshMtlsConnectionPool`).
    SidecarMtls,
}

/// Materialize OUTBOUND (egress) routes for the in-mesh services this proxy may
/// reach, so captured outbound traffic on the outbound listener (`:15001`) is
/// routed to the destination workload over the topology's transport. Before this
/// native outbound had no materialized routes and 404'd.
///
/// **Topology-aware transport** (see `.claude/rules/mesh.md` "Datapath
/// Layering"): mesh transports differ by topology, so egress materialization
/// does too —
/// - **Ambient / Waypoint** egress uses **HBONE** (HTTP/2 CONNECT over mTLS to
///   the destination's `:15008`): `mesh.hbone`-tagged targets light up
///   `current_dispatch_hbone` → `HboneConnectionPool`.
/// - **Sidecar** egress uses plain **SVID-mTLS HTTP/2** to the peer sidecar's
///   inbound `:15006` (HBONE is NOT Sidecar's transport): `mesh.mtls`-tagged
///   targets light up `current_dispatch_mesh_mtls` → `MeshMtlsConnectionPool`.
///   Sidecar egress yields to the local workload's own materialized INBOUND
///   route (the route table holds one proxy per host+path), so a service's
///   own-sidecar traffic stays on the loopback route.
///
/// Driven by `MeshSlice.services` (the egress-narrowed view). For each in-mesh
/// service: host = the service FQDN variants (the router strips the request
/// port), upstream targets = the service's local-cluster workload addresses
/// tagged for the topology's transport (each carrying the destination identity
/// the outbound mTLS handshake pins), one HTTP-family `/` proxy **per
/// HTTP-family service port** with a matching per-port upstream. The route
/// table groups a service's per-port siblings under one lowest-port
/// representative (they share hosts + `/`) and the request path swaps in the
/// sibling matching the connection's captured original-destination port
/// (`SO_ORIGINAL_DST`), failing closed when the dialed port cannot be
/// determined for a multi-port service — see
/// `HostRouteTable::select_mesh_outbound_port_route`. Proxies carry
/// [`MESH_OUTBOUND_PROXY_ID_PREFIX`] so the request path keeps them off the
/// inbound listener (direction scoping); they yield to explicit operator proxies
/// on overlapping hosts. `targetPort` is honored, mirroring the inbound
/// materializer.
fn materialize_mesh_outbound_proxies(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    let transport = match runtime.topology {
        MeshTopology::Ambient => MeshEgressTransport::Hbone,
        MeshTopology::Sidecar => MeshEgressTransport::SidecarMtls,
        // Gateway topologies (east-west / egress / waypoints) have their own
        // materializers and no plaintext outbound capture listener.
        _ => return,
    };
    let now = chrono::Utc::now();
    // Exclude remote-cluster endpoints: direct outbound HBONE targets a
    // destination service's LOCAL-cluster pods (remote clusters are reached via
    // the east-west gateway, not a per-pod HBONE tunnel). Local workloads are
    // `None` or `Some(local_cluster)`; remote ones carry a different cluster.
    let local_cluster = mesh_slice
        .multi_cluster
        .as_ref()
        .and_then(|mc| mc.local_cluster.as_deref());
    let mut materialized = 0usize;
    for service in &mesh_slice.services {
        // HTTP-family routability is read from the SERVICE port protocol
        // (Kubernetes container ports carry only the transport protocol).
        // Multi-port services materialize one route + upstream PER HTTP-family
        // port: the route table holds one lowest-port representative per
        // service (host tiers are (host, path)-keyed) and the request path
        // swaps in the sibling matching the connection's captured
        // original-destination port (`SO_ORIGINAL_DST`), failing closed when
        // the dialed port cannot be determined. Per-port upstreams keep LB
        // counters, hash rings, passive health, and pool keys isolated per
        // app port. Shared predicate with the router grouping / uniqueness
        // exemption (`mesh_outbound_service_groups`) so they cannot drift.
        let http_ports = service_http_family_ports(service);
        // Sidecar destination INBOUND multi-port still fails closed (inbound
        // :15006 dials are direct, never NATed — disambiguation by the
        // preserved Host port is a later stage), so per-port Sidecar egress
        // would dial the peer only to 404 there. Keep Sidecar multi-port
        // fail-closed AT THE SOURCE until inbound disambiguation lands;
        // Ambient is end-to-end complete (its inbound is the transparent
        // HBONE relay dialing the CONNECT authority's app port).
        if transport == MeshEgressTransport::SidecarMtls && http_ports.len() > 1 {
            warn!(
                service = %service.name,
                namespace = %service.namespace,
                http_ports = http_ports.len(),
                "In-mesh service exposes multiple HTTP-family ports; Sidecar egress stays \
                 fail-closed until the destination sidecar's inbound port disambiguation lands \
                 (the peer's inbound materializer still skips multi-port local services). \
                 Skipping outbound materialization for this service; define an explicit proxy \
                 to route a specific port."
            );
            continue;
        }
        for service_port in &http_ports {
            let protocol = service
                .protocol_overrides
                .get(&service_port.port)
                .copied()
                .unwrap_or(service_port.protocol);
            let targets = build_outbound_mesh_targets(
                transport,
                runtime,
                service,
                service_port,
                protocol,
                &mesh_slice.workloads,
                local_cluster,
            );
            if targets.is_empty() {
                debug!(
                    service = %service.name,
                    namespace = %service.namespace,
                    service_port = service_port.port,
                    "Skipping outbound mesh service port with no reachable local-cluster workload targets"
                );
                continue;
            }
            let upstream_id =
                mesh_outbound_upstream_id(&service.namespace, &service.name, service_port.port);
            let proxy = mesh_outbound_route_proxy(
                &mesh_outbound_proxy_id(&service.namespace, &service.name, service_port.port),
                mesh_service_host_variants(
                    &service.name,
                    &service.namespace,
                    &runtime.cluster_domain,
                ),
                &service.namespace,
                &upstream_id,
                now,
            );
            // Yield to any existing proxy already routing this host at an
            // overlapping path. That covers explicit operator proxies (the
            // operator's routing wins) AND — for Sidecar — the local workload's own
            // materialized INBOUND loopback route (materialized before this pass):
            // the route table holds one proxy per host+path, so the local service's
            // host must keep its inbound route rather than be re-tunnelled out to
            // the mesh. Sibling OUTBOUND routes carry distinct service hosts (or are
            // this service's own per-port siblings, grouped by the router) and
            // are skipped only for re-materialization idempotency. Stream proxies
            // route by `listen_port` and are skipped.
            if config.proxies.iter().any(|p| {
                if p.id == proxy.id
                    || p.dispatch_kind.is_stream()
                    || is_mesh_outbound_route_id(&p.id)
                {
                    return false;
                }
                let shadows_or_collides = p.listen_path == proxy.listen_path
                    || p.listen_path.is_none()
                    || p.listen_path
                        .as_deref()
                        .is_some_and(|lp| lp.starts_with('~'));
                shadows_or_collides && crate::config::types::hosts_overlap(&p.hosts, &proxy.hosts)
            }) {
                debug!(
                    proxy_id = %proxy.id,
                    "Skipping outbound route materialization; an existing operator proxy already routes this host/path"
                );
                continue;
            }
            // Name the upstream with the service FQDN (not the internal id) so a
            // DestinationRule keyed on the service host matches it
            // (`destination_rule_matches_upstream` matches by target host / upstream
            // NAME / id, and the targets are pod IPs) — otherwise no DR traffic policy
            // would apply to outbound HBONE routes (top-level connectTimeout / LB /
            // outlier, plus per-port `portLevelSettings`, which `apply_destination_rules`
            // re-keys onto the dial port via `mesh_outbound_upstream_port_remap`).
            let service_fqdn = format!(
                "{}.{}.svc.{}",
                service.name,
                service.namespace,
                runtime.cluster_domain.trim_matches('.')
            );
            let upstream = mesh_outbound_route_upstream(
                &upstream_id,
                &service.namespace,
                &service_fqdn,
                targets,
                now,
            );
            if let Some(existing) = config.upstreams.iter_mut().find(|u| u.id == upstream.id) {
                *existing = upstream;
            } else {
                config.upstreams.push(upstream);
            }
            if let Some(existing) = config.proxies.iter_mut().find(|p| p.id == proxy.id) {
                *existing = proxy;
            } else {
                config.proxies.push(proxy);
            }
            materialized += 1;
        }
    }

    if materialized > 0 {
        info!(
            outbound_proxies = materialized,
            transport = match transport {
                MeshEgressTransport::Hbone => "hbone",
                MeshEgressTransport::SidecarMtls => "mtls",
            },
            "Materialized mesh outbound egress routes to in-mesh services"
        );
    }
}

/// Build transport-tagged upstream targets for an in-mesh service's workloads,
/// for outbound (`:15001`-capture) egress materialization. Matches workloads
/// by `WorkloadRef` SPIFFE (one-to-one by index so replicas sharing a SPIFFE id
/// still produce distinct targets, with remote-cluster endpoints filtered out),
/// tags each target for the topology's transport via the shared
/// `service_discovery::mesh` tag builders (HBONE for Ambient, SVID-mTLS for
/// Sidecar — each carrying the destination identity the handshake pins), and
/// sets `UpstreamTarget.port` to the app (container) port the service port
/// forwards to (the HBONE CONNECT authority port / DR `port_overrides` key),
/// not the service port. The transport's own DIAL port (15008 / 15006, or the
/// operator's `FERRUM_MESH_EGRESS_*_PORT` override stamped as a tag) is
/// resolved by the pools at dispatch time.
fn build_outbound_mesh_targets(
    transport: MeshEgressTransport,
    runtime: &MeshRuntimeConfig,
    service: &crate::modes::mesh::config::MeshService,
    service_port: &crate::modes::mesh::config::ServicePort,
    protocol: AppProtocol,
    workloads: &[crate::modes::mesh::config::Workload],
    local_cluster: Option<&str>,
) -> Vec<UpstreamTarget> {
    let mut targets = Vec::new();
    for workload in matched_local_service_workloads(service, workloads, local_cluster) {
        // App (container) port the request is for. A DECLARED `targetPort` is
        // authoritative: resolve it, or SKIP this target (fail closed) rather
        // than fall back to the service port — an unresolved named targetPort
        // (rollout skew / typo) must not dial the wrong port. Only an ABSENT
        // targetPort falls back to the service port.
        let app_port = match service_port.target_port.as_ref() {
            Some(_) => {
                match resolve_target_port(service_port.target_port.as_ref(), &workload.ports) {
                    Some(p) if p != 0 => p,
                    _ => continue,
                }
            }
            None => service_port.port,
        };
        if app_port == 0 {
            continue;
        }

        let mut tags = match transport {
            MeshEgressTransport::Hbone => crate::service_discovery::mesh::mesh_hbone_target_tags(
                service,
                workload,
                protocol,
                service_port.name.as_deref(),
            ),
            MeshEgressTransport::SidecarMtls => {
                crate::service_discovery::mesh::mesh_sidecar_mtls_target_tags(
                    service,
                    workload,
                    protocol,
                    service_port.name.as_deref(),
                )
            }
        };
        // Stamp a non-default egress dial port so heterogeneous meshes (and the
        // two-gateways-on-one-host functional harness) can address peers whose
        // transport listener is not on the Istio-convention port.
        match transport {
            MeshEgressTransport::Hbone => {
                if runtime.egress_hbone_port != hbone::ISTIO_HBONE_PORT {
                    tags.insert(
                        crate::proxy::hbone_pool::HBONE_PORT_TAG.to_string(),
                        runtime.egress_hbone_port.to_string(),
                    );
                }
            }
            MeshEgressTransport::SidecarMtls => {
                if runtime.egress_mtls_port
                    != crate::proxy::mesh_mtls_pool::ISTIO_SIDECAR_INBOUND_PORT
                {
                    tags.insert(
                        crate::proxy::mesh_mtls_pool::MESH_MTLS_PORT_TAG.to_string(),
                        runtime.egress_mtls_port.to_string(),
                    );
                }
            }
        }
        for address in &workload.addresses {
            targets.push(UpstreamTarget {
                host: address.clone(),
                port: app_port,
                weight: 1,
                tags: tags.clone(),
                locality: workload.locality.clone(),
                path: None,
            });
        }
    }

    targets
}

/// An HTTP-family `/` proxy on the outbound capture listener whose `HttpPool`
/// dispatch (from `backend_scheme: Http`) lights up the topology's mesh
/// transport for any `mesh.hbone=true` / `mesh.mtls=true` upstream target. No
/// backend host/port of its own — it dispatches through `upstream_id`.
/// `retry: None` (the streamed request body is not replayable).
/// `preserve_host_header` so the destination sees its own service Host /
/// `:authority`, not a rewritten one.
fn mesh_outbound_route_proxy(
    id: &str,
    hosts: Vec<String>,
    namespace: &str,
    upstream_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("mesh outbound {id}")),
        namespace: namespace.to_string(),
        hosts,
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: Default::default(),
        backend_host: String::new(),
        backend_port: 0,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: true,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// The upstream backing a materialized outbound egress proxy: the service's
/// transport-tagged workload targets with passive health and round-robin LB.
/// Mirrors the east-west service upstream. Top-level DR traffic policy applies
/// (the upstream is FQDN-named so DestinationRules match it), and per-port
/// `portLevelSettings` authored on the service port are re-keyed onto the dial
/// port by [`mesh_outbound_upstream_port_remap`] in `apply_destination_rules`, so
/// a numeric `targetPort != port` service keeps its per-port settings. A *named*
/// `targetPort` stays under the service port — a residual matching the
/// service-discovery / egress-ServiceEntry paths.
fn mesh_outbound_route_upstream(
    upstream_id: &str,
    namespace: &str,
    service_fqdn: &str,
    targets: Vec<UpstreamTarget>,
    now: chrono::DateTime<chrono::Utc>,
) -> Upstream {
    Upstream {
        id: upstream_id.to_string(),
        // DR-matchable service host (see the materializer call site).
        name: Some(service_fqdn.to_string()),
        namespace: namespace.to_string(),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: Some(HealthCheckConfig {
            active: None,
            passive: Some(PassiveHealthCheck::default()),
        }),
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

// ── DestinationRule application ────────────────────────────────────────

/// Apply DestinationRule traffic policies onto matching upstreams.
///
/// For each DestinationRule, we find upstreams whose targets match the DR
/// host and apply:
/// - `connectionPool.tcp.connectTimeout` onto proxies referencing the upstream
/// - `outlierDetection` onto the upstream's passive health check
/// - `loadBalancer` onto the upstream's algorithm
/// - `subsets` as `SubsetDefinition` entries on the upstream
///
/// Multiple DRs targeting the same upstream are applied in a deterministic
/// order — sorted by `(namespace, name)` — so the last-writer-wins outcome
/// is reproducible across CP restarts and DP subscribers.
/// Resolve the in-mesh `MeshService` a service-discovery upstream routes to, for
/// re-keying targetPort-remapped port-level policy (round-12 F2). A mesh-provider
/// service-discovery upstream names the service in its config; the discoverer
/// resolves its workload-address targets to the Service `targetPort` at runtime
/// (`service_discovery::mesh`), so a DestinationRule `portLevelSettings` entry
/// keyed on the Service port must be re-keyed to that dial port. Returns `None`
/// for non-mesh-discovery upstreams.
fn mesh_upstream_service<'a>(
    upstream: &Upstream,
    mesh_slice: &'a MeshSlice,
) -> Option<&'a crate::modes::mesh::config::MeshService> {
    let mesh_sd = upstream.service_discovery.as_ref()?.mesh.as_ref()?;
    let namespace = mesh_sd.namespace.as_deref().unwrap_or(&upstream.namespace);
    mesh_slice
        .services
        .iter()
        .find(|s| s.name == mesh_sd.service_name && s.namespace == namespace)
}

/// Resolve in-mesh Service service-port→dial-port remaps for a materialized
/// Ambient outbound HBONE upstream (`__mesh-out-upstream-*`).
///
/// Like an egress ServiceEntry upstream, this upstream is static-target: its
/// targets dial the resolved numeric `targetPort` while a DestinationRule
/// `portLevelSettings` entry is authored on the Service port. Dispatch keys port
/// overrides by the dial port, so a P entry must be re-keyed to T or per-port
/// policy (connect timeout / LB / outlier / per-port TLS / maxConnections) is
/// dropped as a phantom port. Only ports whose numeric `targetPort` is an actual
/// dialed target are remapped, so `portLevelSettings` on a non-materialized (e.g.
/// non-HTTP) service port still fails closed as a phantom rather than bloating
/// `port_overrides`. Named `targetPort`s stay under the Service port (a residual
/// matching the service-discovery / egress paths). Empty for any other upstream.
fn mesh_outbound_upstream_port_remap(
    upstream: &Upstream,
    mesh_slice: &MeshSlice,
) -> std::collections::HashMap<u16, u16> {
    let target_ports: std::collections::HashSet<u16> =
        upstream.targets.iter().map(|t| t.port).collect();
    mesh_slice
        .services
        .iter()
        .flat_map(|svc| {
            // Upstreams are per service port; remap only the owning port's
            // DR entry onto its resolved numeric targetPort.
            svc.ports.iter().filter_map(|sp| {
                if upstream.id != mesh_outbound_upstream_id(&svc.namespace, &svc.name, sp.port) {
                    return None;
                }
                match sp.target_port {
                    Some(ServiceTargetPort::Number(t))
                        if t != 0 && t != sp.port && target_ports.contains(&t) =>
                    {
                        Some((sp.port, t))
                    }
                    _ => None,
                }
            })
        })
        .collect()
}

/// Resolve ServiceEntry service-port→dial-port remaps for an egress upstream.
///
/// Egress upstream IDs intentionally stay keyed on the ServiceEntry service port
/// while their targets may dial a numeric `targetPort`. Istio
/// DestinationRule `portLevelSettings[].port.number` is service-port-scoped,
/// but dispatch looks up Ferrum port overrides by the selected
/// `UpstreamTarget.port` dial port. Re-key matching ServiceEntry ports here so
/// per-port TLS/mTLS and pool policy cannot be dropped as a phantom port after
/// targetPort materialization.
fn egress_service_entry_port_remap(
    upstream: &Upstream,
    mesh_slice: &MeshSlice,
) -> std::collections::HashMap<u16, u16> {
    mesh_slice
        .service_entries
        .iter()
        .filter(|entry| entry.location == ServiceEntryLocation::MeshExternal)
        .flat_map(|entry| {
            entry.hosts.iter().flat_map(move |host| {
                entry.ports.iter().filter_map(move |port| {
                    let upstream_id =
                        mesh_egress_upstream_id(&entry.namespace, &entry.name, host, port.port);
                    if upstream.id != upstream_id
                        && upstream.name.as_deref() != Some(upstream_id.as_str())
                    {
                        return None;
                    }

                    match resolve_target_port(port.target_port.as_ref(), &[]) {
                        Some(target_port) if target_port != port.port => {
                            Some((port.port, target_port))
                        }
                        _ => None,
                    }
                })
            })
        })
        .collect()
}

fn apply_destination_rules(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<(), anyhow::Error> {
    let mut sorted_destination_rules: Vec<&MeshDestinationRule> =
        mesh_slice.destination_rules.iter().collect();
    sorted_destination_rules.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    // Owning Service port per materialized per-port outbound upstream
    // (forward-derived from the slice, like `mesh_outbound_service_groups`).
    // A per-port upstream accepts `portLevelSettings` ONLY for its owning
    // Service port: its targets dial the resolved targetPort T, so the
    // generic "entry port is a target port" acceptance below would otherwise
    // let a DR entry authored for a DIFFERENT service port that numerically
    // equals T leak onto this upstream — each sibling upstream must carry
    // exactly its own port's policy.
    let outbound_upstream_owner_port: std::collections::HashMap<String, u16> = mesh_slice
        .services
        .iter()
        .flat_map(|svc| {
            service_http_family_ports(svc)
                .into_iter()
                .map(|sp| {
                    (
                        mesh_outbound_upstream_id(&svc.namespace, &svc.name, sp.port),
                        sp.port,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();

    for dr in sorted_destination_rules {
        let matching_upstream_indices: Vec<usize> = config
            .upstreams
            .iter()
            .enumerate()
            .filter_map(|(idx, upstream)| {
                destination_rule_matches_upstream(dr, upstream).then_some(idx)
            })
            .collect();

        if matching_upstream_indices.is_empty() {
            debug!(
                host = %dr.host,
                rule = %dr.name,
                "DestinationRule has no matching upstream; skipping"
            );
            continue;
        };

        let connect_timeout_ms = dr
            .traffic_policy
            .as_ref()
            .and_then(|tp| tp.connect_timeout_ms);

        for idx in matching_upstream_indices {
            let upstream = &mut config.upstreams[idx];
            if let Some(ref policy) = dr.traffic_policy {
                apply_traffic_policy_to_upstream(upstream, policy, runtime)?;
            }

            // Build a set of ports actually exposed by this upstream's
            // targets. Used to filter phantom DR entries whose port is not
            // served by any backend — misconfigured DRs (typo in port
            // number) would otherwise silently bloat
            // `Upstream.port_overrides`. Upstreams using service discovery
            // resolve target ports at runtime, so we keep all entries when
            // service_discovery is configured.
            let upstream_target_ports: std::collections::HashSet<u16> =
                upstream.targets.iter().map(|t| t.port).collect();
            let has_service_discovery = upstream.service_discovery.is_some();

            // A mesh upstream can dial a numeric targetPort (T) while policy is
            // still authored against the Service/ServiceEntry port (P). Dispatch
            // keys port overrides by the dial port, so a DR `portLevelSettings`
            // entry keyed on P must be re-keyed to T or it never matches the
            // selected target. Map P→T for service-discovery MeshServices and
            // materialized egress ServiceEntries with numeric targetPorts. Named
            // targetPorts are workload/endpoint-specific and stay under P.
            let mesh_port_remap: std::collections::HashMap<u16, u16> = if has_service_discovery {
                mesh_upstream_service(upstream, mesh_slice)
                    .map(|svc| {
                        svc.ports
                            .iter()
                            .filter_map(|sp| match sp.target_port {
                                Some(ServiceTargetPort::Number(t)) if t != 0 && t != sp.port => {
                                    Some((sp.port, t))
                                }
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                egress_service_entry_port_remap(upstream, mesh_slice)
            };
            // Materialized Ambient outbound HBONE upstreams (`__mesh-out-upstream-*`)
            // are static-target: their targets dial the resolved numeric
            // `targetPort` while a DR `portLevelSettings` entry is keyed on the
            // Service port, so re-key P→T here too or the per-port policy is dropped
            // as a phantom port. Rebound (not folded into the if/else above) so it
            // composes with any service-port→dial-port remap derived there.
            let mut mesh_port_remap = mesh_port_remap;
            mesh_port_remap.extend(mesh_outbound_upstream_port_remap(upstream, mesh_slice));

            // Top-level `connectionPool.tcp.{maxConnections,tcpKeepalive}` fan
            // out to every port served by this upstream. Per-port
            // `portLevelSettings` may overwrite either field below. We only
            // expand when there is at least one target port; service-discovery
            // upstreams skip the fan-out because their target ports aren't
            // known at apply time (the per-port loop still applies if the
            // operator explicitly listed `portLevelSettings`).
            if let Some(ref tp) = dr.traffic_policy
                && (tp.max_connections.is_some() || tp.tcp_keepalive.is_some())
                && !has_service_discovery
            {
                for port in &upstream_target_ports {
                    let override_slot = upstream.port_overrides.entry(*port).or_default();
                    if let Some(max_conn) = tp.max_connections {
                        override_slot.max_connections = Some(max_conn);
                    }
                    if let Some(ref keepalive) = tp.tcp_keepalive {
                        override_slot.tcp_keepalive = Some(keepalive.clone());
                    }
                }
            }

            // Top-level `connectionPool.http.*` fans out to every port served
            // by this upstream so a single DR `trafficPolicy.connectionPool`
            // block applies uniformly across the upstream. Per-port
            // `portLevelSettings.connectionPool.http` overrides per-port
            // below. Service-discovery upstreams skip the fan-out because
            // their target ports aren't known at apply time (the per-port loop
            // below still applies if the operator explicitly listed
            // `portLevelSettings`). Mirrors the T1-D fan-out for
            // `connectionPool.tcp.{maxConnections,tcpKeepalive}`.
            if let Some(ref tp) = dr.traffic_policy
                && let Some(ref http) = tp.connection_pool_http
                && !has_service_discovery
            {
                for port in &upstream_target_ports {
                    let override_slot = upstream.port_overrides.entry(*port).or_default();
                    apply_connection_pool_http_to_port_override(override_slot, http);
                }
            }

            // Second pass: per-port traffic policy overrides land on the
            // upstream's `port_overrides` slot. Pool-level dispatch already
            // keys per destination port, so per-port policy naturally scopes
            // to that port's pool entry. The top-level policy is still applied
            // first so per-port acts as an additive override of the same
            // fields.
            //
            // The upstream-level TLS base (this DR's top-level tls, applied
            // above) is captured owned so the per-port `entry()` mutable borrow
            // below doesn't conflict with the immutable `from_upstream` read.
            let upstream_base_tls = BackendTlsConfig::from_upstream(upstream);
            let upstream_id_for_tls = upstream.id.clone();
            for (port, port_policy) in &dr.port_level_settings {
                // The `port_overrides` key this Service-port-scoped entry must
                // land on. A materialized per-port outbound upstream accepts
                // ONLY its owning Service port's entry (re-keyed to the dial
                // port when a numeric targetPort remap exists) — an entry for
                // any other service port belongs to that port's own sibling
                // upstream, even when it numerically equals this upstream's
                // dial port. Otherwise: a mesh service-discovery upstream
                // whose Service remaps the port via a numeric `targetPort` is
                // re-keyed P→T (round-12 F2); a direct target-port match
                // needs no remap; a service-discovery upstream with no remap
                // keeps the entry under the declared port (targets resolve at
                // runtime); anything else is a phantom DR port.
                let store_port = if let Some(owning_port) =
                    outbound_upstream_owner_port.get(&upstream.id)
                {
                    if port != owning_port {
                        debug!(
                            rule = %dr.name,
                            upstream = %upstream.id,
                            port = port,
                            owning_port = owning_port,
                            "DestinationRule portLevelSettings entry belongs to a sibling per-port upstream; skipping here"
                        );
                        continue;
                    }
                    *mesh_port_remap.get(port).unwrap_or(port)
                } else if upstream_target_ports.contains(port) {
                    *port
                } else if let Some(dial) = mesh_port_remap.get(port) {
                    *dial
                } else if has_service_discovery {
                    *port
                } else {
                    warn!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        port = port,
                        "DestinationRule portLevelSettings entry references a port not used by any target; skipping"
                    );
                    continue;
                };
                // Resolve per-port backend TLS over the upstream base, mirroring
                // the per-subset TLS overlay. Computed before the `override_slot`
                // mutable borrow. Fail-closed: an unresolvable per-port TLS
                // (e.g. ISTIO_MUTUAL without SVID material) rejects the slice
                // rather than silently downgrading the port's backend posture.
                let resolved_port_tls = if let Some(ref port_tls) = port_policy.tls {
                    let mut slot = upstream_base_tls.clone();
                    apply_traffic_policy_tls_to_backend_config(
                        &mut slot,
                        port_tls,
                        runtime,
                        &format!("{upstream_id_for_tls}/port-{port}"),
                    )
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "DestinationRule portLevelSettings.tls projection failed for upstream={upstream_id_for_tls} port={port}: {e}"
                        )
                    })?;
                    Some(slot)
                } else {
                    None
                };

                let override_slot = upstream.port_overrides.entry(store_port).or_default();
                apply_traffic_policy_to_port_override(override_slot, port_policy);
                if let Some(slot) = resolved_port_tls {
                    override_slot.tls = Some(slot);
                }
            }

            if !dr.subsets.is_empty() {
                if upstream.subsets.is_some() {
                    debug!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        "DestinationRule subsets overwriting existing upstream.subsets"
                    );
                }
                let subset_defs: Vec<SubsetDefinition> = dr
                    .subsets
                    .iter()
                    .map(|subset| SubsetDefinition {
                        name: subset.name.clone(),
                        labels: subset.labels.clone(),
                        traffic_policy: subset.traffic_policy.as_ref().map(|sp| {
                            // Resolve the subset's outlierDetection into a
                            // PassiveHealthCheck (ejection thresholds) up front,
                            // the same projection the upstream-level path uses.
                            let passive_health_check = sp.outlier_detection.as_ref().map(|od| {
                                let mut passive = PassiveHealthCheck::default();
                                apply_outlier_detection_to_passive(&mut passive, od);
                                passive
                            });
                            SubsetTrafficPolicy {
                                load_balancer_algorithm: mesh_lb_to_ferrum(&sp.load_balancer),
                                tls: sp.tls.clone(),
                                connect_timeout_ms: sp.connect_timeout_ms,
                                passive_health_check,
                            }
                        }),
                    })
                    .collect();
                upstream.subsets = Some(subset_defs);
                // Drop any stale per-subset TLS overlays from a previous DR
                // application of this upstream. The next pass below
                // recomputes overlays for the new subset set against the
                // final upstream-level TLS.
                upstream.resolved_subset_tls.clear();
            }

            // Per-subset `connectionPool.tcp.connectTimeout` overrides the DR
            // top-level connectTimeout for proxies bound to that subset (Istio:
            // a subset trafficPolicy field-overrides the DR top-level for that
            // subset). Captured as owned data so the `upstream` borrow ends
            // before the `config.proxies` loop below.
            // Derive subset connectTimeouts from THIS DR's own subsets, not the
            // accumulated `upstream.subsets` an earlier sorted rule may have
            // populated. Reading the accumulated set would let a stale subset
            // timeout from a previous rule shadow this rule's top-level
            // connectTimeout at the `.or(connect_timeout_ms)` below, breaking
            // deterministic last-writer-wins for a later rule that defines no
            // subsets of its own.
            let subset_connect_timeouts: Vec<(String, u64)> = dr
                .subsets
                .iter()
                .filter_map(|s| {
                    s.traffic_policy
                        .as_ref()
                        .and_then(|tp| tp.connect_timeout_ms)
                        .map(|ms| (s.name.clone(), ms))
                })
                .collect();

            if connect_timeout_ms.is_some() || !subset_connect_timeouts.is_empty() {
                let upstream_id = upstream.id.clone();
                let upstream_namespace = upstream.namespace.clone();
                for proxy in &mut config.proxies {
                    if proxy.upstream_id.as_deref() != Some(upstream_id.as_str())
                        || proxy.namespace != upstream_namespace
                    {
                        continue;
                    }
                    // A subset-bound proxy uses its subset's connectTimeout when
                    // the subset sets one; otherwise the DR top-level applies
                    // (as it does to every proxy referencing this upstream).
                    let effective_ms = proxy
                        .upstream_subset
                        .as_deref()
                        .and_then(|name| {
                            subset_connect_timeouts
                                .iter()
                                .find(|(n, _)| n == name)
                                .map(|(_, ms)| *ms)
                        })
                        .or(connect_timeout_ms);
                    if let Some(timeout_ms) = effective_ms
                        && proxy.backend_connect_timeout_ms != timeout_ms
                    {
                        debug!(
                            proxy = %proxy.id,
                            upstream = %upstream_id,
                            subset = proxy.upstream_subset.as_deref().unwrap_or(""),
                            previous_ms = proxy.backend_connect_timeout_ms,
                            new_ms = timeout_ms,
                            rule = %dr.name,
                            "DestinationRule overriding proxy backend_connect_timeout_ms"
                        );
                        proxy.backend_connect_timeout_ms = timeout_ms;
                    }
                }
            }
        }
    }

    // Final pass: project per-subset `trafficPolicy.tls` overlays onto each
    // upstream's `resolved_subset_tls` map. Runs once after all DRs are
    // applied so subset TLS layers over the FINAL upstream-level TLS rather
    // than whatever value a mid-loop pass would have observed.
    resolve_subset_traffic_policy_tls(config, runtime)?;

    Ok(())
}

/// Compute each upstream's per-subset resolved TLS overlay against the
/// upstream's settled `backend_tls_*` posture. Skips upstreams with no
/// subsets and subsets with no `trafficPolicy.tls`. The result lands on
/// `Upstream.resolved_subset_tls` keyed by subset name; consulted by
/// [`GatewayConfig::resolve_upstream_tls`] for proxies whose
/// `upstream_subset` selects that subset.
///
/// Fail-closed: any subset whose `trafficPolicy.tls` cannot be resolved
/// (e.g., `ISTIO_MUTUAL` requested without SVID material) rejects the entire
/// slice via `Err`, matching [`apply_traffic_policy_tls_to_upstream`]'s
/// upstream-level semantics. Silently degrading to upstream-level TLS would
/// turn an operator-requested mTLS posture into whatever the upstream defaults
/// to (potentially `SIMPLE` with a public CA).
fn resolve_subset_traffic_policy_tls(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
) -> Result<(), anyhow::Error> {
    for upstream in &mut config.upstreams {
        let Some(subsets) = upstream.subsets.as_ref() else {
            // No subsets — make sure any stale map from a previous apply
            // doesn't survive a slice that removed all subsets.
            upstream.resolved_subset_tls.clear();
            continue;
        };
        let upstream_base_tls = BackendTlsConfig::from_upstream(upstream);
        let mut resolved_map: HashMap<String, ResolvedSubsetTrafficPolicy> = HashMap::new();
        for subset in subsets {
            let tp = subset.traffic_policy.as_ref();
            // Per-subset TLS overlay, resolved over the upstream-level TLS.
            let resolved_tls = if let Some(subset_tls) = tp.and_then(|tp| tp.tls.as_ref()) {
                let identity = format!("{}/{}", upstream.id, subset.name);
                let mut slot = upstream_base_tls.clone();
                apply_traffic_policy_tls_to_backend_config(&mut slot, subset_tls, runtime, &identity)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "DestinationRule subset trafficPolicy.tls projection failed for upstream={} subset={}: {}",
                            upstream.id,
                            subset.name,
                            e
                        )
                    })?;
                Some(slot)
            } else {
                None
            };
            // Per-subset passive health (ejection thresholds), already resolved
            // from the subset's outlierDetection in apply_destination_rules.
            let passive = tp.and_then(|tp| tp.passive_health_check.clone());
            if let Some(resolved) = ResolvedSubsetTrafficPolicy::new(resolved_tls, passive) {
                resolved_map.insert(subset.name.clone(), resolved);
            }
        }
        upstream.resolved_subset_tls = resolved_map;
    }
    Ok(())
}

/// Project a `MeshTrafficPolicy` onto a per-port `UpstreamPortOverride` slot.
///
/// Per-port `tls` is intentionally not applied here today because backend TLS
/// posture is stored at upstream scope (`backend_tls_*`), not per-port.
fn apply_traffic_policy_to_port_override(
    slot: &mut UpstreamPortOverride,
    policy: &MeshTrafficPolicy,
) {
    if let Some(timeout_ms) = policy.connect_timeout_ms {
        slot.connect_timeout_ms = Some(timeout_ms);
    }
    if let Some(algorithm) = mesh_lb_to_ferrum(&policy.load_balancer) {
        slot.algorithm = Some(algorithm);
        // Unconditional: clears stale hash keys when switching a port to a non-hash algorithm.
        slot.hash_on = mesh_hash_on_to_ferrum(&policy.load_balancer);
    }
    if let Some(ref od) = policy.outlier_detection {
        let mut passive = slot.passive_health_check.clone().unwrap_or_default();
        apply_outlier_detection_to_passive(&mut passive, od);
        slot.passive_health_check = Some(passive);
    }
    // Per-port localityLbSetting projection. A later matching DR entry with no
    // localityLbSetting clears an earlier value, mirroring the upstream-level
    // semantics in `apply_traffic_policy_to_upstream`.
    slot.locality_lb_setting = policy
        .locality_lb_setting
        .as_ref()
        .map(into_upstream_locality);
    // Per-port `connectionPool.tcp.{maxConnections,tcpKeepalive}`. Per-port
    // overrides win over any top-level fan-out applied above; an unset
    // per-port field leaves the existing slot value (which may have come from
    // the top-level fan-out) in place rather than clearing it. This matches
    // Istio's "per-port settings layer over top-level" semantics for
    // connectionPool fields.
    if let Some(max_conn) = policy.max_connections {
        slot.max_connections = Some(max_conn);
    }
    if let Some(ref keepalive) = policy.tcp_keepalive {
        slot.tcp_keepalive = Some(keepalive.clone());
    }
    // Per-port `connectionPool.http.*`. Per-port overrides win over any
    // top-level fan-out applied earlier; an unset per-port field leaves the
    // existing slot value (which may have come from the top-level fan-out) in
    // place rather than clearing it, matching Istio's "per-port settings
    // layer over top-level" semantics for connectionPool fields.
    if let Some(ref http) = policy.connection_pool_http {
        apply_connection_pool_http_to_port_override(slot, http);
    }
}

/// Project an HTTP connection-pool overlay onto a per-port slot.
///
/// Each field is overlaid independently — `None` leaves the existing slot
/// value untouched so a per-port partial overlay can layer over a top-level
/// fan-out without clearing fields the operator did not respecify.
fn apply_connection_pool_http_to_port_override(
    slot: &mut UpstreamPortOverride,
    http: &crate::modes::mesh::config::MeshConnectionPoolHttp,
) {
    if let Some(max) = http.max_requests_per_connection {
        slot.http_max_requests_per_connection = Some(max);
    }
    if let Some(idle_ms) = http.idle_timeout_ms {
        slot.http_idle_timeout_ms = Some(idle_ms);
    }
    if let Some(max_streams) = http.http2_max_requests {
        slot.h2_max_concurrent_streams = Some(max_streams);
    }
}

/// Project a mesh-derived `MeshLocalityLbSetting` onto its Ferrum
/// `UpstreamLocalityLbSetting` counterpart. Used by both the upstream-level
/// and per-port projection paths so they cannot drift apart.
fn into_upstream_locality(
    locality: &MeshLocalityLbSetting,
) -> crate::config::types::UpstreamLocalityLbSetting {
    crate::config::types::UpstreamLocalityLbSetting {
        enabled: locality.enabled,
        distribute: locality
            .distribute
            .iter()
            .map(|entry| crate::config::types::LocalityDistribute {
                from: entry.from.clone(),
                to: entry.to.clone(),
            })
            .collect(),
        failover: locality
            .failover
            .iter()
            .map(|entry| crate::config::types::LocalityFailover {
                from: entry.from.clone(),
                to: entry.to.clone(),
            })
            .collect(),
    }
}

fn destination_rule_matches_upstream(dr: &MeshDestinationRule, upstream: &Upstream) -> bool {
    upstream
        .targets
        .iter()
        .any(|target| destination_rule_host_matches(&dr.host, &dr.namespace, &target.host))
        || upstream
            .name
            .as_deref()
            .is_some_and(|name| destination_rule_host_matches(&dr.host, &dr.namespace, name))
        || destination_rule_host_matches(&dr.host, &dr.namespace, &upstream.id)
}

fn destination_rule_host_matches(rule_host: &str, namespace: &str, candidate: &str) -> bool {
    let rule_host = rule_host.trim_end_matches('.').to_ascii_lowercase();
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    if candidate == rule_host {
        return true;
    }

    if !rule_host.contains('.') {
        let namespaced = format!("{rule_host}.{namespace}");
        return candidate == namespaced || candidate.starts_with(&format!("{namespaced}.svc."));
    }

    let dot_count = rule_host.bytes().filter(|byte| *byte == b'.').count();
    if dot_count == 1 {
        return candidate.starts_with(&format!("{rule_host}.svc."));
    }
    if rule_host.ends_with(".svc") {
        return candidate.starts_with(&format!("{rule_host}."));
    }

    false
}

/// Apply a `MeshTrafficPolicy` onto a Ferrum `Upstream`.
///
/// When `policy.tls` is `None` the upstream's `backend_tls_*` fields are
/// left untouched and the workload's PeerAuthentication-derived mTLS
/// posture continues to apply. When `policy.tls` is `Some(...)` the DR's
/// TLS settings override the PeerAuthentication defaults via
/// `apply_traffic_policy_tls_to_upstream`.
fn apply_traffic_policy_to_upstream(
    upstream: &mut Upstream,
    policy: &MeshTrafficPolicy,
    runtime: &MeshRuntimeConfig,
) -> Result<(), anyhow::Error> {
    if let Some(algorithm) = mesh_lb_to_ferrum(&policy.load_balancer) {
        upstream.algorithm = algorithm;
    }
    if let Some(hash_on) = mesh_hash_on_to_ferrum(&policy.load_balancer) {
        upstream.hash_on = Some(hash_on);
    }

    // Outlier detection -> passive health check.
    if let Some(ref od) = policy.outlier_detection {
        let passive = upstream
            .health_checks
            .get_or_insert_with(HealthCheckConfig::default)
            .passive
            .get_or_insert_with(PassiveHealthCheck::default);

        apply_outlier_detection_to_passive(passive, od);
    }

    // Backend TLS posture override from DestinationRule.trafficPolicy.tls.
    if let Some(ref tls) = policy.tls {
        apply_traffic_policy_tls_to_upstream(upstream, tls, runtime)?;
    }

    // localityLbSetting projection. The current traffic policy owns this
    // mesh-derived slot, so a later matching DestinationRule with no
    // localityLbSetting clears an earlier value instead of leaving stale
    // distribute/failover state behind.
    upstream.locality_lb_setting = policy
        .locality_lb_setting
        .as_ref()
        .map(into_upstream_locality);

    Ok(())
}

/// Project `MeshTrafficPolicyTls` onto an `Upstream`'s `backend_tls_*`
/// fields. Thin shim over [`apply_traffic_policy_tls_to_backend_config`] that
/// builds a `BackendTlsConfig` view of the upstream's TLS fields, runs the
/// shared overlay, and writes the result back. The DR wins over the
/// PeerAuthentication-derived default for every field it sets.
///
/// See [`apply_traffic_policy_tls_to_backend_config`] for the per-mode mapping
/// (`Disable` / `Simple` / `Mutual` / `IstioMutual`), the
/// `insecure_skip_verify` precedence rules, and SAN/SNI bounding behaviour.
fn apply_traffic_policy_tls_to_upstream(
    upstream: &mut Upstream,
    tls: &MeshTrafficPolicyTls,
    runtime: &MeshRuntimeConfig,
) -> Result<(), anyhow::Error> {
    let mut slot = BackendTlsConfig::from_upstream(upstream);
    apply_traffic_policy_tls_to_backend_config(&mut slot, tls, runtime, &upstream.id)?;
    upstream.backend_tls_client_cert_path = slot.client_cert_path;
    upstream.backend_tls_client_key_path = slot.client_key_path;
    upstream.backend_tls_server_ca_cert_path = slot.server_ca_cert_path;
    upstream.backend_tls_verify_server_cert = slot.verify_server_cert;
    upstream.backend_tls_sni = slot.sni;
    upstream.backend_tls_san_allow_list = slot.san_allow_list;
    Ok(())
}

/// Project `MeshTrafficPolicyTls` onto a `BackendTlsConfig` slot.
///
/// Shared overlay used by both the upstream-level apply
/// ([`apply_traffic_policy_tls_to_upstream`]) and the per-subset apply
/// ([`apply_subset_traffic_policy_tls`]), so subset TLS overrides cannot drift
/// from the upstream-level translation. `identity` is used only for log /
/// error context (the upstream id, or `<upstream>/<subset>`).
///
/// Mapping:
/// - `Disable`: clear all client TLS material and stale SNI / SAN allow-list;
///   leave `verify_server_cert` at its current value (TLS may still originate
///   when the proxy's `backend_scheme` is `https`) unless the operator also
///   asked for `insecure_skip_verify`.
/// - `Simple`: enable server-cert verification; populate CA from
///   `ca_certificates`; clear any stale client cert/key.
/// - `Mutual`: enable server-cert verification; populate CA, client cert,
///   and private key from the DR.
/// - `IstioMutual`: enable server-cert verification; project the workload's
///   X.509-SVID cert/key paths and trust bundle from the mesh runtime onto the
///   slot.
///
/// `insecure_skip_verify=true` always wins: it forces
/// `verify_server_cert=false` regardless of mode.
///
/// SNI (`tls.sni`) and `subject_alt_names` project onto slot fields here. SAN
/// lists are bounded because mesh-projected slots skip admin admission. The
/// SAN-allow-list digest is recomputed at the end so pool keys partition on
/// the current SAN set.
fn apply_traffic_policy_tls_to_backend_config(
    slot: &mut BackendTlsConfig,
    tls: &MeshTrafficPolicyTls,
    runtime: &MeshRuntimeConfig,
    identity: &str,
) -> Result<(), anyhow::Error> {
    match tls.mode {
        MtlsMode::Disable => {
            slot.client_cert_path = None;
            slot.client_key_path = None;
            slot.server_ca_cert_path = None;
            slot.sni = None;
            slot.san_allow_list.clear();
            // When mTLS is explicitly disabled, leave `verify_server_cert`
            // at its current value (TLS may still originate when the
            // proxy's `backend_scheme` is `https`) unless the operator
            // also asked for skip_verify.
        }
        MtlsMode::Simple => {
            slot.client_cert_path = None;
            slot.client_key_path = None;
            slot.server_ca_cert_path = tls.ca_certificates.clone();
        }
        MtlsMode::Mutual => {
            slot.client_cert_path = tls.client_certificate.clone();
            slot.client_key_path = tls.private_key.clone();
            slot.server_ca_cert_path = tls.ca_certificates.clone();
        }
        MtlsMode::IstioMutual => {
            let (Some(cert_path), Some(key_path)) = (
                runtime.workload_svid_cert_path.clone(),
                runtime.workload_svid_key_path.clone(),
            ) else {
                return Err(anyhow::anyhow!(
                    "DestinationRule ISTIO_MUTUAL for '{}' requires FERRUM_GATEWAY_SVID_CERT_PATH and FERRUM_GATEWAY_SVID_KEY_PATH",
                    identity
                ));
            };
            slot.server_ca_cert_path = runtime.workload_svid_trust_bundle_path.clone();
            if runtime.workload_svid_trust_bundle_path.is_none() {
                warn!(
                    identity = %identity,
                    "DestinationRule ISTIO_MUTUAL requested but workload SVID trust bundle path is not configured; clearing any stale CA and falling back to global/default trust"
                );
            }
            slot.client_cert_path = Some(cert_path);
            slot.client_key_path = Some(key_path);
        }
        // PeerAuthentication-side modes are rejected at translate time;
        // an in-memory slice that still carries one is a programming
        // error. Treat as a no-op rather than panic on the cold path.
        MtlsMode::Strict | MtlsMode::Permissive => {
            warn!(
                identity = %identity,
                mode = ?tls.mode,
                "DestinationRule trafficPolicy.tls.mode is a server-side mode and cannot apply to client-side backend TLS; ignoring"
            );
            return Ok(());
        }
    }

    // `verify_server_cert` precedence: explicit `insecureSkipVerify=true`
    // forces false; otherwise SIMPLE/MUTUAL/ISTIO_MUTUAL require verify=true
    // and DISABLE leaves the existing value alone.
    if tls.insecure_skip_verify {
        slot.verify_server_cert = false;
    } else if matches!(
        tls.mode,
        MtlsMode::Simple | MtlsMode::Mutual | MtlsMode::IstioMutual
    ) {
        slot.verify_server_cert = true;
    }

    if tls.mode != MtlsMode::Disable {
        slot.sni = bounded_backend_tls_sni(identity, tls.sni.as_deref());
        slot.san_allow_list = bounded_backend_tls_san_allow_list(identity, &tls.subject_alt_names);
    }

    slot.recompute_san_digest();
    Ok(())
}

fn bounded_backend_tls_sni(identity: &str, sni: Option<&str>) -> Option<String> {
    let sni = sni?;
    match crate::config::types::validate_backend_tls_sni(sni) {
        Ok(()) => Some(sni.to_ascii_lowercase()),
        Err(error) => {
            warn!(
                identity = %identity,
                error = %error,
                "DestinationRule trafficPolicy.tls.sni is invalid for backend TLS; dropping SNI override"
            );
            None
        }
    }
}

fn bounded_backend_tls_san_allow_list(identity: &str, sans: &[String]) -> Vec<String> {
    let mut bounded = Vec::with_capacity(sans.len().min(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES));
    if sans.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
        warn!(
            identity = %identity,
            count = sans.len(),
            max = MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
            "DestinationRule subjectAltNames exceeds backend TLS SAN allow-list limit; dropping extra entries"
        );
    }

    for san in sans.iter().take(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES) {
        if san.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH {
            warn!(
                identity = %identity,
                len = san.len(),
                max = MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
                "DestinationRule subjectAltNames entry exceeds backend TLS SAN allow-list entry limit; dropping entry"
            );
            continue;
        }
        if let Err(error) = crate::config::types::validate_backend_tls_san_allow_list_entry(san) {
            warn!(
                identity = %identity,
                error = %error,
                "DestinationRule subjectAltNames entry is invalid for backend TLS SAN allow-list; dropping entry"
            );
            continue;
        }
        let mut san = san.clone();
        crate::config::types::normalize_backend_tls_san_allow_list_entry(&mut san);
        bounded.push(san);
    }

    bounded
}

/// Convert a mesh LB config to a Ferrum `LoadBalancerAlgorithm`.
fn mesh_lb_to_ferrum(lb: &Option<MeshLoadBalancer>) -> Option<LoadBalancerAlgorithm> {
    match lb {
        Some(MeshLoadBalancer::Simple(simple)) => match simple {
            MeshSimpleLb::RoundRobin => Some(LoadBalancerAlgorithm::RoundRobin),
            MeshSimpleLb::LeastRequest => Some(LoadBalancerAlgorithm::LeastConnections),
            MeshSimpleLb::Random => Some(LoadBalancerAlgorithm::Random),
            // Istio PASSTHROUGH means direct-to-original-IP; Ferrum always routes via upstreams so RoundRobin is the closest approximation.
            MeshSimpleLb::Passthrough => Some(LoadBalancerAlgorithm::RoundRobin),
        },
        Some(MeshLoadBalancer::ConsistentHash(_)) => Some(LoadBalancerAlgorithm::ConsistentHashing),
        None => None,
    }
}

fn mesh_hash_on_to_ferrum(lb: &Option<MeshLoadBalancer>) -> Option<String> {
    let Some(MeshLoadBalancer::ConsistentHash(ch)) = lb else {
        return None;
    };
    if let Some(header) = &ch.http_header_name {
        Some(format!("header:{header}"))
    } else if let Some(cookie) = &ch.http_cookie_name {
        Some(format!("cookie:{cookie}"))
    } else if ch.use_source_ip {
        Some("ip".to_string())
    } else {
        None
    }
}

fn apply_outlier_detection_to_passive(passive: &mut PassiveHealthCheck, od: &MeshOutlierDetection) {
    if let Some(consecutive) = od.consecutive_errors {
        passive.unhealthy_threshold = consecutive;
    }
    if let Some(interval) = od.interval_seconds {
        passive.unhealthy_window_seconds = interval;
    }
    if let Some(ejection) = od.base_ejection_seconds {
        passive.healthy_after_seconds = ejection;
    }
    if let Some(max_pct) = od.max_ejection_percent {
        passive.max_ejection_percent = Some(max_pct);
    }
}

// ── Egress gateway proxy materialization ─────────────────────────────────

/// Materialize HTTP-family proxies and upstreams from external `ServiceEntry`
/// resources when the topology is `EgressGateway`.
///
/// Each external `ServiceEntry` port produces one `Upstream` (targets from
/// endpoints or DNS hosts) and one `Proxy` per host (host-only routing, no
/// `listen_path`). The resulting proxies accept mesh-internal mTLS from
/// sidecars and forward to external backends with optional re-encryption.
fn materialize_egress_gateway_proxies(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    if runtime.topology != MeshTopology::EgressGateway {
        return;
    }

    let service_entries = &mesh_slice.service_entries;
    if service_entries.is_empty() {
        debug!("egress gateway has no service entries to materialize");
        return;
    }

    // Stream-family egress proxies bind their own listen_port. Skip ports that
    // collide with the egress gateway's own mTLS-termination listener
    // (`egress_listen_addr`, default 15090). Without this guard a ServiceEntry
    // for, say, `external.io:15090/TCP` would materialize a stream proxy on
    // the same port the gateway is already binding for HTTP-family egress,
    // causing the stream listener bind to fail at runtime (EADDRINUSE) with
    // no actionable signal to the operator.
    let mut mesh_reserved_ports = std::collections::HashSet::new();
    mesh_reserved_ports.insert(runtime.egress_listen_addr.port());

    let (proxies, upstreams) = build_egress_proxies_and_upstreams(
        service_entries,
        &runtime.namespace,
        &mesh_reserved_ports,
        runtime.egress_stream_enabled,
    );

    if proxies.is_empty() {
        debug!("no external service entries produced egress proxies");
        return;
    }

    info!(
        egress_proxies = proxies.len(),
        egress_upstreams = upstreams.len(),
        "Materializing egress gateway proxies from external ServiceEntries"
    );

    // Merge upstreams: replace existing by ID or append.
    for upstream in upstreams {
        if let Some(existing) = config
            .upstreams
            .iter_mut()
            .find(|candidate| candidate.id == upstream.id)
        {
            *existing = upstream;
        } else {
            config.upstreams.push(upstream);
        }
    }

    // Merge proxies: replace existing by ID or append.
    for proxy in proxies {
        if let Some(existing) = config
            .proxies
            .iter_mut()
            .find(|candidate| candidate.id == proxy.id)
        {
            *existing = proxy;
        } else {
            config.proxies.push(proxy);
        }
    }
}

/// Build proxy + upstream pairs from external `ServiceEntry` resources.
///
/// Only entries with `location == MeshExternal` are materialized. For each
/// qualifying entry, one upstream per port is created (keyed by host + port
/// number). DNS-resolution entries use the ServiceEntry hosts as backend
/// targets; static-resolution entries use the endpoint addresses.
///
/// HTTP-family ports (`http`, `http2`, `grpc`, `tls`) are materialized as
/// host-routed HTTP-family proxies sharing the egress gateway listener
/// (mTLS termination at `egress_listen_addr`, default 15090). Each host
/// admits only one HTTP-family proxy across all ports (host-only routing
/// can't safely disambiguate ports).
///
/// Stream-family ports (`tcp`, `mongo`, `redis`, `mysql`, `postgres`) are
/// materialized as raw L4 stream proxies bound on the ServiceEntry's own
/// port (e.g., `mongo.external.io:27017/TCP` produces a TCP listener on
/// port 27017). Each `listen_port` admits at most one stream proxy; later
/// SEs requesting the same port are skipped with a warning. The materialized
/// stream proxy and the outbound capture flow share the destination port so
/// sidecars dialing the external host are routed to the egress gateway
/// without rewriting the destination port. ServiceEntry ports that collide
/// with `mesh_reserved_ports` (the egress gateway's own listener port) are
/// skipped with a warning instead of materializing — letting them through
/// would fail at listener bind time with EADDRINUSE.
fn build_egress_proxies_and_upstreams(
    service_entries: &[ServiceEntry],
    namespace: &str,
    mesh_reserved_ports: &std::collections::HashSet<u16>,
    egress_stream_enabled: bool,
) -> (Vec<Proxy>, Vec<Upstream>) {
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();
    // HTTP-family materialization is host-keyed because the egress listener
    // shares one port (15090) with host-based routing.
    let mut materialized_http_hosts = std::collections::HashSet::new();
    // Stream-family materialization is port-keyed because each stream proxy
    // owns its own listen_port. Two SEs trying to bind the same port produce
    // a non-fatal skip (the second one warns).
    let mut materialized_stream_ports = std::collections::HashSet::new();
    let now = chrono::Utc::now();

    for entry in service_entries {
        if !service_entry_exported_to_namespace(entry, namespace) {
            continue;
        }

        if entry.location != ServiceEntryLocation::MeshExternal {
            continue;
        }

        if entry.hosts.is_empty() {
            continue;
        }

        for port_spec in &entry.ports {
            let Some(backend_scheme) = egress_backend_scheme(port_spec.protocol) else {
                // Defensive: every AppProtocol variant maps to a concrete
                // scheme today (HTTP-family or stream-family). Future
                // protocol additions that haven't been classified land
                // here and get skipped with a warning instead of panicking.
                warn!(
                    service_entry = %entry.name,
                    namespace = %entry.namespace,
                    port = port_spec.port,
                    protocol = ?port_spec.protocol,
                    "Skipping ServiceEntry port for egress gateway: unknown protocol classification"
                );
                continue;
            };

            if egress_is_stream_protocol(port_spec.protocol) {
                if !egress_stream_enabled {
                    warn!(
                        service_entry = %entry.name,
                        namespace = %entry.namespace,
                        port = port_spec.port,
                        protocol = ?port_spec.protocol,
                        "Skipping stream egress ServiceEntry port: stream egress proxies \
                         bind plaintext listeners without mTLS and mesh_authz cannot \
                         authenticate connections. Set FERRUM_MESH_EGRESS_STREAM_ENABLED=true \
                         to opt in after configuring alternative authentication."
                    );
                    continue;
                }
                build_stream_egress_for_entry(
                    entry,
                    port_spec,
                    backend_scheme,
                    namespace,
                    now,
                    mesh_reserved_ports,
                    &mut materialized_stream_ports,
                    &mut proxies,
                    &mut upstreams,
                );
            } else {
                build_http_egress_for_entry(
                    entry,
                    port_spec,
                    backend_scheme,
                    namespace,
                    now,
                    &mut materialized_http_hosts,
                    &mut proxies,
                    &mut upstreams,
                );
            }
        }
    }

    (proxies, upstreams)
}

/// HTTP-family egress materialization branch. One proxy per host, host-routed
/// off the shared egress listener (15090). Each host admits only the first
/// port we see for it — host-only routing can't disambiguate ports.
#[allow(clippy::too_many_arguments)]
fn build_http_egress_for_entry(
    entry: &ServiceEntry,
    port_spec: &crate::modes::mesh::config::ServicePort,
    backend_scheme: BackendScheme,
    namespace: &str,
    now: chrono::DateTime<chrono::Utc>,
    materialized_http_hosts: &mut std::collections::HashSet<String>,
    proxies: &mut Vec<Proxy>,
    upstreams: &mut Vec<Upstream>,
) {
    let proxy_hosts: Vec<&String> = entry
        .hosts
        .iter()
        .filter(|host| !materialized_http_hosts.contains(*host))
        .collect();
    if proxy_hosts.is_empty() {
        warn!(
            service_entry = %entry.name,
            namespace = %entry.namespace,
            port = port_spec.port,
            "Skipping egress ServiceEntry port because its hosts were already materialized as HTTP-family"
        );
        return;
    }

    // Honor a numeric ServiceEntry `targetPort` for the backend (the proxy/
    // upstream IDs below stay keyed on the service `port`). A numeric targetPort
    // also overrides the per-endpoint named port map for STATIC endpoints, so
    // pass NO port name in that case — otherwise the static path requires each
    // endpoint to carry a matching `ports[name]` entry and ignores the resolved
    // targetPort. A named/absent targetPort keeps the endpoint port map.
    let (backend_port, backend_port_name) =
        match resolve_target_port(port_spec.target_port.as_ref(), &[]) {
            Some(resolved) => (resolved, None),
            None => (port_spec.port, port_spec.name.clone()),
        };
    for host in proxy_hosts {
        let targets = build_egress_upstream_targets(entry, host, backend_port, &backend_port_name);

        if targets.is_empty() {
            debug!(
                service_entry = %entry.name,
                host = %host,
                port = port_spec.port,
                "Skipping egress host with no resolvable targets"
            );
            continue;
        }

        materialized_http_hosts.insert(host.clone());

        let upstream_id =
            mesh_egress_upstream_id(&entry.namespace, &entry.name, host, port_spec.port);

        upstreams.push(build_egress_upstream(&upstream_id, namespace, targets, now));

        let proxy_id = mesh_egress_proxy_id(&entry.namespace, &entry.name, host, port_spec.port);
        let proxy = egress_gateway_proxy(
            &proxy_id,
            host,
            namespace,
            Some(backend_scheme),
            &upstream_id,
            now,
        );
        proxies.push(proxy);
    }
}

/// Stream-family (TCP / UDP) egress materialization branch. One stream proxy
/// per ServiceEntry port, listening on the entry's own port number so that
/// sidecar outbound capture routes traffic to the same destination port the
/// workload was already dialing. The proxy chooses the first host in the
/// entry's `hosts` list as the upstream target identity (DNS resolution
/// flow) or every endpoint address (static resolution flow). Additional
/// hosts on the same entry / port are ignored — a raw L4 listener cannot
/// distinguish hosts (no SNI for plain TCP/UDP), so operators should split
/// multi-host external services into one ServiceEntry per host.
#[allow(clippy::too_many_arguments)]
fn build_stream_egress_for_entry(
    entry: &ServiceEntry,
    port_spec: &crate::modes::mesh::config::ServicePort,
    backend_scheme: BackendScheme,
    namespace: &str,
    now: chrono::DateTime<chrono::Utc>,
    mesh_reserved_ports: &std::collections::HashSet<u16>,
    materialized_stream_ports: &mut std::collections::HashSet<u16>,
    proxies: &mut Vec<Proxy>,
    upstreams: &mut Vec<Upstream>,
) {
    if port_spec.port == 0 {
        warn!(
            service_entry = %entry.name,
            namespace = %entry.namespace,
            protocol = ?port_spec.protocol,
            "Skipping stream egress ServiceEntry port 0: stream proxy listen_port must be >= 1"
        );
        return;
    }

    if mesh_reserved_ports.contains(&port_spec.port) {
        warn!(
            service_entry = %entry.name,
            namespace = %entry.namespace,
            port = port_spec.port,
            protocol = ?port_spec.protocol,
            "Skipping stream egress ServiceEntry port: collides with a mesh gateway listener port \
             (would fail to bind at runtime). Operators should choose a different ServiceEntry \
             port or relocate the egress gateway listener."
        );
        return;
    }

    if materialized_stream_ports.contains(&port_spec.port) {
        warn!(
            service_entry = %entry.name,
            namespace = %entry.namespace,
            port = port_spec.port,
            protocol = ?port_spec.protocol,
            "Skipping stream egress ServiceEntry port: another ServiceEntry already \
             materialized a stream proxy on this listen_port"
        );
        return;
    }

    // Stream-family proxies route by port, not by host, so we materialize at
    // most one proxy per (entry, port) — using the first host as the upstream
    // target identity (DNS) or all endpoints (Static). Multi-host stream
    // entries are not splittable at the L4 listener boundary.
    let representative_host = match entry.hosts.first() {
        Some(host) => host,
        None => {
            // Guarded above by `entry.hosts.is_empty()`; defensive only.
            return;
        }
    };

    // Honor a numeric ServiceEntry `targetPort` for the backend dial port while
    // the listener, proxy/upstream IDs, and port-dedup stay keyed on the service
    // `port`. Mirrors the HTTP egress branch; without it a TCP ServiceEntry like
    // `number: 5432, targetPort: 15432` would bind 5432 but dial 5432. A numeric
    // targetPort also overrides the per-endpoint named port map for STATIC
    // endpoints, so pass NO port name in that case — otherwise
    // `build_egress_upstream_targets` requires each endpoint to carry a matching
    // `ports[name]` entry and ignores the resolved targetPort.
    let (backend_port, backend_port_name) =
        match resolve_target_port(port_spec.target_port.as_ref(), &[]) {
            Some(resolved) => (resolved, None),
            None => (port_spec.port, port_spec.name.clone()),
        };
    let targets =
        build_egress_upstream_targets(entry, representative_host, backend_port, &backend_port_name);

    if targets.is_empty() {
        debug!(
            service_entry = %entry.name,
            host = %representative_host,
            port = port_spec.port,
            protocol = ?port_spec.protocol,
            "Skipping stream egress port with no resolvable targets"
        );
        return;
    }

    materialized_stream_ports.insert(port_spec.port);

    let upstream_id = mesh_egress_upstream_id(
        &entry.namespace,
        &entry.name,
        representative_host,
        port_spec.port,
    );
    upstreams.push(build_egress_upstream(&upstream_id, namespace, targets, now));

    let proxy_id = mesh_egress_proxy_id(
        &entry.namespace,
        &entry.name,
        representative_host,
        port_spec.port,
    );
    let proxy = stream_egress_gateway_proxy(
        &proxy_id,
        representative_host,
        namespace,
        backend_scheme,
        port_spec.port,
        port_spec.protocol,
        &upstream_id,
        now,
    );
    proxies.push(proxy);
}

/// Shared upstream constructor used by both HTTP- and stream-family egress
/// materialization. Keeps the proxy/upstream pair fields in sync — any new
/// upstream field added here flows to both materialization paths.
fn build_egress_upstream(
    upstream_id: &str,
    namespace: &str,
    targets: Vec<UpstreamTarget>,
    now: chrono::DateTime<chrono::Utc>,
) -> Upstream {
    Upstream {
        id: upstream_id.to_string(),
        name: Some(upstream_id.to_string()),
        namespace: namespace.to_string(),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: egress_health_checks(),
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn egress_health_checks() -> Option<HealthCheckConfig> {
    Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck::default()),
    })
}

/// Build upstream targets from a `ServiceEntry`. When the entry uses static
/// resolution with explicit endpoints, those addresses become targets. When
/// endpoints are empty (DNS or None resolution), each host becomes a target.
fn build_egress_upstream_targets(
    entry: &ServiceEntry,
    host: &str,
    port_number: u16,
    port_name: &Option<String>,
) -> Vec<UpstreamTarget> {
    if entry.resolution == Resolution::Static && !entry.endpoints.is_empty() {
        entry
            .endpoints
            .iter()
            .filter_map(|ep| {
                // Named endpoint ports must be present on each endpoint. Falling
                // back to the ServiceEntry port would route to an unrelated
                // service when endpoint port maps are partial.
                let target_port = match port_name.as_ref() {
                    Some(name) => ep.ports.get(name).copied(),
                    None => Some(port_number),
                }?;

                Some(UpstreamTarget {
                    host: ep.address.clone(),
                    port: target_port,
                    weight: 1,
                    tags: ep.labels.clone(),
                    locality: None,
                    path: None,
                })
            })
            .collect()
    } else {
        // DNS or None resolution: keep each host's proxy pinned to that host so
        // SNI/Host expectations cannot be crossed by load balancing.
        vec![UpstreamTarget {
            host: host.to_string(),
            port: port_number,
            weight: 1,
            tags: std::collections::HashMap::new(),
            locality: None,
            path: None,
        }]
    }
}

/// Determine the backend scheme from the ServiceEntry port protocol.
///
/// HTTP-family protocols (`Http`, `Https/Tls`, `Http2`, `Grpc`, `Unknown`) map
/// to `Http` / `Https` so the egress gateway terminates inbound mTLS and
/// re-emits HTTP-family traffic to the external backend. Stream-family
/// protocols (`Tcp`, `Mongo`, `Redis`, `Mysql`, `Postgres`) map to
/// `BackendScheme::Tcp` and are materialized as raw L4 stream proxies via
/// [`build_stream_egress_for_entry`]; protocol-aware mediation
/// (e.g., Mongo / Redis wire decode) is intentionally out of scope and tracked
/// separately as T5-C.
fn egress_backend_scheme(protocol: AppProtocol) -> Option<BackendScheme> {
    match protocol {
        AppProtocol::Tls | AppProtocol::Http2 | AppProtocol::Grpc => Some(BackendScheme::Https),
        AppProtocol::Http | AppProtocol::Unknown => Some(BackendScheme::Http),
        AppProtocol::Tcp
        | AppProtocol::Mongo
        | AppProtocol::Redis
        | AppProtocol::Mysql
        | AppProtocol::Postgres => Some(BackendScheme::Tcp),
    }
}

/// True when the ServiceEntry protocol should materialize a stream-family
/// (TCP / UDP) egress proxy rather than an HTTP-family one. Stream proxies
/// route on `listen_port` rather than `hosts`, so the materializer uses a
/// distinct port-dedup path and binds one listener per ServiceEntry port.
fn egress_is_stream_protocol(protocol: AppProtocol) -> bool {
    matches!(
        protocol,
        AppProtocol::Tcp
            | AppProtocol::Mongo
            | AppProtocol::Redis
            | AppProtocol::Mysql
            | AppProtocol::Postgres
    )
}

/// Pre-interned protocol label used in `Proxy.name` (and consumed by
/// transaction logs / metrics) so the stream egress materialization stays
/// allocation-free per call. The same `&'static str` convention is used
/// by mesh outbound enforcement (T5-B sibling PR) so observability stays
/// consistent across HTTP / stream egress.
fn egress_app_protocol_label(protocol: AppProtocol) -> &'static str {
    match protocol {
        AppProtocol::Http => "http",
        AppProtocol::Http2 => "http2",
        AppProtocol::Grpc => "grpc",
        AppProtocol::Tls => "tls",
        AppProtocol::Tcp => "tcp",
        AppProtocol::Mongo => "mongo",
        AppProtocol::Redis => "redis",
        AppProtocol::Mysql => "mysql",
        AppProtocol::Postgres => "postgres",
        AppProtocol::Unknown => "unknown",
    }
}

/// Construct a single egress gateway proxy. Mirrors `east_west_gateway_proxy`
/// in struct construction style but uses HTTP-family settings (host-only
/// routing, no passthrough; the mesh listener owns frontend mTLS termination.
fn egress_gateway_proxy(
    id: &str,
    host: &str,
    namespace: &str,
    backend_scheme: Option<BackendScheme>,
    upstream_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("mesh egress {host}")),
        namespace: namespace.to_string(),
        hosts: vec![host.to_string()],
        listen_path: None,
        backend_scheme,
        dispatch_kind: Default::default(),
        backend_host: String::new(),
        backend_port: 0,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: true,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// Construct a stream-family (TCP / UDP / TCP+TLS / UDP+DTLS) egress gateway
/// proxy. Unlike `egress_gateway_proxy` (HTTP-family, host-routed off the
/// shared 15090 listener), the stream variant routes by `listen_port`, owns
/// its own listener bound to the ServiceEntry's destination port, and has
/// `hosts: []` / `listen_path: None` per the stream-family proxy contract
/// (CLAUDE.md "Proxy hosts/listen_path/listen_port contract").
///
/// The protocol tag is stamped onto `Proxy.name` for observability (transaction
/// logs surface the proxy name); the wire-level dispatch is identical for all
/// stream variants and uses `BackendScheme::Tcp` (TCP-based protocols) per
/// `egress_backend_scheme`. Protocol-aware mediation (Mongo / Redis wire
/// inspection) is tracked separately as T5-C.
#[allow(clippy::too_many_arguments)]
fn stream_egress_gateway_proxy(
    id: &str,
    representative_host: &str,
    namespace: &str,
    backend_scheme: BackendScheme,
    listen_port: u16,
    protocol: AppProtocol,
    upstream_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    let protocol_label = egress_app_protocol_label(protocol);
    Proxy {
        id: id.to_string(),
        name: Some(format!(
            "mesh egress {protocol_label} {representative_host}:{listen_port}"
        )),
        namespace: namespace.to_string(),
        // Stream-family proxies MUST NOT set `hosts` (route key is
        // `listen_port`). See `validate_stream_proxies()` in
        // `src/config/types.rs`.
        hosts: Vec::new(),
        listen_path: None,
        backend_scheme: Some(backend_scheme),
        dispatch_kind: Default::default(),
        backend_host: String::new(),
        backend_port: 0,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: Some(listen_port),
        // Stream egress proxies own their own per-port plaintext listener
        // (e.g., 27017 for Mongo) and forward to the external backend with
        // `BackendScheme::Tcp`. They are NOT raw SNI passthrough (that's the
        // east-west gateway flow) — passthrough is false so the bytes pass
        // through the regular TCP proxy pipeline (idle timeouts, transaction
        // logging, etc.) rather than `splice(2)` between sockets.
        //
        // `frontend_tls: false` reflects the per-port stream LISTENER being
        // plain TCP. Sidecar traffic still routes to the egress gateway by
        // way of the workload's outbound capture; the inbound mTLS sidecar
        // boundary lives on the egress mTLS-termination listener (15090) for
        // HTTP-family flows, which is a sibling listener — it is not the
        // termination point for this per-port stream listener.
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_egress_proxy_id(namespace: &str, name: &str, host: &str, port: u16) -> String {
    format!(
        "mesh-egress-{}-{}-{}-{port}",
        sanitize_egress_id_part(namespace),
        sanitize_egress_id_part(name),
        sanitize_egress_host_id_part(host)
    )
}

fn mesh_egress_upstream_id(namespace: &str, name: &str, host: &str, port: u16) -> String {
    format!(
        "mesh-egress-up-{}-{}-{}-{port}",
        sanitize_egress_id_part(namespace),
        sanitize_egress_id_part(name),
        sanitize_egress_host_id_part(host)
    )
}

fn sanitize_egress_id_part(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '*' {
            if !sanitized.is_empty() && !sanitized.ends_with('-') {
                sanitized.push('-');
            }
            sanitized.push_str("wildcard");
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            sanitized.push(ch);
        } else if !sanitized.ends_with('-') {
            sanitized.push('-');
        }
    }
    let sanitized = sanitized.trim_matches('-');
    if sanitized.is_empty() {
        "any".to_string()
    } else {
        sanitized.to_string()
    }
}

fn sanitize_egress_host_id_part(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' => push_egress_id_token(&mut sanitized, "wildcard"),
            '.' => push_egress_id_token(&mut sanitized, "dot"),
            '-' => push_egress_id_token(&mut sanitized, "dash"),
            '/' => push_egress_id_token(&mut sanitized, "slash"),
            ch if ch.is_ascii_alphanumeric() || ch == '_' => sanitized.push(ch),
            ch => {
                let token = format!("x{:x}", ch as u32);
                push_egress_id_token(&mut sanitized, &token);
            }
        }
    }
    let sanitized = sanitized.trim_matches('-');
    if sanitized.is_empty() {
        "any".to_string()
    } else {
        sanitized.to_string()
    }
}

fn push_egress_id_token(sanitized: &mut String, token: &str) {
    if !sanitized.is_empty() && !sanitized.ends_with('-') {
        sanitized.push('-');
    }
    sanitized.push_str(token);
    sanitized.push('-');
}

fn inject_mesh_global_plugins(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    ensure_global_plugin(
        config,
        MESH_SPIFFE_IDENTITY_PLUGIN_ID,
        "spiffe_identity",
        serde_json::json!({}),
        &runtime.namespace,
    );
    let trust_domain_aliases: Vec<String> = runtime
        .trust_domain_aliases
        .iter()
        .map(|td| td.as_str().to_string())
        .collect();
    let operator_mesh_authz_config = config
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.scope == PluginScope::Global
                && plugin.plugin_name == "mesh_authz"
                && plugin.id != MESH_AUTHZ_PLUGIN_ID
        })
        .map(|plugin| plugin.config.clone());
    let operator_mesh_authz_present = operator_mesh_authz_config.is_some();
    let operator_mesh_authz_trusted_assertors = operator_mesh_authz_config
        .as_ref()
        .and_then(|cfg| cfg.get("trusted_hbone_assertors").cloned());
    let mut mesh_authz_config = serde_json::json!({
        "mesh_slice": mesh_slice,
        "trust_domain_aliases": trust_domain_aliases,
        "per_pod_policy_scoping": runtime.topology == MeshTopology::NodeWaypoint,
    });
    // Only thread the operator-set assertor list when present; otherwise
    // let mesh_authz fall back to its built-in defaults (ztunnel, waypoint).
    // Passing an empty array would lock baggage rewriting down entirely, so
    // unset and `=` need to remain distinguishable surfaces.
    if !runtime.trusted_hbone_assertors.is_empty() {
        mesh_authz_config["trusted_hbone_assertors"] = serde_json::Value::Array(
            runtime
                .trusted_hbone_assertors
                .iter()
                .map(|raw| serde_json::Value::String(raw.clone()))
                .collect(),
        );
    }
    ensure_global_plugin(
        config,
        MESH_AUTHZ_PLUGIN_ID,
        "mesh_authz",
        mesh_authz_config,
        &runtime.namespace,
    );

    // Outbound registry: inject the `mesh_outbound_registry` plugin when
    // either the slice (CRD path) OR the runtime env var declares
    // REGISTRY_ONLY. Both default to AllowAny (no plugin) so non-mesh
    // and permissive deployments pay zero per-request cost.
    let effective_outbound_policy = mesh_slice
        .outbound_traffic_policy
        .unwrap_or(runtime.outbound_traffic_policy);
    if matches!(
        effective_outbound_policy,
        crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly
    ) {
        let registry = mesh_slice.build_known_destinations(&runtime.cluster_domain);
        let outbound_listen_ports = mesh_outbound_registry_listen_ports(runtime);
        if outbound_listen_ports.is_empty() {
            config
                .plugin_configs
                .retain(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
        } else {
            let plugin_config = serde_json::json!({
                "registry": registry,
                "outbound_listen_ports": outbound_listen_ports,
                "reject_status": runtime.outbound_registry_reject_status,
                "namespace": runtime.namespace.clone(),
            });
            ensure_global_plugin(
                config,
                MESH_OUTBOUND_REGISTRY_PLUGIN_ID,
                "mesh_outbound_registry",
                plugin_config,
                &runtime.namespace,
            );
        }
    } else {
        // Remove any stale instance (e.g., operator flipped policy back).
        config
            .plugin_configs
            .retain(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
    }

    // Merge applicable Telemetry resources (most specific scope wins per section).
    let merged_telemetry = merge_applicable_telemetry(mesh_slice);

    let mut workload_metrics_config = serde_json::json!({
        "node_id": runtime.node_id.clone(),
        "topology": runtime.topology.as_str(),
        "namespace": mesh_slice.namespace.clone(),
        "workload_spiffe_id": mesh_slice.workload_spiffe_id.clone(),
        "labels": mesh_slice.labels.clone(),
        "trust_domain_aliases": trust_domain_aliases,
    });
    // Mirror the EFFECTIVE mesh_authz assertor gate so telemetry source-identity
    // attribution honors HBONE baggage only from the same trusted assertors.
    // If an operator-managed global mesh_authz overrides the mesh-managed
    // instance, copy its `trusted_hbone_assertors` field verbatim (including
    // `[]`); if it omits the field, workload_metrics also omits it so both
    // plugins fall back to their shared defaults. Without an override, thread
    // the runtime/env list exactly as the mesh-managed mesh_authz config does.
    if let Some(value) = operator_mesh_authz_trusted_assertors {
        workload_metrics_config["trusted_hbone_assertors"] = value;
    } else if !operator_mesh_authz_present && !runtime.trusted_hbone_assertors.is_empty() {
        workload_metrics_config["trusted_hbone_assertors"] = serde_json::Value::Array(
            runtime
                .trusted_hbone_assertors
                .iter()
                .map(|raw| serde_json::Value::String(raw.clone()))
                .collect(),
        );
    }
    // Apply ProxyConfig sampling as a baseline. The more granular Telemetry
    // resource below may override on the `sampling_percentage` key.
    if let Some(proxy_cfg) = mesh_slice.resolved_proxy_config()
        && let Some(sampling) = proxy_cfg.tracing_sampling
    {
        workload_metrics_config["sampling_percentage"] = serde_json::json!(sampling);
    }
    // Apply tracing config from Telemetry CRD
    if let Some(tracing) = &merged_telemetry.tracing {
        if let Some(sampling_percentage) = tracing.sampling_percentage {
            workload_metrics_config["sampling_percentage"] = serde_json::json!(sampling_percentage);
        }
        if !tracing.custom_tags.is_empty() {
            workload_metrics_config["custom_tags"] = serde_json::json!(tracing.custom_tags);
        }
        if !tracing.custom_header_tags.is_empty() {
            workload_metrics_config["custom_header_tags"] =
                serde_json::json!(tracing.custom_header_tags);
        }
        if tracing.disable_span_reporting.unwrap_or(false) {
            workload_metrics_config["span_reporting_disabled"] = serde_json::json!(true);
        }
        if !tracing.providers.is_empty() {
            // Keep provider config visible for introspection and propagation even
            // when span_reporting_disabled makes WorkloadMetrics skip exporters.
            workload_metrics_config["tracing_providers"] = serde_json::json!(tracing.providers);
        }
        // GAP-3F: project `Telemetry.tracing[].match.mode` into the plugin's
        // `direction_emit` so a single auto-injected workload_metrics instance
        // can serve both directions. Default (no explicit mode) preserves the
        // pre-GAP-3F SERVER-only emit behaviour.
        if let Some(mode) = tracing.mode {
            workload_metrics_config["direction_emit"] = serde_json::json!({
                "server": mode.emits_server(),
                "client": mode.emits_client(),
            });
        }
    }
    if let Some(metrics) = &merged_telemetry.metrics {
        workload_metrics_config["metrics"] = serde_json::json!(metrics);
    }
    ensure_global_plugin(
        config,
        MESH_WORKLOAD_METRICS_PLUGIN_ID,
        "workload_metrics",
        workload_metrics_config,
        &runtime.namespace,
    );
    inject_mesh_request_auth_plugin(config, runtime, mesh_slice);

    // Build access log config with optional filter from Telemetry CRD.
    // `None` means "access logging is explicitly disabled" — we retain-remove
    // any existing mesh access-log plugin and skip injection, but we MUST NOT
    // short-circuit the rest of inject_mesh_global_plugins (e.g. the bpf_metrics
    // branch below). Earlier versions used `return;` here, which silently
    // skipped bpf_metrics injection/cleanup on NodeWaypoint topology whenever
    // Telemetry CRD disabled access logging.
    //
    // The injected sink is `stdout_logging`: it serializes the same
    // transaction/stream summaries and honors the same `filter` config, and
    // writes through the non-blocking stdout writer rather than the tracing
    // fmt stack. The reserved ID stays `__mesh_access_log` so existing
    // injected plugins are updated in place across upgrades.
    let access_log_config: Option<serde_json::Value> = match &merged_telemetry.access_logging {
        Some(al) if !al.enabled => {
            config
                .plugin_configs
                .retain(|p| p.id != MESH_ACCESS_LOG_PLUGIN_ID);
            None
        }
        Some(al) => Some(match &al.filter {
            Some(filter) => serde_json::json!({ "filter": filter }),
            None => serde_json::json!({}),
        }),
        None => Some(serde_json::json!({})),
    };
    if let Some(cfg) = access_log_config {
        ensure_global_plugin(
            config,
            MESH_ACCESS_LOG_PLUGIN_ID,
            "stdout_logging",
            cfg,
            &runtime.namespace,
        );
    }

    // GAP-SC3: `__mesh_bpf_metrics` exposes BPF SOCK_OPS counters as
    // Prometheus metrics. Auto-inject only on `NodeWaypoint` topology;
    // other topologies don't run the SOCK_OPS BPF program, and emitting
    // always-zero counters from them would mislead operator dashboards.
    // Operators on other topologies can still inject the plugin
    // explicitly; this just controls the default-inject behavior.
    if runtime.topology == MeshTopology::NodeWaypoint {
        ensure_global_plugin(
            config,
            MESH_BPF_METRICS_PLUGIN_ID,
            "__mesh_bpf_metrics",
            serde_json::json!({}),
            &runtime.namespace,
        );
    } else {
        config
            .plugin_configs
            .retain(|p| p.id != MESH_BPF_METRICS_PLUGIN_ID);
    }
}

fn mesh_outbound_registry_listen_ports(runtime: &MeshRuntimeConfig) -> Vec<u16> {
    let mut ports: Vec<u16> = runtime
        .listener_plan()
        .into_iter()
        .filter(|listener| listener.direction == MeshTrafficDirection::Outbound)
        .filter_map(|listener| {
            let port = listener.addr.port();
            (port != 0).then_some(port)
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Refresh the proxy-state mesh outbound enforcement slot from the latest
/// applied slice (T5-B). Called from the slice-apply loop after a slice
/// is accepted by `proxy_state.update_config`. Mirrors the HTTP plugin
/// auto-injection: when the effective policy is `RegistryOnly` AND the
/// runtime owns at least one mesh outbound capture port, the slot is
/// populated with the slice-derived registry; otherwise the slot is
/// cleared so the stream proxies fall through to `Decision::Skip` for
/// every connect.
fn refresh_mesh_outbound_enforcement(
    proxy_state: &ProxyState,
    runtime: &MeshRuntimeConfig,
    slice: &MeshSlice,
) {
    let effective_policy = slice
        .outbound_traffic_policy
        .unwrap_or(runtime.outbound_traffic_policy);
    let next = if matches!(
        effective_policy,
        crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly
    ) {
        let ports = mesh_outbound_registry_listen_ports(runtime);
        crate::modes::mesh::outbound_enforcement::MeshOutboundEnforcement::from_slice(
            slice,
            &runtime.cluster_domain,
            runtime.namespace.clone(),
            ports,
        )
        .map(Arc::new)
    } else {
        None
    };
    proxy_state.mesh_outbound_enforcement.store(Arc::new(next));
}

/// Merge applicable `MeshTelemetryResource` entries by scope specificity.
///
/// More specific scopes (WorkloadSelector > Namespace > MeshWide) override
/// less specific ones per config section (tracing, metrics, access_logging
/// independently). Within the same scope level, later resources win.
fn merge_applicable_telemetry(mesh_slice: &MeshSlice) -> MeshTelemetryConfig {
    use crate::modes::mesh::config::scope_applies_to_workload;

    let mut applicable: Vec<(u8, &str, &str, &MeshTelemetryConfig)> = mesh_slice
        .telemetry_resources
        .iter()
        .filter(|t| scope_applies_to_workload(&t.scope, &mesh_slice.namespace, &mesh_slice.labels))
        .map(|t| {
            let specificity = match &t.scope {
                PolicyScope::MeshWide => 0,
                PolicyScope::Namespace { .. } => 1,
                PolicyScope::WorkloadSelector { .. } => 2,
            };
            (
                specificity,
                t.namespace.as_str(),
                t.name.as_str(),
                &t.config,
            )
        })
        .collect();

    // Sort by specificity ascending so more-specific overwrites less-specific.
    // Namespace/name tie-breaks make same-specificity merges deterministic
    // across informer delivery orders.
    applicable.sort_by(|left, right| (left.0, left.1, left.2).cmp(&(right.0, right.1, right.2)));

    let mut merged = MeshTelemetryConfig::default();
    for (_, _, _, config) in &applicable {
        if let Some(tracing) = &config.tracing {
            merge_tracing_config(&mut merged.tracing, tracing);
        }
        if config.metrics.is_some() {
            merged.metrics.clone_from(&config.metrics);
        }
        if config.access_logging.is_some() {
            merged.access_logging.clone_from(&config.access_logging);
        }
    }
    merged
}

fn merge_tracing_config(
    merged: &mut Option<crate::modes::mesh::config::MeshTracingConfig>,
    next: &crate::modes::mesh::config::MeshTracingConfig,
) {
    let current = merged.get_or_insert_with(|| crate::modes::mesh::config::MeshTracingConfig {
        mode: None,
        sampling_percentage: None,
        disable_span_reporting: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: Vec::new(),
    });

    if next.mode.is_some() {
        current.mode = next.mode;
    }
    if next.sampling_percentage.is_some() {
        current.sampling_percentage = next.sampling_percentage;
    }
    if next.disable_span_reporting.is_some() {
        current.disable_span_reporting = next.disable_span_reporting;
    }
    if !next.custom_tags.is_empty() {
        current.custom_tags.clone_from(&next.custom_tags);
    }
    if !next.custom_header_tags.is_empty() {
        current
            .custom_header_tags
            .clone_from(&next.custom_header_tags);
    }
    if !next.providers.is_empty() {
        current.providers.clone_from(&next.providers);
    }
}

/// Inject a `jwks_auth` global plugin when the mesh slice carries applicable
/// `MeshRequestAuthentication` resources with JWT rules.
///
/// Istio semantics: RequestAuthentication is **permissive** — it declares
/// which JWTs are *valid*, not which are *required*. A request with no JWT
/// passes through. An invalid JWT is rejected. Enforcement (requiring a
/// JWT) comes from AuthorizationPolicy. So the plugin is configured with
/// `anonymous_on_missing_token: true`.
fn inject_mesh_request_auth_plugin(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    use crate::modes::mesh::config::scope_applies_to_workload;

    let applicable: Vec<&MeshRequestAuthentication> = mesh_slice
        .request_authentications
        .iter()
        .filter(|ra| {
            scope_applies_to_workload(&ra.scope, &mesh_slice.namespace, &mesh_slice.labels)
        })
        .collect();

    if applicable.is_empty() {
        // No applicable RequestAuthentication — remove any previously injected
        // mesh request auth plugin so it doesn't persist across config updates.
        config
            .plugin_configs
            .retain(|plugin| plugin.id != MESH_REQUEST_AUTH_PLUGIN_ID);
        return;
    }

    let mut providers = Vec::new();
    for ra in &applicable {
        for rule in &ra.jwt_rules {
            if let Some(provider) = build_jwks_provider_config(rule) {
                providers.push(provider);
            }
        }
    }

    if providers.is_empty() {
        config
            .plugin_configs
            .retain(|plugin| plugin.id != MESH_REQUEST_AUTH_PLUGIN_ID);
        return;
    }

    // jwks_auth already passes through requests with no token
    // (ExtractedCredential::Missing -> PluginResult::Continue), which matches
    // Istio's permissive RequestAuthentication semantics. No extra flag needed.
    //
    // `require_exp` defaults to the secure posture (true): tokens that omit
    // `exp` are rejected so they cannot live forever, satisfying the
    // "validate_exp = true" invariant. Some Istio issuers legitimately omit
    // `exp`, so operators can relax this with
    // `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=false`. Expiry *validation* stays
    // on regardless — a present-but-expired `exp` is always rejected.
    let jwks_config = serde_json::json!({
        "providers": providers,
        "require_exp": runtime.request_auth_require_exp,
        "emit_mesh_request_principal_metadata": true,
    });

    ensure_global_plugin(
        config,
        MESH_REQUEST_AUTH_PLUGIN_ID,
        "jwks_auth",
        jwks_config,
        &runtime.namespace,
    );
}

/// Build a single `jwks_auth` provider configuration from a [`MeshJwtRule`].
fn build_jwks_provider_config(rule: &MeshJwtRule) -> Option<serde_json::Value> {
    let mut provider = serde_json::json!({
        "issuer": rule.issuer,
        "forward_original_token": rule.forward_original_token,
    });

    if let Some(uri) = &rule.jwks_uri {
        provider["jwks_uri"] = serde_json::json!(uri);
    } else if let Some(jwks) = &rule.jwks {
        provider["jwks"] = serde_json::json!(jwks);
    } else {
        warn!(
            issuer = %rule.issuer,
            "Skipping MeshRequestAuthentication JWT rule with no jwks_uri or jwks"
        );
        return None;
    }

    if !rule.audiences.is_empty() {
        provider["audiences"] = serde_json::json!(rule.audiences);
    }

    if !rule.from_headers.is_empty() {
        provider["from_headers"] = serde_json::json!(rule.from_headers);
    }

    if !rule.from_params.is_empty() {
        provider["from_params"] = serde_json::json!(rule.from_params);
    }

    Some(provider)
}

fn ensure_global_plugin(
    config: &mut GatewayConfig,
    id: &str,
    plugin_name: &str,
    plugin_config: serde_json::Value,
    namespace: &str,
) {
    let now = chrono::Utc::now();
    let mesh_plugin = PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config: plugin_config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    if let Some(existing) = config
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin.id == id)
    {
        *existing = mesh_plugin;
    } else if config
        .plugin_configs
        .iter()
        .any(|plugin| plugin.scope == PluginScope::Global && plugin.plugin_name == plugin_name)
    {
        // A user-managed global plugin of the same type is an explicit
        // operator override. Reserved mesh-managed IDs still update above.
    } else {
        config.plugin_configs.push(mesh_plugin);
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let runtime = MeshRuntimeConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!("invalid mesh runtime configuration: {e}"))?;
    ensure_runtime_config_protocol_supported(&runtime)?;

    info!(
        node_id = %runtime.node_id,
        namespace = %runtime.namespace,
        topology = runtime.topology.as_str(),
        config_protocol = runtime.config_protocol.as_str(),
        inbound = %runtime.inbound_listen_addr,
        outbound = %runtime.outbound_listen_addr,
        hbone = %runtime.hbone_listen_addr,
        east_west_listen_port = runtime.east_west_listen_port,
        egress = %runtime.egress_listen_addr,
        cp_urls = runtime.cp_urls.len(),
        "Mesh mode starting"
    );

    // Configure the process-singleton policy-deny recorder before anything can
    // record into it. This is idempotent and a no-op on subsequent calls
    // (e.g., a restart-without-fork test harness) so we never wipe history
    // mid-process.
    crate::modes::mesh::policy_deny_log::configure_global_capacity(
        env_config.mesh_policy_deny_log_capacity,
    );

    let mesh_state = MeshRuntimeState::new();

    let mut background_handles = Vec::new();
    if runtime.config_protocol == MeshConfigProtocol::File {
        // Localized file source: no control plane, so no CP/DP JWT secret and
        // no DP gRPC TLS machinery. The initial load is synchronous and
        // fail-closed — an unreadable or invalid mesh document refuses
        // startup, matching file-mode validation semantics. Subsequent SIGHUP
        // reloads keep the last good slice on error.
        let file_path = runtime.file_config_path.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "FERRUM_MESH_FILE_CONFIG_PATH is required when FERRUM_MESH_CONFIG_PROTOCOL=file"
            )
        })?;
        let initial_slice = config_consumer::file_source::load_mesh_slice_from_file(
            std::path::Path::new(&file_path),
            runtime.mesh_slice_request(),
        )
        .with_context(|| format!("failed to load localized mesh config from '{file_path}'"))?;
        // Fail-closed beyond mesh-field validity: run the full slice→config
        // preparation (plugin injection, materialization, DestinationRule
        // projection — which can reject e.g. unloadable ISTIO_MUTUAL TLS
        // material) before installing the slice. The CP consumers tolerate a
        // rejected initial slice by waiting for the CP to push a fix; the
        // file source has no pusher, so a slice the runtime would reject must
        // refuse startup instead of hanging in the initial-config wait.
        gateway_config_from_mesh_slice(&initial_slice, &runtime, None, None).with_context(
            || format!("localized mesh config '{file_path}' failed runtime preparation"),
        )?;
        let initial_version = initial_slice.version.clone();
        mesh_state.install_slice(initial_slice);
        let handle = tokio::spawn(
            config_consumer::file_source::start_mesh_file_source_with_shutdown(
                file_path.clone(),
                runtime.mesh_slice_request(),
                mesh_state.clone(),
                shutdown_tx.subscribe(),
            ),
        );
        background_handles.push(handle);
        info!(
            node_id = %runtime.node_id,
            namespace = %runtime.namespace,
            file_path = %file_path,
            mesh_slice_version = %initial_version,
            "Mesh mode initialized localized file config source (SIGHUP reloads)"
        );
    } else {
        let jwt_secret = GrpcJwtSecret::with_issuer(
            env_config.cp_dp_grpc_jwt_secret.clone().ok_or_else(|| {
                anyhow::anyhow!("FERRUM_CP_DP_GRPC_JWT_SECRET is required in mesh mode")
            })?,
            env_config.cp_dp_grpc_jwt_issuer.clone(),
        );
        let grpc_tls = build_dp_grpc_tls_config(&env_config, &runtime.cp_urls, "Mesh")?;
        let mesh_grpc_tls_reload_handle =
            crate::modes::grpc_tls_reload::start_dp_grpc_tls_reload_task(
                Arc::new(env_config.clone()),
                Arc::new(runtime.cp_urls.clone()),
                "Mesh",
                Some(shutdown_tx.subscribe()),
            );
        let grpc_tls_reload = mesh_grpc_tls_reload_handle.map(|handle| {
            let reload = DpGrpcTlsReload {
                env_config: Arc::new(env_config.clone()),
                label: "Mesh",
                revision_rx: handle.revision_rx,
            };
            background_handles.push(handle.watcher_handle);
            reload
        });

        if runtime.config_protocol == MeshConfigProtocol::Native {
            let client_config = runtime.native_client_config();
            let request = client_config.subscribe_request(crate::FERRUM_VERSION);
            let cp_urls = runtime.cp_urls.clone();
            let state = mesh_state.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(
                config_consumer::native_client::start_native_mesh_client_with_shutdown(
                    cp_urls,
                    jwt_secret.clone(),
                    client_config,
                    state,
                    shutdown_rx,
                    grpc_tls.clone(),
                    grpc_tls_reload,
                ),
            );
            background_handles.push(handle);
            info!(
                node_id = %request.node_id,
                namespace = %request.namespace,
                cp_urls = runtime.cp_urls.len(),
                has_first_slice = mesh_state.has_first_slice(),
                "Mesh mode initialized native MeshSubscribe consumer"
            );
        } else {
            let xds_config = runtime.xds_client_config();
            let state = mesh_state.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(config_consumer::xds_client::start_xds_client_with_shutdown(
                jwt_secret.clone(),
                xds_config,
                state,
                shutdown_rx,
                grpc_tls.clone(),
                grpc_tls_reload,
            ));
            background_handles.push(handle);
            info!(
                node_id = %runtime.node_id,
                namespace = %runtime.namespace,
                cp_urls = runtime.cp_urls.len(),
                has_first_slice = mesh_state.has_first_slice(),
                "Mesh mode initialized xDS ADS consumer"
            );
        }
    }
    let (bootstrap_config, initial_applied_mesh_slice) =
        wait_for_initial_mesh_config(&mesh_state, &runtime, shutdown_tx.subscribe())
            .await
            .context("mesh runtime stopped before receiving a valid initial mesh slice")?;
    info!(
        mesh_global_plugins = bootstrap_config.plugin_configs.len(),
        mesh_slice_version = %initial_applied_mesh_slice.version,
        "Mesh global plugin chain prepared from initial mesh slice"
    );

    serve_mesh_runtime(
        env_config,
        runtime,
        bootstrap_config,
        shutdown_tx,
        mesh_state,
        Some(initial_applied_mesh_slice),
        background_handles,
    )
    .await
}

fn ensure_runtime_config_protocol_supported(
    runtime: &MeshRuntimeConfig,
) -> Result<(), anyhow::Error> {
    match runtime.config_protocol {
        MeshConfigProtocol::Native | MeshConfigProtocol::Xds | MeshConfigProtocol::File => Ok(()),
    }
}

async fn serve_mesh_runtime(
    env_config: EnvConfig,
    runtime: MeshRuntimeConfig,
    config: GatewayConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    mesh_state: MeshRuntimeState,
    initial_applied_mesh_slice: Option<Arc<MeshSlice>>,
    mut mesh_background_handles: Vec<JoinHandle<()>>,
) -> Result<(), anyhow::Error> {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        ttl_override_seconds: env_config.dns_ttl_override,
        min_ttl_seconds: env_config.dns_min_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
        warmup_concurrency: env_config.dns_warmup_concurrency,
        slow_threshold_ms: env_config.dns_slow_threshold_ms,
        refresh_threshold_percent: env_config.dns_refresh_threshold_percent,
        failed_retry_interval_seconds: env_config.dns_failed_retry_interval,
        try_tcp_on_error: env_config.dns_try_tcp_on_error,
        num_concurrent_reqs: env_config.dns_num_concurrent_reqs,
        max_active_requests: env_config.dns_max_active_requests,
        max_concurrent_refreshes: env_config.dns_max_concurrent_refreshes,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
        shard_amount: env_config.pool_shard_amount,
    });

    let mut hostnames: Vec<_> = config
        .proxies
        .iter()
        .map(|proxy| {
            (
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
            )
        })
        .collect();
    for upstream in &config.upstreams {
        for target in &upstream.targets {
            hostnames.push((target.host.clone(), None, None));
        }
    }

    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    // GAP-3D: on node-waypoint topology, create the SOCK_OPS metrics
    // state up front so plugin construction inside `ProxyState::new`
    // picks it up via PluginHttpClient and the spawned ringbuf consumer
    // updates the same Arc.
    let bpf_metrics_state = if runtime.topology == MeshTopology::NodeWaypoint {
        Some(crate::ebpf::bpf_metrics::BpfMetricsState::new())
    } else {
        None
    };
    let (proxy_state, health_check_handles) = ProxyState::new_with_bpf_metrics(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
        Some(shutdown_tx.subscribe()),
        bpf_metrics_state.clone(),
    )?;
    let proxy_state = if runtime.topology == MeshTopology::NodeWaypoint {
        info!("Node-waypoint identity resolver enabled; unknown socket cookies fail closed");
        let resolver = Arc::new(node_waypoint::NodeWaypointIdentityResolver::new(
            env_config.pool_shard_amount,
        ));
        if let Some(initial_slice) = initial_applied_mesh_slice.as_ref() {
            let snapshot =
                resolver.build_policy_scope_snapshot_from_workloads(&initial_slice.workloads);
            resolver.install_policy_scope_snapshot(snapshot);
        }
        if let Some(handle) = node_waypoint::spawn_cgroup_sweep_task(
            resolver.clone(),
            env_config.mesh_node_waypoint_cgroup_sweep_interval_secs,
            shutdown_tx.subscribe(),
        ) {
            mesh_background_handles.push(handle);
        }
        // Spawn the SOCK_OPS ringbuf consumer. When the kernel program
        // is not pinned (no node-agent on this host, kernel < 5.7, or
        // build without the ebpf feature), the spawned task logs once
        // and exits — the plugin still emits zero counters.
        if let Some(state) = bpf_metrics_state.as_ref()
            && let Some(handle) = spawn_sock_ops_consumer_task(state.clone(), &shutdown_tx)
        {
            mesh_background_handles.push(handle);
        }
        // Spawn the orig-dst → identity bridge. It reads the pinned
        // FERRUM_ORIG_DST4/6 maps the node-agent populated, mirrors each
        // socket-cookie record into the resolver, and installs the synchronous
        // accept-path fallback. Without a node-agent / eBPF build the spawned
        // task logs loudly and returns; the resolver stays empty and the accept
        // path fails closed.
        //
        // Node-waypoint resolution is now wired end-to-end: the accept-side
        // cookie registrar (GAP-2M) lives in the kernel sock_ops program, and
        // the snapshot installed above seeds BOTH policy scopes AND a
        // workload_spiffe_hash → SPIFFE index, so `resolve_record` lazily
        // enrolls `pod_uid` → identity by hash-join against the eBPF-stamped
        // records (no separate enrollment channel). The path is complete in
        // code and CI-verified at the load/attach level (`ebpf-live`); it stays
        // unexercised on a live multi-pod datapath, where a tuple/byte-order or
        // enrollment miss fails closed (never misattributes).
        mesh_background_handles.push(spawn_orig_dst_bridge_task(resolver.clone(), &shutdown_tx));
        proxy_state.with_node_waypoint_identity_resolver(resolver)
    } else {
        proxy_state
    };
    // Node-waypoint in-netns outbound capture listeners (opt-in). The default
    // outbound listener binds 127.0.0.1:15001 in the HOST netns, which a pod's
    // loopback-rewritten capture (`connect4` → 127.0.0.1:15001) can never reach;
    // with this enabled the proxy additionally opens a 127.0.0.1:15001 listener
    // INSIDE each enrolled pod's network namespace, so captured connections are
    // accepted there and the GAP-2M sock_ops same-netns cookie bridge resolves
    // their source identity. Pods are discovered from the registry the node-agent
    // publishes. Linux-only; the full pod-loopback datapath is verified only on a
    // live multi-pod node (see `src/proxy/netns_capture.rs`).
    if runtime.topology == MeshTopology::NodeWaypoint {
        // `connect4` rewrites captured pod egress to `127.0.0.1:<port>` in the
        // POD's loopback, taking only the port from FERRUM_MESH_OUTBOUND_LISTEN_ADDR
        // (the rewrite IP is hardcoded loopback). So the in-netns listener must
        // bind loopback and inherit ONLY the configured port — binding the
        // configured IP verbatim (e.g. a node IP or `[::1]`) would listen on an
        // address the pod never dials and refuse every IPv4 capture. The IP part
        // of the configured address governs the HOST outbound listener, not this
        // pod-netns one. Port `0` disables the outbound listener entirely
        // (nothing is captured), so skip starting the manager.
        let capture_port = runtime.outbound_listen_addr.port();
        if capture_port == 0 {
            info!(
                "Node-waypoint in-netns capture listeners requested, but the outbound listen \
                 port is 0 (disabled); not starting in-netns capture"
            );
        } else {
            let capture_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                capture_port,
            );
            if !runtime.outbound_listen_addr.ip().is_loopback()
                && !runtime.outbound_listen_addr.ip().is_unspecified()
            {
                info!(
                    configured = %runtime.outbound_listen_addr,
                    bound = %capture_addr,
                    "Node-waypoint in-netns capture binds pod loopback with the configured \
                     outbound port; the configured IP applies only to the host listener"
                );
            }
            // One connection semaphore shared across all in-netns listeners,
            // sized from `max_connections` exactly like every other listener path
            // (each `run_accept_loop` builds its own — `max_connections` is a
            // per-listener cap in Ferrum, not a single process-wide one). This
            // bounds captured pod egress with a `max_connections`-sized limiter
            // rather than leaving it unbounded (`None`); it is intentionally a
            // separate cap from the inbound HBONE listener's so a saturated
            // inbound path cannot starve all local-pod egress (and vice versa).
            let conn_semaphore: Option<Arc<tokio::sync::Semaphore>> =
                if env_config.max_connections > 0 {
                    Some(Arc::new(tokio::sync::Semaphore::new(
                        env_config.max_connections,
                    )))
                } else {
                    None
                };
            let source = Arc::new(crate::proxy::netns_capture::DirectoryCaptureSource::new(
                env_config.mesh_node_waypoint_pod_registry_dir.clone(),
            ));
            let backend = crate::proxy::netns_capture::ProxyNetnsBackend::new(
                proxy_state.clone(),
                conn_semaphore,
                Some(MeshTrafficDirection::Outbound),
                shutdown_tx.subscribe(),
            );
            // Listener-readiness markers go in a `.ready` subdir of the registry
            // dir; the node-agent gates enabling a pod's eBPF outbound redirect
            // on its marker so a freshly enrolled pod's egress is not captured
            // before a listener exists. `DirectoryCaptureSource` skips dotfiles,
            // so the subdir is invisible to the pod-discovery scan.
            let ready_dir = std::path::Path::new(&env_config.mesh_node_waypoint_pod_registry_dir)
                .join(".ready");
            let manager = crate::proxy::netns_capture::NetnsCaptureManager::new(
                capture_addr,
                source,
                backend,
                std::time::Duration::from_secs(2),
            )
            .with_ready_dir(Some(ready_dir));
            let manager_shutdown = shutdown_tx.subscribe();
            info!(
                registry_dir = %env_config.mesh_node_waypoint_pod_registry_dir,
                capture_addr = %capture_addr,
                "Node-waypoint in-netns outbound capture listeners enabled"
            );
            mesh_background_handles.push(tokio::spawn(async move {
                manager.run(manager_shutdown).await;
            }));
        }
    }
    if let Some(ref slice) = initial_applied_mesh_slice {
        mesh_state.record_applied_slice(slice);
    }
    let startup_ready = Arc::new(AtomicBool::new(false));
    let admin_handles = start_mesh_admin_listeners(
        &env_config,
        &shutdown_tx,
        proxy_state.clone(),
        mesh_state.clone(),
        startup_ready.clone(),
        &tls_policy,
        &crls,
    )?;
    mesh_background_handles.extend(admin_handles);
    crate::runtime_metrics::global().configure(
        env_config.status_counts_max_entries,
        env_config.runtime_metrics_pool_tracking_enabled,
        env_config.runtime_metrics_status_tracking_enabled,
        env_config.runtime_metrics_cache_ttl_ms,
    );
    proxy_state
        .stream_listener_manager
        .set_global_shutdown_rx(shutdown_tx.subscribe());

    // Share the node-waypoint identity resolver with the stream listener
    // manager so TCP stream accept loops resolve each connection's source pod
    // identity and stamp the per-pod `PolicyScopeCache`, giving scoped
    // (Namespace/WorkloadSelector) mesh policies the same enforcement on raw
    // TCP streams that the HTTP/HBONE path already gets. Injected here, after
    // `with_node_waypoint_identity_resolver` populated the field on
    // `proxy_state`, and BEFORE `initial_reconcile_stream_listeners()` below so
    // listeners binding on startup observe it. `None` (and thus a no-op) in
    // every non-NodeWaypoint topology. UDP/DTLS listeners deliberately do not
    // consume the resolver — see `StreamListenerManager::set_node_waypoint_identity_resolver`.
    if let Some(resolver) = proxy_state.node_waypoint_identity_resolver.as_ref() {
        proxy_state
            .stream_listener_manager
            .set_node_waypoint_identity_resolver(resolver.clone());
    }

    // Install the initial mesh outbound enforcement slot (T5-B). The
    // slice-apply loop refreshes this on every subsequent accepted slice,
    // but the very first slice was already applied by
    // `prepare_gateway_config_for_native_slice` before `ProxyState::new`
    // existed, so the apply-loop wiring would otherwise miss it.
    if let Some(ref slice) = initial_applied_mesh_slice {
        refresh_mesh_outbound_enforcement(&proxy_state, &runtime, slice);
    }

    for host in proxy_state.plugin_cache.collect_warmup_hostnames() {
        hostnames.push((host, None, None));
    }
    dns_cache.warmup(hostnames).await;

    if env_config.pool_warmup_enabled {
        proxy_state.warmup_connection_pools().await;
    }
    proxy_state.start_backend_capability_refresh_task(
        !env_config.pool_warmup_enabled,
        Some(shutdown_tx.subscribe()),
    );
    proxy_state.start_service_discovery(Some(shutdown_tx.subscribe()));

    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));
    let dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));
    let per_ip_cleanup_handle =
        proxy_state.start_per_ip_cleanup_task(Some(shutdown_tx.subscribe()));
    let overload_handle = crate::overload::start_monitor(
        proxy_state.overload.clone(),
        env_config.overload_config(),
        env_config.max_connections,
        env_config.max_requests,
        shutdown_tx.subscribe(),
    );
    let metrics_handle = crate::metrics::start_metrics_monitor(
        proxy_state.request_count.clone(),
        proxy_state.status_counts.clone(),
        proxy_state.windowed_metrics.clone(),
        env_config.status_metrics_window_seconds,
        shutdown_tx.subscribe(),
    );
    let runtime_system_handle = crate::system_metrics::start_sampler(
        Some(proxy_state.clone()),
        env_config.runtime_metrics_system_sample_interval_ms,
        shutdown_tx.subscribe(),
    );
    let runtime_window_handle = crate::runtime_metrics::start_window_rotator(
        env_config.runtime_metrics_window_1m_seconds,
        env_config.runtime_metrics_window_5m_seconds,
        shutdown_tx.subscribe(),
    );
    // Start mesh DNS proxy if enabled
    let dns_proxy_handle = if runtime.dns_enabled {
        let dns_proxy = Arc::new(MeshDnsProxy::new(
            runtime.dns_listen_addr,
            runtime.dns_upstream_addr,
            runtime.dns_ttl_seconds,
            runtime.dns_max_concurrent_queries,
            runtime.dns_response_cache_max_entries,
            runtime.cluster_domain.clone(),
        ));
        // Build initial resolution table from the applied slice
        if let Some(ref slice) = initial_applied_mesh_slice {
            dns_proxy.update_from_slice(slice);
        }
        let dns_sockets = dns_proxy.bind().await.with_context(|| {
            format!(
                "failed to bind mesh DNS proxy at {}",
                runtime.dns_listen_addr
            )
        })?;
        let dns_shutdown = shutdown_tx.subscribe();
        let dns_runner = dns_proxy.clone();
        mesh_background_handles.push(tokio::spawn(async move {
            dns_runner.run_bound(dns_sockets, dns_shutdown).await;
        }));
        info!(
            addr = %runtime.dns_listen_addr,
            upstream = %runtime.dns_upstream_addr,
            ttl = runtime.dns_ttl_seconds,
            max_concurrent_queries = runtime.dns_max_concurrent_queries,
            response_cache_max_entries = runtime.dns_response_cache_max_entries,
            cluster_domain = %runtime.cluster_domain,
            "Mesh DNS proxy started"
        );
        Some(dns_proxy)
    } else {
        None
    };

    // Resolve mTLS mode from the initial mesh slice. By default this remains a
    // startup-only decision. When the opt-in live reload flag is enabled, the
    // mesh accept loops read `proxy_state.mesh_inbound_tls` on every accept and
    // slice apply may atomically swap the inbound ServerConfig.
    let inbound_mtls_mode =
        startup_inbound_mtls_mode(initial_applied_mesh_slice.as_deref(), &runtime)?;
    validate_egress_gateway_mtls_config(&runtime, &env_config)?;
    let mesh_frontend_identity = load_mesh_frontend_server_identity(&env_config)?;
    let initial_inbound_tls_snapshot = if env_config.mesh_peer_auth_live_reload_enabled {
        Some(mesh_inbound_tls_reload_snapshot(
            &env_config,
            inbound_mtls_mode,
        )?)
    } else {
        None
    };
    // SPIFFE inbound peer-verification slot (gateway SVID local bundle merged
    // with the initial slice's federated bundles). `None` when no gateway SVID
    // material is configured — the listener then keeps operator-CA chain
    // verification. The slot is read live by the verifier and re-published on
    // slice apply so federated trust changes propagate lock-free.
    let mesh_inbound_spiffe_slot =
        build_mesh_inbound_spiffe_slot(&env_config, initial_applied_mesh_slice.as_deref());
    let frontend_tls = load_mesh_frontend_tls(
        &env_config,
        &tls_policy,
        &crls,
        inbound_mtls_mode,
        mesh_frontend_identity.as_deref(),
        initial_inbound_tls_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.client_ca_bundle.as_ref()),
        mesh_inbound_spiffe_slot.as_ref(),
    )?;
    // Runtime fail-closed enforcement (issue #1523): #1522's config-time gate
    // only checks that identity material is *named*. Here the inbound listener's
    // actual resolved posture is known, so a production mesh refuses to come up
    // with a plaintext inbound termination listener or a configured-but-
    // unloadable SPIFFE verifier, instead of silently falling open to the
    // PERMISSIVE-plaintext posture (dev allows it with a loud warning). The
    // production flag is read once here and threaded into the live-reload gate
    // so it is fixed for the process lifetime.
    let mesh_production_mode = crate::identity::production_mode();
    enforce_mesh_inbound_fail_closed(
        &runtime,
        &env_config,
        inbound_mtls_mode,
        frontend_tls.as_ref(),
        mesh_inbound_spiffe_slot.as_ref(),
        mesh_production_mode,
    )?;
    // Keep the slot populated with startup TLS even when live reload is
    // disabled. The flag controls which listener source is used; without live
    // reload the slot never updates again, so readers must not treat it as the
    // current PeerAuthentication state.
    proxy_state
        .mesh_inbound_tls
        .store(Arc::new(frontend_tls.clone()));
    if let Some(ref tls_config) = frontend_tls {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_config.clone()))
            .await;
    }

    // Spawn the SPIFFE trust-bundle federation poller reconciler before the
    // apply task so the first slice apply observes whatever the poller has
    // already fetched. Unlike the old one-shot spawn, the reconciler watches
    // accepted slice updates: it starts pollers for federation endpoints added
    // after startup, stops pollers for removed clusters, and retires a
    // withdrawn cluster's federation store generation so stale poll results
    // cannot keep being overlaid onto slice applies. Reconcile is intentionally
    // coupled to accepted slices, not merely received slices, so an invalid
    // update rejected by the apply task cannot stop existing pollers or remove
    // cached bundles still used by the live proxy config. No pollers run when
    // `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0` or no remote cluster
    // carries a federation endpoint.
    let federation_poller_config = federation::FederationPollerConfig::from_env(
        env_config.mesh_federation_poll_interval_seconds,
        env_config.mesh_federation_poll_timeout_seconds,
        env_config.mesh_federation_fail_open,
    );
    let federation_manager = federation::FederationPollerManager::new(
        federation_poller_config,
        proxy_state.plugin_cache.http_client().clone(),
        mesh_state.federation_store().clone(),
    );
    mesh_background_handles.push(start_federation_poller_reconcile_task(
        mesh_state.clone(),
        federation_manager,
        shutdown_tx.subscribe(),
    ));
    info!("SPIFFE trust-bundle federation poller reconciler running");

    // Spawn cross-cluster endpoint discovery (Tier 3b). A reconciler watches
    // slice + federation updates and keeps one poller per currently eligible
    // `RemoteCluster.control_plane_url`. This is fail-closed on trust: a remote
    // cluster is only dialed while a federated trust bundle for its trust domain
    // exists, and stale endpoints are removed when config or trust withdraws.
    // Guard the entire TLS-build + discovery-config block: when the interval
    // is 0 (the default — discovery is disabled), skip the TLS material clone,
    // the build_dp_grpc_tls_config calls, and the associated log lines entirely.
    // Previously these ran unconditionally, causing cert-file reads and a
    // "MeshRemoteDiscovery gRPC TLS configured" log on every mesh startup even
    // when discovery was never enabled (F4).
    let remote_discovery_config = if env_config.mesh_remote_discovery_poll_interval_seconds != 0 {
        let remote_grpc_secret = env_config.cp_dp_grpc_jwt_secret.clone().map(|secret| {
            crate::grpc::dp_client::GrpcJwtSecret::with_issuer(
                secret,
                env_config.cp_dp_grpc_jwt_issuer.clone(),
            )
        });
        let remote_grpc_tls = multicluster::RemoteDiscoveryTlsConfig {
            tls_urls: build_dp_grpc_tls_config(
                &env_config,
                &["https://remote-control-plane.invalid".to_string()],
                "MeshRemoteDiscovery",
            )?,
            // The scheme is authoritative for plaintext remotes: a `grpc://` /
            // `http://` control_plane_url must NOT get DP gRPC TLS material
            // attached just because TLS env vars are set, or
            // `fetch_remote_slice_endpoints` would attempt a TLS handshake
            // against a plaintext port. (`build_dp_grpc_tls_config(.., &[], ..)`
            // returns `Some(tls)` whenever any TLS env is set, independent of
            // scheme — so force `None` here.) A `grpcs://` / `https://` remote
            // uses `tls_urls` above.
            plain_urls: None,
        };
        multicluster::RemoteDiscoveryConfig::new(
            env_config.mesh_remote_discovery_poll_interval_seconds,
            env_config.mesh_remote_discovery_poll_timeout_seconds,
            remote_grpc_secret,
            runtime.node_id.clone(),
            runtime.namespace.clone(),
            remote_grpc_tls,
        )
    } else {
        None
    };
    if let Some(remote_discovery_config) = remote_discovery_config {
        // F1: warn when discovery is enabled but the local workload locality
        // is absent. Without a source locality the priority-tier load balancer
        // has no source region to prefer, so `target_locality_ranks` stays
        // empty and ALL candidates (local + remote) are returned together —
        // failing open rather than local-first. This is not a bug in the LB
        // itself; it is the expected behavior when no locality is configured.
        // However it is surprising to operators who enabled discovery expecting
        // local-first failover. Emit a startup WARN so the misconfiguration is
        // visible.
        if initial_applied_mesh_slice
            .as_deref()
            .is_none_or(|slice| mesh_source_workload_locality(slice).is_none())
        {
            warn!(
                poll_interval_seconds = env_config.mesh_remote_discovery_poll_interval_seconds,
                "Cross-cluster endpoint discovery is enabled \
                 (FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0) but the local \
                 workload source locality is not set (topology.kubernetes.io/region+zone \
                 labels missing or SPIFFE-matched workload has no locality). \
                 The locality-aware priority-tier load balancer requires a source locality \
                 to prefer local endpoints over remote ones; without it, local and remote \
                 endpoints are selected together (fails open, not local-first). \
                 See docs/mesh.md \"Cross-Cluster Endpoint Discovery\" for the precondition."
            );
        }
        let remote_discovery_manager = multicluster::RemoteDiscoveryManager::new(
            Some(remote_discovery_config),
            mesh_state.remote_endpoint_store().clone(),
            multicluster::native_source_factory,
        );
        mesh_background_handles.push(start_remote_cluster_discovery_reconcile_task(
            mesh_state.clone(),
            remote_discovery_manager,
            shutdown_tx.subscribe(),
        ));
        info!("Cross-cluster endpoint discovery reconciler running");
    }

    let mesh_apply_handle = start_mesh_slice_apply_task(
        mesh_state,
        proxy_state.clone(),
        runtime.clone(),
        initial_applied_mesh_slice,
        MeshInboundTlsReloadState {
            server_identity: mesh_frontend_identity,
            last_snapshot: initial_inbound_tls_snapshot,
            spiffe_bundle_slot: mesh_inbound_spiffe_slot,
            production: mesh_production_mode,
        },
        shutdown_tx.subscribe(),
        dns_proxy_handle,
    );

    info!(
        listeners = runtime.listener_plan().len(),
        ?inbound_mtls_mode,
        "Mesh listener plan prepared"
    );
    let mut listener_handles = Vec::new();
    let mut startup_signals = Vec::new();
    for listener in runtime.listener_plan() {
        let uses_live_inbound_tls = env_config.mesh_peer_auth_live_reload_enabled
            && matches!(
                listener.kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            );
        let tls_config = if uses_live_inbound_tls {
            None
        } else {
            listener_tls_config_for_mtls_mode(&listener, frontend_tls.clone(), inbound_mtls_mode)
        };
        let listener_has_tls = if uses_live_inbound_tls {
            proxy_state.mesh_inbound_tls.load().as_ref().is_some()
        } else {
            tls_config.is_some()
        };
        if !listener_has_tls
            && matches!(
                listener.kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            )
            && inbound_mtls_mode != config::MtlsMode::Disable
        {
            warn!(
                direction = ?listener.direction,
                addr = %listener.addr,
                "Mesh TLS listener is running without frontend TLS because no mesh/frontend certificate is configured"
            );
        }

        let label = format!("{:?} mesh listener", listener.direction);
        let state = proxy_state.clone();
        let shutdown = shutdown_tx.subscribe();
        let addr = listener.addr;
        let direction = listener.direction;
        let kind = listener.kind;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            info!(
                direction = ?direction,
                kind = ?kind,
                addr = %addr,
                "Starting mesh listener"
            );
            let records_mesh_mtls_metric = matches!(
                kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            );
            let listener_result = if state.env_config.mesh_peer_auth_live_reload_enabled
                && records_mesh_mtls_metric
            {
                proxy::start_proxy_listener_with_mesh_inbound_tls_and_signal(
                    addr,
                    state,
                    shutdown,
                    Some(direction),
                    Some(started_tx),
                )
                .await
            } else if records_mesh_mtls_metric {
                proxy::start_mesh_proxy_listener_with_tls_and_signal(
                    addr,
                    state,
                    shutdown,
                    tls_config,
                    Some(direction),
                    Some(started_tx),
                )
                .await
            } else {
                // Outbound capture (plaintext) — non-mTLS mesh listener. Use the
                // generic listener entry but stamp direction by routing through
                // the mesh mTLS variant with `record_mesh_mtls_metric=false`.
                // We accomplish that by constructing the underlying call
                // directly so we can pass `mesh_direction` even though TLS
                // termination is disabled.
                proxy::start_mesh_plaintext_listener_with_signal(
                    addr,
                    state,
                    shutdown,
                    tls_config,
                    Some(direction),
                    Some(started_tx),
                )
                .await
            };
            if let Err(e) = listener_result {
                error!(
                    direction = ?direction,
                    kind = ?kind,
                    addr = %addr,
                    "Mesh listener error: {}",
                    e
                );
            }
        });
        listener_handles.push(handle);
        startup_signals.push((label, started_rx));
    }

    let startup_result: Result<(), anyhow::Error> = async {
        proxy_state.initial_reconcile_stream_listeners().await?;
        wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
        proxy_state
            .stream_listener_manager
            .wait_until_started(Duration::from_secs(10))
            .await?;
        startup_ready.store(true, std::sync::atomic::Ordering::Release);
        info!("Mesh runtime startup complete");
        Ok(())
    }
    .await;
    if let Err(e) = startup_result {
        warn!(
            "Mesh runtime startup failed after spawning tasks: {}; draining before returning",
            e
        );
        let _ = shutdown_tx.send(true);
        let _ =
            await_mesh_listener_handles(listener_handles, shutdown_tx.clone(), "startup failure")
                .await;
        shutdown_and_join_mesh(
            proxy_state,
            MeshBackgroundTasks {
                handles: vec![
                    dns_handle,
                    overload_handle,
                    metrics_handle,
                    runtime_system_handle,
                    runtime_window_handle,
                    mesh_apply_handle,
                ],
                dns_retry_handle,
                per_ip_cleanup_handle,
                health_check_handles,
                mesh_background_handles,
            },
            env_config.shutdown_drain_seconds,
        )
        .await;
        return Err(e);
    }

    let listener_result =
        await_mesh_listener_handles(listener_handles, shutdown_tx.clone(), "shutdown").await;

    shutdown_and_join_mesh(
        proxy_state,
        MeshBackgroundTasks {
            handles: vec![
                dns_handle,
                overload_handle,
                metrics_handle,
                runtime_system_handle,
                runtime_window_handle,
                mesh_apply_handle,
            ],
            dns_retry_handle,
            per_ip_cleanup_handle,
            health_check_handles,
            mesh_background_handles,
        },
        env_config.shutdown_drain_seconds,
    )
    .await;
    info!("Mesh runtime mode shutting down");
    listener_result?;
    Ok(())
}

fn start_mesh_admin_listeners(
    env_config: &EnvConfig,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    proxy_state: ProxyState,
    mesh_state: MeshRuntimeState,
    startup_ready: Arc<AtomicBool>,
    tls_policy: &TlsPolicy,
    crls: &tls::CrlList,
) -> Result<Vec<JoinHandle<()>>, anyhow::Error> {
    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|err| anyhow::anyhow!("Invalid FERRUM_ADMIN_ALLOWED_CIDRS: {err}"))?,
    );
    let jwt_manager = match create_jwt_manager_from_env() {
        Ok(manager) => manager,
        Err(err) => {
            warn!(
                "Admin JWT not configured for mesh mode ({}), admin endpoints will reject operator tokens",
                err
            );
            let random_secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            crate::admin::jwt_auth::JwtManager::new(crate::admin::jwt_auth::JwtConfig {
                secret: random_secret,
                ..Default::default()
            })
        }
    };
    let admin_state = AdminState {
        db: None,
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "mesh".to_string(),
        read_only: true,
        admin_audit_enabled: env_config.admin_audit_enabled,
        startup_ready: Some(startup_ready),
        db_available: None,
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: env_config.reserved_gateway_ports(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs,
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
        mesh_runtime_state: Some(mesh_state),
        admin_tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
    };

    let mut handles = Vec::new();
    let admin_state_for_https = admin_state.clone();

    if env_config.admin_http_port != 0 {
        let admin_http_addr = env_config.admin_socket_addr(env_config.admin_http_port);
        let shutdown = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            info!("Starting mesh admin HTTP listener on {}", admin_http_addr);
            if let Err(err) =
                admin::start_admin_listener(admin_http_addr, admin_state, shutdown).await
            {
                error!("Mesh admin HTTP listener error: {}", err);
            }
        }));
    } else {
        info!("FERRUM_ADMIN_HTTP_PORT=0 — plaintext mesh admin HTTP listener disabled");
    }

    if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr = env_config.admin_socket_addr(env_config.admin_https_port);
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = tls::load_tls_config_with_client_auth_and_ocsp(
            admin_cert_path,
            admin_key_path,
            admin_client_ca_bundle,
            env_config.admin_tls_ocsp_response_source.as_deref(),
            env_config.admin_tls_no_verify,
            tls_policy,
            env_config.tls_cert_expiry_warning_days,
            crls,
        )
        .map_err(|err| anyhow::anyhow!("Invalid mesh admin TLS configuration: {err}"))?;
        let admin_reload_handles = crate::modes::tls_reload::prepare_admin_frontend_tls(
            admin_tls_config.clone(),
            env_config,
            tls_policy,
            crls,
            Some(shutdown_tx.subscribe()),
        );
        if admin_reload_handles.watcher_handle.is_some() {
            info!("Frontend TLS live reload enabled for mesh admin HTTPS");
        }
        let admin_tls_slot = admin_reload_handles.slot.clone();
        let shutdown = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            info!("Starting mesh admin HTTPS listener on {}", admin_https_addr);
            let result = if let Some(slot) = admin_tls_slot {
                admin::start_admin_listener_with_dynamic_tls(
                    admin_https_addr,
                    admin_state_for_https,
                    shutdown,
                    slot,
                )
                .await
            } else {
                admin::start_admin_listener_with_tls(
                    admin_https_addr,
                    admin_state_for_https,
                    shutdown,
                    Some(admin_tls_config),
                )
                .await
            };
            if let Err(err) = result {
                error!("Mesh admin HTTPS listener error: {}", err);
            }
        }));
    } else {
        info!("Mesh admin TLS not configured - HTTPS listener disabled");
    }

    if env_config.admin_http_port == 0 && env_config.admin_tls_cert_path.is_none() {
        warn!(
            "No mesh admin API listeners are active — FERRUM_ADMIN_HTTP_PORT=0 and no admin TLS configured. The admin API is unreachable."
        );
    }

    Ok(handles)
}

/// Resolve the effective mTLS mode for the inbound TLS-terminating listener
/// from the initial mesh slice. Falls back to `Permissive` when no slice or no
/// PeerAuthentication policies are available.
///
/// Port selection follows the topology's TLS-terminating listener (see
/// `listener_plan()`), so PeerAuthentication `port_overrides` keyed on the
/// actual listener port are honoured for every topology, not just Sidecar.
fn resolve_inbound_mtls_mode(
    initial_slice: Option<&MeshSlice>,
    runtime: &MeshRuntimeConfig,
) -> config::MtlsMode {
    let Some(slice) = initial_slice else {
        return config::MtlsMode::Permissive;
    };
    slice.resolve_effective_mtls_mode(inbound_mtls_resolution_port(runtime))
}

/// Pick the port used to resolve PeerAuthentication `port_overrides` for the
/// inbound TLS-terminating listener of the current topology.
fn inbound_mtls_resolution_port(runtime: &MeshRuntimeConfig) -> u16 {
    match runtime.topology {
        MeshTopology::Sidecar => runtime.inbound_listen_addr.port(),
        MeshTopology::Ambient | MeshTopology::NodeWaypoint | MeshTopology::ServiceWaypoint => {
            runtime.hbone_listen_addr.port()
        }
        MeshTopology::EgressGateway => runtime.egress_listen_addr.port(),
        // East-west gateways do SNI passthrough — no TLS termination, no port
        // override surface. Use inbound for stability; the resolved mode is
        // not consumed by any TLS listener in this topology.
        MeshTopology::EastWestGateway => runtime.inbound_listen_addr.port(),
    }
}

/// Reject `MtlsMode::Disable` on topologies whose inbound listener is
/// fundamentally mTLS-only:
///
/// - **Ambient / NodeWaypoint**: HBONE is HTTP/2 CONNECT over mTLS — running
///   it plaintext is not a valid HBONE listener.
/// - **EgressGateway**: the egress listener must verify sidecar client
///   certificates (already enforced for env-derived TLS materials by
///   `validate_egress_gateway_mtls_config`; this check covers the
///   policy-derived path).
///
/// Sidecar and EastWestGateway accept any resolved mode (EastWestGateway
/// has no TLS termination so it is structurally a no-op).
fn validate_inbound_mtls_mode_for_topology(
    runtime: &MeshRuntimeConfig,
    mtls_mode: config::MtlsMode,
) -> Result<(), anyhow::Error> {
    if mtls_mode != config::MtlsMode::Disable {
        return Ok(());
    }
    match runtime.topology {
        MeshTopology::Ambient | MeshTopology::NodeWaypoint | MeshTopology::ServiceWaypoint => {
            Err(anyhow::anyhow!(
                "Mesh PeerAuthentication resolved to DISABLE on {} topology, but HBONE \
             (HTTP/2 CONNECT over mTLS) requires mTLS. Use PERMISSIVE or STRICT for this \
             workload, or move it to Sidecar topology if plaintext-only is intended.",
                runtime.topology.as_str()
            ))
        }
        MeshTopology::EgressGateway => Err(anyhow::anyhow!(
            "Mesh PeerAuthentication resolved to DISABLE on EgressGateway topology, but the \
             egress mTLS listener must verify sidecar client certificates. Use PERMISSIVE or \
             STRICT for this workload."
        )),
        MeshTopology::Sidecar | MeshTopology::EastWestGateway => Ok(()),
    }
}

fn startup_inbound_mtls_mode(
    initial_slice: Option<&MeshSlice>,
    runtime: &MeshRuntimeConfig,
) -> Result<config::MtlsMode, anyhow::Error> {
    let resolved = resolve_inbound_mtls_mode(initial_slice, runtime);
    validate_inbound_mtls_mode_for_topology(runtime, resolved)?;
    Ok(resolved)
}

fn live_reload_inbound_mtls_mode(
    slice: &MeshSlice,
    runtime: &MeshRuntimeConfig,
) -> Option<config::MtlsMode> {
    let resolved = resolve_inbound_mtls_mode(Some(slice), runtime);
    if let Err(error) = validate_inbound_mtls_mode_for_topology(runtime, resolved) {
        warn!(
            mesh_slice_version = %slice.version,
            ?resolved,
            topology = ?runtime.topology,
            "Rejecting mesh slice apply because PeerAuthentication mTLS mode is invalid \
             for this topology: {error}; keeping the previous mesh config"
        );
        return None;
    }
    Some(resolved)
}

#[derive(Clone, Eq)]
struct MeshInboundClientCaBundle {
    path: String,
    pem: Arc<[u8]>,
}

impl PartialEq for MeshInboundClientCaBundle {
    fn eq(&self, other: &Self) -> bool {
        self.pem == other.pem
    }
}

impl fmt::Debug for MeshInboundClientCaBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeshInboundClientCaBundle")
            .field("path", &self.path)
            .field("pem_len", &self.pem.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeshInboundTlsReloadSnapshot {
    mtls_mode: config::MtlsMode,
    client_ca_bundle: Option<MeshInboundClientCaBundle>,
}

struct MeshInboundTlsReloadState {
    server_identity: Option<Arc<tls::MeshServerIdentity>>,
    last_snapshot: Option<MeshInboundTlsReloadSnapshot>,
    /// Lock-free SVID bundle slot used to build the SPIFFE trust-domain
    /// verifier for inbound peer certs. `None` when no gateway SVID material
    /// is configured (falls back to operator-CA chain verification). When
    /// present, the slot carries the gateway SVID's local trust bundle merged
    /// with the slice's federated bundles; the verifier reads it live, and
    /// slice apply re-publishes it so federated trust-domain changes take
    /// effect without a listener restart (per the lock-free SVID slot model
    /// in `.claude/rules/tls-security.md`).
    spiffe_bundle_slot: Option<tls::SharedBundleSlot>,
    /// `FERRUM_MESH_PRODUCTION_MODE` captured once at startup. The live-reload
    /// fail-closed gate (issue #1523) consults this instead of re-reading the
    /// environment on every slice apply: the flag is fixed for the process
    /// lifetime, and a per-apply env read would also be racy under the test
    /// harness's env mutation. A production mesh refuses a PeerAuthentication
    /// update that would downgrade the inbound listener to plaintext.
    production: bool,
}

/// Build the optional SPIFFE inbound trust-bundle slot from the gateway SVID
/// file material, merging in the slice's federated trust bundles so inbound
/// peer SANs from federated trust domains validate too. Returns `None` when no
/// gateway SVID material is configured (the inbound listener then keeps the
/// operator client-CA chain verification it has always used). It also returns
/// `None` (logged) when SVID material *is* configured but fails to load — but
/// the caller does NOT silently degrade to chain-only in that case (issue
/// #1523): at startup a configured-but-unloadable SVID is fatal (see the F2
/// note in the body, and `enforce_mesh_inbound_fail_closed`), and on live reload
/// the previous trust bundle is retained. See `build_mesh_inbound_spiffe_slot`'s
/// F2 comment for the precise per-caller disposition.
fn build_mesh_inbound_spiffe_slot(
    env_config: &EnvConfig,
    slice: Option<&MeshSlice>,
) -> Option<tls::SharedBundleSlot> {
    let (cert_path, key_path, trust_bundle_path) = match (
        env_config.gateway_svid_cert_path.as_deref(),
        env_config.gateway_svid_key_path.as_deref(),
        env_config.gateway_svid_trust_bundle_path.as_deref(),
    ) {
        (Some(cert), Some(key), Some(trust)) => (cert, key, trust),
        _ => return None,
    };

    // F2 (accepted coupling, documented): `load_svid_bundle_from_files`
    // validates the gateway SVID *leaf* (notBefore/notAfter, non-CA) as well as
    // the trust-bundle CAs, so an expired/mid-rotation leaf OR a corrupt trust
    // bundle fails the whole load and this returns `None`. The disposition is the
    // CALLER's, and (issue #1523) it is NOT graceful chain-only at startup:
    //   - Startup: a configured-but-unloadable gateway SVID is a hard fault. The
    //     SAME material is loaded and validated by `load_gateway_svid_bundle` in
    //     ProxyState construction (`new_with_bpf_metrics`), which refuses startup
    //     *first*; `enforce_mesh_inbound_fail_closed` is the inbound-local guard
    //     for the identical condition. So a configured SVID that fails to load —
    //     including an expired/mid-rotation leaf — aborts startup; it does not
    //     silently degrade to chain-only.
    //   - Live reload: `stage_mesh_inbound_spiffe_bundle` keeps the PREVIOUS trust
    //     bundle (the running verifier is retained, not dropped to chain-only), so
    //     a transient mid-rotation failure does not drop inbound trust-domain
    //     enforcement.
    // We intentionally do not load only the trust bundle here: the gateway leaf
    // must also be currently valid for the listener to present a usable server
    // identity, so an expired leaf is a real fault, not a reason to half-load.
    let mut bundle = match crate::identity::file_loader::load_svid_bundle_from_files(
        std::path::Path::new(cert_path),
        std::path::Path::new(key_path),
        std::path::Path::new(trust_bundle_path),
        env_config.gateway_spiffe_id.as_deref(),
    ) {
        Ok(bundle) => bundle,
        Err(error) => {
            // Neutral report — the caller decides the disposition: fatal at
            // startup (also independently enforced by `load_gateway_svid_bundle`),
            // previous-bundle-retained on live reload.
            error!(
                %error,
                "Failed to load gateway SVID material for the mesh inbound SPIFFE peer \
                 verifier (startup: fatal; live reload: previous trust bundle retained)"
            );
            return None;
        }
    };

    merge_slice_federation_into_svid_bundle(&mut bundle, slice);

    Some(Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(bundle)))))
}

/// Overlay the slice's federated (and any extra local) trust bundles onto the
/// gateway SVID bundle so the inbound SPIFFE verifier accepts peers from
/// federated trust domains. The SVID's own local bundle (its trust domain's
/// roots) is preserved; federated entries from the slice are added.
///
/// F3 (documented design choice): the CP-pushed slice is the SOLE authority for
/// inbound trust domains. Unlike the backend/outbound path
/// (`gateway_config_from_mesh_slice`), this does NOT overlay the federation
/// poller store snapshot. A federation-poller-added trust domain therefore
/// validates for outbound mTLS but is rejected for inbound until the CP pushes
/// it in a slice. This is intentional: inbound peer trust is governed by mesh
/// PeerAuthentication/slice config, while the poller's live cross-cluster
/// bundles are an outbound-only freshness overlay.
fn merge_slice_federation_into_svid_bundle(
    bundle: &mut crate::identity::SvidBundle,
    slice: Option<&MeshSlice>,
) {
    let Some(slice) = slice else {
        return;
    };
    let Some(serialized) = slice.trust_bundles.as_ref() else {
        return;
    };
    let runtime = match serialized.to_runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            warn!(
                %error,
                "Ignoring malformed slice trust bundles when building mesh inbound \
                 SPIFFE verifier; using gateway SVID local bundle only"
            );
            return;
        }
    };
    // Add federated bundles from the slice. The local bundle stays anchored to
    // the gateway SVID's own trust domain (we do not let the slice override the
    // local roots the SVID itself chains to).
    for (trust_domain, federated) in runtime.federated {
        bundle
            .trust_bundles
            .federated
            .entry(trust_domain)
            .or_insert(federated);
    }
    // If the slice's local bundle is for a different trust domain than the
    // SVID's, treat it as a federated peer trust domain so cross-trust peers
    // still validate.
    if runtime.local.trust_domain != bundle.trust_bundles.local.trust_domain {
        bundle
            .trust_bundles
            .federated
            .entry(runtime.local.trust_domain.clone())
            .or_insert(runtime.local);
    }
}

/// Rebuild the inbound SPIFFE trust-bundle from the gateway SVID files plus the
/// current slice's federated bundles, returning it STAGED (not yet stored into
/// the live slot). The caller publishes it into the live slot only after the
/// candidate proxy config is accepted, so a rejected slice cannot leave new
/// federated trust domains active for inbound handshakes. A rebuild failure
/// returns `None` (logged) and the caller leaves the previous trust bundles in
/// place — this never fails the slice.
fn stage_mesh_inbound_spiffe_bundle(
    slot: Option<&tls::SharedBundleSlot>,
    env_config: &EnvConfig,
    slice: &MeshSlice,
) -> Option<StagedSpiffeBundle> {
    let slot = slot?;
    match build_mesh_inbound_spiffe_slot(env_config, Some(slice)) {
        Some(rebuilt) => Some(StagedSpiffeBundle {
            slot: slot.clone(),
            bundle: rebuilt.load_full(),
        }),
        None => {
            warn!(
                mesh_slice_version = %slice.version,
                "Unable to rebuild mesh inbound SPIFFE trust-bundle slot from slice; \
                 keeping previous trust bundles"
            );
            None
        }
    }
}

/// Build the inbound SPIFFE client-cert verifier for the given mTLS mode and
/// bundle slot. PERMISSIVE uses `peer_required = false` so a peer that offers
/// no cert is still admitted (but an offered cert is trust-domain-validated);
/// STRICT requires + validates a peer cert. Returns `None` when no slot is
/// available or the mode is DISABLE.
///
/// `crls` is threaded into the verifier so inbound mesh peers get end-entity
/// revocation checking, matching the operator-CA mTLS path. An empty CRL list
/// disables revocation checking (the pre-CRL behavior).
fn mesh_inbound_spiffe_verifier(
    slot: Option<&tls::SharedBundleSlot>,
    mtls_mode: config::MtlsMode,
    crls: tls::CrlList,
) -> Option<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let slot = slot?;
    match mtls_mode {
        config::MtlsMode::Strict => Some(tls::build_spiffe_client_cert_verifier(
            slot.clone(),
            true,
            crls,
        )),
        config::MtlsMode::Permissive => Some(tls::build_spiffe_client_cert_verifier(
            slot.clone(),
            false,
            crls,
        )),
        // DISABLE has no TLS; client-side DR modes never reach here.
        _ => None,
    }
}

fn mesh_inbound_tls_reload_snapshot(
    env_config: &EnvConfig,
    mtls_mode: config::MtlsMode,
) -> Result<MeshInboundTlsReloadSnapshot, anyhow::Error> {
    let client_ca_bundle = if mtls_mode == config::MtlsMode::Disable {
        None
    } else if let Some(path) = env_config.frontend_tls_client_ca_bundle_path.as_deref() {
        let source = CertSource::parse(path, MaterialKind::CaBundle);
        let material =
            load_material_blocking(&source, MaterialKind::CaBundle).with_context(|| {
                format!(
                    "failed to load mesh frontend client CA bundle at {}",
                    source.source_id()
                )
            })?;
        let pem: Arc<[u8]> = material.bytes.expose_secret().to_vec().into();
        Some(MeshInboundClientCaBundle {
            path: material.source_id,
            pem,
        })
    } else {
        None
    };
    Ok(MeshInboundTlsReloadSnapshot {
        mtls_mode,
        client_ca_bundle,
    })
}

fn load_mesh_frontend_server_identity(
    env_config: &EnvConfig,
) -> Result<Option<Arc<tls::MeshServerIdentity>>, anyhow::Error> {
    // The explicit frontend TLS cert/key is the operator override for the
    // inbound listener's server identity.
    if let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.as_deref(),
        env_config.frontend_tls_key_path.as_deref(),
    ) {
        return Ok(Some(tls::load_mesh_server_identity(
            cert_path,
            key_path,
            env_config.tls_cert_expiry_warning_days,
        )?));
    }
    // Otherwise fall back to the gateway SVID material as the inbound server
    // identity (issue #1523, gap #3 — "gateway SVID ≠ inbound server identity").
    // Previously a mesh configured with ONLY FERRUM_GATEWAY_SVID_* had a SPIFFE
    // peer *verifier* (built separately by `build_mesh_inbound_spiffe_slot`) but
    // no server *cert*, so `load_mesh_frontend_tls` fell open to `Ok(None)`
    // (plaintext) under the default PERMISSIVE mode. The gateway SVID IS the
    // mesh's workload identity, so it should back the listener's server cert.
    // The SVID's leaf cert + PKCS#8 key load via the same path as an explicit
    // frontend cert; a load failure here is a hard error (fail closed) because
    // configured-but-broken identity is a real fault, not a dev-plaintext
    // posture ("no identity at all" is gated separately at config time by #1522).
    if let (Some(cert_path), Some(key_path)) = (
        env_config.gateway_svid_cert_path.as_deref(),
        env_config.gateway_svid_key_path.as_deref(),
    ) {
        // Operability caveat (issue #1523): this server cert is loaded once here
        // and pinned for the process lifetime. The gateway SVID file watcher
        // (`run_gateway_svid_file_rotation_loop`) rotates only the BACKEND
        // (outbound) identity, so after the file-based SVID rotates this inbound
        // listener keeps presenting the startup leaf until restart — and once the
        // pinned leaf expires (~one rotation period), inbound mTLS handshakes
        // fail. Auto-rotating the SVID-backed inbound identity (a live
        // `ResolvesServerCert`) is the deferred rotation work tracked alongside
        // FERRUM_MESH_CA_BACKEND wiring; warn loudly so operators either supply
        // explicit FERRUM_FRONTEND_TLS_* (with their own rotation) or
        // restart/rolling-redeploy on SVID rotation.
        warn!(
            "Mesh inbound listener using gateway SVID material as its TLS server \
             identity (no explicit FERRUM_FRONTEND_TLS_CERT_PATH / KEY_PATH set). \
             This inbound server certificate is pinned at startup and is NOT \
             auto-rotated (the gateway SVID file watcher rotates only the backend \
             identity), so after the SVID rotates this listener keeps presenting \
             the startup leaf until the gateway is restarted — inbound mTLS will \
             fail once that leaf expires. Supply FERRUM_FRONTEND_TLS_CERT_PATH / \
             KEY_PATH with your own rotation, or restart on SVID rotation."
        );
        return Ok(Some(tls::load_mesh_server_identity(
            cert_path,
            key_path,
            env_config.tls_cert_expiry_warning_days,
        )?));
    }
    Ok(None)
}

/// Outcome of resolving a PeerAuthentication mTLS mode into an inbound
/// rustls client-auth posture, given which trust anchors are available.
///
/// Kept separate from [`tls::MeshClientAuth`] so the caller can emit a single
/// loud warning for the one degraded case (PERMISSIVE with no trust anchor at
/// all) without that warning living inside an otherwise-pure decision that
/// tests want to assert on directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshClientAuthDecision {
    /// A concrete client-auth posture was resolved.
    Resolved(tls::MeshClientAuth),
    /// PERMISSIVE was requested but neither an operator client-CA bundle nor a
    /// gateway SVID trust anchor exists, so a presented peer cert cannot be
    /// verified and no SPIFFE identity can be recorded. Resolves to
    /// [`tls::MeshClientAuth::None`] (no CertificateRequest), and the caller is
    /// expected to warn once.
    PermissiveNoTrustAnchor,
}

impl MeshClientAuthDecision {
    /// The rustls client-auth posture this decision maps to.
    fn client_auth(self) -> tls::MeshClientAuth {
        match self {
            MeshClientAuthDecision::Resolved(auth) => auth,
            MeshClientAuthDecision::PermissiveNoTrustAnchor => tls::MeshClientAuth::None,
        }
    }
}

/// Resolve the inbound rustls client-auth posture for a PeerAuthentication mTLS
/// mode, given whether an operator client-CA bundle and/or a gateway SVID
/// trust-domain verifier are available.
///
/// This is the security-critical decision behind mesh inbound mTLS:
/// - `STRICT` → `Required`: a peer cert is mandatory and verified.
/// - `PERMISSIVE` with **any** trust anchor (SVID verifier preferred, else the
///   operator client-CA bundle) → `Optional`: the listener requests a client
///   cert and verifies it when offered, but cert-less peers are still admitted.
///   This is what lets PERMISSIVE record `peer_spiffe_id` for a peer that
///   presents a valid SVID instead of silently treating it as anonymous.
/// - `PERMISSIVE` with **no** trust anchor → [`MeshClientAuthDecision::PermissiveNoTrustAnchor`]:
///   no CertificateRequest is sent because a presented cert could not be
///   verified anyway. The caller emits a single loud warning.
/// - `DISABLE` never reaches here (handled by the plaintext-listener early
///   return in [`load_mesh_frontend_tls`]).
/// - `Simple` / `Mutual` / `IstioMutual` are client-side `DestinationRule.tls`
///   modes that must never reach this server-side resolver; they fall back to
///   no client auth so a mistranslation cannot crash a running data plane.
fn resolve_mesh_inbound_client_auth(
    mtls_mode: config::MtlsMode,
    has_client_ca_bundle: bool,
    has_spiffe_verifier: bool,
) -> MeshClientAuthDecision {
    match mtls_mode {
        config::MtlsMode::Strict => MeshClientAuthDecision::Resolved(tls::MeshClientAuth::Required),
        config::MtlsMode::Permissive if has_client_ca_bundle || has_spiffe_verifier => {
            MeshClientAuthDecision::Resolved(tls::MeshClientAuth::Optional)
        }
        config::MtlsMode::Permissive => MeshClientAuthDecision::PermissiveNoTrustAnchor,
        // DISABLE has no TLS and is handled before this resolver runs.
        config::MtlsMode::Disable => MeshClientAuthDecision::Resolved(tls::MeshClientAuth::None),
        // `Simple` / `Mutual` / `IstioMutual` are client-side `DestinationRule`
        // modes; they never apply to a server-side PeerAuthentication listener.
        config::MtlsMode::Simple | config::MtlsMode::Mutual | config::MtlsMode::IstioMutual => {
            MeshClientAuthDecision::Resolved(tls::MeshClientAuth::None)
        }
    }
}

/// Build the mesh frontend TLS configuration respecting the resolved mTLS mode.
///
/// - `Strict` / `Permissive`: Load TLS with the appropriate client-auth mode.
/// - `Disable`: Return `None` (plaintext listener).
fn load_mesh_frontend_tls(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
    mtls_mode: config::MtlsMode,
    server_identity: Option<&tls::MeshServerIdentity>,
    client_ca_bundle: Option<&MeshInboundClientCaBundle>,
    spiffe_bundle_slot: Option<&tls::SharedBundleSlot>,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    if mtls_mode == config::MtlsMode::Disable {
        info!(
            "Mesh PeerAuthentication mTLS mode is DISABLE; inbound listener will accept plaintext only"
        );
        return Ok(None);
    }

    let Some(server_identity) = server_identity else {
        if mtls_mode == config::MtlsMode::Strict {
            return Err(anyhow::anyhow!(
                "Mesh PeerAuthentication STRICT requires FERRUM_FRONTEND_TLS_CERT_PATH and FERRUM_FRONTEND_TLS_KEY_PATH"
            ));
        }
        return Ok(None);
    };

    // SPIFFE trust-domain verifier (validates peer SANs against local+federated
    // bundles). Present only when gateway SVID material is configured. When
    // present it drives client auth even without an operator client CA bundle,
    // because it carries its own trust anchors from the SVID bundle. The
    // gateway CRLs are threaded in so inbound mesh peers get the same
    // end-entity revocation enforcement the operator-CA path already applies
    // (empty CRLs => no revocation checking, unchanged behavior).
    let spiffe_verifier =
        mesh_inbound_spiffe_verifier(spiffe_bundle_slot, mtls_mode, Arc::new(crls.to_vec()));

    let client_ca_bundle_path = client_ca_bundle
        .map(|bundle| bundle.path.as_str())
        .or(env_config.frontend_tls_client_ca_bundle_path.as_deref());
    let client_auth = match resolve_mesh_inbound_client_auth(
        mtls_mode,
        client_ca_bundle_path.is_some(),
        spiffe_verifier.is_some(),
    ) {
        MeshClientAuthDecision::Resolved(auth) => {
            // A client-side `DestinationRule.tls` mode reaching this server-side
            // resolver is a translator bug; surface it loudly. The resolver
            // already maps it to no client auth so a mistranslation cannot crash
            // a running data plane.
            if matches!(
                mtls_mode,
                config::MtlsMode::Simple | config::MtlsMode::Mutual | config::MtlsMode::IstioMutual
            ) {
                warn!(
                    mode = ?mtls_mode,
                    "Mesh PeerAuthentication received a client-side DR.tls mode; \
                     falling back to no client auth (this is a programming error \
                     in the K8s translator if observed)"
                );
            }
            auth
        }
        decision @ MeshClientAuthDecision::PermissiveNoTrustAnchor => {
            // Loud, single warning: PERMISSIVE with no trust anchor at all means
            // a presented peer cert cannot be verified and no SPIFFE identity
            // can be recorded. We do not silently pretend to do mTLS — we make
            // the missing-anchor degradation explicit.
            warn!(
                "Mesh PeerAuthentication mTLS mode is PERMISSIVE but no \
                 FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH or gateway SVID material is \
                 configured; client certificates will not be requested or verified and \
                 no peer SPIFFE identity will be recorded for inbound connections"
            );
            decision.client_auth()
        }
    };
    // The SPIFFE verifier only applies when we actually request client certs.
    let spiffe_verifier = if matches!(client_auth, tls::MeshClientAuth::None) {
        None
    } else {
        spiffe_verifier
    };
    if spiffe_verifier.is_some() {
        info!(
            ?mtls_mode,
            "Mesh inbound listener verifying peer SPIFFE SAN trust domains against \
             local + federated SVID bundles"
        );
    }

    let mut tls_config = if let Some(bundle) = client_ca_bundle {
        tls::load_mesh_tls_config_with_identity_and_client_ca_bytes(
            server_identity,
            Some(tls::ClientCaBundleRef {
                path: bundle.path.as_str(),
                pem: bundle.pem.as_ref(),
            }),
            client_auth,
            tls_policy,
            env_config.tls_cert_expiry_warning_days,
            crls,
            spiffe_verifier,
        )
    } else {
        tls::load_mesh_tls_config_with_identity(
            server_identity,
            client_ca_bundle_path,
            client_auth,
            tls_policy,
            env_config.tls_cert_expiry_warning_days,
            crls,
            spiffe_verifier,
        )
    }
    .map_err(|e| anyhow::anyhow!("Invalid mesh frontend TLS configuration: {}", e))?;
    tls::enable_early_data(&mut tls_config, tls_policy);
    if env_config.ktls_enabled.could_be_enabled() {
        tls::enable_secret_extraction_for_ktls(&mut tls_config);
    }
    Ok(Some(tls_config))
}

/// Posture decision for a mesh inbound listener that would serve **plaintext**
/// (issue #1523). Pure so the truth table can be unit-tested without touching the
/// environment; the env reads + logging live in [`enforce_mesh_inbound_fail_closed`].
///
/// | trigger (plaintext) | production | result             |
/// |---------------------|------------|--------------------|
/// | false               | *          | `Ok`               |
/// | true                | true       | `Refuse`           |
/// | true                | false      | `AllowWithWarning` |
///
/// The **production** contract is absolute: a production mesh must serve mTLS on
/// its inbound listener, so a plaintext posture is refused. **Dev** allows it
/// with a loud warning — reaching plaintext in dev is always *intentional*: the
/// no-identity *silent default* trap is separately fail-closed at config time by
/// the `FERRUM_MESH_ALLOW_NO_CA` gate (`EnvConfig::validate`), so the only ways to
/// get here in dev are (a) that opt-out already acknowledged, or (b) an explicit
/// `PeerAuthentication` DISABLE. The runtime gate therefore does not re-consult
/// the dev opt-out.
///
/// This governs ONLY the plaintext posture. A *configured-but-unloadable* SVID
/// verifier (the listener serves TLS but its SPIFFE trust-domain verifier failed
/// to load) is a genuine misconfiguration, not an intentional dev posture, so
/// [`enforce_mesh_inbound_fail_closed`] hard-errors that case regardless of
/// `production` — never routing it through this decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshInboundFailClosed {
    /// Listener is mTLS-capable (or there is nothing to enforce); proceed.
    Ok,
    /// Insecure posture tolerated in dev/test; proceed after a loud warning.
    AllowWithWarning,
    /// Refuse — a production mesh must not serve a plaintext inbound listener.
    Refuse,
}

fn decide_mesh_inbound_fail_closed(trigger: bool, production: bool) -> MeshInboundFailClosed {
    if !trigger {
        MeshInboundFailClosed::Ok
    } else if production {
        MeshInboundFailClosed::Refuse
    } else {
        MeshInboundFailClosed::AllowWithWarning
    }
}

/// Fail closed when the *resolved* mesh inbound listener would not actually
/// enforce mTLS (issue #1523 — the runtime complement to #1522's config-time
/// presence check).
///
/// #1522 guarantees that a production mesh *names* file-based gateway SVID
/// material, but that is only a presence check: it cannot see whether the
/// material loads or whether the resolved PeerAuthentication mode would leave
/// the inbound mTLS/HBONE termination listener serving plaintext. This runs at
/// the startup TLS-setup path, where the listener's real posture is known, and
/// closes two distinct escapes — with deliberately different severity:
///
///  - **configured-but-unloadable SVID verifier** (gap #2): the listener serves
///    TLS but gateway SVID material is configured and failed to load, so the
///    SPIFFE peer-trust-domain verifier is absent (an offered peer cert would not
///    be trust-domain validated). The operator named all three
///    `FERRUM_GATEWAY_SVID_*` paths intending verification, so this is a genuine
///    misconfiguration — **fatal regardless of `production`**, mirroring how
///    [`load_mesh_frontend_server_identity`] already hard-errors a broken SVID
///    cert/key. (`ProxyState` construction's `load_gateway_svid_bundle` rejects
///    the same broken material independently; this is the inbound-local guard.)
///  - **would-serve-plaintext**: a termination listener exists but the resolved
///    inbound `ServerConfig` is `None` (PeerAuthentication DISABLE, or no usable
///    server identity), so the listener would accept unauthenticated plaintext.
///    Refused under `production`; in dev allowed with a loud warning (intentional
///    — see [`decide_mesh_inbound_fail_closed`]).
///
/// Topologies without a TLS-terminating inbound listener (EastWestGateway does
/// SNI passthrough — encrypted bytes are forwarded, never terminated) have no
/// plaintext-inbound posture to enforce against and are skipped.
fn enforce_mesh_inbound_fail_closed(
    runtime: &MeshRuntimeConfig,
    env_config: &EnvConfig,
    mtls_mode: config::MtlsMode,
    frontend_tls: Option<&Arc<rustls::ServerConfig>>,
    spiffe_bundle_slot: Option<&tls::SharedBundleSlot>,
    production: bool,
) -> Result<(), anyhow::Error> {
    if !runtime.has_inbound_tls_termination_listener() {
        return Ok(());
    }

    // A configured-but-unloadable SVID verifier on a TLS-serving listener is a
    // genuine fault, not an intentional posture, so it is fatal regardless of
    // `production` (consistent with the hard error a broken SVID cert/key already
    // gets in `load_mesh_frontend_server_identity`). "Configured" is exact: blank
    // FERRUM_GATEWAY_SVID_* values were normalized to `None` at parse (#1522), so
    // all-three-`Some` means material was named; `build_mesh_inbound_spiffe_slot`
    // returning `None` for named material then means the load failed (it logs the
    // underlying error first). This is gated on `frontend_tls.is_some()` so a
    // resolved-plaintext listener (DISABLE — the verifier is unused) falls to the
    // plaintext branch below instead.
    let gateway_svid_configured = env_config.gateway_svid_cert_path.is_some()
        && env_config.gateway_svid_key_path.is_some()
        && env_config.gateway_svid_trust_bundle_path.is_some();
    if frontend_tls.is_some() && gateway_svid_configured && spiffe_bundle_slot.is_none() {
        return Err(anyhow::anyhow!(
            "gateway SVID material is configured (FERRUM_GATEWAY_SVID_*) but failed to load on \
             {} topology, so the mesh inbound listener would serve TLS WITHOUT SPIFFE \
             peer-trust-domain verification (an offered peer certificate would not be \
             trust-domain validated). Fix the SVID cert/key/trust-bundle material, or unset it \
             to fall back to operator client-CA verification.",
            runtime.topology.as_str()
        ));
    }

    // Otherwise the only remaining escape is a listener that would serve
    // plaintext (PeerAuthentication DISABLE, or no usable server identity).
    let reason: &str = if mtls_mode == config::MtlsMode::Disable {
        "PeerAuthentication resolved to DISABLE, so the inbound mTLS/HBONE termination \
         listener would accept unauthenticated plaintext"
    } else {
        "the inbound mTLS/HBONE termination listener resolved to no usable TLS server identity \
         (set FERRUM_GATEWAY_SVID_CERT_PATH / KEY_PATH / TRUST_BUNDLE_PATH, or \
         FERRUM_FRONTEND_TLS_CERT_PATH / KEY_PATH), so it would accept unauthenticated plaintext"
    };
    match decide_mesh_inbound_fail_closed(frontend_tls.is_none(), production) {
        MeshInboundFailClosed::Ok => Ok(()),
        MeshInboundFailClosed::AllowWithWarning => {
            warn!(
                topology = runtime.topology.as_str(),
                ?mtls_mode,
                "{reason}. The mesh inbound listener is coming up WITHOUT enforced mTLS and may \
                 accept unauthenticated plaintext traffic. Dev/test only — configure gateway \
                 SVID material and set FERRUM_MESH_PRODUCTION_MODE=true for production."
            );
            Ok(())
        }
        // Refuse only happens under production mode (see decide_*).
        MeshInboundFailClosed::Refuse => Err(anyhow::anyhow!(
            "FERRUM_MESH_PRODUCTION_MODE=true but {reason} on {} topology. Refusing to start: a \
             production mesh must serve mTLS on its inbound listener.",
            runtime.topology.as_str()
        )),
    }
}

fn validate_egress_gateway_mtls_config(
    runtime: &MeshRuntimeConfig,
    env_config: &EnvConfig,
) -> Result<(), anyhow::Error> {
    if runtime.topology != MeshTopology::EgressGateway {
        return Ok(());
    }

    if env_config.frontend_tls_cert_path.is_none() || env_config.frontend_tls_key_path.is_none() {
        return Err(anyhow::anyhow!(
            "FERRUM_MESH_TOPOLOGY=egress_gateway requires FERRUM_FRONTEND_TLS_CERT_PATH and FERRUM_FRONTEND_TLS_KEY_PATH for the egress mTLS listener"
        ));
    }

    if env_config.tls_no_verify {
        return Err(anyhow::anyhow!(
            "FERRUM_MESH_TOPOLOGY=egress_gateway cannot be used with FERRUM_TLS_NO_VERIFY=true because the egress mTLS listener must verify sidecar client certificates"
        ));
    }

    if env_config.frontend_tls_client_ca_bundle_path.is_none() {
        return Err(anyhow::anyhow!(
            "FERRUM_MESH_TOPOLOGY=egress_gateway requires FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH so sidecar client certificates are verified"
        ));
    }

    Ok(())
}

fn listener_tls_config(
    listener: &MeshListener,
    frontend_tls: Option<Arc<rustls::ServerConfig>>,
) -> Option<Arc<rustls::ServerConfig>> {
    match listener.kind {
        MeshListenerKind::PlaintextCapture => None,
        MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination => frontend_tls,
    }
}

/// Resolve the per-listener TLS config, respecting PeerAuthentication mTLS mode.
///
/// - `Disable` mode: all listeners run plaintext (no TLS config).
/// - `Strict` / `Permissive`: mTLS/HBONE listeners get the frontend TLS config;
///   plaintext-capture listeners stay plaintext.
fn listener_tls_config_for_mtls_mode(
    listener: &MeshListener,
    frontend_tls: Option<Arc<rustls::ServerConfig>>,
    mtls_mode: config::MtlsMode,
) -> Option<Arc<rustls::ServerConfig>> {
    if mtls_mode == config::MtlsMode::Disable {
        return None;
    }
    listener_tls_config(listener, frontend_tls)
}

enum MeshInboundTlsReloadPlan {
    /// No listener TLS-config change is needed (mode + client CA bundle are
    /// unchanged), but the SPIFFE federated trust-bundle may still need
    /// publishing because the snapshot does not capture the slice's federated
    /// trust domains. The staged bundle is published only after the proxy
    /// config is accepted.
    Unchanged {
        staged_spiffe: Option<StagedSpiffeBundle>,
    },
    Swap {
        snapshot: MeshInboundTlsReloadSnapshot,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        /// SPIFFE inbound trust-bundle staged during reload planning but NOT yet
        /// stored into the live slot. It is published into the live slot only
        /// when the proxy config is accepted (alongside the TLS swap), so a
        /// rejected slice never leaves new federated trust domains live for
        /// inbound handshakes. `None` when there is no SPIFFE slot (no gateway
        /// SVID material) or the rebuild failed (the live slot is left intact).
        staged_spiffe: Option<StagedSpiffeBundle>,
    },
}

/// A rebuilt inbound SPIFFE trust-bundle plus the live slot it should be stored
/// into once the reload is accepted. Staging keeps the live verifier reading
/// the previous trust bundles until the candidate proxy config is accepted.
struct StagedSpiffeBundle {
    slot: tls::SharedBundleSlot,
    bundle: Arc<Option<crate::identity::SvidBundle>>,
}

#[allow(clippy::too_many_arguments)]
fn plan_mesh_inbound_tls_reload(
    proxy_state: &ProxyState,
    runtime: &MeshRuntimeConfig,
    slice: &MeshSlice,
    mtls_mode: config::MtlsMode,
    server_identity: Option<&tls::MeshServerIdentity>,
    last_snapshot: Option<&MeshInboundTlsReloadSnapshot>,
    spiffe_bundle_slot: Option<&tls::SharedBundleSlot>,
    production: bool,
    // Precomputed once by the apply task (topology is process-fixed) so the reload
    // path does not re-derive `runtime.listener_plan()` on every slice apply.
    has_termination_listener: bool,
) -> Option<MeshInboundTlsReloadPlan> {
    let next_snapshot = match mesh_inbound_tls_reload_snapshot(&proxy_state.env_config, mtls_mode) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(
                mesh_slice_version = %slice.version,
                ?mtls_mode,
                "Unable to inspect mesh inbound TLS reload inputs: {error}; rejecting the entire mesh slice and keeping the last good config in its entirety (no authz/policy/ServiceEntry/endpoint update from this slice is applied) until the inbound TLS inputs are readable again"
            );
            return None;
        }
    };
    // Rebuild the SPIFFE inbound trust-bundle from the new slice's federated
    // bundles, but STAGE it rather than storing it into the live slot here.
    // Storing during planning would let a slice that is later rejected leave
    // its federated trust domains active for new inbound handshakes (a rejected
    // update could trust new peer domains or drop existing ones with no backing
    // mesh config). The staged bundle is published into the live slot only after
    // the candidate proxy config is accepted. The verifier reads the slot live,
    // so this still propagates federated trust-domain changes lock-free even
    // when the operator client CA bundle and mTLS mode are otherwise unchanged.
    // Only the federated set is recomputed; the SVID local roots/cert/key stay
    // the file-based startup inputs per the peer-auth reload invariant.
    let staged_spiffe =
        stage_mesh_inbound_spiffe_bundle(spiffe_bundle_slot, &proxy_state.env_config, slice);
    if last_snapshot == Some(&next_snapshot) {
        return Some(MeshInboundTlsReloadPlan::Unchanged { staged_spiffe });
    }
    let Some(tls_policy) = proxy_state.tls_policy.as_deref() else {
        error!(
            mesh_slice_version = %slice.version,
            ?mtls_mode,
            "Mesh PeerAuthentication live reload requested but TLS policy is unavailable; this is a programming error. Applying proxy config only; the inbound TLS slot remains at its previous value until restart and will be re-evaluated on later slice applies."
        );
        return Some(MeshInboundTlsReloadPlan::Unchanged { staged_spiffe });
    };
    match load_mesh_frontend_tls(
        &proxy_state.env_config,
        tls_policy,
        &proxy_state.crls,
        mtls_mode,
        server_identity,
        next_snapshot.client_ca_bundle.as_ref(),
        spiffe_bundle_slot,
    ) {
        Ok(tls_config) => {
            // Runtime fail-closed for PeerAuthentication LIVE RELOAD (issue
            // #1523): the startup gate (`enforce_mesh_inbound_fail_closed`) only
            // sees the initial slice. A later accepted update that resolves the
            // inbound termination listener to plaintext — e.g. PeerAuthentication
            // DISABLE makes `load_mesh_frontend_tls` return `None`, which
            // `apply_mesh_inbound_tls_reload` would store, clearing the inbound +
            // shared-stream TLS slots — would silently downgrade a running
            // production sidecar to plaintext. Reject the slice instead (return
            // `None` → the apply task keeps the last-good mTLS config in its
            // entirety; fail-closed by retention, never crashing a live data
            // plane). Same posture as startup: refused under production; dev allows
            // it with a warning (an explicit DISABLE is an intentional choice).
            // Topologies without a TLS-terminating inbound listener (EastWestGateway
            // SNI passthrough) are exempt (`has_termination_listener` is false).
            if has_termination_listener && tls_config.is_none() {
                match decide_mesh_inbound_fail_closed(true, production) {
                    MeshInboundFailClosed::Refuse => {
                        warn!(
                            mesh_slice_version = %slice.version,
                            ?mtls_mode,
                            topology = runtime.topology.as_str(),
                            "Rejecting mesh slice: this PeerAuthentication update resolves the \
                             inbound mTLS/HBONE termination listener to plaintext (no TLS server \
                             config), which a production mesh must not serve. Keeping the last-good \
                             mTLS config in its entirety (no authz/policy/ServiceEntry/endpoint \
                             update from this slice is applied)."
                        );
                        // Drop the staged SPIFFE bundle: the slice is rejected, so
                        // the live slot keeps its previous trust bundles.
                        return None;
                    }
                    MeshInboundFailClosed::AllowWithWarning => {
                        warn!(
                            mesh_slice_version = %slice.version,
                            ?mtls_mode,
                            topology = runtime.topology.as_str(),
                            "Applying a PeerAuthentication update that downgrades the inbound \
                             listener to plaintext. The mesh inbound listener will accept \
                             unauthenticated plaintext traffic. Dev/test only."
                        );
                    }
                    MeshInboundFailClosed::Ok => {}
                }
            }
            Some(MeshInboundTlsReloadPlan::Swap {
                snapshot: next_snapshot,
                tls_config,
                staged_spiffe,
            })
        }
        Err(error) => {
            warn!(
                mesh_slice_version = %slice.version,
                ?mtls_mode,
                "Failed to rebuild mesh inbound TLS config from PeerAuthentication update: {error}; rejecting the entire mesh slice and keeping the last good config in its entirety (no authz/policy/ServiceEntry/endpoint update from this slice is applied) until the inbound TLS rebuild succeeds"
            );
            // Drop the staged SPIFFE bundle: the slice is being rejected, so the
            // live slot must keep its previous trust bundles.
            None
        }
    }
}

async fn apply_mesh_inbound_tls_reload(
    proxy_state: &ProxyState,
    slice: &MeshSlice,
    mtls_mode: config::MtlsMode,
    plan: MeshInboundTlsReloadPlan,
    last_snapshot: &mut Option<MeshInboundTlsReloadSnapshot>,
) {
    match plan {
        MeshInboundTlsReloadPlan::Unchanged { staged_spiffe } => {
            // Listener TLS config is unchanged, but a federated trust-domain
            // change may still need publishing. Now that the proxy config was
            // accepted, store the staged SPIFFE bundle into the live slot.
            publish_staged_spiffe_bundle(staged_spiffe);
        }
        MeshInboundTlsReloadPlan::Swap {
            snapshot,
            tls_config,
            staged_spiffe,
        } => {
            // Publish the staged SPIFFE trust-bundle into the live slot first,
            // then swap the listener TLS config. Both happen only post-accept so
            // a rejected slice never alters inbound trust. The verifier reads
            // the slot live; the new TLS config's verifier will observe the new
            // bundle on its next handshake.
            publish_staged_spiffe_bundle(staged_spiffe);
            proxy_state
                .mesh_inbound_tls
                .store(Arc::new(tls_config.clone()));
            // Extend the live carve-out to mesh-shared TCP+TLS stream
            // listeners: swap the shared `rustls::ServerConfig` slot that
            // every TCP+TLS accept loop snapshots per accept. Existing
            // sessions keep the `ServerConfig` they handshake with until
            // they end; new accepts use the swapped config on the next
            // handshake. Skips when the slot is empty (PeerAuth resolved
            // to `Disable`).
            proxy_state
                .stream_listener_manager
                .swap_frontend_tls_config(tls_config);
            // And the same for UDP+DTLS: rebuild a `FrontendDtlsConfig`
            // from the current env-config inputs and have every active
            // `DtlsServer` swap atomically. Existing DTLS sessions keep
            // the crypto material they handshake with; new sessions pick
            // up the swap on the next ClientHello.
            //
            // The DTLS rebuild reuses operator-supplied cert/key/client-CA
            // paths because PeerAuth live reload, per the operating
            // invariant, never rotates cert/key paths — those remain
            // static restart-required inputs. What changes here is the
            // *mode* (Permissive ↔ Strict) and whether the client CA bundle
            // is required for mTLS verification.
            //
            // Skip the DTLS rebuild entirely on `Disable`: TCP+TLS goes to
            // plaintext via the cleared slot above, but DTLS cannot speak
            // plaintext (it is encryption by definition). On topologies
            // where `Disable` is allowed (Sidecar / EastWestGateway), an
            // operator with UDP+DTLS listeners is expected to remove
            // them from the proxy config rather than rely on a PeerAuth
            // flip; the existing DtlsServer keeps its startup material
            // so in-flight sessions and any pre-existing handshake
            // contract remain intact until the listener is reconciled
            // away.
            if mtls_mode != config::MtlsMode::Disable {
                let env = &proxy_state.env_config;
                let crls = proxy_state.crls.clone();
                let dtls_cert_key = env
                    .frontend_tls_cert_path
                    .as_deref()
                    .zip(env.frontend_tls_key_path.as_deref())
                    .map(|(c, k)| (c.to_string(), k.to_string()));
                let dtls_client_ca = env.frontend_tls_client_ca_bundle_path.clone();
                if let Some((cert_path, key_path)) = dtls_cert_key {
                    let swapped = proxy_state
                        .stream_listener_manager
                        .swap_active_dtls_frontend_configs(|| {
                            crate::dtls::build_frontend_dtls_config(
                                &cert_path,
                                &key_path,
                                dtls_client_ca.as_deref(),
                                &crls,
                            )
                        })
                        .await;
                    if swapped > 0 {
                        info!(
                            mesh_slice_version = %slice.version,
                            ?mtls_mode,
                            dtls_listeners = swapped,
                            "Mesh inbound PeerAuthentication DTLS configs reloaded"
                        );
                    }
                }
            }
            *last_snapshot = Some(snapshot);
            info!(
                mesh_slice_version = %slice.version,
                ?mtls_mode,
                "Mesh inbound PeerAuthentication TLS config reloaded"
            );
        }
    }
}

/// Reconcile the SPIFFE federation pollers against the latest accepted mesh
/// slice. Destructive actions (stopping pollers / removing bundles) must not run
/// from a merely received slice because the apply task may reject that slice and
/// keep serving the previous accepted proxy config.
fn start_federation_poller_reconcile_task(
    mesh_state: MeshRuntimeState,
    mut manager: federation::FederationPollerManager,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = mesh_state.subscribe_applied();
        loop {
            if *shutdown_rx.borrow() {
                manager.shutdown();
                return;
            }

            let snapshot = mesh_state.applied_snapshot();
            let multi_cluster = snapshot
                .as_ref()
                .as_ref()
                .and_then(|slice| slice.multi_cluster.as_ref());
            manager.reconcile(multi_cluster);

            tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        manager.shutdown();
                        return;
                    }
                }
                _ = wait_for_mesh_shutdown(&mut shutdown_rx) => {
                    manager.shutdown();
                    return;
                }
            }
        }
    })
}

fn start_remote_cluster_discovery_reconcile_task(
    mesh_state: MeshRuntimeState,
    mut manager: multicluster::RemoteDiscoveryManager,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = mesh_state.subscribe();
        let mut federation_updates = mesh_state.federation_store().subscribe();
        loop {
            if *shutdown_rx.borrow() {
                manager.shutdown();
                return;
            }

            let snapshot = mesh_state.snapshot();
            let slice = snapshot.as_ref().as_ref();
            let federation_snapshot = mesh_state.federation_store().snapshot();
            let trust_domains = multicluster::trust_domains_from_bundles(
                slice.and_then(|slice| slice.trust_bundles.as_ref()),
                &federation_snapshot,
            );
            manager.reconcile(
                slice.and_then(|slice| slice.multi_cluster.as_ref()),
                trust_domains,
            );

            tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        manager.shutdown();
                        return;
                    }
                }
                changed = federation_updates.changed() => {
                    if changed.is_err() {
                        manager.shutdown();
                        return;
                    }
                }
                _ = wait_for_mesh_shutdown(&mut shutdown_rx) => {
                    manager.shutdown();
                    return;
                },
            }
        }
    })
}

/// Publish a staged inbound SPIFFE trust-bundle into its live slot. Called only
/// after the candidate proxy config is accepted, so the live verifier never
/// trusts (or stops trusting) peer domains for a slice the runtime rejected.
/// The verifier holds an `Arc` to this slot and observes the new bundle on its
/// next handshake.
fn publish_staged_spiffe_bundle(staged: Option<StagedSpiffeBundle>) {
    if let Some(StagedSpiffeBundle { slot, bundle }) = staged {
        slot.store(bundle);
    }
}

fn start_mesh_slice_apply_task(
    mesh_state: MeshRuntimeState,
    proxy_state: ProxyState,
    runtime: MeshRuntimeConfig,
    initial_applied_mesh_slice: Option<Arc<MeshSlice>>,
    mut inbound_tls_reload: MeshInboundTlsReloadState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    dns_proxy: Option<Arc<MeshDnsProxy>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Topology is process-fixed, so whether this data plane has an inbound
        // TLS-terminating listener never changes — compute it once here rather
        // than re-deriving the listener plan on every slice apply.
        let has_termination_listener = runtime.has_inbound_tls_termination_listener();
        let mut updates = mesh_state.subscribe();
        let mut federation_updates = mesh_state.federation_store().subscribe();
        let mut remote_endpoint_updates = mesh_state.remote_endpoint_store().subscribe();
        let mut last_applied_slice = initial_applied_mesh_slice;
        let mut last_applied_federation_revision = *federation_updates.borrow();
        let mut last_applied_remote_revision = *remote_endpoint_updates.borrow();
        loop {
            if *shutdown_rx.borrow() {
                return;
            }

            let snapshot = mesh_state.snapshot();
            let current_federation_revision = *federation_updates.borrow();
            let current_remote_revision = *remote_endpoint_updates.borrow();
            // The apply loop re-runs on slice OR federation OR remote-endpoint
            // changes. Without these checks, a no-op slice (CP did not push
            // anything new) would skip applying a freshly polled federation
            // bundle or a remote cluster's scaled endpoint set: the
            // `content_eq` short-circuit only catches the slice, not the
            // bundles / remote endpoints we overlay on top.
            let federation_changed =
                current_federation_revision != last_applied_federation_revision;
            let remote_changed = current_remote_revision != last_applied_remote_revision;
            if let Some(slice) = snapshot.as_ref().as_ref() {
                let slice_unchanged =
                    mesh_slice_matches_last_applied(last_applied_slice.as_deref(), slice);
                if slice_unchanged && !federation_changed && !remote_changed {
                    record_mesh_slice_apply_result(
                        &mesh_state,
                        &mut last_applied_slice,
                        slice,
                        true,
                    );
                    debug!(
                        mesh_slice_version = %slice.version,
                        "Skipping no-op mesh slice update"
                    );
                } else {
                    let live_reload_enabled =
                        proxy_state.env_config.mesh_peer_auth_live_reload_enabled;
                    let live_reload = if live_reload_enabled {
                        live_reload_inbound_mtls_mode(slice, &runtime).and_then(|mtls_mode| {
                            plan_mesh_inbound_tls_reload(
                                &proxy_state,
                                &runtime,
                                slice,
                                mtls_mode,
                                inbound_tls_reload.server_identity.as_deref(),
                                inbound_tls_reload.last_snapshot.as_ref(),
                                inbound_tls_reload.spiffe_bundle_slot.as_ref(),
                                inbound_tls_reload.production,
                                has_termination_listener,
                            )
                            .map(|plan| (mtls_mode, plan))
                        })
                    } else {
                        None
                    };
                    if live_reload_enabled && live_reload.is_none() {
                        warn!(
                            mesh_slice_version = %slice.version,
                            "Rejected mesh slice before proxy config apply because inbound mTLS live reload preparation failed"
                        );
                    } else {
                        let federation_snapshot = mesh_state.federation_store().snapshot();
                        let remote_snapshot = mesh_state.remote_endpoint_store().snapshot();
                        match gateway_config_from_mesh_slice(
                            slice,
                            &runtime,
                            Some(&federation_snapshot),
                            Some(&remote_snapshot),
                        ) {
                            Ok(config) => {
                                let previous_loaded_at = proxy_state.config.load_full().loaded_at;
                                let candidate_loaded_at = config.loaded_at;
                                // GAP-2M.4: build node-waypoint per-pod policy scopes before
                                // config apply, but publish them only after update_config accepts
                                // the candidate. Pre-swapping scopes can pair old policies with a
                                // rejected slice's workload metadata indefinitely; staging keeps
                                // rejection side-effect free while making the post-accept swap a
                                // cheap ArcSwap publish.
                                let staged_policy_scopes =
                                    if runtime.topology == MeshTopology::NodeWaypoint {
                                        proxy_state.node_waypoint_identity_resolver.as_ref().map(
                                            |resolver| {
                                                (
                                                    Arc::clone(resolver),
                                                    resolver
                                                        .build_policy_scope_snapshot_from_workloads(
                                                            &slice.workloads,
                                                        ),
                                                )
                                            },
                                        )
                                    } else {
                                        None
                                    };
                                // The TLS reload plan (listener config + staged SPIFFE inbound
                                // trust-bundle) is built before config apply, but both are
                                // published only after proxy config acceptance inside
                                // `apply_mesh_inbound_tls_reload`. This avoids pre-swapping TLS or
                                // mutating inbound trust domains for a proxy config the runtime
                                // rejects, at the cost of a tiny accept window where listeners may
                                // still see the previous TLS config and the previous trust bundle.
                                // On a Permissive-to-Strict escalation, an accepted connection in
                                // that window can enter the new plugin chain without a peer
                                // principal; mesh authz still fails closed for identity-required
                                // policy until the slot swaps.
                                let applied = proxy_state.update_config(config);
                                let current_loaded_at = proxy_state.config.load_full().loaded_at;
                                let accepted = mesh_proxy_update_was_accepted(
                                    applied,
                                    previous_loaded_at,
                                    current_loaded_at,
                                    candidate_loaded_at,
                                );
                                // Publish the node-waypoint resolver snapshot the
                                // instant the proxy config is accepted — before
                                // recording the apply result or reloading TLS — so
                                // the window where the new config is live but the
                                // resolver still holds the previous generation is
                                // the minimum possible. Config and resolver are
                                // independent ArcSwaps that cannot swap atomically,
                                // and staging-until-accept keeps a rejected slice
                                // side-effect-free, which precludes pre-swapping the
                                // resolver before update_config. So config swaps
                                // first and the resolver swaps here, one statement
                                // later: within that bounded window the OLD
                                // generation still answers, so a workload the new
                                // slice removed keeps resolving its old scope
                                // (served briefly — NOT failed closed in-window),
                                // and a newly added one is not yet enrolled. This is
                                // the accepted, self-correcting apply-gap residual:
                                // it closes the instant the store below runs, and
                                // because the HTTP/HBONE path re-queries the scope
                                // per request it picks up the new generation on the
                                // next request (the stream path captures at accept).
                                // The fail-closed authz gate is enforced against
                                // whichever generation is live — it is not an
                                // in-window guarantee.
                                if accepted && let Some((resolver, snapshot)) = staged_policy_scopes
                                {
                                    resolver.install_policy_scope_snapshot(snapshot);
                                }
                                record_mesh_slice_apply_result(
                                    &mesh_state,
                                    &mut last_applied_slice,
                                    slice,
                                    accepted,
                                );
                                if accepted && let Some((mtls_mode, plan)) = live_reload {
                                    apply_mesh_inbound_tls_reload(
                                        &proxy_state,
                                        slice,
                                        mtls_mode,
                                        plan,
                                        &mut inbound_tls_reload.last_snapshot,
                                    )
                                    .await;
                                }
                                if accepted && let Some(ref dns_proxy) = dns_proxy {
                                    dns_proxy.update_from_slice(slice);
                                }
                                if accepted {
                                    refresh_mesh_outbound_enforcement(
                                        &proxy_state,
                                        &runtime,
                                        slice,
                                    );
                                }
                                if applied {
                                    info!(
                                        mesh_slice_version = %slice.version,
                                        "Applied mesh slice to proxy runtime"
                                    );
                                } else if accepted {
                                    debug!(
                                        mesh_slice_version = %slice.version,
                                        "Accepted mesh slice with no proxy runtime delta"
                                    );
                                } else {
                                    warn!(
                                        mesh_slice_version = %slice.version,
                                        "Rejected mesh slice proxy config; leaving last applied slice and DNS table unchanged"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    mesh_slice_version = %slice.version,
                                    error = %e,
                                    "Ignoring invalid mesh slice update"
                                );
                            }
                        }
                    }
                }
                // Federation / remote-endpoint revisions are consumed after
                // every apply attempt, whether successful or not. A rejected
                // apply still advances the markers so a transient invalid slice
                // doesn't pin the apply loop in a re-apply spin on every poll.
                last_applied_federation_revision = current_federation_revision;
                last_applied_remote_revision = current_remote_revision;
            }

            tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                changed = federation_updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                changed = remote_endpoint_updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = wait_for_mesh_shutdown(&mut shutdown_rx) => return,
            }
        }
    })
}

fn mesh_slice_matches_last_applied(
    last_applied_slice: Option<&MeshSlice>,
    slice: &MeshSlice,
) -> bool {
    last_applied_slice.is_some_and(|applied| applied.content_eq(slice))
}

fn record_mesh_slice_apply_result(
    mesh_state: &MeshRuntimeState,
    last_applied_slice: &mut Option<Arc<MeshSlice>>,
    slice: &MeshSlice,
    applied: bool,
) {
    if applied {
        mesh_state.record_applied_slice(slice);
        *last_applied_slice = Some(Arc::new(slice.clone()));
    }
}

fn mesh_proxy_update_was_accepted(
    applied: bool,
    previous_loaded_at: chrono::DateTime<chrono::Utc>,
    current_loaded_at: chrono::DateTime<chrono::Utc>,
    candidate_loaded_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    applied || (current_loaded_at == candidate_loaded_at && current_loaded_at != previous_loaded_at)
}

struct MeshBackgroundTasks {
    handles: Vec<JoinHandle<()>>,
    dns_retry_handle: Option<JoinHandle<()>>,
    per_ip_cleanup_handle: Option<JoinHandle<()>>,
    health_check_handles: Vec<JoinHandle<()>>,
    mesh_background_handles: Vec<JoinHandle<()>>,
}

async fn await_mesh_listener_handles(
    listener_handles: Vec<JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    reason: &str,
) -> Result<(), tokio::task::JoinError> {
    if listener_handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
        info!(
            reason,
            "Mesh runtime observed shutdown with no active listeners"
        );
        Ok(())
    } else {
        let shutdown_on_panic = move || {
            let _ = shutdown_tx.send(true);
        };
        crate::modes::file::await_listener_handles(listener_handles, shutdown_on_panic).await
    }
}

async fn shutdown_and_join_mesh(
    proxy_state: ProxyState,
    mut tasks: MeshBackgroundTasks,
    drain_seconds: u64,
) {
    proxy_state.stream_listener_manager.shutdown_all().await;
    crate::overload::begin_drain(&proxy_state.overload);
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    if let Some(handle) = tasks.dns_retry_handle {
        tasks.handles.push(handle);
    }
    if let Some(handle) = tasks.per_ip_cleanup_handle {
        tasks.handles.push(handle);
    }
    tasks
        .health_check_handles
        .extend(proxy_state.health_checker.take_active_check_handles());
    tasks.handles.extend(tasks.health_check_handles);
    tasks.handles.extend(tasks.mesh_background_handles);

    crate::modes::file::join_background_handles(tasks.handles, Duration::from_secs(5)).await;
}

fn parse_socket_addr(key: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse::<SocketAddr>()
        .map_err(|e| format!("{key} must be a socket address (got '{raw}'): {e}"))
}

/// Parse `FERRUM_MESH_WORKLOAD_LABELS` (`k1=v1,k2=v2`). Empty / `None` returns
/// an empty map. Whitespace around keys/values is trimmed; empty entries are
/// skipped (so a trailing `,` is harmless). Duplicate keys are rejected so the
/// operator catches a typo immediately.
fn parse_workload_labels(
    raw: Option<&str>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut labels = std::collections::HashMap::new();
    let Some(raw) = raw else {
        return Ok(labels);
    };
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            format!("FERRUM_MESH_WORKLOAD_LABELS entry '{entry}' must be in 'key=value' form")
        })?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err(format!(
                "FERRUM_MESH_WORKLOAD_LABELS entry '{entry}' has an empty key"
            ));
        }
        if labels.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!(
                "FERRUM_MESH_WORKLOAD_LABELS contains duplicate key '{key}'"
            ));
        }
    }
    Ok(labels)
}

fn parse_port(key: &str, raw: &str) -> Result<u16, String> {
    let port = raw
        .parse::<u16>()
        .map_err(|e| format!("{key} must be a TCP port (got '{raw}'): {e}"))?;
    if port == 0 {
        Err(format!("{key} must be between 1 and 65535 (got 0)"))
    } else {
        Ok(port)
    }
}

fn parse_duration_seconds(key: &str, raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|e| format!("{key} must be a duration in seconds (got '{raw}'): {e}"))
}

/// Spawn the SOCK_OPS ringbuf consumer for `__mesh_bpf_metrics`.
///
/// On Linux + `ebpf` feature builds, opens the pinned ringbuf from the
/// node-agent and drives a `tokio::select!` poll loop that updates the
/// shared `BpfMetricsState`. On every other build target this is a no-op
/// — the plugin still emits zero counters via the empty `BpfMetricsState`.
fn spawn_sock_ops_consumer_task(
    state: std::sync::Arc<crate::ebpf::bpf_metrics::BpfMetricsState>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        let consumer = crate::ebpf::event_consumer::SockOpsConsumer::new(state);
        let shutdown_rx = shutdown_tx.subscribe();
        Some(tokio::spawn(async move {
            if let Err(err) =
                crate::ebpf::event_consumer::production::run_pinned_consumer(consumer, shutdown_rx)
                    .await
            {
                tracing::warn!(error = %err, "SOCK_OPS ringbuf consumer task exited with error");
            }
        }))
    }
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    {
        // Reference the args so the no-op branch compiles cleanly.
        let _ = state;
        let _ = shutdown_tx;
        tracing::debug!(
            "SOCK_OPS ringbuf consumer skipped (build without ebpf feature or non-Linux target)"
        );
        None
    }
}

/// Spawn the node-waypoint orig-dst → identity bridge (GAP-1b). Always returns
/// a handle: on non-eBPF / non-Linux builds the task logs once that no capture
/// runs and returns, so the resolver stays empty and the accept path fails
/// closed. The bridge owns the startup-race retry and node-agent-restart
/// re-open logic in `crate::ebpf::orig_dst_bridge`.
fn spawn_orig_dst_bridge_task(
    resolver: std::sync::Arc<crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> tokio::task::JoinHandle<()> {
    let shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(err) =
            crate::ebpf::orig_dst_bridge::run_orig_dst_bridge(resolver, shutdown_rx).await
        {
            tracing::warn!(error = %err, "Node-waypoint orig-dst bridge task exited with error");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvConfig;
    use crate::config::types::PluginScope;
    use crate::dns::{DnsCache, DnsConfig};
    use crate::identity::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AccessLogFilter, AppProtocol, EastWestGateway, JwtHeader, MeshAccessLoggingConfig,
        MeshConfig, MeshEndpoint, MeshJwtRule, MeshPolicy, MeshRequestAuthentication, MeshRule,
        MeshService, MeshSubset, MeshTelemetryResource, MeshTracingConfig, MultiClusterConfig,
        PolicyAction, PolicyScope, PrincipalMatch, Resolution, ServiceEntry, ServiceEntryLocation,
        ServicePort, TracingProvider, Workload, WorkloadPort, WorkloadSelector,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn with_mesh_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MODE",
            "FERRUM_NAMESPACE",
            "FERRUM_DP_CP_GRPC_URLS",
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "FERRUM_MESH_NODE_ID",
            "FERRUM_MESH_CONFIG_PROTOCOL",
            "FERRUM_MESH_FILE_CONFIG_PATH",
            "FERRUM_MESH_XDS_NODE_CLUSTER",
            "FERRUM_MESH_TOPOLOGY",
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            "FERRUM_MESH_EAST_WEST_LISTEN_PORT",
            "FERRUM_MESH_EGRESS_HBONE_PORT",
            "FERRUM_MESH_EGRESS_MTLS_PORT",
            "FERRUM_MESH_EGRESS_LISTEN_ADDR",
            "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
            "FERRUM_MESH_WORKLOAD_LABELS",
            "FERRUM_MESH_TRUST_DOMAIN_ALIASES",
            "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS",
            "FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS",
            "FERRUM_MESH_DNS_PROXY_ENABLED",
            "FERRUM_MESH_DNS_LISTEN_ADDR",
            "FERRUM_MESH_DNS_UPSTREAM_ADDR",
            "FERRUM_MESH_DNS_TTL_SECONDS",
            "FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES",
            "FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES",
            "FERRUM_MESH_CLUSTER_DOMAIN",
            "FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY",
            "FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS",
            "FERRUM_MESH_SIDECAR_ENFORCED",
            "FERRUM_MESH_SIDECAR_IDENTITY_NARROWING",
            "FERRUM_XDS_STREAM_CHANNEL_CAPACITY",
            "FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS",
            "FERRUM_POOL_WARMUP_ENABLED",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS",
            "FERRUM_MESH_CA_BACKEND",
            "FERRUM_MESH_ALLOW_NO_CA",
        ];

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            unsafe { std::env::set_var(key, value) };
        }
        // These tests build mesh runtime configs without exercising the
        // PERMISSIVE-no-CA startup gate; unless the caller pins CA settings,
        // acknowledge the no-CA dev posture so that gate does not reject the
        // config under test.
        if !vars
            .iter()
            .any(|(k, _)| *k == "FERRUM_MESH_CA_BACKEND" || *k == "FERRUM_MESH_ALLOW_NO_CA")
        {
            unsafe { std::env::set_var("FERRUM_MESH_ALLOW_NO_CA", "true") };
        }

        f();

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn mesh_runtime_config_defaults_to_sidecar_native_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.node_id, "node-a");
                assert_eq!(runtime.namespace, "ferrum");
                assert_eq!(runtime.cp_urls, vec!["http://cp:50051"]);
                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Sidecar);
                assert_eq!(
                    runtime.inbound_listen_addr,
                    DEFAULT_INBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    DEFAULT_OUTBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.hbone_listen_addr,
                    DEFAULT_HBONE_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(runtime.east_west_listen_port, DEFAULT_EAST_WEST_LISTEN_PORT);
                assert_eq!(
                    runtime.dns_max_concurrent_queries,
                    DEFAULT_DNS_MAX_CONCURRENT_QUERIES
                );
                assert_eq!(
                    runtime.dns_response_cache_max_entries,
                    dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES
                );
                assert_eq!(runtime.cluster_domain, dns_proxy::DEFAULT_CLUSTER_DOMAIN);
                assert_eq!(runtime.outbound_registry_reject_status, 502);
                assert!(!runtime.sidecar_identity_narrowing);
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_sidecar_identity_narrowing_flag() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_SIDECAR_IDENTITY_NARROWING", "true"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                assert!(runtime.sidecar_identity_narrowing);
                assert!(
                    !runtime.sidecar_enforced,
                    "identity narrowing is parsed independently but only takes effect during slicing when Sidecar enforcement is also enabled"
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_native_ambient_overrides() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                (
                    "FERRUM_DP_CP_GRPC_URLS",
                    "https://cp1:50051,https://cp2:50051",
                ),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-b"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
                ("FERRUM_MESH_INBOUND_LISTEN_ADDR", "127.0.0.1:16006"),
                ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:16001"),
                ("FERRUM_MESH_HBONE_LISTEN_ADDR", "127.0.0.1:16008"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "16443"),
                ("FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES", "2048"),
                ("FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES", "8192"),
                ("FERRUM_MESH_CLUSTER_DOMAIN", "corp.local"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Ambient);
                assert_eq!(runtime.cp_urls.len(), 2);
                assert_eq!(
                    runtime.workload_spiffe_id.as_deref(),
                    Some("spiffe://cluster.local/ns/default/sa/api")
                );
                assert_eq!(
                    runtime.inbound_listen_addr,
                    "127.0.0.1:16006".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    "127.0.0.1:16001".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.hbone_listen_addr,
                    "127.0.0.1:16008".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(runtime.east_west_listen_port, 16443);
                assert_eq!(runtime.dns_max_concurrent_queries, 2048);
                assert_eq!(runtime.dns_response_cache_max_entries, 8192);
                assert_eq!(runtime.cluster_domain, "corp.local");
            },
        );
    }

    #[test]
    fn mesh_runtime_accepts_xds_protocol() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-x"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "xds"),
                ("FERRUM_MESH_XDS_NODE_CLUSTER", "cluster-a"),
                ("FERRUM_XDS_STREAM_CHANNEL_CAPACITY", "64"),
                ("FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS", "17"),
                ("FERRUM_MESH_WORKLOAD_LABELS", "app=api,version=v1"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config accepts xDS");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let xds_config = runtime.xds_client_config();

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Xds);
                assert!(ensure_runtime_config_protocol_supported(&runtime).is_ok());
                assert_eq!(xds_config.cp_urls, vec!["http://cp:50051"]);
                assert_eq!(xds_config.node_id, "node-x");
                assert_eq!(xds_config.cluster, "cluster-a");
                assert_eq!(xds_config.stream_channel_capacity, 64);
                assert_eq!(xds_config.primary_retry_secs, 300);
                assert_eq!(xds_config.connect_timeout_seconds, 17);
                assert_eq!(
                    xds_config.labels.get("app").map(String::as_str),
                    Some("api")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_accepts_file_protocol_without_control_plane() {
        // The localized file source has no CP: neither FERRUM_DP_CP_GRPC_URLS
        // nor FERRUM_CP_DP_GRPC_JWT_SECRET is set here, and both EnvConfig
        // validation and MeshRuntimeConfig parsing must accept that.
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_MESH_NODE_ID", "node-f"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "file"),
                ("FERRUM_MESH_FILE_CONFIG_PATH", "/etc/ferrum/mesh.yaml"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config accepts file protocol");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::File);
                assert!(!runtime.config_protocol.requires_control_plane());
                assert!(ensure_runtime_config_protocol_supported(&runtime).is_ok());
                assert_eq!(
                    runtime.file_config_path.as_deref(),
                    Some("/etc/ferrum/mesh.yaml")
                );
                assert!(runtime.cp_urls.is_empty());
            },
        );
    }

    #[test]
    fn mesh_runtime_file_protocol_requires_file_path() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "file"),
            ],
            || {
                let err = EnvConfig::from_env()
                    .expect_err("file protocol without a path must fail validation");
                assert!(
                    err.contains("FERRUM_MESH_FILE_CONFIG_PATH"),
                    "unexpected error: {err}"
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_native_protocol_still_requires_cp_urls_and_jwt_secret() {
        // Relaxing the CP requirements for the file protocol must not loosen
        // the native/xDS posture.
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
            ],
            || {
                let err = EnvConfig::from_env()
                    .expect_err("native protocol without CP URLs must fail validation");
                assert!(
                    err.contains("FERRUM_DP_CP_GRPC_URLS"),
                    "unexpected error: {err}"
                );
            },
        );
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            ],
            || {
                let err = EnvConfig::from_env()
                    .expect_err("native protocol without the CP/DP JWT secret must fail");
                assert!(
                    err.contains("FERRUM_CP_DP_GRPC_JWT_SECRET"),
                    "unexpected error: {err}"
                );
            },
        );
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                ("FERRUM_CP_DP_GRPC_JWT_SECRET", "too-short"),
            ],
            || {
                let err = EnvConfig::from_env()
                    .expect_err("a sub-minimum CP/DP JWT secret must still fail in mesh mode");
                assert!(
                    err.contains("FERRUM_CP_DP_GRPC_JWT_SECRET") && err.contains("at least"),
                    "unexpected error: {err}"
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_east_west_gateway_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15444"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.topology, MeshTopology::EastWestGateway);
                assert_eq!(runtime.east_west_listen_port, 15444);
                assert!(runtime.listener_plan().is_empty());
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_workload_labels() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", " app = api , version=v1 , ,"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.workload_labels.len(), 2);
                assert_eq!(
                    runtime.workload_labels.get("app").map(String::as_str),
                    Some("api")
                );
                assert_eq!(
                    runtime.workload_labels.get("version").map(String::as_str),
                    Some("v1")
                );
                let request = runtime.mesh_slice_request();
                assert_eq!(request.labels.get("app").map(String::as_str), Some("api"));
                assert_eq!(
                    request.labels.get("version").map(String::as_str),
                    Some("v1")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_trust_domain_aliases_and_egress_strip_keys() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                (
                    "FERRUM_MESH_TRUST_DOMAIN_ALIASES",
                    " partner.local , legacy.cluster.local ,",
                ),
                (
                    "FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS",
                    " source. , mesh. ,",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let aliases: Vec<_> = runtime
                    .trust_domain_aliases
                    .iter()
                    .map(|alias| alias.as_str())
                    .collect();
                assert_eq!(aliases, vec!["partner.local", "legacy.cluster.local"]);
                assert_eq!(
                    env.mesh_egress_strip_baggage_keys,
                    vec!["source.".to_string(), "mesh.".to_string()]
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_invalid_trust_domain_alias() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TRUST_DOMAIN_ALIASES", "Bad.Trust"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TRUST_DOMAIN_ALIASES"));
                assert!(err.contains("Bad.Trust"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_trusted_hbone_assertors() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                (
                    "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS",
                    "ztunnel , default-waypoint, \
                     spiffe://cluster.local/ns/istio-system/sa/ztunnel ,",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                assert_eq!(
                    runtime.trusted_hbone_assertors,
                    vec![
                        "ztunnel".to_string(),
                        "default-waypoint".to_string(),
                        "spiffe://cluster.local/ns/istio-system/sa/ztunnel".to_string(),
                    ]
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_trusted_hbone_assertor_with_wrong_scheme() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                (
                    "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS",
                    "https://cluster.local/ns/x/sa/y",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TRUSTED_HBONE_ASSERTORS"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_workload_label_without_equals() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", "appapi"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_WORKLOAD_LABELS"));
                assert!(err.contains("key=value"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_duplicate_workload_label_key() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", "app=api,app=worker"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("duplicate key"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_bad_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east-west"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TOPOLOGY"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_outbound_registry_reject_status() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS", "403"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.outbound_registry_reject_status, 403);
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_invalid_outbound_registry_reject_status() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS", "399"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS"));
            },
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_starts_listeners_and_shuts_down() {
        ensure_crypto_provider();
        // Provide a frontend TLS server identity so the inbound mTLS termination
        // listener is mTLS-capable and the runtime inbound fail-closed gate
        // (issue #1523) is satisfied without depending on process-env guardrail
        // state — this async test cannot hold the sync ENV_LOCK across `.await`.
        let env = EnvConfig {
            mode: crate::config::OperatingMode::Mesh,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            accept_threads: 1,
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            ..EnvConfig::default()
        };
        let runtime = MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            file_config_path: None,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
            egress_hbone_port: hbone::ISTIO_HBONE_PORT,
            egress_mtls_port: crate::proxy::mesh_mtls_pool::ISTIO_SIDECAR_INBOUND_PORT,
            egress_listen_addr: DEFAULT_EGRESS_LISTEN_ADDR.parse().unwrap(),
            workload_spiffe_id: None,
            waypoint_name: None,
            xds_node_cluster: "ferrum".to_string(),
            xds_stream_channel_capacity: 32,
            xds_primary_retry_secs: 300,
            xds_connect_timeout_seconds: 10,
            trust_domain_aliases: Vec::new(),
            trusted_hbone_assertors: Vec::new(),
            workload_labels: HashMap::new(),
            workload_svid_cert_path: None,
            workload_svid_key_path: None,
            workload_svid_trust_bundle_path: None,
            dns_enabled: false,
            dns_listen_addr: DEFAULT_DNS_LISTEN_ADDR.parse().unwrap(),
            dns_upstream_addr: DEFAULT_DNS_UPSTREAM_ADDR.parse().unwrap(),
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            dns_max_concurrent_queries: DEFAULT_DNS_MAX_CONCURRENT_QUERIES,
            dns_response_cache_max_entries: dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
            cluster_domain: dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            capture_mode: crate::capture::CaptureMode::Explicit,
            outbound_traffic_policy: crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            outbound_registry_reject_status: 502,
            sidecar_enforced: false,
            sidecar_enforced_dry_run: false,
            sidecar_identity_narrowing: false,
            egress_stream_enabled: false,
            request_auth_require_exp: true,
        };
        let config = prepare_gateway_config_for_mesh(GatewayConfig::default(), &runtime).unwrap();
        let mesh_state = MeshRuntimeState::new();
        mesh_state.install_slice(MeshSlice {
            version: chrono::Utc::now().to_rfc3339(),
            ..MeshSlice::default()
        });
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let task_shutdown = shutdown_tx.clone();
        let task = tokio::spawn(async move {
            serve_mesh_runtime(
                env,
                runtime,
                config,
                task_shutdown,
                mesh_state,
                None,
                Vec::new(),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !task.is_finished(),
            "mesh runtime should keep serving until shutdown"
        );
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("mesh runtime shut down before timeout")
            .expect("mesh runtime task joined");
        assert!(result.is_ok(), "mesh runtime returned error: {result:?}");
    }

    fn workload(name: &str, app: &str) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{name}"))
                .unwrap(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), app.to_string())]),
                namespace: Some("default".to_string()),
            },
            service_name: name.to_string(),
            addresses: Vec::new(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
        }
    }

    fn test_mesh_runtime_config() -> MeshRuntimeConfig {
        MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            file_config_path: None,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
            egress_hbone_port: hbone::ISTIO_HBONE_PORT,
            egress_mtls_port: crate::proxy::mesh_mtls_pool::ISTIO_SIDECAR_INBOUND_PORT,
            egress_listen_addr: DEFAULT_EGRESS_LISTEN_ADDR.parse().unwrap(),
            workload_spiffe_id: None,
            waypoint_name: None,
            xds_node_cluster: "default".to_string(),
            xds_stream_channel_capacity: 32,
            xds_primary_retry_secs: 300,
            xds_connect_timeout_seconds: 10,
            trust_domain_aliases: Vec::new(),
            trusted_hbone_assertors: Vec::new(),
            workload_labels: HashMap::new(),
            workload_svid_cert_path: None,
            workload_svid_key_path: None,
            workload_svid_trust_bundle_path: None,
            dns_enabled: false,
            dns_listen_addr: DEFAULT_DNS_LISTEN_ADDR.parse().unwrap(),
            dns_upstream_addr: DEFAULT_DNS_UPSTREAM_ADDR.parse().unwrap(),
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            dns_max_concurrent_queries: DEFAULT_DNS_MAX_CONCURRENT_QUERIES,
            dns_response_cache_max_entries: dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
            cluster_domain: dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            capture_mode: crate::capture::CaptureMode::Explicit,
            outbound_traffic_policy: crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            outbound_registry_reject_status: 502,
            sidecar_enforced: false,
            sidecar_enforced_dry_run: false,
            sidecar_identity_narrowing: false,
            egress_stream_enabled: false,
            request_auth_require_exp: true,
        }
    }

    /// Build a single-HTTP-port service backed by the named workload's SPIFFE id.
    fn reviews_service() -> MeshService {
        MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").unwrap(),
            }],
            protocol_overrides: HashMap::new(),
        }
    }

    #[test]
    fn sidecar_inbound_proxies_materialize_for_local_workload_services() {
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some("spiffe://cluster.local/ns/default/sa/reviews".to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![reviews_service()],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");

        let inbound = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-inbound-default-reviews-8080")
            .expect("inbound proxy materialized for the local workload's service");
        assert_eq!(inbound.backend_host, "127.0.0.1");
        assert_eq!(inbound.backend_port, 8080);
        assert_eq!(inbound.backend_scheme, Some(BackendScheme::Http));
        assert!(!inbound.passthrough);
        assert!(
            inbound
                .hosts
                .iter()
                .any(|h| h == "reviews.default.svc.cluster.local"),
            "inbound proxy must match the service FQDN: {:?}",
            inbound.hosts
        );
        assert!(
            inbound.hosts.iter().any(|h| h == "reviews"),
            "inbound proxy must match the bare service name: {:?}",
            inbound.hosts
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_services_not_backed_by_local_workload() {
        // The local workload is "client"; the only service is backed by "reviews".
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![reviews_service()],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "no inbound proxy should materialize for a service the local workload does not back"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_absent_without_local_workload_identity() {
        // No FERRUM_MESH_WORKLOAD_SPIFFE_ID → cannot identify the local workload.
        let runtime = test_mesh_runtime_config();
        assert!(runtime.workload_spiffe_id.is_none());
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![reviews_service()],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "no inbound proxy should materialize without a local workload identity"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_use_workload_port_and_own_service_only() {
        // The local workload backs service "reviews" with a TCP *container* port
        // 9090 (the app/target port); the Service declares the port as HTTP on 80.
        // A different service "ratings" merely shares the SPIFFE id. The inbound
        // route must (a) key on the workload's OWN service ("reviews", not
        // "ratings"), (b) be routable from the SERVICE port's HTTP protocol
        // despite the workload port being TCP, and (c) target the workload's app
        // port 9090 (not the service port 80).
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut local = workload("reviews", "reviews");
        local.ports = vec![WorkloadPort {
            port: 9090,
            protocol: AppProtocol::Tcp,
            name: Some("http".to_string()),
        }];
        let http_service = |name: &str| MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                spiffe_id: SpiffeId::new(spiffe).unwrap(),
            }],
            protocol_overrides: HashMap::new(),
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![local],
            services: vec![http_service("reviews"), http_service("ratings")],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");

        let inbound: Vec<&str> = config
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("__mesh-inbound-"))
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(
            inbound,
            vec!["__mesh-inbound-default-reviews-80"],
            "exactly one inbound route, for the local workload's OWN service (not 'ratings')"
        );
        let route = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-inbound-default-reviews-80")
            .expect("reviews route");
        assert_eq!(
            route.backend_port, 9090,
            "inbound route must target the workload's app port, not the service port"
        );
        assert!(
            route
                .hosts
                .iter()
                .any(|h| h == "reviews.default.svc.cluster.local")
        );
    }

    /// Build an HTTP `MeshService` named `name` on `port`, backed by `spiffe`.
    fn http_mesh_service(name: &str, port: u16, spiffe: &str) -> MeshService {
        MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                spiffe_id: SpiffeId::new(spiffe).unwrap(),
            }],
            protocol_overrides: HashMap::new(),
        }
    }

    // ── Ambient outbound (egress) HBONE materialization ───────────────────

    /// A workload with a pod address so the outbound materializer can build HBONE
    /// targets (the bare `workload()` helper has no addresses).
    fn workload_with_address(name: &str, app: &str, address: &str) -> Workload {
        let mut wl = workload(name, app);
        wl.addresses = vec![address.to_string()];
        wl
    }

    fn ambient_runtime() -> MeshRuntimeConfig {
        MeshRuntimeConfig {
            topology: MeshTopology::Ambient,
            ..test_mesh_runtime_config()
        }
    }

    #[test]
    fn mesh_outbound_materializes_hbone_route_for_ambient_service() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);

        let proxy = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-outbound-default-reviews-8080")
            .expect("ambient outbound proxy materialized");
        assert_eq!(proxy.listen_path.as_deref(), Some("/"));
        // backend_scheme Http -> HttpPool dispatch -> lights up the HBONE transport.
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Http));
        assert_eq!(
            proxy.upstream_id.as_deref(),
            Some("__mesh-out-upstream-default-reviews-8080")
        );
        assert!(
            proxy.retry.is_none(),
            "an HBONE CONNECT tunnel is not replayable"
        );
        assert!(
            proxy
                .hosts
                .iter()
                .any(|h| h == "reviews.default.svc.cluster.local")
        );

        let upstream = config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-8080")
            .expect("ambient outbound upstream materialized");
        let target = &upstream.targets[0];
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 8080, "HBONE CONNECT dials the app port");
        assert_eq!(
            target.tags.get("mesh.hbone").map(String::as_str),
            Some("true"),
            "target must be tagged for HBONE dispatch"
        );
        assert_eq!(
            target.tags.get("mesh.spiffe_id").map(String::as_str),
            Some(spiffe),
            "peer identity for SVID-mTLS verification"
        );
    }

    #[test]
    fn mesh_outbound_materializes_per_port_routes_for_multi_port_service() {
        // Multi-port services materialize one route + one upstream PER
        // HTTP-family port; the route table groups the siblings and the
        // request path picks by captured original-destination port. Non-HTTP
        // ports still materialize nothing.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports.push(ServicePort {
            port: 90,
            protocol: AppProtocol::Grpc,
            name: Some("grpc".to_string()),
            target_port: None,
        });
        svc.ports.push(ServicePort {
            port: 5432,
            protocol: AppProtocol::Tcp,
            name: Some("db".to_string()),
            target_port: None,
        });
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![svc],
            ..MeshSlice::default()
        };
        // Mirror `gateway_config_from_mesh_slice`: the prepared config carries
        // the slice's services in its `mesh` block — the uniqueness validator
        // and the router grouping both derive sibling identity from it.
        let mut config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: slice.services.clone(),
                workloads: slice.workloads.clone(),
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);

        for port in [80u16, 90] {
            let proxy = config
                .proxies
                .iter()
                .find(|p| p.id == format!("__mesh-outbound-default-reviews-{port}"))
                .unwrap_or_else(|| panic!("per-port outbound proxy for {port} materialized"));
            assert_eq!(
                proxy.upstream_id.as_deref(),
                Some(format!("__mesh-out-upstream-default-reviews-{port}").as_str())
            );
            let upstream = config
                .upstreams
                .iter()
                .find(|u| u.id == format!("__mesh-out-upstream-default-reviews-{port}"))
                .unwrap_or_else(|| panic!("per-port outbound upstream for {port} materialized"));
            assert_eq!(
                upstream.targets[0].port, port,
                "each per-port upstream dials its own service port's app port"
            );
        }
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id == "__mesh-outbound-default-reviews-5432"),
            "non-HTTP (TCP) service ports must not materialize HTTP outbound routes"
        );
        // The swap path (`ProxyState::update_config` → `validate_full_config`)
        // runs this validator on every slice apply; the per-port siblings
        // share hosts + `/` by design and must pass via the same-service
        // exemption — otherwise multi-port slices are rejected at apply.
        assert!(
            config.validate_unique_listen_paths().is_ok(),
            "per-port outbound siblings must survive the uniqueness validator: {:?}",
            config.validate_unique_listen_paths()
        );
    }

    #[test]
    fn prepare_gateway_config_back_projects_narrowed_services() {
        // `config.mesh.services` must carry the slice's NARROWED view after
        // preparation (CP parity: `gateway_config_from_mesh_slice` builds the
        // mesh block FROM the slice on the CP-driven paths). The router's
        // outbound sibling grouping derives declared-HTTP-port counts from
        // it, so an un-narrowed declaration would demand orig-dst for ports
        // (or whole services) the slice narrowed away.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let local = http_mesh_service("reviews", 80, spiffe);
        let mut foreign = http_mesh_service("ratings", 80, spiffe);
        foreign.namespace = "other".to_string();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![local, foreign],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.namespace, "default");
        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh prepare");
        let mesh = prepared.mesh.expect("mesh block survives preparation");
        assert_eq!(
            mesh.services
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["reviews"],
            "the prepared config carries the slice-narrowed services view"
        );
    }

    #[test]
    fn mesh_outbound_sidecar_keeps_multi_port_fail_closed() {
        // Sidecar destination INBOUND multi-port still fails closed (inbound
        // dials are direct, never NATed), so per-port Sidecar egress would
        // dial the peer only to 404 there. Until inbound port disambiguation
        // lands, Sidecar multi-port services materialize NOTHING — the old
        // source-side fail-closed behavior. Ambient (above) is per-port.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports.push(ServicePort {
            port: 90,
            protocol: AppProtocol::Grpc,
            name: Some("grpc".to_string()),
            target_port: None,
        });
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![svc],
            ..MeshSlice::default()
        };
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.topology, MeshTopology::Sidecar);
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &runtime, &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-outbound-")),
            "Sidecar multi-port services must stay fail-closed at the source until \
             inbound port disambiguation lands"
        );
    }

    #[test]
    fn mesh_outbound_honors_numeric_target_port() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![svc],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);
        let upstream = config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-80")
            .expect("upstream");
        assert_eq!(
            upstream.targets[0].port, 8080,
            "the HBONE CONNECT dials the resolved targetPort"
        );
    }

    #[test]
    fn mesh_outbound_rekeys_port_policy_to_target_port() {
        // A DestinationRule portLevelSettings entry is keyed on the SERVICE port
        // (80), but the materialized outbound HBONE upstream's target dials the
        // numeric targetPort (8080). The per-port policy must be re-keyed onto the
        // dial port so dispatch applies it — otherwise it is dropped as a phantom
        // port (the egress-ServiceEntry bug class fixed in #1548, here for outbound
        // HBONE upstreams).
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![svc],
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::from([(
                    80u16,
                    MeshTrafficPolicy {
                        connect_timeout_ms: Some(1234),
                        ..MeshTrafficPolicy::default()
                    },
                )]),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);
        apply_destination_rules(&mut config, &ambient_runtime(), &slice)
            .expect("destination rules apply");

        let upstream = config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-80")
            .expect("outbound upstream materialized");
        assert_eq!(
            upstream
                .port_overrides
                .get(&8080)
                .and_then(|slot| slot.connect_timeout_ms),
            Some(1234),
            "service-port portLevelSettings must be re-keyed onto the dial port 8080"
        );
        assert!(
            !upstream.port_overrides.contains_key(&80),
            "per-port policy must not remain under the service port 80"
        );
    }

    #[test]
    fn mesh_outbound_port_policy_does_not_leak_across_sibling_upstreams() {
        // Service declares ports 80 (targetPort 8080) and 8080. Port 80's
        // upstream DIALS 8080, so the generic "entry port is a target port"
        // acceptance would wrongly apply the DR entry authored for SERVICE
        // port 8080 to port 80's upstream. Each per-port sibling must carry
        // exactly its own service port's policy.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        svc.ports.push(ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
            target_port: None,
        });
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![svc],
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::from([
                    (
                        80u16,
                        MeshTrafficPolicy {
                            connect_timeout_ms: Some(1111),
                            ..MeshTrafficPolicy::default()
                        },
                    ),
                    (
                        8080u16,
                        MeshTrafficPolicy {
                            connect_timeout_ms: Some(2222),
                            ..MeshTrafficPolicy::default()
                        },
                    ),
                ]),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);
        apply_destination_rules(&mut config, &ambient_runtime(), &slice)
            .expect("destination rules apply");

        let upstream_80 = config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-80")
            .expect("port-80 upstream materialized");
        assert_eq!(
            upstream_80
                .port_overrides
                .get(&8080)
                .and_then(|slot| slot.connect_timeout_ms),
            Some(1111),
            "port 80's upstream carries ITS OWN service port's policy, \
             re-keyed onto its dial port 8080"
        );

        let upstream_8080 = config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-8080")
            .expect("port-8080 upstream materialized");
        assert_eq!(
            upstream_8080
                .port_overrides
                .get(&8080)
                .and_then(|slot| slot.connect_timeout_ms),
            Some(2222),
            "service port 8080's policy lands only on its own sibling upstream"
        );
    }

    #[test]
    fn mesh_outbound_skips_unresolved_named_target_port() {
        // A named targetPort the workload doesn't expose fails closed (drops the
        // target), consistent with the inbound/discovery/east-west paths.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports[0].target_port = Some(ServiceTargetPort::Name("http".to_string()));
        let mut wl = workload_with_address("reviews", "reviews", "10.0.0.1");
        wl.ports = vec![WorkloadPort {
            port: 9999,
            protocol: AppProtocol::Http,
            name: Some("grpc".to_string()),
        }];
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![wl],
            services: vec![svc],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);
        assert!(
            !config
                .upstreams
                .iter()
                .any(|u| u.id.starts_with("__mesh-out-upstream-")),
            "an unresolved named targetPort must drop the target (fail closed), leaving no upstream"
        );
    }

    #[test]
    fn mesh_outbound_skips_for_gateway_topologies() {
        // Gateway topologies (east-west / egress) have their own materializers
        // and no plaintext outbound capture listener — no egress routes here.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EastWestGateway,
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &runtime, &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-outbound-"))
        );
    }

    #[test]
    fn mesh_outbound_materializes_mtls_route_for_sidecar_service() {
        // Sidecar egress emits SVID-mTLS targets (mesh.mtls, NOT mesh.hbone):
        // the peer sidecar speaks plain mTLS HTTP on :15006 and has no HBONE
        // listener.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.topology, MeshTopology::Sidecar);
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &runtime, &slice);

        let proxy = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-outbound-default-reviews-8080")
            .expect("sidecar outbound proxy materialized");
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Http));
        assert!(proxy.retry.is_none());
        let upstream = config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-8080")
            .expect("sidecar outbound upstream materialized");
        let target = &upstream.targets[0];
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(
            target.port, 8080,
            "DR port_overrides key stays the app port"
        );
        assert_eq!(
            target.tags.get("mesh.mtls").map(String::as_str),
            Some("true"),
            "Sidecar egress targets must be tagged for SVID-mTLS dispatch"
        );
        assert!(
            !target.tags.contains_key("mesh.hbone"),
            "HBONE is NOT Sidecar's transport — a Sidecar egress target must not carry mesh.hbone"
        );
        assert_eq!(
            target.tags.get("mesh.spiffe_id").map(String::as_str),
            Some(spiffe),
            "pinned destination identity for the mTLS handshake"
        );
    }

    #[test]
    fn mesh_outbound_sidecar_yields_to_local_inbound_route() {
        // The local workload's own service already has a materialized INBOUND
        // loopback route (built before the outbound pass); the route table
        // holds one proxy per host+path, so Sidecar egress must yield rather
        // than re-tunnel the local service's traffic out to the mesh.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.topology, MeshTopology::Sidecar);
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        config.proxies.push(mesh_inbound_loopback_proxy(
            &mesh_inbound_proxy_id("default", "reviews", 8080),
            mesh_service_host_variants("reviews", "default", "cluster.local"),
            "default",
            8080,
            chrono::Utc::now(),
        ));
        materialize_mesh_outbound_proxies(&mut config, &runtime, &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-outbound-")),
            "Sidecar egress must yield to the local service's inbound loopback route"
        );
        assert!(
            config
                .proxies
                .iter()
                .any(|p| is_mesh_inbound_route_id(&p.id)),
            "the inbound route must remain"
        );
    }

    #[test]
    fn mesh_outbound_stamps_non_default_egress_dial_ports() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        // Ambient: non-default FERRUM_MESH_EGRESS_HBONE_PORT rides the
        // mesh.hbone_port tag the HBONE pool dials.
        let runtime = MeshRuntimeConfig {
            egress_hbone_port: 16008,
            ..ambient_runtime()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &runtime, &slice);
        let target = &config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-8080")
            .expect("upstream")
            .targets[0];
        assert_eq!(
            target.tags.get("mesh.hbone_port").map(String::as_str),
            Some("16008")
        );

        // Sidecar: non-default FERRUM_MESH_EGRESS_MTLS_PORT rides the
        // mesh.mtls_port tag the mTLS pool dials. Default ports stamp nothing.
        let runtime = MeshRuntimeConfig {
            egress_mtls_port: 16006,
            ..test_mesh_runtime_config()
        };
        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &runtime, &slice);
        let target = &config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-8080")
            .expect("upstream")
            .targets[0];
        assert_eq!(
            target.tags.get("mesh.mtls_port").map(String::as_str),
            Some("16006")
        );

        let mut config = GatewayConfig::default();
        materialize_mesh_outbound_proxies(&mut config, &test_mesh_runtime_config(), &slice);
        let target = &config
            .upstreams
            .iter()
            .find(|u| u.id == "__mesh-out-upstream-default-reviews-8080")
            .expect("upstream")
            .targets[0];
        assert!(
            !target.tags.contains_key("mesh.mtls_port"),
            "the Istio-convention default port must not bloat target tags"
        );
    }

    #[test]
    fn mesh_outbound_yields_to_operator_proxy() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let slice = MeshSlice {
            namespace: "default".to_string(),
            workloads: vec![workload_with_address("reviews", "reviews", "10.0.0.1")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };
        let mut config = GatewayConfig::default();
        config.proxies.push(mesh_inbound_loopback_proxy(
            "operator-reviews",
            mesh_service_host_variants("reviews", "default", "cluster.local"),
            "default",
            9999,
            chrono::Utc::now(),
        ));
        materialize_mesh_outbound_proxies(&mut config, &ambient_runtime(), &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-outbound-")),
            "must yield to the operator proxy on the overlapping host"
        );
        assert!(config.proxies.iter().any(|p| p.id == "operator-reviews"));
    }

    #[test]
    fn mesh_route_direction_classifies_id_prefixes() {
        assert_eq!(
            mesh_route_direction("__mesh-inbound-default-reviews-8080"),
            Some(MeshTrafficDirection::Inbound)
        );
        assert_eq!(
            mesh_route_direction("__mesh-outbound-default-reviews-8080"),
            Some(MeshTrafficDirection::Outbound)
        );
        assert_eq!(mesh_route_direction("operator-proxy"), None);
        assert_eq!(mesh_route_direction("__mesh-ew-svc-default-reviews"), None);
    }

    /// `mesh_outbound_service_groups` is the single source of truth for
    /// per-port sibling identity: `RouterCache` grouping and the
    /// `validate_unique_listen_paths` exemption both consume it. Lock the
    /// forward-derivation contract — including immunity to the lossy
    /// `{ns}-{name}` id join (ns `a` / svc `b-c` vs ns `a-b` / svc `c`).
    #[test]
    fn mesh_outbound_service_groups_derive_sibling_ids_forward() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/x";
        let mut multi = http_mesh_service("reviews", 80, spiffe);
        multi.ports.push(ServicePort {
            port: 9080,
            protocol: AppProtocol::Grpc,
            name: Some("grpc".to_string()),
            target_port: None,
        });
        multi.ports.push(ServicePort {
            port: 5432,
            protocol: AppProtocol::Tcp,
            name: Some("db".to_string()),
            target_port: None,
        });
        // The lossy-join collision pair: distinct services whose joined ids
        // share a prefix. Forward derivation keeps them in separate groups.
        let mut svc_bc = http_mesh_service("b-c", 80, spiffe);
        svc_bc.namespace = "a".to_string();
        let mut svc_c = http_mesh_service("c", 90, spiffe);
        svc_c.namespace = "a-b".to_string();

        let mesh = MeshConfig {
            services: vec![multi, svc_bc, svc_c],
            ..MeshConfig::default()
        };
        let groups = mesh_outbound_service_groups(&mesh);
        assert_eq!(groups.len(), 3, "one group per service with HTTP ports");

        let reviews = &groups[0];
        assert_eq!(
            reviews.declared_http_ports, 2,
            "TCP ports are not HTTP-family-declared"
        );
        assert_eq!(
            reviews.siblings,
            vec![
                (80, "__mesh-outbound-default-reviews-80".to_string()),
                (9080, "__mesh-outbound-default-reviews-9080".to_string()),
            ]
        );

        // Collision pair: ids share the joined prefix but belong to distinct
        // groups, so the router never conflates them.
        assert_eq!(
            groups[1].siblings,
            vec![(80, "__mesh-outbound-a-b-c-80".to_string())]
        );
        assert_eq!(
            groups[2].siblings,
            vec![(90, "__mesh-outbound-a-b-c-90".to_string())]
        );
    }

    #[test]
    fn sidecar_inbound_proxies_disambiguate_shared_spiffe_by_labels() {
        // Two workloads share the SPIFFE id but back different services and carry
        // different labels. The sidecar's own labels (CP-provided) select only the
        // matching workload, so only its service's route materializes.
        let shared = "spiffe://cluster.local/ns/default/sa/default";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(shared.to_string()),
            ..test_mesh_runtime_config()
        };
        let shared_id = |service: &str, app: &str| {
            let mut w = workload(service, app);
            w.spiffe_id = SpiffeId::new(shared).unwrap();
            w
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            labels: BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            workloads: vec![
                shared_id("reviews", "reviews"),
                shared_id("ratings", "ratings"),
            ],
            services: vec![
                http_mesh_service("reviews", 8080, shared),
                http_mesh_service("ratings", 8080, shared),
            ],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        let inbound: Vec<&str> = config
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("__mesh-inbound-"))
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(
            inbound,
            vec!["__mesh-inbound-default-reviews-8080"],
            "only the label-matched local workload's service may be materialized"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_reject_empty_selector_when_sidecar_labeled() {
        // A workload sharing the SPIFFE id but with an EMPTY selector must NOT be
        // treated as local when the sidecar's labels are known — an empty selector
        // matches "any" and would reintroduce the cross-service leak.
        let shared = "spiffe://cluster.local/ns/default/sa/default";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(shared.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut reviews = workload("reviews", "reviews");
        reviews.spiffe_id = SpiffeId::new(shared).unwrap();
        let mut legacy = workload("legacy", "legacy");
        legacy.spiffe_id = SpiffeId::new(shared).unwrap();
        legacy.selector.labels.clear();
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            labels: BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            workloads: vec![reviews, legacy],
            services: vec![
                http_mesh_service("reviews", 8080, shared),
                http_mesh_service("legacy", 8080, shared),
            ],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        let inbound: Vec<&str> = config
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("__mesh-inbound-"))
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(
            inbound,
            vec!["__mesh-inbound-default-reviews-8080"],
            "an empty-selector workload must not be treated as local when the sidecar has labels"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_multi_http_port_service() {
        // Host-only routing can't disambiguate ports yet (the router strips the
        // request port), so a single `/` route on the shared host would forward
        // EVERY port's traffic to the first port's backend — a cross-port
        // misroute. Fail closed: a service exposing more than one HTTP-family
        // port materializes NO inbound route until original-destination routing
        // lands. Operators can define an explicit proxy for a specific port.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![MeshService {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                ports: vec![
                    ServicePort {
                        port: 80,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                        target_port: None,
                    },
                    ServicePort {
                        port: 90,
                        protocol: AppProtocol::Grpc,
                        name: Some("grpc".to_string()),
                        target_port: None,
                    },
                ],
                workloads: vec![crate::modes::mesh::config::WorkloadRef {
                    spiffe_id: SpiffeId::new(spiffe).unwrap(),
                }],
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        let inbound: Vec<&str> = config
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("__mesh-inbound-"))
            .map(|p| p.id.as_str())
            .collect();
        assert!(
            inbound.is_empty(),
            "a service with >1 HTTP-family port must materialize no inbound route \
             (fail closed against cross-port misrouting), got {inbound:?}"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_route_overlapping_explicit_proxy() {
        // In file/config mode the prepared config starts from operator proxies. If
        // one already routes the service host at "/", materialization must NOT add
        // a colliding `__mesh-inbound-*` route (which would fail unique-listen-path
        // validation); the operator's proxy wins.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        // An operator proxy already routes the reviews FQDN at "/".
        let mut config = GatewayConfig::default();
        config.proxies.push(mesh_inbound_loopback_proxy(
            "operator-reviews",
            mesh_service_host_variants("reviews", "default", "cluster.local"),
            "default",
            7777,
            chrono::Utc::now(),
        ));

        materialize_sidecar_inbound_proxies(&mut config, &runtime, &slice);

        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "must not materialize a route that collides with an existing explicit proxy"
        );
        assert!(
            config.proxies.iter().any(|p| p.id == "operator-reviews"),
            "the operator's proxy must be left intact"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_yield_to_catch_all_operator_proxy() {
        // A catch-all operator proxy (empty hosts) overlaps every host under
        // `validate_unique_listen_paths`. A literal host match would miss it and
        // materialize a colliding route that validation later rejects, failing
        // startup/reload; host-overlap semantics must let the catch-all win.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        // An operator catch-all proxy (empty hosts) already routes "/".
        let mut config = GatewayConfig::default();
        config.proxies.push(mesh_inbound_loopback_proxy(
            "operator-catch-all",
            Vec::new(),
            "default",
            7777,
            chrono::Utc::now(),
        ));

        materialize_sidecar_inbound_proxies(&mut config, &runtime, &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "must not materialize a route overlapping a catch-all operator proxy"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_require_service_to_reference_local_workload() {
        // The local workload backs "reviews" by name, but the Service's workload
        // refs omit this SPIFFE id (config typo, EndpointSlice lag). The service
        // must not be routed to the local app on a name match alone.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut service = http_mesh_service("reviews", 8080, spiffe);
        service.workloads.clear();
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![service],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "a service that does not reference the local workload must not be routed"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_when_backend_port_is_ambiguous() {
        // The service port shares neither a name nor a number with any of the
        // workload's *multiple unnamed* container ports, and the model does not
        // carry the Service's targetPort. The backend is genuinely ambiguous, so
        // the route is skipped — never silently routed to an arbitrary port.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut local = workload("reviews", "reviews");
        local.ports = vec![
            WorkloadPort {
                port: 8081,
                protocol: AppProtocol::Tcp,
                name: None,
            },
            WorkloadPort {
                port: 8082,
                protocol: AppProtocol::Tcp,
                name: None,
            },
        ];
        // Service port 80, unnamed: no name match, no number match (80 ∉ {8081,8082}).
        let mut service = http_mesh_service("reviews", 80, spiffe);
        service.ports[0].name = None;
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![local],
            services: vec![service],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "an ambiguous backend port must not materialize a (mis)routed inbound proxy"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_honor_numeric_target_port() {
        // A Service with a numeric targetPort distinct from `port`, backed by a
        // pod with multiple unnamed container ports — the shape that was
        // ambiguous before targetPort was captured. The route must target the
        // targetPort (the container port), not skip or guess.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut local = workload("reviews", "reviews");
        local.ports = vec![
            WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Tcp,
                name: None,
            },
            WorkloadPort {
                port: 9090,
                protocol: AppProtocol::Tcp,
                name: None,
            },
        ];
        let mut service = http_mesh_service("reviews", 80, spiffe);
        service.ports[0].name = None;
        service.ports[0].target_port = Some(ServiceTargetPort::Number(9090));
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![local],
            services: vec![service],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        let route = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-inbound-default-reviews-80")
            .expect("route materialized via numeric targetPort");
        assert_eq!(
            route.backend_port, 9090,
            "a numeric targetPort must select the container port directly"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_honor_named_target_port() {
        // A named targetPort resolves against the CONTAINER port name, which can
        // differ from the Service port's own name — so name resolution must use
        // targetPort, not the service port name.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut local = workload("reviews", "reviews");
        local.ports = vec![
            WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("web".to_string()),
            },
            WorkloadPort {
                port: 9090,
                protocol: AppProtocol::Http,
                name: Some("admin".to_string()),
            },
        ];
        // Service port named "http"; targetPort names the "admin" container port.
        let mut service = http_mesh_service("reviews", 80, spiffe);
        service.ports[0].target_port = Some(ServiceTargetPort::Name("admin".to_string()));
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![local],
            services: vec![service],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        let route = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-inbound-default-reviews-80")
            .expect("route materialized via named targetPort");
        assert_eq!(
            route.backend_port, 9090,
            "a named targetPort must resolve to the matching container port, \
             not the service port's own name"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_exclude_remote_cluster_workloads() {
        // A multi-cluster slice carries a remote workload that shares this
        // sidecar's SPIFFE id, service, and labels but originates in another
        // cluster (cluster = Some(...)). It must not be treated as local — else
        // it could replace the loopback route and point the backend at a remote
        // container port. Only the local (untagged) workload's port is used.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let local = workload("reviews", "reviews"); // cluster: None, port http=8080
        let mut remote = workload("reviews", "reviews");
        remote.cluster = Some("remote-west".to_string());
        remote.ports = vec![WorkloadPort {
            port: 9999,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }];
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![local, remote],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        let inbound: Vec<&str> = config
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("__mesh-inbound-"))
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(
            inbound,
            vec!["__mesh-inbound-default-reviews-8080"],
            "exactly one local inbound route"
        );
        let route = config
            .proxies
            .iter()
            .find(|p| p.id == "__mesh-inbound-default-reviews-8080")
            .expect("reviews route");
        assert_eq!(
            route.backend_port, 8080,
            "must target the LOCAL workload's port, not the remote cluster's"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_yield_to_host_only_operator_proxy() {
        // An operator host-only proxy (listen_path: None) routes every path for
        // the service host and sits in the router's host-only fallback tier. Our
        // materialized "/" prefix route would shadow it, so we must yield.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        // An operator host-only proxy (matches every path for the host).
        let mut config = GatewayConfig::default();
        let mut host_only = mesh_inbound_loopback_proxy(
            "operator-host-only",
            mesh_service_host_variants("reviews", "default", "cluster.local"),
            "default",
            7777,
            chrono::Utc::now(),
        );
        host_only.listen_path = None;
        config.proxies.push(host_only);

        materialize_sidecar_inbound_proxies(&mut config, &runtime, &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "must yield to a same-host host-only operator proxy"
        );
        assert!(
            config.proxies.iter().any(|p| p.id == "operator-host-only"),
            "the operator's host-only proxy must be left intact"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_allow_local_cluster_tagged_workload() {
        // A VM/WorkloadEntry local workload carries the local cluster name. With
        // the slice's `multi_cluster.local_cluster` matching, it must be treated
        // as local and materialize a route — not dropped as if it were remote.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut local = workload("reviews", "reviews");
        local.cluster = Some("cluster-a".to_string());
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![local],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            multi_cluster: Some(MultiClusterConfig {
                local_cluster: Some("cluster-a".to_string()),
                ..MultiClusterConfig::default()
            }),
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            config
                .proxies
                .iter()
                .any(|p| p.id == "__mesh-inbound-default-reviews-8080"),
            "a workload tagged with the local cluster name must materialize a route"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_yield_to_regex_operator_route() {
        // An operator regex route (`~...`) on the service host is searched after
        // the prefix tier, so our materialized `/` prefix would shadow it. Yield.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        let mut config = GatewayConfig::default();
        let mut regex_route = mesh_inbound_loopback_proxy(
            "operator-regex",
            mesh_service_host_variants("reviews", "default", "cluster.local"),
            "default",
            7777,
            chrono::Utc::now(),
        );
        regex_route.listen_path = Some("~^/api/.*".to_string());
        config.proxies.push(regex_route);

        materialize_sidecar_inbound_proxies(&mut config, &runtime, &slice);
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "must yield to a same-host regex operator route"
        );
        assert!(config.proxies.iter().any(|p| p.id == "operator-regex"));
    }

    #[test]
    fn sidecar_inbound_proxies_ignore_stream_proxies_in_overlap() {
        // A TCP stream proxy carries empty hosts + null listen_path (it routes by
        // listen_port). It must NOT read as a host-only catch-all that suppresses
        // HTTP inbound materialization, matching `validate_unique_listen_paths`.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        let mut config = GatewayConfig::default();
        let mut tcp_proxy = mesh_inbound_loopback_proxy(
            "operator-tcp",
            Vec::new(),
            "default",
            9000,
            chrono::Utc::now(),
        );
        tcp_proxy.listen_path = None;
        tcp_proxy.hosts = Vec::new();
        tcp_proxy.dispatch_kind = crate::config::types::DispatchKind::TcpRaw;
        config.proxies.push(tcp_proxy);

        materialize_sidecar_inbound_proxies(&mut config, &runtime, &slice);
        assert!(
            config
                .proxies
                .iter()
                .any(|p| p.id == "__mesh-inbound-default-reviews-8080"),
            "a stream proxy must not suppress HTTP inbound materialization"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_use_local_inbound_services_view() {
        // Sidecar egress narrowing can drop the local service from `services`.
        // Inbound serving must not be gated by egress scope, so the materializer
        // reads the un-narrowed `local_inbound_services` view. Here `services`
        // is empty (as if fully egress-narrowed) yet the route still materializes
        // from `local_inbound_services`.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: Vec::new(),
            local_inbound_workloads: Some(vec![workload("reviews", "reviews")]),
            local_inbound_services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            config
                .proxies
                .iter()
                .any(|p| p.id == "__mesh-inbound-default-reviews-8080"),
            "must materialize from the un-narrowed local_inbound_services view \
             even when egress narrowing emptied `services`"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_when_resolved_view_is_ambiguous_empty() {
        // The slice builder resolved the local-inbound view but found it
        // ambiguous (shared SPIFFE, no labels) → Some(empty). The narrowed
        // `workloads`/`services` here WOULD materialize a single service via the
        // fallback path, but the authoritative empty view must win: skip, never
        // fall back to the narrowed sets (which could collapse the ambiguity to
        // one wrong service).
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![workload("reviews", "reviews")],
            services: vec![http_mesh_service("reviews", 8080, spiffe)],
            local_inbound_workloads: Some(Vec::new()),
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "an authoritative empty (ambiguous) inbound view must skip, not fall back to \
             the narrowed workloads/services"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_use_preserved_local_workload_when_narrowed() {
        // Sidecar identity narrowing can drop the local workload from
        // `workloads`. The preserved `local_inbound_workloads` view must let the
        // materializer still find it (and its container port). Here `workloads`
        // is empty (as if identity-narrowed) yet the route materializes.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..test_mesh_runtime_config()
        };
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: Vec::new(),
            services: Vec::new(),
            local_inbound_workloads: Some(vec![workload("reviews", "reviews")]),
            local_inbound_services: vec![http_mesh_service("reviews", 8080, spiffe)],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            config
                .proxies
                .iter()
                .any(|p| p.id == "__mesh-inbound-default-reviews-8080"),
            "must materialize from the preserved local_inbound_workloads view when \
             identity narrowing emptied `workloads`"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_ambiguous_shared_spiffe_without_labels() {
        // Two workloads share the service-account SPIFFE but back different
        // services, and the sidecar carries no labels to disambiguate. The local
        // identity is ambiguous, so NO inbound route is materialized (rather than
        // routing to the wrong loopback app).
        let shared = "spiffe://cluster.local/ns/default/sa/shared";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(shared.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut reviews = workload("reviews", "reviews");
        reviews.spiffe_id = SpiffeId::new(shared).unwrap();
        let mut ratings = workload("ratings", "ratings");
        ratings.spiffe_id = SpiffeId::new(shared).unwrap();
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            workloads: vec![reviews, ratings],
            services: vec![
                http_mesh_service("reviews", 8080, shared),
                http_mesh_service("ratings", 8080, shared),
            ],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "ambiguous shared-SPIFFE local identity without labels must not materialize routes"
        );
    }

    #[test]
    fn sidecar_inbound_proxies_skip_ambiguous_shared_spiffe_with_matching_labels() {
        // Two workloads share the service-account SPIFFE AND the same labels but
        // back different services. The sidecar's labels match BOTH, so labels do
        // not disambiguate (they aren't pod-unique) — the identity is still
        // ambiguous and must materialize NO routes.
        let shared = "spiffe://cluster.local/ns/default/sa/shared";
        let runtime = MeshRuntimeConfig {
            workload_spiffe_id: Some(shared.to_string()),
            ..test_mesh_runtime_config()
        };
        let mut reviews = workload("reviews", "shared-app");
        reviews.spiffe_id = SpiffeId::new(shared).unwrap();
        let mut ratings = workload("ratings", "shared-app");
        ratings.spiffe_id = SpiffeId::new(shared).unwrap();
        let slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "test".to_string(),
            labels: BTreeMap::from([("app".to_string(), "shared-app".to_string())]),
            workloads: vec![reviews, ratings],
            services: vec![
                http_mesh_service("reviews", 8080, shared),
                http_mesh_service("ratings", 8080, shared),
            ],
            ..MeshSlice::default()
        };

        let config =
            gateway_config_from_mesh_slice(&slice, &runtime, None, None).expect("slice → config");
        assert!(
            !config
                .proxies
                .iter()
                .any(|p| p.id.starts_with("__mesh-inbound-")),
            "labels matching multiple shared-SPIFFE services must not materialize routes"
        );
    }

    #[test]
    fn waypoint_name_only_propagates_for_service_waypoint_topology() {
        let mut runtime = test_mesh_runtime_config();
        runtime.waypoint_name = Some("api-waypoint".to_string());

        assert_eq!(runtime.native_client_config().waypoint_name, None);
        assert_eq!(runtime.xds_client_config().waypoint_name, None);
        assert_eq!(runtime.mesh_slice_request().waypoint_name, None);

        runtime.topology = MeshTopology::ServiceWaypoint;

        assert_eq!(
            runtime.native_client_config().waypoint_name.as_deref(),
            Some("api-waypoint")
        );
        assert_eq!(
            runtime.xds_client_config().waypoint_name.as_deref(),
            Some("api-waypoint")
        );
        assert_eq!(
            runtime.mesh_slice_request().waypoint_name.as_deref(),
            Some("api-waypoint")
        );
    }

    fn make_test_proxy_state(initial_config: GatewayConfig) -> ProxyState {
        ProxyState::new(
            initial_config,
            DnsCache::new(DnsConfig::default()),
            EnvConfig {
                pool_warmup_enabled: false,
                shutdown_drain_seconds: 0,
                ..EnvConfig::default()
            },
            None,
            None,
        )
        .expect("ProxyState construction should succeed in tests")
        .0
    }

    fn make_test_proxy_state_with_env(initial_config: GatewayConfig, env: EnvConfig) -> ProxyState {
        ensure_crypto_provider();
        let tls_policy = TlsPolicy::from_env_config(&env).expect("test TLS policy");
        ProxyState::new(
            initial_config,
            DnsCache::new(DnsConfig::default()),
            env,
            Some(tls_policy),
            None,
        )
        .expect("ProxyState construction should succeed in tests")
        .0
    }

    fn destination_rule_test_upstream(id: &str, host: &str) -> Upstream {
        let now = chrono::Utc::now();
        Upstream {
            id: id.to_string(),
            namespace: "default".to_string(),
            name: Some(id.to_string()),
            targets: vec![UpstreamTarget {
                host: host.to_string(),
                port: 8080,
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            }],
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn destination_rule_test_proxy(id: &str, upstream_id: &str) -> Proxy {
        // PR a8dce394 scoped DestinationRule application to namespace, so
        // the test proxy must share the namespace of the test upstream and
        // the test DR (both `"default"`) — otherwise the namespace gate
        // skips the projection and tests inherit the un-updated upstream
        // defaults. `destination_rule_does_not_apply_across_namespaces`
        // covers the cross-namespace deny path explicitly.
        serde_json::from_value(serde_json::json!({
            "id": id,
            "namespace": "default",
            "hosts": [format!("{id}.example.com")],
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": upstream_id
        }))
        .expect("test proxy")
    }

    #[test]
    fn destination_rule_applies_short_host_to_all_matching_upstreams() {
        let mut config = GatewayConfig {
            proxies: vec![
                destination_rule_test_proxy("p1", "u1"),
                destination_rule_test_proxy("p2", "u2"),
            ],
            upstreams: vec![
                destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local"),
                destination_rule_test_upstream("u2", "reviews.default.svc.cluster.local"),
            ],
            ..GatewayConfig::default()
        };
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connect_timeout_ms: Some(1234),
                    load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        assert!(
            config
                .upstreams
                .iter()
                .all(|upstream| upstream.algorithm == LoadBalancerAlgorithm::Random)
        );
        assert!(
            config
                .proxies
                .iter()
                .all(|proxy| proxy.backend_connect_timeout_ms == 1234)
        );
    }

    #[test]
    fn destination_rule_does_not_apply_across_namespaces() {
        let mut victim_upstream =
            destination_rule_test_upstream("u-victim", "reviews.victim.svc.cluster.local");
        victim_upstream.namespace = "victim".to_string();
        let mut victim_proxy = destination_rule_test_proxy("p-victim", "u-victim");
        victim_proxy.namespace = "victim".to_string();

        let config = GatewayConfig {
            proxies: vec![victim_proxy],
            upstreams: vec![victim_upstream],
            mesh: Some(Box::new(MeshConfig {
                destination_rules: vec![MeshDestinationRule {
                    name: "reviews".to_string(),
                    namespace: "attacker".to_string(),
                    host: "reviews.victim.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(1),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: vec![MeshSubset {
                        name: "attacker-subset".to_string(),
                        labels: HashMap::from([("version".to_string(), "v2".to_string())]),
                        traffic_policy: None,
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let original_timeout_ms = config.proxies[0].backend_connect_timeout_ms;
        let runtime = MeshRuntimeConfig {
            namespace: "victim".to_string(),
            ..test_mesh_runtime_config()
        };

        let config =
            prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

        assert_eq!(
            config.upstreams[0].algorithm,
            LoadBalancerAlgorithm::RoundRobin
        );
        assert!(config.upstreams[0].subsets.is_none());
        assert_eq!(
            config.proxies[0].backend_connect_timeout_ms,
            original_timeout_ms
        );
    }

    #[test]
    fn destination_rule_apply_order_is_deterministic_by_namespace_then_name() {
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        // Insert in reverse alphabetical order; sort by (namespace, name) means
        // "default/a-first" applies first and "default/z-last" wins.
        let slice = MeshSlice {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "z-last".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(9999),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "a-first".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(1111),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        assert_eq!(config.upstreams[0].algorithm, LoadBalancerAlgorithm::Random);
        assert_eq!(config.proxies[0].backend_connect_timeout_ms, 9999);
    }

    #[test]
    fn later_destination_rule_without_locality_lb_clears_earlier_projection() {
        let mut config = GatewayConfig {
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let mut distribute_to = BTreeMap::new();
        distribute_to.insert("us-west".to_string(), 100);
        let slice = MeshSlice {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "a-locality".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)),
                        locality_lb_setting: Some(
                            crate::modes::mesh::config::MeshLocalityLbSetting {
                                enabled: true,
                                distribute: vec![
                                    crate::modes::mesh::config::MeshLocalityDistribute {
                                        from: "us-west/us-west-1/a".to_string(),
                                        to: distribute_to,
                                    },
                                ],
                                failover: Vec::new(),
                            },
                        ),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "z-no-locality".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        assert_eq!(config.upstreams[0].algorithm, LoadBalancerAlgorithm::Random);
        assert!(
            config.upstreams[0].locality_lb_setting.is_none(),
            "later trafficPolicy without localityLbSetting must clear stale locality LB"
        );
    }

    // ── DestinationRule trafficPolicy.tls cold-path apply ──────────────

    #[test]
    fn dr_tls_none_preserves_existing_upstream_backend_tls() {
        // When MeshTrafficPolicy.tls is None the upstream's existing
        // backend_tls_* fields must NOT be touched — PeerAuthentication
        // defaults continue to drive the mTLS posture.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/pre/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/pre/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/pre/ca.pem".to_string());
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            connect_timeout_ms: Some(1000),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        // backend_tls_* untouched.
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/pre/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/pre/client.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/pre/ca.pem")
        );
        assert!(upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_simple_projects_ca_and_clears_client_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/stale/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/stale/client.key".to_string());

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some("reviews.example.com".to_string()),
                ca_certificates: Some("/etc/certs/ca.pem".to_string()),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/ca.pem")
        );
        assert!(upstream.backend_tls_client_cert_path.is_none());
        assert!(upstream.backend_tls_client_key_path.is_none());
        assert!(upstream.backend_tls_verify_server_cert);
        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some("reviews.example.com")
        );
    }

    #[test]
    fn dr_tls_mutual_projects_full_mtls_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Mutual,
                ca_certificates: Some("/etc/certs/ca.pem".to_string()),
                client_certificate: Some("/etc/certs/client.pem".to_string()),
                private_key: Some("/etc/certs/client.key".to_string()),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/etc/certs/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/etc/certs/client.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/ca.pem")
        );
        assert!(upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_disable_clears_upstream_backend_tls_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/pre/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/pre/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/pre/ca.pem".to_string());
        upstream.backend_tls_sni = Some("stale.mesh.internal".to_string());
        upstream.backend_tls_san_allow_list = vec!["stale.mesh.internal".to_string()];
        // Pre-set verify=true and confirm DISABLE without insecure_skip_verify
        // leaves it at its current value (the comment on
        // `apply_traffic_policy_tls_to_upstream` documents this invariant).
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Disable,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert!(upstream.backend_tls_client_cert_path.is_none());
        assert!(upstream.backend_tls_client_key_path.is_none());
        assert!(upstream.backend_tls_server_ca_cert_path.is_none());
        assert!(upstream.backend_tls_sni.is_none());
        assert!(upstream.backend_tls_san_allow_list.is_empty());
        assert!(
            upstream.backend_tls_verify_server_cert,
            "DISABLE without insecure_skip_verify must preserve the existing \
             backend_tls_verify_server_cert value (was true before apply)"
        );
    }

    #[test]
    fn dr_tls_disable_with_insecure_skip_verify_flips_verify_false() {
        // Even on DISABLE the explicit `insecureSkipVerify=true` must force
        // backend_tls_verify_server_cert=false — `insecure_skip_verify` has
        // operator-intent precedence over the mode-derived defaults.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Disable,
                insecure_skip_verify: true,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert!(!upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_insecure_skip_verify_forces_verify_false() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                insecure_skip_verify: true,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert!(!upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_istio_mutual_projects_runtime_svid_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/stale/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/stale/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/stale/ca.pem".to_string());
        upstream.backend_tls_verify_server_cert = false;
        let runtime = MeshRuntimeConfig {
            workload_svid_cert_path: Some("/var/run/secrets/ferrum/svid.pem".to_string()),
            workload_svid_key_path: Some("/var/run/secrets/ferrum/svid.key".to_string()),
            workload_svid_trust_bundle_path: Some(
                "/var/run/secrets/ferrum/trust-bundle.pem".to_string(),
            ),
            ..test_mesh_runtime_config()
        };

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::IstioMutual,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &runtime)
            .expect("traffic policy applies");

        assert!(upstream.backend_tls_verify_server_cert);
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/var/run/secrets/ferrum/svid.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/var/run/secrets/ferrum/svid.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/var/run/secrets/ferrum/trust-bundle.pem")
        );
    }

    #[test]
    fn dr_tls_istio_mutual_without_svid_fails_closed() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/existing/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/existing/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/stale/ca.pem".to_string());
        upstream.backend_tls_verify_server_cert = false;
        let runtime = MeshRuntimeConfig {
            workload_svid_cert_path: None,
            workload_svid_key_path: None,
            workload_svid_trust_bundle_path: None,
            ..test_mesh_runtime_config()
        };

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::IstioMutual,
                sni: Some("reviews.mesh.internal".to_string()),
                subject_alt_names: vec!["reviews.mesh.internal".to_string()],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        let err = apply_traffic_policy_to_upstream(&mut upstream, &policy, &runtime)
            .expect_err("ISTIO_MUTUAL without SVID cert/key must fail closed");

        assert!(
            err.to_string()
                .contains("requires FERRUM_GATEWAY_SVID_CERT_PATH"),
            "got: {err}"
        );
    }

    #[test]
    fn dr_tls_sni_and_sans_project_onto_upstream() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some("reviews.mesh.internal".to_string()),
                subject_alt_names: vec![
                    "reviews.mesh.internal".to_string(),
                    "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                ],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some("reviews.mesh.internal")
        );
        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec![
                "reviews.mesh.internal".to_string(),
                "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
            ]
        );
    }

    #[test]
    fn dr_tls_drops_invalid_sni_and_sans_before_projection() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_sni = Some("stale.mesh.internal".to_string());
        upstream.backend_tls_san_allow_list = vec!["stale.mesh.internal".to_string()];
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some("bad host name".to_string()),
                subject_alt_names: vec![
                    "REVIEWS.Mesh.Internal".to_string(),
                    "10.0.0.8".to_string(),
                    "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                    "https://not-accepted.example".to_string(),
                    String::new(),
                ],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert!(upstream.backend_tls_sni.is_none());
        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec![
                "reviews.mesh.internal".to_string(),
                "10.0.0.8".to_string(),
                "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
            ]
        );
    }

    #[test]
    fn dr_tls_drops_overlong_sni_before_projection() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some(format!("{}.mesh.internal", "a".repeat(300))),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert!(upstream.backend_tls_sni.is_none());
    }

    #[test]
    fn dr_tls_san_allow_list_drops_entries_over_mesh_limit() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                subject_alt_names: (0..=MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES)
                    .map(|i| format!("san-{i}.mesh.internal"))
                    .collect(),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert_eq!(
            upstream.backend_tls_san_allow_list.len(),
            MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES
        );
        assert_eq!(
            upstream
                .backend_tls_san_allow_list
                .last()
                .map(String::as_str),
            Some("san-255.mesh.internal")
        );
    }

    #[test]
    fn dr_tls_san_allow_list_drops_overlong_entries() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                subject_alt_names: vec![
                    "reviews.mesh.internal".to_string(),
                    format!(
                        "{}.mesh.internal",
                        "a".repeat(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH)
                    ),
                ],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config())
            .expect("traffic policy applies");

        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec!["reviews.mesh.internal".to_string()]
        );
    }

    #[test]
    fn dr_tls_flows_end_to_end_through_apply_destination_rules() {
        // Integration-style: a DR with trafficPolicy.tls produces an
        // upstream whose backend_tls_* fields reflect the DR settings.
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-mtls".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::Mutual,
                        ca_certificates: Some("/etc/certs/ca.pem".to_string()),
                        client_certificate: Some("/etc/certs/client.pem".to_string()),
                        private_key: Some("/etc/certs/client.key".to_string()),
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let upstream = &config.upstreams[0];
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/etc/certs/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/etc/certs/client.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/ca.pem")
        );
        assert!(upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_subset_tls_overrides_upstream_level_tls_at_apply() {
        // A DestinationRule that sets BOTH upstream-level `trafficPolicy.tls`
        // AND per-subset `trafficPolicy.tls` must produce:
        //   - Upstream-level fields (`upstream.backend_tls_*`) reflect the
        //     top-level TLS — so proxies that DON'T select the subset still
        //     pick up upstream-level TLS.
        //   - `upstream.resolved_subset_tls["v1"]` carries the subset's
        //     overlaid `BackendTlsConfig` (subset CA / SNI / mTLS material)
        //     so `resolve_upstream_tls` can swap it into `Proxy.resolved_tls`
        //     for proxies whose `upstream_subset == "v1"`.
        //
        // Proves that subset TLS overrides upstream-level TLS rather than
        // merging into it: the v1 subset's CA replaces the upstream-level CA
        // for v1 dispatch, not "in addition to."
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::Simple,
                        ca_certificates: Some("/etc/certs/upstream-ca.pem".to_string()),
                        sni: Some("reviews.default.svc.cluster.local".to_string()),
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: vec![MeshSubset {
                    name: "v1".to_string(),
                    labels: HashMap::from([("version".to_string(), "v1".to_string())]),
                    traffic_policy: Some(MeshTrafficPolicy {
                        tls: Some(MeshTrafficPolicyTls {
                            mode: MtlsMode::Mutual,
                            ca_certificates: Some("/etc/certs/v1-ca.pem".to_string()),
                            client_certificate: Some("/etc/certs/v1-client.pem".to_string()),
                            private_key: Some("/etc/certs/v1-client.key".to_string()),
                            sni: Some("v1.reviews.mesh.internal".to_string()),
                            ..MeshTrafficPolicyTls::default()
                        }),
                        ..MeshTrafficPolicy::default()
                    }),
                }],
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let upstream = &config.upstreams[0];
        // Upstream-level TLS reflects the top-level DR.tls.
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/upstream-ca.pem"),
            "upstream CA still reflects upstream-level DR.tls"
        );
        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some("reviews.default.svc.cluster.local")
        );
        assert!(upstream.backend_tls_client_cert_path.is_none());

        // Per-subset overlay landed on `resolved_subset_tls`.
        let subset_tls = upstream
            .resolved_subset_tls
            .get("v1")
            .expect("v1 subset has resolved TLS")
            .tls
            .as_ref()
            .expect("v1 resolved tls is Some");
        assert_eq!(
            subset_tls.server_ca_cert_path.as_deref(),
            Some("/etc/certs/v1-ca.pem"),
            "subset overlay swaps the CA for v1 dispatch"
        );
        assert_eq!(
            subset_tls.client_cert_path.as_deref(),
            Some("/etc/certs/v1-client.pem")
        );
        assert_eq!(
            subset_tls.client_key_path.as_deref(),
            Some("/etc/certs/v1-client.key")
        );
        assert_eq!(
            subset_tls.sni.as_deref(),
            Some("v1.reviews.mesh.internal"),
            "subset overlay also wins on SNI"
        );
        assert!(subset_tls.verify_server_cert);
    }

    #[test]
    fn dr_subset_connect_timeout_overrides_top_level_for_subset_bound_proxies() {
        // Istio precedence: a subset's `trafficPolicy.connectionPool.tcp.connectTimeout`
        // overrides the DR top-level connectTimeout for proxies bound to that
        // subset, while proxies with no subset keep the top-level value.
        let mut config = GatewayConfig {
            // p1 has no upstream_subset — keeps the top-level connectTimeout.
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        // p2 selects subset v1 — picks up the subset's connectTimeout.
        let mut p2: Proxy = serde_json::from_value(serde_json::json!({
            "id": "p2",
            "namespace": "default",
            "hosts": ["p2.example.com"],
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "u1",
            "upstream_subset": "v1",
        }))
        .expect("test proxy with subset");
        p2.normalize_fields();
        config.proxies.push(p2);

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connect_timeout_ms: Some(5000),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: vec![MeshSubset {
                    name: "v1".to_string(),
                    labels: HashMap::from([("version".to_string(), "v1".to_string())]),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(2000),
                        ..MeshTrafficPolicy::default()
                    }),
                }],
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let p1 = config.proxies.iter().find(|p| p.id == "p1").expect("p1");
        let p2 = config.proxies.iter().find(|p| p.id == "p2").expect("p2");
        assert_eq!(
            p1.backend_connect_timeout_ms, 5000,
            "non-subset proxy uses the DR top-level connectTimeout"
        );
        assert_eq!(
            p2.backend_connect_timeout_ms, 2000,
            "subset-bound proxy uses its subset's connectTimeout (overrides top-level)"
        );
    }

    #[test]
    fn dr_later_rule_top_level_connect_timeout_overrides_earlier_subset() {
        // Two DestinationRules match the same upstream. The earlier-sorted rule
        // defines subset v1 with its own connectTimeout; the later-sorted rule
        // has no subsets but sets a top-level connectTimeout. Last-writer-wins:
        // the later top-level must override the subset-bound proxy even though an
        // earlier rule already populated upstream.subsets. Regression guard for
        // reading the accumulated upstream.subsets instead of the current rule's.
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let mut p2: Proxy = serde_json::from_value(serde_json::json!({
            "id": "p2",
            "namespace": "default",
            "hosts": ["p2.example.com"],
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "u1",
            "upstream_subset": "v1",
        }))
        .expect("test proxy with subset");
        p2.normalize_fields();
        config.proxies.push(p2);

        let slice = MeshSlice {
            destination_rules: vec![
                // Earlier (name "reviews-a"): defines subset v1, no top-level.
                MeshDestinationRule {
                    name: "reviews-a".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: vec![MeshSubset {
                        name: "v1".to_string(),
                        labels: HashMap::from([("version".to_string(), "v1".to_string())]),
                        traffic_policy: Some(MeshTrafficPolicy {
                            connect_timeout_ms: Some(2000),
                            ..MeshTrafficPolicy::default()
                        }),
                    }],
                },
                // Later (name "reviews-b"): no subsets, top-level connectTimeout.
                MeshDestinationRule {
                    name: "reviews-b".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(8000),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let p1 = config.proxies.iter().find(|p| p.id == "p1").expect("p1");
        let p2 = config.proxies.iter().find(|p| p.id == "p2").expect("p2");
        assert_eq!(
            p1.backend_connect_timeout_ms, 8000,
            "non-subset proxy uses the later rule's top-level connectTimeout"
        );
        assert_eq!(
            p2.backend_connect_timeout_ms, 8000,
            "subset-bound proxy must adopt the later rule's top-level connectTimeout, \
             not a stale subset timeout from the earlier rule"
        );
    }

    #[test]
    fn dr_port_level_tls_resolves_onto_port_override() {
        // portLevelSettings[].tls is resolved per-port (over the upstream-level
        // TLS base) and lands on Upstream.port_overrides[port].tls, ready to
        // project onto the effective proxy's resolved_tls at dispatch.
        let mut config = GatewayConfig {
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "secure.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        // The test upstream serves port 8080; use it so the entry is not skipped
        // as a phantom port.
        let mut port_level = HashMap::new();
        port_level.insert(
            8080u16,
            MeshTrafficPolicy {
                tls: Some(MeshTrafficPolicyTls {
                    mode: MtlsMode::Simple,
                    ca_certificates: Some("/etc/certs/port-8080-ca.pem".to_string()),
                    sni: Some("port8080.secure.internal".to_string()),
                    ..MeshTrafficPolicyTls::default()
                }),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "secure".to_string(),
                namespace: "default".to_string(),
                host: "secure.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: port_level,
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let override_slot = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .expect("port 8080 override exists");
        let tls = override_slot
            .tls
            .as_ref()
            .expect("port 8080 resolved backend TLS");
        assert_eq!(
            tls.server_ca_cert_path.as_deref(),
            Some("/etc/certs/port-8080-ca.pem"),
            "per-port TLS resolves the CA for port 8080"
        );
        assert_eq!(tls.sni.as_deref(), Some("port8080.secure.internal"));
    }

    #[test]
    fn dr_subset_outlier_resolves_passive_health_thresholds() {
        // A subset's outlierDetection thresholds resolve into the subset's
        // passive-health overlay on `Upstream.resolved_subset_tls`, consulted by
        // `passive_health_for_target` for proxies bound to the subset.
        let mut config = GatewayConfig {
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: vec![MeshSubset {
                    name: "v1".to_string(),
                    labels: HashMap::from([("version".to_string(), "v1".to_string())]),
                    traffic_policy: Some(MeshTrafficPolicy {
                        outlier_detection: Some(MeshOutlierDetection {
                            consecutive_errors: Some(5),
                            interval_seconds: Some(20),
                            base_ejection_seconds: None,
                            max_ejection_percent: None,
                        }),
                        ..MeshTrafficPolicy::default()
                    }),
                }],
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let resolved = config.upstreams[0]
            .resolved_subset_tls
            .get("v1")
            .expect("v1 subset resolved");
        let passive = resolved
            .passive_health_check
            .as_ref()
            .expect("v1 subset passive health resolved from outlierDetection");
        assert_eq!(passive.unhealthy_threshold, 5);
        assert_eq!(passive.unhealthy_window_seconds, 20);
    }

    #[test]
    fn dr_subset_tls_projects_onto_proxy_resolved_tls_via_resolve_upstream_tls() {
        // End-to-end: subset overlay reaches `Proxy.resolved_tls` so the pool
        // key construction (which consumes `proxy.resolved_tls`) naturally
        // fragments per subset.
        let mut config = GatewayConfig {
            proxies: vec![
                // p1 has no upstream_subset — picks up upstream-level TLS.
                destination_rule_test_proxy("p1", "u1"),
            ],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        // p2 selects subset v1 — should pick up the subset overlay.
        let mut p2: Proxy = serde_json::from_value(serde_json::json!({
            "id": "p2",
            "hosts": ["p2.example.com"],
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "u1",
            "upstream_subset": "v1",
        }))
        .expect("test proxy with subset");
        p2.normalize_fields();
        config.proxies.push(p2);

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::Simple,
                        ca_certificates: Some("/etc/certs/upstream-ca.pem".to_string()),
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: vec![MeshSubset {
                    name: "v1".to_string(),
                    labels: HashMap::from([("version".to_string(), "v1".to_string())]),
                    traffic_policy: Some(MeshTrafficPolicy {
                        tls: Some(MeshTrafficPolicyTls {
                            mode: MtlsMode::Simple,
                            ca_certificates: Some("/etc/certs/v1-ca.pem".to_string()),
                            ..MeshTrafficPolicyTls::default()
                        }),
                        ..MeshTrafficPolicy::default()
                    }),
                }],
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");
        config.resolve_upstream_tls();

        let p1 = config.proxies.iter().find(|p| p.id == "p1").expect("p1");
        let p2 = config.proxies.iter().find(|p| p.id == "p2").expect("p2");

        assert_eq!(
            p1.resolved_tls.server_ca_cert_path.as_deref(),
            Some("/etc/certs/upstream-ca.pem"),
            "proxy without upstream_subset gets upstream-level CA"
        );
        assert_eq!(
            p2.resolved_tls.server_ca_cert_path.as_deref(),
            Some("/etc/certs/v1-ca.pem"),
            "proxy with upstream_subset='v1' gets subset overlay CA"
        );
    }

    #[test]
    fn dr_subset_without_tls_falls_back_to_upstream_level_tls() {
        // A subset without `trafficPolicy.tls` must NOT populate
        // `resolved_subset_tls`, so `resolve_upstream_tls` falls back to the
        // upstream-level posture for proxies that select that subset.
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::Simple,
                        ca_certificates: Some("/etc/certs/upstream-ca.pem".to_string()),
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: vec![MeshSubset {
                    name: "v1".to_string(),
                    labels: HashMap::from([("version".to_string(), "v1".to_string())]),
                    // Subset carries a load_balancer override but no TLS.
                    traffic_policy: Some(MeshTrafficPolicy {
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                }],
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let upstream = &config.upstreams[0];
        assert!(
            upstream.resolved_subset_tls.is_empty(),
            "subset without trafficPolicy.tls must not populate resolved_subset_tls"
        );
        // The non-TLS subset traffic-policy fields still translate.
        let subsets = upstream.subsets.as_ref().expect("subsets present");
        let v1 = &subsets[0];
        assert_eq!(
            v1.traffic_policy
                .as_ref()
                .expect("v1 traffic policy")
                .load_balancer_algorithm,
            Some(LoadBalancerAlgorithm::Random)
        );
    }

    #[test]
    fn dr_subset_tls_apply_clears_stale_resolved_subset_tls() {
        // A DR application that overwrites `upstream.subsets` (e.g., the next
        // slice removed the v1 subset) must also clear any stale
        // `resolved_subset_tls` entries — otherwise a proxy that still
        // references the removed subset name would silently get its old TLS
        // overlay through `resolve_upstream_tls`.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.resolved_subset_tls.insert(
            "ghost".to_string(),
            ResolvedSubsetTrafficPolicy {
                tls: Some(BackendTlsConfig {
                    server_ca_cert_path: Some("/etc/certs/stale-ca.pem".to_string()),
                    ..BackendTlsConfig::default_verify()
                }),
                passive_health_check: None,
            },
        );
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![upstream],
            ..GatewayConfig::default()
        };

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                // New slice carries a different subset that has NO TLS.
                subsets: vec![MeshSubset {
                    name: "v2".to_string(),
                    labels: HashMap::from([("version".to_string(), "v2".to_string())]),
                    traffic_policy: None,
                }],
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let upstream = &config.upstreams[0];
        assert!(
            !upstream.resolved_subset_tls.contains_key("ghost"),
            "stale resolved_subset_tls entry must be cleared on DR re-apply"
        );
        assert!(
            upstream.resolved_subset_tls.is_empty(),
            "no subsets carry TLS in the new slice, resolved map must be empty"
        );
    }

    #[test]
    fn dr_subset_tls_pool_key_differs_across_subsets() {
        // Two proxies that share `upstream_id` but select different subsets
        // must produce different backend pool keys, even when their TLS
        // material is byte-identical — `upstream_subset` enters the pool
        // key as a defense-in-depth backstop on top of TLS partitioning.
        let mut p_v1: Proxy = serde_json::from_value(serde_json::json!({
            "id": "p_v1",
            "hosts": ["p.example.com"],
            "backend_host": "reviews.default.svc.cluster.local",
            "backend_port": 8080,
            "backend_scheme": "https",
            "upstream_id": "u1",
            "upstream_subset": "v1",
        }))
        .expect("proxy v1");
        let mut p_v2: Proxy = serde_json::from_value(serde_json::json!({
            "id": "p_v2",
            "hosts": ["p.example.com"],
            "backend_host": "reviews.default.svc.cluster.local",
            "backend_port": 8080,
            "backend_scheme": "https",
            "upstream_id": "u1",
            "upstream_subset": "v2",
        }))
        .expect("proxy v2");
        p_v1.normalize_fields();
        p_v2.normalize_fields();
        // Identical resolved TLS — the subset name is the only differentiator.
        p_v1.resolved_tls = BackendTlsConfig::default_verify();
        p_v2.resolved_tls = BackendTlsConfig::default_verify();

        let pool_v1 = crate::http3::client::Http3ConnectionPool::pool_key_for_target(
            &p_v1,
            "reviews.default.svc.cluster.local",
            8080,
            0,
        );
        let pool_v2 = crate::http3::client::Http3ConnectionPool::pool_key_for_target(
            &p_v2,
            "reviews.default.svc.cluster.local",
            8080,
            0,
        );

        assert_ne!(
            pool_v1, pool_v2,
            "H3 pool keys must differ when upstream_subset differs, even with identical TLS"
        );
        assert!(pool_v1.contains("|v1|"), "v1 marker present in pool key");
        assert!(pool_v2.contains("|v2|"), "v2 marker present in pool key");
    }

    #[test]
    fn destination_rule_top_level_and_per_port_override_apply_independently() {
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let mut port_level = HashMap::new();
        port_level.insert(
            8080u16,
            MeshTrafficPolicy {
                connect_timeout_ms: Some(2222),
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connect_timeout_ms: Some(1111),
                    load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: port_level,
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        // Top-level policy still applies to the upstream itself.
        assert_eq!(
            config.upstreams[0].algorithm,
            LoadBalancerAlgorithm::RoundRobin
        );
        assert_eq!(config.proxies[0].backend_connect_timeout_ms, 1111);

        // Per-port policy lands on port_overrides[8080] without disturbing
        // the upstream-level fields or the proxy-default connect timeout.
        let port_8080 = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .expect("port 8080 override");
        assert_eq!(port_8080.connect_timeout_ms, Some(2222));
        assert_eq!(port_8080.algorithm, Some(LoadBalancerAlgorithm::Random));

        // Proof that the override is actually consulted at dispatch time via
        // the helper the hot path uses — port 8080 wins, other ports fall
        // back to the proxy default.
        let upstream = &config.upstreams[0];
        assert_eq!(upstream.effective_connect_timeout_ms(8080, 1111), 2222);
        assert_eq!(upstream.effective_connect_timeout_ms(9090, 1111), 1111);
    }

    #[test]
    fn destination_rule_two_per_port_overrides_land_on_distinct_slots() {
        // Upstream must expose BOTH ports the DR references — the phantom-
        // port filter in `apply_destination_rules` rejects per-port settings
        // whose port is not served by any target. Add a 9090 target so the
        // second DR entry has somewhere to land.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.targets.push(UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 9090,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        });
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![upstream],
            ..GatewayConfig::default()
        };
        let mut port_level = HashMap::new();
        port_level.insert(
            8080u16,
            MeshTrafficPolicy {
                connect_timeout_ms: Some(750),
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
                ..MeshTrafficPolicy::default()
            },
        );
        port_level.insert(
            9090u16,
            MeshTrafficPolicy {
                connect_timeout_ms: Some(3000),
                load_balancer: Some(MeshLoadBalancer::ConsistentHash(
                    crate::modes::mesh::config::MeshConsistentHash {
                        http_header_name: Some("x-user".to_string()),
                        http_cookie_name: None,
                        use_source_ip: false,
                    },
                )),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: port_level,
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let p8080 = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .expect("port 8080 override");
        assert_eq!(p8080.connect_timeout_ms, Some(750));
        assert_eq!(
            p8080.algorithm,
            Some(LoadBalancerAlgorithm::LeastConnections)
        );

        let p9090 = config.upstreams[0]
            .port_overrides
            .get(&9090)
            .expect("port 9090 override");
        assert_eq!(p9090.connect_timeout_ms, Some(3000));
        assert_eq!(
            p9090.algorithm,
            Some(LoadBalancerAlgorithm::ConsistentHashing)
        );
        assert_eq!(p9090.hash_on.as_deref(), Some("header:x-user"));

        // Effective-timeout helper is what the dispatch hot path consults.
        // Each port's own override wins; an unrelated port falls back to the
        // proxy default (here passed in as 5000ms).
        let upstream = &config.upstreams[0];
        assert_eq!(upstream.effective_connect_timeout_ms(8080, 5000), 750);
        assert_eq!(upstream.effective_connect_timeout_ms(9090, 5000), 3000);
        assert_eq!(upstream.effective_connect_timeout_ms(7777, 5000), 5000);
    }

    #[test]
    fn destination_rule_per_port_outlier_detection_merges_partial_overrides() {
        let mut config = GatewayConfig {
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let mut first_port_policy = HashMap::new();
        first_port_policy.insert(
            8080,
            MeshTrafficPolicy {
                outlier_detection: Some(MeshOutlierDetection {
                    consecutive_errors: Some(7),
                    interval_seconds: Some(30),
                    base_ejection_seconds: Some(60),
                    max_ejection_percent: Some(40),
                }),
                ..MeshTrafficPolicy::default()
            },
        );
        let mut second_port_policy = HashMap::new();
        second_port_policy.insert(
            8080,
            MeshTrafficPolicy {
                outlier_detection: Some(MeshOutlierDetection {
                    consecutive_errors: Some(2),
                    interval_seconds: None,
                    base_ejection_seconds: None,
                    max_ejection_percent: None,
                }),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "a-base".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: None,
                    port_level_settings: first_port_policy,
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "b-partial".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: None,
                    port_level_settings: second_port_policy,
                    subsets: Vec::new(),
                },
            ],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let passive = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .and_then(|override_config| override_config.passive_health_check.as_ref())
            .expect("port passive health");
        assert_eq!(passive.unhealthy_threshold, 2);
        assert_eq!(passive.unhealthy_window_seconds, 30);
        assert_eq!(passive.healthy_after_seconds, 60);
        assert_eq!(passive.max_ejection_percent, Some(40));
    }

    #[test]
    fn destination_rule_per_port_non_hash_policy_clears_stale_hash_key() {
        let mut config = GatewayConfig {
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let mut hash_policy = HashMap::new();
        hash_policy.insert(
            8080,
            MeshTrafficPolicy {
                load_balancer: Some(MeshLoadBalancer::ConsistentHash(
                    crate::modes::mesh::config::MeshConsistentHash {
                        http_header_name: Some("x-user".to_string()),
                        http_cookie_name: None,
                        use_source_ip: false,
                    },
                )),
                ..MeshTrafficPolicy::default()
            },
        );
        let mut random_policy = HashMap::new();
        random_policy.insert(
            8080,
            MeshTrafficPolicy {
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "a-hash".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: None,
                    port_level_settings: hash_policy,
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "b-random".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: None,
                    port_level_settings: random_policy,
                    subsets: Vec::new(),
                },
            ],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let port = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .expect("port 8080 override");
        assert_eq!(port.algorithm, Some(LoadBalancerAlgorithm::Random));
        assert!(
            port.hash_on.is_none(),
            "later non-hash policy must clear an earlier hash key"
        );
    }

    #[test]
    fn telemetry_tracing_merge_preserves_inherited_sampling_for_tag_only_override() {
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: "test".to_string(),
            workloads: Vec::new(),
            services: Vec::new(),
            local_inbound_services: Vec::new(),
            local_inbound_workloads: None,
            mesh_policies: Vec::new(),
            peer_authentications: Vec::new(),
            service_entries: Vec::new(),
            request_authentications: Vec::new(),
            telemetry_resources: vec![
                MeshTelemetryResource {
                    name: "mesh-defaults".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    config: MeshTelemetryConfig {
                        tracing: Some(MeshTracingConfig {
                            mode: None,
                            sampling_percentage: Some(100.0),
                            disable_span_reporting: Some(true),
                            custom_tags: HashMap::new(),
                            custom_header_tags: HashMap::new(),
                            providers: Vec::new(),
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
                MeshTelemetryResource {
                    name: "api-tags".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    config: MeshTelemetryConfig {
                        tracing: Some(MeshTracingConfig {
                            mode: None,
                            sampling_percentage: None,
                            disable_span_reporting: None,
                            custom_tags: HashMap::from([("env".to_string(), "prod".to_string())]),
                            custom_header_tags: HashMap::from([(
                                "tenant".to_string(),
                                "x-tenant".to_string(),
                            )]),
                            providers: Vec::new(),
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
            ],
            destination_rules: Vec::new(),
            proxy_configs: Vec::new(),
            trust_bundles: None,
            multi_cluster: None,
            outbound_traffic_policy: None,
            sidecar_egress_scope: None,
            extension_configs: Vec::new(),
            runtime_overlay: crate::modes::mesh::config::MeshRuntimeOverlay::default(),
        };

        let merged = merge_applicable_telemetry(&mesh_slice);
        let tracing = merged.tracing.expect("tracing merged");

        assert_eq!(tracing.sampling_percentage, Some(100.0));
        assert_eq!(tracing.disable_span_reporting, Some(true));
        assert_eq!(
            tracing.custom_tags.get("env").map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            tracing.custom_header_tags.get("tenant").map(String::as_str),
            Some("x-tenant")
        );
    }

    #[test]
    fn telemetry_tracing_merge_replaces_tags_and_providers_across_scopes() {
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: "test".to_string(),
            telemetry_resources: vec![
                MeshTelemetryResource {
                    name: "mesh-defaults".to_string(),
                    namespace: "istio-system".to_string(),
                    scope: PolicyScope::MeshWide,
                    config: MeshTelemetryConfig {
                        tracing: Some(MeshTracingConfig {
                            mode: None,
                            sampling_percentage: Some(25.0),
                            disable_span_reporting: None,
                            custom_tags: HashMap::from([
                                ("env".to_string(), "staging".to_string()),
                                ("mesh".to_string(), "ferrum".to_string()),
                            ]),
                            custom_header_tags: HashMap::from([(
                                "mesh-tenant".to_string(),
                                "x-mesh-tenant".to_string(),
                            )]),
                            providers: vec![TracingProvider::Zipkin {
                                url: "http://zipkin:9411/api/v2/spans".to_string(),
                            }],
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
                MeshTelemetryResource {
                    name: "workload-override".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    config: MeshTelemetryConfig {
                        tracing: Some(MeshTracingConfig {
                            mode: None,
                            sampling_percentage: None,
                            disable_span_reporting: None,
                            custom_tags: HashMap::from([
                                ("env".to_string(), "prod".to_string()),
                                ("region".to_string(), "us-east".to_string()),
                            ]),
                            custom_header_tags: HashMap::from([(
                                "tenant".to_string(),
                                "x-tenant".to_string(),
                            )]),
                            providers: vec![TracingProvider::OpenTelemetry {
                                endpoint: "http://otel:4318/v1/traces".to_string(),
                            }],
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
            ],
            ..MeshSlice::default()
        };

        let merged = merge_applicable_telemetry(&mesh_slice);
        let tracing = merged.tracing.expect("tracing merged");

        assert_eq!(tracing.sampling_percentage, Some(25.0));
        assert_eq!(
            tracing.custom_tags.get("env").map(String::as_str),
            Some("prod")
        );
        assert!(!tracing.custom_tags.contains_key("mesh"));
        assert_eq!(
            tracing.custom_tags.get("region").map(String::as_str),
            Some("us-east")
        );
        assert!(!tracing.custom_header_tags.contains_key("mesh-tenant"));
        assert_eq!(
            tracing.custom_header_tags.get("tenant").map(String::as_str),
            Some("x-tenant")
        );
        assert_eq!(tracing.providers.len(), 1);
        assert!(matches!(
            tracing.providers.first(),
            Some(TracingProvider::OpenTelemetry { .. })
        ));
    }

    #[test]
    fn mesh_runtime_telemetry_uses_mesh_slice_identity_for_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            telemetry_resources: vec![MeshTelemetryResource {
                name: "api-access-log".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                config: MeshTelemetryConfig {
                    access_logging: Some(MeshAccessLoggingConfig {
                        enabled: true,
                        filter: Some(AccessLogFilter {
                            status_code_min: Some(500),
                            status_code_max: None,
                            min_latency_ms: None,
                            errors_only: false,
                        }),
                    }),
                    ..MeshTelemetryConfig::default()
                },
            }],
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let access_log = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_ACCESS_LOG_PLUGIN_ID)
            .expect("mesh access-log (stdout_logging) plugin injected");

        assert_eq!(access_log.plugin_name, "stdout_logging");
        assert_eq!(access_log.config["filter"]["status_code_min"], 500);
    }

    #[test]
    fn inject_mesh_global_plugins_injects_outbound_registry_from_slice_policy() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![MeshService {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                ports: vec![ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly,
            ),
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let registry_plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin injected");
        let registry = registry_plugin.config["registry"]
            .as_array()
            .expect("registry array");

        assert_eq!(registry_plugin.plugin_name, "mesh_outbound_registry");
        assert_eq!(
            registry_plugin.config["outbound_listen_ports"],
            serde_json::json!([15001])
        );
        assert_eq!(registry_plugin.config["reject_status"], 502);
        assert!(registry.iter().any(|entry| entry == "reviews"));
        assert!(registry.iter().any(|entry| entry == "reviews.default"));
        assert!(
            registry
                .iter()
                .any(|entry| entry == "reviews.default.svc.cluster.local:8080")
        );
    }

    #[test]
    fn inject_mesh_global_plugins_uses_runtime_outbound_registry_reject_status() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        runtime.outbound_registry_reject_status = 403;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let registry_plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin injected");

        assert_eq!(registry_plugin.config["reject_status"], 403);
    }

    #[test]
    fn inject_mesh_global_plugins_skips_outbound_registry_without_outbound_listener() {
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = MeshTopology::EgressGateway;
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");

        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_injects_bpf_metrics_on_node_waypoint_topology() {
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = MeshTopology::NodeWaypoint;
        runtime.hbone_listen_addr = "127.0.0.1:15008".parse().unwrap();
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let bpf_plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_BPF_METRICS_PLUGIN_ID)
            .expect("bpf_metrics plugin auto-injected on NodeWaypoint");
        assert_eq!(bpf_plugin.plugin_name, "__mesh_bpf_metrics");
    }

    #[test]
    fn inject_mesh_global_plugins_skips_bpf_metrics_on_non_node_waypoint_topology() {
        for topology in [
            MeshTopology::Sidecar,
            MeshTopology::Ambient,
            MeshTopology::EastWestGateway,
            MeshTopology::EgressGateway,
        ] {
            let mut runtime = test_mesh_runtime_config();
            runtime.topology = topology;
            runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
            runtime.hbone_listen_addr = "127.0.0.1:15008".parse().unwrap();
            runtime.egress_listen_addr = "127.0.0.1:15090".parse().unwrap();
            let mesh_slice = MeshSlice {
                namespace: "default".to_string(),
                ..MeshSlice::default()
            };

            let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
                .expect("mesh slice config");
            assert!(
                prepared
                    .plugin_configs
                    .iter()
                    .all(|plugin| plugin.id != MESH_BPF_METRICS_PLUGIN_ID),
                "bpf_metrics must NOT be auto-injected for topology {topology:?}"
            );
        }
    }

    #[test]
    fn inject_mesh_global_plugins_still_injects_bpf_metrics_when_access_logging_disabled_on_node_waypoint()
     {
        // Regression: earlier versions of `inject_mesh_global_plugins`
        // `return`'d after retain-removing the access_log plugin when
        // `Telemetry.access_logging.enabled == false`, which silently
        // skipped the bpf_metrics injection branch below it. On
        // NodeWaypoint with access logging disabled, operators lost
        // BPF SOCK_OPS Prometheus metrics entirely. Lock in that
        // disabling access logging does NOT suppress bpf_metrics
        // injection on NodeWaypoint.
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = MeshTopology::NodeWaypoint;
        runtime.hbone_listen_addr = "127.0.0.1:15008".parse().unwrap();
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            telemetry_resources: vec![MeshTelemetryResource {
                name: "no-access-logs".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                config: MeshTelemetryConfig {
                    access_logging: Some(MeshAccessLoggingConfig {
                        enabled: false,
                        filter: None,
                    }),
                    ..MeshTelemetryConfig::default()
                },
            }],
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");

        // Access log plugin is explicitly absent (Telemetry disabled).
        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|p| p.id != MESH_ACCESS_LOG_PLUGIN_ID),
            "access_log plugin must be absent when Telemetry disables access logging"
        );
        // BPF metrics plugin MUST still be present — NodeWaypoint always
        // gets it, regardless of the Telemetry access-logging toggle.
        assert!(
            prepared
                .plugin_configs
                .iter()
                .any(|p| p.id == MESH_BPF_METRICS_PLUGIN_ID),
            "bpf_metrics plugin must be injected on NodeWaypoint even when access logging disabled"
        );
    }

    #[test]
    fn inject_mesh_global_plugins_drops_bpf_metrics_when_topology_changes_away_from_node_waypoint()
    {
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = MeshTopology::NodeWaypoint;
        runtime.hbone_listen_addr = "127.0.0.1:15008".parse().unwrap();
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            ..MeshSlice::default()
        };

        let mut prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        assert!(
            prepared
                .plugin_configs
                .iter()
                .any(|p| p.id == MESH_BPF_METRICS_PLUGIN_ID),
            "should be present after NodeWaypoint slice apply"
        );

        // Operator switches the same DP to ambient topology (uncommon in
        // practice, but verifies the cleanup arm of inject_mesh_global_plugins).
        runtime.topology = MeshTopology::Ambient;
        inject_mesh_global_plugins(&mut prepared, &runtime, &mesh_slice);
        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|p| p.id != MESH_BPF_METRICS_PLUGIN_ID),
            "topology change to Ambient must drop the bpf_metrics plugin"
        );
    }

    #[test]
    fn inject_mesh_global_plugins_runtime_registry_only_applies_when_slice_policy_absent() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![MeshService {
                name: "ratings".to_string(),
                namespace: "default".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");

        let plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin injected");
        let registry = plugin
            .config
            .get("registry")
            .and_then(serde_json::Value::as_array)
            .expect("registry config array");
        assert!(
            registry
                .iter()
                .any(|entry| entry.as_str() == Some("ratings.default"))
        );
        assert!(
            registry
                .iter()
                .any(|entry| entry.as_str() == Some("ratings.default:*"))
        );
    }

    #[test]
    fn inject_mesh_global_plugins_skips_outbound_registry_when_outbound_port_is_zero() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:0".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");

        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_slice_allow_any_overrides_runtime_registry_only() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            ),
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");

        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_removes_stale_outbound_registry_when_allow_any() {
        let runtime = test_mesh_runtime_config();
        let now = chrono::Utc::now();
        let mut config = GatewayConfig {
            plugin_configs: vec![crate::config::types::PluginConfig {
                id: MESH_OUTBOUND_REGISTRY_PLUGIN_ID.to_string(),
                plugin_name: "mesh_outbound_registry".to_string(),
                namespace: "default".to_string(),
                config: serde_json::json!({"registry": ["stale.default"]}),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            }],
            ..GatewayConfig::default()
        };
        let mesh_slice = MeshSlice {
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            ),
            ..MeshSlice::default()
        };

        inject_mesh_global_plugins(&mut config, &runtime, &mesh_slice);

        assert!(
            config
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_rebuilds_outbound_registry_on_slice_update() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let now = chrono::Utc::now();
        let mut config = GatewayConfig {
            plugin_configs: vec![crate::config::types::PluginConfig {
                id: MESH_OUTBOUND_REGISTRY_PLUGIN_ID.to_string(),
                plugin_name: "mesh_outbound_registry".to_string(),
                namespace: "default".to_string(),
                config: serde_json::json!({"registry": ["stale.default"]}),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            }],
            ..GatewayConfig::default()
        };
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![MeshService {
                name: "ratings".to_string(),
                namespace: "default".to_string(),
                ports: vec![ServicePort {
                    port: 9080,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        inject_mesh_global_plugins(&mut config, &runtime, &mesh_slice);
        let registry_plugin = config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin retained");
        let registry = registry_plugin.config["registry"]
            .as_array()
            .expect("registry array");

        assert!(registry.iter().any(|entry| entry == "ratings.default"));
        assert!(!registry.iter().any(|entry| entry == "stale.default"));
    }

    #[test]
    fn inject_mesh_global_plugins_copies_operator_authz_assertor_override_to_workload_metrics() {
        let mut runtime = test_mesh_runtime_config();
        runtime.trusted_hbone_assertors =
            vec!["spiffe://cluster.local/ns/istio-system/sa/env-assertor".to_string()];
        let now = chrono::Utc::now();
        let mut config = GatewayConfig {
            plugin_configs: vec![crate::config::types::PluginConfig {
                id: "operator-mesh-authz".to_string(),
                plugin_name: "mesh_authz".to_string(),
                namespace: "default".to_string(),
                config: serde_json::json!({
                    "trusted_hbone_assertors": []
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            }],
            ..GatewayConfig::default()
        };

        inject_mesh_global_plugins(&mut config, &runtime, &MeshSlice::default());

        assert!(
            config
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_AUTHZ_PLUGIN_ID),
            "operator-managed mesh_authz must remain the effective authz plugin"
        );
        let workload_metrics = config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
            .expect("workload_metrics plugin injected");
        assert_eq!(
            workload_metrics.config.get("trusted_hbone_assertors"),
            Some(&serde_json::json!([])),
            "workload_metrics must honor the operator mesh_authz empty allow-list instead of the runtime/env list"
        );
    }

    #[test]
    fn inject_mesh_global_plugins_omits_runtime_assertors_when_operator_authz_uses_defaults() {
        let mut runtime = test_mesh_runtime_config();
        runtime.trusted_hbone_assertors =
            vec!["spiffe://cluster.local/ns/istio-system/sa/env-assertor".to_string()];
        let now = chrono::Utc::now();
        let mut config = GatewayConfig {
            plugin_configs: vec![crate::config::types::PluginConfig {
                id: "operator-mesh-authz".to_string(),
                plugin_name: "mesh_authz".to_string(),
                namespace: "default".to_string(),
                config: serde_json::json!({}),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            }],
            ..GatewayConfig::default()
        };

        inject_mesh_global_plugins(&mut config, &runtime, &MeshSlice::default());

        let workload_metrics = config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
            .expect("workload_metrics plugin injected");
        assert!(
            workload_metrics
                .config
                .get("trusted_hbone_assertors")
                .is_none(),
            "when operator mesh_authz omits trusted_hbone_assertors, workload_metrics must omit it too so both use shared defaults"
        );
    }

    #[test]
    fn inject_mesh_global_plugins_merges_zipkin_provider_into_workload_metrics() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            telemetry_resources: vec![MeshTelemetryResource {
                name: "api-tracing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                config: MeshTelemetryConfig {
                    tracing: Some(MeshTracingConfig {
                        mode: None,
                        sampling_percentage: Some(10.0),
                        disable_span_reporting: None,
                        custom_tags: HashMap::new(),
                        custom_header_tags: HashMap::new(),
                        providers: vec![TracingProvider::Zipkin {
                            url: "http://zipkin.istio-system:9411/api/v2/spans".to_string(),
                        }],
                    }),
                    ..MeshTelemetryConfig::default()
                },
            }],
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let workload_metrics = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
            .expect("workload_metrics plugin injected");

        let providers = workload_metrics
            .config
            .get("tracing_providers")
            .and_then(serde_json::Value::as_array)
            .expect("tracing_providers merged into workload_metrics");
        let provider = providers.first().expect("zipkin provider present");
        assert_eq!(
            provider.get("kind").and_then(serde_json::Value::as_str),
            Some("zipkin")
        );
        assert_eq!(
            provider
                .pointer("/config/url")
                .and_then(serde_json::Value::as_str),
            Some("http://zipkin.istio-system:9411/api/v2/spans")
        );
        // Sampling percentage from the same Telemetry block is still applied.
        assert_eq!(
            workload_metrics.config["sampling_percentage"],
            serde_json::json!(10.0)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_preserves_provider_when_span_reporting_disabled() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            telemetry_resources: vec![MeshTelemetryResource {
                name: "api-tracing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                config: MeshTelemetryConfig {
                    tracing: Some(MeshTracingConfig {
                        mode: None,
                        sampling_percentage: Some(100.0),
                        disable_span_reporting: Some(true),
                        custom_tags: HashMap::new(),
                        custom_header_tags: HashMap::new(),
                        providers: vec![TracingProvider::Zipkin {
                            url: "http://zipkin.istio-system:9411/api/v2/spans".to_string(),
                        }],
                    }),
                    ..MeshTelemetryConfig::default()
                },
            }],
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let workload_metrics = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
            .expect("workload_metrics plugin injected");

        assert_eq!(
            workload_metrics.config["span_reporting_disabled"],
            serde_json::json!(true)
        );
        let providers = workload_metrics
            .config
            .get("tracing_providers")
            .and_then(serde_json::Value::as_array)
            .expect("tracing_providers kept for propagation");
        assert_eq!(
            providers
                .first()
                .and_then(|provider| provider.get("kind"))
                .and_then(serde_json::Value::as_str),
            Some("zipkin")
        );
    }

    async fn wait_for_mesh_authz_label(proxy_state: &ProxyState, key: &str, expected: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let observed = mesh_authz_label(proxy_state, key);
                if observed.as_deref() == Some(expected) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("mesh_authz label {key} did not become {expected}"));
    }

    fn mesh_authz_label(proxy_state: &ProxyState, key: &str) -> Option<String> {
        proxy_state
            .current_config()
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
            .and_then(|plugin| {
                plugin
                    .config
                    .pointer(&format!("/mesh_slice/labels/{key}"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
    }

    async fn wait_for_mesh_inbound_tls(proxy_state: &ProxyState, expected_present: bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if proxy_state.mesh_inbound_tls.load_full().is_some() == expected_present {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("mesh inbound TLS slot should update");
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_sidecar_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::MtlsTermination
                        && listener.addr.port() == 15006
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_ambient_hbone_port() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::HboneTermination
                        && listener.addr.port() == 15008
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_node_waypoint_hbone_only() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "node_waypoint"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 1);
                assert_eq!(plan[0].direction, MeshTrafficDirection::Inbound);
                assert_eq!(plan[0].kind, MeshListenerKind::HboneTermination);
                assert_eq!(plan[0].addr.port(), 15008);
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_east_west_passthrough_proxies() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "mesh-system"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        multi_cluster: Some(MultiClusterConfig {
                            east_west_gateways: vec![EastWestGateway {
                                name: "remote-a".to_string(),
                                namespace: "mesh-system".to_string(),
                                host: "EastWest.Remote.Example".to_string(),
                                port: 443,
                                sni_hosts: vec!["API.Remote.Example".to_string()],
                                trust_domain: Some(TrustDomain::new("remote.test").unwrap()),
                                network: Some("network-a".to_string()),
                            }],
                            ..MultiClusterConfig::default()
                        }),
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let proxy = prepared
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == "__mesh-east-west-mesh-system-remote-a")
                    .expect("east-west proxy");

                assert_eq!(proxy.listen_port, Some(15443));
                assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
                assert_eq!(
                    proxy.dispatch_kind,
                    crate::config::types::DispatchKind::TcpRaw
                );
                assert!(proxy.passthrough);
                assert_eq!(proxy.backend_host, "eastwest.remote.example");
                assert_eq!(proxy.hosts, vec!["api.remote.example"]);
            },
        );
    }

    #[test]
    fn east_west_gateway_materializes_service_proxies_from_slice() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![MeshService {
                            name: "reviews".to_string(),
                            namespace: "default".to_string(),
                            ports: vec![ServicePort {
                                port: 9080,
                                protocol: AppProtocol::Http,
                                name: Some("http".to_string()),
                                target_port: None,
                            }],
                            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                spiffe_id: SpiffeId::new(
                                    "spiffe://cluster.local/ns/default/sa/reviews",
                                )
                                .unwrap(),
                            }],
                            protocol_overrides: HashMap::new(),
                        }],
                        workloads: vec![{
                            let mut wl = workload("reviews", "reviews");
                            wl.addresses = vec!["10.0.0.5".to_string()];
                            wl
                        }],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

                // Verify service proxy was materialized.
                let proxy = prepared
                    .proxies
                    .iter()
                    .find(|p| p.id == "__mesh-ew-svc-default-reviews")
                    .expect("east-west service proxy");

                assert_eq!(proxy.listen_port, Some(15443));
                assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
                assert!(proxy.passthrough);
                assert_eq!(proxy.hosts, vec!["reviews.default.svc.cluster.local"]);
                assert_eq!(
                    proxy.upstream_id.as_deref(),
                    Some("__mesh-ew-upstream-default-reviews")
                );

                // Verify upstream was materialized.
                let upstream = prepared
                    .upstreams
                    .iter()
                    .find(|u| u.id == "__mesh-ew-upstream-default-reviews")
                    .expect("east-west service upstream");

                assert_eq!(upstream.targets.len(), 1);
                assert_eq!(upstream.targets[0].host, "10.0.0.5");
                assert_eq!(upstream.targets[0].port, 9080);
            },
        );
    }

    #[test]
    fn east_west_gateway_skips_services_without_workload_addresses() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![MeshService {
                            name: "pending".to_string(),
                            namespace: "default".to_string(),
                            ports: vec![ServicePort {
                                port: 8080,
                                protocol: AppProtocol::Http,
                                name: None,
                                target_port: None,
                            }],
                            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                spiffe_id: SpiffeId::new(
                                    "spiffe://cluster.local/ns/default/sa/pending",
                                )
                                .unwrap(),
                            }],
                            protocol_overrides: HashMap::new(),
                        }],
                        // Workload exists but has no addresses (pod IP not yet assigned).
                        workloads: vec![workload("pending", "pending")],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

                assert!(
                    !prepared
                        .proxies
                        .iter()
                        .any(|p| p.id == "__mesh-ew-svc-default-pending"),
                    "service with no reachable targets should not produce a proxy"
                );
            },
        );
    }

    #[test]
    fn east_west_gateway_multiple_services_correct_upstream_targets() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![
                            MeshService {
                                name: "reviews".to_string(),
                                namespace: "default".to_string(),
                                ports: vec![ServicePort {
                                    port: 9080,
                                    protocol: AppProtocol::Http,
                                    name: None,
                                    target_port: None,
                                }],
                                workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: SpiffeId::new(
                                        "spiffe://cluster.local/ns/default/sa/reviews",
                                    )
                                    .unwrap(),
                                }],
                                protocol_overrides: HashMap::new(),
                            },
                            MeshService {
                                name: "ratings".to_string(),
                                namespace: "default".to_string(),
                                ports: vec![ServicePort {
                                    port: 3000,
                                    protocol: AppProtocol::Http,
                                    name: None,
                                    target_port: None,
                                }],
                                workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: SpiffeId::new(
                                        "spiffe://cluster.local/ns/default/sa/ratings",
                                    )
                                    .unwrap(),
                                }],
                                protocol_overrides: HashMap::new(),
                            },
                        ],
                        workloads: vec![
                            {
                                let mut wl = workload("reviews", "reviews");
                                wl.addresses = vec!["10.0.0.5".to_string()];
                                wl
                            },
                            {
                                let mut wl = workload("ratings", "ratings");
                                wl.addresses = vec!["10.0.0.6".to_string(), "10.0.0.7".to_string()];
                                wl
                            },
                        ],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

                // Both services should produce proxies.
                let reviews_proxy = prepared
                    .proxies
                    .iter()
                    .find(|p| p.id == "__mesh-ew-svc-default-reviews")
                    .expect("reviews proxy");
                assert_eq!(reviews_proxy.listen_port, Some(15443));
                assert_eq!(
                    reviews_proxy.hosts,
                    vec!["reviews.default.svc.cluster.local"]
                );

                let ratings_proxy = prepared
                    .proxies
                    .iter()
                    .find(|p| p.id == "__mesh-ew-svc-default-ratings")
                    .expect("ratings proxy");
                assert_eq!(ratings_proxy.listen_port, Some(15443));
                assert_eq!(
                    ratings_proxy.hosts,
                    vec!["ratings.default.svc.cluster.local"]
                );

                // Ratings upstream should have 2 targets (two addresses).
                let ratings_upstream = prepared
                    .upstreams
                    .iter()
                    .find(|u| u.id == "__mesh-ew-upstream-default-ratings")
                    .expect("ratings upstream");
                assert_eq!(ratings_upstream.targets.len(), 2);
                assert_eq!(ratings_upstream.targets[0].host, "10.0.0.6");
                assert_eq!(ratings_upstream.targets[1].host, "10.0.0.7");
                assert_eq!(ratings_upstream.targets[0].port, 3000);
            },
        );
    }

    #[test]
    fn east_west_service_targets_preserve_replicas_sharing_spiffe_id() {
        let shared_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").unwrap();
        let mut first = workload("reviews", "reviews");
        first.spiffe_id = shared_spiffe.clone();
        first.addresses = vec!["10.0.0.5".to_string()];
        first.locality = Some("us-west/us-west-1/a".to_string());
        let mut second = workload("reviews", "reviews");
        second.spiffe_id = shared_spiffe.clone();
        second.addresses = vec!["10.0.0.6".to_string()];
        second.locality = Some("us-west/us-west-1/b".to_string());
        let service = MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 9080,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![
                crate::modes::mesh::config::WorkloadRef {
                    spiffe_id: shared_spiffe.clone(),
                },
                crate::modes::mesh::config::WorkloadRef {
                    spiffe_id: shared_spiffe,
                },
            ],
            protocol_overrides: HashMap::new(),
        };

        let targets = build_east_west_service_targets(&service, &[first, second], None);

        let hosts: Vec<&str> = targets.iter().map(|target| target.host.as_str()).collect();
        assert_eq!(hosts, vec!["10.0.0.5", "10.0.0.6"]);
        assert!(targets.iter().all(|target| target.port == 9080));
        let localities: Vec<Option<&str>> = targets
            .iter()
            .map(|target| target.locality.as_deref())
            .collect();
        assert_eq!(
            localities,
            vec![Some("us-west/us-west-1/a"), Some("us-west/us-west-1/b")]
        );
    }

    #[test]
    fn mesh_source_workload_locality_projects_to_upstreams() {
        let mut source = workload("api", "api");
        source.addresses = vec!["10.0.0.9".to_string()];
        source.locality = Some("us-east/us-east-1/a".to_string());
        let source_spiffe = source.spiffe_id.as_str().to_string();
        let mut config = GatewayConfig::default();
        let loaded_at = config.loaded_at;
        let now = chrono::Utc::now();
        config.upstreams.push(Upstream {
            id: "reviews".to_string(),
            namespace: "default".to_string(),
            name: Some("reviews".to_string()),
            targets: vec![UpstreamTarget {
                host: "10.0.0.5".to_string(),
                port: 8080,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-east/us-east-1/b".to_string()),
                path: None,
            }],
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        });
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            workload_spiffe_id: Some(source_spiffe),
            waypoint_name: None,
            workloads: vec![source],
            ..MeshSlice::default()
        };

        project_mesh_source_locality(&mut config, &mesh_slice);

        assert_eq!(
            config.upstreams[0].source_locality.as_deref(),
            Some("us-east/us-east-1/a")
        );
        assert_eq!(config.upstreams[0].updated_at, loaded_at);
    }

    #[test]
    fn mesh_source_workload_locality_accepts_multi_replica_same_locality() {
        let mut first = workload("reviews-1", "reviews");
        first.locality = Some("us-west/us-west-1/a".to_string());
        let mut second = workload("reviews-2", "reviews");
        second.locality = Some("us-west/us-west-1/a".to_string());
        let mut third = workload("reviews-3", "reviews");
        third.locality = Some("us-west/us-west-1/a".to_string());

        let slice = MeshSlice {
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            workload_spiffe_id: None,
            waypoint_name: None,
            workloads: vec![first, second, third],
            ..MeshSlice::default()
        };

        assert_eq!(
            mesh_source_workload_locality(&slice),
            Some("us-west/us-west-1/a")
        );
    }

    #[test]
    fn mesh_source_workload_locality_returns_none_when_label_matches_disagree() {
        let mut first = workload("reviews-1", "reviews");
        first.locality = Some("us-west/us-west-1/a".to_string());
        let mut second = workload("reviews-2", "reviews");
        second.locality = Some("us-west/us-west-1/b".to_string());

        let slice = MeshSlice {
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            workload_spiffe_id: None,
            waypoint_name: None,
            workloads: vec![first, second],
            ..MeshSlice::default()
        };

        assert_eq!(mesh_source_workload_locality(&slice), None);
    }

    #[test]
    fn mesh_source_workload_locality_spiffe_match_without_locality_is_authoritative() {
        // SPIFFE-matched workload has no locality — answer is `None`, even
        // though another label-matching workload would supply one.
        let mut source = workload("api", "api");
        source.locality = None;
        let spiffe = source.spiffe_id.as_str().to_string();

        let mut sibling = workload("api-noisy", "api");
        sibling.locality = Some("us-east/us-east-1/a".to_string());

        let slice = MeshSlice {
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            workload_spiffe_id: Some(spiffe),
            waypoint_name: None,
            workloads: vec![source, sibling],
            ..MeshSlice::default()
        };

        assert_eq!(mesh_source_workload_locality(&slice), None);
    }

    #[test]
    fn east_west_service_targets_honor_target_port() {
        // Service port 80 with targetPort 8080; the pod listens on container port
        // 8080. East-west targets dial workload addresses, so they must use 8080.
        let spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").unwrap();
        let mut wl = workload("reviews", "reviews");
        wl.spiffe_id = spiffe.clone();
        wl.addresses = vec!["10.0.0.5".to_string()];
        let service = MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: Some(ServiceTargetPort::Number(8080)),
            }],
            workloads: vec![crate::modes::mesh::config::WorkloadRef { spiffe_id: spiffe }],
            protocol_overrides: HashMap::new(),
        };

        let targets = build_east_west_service_targets(&service, &[wl], None);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.5");
        assert_eq!(
            targets[0].port, 8080,
            "east-west must dial the container port (targetPort), not the service port"
        );
    }

    #[test]
    fn east_west_service_targets_preserve_explicit_refs_with_stale_service_metadata() {
        let spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").unwrap();
        let mut legacy = workload("legacy-reviews", "legacy-reviews");
        legacy.spiffe_id = spiffe.clone();
        legacy.addresses = vec!["10.0.0.5".to_string()];
        let service = MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 9080,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![crate::modes::mesh::config::WorkloadRef { spiffe_id: spiffe }],
            protocol_overrides: HashMap::new(),
        };

        let targets = build_east_west_service_targets(&service, &[legacy], None);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.5");
        assert_eq!(targets[0].port, 9080);
    }

    #[test]
    fn east_west_gateway_service_targets_ignore_remote_cluster_workloads() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let mut local = workload("reviews-local", "reviews");
                local.addresses = vec!["10.0.0.5".to_string()];
                local.cluster = Some("cluster-a".to_string());
                local.service_name = "reviews".to_string();
                let mut remote = workload("reviews-remote", "reviews");
                remote.addresses = vec!["172.16.0.5".to_string()];
                remote.cluster = Some("cluster-b".to_string());
                remote.service_name = "reviews".to_string();
                let mut clusterless = workload("reviews-clusterless", "reviews");
                clusterless.addresses = vec!["10.0.0.6".to_string()];
                clusterless.service_name = "reviews".to_string();

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![MeshService {
                            name: "reviews".to_string(),
                            namespace: "default".to_string(),
                            ports: vec![ServicePort {
                                port: 9080,
                                protocol: AppProtocol::Http,
                                name: None,
                                target_port: None,
                            }],
                            workloads: vec![
                                crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: local.spiffe_id.clone(),
                                },
                                crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: remote.spiffe_id.clone(),
                                },
                                crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: clusterless.spiffe_id.clone(),
                                },
                            ],
                            protocol_overrides: HashMap::new(),
                        }],
                        workloads: vec![local, remote, clusterless],
                        multi_cluster: Some(MultiClusterConfig {
                            local_cluster: Some("cluster-a".to_string()),
                            ..MultiClusterConfig::default()
                        }),
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let upstream = prepared
                    .upstreams
                    .iter()
                    .find(|u| u.id == "__mesh-ew-upstream-default-reviews")
                    .expect("reviews upstream");
                let hosts: Vec<&str> = upstream
                    .targets
                    .iter()
                    .map(|target| target.host.as_str())
                    .collect();

                assert_eq!(hosts, vec!["10.0.0.5", "10.0.0.6"]);
                assert!(
                    !hosts.contains(&"172.16.0.5"),
                    "remote-cluster workloads should not become local east-west targets"
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_global_mesh_plugins_from_slice() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let api_policy = MeshPolicy {
                    name: "api-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: vec![MeshRule {
                        from: vec![PrincipalMatch {
                            spiffe_id_pattern: Some(
                                "spiffe://cluster.local/ns/default/sa/client".to_string(),
                            ),
                            namespace_pattern: None,
                            trust_domain: None,
                            trust_domain_pattern: None,
                        }],
                        to: Vec::new(),
                        when: Vec::new(),
                        request_principals: Vec::new(),
                        not_request_principals: Vec::new(),
                        source_negation: Default::default(),
                        never_matches: false,
                        action: PolicyAction::Allow,
                    }],
                };
                let worker_policy = MeshPolicy {
                    name: "worker-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "worker".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: Vec::new(),
                };
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        workloads: vec![workload("api", "api"), workload("worker", "worker")],
                        mesh_policies: vec![api_policy, worker_policy],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let by_id = |id: &str| {
                    prepared
                        .plugin_configs
                        .iter()
                        .find(|plugin| plugin.id == id)
                        .expect("mesh plugin injected")
                };

                assert_eq!(
                    by_id(MESH_SPIFFE_IDENTITY_PLUGIN_ID).plugin_name,
                    "spiffe_identity"
                );
                assert_eq!(by_id(MESH_AUTHZ_PLUGIN_ID).plugin_name, "mesh_authz");
                assert_eq!(
                    by_id(MESH_WORKLOAD_METRICS_PLUGIN_ID).plugin_name,
                    "workload_metrics"
                );
                assert_eq!(
                    by_id(MESH_ACCESS_LOG_PLUGIN_ID).plugin_name,
                    "stdout_logging"
                );
                assert!(
                    prepared
                        .plugin_configs
                        .iter()
                        .all(|plugin| plugin.scope == PluginScope::Global)
                );

                let mesh_slice = by_id(MESH_AUTHZ_PLUGIN_ID)
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");
                let policies = mesh_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
                assert_eq!(
                    mesh_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_uses_native_slice_without_reslicing_policies() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let slice = MeshSlice {
                    node_id: "node-a".to_string(),
                    namespace: "default".to_string(),
                    labels: [("app".to_string(), "api".to_string())].into(),
                    version: chrono::Utc::now().to_rfc3339(),
                    mesh_policies: vec![MeshPolicy {
                        name: "api-only".to_string(),
                        namespace: "default".to_string(),
                        scope: PolicyScope::WorkloadSelector {
                            selector: WorkloadSelector {
                                labels: HashMap::from([("app".to_string(), "api".to_string())]),
                                namespace: Some("default".to_string()),
                            },
                        },
                        rules: vec![MeshRule {
                            from: vec![PrincipalMatch {
                                spiffe_id_pattern: Some(
                                    "spiffe://cluster.local/ns/default/sa/client".to_string(),
                                ),
                                namespace_pattern: None,
                                trust_domain: None,
                                trust_domain_pattern: None,
                            }],
                            to: Vec::new(),
                            when: Vec::new(),
                            request_principals: Vec::new(),
                            not_request_principals: Vec::new(),
                            source_negation: Default::default(),
                            never_matches: false,
                            action: PolicyAction::Allow,
                        }],
                    }],
                    ..MeshSlice::default()
                };

                let prepared = gateway_config_from_mesh_slice(&slice, &runtime, None, None)
                    .expect("native slice config");
                let mesh_authz = prepared
                    .plugin_configs
                    .iter()
                    .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
                    .expect("mesh_authz plugin");
                let plugin_slice = mesh_authz
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");

                assert_eq!(
                    plugin_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
                let policies = plugin_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
            },
        );
    }

    #[test]
    fn mesh_slice_rejection_does_not_advance_apply_dedupe_baseline() {
        let mesh_state = MeshRuntimeState::new();
        let mut last_applied_slice = None;
        let rejected = MeshSlice {
            version: "bad-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        };
        record_mesh_slice_apply_result(&mesh_state, &mut last_applied_slice, &rejected, false);
        assert!(last_applied_slice.is_none());
        assert!(mesh_state.applied_snapshot().as_ref().is_none());
        assert!(!mesh_slice_matches_last_applied(
            last_applied_slice.as_deref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));

        record_mesh_slice_apply_result(&mesh_state, &mut last_applied_slice, &rejected, true);
        assert!(mesh_state.applied_snapshot().as_ref().is_some());
        assert!(mesh_slice_matches_last_applied(
            last_applied_slice.as_deref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));
    }

    #[test]
    fn no_op_restamp_updates_applied_snapshot_version() {
        let mesh_state = MeshRuntimeState::new();
        let mut last_applied_slice = None;
        let v1 = MeshSlice {
            version: "v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        };
        let v2 = MeshSlice {
            version: "v2".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        };

        record_mesh_slice_apply_result(&mesh_state, &mut last_applied_slice, &v1, true);
        assert!(mesh_slice_matches_last_applied(
            last_applied_slice.as_deref(),
            &v2
        ));
        record_mesh_slice_apply_result(&mesh_state, &mut last_applied_slice, &v2, true);

        let applied = mesh_state.applied_snapshot();
        assert_eq!(
            applied
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v2")
        );
    }

    #[test]
    fn mesh_proxy_update_acceptance_distinguishes_no_delta_from_rejection() {
        let previous = chrono::Utc::now();
        let candidate = previous + chrono::Duration::milliseconds(1);

        assert!(mesh_proxy_update_was_accepted(
            true, previous, previous, candidate
        ));
        assert!(mesh_proxy_update_was_accepted(
            false, previous, candidate, candidate
        ));
        assert!(!mesh_proxy_update_was_accepted(
            false, previous, previous, candidate
        ));
        assert!(!mesh_proxy_update_was_accepted(
            false, previous, previous, previous
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_apply_task_propagates_subsequent_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_state = MeshRuntimeState::new();
        let proxy_state = make_test_proxy_state(GatewayConfig::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let apply_task = start_mesh_slice_apply_task(
            mesh_state.clone(),
            proxy_state.clone(),
            runtime,
            None,
            MeshInboundTlsReloadState {
                server_identity: None,
                last_snapshot: None,
                spiffe_bundle_slot: None,
                production: false,
            },
            shutdown_rx,
            None,
        );

        mesh_state.install_slice(MeshSlice {
            version: "slice-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "api").await;

        mesh_state.install_slice(MeshSlice {
            version: "slice-v2".to_string(),
            labels: [("app".to_string(), "worker".to_string())].into(),
            ..MeshSlice::default()
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "worker").await;

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), apply_task)
            .await
            .expect("apply task should stop")
            .expect("apply task should join");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_apply_task_live_reloads_peer_auth_tls_slot() {
        let mut runtime = test_mesh_runtime_config();
        runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
        let env = EnvConfig {
            mesh_peer_auth_live_reload_enabled: true,
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: Some("tests/certs/server.crt".to_string()),
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            ..EnvConfig::default()
        };
        let proxy_state = make_test_proxy_state_with_env(GatewayConfig::default(), env.clone());
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("mesh frontend identity");
        let initial_snapshot = mesh_inbound_tls_reload_snapshot(&env, config::MtlsMode::Disable)
            .expect("initial snapshot");
        let mesh_state = MeshRuntimeState::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let apply_task = start_mesh_slice_apply_task(
            mesh_state.clone(),
            proxy_state.clone(),
            runtime,
            None,
            MeshInboundTlsReloadState {
                server_identity: mesh_frontend_identity,
                last_snapshot: Some(initial_snapshot),
                spiffe_bundle_slot: None,
                production: false,
            },
            shutdown_rx,
            None,
        );

        mesh_state.install_slice(MeshSlice {
            version: "strict".to_string(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Strict,
            )])
        });
        wait_for_mesh_inbound_tls(&proxy_state, true).await;
        let strict_tls_slot = proxy_state.mesh_inbound_tls.load_full();

        mesh_state.install_slice(MeshSlice {
            version: "strict-label-only".to_string(),
            labels: [("app".to_string(), "same-peer-auth".to_string())].into(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Strict,
            )])
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "same-peer-auth").await;
        let unchanged_tls_slot = proxy_state.mesh_inbound_tls.load_full();
        assert!(
            Arc::ptr_eq(&strict_tls_slot, &unchanged_tls_slot),
            "unchanged PeerAuthentication inputs should not rebuild the TLS slot"
        );

        mesh_state.install_slice(MeshSlice {
            version: "disable".to_string(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Disable,
            )])
        });
        wait_for_mesh_inbound_tls(&proxy_state, false).await;

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), apply_task)
            .await
            .expect("apply task should stop")
            .expect("apply task should join");
    }

    /// T3-A: apply_mesh_inbound_tls_reload must also publish the swapped
    /// TLS config into the stream-listener slot so mesh-shared TCP+TLS
    /// listeners see the new `ServerConfig` on the next accept. Existing
    /// HBONE/HTTP-frontend slot behavior is preserved (covered by the
    /// neighbouring `mesh_runtime_apply_task_live_reloads_peer_auth_tls_slot`).
    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_apply_task_propagates_peer_auth_swap_to_stream_listener_slot() {
        let mut runtime = test_mesh_runtime_config();
        runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
        let env = EnvConfig {
            mesh_peer_auth_live_reload_enabled: true,
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: Some("tests/certs/server.crt".to_string()),
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            ..EnvConfig::default()
        };
        let proxy_state = make_test_proxy_state_with_env(GatewayConfig::default(), env.clone());
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("mesh frontend identity");
        let initial_snapshot = mesh_inbound_tls_reload_snapshot(&env, config::MtlsMode::Disable)
            .expect("initial snapshot");
        let mesh_state = MeshRuntimeState::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let apply_task = start_mesh_slice_apply_task(
            mesh_state.clone(),
            proxy_state.clone(),
            runtime,
            None,
            MeshInboundTlsReloadState {
                server_identity: mesh_frontend_identity,
                last_snapshot: Some(initial_snapshot),
                spiffe_bundle_slot: None,
                production: false,
            },
            shutdown_rx,
            None,
        );

        // Baseline: stream listener slot starts empty (no startup TLS publish
        // by this test harness).
        assert!(
            proxy_state
                .stream_listener_manager
                .snapshot_frontend_tls_config()
                .is_none(),
            "stream listener slot starts empty before any slice apply"
        );

        // Apply a Strict slice; the apply task must publish the new
        // ServerConfig into BOTH the HBONE slot AND the stream-listener slot.
        mesh_state.install_slice(MeshSlice {
            version: "strict-stream".to_string(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Strict,
            )])
        });
        wait_for_mesh_inbound_tls(&proxy_state, true).await;

        let hbone_slot = proxy_state.mesh_inbound_tls.load_full();
        let hbone_slot_ref = hbone_slot
            .as_ref()
            .as_ref()
            .expect("HBONE slot populated by Strict apply");

        // Poll briefly for the stream-listener slot publish (the apply path
        // populates both slots in the same await, but the slot read here can
        // race the publishing store on the read side).
        let stream_slot = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(cfg) = proxy_state
                    .stream_listener_manager
                    .snapshot_frontend_tls_config()
                {
                    return cfg;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stream listener slot should be populated by apply task");

        assert!(
            Arc::ptr_eq(hbone_slot_ref, &stream_slot),
            "apply_mesh_inbound_tls_reload must publish the same ServerConfig Arc \
             into both the HBONE and the stream-listener slots"
        );

        // Disable PeerAuth: both slots must clear.
        mesh_state.install_slice(MeshSlice {
            version: "disable-stream".to_string(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Disable,
            )])
        });
        wait_for_mesh_inbound_tls(&proxy_state, false).await;

        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy_state
                .stream_listener_manager
                .snapshot_frontend_tls_config()
                .is_some()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stream-listener slot should clear when PeerAuth flips to Disable");

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), apply_task)
            .await
            .expect("apply task should stop")
            .expect("apply task should join");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_apply_task_rejects_peer_auth_reload_when_tls_rebuild_fails() {
        let mut runtime = test_mesh_runtime_config();
        runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
        let env = EnvConfig {
            mesh_peer_auth_live_reload_enabled: true,
            frontend_tls_cert_path: Some("/missing/server.crt".to_string()),
            frontend_tls_key_path: Some("/missing/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: Some("tests/certs/server.crt".to_string()),
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            ..EnvConfig::default()
        };
        let proxy_state = make_test_proxy_state_with_env(GatewayConfig::default(), env.clone());
        let initial_snapshot = mesh_inbound_tls_reload_snapshot(&env, config::MtlsMode::Disable)
            .expect("initial snapshot");
        let mesh_state = MeshRuntimeState::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let apply_task = start_mesh_slice_apply_task(
            mesh_state.clone(),
            proxy_state.clone(),
            runtime,
            None,
            MeshInboundTlsReloadState {
                server_identity: None,
                last_snapshot: Some(initial_snapshot),
                spiffe_bundle_slot: None,
                production: false,
            },
            shutdown_rx,
            None,
        );

        mesh_state.install_slice(MeshSlice {
            version: "good-disable".to_string(),
            labels: [("app".to_string(), "good-baseline".to_string())].into(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Disable,
            )])
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "good-baseline").await;

        mesh_state.install_slice(MeshSlice {
            version: "bad-strict".to_string(),
            labels: [("app".to_string(), "bad-tls".to_string())].into(),
            ..slice_with_peer_auths(vec![peer_auth_with_port_override(
                15006,
                config::MtlsMode::Strict,
            )])
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            proxy_state.mesh_inbound_tls.load_full().is_none(),
            "failed TLS rebuild should keep the previous plaintext slot"
        );
        assert_eq!(
            mesh_authz_label(&proxy_state, "app").as_deref(),
            Some("good-baseline"),
            "failed TLS rebuild should keep the previous proxy config"
        );

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), apply_task)
            .await
            .expect("apply task should stop")
            .expect("apply task should join");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn plan_mesh_inbound_tls_reload_fails_closed_on_plaintext_downgrade() {
        // Issue #1523 live-reload complement: a PeerAuthentication update that
        // resolves the inbound termination listener to plaintext (DISABLE →
        // `tls_config` None) must be rejected under production, so a running
        // production sidecar is not silently downgraded mid-flight. The apply
        // task treats a `None` plan as "keep the last-good config". `production`
        // is passed explicitly (captured once at startup in the real runtime), so
        // this test is deterministic and does not touch the environment.
        ensure_crypto_provider();
        let mut runtime = test_mesh_runtime_config(); // Sidecar → has MtlsTermination
        runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
        let env = EnvConfig {
            mesh_peer_auth_live_reload_enabled: true,
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            ..EnvConfig::default()
        };
        let disable_slice = MeshSlice {
            version: "disable-reload".to_string(),
            ..MeshSlice::default()
        };
        let proxy_state = make_test_proxy_state_with_env(GatewayConfig::default(), env.clone());
        let identity = load_mesh_frontend_server_identity(&env).expect("server identity");

        // Production rejects the plaintext (DISABLE) downgrade: plan() is None,
        // which the apply task treats as "keep the last-good mTLS config".
        let plan = plan_mesh_inbound_tls_reload(
            &proxy_state,
            &runtime,
            &disable_slice,
            config::MtlsMode::Disable,
            identity.as_deref(),
            None,
            None,
            true, // production
            true, // has a TLS-terminating inbound listener (Sidecar)
        );
        assert!(
            plan.is_none(),
            "production must reject a DISABLE (plaintext) inbound live reload"
        );

        // Dev (non-production) tolerates the downgrade (warns + swaps to None) —
        // an explicit DISABLE reload is an intentional operator choice.
        let plan = plan_mesh_inbound_tls_reload(
            &proxy_state,
            &runtime,
            &disable_slice,
            config::MtlsMode::Disable,
            identity.as_deref(),
            None,
            None,
            false, // dev
            true,  // has a TLS-terminating inbound listener (Sidecar)
        );
        assert!(
            matches!(
                plan,
                Some(MeshInboundTlsReloadPlan::Swap {
                    tls_config: None,
                    ..
                })
            ),
            "dev (non-production) may apply a plaintext inbound reload"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_waits_for_valid_initial_native_slice() {
        let runtime = test_mesh_runtime_config();
        let mesh_state = MeshRuntimeState::new();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = mesh_state.clone();

        let wait = tokio::spawn(async move {
            wait_for_initial_mesh_config(&state, &runtime, shutdown_rx).await
        });

        mesh_state.install_slice(MeshSlice {
            version: "bad-slice".to_string(),
            services: vec![MeshService {
                name: String::new(),
                namespace: "default".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!wait.is_finished());

        mesh_state.install_slice(MeshSlice {
            version: "good-slice".to_string(),
            ..MeshSlice::default()
        });

        let (config, slice) = wait
            .await
            .expect("wait task joins")
            .expect("valid slice is accepted");
        assert_eq!(slice.version, "good-slice");
        assert!(!config.plugin_configs.is_empty());
    }

    #[test]
    fn mesh_runtime_preserves_operator_global_mesh_plugin_override() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let existing = PluginConfig {
                    id: "operator-mesh-authz".to_string(),
                    plugin_name: "mesh_authz".to_string(),
                    namespace: "ferrum".to_string(),
                    config: serde_json::json!({ "mesh_slice": MeshSlice::default() }),
                    scope: PluginScope::Global,
                    proxy_id: None,
                    enabled: true,
                    priority_override: Some(2005),
                    api_spec_id: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                let config = GatewayConfig {
                    plugin_configs: vec![existing],
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let mesh_authz: Vec<_> = prepared
                    .plugin_configs
                    .iter()
                    .filter(|plugin| plugin.plugin_name == "mesh_authz")
                    .collect();

                assert_eq!(mesh_authz.len(), 1);
                assert_eq!(mesh_authz[0].id, "operator-mesh-authz");
                assert!(prepared.plugin_configs.iter().any(|plugin| {
                    plugin.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID
                        && plugin.plugin_name == "spiffe_identity"
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_updates_mesh_managed_global_plugin_by_id() {
        let runtime = test_mesh_runtime_config();
        let now = chrono::Utc::now();
        let existing = PluginConfig {
            id: MESH_REQUEST_AUTH_PLUGIN_ID.to_string(),
            plugin_name: "jwks_auth".to_string(),
            namespace: "default".to_string(),
            config: serde_json::json!({
                "providers": [
                    { "issuer": "https://stale.example.com", "jwks_uri": "https://stale.example.com/jwks" }
                ]
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![test_request_authentication(
                    "fresh",
                    PolicyScope::MeshWide,
                )],
                ..MeshConfig::default()
            })),
            plugin_configs: vec![existing],
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks_plugins: Vec<_> = prepared
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .collect();
        assert_eq!(jwks_plugins.len(), 1);
        assert_eq!(
            jwks_plugins[0].config["providers"][0]
                .get("issuer")
                .and_then(|issuer| issuer.as_str()),
            Some("https://fresh.example.com")
        );
    }

    // ── RequestAuthentication injection ──────────────────────────────────

    fn test_request_authentication(name: &str, scope: PolicyScope) -> MeshRequestAuthentication {
        MeshRequestAuthentication {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope,
            jwt_rules: vec![MeshJwtRule {
                issuer: format!("https://{name}.example.com"),
                audiences: vec!["test-app".to_string()],
                jwks_uri: Some(format!("https://{name}.example.com/jwks")),
                jwks: None,
                from_headers: Vec::new(),
                from_params: Vec::new(),
                forward_original_token: false,
            }],
        }
    }

    #[test]
    fn mesh_runtime_injects_jwks_auth_for_matching_request_authentication() {
        let runtime = MeshRuntimeConfig {
            workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![test_request_authentication(
                    "api-jwt",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");

        assert_eq!(jwks.plugin_name, "jwks_auth");
        assert_eq!(jwks.scope, PluginScope::Global);
        let providers = jwks
            .config
            .get("providers")
            .and_then(|v| v.as_array())
            .expect("providers array");
        assert_eq!(providers.len(), 1);
        assert_eq!(
            providers[0].get("issuer").and_then(|v| v.as_str()),
            Some("https://api-jwt.example.com")
        );
    }

    #[test]
    fn mesh_runtime_request_auth_uses_mesh_slice_identity_for_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            request_authentications: vec![test_request_authentication(
                "api-jwt",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
            )],
            ..MeshSlice::default()
        };

        let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None, None)
            .expect("mesh slice config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");
        let providers = jwks
            .config
            .get("providers")
            .and_then(|v| v.as_array())
            .expect("providers array");

        assert_eq!(
            providers[0].get("issuer").and_then(|v| v.as_str()),
            Some("https://api-jwt.example.com")
        );
    }

    #[test]
    fn mesh_runtime_does_not_inject_jwks_auth_for_non_matching_selector() {
        let runtime = MeshRuntimeConfig {
            workload_labels: HashMap::from([("app".to_string(), "worker".to_string())]),
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![test_request_authentication(
                    "api-only-jwt",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        assert!(
            !prepared
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID),
            "jwks_auth should not be injected for non-matching workload"
        );
    }

    #[test]
    fn mesh_runtime_merges_multiple_request_authentications() {
        let runtime = MeshRuntimeConfig {
            workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![
                    test_request_authentication(
                        "google",
                        PolicyScope::Namespace {
                            namespace: "default".to_string(),
                        },
                    ),
                    test_request_authentication("okta", PolicyScope::MeshWide),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");

        let providers = jwks
            .config
            .get("providers")
            .and_then(|v| v.as_array())
            .expect("providers array");
        assert_eq!(
            providers.len(),
            2,
            "both request authentications' rules should merge into providers"
        );
    }

    #[test]
    fn mesh_runtime_does_not_inject_jwks_auth_for_empty_rules() {
        let runtime = test_mesh_runtime_config();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "empty".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: Vec::new(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        assert!(
            !prepared
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID),
            "empty jwt_rules should not inject jwks_auth"
        );
    }

    #[test]
    fn mesh_runtime_request_auth_jwks_config_contains_audience() {
        let runtime = test_mesh_runtime_config();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "with-aud".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: vec![MeshJwtRule {
                        issuer: "https://auth.example.com".to_string(),
                        audiences: vec!["my-api".to_string()],
                        jwks_uri: Some("https://auth.example.com/jwks".to_string()),
                        jwks: None,
                        from_headers: Vec::new(),
                        from_params: Vec::new(),
                        forward_original_token: false,
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        let provider = &jwks.config["providers"][0];
        assert_eq!(
            provider
                .get("audiences")
                .and_then(|v| v.as_array())
                .cloned(),
            Some(vec![serde_json::json!("my-api")]),
            "audiences should be set"
        );
        assert_eq!(
            provider.get("jwks_uri").and_then(|v| v.as_str()),
            Some("https://auth.example.com/jwks")
        );
    }

    #[test]
    fn mesh_runtime_request_auth_jwks_config_emits_inline_jwks_and_custom_locations() {
        let runtime = test_mesh_runtime_config();
        let inline_jwks = r#"{"keys":[]}"#.to_string();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "with-inline".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: vec![MeshJwtRule {
                        issuer: "https://auth.example.com".to_string(),
                        audiences: vec!["my-api".to_string()],
                        jwks_uri: None,
                        jwks: Some(inline_jwks.clone()),
                        from_headers: vec![
                            JwtHeader {
                                name: "X-Token".to_string(),
                                prefix: Some("Token ".to_string()),
                            },
                            JwtHeader {
                                name: "X-Raw-Token".to_string(),
                                prefix: Some(String::new()),
                            },
                        ],
                        from_params: vec!["access_token".to_string()],
                        forward_original_token: false,
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        let provider = &jwks.config["providers"][0];
        assert_eq!(
            provider.get("jwks").and_then(|v| v.as_str()),
            Some(inline_jwks.as_str())
        );
        assert_eq!(
            provider.get("from_headers"),
            Some(&serde_json::json!([
                {"name": "X-Token", "prefix": "Token "},
                {"name": "X-Raw-Token", "prefix": ""}
            ]))
        );
        assert_eq!(
            provider.get("from_params"),
            Some(&serde_json::json!(["access_token"]))
        );
        assert_eq!(
            provider
                .get("forward_original_token")
                .and_then(|value| value.as_bool()),
            Some(false)
        );
    }

    fn request_auth_config_for_require_exp() -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "exp-test".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: vec![MeshJwtRule {
                        issuer: "https://auth.example.com".to_string(),
                        audiences: Vec::new(),
                        jwks_uri: Some("https://auth.example.com/jwks".to_string()),
                        jwks: None,
                        from_headers: Vec::new(),
                        from_params: Vec::new(),
                        forward_original_token: false,
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn mesh_inbound_spiffe_slot_absent_without_gateway_svid_config() {
        // No gateway SVID material → no SPIFFE slot → inbound listener keeps
        // operator-CA chain verification (the pre-existing behavior).
        let env = EnvConfig::default();
        assert!(env.gateway_svid_cert_path.is_none());
        assert!(build_mesh_inbound_spiffe_slot(&env, None).is_none());
    }

    #[test]
    fn mesh_inbound_spiffe_verifier_respects_mode_and_slot() {
        // No slot → no verifier regardless of mode.
        assert!(
            mesh_inbound_spiffe_verifier(None, config::MtlsMode::Strict, Arc::new(Vec::new()))
                .is_none()
        );

        // A present (even empty) slot yields a verifier for STRICT/PERMISSIVE
        // with the correct client-auth-mandatory posture, and none for DISABLE.
        let slot: tls::SharedBundleSlot = Arc::new(arc_swap::ArcSwap::new(Arc::new(None)));
        let strict = mesh_inbound_spiffe_verifier(
            Some(&slot),
            config::MtlsMode::Strict,
            Arc::new(Vec::new()),
        )
        .expect("STRICT yields a verifier");
        assert!(
            rustls::server::danger::ClientCertVerifier::client_auth_mandatory(strict.as_ref()),
            "STRICT must mandate client auth"
        );
        let permissive = mesh_inbound_spiffe_verifier(
            Some(&slot),
            config::MtlsMode::Permissive,
            Arc::new(Vec::new()),
        )
        .expect("PERMISSIVE yields a verifier");
        assert!(
            !rustls::server::danger::ClientCertVerifier::client_auth_mandatory(permissive.as_ref()),
            "PERMISSIVE must not mandate client auth"
        );
        assert!(
            mesh_inbound_spiffe_verifier(
                Some(&slot),
                config::MtlsMode::Disable,
                Arc::new(Vec::new())
            )
            .is_none(),
            "DISABLE has no TLS, so no verifier"
        );
    }

    #[test]
    fn staged_spiffe_bundle_publishes_only_on_apply() {
        // F4: a rebuilt inbound SPIFFE trust-bundle must NOT reach the live slot
        // until the slice is accepted. `publish_staged_spiffe_bundle` is the
        // post-accept publish step; until it runs the live slot keeps its
        // previous value, and `None` (rejected/no-slot) leaves it untouched.
        use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet};

        let td = TrustDomain::new("td.stage-test").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let original = Arc::new(Some(SvidBundle {
            spiffe_id: id.clone(),
            cert_chain_der: vec![vec![1, 2, 3]],
            private_key_pkcs8_der: Vec::new(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td.clone(),
                x509_authorities: vec![vec![4, 5, 6]],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }),
        }));
        let slot: tls::SharedBundleSlot = Arc::new(arc_swap::ArcSwap::new(original.clone()));

        // A `None` staged bundle (rejected slice or no SVID slot) is a no-op.
        publish_staged_spiffe_bundle(None);
        assert!(
            Arc::ptr_eq(&slot.load_full(), &original),
            "publishing None must leave the live slot untouched"
        );

        // Build a replacement bundle and stage it. Staging must NOT mutate the
        // live slot.
        let replacement = Arc::new(Some(SvidBundle {
            spiffe_id: id,
            cert_chain_der: vec![vec![7, 8, 9]],
            private_key_pkcs8_der: Vec::new(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td,
                x509_authorities: vec![vec![10, 11, 12]],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }),
        }));
        let staged = Some(StagedSpiffeBundle {
            slot: slot.clone(),
            bundle: replacement.clone(),
        });
        assert!(
            Arc::ptr_eq(&slot.load_full(), &original),
            "merely holding a staged bundle must not change the live slot"
        );

        // Publishing (post-accept) swaps the slot to the staged bundle.
        publish_staged_spiffe_bundle(staged);
        assert!(
            Arc::ptr_eq(&slot.load_full(), &replacement),
            "publish must store the staged bundle into the live slot"
        );
    }

    #[test]
    fn mesh_runtime_request_auth_require_exp_defaults_secure() {
        // Secure default: the auto-injected mesh request-auth plugin requires
        // the JWT `exp` claim so `exp`-less tokens cannot live forever. This
        // honors the "validate_exp = true" invariant.
        let runtime = test_mesh_runtime_config();
        assert!(
            runtime.request_auth_require_exp,
            "test runtime should carry the secure default"
        );
        let prepared =
            prepare_gateway_config_for_mesh(request_auth_config_for_require_exp(), &runtime)
                .expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        assert_eq!(
            jwks.config.get("require_exp").and_then(|v| v.as_bool()),
            Some(true),
            "mesh request auth must default require_exp=true (secure)"
        );
    }

    #[test]
    fn mesh_runtime_request_auth_require_exp_can_be_relaxed() {
        // Operators with Istio issuers that omit `exp` can opt out via
        // FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=false.
        let mut runtime = test_mesh_runtime_config();
        runtime.request_auth_require_exp = false;
        let prepared =
            prepare_gateway_config_for_mesh(request_auth_config_for_require_exp(), &runtime)
                .expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        assert_eq!(
            jwks.config.get("require_exp").and_then(|v| v.as_bool()),
            Some(false),
            "FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=false must relax require_exp"
        );
    }

    // ── Mesh topology tests ──────────────────────────────────────────────

    #[test]
    fn mesh_topology_parses_node_waypoint_variants() {
        assert_eq!(
            MeshTopology::parse("node_waypoint").unwrap(),
            MeshTopology::NodeWaypoint
        );
        assert_eq!(
            MeshTopology::parse("node-waypoint").unwrap(),
            MeshTopology::NodeWaypoint
        );
        assert_eq!(
            MeshTopology::parse("NODE_WAYPOINT").unwrap(),
            MeshTopology::NodeWaypoint
        );
        assert_eq!(MeshTopology::NodeWaypoint.as_str(), "node_waypoint");
    }

    #[test]
    fn mesh_topology_parses_egress_gateway_variants() {
        assert_eq!(
            MeshTopology::parse("egress_gateway").unwrap(),
            MeshTopology::EgressGateway
        );
        assert_eq!(
            MeshTopology::parse("egress-gateway").unwrap(),
            MeshTopology::EgressGateway
        );
        assert_eq!(
            MeshTopology::parse("EGRESS_GATEWAY").unwrap(),
            MeshTopology::EgressGateway
        );
        assert!(MeshTopology::parse("egress").is_err());
        assert_eq!(MeshTopology::EgressGateway.as_str(), "egress_gateway");
    }

    #[test]
    fn mesh_runtime_config_parses_egress_gateway_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "egress_gateway"),
                ("FERRUM_MESH_EGRESS_LISTEN_ADDR", "0.0.0.0:15444"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.topology, MeshTopology::EgressGateway);
                assert_eq!(
                    runtime.egress_listen_addr,
                    "0.0.0.0:15444".parse::<SocketAddr>().unwrap()
                );
            },
        );
    }

    #[test]
    fn mesh_egress_gateway_listener_plan_has_single_mtls_listener() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "egress_gateway"),
                ("FERRUM_MESH_EGRESS_LISTEN_ADDR", "0.0.0.0:15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 1);
                let listener = &plan[0];
                assert_eq!(listener.direction, MeshTrafficDirection::Inbound);
                assert_eq!(listener.kind, MeshListenerKind::MtlsTermination);
                assert_eq!(listener.addr.port(), 15443);
            },
        );
    }

    #[test]
    fn egress_gateway_requires_mtls_materials() {
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let mut env = EnvConfig::default();

        let err = validate_egress_gateway_mtls_config(&runtime, &env).unwrap_err();
        assert!(err.to_string().contains("FERRUM_FRONTEND_TLS_CERT_PATH"));

        env.frontend_tls_cert_path = Some("/tmp/server.crt".to_string());
        env.frontend_tls_key_path = Some("/tmp/server.key".to_string());
        let err = validate_egress_gateway_mtls_config(&runtime, &env).unwrap_err();
        assert!(
            err.to_string()
                .contains("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH")
        );

        env.frontend_tls_client_ca_bundle_path = Some("/tmp/client-ca.pem".to_string());
        validate_egress_gateway_mtls_config(&runtime, &env).expect("mTLS config is complete");

        env.tls_no_verify = true;
        let err = validate_egress_gateway_mtls_config(&runtime, &env).unwrap_err();
        assert!(err.to_string().contains("FERRUM_TLS_NO_VERIFY=true"));
    }

    #[test]
    fn strict_peer_auth_fails_closed_without_frontend_tls_materials() {
        let env = EnvConfig::default();
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");

        let err = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Strict,
            None,
            None,
            None,
        )
        .expect_err("strict mTLS must require cert and key material");

        assert!(
            err.to_string()
                .contains("PeerAuthentication STRICT requires")
        );
    }

    #[test]
    fn permissive_peer_auth_allows_missing_frontend_tls_materials() {
        let env = EnvConfig::default();
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");

        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Permissive,
            None,
            None,
            None,
        )
        .expect("permissive mTLS can run without frontend TLS materials");

        assert!(tls_config.is_none());
    }

    #[test]
    fn permissive_without_ca_bundle_degrades_to_no_client_auth() {
        ensure_crypto_provider();
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: None,
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("mesh frontend identity");

        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Permissive,
            mesh_frontend_identity.as_deref(),
            None,
            None,
        )
        .expect("permissive without CA bundle should succeed");

        assert!(
            tls_config.is_some(),
            "TLS config should be built (no client auth, but server TLS active)"
        );
    }

    #[test]
    fn decide_mesh_inbound_fail_closed_matrix() {
        // No trigger (listener is mTLS-capable) → always Ok.
        assert_eq!(
            decide_mesh_inbound_fail_closed(false, false),
            MeshInboundFailClosed::Ok
        );
        assert_eq!(
            decide_mesh_inbound_fail_closed(false, true),
            MeshInboundFailClosed::Ok
        );
        // Triggered + production → Refuse (a production mesh must serve mTLS on
        // its inbound listener).
        assert_eq!(
            decide_mesh_inbound_fail_closed(true, true),
            MeshInboundFailClosed::Refuse
        );
        // Triggered + dev → allow with a warning. Reaching a plaintext posture in
        // dev is intentional (explicit DISABLE, or an acknowledged no-identity
        // posture that the config-time FERRUM_MESH_ALLOW_NO_CA gate already let
        // through), so the runtime gate does not re-refuse it.
        assert_eq!(
            decide_mesh_inbound_fail_closed(true, false),
            MeshInboundFailClosed::AllowWithWarning
        );
    }

    #[test]
    fn load_mesh_frontend_server_identity_falls_back_to_gateway_svid() {
        ensure_crypto_provider();
        // Only gateway SVID material set (no explicit frontend TLS): the SVID
        // must back the inbound server identity so the listener is not plaintext
        // (issue #1523, gap #3).
        let env = EnvConfig {
            gateway_svid_cert_path: Some("tests/certs/server.crt".to_string()),
            gateway_svid_key_path: Some("tests/certs/server.key".to_string()),
            ..EnvConfig::default()
        };
        let identity = load_mesh_frontend_server_identity(&env)
            .expect("gateway SVID load should succeed")
            .expect("gateway SVID must back the inbound server identity");
        assert_eq!(identity.cert_path(), "tests/certs/server.crt");

        // Explicit frontend TLS takes precedence over the SVID fallback (a
        // broken SVID path here must be ignored because frontend TLS is set).
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            gateway_svid_cert_path: Some("/nonexistent/svid.crt".to_string()),
            gateway_svid_key_path: Some("/nonexistent/svid.key".to_string()),
            ..EnvConfig::default()
        };
        let identity = load_mesh_frontend_server_identity(&env)
            .expect("explicit frontend TLS load should succeed")
            .expect("explicit frontend TLS identity");
        assert_eq!(identity.cert_path(), "tests/certs/server.crt");

        // Neither configured → no server identity (not an error here; the
        // fail-closed gate decides what to do with a plaintext posture).
        assert!(
            load_mesh_frontend_server_identity(&EnvConfig::default())
                .expect("no identity is not a load error")
                .is_none()
        );
    }

    #[test]
    fn enforce_mesh_inbound_fail_closed_skips_passthrough_topology() {
        // EastWestGateway has no TLS-terminating inbound listener (SNI
        // passthrough forwards encrypted bytes), so there is no plaintext-inbound
        // posture to enforce against — Ok even with DISABLE mode, no identity, and
        // production=true (the no-termination-listener early return runs first).
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EastWestGateway,
            ..test_mesh_runtime_config()
        };
        enforce_mesh_inbound_fail_closed(
            &runtime,
            &EnvConfig::default(),
            config::MtlsMode::Disable,
            None,
            None,
            true,
        )
        .expect("east-west gateway has no termination listener to fail closed on");
    }

    #[test]
    fn enforce_mesh_inbound_fail_closed_refuses_plaintext_under_production_only() {
        // A termination-listener topology whose resolved inbound listener would
        // serve plaintext (`frontend_tls` None — PeerAuthentication DISABLE, or no
        // usable server identity) is refused under production and allowed with a
        // warning in dev. This exercises the `enforce_` wrapper's plaintext branch
        // directly: `decide_mesh_inbound_fail_closed_matrix` covers the pure
        // decision, and the `#[ignore]` functional test covers the production
        // refusal end-to-end, but the wrapper's own routing (no-SVID env →
        // plaintext branch, reason selection, error vs Ok) is otherwise only hit
        // in `--ignored` runs. No gateway SVID is configured, so the
        // configured-but-unloadable SVID branch does not apply.
        let runtime = test_mesh_runtime_config(); // Sidecar → has MtlsTermination

        // Production refuses to bring up a plaintext inbound listener (DISABLE).
        let err = enforce_mesh_inbound_fail_closed(
            &runtime,
            &EnvConfig::default(),
            config::MtlsMode::Disable,
            None, // frontend_tls: would serve plaintext
            None, // spiffe_bundle_slot
            true, // production
        )
        .expect_err("production must refuse a plaintext inbound termination listener");
        let msg = err.to_string();
        assert!(
            msg.contains("FERRUM_MESH_PRODUCTION_MODE=true") && msg.contains("DISABLE"),
            "unexpected refusal message: {msg}"
        );

        // Dev tolerates plaintext with a warning — here via the "no usable server
        // identity" reason path (PERMISSIVE, still no identity → `frontend_tls`
        // None), the other way a termination listener resolves to plaintext.
        enforce_mesh_inbound_fail_closed(
            &runtime,
            &EnvConfig::default(),
            config::MtlsMode::Permissive,
            None,
            None,
            false, // dev
        )
        .expect("dev tolerates a plaintext inbound listener with a warning");
    }

    #[test]
    fn enforce_mesh_inbound_fail_closed_rejects_configured_but_unloadable_svid_verifier() {
        ensure_crypto_provider();
        // gap #2: a TLS-serving inbound listener whose configured gateway SVID
        // verifier failed to load (slot None while all three FERRUM_GATEWAY_SVID_*
        // are named) is a genuine misconfiguration — fatal regardless of
        // FERRUM_MESH_PRODUCTION_MODE, mirroring the hard error a broken SVID
        // cert/key already gets. It is NOT the intentional plaintext/DISABLE
        // posture the dev relaxation is for.
        let runtime = test_mesh_runtime_config(); // Sidecar → has MtlsTermination
        let env = EnvConfig {
            // A real frontend identity so the listener serves TLS (frontend_tls Some).
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            // Gateway SVID material is *configured* (all three paths named).
            gateway_svid_cert_path: Some("tests/certs/server.crt".to_string()),
            gateway_svid_key_path: Some("tests/certs/server.key".to_string()),
            gateway_svid_trust_bundle_path: Some("/nonexistent/svid-bundle.pem".to_string()),
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let identity = load_mesh_frontend_server_identity(&env).expect("server identity");
        let frontend_tls = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Permissive,
            identity.as_deref(),
            None,
            None,
        )
        .expect("frontend tls builds")
        .expect("frontend tls present");

        // The SPIFFE verifier slot failed to load (None) → fatal in BOTH dev and
        // production.
        for production in [false, true] {
            let err = enforce_mesh_inbound_fail_closed(
                &runtime,
                &env,
                config::MtlsMode::Permissive,
                Some(&frontend_tls),
                None, // SPIFFE verifier slot failed to load
                production,
            )
            .expect_err("a configured-but-unloadable SVID verifier must be fatal");
            let msg = err.to_string();
            assert!(
                msg.contains("SVID material is configured") && msg.contains("WITHOUT SPIFFE"),
                "unexpected error (production={production}): {msg}"
            );
        }
    }

    #[test]
    fn resolve_mesh_inbound_client_auth_matrix() {
        use config::MtlsMode;
        use tls::MeshClientAuth;

        // STRICT always requires a peer cert, regardless of trust anchors.
        for (has_ca, has_spiffe) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(
                resolve_mesh_inbound_client_auth(MtlsMode::Strict, has_ca, has_spiffe),
                MeshClientAuthDecision::Resolved(MeshClientAuth::Required),
                "STRICT must require a peer cert"
            );
        }

        // PERMISSIVE with any trust anchor → Optional (request + verify-if-offered,
        // still admit cert-less peers). This is the finding's core fix: identity
        // is recorded when a cert is offered instead of degrading to anonymous.
        for (has_ca, has_spiffe) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                resolve_mesh_inbound_client_auth(MtlsMode::Permissive, has_ca, has_spiffe),
                MeshClientAuthDecision::Resolved(MeshClientAuth::Optional),
                "PERMISSIVE with a trust anchor (ca={has_ca}, spiffe={has_spiffe}) must request \
                 and verify-if-offered, not skip client auth"
            );
        }

        // PERMISSIVE with NO trust anchor → the explicit degraded decision (the
        // caller warns once); it maps to no client auth.
        let no_anchor = resolve_mesh_inbound_client_auth(MtlsMode::Permissive, false, false);
        assert_eq!(no_anchor, MeshClientAuthDecision::PermissiveNoTrustAnchor);
        assert_eq!(no_anchor.client_auth(), MeshClientAuth::None);

        // Client-side DR.tls modes must never request client auth on a
        // server-side listener even if anchors happen to exist.
        for mode in [MtlsMode::Simple, MtlsMode::Mutual, MtlsMode::IstioMutual] {
            assert_eq!(
                resolve_mesh_inbound_client_auth(mode, true, true),
                MeshClientAuthDecision::Resolved(MeshClientAuth::None),
                "client-side DR.tls mode {mode:?} must not request client auth"
            );
        }

        // DISABLE never reaches the resolver in production (early return in
        // load_mesh_frontend_tls), but the defensive mapping that replaced the
        // former unreachable!() must stay no-client-auth and never panic.
        assert_eq!(
            resolve_mesh_inbound_client_auth(MtlsMode::Disable, true, true),
            MeshClientAuthDecision::Resolved(MeshClientAuth::None),
            "DISABLE must map to no client auth, never panic"
        );
    }

    /// Build a populated inbound SPIFFE bundle slot for tests that only need the
    /// slot to be present (so `mesh_inbound_spiffe_verifier` yields a verifier).
    /// The DER bytes are synthetic — these tests assert client-auth *wiring*, not
    /// peer-chain verification, which is covered in `tls::spiffe` tests.
    fn populated_spiffe_slot() -> tls::SharedBundleSlot {
        use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet};
        let td = TrustDomain::new("td.permissive-wiring").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let bundle = SvidBundle {
            spiffe_id: id,
            cert_chain_der: vec![vec![1, 2, 3]],
            private_key_pkcs8_der: Vec::new(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td,
                x509_authorities: vec![vec![4, 5, 6]],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }),
        };
        Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(bundle))))
    }

    #[test]
    fn permissive_with_spiffe_slot_records_identity_via_optional_client_auth() {
        // The finding: in PERMISSIVE, when a gateway SVID trust anchor exists the
        // listener must request + verify-if-offered (so a peer's SVID identity is
        // recorded) rather than silently skip client auth. With an SVID slot and
        // NO operator client CA bundle, `load_mesh_frontend_tls` must still build
        // a TLS config wired to the SPIFFE trust-domain verifier in Optional mode.
        ensure_crypto_provider();
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: None,
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("mesh frontend identity");
        let slot = populated_spiffe_slot();

        // The verifier built for this slot in PERMISSIVE must request but not
        // mandate client auth — that is exactly what records identity when a
        // cert is offered while still admitting cert-less peers.
        let verifier = mesh_inbound_spiffe_verifier(
            Some(&slot),
            config::MtlsMode::Permissive,
            Arc::new(Vec::new()),
        )
        .expect("PERMISSIVE with an SVID slot must yield a verifier");
        assert!(
            rustls::server::danger::ClientCertVerifier::offer_client_auth(verifier.as_ref()),
            "PERMISSIVE must still request a client cert so identity is recorded when present"
        );
        assert!(
            !rustls::server::danger::ClientCertVerifier::client_auth_mandatory(verifier.as_ref()),
            "PERMISSIVE must not require a client cert"
        );

        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Permissive,
            mesh_frontend_identity.as_deref(),
            None,
            Some(&slot),
        )
        .expect("permissive with an SVID slot should build a TLS config")
        .expect("TLS config present (server TLS + optional SPIFFE client auth)");
        // ALPN proves we built a real mesh frontend ServerConfig, not a plaintext
        // fallback (`Disable` returns None and never reaches here).
        assert!(
            tls_config.alpn_protocols.contains(&b"h2".to_vec()),
            "mesh frontend TLS must advertise h2"
        );
    }

    #[test]
    fn permissive_with_operator_ca_uses_optional_client_auth_without_spiffe_slot() {
        // Fallback trust anchor: no gateway SVID material, but an operator client
        // CA bundle is configured. PERMISSIVE must request + verify-if-offered via
        // the operator CA (WebPki `allow_unauthenticated`), not skip client auth.
        ensure_crypto_provider();
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            // Reuse the server cert as a stand-in client CA bundle (valid PEM).
            frontend_tls_client_ca_bundle_path: Some("tests/certs/server.crt".to_string()),
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("mesh frontend identity");

        assert_eq!(
            resolve_mesh_inbound_client_auth(config::MtlsMode::Permissive, true, false),
            MeshClientAuthDecision::Resolved(tls::MeshClientAuth::Optional),
            "PERMISSIVE with only an operator CA bundle must resolve to Optional"
        );

        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Permissive,
            mesh_frontend_identity.as_deref(),
            None,
            None,
        )
        .expect("permissive with operator CA should build a TLS config")
        .expect("TLS config present (server TLS + optional operator-CA client auth)");
        assert!(
            tls_config.alpn_protocols.contains(&b"h2".to_vec()),
            "mesh frontend TLS must advertise h2"
        );
    }

    #[test]
    fn mesh_frontend_tls_rebuild_uses_cached_server_identity() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::copy("tests/certs/server.crt", &cert_path).expect("copy cert");
        std::fs::copy("tests/certs/server.key", &key_path).expect("copy key");
        let env = EnvConfig {
            frontend_tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
            frontend_tls_key_path: Some(key_path.to_string_lossy().into_owned()),
            frontend_tls_client_ca_bundle_path: Some("tests/certs/server.crt".to_string()),
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("load identity");

        std::fs::write(&cert_path, b"not a cert").expect("replace cert");
        std::fs::write(&key_path, b"not a key").expect("replace key");

        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Strict,
            mesh_frontend_identity.as_deref(),
            None,
            None,
        )
        .expect("strict rebuild should use cached server identity");

        assert!(tls_config.is_some());
    }

    #[test]
    fn mesh_frontend_tls_rebuild_uses_snapshot_client_ca_bytes() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("client-ca.pem");
        std::fs::copy("tests/certs/server.crt", &ca_path).expect("copy CA");
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: Some(ca_path.to_string_lossy().into_owned()),
            ..EnvConfig::default()
        };
        let snapshot = mesh_inbound_tls_reload_snapshot(&env, config::MtlsMode::Strict)
            .expect("snapshot reads CA bytes");
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("load identity");

        std::fs::write(&ca_path, b"not a ca").expect("replace CA");

        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Strict,
            mesh_frontend_identity.as_deref(),
            snapshot.client_ca_bundle.as_ref(),
            None,
        )
        .expect("strict rebuild should use snapshot CA bytes");

        assert!(tls_config.is_some());
    }

    // ── Topology-aware port resolution + Disable-mode validation ────────

    fn runtime_with_topology(topology: MeshTopology) -> MeshRuntimeConfig {
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = topology;
        runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
        runtime.hbone_listen_addr = "127.0.0.1:15008".parse().unwrap();
        runtime.egress_listen_addr = "127.0.0.1:15090".parse().unwrap();
        runtime
    }

    fn peer_auth_with_port_override(
        port: u16,
        mode: config::MtlsMode,
    ) -> config::PeerAuthentication {
        config::PeerAuthentication {
            name: "ns-policy".to_string(),
            namespace: "default".to_string(),
            scope: None,
            selector: None,
            mtls_mode: config::MtlsMode::Permissive,
            port_overrides: HashMap::from([(port, mode)]),
        }
    }

    fn slice_with_peer_auths(peer_auths: Vec<config::PeerAuthentication>) -> MeshSlice {
        MeshSlice {
            namespace: "default".to_string(),
            peer_authentications: peer_auths,
            ..MeshSlice::default()
        }
    }

    #[test]
    fn inbound_mtls_resolution_port_picks_topology_correct_port() {
        let sidecar = runtime_with_topology(MeshTopology::Sidecar);
        assert_eq!(inbound_mtls_resolution_port(&sidecar), 15006);

        let ambient = runtime_with_topology(MeshTopology::Ambient);
        assert_eq!(inbound_mtls_resolution_port(&ambient), 15008);

        let node_waypoint = runtime_with_topology(MeshTopology::NodeWaypoint);
        assert_eq!(inbound_mtls_resolution_port(&node_waypoint), 15008);

        let egress = runtime_with_topology(MeshTopology::EgressGateway);
        assert_eq!(inbound_mtls_resolution_port(&egress), 15090);

        // East-west has no TLS termination; pick a stable port for the call.
        let east_west = runtime_with_topology(MeshTopology::EastWestGateway);
        assert_eq!(inbound_mtls_resolution_port(&east_west), 15006);
    }

    #[test]
    fn resolve_inbound_mtls_mode_honours_hbone_port_override_for_ambient() {
        // Port override keyed on the HBONE port (15008). With the prior bug
        // (always looking up 15006) this would have fallen through to the
        // top-level Permissive mode.
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15008,
            config::MtlsMode::Strict,
        )]);
        let runtime = runtime_with_topology(MeshTopology::Ambient);

        assert_eq!(
            resolve_inbound_mtls_mode(Some(&slice), &runtime),
            config::MtlsMode::Strict,
        );
    }

    #[test]
    fn resolve_inbound_mtls_mode_honours_egress_port_override_for_egress_gateway() {
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15090,
            config::MtlsMode::Strict,
        )]);
        let runtime = runtime_with_topology(MeshTopology::EgressGateway);

        assert_eq!(
            resolve_inbound_mtls_mode(Some(&slice), &runtime),
            config::MtlsMode::Strict,
        );
    }

    #[test]
    fn resolve_inbound_mtls_mode_honours_inbound_port_override_for_sidecar() {
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15006,
            config::MtlsMode::Strict,
        )]);
        let runtime = runtime_with_topology(MeshTopology::Sidecar);

        assert_eq!(
            resolve_inbound_mtls_mode(Some(&slice), &runtime),
            config::MtlsMode::Strict,
        );
    }

    #[test]
    fn validate_inbound_mtls_mode_rejects_disable_on_ambient() {
        let runtime = runtime_with_topology(MeshTopology::Ambient);
        let err = validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect_err("Disable on Ambient must be rejected");

        assert!(err.to_string().contains("ambient"));
        assert!(err.to_string().contains("HBONE"));
    }

    #[test]
    fn validate_inbound_mtls_mode_rejects_disable_on_node_waypoint() {
        let runtime = runtime_with_topology(MeshTopology::NodeWaypoint);
        let err = validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect_err("Disable on NodeWaypoint must be rejected");

        assert!(err.to_string().contains("node_waypoint"));
        assert!(err.to_string().contains("HBONE"));
    }

    #[test]
    fn validate_inbound_mtls_mode_rejects_disable_on_egress_gateway() {
        let runtime = runtime_with_topology(MeshTopology::EgressGateway);
        let err = validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect_err("Disable on EgressGateway must be rejected");

        assert!(err.to_string().contains("EgressGateway"));
    }

    #[test]
    fn validate_inbound_mtls_mode_accepts_disable_on_sidecar() {
        let runtime = runtime_with_topology(MeshTopology::Sidecar);
        validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect("Disable on Sidecar is allowed (plaintext-only inbound)");
    }

    #[test]
    fn startup_inbound_mtls_mode_rejects_invalid_initial_disable() {
        let runtime = runtime_with_topology(MeshTopology::Ambient);
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15008,
            config::MtlsMode::Disable,
        )]);

        let err = startup_inbound_mtls_mode(Some(&slice), &runtime)
            .expect_err("Disable on Ambient should fail closed at startup");

        assert!(err.to_string().contains("ambient"));
    }

    #[test]
    fn startup_inbound_mtls_mode_accepts_valid_initial_mode() {
        let runtime = runtime_with_topology(MeshTopology::Ambient);
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15008,
            config::MtlsMode::Strict,
        )]);

        let mode = startup_inbound_mtls_mode(Some(&slice), &runtime)
            .expect("strict mode should be accepted at startup");

        assert_eq!(mode, config::MtlsMode::Strict);
    }

    #[test]
    fn live_reload_inbound_mtls_mode_rejects_invalid_disable_slice() {
        let runtime = runtime_with_topology(MeshTopology::EgressGateway);
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15090,
            config::MtlsMode::Disable,
        )]);

        assert!(
            live_reload_inbound_mtls_mode(&slice, &runtime).is_none(),
            "invalid live PeerAuthentication update should be rejected"
        );
    }

    #[test]
    fn mesh_inbound_tls_reload_snapshot_tracks_client_ca_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("client-ca.pem");
        std::fs::write(&ca_path, b"first-ca").expect("write first CA");
        let env = EnvConfig {
            frontend_tls_client_ca_bundle_path: Some(ca_path.to_string_lossy().to_string()),
            ..EnvConfig::default()
        };

        let first = mesh_inbound_tls_reload_snapshot(&env, config::MtlsMode::Strict)
            .expect("first snapshot");
        std::fs::write(&ca_path, b"second-ca").expect("write second CA");
        let second = mesh_inbound_tls_reload_snapshot(&env, config::MtlsMode::Strict)
            .expect("second snapshot");

        assert_ne!(first, second);
    }

    #[test]
    fn mesh_inbound_tls_slot_swaps_atomically() {
        ensure_crypto_provider();
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let mesh_frontend_identity =
            load_mesh_frontend_server_identity(&env).expect("mesh frontend identity");
        let tls_config = load_mesh_frontend_tls(
            &env,
            &tls_policy,
            &[],
            config::MtlsMode::Permissive,
            mesh_frontend_identity.as_deref(),
            None,
            None,
        )
        .expect("TLS config builds")
        .expect("TLS config present");
        let slot: crate::proxy::SharedMeshInboundTls =
            Arc::new(arc_swap::ArcSwap::new(Arc::new(None)));

        slot.store(Arc::new(Some(tls_config.clone())));
        let loaded = slot.load_full();
        assert!(
            loaded
                .as_ref()
                .as_ref()
                .is_some_and(|candidate| Arc::ptr_eq(candidate, &tls_config)),
            "load_full should observe the swapped TLS config"
        );

        slot.store(Arc::new(None));
        assert!(
            slot.load_full().is_none(),
            "load_full should observe the plaintext swap"
        );
    }

    #[test]
    fn validate_inbound_mtls_mode_accepts_disable_on_east_west_gateway() {
        // East-west gateways do SNI passthrough — there is no TLS-terminating
        // listener to fail closed. The resolved mode is structurally unused.
        let runtime = runtime_with_topology(MeshTopology::EastWestGateway);
        validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect("Disable on EastWestGateway is structurally a no-op");
    }

    #[test]
    fn validate_inbound_mtls_mode_accepts_permissive_and_strict_on_all_topologies() {
        for topology in [
            MeshTopology::Sidecar,
            MeshTopology::Ambient,
            MeshTopology::NodeWaypoint,
            MeshTopology::EastWestGateway,
            MeshTopology::EgressGateway,
        ] {
            let runtime = runtime_with_topology(topology);
            validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Permissive)
                .unwrap_or_else(|e| panic!("Permissive on {:?} should succeed: {}", topology, e));
            validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Strict)
                .unwrap_or_else(|e| panic!("Strict on {:?} should succeed: {}", topology, e));
        }
    }

    fn test_external_service_entry(
        name: &str,
        hosts: Vec<String>,
        port: u16,
        protocol: AppProtocol,
    ) -> ServiceEntry {
        ServiceEntry {
            name: name.to_string(),
            namespace: "default".to_string(),
            hosts,
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port,
                protocol,
                name: Some("http".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }
    }

    #[test]
    fn egress_materializes_proxies_from_external_service_entries() {
        let service_entries = vec![test_external_service_entry(
            "external-api",
            vec!["api.external.com".to_string()],
            443,
            AppProtocol::Tls,
        )];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);

        let proxy = &proxies[0];
        assert_eq!(
            proxy.id,
            "mesh-egress-default-external-api-api-dot-external-dot-com-443"
        );
        assert_eq!(proxy.hosts, vec!["api.external.com"]);
        assert!(proxy.listen_path.is_none());
        assert!(proxy.listen_port.is_none());
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Https));
        assert!(!proxy.frontend_tls);
        assert!(!proxy.passthrough);
        assert_eq!(
            proxy.upstream_id.as_deref(),
            Some("mesh-egress-up-default-external-api-api-dot-external-dot-com-443")
        );
        assert!(proxy.preserve_host_header);

        let upstream = &upstreams[0];
        assert_eq!(
            upstream.id,
            "mesh-egress-up-default-external-api-api-dot-external-dot-com-443"
        );
        assert!(
            upstream
                .health_checks
                .as_ref()
                .is_some_and(|checks| { checks.active.is_none() && checks.passive.is_some() })
        );
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].host, "api.external.com");
        assert_eq!(upstream.targets[0].port, 443);
    }

    #[test]
    fn egress_skips_mesh_internal_service_entries() {
        let service_entries = vec![ServiceEntry {
            name: "internal-svc".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["internal.svc.cluster.local".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshInternal,
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_skips_mesh_internal_service_entries_with_static_endpoints() {
        let service_entries = vec![ServiceEntry {
            name: "internal-static".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["internal.svc.cluster.local".to_string()],
            endpoints: vec![MeshEndpoint {
                address: "10.1.0.2".to_string(),
                ports: HashMap::from([("http".to_string(), 8080)]),
                labels: HashMap::new(),
                network: None,
            }],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshInternal,
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_respects_namespace_and_export_to_visibility() {
        let mut service_entry = test_external_service_entry(
            "payments-api",
            vec!["payments.example.com".to_string()],
            443,
            AppProtocol::Tls,
        );
        service_entry.namespace = "payments".to_string();

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &[service_entry.clone()],
            "default",
            &std::collections::HashSet::new(),
            true,
        );
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());

        service_entry.export_to = vec!["*".to_string()];
        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &[service_entry],
            "default",
            &std::collections::HashSet::new(),
            true,
        );
        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
    }

    #[test]
    fn egress_materializes_l4_service_entry_ports_as_stream_proxies() {
        // Pre-T5-A this entry was skipped (L4 protocols had no materialization
        // path). T5-A added stream-family materialization: an L4 SE now
        // produces a `tcp` stream proxy bound on the SE's own port.
        let service_entries = vec![ServiceEntry {
            name: "mysql".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["db.external.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 3306,
                protocol: AppProtocol::Mysql,
                name: Some("mysql".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );
        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);

        let proxy = &proxies[0];
        assert!(proxy.hosts.is_empty(), "stream proxy must have no hosts");
        assert!(proxy.listen_path.is_none());
        assert_eq!(proxy.listen_port, Some(3306));
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert!(!proxy.passthrough);
        assert!(!proxy.frontend_tls);
        assert_eq!(
            proxy.name.as_deref(),
            Some("mesh egress mysql db.external.com:3306")
        );

        let upstream = &upstreams[0];
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].host, "db.external.com");
        assert_eq!(upstream.targets[0].port, 3306);
    }

    #[test]
    fn egress_sanitizes_wildcard_host_ids_but_preserves_route_host() {
        let service_entries = vec![test_external_service_entry(
            "wildcard-api",
            vec!["*.api.external.com".to_string()],
            443,
            AppProtocol::Tls,
        )];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(
            proxies[0].id,
            "mesh-egress-default-wildcard-api-wildcard-dot-api-dot-external-dot-com-443"
        );
        assert_eq!(proxies[0].hosts, vec!["*.api.external.com"]);
        assert_eq!(
            upstreams[0].id,
            "mesh-egress-up-default-wildcard-api-wildcard-dot-api-dot-external-dot-com-443"
        );
    }

    #[test]
    fn egress_host_id_sanitization_preserves_distinct_valid_hostnames() {
        assert_ne!(
            sanitize_egress_host_id_part("a.b.com"),
            sanitize_egress_host_id_part("a-b.com")
        );
        assert_eq!(
            sanitize_egress_host_id_part("*.api.external.com"),
            "wildcard-dot-api-dot-external-dot-com"
        );
    }

    #[test]
    fn egress_creates_one_host_only_proxy_per_host() {
        let service_entries = vec![ServiceEntry {
            name: "multi-host".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![
                ServicePort {
                    port: 80,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                    target_port: None,
                },
                ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                    target_port: None,
                },
            ],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        // Host-only HTTP proxies cannot safely distinguish multiple ports for
        // the same host, so only the first materialized port owns each host.
        assert_eq!(proxies.len(), 2);
        assert_eq!(upstreams.len(), 2);

        assert!(
            proxies
                .iter()
                .any(|p| p.id == "mesh-egress-default-multi-host-api-dot-example-dot-com-80")
        );
        assert!(
            proxies
                .iter()
                .any(|p| p.id == "mesh-egress-default-multi-host-cdn-dot-example-dot-com-80")
        );

        let http_proxy = proxies
            .iter()
            .find(|p| p.id == "mesh-egress-default-multi-host-api-dot-example-dot-com-80")
            .unwrap();
        assert_eq!(http_proxy.backend_scheme, Some(BackendScheme::Http));
    }

    #[test]
    fn egress_uses_static_endpoints_with_named_ports_as_targets() {
        let service_entries = vec![ServiceEntry {
            name: "static-backend".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["api.external.com".to_string()],
            endpoints: vec![
                MeshEndpoint {
                    address: "10.0.0.1".to_string(),
                    ports: HashMap::from([("http".to_string(), 8080)]),
                    labels: HashMap::from([("az".to_string(), "us-east-1a".to_string())]),
                    network: None,
                },
                MeshEndpoint {
                    address: "10.0.0.2".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                },
            ],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);

        let upstream = &upstreams[0];
        assert_eq!(upstream.targets.len(), 1);

        assert_eq!(upstream.targets[0].host, "10.0.0.1");
        assert_eq!(upstream.targets[0].port, 8080);
        assert_eq!(
            upstream.targets[0].tags.get("az").map(String::as_str),
            Some("us-east-1a")
        );
    }

    #[test]
    fn egress_dns_resolution_uses_hosts_as_targets() {
        let service_entries = vec![test_external_service_entry(
            "dns-svc",
            vec![
                "primary.external.com".to_string(),
                "secondary.external.com".to_string(),
            ],
            443,
            AppProtocol::Tls,
        )];

        let (_, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(upstreams.len(), 2);
        let primary = upstreams
            .iter()
            .find(|upstream| upstream.id.contains("primary-dot-external-dot-com"))
            .expect("primary upstream");
        assert_eq!(primary.targets.len(), 1);
        assert_eq!(primary.targets[0].host, "primary.external.com");
        assert_eq!(primary.targets[0].port, 443);

        let secondary = upstreams
            .iter()
            .find(|upstream| upstream.id.contains("secondary-dot-external-dot-com"))
            .expect("secondary upstream");
        assert_eq!(secondary.targets.len(), 1);
        assert_eq!(secondary.targets[0].host, "secondary.external.com");
        assert_eq!(secondary.targets[0].port, 443);
    }

    #[test]
    fn egress_dns_resolution_honors_service_entry_target_port() {
        // ServiceEntry port 443 with targetPort 8443 (DNS resolution): the egress
        // upstream target must dial the backend port 8443, not the service port.
        let mut entry = test_external_service_entry(
            "dns-svc",
            vec!["primary.external.com".to_string()],
            443,
            AppProtocol::Tls,
        );
        entry.ports[0].target_port = Some(ServiceTargetPort::Number(8443));

        let (_, upstreams) = build_egress_proxies_and_upstreams(
            &[entry],
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].targets.len(), 1);
        assert_eq!(upstreams[0].targets[0].host, "primary.external.com");
        assert_eq!(
            upstreams[0].targets[0].port, 8443,
            "egress must dial the ServiceEntry targetPort, not the service port"
        );
    }

    #[test]
    fn destination_rule_egress_service_entry_rekeys_port_policy_to_target_port() {
        // Istio DestinationRule portLevelSettings are keyed by the ServiceEntry
        // service port (443), while the egress upstream target dials the numeric
        // targetPort (8443). The port-level TLS policy must be stored under the
        // dial port so dispatch applies it to the selected target.
        let mut entry = test_external_service_entry(
            "dns-svc",
            vec!["primary.external.com".to_string()],
            443,
            AppProtocol::Tls,
        );
        entry.ports[0].target_port = Some(ServiceTargetPort::Number(8443));

        let (_, upstreams) = build_egress_proxies_and_upstreams(
            &[entry.clone()],
            "default",
            &std::collections::HashSet::new(),
            true,
        );
        let mut config = GatewayConfig {
            upstreams,
            ..GatewayConfig::default()
        };

        let slice = MeshSlice {
            namespace: "default".to_string(),
            service_entries: vec![entry],
            destination_rules: vec![MeshDestinationRule {
                name: "dns-svc".to_string(),
                namespace: "default".to_string(),
                host: "primary.external.com".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::from([(
                    443u16,
                    MeshTrafficPolicy {
                        tls: Some(MeshTrafficPolicyTls {
                            mode: MtlsMode::Simple,
                            ca_certificates: Some("/etc/certs/primary-ca.pem".to_string()),
                            sni: Some("primary.external.com".to_string()),
                            ..MeshTrafficPolicyTls::default()
                        }),
                        ..MeshTrafficPolicy::default()
                    },
                )]),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let upstream = &config.upstreams[0];
        assert!(
            upstream.port_overrides.contains_key(&8443),
            "service-port policy must be re-keyed onto targetPort 8443, got {:?}",
            upstream.port_overrides.keys().collect::<Vec<_>>()
        );
        assert!(
            !upstream.port_overrides.contains_key(&443),
            "policy must not remain under service port 443"
        );
        let tls = upstream
            .port_overrides
            .get(&8443)
            .and_then(|slot| slot.tls.as_ref())
            .expect("targetPort override carries resolved TLS policy");
        assert_eq!(
            tls.server_ca_cert_path.as_deref(),
            Some("/etc/certs/primary-ca.pem")
        );
        assert_eq!(tls.sni.as_deref(), Some("primary.external.com"));
    }

    #[test]
    fn egress_empty_service_entries_produces_no_proxies() {
        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &[],
            "default",
            &std::collections::HashSet::new(),
            true,
        );
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn mesh_runtime_materializes_egress_proxies_in_prepared_config() {
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_service_entry(
                    "ext-api",
                    vec!["api.partner.com".to_string()],
                    443,
                    AppProtocol::Tls,
                )],
                destination_rules: vec![MeshDestinationRule {
                    name: "partner-policy".to_string(),
                    namespace: "default".to_string(),
                    host: "api.partner.com".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(1234),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        // Should have the egress proxy
        let egress_proxy = prepared
            .proxies
            .iter()
            .find(|proxy| proxy.id == "mesh-egress-default-ext-api-api-dot-partner-dot-com-443")
            .expect("egress proxy should be materialized");
        assert_eq!(egress_proxy.hosts, vec!["api.partner.com"]);
        assert!(!egress_proxy.frontend_tls);
        assert_eq!(egress_proxy.backend_scheme, Some(BackendScheme::Https));
        assert_eq!(egress_proxy.backend_connect_timeout_ms, 1234);

        // Should have the egress upstream
        let egress_upstream = prepared
            .upstreams
            .iter()
            .find(|upstream| {
                upstream.id == "mesh-egress-up-default-ext-api-api-dot-partner-dot-com-443"
            })
            .expect("egress upstream should be materialized");
        assert_eq!(egress_upstream.targets.len(), 1);
        assert_eq!(egress_upstream.targets[0].host, "api.partner.com");
        assert_eq!(egress_upstream.algorithm, LoadBalancerAlgorithm::Random);

        // Mesh plugins should be injected
        assert!(
            prepared
                .plugin_configs
                .iter()
                .any(|p| p.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID)
        );
        assert!(
            prepared
                .plugin_configs
                .iter()
                .any(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        );
    }

    #[test]
    fn egress_does_not_materialize_when_topology_is_sidecar() {
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.topology, MeshTopology::Sidecar);

        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_service_entry(
                    "ext-api",
                    vec!["api.partner.com".to_string()],
                    443,
                    AppProtocol::Tls,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        // No egress proxies should be materialized for sidecar topology
        assert!(
            !prepared
                .proxies
                .iter()
                .any(|p| p.id.starts_with("mesh-egress-"))
        );
    }

    #[test]
    fn egress_backend_scheme_maps_protocols_correctly() {
        // HTTP-family
        assert_eq!(
            egress_backend_scheme(AppProtocol::Tls),
            Some(BackendScheme::Https)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Http2),
            Some(BackendScheme::Https)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Grpc),
            Some(BackendScheme::Https)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Http),
            Some(BackendScheme::Http)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Unknown),
            Some(BackendScheme::Http)
        );
        // Stream-family (T5-A): TCP-based L4 protocols all map to
        // `BackendScheme::Tcp`. Protocol-aware mediation is T5-C.
        for protocol in [
            AppProtocol::Tcp,
            AppProtocol::Mongo,
            AppProtocol::Redis,
            AppProtocol::Mysql,
            AppProtocol::Postgres,
        ] {
            assert_eq!(
                egress_backend_scheme(protocol),
                Some(BackendScheme::Tcp),
                "AppProtocol::{:?} must map to BackendScheme::Tcp",
                protocol
            );
            assert!(
                egress_is_stream_protocol(protocol),
                "AppProtocol::{:?} must classify as stream-family",
                protocol
            );
        }
        // HTTP-family must NOT be classified as stream-family.
        for protocol in [
            AppProtocol::Http,
            AppProtocol::Http2,
            AppProtocol::Grpc,
            AppProtocol::Tls,
            AppProtocol::Unknown,
        ] {
            assert!(
                !egress_is_stream_protocol(protocol),
                "AppProtocol::{:?} must NOT classify as stream-family",
                protocol
            );
        }
    }

    #[test]
    fn egress_resolution_none_uses_hosts_as_targets() {
        let service_entries = vec![ServiceEntry {
            name: "passthrough-ext".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["cdn.example.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::None,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Tls,
                name: Some("https".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].targets.len(), 1);
        assert_eq!(upstreams[0].targets[0].host, "cdn.example.com");
        assert_eq!(upstreams[0].targets[0].port, 443);
    }

    #[test]
    fn egress_static_resolution_unnamed_port_uses_entry_port() {
        let service_entries = vec![ServiceEntry {
            name: "static-unnamed".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["api.vendor.com".to_string()],
            endpoints: vec![
                MeshEndpoint {
                    address: "203.0.113.10".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                },
                MeshEndpoint {
                    address: "203.0.113.11".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                },
            ],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 8443,
                protocol: AppProtocol::Tls,
                name: None,
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
        // Proxy stays pinned to the ServiceEntry host so SNI/Host headers are
        // not crossed by load balancing across endpoint IPs.
        assert_eq!(proxies[0].hosts, vec!["api.vendor.com"]);
        assert_eq!(upstreams[0].targets.len(), 2);
        assert_eq!(upstreams[0].targets[0].host, "203.0.113.10");
        assert_eq!(upstreams[0].targets[0].port, 8443);
        assert_eq!(upstreams[0].targets[1].host, "203.0.113.11");
        assert_eq!(upstreams[0].targets[1].port, 8443);
    }

    #[test]
    fn egress_skips_service_entries_with_empty_hosts() {
        let service_entries = vec![ServiceEntry {
            name: "no-hosts".to_string(),
            namespace: "default".to_string(),
            hosts: Vec::new(),
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Tls,
                name: Some("https".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_mixed_internal_external_only_materializes_external() {
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![
                    // MeshExternal -- should be materialized
                    test_external_service_entry(
                        "ext-api",
                        vec!["api.partner.com".to_string()],
                        443,
                        AppProtocol::Tls,
                    ),
                    // MeshInternal -- should be skipped
                    ServiceEntry {
                        name: "internal-svc".to_string(),
                        namespace: "default".to_string(),
                        hosts: vec!["internal.svc.cluster.local".to_string()],
                        endpoints: Vec::new(),
                        resolution: Resolution::Dns,
                        location: ServiceEntryLocation::MeshInternal,
                        ports: vec![ServicePort {
                            port: 8080,
                            protocol: AppProtocol::Http,
                            name: None,
                            target_port: None,
                        }],
                        export_to: Vec::new(),
                        workload_selector: None,
                    },
                    // Another MeshExternal -- should be materialized
                    test_external_service_entry(
                        "ext-metrics",
                        vec!["metrics.vendor.com".to_string()],
                        443,
                        AppProtocol::Tls,
                    ),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        let egress_proxies: Vec<_> = prepared
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("mesh-egress-"))
            .collect();
        assert_eq!(egress_proxies.len(), 2);

        let egress_upstreams: Vec<_> = prepared
            .upstreams
            .iter()
            .filter(|u| u.id.starts_with("mesh-egress-up-"))
            .collect();
        assert_eq!(egress_upstreams.len(), 2);

        // Verify the external ones are present
        assert!(
            egress_proxies
                .iter()
                .any(|p| p.hosts == vec!["api.partner.com"])
        );
        assert!(
            egress_proxies
                .iter()
                .any(|p| p.hosts == vec!["metrics.vendor.com"])
        );

        // Verify the internal one is NOT present
        assert!(
            !egress_proxies
                .iter()
                .any(|p| p.hosts.contains(&"internal.svc.cluster.local".to_string()))
        );
    }

    // ── T5-A: stream-family egress materialization ───────────────────────

    fn test_external_stream_service_entry(
        name: &str,
        host: &str,
        port: u16,
        protocol: AppProtocol,
    ) -> ServiceEntry {
        assert!(
            egress_is_stream_protocol(protocol),
            "test helper requires a stream-family AppProtocol"
        );
        ServiceEntry {
            name: name.to_string(),
            namespace: "default".to_string(),
            hosts: vec![host.to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port,
                protocol,
                name: Some("stream".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }
    }

    #[test]
    fn egress_stream_tcp_service_entry_produces_one_tcp_stream_proxy() {
        let service_entries = vec![test_external_stream_service_entry(
            "raw-tcp",
            "raw.external.io",
            6380,
            AppProtocol::Tcp,
        )];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);

        let proxy = &proxies[0];
        assert!(
            proxy.hosts.is_empty(),
            "stream proxies route by listen_port, not host"
        );
        assert!(proxy.listen_path.is_none());
        assert_eq!(proxy.listen_port, Some(6380));
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert!(!proxy.passthrough);
        assert!(!proxy.frontend_tls);
        assert_eq!(
            proxy.upstream_id.as_deref(),
            Some("mesh-egress-up-default-raw-tcp-raw-dot-external-dot-io-6380")
        );

        let upstream = &upstreams[0];
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].host, "raw.external.io");
        assert_eq!(upstream.targets[0].port, 6380);
    }

    #[test]
    fn egress_stream_mongo_service_entry_produces_tcp_proxy_with_protocol_tag_in_name() {
        let service_entries = vec![test_external_stream_service_entry(
            "mongo-prod",
            "mongo.external.io",
            27017,
            AppProtocol::Mongo,
        )];

        let (proxies, _) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        let proxy = &proxies[0];
        // Mongo is TCP-based: same wire-level dispatch, but the protocol
        // tag in `proxy.name` keeps it observable in transaction logs.
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert_eq!(
            proxy.name.as_deref(),
            Some("mesh egress mongo mongo.external.io:27017")
        );
        assert_eq!(proxy.listen_port, Some(27017));
    }

    #[test]
    fn egress_stream_static_resolution_uses_endpoint_addresses_as_targets() {
        // Same shape as the HTTP-family static-resolution test, but for a
        // TCP service entry. Endpoints become upstream targets; the proxy
        // listens on the SE's own port.
        let service_entries = vec![ServiceEntry {
            name: "mysql-static".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["db.vendor.com".to_string()],
            endpoints: vec![
                MeshEndpoint {
                    address: "203.0.113.20".to_string(),
                    ports: HashMap::from([("mysql".to_string(), 3306)]),
                    labels: HashMap::new(),
                    network: None,
                },
                MeshEndpoint {
                    address: "203.0.113.21".to_string(),
                    ports: HashMap::from([("mysql".to_string(), 3306)]),
                    labels: HashMap::new(),
                    network: None,
                },
            ],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 3306,
                protocol: AppProtocol::Mysql,
                name: Some("mysql".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
        assert_eq!(proxies[0].listen_port, Some(3306));

        let upstream = &upstreams[0];
        assert_eq!(upstream.targets.len(), 2);
        assert_eq!(upstream.targets[0].host, "203.0.113.20");
        assert_eq!(upstream.targets[0].port, 3306);
        assert_eq!(upstream.targets[1].host, "203.0.113.21");
        assert_eq!(upstream.targets[1].port, 3306);
    }

    #[test]
    fn egress_stream_port_collision_skips_second_entry_with_warning() {
        // Two SEs requesting the same listen_port: the second one is
        // skipped because each stream proxy must own its listen_port.
        // The first SE wins (deterministic by config order).
        let service_entries = vec![
            test_external_stream_service_entry(
                "first-redis",
                "redis-a.external.io",
                6379,
                AppProtocol::Redis,
            ),
            test_external_stream_service_entry(
                "second-redis",
                "redis-b.external.io",
                6379,
                AppProtocol::Redis,
            ),
        ];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 1, "only the first SE wins on port collision");
        assert_eq!(upstreams.len(), 1);
        assert_eq!(
            upstreams[0].targets[0].host, "redis-a.external.io",
            "first SE in config order should win"
        );
    }

    #[test]
    fn egress_mixed_http_and_stream_entries_materialize_independently() {
        // Mixed manifest: one HTTP SE, one TCP SE. Both materialize without
        // cross-contamination (the HTTP host-dedup set and the stream
        // port-dedup set are independent).
        let service_entries = vec![
            test_external_service_entry(
                "http-api",
                vec!["api.external.io".to_string()],
                443,
                AppProtocol::Tls,
            ),
            test_external_stream_service_entry(
                "tcp-db",
                "db.external.io",
                5432,
                AppProtocol::Postgres,
            ),
        ];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 2);
        assert_eq!(upstreams.len(), 2);

        // HTTP-family proxy: host-routed, no listen_port.
        let http_proxy = proxies
            .iter()
            .find(|p| p.hosts == vec!["api.external.io".to_string()])
            .expect("http proxy materialized");
        assert!(http_proxy.listen_port.is_none());
        assert_eq!(http_proxy.backend_scheme, Some(BackendScheme::Https));

        // Stream-family proxy: port-routed, no hosts.
        let stream_proxy = proxies
            .iter()
            .find(|p| p.listen_port == Some(5432))
            .expect("stream proxy materialized");
        assert!(stream_proxy.hosts.is_empty());
        assert_eq!(stream_proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert_eq!(
            stream_proxy.name.as_deref(),
            Some("mesh egress postgres db.external.io:5432")
        );
    }

    #[test]
    fn egress_stream_service_entry_with_multiple_ports_binds_each_port_separately() {
        // One SE exposing the same external host on two different stream
        // ports (e.g., a database with primary 5432 and replica 5433).
        // Both get their own stream proxy because each port owns its
        // own listener.
        let service_entries = vec![ServiceEntry {
            name: "multi-port-db".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["db.vendor.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![
                ServicePort {
                    port: 5432,
                    protocol: AppProtocol::Postgres,
                    name: Some("primary".to_string()),
                    target_port: None,
                },
                ServicePort {
                    port: 5433,
                    protocol: AppProtocol::Postgres,
                    name: Some("replica".to_string()),
                    target_port: None,
                },
            ],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(proxies.len(), 2);
        assert_eq!(upstreams.len(), 2);
        assert!(proxies.iter().any(|p| p.listen_port == Some(5432)));
        assert!(proxies.iter().any(|p| p.listen_port == Some(5433)));
    }

    #[test]
    fn egress_stream_service_entry_honors_target_port_for_backend_dial() {
        // A stream (TCP-family) ServiceEntry with `targetPort` must listen on the
        // service `port` (where captured outbound traffic arrives) but dial the
        // backend on the resolved `targetPort` — mirroring the HTTP egress path.
        // Without this the listener and dial port stay pinned together and a
        // `number: 5432, targetPort: 15432` entry would dial 5432, not 15432.
        let service_entries = vec![ServiceEntry {
            name: "db-with-target-port".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["db.vendor.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 5432,
                protocol: AppProtocol::Postgres,
                name: Some("primary".to_string()),
                target_port: Some(ServiceTargetPort::Number(15432)),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        let stream_proxy = proxies
            .iter()
            .find(|p| p.listen_port == Some(5432))
            .expect("stream proxy listens on the service port, not the targetPort");
        assert_eq!(
            stream_proxy.backend_scheme,
            Some(BackendScheme::Tcp),
            "postgres is a stream-family protocol"
        );

        assert_eq!(
            upstreams.len(),
            1,
            "one upstream for the single stream port"
        );
        let target_ports: Vec<u16> = upstreams[0].targets.iter().map(|t| t.port).collect();
        assert_eq!(
            target_ports,
            vec![15432],
            "the upstream must dial the resolved targetPort, not the service port"
        );
    }

    #[test]
    fn egress_static_service_entry_honors_numeric_target_port_for_named_port() {
        // A STATIC ServiceEntry with a NAMED port + numeric targetPort whose
        // endpoints carry no per-endpoint port map for that name must still dial
        // the numeric targetPort: the targetPort overrides the endpoint named-port
        // map (without the fix the endpoint is dropped for lack of `ports[name]`).
        let service_entries = vec![ServiceEntry {
            name: "ext-db".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["db.vendor.com".to_string()],
            endpoints: vec![MeshEndpoint {
                address: "10.9.9.9".to_string(),
                ports: HashMap::new(),
                labels: HashMap::new(),
                network: None,
            }],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 5432,
                protocol: AppProtocol::Postgres,
                name: Some("tcp".to_string()),
                target_port: Some(ServiceTargetPort::Number(15432)),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (_proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert_eq!(
            upstreams.len(),
            1,
            "one upstream for the static stream port"
        );
        let target_ports: Vec<u16> = upstreams[0].targets.iter().map(|t| t.port).collect();
        assert_eq!(
            target_ports,
            vec![15432],
            "numeric targetPort overrides the (absent) endpoint named-port map for static endpoints"
        );
    }

    #[test]
    fn service_discovery_upstream_rekeys_port_policy_to_numeric_target_port() {
        // A mesh service-discovery upstream for a Service with port 80 ->
        // targetPort 8080 resolves its targets to 8080 at runtime; a DR
        // portLevelSettings keyed on 80 must be re-keyed to 8080 so dispatch
        // (which keys overrides by the dial port) applies it (round-12 F2).
        let mut upstream = destination_rule_test_upstream(
            "reviews.default.svc.cluster.local",
            "reviews.default.svc.cluster.local",
        );
        upstream.targets.clear(); // service-discovery resolves targets at runtime
        upstream.service_discovery = Some(crate::config::types::ServiceDiscoveryConfig {
            provider: crate::config::types::SdProvider::Mesh,
            dns_sd: None,
            kubernetes: None,
            consul: None,
            mesh: Some(crate::config::types::MeshSdConfig {
                service_name: "reviews".to_string(),
                namespace: Some("default".to_string()),
                port: None,
                poll_interval_seconds: 30,
            }),
            default_weight: 1,
        });
        let mut config = GatewayConfig {
            upstreams: vec![upstream],
            ..GatewayConfig::default()
        };

        let mut svc = http_mesh_service(
            "reviews",
            80,
            "spiffe://cluster.local/ns/default/sa/reviews",
        );
        svc.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        let slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![svc],
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: HashMap::from([(
                    80u16,
                    MeshTrafficPolicy {
                        max_connections: Some(7),
                        ..MeshTrafficPolicy::default()
                    },
                )]),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice)
            .expect("destination rules apply");

        let upstream = &config.upstreams[0];
        assert!(
            upstream.port_overrides.contains_key(&8080),
            "port-level policy must be re-keyed onto the dial port 8080, got {:?}",
            upstream.port_overrides.keys().collect::<Vec<_>>()
        );
        assert!(
            !upstream.port_overrides.contains_key(&80),
            "policy must not stay under the service port 80"
        );
    }

    #[test]
    fn east_west_drops_target_when_named_target_port_unresolved() {
        // build_east_west_service_targets: a named targetPort that does not
        // resolve against the workload ports must drop the target (fail closed),
        // not fall back to the Service port.
        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let mut svc = http_mesh_service("reviews", 80, spiffe);
        svc.ports[0].target_port = Some(ServiceTargetPort::Name("http".to_string()));
        let mut wl = workload("reviews", "reviews");
        wl.addresses = vec!["10.0.0.1".to_string()];
        wl.ports = vec![WorkloadPort {
            port: 9999,
            protocol: AppProtocol::Http,
            name: Some("grpc".to_string()),
        }];
        let targets = build_east_west_service_targets(&svc, &[wl], None);
        assert!(
            targets.is_empty(),
            "an unresolved named targetPort must drop the east-west target, not dial the Service port"
        );
    }

    #[test]
    fn egress_stream_topology_gate_skips_when_not_egress_gateway() {
        // Sidecar topology should NOT materialize stream egress proxies
        // even when the slice carries L4 ServiceEntries — same topology
        // gate as the existing HTTP-family egress materialization.
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.topology, MeshTopology::Sidecar);

        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_stream_service_entry(
                    "ghost-tcp",
                    "ghost.external.io",
                    6379,
                    AppProtocol::Redis,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        assert!(
            !prepared
                .proxies
                .iter()
                .any(|p| p.id.starts_with("mesh-egress-")),
            "no egress proxies should materialize under sidecar topology"
        );
    }

    #[test]
    fn egress_stream_in_egress_gateway_topology_passes_full_validation() {
        // Full end-to-end materialization via `prepare_gateway_config_for_mesh`
        // exercises the validation pipeline that runs after materialization.
        // A stream egress proxy with a valid listen_port must pass
        // `validate_stream_proxies()` (each stream proxy needs listen_port,
        // each port owns one proxy).
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            egress_stream_enabled: true,
            request_auth_require_exp: true,
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_stream_service_entry(
                    "ext-redis",
                    "redis.external.io",
                    6379,
                    AppProtocol::Redis,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared =
            prepare_gateway_config_for_mesh(config, &runtime).expect("prepared mesh config");

        let stream_proxy = prepared
            .proxies
            .iter()
            .find(|p| p.listen_port == Some(6379))
            .expect("stream proxy should be materialized");
        assert_eq!(stream_proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert!(stream_proxy.dispatch_kind.is_stream());
        // Post-materialization stream-proxy validation must pass; the proxy's
        // `listen_port` is the SE's own port, and there is only one SE on it.
        prepared
            .validate_stream_proxies()
            .expect("stream proxy validation should pass for a single port");
    }

    #[test]
    fn egress_stream_skips_service_entry_port_that_collides_with_mesh_listener() {
        // ServiceEntry port matching `egress_listen_addr.port()` (default
        // 15090) would bind on the same socket as the egress gateway's own
        // mTLS-termination listener. The materializer must skip these entries
        // with a warning rather than emit a stream proxy that fails to bind
        // at runtime (EADDRINUSE).
        let mut reserved = std::collections::HashSet::new();
        reserved.insert(15090);

        let service_entries = vec![test_external_stream_service_entry(
            "colliding-tcp",
            "external.io",
            15090,
            AppProtocol::Tcp,
        )];

        let (proxies, upstreams) =
            build_egress_proxies_and_upstreams(&service_entries, "default", &reserved, true);

        assert!(
            proxies.is_empty(),
            "stream proxy on the mesh listener port must be skipped"
        );
        assert!(
            upstreams.is_empty(),
            "no upstream should be emitted when the proxy is skipped"
        );
    }

    #[test]
    fn egress_stream_skips_zero_port_service_entry() {
        // Stream proxies require listen_port >= 1 (validated by
        // `validate_stream_proxies`). A ServiceEntry with port: 0 would
        // produce a proxy that fails validation later, killing the entire
        // slice apply. Skip with a warning instead.
        let service_entries = vec![test_external_stream_service_entry(
            "zero-port",
            "external.io",
            0,
            AppProtocol::Tcp,
        )];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
            true,
        );

        assert!(
            proxies.is_empty(),
            "stream proxy with port 0 must be skipped"
        );
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_materialize_skips_mesh_listener_collision_full_path() {
        // End-to-end: `materialize_egress_gateway_proxies` populates
        // `mesh_reserved_ports` from `runtime.egress_listen_addr.port()` and
        // must skip ServiceEntries that target the same port. This guards
        // against a regression where the runtime forgets to plumb the
        // reserved ports through to `build_egress_proxies_and_upstreams`.
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let egress_port = runtime.egress_listen_addr.port();

        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_stream_service_entry(
                    "colliding-tcp",
                    "external.io",
                    egress_port,
                    AppProtocol::Tcp,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared =
            prepare_gateway_config_for_mesh(config, &runtime).expect("prepared mesh config");

        assert!(
            !prepared
                .proxies
                .iter()
                .any(|p| p.listen_port == Some(egress_port)),
            "no stream proxy should bind on the mesh egress listener port"
        );
    }
}
