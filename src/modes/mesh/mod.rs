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
pub mod node_waypoint;
pub mod outbound_enforcement;
pub mod policy;
pub mod runtime;
pub mod runtime_overlay_consumers;
pub mod slice;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

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
use crate::grpc::dp_client::{GrpcJwtSecret, build_dp_grpc_tls_config};
use crate::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshDestinationRule, MeshJwtRule, MeshLoadBalancer,
    MeshLocalityLbSetting, MeshOutlierDetection, MeshRequestAuthentication, MeshSimpleLb,
    MeshTelemetryConfig, MeshTrafficPolicy, MeshTrafficPolicyTls, MtlsMode, PolicyScope,
    Resolution, ServiceEntry, ServiceEntryLocation, service_entry_exported_to_namespace,
};
use crate::modes::mesh::config_consumer::native_client::NativeMeshClientConfig;
use crate::modes::mesh::config_consumer::xds_client::XdsClientConfig;
use crate::modes::mesh::dns_proxy::MeshDnsProxy;
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
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
}

impl MeshConfigProtocol {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "xds" => Ok(Self::Xds),
            other => Err(format!(
                "Invalid FERRUM_MESH_CONFIG_PROTOCOL '{other}'. Expected: native or xds"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xds => "xds",
        }
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
    pub topology: MeshTopology,
    pub inbound_listen_addr: SocketAddr,
    pub outbound_listen_addr: SocketAddr,
    pub hbone_listen_addr: SocketAddr,
    pub east_west_listen_port: u16,
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
}

impl MeshRuntimeConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let cp_urls = env_config.resolved_dp_cp_grpc_urls();
        if cp_urls.is_empty() {
            return Err("FERRUM_DP_CP_GRPC_URLS is required in mesh mode".into());
        }

        let node_id = resolve_ferrum_var("FERRUM_MESH_NODE_ID")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "ferrum-mesh-node".to_string());
        let config_protocol = MeshConfigProtocol::parse(&env_config.mesh_config_protocol)?;
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
            topology,
            inbound_listen_addr,
            outbound_listen_addr,
            hbone_listen_addr,
            east_west_listen_port,
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
        })
    }

    fn native_client_config(&self) -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            waypoint_name: self.service_waypoint_name(),
            labels: self.workload_labels.clone(),
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

    #[allow(dead_code)] // Used by tests and future xDS bootstrap wiring.
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
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: slice.workloads.clone(),
            services: slice.services.clone(),
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
            match gateway_config_from_mesh_slice(slice, runtime, Some(&federation_snapshot)) {
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
    // WorkloadRefs are intentionally matched one-to-one by workload index:
    // replicated pods can share a SPIFFE ID and still produce distinct targets.
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

        // Use the first service port as the target port. If the service has no
        // ports, fall back to the workload's first port.
        let target_port = service
            .ports
            .first()
            .map(|p| p.port)
            .or_else(|| workload.ports.first().map(|p| p.port))
            .unwrap_or(80);

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
fn apply_destination_rules(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<(), anyhow::Error> {
    let mut sorted_destination_rules: Vec<&MeshDestinationRule> =
        mesh_slice.destination_rules.iter().collect();
    sorted_destination_rules.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

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
            for (port, port_policy) in &dr.port_level_settings {
                if !has_service_discovery && !upstream_target_ports.contains(port) {
                    warn!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        port = port,
                        "DestinationRule portLevelSettings entry references a port not used by any target; skipping"
                    );
                    continue;
                }
                if port_policy.tls.is_some() {
                    warn!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        port = port,
                        "DestinationRule portLevelSettings.tls is parsed but not enforced per-port today (gateway applies backend TLS policy at upstream scope); only port-level connectTimeout/loadBalancer/outlierDetection are applied"
                    );
                }

                let override_slot = upstream.port_overrides.entry(*port).or_default();
                apply_traffic_policy_to_port_override(override_slot, port_policy);
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
                            SubsetTrafficPolicy {
                                load_balancer_algorithm: mesh_lb_to_ferrum(&sp.load_balancer),
                                tls: sp.tls.clone(),
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

            if let Some(timeout_ms) = connect_timeout_ms {
                let upstream_id = upstream.id.clone();
                let upstream_namespace = upstream.namespace.clone();
                for proxy in &mut config.proxies {
                    if proxy.upstream_id.as_deref() == Some(upstream_id.as_str())
                        && proxy.namespace == upstream_namespace
                        && proxy.backend_connect_timeout_ms != timeout_ms
                    {
                        debug!(
                            proxy = %proxy.id,
                            upstream = %upstream_id,
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
            let Some(subset_tls) = subset
                .traffic_policy
                .as_ref()
                .and_then(|tp| tp.tls.as_ref())
            else {
                continue;
            };
            let identity = format!("{}/{}", upstream.id, subset.name);
            let mut slot = upstream_base_tls.clone();
            apply_traffic_policy_tls_to_backend_config(
                &mut slot, subset_tls, runtime, &identity,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "DestinationRule subset trafficPolicy.tls projection failed for upstream={} subset={}: {}",
                    upstream.id,
                    subset.name,
                    e
                )
            })?;
            if let Some(resolved) = ResolvedSubsetTrafficPolicy::from_tls(Some(slot)) {
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

    for host in proxy_hosts {
        let targets = build_egress_upstream_targets(entry, host, port_spec.port, &port_spec.name);

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

    let targets =
        build_egress_upstream_targets(entry, representative_host, port_spec.port, &port_spec.name);

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
    // any existing mesh access_log plugin and skip injection, but we MUST NOT
    // short-circuit the rest of inject_mesh_global_plugins (e.g. the bpf_metrics
    // branch below). Earlier versions used `return;` here, which silently
    // skipped bpf_metrics injection/cleanup on NodeWaypoint topology whenever
    // Telemetry CRD disabled access logging.
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
            "access_log",
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
    // Istio JWTs may omit the `exp` claim, so we disable the default
    // `require_exp=true` that the non-mesh jwks_auth plugin enforces.
    let jwks_config = serde_json::json!({
        "providers": providers,
        "require_exp": false,
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
        .map_err(|e| anyhow::anyhow!(e))
        .context("invalid mesh runtime configuration")?;
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

    let mesh_state = MeshRuntimeState::new();

    let jwt_secret = GrpcJwtSecret::with_issuer(
        env_config.cp_dp_grpc_jwt_secret.clone().ok_or_else(|| {
            anyhow::anyhow!("FERRUM_CP_DP_GRPC_JWT_SECRET is required in mesh mode")
        })?,
        env_config.cp_dp_grpc_jwt_issuer.clone(),
    );
    let grpc_tls = build_dp_grpc_tls_config(&env_config, &runtime.cp_urls, "Mesh")?;
    let mut background_handles = Vec::new();

    match runtime.config_protocol {
        MeshConfigProtocol::Native => {
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
        }
        MeshConfigProtocol::Xds => {
            let xds_config = runtime.xds_client_config();
            let state = mesh_state.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(config_consumer::xds_client::start_xds_client_with_shutdown(
                jwt_secret.clone(),
                xds_config,
                state,
                shutdown_rx,
                grpc_tls.clone(),
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
        MeshConfigProtocol::Native | MeshConfigProtocol::Xds => Ok(()),
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
        proxy_state.with_node_waypoint_identity_resolver(resolver)
    } else {
        proxy_state
    };
    crate::runtime_metrics::global().configure(
        env_config.status_counts_max_entries,
        env_config.runtime_metrics_pool_tracking_enabled,
        env_config.runtime_metrics_status_tracking_enabled,
        env_config.runtime_metrics_cache_ttl_ms,
    );
    proxy_state
        .stream_listener_manager
        .set_global_shutdown_rx(shutdown_tx.subscribe());

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
    let frontend_tls = load_mesh_frontend_tls(
        &env_config,
        &tls_policy,
        &crls,
        inbound_mtls_mode,
        mesh_frontend_identity.as_deref(),
        initial_inbound_tls_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.client_ca_bundle.as_ref()),
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

    // Spawn the SPIFFE trust-bundle federation poller before the apply task so
    // the first slice apply observes whatever the poller has already fetched.
    // The poller updates `mesh_state.federation_store()` on each successful
    // poll; the apply task subscribes to the same store. Disabled when
    // `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0` or when the slice has
    // no remote clusters configured.
    let federation_poller_config = federation::FederationPollerConfig::from_env(
        env_config.mesh_federation_poll_interval_seconds,
        env_config.mesh_federation_poll_timeout_seconds,
        env_config.mesh_federation_fail_open,
    );
    let initial_multi_cluster = initial_applied_mesh_slice
        .as_ref()
        .and_then(|slice| slice.multi_cluster.clone());
    if let Some(handles) = federation::spawn_federation_poller(
        initial_multi_cluster.as_ref(),
        federation_poller_config,
        proxy_state.plugin_cache.http_client().clone(),
        mesh_state.federation_store().clone(),
        shutdown_tx.subscribe(),
    ) {
        for handle in handles.tasks {
            mesh_background_handles.push(handle);
        }
        info!("SPIFFE trust-bundle federation poller running");
    }

    let mesh_apply_handle = start_mesh_slice_apply_task(
        mesh_state,
        proxy_state.clone(),
        runtime.clone(),
        initial_applied_mesh_slice,
        MeshInboundTlsReloadState {
            server_identity: mesh_frontend_identity,
            last_snapshot: initial_inbound_tls_snapshot,
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
}

fn mesh_inbound_tls_reload_snapshot(
    env_config: &EnvConfig,
    mtls_mode: config::MtlsMode,
) -> Result<MeshInboundTlsReloadSnapshot, anyhow::Error> {
    let client_ca_bundle = if mtls_mode == config::MtlsMode::Disable {
        None
    } else if let Some(path) = env_config.frontend_tls_client_ca_bundle_path.as_deref() {
        let pem: Arc<[u8]> = std::fs::read(path)
            .with_context(|| format!("failed to read mesh frontend client CA bundle at {path}"))?
            .into();
        Some(MeshInboundClientCaBundle {
            path: path.to_string(),
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
    match (
        env_config.frontend_tls_cert_path.as_deref(),
        env_config.frontend_tls_key_path.as_deref(),
    ) {
        (Some(cert_path), Some(key_path)) => Ok(Some(tls::load_mesh_server_identity(
            cert_path,
            key_path,
            env_config.tls_cert_expiry_warning_days,
        )?)),
        _ => Ok(None),
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

    let client_ca_bundle_path = client_ca_bundle
        .map(|bundle| bundle.path.as_str())
        .or(env_config.frontend_tls_client_ca_bundle_path.as_deref());
    let client_auth = match mtls_mode {
        config::MtlsMode::Strict => tls::MeshClientAuth::Required,
        config::MtlsMode::Permissive if client_ca_bundle_path.is_some() => {
            tls::MeshClientAuth::Optional
        }
        config::MtlsMode::Permissive => {
            warn!(
                "Mesh PeerAuthentication mTLS mode is PERMISSIVE but no \
                 FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH is configured; \
                 client certificates will not be requested or verified"
            );
            tls::MeshClientAuth::None
        }
        config::MtlsMode::Disable => unreachable!("handled above"),
        // `Simple` / `Mutual` / `IstioMutual` are client-side modes from
        // `DestinationRule.trafficPolicy.tls` and never reach this
        // server-side PeerAuthentication resolver. Treat as a programming
        // error: warn and fall back to no client auth so we don't crash a
        // running data plane.
        config::MtlsMode::Simple | config::MtlsMode::Mutual | config::MtlsMode::IstioMutual => {
            warn!(
                mode = ?mtls_mode,
                "Mesh PeerAuthentication received a client-side DR.tls mode; \
                 falling back to no client auth (this is a programming error \
                 in the K8s translator if observed)"
            );
            tls::MeshClientAuth::None
        }
    };

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
        )
    } else {
        tls::load_mesh_tls_config_with_identity(
            server_identity,
            client_ca_bundle_path,
            client_auth,
            tls_policy,
            env_config.tls_cert_expiry_warning_days,
            crls,
        )
    }
    .map_err(|e| anyhow::anyhow!("Invalid mesh frontend TLS configuration: {}", e))?;
    tls::enable_early_data(&mut tls_config, tls_policy);
    if env_config.ktls_enabled.could_be_enabled() {
        tls::enable_secret_extraction_for_ktls(&mut tls_config);
    }
    Ok(Some(tls_config))
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
    Unchanged,
    Swap {
        snapshot: MeshInboundTlsReloadSnapshot,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    },
}

fn plan_mesh_inbound_tls_reload(
    proxy_state: &ProxyState,
    slice: &MeshSlice,
    mtls_mode: config::MtlsMode,
    server_identity: Option<&tls::MeshServerIdentity>,
    last_snapshot: Option<&MeshInboundTlsReloadSnapshot>,
) -> Option<MeshInboundTlsReloadPlan> {
    let next_snapshot = match mesh_inbound_tls_reload_snapshot(&proxy_state.env_config, mtls_mode) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(
                mesh_slice_version = %slice.version,
                ?mtls_mode,
                "Unable to inspect mesh inbound TLS reload inputs: {error}; keeping previous TLS config"
            );
            return None;
        }
    };
    if last_snapshot == Some(&next_snapshot) {
        return Some(MeshInboundTlsReloadPlan::Unchanged);
    }
    let Some(tls_policy) = proxy_state.tls_policy.as_deref() else {
        error!(
            mesh_slice_version = %slice.version,
            ?mtls_mode,
            "Mesh PeerAuthentication live reload requested but TLS policy is unavailable; this is a programming error. Applying proxy config only; the inbound TLS slot remains at its previous value until restart and will be re-evaluated on later slice applies."
        );
        return Some(MeshInboundTlsReloadPlan::Unchanged);
    };
    match load_mesh_frontend_tls(
        &proxy_state.env_config,
        tls_policy,
        &proxy_state.crls,
        mtls_mode,
        server_identity,
        next_snapshot.client_ca_bundle.as_ref(),
    ) {
        Ok(tls_config) => Some(MeshInboundTlsReloadPlan::Swap {
            snapshot: next_snapshot,
            tls_config,
        }),
        Err(error) => {
            warn!(
                mesh_slice_version = %slice.version,
                ?mtls_mode,
                "Failed to rebuild mesh inbound TLS config from PeerAuthentication update: {error}; keeping previous TLS config"
            );
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
        MeshInboundTlsReloadPlan::Unchanged => {}
        MeshInboundTlsReloadPlan::Swap {
            snapshot,
            tls_config,
        } => {
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
        let mut updates = mesh_state.subscribe();
        let mut federation_updates = mesh_state.federation_store().subscribe();
        let mut last_applied_slice = initial_applied_mesh_slice;
        let mut last_applied_federation_revision = *federation_updates.borrow();
        loop {
            if *shutdown_rx.borrow() {
                return;
            }

            let snapshot = mesh_state.snapshot();
            let current_federation_revision = *federation_updates.borrow();
            // The apply loop re-runs on slice OR federation changes. Without
            // the second check, a no-op slice (CP did not push anything new)
            // would skip applying a freshly polled federation bundle: the
            // `content_eq` short-circuit only catches the slice, not the
            // bundles we overlay on top.
            let federation_changed =
                current_federation_revision != last_applied_federation_revision;
            if let Some(slice) = snapshot.as_ref().as_ref() {
                let slice_unchanged =
                    mesh_slice_matches_last_applied(last_applied_slice.as_deref(), slice);
                if slice_unchanged && !federation_changed {
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
                                slice,
                                mtls_mode,
                                inbound_tls_reload.server_identity.as_deref(),
                                inbound_tls_reload.last_snapshot.as_ref(),
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
                        match gateway_config_from_mesh_slice(
                            slice,
                            &runtime,
                            Some(&federation_snapshot),
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
                                // The TLS reload plan is validated before config apply, but the
                                // live slot is swapped only after proxy config acceptance. That
                                // creates a tiny accept window where listeners may still see the
                                // previous TLS config, and avoids pre-swapping TLS for a proxy
                                // config that the runtime rejects. On a Permissive-to-Strict
                                // escalation, an accepted connection in that window can enter the
                                // new plugin chain without a peer principal; mesh authz still
                                // fails closed for identity-required policy until the slot swaps.
                                let applied = proxy_state.update_config(config);
                                let current_loaded_at = proxy_state.config.load_full().loaded_at;
                                let accepted = mesh_proxy_update_was_accepted(
                                    applied,
                                    previous_loaded_at,
                                    current_loaded_at,
                                    candidate_loaded_at,
                                );
                                record_mesh_slice_apply_result(
                                    &mut last_applied_slice,
                                    slice,
                                    accepted,
                                );
                                if accepted && let Some((resolver, snapshot)) = staged_policy_scopes
                                {
                                    resolver.install_policy_scope_snapshot(snapshot);
                                }
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
                // Federation revision is consumed after every apply attempt,
                // whether successful or not. A rejected apply still advances
                // the marker so a transient invalid slice doesn't pin the apply
                // loop in a re-apply spin on every poll.
                last_applied_federation_revision = current_federation_revision;
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
    last_applied_slice: &mut Option<Arc<MeshSlice>>,
    slice: &MeshSlice,
    applied: bool,
) {
    if applied {
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
            "FERRUM_MESH_XDS_NODE_CLUSTER",
            "FERRUM_MESH_TOPOLOGY",
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            "FERRUM_MESH_EAST_WEST_LISTEN_PORT",
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
        ];

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            unsafe { std::env::set_var(key, value) };
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
        let env = EnvConfig {
            mode: crate::config::OperatingMode::Mesh,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            accept_threads: 1,
            ..EnvConfig::default()
        };
        let runtime = MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
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
        }
    }

    fn test_mesh_runtime_config() -> MeshRuntimeConfig {
        MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
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
        }
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
        let access_log = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_ACCESS_LOG_PLUGIN_ID)
            .expect("access_log plugin injected");

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
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly,
            ),
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");

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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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

            let prepared = gateway_config_from_mesh_slice(&mesh_slice, &runtime, None)
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");

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

        let mut prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");

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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");

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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");

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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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
                        }],
                        to: Vec::new(),
                        when: Vec::new(),
                        request_principals: Vec::new(),
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
                assert_eq!(by_id(MESH_ACCESS_LOG_PLUGIN_ID).plugin_name, "access_log");
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
                            }],
                            to: Vec::new(),
                            when: Vec::new(),
                            request_principals: Vec::new(),
                            never_matches: false,
                            action: PolicyAction::Allow,
                        }],
                    }],
                    ..MeshSlice::default()
                };

                let prepared = gateway_config_from_mesh_slice(&slice, &runtime, None)
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
        let mut last_applied_slice = None;
        let rejected = MeshSlice {
            version: "bad-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        };
        record_mesh_slice_apply_result(&mut last_applied_slice, &rejected, false);
        assert!(last_applied_slice.is_none());
        assert!(!mesh_slice_matches_last_applied(
            last_applied_slice.as_deref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));

        record_mesh_slice_apply_result(&mut last_applied_slice, &rejected, true);
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

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime, None).expect("mesh slice config");
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

    #[test]
    fn mesh_runtime_request_auth_sets_require_exp_false() {
        let runtime = test_mesh_runtime_config();
        let config = GatewayConfig {
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
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        // Istio JWTs may omit `exp`, so mesh injection must disable
        // the default require_exp=true behavior.
        assert_eq!(
            jwks.config.get("require_exp").and_then(|v| v.as_bool()),
            Some(false),
            "mesh request auth must set require_exp=false for Istio compatibility"
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

        let err =
            load_mesh_frontend_tls(&env, &tls_policy, &[], config::MtlsMode::Strict, None, None)
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
        )
        .expect("permissive without CA bundle should succeed");

        assert!(
            tls_config.is_some(),
            "TLS config should be built (no client auth, but server TLS active)"
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
        );
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());

        service_entry.export_to = vec!["*".to_string()];
        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &[service_entry],
            "default",
            &std::collections::HashSet::new(),
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
                },
                ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                },
            ],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
    fn egress_empty_service_entries_produces_no_proxies() {
        let (proxies, upstreams) =
            build_egress_proxies_and_upstreams(&[], "default", &std::collections::HashSet::new());
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
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
                },
                ServicePort {
                    port: 5433,
                    protocol: AppProtocol::Postgres,
                    name: Some("replica".to_string()),
                },
            ],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(
            &service_entries,
            "default",
            &std::collections::HashSet::new(),
        );

        assert_eq!(proxies.len(), 2);
        assert_eq!(upstreams.len(), 2);
        assert!(proxies.iter().any(|p| p.listen_port == Some(5432)));
        assert!(proxies.iter().any(|p| p.listen_port == Some(5433)));
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
            build_egress_proxies_and_upstreams(&service_entries, "default", &reserved);

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
