//! Control Plane gRPC server implementing the `ConfigSync` service.
//!
//! Provides two RPCs:
//! - `Subscribe` — server-streaming: DP connects and receives a `FULL_SNAPSHOT`
//!   (update_type=0), then incremental `DELTA` updates (update_type=1) as config changes.
//!   If a DP lags behind the broadcast channel (default capacity 128, configurable
//!   via `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`), it receives a fresh
//!   full snapshot instead of the missed deltas.
//! - `GetFullConfig` — unary: returns the current full config snapshot on demand.
//!
//! Authentication: HS256 JWT in the `authorization` gRPC metadata key.
//! Required claims: `exp`, `iat`, `sub`, `iss`. The `iss` claim must exactly
//! match the configured expected issuer (`FERRUM_CP_DP_GRPC_JWT_ISSUER`,
//! default `"ferrum-edge-cp-dp"`); this prevents a token minted with the same
//! shared secret for a different audience (e.g. the admin API JWT secret if
//! it was reused) from authenticating to the gRPC channel. The CP enforces
//! `major.minor` version compatibility — a DP running a different minor
//! version is rejected.
//!
//! Issuer rotation: changing `FERRUM_CP_DP_GRPC_JWT_ISSUER` is a breaking
//! change. The CP rejects any token whose `iss` does not match its expected
//! value, so the CP and all DPs must roll together. Pre-deployment, decide
//! whether to roll DPs first (CP keeps accepting old issuer until upgraded)
//! or CP first (CP must temporarily accept multiple issuers — not currently
//! supported, so prefer DPs-first) and plan accordingly.
//!
//! Multi-namespace CPs (MESH-T2-A): a single CP can serve DPs across many
//! namespaces. The scope is controlled by [`CpScope`] (built from
//! `FERRUM_CP_NAMESPACES`), and per-namespace broadcast channels guarantee a
//! DP only receives deltas for its own namespace. JWT tokens carry an `ns`
//! claim (single string or array) that pins which namespaces the bearer is
//! authorised to subscribe to. `Set` and `All` scopes require this claim
//! automatically; `Single` scope preserves the legacy no-claim path unless
//! `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`. See
//! `docs/cp_namespace_tenancy.md` for the operator guide.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::stream;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{Instant, interval_at};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::auth::{AllowedNamespaces, verify_grpc_jwt_metadata_with_claims};
use super::configsync_lifecycle::CONFIGSYNC_HEARTBEAT_INTERVAL_SECS;
use super::cp_trust::{CpDpVerifier, CpGrpcConnectInfo};
use super::proto::config_sync_server::{ConfigSync, ConfigSyncServer};
use super::proto::{ConfigUpdate, FullConfigRequest, FullConfigResponse, SubscribeRequest};
use crate::FERRUM_VERSION;
use crate::config::types::{GatewayConfig, default_namespace};
use crate::modes::mesh::config::{
    MeshConfig, MeshSidecar, MeshSidecarEgress, PeerAuthentication, PolicyScope,
    SidecarHostPattern, Workload, WorkloadSelector, service_entry_exported_to_namespace,
};
use crate::modes::mesh::slice::{
    MeshSliceRequest, node_waypoint_assertors_from_workloads,
    node_waypoint_capture_destinations_from_workloads,
};

/// Application-level ConfigSync heartbeat interval (matches DP silence budget).
pub const CONFIGSYNC_SUBSCRIBE_HEARTBEAT_INTERVAL: Duration =
    Duration::from_secs(CONFIGSYNC_HEARTBEAT_INTERVAL_SECS);

fn filter_frontend_tls_sources_to_namespace(config: &mut GatewayConfig, namespace: &str) {
    if let Some(source) = config
        .frontend_tls_namespace_sources
        .iter()
        .find(|source| source.namespace == namespace)
        .cloned()
    {
        config.frontend_tls_cert_path = Some(source.cert_path);
        config.frontend_tls_key_path = Some(source.key_path);
        config.frontend_tls_source_namespace = Some(source.namespace);
        config.frontend_tls_namespace_sources.clear();
        return;
    }
    config.frontend_tls_namespace_sources.clear();
    if config
        .frontend_tls_source_namespace
        .as_deref()
        .is_some_and(|source_namespace| source_namespace != namespace)
    {
        config.frontend_tls_cert_path = None;
        config.frontend_tls_key_path = None;
        config.frontend_tls_source_namespace = None;
    }
}

/// What set of namespaces a CP instance is authorised to serve.
///
/// Built from `FERRUM_CP_NAMESPACES` + `FERRUM_NAMESPACE` at CP startup:
///
/// - empty `FERRUM_CP_NAMESPACES` → `Single(FERRUM_NAMESPACE)` (back-compat).
/// - `FERRUM_CP_NAMESPACES="*"` → `All` (cluster-wide CP).
/// - `FERRUM_CP_NAMESPACES="prod,staging"` → `Set({prod,staging})`.
///
/// The scope is the *upper bound* on which namespaces a DP can subscribe to.
/// JWT `ns` claims further restrict this on a per-token basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpScope {
    /// Back-compat single-namespace CP. Identical semantics to the pre-T2-A
    /// behavior: a DP that advertises any other namespace is rejected at
    /// `Subscribe` / `GetFullConfig` time.
    Single(String),
    /// Multi-tenant CP serving an explicit set of namespaces. A DP that
    /// advertises a namespace not in the set is rejected.
    Set(HashSet<String>),
    /// Cluster-wide CP serving every namespace present in the database. The
    /// scope check is a no-op; the per-token JWT `ns` claim bounds what each
    /// DP sees.
    All,
}

impl CpScope {
    /// Resolve the operator's `FERRUM_CP_NAMESPACES` + `FERRUM_NAMESPACE`
    /// values into a [`CpScope`]. The parser already validated entries; here
    /// we only translate them.
    pub fn from_env(cp_namespaces: &[String], fallback_namespace: &str) -> Self {
        if cp_namespaces.is_empty() {
            return CpScope::Single(fallback_namespace.to_string());
        }
        if cp_namespaces.iter().any(|raw| raw.trim() == "*") {
            return CpScope::All;
        }
        let set: HashSet<String> = cp_namespaces
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if set.is_empty() {
            // Defensive: all-whitespace input falls back to single-namespace
            // so the CP still starts up with a usable default.
            return CpScope::Single(fallback_namespace.to_string());
        }
        if set.len() == 1 {
            // Logically equivalent to Single; pick the simpler representation
            // so back-compat code paths see the same shape they used to.
            return CpScope::Single(set.into_iter().next().expect("non-empty set"));
        }
        CpScope::Set(set)
    }

    /// True when this CP scope authorises serving `namespace`. `All`
    /// returns `true` for every namespace.
    pub fn includes(&self, namespace: &str) -> bool {
        match self {
            CpScope::Single(ns) => ns == namespace,
            CpScope::Set(set) => set.contains(namespace),
            CpScope::All => true,
        }
    }

    /// Multi-namespace scopes must not rely on the legacy "shared bearer
    /// authorises every namespace in CP scope" behavior.
    pub fn requires_namespace_claim_by_default(&self) -> bool {
        matches!(self, CpScope::Set(_) | CpScope::All)
    }

    /// True when callers must require a JWT `ns` claim for this scope.
    pub fn namespace_claim_required(&self, require_ns_claim: bool) -> bool {
        require_ns_claim || self.requires_namespace_claim_by_default()
    }

    /// Returns the explicit namespace list the CP loads from the database.
    ///
    /// - `Single(ns)` → `Some(vec![ns])`
    /// - `Set({ns_a, ns_b, ...})` → `Some(vec![ns_a, ns_b, ...])` (stable order)
    /// - `All` → `None` — the caller must discover namespaces dynamically.
    pub fn explicit_namespaces(&self) -> Option<Vec<String>> {
        match self {
            CpScope::Single(ns) => Some(vec![ns.clone()]),
            CpScope::Set(set) => {
                let mut v: Vec<String> = set.iter().cloned().collect();
                v.sort();
                Some(v)
            }
            CpScope::All => None,
        }
    }

    /// Human-readable scope description for startup logs.
    pub fn describe(&self) -> String {
        match self {
            CpScope::Single(ns) => format!("single namespace '{ns}'"),
            CpScope::Set(set) => {
                let mut v: Vec<&String> = set.iter().collect();
                v.sort();
                format!("{} namespaces: [{}]", v.len(), {
                    let joined: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
                    joined.join(", ")
                })
            }
            CpScope::All => "ALL namespaces (cluster-wide)".to_string(),
        }
    }

    /// Durable mesh config-revision sequence for a CP full load (issue #2473).
    ///
    /// The sequence domain must match what incremental polling advances from,
    /// otherwise identical-scope replicas diverge across a restart:
    ///
    /// - [`CpScope::Single`] / [`CpScope::Set`]: maximum of the durable
    ///   per-namespace `latest_change_sequence` cursors for the explicit scope.
    ///   An unrelated namespace's change must not advance (or permanently
    ///   quarantine) a restarted peer that never observed that namespace.
    /// - [`CpScope::All`]: the store-global `config_changes` high-water mark,
    ///   because the dynamically discovered namespace list can shrink after the
    ///   last resource in a namespace is deleted and a restarted CP would
    ///   otherwise rewind past that deleted namespace's sequences.
    ///
    /// `floor` is the in-process published high-water mark so an in-process
    /// full reload cannot stamp backwards either.
    pub fn mesh_full_load_sequence(
        &self,
        scoped_namespace_sequences: &HashMap<String, u64>,
        store_global_sequence: u64,
        floor: u64,
    ) -> u64 {
        let domain = match self {
            CpScope::Single(_) | CpScope::Set(_) => scoped_namespace_sequences
                .values()
                .copied()
                .max()
                .unwrap_or(0),
            CpScope::All => store_global_sequence,
        };
        domain.max(floor)
    }
}

/// Per-namespace broadcast channel set.
///
/// Each namespace served by the CP gets its own `broadcast::Sender`. A DP
/// subscribes to exactly one channel (its own namespace), so a delta for
/// namespace A is never seen by a subscriber in namespace B — fixing the
/// pre-T2-A cross-namespace fan-out.
///
/// Channels are created lazily on first use (first subscriber or first
/// broadcast). Each channel is sized at `channel_capacity`, so per-namespace
/// memory usage is bounded by `channel_capacity * |namespaces|`.
pub struct NamespaceBroadcasts {
    channels: DashMap<String, broadcast::Sender<ConfigUpdate>>,
    channel_capacity: usize,
}

impl NamespaceBroadcasts {
    pub fn new(channel_capacity: usize) -> Self {
        Self {
            channels: DashMap::new(),
            channel_capacity: channel_capacity.max(1),
        }
    }

    /// Return the existing sender for `namespace`, creating one lazily.
    pub fn sender_for(&self, namespace: &str) -> broadcast::Sender<ConfigUpdate> {
        if let Some(existing) = self.channels.get(namespace) {
            return existing.value().clone();
        }
        // Two writers can race here; whichever inserts second drops its
        // freshly-created sender on `or_insert_with`. Acceptable: this is a
        // one-time cost per namespace, off the request hot path.
        self.channels
            .entry(namespace.to_string())
            .or_insert_with(|| broadcast::channel(self.channel_capacity).0)
            .value()
            .clone()
    }

    /// Return the existing sender for `namespace` without creating one when
    /// it doesn't exist. Used by `broadcast_*` helpers so they no-op when
    /// no subscriber has registered for the namespace yet.
    pub fn try_sender_for(&self, namespace: &str) -> Option<broadcast::Sender<ConfigUpdate>> {
        self.channels.get(namespace).map(|e| e.value().clone())
    }

    /// Total namespaces with active or previously-active broadcast channels.
    /// Exposed for observability and tests.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Whether any broadcast channels exist.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Snapshot of namespace names with live broadcast channels (sorted).
    /// Used by the CP polling loop to fan trust-bundle-only ticks to every
    /// subscribed namespace.
    pub fn namespaces(&self) -> Vec<String> {
        let mut v: Vec<String> = self.channels.iter().map(|e| e.key().clone()).collect();
        v.sort();
        v
    }
}

/// Metadata about a connected Data Plane node.
#[derive(Clone, Serialize)]
pub struct DpNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: DateTime<Utc>,
    pub last_update_at: DateTime<Utc>,
}

/// Registry of connected DP nodes. Shared between the gRPC server and the
/// admin API so that `GET /cluster` can report live connection state.
#[derive(Default)]
pub struct DpNodeRegistry {
    nodes: DashMap<String, DpNodeInfo>,
}

impl DpNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    pub fn insert(&self, info: DpNodeInfo) {
        self.nodes.insert(info.node_id.clone(), info);
    }

    /// Remove a node only if its `connected_at` matches the expected timestamp.
    /// This prevents a stale stream drop from removing a newer reconnection's entry.
    pub fn remove_if_stale(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        self.nodes.remove_if(node_id, |_, info| {
            info.connected_at == expected_connected_at
        });
    }

    /// Update `last_update_at` for all connected nodes (called after broadcast).
    pub fn touch_all(&self) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            entry.last_update_at = now;
        }
    }

    /// Update `last_update_at` for connected nodes in a specific namespace.
    /// Used by the per-namespace broadcast path so a delta for namespace A
    /// does not bump the `last_update_at` of namespace B's DPs.
    pub fn touch_namespace(&self, namespace: &str) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            if entry.namespace == namespace {
                entry.last_update_at = now;
            }
        }
    }

    /// Return a snapshot of all connected nodes.
    pub fn snapshot(&self) -> Vec<DpNodeInfo> {
        self.nodes
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Number of connected node IDs.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    /// Whether the registry has no connected node IDs.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A stream wrapper that removes the DP node from the registry when the
/// gRPC stream is dropped (i.e. the DP disconnects). Uses `connected_at`
/// to guard against stale drops: if the DP reconnects before the old stream
/// is dropped, the old drop will not remove the newer entry.
struct TrackedStream<S> {
    inner: Pin<Box<S>>,
    registry: Arc<DpNodeRegistry>,
    node_id: String,
    connected_at: DateTime<Utc>,
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        self.registry
            .remove_if_stale(&self.node_id, self.connected_at);
        info!("DP node '{}' disconnected (stream dropped)", self.node_id);
    }
}

impl<S> tokio_stream::Stream for TrackedStream<S>
where
    S: tokio_stream::Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Default expected issuer for CP/DP gRPC JWTs. Operators override via
/// `FERRUM_CP_DP_GRPC_JWT_ISSUER`. Kept as a `pub const` so the DP token
/// minter can fall back to the same constant when constructing tokens
/// without an `EnvConfig` in scope (tests, library callers).
pub const DEFAULT_CP_DP_JWT_ISSUER: &str = "ferrum-edge-cp-dp";

/// CP gRPC server state.
pub struct CpGrpcServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    /// How inbound tokens are verified and what namespaces each credential is
    /// bound to. Shared with the mesh and xDS servers so all three
    /// configuration surfaces enforce one authorization source
    /// (advisory GHSA-3f2j-wwqw-grmg).
    verifier: Arc<CpDpVerifier>,
    /// Expected `iss` claim on inbound DP tokens. Tokens whose `iss` does not
    /// exactly match this string are rejected with `unauthenticated`.
    expected_issuer: String,
    /// Per-namespace broadcast channels. The legacy single `update_tx`
    /// returned to construction callers is just the sender for the back-compat
    /// `Single(...)` namespace.
    broadcasts: Arc<NamespaceBroadcasts>,
    registry: Arc<DpNodeRegistry>,
    /// Which namespaces this CP is authorised to serve. See [`CpScope`].
    scope: CpScope,
    /// When `true`, every inbound JWT must carry an `ns` claim and the
    /// requested namespace must be in it. `Set` and `All` scopes enforce the
    /// same rule automatically even when this flag is `false`.
    require_ns_claim: bool,
    /// Effective CP-side `FERRUM_REAL_IP_HEADER`. Every DP must advertise the
    /// same value before receiving configuration, making this an enforced
    /// cluster ownership contract rather than a CP-local assumption.
    real_ip_header: Option<String>,
}

impl CpGrpcServer {
    /// Create a new CP gRPC server with the default broadcast channel capacity (128)
    /// plus the default expected issuer and namespace.
    ///
    /// Used by tests. Production code calls `builder()` so it can thread the
    /// operator-configured capacity, issuer, namespace, scope, and claim
    /// policy through from `EnvConfig`.
    #[allow(dead_code)]
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::builder(config, jwt_secret).build()
    }

    #[allow(dead_code)]
    pub fn with_channel_capacity(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .build()
    }

    #[allow(dead_code)]
    pub fn with_channel_capacity_and_registry(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .registry(registry)
            .build()
    }

    /// Constructor that threads through the operator-configured expected issuer
    /// (`FERRUM_CP_DP_GRPC_JWT_ISSUER`) and uses the default namespace.
    #[allow(dead_code)]
    pub fn with_channel_capacity_registry_and_issuer(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
        expected_issuer: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .registry(registry)
            .expected_issuer(expected_issuer)
            .build()
    }

    /// Constructor that threads through the CP's configured namespace and uses
    /// the default CP/DP JWT issuer.
    #[allow(dead_code)]
    pub fn with_channel_capacity_registry_and_namespace(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
        namespace: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .registry(registry)
            .scope(CpScope::Single(namespace))
            .build()
    }

    /// Production-grade constructor that threads through both the operator-
    /// configured expected issuer (`FERRUM_CP_DP_GRPC_JWT_ISSUER`) and the
    /// CP namespace (`FERRUM_NAMESPACE`). Kept for back-compat call sites;
    /// new call sites should use [`Self::builder`] directly.
    #[allow(dead_code)]
    pub fn with_channel_capacity_registry_issuer_and_namespace(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
        expected_issuer: String,
        namespace: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::builder(config, jwt_secret)
            .channel_capacity(channel_capacity)
            .registry(registry)
            .expected_issuer(expected_issuer)
            .scope(CpScope::Single(namespace))
            .build()
    }

    /// Fluent builder. Production code in `control_plane.rs` uses this to
    /// pass the full set of T2-A knobs (scope + require-claim) without
    /// growing yet another constructor overload.
    /// Fluent builder seeded with the legacy fleet-wide shared secret.
    ///
    /// Production CP startup replaces the seeded verifier via
    /// [`CpGrpcServerBuilder::verifier`] whenever a namespace-bound trust
    /// bundle is configured; the shared-secret seed survives only for
    /// single-namespace control planes and tests, where it is
    /// security-equivalent.
    pub fn builder(config: Arc<ArcSwap<GatewayConfig>>, jwt_secret: String) -> CpGrpcServerBuilder {
        CpGrpcServerBuilder {
            config,
            verifier: Arc::new(CpDpVerifier::SharedSecret(jwt_secret)),
            channel_capacity: 128,
            registry: None,
            expected_issuer: DEFAULT_CP_DP_JWT_ISSUER.to_string(),
            scope: CpScope::Single(default_namespace()),
            require_ns_claim: false,
            real_ip_header: None,
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_real_ip_header_compatibility(&self, advertised: Option<&str>) -> Result<(), Status> {
        let Some(advertised) = advertised else {
            return Err(Status::failed_precondition(
                "DP did not advertise its effective FERRUM_REAL_IP_HEADER; upgrade or restart the DP with the current CP/DP ownership contract",
            ));
        };
        let advertised = (!advertised.is_empty()).then_some(advertised);
        let expected = self
            .real_ip_header
            .as_deref()
            .filter(|header| !header.is_empty());
        let matches = match (expected, advertised) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
            _ => false,
        };
        if matches {
            return Ok(());
        }

        Err(Status::failed_precondition(format!(
            "DP effective FERRUM_REAL_IP_HEADER ({advertised:?}) does not match the CP cluster ownership contract ({:?}); configure the same value on every CP and DP",
            expected
        )))
    }

    /// Resolve the bearer's allowed namespace set, then check whether the
    /// requested DP namespace is permitted under both the CP scope and the
    /// JWT claim. Returns the broadcast sender for the namespace on success.
    #[allow(clippy::result_large_err)]
    fn authorise_namespace(
        &self,
        allowed: &AllowedNamespaces,
        dp_namespace: &str,
    ) -> Result<broadcast::Sender<ConfigUpdate>, Status> {
        Self::authorise_namespace_for_scope(
            &self.scope,
            self.require_ns_claim,
            allowed,
            dp_namespace,
        )?;
        Ok(self.broadcasts.sender_for(dp_namespace))
    }

    /// Shared tenant authorisation for every CP-facing configuration surface.
    /// Missing claims are accepted only for genuinely single-namespace CPs
    /// unless the operator opted into strict claims there as well.
    #[allow(clippy::result_large_err)]
    pub(crate) fn authorise_namespace_for_scope(
        scope: &CpScope,
        require_ns_claim: bool,
        allowed: &AllowedNamespaces,
        namespace: &str,
    ) -> Result<(), Status> {
        if namespace.is_empty() {
            return Err(Status::failed_precondition(
                "DP did not advertise a namespace",
            ));
        }

        if scope.namespace_claim_required(require_ns_claim) && !allowed.is_present() {
            if require_ns_claim && !scope.requires_namespace_claim_by_default() {
                return Err(Status::permission_denied(
                    "FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true on this CP: the JWT must include an `ns` claim listing the namespaces this DP may subscribe to",
                ));
            }
            return Err(Status::permission_denied(
                "Multi-namespace CP scope requires the JWT to include an `ns` claim listing the namespaces this DP may subscribe to",
            ));
        }

        // Enforce the effective set (claim and/or server-derived ceiling) even
        // when the JWT carried no `ns` claim. A missing claim must not drop a
        // trust-bundle / SPIFFE bound.
        if allowed.effective_namespaces().is_some() && !allowed.allows(namespace) {
            if allowed.is_present() {
                return Err(Status::permission_denied(format!(
                    "JWT `ns` claim does not authorise namespace '{namespace}'; \
                     the bearer can only subscribe to the namespaces listed in its token"
                )));
            }
            return Err(Status::permission_denied(format!(
                "Presented credential is not authorised for namespace '{namespace}'"
            )));
        }

        if !scope.includes(namespace) {
            return Err(Status::failed_precondition(format!(
                "CP scope ({}) does not include DP namespace '{namespace}'. \
                 Add it to FERRUM_CP_NAMESPACES (or use `*` for cluster-wide).",
                scope.describe()
            )));
        }

        Ok(())
    }

    /// Resolve the tenant namespace for stream protocols that do not carry an
    /// explicit namespace request (xDS ADS). Multi-namespace scopes require a
    /// single-namespace claim; a multi-namespace claim is ambiguous and fails
    /// closed instead of letting node metadata choose the tenant.
    #[allow(clippy::result_large_err)]
    pub(crate) fn resolve_stream_namespace_for_scope(
        scope: &CpScope,
        require_ns_claim: bool,
        allowed: &AllowedNamespaces,
    ) -> Result<String, Status> {
        // Compatible single-scope path when no claim is required. Still apply
        // any server-derived ceiling before accepting the CP's sole namespace —
        // a missing claim must not drop the credential/peer bound.
        if !scope.namespace_claim_required(require_ns_claim)
            && !allowed.is_present()
            && let CpScope::Single(namespace) = scope
        {
            Self::authorise_namespace_for_scope(scope, require_ns_claim, allowed, namespace)?;
            return Ok(namespace.clone());
        }

        if scope.namespace_claim_required(require_ns_claim) && !allowed.is_present() {
            return Err(Status::permission_denied(
                "Multi-namespace CP scope requires xDS JWTs to include a single `ns` claim",
            ));
        }

        if let CpScope::Single(namespace) = scope {
            Self::authorise_namespace_for_scope(scope, require_ns_claim, allowed, namespace)?;
            return Ok(namespace.clone());
        }

        let Some(namespace) = allowed.sole_namespace() else {
            return Err(Status::permission_denied(
                "xDS requires a JWT `ns` claim containing exactly one namespace",
            ));
        };
        Self::authorise_namespace_for_scope(scope, require_ns_claim, allowed, namespace)?;
        Ok(namespace.to_string())
    }

    pub(crate) fn audit_tenant_subscription(
        surface: &'static str,
        node_id: &str,
        namespace: &str,
        result: &'static str,
        reason: &str,
    ) {
        match result {
            "success" => info!(
                audit.event = "tenant_subscription",
                surface, node_id, namespace, result, "Tenant subscription accepted"
            ),
            _ => warn!(
                audit.event = "tenant_subscription",
                surface, node_id, namespace, result, reason, "Tenant subscription rejected"
            ),
        }
    }

    /// Verify a ConfigSync token and resolve the namespaces its bearer is
    /// actually authorized for.
    ///
    /// `extensions` carries the per-connection [`CpGrpcConnectInfo`] the CP
    /// gRPC listener attaches at handshake time. When that connection presented
    /// an mTLS certificate encoding a SPIFFE namespace, the resolved set is
    /// intersected with it — server-derived evidence that the bearer cannot
    /// influence.
    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<AllowedNamespaces, Status> {
        verify_grpc_jwt_metadata_with_claims(
            metadata,
            &self.verifier,
            &self.expected_issuer,
            extensions.get::<CpGrpcConnectInfo>(),
        )
    }

    pub fn into_service(self) -> ConfigSyncServer<Self> {
        ConfigSyncServer::new(self)
    }

    /// Access the per-namespace broadcast map. Used by the CP polling loop
    /// to partition deltas at broadcast time.
    pub fn broadcasts(&self) -> Arc<NamespaceBroadcasts> {
        self.broadcasts.clone()
    }

    /// Access the scope this CP was configured with. Used by the CP polling
    /// loop to decide which namespaces to load from the database.
    #[allow(dead_code)]
    pub fn scope(&self) -> &CpScope {
        &self.scope
    }

    /// Check whether the DP's reported version is compatible with this CP.
    ///
    /// Compatibility uses SemVer parsing. Major and minor versions must match.
    /// Patch-level and prerelease/build differences are allowed (see
    /// [`crate::grpc::configsync_lifecycle::check_peer_version_compatibility`]).
    /// Empty and malformed versions are rejected with `FailedPrecondition`
    /// (issue #2395).
    #[allow(clippy::result_large_err)]
    pub(crate) fn check_version_compatibility(dp_version: &str) -> Result<(), Status> {
        use crate::grpc::configsync_lifecycle::check_peer_version_compatibility;

        check_peer_version_compatibility(FERRUM_VERSION, dp_version)
            .map_err(|err| Status::failed_precondition(err.message("CP", "DP", FERRUM_VERSION)))?;

        // Log patch-only differences for operators (still compatible).
        if let (Ok(local), Ok(peer)) = (
            semver::Version::parse(FERRUM_VERSION),
            semver::Version::parse(dp_version),
        ) && (local.patch != peer.patch || local.pre != peer.pre || local.build != peer.build)
        {
            info!(
                "DP v{} connected to CP v{} (patch/prerelease difference OK)",
                dp_version, FERRUM_VERSION
            );
        }

        Ok(())
    }

    /// Filter a multi-namespace `GatewayConfig` down to a single namespace.
    ///
    /// Multi-tenant CPs load every served namespace into a single
    /// `GatewayConfig` (so admin / observability paths still see the whole
    /// picture), but each DP must only receive its own namespace's slice.
    /// This filter strips cross-namespace resources before the snapshot
    /// reaches the broadcast wire — the DP-side defense-in-depth filter in
    /// `dp_client::filter_config_to_namespace` is a redundant backstop, not
    /// the primary boundary.
    pub(crate) fn filter_config_to_namespace(
        config: &GatewayConfig,
        namespace: &str,
    ) -> GatewayConfig {
        let mut filtered = config.clone();
        Self::filter_non_mesh_config_to_namespace(&mut filtered, namespace);
        if let Some(mesh) = filtered.mesh.as_mut() {
            Self::filter_mesh_config_to_namespace(mesh, namespace);
        }
        filtered
    }

    fn filter_non_mesh_config_to_namespace(config: &mut GatewayConfig, namespace: &str) {
        config.proxies.retain(|p| p.namespace == namespace);
        config.consumers.retain(|c| c.namespace == namespace);
        config.plugin_configs.retain(|pc| pc.namespace == namespace);
        config.upstreams.retain(|u| u.namespace == namespace);
        config.known_namespaces = vec![namespace.to_string()];
        filter_frontend_tls_sources_to_namespace(config, namespace);
    }

    #[cfg(test)]
    pub(crate) fn filter_config_to_mesh_request_for_scope(
        config: &GatewayConfig,
        request: &MeshSliceRequest,
        scope: &CpScope,
    ) -> GatewayConfig {
        Self::filter_config_to_mesh_request_for_scope_and_bearer(config, request, scope, None)
    }

    pub(crate) fn filter_config_to_mesh_request_for_scope_and_bearer(
        config: &GatewayConfig,
        request: &MeshSliceRequest,
        scope: &CpScope,
        bearer_namespaces: Option<&HashSet<String>>,
    ) -> GatewayConfig {
        let mut filtered = config.clone();
        Self::filter_non_mesh_config_to_namespace(&mut filtered, &request.namespace);
        if let Some(mesh) = filtered.mesh.as_mut() {
            Self::filter_mesh_config_to_request(
                mesh,
                request,
                true,
                Some(scope),
                bearer_namespaces,
            );
        }
        if scope.requires_namespace_claim_by_default() {
            Self::clear_unpartitioned_trust_material(&mut filtered);
        }
        filtered
    }

    fn filter_mesh_config_to_namespace(mesh: &mut MeshConfig, namespace: &str) {
        let request = MeshSliceRequest {
            namespace: namespace.to_string(),
            ..MeshSliceRequest::default()
        };
        Self::filter_mesh_config_to_request(mesh, &request, false, None, None);
    }

    fn filter_mesh_config_to_request(
        mesh: &mut MeshConfig,
        request: &MeshSliceRequest,
        allow_cross_namespace_mesh_visibility: bool,
        scope: Option<&CpScope>,
        bearer_namespaces: Option<&HashSet<String>>,
    ) {
        let namespace = request.namespace.as_str();
        let mut visible_namespaces =
            Self::mesh_visible_namespaces(mesh, request, allow_cross_namespace_mesh_visibility);
        Self::constrain_visible_namespaces_to_scope(&mut visible_namespaces, scope);
        // A ServiceWaypoint terminates traffic for destination-visible services,
        // but trusted Ambient UDP evidence can name a source pod from any
        // namespace this CP is allowed to serve. An explicit bearer claim
        // further intersects this superset with all namespaces authorized by
        // that claim. Preserve only
        // pod-addressable source workloads and their policy namespaces beyond
        // the destination view; the slice builder performs the exact
        // UID/SPIFFE/selector bind.
        let ambient_udp_source_namespaces: BTreeSet<String> = if request.ambient_udp_source_scoping
        {
            mesh.workloads
                .iter()
                .filter(|workload| {
                    workload.pod_uid.is_some()
                        && Self::ambient_udp_source_namespace_allowed(&workload.namespace, scope)
                        && bearer_namespaces
                            .is_none_or(|allowed| allowed.contains(&workload.namespace))
                })
                .map(|workload| workload.namespace.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        let istio_root_namespace = mesh.istio_root_namespace.clone();

        // Raw authoritative configs never carry this runtime-only field. When
        // a stream-local config is refiltered after an incremental delta,
        // though, it may already contain source assertors that are no longer
        // visible in `mesh.workloads`; preserve them rather than shrinking the
        // allow-list to the destination-visible workload slice.
        if mesh.node_waypoint_assertors.is_empty() {
            mesh.node_waypoint_assertors = Self::node_waypoint_assertors_for_request(
                mesh,
                namespace,
                allow_cross_namespace_mesh_visibility,
                scope,
            );
        }

        // NodeWaypoint transparent-inbound-capture inventory (issue #3287).
        // Resolved HERE — before the `workloads` / `peer_authentications` retains
        // below narrow both to the subscription namespace — because a
        // NodeWaypoint captures direct plaintext for every ENROLLED pod on its
        // node, and those pods can live in other namespaces. Deriving it after
        // the retains would drop exactly the cross-namespace destination whose
        // STRICT PeerAuthentication must be enforced, and the capture resolver
        // would then see no policy and default PERMISSIVE.
        //
        // Least privilege: only workloads whose trusted
        // `Workload.node_waypoint.spiffe_id` names THIS NodeWaypoint, and only
        // within namespaces this CP scope and the bearer's `ns` claim authorize.
        // The result rides its own slice fields — the ordinary routing views are
        // untouched.
        //
        // Preserved when already present for the same reason the assertor
        // inventory is: a stream-local config refiltered after an incremental
        // delta has ALREADY had its `workloads` narrowed, so recomputing would
        // shrink the inventory to the destination-visible slice. Deltas never
        // carry mesh resources (mesh changes arrive as full snapshots, which
        // refilter from the authoritative config), so the preserved value cannot
        // go stale.
        if request.node_waypoint_capture_scoping {
            if mesh.node_waypoint_capture_destinations.is_empty() {
                let destinations = node_waypoint_capture_destinations_from_workloads(
                    mesh.workloads.iter().filter(|workload| {
                        Self::node_waypoint_capture_namespace_allowed(&workload.namespace, scope)
                            && bearer_namespaces
                                .is_none_or(|allowed| allowed.contains(&workload.namespace))
                    }),
                    request.workload_spiffe_id.as_deref(),
                );
                mesh.node_waypoint_capture_destinations = destinations;
            }
            if mesh.node_waypoint_capture_peer_authentications.is_empty() {
                let capture_peer_authentications =
                    Self::node_waypoint_capture_peer_authentications_for_destinations(
                        &mesh.peer_authentications,
                        &mesh.node_waypoint_capture_destinations,
                        &istio_root_namespace,
                    );
                mesh.node_waypoint_capture_peer_authentications = capture_peer_authentications;
            }
        }
        mesh.workloads.retain(|workload| {
            visible_namespaces.contains(&workload.namespace)
                || (workload.pod_uid.is_some()
                    && ambient_udp_source_namespaces.contains(&workload.namespace))
        });
        if request.ambient_udp_source_scoping {
            // Destination-visible ServiceWaypoint workloads must remain in the
            // ordinary workload view for routing and destination-policy scope,
            // even when their namespace is outside the CP-authorized SOURCE
            // evidence boundary. `MeshSlice` derives its separate Ambient UDP
            // source inventory from `pod_uid.is_some()`, so clear only that
            // source-attestation key on destination-only records. This avoids
            // reintroducing a cross-namespace source pod through the common
            // workload carrier without dropping the destination workload.
            for workload in &mut mesh.workloads {
                if !ambient_udp_source_namespaces.contains(&workload.namespace) {
                    workload.pod_uid = None;
                }
            }
        }
        let workload_ids: HashSet<_> = mesh
            .workloads
            .iter()
            .map(|workload| workload.spiffe_id.clone())
            .collect();
        mesh.services.retain_mut(|service| {
            visible_namespaces.contains(&service.namespace) && {
                service
                    .workloads
                    .retain(|workload| workload_ids.contains(&workload.spiffe_id));
                true
            }
        });
        mesh.mesh_policies.retain(|policy| {
            Self::policy_scope_can_apply_to_namespace(
                &policy.namespace,
                &policy.scope,
                namespace,
                &istio_root_namespace,
            ) || (request.waypoint_name.is_some()
                && visible_namespaces.iter().any(|destination_namespace| {
                    Self::policy_scope_can_apply_to_namespace(
                        &policy.namespace,
                        &policy.scope,
                        destination_namespace,
                        &istio_root_namespace,
                    )
                }))
                || (request.ambient_udp_source_scoping
                    && ambient_udp_source_namespaces
                        .iter()
                        .any(|candidate_namespace| {
                            Self::policy_scope_can_apply_to_namespace(
                                &policy.namespace,
                                &policy.scope,
                                candidate_namespace,
                                &istio_root_namespace,
                            )
                        }))
        });
        mesh.peer_authentications.retain(|policy| {
            Self::peer_auth_can_apply_to_namespace(policy, namespace, &istio_root_namespace)
        });
        mesh.service_entries.retain(|entry| {
            if !Self::namespace_allowed_by_scope(&entry.namespace, scope) {
                return false;
            }
            if allow_cross_namespace_mesh_visibility {
                service_entry_exported_to_namespace(entry, namespace)
            } else {
                entry.namespace == namespace
            }
        });
        mesh.request_authentications.retain(|resource| {
            Self::policy_scope_can_apply_to_namespace(
                &resource.namespace,
                &resource.scope,
                namespace,
                &istio_root_namespace,
            )
        });
        mesh.telemetry_resources.retain(|resource| {
            Self::policy_scope_can_apply_to_namespace(
                &resource.namespace,
                &resource.scope,
                namespace,
                &istio_root_namespace,
            )
        });
        mesh.destination_rules
            .retain(|rule| visible_namespaces.contains(&rule.namespace));
        mesh.proxy_configs.retain(|config| {
            Self::policy_scope_can_apply_to_namespace(
                &config.namespace,
                &config.scope,
                namespace,
                &istio_root_namespace,
            )
        });
        mesh.sidecars.retain(|sidecar| {
            sidecar.namespace == namespace || sidecar.namespace == istio_root_namespace
        });
        let requested_waypoint = request
            .waypoint_name
            .as_deref()
            .filter(|name| !name.trim().is_empty());
        mesh.waypoint_bindings.retain_mut(|binding| {
            if binding.namespace != namespace {
                return false;
            }
            if allow_cross_namespace_mesh_visibility && let Some(waypoint) = requested_waypoint {
                return binding.name == waypoint;
            }
            {
                binding
                    .services
                    .retain(|service| service.namespace == namespace);
                true
            }
        });
        if let Some(multi_cluster) = mesh.multi_cluster.as_mut() {
            multi_cluster
                .east_west_gateways
                .retain(|gateway| gateway.namespace == namespace);
        }
        if let Some(local_services) = mesh.local_inbound_services.as_mut() {
            local_services.retain(|service| service.namespace == namespace);
        }
        mesh.local_inbound_tcp_routes
            .retain(|route| route.namespace == namespace);
        mesh.extension_configs
            .retain(|extension| visible_namespaces.contains(&extension.namespace));
    }

    pub(crate) fn filter_config_to_namespace_for_scope(
        config: &GatewayConfig,
        namespace: &str,
        scope: &CpScope,
    ) -> GatewayConfig {
        let mut filtered = Self::filter_config_to_namespace(config, namespace);
        if scope.requires_namespace_claim_by_default() {
            Self::clear_unpartitioned_trust_material(&mut filtered);
        }
        filtered
    }

    fn mesh_visible_namespaces(
        mesh: &MeshConfig,
        request: &MeshSliceRequest,
        allow_cross_namespace_mesh_visibility: bool,
    ) -> BTreeSet<String> {
        let mut namespaces = BTreeSet::new();
        namespaces.insert(request.namespace.clone());
        if !allow_cross_namespace_mesh_visibility {
            return namespaces;
        }
        Self::add_waypoint_visible_namespaces(mesh, request, &mut namespaces);
        if request.enforce_sidecar_egress || request.sidecar_egress_dry_run {
            Self::add_sidecar_visible_namespaces(mesh, request, &mut namespaces);
        }
        namespaces
    }

    fn add_waypoint_visible_namespaces(
        mesh: &MeshConfig,
        request: &MeshSliceRequest,
        namespaces: &mut BTreeSet<String>,
    ) {
        let Some(waypoint_name) = request
            .waypoint_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
        else {
            return;
        };
        if let Some(binding) = mesh
            .waypoint_bindings
            .iter()
            .find(|binding| binding.name == waypoint_name && binding.namespace == request.namespace)
        {
            namespaces.extend(
                binding
                    .services
                    .iter()
                    .map(|service| service.namespace.clone()),
            );
        }
    }

    fn add_sidecar_visible_namespaces(
        mesh: &MeshConfig,
        request: &MeshSliceRequest,
        namespaces: &mut BTreeSet<String>,
    ) {
        let all_resource_namespaces = Self::mesh_resource_namespaces(mesh);
        for sidecar in &mesh.sidecars {
            if !Self::sidecar_can_apply_to_request_namespace(
                sidecar,
                &request.namespace,
                &mesh.istio_root_namespace,
            ) {
                continue;
            }
            let sidecar_namespace = Self::sidecar_host_match_namespace(
                sidecar,
                &request.namespace,
                &mesh.istio_root_namespace,
            );
            for egress in &sidecar.egress {
                Self::add_namespaces_from_sidecar_egress(
                    egress,
                    sidecar_namespace,
                    namespaces,
                    &all_resource_namespaces,
                );
            }
        }
    }

    fn sidecar_can_apply_to_request_namespace(
        sidecar: &MeshSidecar,
        request_namespace: &str,
        root_namespace: &str,
    ) -> bool {
        let selector_can_apply = sidecar.workload_selector.as_ref().is_none_or(|selector| {
            Self::selector_can_apply_to_namespace(selector, request_namespace)
        });
        selector_can_apply
            && (sidecar.namespace == request_namespace
                || (!root_namespace.is_empty() && sidecar.namespace == root_namespace))
    }

    fn sidecar_host_match_namespace<'a>(
        sidecar: &'a MeshSidecar,
        request_namespace: &'a str,
        root_namespace: &str,
    ) -> &'a str {
        if !root_namespace.is_empty()
            && sidecar.namespace == root_namespace
            && sidecar.namespace != request_namespace
        {
            request_namespace
        } else {
            sidecar.namespace.as_str()
        }
    }

    fn add_namespaces_from_sidecar_egress(
        egress: &MeshSidecarEgress,
        sidecar_namespace: &str,
        namespaces: &mut BTreeSet<String>,
        all_resource_namespaces: &BTreeSet<String>,
    ) {
        for host in &egress.hosts {
            match MeshSidecarEgress::parse_host_pattern(host) {
                SidecarHostPattern::AllowAll | SidecarHostPattern::AnyNamespaceHost { .. } => {
                    namespaces.extend(all_resource_namespaces.iter().cloned());
                }
                SidecarHostPattern::SameNamespaceHost { .. }
                | SidecarHostPattern::SameNamespaceHostBare { .. } => {
                    namespaces.insert(sidecar_namespace.to_string());
                }
                SidecarHostPattern::NamespaceWildcard { namespace }
                | SidecarHostPattern::NamespaceHost { namespace, .. } => {
                    namespaces.insert(namespace.to_string());
                }
            }
        }
    }

    fn mesh_resource_namespaces(mesh: &MeshConfig) -> BTreeSet<String> {
        let mut namespaces = BTreeSet::new();
        namespaces.extend(mesh.workloads.iter().map(|w| w.namespace.clone()));
        namespaces.extend(mesh.services.iter().map(|s| s.namespace.clone()));
        namespaces.extend(mesh.destination_rules.iter().map(|d| d.namespace.clone()));
        namespaces.extend(mesh.extension_configs.iter().map(|e| e.namespace.clone()));
        namespaces.retain(|namespace| !namespace.trim().is_empty());
        namespaces
    }

    fn constrain_visible_namespaces_to_scope(
        namespaces: &mut BTreeSet<String>,
        scope: Option<&CpScope>,
    ) {
        namespaces.retain(|namespace| Self::namespace_allowed_by_scope(namespace, scope));
    }

    fn namespace_allowed_by_scope(namespace: &str, scope: Option<&CpScope>) -> bool {
        match scope {
            Some(CpScope::Set(scope_namespaces)) => scope_namespaces.contains(namespace),
            _ => true,
        }
    }

    fn ambient_udp_source_namespace_allowed(namespace: &str, scope: Option<&CpScope>) -> bool {
        match scope {
            // `Single` historically permits cross-namespace destination
            // visibility for a ServiceWaypoint binding, so the general scope
            // helper above intentionally treats it as unrestricted. Ambient
            // UDP SOURCE evidence is different: the single-namespace CP is an
            // authorization boundary, and a no-claim token must never receive
            // pod identities/policies from namespaces other than its validated
            // subscription namespace.
            Some(CpScope::Single(scope_namespace)) => namespace == scope_namespace,
            Some(CpScope::Set(scope_namespaces)) => scope_namespaces.contains(namespace),
            Some(CpScope::All) | None => true,
        }
    }

    /// Namespace authorization for the NodeWaypoint capture destination
    /// inventory (issue #3287).
    ///
    /// Identical boundary to Ambient UDP source evidence, and deliberately so: a
    /// `Single`-scope CP is an authorization boundary for cross-namespace
    /// EVIDENCE even though the general helper treats `Single` as unrestricted
    /// for ordinary destination visibility. A no-claim token must never receive
    /// pod records or policy from namespaces other than its validated
    /// subscription namespace, whichever cross-namespace inventory asked.
    fn node_waypoint_capture_namespace_allowed(namespace: &str, scope: Option<&CpScope>) -> bool {
        Self::ambient_udp_source_namespace_allowed(namespace, scope)
    }

    /// PeerAuthentication candidates the CP may hand a NodeWaypoint for its
    /// capture destinations (issue #3287).
    ///
    /// Namespace-level applicability only — the CP does not evaluate selectors
    /// against a destination it is not serving. The exact per-workload narrowing
    /// (and Istio precedence / port overrides) happens in the slice builder and
    /// at capture time, so this hop stays the coarsest of the three while still
    /// carrying strictly less than the whole mesh's PeerAuthentication set.
    fn node_waypoint_capture_peer_authentications_for_destinations(
        peer_authentications: &[PeerAuthentication],
        destinations: &[Workload],
        root_namespace: &str,
    ) -> Vec<PeerAuthentication> {
        if destinations.is_empty() {
            return Vec::new();
        }
        let destination_namespaces: BTreeSet<&str> = destinations
            .iter()
            .map(|workload| workload.namespace.as_str())
            .collect();
        peer_authentications
            .iter()
            .filter(|policy| {
                destination_namespaces.iter().any(|namespace| {
                    Self::peer_auth_can_apply_to_namespace(policy, namespace, root_namespace)
                })
            })
            .cloned()
            .collect()
    }

    fn node_waypoint_assertors_for_request(
        mesh: &MeshConfig,
        namespace: &str,
        allow_cross_namespace_mesh_visibility: bool,
        scope: Option<&CpScope>,
    ) -> Vec<crate::identity::spiffe::SpiffeId> {
        node_waypoint_assertors_from_workloads(mesh.workloads.iter().filter(|workload| {
            if !allow_cross_namespace_mesh_visibility && workload.namespace != namespace {
                return false;
            }
            Self::namespace_allowed_by_scope(&workload.namespace, scope)
        }))
    }

    fn policy_scope_can_apply_to_namespace(
        owner_namespace: &str,
        scope: &PolicyScope,
        namespace: &str,
        root_namespace: &str,
    ) -> bool {
        if !Self::resource_owner_can_apply_to_namespace(owner_namespace, namespace, root_namespace)
        {
            return false;
        }
        match scope {
            PolicyScope::MeshWide => true,
            PolicyScope::Namespace {
                namespace: policy_namespace,
            } => policy_namespace == namespace,
            PolicyScope::WorkloadSelector { selector } => {
                Self::selector_can_apply_to_namespace(selector, namespace)
            }
        }
    }

    fn peer_auth_can_apply_to_namespace(
        policy: &PeerAuthentication,
        namespace: &str,
        root_namespace: &str,
    ) -> bool {
        if let Some(scope) = &policy.scope {
            return Self::policy_scope_can_apply_to_namespace(
                &policy.namespace,
                scope,
                namespace,
                root_namespace,
            );
        }

        policy.namespace == namespace
            && policy
                .selector
                .as_ref()
                .is_none_or(|selector| Self::selector_can_apply_to_namespace(selector, namespace))
    }

    fn selector_can_apply_to_namespace(selector: &WorkloadSelector, namespace: &str) -> bool {
        selector
            .namespace
            .as_deref()
            .is_none_or(|selector_namespace| selector_namespace == namespace)
    }

    fn resource_owner_can_apply_to_namespace(
        owner_namespace: &str,
        namespace: &str,
        root_namespace: &str,
    ) -> bool {
        owner_namespace == namespace
            || (!root_namespace.is_empty() && owner_namespace == root_namespace)
    }

    fn clear_unpartitioned_trust_material(config: &mut GatewayConfig) {
        config.trust_bundles = None;
        if let Some(mesh) = config.mesh.as_mut() {
            mesh.trust_bundles = None;
        }
    }

    /// Broadcast a full config snapshot to all DPs in `namespace`.
    ///
    /// Single-namespace deployments call the legacy
    /// [`Self::broadcast_update`] / [`Self::broadcast_update_with_registry`]
    /// helpers, which forward to this method via the back-compat shim. New
    /// multi-namespace code paths in the CP polling loop call this directly
    /// and partition the work by namespace.
    pub fn broadcast_namespace_update(
        broadcasts: &NamespaceBroadcasts,
        namespace: &str,
        config: &GatewayConfig,
        registry: &DpNodeRegistry,
        scope: &CpScope,
    ) {
        let Some(tx) = broadcasts.try_sender_for(namespace) else {
            return;
        };
        let filtered = Self::filter_config_to_namespace_for_scope(config, namespace, scope);
        Self::broadcast_update(&tx, &filtered);
        registry.touch_namespace(namespace);
    }

    /// Broadcast an incremental delta to all DPs in `namespace`. The caller
    /// must pre-filter `result` to entries belonging to that namespace; this
    /// helper does not filter to avoid re-walking large vectors.
    pub fn broadcast_namespace_delta(
        broadcasts: &NamespaceBroadcasts,
        namespace: &str,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
        registry: &DpNodeRegistry,
        trust_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
        scope: &CpScope,
    ) {
        let Some(tx) = broadcasts.try_sender_for(namespace) else {
            return;
        };
        let trust_bundles = if scope.requires_namespace_claim_by_default() {
            None
        } else {
            trust_bundles
        };
        Self::broadcast_delta_with_trust_bundles(&tx, result, version, trust_bundles);
        registry.touch_namespace(namespace);
    }

    /// Broadcast a full config snapshot to all connected DPs.
    ///
    /// Back-compat helper for single-namespace deployments. Multi-namespace
    /// callers must use [`Self::broadcast_namespace_update`] so each DP only
    /// receives its own namespace.
    #[allow(dead_code)]
    pub fn broadcast_update_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        config: &GatewayConfig,
        registry: &DpNodeRegistry,
    ) {
        Self::broadcast_update(tx, config);
        registry.touch_all();
    }

    /// Build a keepalive frame. Only ever emitted on a subscription whose DP
    /// advertised `SubscribeRequest.supports_heartbeat`, so the frame always
    /// restates the negotiated capability.
    fn build_configsync_heartbeat(version: String) -> ConfigUpdate {
        ConfigUpdate {
            update_type: 0,
            config_json: String::new(),
            version,
            timestamp: Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
            trust_bundles_json: String::new(),
            heartbeat: true,
            heartbeat_negotiated: true,
        }
    }

    /// Broadcast a full config snapshot to all connected DPs.
    pub fn broadcast_update(tx: &broadcast::Sender<ConfigUpdate>, config: &GatewayConfig) {
        let config_json = match Self::config_json_for_dp(config) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize config for broadcast: {}", e);
                return;
            }
        };
        let trust_bundles_json = match Self::trust_bundles_json(config.trust_bundles.as_deref()) {
            Ok(json) => json,
            Err(e) => {
                error!(
                    "Failed to serialize gateway trust bundles for broadcast; skipping update: {}",
                    e
                );
                return;
            }
        };
        let update = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
            trust_bundles_json,
            heartbeat: false,
            heartbeat_negotiated: false,
        };
        let _ = tx.send(update);
    }

    /// Broadcast an incremental delta to all connected DPs (with registry update).
    #[allow(dead_code)]
    pub fn broadcast_delta_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
        registry: &DpNodeRegistry,
        trust_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
    ) {
        Self::broadcast_delta_with_trust_bundles(tx, result, version, trust_bundles);
        registry.touch_all();
    }

    /// Broadcast an incremental delta to all connected DPs.
    ///
    /// Sends only the resources that changed (added/modified/removed) instead
    /// of the full config. DPs apply the delta via `ProxyState::apply_incremental`.
    #[allow(dead_code)] // Used by integration tests and external callers without trust-bundle side-channel needs.
    pub fn broadcast_delta(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
    ) {
        Self::broadcast_delta_with_trust_bundles_json(tx, result, version, String::new());
    }

    /// Broadcast an incremental delta with optional gateway trust bundles.
    pub fn broadcast_delta_with_trust_bundles(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
        trust_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
    ) {
        let trust_bundles_json = match Self::trust_bundles_json(trust_bundles) {
            Ok(json) => json,
            Err(e) => {
                error!(
                    "Failed to serialize gateway trust bundles for delta broadcast; skipping update: {}",
                    e
                );
                return;
            }
        };
        Self::broadcast_delta_with_trust_bundles_json(tx, result, version, trust_bundles_json);
    }

    fn broadcast_delta_with_trust_bundles_json(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
        trust_bundles_json: String,
    ) {
        let config_json = match serde_json::to_string(result) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize delta for broadcast: {}", e);
                return;
            }
        };
        let update = ConfigUpdate {
            update_type: 1, // DELTA
            config_json,
            version: version.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
            trust_bundles_json,
            heartbeat: false,
            heartbeat_negotiated: false,
        };
        let _ = tx.send(update);
    }

    fn trust_bundles_json(
        trust_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
    ) -> Result<String, serde_json::Error> {
        match trust_bundles {
            Some(trust_bundles) => {
                let validation_errors = crate::modes::mesh::config::validate_mesh_config(
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    Some(trust_bundles),
                );
                if !validation_errors.is_empty() {
                    error!(
                        "Clearing invalid gateway trust bundles from CP broadcast: {}",
                        validation_errors.join("; ")
                    );
                    return Ok("null".to_string());
                }

                serde_json::to_string(trust_bundles)
            }
            None => Ok("null".to_string()),
        }
    }

    fn config_json_for_dp(config: &GatewayConfig) -> Result<String, serde_json::Error> {
        let mut snapshot = config.clone();
        // Trust bundles travel exclusively through `ConfigUpdate.trust_bundles_json`.
        // Keeping them out of the regular GatewayConfig JSON preserves compatibility
        // with older DPs whose `GatewayConfig` deserializer denies unknown fields.
        snapshot.trust_bundles = None;
        serde_json::to_string(&snapshot)
    }
}

/// Builder for [`CpGrpcServer`]. Construction-order independent — call the
/// setters in any order, then `.build()`.
pub struct CpGrpcServerBuilder {
    config: Arc<ArcSwap<GatewayConfig>>,
    verifier: Arc<CpDpVerifier>,
    channel_capacity: usize,
    registry: Option<Arc<DpNodeRegistry>>,
    expected_issuer: String,
    scope: CpScope,
    require_ns_claim: bool,
    real_ip_header: Option<String>,
}

impl CpGrpcServerBuilder {
    pub fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }

    pub fn registry(mut self, registry: Arc<DpNodeRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn expected_issuer(mut self, issuer: String) -> Self {
        self.expected_issuer = issuer;
        self
    }

    /// Replace the seeded shared-secret verifier with the CP's configured
    /// namespace-bound trust bundle.
    pub fn verifier(mut self, verifier: Arc<CpDpVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    pub fn scope(mut self, scope: CpScope) -> Self {
        self.scope = scope;
        self
    }

    #[allow(dead_code)]
    pub fn require_ns_claim(mut self, require: bool) -> Self {
        self.require_ns_claim = require;
        self
    }

    pub fn real_ip_header(mut self, real_ip_header: Option<String>) -> Self {
        self.real_ip_header = real_ip_header;
        self
    }

    /// Finish construction. Returns the server plus the broadcast sender
    /// for the scope's *first* namespace — kept for back-compat with the
    /// pre-T2-A construction signature, which returned a single sender.
    /// Multi-namespace callers should immediately call [`CpGrpcServer::broadcasts`]
    /// to gain access to the full per-namespace map.
    pub fn build(self) -> (CpGrpcServer, broadcast::Sender<ConfigUpdate>) {
        let registry = self
            .registry
            .unwrap_or_else(|| Arc::new(DpNodeRegistry::new()));
        let broadcasts = Arc::new(NamespaceBroadcasts::new(self.channel_capacity));

        // Pre-create the broadcast channel for the back-compat single-namespace
        // case so the returned `update_tx` matches the pre-T2-A behavior (the
        // sender exists even before the first subscriber connects). For multi-
        // tenant `Set` / `All` scopes we still pre-create channels for every
        // known namespace so the polling loop never silently drops the very
        // first delta — `try_sender_for` skips broadcasting when no channel
        // exists, which would race the polling loop's first tick against the
        // first subscriber.
        let primary_namespace = match &self.scope {
            CpScope::Single(ns) => ns.clone(),
            CpScope::Set(set) => {
                // Pre-create channels for every explicit namespace.
                for ns in set {
                    let _ = broadcasts.sender_for(ns);
                }
                // Pick a stable name (sorted) for the back-compat return value.
                let mut v: Vec<&String> = set.iter().collect();
                v.sort();
                v.first().map(|s| (*s).clone()).unwrap_or_default()
            }
            CpScope::All => {
                // Cluster-wide CP — no explicit namespaces to pre-create.
                // The back-compat `tx` falls back to the default namespace so
                // legacy callers that still reach for the returned sender
                // don't get an empty channel. New callers (multi-namespace
                // polling loop) should consult `broadcasts()` instead.
                default_namespace()
            }
        };
        let primary_tx = broadcasts.sender_for(&primary_namespace);

        (
            CpGrpcServer {
                config: self.config,
                verifier: self.verifier,
                expected_issuer: self.expected_issuer,
                broadcasts,
                registry,
                scope: self.scope,
                require_ns_claim: self.require_ns_claim,
                real_ip_header: self.real_ip_header,
            },
            primary_tx,
        )
    }
}

#[tonic::async_trait]
impl ConfigSync for CpGrpcServer {
    type SubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ConfigUpdate, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let allowed = match self.verify_jwt_metadata(request.metadata(), request.extensions()) {
            Ok(allowed) => allowed,
            Err(status) => {
                let req = request.get_ref();
                Self::audit_tenant_subscription(
                    "ConfigSync.Subscribe",
                    &req.node_id,
                    &req.namespace,
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };

        let inner = request.into_inner();
        let node_id = inner.node_id;
        let dp_version = inner.ferrum_version;
        let dp_namespace = inner.namespace;
        // Heartbeat capability is negotiated, not assumed. A DP that predates
        // `ConfigUpdate.heartbeat` would read an empty heartbeat envelope as an
        // unusable FULL_SNAPSHOT and churn through reconnects, so only
        // advertising subscribers ever receive keepalive frames.
        let heartbeats_negotiated = inner.supports_heartbeat;

        // Reject DPs with incompatible versions before streaming any config.
        Self::check_version_compatibility(&dp_version)?;
        if let Err(status) =
            self.check_real_ip_header_compatibility(inner.real_ip_header.as_deref())
        {
            Self::audit_tenant_subscription(
                "ConfigSync.Subscribe",
                &node_id,
                &dp_namespace,
                "failure",
                status.message(),
            );
            return Err(status);
        }
        // Reject DPs whose namespace fails the JWT `ns` claim or CP scope
        // check. The returned sender is the per-namespace broadcast channel
        // — DPs in different namespaces are guaranteed to receive only their
        // own slice.
        let namespace_tx = match self.authorise_namespace(&allowed, &dp_namespace) {
            Ok(tx) => tx,
            Err(status) => {
                Self::audit_tenant_subscription(
                    "ConfigSync.Subscribe",
                    &node_id,
                    &dp_namespace,
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };
        Self::audit_tenant_subscription(
            "ConfigSync.Subscribe",
            &node_id,
            &dp_namespace,
            "success",
            "",
        );

        info!(
            "DP node '{}' (v{}) subscribed for config updates (namespace='{}', scope={})",
            node_id,
            dp_version,
            dp_namespace,
            self.scope.describe()
        );

        // Register the DP in the node registry (removed on stream drop).
        let now = Utc::now();
        self.registry.insert(DpNodeInfo {
            node_id: node_id.clone(),
            version: dp_version.clone(),
            namespace: dp_namespace.clone(),
            connected_at: now,
            last_update_at: now,
        });

        // Register the receiver before loading the initial snapshot so a
        // concurrent CP broadcast is either captured by this stream or already
        // reflected in the loaded snapshot.
        let rx = namespace_tx.subscribe();

        // Send initial full config — filtered to the DP's namespace so the
        // initial snapshot matches the per-namespace broadcast stream.
        let config = self.config.load_full();
        let filtered =
            Self::filter_config_to_namespace_for_scope(config.as_ref(), &dp_namespace, &self.scope);
        let config_json = Self::config_json_for_dp(&filtered).map_err(|e| {
            error!("Failed to serialize config in subscribe: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;
        let trust_bundles_json = Self::trust_bundles_json(filtered.trust_bundles.as_deref())
            .map_err(|e| {
                error!(
                    "Failed to serialize gateway trust bundles in subscribe: {}",
                    e
                );
                Status::internal("Failed to serialize gateway trust bundles")
            })?;
        let initial = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
            trust_bundles_json,
            heartbeat: false,
            // Confirm the capability on the first message of the stream so the
            // DP arms its application silence watchdog only against a CP that
            // actually committed to sending heartbeats. A CP that predates this
            // field leaves it false and the DP never arms the watchdog.
            heartbeat_negotiated: heartbeats_negotiated,
        };

        let config_for_recovery = self.config.clone();
        let recovery_namespace = dp_namespace.clone();
        let recovery_scope = self.scope.clone();
        let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
            Ok(update) => Some(Ok(update)),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                warn!(
                    "DP config stream lagged behind by {} updates — sending full snapshot to recover",
                    n
                );
                // Send a namespace-filtered full snapshot so the DP recovers
                // from missed deltas without re-leaking other namespaces'
                // config.
                let current = config_for_recovery.load_full();
                let filtered = Self::filter_config_to_namespace_for_scope(
                    current.as_ref(),
                    &recovery_namespace,
                    &recovery_scope,
                );
                match Self::config_json_for_dp(&filtered) {
                    Ok(config_json) => {
                        let trust_bundles_json = match Self::trust_bundles_json(
                            filtered.trust_bundles.as_deref(),
                        ) {
                            Ok(json) => json,
                            Err(e) => {
                                error!(
                                    "Failed to serialize gateway trust bundles for recovery snapshot: {}",
                                    e
                                );
                                return None;
                            }
                        };
                        Some(Ok(ConfigUpdate {
                            update_type: 0, // FULL_SNAPSHOT
                            config_json,
                            version: current.loaded_at.to_rfc3339(),
                            timestamp: chrono::Utc::now().timestamp(),
                            ferrum_version: FERRUM_VERSION.to_string(),
                            trust_bundles_json,
                            heartbeat: false,
                            heartbeat_negotiated: false,
                        }))
                    }
                    Err(e) => {
                        error!("Failed to serialize recovery snapshot: {}", e);
                        None
                    }
                }
            }
        });

        // Prepend initial config, interleave application heartbeats for
        // silent-partition detection, then wrap in TrackedStream so the DP is
        // automatically de-registered when the gRPC stream is dropped.
        //
        // The timer is built unconditionally to keep one concrete stream type;
        // when the DP did not advertise heartbeat support every tick is dropped
        // and no frame is ever written, so a legacy subscriber sees exactly the
        // pre-heartbeat stream contents.
        let initial_stream = tokio_stream::once(Ok(initial));
        let heartbeat_config = self.config.clone();
        let heartbeat_stream = IntervalStream::new(interval_at(
            Instant::now() + CONFIGSYNC_SUBSCRIBE_HEARTBEAT_INTERVAL,
            CONFIGSYNC_SUBSCRIBE_HEARTBEAT_INTERVAL,
        ))
        .filter_map(move |_| {
            if !heartbeats_negotiated {
                return None;
            }
            let current = heartbeat_config.load_full();
            Some(Ok(Self::build_configsync_heartbeat(
                current.loaded_at.to_rfc3339(),
            )))
        });
        let combined = initial_stream.chain(stream::select(stream, heartbeat_stream));
        let tracked = TrackedStream {
            inner: Box::pin(combined),
            registry: self.registry.clone(),
            node_id,
            connected_at: now,
        };

        Ok(Response::new(Box::pin(tracked)))
    }

    async fn get_full_config(
        &self,
        request: Request<FullConfigRequest>,
    ) -> Result<Response<FullConfigResponse>, Status> {
        let allowed = match self.verify_jwt_metadata(request.metadata(), request.extensions()) {
            Ok(allowed) => allowed,
            Err(status) => {
                let req = request.get_ref();
                Self::audit_tenant_subscription(
                    "ConfigSync.GetFullConfig",
                    &req.node_id,
                    &req.namespace,
                    "failure",
                    status.message(),
                );
                return Err(status);
            }
        };

        let req = request.get_ref();
        let dp_version = &req.ferrum_version;
        Self::check_version_compatibility(dp_version)?;
        if let Err(status) = self.check_real_ip_header_compatibility(req.real_ip_header.as_deref())
        {
            Self::audit_tenant_subscription(
                "ConfigSync.GetFullConfig",
                &req.node_id,
                &req.namespace,
                "failure",
                status.message(),
            );
            return Err(status);
        }
        // Same cross-namespace guard as `Subscribe` — without it
        // `GetFullConfig` would leak the wrong namespace's snapshot. We
        // discard the returned sender; `GetFullConfig` is unary.
        if let Err(status) = self.authorise_namespace(&allowed, &req.namespace) {
            Self::audit_tenant_subscription(
                "ConfigSync.GetFullConfig",
                &req.node_id,
                &req.namespace,
                "failure",
                status.message(),
            );
            return Err(status);
        }
        Self::audit_tenant_subscription(
            "ConfigSync.GetFullConfig",
            &req.node_id,
            &req.namespace,
            "success",
            "",
        );

        info!(
            "DP '{}' (v{}) requested full config (namespace='{}')",
            req.node_id, dp_version, req.namespace
        );

        let config = self.config.load_full();
        let filtered = Self::filter_config_to_namespace_for_scope(
            config.as_ref(),
            &req.namespace,
            &self.scope,
        );
        let config_json = Self::config_json_for_dp(&filtered).map_err(|e| {
            error!("Failed to serialize config in get_full_config: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;
        let trust_bundles_json = Self::trust_bundles_json(filtered.trust_bundles.as_deref())
            .map_err(|e| {
                error!(
                    "Failed to serialize gateway trust bundles in get_full_config: {}",
                    e
                );
                Status::internal("Failed to serialize gateway trust bundles")
            })?;

        Ok(Response::new(FullConfigResponse {
            config_json,
            version: config.loaded_at.to_rfc3339(),
            ferrum_version: FERRUM_VERSION.to_string(),
            trust_bundles_json,
        }))
    }
}

// Version compatibility is tested inline because `check_version_compatibility` is private.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;

    fn test_trust_bundles() -> crate::modes::mesh::config::TrustBundleSet {
        crate::modes::mesh::config::TrustBundleSet {
            local: crate::modes::mesh::config::TrustBundle {
                trust_domain: crate::identity::TrustDomain::new("cluster.local")
                    .expect("test trust domain should be valid"),
                x509_authorities: vec!["AQIDBA==".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }
    }

    fn invalid_test_trust_bundles() -> crate::modes::mesh::config::TrustBundleSet {
        crate::modes::mesh::config::TrustBundleSet {
            local: crate::modes::mesh::config::TrustBundle {
                trust_domain: crate::identity::TrustDomain::new("cluster.local")
                    .expect("test trust domain should be valid"),
                x509_authorities: Vec::new(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }
    }

    fn registry_info(node_id: &str, version: &str, connected_at: DateTime<Utc>) -> DpNodeInfo {
        DpNodeInfo {
            node_id: node_id.to_string(),
            version: version.to_string(),
            namespace: "ferrum".to_string(),
            connected_at,
            last_update_at: connected_at,
        }
    }

    #[test]
    fn registry_insert_replaces_same_dp_node() {
        let registry = DpNodeRegistry::new();
        let first_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let second_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", first_connected_at));
        registry.insert(registry_info("node-a", "new-version", second_connected_at));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, second_connected_at);
    }

    #[test]
    fn config_json_for_dp_strips_gateway_trust_bundles() {
        let mut config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            trust_bundles: Some(Box::new(test_trust_bundles())),
            ..Default::default()
        };
        config.known_namespaces.push("ferrum".to_string());

        let json = CpGrpcServer::config_json_for_dp(&config).expect("DP config should serialize");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("DP config JSON should parse");
        assert!(value.get("trust_bundles").is_none());

        let parsed: GatewayConfig =
            serde_json::from_str(&json).expect("stripped DP config should deserialize");
        assert!(parsed.trust_bundles.is_none());
        assert_eq!(parsed.known_namespaces, vec!["ferrum"]);
    }

    #[test]
    fn broadcast_update_sends_trust_bundles_only_in_side_channel() {
        let config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            trust_bundles: Some(Box::new(test_trust_bundles())),
            ..Default::default()
        };
        let (tx, mut rx) = broadcast::channel(1);

        CpGrpcServer::broadcast_update(&tx, &config);
        let update = rx.try_recv().expect("broadcast should deliver update");

        let value: serde_json::Value =
            serde_json::from_str(&update.config_json).expect("config JSON should parse");
        assert!(value.get("trust_bundles").is_none());
        assert_ne!(update.trust_bundles_json, "null");
        assert!(update.trust_bundles_json.contains("cluster.local"));
    }

    #[test]
    fn broadcast_update_clears_invalid_trust_bundle_side_channel() {
        let config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            trust_bundles: Some(Box::new(invalid_test_trust_bundles())),
            ..Default::default()
        };
        let (tx, mut rx) = broadcast::channel(1);

        CpGrpcServer::broadcast_update(&tx, &config);
        let update = rx.try_recv().expect("broadcast should deliver update");

        let value: serde_json::Value =
            serde_json::from_str(&update.config_json).expect("config JSON should parse");
        assert!(value.get("trust_bundles").is_none());
        assert_eq!(update.trust_bundles_json, "null");
    }

    #[test]
    fn registry_stale_drop_does_not_remove_newer_dp_entry() {
        let registry = DpNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", old_connected_at));
        registry.insert(registry_info("node-a", "new-version", new_connected_at));
        registry.remove_if_stale("node-a", old_connected_at);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, new_connected_at);
    }

    #[test]
    fn version_check_same_version_ok() {
        assert!(CpGrpcServer::check_version_compatibility(FERRUM_VERSION).is_ok());
    }

    #[test]
    fn version_check_empty_version_rejected() {
        let result = CpGrpcServer::check_version_compatibility("");
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn version_check_same_major_minor_different_patch_ok() {
        let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        if parts.len() >= 3 {
            let patch: u32 = parts[2].parse().unwrap_or(0);
            let modified = format!("{}.{}.{}", parts[0], parts[1], patch + 1);
            assert!(CpGrpcServer::check_version_compatibility(&modified).is_ok());
        }
    }

    #[test]
    fn version_check_different_minor_rejected() {
        let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        if parts.len() >= 2 {
            let minor: u32 = parts[1].parse().unwrap_or(0);
            let modified = format!("{}.{}.0", parts[0], minor + 1);
            let result = CpGrpcServer::check_version_compatibility(&modified);
            assert!(result.is_err());
        }
    }

    #[test]
    fn version_check_unparseable_version_rejected() {
        let result = CpGrpcServer::check_version_compatibility("1");
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains("Unable to parse"));
    }

    #[test]
    fn version_check_garbage_version_rejected() {
        let result = CpGrpcServer::check_version_compatibility("garbage");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn version_check_prerelease_same_major_minor_ok() {
        let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        if parts.len() >= 2 {
            let peer = format!("{}.{}.0-rc.1", parts[0], parts[1]);
            assert!(CpGrpcServer::check_version_compatibility(&peer).is_ok());
        }
    }

    #[test]
    fn version_check_different_major_rejected() {
        let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        if !parts.is_empty() {
            let major: u64 = parts[0].parse().unwrap_or(0);
            let modified = format!("{}.0.0", major + 1);
            let result = CpGrpcServer::check_version_compatibility(&modified);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
        }
    }

    fn cp_with_namespace(namespace: &str) -> CpGrpcServer {
        let cfg = Arc::new(ArcSwap::new(Arc::new(GatewayConfig::default())));
        let (server, _tx) = CpGrpcServer::with_channel_capacity_registry_and_namespace(
            cfg,
            "test-secret".to_string(),
            128,
            Arc::new(DpNodeRegistry::new()),
            namespace.to_string(),
        );
        server
    }

    fn cp_with_scope(scope: CpScope, require_ns_claim: bool) -> CpGrpcServer {
        let cfg = Arc::new(ArcSwap::new(Arc::new(GatewayConfig::default())));
        let (server, _tx) = CpGrpcServer::builder(cfg, "test-secret".to_string())
            .channel_capacity(128)
            .registry(Arc::new(DpNodeRegistry::new()))
            .scope(scope)
            .require_ns_claim(require_ns_claim)
            .build();
        server
    }

    // ── Back-compat: single-namespace behavior is byte-identical ────────────

    #[test]
    fn single_scope_accepts_matching_namespace() {
        let server = cp_with_namespace("production");
        let allowed = AllowedNamespaces::empty();
        assert!(server.authorise_namespace(&allowed, "production").is_ok());
    }

    #[test]
    fn single_scope_rejects_mismatched_namespace_with_both_in_message() {
        let server = cp_with_namespace("production");
        let err = server
            .authorise_namespace(&AllowedNamespaces::empty(), "staging")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let msg = err.message();
        assert!(
            msg.contains("staging") && msg.contains("production"),
            "error message should mention both namespaces, got: {}",
            msg
        );
    }

    #[test]
    fn single_scope_rejects_empty_dp_namespace() {
        // Empty DP namespace must not silently match the default; tests
        // that the comparison is strict equality, not "default if empty".
        let server = cp_with_namespace("ferrum");
        assert!(
            server
                .authorise_namespace(&AllowedNamespaces::empty(), "")
                .is_err()
        );
    }

    // ── CpScope ─────────────────────────────────────────────────────────────

    #[test]
    fn cp_scope_from_env_empty_falls_back_to_single() {
        let scope = CpScope::from_env(&[], "ferrum");
        assert_eq!(scope, CpScope::Single("ferrum".to_string()));
    }

    #[test]
    fn cp_scope_from_env_star_yields_all() {
        let scope = CpScope::from_env(&["*".to_string()], "ferrum");
        assert_eq!(scope, CpScope::All);
    }

    #[test]
    fn cp_scope_from_env_single_entry_collapses_to_single() {
        let scope = CpScope::from_env(&["prod".to_string()], "ferrum");
        assert_eq!(scope, CpScope::Single("prod".to_string()));
    }

    #[test]
    fn cp_scope_from_env_csv_yields_set() {
        let scope = CpScope::from_env(&["prod".to_string(), "staging".to_string()], "ferrum");
        if let CpScope::Set(set) = scope {
            assert!(set.contains("prod"));
            assert!(set.contains("staging"));
            assert_eq!(set.len(), 2);
        } else {
            panic!("expected Set scope");
        }
    }

    #[test]
    fn cp_scope_from_env_trims_whitespace() {
        let scope = CpScope::from_env(&[" prod ".to_string(), " staging ".to_string()], "ferrum");
        if let CpScope::Set(set) = scope {
            assert!(set.contains("prod"));
            assert!(set.contains("staging"));
        } else {
            panic!("expected Set scope");
        }
    }

    #[test]
    fn cp_scope_includes_single() {
        let scope = CpScope::Single("prod".to_string());
        assert!(scope.includes("prod"));
        assert!(!scope.includes("staging"));
    }

    #[test]
    fn cp_scope_includes_set() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let scope = CpScope::Set(set);
        assert!(scope.includes("prod"));
        assert!(scope.includes("staging"));
        assert!(!scope.includes("dev"));
    }

    #[test]
    fn cp_scope_includes_all_is_universal() {
        let scope = CpScope::All;
        assert!(scope.includes("prod"));
        assert!(scope.includes("anything-else"));
    }

    #[test]
    fn cp_scope_explicit_namespaces_returns_none_for_all() {
        assert_eq!(CpScope::All.explicit_namespaces(), None);
    }

    #[test]
    fn cp_scope_explicit_namespaces_returns_sorted_set() {
        let mut set = HashSet::new();
        set.insert("z-ns".to_string());
        set.insert("a-ns".to_string());
        set.insert("m-ns".to_string());
        let scope = CpScope::Set(set);
        let v = scope
            .explicit_namespaces()
            .expect("set should be enumerable");
        assert_eq!(v, vec!["a-ns", "m-ns", "z-ns"]);
    }

    // ── Set scope: only allowed namespaces accepted ────────────────────────

    #[test]
    fn set_scope_rejects_missing_claim_by_default() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let server = cp_with_scope(CpScope::Set(set), false);
        let err = server
            .authorise_namespace(&AllowedNamespaces::empty(), "prod")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("Multi-namespace"));
    }

    #[test]
    fn set_scope_accepts_listed_namespace_with_claim() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let server = cp_with_scope(CpScope::Set(set), false);
        let mut allowed = HashSet::new();
        allowed.insert("prod".to_string());
        let allowed = AllowedNamespaces::claimed(allowed);
        assert!(server.authorise_namespace(&allowed, "prod").is_ok());
    }

    #[test]
    fn set_scope_rejects_unlisted_namespace() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let server = cp_with_scope(CpScope::Set(set), false);
        let mut allowed = HashSet::new();
        allowed.insert("dev".to_string());
        let allowed = AllowedNamespaces::claimed(allowed);
        let err = server.authorise_namespace(&allowed, "dev").unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("dev"));
    }

    // ── All scope: any namespace accepted, claim still respected ──────────

    #[test]
    fn all_scope_rejects_missing_claim_by_default() {
        let server = cp_with_scope(CpScope::All, false);
        let err = server
            .authorise_namespace(&AllowedNamespaces::empty(), "any-ns")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn all_scope_accepts_any_namespace_with_claim() {
        let server = cp_with_scope(CpScope::All, false);
        let mut allowed = HashSet::new();
        allowed.insert("any-ns".to_string());
        let allowed = AllowedNamespaces::claimed(allowed);
        assert!(server.authorise_namespace(&allowed, "any-ns").is_ok());
    }

    #[test]
    fn single_scope_xds_accepts_array_claim_containing_scope_namespace() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let allowed = AllowedNamespaces::claimed(set);

        let namespace = CpGrpcServer::resolve_stream_namespace_for_scope(
            &CpScope::Single("prod".to_string()),
            false,
            &allowed,
        )
        .expect("single-scope xDS should resolve to the configured namespace");

        assert_eq!(namespace, "prod");
    }

    #[test]
    fn single_scope_xds_rejects_array_claim_missing_scope_namespace() {
        let mut set = HashSet::new();
        set.insert("staging".to_string());
        set.insert("dev".to_string());
        let allowed = AllowedNamespaces::claimed(set);

        let err = CpGrpcServer::resolve_stream_namespace_for_scope(
            &CpScope::Single("prod".to_string()),
            false,
            &allowed,
        )
        .expect_err("claim that omits the single scope namespace must be rejected");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // ── JWT claim authorisation ────────────────────────────────────────────

    #[test]
    fn claim_present_must_authorise_requested_namespace() {
        let mut set = HashSet::new();
        set.insert("staging".to_string());
        let allowed = AllowedNamespaces::claimed(set);
        let server = cp_with_scope(CpScope::All, false);
        // Claim only allows staging — production must be rejected.
        let err = server
            .authorise_namespace(&allowed, "production")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("production"));
    }

    #[test]
    fn claim_present_allowing_namespace_passes_scope_check() {
        let mut set = HashSet::new();
        set.insert("production".to_string());
        let allowed = AllowedNamespaces::claimed(set);
        let server = cp_with_scope(CpScope::Single("production".to_string()), false);
        assert!(server.authorise_namespace(&allowed, "production").is_ok());
    }

    #[test]
    fn require_claim_rejects_missing_claim() {
        let server = cp_with_scope(CpScope::Single("prod".to_string()), true);
        let err = server
            .authorise_namespace(&AllowedNamespaces::empty(), "prod")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("FERRUM_CP_REQUIRE_NAMESPACE_CLAIM"));
    }

    #[test]
    fn require_claim_accepts_when_claim_matches() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        let allowed = AllowedNamespaces::claimed(set);
        let server = cp_with_scope(CpScope::Single("prod".to_string()), true);
        assert!(server.authorise_namespace(&allowed, "prod").is_ok());
    }

    #[test]
    fn server_derived_effective_set_without_claim_still_constrains() {
        // Trust-bundle / SPIFFE ceiling with no JWT `ns` claim: is_present is
        // false (claim requirement still applies for multi-namespace), but the
        // effective set must still authorise the requested namespace.
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        let allowed = AllowedNamespaces::resolved(false, Some(set));
        let server = cp_with_scope(CpScope::Single("prod".to_string()), false);
        assert!(server.authorise_namespace(&allowed, "prod").is_ok());
        let err = server.authorise_namespace(&allowed, "staging").unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("staging"));
    }

    #[test]
    fn all_scope_xds_rejects_effective_sole_namespace_without_claim() {
        // The pre-fix bug: a single-namespace-bound credential with no `ns`
        // claim produced an effective sole namespace that xDS misread as a
        // present claim under CpScope::All.
        let mut set = HashSet::new();
        set.insert("tenant-a".to_string());
        let allowed = AllowedNamespaces::resolved(false, Some(set));
        let err = CpGrpcServer::resolve_stream_namespace_for_scope(&CpScope::All, false, &allowed)
            .expect_err("missing claim must not be satisfied by a server-derived sole namespace");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("ns"));
    }

    // ── Per-namespace broadcast partition ──────────────────────────────────

    #[test]
    fn broadcasts_create_per_namespace_channels_lazily() {
        let b = NamespaceBroadcasts::new(16);
        assert!(b.is_empty());
        let _ = b.sender_for("ns-a");
        assert_eq!(b.len(), 1);
        let _ = b.sender_for("ns-a");
        // Re-using a namespace must not double-create.
        assert_eq!(b.len(), 1);
        let _ = b.sender_for("ns-b");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn broadcasts_try_sender_returns_none_for_unseen_namespace() {
        let b = NamespaceBroadcasts::new(16);
        assert!(b.try_sender_for("ns-a").is_none());
        let _ = b.sender_for("ns-a");
        assert!(b.try_sender_for("ns-a").is_some());
    }

    #[test]
    fn broadcasts_partition_a_delta_does_not_reach_other_namespace() {
        let b = NamespaceBroadcasts::new(16);
        let tx_a = b.sender_for("ns-a");
        let tx_b = b.sender_for("ns-b");
        let mut rx_a = tx_a.subscribe();
        let mut rx_b = tx_b.subscribe();

        // Send to ns-a only.
        let config_a = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            ..Default::default()
        };
        CpGrpcServer::broadcast_update(&tx_a, &config_a);

        let _update = rx_a
            .try_recv()
            .expect("ns-a subscriber must receive update");
        assert!(
            matches!(
                rx_b.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "ns-b subscriber must NOT receive ns-a's update"
        );
    }

    #[test]
    fn namespace_filter_strips_cross_namespace_resources() {
        use crate::config::types::*;
        let p_a = serde_json::from_value::<Proxy>(serde_json::json!({
            "id": "p-a",
            "namespace": "ns-a",
            "backend_host": "example.com",
            "backend_port": 443,
        }))
        .expect("proxy fixture should deserialize");
        let p_b = serde_json::from_value::<Proxy>(serde_json::json!({
            "id": "p-b",
            "namespace": "ns-b",
            "backend_host": "example.com",
            "backend_port": 443,
        }))
        .expect("proxy fixture should deserialize");

        let config = GatewayConfig {
            version: CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            proxies: vec![p_a, p_b],
            ..Default::default()
        };
        let filtered = CpGrpcServer::filter_config_to_namespace(&config, "ns-a");
        assert_eq!(filtered.proxies.len(), 1);
        assert_eq!(filtered.proxies[0].namespace, "ns-a");
        assert_eq!(filtered.proxies[0].id, "p-a");
    }

    #[test]
    fn namespace_filter_preserves_mesh_wide_root_namespace_policies() {
        use crate::modes::mesh::config::{
            MeshRequestAuthentication, MeshTelemetryConfig, MeshTelemetryResource, MtlsMode,
        };

        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                istio_root_namespace: "istio-system".to_string(),
                mesh_policies: vec![
                    crate::modes::mesh::config::MeshPolicy {
                        name: "root-authz".to_string(),
                        namespace: "istio-system".to_string(),
                        scope: PolicyScope::MeshWide,
                        rules: Vec::new(),
                    },
                    crate::modes::mesh::config::MeshPolicy {
                        name: "other-authz".to_string(),
                        namespace: "ns-b".to_string(),
                        scope: PolicyScope::Namespace {
                            namespace: "ns-b".to_string(),
                        },
                        rules: Vec::new(),
                    },
                    crate::modes::mesh::config::MeshPolicy {
                        name: "foreign-mesh-wide".to_string(),
                        namespace: "ns-b".to_string(),
                        scope: PolicyScope::MeshWide,
                        rules: Vec::new(),
                    },
                ],
                peer_authentications: vec![PeerAuthentication {
                    name: "root-peer".to_string(),
                    namespace: "istio-system".to_string(),
                    scope: Some(PolicyScope::MeshWide),
                    selector: None,
                    mtls_mode: MtlsMode::Strict,
                    port_overrides: Default::default(),
                }],
                request_authentications: vec![MeshRequestAuthentication {
                    name: "root-ra".to_string(),
                    namespace: "istio-system".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: Vec::new(),
                }],
                telemetry_resources: vec![MeshTelemetryResource {
                    name: "root-telemetry".to_string(),
                    namespace: "istio-system".to_string(),
                    scope: PolicyScope::MeshWide,
                    config: MeshTelemetryConfig::default(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let filtered = CpGrpcServer::filter_config_to_namespace(&config, "ns-a");
        let mesh = filtered.mesh.expect("mesh should remain");

        assert_eq!(mesh.mesh_policies.len(), 1);
        assert_eq!(mesh.mesh_policies[0].name, "root-authz");
        assert_eq!(mesh.peer_authentications.len(), 1);
        assert_eq!(mesh.request_authentications.len(), 1);
        assert_eq!(mesh.telemetry_resources.len(), 1);
    }

    #[test]
    fn namespace_filter_keeps_namespaced_extension_configs_in_multi_scope() {
        use crate::modes::mesh::slice::MeshExtensionConfig;

        let mut set = HashSet::new();
        set.insert("ns-a".to_string());
        set.insert("ns-b".to_string());
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                extension_configs: vec![
                    MeshExtensionConfig {
                        name: "ext-a".to_string(),
                        namespace: "ns-a".to_string(),
                        type_url: "type.googleapis.com/ferrum.ext.A".to_string(),
                        value: b"a".to_vec(),
                    },
                    MeshExtensionConfig {
                        name: "ext-b".to_string(),
                        namespace: "ns-b".to_string(),
                        type_url: "type.googleapis.com/ferrum.ext.B".to_string(),
                        value: b"b".to_vec(),
                    },
                ],
                ..MeshConfig::default()
            })),
            trust_bundles: Some(Box::new(test_trust_bundles())),
            ..GatewayConfig::default()
        };

        let filtered =
            CpGrpcServer::filter_config_to_namespace_for_scope(&config, "ns-a", &CpScope::Set(set));
        let mesh = filtered.mesh.expect("mesh should remain");

        assert!(filtered.trust_bundles.is_none());
        assert_eq!(mesh.extension_configs.len(), 1);
        assert_eq!(mesh.extension_configs[0].name, "ext-a");
    }

    #[test]
    fn mesh_request_filter_preserves_exported_service_entries() {
        use crate::modes::mesh::config::{Resolution, ServiceEntry, ServiceEntryLocation};

        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![
                    ServiceEntry {
                        name: "shared-api".to_string(),
                        namespace: "shared".to_string(),
                        hosts: vec!["shared.example.com".to_string()],
                        endpoints: Vec::new(),
                        resolution: Resolution::Dns,
                        location: ServiceEntryLocation::MeshExternal,
                        ports: Vec::new(),
                        export_to: vec!["ns-a".to_string()],
                        workload_selector: None,
                    },
                    ServiceEntry {
                        name: "private-api".to_string(),
                        namespace: "ns-b".to_string(),
                        hosts: vec!["private.example.com".to_string()],
                        endpoints: Vec::new(),
                        resolution: Resolution::Dns,
                        location: ServiceEntryLocation::MeshExternal,
                        ports: Vec::new(),
                        export_to: Vec::new(),
                        workload_selector: None,
                    },
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let request = MeshSliceRequest {
            namespace: "ns-a".to_string(),
            ..MeshSliceRequest::default()
        };

        let mesh_config = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Single("ns-a".to_string()),
        );
        let strict_config = CpGrpcServer::filter_config_to_namespace(&config, "ns-a");

        let mesh = mesh_config
            .mesh
            .expect("mesh request view should retain mesh");
        assert_eq!(mesh.service_entries.len(), 1);
        assert_eq!(mesh.service_entries[0].name, "shared-api");
        assert!(
            strict_config
                .mesh
                .expect("strict view should retain mesh")
                .service_entries
                .is_empty(),
            "ConfigSync namespace filtering must not serialize foreign ServiceEntries"
        );

        let mut ns_a_only = HashSet::new();
        ns_a_only.insert("ns-a".to_string());
        let scoped_config = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Set(ns_a_only),
        );
        assert!(
            scoped_config
                .mesh
                .expect("mesh request view should retain mesh")
                .service_entries
                .is_empty(),
            "explicit Set scope must not serialize exported ServiceEntries owned by namespaces outside FERRUM_CP_NAMESPACES"
        );
    }

    #[test]
    fn mesh_request_filter_preserves_waypoint_bound_cross_namespace_services() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{
            AppProtocol, MeshService, MeshWaypointBinding, MeshWaypointServiceRef, ServicePort,
            Workload, WorkloadRef,
        };

        let destination_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews")
            .expect("destination SPIFFE ID");
        let service = MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: destination_spiffe.clone(),
            }],
            protocol_overrides: Default::default(),
            cluster_ips: Vec::new(),
        };
        let source_workload = Workload {
            spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/clients/sa/client")
                .expect("source SPIFFE ID"),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "client".to_string())]),
                namespace: Some("clients".to_string()),
            },
            service_name: "client".to_string(),
            addresses: vec!["10.2.0.11".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("source trust domain"),
            namespace: "clients".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("client".to_string()),
            pod_uid: Some("16b2c3d4-9dad-11d1-80b4-00c04fd430c8".to_string()),
            node_waypoint: None,
            remote_provenance: false,
        };
        let destination_workload = Workload {
            spiffe_id: destination_spiffe,
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some("default".to_string()),
            },
            service_name: "reviews".to_string(),
            addresses: vec!["10.2.0.12".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("destination trust domain"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("reviews".to_string()),
            pod_uid: Some("26b2c3d4-9dad-11d1-80b4-00c04fd430c8".to_string()),
            node_waypoint: None,
            remote_provenance: false,
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![source_workload, destination_workload],
                services: vec![service],
                mesh_policies: vec![
                    crate::modes::mesh::config::MeshPolicy {
                        name: "clients-source-policy".to_string(),
                        namespace: "clients".to_string(),
                        scope: PolicyScope::Namespace {
                            namespace: "clients".to_string(),
                        },
                        rules: Vec::new(),
                    },
                    crate::modes::mesh::config::MeshPolicy {
                        name: "reviews-destination-policy".to_string(),
                        namespace: "default".to_string(),
                        scope: PolicyScope::Namespace {
                            namespace: "default".to_string(),
                        },
                        rules: Vec::new(),
                    },
                ],
                waypoint_bindings: vec![MeshWaypointBinding {
                    name: "waypoint".to_string(),
                    namespace: "infra".to_string(),
                    waypoint_for: "service".to_string(),
                    services: vec![MeshWaypointServiceRef {
                        namespace: "default".to_string(),
                        name: "reviews".to_string(),
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let request = MeshSliceRequest {
            namespace: "infra".to_string(),
            waypoint_name: Some("waypoint".to_string()),
            ambient_udp_source_scoping: true,
            ..MeshSliceRequest::default()
        };

        let mesh_config =
            CpGrpcServer::filter_config_to_mesh_request_for_scope(&config, &request, &CpScope::All);
        let single_scope_config = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Single("infra".to_string()),
        );
        let mut request_without_udp_scoping = request.clone();
        request_without_udp_scoping.ambient_udp_source_scoping = false;
        let mesh_config_without_udp_scoping = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request_without_udp_scoping,
            &CpScope::Single("infra".to_string()),
        );
        let bearer_restricted = CpGrpcServer::filter_config_to_mesh_request_for_scope_and_bearer(
            &config,
            &request,
            &CpScope::Set(HashSet::from([
                "infra".to_string(),
                "clients".to_string(),
                "default".to_string(),
            ])),
            Some(&HashSet::from(["infra".to_string()])),
        );
        let strict_config = CpGrpcServer::filter_config_to_namespace(&config, "infra");

        let mesh = mesh_config
            .mesh
            .expect("mesh request view should retain mesh");
        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.services[0].namespace, "default");
        assert_eq!(mesh.services[0].name, "reviews");
        assert_eq!(mesh.waypoint_bindings.len(), 1);
        assert_eq!(mesh.waypoint_bindings[0].services.len(), 1);
        assert_eq!(mesh.waypoint_bindings[0].services[0].namespace, "default");
        assert_eq!(mesh.workloads.len(), 2);
        assert!(
            mesh.workloads
                .iter()
                .any(|workload| workload.namespace == "clients" && workload.pod_uid.is_some())
        );
        assert_eq!(mesh.mesh_policies.len(), 2);
        assert!(
            mesh.mesh_policies
                .iter()
                .any(|policy| policy.name == "clients-source-policy")
        );
        assert!(
            mesh.mesh_policies
                .iter()
                .any(|policy| policy.name == "reviews-destination-policy")
        );
        let single_scope_mesh = single_scope_config
            .mesh
            .expect("single-scope mesh view should remain");
        assert_eq!(single_scope_mesh.services.len(), 1);
        assert_eq!(single_scope_mesh.workloads.len(), 1);
        assert_eq!(single_scope_mesh.workloads[0].namespace, "default");
        assert!(single_scope_mesh.workloads[0].pod_uid.is_none());
        assert_eq!(single_scope_mesh.mesh_policies.len(), 1);
        assert_eq!(
            single_scope_mesh.mesh_policies[0].name,
            "reviews-destination-policy"
        );
        let bearer_mesh = bearer_restricted
            .mesh
            .expect("bearer-restricted mesh view should remain");
        assert_eq!(bearer_mesh.workloads.len(), 1);
        assert_eq!(bearer_mesh.workloads[0].namespace, "default");
        assert!(bearer_mesh.workloads[0].pod_uid.is_none());
        assert_eq!(bearer_mesh.mesh_policies.len(), 1);
        assert_eq!(
            bearer_mesh.mesh_policies[0].name,
            "reviews-destination-policy"
        );
        assert_eq!(bearer_mesh.services.len(), 1);
        assert!(
            mesh_config_without_udp_scoping
                .mesh
                .expect("mesh request view should retain mesh")
                .mesh_policies
                .iter()
                .all(|policy| policy.name != "clients-source-policy"),
            "cross-namespace source policies require the explicit Ambient UDP scoping request; destination policies remain visible"
        );
        assert!(
            strict_config
                .mesh
                .expect("strict view should retain mesh")
                .services
                .is_empty(),
            "ConfigSync namespace filtering must not serialize foreign services"
        );
    }

    #[test]
    fn mesh_request_filter_preserves_source_node_waypoint_assertors_before_workload_narrowing() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{NodeWaypointEndpoint, Workload};
        use crate::modes::mesh::slice::MeshSlice;

        let waypoint_alpha = "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-alpha";
        let waypoint_beta = "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-beta";
        let workload =
            |namespace: &str, service_name: &str, waypoint_spiffe: &str, address: &str| Workload {
                spiffe_id: SpiffeId::new(format!(
                    "spiffe://test.local/ns/{namespace}/sa/{service_name}"
                ))
                .expect("fixture SPIFFE ID should be valid"),
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), service_name.to_string())]),
                    namespace: Some(namespace.to_string()),
                },
                service_name: service_name.to_string(),
                addresses: vec![address.to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("test.local")
                    .expect("fixture trust domain should be valid"),
                namespace: namespace.to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: Some(service_name.to_string()),
                pod_uid: None,
                node_waypoint: Some(NodeWaypointEndpoint {
                    address: address.to_string(),
                    hbone_port: 15008,
                    spiffe_id: SpiffeId::new(waypoint_spiffe)
                        .expect("fixture waypoint SPIFFE ID should be valid"),
                    node_name: None,
                    node_uid: None,
                    network: None,
                    cluster: None,
                }),
                remote_provenance: false,
            };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![
                    workload("alpha", "client", waypoint_alpha, "10.2.0.11"),
                    workload("beta", "reviews", waypoint_beta, "10.2.0.12"),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let request = MeshSliceRequest {
            namespace: "beta".to_string(),
            ..MeshSliceRequest::default()
        };

        let mut full_scope = HashSet::new();
        full_scope.insert("alpha".to_string());
        full_scope.insert("beta".to_string());
        let filtered = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Set(full_scope),
        );
        let mesh = filtered.mesh.as_ref().expect("mesh should remain");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].namespace, "beta");
        assert_eq!(
            mesh.node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_alpha, waypoint_beta],
            "CP should derive assertors from scope-authorized workloads before request-visible workload narrowing"
        );

        let slice = MeshSlice::from_gateway_config(&filtered, request.clone());
        assert_eq!(
            slice
                .node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_alpha, waypoint_beta],
            "the narrowed slice must carry source-node assertors that are no longer visible as workloads"
        );

        let mut beta_only_scope = HashSet::new();
        beta_only_scope.insert("beta".to_string());
        let beta_only = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Set(beta_only_scope),
        );
        let beta_only_mesh = beta_only.mesh.as_ref().expect("mesh should remain");
        assert_eq!(
            beta_only_mesh
                .node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_beta],
            "explicit CP namespace scopes must bound the assertor inventory"
        );
    }

    /// Issue #3287 root finding: a NodeWaypoint deployed in `ferrum` captures
    /// direct plaintext for an enrolled pod in `payments`. The CP narrows
    /// `workloads` and `peer_authentications` to the subscription namespace, so
    /// without a dedicated inventory the `payments` STRICT PeerAuthentication
    /// never reaches the DP and the capture resolver defaults PERMISSIVE.
    ///
    /// Also pins the authorization boundary: an unauthorized namespace (outside
    /// the CP scope, or outside the bearer `ns` claim) contributes NOTHING, and a
    /// pod enrolled on a DIFFERENT NodeWaypoint is never carried.
    #[test]
    fn mesh_request_filter_carries_cross_namespace_node_waypoint_capture_inventory() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{MtlsMode, NodeWaypointEndpoint, Workload};
        use crate::modes::mesh::slice::MeshSlice;

        let this_waypoint = "spiffe://test.local/ns/ferrum/sa/node-waypoint-a";
        let other_waypoint = "spiffe://test.local/ns/ferrum/sa/node-waypoint-b";
        let workload = |namespace: &str, name: &str, waypoint: &str, address: &str| Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://test.local/ns/{namespace}/sa/{name}"))
                .expect("fixture SPIFFE ID should be valid"),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), name.to_string())]),
                namespace: Some(namespace.to_string()),
            },
            service_name: name.to_string(),
            addresses: vec![address.to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("test.local")
                .expect("fixture trust domain should be valid"),
            namespace: namespace.to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some(name.to_string()),
            pod_uid: None,
            node_waypoint: Some(NodeWaypointEndpoint {
                address: "10.0.0.1".to_string(),
                hbone_port: 15008,
                spiffe_id: SpiffeId::new(waypoint)
                    .expect("fixture waypoint SPIFFE ID should be valid"),
                node_name: None,
                node_uid: None,
                network: None,
                cluster: None,
            }),
            remote_provenance: false,
        };
        let namespace_peer_auth = |namespace: &str, mode: MtlsMode| PeerAuthentication {
            name: format!("{namespace}-default"),
            namespace: namespace.to_string(),
            scope: Some(PolicyScope::Namespace {
                namespace: namespace.to_string(),
            }),
            selector: None,
            mtls_mode: mode,
            port_overrides: HashMap::new(),
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![
                    // Enrolled on THIS NodeWaypoint, in another namespace.
                    workload("payments", "ledger", this_waypoint, "10.244.1.7"),
                    // Enrolled on ANOTHER node's NodeWaypoint.
                    workload("payments", "reports", other_waypoint, "10.244.1.8"),
                    // Enrolled on THIS NodeWaypoint but in a namespace the
                    // restricted scopes below do not authorize.
                    workload("secrets", "vault", this_waypoint, "10.244.1.9"),
                ],
                peer_authentications: vec![
                    namespace_peer_auth("payments", MtlsMode::Strict),
                    namespace_peer_auth("secrets", MtlsMode::Strict),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let request = MeshSliceRequest {
            namespace: "ferrum".to_string(),
            workload_spiffe_id: Some(this_waypoint.to_string()),
            node_waypoint_capture_scoping: true,
            ..MeshSliceRequest::default()
        };

        let filtered =
            CpGrpcServer::filter_config_to_mesh_request_for_scope(&config, &request, &CpScope::All);
        let mesh = filtered.mesh.as_ref().expect("mesh should remain");
        assert!(
            mesh.workloads.is_empty() && mesh.peer_authentications.is_empty(),
            "the ordinary namespace views must stay narrowed to `ferrum` — the inventory is the \
             ONLY channel, so this must not widen routing visibility"
        );
        assert_eq!(
            mesh.node_waypoint_capture_destinations
                .iter()
                .map(|workload| workload.service_name.as_str())
                .collect::<Vec<_>>(),
            vec!["ledger", "vault"],
            "only workloads enrolled on THIS NodeWaypoint may enter the capture inventory"
        );
        assert_eq!(
            mesh.node_waypoint_capture_peer_authentications
                .iter()
                .map(|policy| policy.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["payments", "secrets"],
            "each captured destination's own-namespace PeerAuthentication must be carried"
        );

        let slice = MeshSlice::from_gateway_config(&filtered, request.clone());
        assert_eq!(
            slice
                .node_waypoint_capture_destinations
                .iter()
                .map(|workload| workload.service_name.as_str())
                .collect::<Vec<_>>(),
            vec!["ledger", "vault"],
            "the narrowed slice must carry capture destinations that are no longer visible as \
             workloads"
        );
        assert_eq!(
            slice.node_waypoint_capture_peer_authentications.len(),
            2,
            "and the PeerAuthentication candidates applicable to them"
        );

        // A `Single`-scope CP is an authorization boundary for cross-namespace
        // evidence: only its own namespace may contribute, so a NodeWaypoint
        // subscribed as `ferrum` gets NOTHING here.
        let single = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Single("ferrum".to_string()),
        );
        let single_mesh = single.mesh.as_ref().expect("mesh should remain");
        assert!(
            single_mesh.node_waypoint_capture_destinations.is_empty()
                && single_mesh
                    .node_waypoint_capture_peer_authentications
                    .is_empty(),
            "a single-namespace CP scope must not hand out other namespaces' pods or policy"
        );

        // An explicit bearer `ns` claim intersects the scope: `payments` is
        // authorized, `secrets` is not.
        let bearer = CpGrpcServer::filter_config_to_mesh_request_for_scope_and_bearer(
            &config,
            &request,
            &CpScope::Set(HashSet::from([
                "ferrum".to_string(),
                "payments".to_string(),
                "secrets".to_string(),
            ])),
            Some(&HashSet::from(["payments".to_string()])),
        );
        let bearer_mesh = bearer.mesh.as_ref().expect("mesh should remain");
        assert_eq!(
            bearer_mesh
                .node_waypoint_capture_destinations
                .iter()
                .map(|workload| workload.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["payments"],
            "an unauthorized namespace must be absent from the capture inventory"
        );
        assert_eq!(
            bearer_mesh
                .node_waypoint_capture_peer_authentications
                .iter()
                .map(|policy| policy.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["payments"],
            "and its policy must not ride along either"
        );

        // Without the flag the CP resolves no inventory at all.
        let mut unflagged_request = request;
        unflagged_request.node_waypoint_capture_scoping = false;
        let unflagged = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &unflagged_request,
            &CpScope::All,
        );
        let unflagged_mesh = unflagged.mesh.as_ref().expect("mesh should remain");
        assert!(
            unflagged_mesh.node_waypoint_capture_destinations.is_empty()
                && unflagged_mesh
                    .node_waypoint_capture_peer_authentications
                    .is_empty(),
            "a non-NodeWaypoint subscription must not receive the capture inventory"
        );
    }

    #[test]
    fn mesh_request_filter_preserves_sidecar_admitted_cross_namespace_services() {
        use crate::modes::mesh::config::{
            AppProtocol, MeshDestinationRule, MeshService, MeshSidecar, MeshSidecarEgress,
            ServicePort,
        };
        use crate::modes::mesh::slice::MeshSlice;

        let service = |namespace: &str, name: &str| MeshService {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: Default::default(),
            cluster_ips: Vec::new(),
        };
        let destination_rule = |namespace: &str, name: &str, host: &str| MeshDestinationRule {
            name: name.to_string(),
            namespace: namespace.to_string(),
            host: host.to_string(),
            traffic_policy: None,
            port_level_settings: Default::default(),
            subsets: Vec::new(),
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                sidecars: vec![MeshSidecar {
                    name: "beta-egress".to_string(),
                    namespace: "alpha".to_string(),
                    workload_selector: None,
                    egress_inherits_defaults: false,
                    egress: vec![MeshSidecarEgress {
                        hosts: vec!["beta/*".to_string()],
                        port: None,
                    }],
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: None,
                }],
                services: vec![
                    service("alpha", "reviews"),
                    service("beta", "checkout"),
                    service("gamma", "payments"),
                ],
                destination_rules: vec![
                    destination_rule("alpha", "alpha-reviews-dr", "reviews"),
                    destination_rule("beta", "beta-checkout-dr", "checkout"),
                    destination_rule("gamma", "gamma-payments-dr", "payments"),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let request = MeshSliceRequest {
            namespace: "alpha".to_string(),
            enforce_sidecar_egress: true,
            ..MeshSliceRequest::default()
        };

        let filtered = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Single("alpha".to_string()),
        );
        let mesh = filtered.mesh.as_ref().expect("mesh should remain");

        assert!(
            mesh.services
                .iter()
                .any(|service| service.namespace == "beta" && service.name == "checkout"),
            "sidecar-admitted beta service must survive the prefilter"
        );
        assert!(
            !mesh
                .services
                .iter()
                .any(|service| service.namespace == "gamma"),
            "unadmitted gamma service must still be dropped before slicing"
        );
        assert!(
            mesh.destination_rules
                .iter()
                .any(|rule| rule.name == "beta-checkout-dr"),
            "sidecar-admitted beta DestinationRule must survive the prefilter"
        );
        assert!(
            !mesh
                .destination_rules
                .iter()
                .any(|rule| rule.name == "gamma-payments-dr"),
            "unadmitted gamma DestinationRule must still be dropped before slicing"
        );

        let mut alpha_only_scope = HashSet::new();
        alpha_only_scope.insert("alpha".to_string());
        let alpha_only = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Set(alpha_only_scope),
        );
        let alpha_only_mesh = alpha_only.mesh.as_ref().expect("mesh should remain");
        assert!(
            !alpha_only_mesh
                .services
                .iter()
                .any(|service| service.namespace == "beta"),
            "explicit Set scope must not serialize sidecar-visible namespaces outside FERRUM_CP_NAMESPACES"
        );
        assert!(
            !alpha_only_mesh
                .destination_rules
                .iter()
                .any(|rule| rule.namespace == "beta"),
            "explicit Set scope must not serialize sidecar-visible DestinationRules outside FERRUM_CP_NAMESPACES"
        );

        let slice = MeshSlice::from_gateway_config(&filtered, request);
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].namespace, "beta");
        assert_eq!(slice.services[0].name, "checkout");
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-checkout-dr");
    }

    #[test]
    fn multi_scope_filter_preserves_namespace_scoped_multicluster_config() {
        use crate::modes::mesh::config::{EastWestGateway, MultiClusterConfig, RemoteCluster};

        let mut set = HashSet::new();
        set.insert("ns-a".to_string());
        set.insert("ns-b".to_string());
        let config = GatewayConfig {
            trust_bundles: Some(Box::new(test_trust_bundles())),
            mesh: Some(Box::new(MeshConfig {
                trust_bundles: Some(test_trust_bundles()),
                multi_cluster: Some(MultiClusterConfig {
                    local_cluster: Some("local".to_string()),
                    federation_endpoint: Some("https://federation.example.test".to_string()),
                    remote_clusters: vec![RemoteCluster {
                        name: "remote".to_string(),
                        trust_domain: crate::identity::TrustDomain::new("remote.test")
                            .expect("test trust domain should be valid"),
                        network: Some("remote-net".to_string()),
                        control_plane_url: Some("https://remote-cp.example.test".to_string()),
                        federation_endpoint: Some("https://remote-fed.example.test".to_string()),
                        discovery_credential_ref: None,
                    }],
                    east_west_gateways: vec![
                        EastWestGateway {
                            name: "ewa".to_string(),
                            namespace: "ns-a".to_string(),
                            host: "ewa.example.test".to_string(),
                            port: 15443,
                            sni_hosts: vec!["*.ns-a.remote.test".to_string()],
                            trust_domain: Some(
                                crate::identity::TrustDomain::new("ns-a.test")
                                    .expect("test trust domain should be valid"),
                            ),
                            network: Some("net-a".to_string()),
                        },
                        EastWestGateway {
                            name: "ewb".to_string(),
                            namespace: "ns-b".to_string(),
                            host: "ewb.example.test".to_string(),
                            port: 15443,
                            sni_hosts: vec!["*.ns-b.remote.test".to_string()],
                            trust_domain: None,
                            network: Some("net-b".to_string()),
                        },
                    ],
                }),
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let request = MeshSliceRequest {
            namespace: "ns-a".to_string(),
            ..MeshSliceRequest::default()
        };

        let filtered = CpGrpcServer::filter_config_to_mesh_request_for_scope(
            &config,
            &request,
            &CpScope::Set(set),
        );
        let mesh = filtered.mesh.expect("mesh should remain");
        let multi_cluster = mesh
            .multi_cluster
            .expect("namespace-scoped multicluster metadata should remain");

        assert!(filtered.trust_bundles.is_none());
        assert!(mesh.trust_bundles.is_none());
        assert_eq!(multi_cluster.local_cluster.as_deref(), Some("local"));
        assert_eq!(multi_cluster.remote_clusters.len(), 1);
        assert_eq!(multi_cluster.east_west_gateways.len(), 1);
        assert_eq!(multi_cluster.east_west_gateways[0].namespace, "ns-a");
        assert_eq!(multi_cluster.east_west_gateways[0].name, "ewa");
    }

    #[test]
    fn namespace_filter_keeps_granted_cross_namespace_frontend_tls_secret_sources() {
        use crate::config::types::*;

        let config = GatewayConfig {
            version: CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            frontend_tls_cert_path: Some("k8s://ns-b/gateway-cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://ns-b/gateway-cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("ns-a".to_string()),
            ..Default::default()
        };

        let filtered = CpGrpcServer::filter_config_to_namespace(&config, "ns-a");
        assert_eq!(
            filtered.frontend_tls_cert_path.as_deref(),
            Some("k8s://ns-b/gateway-cert#tls.crt")
        );
        assert_eq!(
            filtered.frontend_tls_key_path.as_deref(),
            Some("k8s://ns-b/gateway-cert#tls.key")
        );
    }

    #[test]
    fn namespace_filter_projects_namespace_scoped_gateway_frontend_tls_sources() {
        use crate::config::types::*;

        let config = GatewayConfig {
            version: CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            frontend_tls_cert_path: Some("k8s://ns-a/gateway-cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://ns-a/gateway-cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("ns-a".to_string()),
            frontend_tls_namespace_sources: vec![
                FrontendTlsNamespaceSource {
                    namespace: "ns-a".to_string(),
                    cert_path: "k8s://ns-a/gateway-cert#tls.crt".to_string(),
                    key_path: "k8s://ns-a/gateway-cert#tls.key".to_string(),
                },
                FrontendTlsNamespaceSource {
                    namespace: "ns-b".to_string(),
                    cert_path: "k8s://ns-b/gateway-cert#tls.crt".to_string(),
                    key_path: "k8s://ns-b/gateway-cert#tls.key".to_string(),
                },
            ],
            ..Default::default()
        };

        let filtered = CpGrpcServer::filter_config_to_namespace(&config, "ns-b");
        assert_eq!(
            filtered.frontend_tls_cert_path.as_deref(),
            Some("k8s://ns-b/gateway-cert#tls.crt")
        );
        assert_eq!(
            filtered.frontend_tls_key_path.as_deref(),
            Some("k8s://ns-b/gateway-cert#tls.key")
        );
        assert_eq!(
            filtered.frontend_tls_source_namespace.as_deref(),
            Some("ns-b")
        );
        assert!(filtered.frontend_tls_namespace_sources.is_empty());
    }

    #[test]
    fn namespace_filter_strips_foreign_gateway_frontend_tls_sources() {
        use crate::config::types::*;

        let config = GatewayConfig {
            version: CURRENT_CONFIG_VERSION.to_string(),
            loaded_at: Utc::now(),
            frontend_tls_cert_path: Some("k8s://ns-b/gateway-cert#tls.crt".to_string()),
            frontend_tls_key_path: Some("k8s://ns-b/gateway-cert#tls.key".to_string()),
            frontend_tls_source_namespace: Some("ns-b".to_string()),
            ..Default::default()
        };

        let filtered = CpGrpcServer::filter_config_to_namespace(&config, "ns-a");
        assert_eq!(filtered.frontend_tls_cert_path, None);
        assert_eq!(filtered.frontend_tls_key_path, None);
        assert_eq!(filtered.frontend_tls_source_namespace, None);
    }
}
