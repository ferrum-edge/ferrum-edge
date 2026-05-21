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
//! DP only receives deltas for its own namespace. JWT tokens may carry an
//! `ns` claim (single string or array) that pins which namespaces the bearer
//! is authorised to subscribe to. When `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM`
//! is `true`, tokens without an `ns` claim are rejected entirely; otherwise
//! the CP falls back to the scope-only check for back-compat. See
//! `docs/cp_namespace_tenancy.md` for the operator guide.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::auth::{AllowedNamespaces, verify_grpc_jwt_metadata_with_claims};
use super::proto::config_sync_server::{ConfigSync, ConfigSyncServer};
use super::proto::{ConfigUpdate, FullConfigRequest, FullConfigResponse, SubscribeRequest};
use crate::FERRUM_VERSION;
use crate::config::types::{GatewayConfig, default_namespace};

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
    /// scope check is a no-op; only the per-token JWT `ns` claim (when
    /// `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`) bounds what each DP sees.
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
    jwt_secret: String,
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
    /// requested namespace must be in it. When `false` (default), tokens
    /// without an `ns` claim fall back to the scope-only check.
    require_ns_claim: bool,
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
    pub fn builder(config: Arc<ArcSwap<GatewayConfig>>, jwt_secret: String) -> CpGrpcServerBuilder {
        CpGrpcServerBuilder {
            config,
            jwt_secret,
            channel_capacity: 128,
            registry: None,
            expected_issuer: DEFAULT_CP_DP_JWT_ISSUER.to_string(),
            scope: CpScope::Single(default_namespace()),
            require_ns_claim: false,
        }
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
        // Reject empty DP namespace strings — they cannot match either the
        // CP scope or any plausible claim.
        if dp_namespace.is_empty() {
            return Err(Status::failed_precondition(
                "DP did not advertise a namespace in the Subscribe request",
            ));
        }

        // 1) JWT claim presence policy.
        if self.require_ns_claim && !allowed.is_present() {
            return Err(Status::permission_denied(
                "FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true on this CP: the JWT must \
                 include an `ns` claim listing the namespaces this DP may subscribe to",
            ));
        }

        // 2) JWT claim authorisation (if present).
        if allowed.is_present() && !allowed.allows(dp_namespace) {
            return Err(Status::permission_denied(format!(
                "JWT `ns` claim does not authorise namespace '{dp_namespace}'; \
                 the bearer can only subscribe to the namespaces listed in its token"
            )));
        }

        // 3) CP scope authorisation.
        if !self.scope.includes(dp_namespace) {
            return Err(Status::failed_precondition(format!(
                "CP scope ({}) does not include DP namespace '{dp_namespace}'. \
                 Add it to FERRUM_CP_NAMESPACES (or use `*` for cluster-wide).",
                self.scope.describe()
            )));
        }

        Ok(self.broadcasts.sender_for(dp_namespace))
    }

    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<AllowedNamespaces, Status> {
        verify_grpc_jwt_metadata_with_claims(metadata, &self.jwt_secret, &self.expected_issuer)
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
    /// Compatibility rule: major and minor versions must match. Patch-level
    /// differences are always allowed (bug-fix releases don't change the
    /// config schema or gRPC wire format).
    #[allow(clippy::result_large_err)]
    pub(crate) fn check_version_compatibility(dp_version: &str) -> Result<(), Status> {
        // Empty version means old DP that predates the version field — reject.
        if dp_version.is_empty() {
            return Err(Status::failed_precondition(format!(
                "DP did not report its version. CP is running Ferrum Edge v{}. \
                 Upgrade the DP to a version that supports version negotiation.",
                FERRUM_VERSION
            )));
        }

        let cp_parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        let dp_parts: Vec<&str> = dp_version.split('.').collect();

        if cp_parts.len() < 2 || dp_parts.len() < 2 {
            warn!(
                "Unable to parse version for compatibility check (CP={}, DP={}), allowing connection",
                FERRUM_VERSION, dp_version
            );
            return Ok(());
        }

        if cp_parts[0] != dp_parts[0] || cp_parts[1] != dp_parts[1] {
            return Err(Status::failed_precondition(format!(
                "Version mismatch: CP is v{} but DP is v{}. \
                 Major and minor versions must match. \
                 Upgrade the CP first, then upgrade DPs to the same major.minor version.",
                FERRUM_VERSION, dp_version
            )));
        }

        if cp_parts.get(2) != dp_parts.get(2) {
            info!(
                "DP v{} connected to CP v{} (patch difference OK)",
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
    fn filter_config_to_namespace(config: &GatewayConfig, namespace: &str) -> GatewayConfig {
        let mut filtered = config.clone();
        filtered.proxies.retain(|p| p.namespace == namespace);
        filtered.consumers.retain(|c| c.namespace == namespace);
        filtered
            .plugin_configs
            .retain(|pc| pc.namespace == namespace);
        filtered.upstreams.retain(|u| u.namespace == namespace);
        if let Some(mesh) = filtered.mesh.as_mut() {
            mesh.retain_namespace(namespace);
        }
        filtered
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
    ) {
        let Some(tx) = broadcasts.try_sender_for(namespace) else {
            return;
        };
        let filtered = Self::filter_config_to_namespace(config, namespace);
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
    ) {
        let Some(tx) = broadcasts.try_sender_for(namespace) else {
            return;
        };
        Self::broadcast_delta_with_trust_bundles(&tx, result, version, trust_bundles);
        registry.touch_namespace(namespace);
    }

    /// Broadcast a full config snapshot to all connected DPs.
    ///
    /// Back-compat helper for single-namespace deployments. Multi-namespace
    /// callers must use [`Self::broadcast_namespace_update`] so each DP only
    /// receives its own namespace.
    pub fn broadcast_update_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        config: &GatewayConfig,
        registry: &DpNodeRegistry,
    ) {
        Self::broadcast_update(tx, config);
        registry.touch_all();
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
    jwt_secret: String,
    channel_capacity: usize,
    registry: Option<Arc<DpNodeRegistry>>,
    expected_issuer: String,
    scope: CpScope,
    require_ns_claim: bool,
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

    pub fn scope(mut self, scope: CpScope) -> Self {
        self.scope = scope;
        self
    }

    #[allow(dead_code)]
    pub fn require_ns_claim(mut self, require: bool) -> Self {
        self.require_ns_claim = require;
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
                jwt_secret: self.jwt_secret,
                expected_issuer: self.expected_issuer,
                broadcasts,
                registry,
                scope: self.scope,
                require_ns_claim: self.require_ns_claim,
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
        let allowed = self.verify_jwt_metadata(request.metadata())?;

        let inner = request.into_inner();
        let node_id = inner.node_id;
        let dp_version = inner.ferrum_version;
        let dp_namespace = inner.namespace;

        // Reject DPs with incompatible versions before streaming any config.
        Self::check_version_compatibility(&dp_version)?;
        // Reject DPs whose namespace fails the JWT `ns` claim or CP scope
        // check. The returned sender is the per-namespace broadcast channel
        // — DPs in different namespaces are guaranteed to receive only their
        // own slice.
        let namespace_tx = self.authorise_namespace(&allowed, &dp_namespace)?;

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
        let filtered = Self::filter_config_to_namespace(config.as_ref(), &dp_namespace);
        let config_json = Self::config_json_for_dp(&filtered).map_err(|e| {
            error!("Failed to serialize config in subscribe: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;
        let trust_bundles_json = Self::trust_bundles_json(config.trust_bundles.as_deref())
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
        };

        let config_for_recovery = self.config.clone();
        let recovery_namespace = dp_namespace.clone();
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
                let filtered = Self::filter_config_to_namespace(current.as_ref(), &recovery_namespace);
                match Self::config_json_for_dp(&filtered) {
                    Ok(config_json) => {
                        let trust_bundles_json = match Self::trust_bundles_json(
                            current.trust_bundles.as_deref(),
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
                        }))
                    }
                    Err(e) => {
                        error!("Failed to serialize recovery snapshot: {}", e);
                        None
                    }
                }
            }
        });

        // Prepend initial config, then wrap in TrackedStream so the DP is
        // automatically de-registered when the gRPC stream is dropped.
        let initial_stream = tokio_stream::once(Ok(initial));
        let combined = initial_stream.chain(stream);
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
        let allowed = self.verify_jwt_metadata(request.metadata())?;

        let req = request.get_ref();
        let dp_version = &req.ferrum_version;
        Self::check_version_compatibility(dp_version)?;
        // Same cross-namespace guard as `Subscribe` — without it
        // `GetFullConfig` would leak the wrong namespace's snapshot. We
        // discard the returned sender; `GetFullConfig` is unary.
        let _ = self.authorise_namespace(&allowed, &req.namespace)?;

        info!(
            "DP '{}' (v{}) requested full config (namespace='{}')",
            req.node_id, dp_version, req.namespace
        );

        let config = self.config.load_full();
        let filtered = Self::filter_config_to_namespace(config.as_ref(), &req.namespace);
        let config_json = Self::config_json_for_dp(&filtered).map_err(|e| {
            error!("Failed to serialize config in get_full_config: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;
        let trust_bundles_json = Self::trust_bundles_json(config.trust_bundles.as_deref())
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
    fn version_check_unparseable_version_allowed() {
        // Single-component version is unparseable (< 2 parts), so it's allowed
        assert!(CpGrpcServer::check_version_compatibility("1").is_ok());
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
    fn set_scope_accepts_listed_namespaces() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let server = cp_with_scope(CpScope::Set(set), false);
        assert!(
            server
                .authorise_namespace(&AllowedNamespaces::empty(), "prod")
                .is_ok()
        );
        assert!(
            server
                .authorise_namespace(&AllowedNamespaces::empty(), "staging")
                .is_ok()
        );
    }

    #[test]
    fn set_scope_rejects_unlisted_namespace() {
        let mut set = HashSet::new();
        set.insert("prod".to_string());
        set.insert("staging".to_string());
        let server = cp_with_scope(CpScope::Set(set), false);
        let err = server
            .authorise_namespace(&AllowedNamespaces::empty(), "dev")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("dev"));
    }

    // ── All scope: any namespace accepted, claim still respected ──────────

    #[test]
    fn all_scope_accepts_any_namespace_without_claim() {
        let server = cp_with_scope(CpScope::All, false);
        assert!(
            server
                .authorise_namespace(&AllowedNamespaces::empty(), "any-ns")
                .is_ok()
        );
    }

    // ── JWT claim authorisation ────────────────────────────────────────────

    #[test]
    fn claim_present_must_authorise_requested_namespace() {
        let mut set = HashSet::new();
        set.insert("staging".to_string());
        let allowed = AllowedNamespaces(Some(set));
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
        let allowed = AllowedNamespaces(Some(set));
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
        let allowed = AllowedNamespaces(Some(set));
        let server = cp_with_scope(CpScope::Single("prod".to_string()), true);
        assert!(server.authorise_namespace(&allowed, "prod").is_ok());
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
}
