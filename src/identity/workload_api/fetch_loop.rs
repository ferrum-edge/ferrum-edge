//! Long-lived background task that keeps a `Workload API` client connected
//! and hot-swaps each fresh [`SvidBundle`] into a shared [`ArcSwap`].
//!
//! Consumers (the `build_spiffe_inbound_config` / `build_spiffe_outbound_config`
//! TLS builders) read from the `ArcSwap` on every connection. The swap is
//! lock-free; readers see either the old bundle or the new one, never a
//! partial.
//!
//! The fetch loop also exposes a `wait_for_first_svid()` future so callers
//! can synchronise on "first SVID is ready" before binding listeners.

use arc_swap::ArcSwap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use super::client::WorkloadApiClient;
use crate::identity::{SpiffeId, SvidBundle};

/// Returns whether the installer already published the backend SVID rotation.
/// A trust-withdrawing `ProxyState` installer must do so inside its admission
/// fence; the fetch loop then skips its ordinary post-install bump.
type SvidInstaller = Arc<dyn Fn(SvidBundle) -> bool + Send + Sync + 'static>;

/// Handle returned by [`spawn_fetch_loop`]. Holds the shared `ArcSwap` and
/// the "first SVID arrived" notifier.
///
/// `revision_tx`, when set, is bumped on every `install` call after the first
/// so backend TLS pools subscribed to the matching `watch::Receiver` can drain
/// stale identity material. An installer that already published the same bump
/// inside a trust-withdrawal fence returns `true` to suppress a duplicate.
/// Production callers pass a clone of `ProxyState.backend_svid_rotation_tx`;
/// tests can leave it unset.
#[derive(Clone)]
pub struct SvidFetchHandle {
    pub current: Arc<ArcSwap<Option<SvidBundle>>>,
    first_ready: Arc<Notify>,
    has_first: Arc<std::sync::atomic::AtomicBool>,
    revision_tx: Arc<OnceLock<watch::Sender<u64>>>,
    installer: Arc<OnceLock<SvidInstaller>>,
}

impl SvidFetchHandle {
    pub fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            revision_tx: Arc::new(OnceLock::new()),
            installer: Arc::new(OnceLock::new()),
        }
    }

    /// Build a fetch handle around an existing SVID slot.
    ///
    /// Mesh mode uses this to let the SPIRE Workload API producer feed the
    /// `ProxyState.gateway_svid_bundle` slot that outbound HBONE/mTLS pools and
    /// inbound SVID presentation already consume.
    pub fn from_slot(current: Arc<ArcSwap<Option<SvidBundle>>>) -> Self {
        let has_first = current.load().is_some();
        Self {
            current,
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(std::sync::atomic::AtomicBool::new(has_first)),
            revision_tx: Arc::new(OnceLock::new()),
            installer: Arc::new(OnceLock::new()),
        }
    }

    /// Wire this handle to the gateway's backend SVID rotation channel.
    ///
    /// Once attached, every `install` after the first publishes a fresh
    /// generation on the channel — consumers (the backend pool drain task)
    /// observe the rotation and invalidate stale TLS configs.
    pub fn with_revision_tx(self, revision_tx: watch::Sender<u64>) -> Self {
        if self.revision_tx.set(revision_tx).is_err() {
            warn!("SVID fetch handle revision channel already configured; keeping existing sender");
        }
        self
    }

    /// Wire a cold-path installer that owns writes to `current`.
    ///
    /// Mesh mode uses this to publish SPIRE rotations through
    /// `ProxyState::install_gateway_runtime_svid_bundle`, preserving CP/slice
    /// trust overlays instead of overwriting the shared slot with the raw SPIRE
    /// bundle. The callback returns whether it already published the backend
    /// rotation as part of a fenced trust withdrawal.
    pub fn with_installer<F>(self, installer: F) -> Self
    where
        F: Fn(SvidBundle) -> bool + Send + Sync + 'static,
    {
        if self.installer.set(Arc::new(installer)).is_err() {
            warn!("SVID fetch handle installer already configured; keeping existing installer");
        }
        self
    }

    /// Snapshot of the current SVID bundle. Returns `None` until the first
    /// bundle arrives.
    pub fn snapshot(&self) -> Arc<Option<SvidBundle>> {
        self.current.load_full()
    }

    /// Resolves once the first SVID has been observed. If a bundle is
    /// already present, resolves immediately.
    ///
    /// Race-free against a concurrent [`install`]: we register as a waiter
    /// (via `Notified::enable`) BEFORE checking `has_first`. `notify_waiters()`
    /// does not stash a permit — a notification fired between the load and
    /// the await would otherwise be lost and this future would block
    /// forever. The order here is:
    ///
    /// 1. Build the `Notified` future and `enable()` it (registers as a
    ///    waiter without polling).
    /// 2. Load the flag. If already set, drop the waiter and return.
    /// 3. Otherwise, await — guaranteed to wake on the next `install()`.
    ///
    /// [`install`]: SvidFetchHandle::install
    pub async fn wait_for_first_svid(&self) {
        let notified = self.first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.has_first.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        notified.await;
    }

    fn install(&self, bundle: SvidBundle, metrics_source: FetchLoopMetricsSource) {
        record_fetch_bundle_metrics(&bundle, metrics_source);
        let rotation_already_published = if let Some(installer) = self.installer.get() {
            installer(bundle)
        } else {
            self.current.store(Arc::new(Some(bundle)));
            false
        };
        let was_first = self
            .has_first
            .swap(true, std::sync::atomic::Ordering::AcqRel);
        if !was_first {
            self.first_ready.notify_waiters();
        } else if !rotation_already_published && let Some(tx) = self.revision_tx.get() {
            // Skip bumping on the very first install: the gateway starts at
            // generation 0 with no traffic in flight, so there is nothing to
            // drain. Every later install reflects a rotation.
            tx.send_modify(|revision| *revision = revision.saturating_add(1));
        }
    }
}

impl Default for SvidFetchHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded telemetry identity for a Workload API fetch loop.
///
/// Keeping this as an enum prevents a caller-controlled metric label from
/// creating unbounded Prometheus cardinality. The mesh SPIRE producer uses
/// [`Self::SpireAgent`]; generic Workload API consumers retain the historical
/// `workload_api` label.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FetchLoopMetricsSource {
    #[default]
    WorkloadApi,
    SpireAgent,
}

impl FetchLoopMetricsSource {
    fn source_label(self) -> &'static str {
        match self {
            Self::WorkloadApi => "workload_api",
            Self::SpireAgent => "spire_agent",
        }
    }

    fn set_ca_health(self, healthy: bool) {
        if matches!(self, Self::SpireAgent) {
            crate::plugins::mesh::prometheus_helpers::set_mesh_ca_health("spire_agent", healthy);
        }
    }
}

/// Configuration for the fetch loop.
#[derive(Debug, Clone)]
pub struct FetchLoopConfig {
    /// Path to the SPIRE agent socket.
    pub socket_path: String,
    /// Optional exact SPIFFE ID to select from multi-SVID Workload API responses.
    pub expected_spiffe_id: Option<SpiffeId>,
    /// Backoff between connection attempts when the agent is unreachable.
    pub reconnect_backoff: Duration,
    /// Maximum backoff cap. Backoff doubles up to this value.
    pub max_reconnect_backoff: Duration,
    /// Bounded source label and optional CA-health identity for telemetry.
    pub metrics_source: FetchLoopMetricsSource,
}

impl Default for FetchLoopConfig {
    fn default() -> Self {
        Self {
            socket_path: crate::identity::ca::spire::DEFAULT_SPIRE_AGENT_SOCKET.to_string(),
            expected_spiffe_id: None,
            reconnect_backoff: Duration::from_secs(1),
            max_reconnect_backoff: Duration::from_secs(30),
            metrics_source: FetchLoopMetricsSource::default(),
        }
    }
}

/// Spawn the fetch loop and return a handle. The task runs until cancelled
/// (drop the returned `JoinHandle`).
pub fn spawn_fetch_loop(config: FetchLoopConfig) -> (SvidFetchHandle, tokio::task::JoinHandle<()>) {
    let handle = SvidFetchHandle::new();
    let join = spawn_fetch_loop_with_handle(config, handle.clone());
    (handle, join)
}

/// Spawn a fetch loop that writes into a caller-supplied handle.
pub fn spawn_fetch_loop_with_handle(
    config: FetchLoopConfig,
    handle: SvidFetchHandle,
) -> tokio::task::JoinHandle<()> {
    let task_handle = handle.clone();
    tokio::spawn(async move { fetch_loop_main(config, task_handle).await })
}

async fn fetch_loop_main(config: FetchLoopConfig, handle: SvidFetchHandle) {
    let mut backoff = config.reconnect_backoff;
    // Materialize the SPIRE health series before the first connection
    // attempt, so an initial outage is visible while mesh startup waits for
    // its first SVID and before any successful sample has existed.
    config.metrics_source.set_ca_health(false);
    loop {
        match WorkloadApiClient::connect(&config.socket_path).await {
            Ok(mut client) => match client
                .fetch_x509_svid_stream(config.expected_spiffe_id.clone())
                .await
            {
                Ok((mut stream, _first_signal)) => {
                    info!(socket = %config.socket_path, "SVID fetch stream established");
                    backoff = config.reconnect_backoff;
                    let mut failure_recorded = false;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bundle) => {
                                debug!(
                                    spiffe_id = %bundle.spiffe_id,
                                    "received fresh SVID from Workload API"
                                );
                                handle.install(bundle, config.metrics_source);
                                config.metrics_source.set_ca_health(true);
                            }
                            Err(e) => {
                                record_workload_api_rotation_failure(
                                    &handle,
                                    config.metrics_source,
                                );
                                failure_recorded = true;
                                warn!(error = %e, "SVID fetch stream error — reconnecting");
                                break;
                            }
                        }
                    }
                    if !failure_recorded {
                        record_workload_api_rotation_failure(&handle, config.metrics_source);
                        warn!("SVID fetch stream ended — reconnecting");
                    }
                }
                Err(e) => {
                    record_workload_api_rotation_failure(&handle, config.metrics_source);
                    error!(error = %e, "Workload API stream RPC failed");
                }
            },
            Err(e) => {
                record_workload_api_rotation_failure(&handle, config.metrics_source);
                error!(error = %e, "failed to connect to Workload API agent");
            }
        }

        sleep(backoff).await;
        backoff = (backoff * 2).min(config.max_reconnect_backoff);
    }
}

fn record_workload_api_rotation_failure(
    handle: &SvidFetchHandle,
    metrics_source: FetchLoopMetricsSource,
) {
    metrics_source.set_ca_health(false);
    let spiffe_id = handle
        .snapshot()
        .as_ref()
        .as_ref()
        .map(|bundle| bundle.spiffe_id.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    crate::plugins::mesh::prometheus_helpers::increment_mesh_cert_rotation_failure(
        &spiffe_id,
        metrics_source.source_label(),
    );
}

fn record_fetch_bundle_metrics(bundle: &SvidBundle, metrics_source: FetchLoopMetricsSource) {
    let source = metrics_source.source_label();
    crate::plugins::mesh::prometheus_helpers::record_mesh_cert_expiry_seconds(
        &bundle.spiffe_id,
        source,
        time_until_expiry(bundle).as_secs(),
    );
    crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle_roots(
        bundle.trust_bundles.local.trust_domain.as_str(),
        source,
        bundle.trust_bundles.local.x509_authorities.as_slice(),
    );
    for federated in bundle.trust_bundles.federated.values() {
        crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle_roots(
            federated.trust_domain.as_str(),
            source,
            federated.x509_authorities.as_slice(),
        );
    }
}

/// Convenience for unit tests / call sites that want to install an SVID
/// without round-tripping through the agent. Not intended for production
/// flows.
pub fn install_test_bundle(handle: &SvidFetchHandle, bundle: SvidBundle) {
    handle.install(bundle, FetchLoopMetricsSource::WorkloadApi);
}

/// Convert a bundle's notAfter into a duration-from-now (used by the fetch
/// loop's bundle metrics). Returns `Duration::ZERO` for already-expired
/// bundles.
pub(crate) fn time_until_expiry(bundle: &SvidBundle) -> Duration {
    use chrono::Utc;
    use x509_parser::prelude::*;
    let leaf = match bundle.cert_chain_der.first() {
        Some(d) => d,
        None => return Duration::ZERO,
    };
    let parsed = match X509Certificate::from_der(leaf) {
        Ok((_, c)) => c,
        Err(_) => return Duration::ZERO,
    };
    let not_after_ts = parsed.validity().not_after.timestamp();
    let now_ts = Utc::now().timestamp();
    if not_after_ts <= now_ts {
        Duration::ZERO
    } else {
        Duration::from_secs((not_after_ts - now_ts) as u64)
    }
}
