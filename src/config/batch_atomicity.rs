//! Graph-level all-or-nothing semantics for `POST /batch`.
//!
//! `POST /batch` installs a *validated dependency graph*: consumers and
//! upstreams, then proxies, then plugin configs, then the proxy↔plugin
//! associations that tie them together. Persisting each family (or each bounded
//! chunk inside a family) in its own transaction meant a later failure left the
//! earlier families durable — not the configuration the caller validated and
//! intended to install, and not idempotently retryable (issue #2401).
//!
//! This module carries the shared vocabulary for the atomic replacement:
//!
//! - [`AtomicBatchGraph`] — the whole submitted graph plus the namespace
//!   config-admission lease that authorized it.
//! - [`AtomicBatchCounts`] — per-family counts, only ever reported for a graph
//!   that committed in full.
//! - [`AtomicBatchUnsupported`] — a backend deployment that cannot provide the
//!   guarantee (standalone MongoDB). Reported *before* any mutation.
//! - [`BatchAdmissionLeaseLost`] — the authorizing lease was no longer held when
//!   the transaction was ready to commit, so the transaction is aborted rather
//!   than compensated after the fact.
//! - [`AtomicBatchFault`] — a deterministic, test-installed failure point at
//!   every dependency phase and after any chunk boundary, so the durability
//!   claim is actually exercised rather than asserted.
//!
//! Backends implement the guarantee with one transaction/session spanning every
//! phase and every chunk. Chunking survives only to bound single statements and
//! driver payloads; a chunk boundary no longer commits anything.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::config::types::{Consumer, PluginConfig, Proxy, Upstream};

/// Stable admin-facing message for a batch the configured backend deployment
/// cannot persist all-or-nothing. Deployment topology details stay in the
/// chained error and the operator docs.
pub const ATOMIC_BATCH_UNSUPPORTED_MESSAGE: &str =
    "Atomic batch configuration is not supported by the configured database deployment";

/// Stable admin-facing message for a batch whose authorizing namespace
/// config-admission lease lapsed before its transaction could commit.
pub const BATCH_ADMISSION_LEASE_LOST_MESSAGE: &str =
    "Namespace config admission was lost before the batch could commit; nothing was applied";

/// The configured backend cannot persist a whole batch graph in a single
/// transaction.
///
/// This is a deployment property, not a property of the submitted payload:
/// standalone MongoDB has no multi-document transactions, so the only way to
/// keep the documented guarantee is to refuse the request before it mutates
/// anything. Callers surface [`ATOMIC_BATCH_UNSUPPORTED_MESSAGE`] plus the
/// remediation detail.
#[derive(Debug, Clone)]
pub struct AtomicBatchUnsupported {
    detail: String,
}

impl AtomicBatchUnsupported {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Operator-actionable remediation. Safe to return to an authenticated
    /// admin caller: it names configuration, never schema or driver internals.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for AtomicBatchUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{ATOMIC_BATCH_UNSUPPORTED_MESSAGE}: {}", self.detail)
    }
}

impl std::error::Error for AtomicBatchUnsupported {}

/// Borrow the typed refusal from anywhere in an error chain so responders
/// render *its* message rather than driver context wrapped above it.
pub fn atomic_batch_unsupported(error: &anyhow::Error) -> Option<&AtomicBatchUnsupported> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<AtomicBatchUnsupported>())
}

/// The namespace config-admission lease that authorized a batch was no longer
/// held by this request when its transaction was ready to commit.
///
/// Backends verify the lease inside the persisting transaction, so this always
/// aborts before commit: no resources become durable and there is nothing to
/// compensate. A retry re-acquires the lease and re-validates from scratch.
#[derive(Debug)]
pub struct BatchAdmissionLeaseLost;

impl std::fmt::Display for BatchAdmissionLeaseLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(BATCH_ADMISSION_LEASE_LOST_MESSAGE)
    }
}

impl std::error::Error for BatchAdmissionLeaseLost {}

pub fn is_batch_admission_lease_lost(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<BatchAdmissionLeaseLost>())
}

/// Identity of the namespace config-admission lease a batch holds.
///
/// Backends re-check this *inside* the transaction that persists the graph.
/// Because every namespace resource writer serializes behind the same
/// datastore admission row/lease, a matching owner and generation immediately
/// before commit proves no other writer interleaved with the graph this
/// request validated.
#[derive(Debug, Clone, Copy)]
pub struct NamespaceConfigAdmissionLeaseRef<'a> {
    pub owner: &'a str,
    pub generation: u64,
}

/// One admission lease a caller holds, together with the admission key it was
/// taken on.
///
/// `POST /batch` only ever needs the graph's own namespace, so it carries a
/// bare [`NamespaceConfigAdmissionLeaseRef`]. A namespace **registry** mutation
/// holds several leases at once — the global
/// [`crate::config::namespace_registry::NAMESPACE_REGISTRY_ADMISSION_KEY`] plus
/// the source and (for a rename) target names — and the backend must re-verify
/// every one of them inside the committing transaction, so each lease has to
/// travel with the key it belongs to.
#[derive(Debug, Clone, Copy)]
pub struct NamespaceAdmissionLeaseHold<'a> {
    /// The `config_admission_locks` key: a namespace name, or the global
    /// registry key.
    pub key: &'a str,
    pub lease: NamespaceConfigAdmissionLeaseRef<'a>,
}

/// One validated batch graph, persisted all-or-nothing.
///
/// Field order matches the dependency order backends must write in: consumers
/// and upstreams have no dependencies, proxies may reference an upstream, and
/// plugin configs reference proxies. Proxy↔plugin associations are attached
/// last, inside the same transaction.
pub struct AtomicBatchGraph<'a> {
    pub namespace: &'a str,
    pub consumers: &'a [Consumer],
    pub upstreams: &'a [Upstream],
    pub proxies: &'a [Proxy],
    pub plugin_configs: &'a [PluginConfig],
    /// `None` only for callers that already hold an equivalent exclusive
    /// datastore guard for the namespace.
    pub admission_lease: Option<NamespaceConfigAdmissionLeaseRef<'a>>,
}

impl AtomicBatchGraph<'_> {
    pub fn is_empty(&self) -> bool {
        self.consumers.is_empty()
            && self.upstreams.is_empty()
            && self.proxies.is_empty()
            && self.plugin_configs.is_empty()
    }

    /// Namespaces carried by the graph's resources, sorted and deduplicated.
    ///
    /// Admin admission normalizes every resource onto the request namespace, so
    /// this is normally just that namespace. Backends still lock the union so a
    /// caller that hands over a cross-namespace payload cannot slip a write
    /// past another namespace's admission row.
    pub fn admission_namespaces(&self) -> Vec<&str> {
        let mut namespaces: Vec<&str> = vec![self.namespace];
        namespaces.extend(self.consumers.iter().map(|c| c.namespace.as_str()));
        namespaces.extend(self.upstreams.iter().map(|u| u.namespace.as_str()));
        namespaces.extend(self.proxies.iter().map(|p| p.namespace.as_str()));
        namespaces.extend(self.plugin_configs.iter().map(|p| p.namespace.as_str()));
        namespaces.sort_unstable();
        namespaces.dedup();
        namespaces
    }

    /// True when post-write namespace admission must re-read the policy
    /// graph after this graph is inserted.
    ///
    /// HTTP-only consumer/proxy chunks with empty plugin associations cannot
    /// change mTLS SAN uniqueness or TCP-throttle attachments. Skipping the
    /// O(namespace) candidate reload keeps per-chunk persist cost bounded by
    /// the chunk plus point uniqueness lookups (issue #4234).
    pub fn requires_post_write_policy_admission(&self) -> bool {
        if self
            .consumers
            .iter()
            .any(|consumer| consumer.has_credential("mtls_auth"))
        {
            return true;
        }
        if self.plugin_configs.iter().any(|plugin| {
            plugin.plugin_name == "mtls_auth" || plugin.plugin_name == "tcp_connection_throttle"
        }) {
            return true;
        }
        self.proxies.iter().any(|proxy| !proxy.plugins.is_empty())
    }
}

/// Per-family counts for a graph that committed in full.
///
/// Partial counts are never reported: a failed atomic batch returns an error
/// with no counts at all, because no resource from the request is durable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AtomicBatchCounts {
    pub consumers: usize,
    pub upstreams: usize,
    pub proxies: usize,
    pub plugin_configs: usize,
}

impl AtomicBatchCounts {
    pub fn any(&self) -> bool {
        self.consumers > 0 || self.upstreams > 0 || self.proxies > 0 || self.plugin_configs > 0
    }
}

/// Dependency phases of one atomic batch graph write, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicBatchPhase {
    Consumers,
    Upstreams,
    Proxies,
    PluginConfigs,
    ProxyPluginAssociations,
    /// Post-write, in-transaction re-validation of the merged namespace graph.
    AdmissionRevalidation,
    /// Immediately before the single commit.
    Commit,
}

impl AtomicBatchPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Consumers => "consumers",
            Self::Upstreams => "upstreams",
            Self::Proxies => "proxies",
            Self::PluginConfigs => "plugin_configs",
            Self::ProxyPluginAssociations => "proxy_plugin_associations",
            Self::AdmissionRevalidation => "admission_revalidation",
            Self::Commit => "commit",
        }
    }
}

/// A deterministic, test-installed failure inside an atomic batch graph write.
///
/// Fault injection is the only way to prove the durability claim end to end:
/// a duplicate key can only fail where the duplicate is, while these faults
/// reach every phase and every chunk boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicBatchFault {
    pub phase: AtomicBatchPhase,
    /// Trip after exactly this many completed chunks within `phase`. `0` trips
    /// before the phase writes anything; `1` trips after the first chunk
    /// boundary. Phases without chunks (`AdmissionRevalidation`, `Commit`) only
    /// ever trip at `0`.
    pub after_chunks: usize,
}

impl AtomicBatchFault {
    pub fn new(phase: AtomicBatchPhase, after_chunks: usize) -> Self {
        Self {
            phase,
            after_chunks,
        }
    }

    pub fn trips(&self, phase: AtomicBatchPhase, completed_chunks: usize) -> bool {
        self.phase == phase && self.after_chunks == completed_chunks
    }

    pub fn error(&self) -> anyhow::Error {
        anyhow::anyhow!(
            "injected atomic batch fault at phase `{}` after {} chunk(s)",
            self.phase.as_str(),
            self.after_chunks
        )
    }
}

/// An application-level reason to abort an atomic batch transaction.
///
/// MongoDB's convenient-transaction runner only aborts when the callback
/// returns an error, and it must never see a silently-handled failure. These
/// reasons therefore travel as a `mongodb::error::Error::custom` payload and are
/// unwrapped back into typed errors once the transaction has aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicBatchAbort {
    AdmissionLeaseLost,
    InjectedFault(AtomicBatchFault),
}

/// Per-namespace test overrides. Empty in production, and gated behind one
/// relaxed atomic load so batch writes never touch the map or its lock.
struct AtomicBatchTestOverrides {
    faults: HashMap<String, AtomicBatchFault>,
    chunk_sizes: HashMap<String, usize>,
}

static ANY_TEST_OVERRIDE: AtomicBool = AtomicBool::new(false);
static TEST_OVERRIDES: OnceLock<Mutex<AtomicBatchTestOverrides>> = OnceLock::new();

/// Lock the override map, recovering from a poisoned lock: a panicking test
/// must not wedge every later batch write in the same process.
fn test_overrides() -> MutexGuard<'static, AtomicBatchTestOverrides> {
    TEST_OVERRIDES
        .get_or_init(|| {
            Mutex::new(AtomicBatchTestOverrides {
                faults: HashMap::new(),
                chunk_sizes: HashMap::new(),
            })
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Install (or clear, with `None`) a deterministic fault for `namespace`.
///
/// Keyed per namespace so tests sharing one process — integration tests run a
/// single process per shard — cannot perturb each other.
pub fn set_atomic_batch_fault(namespace: &str, fault: Option<AtomicBatchFault>) {
    let mut overrides = test_overrides();
    match fault {
        Some(fault) => {
            overrides.faults.insert(namespace.to_string(), fault);
        }
        None => {
            overrides.faults.remove(namespace);
        }
    }
    let any = !overrides.faults.is_empty() || !overrides.chunk_sizes.is_empty();
    ANY_TEST_OVERRIDE.store(any, Ordering::Release);
}

/// Shrink the per-chunk write size for `namespace` so a small fixture can
/// still cross a chunk boundary. `None` restores the backend default.
pub fn set_atomic_batch_chunk_size(namespace: &str, chunk_size: Option<usize>) {
    let mut overrides = test_overrides();
    match chunk_size.filter(|size| *size > 0) {
        Some(size) => {
            overrides.chunk_sizes.insert(namespace.to_string(), size);
        }
        None => {
            overrides.chunk_sizes.remove(namespace);
        }
    }
    let any = !overrides.faults.is_empty() || !overrides.chunk_sizes.is_empty();
    ANY_TEST_OVERRIDE.store(any, Ordering::Release);
}

/// Resolve both overrides for one batch. Called once per batch write, never per
/// record: production takes a single relaxed load and returns immediately.
pub fn atomic_batch_test_overrides(namespace: &str) -> (Option<AtomicBatchFault>, Option<usize>) {
    if !ANY_TEST_OVERRIDE.load(Ordering::Acquire) {
        return (None, None);
    }
    let overrides = test_overrides();
    let fault = overrides.faults.get(namespace).copied();
    let chunk_size = overrides.chunk_sizes.get(namespace).copied();
    (fault, chunk_size)
}

/// Pause a conditional restore after its fenced snapshot comparison, before
/// mutation. Hosted store regressions can cross the real keeper interval and
/// lease TTL without relying on the size or speed of an imported graph.
#[derive(Default)]
pub struct ConditionalRestoreTestPause {
    pub entered: tokio::sync::Notify,
    pub resume: tokio::sync::Notify,
}

static ANY_RESTORE_PAUSE: AtomicBool = AtomicBool::new(false);
static RESTORE_PAUSES: OnceLock<Mutex<HashMap<String, Arc<ConditionalRestoreTestPause>>>> =
    OnceLock::new();

pub fn set_conditional_restore_pause(
    namespace: &str,
    pause: Option<Arc<ConditionalRestoreTestPause>>,
) {
    let mut pauses = RESTORE_PAUSES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pause) = pause {
        pauses.insert(namespace.to_string(), pause);
    } else {
        pauses.remove(namespace);
    }
    ANY_RESTORE_PAUSE.store(!pauses.is_empty(), Ordering::Release);
}

pub(crate) async fn pause_conditional_restore_for_test(namespace: &str) {
    if !ANY_RESTORE_PAUSE.load(Ordering::Acquire) {
        return;
    }
    let pause = RESTORE_PAUSES.get().and_then(|pauses| {
        pauses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(namespace)
            .cloned()
    });
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.resume.notified().await;
    }
}
