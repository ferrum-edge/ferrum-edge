//! API Chargeback Plugin
//!
//! Tracks per-consumer API usage charges across three pricing dimensions:
//!
//! 1. **Per-call pricing** keyed by billable status code (`pricing_tiers`) —
//!    ordinary HTTP uses its wire status, while native gRPC and translated
//!    gRPC-Web use the final terminal status mapped to an effective HTTP status.
//! 2. **Bandwidth pricing** keyed by direction (`bandwidth_pricing`) — applied
//!    to both HTTP-family transactions and stream transactions (TCP, TCP+TLS,
//!    UDP, DTLS) using the gateway-perspective `bytes_sent` / `bytes_received`
//!    counters that the unified [`TransactionSummary`] /
//!    [`StreamTransactionSummary`] schema exposes.
//! 3. **Per-connection pricing** for stream sessions (`stream_connection_pricing`).
//!    Streams have no HTTP status code so they cannot use `pricing_tiers`; this
//!    knob charges a flat fee per stream session at disconnect time.
//!
//! Charges accumulate in-memory via a global singleton registry and are exposed
//! via the admin `/charges` endpoint in both Prometheus and JSON formats for
//! external billing system integration. Only requests with an identified
//! consumer (or authenticated identity) are charged — anonymous traffic is not
//! tracked.
//!
//! **Hot-path optimization**: The recording methods use a thread-local `String`
//! buffer for the DashMap lookup key, achieving **zero heap allocation on cache
//! hits** (99%+ of requests). Only the first
//! record per unique (consumer, proxy, status_code, scope, pricing) combination
//! allocates — subsequent records reuse the existing DashMap entry via a
//! read-lock `get()` on a borrowed `&str`. Published proxy names live in a
//! separate lock-free snapshot used only while rendering, so a name-only reload
//! preserves counter continuity without letting a late retired-generation
//! request restore stale display metadata. Stream entries use a `status_code`
//! sentinel of `0` to share the same key format and code path.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};
use crate::plugins::chargeback::pricing::{
    PricingConfig, checked_add_charge, checked_mul_quantity, require_finite_charge,
};
use crate::plugins::chargeback::{bounded_billing_identity, bounded_display};
use crate::plugins::utils::log_schema::{
    DerivedKind, EmittedKeys, MetadataPolicy, SchemaCapabilities, SchemaSerializable, SchemaView,
    SummarySchema, TimestampFormat, resolve_schema,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// Closed top-level config key set for `api_chargeback` admission.
///
/// Source of truth: keys read by [`ApiChargeback::new`],
/// [`PricingConfig::from_config`], and the `/charges` render projection.
pub const API_CHARGEBACK_CONFIG_KEYS: &[&str] = &[
    "currency",
    "schema",
    "schema_ref",
    "pricing_tiers",
    "bandwidth_pricing",
    "stream_connection_pricing",
    "render_cache_ttl_seconds",
    "stale_entry_ttl_seconds",
    "cache_invalidation_min_age_ms",
    "cleanup_interval_seconds",
    "max_entries",
    "max_retained_bytes",
];

/// Maximum bytes of a billing identity retained in a registry key.
///
/// Authenticated external identities are already rejected above
/// [`crate::plugins::utils::auth_flow::MAX_AUTHENTICATED_IDENTITY_BYTES`] at the
/// authentication boundary; this second bound keeps an operator-configured
/// Consumer username from making a single registry entry arbitrarily large.
/// Oversized values are represented collision-resistantly (prefix + digest of
/// the complete identity), never by a lossy prefix, so two distinct principals
/// can never share one registry entry (GHSA-m28c-f3v5-26qg).
const MAX_REGISTRY_IDENTITY_BYTES: usize = 512;

/// Consumer label used for the fixed-cardinality aggregate row that absorbs
/// charges once the retained-entry (`max_entries`) budget is exhausted.
///
/// This is an *internal* registry representation, not a reserved username.
/// It lives in the digest-form class used by
/// [`bounded_billing_identity`](crate::plugins::chargeback::bounded_billing_identity)
/// (it contains the `~sha256:` marker), so that helper never returns it
/// verbatim for an external identity claim or operator-configured Consumer
/// username. The suffix after the marker is deliberately *not* a 64-hex
/// digest, so a genuine digest-form identity cannot equal this sentinel
/// either. The human-looking label `__cardinality_overflow__` is therefore an
/// ordinary principal that stays on its own row.
///
/// Charges folded here keep their proxy, status, protocol family, currency,
/// namespace, and price dimensions, so billable totals survive admission
/// refusal — only the per-identity attribution is lost, and the refusal is
/// counted and exported.
pub const OVERFLOW_CONSUMER_SENTINEL: &str =
    "__cardinality_overflow__~sha256:ferrum-edge/api-chargeback/overflow/v1";

/// Default maximum number of retained registry entry keys (complete billing
/// rows). One authenticated principal can occupy many slots because the key
/// also includes proxy, status, protocol family, currency, namespace, and prices.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Default maximum retained registry bytes (64 MiB).
pub const DEFAULT_MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;

/// Largest accepted `cleanup_interval_seconds` (one year).
///
/// The interval is handed to `tokio::time::sleep`, whose deadline is
/// `Instant::now() + interval`; an interval near `u64::MAX` seconds overflows
/// that addition and would panic the singleton cleanup task. `0` remains the
/// documented way to disable periodic cleanup.
pub const MAX_CLEANUP_INTERVAL_SECS: u64 = 31_536_000;

/// How many complete registry walks one `/charges` render may attempt while a
/// concurrent reload keeps advancing the proxy-metadata or projection
/// generation. After the last attempt the document is returned uncached
/// instead of re-walking indefinitely on the admin worker.
pub const MAX_RENDER_ATTEMPTS: usize = 3;

/// Fixed per-entry accounting overhead charged on top of the owned key and
/// metadata strings: the `ChargebackEntry` struct, its atomics, the `Arc<str>`
/// headers, and DashMap's own per-slot bookkeeping.
const ENTRY_FIXED_OVERHEAD_BYTES: usize = 256;

/// How often, at most, an admission refusal or drop is logged.
const ADMISSION_WARN_INTERVAL_NANOS: u64 = 60_000_000_000;
/// Sentinel meaning no admission warning has been emitted yet.
const NO_ADMISSION_WARN_NANOS: u64 = u64::MAX;

/// Global chargeback registry (singleton per process).
static CHARGEBACK_REGISTRY: OnceLock<Arc<ChargebackRegistry>> = OnceLock::new();

#[allow(dead_code)] // Used by external tests; production uses try_global_registry / global_registry_with_shard_amount.
pub fn global_registry() -> Arc<ChargebackRegistry> {
    global_registry_with_shard_amount(crate::util::sharding::pool_shard_amount(0))
}

/// Non-owning view of the process-global registry.
///
/// Returns `None` when no `api_chargeback` instance (and no other owning caller)
/// has created the singleton yet. Admin `GET /charges` must use this so an
/// authenticated scrape before the plugin is configured cannot claim the
/// `OnceLock` with auto sharding and permanently prevent a later accepted
/// generation from honoring `PluginHttpClient::pool_shard_amount()`.
pub fn try_global_registry() -> Option<Arc<ChargebackRegistry>> {
    CHARGEBACK_REGISTRY.get().cloned()
}

/// Smallest shard count accepted by `DashMap::with_shard_amount` (power of two
/// and strictly greater than one). Ephemeral empty `/charges` renders use this
/// so the non-owning path never panics before any plugin owns the registry.
const EMPTY_CHARGES_RENDER_SHARD_AMOUNT: usize = 2;
const _: () = assert!(EMPTY_CHARGES_RENDER_SHARD_AMOUNT.is_power_of_two());
const _: () = assert!(EMPTY_CHARGES_RENDER_SHARD_AMOUNT > 1);

/// Authenticated empty `/charges` JSON shape used when the registry has never
/// been created. Allocates only an ephemeral local registry — it does **not**
/// claim [`CHARGEBACK_REGISTRY`].
pub fn empty_charges_json() -> Result<String, String> {
    ChargebackRegistry::with_shard_amount(EMPTY_CHARGES_RENDER_SHARD_AMOUNT).render_json_uncached()
}

/// Authenticated empty `/charges` Prometheus shape used when the registry has
/// never been created. Does **not** claim [`CHARGEBACK_REGISTRY`].
pub fn empty_charges_prometheus() -> Result<String, String> {
    ChargebackRegistry::with_shard_amount(EMPTY_CHARGES_RENDER_SHARD_AMOUNT)
        .render_prometheus_uncached()
}

/// Resolve the process-global registry, creating it with `shard_amount` shards
/// if this is the first access.
///
/// The registry's entry map is written from the request path with
/// attacker-shaped key cardinality, so it must use Ferrum's configured shard
/// count rather than DashMap's default. `shard_amount` must already be
/// normalized (production passes `PluginHttpClient::pool_shard_amount()`, which
/// applies `FERRUM_POOL_SHARD_AMOUNT` exactly once). Later callers observe the
/// already-created registry; the shard count is fixed for the process lifetime.
pub fn global_registry_with_shard_amount(shard_amount: usize) -> Arc<ChargebackRegistry> {
    CHARGEBACK_REGISTRY
        .get_or_init(|| Arc::new(ChargebackRegistry::with_shard_amount(shard_amount)))
        .clone()
}

/// Publish authoritative proxy display names without instantiating the global
/// registry when `api_chargeback` has never been configured.
pub(crate) fn publish_active_proxy_names(config: &crate::config::types::GatewayConfig) {
    let Some(registry) = CHARGEBACK_REGISTRY.get() else {
        return;
    };
    let mut names: HashMap<String, HashMap<String, String>> = HashMap::new();
    for proxy in &config.proxies {
        names.entry(proxy.namespace.clone()).or_default().insert(
            proxy.id.clone(),
            proxy.name.clone().unwrap_or_else(|| "unknown".to_string()),
        );
    }
    registry.set_active_proxy_names(names);
    registry.publish_overflow_reservations(config);
}

/// The aggregate overflow rows the configuration can create, keyed by their
/// registry key, with each row's estimated retained bytes.
///
/// One row per proxy with an effective `api_chargeback` instance and per
/// billable tuple a refused identity can fold into: every priced status of an
/// HTTP-family proxy, plus the shared status-`0` bandwidth row when bandwidth
/// is priced (WebSocket disconnect bandwidth, and bandwidth of statuses no
/// tier prices, fold there); or the single stream row of a stream proxy. The
/// registry reserves these bytes ([`ChargebackRegistry::publish_overflow_reservations`])
/// and [`validate_composition`] refuses a `max_retained_bytes` that cannot hold
/// twice the matrix (the live generation plus a pricing reload's next one).
/// Traffic recorded under no configured proxy (`proxy_id` `unknown`) is not
/// part of the matrix.
pub fn overflow_reservation_matrix(
    config: &crate::config::types::GatewayConfig,
) -> HashMap<String, usize> {
    let mut matrix = HashMap::new();
    for (proxy, effective) in effective_chargeback_plugins_by_proxy(config, "api_chargeback") {
        let [plugin] = effective.as_slice() else {
            continue;
        };
        let Ok(currency) = instance_currency(&plugin.config) else {
            continue;
        };
        let Ok(pricing) = PricingConfig::from_config(&plugin.config, "api_chargeback") else {
            continue;
        };
        let scope = InstanceScope::new(currency, &proxy.namespace);
        let proxy_id = bounded_billing_identity(&proxy.id, MAX_REGISTRY_IDENTITY_BYTES);
        let proxy_name = bounded_display(
            proxy.name.as_deref().unwrap_or("unknown"),
            MAX_REGISTRY_IDENTITY_BYTES,
        );
        let namespace_label = InstanceScope::namespace_label_for(&proxy.namespace);
        let bandwidth_priced = pricing_requires_websocket_framing(&pricing);
        let mut reserve = |status_code: u16, protocol_family: ProtocolFamily, call: f64| {
            let mut key = String::new();
            write_chargeback_key(
                &mut key,
                OVERFLOW_CONSUMER_SENTINEL,
                &proxy.namespace,
                &proxy_id,
                status_code,
                protocol_family,
                &scope,
                EntryPrices {
                    call,
                    bandwidth_sent: pricing.bandwidth_price_sent,
                    bandwidth_received: pricing.bandwidth_price_received,
                },
            );
            let bytes = entry_retained_bytes(
                key.len(),
                OVERFLOW_CONSUMER_SENTINEL.len(),
                proxy_id.len(),
                proxy.namespace.len(),
                proxy_name.len(),
                namespace_label.len(),
                &scope,
            );
            matrix.insert(key, bytes);
        };
        let stream_proxy = proxy
            .backend_scheme
            .as_ref()
            .is_some_and(|scheme| scheme.is_stream());
        if stream_proxy {
            if pricing.stream_connection_price > 0.0 || bandwidth_priced {
                reserve(
                    STREAM_STATUS_SENTINEL,
                    ProtocolFamily::Stream,
                    pricing.stream_connection_price,
                );
            }
        } else {
            for (&status_code, &price) in &pricing.price_by_status {
                reserve(status_code, ProtocolFamily::Http, price);
            }
            if bandwidth_priced {
                reserve(STREAM_STATUS_SENTINEL, ProtocolFamily::Http, 0.0);
            }
        }
    }
    matrix
}

/// After an accepted generation is installed, publish the absence of a
/// `/charges` render projection when no enabled `api_chargeback` remains.
///
/// Instance `commit_background_tasks` publishes a schema while at least one
/// instance exists; a generation with zero instances has no plugin callback,
/// so without this the previous projection would keep projecting retained
/// rows. Does not claim [`CHARGEBACK_REGISTRY`] when it was never created,
/// and never runs during candidate construction/validation.
pub(crate) fn publish_render_schema_absence() {
    let Some(registry) = CHARGEBACK_REGISTRY.get() else {
        return;
    };
    registry.configure_render_schema(None);
}

fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Keep a deterministic fallback for retained rows whose proxy is no longer in
/// the published configuration. Active proxies always supply one identical
/// candidate from the authoritative metadata snapshot.
fn apply_export_proxy_name(agg_name: &mut String, candidate_name: &str) {
    if candidate_name > agg_name.as_str() {
        agg_name.clear();
        agg_name.push_str(candidate_name);
    }
}

/// Protocol family of a recorded entry. Stored on `ChargebackEntry` so the
/// render path can label HTTP and stream activity distinctly without re-parsing
/// the entry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolFamily {
    Http,
    Stream,
}

impl ProtocolFamily {
    /// Stable registry-key / export label for this family (`"http"` or `"stream"`).
    fn label(&self) -> &'static str {
        match self {
            ProtocolFamily::Http => "http",
            ProtocolFamily::Stream => "stream",
        }
    }
}

#[derive(Clone, Copy)]
struct EntryPrices {
    call: f64,
    bandwidth_sent: f64,
    bandwidth_received: f64,
}

type HttpChargeAggregateKey = (String, String, u16, Arc<str>, Arc<str>);
type StreamChargeAggregateKey = (String, String, Arc<str>, Arc<str>);
type BandwidthAggregateKey = (String, String, ProtocolFamily, Arc<str>, Arc<str>);

/// `(consumer, proxy namespace, proxy id, currency)`: the coarsest grouping
/// every exported series and JSON proxy row aggregates within. Idle eviction
/// retires a whole group at once (see [`ChargebackRegistry::evict_stale`]).
type EvictionGroupKey = (Arc<str>, Arc<str>, Arc<str>, Arc<str>);

fn eviction_group_key(entry: &ChargebackEntry) -> EvictionGroupKey {
    (
        Arc::clone(&entry.consumer),
        Arc::clone(&entry.proxy_namespace),
        Arc::clone(&entry.proxy_id),
        Arc::clone(&entry.currency),
    )
}

/// Currency and namespace of a single `api_chargeback` plugin instance
/// (finding #24).
///
/// The chargeback registry is a process-global singleton shared by every
/// `api_chargeback` instance. Currency belongs to the individual instance
/// (global / proxy / proxy_group scope), while namespace comes from the matched
/// proxy. Each instance passes its `InstanceScope` and the transaction's proxy
/// namespace into the registry's `record_*` methods. The cold path stamps
/// immutable render metadata onto the new [`ChargebackEntry`]; the hot path
/// touches none of it, preserving zero-allocation recording. Multiple effective
/// instances on one proxy are rejected (issue #2564).
#[derive(Clone)]
pub struct InstanceScope {
    /// Instance currency label (e.g. "USD"). Emitted per-row at render time.
    pub currency: Arc<str>,
    /// Instance namespace. Direct registry calls use this as the proxy namespace;
    /// production hooks pass the matched proxy's namespace explicitly so a
    /// gateway-wide global instance cannot conflate same-id tenant proxies.
    #[allow(dead_code)]
    // Read by external registry tests; production passes matched namespaces.
    pub namespace: Arc<str>,
}

impl InstanceScope {
    /// Build an instance scope from a currency and owner namespace.
    pub fn new(currency: &str, namespace: &str) -> Self {
        Self {
            currency: Arc::from(currency),
            namespace: Arc::from(namespace),
        }
    }

    /// Build the Prometheus namespace label fragment for a namespace value.
    /// Empty namespace produces an empty fragment so no `namespace=""` label is
    /// emitted.
    pub fn namespace_label_for(namespace: &str) -> String {
        if namespace.is_empty() {
            String::new()
        } else {
            format!(",namespace=\"{}\"", escape_label_value(namespace))
        }
    }
}

/// Estimated bytes one registry entry retains.
///
/// Covers the owned `String` key, the `Arc<str>` metadata the entry clones
/// (consumer, proxy id, proxy namespace, proxy name, currency, namespace
/// label), and a fixed allowance for the struct, its atomics, and DashMap's
/// per-slot bookkeeping.
/// The value is an accounting estimate, not an allocator measurement; it is
/// deliberately conservative so the configured ceiling is never exceeded in
/// real terms.
fn entry_retained_bytes(
    key_len: usize,
    consumer_len: usize,
    proxy_id_len: usize,
    proxy_namespace_len: usize,
    proxy_name_len: usize,
    namespace_label_len: usize,
    scope: &InstanceScope,
) -> usize {
    key_len
        .saturating_add(consumer_len)
        .saturating_add(proxy_id_len)
        .saturating_add(proxy_namespace_len)
        .saturating_add(proxy_name_len)
        .saturating_add(scope.currency.len())
        .saturating_add(namespace_label_len)
        .saturating_add(ENTRY_FIXED_OVERHEAD_BYTES)
}

/// Subtract from a byte counter without wrapping below zero.
fn saturating_fetch_sub(counter: &AtomicUsize, amount: usize) {
    let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_sub(amount))
    });
}

// Keep the hot-path key fields as borrowed scalars: wrapping them in an
// aggregate would add ceremony without reducing the call-site data flow, and
// this helper deliberately writes directly into a reused thread-local buffer.
#[allow(clippy::too_many_arguments)]
fn write_chargeback_key(
    buf: &mut String,
    consumer: &str,
    proxy_namespace: &str,
    proxy_id: &str,
    status_code: u16,
    protocol_family: ProtocolFamily,
    scope: &InstanceScope,
    prices: EntryPrices,
) {
    // Include protocol_family so status-0 WebSocket bandwidth (HTTP family) and
    // zero-connection-price stream sessions cannot collide when every other
    // key dimension matches (issue #2571).
    //
    // The four free-form text dimensions are length-prefixed: names may
    // themselves contain `|`, so without the lengths `("a|b", "c")` and
    // `("a", "b|c")` would build the same key and merge two consumers' (or
    // namespaces') charges into one entry.
    let _ = write!(
        buf,
        "{}.{}.{}.{}|{}|{}|{}|{}|{}|{}|{:016x}|{:016x}|{:016x}",
        consumer.len(),
        proxy_namespace.len(),
        proxy_id.len(),
        scope.currency.len(),
        consumer,
        proxy_namespace,
        proxy_id,
        status_code,
        protocol_family.label(),
        scope.currency,
        prices.call.to_bits(),
        prices.bandwidth_sent.to_bits(),
        prices.bandwidth_received.to_bits()
    );
}

/// Atomic chargeback entry. Tracks call counts, exact byte counters, staleness,
/// and render metadata.
///
/// **Monetary accuracy (finding #76)**: monetary totals are NOT accumulated.
/// Only the exact integer inputs — `call_count`, `bytes_sent_total`,
/// `bytes_received_total` — are summed via plain `fetch_add`, and charges are
/// derived once at render time as `count * price` / `bytes * price`. This
/// eliminates the order-dependent per-add f64 rounding drift that an
/// accumulate-money-as-f64-bits design suffers over high transaction volume,
/// while keeping the lock-free atomics trivial. The per-entry prices
/// (`call_price`, `bw_price_sent`, `bw_price_received`) are config-derived
/// constants fixed at entry creation.
///
/// **Per-instance scoping (finding #24)**: `currency` is stored per entry from
/// the constructing plugin instance rather than in a process-global,
/// last-writer-wins registry field. Namespace is taken from the matched proxy,
/// not the plugin owner, so a gateway-wide global instance keeps same-id tenant
/// proxies distinct. Multiple effective instances on one proxy are rejected
/// (issue #2564) because this registry has no ledger/instance dimension and
/// would double-count the same client transaction.
///
/// The `consumer`, proxy namespace/id, `status_code`, `protocol_family`, prices,
/// and `currency` are set once on creation and read during render. They are
/// included in the DashMap key string so config reloads that change pricing
/// create fresh entries instead of adding new traffic to stale prices, and so
/// HTTP-family status-0 WebSocket bandwidth cannot share an entry with a stream
/// session. The key remains a plain `String`, which lets the hot-path `get()`
/// use a borrowed `&str` from a thread-local buffer with zero allocation.
///
/// **`proxy_name` is live display metadata (issue #2572)**: it is deliberately
/// omitted from the registry key so a name-only reload keeps counter continuity
/// under the stable `(namespace, proxy_id)`. Entries retain their admission-time
/// name for a deterministic fallback after deletion, while renderers use the
/// separately published current-proxy metadata snapshot. Late completions from
/// a retired cache generation therefore cannot restore an old exported name.
///
/// For stream entries the `status_code` is `0` and there is exactly one entry
/// per `(consumer, proxy_id, protocol_family=stream)` (streams have no HTTP
/// status). WebSocket-disconnect bandwidth also uses status `0` but under
/// `protocol_family=http`, so the family discriminator keeps those rows apart.
pub struct ChargebackEntry {
    pub call_count: AtomicU64,
    /// Bytes the gateway sent onward toward the backend on the client's behalf
    /// (request body for HTTP, client→backend half of a stream relay).
    pub bytes_sent_total: AtomicU64,
    /// Bytes the gateway received from the backend and forwarded to the client
    /// (response body for HTTP, backend→client half of a stream relay).
    pub bytes_received_total: AtomicU64,
    pub last_updated: AtomicU64,
    // --- Pricing (immutable after creation, config-derived) ---
    /// Per-call (or per-stream-connection) price. Charge is `call_count * this`.
    pub call_price: f64,
    /// Per-byte price for client→backend bytes.
    pub bw_price_sent: f64,
    /// Per-byte price for backend→client bytes.
    pub bw_price_received: f64,
    // --- Render metadata (immutable after creation) ---
    pub consumer: Arc<str>,
    pub proxy_id: Arc<str>,
    /// Raw matched proxy namespace for JSON output and live-name lookup.
    pub proxy_namespace: Arc<str>,
    /// Admission-time fallback name for `proxy_id`. Active exports use the
    /// authoritative published metadata snapshot instead (issue #2572).
    pub proxy_name: Arc<str>,
    pub status_code: u16,
    pub protocol_family: ProtocolFamily,
    /// Currency label (e.g., "USD", "EUR") of the instance that created the
    /// entry. Per-entry so multiple instances with different currencies do not
    /// misattribute one another's charges.
    pub currency: Arc<str>,
    /// Pre-rendered Prometheus namespace label fragment, e.g.
    /// `,namespace="ferrum"` (empty string when no namespace), of the matched
    /// proxy that created the entry.
    pub namespace_label: Arc<str>,
    /// Bytes this entry reserved against the registry's retained-byte budget.
    /// Released verbatim on eviction so the counter stays exact.
    retained_bytes: usize,
    /// Whether this entry consumed one of the `max_entries` retained-row slots.
    /// Aggregate overflow rows do not (their cardinality is bounded by
    /// configuration — proxy × status × family × currency/namespace × prices —
    /// not by attacker-chosen principals).
    counts_against_identity_budget: bool,
}

impl ChargebackEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        epoch: Instant,
        consumer: Arc<str>,
        proxy_id: Arc<str>,
        proxy_namespace: Arc<str>,
        proxy_name: Arc<str>,
        status_code: u16,
        protocol_family: ProtocolFamily,
        call_price: f64,
        bw_price_sent: f64,
        bw_price_received: f64,
        currency: Arc<str>,
        namespace_label: Arc<str>,
        retained_bytes: usize,
        counts_against_identity_budget: bool,
    ) -> Self {
        Self {
            call_count: AtomicU64::new(0),
            bytes_sent_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            last_updated: AtomicU64::new(epoch.elapsed().as_nanos() as u64),
            call_price,
            bw_price_sent,
            bw_price_received,
            consumer,
            proxy_id,
            proxy_namespace,
            proxy_name,
            status_code,
            protocol_family,
            currency,
            namespace_label,
            retained_bytes,
            counts_against_identity_budget,
        }
    }

    /// A fresh row with this row's identity, pricing, metadata, and byte
    /// reservation, and zero counters.
    fn successor(&self, epoch: Instant) -> Self {
        Self::new(
            epoch,
            Arc::clone(&self.consumer),
            Arc::clone(&self.proxy_id),
            Arc::clone(&self.proxy_namespace),
            Arc::clone(&self.proxy_name),
            self.status_code,
            self.protocol_family,
            self.call_price,
            self.bw_price_sent,
            self.bw_price_received,
            Arc::clone(&self.currency),
            Arc::clone(&self.namespace_label),
            self.retained_bytes,
            self.counts_against_identity_budget,
        )
    }

    fn record(&self, bytes_sent: u64, bytes_received: u64, count_call: bool, epoch: Instant) {
        if count_call {
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }
        if bytes_sent > 0 {
            self.bytes_sent_total
                .fetch_add(bytes_sent, Ordering::Relaxed);
        }
        if bytes_received > 0 {
            self.bytes_received_total
                .fetch_add(bytes_received, Ordering::Relaxed);
        }
        self.publish_timestamp(epoch.elapsed().as_nanos() as u64);
    }

    /// Publish a record timestamp without allowing a delayed recorder to move
    /// the row's idle-age and collection state backwards.
    #[doc(hidden)]
    pub fn publish_timestamp(&self, timestamp_nanos: u64) {
        self.last_updated
            .fetch_max(timestamp_nanos, Ordering::Relaxed);
    }

    /// Total per-call (or per-connection) charge, computed once from exact
    /// inputs: `call_count * call_price`. Returns an error when the product is
    /// non-finite so exporters can fail closed instead of emitting JSON null /
    /// Prometheus `inf`.
    pub fn call_charge(&self) -> Result<f64, String> {
        checked_mul_quantity(self.call_count.load(Ordering::Relaxed), self.call_price)
    }

    /// Bandwidth charge for client→backend bytes: `bytes_sent_total * price`.
    pub fn bandwidth_charge_sent(&self) -> Result<f64, String> {
        checked_mul_quantity(
            self.bytes_sent_total.load(Ordering::Relaxed),
            self.bw_price_sent,
        )
    }

    /// Bandwidth charge for backend→client bytes: `bytes_received_total * price`.
    pub fn bandwidth_charge_received(&self) -> Result<f64, String> {
        checked_mul_quantity(
            self.bytes_received_total.load(Ordering::Relaxed),
            self.bw_price_received,
        )
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// Default stale entry TTL: 1 hour in nanoseconds.
const DEFAULT_STALE_TTL_NANOS: u64 = 3_600_000_000_000;

/// Default render cache TTL: 5 seconds.
pub const DEFAULT_RENDER_CACHE_TTL_SECS: u64 = 5;

/// Default stale-entry TTL in seconds (matches [`DEFAULT_STALE_TTL_NANOS`]).
pub const DEFAULT_STALE_ENTRY_TTL_SECS: u64 = DEFAULT_STALE_TTL_NANOS / 1_000_000_000;

/// Default minimum cache age (in nanoseconds) before record() will invalidate.
const DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS: u64 = 500_000_000; // 500ms

/// Default minimum cache age in milliseconds.
pub const DEFAULT_CACHE_INVALIDATION_MIN_AGE_MS: u64 =
    DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS / 1_000_000;

/// Default background cleanup interval in seconds.
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300;

/// Process-global render/cleanup knobs shared by every `api_chargeback` instance
/// through the singleton `/charges` registry.
///
/// Pricing and currency remain per-instance and may differ across proxies.
/// These four values must agree across every enabled instance because one
/// cleanup task and one render cache serve the whole process (issue #2564).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedRegistryTunables {
    pub render_cache_ttl_secs: u64,
    pub stale_entry_ttl_secs: u64,
    pub cache_invalidation_min_age_ms: u64,
    pub cleanup_interval_seconds: u64,
    /// Hard ceiling on retained billing rows (complete registry entry keys) in
    /// the shared registry. A new row that cannot be admitted is folded into
    /// the fixed-cardinality aggregate instead of being dropped — invoice
    /// totals still reconcile, only per-identity attribution is lost. One
    /// principal can occupy many slots because keys also include proxy, status,
    /// protocol family, currency, namespace, and prices.
    pub max_entries: usize,
    /// Hard ceiling on retained registry bytes, covering ordinary billing rows
    /// and the aggregate overflow rows together. Admission requires it to hold
    /// twice the configured overflow-row matrix (see
    /// [`overflow_reservation_matrix`]).
    pub max_retained_bytes: usize,
}

impl SharedRegistryTunables {
    /// Resolve shared tunables from one plugin config object, applying defaults.
    pub fn from_config(config: &Value) -> Result<Self, String> {
        Ok(Self {
            render_cache_ttl_secs: optional_u64(
                config,
                "render_cache_ttl_seconds",
                DEFAULT_RENDER_CACHE_TTL_SECS,
            )?,
            stale_entry_ttl_secs: optional_u64(
                config,
                "stale_entry_ttl_seconds",
                DEFAULT_STALE_ENTRY_TTL_SECS,
            )?,
            cache_invalidation_min_age_ms: optional_u64(
                config,
                "cache_invalidation_min_age_ms",
                DEFAULT_CACHE_INVALIDATION_MIN_AGE_MS,
            )?,
            cleanup_interval_seconds: bounded_cleanup_interval(config)?,
            max_entries: required_positive_usize(config, "max_entries", DEFAULT_MAX_ENTRIES)?,
            max_retained_bytes: required_positive_usize(
                config,
                "max_retained_bytes",
                DEFAULT_MAX_RETAINED_BYTES,
            )?,
        })
    }
}

/// Read `cleanup_interval_seconds`, refusing values above
/// [`MAX_CLEANUP_INTERVAL_SECS`] so the cleanup task's sleep deadline can never
/// overflow.
fn bounded_cleanup_interval(config: &Value) -> Result<u64, String> {
    let value = optional_u64(
        config,
        "cleanup_interval_seconds",
        DEFAULT_CLEANUP_INTERVAL_SECS,
    )?;
    if value > MAX_CLEANUP_INTERVAL_SECS {
        return Err(format!(
            "api_chargeback: `cleanup_interval_seconds` (\"{value}\") must be at most \
             {MAX_CLEANUP_INTERVAL_SECS} (one year); use 0 to disable periodic cleanup"
        ));
    }
    Ok(value)
}

/// Read a positive `usize` budget key, rejecting `0` and non-integers.
///
/// `0` is rejected rather than treated as "unlimited": an unbounded process-
/// global registry is exactly the exhaustion primitive this budget exists to
/// remove (GHSA-wxmv-8mwr-92xf).
fn required_positive_usize(config: &Value, key: &str, default: usize) -> Result<usize, String> {
    let value = optional_u64(config, key, default as u64)?;
    if value == 0 {
        return Err(format!(
            "api_chargeback: `{key}` must be greater than 0; the shared `/charges` registry has no \
             unlimited mode"
        ));
    }
    usize::try_from(value)
        .map_err(|_| format!("api_chargeback: `{key}` (\"{value}\") exceeds platform `usize`"))
}

/// Resolve enabled chargeback plugin configs that the plugin cache would
/// install for each proxy. Any local proxy/proxy-group instance shadows all
/// global instances of the same plugin type on that proxy — matching the
/// general merge contract — but chargeback additionally requires the resulting
/// effective list to contain at most one instance (issue #2564).
fn effective_chargeback_plugins_by_proxy<'a>(
    config: &'a crate::config::types::GatewayConfig,
    plugin_name: &str,
) -> Vec<(
    &'a crate::config::types::Proxy,
    Vec<&'a crate::config::types::PluginConfig>,
)> {
    use crate::config::types::PluginScope;

    // Association plugin_config_id values are namespace-local to the proxy. A
    // bare-id index would bind a proxy to another tenant's same-id
    // api_chargeback config (mirrors effective_mtls_auth_plugins_by_proxy).
    let plugin_by_key: HashMap<(&str, &str), &crate::config::types::PluginConfig> = config
        .plugin_configs
        .iter()
        .map(|plugin| ((plugin.namespace.as_str(), plugin.id.as_str()), plugin))
        .collect();
    let global_chargeback: Vec<&crate::config::types::PluginConfig> = config
        .plugin_configs
        .iter()
        .filter(|plugin| {
            plugin.enabled
                && plugin.scope == PluginScope::Global
                && plugin.plugin_name == plugin_name
        })
        .collect();

    config
        .proxies
        .iter()
        .map(|proxy| {
            let local_chargeback: Vec<&crate::config::types::PluginConfig> = proxy
                .plugins
                .iter()
                .filter_map(|association| {
                    let plugin = *plugin_by_key.get(&(
                        proxy.namespace.as_str(),
                        association.plugin_config_id.as_str(),
                    ))?;
                    let scope_applies = match plugin.scope {
                        PluginScope::Proxy => {
                            plugin.namespace == proxy.namespace
                                && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
                        }
                        // Config validation already requires proxy-group
                        // instances to omit proxy_id. Applicability here mirrors
                        // the runtime merge, which is driven by scope plus the
                        // proxy's explicit plugin association — still
                        // namespace-local so same-id group configs stay isolated.
                        PluginScope::ProxyGroup => {
                            plugin.namespace == proxy.namespace && plugin.proxy_id.is_none()
                        }
                        PluginScope::Global => false,
                    };
                    (plugin.enabled && plugin.plugin_name == plugin_name && scope_applies)
                        .then_some(plugin)
                })
                .collect();
            let effective = if local_chargeback.is_empty() {
                // Globals are gateway-wide at runtime (`PluginCache` merges the
                // single global list into every proxy in every namespace), so
                // this must NOT be namespace-filtered — only the association
                // lookup above is namespace-local.
                global_chargeback.clone()
            } else {
                local_chargeback
            };
            (proxy, effective)
        })
        .collect()
}

/// Enforce exactly-once `/charges` accounting and deterministic ownership of the
/// shared render/cleanup tunables (issue #2564).
///
/// Rules:
/// 1. The process may have at most one enabled global `api_chargeback`
///    instance. Although a local instance shadows globals on a configured
///    proxy, unmatched/fallback transaction paths retain the global chain, so
///    multiple globals would still double-count.
/// 2. After scope merging, each proxy may have at most one effective
///    `api_chargeback` instance. Multiple proxy-scoped, proxy-group-scoped, or
///    mixed attachments on one proxy are rejected — the process-global registry
///    has no ledger/instance dimension, so every retained hook would double-count
///    the same client transaction.
/// 3. Across the whole process, every enabled `api_chargeback` instance must
///    resolve to identical shared tunables
///    (`render_cache_ttl_seconds`, `stale_entry_ttl_seconds`,
///    `cache_invalidation_min_age_ms`, `cleanup_interval_seconds`,
///    `max_entries`, `max_retained_bytes`). Since every
///    constructor applies the same values, construction order cannot change
///    registry behavior. Pricing and currency may still differ per proxy.
pub fn validate_composition(
    config: &crate::config::types::GatewayConfig,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let global_ids: Vec<&str> = config
        .plugin_configs
        .iter()
        .filter(|plugin| {
            plugin.enabled
                && plugin.plugin_name == "api_chargeback"
                && plugin.scope == crate::config::types::PluginScope::Global
        })
        .map(|plugin| plugin.id.as_str())
        .collect();
    if global_ids.len() > 1 {
        errors.push(format!(
            "api_chargeback permits at most one enabled global instance \
             (shared `/charges` registry is exactly-once); found: {:?}",
            global_ids.join(", ")
        ));
    }

    for (proxy, effective) in effective_chargeback_plugins_by_proxy(config, "api_chargeback") {
        if effective.len() > 1 {
            let ids: Vec<&str> = effective.iter().map(|plugin| plugin.id.as_str()).collect();
            errors.push(format!(
                "api_chargeback permits at most one effective instance per proxy \
                 (shared `/charges` registry is exactly-once); proxy {:?} has: {:?}",
                proxy.id,
                ids.join(", ")
            ));
        }
    }

    for (proxy, effective) in effective_chargeback_plugins_by_proxy(config, "api_chargeback_sink") {
        if effective.len() > 1 {
            let ids: Vec<&str> = effective.iter().map(|plugin| plugin.id.as_str()).collect();
            errors.push(format!(
                "api_chargeback_sink permits at most one effective instance per proxy \
                 (independent event_id dedup keys duplicate durable rows); proxy {:?} has: {:?}",
                proxy.id,
                ids.join(", ")
            ));
        }
    }

    let mut enabled: Vec<&crate::config::types::PluginConfig> = config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.enabled && plugin.plugin_name == "api_chargeback")
        .collect();
    enabled.sort_by(|a, b| a.id.cmp(&b.id));

    if let Some(reference) = enabled.first() {
        let reference_tunables = match SharedRegistryTunables::from_config(&reference.config) {
            Ok(tunables) => tunables,
            Err(error) => {
                errors.push(format!(
                    "api_chargeback shared tunables in {:?}: {error}",
                    reference.id
                ));
                return Err(errors);
            }
        };
        let reference_projection = render_projection_config(&reference.config);
        for sibling in enabled.iter().skip(1) {
            match SharedRegistryTunables::from_config(&sibling.config) {
                Ok(tunables) if tunables == reference_tunables => {}
                Ok(_) => errors.push(format!(
                    "api_chargeback shared render/cleanup tunables must match across all enabled \
                     instances; {:?} disagrees with {:?}. \
                     Align `render_cache_ttl_seconds`, `stale_entry_ttl_seconds`, \
                     `cache_invalidation_min_age_ms`, `cleanup_interval_seconds`, \
                     `max_entries`, and `max_retained_bytes`",
                    reference.id, sibling.id
                )),
                Err(error) => errors.push(format!(
                    "api_chargeback shared tunables in {:?}: {error}",
                    sibling.id
                )),
            }
            // The `/charges` projection governs one process-global render
            // cache, exactly like the tunables above, so every enabled instance
            // must resolve to the same 'schema' / 'schema_ref'.
            if render_projection_config(&sibling.config) != reference_projection {
                errors.push(format!(
                    "api_chargeback `/charges` render projection must match across all enabled \
                     instances (one process-global render cache serves them all); {:?} disagrees \
                     with {:?}. Align `schema` / `schema_ref`",
                    reference.id, sibling.id
                ));
            }
        }

        // The overflow fallback must always fit: refused identities fold into
        // reserved aggregate rows, and a pricing reload's next generation needs
        // its own rows while the retired generation drains.
        let matrix_bytes: usize = overflow_reservation_matrix(config).values().sum();
        let required_bytes = matrix_bytes.saturating_mul(2);
        if required_bytes > reference_tunables.max_retained_bytes {
            errors.push(format!(
                "api_chargeback `max_retained_bytes` ({}) cannot hold the aggregate overflow rows \
                 the configured proxies and pricing tiers need: {matrix_bytes} bytes, reserved \
                 twice ({required_bytes} bytes) so a pricing reload's next generation also fits. \
                 Raise `max_retained_bytes`",
                reference_tunables.max_retained_bytes
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Refuse a candidate configuration whose not-yet-created overflow rows do
/// not fit beside the billing state `registry` already retains (see
/// [`ChargebackRegistry::check_overflow_reservation_fits`]).
///
/// Kept apart from [`validate_composition`], which stays a pure function of
/// the configuration: this rule depends on live registry state.
pub fn live_overflow_reservation_check(
    config: &crate::config::types::GatewayConfig,
    registry: &ChargebackRegistry,
) -> Result<(), String> {
    let Some(reference) = config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.enabled && plugin.plugin_name == "api_chargeback")
    else {
        return Ok(());
    };
    // `validate_composition` already required every enabled instance to agree
    // on the shared tunables, so any one of them carries the budget.
    let tunables = SharedRegistryTunables::from_config(&reference.config)?;
    registry.check_overflow_reservation_fits(
        &overflow_reservation_matrix(config),
        tunables.max_retained_bytes,
    )
}

/// [`live_overflow_reservation_check`] against the process-global registry,
/// when one exists. Called only where the plugin cache builds a generation for
/// publication, so offline and candidate configuration validation never
/// depend on this process's live billing state.
pub(crate) fn validate_live_overflow_reservation(
    config: &crate::config::types::GatewayConfig,
) -> Result<(), String> {
    match try_global_registry() {
        Some(registry) => live_overflow_reservation_check(config, &registry),
        None => Ok(()),
    }
}

/// The `/charges` render-projection configuration of one plugin config.
///
/// Compared verbatim across enabled instances so a disagreement is caught at
/// admission rather than by whichever instance committed last.
fn render_projection_config(config: &Value) -> (Option<&Value>, Option<&Value>) {
    (config.get("schema"), config.get("schema_ref"))
}

/// Whether a populated render cache generated at `generated_at` has reached the
/// configured `cache_invalidation_min_age_ms`.
///
/// An empty cache (`None`) is never "aged": there is nothing to invalidate, and
/// restamping it would allocate a fresh `Arc` on every recorded request.
#[inline]
fn render_cache_reached_min_age(generated_at: Option<Instant>, min_age_nanos: u64) -> bool {
    match generated_at {
        Some(at) => at.elapsed().as_nanos() as u64 >= min_age_nanos,
        None => false,
    }
}

/// Charges recorded onto an aggregate overflow row while an eviction pass has
/// unlinked it (see [`ChargebackRegistry::evict_stale`]). The pass still holds
/// the row and its byte reservation, so a recorder files the charge here,
/// lock-free, instead of reserving a second copy of the row; the pass merges
/// it back when it restores or retires the row.
#[derive(Default)]
struct PendingAggregateCharges {
    calls: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    last_updated: AtomicU64,
    recorded: AtomicBool,
}

impl PendingAggregateCharges {
    fn record(&self, bytes_sent: u64, bytes_received: u64, count_call: bool, epoch: Instant) {
        if count_call {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
        self.last_updated
            .fetch_max(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
        self.recorded.store(true, Ordering::Release);
    }

    fn has_activity(&self) -> bool {
        self.recorded.load(Ordering::Acquire)
    }

    fn merge_into(&self, entry: &ChargebackEntry) {
        entry
            .call_count
            .fetch_add(self.calls.load(Ordering::Relaxed), Ordering::Relaxed);
        entry
            .bytes_sent_total
            .fetch_add(self.bytes_sent.load(Ordering::Relaxed), Ordering::Relaxed);
        entry.bytes_received_total.fetch_add(
            self.bytes_received.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        entry.publish_timestamp(self.last_updated.load(Ordering::Relaxed));
    }
}

/// One aggregate overflow row the accepted configuration reserved bytes for.
struct ReservedOverflowRow {
    /// Estimated retained bytes of the row.
    bytes: usize,
    /// Whether the row currently exists in the registry (its bytes are then
    /// counted in `retained_bytes` rather than in the outstanding reserve).
    present: AtomicBool,
}

/// One cached Prometheus `/charges` document.
struct CachedPrometheusRender {
    generated_at: Instant,
    metadata_generation: u64,
    /// Collection receipt of the walk that produced `output`. A cache hit
    /// returns it so delivering the cached document acknowledges exactly the
    /// counters that document contains.
    receipt: CollectionReceipt,
    output: String,
}

/// One cached JSON `/charges` document.
struct CachedJsonRender {
    generated_at: Instant,
    metadata_generation: u64,
    schema_generation: u64,
    /// See [`CachedPrometheusRender::receipt`].
    receipt: CollectionReceipt,
    output: String,
}

/// Proof that one rendered `/charges` document contains the counters of every
/// row last updated before its registry walk began (issue #5276).
///
/// Rendering alone acknowledges nothing: the receipt must be handed back to
/// [`ChargebackRegistry::acknowledge_collection`] once the document has been
/// delivered. The admin `/charges` handler does that through
/// [`ChargesDeliveryAck`] only after the connection has taken the complete
/// response body, so a scrape abandoned before then cannot authorize idle-age
/// eviction of counters no collector received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectionReceipt {
    walk_started_nanos: u64,
}

/// Response extension carrying a `/charges` [`CollectionReceipt`] to the admin
/// connection's body wrapper, which calls [`Self::acknowledge`] once hyper has
/// taken the complete document.
#[derive(Clone)]
pub struct ChargesDeliveryAck {
    registry: Arc<ChargebackRegistry>,
    receipt: CollectionReceipt,
}

impl ChargesDeliveryAck {
    pub fn new(registry: Arc<ChargebackRegistry>, receipt: CollectionReceipt) -> Self {
        Self { registry, receipt }
    }

    /// Acknowledge collection of the delivered document. Idempotent.
    pub fn acknowledge(&self) {
        self.registry.acknowledge_collection(self.receipt);
    }
}

/// Sentinel `status_code` for stream sessions and WebSocket-disconnect
/// bandwidth rows. Ordinary HTTP wire statuses are in `100..=599`; the
/// registry key also carries [`ProtocolFamily`] so a bandwidth-only stream
/// session and a WebSocket bandwidth record with identical prices cannot
/// collide on this sentinel.
const STREAM_STATUS_SENTINEL: u16 = 0;

/// Chargeback registry holding per-consumer, per-proxy charge accumulators.
///
/// **Key design**: The DashMap uses plain `String` keys formatted as
/// `"consumer|proxy_namespace|proxy_id|status_code|protocol_family|currency|price_bits..."`.
/// Render metadata (consumer, proxy_id, status_code, protocol_family) is stored
/// in the `ChargebackEntry` value and `protocol_family` is also part of the key
/// so immutable family attribution cannot be fixed by insertion order.
/// `proxy_name` is live display metadata only — omitted from the key so a
/// name-only reload preserves counter continuity under the stable `proxy_id`
/// (issue #2572). The render path substitutes the authoritative name snapshot
/// from the published configuration. This allows the hot-path recording methods
/// to use `DashMap::get(&str)` with a thread-local buffer — zero allocation on
/// cache hits. Only the cold path (first record per unique billing/pricing
/// combination) allocates a `String` key and `Arc<str>` metadata. This matches
/// the connection pool key pattern in `connection_pool.rs`.
pub struct ChargebackRegistry {
    epoch: Instant,
    pub entries: DashMap<String, ChargebackEntry>,
    /// Shard count the entry map was built with. Fixed for the process-global
    /// singleton's lifetime; recorded so tests can assert the accepted
    /// generation's `PluginHttpClient::pool_shard_amount()` reached the map.
    shard_amount: usize,
    /// Current display names keyed by raw proxy namespace and proxy id.
    active_proxy_names: ArcSwap<HashMap<String, HashMap<String, String>>>,
    /// Advances whenever `active_proxy_names` is replaced. Render caches carry
    /// this generation so an overlapping reload cannot publish stale labels.
    proxy_metadata_generation: AtomicU64,
    /// Advances whenever the published `/charges` render projection changes.
    /// JSON cache entries carry this so a render that snapped a prior schema
    /// cannot repopulate the cache after a schema transition.
    render_schema_generation: AtomicU64,
    /// Cached render output with timestamp and proxy-metadata generation.
    prometheus_cache: ArcSwap<Option<CachedPrometheusRender>>,
    /// Cached JSON document tagged with proxy-metadata and projection
    /// generations. One document must use one schema snapshot.
    json_cache: ArcSwap<Option<CachedJsonRender>>,
    render_cache_ttl_secs: AtomicU64,
    stale_entry_ttl_nanos: AtomicU64,
    cache_invalidation_min_age_nanos: AtomicU64,
    /// Confirmed collection watermark (nanos since [`Self::epoch`]): every
    /// entry whose `last_updated` precedes it had its current counters in at
    /// least TWO delivered `/charges` documents.
    ///
    /// Idle-age eviction requires that confirmation (issue #5276): without it,
    /// `stale_entry_ttl_seconds` could delete call/byte counters that no
    /// collector ever saw. Two deliveries are required because the gateway has
    /// no transport signal proving one response reached its collector (see
    /// [`Self::acknowledge_collection`]).
    collection_watermark_nanos: AtomicU64,
    /// Walk start of the most recent delivered `/charges` document.
    latest_acknowledged_walk_nanos: std::sync::Mutex<u64>,
    /// Aggregate overflow rows reserved for the accepted configuration, keyed
    /// by their registry key (see [`overflow_reservation_matrix`]).
    overflow_reservations: ArcSwap<HashMap<String, ReservedOverflowRow>>,
    /// Bytes reserved for reserved overflow rows that do not currently exist.
    outstanding_overflow_reserve: AtomicUsize,
    /// Total bytes of the accepted overflow matrix. Ordinary rows also leave
    /// this much headroom free so the next pricing generation's overflow rows
    /// still fit while retired-generation rows drain.
    overflow_reserve_headroom: AtomicUsize,
    /// Excludes `/charges` walks and overflow-reservation publication while an
    /// eviction pass retires series groups, so no export observes a partially
    /// retired group. Never waited on by the recording path: aggregate-row
    /// creation only TRIES it (see `record_new_aggregate_row`).
    retirement_lock: std::sync::RwLock<()>,
    /// Aggregate overflow rows the running eviction pass has unlinked (or is
    /// about to), with the charges recorded onto them meanwhile. Empty outside
    /// a pass.
    retiring_aggregates: DashMap<String, PendingAggregateCharges>,
    /// Registry walks performed by `/charges` renders (diagnostics and tests).
    render_walks: AtomicUsize,
    /// Test hook: advance the proxy-metadata generation after every render
    /// walk, modelling a reload that keeps invalidating each walk.
    invalidate_every_render_walk: AtomicBool,
    /// Entries the most recent [`Self::evict_stale`] pass kept even though they
    /// were idle past the TTL, because no completed export has observed their
    /// current counters. Exported as a fixed-cardinality, identity-free gauge
    /// so an operator can see uncollected billing state accumulating.
    uncollected_retained_entries: AtomicUsize,
    /// Compiled `/charges` billing-row projection published by the accepted
    /// generation. Read-only on the render path behind a lock-free `ArcSwap`.
    render_schema: ArcSwap<Option<Arc<SummarySchema>>>,
    cleanup_interval_seconds: AtomicU64,
    cleanup_interval_changed: tokio::sync::Notify,
    /// Guards against spawning duplicate background cleanup tasks.
    cleanup_task_started: AtomicBool,
    /// Hard ceiling on retained billing rows / complete entry keys
    /// (GHSA-wxmv-8mwr-92xf). Not a distinct-principal ceiling: one identity
    /// can consume many slots across proxy/status/family/currency/namespace/
    /// price dimensions.
    max_entries: AtomicUsize,
    /// Hard ceiling on retained bytes across ordinary and aggregate rows.
    max_retained_bytes: AtomicUsize,
    /// Entry-key slots reserved before a new billing row is published. Reserved
    /// atomically so concurrent cold-path inserts cannot publish state above
    /// `max_entries`.
    reserved_entries: AtomicUsize,
    /// Retained bytes reserved by every live entry, ordinary and aggregate.
    retained_bytes: AtomicUsize,
    /// Charges that were admitted to the fixed-cardinality aggregate row
    /// because the retained-entry budget was exhausted. Billable state is
    /// preserved; only per-identity attribution is lost.
    identity_overflow_total: AtomicU64,
    /// Charges that could not be retained at all because even the aggregate row
    /// could not reserve bytes. This is real billing loss and is exported.
    dropped_charges_total: AtomicU64,
    /// Rate limiter for admission warnings (nanos since `epoch`).
    last_admission_warn_at: AtomicU64,
}

impl Default for ChargebackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChargebackRegistry {
    pub fn new() -> Self {
        Self::with_shard_amount(crate::util::sharding::pool_shard_amount(0))
    }

    /// Build a registry whose entry map uses `shard_amount` shards. The value
    /// must already be normalized by
    /// [`crate::util::sharding::pool_shard_amount`].
    pub fn with_shard_amount(shard_amount: usize) -> Self {
        Self {
            epoch: Instant::now(),
            entries: DashMap::with_shard_amount(shard_amount),
            shard_amount,
            active_proxy_names: ArcSwap::from_pointee(HashMap::new()),
            proxy_metadata_generation: AtomicU64::new(0),
            render_schema_generation: AtomicU64::new(0),
            prometheus_cache: ArcSwap::from_pointee(None),
            json_cache: ArcSwap::from_pointee(None),
            render_cache_ttl_secs: AtomicU64::new(DEFAULT_RENDER_CACHE_TTL_SECS),
            stale_entry_ttl_nanos: AtomicU64::new(DEFAULT_STALE_TTL_NANOS),
            cache_invalidation_min_age_nanos: AtomicU64::new(
                DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS,
            ),
            // Nothing has been exported yet, so nothing is collected.
            collection_watermark_nanos: AtomicU64::new(0),
            latest_acknowledged_walk_nanos: std::sync::Mutex::new(0),
            overflow_reservations: ArcSwap::from_pointee(HashMap::new()),
            outstanding_overflow_reserve: AtomicUsize::new(0),
            overflow_reserve_headroom: AtomicUsize::new(0),
            retirement_lock: std::sync::RwLock::new(()),
            retiring_aggregates: DashMap::with_shard_amount(EMPTY_CHARGES_RENDER_SHARD_AMOUNT),
            render_walks: AtomicUsize::new(0),
            invalidate_every_render_walk: AtomicBool::new(false),
            uncollected_retained_entries: AtomicUsize::new(0),
            render_schema: ArcSwap::from_pointee(None),
            cleanup_interval_seconds: AtomicU64::new(0),
            cleanup_interval_changed: tokio::sync::Notify::new(),
            cleanup_task_started: AtomicBool::new(false),
            max_entries: AtomicUsize::new(DEFAULT_MAX_ENTRIES),
            max_retained_bytes: AtomicUsize::new(DEFAULT_MAX_RETAINED_BYTES),
            reserved_entries: AtomicUsize::new(0),
            retained_bytes: AtomicUsize::new(0),
            identity_overflow_total: AtomicU64::new(0),
            dropped_charges_total: AtomicU64::new(0),
            last_admission_warn_at: AtomicU64::new(NO_ADMISSION_WARN_NANOS),
        }
    }

    /// Replace live display metadata after a gateway configuration is
    /// published. This is a reload cold-path operation.
    #[doc(hidden)]
    pub fn set_active_proxy_names(&self, names: HashMap<String, HashMap<String, String>>) {
        let unchanged = {
            let current = self.active_proxy_names.load();
            current.as_ref() == &names
        };
        if unchanged {
            return;
        }
        self.active_proxy_names.store(Arc::new(names));
        self.proxy_metadata_generation
            .fetch_add(1, Ordering::AcqRel);
        self.prometheus_cache.store(Arc::new(None));
        self.json_cache.store(Arc::new(None));
    }

    /// Reserve bytes for the aggregate overflow rows the published
    /// configuration can create (see [`overflow_reservation_matrix`]).
    ///
    /// Reserved rows that already exist are marked present (their bytes are
    /// in `retained_bytes`); the rest form the outstanding reserve that
    /// ordinary rows may not consume, and the whole matrix is additionally
    /// kept as headroom for the next pricing generation. Runs on the reload
    /// cold path under the retirement lock so it cannot race an eviction pass.
    /// A reserved row created concurrently (aggregate-row creation never waits
    /// for the lock) may stay counted as outstanding — protecting more than
    /// needed — until the next eviction pass reconciles every flag.
    /// The plugin cache has already refused a matrix that does not fit beside
    /// the retained rows ([`live_overflow_reservation_check`]).
    #[doc(hidden)]
    pub fn publish_overflow_reservations(&self, config: &crate::config::types::GatewayConfig) {
        let matrix = overflow_reservation_matrix(config);
        let _retiring = self
            .retirement_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut outstanding = 0usize;
        let mut total = 0usize;
        let reservations: HashMap<String, ReservedOverflowRow> = matrix
            .into_iter()
            .map(|(key, bytes)| {
                let present = self.entries.contains_key(key.as_str());
                total = total.saturating_add(bytes);
                if !present {
                    outstanding = outstanding.saturating_add(bytes);
                }
                (
                    key,
                    ReservedOverflowRow {
                        bytes,
                        present: AtomicBool::new(present),
                    },
                )
            })
            .collect();
        self.overflow_reservations.store(Arc::new(reservations));
        self.outstanding_overflow_reserve
            .store(outstanding, Ordering::Release);
        self.overflow_reserve_headroom
            .store(total, Ordering::Release);
    }

    /// Refuse a candidate overflow matrix this live registry cannot reserve
    /// beside the billing state it already retains.
    ///
    /// Reserving only records which bytes ordinary rows must leave free; it
    /// cannot free bytes retained history already occupies. Retained rows are
    /// never deleted to make room (they may hold uncollected charges, and an
    /// active series keeps its retired pricing generations), so a candidate
    /// whose overflow rows that do not exist yet need more than the free
    /// space would leave its own current-generation charges to be dropped.
    /// [`live_overflow_reservation_check`] refuses such a candidate when the
    /// plugin cache builds it, and the live generation stays in place. Rows
    /// admitted between this check and the candidate's publication are not
    /// counted. A candidate whose reserved rows all exist already is never
    /// refused here, so lowering the budget below current occupancy still just
    /// drains through eviction.
    #[doc(hidden)]
    pub fn check_overflow_reservation_fits(
        &self,
        matrix: &HashMap<String, usize>,
        max_retained_bytes: usize,
    ) -> Result<(), String> {
        let missing_bytes: usize = matrix
            .iter()
            .filter(|(key, _)| !self.entries.contains_key(key.as_str()))
            .map(|(_, bytes)| *bytes)
            .sum();
        if missing_bytes == 0 {
            // Every reserved row already exists, so none is at risk. A budget
            // lowered below current occupancy keeps its drain-by-eviction
            // semantics: new rows are refused until occupancy falls.
            return Ok(());
        }
        let retained_bytes = self.retained_bytes.load(Ordering::Acquire);
        let required_bytes = retained_bytes.saturating_add(missing_bytes);
        if required_bytes > max_retained_bytes {
            return Err(format!(
                "api_chargeback `max_retained_bytes` ({max_retained_bytes}) cannot reserve the \
                 aggregate overflow rows this configuration needs beside the billing state the \
                 live `/charges` registry already retains: {retained_bytes} bytes retained plus \
                 {missing_bytes} bytes of overflow rows not yet created. Raise \
                 `max_retained_bytes`, or let retained rows be collected and evicted before \
                 changing pricing"
            ));
        }
        Ok(())
    }

    /// Bytes currently reserved for reserved overflow rows that do not exist.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn outstanding_overflow_reserve_for_tests(&self) -> usize {
        self.outstanding_overflow_reserve.load(Ordering::Acquire)
    }

    /// Configure the process-global render/cleanup knobs that govern the SHARED
    /// registry infrastructure (render cache TTL, stale-entry eviction TTL,
    /// cache-invalidation min age). These intentionally remain registry-global
    /// because a single cleanup task and a single render cache serve all plugin
    /// instances. Admission requires every enabled `api_chargeback` instance to
    /// resolve to the same tunables so construction order cannot change
    /// ownership (issue #2564). Currency and namespace are NOT configured here —
    /// they are scoped per [`ChargebackEntry`] so instances on different proxies
    /// with different currencies/namespaces never misattribute one another's
    /// charges (finding #24).
    pub fn configure(
        &self,
        render_cache_ttl_secs: u64,
        stale_entry_ttl_secs: u64,
        cache_invalidation_min_age_ms: u64,
        max_entries: usize,
        max_retained_bytes: usize,
    ) {
        // Budgets are raised or lowered in place. Lowering never deletes
        // already-retained billable state: existing entries keep their
        // reservations and are released by ordinary TTL eviction, while new
        // identities are refused (and folded into the aggregate row) until the
        // counters fall back under the new ceiling.
        self.max_entries
            .store(max_entries.max(1), Ordering::Release);
        self.max_retained_bytes
            .store(max_retained_bytes.max(1), Ordering::Release);
        self.render_cache_ttl_secs
            .store(render_cache_ttl_secs, Ordering::Relaxed);
        self.stale_entry_ttl_nanos.store(
            stale_entry_ttl_secs.saturating_mul(1_000_000_000),
            Ordering::Relaxed,
        );
        self.cache_invalidation_min_age_nanos.store(
            cache_invalidation_min_age_ms.saturating_mul(1_000_000),
            Ordering::Relaxed,
        );
    }

    /// Publish the accepted generation's `/charges` render projection.
    ///
    /// Separate from [`Self::configure`] because it is the only shared knob
    /// whose change must drop the cached document. It runs once per accepted
    /// generation, never on the render path. An inline `schema:` compiles a
    /// fresh `Arc` per instance, so this invalidates whenever a projection is
    /// involved at all rather than trying to prove two compiled schemas
    /// equivalent; the unprojected default path never invalidates. Projection
    /// generation advances with every invalidation so an in-flight
    /// [`Self::render_json`] that snapped the prior schema cannot store its
    /// document back into `json_cache`.
    pub fn configure_render_schema(&self, render_schema: Option<Arc<SummarySchema>>) {
        let had_projection = self.render_schema.load().is_some();
        let has_projection = render_schema.is_some();
        self.render_schema.store(Arc::new(render_schema));
        if had_projection || has_projection {
            self.render_schema_generation.fetch_add(1, Ordering::AcqRel);
            self.json_cache.store(Arc::new(None));
        }
    }

    /// Start or reconfigure the background task that periodically evicts stale
    /// entries. The desired interval is reloadable, including transitions to
    /// and from `0`; `Notify` wakes an existing task so a shorter interval or
    /// disable takes effect without waiting for the previous timer.
    ///
    /// Uses `compare_exchange` to ensure only one cleanup task runs per registry.
    /// Guard with `Handle::try_current()` so `new()` works in non-tokio test contexts.
    pub fn start_cleanup_task(self: &Arc<Self>, interval_seconds: u64) {
        self.cleanup_interval_seconds
            .store(interval_seconds, Ordering::Release);
        self.cleanup_interval_changed.notify_waiters();

        if interval_seconds == 0 && !self.cleanup_task_started.load(Ordering::Acquire) {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return; // No tokio runtime (e.g., unit tests)
        }
        if self
            .cleanup_task_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return; // Already started by another plugin instance
        }
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                // Register before loading so an interval update cannot be lost
                // between observing the value and beginning the wait.
                let interval_changed = registry.cleanup_interval_changed.notified();
                let interval_seconds = registry.cleanup_interval_seconds.load(Ordering::Acquire);
                if interval_seconds == 0 {
                    interval_changed.await;
                    continue;
                }

                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_secs(interval_seconds)) => {
                        // If a simultaneous reload changed the interval, let
                        // the next loop honor it instead of evicting on the old
                        // schedule.
                        if registry.cleanup_interval_seconds.load(Ordering::Acquire)
                            == interval_seconds
                        {
                            let ttl_nanos =
                                registry.stale_entry_ttl_nanos.load(Ordering::Relaxed);
                            registry.evict_stale(ttl_nanos);
                        }
                    }
                    () = interval_changed => {}
                }
            }
        });
    }

    #[doc(hidden)]
    #[allow(dead_code)] // Used by external tests; dead in the separately compiled bin target.
    pub fn cleanup_interval_seconds_for_test(&self) -> u64 {
        self.cleanup_interval_seconds.load(Ordering::Acquire)
    }

    /// Record a chargeable HTTP-family transaction (HTTP/1.1, H2, H3, gRPC,
    /// WebSocket upgrade). Status code is the response status.
    #[allow(dead_code)] // External-test convenience wrapper; production supplies proxy namespace.
    #[allow(clippy::too_many_arguments)]
    pub fn record_http(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_http_in_namespace(
            scope,
            scope.namespace.as_ref(),
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            status_code,
            call_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
        );
    }

    /// `overflow_status_code` is the status the charge is filed under if it
    /// folds into the aggregate overflow row: the billable status for a priced
    /// tier, or [`STREAM_STATUS_SENTINEL`] for a status no tier prices (a
    /// bandwidth-only charge), which keeps the overflow matrix bounded by
    /// configuration (see [`overflow_reservation_matrix`]).
    #[allow(clippy::too_many_arguments)]
    fn record_http_in_namespace(
        &self,
        scope: &InstanceScope,
        proxy_namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        overflow_status_code: u16,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            scope,
            proxy_namespace,
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            overflow_status_code,
            ProtocolFamily::Http,
            call_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            true,
        );
    }

    /// Record a chargeable stream session (TCP, TCP+TLS, UDP, DTLS). Streams
    /// have no HTTP status code; entries are keyed by
    /// `(consumer, proxy_id, ProtocolFamily::Stream)` with the
    /// [`STREAM_STATUS_SENTINEL`].
    #[allow(dead_code)] // External-test convenience wrapper; production supplies proxy namespace.
    #[allow(clippy::too_many_arguments)]
    pub fn record_stream(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        connection_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_stream_in_namespace(
            scope,
            scope.namespace.as_ref(),
            consumer,
            proxy_id,
            proxy_name,
            connection_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_stream_in_namespace(
        &self,
        scope: &InstanceScope,
        proxy_namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        connection_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            scope,
            proxy_namespace,
            consumer,
            proxy_id,
            proxy_name,
            STREAM_STATUS_SENTINEL,
            STREAM_STATUS_SENTINEL,
            ProtocolFamily::Stream,
            connection_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            true,
        );
    }

    #[allow(dead_code)] // External-test convenience wrapper; production supplies proxy namespace.
    #[allow(clippy::too_many_arguments)]
    pub fn record_websocket_bandwidth(
        &self,
        scope: &InstanceScope,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_websocket_bandwidth_in_namespace(
            scope,
            scope.namespace.as_ref(),
            consumer,
            proxy_id,
            proxy_name,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_websocket_bandwidth_in_namespace(
        &self,
        scope: &InstanceScope,
        proxy_namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            scope,
            proxy_namespace,
            consumer,
            proxy_id,
            proxy_name,
            STREAM_STATUS_SENTINEL,
            STREAM_STATUS_SENTINEL,
            ProtocolFamily::Http,
            0.0,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            false,
        );
    }

    /// Shared hot-path implementation behind `record_http` / `record_stream`.
    ///
    /// **Hot-path (cache hit)**: Uses `DashMap::get(&str)` with a thread-local
    /// buffer — one `write!` into a pre-allocated `String`, one DashMap read-lock,
    /// and atomic counter updates. Zero heap allocation.
    ///
    /// **Cold-path (first record per unique combination)**: Clones the per-instance
    /// `Arc<str>` render metadata (consumer/proxy/currency/namespace) and allocates
    /// the owned `String` key and a new `ChargebackEntry`. This runs once per unique
    /// `(consumer, proxy namespace, proxy id, status_code, protocol_family,
    /// currency, prices)` combination. Currency comes from the recording plugin
    /// instance; namespace comes from the matched proxy. Both are part of the
    /// key so global instances and same-id tenant proxies cannot reuse an entry
    /// stamped with another scope. `protocol_family` is part of the key so HTTP-family WebSocket
    /// bandwidth and stream sessions stay distinct even when both use status
    /// `0` and identical prices. `proxy_name` is intentionally omitted from the
    /// key (issue #2572).
    ///
    /// **Admission (GHSA-wxmv-8mwr-92xf)**: the cold path reserves one retained
    /// entry-key slot and its retained bytes against the process-global budget
    /// before publishing a new key. A refusal does not discard the charge — it
    /// is re-recorded under the fixed-cardinality
    /// [`OVERFLOW_CONSUMER_SENTINEL`] row, which keeps every non-identity
    /// dimension (proxy, status, family, currency, namespace, prices) and
    /// therefore preserves the billable totals an operator invoices from.
    /// Per-identity attribution is what is lost when a new row cannot be
    /// admitted. The budget counts complete registry keys, not distinct
    /// principals — one identity across multiple statuses/proxies/prices can
    /// consume many slots.
    #[allow(clippy::too_many_arguments)]
    fn record_inner(
        &self,
        scope: &InstanceScope,
        proxy_namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        overflow_status_code: u16,
        protocol_family: ProtocolFamily,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
        count_call: bool,
    ) {
        // Bound the billing identity collision-resistantly: within the bound
        // this borrows and allocates nothing, and an oversized identity keeps a
        // digest of its complete value so two principals sharing a prefix stay
        // distinct entries (GHSA-m28c-f3v5-26qg). Marker-bearing values —
        // including any identity equal to [`OVERFLOW_CONSUMER_SENTINEL`] — are
        // always digested, so a real principal can never share the internal
        // overflow row's consumer label.
        let consumer = bounded_billing_identity(consumer, MAX_REGISTRY_IDENTITY_BYTES);
        debug_assert_ne!(
            consumer.as_ref(),
            OVERFLOW_CONSUMER_SENTINEL,
            "bounded billing identity must never equal the internal overflow sentinel"
        );
        let proxy_id = bounded_billing_identity(proxy_id, MAX_REGISTRY_IDENTITY_BYTES);
        let proxy_name = bounded_display(proxy_name, MAX_REGISTRY_IDENTITY_BYTES);
        self.record_admitted(
            scope,
            proxy_namespace,
            &consumer,
            &proxy_id,
            proxy_name,
            status_code,
            overflow_status_code,
            protocol_family,
            call_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            count_call,
            true,
        );
    }

    /// Record one charge against an already-bounded identity.
    ///
    /// `identity_admission` is `true` for an ordinary billing row (consumes one
    /// `max_entries` slot) and `false` for the aggregate overflow row.
    /// `overflow_status_code` is the status a refused ordinary row folds under.
    #[allow(clippy::too_many_arguments)]
    fn record_admitted(
        &self,
        scope: &InstanceScope,
        proxy_namespace: &str,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        overflow_status_code: u16,
        protocol_family: ProtocolFamily,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
        count_call: bool,
        identity_admission: bool,
    ) {
        thread_local! {
            static KEY_BUF: std::cell::RefCell<String> =
                std::cell::RefCell::new(String::with_capacity(128));
        }

        // Fast path: build key in thread-local buffer, look up with borrowed &str.
        // DashMap::get takes &Q where String: Borrow<Q>, so &str works directly.
        let hit = KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_chargeback_key(
                &mut buf,
                consumer,
                proxy_namespace,
                proxy_id,
                status_code,
                protocol_family,
                scope,
                EntryPrices {
                    call: call_price,
                    bandwidth_sent: bw_price_sent,
                    bandwidth_received: bw_price_received,
                },
            );

            if let Some(entry) = self.entries.get(buf.as_str()) {
                entry.record(bytes_sent, bytes_received, count_call, self.epoch);
                return true;
            }
            false
        });

        if !hit {
            // Cold path: allocate owned key + metadata for DashMap insertion.
            // Currency comes from the recording instance; namespace comes from
            // the matched proxy so global instances preserve tenant identity.
            // Capacity covers separators, status, protocol_family label
            // ("stream" is longest), three 16-hex price bit fields, and the
            // four length prefixes.
            let mut owned_key = String::with_capacity(
                consumer.len()
                    + proxy_namespace.len()
                    + proxy_id.len()
                    + scope.currency.len()
                    + 158,
            );
            write_chargeback_key(
                &mut owned_key,
                consumer,
                proxy_namespace,
                proxy_id,
                status_code,
                protocol_family,
                scope,
                EntryPrices {
                    call: call_price,
                    bandwidth_sent: bw_price_sent,
                    bandwidth_received: bw_price_received,
                },
            );
            // Reserve the entry-key slot and its retained bytes BEFORE the key is
            // published, so concurrent cold-path inserts can never publish state
            // above the configured ceilings.
            let namespace_label = InstanceScope::namespace_label_for(proxy_namespace);
            let entry_bytes = entry_retained_bytes(
                owned_key.len(),
                consumer.len(),
                proxy_id.len(),
                proxy_namespace.len(),
                proxy_name.len(),
                namespace_label.len(),
                scope,
            );
            let make_entry = || {
                ChargebackEntry::new(
                    self.epoch,
                    Arc::from(consumer),
                    Arc::from(proxy_id),
                    Arc::from(proxy_namespace),
                    Arc::from(proxy_name),
                    status_code,
                    protocol_family,
                    if count_call { call_price } else { 0.0 },
                    bw_price_sent,
                    bw_price_received,
                    Arc::clone(&scope.currency),
                    Arc::from(namespace_label.as_str()),
                    entry_bytes,
                    identity_admission,
                )
            };

            if !identity_admission {
                self.record_new_aggregate_row(
                    owned_key,
                    entry_bytes,
                    make_entry,
                    bytes_sent,
                    bytes_received,
                    count_call,
                );
                self.maybe_invalidate_caches();
                return;
            }

            if !self.try_reserve(entry_bytes, true, 0) {
                // Budget exhausted. Fold the charge into the fixed-cardinality
                // aggregate row rather than losing billable state.
                self.maybe_invalidate_caches();
                self.identity_overflow_total.fetch_add(1, Ordering::Relaxed);
                self.warn_on_admission("entry budget exhausted");
                self.record_admitted(
                    scope,
                    proxy_namespace,
                    OVERFLOW_CONSUMER_SENTINEL,
                    proxy_id,
                    proxy_name,
                    overflow_status_code,
                    overflow_status_code,
                    protocol_family,
                    call_price,
                    bytes_sent,
                    bytes_received,
                    bw_price_sent,
                    bw_price_received,
                    count_call,
                    false,
                );
                return;
            }

            let mut created = false;
            {
                let entry = self.entries.entry(owned_key).or_insert_with(|| {
                    created = true;
                    make_entry()
                });
                entry.record(bytes_sent, bytes_received, count_call, self.epoch);
            }
            if !created {
                // Lost the publish race: the winner owns the single reservation
                // for this key. Release ours exactly once so the budget stays
                // exact.
                self.release_reservation(entry_bytes, true);
            }
        }

        self.maybe_invalidate_caches();
    }

    /// Cold path for an aggregate overflow row that the fast path did not
    /// find.
    ///
    /// **Never waits.** A running eviction pass or reservation publication
    /// holds the retirement lock exclusively for a whole-registry walk, and
    /// the request path must not block behind it. The lock is only TRIED: with
    /// it, a newly created reserved row also moves its bytes out of the
    /// outstanding reserve; without it, the row is still created against its
    /// own reservation, and its bytes simply stay counted as outstanding
    /// (conservatively, protecting more than needed) until the pass that holds
    /// the lock re-derives every reservation flag from the rows that exist.
    ///
    /// The byte reservation is taken under the row's shard lock, so
    /// concurrent first creations of the same aggregate row serialize: the
    /// later ones find the row and record into it instead of each reserving
    /// its bytes speculatively and dropping charges one row would hold.
    fn record_new_aggregate_row(
        &self,
        owned_key: String,
        entry_bytes: usize,
        make_entry: impl FnOnce() -> ChargebackEntry,
        bytes_sent: u64,
        bytes_received: u64,
        count_call: bool,
    ) {
        let reservation_guard = match self.retirement_lock.try_read() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        // A running eviction pass may have unlinked this very row while still
        // holding it and its byte reservation. File the charge with the pass
        // instead of reserving a second copy of the row. Checked before the
        // entries map is touched, so the pass (which finalizes a pending
        // record under its lock and then inserts into the entries map) and
        // this path never wait on each other's locks in opposite order.
        if reservation_guard.is_none()
            && let Some(pending) = self.retiring_aggregates.get(owned_key.as_str())
        {
            pending.record(bytes_sent, bytes_received, count_call, self.epoch);
            return;
        }
        let reservations = self.overflow_reservations.load_full();
        let reserved_slot = reservations.get(owned_key.as_str());
        let own_reserved_bytes = reserved_slot
            .filter(|slot| !slot.present.load(Ordering::Acquire))
            .map_or(0, |slot| slot.bytes);
        let created = match self.entries.entry(owned_key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                occupied
                    .get()
                    .record(bytes_sent, bytes_received, count_call, self.epoch);
                false
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                if !self.try_reserve(entry_bytes, false, own_reserved_bytes) {
                    drop(vacant);
                    self.dropped_charges_total.fetch_add(1, Ordering::Relaxed);
                    self.warn_on_admission("retained-byte budget exhausted");
                    return;
                }
                vacant.insert(make_entry()).record(
                    bytes_sent,
                    bytes_received,
                    count_call,
                    self.epoch,
                );
                true
            }
        };
        if created
            && reservation_guard.is_some()
            && let Some(slot) = reserved_slot
            && slot
                .present
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // The reserved row now exists: its bytes moved from the
            // outstanding reserve into `retained_bytes`.
            saturating_fetch_sub(&self.outstanding_overflow_reserve, slot.bytes);
        }
        drop(reservation_guard);
    }

    /// Re-derive every reservation flag and the outstanding reserve from the
    /// rows that exist. Runs under the exclusive retirement lock at the end of
    /// each eviction pass, which also heals the conservative over-count left
    /// by aggregate rows created while the lock was held elsewhere.
    fn reconcile_overflow_reservations(&self) {
        let reservations = self.overflow_reservations.load_full();
        let mut outstanding = 0usize;
        for (key, slot) in reservations.iter() {
            let present = self.entries.contains_key(key.as_str());
            slot.present.store(present, Ordering::Release);
            if !present {
                outstanding = outstanding.saturating_add(slot.bytes);
            }
        }
        self.outstanding_overflow_reserve
            .store(outstanding, Ordering::Release);
    }

    /// Reserve one entry's retained bytes, and a retained-row slot when the
    /// entry is an ordinary billing row (not the aggregate overflow).
    ///
    /// Aggregate overflow rows deliberately skip the `max_entries` ceiling:
    /// their cardinality is bounded by configuration (proxy × status × protocol
    /// family × currency/namespace × price set), not by attacker-selectable
    /// principals. They still reserve bytes, so the retained-byte ceiling stays
    /// a hard bound on total registry footprint.
    ///
    /// Bytes reserved for the accepted configuration's overflow matrix are
    /// protected: an ordinary row may not use the outstanding reserve of
    /// overflow rows that do not exist yet, nor the one-matrix headroom kept
    /// for the next pricing generation; an aggregate row may use everything
    /// except the outstanding reserve of OTHER reserved rows
    /// (`own_reserved_bytes` is its own still-absent reservation). Without this,
    /// ordinary rows could fill the budget and leave no room for the overflow
    /// row a later refused identity folds into, turning a refusal into a
    /// dropped charge.
    fn try_reserve(
        &self,
        entry_bytes: usize,
        identity_admission: bool,
        own_reserved_bytes: usize,
    ) -> bool {
        if identity_admission {
            let max_entries = self.max_entries.load(Ordering::Acquire);
            if self
                .reserved_entries
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < max_entries).then_some(count + 1)
                })
                .is_err()
            {
                return false;
            }
        }
        let outstanding = self.outstanding_overflow_reserve.load(Ordering::Acquire);
        let protected = if identity_admission {
            outstanding.saturating_add(self.overflow_reserve_headroom.load(Ordering::Acquire))
        } else {
            outstanding.saturating_sub(own_reserved_bytes)
        };
        let max_bytes = self
            .max_retained_bytes
            .load(Ordering::Acquire)
            .saturating_sub(protected);
        let reserved = self
            .retained_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let next = used.checked_add(entry_bytes)?;
                (next <= max_bytes).then_some(next)
            })
            .is_ok();
        if !reserved && identity_admission {
            self.reserved_entries.fetch_sub(1, Ordering::AcqRel);
        }
        reserved
    }

    /// Release a reservation taken by [`Self::try_reserve`].
    fn release_reservation(&self, entry_bytes: usize, identity_admission: bool) {
        if identity_admission {
            self.reserved_entries.fetch_sub(1, Ordering::AcqRel);
        }
        self.retained_bytes.fetch_sub(entry_bytes, Ordering::AcqRel);
    }

    /// Log at most one admission warning per
    /// [`ADMISSION_WARN_INTERVAL_NANOS`]. The message carries no identity, only
    /// the fixed reason and the current budget occupancy.
    fn warn_on_admission(&self, reason: &'static str) {
        let now = self.epoch.elapsed().as_nanos() as u64;
        let last = self.last_admission_warn_at.load(Ordering::Relaxed);
        if (last != NO_ADMISSION_WARN_NANOS
            && now.saturating_sub(last) < ADMISSION_WARN_INTERVAL_NANOS)
            || self
                .last_admission_warn_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        tracing::warn!(
            plugin = "api_chargeback",
            reason,
            entries = self.reserved_entries.load(Ordering::Relaxed),
            max_entries = self.max_entries.load(Ordering::Relaxed),
            retained_bytes = self.retained_bytes.load(Ordering::Relaxed),
            max_retained_bytes = self.max_retained_bytes.load(Ordering::Relaxed),
            "api_chargeback registry admission budget reached; charges are being aggregated under the overflow row"
        );
    }

    /// Billing rows (complete registry entry keys) currently reserved against
    /// `max_entries`.
    #[doc(hidden)]
    #[allow(dead_code)] // asserted by external adversarial tests
    pub fn reserved_entries_for_tests(&self) -> usize {
        self.reserved_entries.load(Ordering::Acquire)
    }

    /// Bytes currently reserved across ordinary and aggregate rows.
    #[doc(hidden)]
    #[allow(dead_code)] // asserted by external adversarial tests
    pub fn retained_bytes_for_tests(&self) -> usize {
        self.retained_bytes.load(Ordering::Acquire)
    }

    /// Configured retained-row ceiling. Lifecycle tests assert that construction
    /// leaves it untouched and only an accepted generation publishes it.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn max_entries_for_test(&self) -> usize {
        self.max_entries.load(Ordering::Acquire)
    }

    /// Configured retained-byte ceiling.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn max_retained_bytes_for_test(&self) -> usize {
        self.max_retained_bytes.load(Ordering::Acquire)
    }

    /// Shard count the entry map was built with.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn shard_amount_for_tests(&self) -> usize {
        self.shard_amount
    }

    /// Current proxy-metadata generation carried by render caches.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn proxy_metadata_generation_for_tests(&self) -> u64 {
        self.proxy_metadata_generation.load(Ordering::Acquire)
    }

    /// Current `/charges` projection generation carried by the JSON cache.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn render_schema_generation_for_tests(&self) -> u64 {
        self.render_schema_generation.load(Ordering::Acquire)
    }

    /// Attempt to publish a JSON document into the render cache under the given
    /// generation tags. Returns whether the store was accepted.
    ///
    /// Mirrors the generation-guarded store path in [`Self::render_json`] so
    /// tests can prove a render started under a prior schema cannot repopulate
    /// the cache after a schema transition without relying on timing sleeps.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn try_store_json_cache_for_tests(
        &self,
        metadata_generation: u64,
        schema_generation: u64,
        output: String,
    ) -> bool {
        if self.proxy_metadata_generation.load(Ordering::Acquire) != metadata_generation
            || self.render_schema_generation.load(Ordering::Acquire) != schema_generation
        {
            return false;
        }
        self.json_cache.store(Arc::new(Some(CachedJsonRender {
            generated_at: Instant::now(),
            metadata_generation,
            schema_generation,
            // An arbitrary test document proves nothing was collected.
            receipt: CollectionReceipt {
                walk_started_nanos: 0,
            },
            output,
        })));
        if self.proxy_metadata_generation.load(Ordering::Acquire) == metadata_generation
            && self.render_schema_generation.load(Ordering::Acquire) == schema_generation
        {
            true
        } else {
            self.json_cache.store(Arc::new(None));
            false
        }
    }

    /// Invalidate each render cache that has reached the configured minimum
    /// age, evaluating the two formats independently (issue #5238).
    ///
    /// `cache_invalidation_min_age_ms` is a per-document protection: a `/charges`
    /// collector must be able to re-read the document it just fetched without a
    /// concurrent billed request forcing a full registry walk. Judging both
    /// caches by the Prometheus timestamp alone made that protection depend on
    /// whether some *other* collector happened to scrape the *other* format —
    /// a JSON-only deployment (no Prometheus cache at all) invalidated a
    /// brand-new JSON document on the very next recorded request.
    ///
    /// An already-empty cache is left alone rather than restamped with a fresh
    /// `Arc::new(None)`, so the common recording path allocates nothing.
    fn maybe_invalidate_caches(&self) {
        let min_age_nanos = self
            .cache_invalidation_min_age_nanos
            .load(Ordering::Relaxed);

        let prometheus_at = {
            let cached = self.prometheus_cache.load();
            (**cached).as_ref().map(|cache| cache.generated_at)
        };
        if render_cache_reached_min_age(prometheus_at, min_age_nanos) {
            self.prometheus_cache.store(Arc::new(None));
        }

        let json_at = {
            let cached = self.json_cache.load();
            (**cached).as_ref().map(|cache| cache.generated_at)
        };
        if render_cache_reached_min_age(json_at, min_age_nanos) {
            self.json_cache.store(Arc::new(None));
        }
    }

    /// Snapshot the instant a `/charges` export is about to start walking the
    /// registry. Pair with [`Self::acknowledge_collection`].
    fn begin_collection(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// Record that a `/charges` document was delivered (issue #5276).
    ///
    /// Called by the admin `/charges` handler once the admin connection has
    /// taken the complete response body (see [`ChargesDeliveryAck`]), or
    /// directly by [`Self::render_json`] / [`Self::render_prometheus`] for
    /// in-process callers that consume the returned document themselves. A
    /// failed render produces no receipt, and a scrape abandoned before its
    /// body is taken acknowledges nothing.
    ///
    /// **Two deliveries confirm collection.** Hyper exposes no per-response
    /// signal that a body reached the peer: it takes a `Full` body before HTTP/2
    /// flow-control capacity is granted and before an HTTP/1 write is flushed,
    /// so one acknowledged document may still never arrive. A row therefore
    /// becomes evictable only once its current counters were in two delivered
    /// documents — the confirmed watermark is the earlier walk start of the two
    /// most recent deliveries (two deliveries of one cached document count, as
    /// two hand-offs of the same counters). A single failed delivery can never
    /// authorize deletion. Each receipt's walk start is taken BEFORE its walk,
    /// so a charge recorded mid-walk stays uncollected. Out-of-order deliveries
    /// keep the confirmed watermark monotonic.
    pub fn acknowledge_collection(&self, receipt: CollectionReceipt) {
        let mut latest = self
            .latest_acknowledged_walk_nanos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let confirmed = (*latest).min(receipt.walk_started_nanos);
        *latest = (*latest).max(receipt.walk_started_nanos);
        self.collection_watermark_nanos
            .fetch_max(confirmed, Ordering::Release);
    }

    /// Evict entries idle for at least `ttl_nanos` **whose counters two
    /// delivered `/charges` exports have already collected**.
    ///
    /// Idle age alone is not a safe deletion trigger for a billing ledger: the
    /// in-memory registry is authoritative for `/charges`, and dropping an entry
    /// that no export ever observed destroys billable state with no record that
    /// it existed (issue #5276). An idle entry whose last update postdates the
    /// registry's confirmed collection watermark is therefore retained until
    /// exports collect it, and counted into `uncollected_retained_entries` so
    /// the condition is observable.
    ///
    /// This does not weaken the registry's memory bound: retained rows still
    /// hold their `max_entries` / `max_retained_bytes` reservations, and a
    /// registry at either ceiling folds further new rows into the
    /// fixed-cardinality aggregate overflow row exactly as before.
    ///
    /// **Eviction is all-or-nothing per exported series group.** Several
    /// internal rows (one per billable status and pricing generation) sum into
    /// one exported Prometheus counter and one JSON proxy row. Removing only the
    /// idle members of such a group would make a live cumulative counter
    /// decrease, which `increase()` / `rate()` read as a reset and re-count the
    /// surviving history as new usage. A group of rows sharing `(consumer, proxy
    /// namespace, proxy id, currency)` is therefore retired only as a whole:
    ///
    /// 1. candidate groups are those whose every member is idle and collected;
    /// 2. each candidate member is removed only if it is STILL evictable under
    ///    its shard lock (a record racing the pass either lands before the
    ///    removal, making the check fail, or after it, as a fresh row);
    /// 3. a group whose member was refreshed, or which gained any row while
    ///    its members were being removed, is revived: every removed member is
    ///    put back (merged into a fresh row for the same key, if one appeared).
    ///
    /// The whole pass holds the retirement lock exclusively, so no `/charges`
    /// walk observes a group between removal and restoration. A record that
    /// lands after the pass finishes starts a new series for a group that has
    /// been retired completely.
    pub fn evict_stale(&self, ttl_nanos: u64) -> usize {
        self.evict_stale_with(ttl_nanos, || {}, || {})
    }

    /// [`Self::evict_stale`] with callbacks run after candidate selection and
    /// after candidate removal, so tests can interleave a record with a pass
    /// deterministically. A callback may record onto existing rows or create
    /// new ones, including aggregate overflow rows: their creation only tries
    /// the retirement lock this pass holds, so it proceeds without waiting.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn evict_stale_interleaved_for_tests(
        &self,
        ttl_nanos: u64,
        after_selection: impl FnOnce(),
        after_removal: impl FnOnce(),
    ) -> usize {
        self.evict_stale_with(ttl_nanos, after_selection, after_removal)
    }

    fn evict_stale_with(
        &self,
        ttl_nanos: u64,
        after_selection: impl FnOnce(),
        after_removal: impl FnOnce(),
    ) -> usize {
        let _retiring = self
            .retirement_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let collected_before = self.collection_watermark_nanos.load(Ordering::Acquire);
        let evictable = |v: &ChargebackEntry| {
            v.nanos_since_update(self.epoch) >= ttl_nanos
                && v.last_updated.load(Ordering::Relaxed) < collected_before
        };

        // Pass 1: find the series groups that must stay because at least one
        // member is still active or holds uncollected counters.
        let mut uncollected = 0;
        let mut retained_groups: HashSet<EvictionGroupKey> = HashSet::new();
        // (group, key, whether the row is an aggregate overflow row)
        let mut candidates: Vec<(EvictionGroupKey, String, bool)> = Vec::new();
        for entry in self.entries.iter() {
            let v = entry.value();
            if evictable(v) {
                candidates.push((
                    eviction_group_key(v),
                    entry.key().clone(),
                    !v.counts_against_identity_budget,
                ));
                continue;
            }
            if v.nanos_since_update(self.epoch) >= ttl_nanos {
                // Idle, but its current counters have not been confirmed
                // collected. Deleting it would silently discard charges.
                uncollected += 1;
            }
            retained_groups.insert(eviction_group_key(v));
        }
        self.uncollected_retained_entries
            .store(uncollected, Ordering::Relaxed);
        candidates.retain(|(group, _, _)| !retained_groups.contains(group));
        if candidates.is_empty() {
            self.reconcile_overflow_reservations();
            return 0;
        }
        after_selection();

        // Pass 2: remove every member of every candidate group, rechecking
        // each under its shard lock.
        let mut revived: HashSet<EvictionGroupKey> = HashSet::new();
        let mut removed: Vec<(EvictionGroupKey, String, ChargebackEntry)> = Vec::new();
        for (group, key, aggregate) in candidates {
            if aggregate {
                // Published BEFORE the row is unlinked: a recorder that misses
                // the row afterwards finds this and files its charge here
                // rather than reserving a second copy of a row this pass still
                // holds (PR #6842).
                self.retiring_aggregates
                    .insert(key.clone(), PendingAggregateCharges::default());
            }
            match self.entries.remove_if(key.as_str(), |_, v| evictable(v)) {
                Some((key, entry)) => removed.push((group, key, entry)),
                None => {
                    if aggregate {
                        self.retiring_aggregates.remove(key.as_str());
                    }
                    revived.insert(group);
                }
            }
        }

        after_removal();

        // Pass 3: a removed group that now has any row (a refreshed member or a
        // row created during pass 2), or whose unlinked aggregate row received
        // a charge, is live and must not shrink.
        let removed_groups: HashSet<EvictionGroupKey> =
            removed.iter().map(|(group, _, _)| group.clone()).collect();
        for entry in self.entries.iter() {
            let group = eviction_group_key(entry.value());
            if removed_groups.contains(&group) {
                revived.insert(group);
            }
        }
        for (group, key, entry) in &removed {
            if !entry.counts_against_identity_budget
                && self
                    .retiring_aggregates
                    .get(key.as_str())
                    .is_some_and(|pending| pending.has_activity())
            {
                revived.insert(group.clone());
            }
        }

        let mut evicted = 0;
        for (group, key, entry) in removed {
            let revive = revived.contains(&group);
            if !entry.counts_against_identity_budget {
                if self.finalize_removed_aggregate(key, entry, revive) {
                    evicted += 1;
                }
                continue;
            }
            if revive {
                self.restore_entry(key, entry);
                continue;
            }
            evicted += 1;
            // Release the retired entry's reservation so capacity recovers
            // exactly.
            self.release_reservation(entry.retained_bytes, entry.counts_against_identity_budget);
        }
        // A retired reserved overflow row returns its bytes to the outstanding
        // reserve; rows created during the pass are counted as present.
        self.reconcile_overflow_reservations();
        if evicted > 0 {
            self.prometheus_cache.store(Arc::new(None));
            self.json_cache.store(Arc::new(None));
        }
        evicted
    }

    /// Restore or retire an aggregate overflow row the pass unlinked, folding
    /// in any charge recorded onto it meanwhile. Returns whether the row's
    /// previous counters were retired.
    ///
    /// Runs while holding the row's pending record exclusively, so no recorder
    /// can file another charge into it; once the pending record is gone a
    /// recorder finds the restored (or successor) row, or — if the row was
    /// retired with nothing pending — a released reservation it can reuse.
    fn finalize_removed_aggregate(
        &self,
        key: String,
        entry: ChargebackEntry,
        revive: bool,
    ) -> bool {
        let mut removed_entry = Some(entry);
        let mut retired = true;
        self.retiring_aggregates
            .remove_if(key.as_str(), |_, pending| {
                if let Some(entry) = removed_entry.take() {
                    retired = self.settle_removed_aggregate(&key, entry, pending, revive);
                }
                true
            });
        if let Some(entry) = removed_entry.take() {
            // No pending record (it is published before the row is unlinked,
            // so this is only reached defensively): nothing was filed.
            retired = self.settle_removed_aggregate(
                &key,
                entry,
                &PendingAggregateCharges::default(),
                revive,
            );
        }
        retired
    }

    fn settle_removed_aggregate(
        &self,
        key: &str,
        entry: ChargebackEntry,
        pending: &PendingAggregateCharges,
        revive: bool,
    ) -> bool {
        if revive {
            self.restore_entry(key.to_string(), entry);
            if pending.has_activity()
                && let Some(live) = self.entries.get(key)
            {
                pending.merge_into(&live);
            }
            return false;
        }
        if !pending.has_activity() {
            self.release_reservation(entry.retained_bytes, entry.counts_against_identity_budget);
            return true;
        }
        // The group retired as a whole; charges filed after it was decided
        // start a new series in a successor row that inherits the retired
        // row's byte reservation, so they need no second reservation.
        match self.entries.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                pending.merge_into(occupied.get());
                drop(occupied);
                self.release_reservation(
                    entry.retained_bytes,
                    entry.counts_against_identity_budget,
                );
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let successor = entry.successor(self.epoch);
                pending.merge_into(&successor);
                vacant.insert(successor);
            }
        }
        true
    }

    /// Put back a member removed by [`Self::evict_stale`] whose group was
    /// revived. If a fresh row for the same key appeared meanwhile, the
    /// removed counters are merged into it and the removed copy's reservation
    /// is released (the fresh row holds its own).
    fn restore_entry(&self, key: String, entry: ChargebackEntry) {
        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let live = occupied.get();
                live.call_count
                    .fetch_add(entry.call_count.load(Ordering::Relaxed), Ordering::Relaxed);
                live.bytes_sent_total.fetch_add(
                    entry.bytes_sent_total.load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                live.bytes_received_total.fetch_add(
                    entry.bytes_received_total.load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                live.publish_timestamp(entry.last_updated.load(Ordering::Relaxed));
                drop(occupied);
                self.release_reservation(
                    entry.retained_bytes,
                    entry.counts_against_identity_budget,
                );
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(entry);
            }
        }
    }

    /// Count one completed registry walk of a cached render loop. The test
    /// hook models a reload that invalidates every walk.
    fn note_render_walk(&self) {
        self.render_walks.fetch_add(1, Ordering::Relaxed);
        if self.invalidate_every_render_walk.load(Ordering::Relaxed) {
            self.proxy_metadata_generation
                .fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Registry walks `/charges` render loops have performed.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn render_walks_for_tests(&self) -> usize {
        self.render_walks.load(Ordering::Relaxed)
    }

    /// Make every subsequent render walk advance the proxy-metadata
    /// generation, as a reload that keeps racing the render would.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn invalidate_every_render_walk_for_tests(&self, enabled: bool) {
        self.invalidate_every_render_walk
            .store(enabled, Ordering::Relaxed);
    }

    /// Render in Prometheus exposition format with caching, acknowledging
    /// collection immediately.
    ///
    /// For in-process callers that consume the returned document themselves.
    /// The admin `/charges` endpoint uses [`Self::render_prometheus_pending`]
    /// and acknowledges only after delivery.
    ///
    /// Returns `Err` when any monetary sample would be non-finite; callers must
    /// surface that as an explicit export failure rather than emitting `inf`.
    pub fn render_prometheus(&self) -> Result<String, String> {
        let (output, receipt) = self.render_prometheus_pending()?;
        self.acknowledge_collection(receipt);
        Ok(output)
    }

    /// Render in Prometheus exposition format with caching, returning the
    /// document and its not-yet-acknowledged [`CollectionReceipt`].
    ///
    /// Pass the receipt to [`Self::acknowledge_collection`] only once the
    /// document has been delivered (issue #5276). A cache hit returns the
    /// receipt of the walk that produced the cached document.
    ///
    /// A reload that keeps advancing the proxy-metadata generation during the
    /// walk is retried at most [`MAX_RENDER_ATTEMPTS`] times; the last document
    /// is then returned without being cached. Its counters are complete for its
    /// walk — only the display-name snapshot may be one generation old — so its
    /// receipt is still valid.
    pub fn render_prometheus_pending(&self) -> Result<(String, CollectionReceipt), String> {
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let metadata_generation = self.proxy_metadata_generation.load(Ordering::Acquire);
        {
            let cached = self.prometheus_cache.load();
            if let Some(cache) = (**cached).as_ref()
                && cache.metadata_generation == metadata_generation
                && cache.generated_at.elapsed().as_secs() < ttl_secs
            {
                return Ok((cache.output.clone(), cache.receipt));
            }
        }

        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        // Snapshot before the first walk. The receipt is only handed out with
        // a produced document: an export that errors out acknowledges nothing.
        let receipt = CollectionReceipt {
            walk_started_nanos: self.begin_collection(),
        };
        let mut attempt = 1;
        loop {
            let metadata_generation = self.proxy_metadata_generation.load(Ordering::Acquire);
            let output = self.render_prometheus_uncached()?;
            self.note_render_walk();
            if self.proxy_metadata_generation.load(Ordering::Acquire) == metadata_generation {
                self.prometheus_cache
                    .store(Arc::new(Some(CachedPrometheusRender {
                        generated_at: Instant::now(),
                        metadata_generation,
                        receipt,
                        output: output.clone(),
                    })));
                if self.proxy_metadata_generation.load(Ordering::Acquire) == metadata_generation {
                    return Ok((output, receipt));
                }
                self.prometheus_cache.store(Arc::new(None));
            }
            if attempt >= MAX_RENDER_ATTEMPTS {
                return Ok((output, receipt));
            }
            attempt += 1;
        }
    }

    pub fn render_prometheus_uncached(&self) -> Result<String, String> {
        // Shared with other walks; excludes an eviction pass so the document
        // never shows a series group mid-retirement.
        let _walking = self
            .retirement_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Multiple counter families × ~200 bytes per entry
        let estimated_cap = 1024 + self.entries.len() * 600;
        let mut output = String::with_capacity(estimated_cap);
        let active_proxy_names = self.active_proxy_names.load();

        // --- Per-call metrics (HTTP entries only — streams have no status code) ---
        struct ChargeAggregate {
            proxy_name: String,
            currency: Arc<str>,
            namespace_label: Arc<str>,
            count: u64,
            charges: f64,
        }

        // Entries are keyed by pricing bits so config reloads do not reuse
        // stale prices, but Prometheus label sets intentionally omit those
        // bits (and omit `proxy_name` from the aggregation key) so a name-only
        // reload preserves registry counter continuity. Aggregate by the billing
        // identity before rendering and take live display metadata from the
        // published configuration snapshot (issue #2572).
        let mut http_aggregates: HashMap<HttpChargeAggregateKey, ChargeAggregate> = HashMap::new();
        let mut stream_aggregates: HashMap<StreamChargeAggregateKey, ChargeAggregate> =
            HashMap::new();

        for entry in self.entries.iter() {
            let v = entry.value();
            let proxy_name = active_proxy_names
                .get(v.proxy_namespace.as_ref())
                .and_then(|namespace| namespace.get(v.proxy_id.as_ref()))
                .map(String::as_str)
                .unwrap_or(v.proxy_name.as_ref());
            match v.protocol_family {
                ProtocolFamily::Http => {
                    let agg = http_aggregates
                        .entry((
                            v.consumer.to_string(),
                            v.proxy_id.to_string(),
                            v.status_code,
                            Arc::clone(&v.currency),
                            Arc::clone(&v.namespace_label),
                        ))
                        .or_insert_with(|| ChargeAggregate {
                            proxy_name: proxy_name.to_string(),
                            currency: Arc::clone(&v.currency),
                            namespace_label: Arc::clone(&v.namespace_label),
                            count: 0,
                            charges: 0.0,
                        });
                    apply_export_proxy_name(&mut agg.proxy_name, proxy_name);
                    agg.count += v.call_count.load(Ordering::Relaxed);
                    agg.charges = checked_add_charge(agg.charges, v.call_charge()?)?;
                }
                ProtocolFamily::Stream => {
                    let agg = stream_aggregates
                        .entry((
                            v.consumer.to_string(),
                            v.proxy_id.to_string(),
                            Arc::clone(&v.currency),
                            Arc::clone(&v.namespace_label),
                        ))
                        .or_insert_with(|| ChargeAggregate {
                            proxy_name: proxy_name.to_string(),
                            currency: Arc::clone(&v.currency),
                            namespace_label: Arc::clone(&v.namespace_label),
                            count: 0,
                            charges: 0.0,
                        });
                    apply_export_proxy_name(&mut agg.proxy_name, proxy_name);
                    agg.count += v.call_count.load(Ordering::Relaxed);
                    agg.charges = checked_add_charge(agg.charges, v.call_charge()?)?;
                }
            }
        }

        output.push_str(
            "# HELP ferrum_api_chargeable_calls_total Total chargeable HTTP-family API calls per consumer by billable status.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeable_calls_total counter\n");
        for ((consumer, proxy_id, status_code, _, _), agg) in &http_aggregates {
            output.push_str(&format!(
                "ferrum_api_chargeable_calls_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\",currency=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                status_code,
                escape_label_value(&agg.currency),
                agg.namespace_label,
                agg.count
            ));
        }

        output.push_str(
            "# HELP ferrum_api_charges_total Total per-call charges accumulated per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_charges_total counter\n");
        for ((consumer, proxy_id, status_code, _, _), agg) in &http_aggregates {
            let charges = require_finite_charge(agg.charges, "ferrum_api_charges_total")?;
            output.push_str(&format!(
                "ferrum_api_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\",currency=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                status_code,
                escape_label_value(&agg.currency),
                agg.namespace_label,
                charges
            ));
        }

        // --- Stream connection metrics (stream entries only) ---

        output.push_str(
            "# HELP ferrum_api_stream_connections_total Total stream sessions (TCP/UDP/DTLS) per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_stream_connections_total counter\n");
        for ((consumer, proxy_id, _, _), agg) in &stream_aggregates {
            output.push_str(&format!(
                "ferrum_api_stream_connections_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                agg.namespace_label,
                agg.count
            ));
        }

        output.push_str(
            "# HELP ferrum_api_stream_connection_charges_total Total per-connection charges for stream sessions.\n",
        );
        output.push_str("# TYPE ferrum_api_stream_connection_charges_total counter\n");
        for ((consumer, proxy_id, _, _), agg) in &stream_aggregates {
            let charges =
                require_finite_charge(agg.charges, "ferrum_api_stream_connection_charges_total")?;
            output.push_str(&format!(
                "ferrum_api_stream_connection_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                agg.namespace_label,
                charges
            ));
        }

        // --- Bandwidth metrics. Aggregated per (consumer, proxy_id,
        //     protocol_family, currency, namespace) so HTTP entries spread
        //     across status codes collapse to one row per direction, while
        //     HTTP/stream and distinct billing scopes under the same proxy_id
        //     stay on separate, deterministically labeled rows.
        struct BandwidthAggregate {
            proxy_name: String,
            currency: Arc<str>,
            namespace_label: Arc<str>,
            bytes_sent: u64,
            bytes_received: u64,
            charge_sent: f64,
            charge_received: f64,
        }

        let mut bw_aggregates: HashMap<BandwidthAggregateKey, BandwidthAggregate> = HashMap::new();
        for entry in self.entries.iter() {
            let v = entry.value();
            let proxy_name = active_proxy_names
                .get(v.proxy_namespace.as_ref())
                .and_then(|namespace| namespace.get(v.proxy_id.as_ref()))
                .map(String::as_str)
                .unwrap_or(v.proxy_name.as_ref());
            let agg = bw_aggregates
                .entry((
                    v.consumer.to_string(),
                    v.proxy_id.to_string(),
                    v.protocol_family,
                    Arc::clone(&v.currency),
                    Arc::clone(&v.namespace_label),
                ))
                .or_insert_with(|| BandwidthAggregate {
                    proxy_name: proxy_name.to_string(),
                    currency: Arc::clone(&v.currency),
                    namespace_label: Arc::clone(&v.namespace_label),
                    bytes_sent: 0,
                    bytes_received: 0,
                    charge_sent: 0.0,
                    charge_received: 0.0,
                });
            apply_export_proxy_name(&mut agg.proxy_name, proxy_name);
            agg.bytes_sent += v.bytes_sent_total.load(Ordering::Relaxed);
            agg.bytes_received += v.bytes_received_total.load(Ordering::Relaxed);
            agg.charge_sent = checked_add_charge(agg.charge_sent, v.bandwidth_charge_sent()?)?;
            agg.charge_received =
                checked_add_charge(agg.charge_received, v.bandwidth_charge_received()?)?;
        }

        output.push_str(
            "# HELP ferrum_api_bytes_sent_total Total bytes the gateway sent client->backend on this consumer's behalf.\n",
        );
        output.push_str("# TYPE ferrum_api_bytes_sent_total counter\n");
        for ((consumer, proxy_id, family, _, _), agg) in &bw_aggregates {
            output.push_str(&format!(
                "ferrum_api_bytes_sent_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\",protocol_family=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                agg.bytes_sent
            ));
        }

        output.push_str(
            "# HELP ferrum_api_bytes_received_total Total bytes the gateway received backend->client and forwarded to this consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_bytes_received_total counter\n");
        for ((consumer, proxy_id, family, _, _), agg) in &bw_aggregates {
            output.push_str(&format!(
                "ferrum_api_bytes_received_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\",protocol_family=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                agg.bytes_received
            ));
        }

        output.push_str(
            "# HELP ferrum_api_bandwidth_charges_total Total bandwidth charges per consumer, split by direction.\n",
        );
        output.push_str("# TYPE ferrum_api_bandwidth_charges_total counter\n");
        for ((consumer, proxy_id, family, _, _), agg) in &bw_aggregates {
            let charge_sent =
                require_finite_charge(agg.charge_sent, "ferrum_api_bandwidth_charges_total")?;
            let charge_received =
                require_finite_charge(agg.charge_received, "ferrum_api_bandwidth_charges_total")?;
            output.push_str(&format!(
                "ferrum_api_bandwidth_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",direction=\"sent\",currency=\"{}\",protocol_family=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                charge_sent
            ));
            output.push_str(&format!(
                "ferrum_api_bandwidth_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",direction=\"received\",currency=\"{}\",protocol_family=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&agg.currency),
                family.label(),
                agg.namespace_label,
                charge_received
            ));
        }

        // --- Registry saturation. Fixed cardinality and identity-free, so an
        //     operator can alert on admission pressure without the diagnostics
        //     themselves becoming an exhaustion vector.
        output.push_str(
            "# HELP ferrum_api_chargeback_registry_entries Billing rows (complete registry entry keys) currently retained against max_entries.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_registry_entries gauge\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_registry_entries {}\n",
            self.reserved_entries.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP ferrum_api_chargeback_registry_max_entries Configured ceiling on retained billing rows (complete registry entry keys).\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_registry_max_entries gauge\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_registry_max_entries {}\n",
            self.max_entries.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP ferrum_api_chargeback_registry_retained_bytes Estimated bytes retained by the shared registry.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_registry_retained_bytes gauge\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_registry_retained_bytes {}\n",
            self.retained_bytes.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP ferrum_api_chargeback_registry_max_retained_bytes Configured ceiling on retained registry bytes.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_registry_max_retained_bytes gauge\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_registry_max_retained_bytes {}\n",
            self.max_retained_bytes.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP ferrum_api_chargeback_identity_overflow_total Charges folded into the aggregate overflow row because a new billing row could not be admitted under max_entries (per-identity attribution lost).\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_identity_overflow_total counter\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_identity_overflow_total {}\n",
            self.identity_overflow_total.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP ferrum_api_chargeback_dropped_charges_total Charges lost because neither an ordinary billing row nor the aggregate row could be admitted.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_dropped_charges_total counter\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_dropped_charges_total {}\n",
            self.dropped_charges_total.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP ferrum_api_chargeback_uncollected_retained_entries Billing rows the last eviction pass kept past stale_entry_ttl_seconds because no completed /charges export has collected their current counters.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeback_uncollected_retained_entries gauge\n");
        output.push_str(&format!(
            "ferrum_api_chargeback_uncollected_retained_entries {}\n",
            self.uncollected_retained_entries.load(Ordering::Relaxed)
        ));

        Ok(output)
    }

    /// Fixed-cardinality registry saturation snapshot shared by the JSON
    /// renderer and the status surfaces. Contains no identity values.
    fn registry_status(&self) -> serde_json::Value {
        serde_json::json!({
            "entries": self.reserved_entries.load(Ordering::Relaxed),
            "max_entries": self.max_entries.load(Ordering::Relaxed),
            "retained_bytes": self.retained_bytes.load(Ordering::Relaxed),
            "max_retained_bytes": self.max_retained_bytes.load(Ordering::Relaxed),
            "identity_overflow_total": self.identity_overflow_total.load(Ordering::Relaxed),
            "dropped_charges_total": self.dropped_charges_total.load(Ordering::Relaxed),
            "uncollected_retained_entries": self
                .uncollected_retained_entries
                .load(Ordering::Relaxed),
            "overflow_consumer_id": OVERFLOW_CONSUMER_SENTINEL,
        })
    }

    /// Render as JSON with caching, acknowledging collection immediately.
    ///
    /// For in-process callers that consume the returned document themselves.
    /// The admin `/charges` endpoint uses [`Self::render_json_pending`] and
    /// acknowledges only after delivery.
    ///
    /// Returns `Err` when any monetary field would be non-finite; callers must
    /// return an explicit error response rather than serializing JSON `null`.
    pub fn render_json(&self) -> Result<String, String> {
        let (output, receipt) = self.render_json_pending()?;
        self.acknowledge_collection(receipt);
        Ok(output)
    }

    /// Render as JSON with caching, returning the document and its
    /// not-yet-acknowledged [`CollectionReceipt`] (issue #5276).
    ///
    /// Cached documents are tagged with both proxy-metadata and projection
    /// generations. A render that snapped a prior schema (or prior proxy-name
    /// snapshot) can never repopulate the cache after those generations advance.
    /// Like [`Self::render_prometheus_pending`], a walk invalidated by a
    /// concurrent generation change is retried at most [`MAX_RENDER_ATTEMPTS`]
    /// times and the last document is then returned uncached. Each document
    /// still uses one schema snapshot throughout.
    pub fn render_json_pending(&self) -> Result<(String, CollectionReceipt), String> {
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let metadata_generation = self.proxy_metadata_generation.load(Ordering::Acquire);
        let schema_generation = self.render_schema_generation.load(Ordering::Acquire);
        {
            let cached = self.json_cache.load();
            if let Some(cache) = (**cached).as_ref()
                && cache.metadata_generation == metadata_generation
                && cache.schema_generation == schema_generation
                && cache.generated_at.elapsed().as_secs() < ttl_secs
            {
                return Ok((cache.output.clone(), cache.receipt));
            }
        }

        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        // Same collection contract as the Prometheus export (issue #5276):
        // snapshot before the walk, hand the receipt out only with a document.
        let receipt = CollectionReceipt {
            walk_started_nanos: self.begin_collection(),
        };
        let mut attempt = 1;
        loop {
            let metadata_generation = self.proxy_metadata_generation.load(Ordering::Acquire);
            let schema_generation = self.render_schema_generation.load(Ordering::Acquire);
            let output = self.render_json_uncached()?;
            self.note_render_walk();
            let generations_unchanged = || {
                self.proxy_metadata_generation.load(Ordering::Acquire) == metadata_generation
                    && self.render_schema_generation.load(Ordering::Acquire) == schema_generation
            };
            if generations_unchanged() {
                self.json_cache.store(Arc::new(Some(CachedJsonRender {
                    generated_at: Instant::now(),
                    metadata_generation,
                    schema_generation,
                    receipt,
                    output: output.clone(),
                })));
                if generations_unchanged() {
                    return Ok((output, receipt));
                }
                self.json_cache.store(Arc::new(None));
            }
            if attempt >= MAX_RENDER_ATTEMPTS {
                return Ok((output, receipt));
            }
            attempt += 1;
        }
    }

    pub fn render_json_uncached(&self) -> Result<String, String> {
        // See `render_prometheus_uncached`.
        let _walking = self
            .retirement_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active_proxy_names = self.active_proxy_names.load();
        // One lock-free snapshot for the whole document so a concurrent reload
        // cannot project half the rows under a different schema.
        let render_schema_guard = self.render_schema.load();
        let render_schema: Option<&Arc<SummarySchema>> = (**render_schema_guard).as_ref();
        // Nested structure: consumer -> proxy -> {protocol, by_status, stream, bandwidth}.
        //
        // Currency is carried per proxy (it is a property of the recording
        // plugin instance — finding #24) and the proxy retains separate HTTP
        // (`by_status`) and stream (`stream_*`) breakdowns so a proxy serving
        // both families reports a deterministic `protocol_family` and always
        // emits its `stream` sub-object when stream activity exists (finding
        // #75).
        struct ProxyAggregate {
            proxy_name: String,
            currency: Arc<str>,
            has_http: bool,
            has_stream: bool,
            by_status: HashMap<u16, (u64, f64)>,
            stream_connections: u64,
            stream_charges: f64,
            bytes_sent: u64,
            bytes_received: u64,
            bandwidth_charge_sent: f64,
            bandwidth_charge_received: f64,
        }

        type ProxyAggregateKey = (String, Arc<str>, Arc<str>);
        type ConsumerProxyAggregates = HashMap<ProxyAggregateKey, ProxyAggregate>;

        let mut consumers: HashMap<String, ConsumerProxyAggregates> = HashMap::new();
        // Top-level currency: the single currency in use, or "mixed" when
        // instances disagree (consumers must then read per-proxy `currency`).
        let mut overall_currency: Option<Arc<str>> = None;
        let mut currency_mixed = false;

        for entry in self.entries.iter() {
            let v = entry.value();
            let calls = v.call_count.load(Ordering::Relaxed);
            let call_charge = v.call_charge()?;
            let bytes_sent = v.bytes_sent_total.load(Ordering::Relaxed);
            let bytes_received = v.bytes_received_total.load(Ordering::Relaxed);
            let bw_sent = v.bandwidth_charge_sent()?;
            let bw_received = v.bandwidth_charge_received()?;
            let proxy_name = active_proxy_names
                .get(v.proxy_namespace.as_ref())
                .and_then(|namespace| namespace.get(v.proxy_id.as_ref()))
                .map(String::as_str)
                .unwrap_or(v.proxy_name.as_ref());

            if !currency_mixed {
                match overall_currency.as_ref() {
                    None => overall_currency = Some(Arc::clone(&v.currency)),
                    Some(existing) if existing.as_ref() != v.currency.as_ref() => {
                        currency_mixed = true;
                    }
                    Some(_) => {}
                }
            }

            let proxy_map = consumers.entry(v.consumer.to_string()).or_default();
            let proxy_entry = proxy_map
                .entry((
                    v.proxy_id.to_string(),
                    Arc::clone(&v.currency),
                    Arc::clone(&v.proxy_namespace),
                ))
                .or_insert_with(|| ProxyAggregate {
                    proxy_name: proxy_name.to_string(),
                    currency: Arc::clone(&v.currency),
                    has_http: false,
                    has_stream: false,
                    by_status: HashMap::new(),
                    stream_connections: 0,
                    stream_charges: 0.0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    bandwidth_charge_sent: 0.0,
                    bandwidth_charge_received: 0.0,
                });
            apply_export_proxy_name(&mut proxy_entry.proxy_name, proxy_name);
            proxy_entry.bytes_sent += bytes_sent;
            proxy_entry.bytes_received += bytes_received;
            proxy_entry.bandwidth_charge_sent =
                checked_add_charge(proxy_entry.bandwidth_charge_sent, bw_sent)?;
            proxy_entry.bandwidth_charge_received =
                checked_add_charge(proxy_entry.bandwidth_charge_received, bw_received)?;

            match v.protocol_family {
                ProtocolFamily::Http => {
                    proxy_entry.has_http = true;
                    let status_entry = proxy_entry
                        .by_status
                        .entry(v.status_code)
                        .or_insert((0, 0.0));
                    status_entry.0 += calls;
                    status_entry.1 = checked_add_charge(status_entry.1, call_charge)?;
                }
                ProtocolFamily::Stream => {
                    proxy_entry.has_stream = true;
                    proxy_entry.stream_connections += calls;
                    proxy_entry.stream_charges =
                        checked_add_charge(proxy_entry.stream_charges, call_charge)?;
                }
            }
        }

        // Per-currency monetary rollup for a consumer. Never sum across
        // currencies into a unitless headline total (issue #2569).
        #[derive(Clone, Default)]
        struct CurrencyTotals {
            total_calls: u64,
            per_call_charges: f64,
            stream_connection_charges: f64,
            bandwidth_charges: f64,
        }

        impl CurrencyTotals {
            fn total_charges(&self) -> Result<f64, String> {
                checked_add_charge(self.per_call_charges, self.stream_connection_charges)
                    .and_then(|partial| checked_add_charge(partial, self.bandwidth_charges))
            }

            fn to_json(&self) -> Result<serde_json::Value, String> {
                Ok(serde_json::json!({
                    "total_calls": self.total_calls,
                    "total_charges": self.total_charges()?,
                    "per_call_charges": self.per_call_charges,
                    "stream_connection_charges": self.stream_connection_charges,
                    "bandwidth_charges": self.bandwidth_charges,
                }))
            }
        }

        let mut consumer_objects = serde_json::Map::new();
        for (consumer, proxies) in &consumers {
            let mut total_calls = 0u64;
            let mut by_currency: HashMap<String, CurrencyTotals> = HashMap::new();
            let mut proxy_objects = serde_json::Map::new();

            let mut proxy_id_counts: HashMap<&str, usize> = HashMap::new();
            for (proxy_id, _, _) in proxies.keys() {
                *proxy_id_counts.entry(proxy_id.as_str()).or_default() += 1;
            }

            for ((proxy_id, _, proxy_namespace), agg) in proxies {
                let mut proxy_per_call_charges = 0.0f64;
                let mut proxy_calls = 0u64;
                let mut status_objects = serde_json::Map::new();

                for (status_code, (calls, charge)) in &agg.by_status {
                    let charge = require_finite_charge(*charge, "by_status.charges")?;
                    proxy_per_call_charges = checked_add_charge(proxy_per_call_charges, charge)?;
                    proxy_calls += calls;
                    status_objects.insert(
                        status_code.to_string(),
                        serde_json::json!({
                            "calls": calls,
                            "charges": charge,
                        }),
                    );
                }

                let stream_charges =
                    require_finite_charge(agg.stream_charges, "stream.connection_charges")?;
                let bw_sent =
                    require_finite_charge(agg.bandwidth_charge_sent, "bandwidth.charge_sent")?;
                let bw_received = require_finite_charge(
                    agg.bandwidth_charge_received,
                    "bandwidth.charge_received",
                )?;

                // Stream connections also count toward total_calls for headline numbers.
                let proxy_total_calls = proxy_calls + agg.stream_connections;
                let proxy_total_charges =
                    checked_add_charge(proxy_per_call_charges, stream_charges)
                        .and_then(|partial| checked_add_charge(partial, bw_sent))
                        .and_then(|partial| checked_add_charge(partial, bw_received))?;
                require_finite_charge(proxy_total_charges, "proxy.total_charges")?;

                total_calls += proxy_total_calls;
                let proxy_bandwidth_charges = checked_add_charge(bw_sent, bw_received)?;
                let currency_totals = by_currency
                    .entry(agg.currency.as_ref().to_string())
                    .or_default();
                currency_totals.total_calls += proxy_total_calls;
                currency_totals.per_call_charges =
                    checked_add_charge(currency_totals.per_call_charges, proxy_per_call_charges)?;
                currency_totals.stream_connection_charges =
                    checked_add_charge(currency_totals.stream_connection_charges, stream_charges)?;
                currency_totals.bandwidth_charges =
                    checked_add_charge(currency_totals.bandwidth_charges, proxy_bandwidth_charges)?;

                // Deterministic protocol_family label: "mixed" when a proxy
                // carries both HTTP and stream activity, otherwise the single
                // family present (finding #75).
                let protocol_family = match (agg.has_http, agg.has_stream) {
                    (true, true) => "mixed",
                    (false, true) => ProtocolFamily::Stream.label(),
                    _ => ProtocolFamily::Http.label(),
                };

                // Always emit the stream sub-object when stream activity exists,
                // regardless of whether an HTTP entry shares the proxy_id, so the
                // visible breakdown reconciles with the totals (finding #75).
                let stream_object = agg.has_stream.then(|| {
                    serde_json::json!({
                        "connections": agg.stream_connections,
                        "connection_charges": stream_charges,
                    })
                });
                let row = ChargebackProxyRow {
                    proxy_id,
                    namespace: proxy_namespace.as_ref(),
                    proxy_name: &agg.proxy_name,
                    currency: agg.currency.as_ref(),
                    protocol_family,
                    total_calls: proxy_total_calls,
                    total_charges: proxy_total_charges,
                    by_status: serde_json::Value::Object(status_objects),
                    bandwidth: serde_json::json!({
                        "bytes_sent": agg.bytes_sent,
                        "bytes_received": agg.bytes_received,
                        "charge_sent": bw_sent,
                        "charge_received": bw_received,
                    }),
                    stream: stream_object,
                };
                // No schema configured: emit the native row exactly as before,
                // with no projection machinery and no extra allocation beyond
                // the row itself.
                let proxy_obj = match render_schema {
                    None => row.to_native_json(),
                    Some(schema) => serde_json::to_value(SchemaView {
                        summary: &row,
                        schema: schema.as_ref(),
                    })
                    .map_err(|error| {
                        format!("api_chargeback: failed to project charges row: {error}")
                    })?,
                };

                let output_key = if proxy_id_counts.get(proxy_id.as_str()).copied().unwrap_or(0) > 1
                {
                    format!(
                        "{}|currency={}|namespace={}",
                        proxy_id,
                        agg.currency.as_ref(),
                        proxy_namespace.as_ref()
                    )
                } else {
                    proxy_id.clone()
                };
                proxy_objects.insert(output_key, proxy_obj);
            }

            // Single-currency consumers keep the historical flat monetary fields.
            // Mixed-currency consumers null those fields and expose
            // `charges_by_currency` so billing integrations never treat a
            // USD+EUR sum as a settlement total (issue #2569). Call counts stay
            // flat because they are unitless. Per-proxy rows remain authoritative
            // within each currency and must reconcile with the matching
            // `charges_by_currency` partition.
            let mut consumer_obj = serde_json::Map::new();
            consumer_obj.insert("total_calls".to_string(), serde_json::json!(total_calls));
            consumer_obj.insert(
                "proxies".to_string(),
                serde_json::Value::Object(proxy_objects),
            );

            if by_currency.len() <= 1 {
                let totals = by_currency.values().next().cloned().unwrap_or_default();
                consumer_obj.insert(
                    "total_charges".to_string(),
                    serde_json::json!(totals.total_charges()?),
                );
                consumer_obj.insert(
                    "per_call_charges".to_string(),
                    serde_json::json!(totals.per_call_charges),
                );
                consumer_obj.insert(
                    "stream_connection_charges".to_string(),
                    serde_json::json!(totals.stream_connection_charges),
                );
                consumer_obj.insert(
                    "bandwidth_charges".to_string(),
                    serde_json::json!(totals.bandwidth_charges),
                );
            } else {
                consumer_obj.insert("total_charges".to_string(), serde_json::Value::Null);
                consumer_obj.insert("per_call_charges".to_string(), serde_json::Value::Null);
                consumer_obj.insert(
                    "stream_connection_charges".to_string(),
                    serde_json::Value::Null,
                );
                consumer_obj.insert("bandwidth_charges".to_string(), serde_json::Value::Null);

                let mut currency_entries: Vec<_> = by_currency.into_iter().collect();
                currency_entries.sort_by(|a, b| a.0.cmp(&b.0));
                let mut currency_objects = serde_json::Map::new();
                for (currency, totals) in currency_entries {
                    currency_objects.insert(currency, totals.to_json()?);
                }
                consumer_obj.insert(
                    "charges_by_currency".to_string(),
                    serde_json::Value::Object(currency_objects),
                );
            }

            consumer_objects.insert(consumer.clone(), serde_json::Value::Object(consumer_obj));
        }

        let currency = if currency_mixed {
            "mixed".to_string()
        } else {
            overall_currency
                .as_deref()
                .map(str::to_string)
                // With no recorded entries there is no authoritative instance
                // currency. Keep the response deterministic instead of using
                // constructor order from the process-global registry.
                .unwrap_or_else(|| "USD".to_string())
        };

        let result = serde_json::json!({
            "currency": currency,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "registry": self.registry_status(),
            "consumers": serde_json::Value::Object(consumer_objects),
        });

        serde_json::to_string_pretty(&result)
            .map_err(|err| format!("api_chargeback: failed to serialize charges JSON: {err}"))
    }
}

// ---------------------------------------------------------------------------
// `/charges` billing-row projection
// ---------------------------------------------------------------------------

/// One rendered per-proxy billing row inside the `/charges` document.
///
/// This is `api_chargeback`'s externally documented representation boundary.
/// The registry entry key, the billing identity, the charge accounting, and the
/// Prometheus label sets are all computed before this row exists and are never
/// touched by projection — only the rendered JSON row is projected.
///
/// `by_status`, `bandwidth`, and `stream` are pre-built nested objects: they can
/// be renamed, omitted, or reordered as whole members, but their inner keys are
/// not part of the schema surface.
pub(crate) struct ChargebackProxyRow<'a> {
    pub(crate) proxy_id: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) proxy_name: &'a str,
    pub(crate) currency: &'a str,
    pub(crate) protocol_family: &'static str,
    pub(crate) total_calls: u64,
    pub(crate) total_charges: f64,
    pub(crate) by_status: Value,
    pub(crate) bandwidth: Value,
    /// Present only when the row carries stream activity.
    pub(crate) stream: Option<Value>,
}

impl<'a> ChargebackProxyRow<'a> {
    /// The unprojected row, byte-for-byte identical to the pre-schema
    /// rendering. Taken whenever no schema is configured.
    fn to_native_json(&self) -> Value {
        let mut object = serde_json::json!({
            "proxy_id": self.proxy_id,
            "namespace": self.namespace,
            "proxy_name": self.proxy_name,
            "currency": self.currency,
            "protocol_family": self.protocol_family,
            "total_calls": self.total_calls,
            "total_charges": self.total_charges,
            "by_status": self.by_status,
            "bandwidth": self.bandwidth,
        });
        if let Some(stream) = &self.stream {
            object["stream"] = stream.clone();
        }
        object
    }
}

impl<'a> SchemaSerializable for ChargebackProxyRow<'a> {
    fn owns_native(&self, source: &str) -> bool {
        crate::plugins::utils::log_schema::CHARGEBACK_REPORT_FIELDS
            .iter()
            .any(|field| field.name == source)
    }

    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        _ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        match source {
            "proxy_id" => map.serialize_entry(out_key, self.proxy_id),
            "namespace" => map.serialize_entry(out_key, self.namespace),
            "proxy_name" => map.serialize_entry(out_key, self.proxy_name),
            "currency" => map.serialize_entry(out_key, self.currency),
            "protocol_family" => map.serialize_entry(out_key, self.protocol_family),
            "total_calls" => map.serialize_entry(out_key, &self.total_calls),
            "total_charges" => map.serialize_entry(out_key, &self.total_charges),
            "by_status" => map.serialize_entry(out_key, &self.by_status),
            "bandwidth" => map.serialize_entry(out_key, &self.bandwidth),
            // Mirrors the native rendering: absent unless the row carries
            // stream activity.
            "stream" => match &self.stream {
                Some(stream) => map.serialize_entry(out_key, stream),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        match kind {
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "chargeback_proxy")?;
                Ok(true)
            }
            // Every other kind is rejected at compile time for this family: a
            // billing row aggregates many transactions and has no single
            // status, backend, or outcome.
            _ => Ok(false),
        }
    }

    fn serialize_metadata<S>(
        &self,
        _policy: &MetadataPolicy,
        _emitted: &EmittedKeys<'_>,
        _map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        // Billing rows carry no metadata map; the compiler rejects a `metadata`
        // policy for this family.
        Ok(())
    }
}

pub struct ApiChargeback {
    registry: Arc<ChargebackRegistry>,
    pricing: PricingConfig,
    /// This instance's currency + namespace, stamped onto every entry it
    /// records so multiple instances never misattribute one another's charges
    /// (finding #24).
    scope: InstanceScope,
    /// Compiled `/charges` billing-row projection resolved at construction.
    /// Like the other render tunables this governs one process-global render
    /// cache, so [`validate_composition`] requires every enabled instance to
    /// agree on it. `None` keeps the `/charges` document byte-for-byte.
    render_schema: Option<Arc<SummarySchema>>,
    /// Process-global registry knobs resolved at construction and applied only
    /// once this instance's generation is accepted.
    tunables: SharedRegistryTunables,
}

/// The trimmed instance currency label (`"USD"` when omitted).
fn instance_currency(config: &Value) -> Result<&str, String> {
    match config.get("currency") {
        Some(value) => {
            let currency = value
                .as_str()
                .ok_or_else(|| "api_chargeback: `currency` must be a string".to_string())?
                .trim();
            if currency.is_empty() {
                return Err("api_chargeback: `currency` must not be empty".to_string());
            }
            Ok(currency)
        }
        None => Ok("USD"),
    }
}

/// Whether a resolved pricing configuration bills WebSocket bandwidth and so
/// needs the parsed relay's payload byte counters.
fn pricing_requires_websocket_framing(pricing: &PricingConfig) -> bool {
    pricing.bandwidth_price_sent > 0.0 || pricing.bandwidth_price_received > 0.0
}

/// Config-level form of [`Plugin::requires_websocket_framing`] for
/// `websocket_permessage_deflate: passthrough` admission, which must not
/// construct the plugin: an `api_chargeback` config needs the parsed WebSocket
/// relay exactly when it prices bandwidth. An unparseable pricing block is an
/// error so admission fails closed.
pub(crate) fn config_requires_websocket_framing(config: &Value) -> Result<bool, String> {
    let pricing = PricingConfig::from_config(config, "api_chargeback")?;
    Ok(pricing_requires_websocket_framing(&pricing))
}

fn optional_u64(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("api_chargeback: `{key}` must be an unsigned integer")),
        None => Ok(default),
    }
}

impl ApiChargeback {
    #[allow(dead_code)] // Used by external tests; production uses new_with_shard_amount.
    pub fn new(config: &Value, namespace: &str) -> Result<Self, String> {
        Self::new_with_shard_amount(
            config,
            namespace,
            crate::util::sharding::pool_shard_amount(0),
        )
    }

    /// Construct an instance, sizing the process-global registry's entry map
    /// with `shard_amount` shards on first use.
    ///
    /// `shard_amount` must already be normalized — production passes
    /// `PluginHttpClient::pool_shard_amount()` so `FERRUM_POOL_SHARD_AMOUNT` is
    /// applied exactly once.
    pub fn new_with_shard_amount(
        config: &Value,
        namespace: &str,
        shard_amount: usize,
    ) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "api_chargeback: `config` must be an object".to_string())?;
        // Compile / resolve once here — never on the `/charges` render path.
        // `schema_ref` keeps the global-first lifecycle and fails closed for a
        // missing or incompatible named definition.
        let render_schema =
            resolve_schema(config, "api_chargeback", SchemaCapabilities::API_CHARGEBACK)?;
        reject_unknown_keys(
            object,
            "config",
            API_CHARGEBACK_CONFIG_KEYS,
            "api_chargeback: `config`: ",
        )?;

        let registry = global_registry_with_shard_amount(shard_amount);

        let currency = instance_currency(config)?;

        // Resolve shared tunables before mutating the registry so a bad value
        // never leaves process-global state half-applied. When multiple
        // instances exist on different proxies they must already agree on these
        // values (see [`validate_composition`]).
        let tunables = SharedRegistryTunables::from_config(config)?;

        // Validate ALL pricing dimensions before touching the global registry,
        // so a config error never leaves shared state half-mutated.
        let pricing = PricingConfig::from_config(config, "api_chargeback")?;

        if !pricing.has_any_pricing() {
            return Err(
                "api_chargeback: at least one of `pricing_tiers`, `bandwidth_pricing`, or \
                 `stream_connection_pricing` must be configured — the plugin would otherwise \
                 record nothing"
                    .to_string(),
            );
        }

        // Construction stays side-effect free on the process-global registry.
        // Admin validation and a staged plugin-cache generation both build an
        // instance, and a candidate that is later rejected must not have
        // repointed the shared budgets, render TTLs, or cleanup schedule that
        // the live generation is still using. The resolved tunables are applied
        // in `commit_background_tasks`, which runs only after the generation is
        // atomically installed.
        let scope = InstanceScope::new(currency, namespace);

        Ok(Self {
            registry,
            pricing,
            scope,
            tunables,
            render_schema,
        })
    }

    /// The compiled `/charges` render projection this instance resolved.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub fn render_schema(&self) -> Option<&Arc<SummarySchema>> {
        self.render_schema.as_ref()
    }

    /// Shard count the process-global entry map was built with when this
    /// instance resolved it (or the already-created singleton's fixed count).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn registry_shard_amount_for_tests(&self) -> usize {
        self.registry.shard_amount_for_tests()
    }
}

#[async_trait]
impl Plugin for ApiChargeback {
    fn name(&self) -> &str {
        "api_chargeback"
    }

    fn priority(&self) -> u16 {
        super::priority::API_CHARGEBACK
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // Stream protocols (TCP/UDP/DTLS) are now supported via on_stream_disconnect.
        super::ALL_PROTOCOLS
    }

    /// Publish this generation's process-global registry knobs.
    ///
    /// Infallible and idempotent, and reached only after the plugin cache has
    /// atomically installed the generation — so validation and a rejected
    /// candidate never mutate the shared registry. Every enabled instance must
    /// already agree on these values (see [`validate_composition`]), so commit
    /// order cannot change registry behavior. Currency and namespace stay
    /// per-entry via this instance's [`InstanceScope`].
    fn commit_background_tasks(&self) {
        self.registry.configure(
            self.tunables.render_cache_ttl_secs,
            self.tunables.stale_entry_ttl_secs,
            self.tunables.cache_invalidation_min_age_ms,
            self.tunables.max_entries,
            self.tunables.max_retained_bytes,
        );
        self.registry
            .configure_render_schema(self.render_schema.clone());
        self.registry
            .start_cleanup_task(self.tunables.cleanup_interval_seconds);
    }

    async fn log(&self, summary: &TransactionSummary) {
        // Shadow/mirror summaries retain the primary consumer identity for
        // logging correlation, but they are internal backend probes — never
        // consumer-billable per-call or bandwidth charges (issue #2437).
        if summary.mirror {
            return;
        }

        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        let status_code = super::chargeback::http_billing_outcome(summary).status_code;

        let Some(charge) =
            self.pricing
                .compute_http(status_code, summary.bytes_sent, summary.bytes_received)
        else {
            return;
        };

        let proxy_id = summary.proxy_id.as_deref().unwrap_or("unknown");
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");
        // A status no tier prices carries only bandwidth; if it folds into the
        // overflow row it is filed under the shared status-0 bandwidth row so
        // the reserved overflow matrix stays bounded by configuration.
        let overflow_status_code = if self.pricing.price_by_status.contains_key(&status_code) {
            status_code
        } else {
            STREAM_STATUS_SENTINEL
        };

        self.registry.record_http_in_namespace(
            &self.scope,
            &summary.namespace,
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            overflow_status_code,
            charge.charge_call,
            summary.bytes_sent,
            summary.bytes_received,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        let Some(charge) = self
            .pricing
            .compute_stream(summary.bytes_sent, summary.bytes_received)
        else {
            return;
        };

        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");

        self.registry.record_stream_in_namespace(
            &self.scope,
            &summary.namespace,
            consumer,
            &summary.proxy_id,
            proxy_name,
            charge.charge_call,
            summary.bytes_sent,
            summary.bytes_received,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    /// Bandwidth pricing bills WebSocket sessions from the parsed relay's
    /// payload byte counters. The H1 raw tunnel (`FERRUM_WEBSOCKET_TUNNEL_MODE`
    /// or a negotiated `permessage-deflate` passthrough) instead counts wire
    /// bytes, and reports none of the relayed bytes when gateway policy stops
    /// the session, so a bandwidth-priced instance keeps its sessions on the
    /// parsed relay: one billing basis regardless of relay mode.
    fn requires_websocket_framing(&self) -> bool {
        pricing_requires_websocket_framing(&self.pricing)
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        if self
            .pricing
            .compute_websocket_bandwidth(
                summary.bytes_client_to_backend,
                summary.bytes_backend_to_client,
            )
            .is_none()
        {
            return;
        }
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");
        self.registry.record_websocket_bandwidth_in_namespace(
            &self.scope,
            &summary.namespace,
            consumer,
            &summary.proxy_id,
            proxy_name,
            summary.bytes_client_to_backend,
            summary.bytes_backend_to_client,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }
}
