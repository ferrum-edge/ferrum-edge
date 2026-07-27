//! Request Deduplication Plugin
//!
//! Prevents duplicate API calls by tracking idempotency keys. When a request
//! arrives with an idempotency key header (e.g., `Idempotency-Key`) and the
//! same key was seen within the configured TTL, the plugin returns the cached
//! response instead of forwarding to the backend.
//!
//! Supports two storage modes:
//! - **local** (default): In-memory `DashMap` with TTL-based eviction. Suitable
//!   for single-instance deployments.
//! - **redis**: Centralized storage via Redis/Valkey/DragonflyDB/KeyDB/Garnet.
//!   Enables deduplication across multiple gateway instances. Uses the shared
//!   `RedisRateLimitClient` infrastructure with automatic local fallback when
//!   Redis is unreachable.
//!
//! Only applies to non-safe HTTP methods (POST, PUT, PATCH by default).
//!
//! ## Replay provenance
//!
//! An idempotent replay is a *finalized* client representation: the synthetic
//! replay path deliberately skips ordinary presentation transforms
//! (`RequestContext::finalized_response_replay`) so non-idempotent
//! `response_transformer` header/body `add` sequences cannot run a second time
//! over an already-transformed body. That skip is only sound while the stored
//! bytes are still the product of the *live* presentation policy.
//!
//! Unlike `response_caching`, this plugin cannot lean on "a config reload
//! builds a new instance with an empty cache": a Redis entry outlives the
//! plugin instance, the cache generation, and the process, and a
//! `proxy_group`-scoped instance with unchanged config is even retained across
//! an incremental rebuild. Every retained response therefore carries a complete
//! `ResponsePolicyProvenance` — the content digest of the published RTDS
//! response-side gate map *and* the content digest of the effective static
//! rules of **every** plugin whose response-body transform the replay skips
//! (`response_transformer` and `sse` today; see
//! `Plugin::response_presentation_policy` for the audited set and why
//! `compression`, `grpc_web`, `ai_response_guard`, and `ai_tool_governor` are
//! excluded) — and replays only while both still match:
//!
//! - **Lookup**: a stored response whose provenance differs from the live one
//!   is refused with 409 rather than replayed. It is not re-executed: the
//!   backend side effect may already have happened, so serving a superseded
//!   representation and repeating the operation are both unacceptable, and the
//!   client must retry after the bounded TTL.
//! - **Store**: a response whose request straddled a gate publication, or whose
//!   effective presentation policy could not be established, is retained
//!   nowhere — not in Redis and not in the local map. Its bytes belong to no
//!   provable policy. In-flight ownership is untouched, so concurrent-duplicate
//!   protection still holds; only the finalized replay is given up. When the
//!   request already performed a protected external operation (a terminate-mode
//!   `serverless_function` invocation, an `ai_federation` provider call), giving
//!   up the replay is not enough: the bounded in-flight lease is replaced by the
//!   fixed non-replayable 409 execution barrier through the same fenced
//!   ownership transition, so the operation cannot become executable again when
//!   `inflight_ttl_seconds` elapses (GHSA-8cr6-rw38-7j59).
//! - **Legacy/malformed payloads**: a Redis record without complete, decodable
//!   provenance is rejected. It can never be replayed on the strength of an
//!   assumed policy.
//!
//! Both halves are required. The gate map alone covers only enable/disable
//! flips of an RTDS-scoped instance; a redaction/header/body *rule* edit — or
//! the addition, removal, or reordering of any other enrolled presentation
//! plugin — that leaves the gate map identical would otherwise let an old Redis
//! representation match the current digest and skip the new transform. An
//! *incomplete* provenance matches nothing, including another incomplete one:
//! two requests that both failed to establish the policy have not proven they
//! share it. Only fixed-size digests are stored — never rule text, header
//! values, catalog entries, upstream URLs, session identifiers, or any other
//! configuration or runtime content.
//!
//! ## Plugins that cannot be composed with deduplication
//!
//! Some response-body rewrites are not a function of configuration at all.
//! `mcp_gateway` resolves public resource/tool/prompt URIs against a
//! per-downstream-session catalog it re-lists from upstream whenever its
//! discovery TTL expires; entries appear, disappear, get remapped, or become
//! ambiguous with no config edit and no plugin-cache rebuild. Worse, this
//! plugin's `before_proxy` short-circuits at priority
//! `priorities::REQUEST_DEDUPLICATION`, ahead of `priorities::MCP_GATEWAY`, so
//! a replay is served without MCP validating or routing the request against the
//! current catalog at all. No digest available before the lookup can witness
//! that state, and deriving one would mean an upstream round trip under a
//! per-session lock on the hot path.
//!
//! Rather than replay under an unprovable policy, the composition is refused:
//! [`validate_composition`] rejects the pair at config admission and at
//! plugin-cache construction. For the admission paths that only warn on
//! pre-existing data, `ResponsePresentationPolicy::Dynamic` collapses the
//! proxy's presentation digest to `None` at runtime, which fails both storage
//! and replay closed through the rules above.

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use http::{HeaderName, Method};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::mem;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::debug;

/// Process-relative monotonic anchor for the cleanup throttle. Captured once
/// per process so the throttle and the entry-expiry checks (which use
/// `Instant`) share the same monotonic clock. Using a wall clock here would let
/// a backward NTP/VM/manual clock step suppress periodic cleanup until the wall
/// clock caught back up. See finding #57.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Default minimum seconds between full local-cache cleanup scans. The scan
/// takes write locks across all `DashMap` shards, so it must run at most once
/// per interval regardless of cache pressure (finding #12). Shorter
/// `inflight_ttl_seconds` values lower the interval so stale in-flight markers
/// do not outlive their configured TTL under key churn.
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Sentinel `last_cleanup` value meaning "no cleanup has run yet"; forces the
/// first applicable request to perform a scan. Tests also store this to force a
/// scan deterministically without depending on how far into the process they
/// run.
const CLEANUP_NEVER: u64 = u64::MAX;

const DEDUP_LOGICAL_KEY_VERSION: &str = "ferrum-dedup-logical-v4";
const DEDUP_FINGERPRINT_VERSION: &str = "ferrum-dedup-fingerprint-v2";
/// Version stamped into every Redis operation record. A peer running an older
/// or newer record format is treated as a conflict rather than being parsed
/// optimistically, so a rolling upgrade can never publish through a fence the
/// other side does not implement.
const DEDUP_REDIS_RECORD_VERSION: u32 = 1;
const DEDUP_RECORD_STATE_INFLIGHT: &str = "inflight";
const DEDUP_RECORD_STATE_COMPLETED: &str = "completed";
/// Deterministic body for a fail-closed refusal when the centralized
/// idempotency store cannot be consulted.
const REDIS_UNAVAILABLE_BODY: &str = r#"{"error":"Idempotency coordination store is unavailable"}"#;
/// Deterministic refusal while the bounded per-key execution-barrier budget is
/// saturated. One process-global deadline covers any additional completed
/// operations fail-closed without allocating attacker-amplified per-key state.
const EXECUTION_BARRIER_CAPACITY_BODY: &str =
    r#"{"error":"Idempotency execution-barrier capacity is saturated"}"#;
/// Deterministic body for a completion that must never be replayed: the
/// protected operation already ran externally and has no safe replay value.
const NON_REPLAYABLE_COMPLETION_BODY: &str = r#"{"error":"This idempotency key already completed an external operation and cannot be replayed safely"}"#;
/// Transient per-request marker, set only while
/// [`RequestDeduplication::publish_external_operation_tombstone`] drives the
/// final-body hook, and carrying the publishing instance id so sibling
/// instances cannot claim one another's publication.
///
/// The value published under it is the fixed [`NON_REPLAYABLE_COMPLETION_BODY`]
/// refusal, not a transformed backend representation, so it asserts nothing
/// about the response-side presentation policy. The replay-provenance gates in
/// `on_final_response_body` therefore do not apply: withholding this tombstone
/// because the live policy is unprovable would leave an already-performed
/// external operation re-executable the moment its in-flight lease expires,
/// which is exactly the exposure GHSA-8cr6-rw38-7j59 closes.
const EXTERNAL_OPERATION_TOMBSTONE_PUBLICATION_KEY: &str =
    "request_deduplication.publishing_external_operation_tombstone";
/// Bounded retries for the acquire/observe loop, covering the narrow window
/// where an observed record expires between `SET NX` and the follow-up `GET`.
const REDIS_ADMISSION_ATTEMPTS: usize = 3;
const DEFAULT_INSTANCE_ID: &str = "standalone";
const DEFAULT_MAX_ENTRY_SIZE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_TOTAL_SIZE_BYTES: usize = 100 * 1024 * 1024;
const MAX_CANONICAL_DECODED_BODY_BYTES: usize = 1024 * 1024;
const HOP_BY_HOP_FINGERPRINT_EXCLUSIONS: &[&str] = &[
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
const SCOPED_CREDENTIAL_FINGERPRINT_EXCLUSIONS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-forwarded-authorization",
];
/// Plugin-specific root config keys, excluding the shared Redis fields.
#[allow(dead_code)] // Used by external unit tests that verify OpenAPI/allowlist parity.
pub const REQUEST_DEDUPLICATION_POLICY_CONFIG_KEYS: &[&str] = &[
    "header_name",
    "ttl_seconds",
    "inflight_ttl_seconds",
    "max_entries",
    "max_entry_size_bytes",
    "max_total_size_bytes",
    "applicable_methods",
    "scope_by_consumer",
    "enforce_required",
    "on_redis_unavailable",
];

/// Closed top-level key set for `request_deduplication` plugin config.
///
/// Must stay aligned with OpenAPI `RequestDeduplicationConfig`,
/// `REDIS_PLUGIN_CONFIG_KEYS`, and `docs/plugins.md`. Unknown root keys fail
/// closed so a typo cannot silently replace an idempotency-enforcement,
/// scoping, retention, or synchronization decision with a permissive default.
pub const REQUEST_DEDUPLICATION_CONFIG_KEYS: &[&str] = &[
    "header_name",
    "ttl_seconds",
    "inflight_ttl_seconds",
    "max_entries",
    "max_entry_size_bytes",
    "max_total_size_bytes",
    "applicable_methods",
    "scope_by_consumer",
    "enforce_required",
    "on_redis_unavailable",
    // Shared Redis sync (see REDIS_PLUGIN_CONFIG_KEYS)
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
];

/// Keys that only have meaning under `sync_mode: "redis"`. Supplying any of
/// them in local mode is rejected: the usual cause is a misspelled `sync_mode`,
/// which would otherwise leave the deployment silently process-local.
const REDIS_ONLY_CONFIG_KEYS: &[&str] = &[
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
    "on_redis_unavailable",
];

/// Monotonic seconds since process start. Immune to wall-clock steps, matching
/// the `Instant`-based entry expiry.
fn monotonic_secs() -> u64 {
    PROCESS_START.elapsed().as_secs()
}

fn monotonic_millis() -> u64 {
    u64::try_from(PROCESS_START.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Whether a full cleanup scan is due, given the last scan's recorded monotonic
/// second (`last`) and the current monotonic second (`now_secs`).
///
/// `now_secs` is always derived from `monotonic_secs()`, so `now_secs >= last`
/// holds for any real `last` and a backward wall-clock step cannot make the
/// elapsed delta appear to be zero — the wall-clock-suppression defect of the
/// previous `SystemTime`-based gate (finding #57). The gate is unconditional:
/// it does not depend on cache occupancy, so an over-capacity cache cannot
/// force a per-request scan (finding #12).
fn cleanup_due(last: u64, now_secs: u64, interval_secs: u64) -> bool {
    last == CLEANUP_NEVER || now_secs.saturating_sub(last) >= interval_secs
}

fn decrement_atomic(value: &AtomicUsize) -> usize {
    value
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(1))
        })
        .map(|previous| previous.saturating_sub(1))
        .unwrap_or(0)
}

use super::utils::body_transform::is_event_stream_content_type;
use super::utils::cache_headers::{is_per_request_trace_header, sanitize_cached_headers};
use super::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext, ResponsePolicyProvenance};

/// Plugins whose response-body rewrite is derived from live runtime state that
/// no construction-time digest can describe, and which therefore cannot be
/// composed with `request_deduplication` on the same proxy.
///
/// This is the config-admission mirror of the plugins that report
/// [`super::ResponsePresentationPolicy::Dynamic`]. Admission works on
/// `PluginConfig` names before any plugin is constructed, so the two surfaces
/// are joined by name; `tests/unit/plugins/request_deduplication_tests.rs`
/// asserts a constructed instance of each name actually reports `Dynamic`, so
/// the list cannot drift away from the runtime behavior it stands in for.
pub const DYNAMIC_RESPONSE_PRESENTATION_PLUGINS: &[&str] = &["mcp_gateway"];

fn dynamic_response_presentation_is_active(plugin: &crate::config::types::PluginConfig) -> bool {
    if !plugin.enabled {
        return false;
    }
    match plugin.plugin_name.as_str() {
        // `mcp_gateway` retains an explicit, validated inner enable switch.
        // When false, none of its request or response hooks apply, so there is
        // no dynamic presentation policy to make deduplication unprovable.
        "mcp_gateway" => {
            plugin
                .config
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
        }
        _ => true,
    }
}

/// Reject composing `request_deduplication` with a plugin whose response-body
/// presentation policy cannot be proven stable for a retained representation.
///
/// A dedup replay is a *finalized* representation: the synthetic replay path
/// skips ordinary presentation transforms, and `request_deduplication`'s
/// `before_proxy` short-circuits ahead of every plugin with a higher priority
/// value — including `mcp_gateway`. So a hit is served without the MCP catalog
/// ever being consulted, under a public-URI mapping that this gateway refreshes
/// from upstream on its own schedule. There is no digest that can witness that
/// state, so the composition is refused here rather than silently replaying
/// bytes whose producing policy cannot be established.
///
/// Runtime plugin-cache construction repeats this check as a fail-closed
/// backstop, and `ResponsePresentationPolicy::Dynamic` degrades the request
/// path to never retaining or replaying, for the admission paths that only warn
/// on pre-existing bad data.
pub fn validate_composition(
    config: &crate::config::types::GatewayConfig,
) -> Result<(), Vec<String>> {
    use crate::config::types::{PluginConfig, PluginScope};

    // Keyed by `(namespace, id)` exactly like the runtime merge's scoped-plugin
    // map: a proxy only ever resolves associations against plugin configs in
    // its own namespace, so an id reused across namespaces cannot cross over.
    let plugin_by_scoped_id: HashMap<(&str, &str), &PluginConfig> = config
        .plugin_configs
        .iter()
        .map(|plugin| ((plugin.namespace.as_str(), plugin.id.as_str()), plugin))
        .collect();

    // Resolve each name the way the runtime merge does before deciding whether
    // the pair is actually effective together. Two properties of that merge are
    // load-bearing here:
    //
    // - Globals are gateway-wide: every global instance is merged into every
    //   proxy unless a scoped instance of the same plugin name shadows it.
    // - Shadowing is decided by the outer `enabled` flag alone. An instance
    //   whose *inner* switch is off is still constructed and still replaces the
    //   same-named global for that proxy, so the effective set has to be
    //   resolved first and only then asked which members actually apply a
    //   dynamic rewrite. Filtering by activity before shadow resolution would
    //   fall back to a global that the runtime never merges, and reject a
    //   composition that cannot occur.
    let effective_ids = |proxy: &crate::config::types::Proxy, name: &str| -> Vec<String> {
        let local: Vec<&PluginConfig> = proxy
            .plugins
            .iter()
            .filter_map(|association| {
                let plugin = *plugin_by_scoped_id.get(&(
                    proxy.namespace.as_str(),
                    association.plugin_config_id.as_str(),
                ))?;
                let scope_applies = match plugin.scope {
                    PluginScope::Proxy => plugin.proxy_id.as_deref() == Some(proxy.id.as_str()),
                    // Proxy-group instances are required to omit `proxy_id`;
                    // the explicit association is what makes them applicable.
                    PluginScope::ProxyGroup => true,
                    PluginScope::Global => false,
                };
                (plugin.enabled && plugin.plugin_name == name && scope_applies).then_some(plugin)
            })
            .collect();
        let effective: Vec<&PluginConfig> = if local.is_empty() {
            // Runtime globals are process-wide rather than namespace-scoped,
            // so admission must consider every enabled global here too.
            config
                .plugin_configs
                .iter()
                .filter(|plugin| {
                    plugin.enabled
                        && plugin.scope == PluginScope::Global
                        && plugin.plugin_name == name
                })
                .collect()
        } else {
            local
        };
        effective
            .into_iter()
            .filter(|plugin| dynamic_response_presentation_is_active(plugin))
            .map(|plugin| plugin.id.clone())
            .collect()
    };

    let mut errors = Vec::new();
    for proxy in &config.proxies {
        let dedup_ids = effective_ids(proxy, "request_deduplication");
        if dedup_ids.is_empty() {
            continue;
        }
        for dynamic_name in DYNAMIC_RESPONSE_PRESENTATION_PLUGINS {
            let dynamic_ids = effective_ids(proxy, dynamic_name);
            if dynamic_ids.is_empty() {
                continue;
            }
            errors.push(format!(
                "request_deduplication cannot be composed with {dynamic_name} on proxy '{}': \
                 an idempotent replay is served without re-running {dynamic_name}'s response \
                 rewrite, which is derived from live upstream discovery state rather than \
                 configuration, so a replay cannot be proven to match the current policy. \
                 request_deduplication: {}; {dynamic_name}: {}. \
                 Disable one of them on this proxy",
                proxy.id,
                dedup_ids.join(", "),
                dynamic_ids.join(", ")
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// A cached response stored for deduplication replay.
#[derive(Debug, Clone)]
struct CachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
    /// How long this completion stays authoritative, measured from
    /// `inserted_at`.
    ///
    /// An ordinary replayable completion uses `ttl_seconds`: once it expires the
    /// key is legitimately re-executable. A completion published only to
    /// *refuse* re-execution — the non-replayable external-operation tombstone —
    /// uses [`RequestDeduplication::execution_barrier_retention`] instead,
    /// because it replaces an in-flight marker that would have blocked for
    /// `inflight_ttl_seconds`. Reusing `ttl_seconds` there would make a
    /// deployment with `inflight_ttl_seconds > ttl_seconds` re-execute an
    /// already-performed billable operation *sooner* than the bare marker did.
    retention: Duration,
    /// Response-side presentation policy this representation was produced
    /// under. Replay is admitted only while it still equals the live policy.
    response_policy: ResponsePolicyProvenance,
}

impl CachedResponse {
    fn retained_size(&self) -> usize {
        cached_response_retained_size(self.body.len(), &self.headers)
    }
}

fn cached_response_retained_size(body_len: usize, headers: &HashMap<String, String>) -> usize {
    mem::size_of::<CachedResponse>()
        .saturating_add(body_len)
        .saturating_add(
            headers
                .iter()
                .map(|(name, value)| name.len().saturating_add(value.len()))
                .sum::<usize>(),
        )
}

/// In-flight marker to handle concurrent duplicate requests.
///
/// `InFlight` carries the timestamp it was inserted so stale markers (from
/// requests that died after `before_proxy` but before response completion,
/// e.g., backend timeout, downstream plugin reject, dropped connection) can be
/// detected and replaced rather than indefinitely returning 409 Conflict. It
/// also carries an owner token so a stale request's terminal hook cannot clear
/// a successor marker for the same key/fingerprint after `inflight_ttl`.
#[derive(Debug, Clone)]
enum DeduplicationEntry {
    /// Request is currently being processed. `started_at` allows stale-marker
    /// detection so abandoned in-flight entries don't permanently block retries.
    InFlight {
        started_at: Instant,
        fingerprint: String,
        owner_token: String,
    },
    /// The protected operation completed, but no replayable response bytes can
    /// remain in the bounded local cache.
    ///
    /// This state is deliberately fixed-size: the key and fingerprint are
    /// already bounded digests, the owner token is process-generated, and no
    /// response bytes or attacker-controlled headers are retained. It replaces
    /// an existing owned entry in place, so publishing a barrier never adds a
    /// second per-key allocation. Its own retention is authoritative; unlike an
    /// `InFlight` marker it must not fall back to `inflight_ttl_seconds` after a
    /// completion established a longer deadline.
    ExecutionBarrier {
        inserted_at: Instant,
        retention: Duration,
        fingerprint: String,
        /// Kept solely to fence removal after a distributed publication says
        /// this local publisher was stale. Ordinary in-flight cleanup never
        /// matches this variant.
        owner_token: String,
    },
    /// Response has been cached.
    Completed {
        cached: CachedResponse,
        sequence: u64,
        fingerprint: String,
        /// Exact local publisher whose in-flight entry became this completion.
        /// If concurrent eviction converts the completion to a barrier while a
        /// Redis compare-and-set is awaiting, a `NotOwner` result can remove
        /// that exact barrier without touching a successor.
        publisher_owner_token: String,
        /// Replace this replay with a fixed-size execution barrier carrying the
        /// completion's original retention clock instead of removing it when
        /// capacity pressure makes response retention impossible. This is set
        /// for externally executing terminal responses until a distributed
        /// replay is known to be visible.
        retain_barrier_on_eviction: bool,
    },
}

enum LocalDeduplicationAction {
    Fresh,
    Replay(CachedResponse),
    Conflict(DeduplicationConflict),
}

enum DeduplicationConflict {
    InFlight,
    FingerprintMismatch,
}

/// Outcome of the single-key Redis admission step.
enum RedisAdmission {
    /// This request now owns the operation record.
    Acquired(RedisOwnership),
    /// A completed record carries a replayable response for this fingerprint.
    Replay(CachedResponse),
    /// A completed record exists for this fingerprint but was published
    /// without a safe replay value (oversized response or an external
    /// operation with no replayable representation).
    CompletedNonReplayable,
    /// A record exists for this key but carries no usable replay provenance
    /// (legacy payload, corrupted value, or malformed digests). It can neither
    /// be replayed — that would skip the live presentation policy — nor be
    /// treated as a miss, which would re-execute a non-safe request whose
    /// original side effect may already have completed.
    UnprovableRecord,
    Conflict(DeduplicationConflict),
    /// Redis could not be consulted. The caller applies the configured
    /// unavailability policy; it must not silently take a purely local
    /// ownership decision unless the operator asked for that.
    Unavailable,
}

/// Parsed view of the operation record stored under one logical key.
enum RedisRecordState {
    Absent,
    /// An owner holds the operation. Carries the owner's request fingerprint.
    InFlight(String),
    /// The operation completed. Carries the fingerprint and, when the
    /// completion is safe to replay, its stored response. A completed record
    /// without a response is a deliberate non-replayable tombstone.
    Completed(String, Option<CachedResponse>),
    /// Present but not parseable as a current-version record. Treated as a
    /// conflict so an unknown peer format fails closed.
    Unreadable,
    /// A current-version completed record whose retained replay carries no
    /// decodable response-policy provenance. It can neither be replayed — that
    /// would skip the live presentation policy — nor be treated as a miss,
    /// which would re-execute a non-safe request whose original side effect may
    /// already have completed.
    Unprovable,
    Unavailable,
}

/// Fenced publication outcome.
enum RedisPublication {
    /// The operation record atomically transitioned from this request's
    /// in-flight ownership to a completed record. `replayable` is false when
    /// only a non-replayable tombstone could be published.
    Published {
        replayable: bool,
    },
    /// The still-current record is not this request's ownership token: the
    /// lease expired, a successor owns the operation, or the record is already
    /// completed. Nothing was written.
    NotOwner,
    Unavailable,
}

/// Redis in-flight ownership for one request.
///
/// The exact serialized in-flight record is retained alongside the token
/// because it is the compare operand for both fenced publication and fenced
/// release. Recomputing those bytes at completion time would make the fence
/// silently ineffective if the record representation ever drifted.
#[derive(Clone)]
pub(crate) struct RedisOwnership {
    record: Arc<Vec<u8>>,
}

impl RedisOwnership {
    fn new(fingerprint: &str, token: &str) -> Option<Self> {
        let record = SerializableDedupRecord::inflight(fingerprint, token);
        let bytes = serde_json::to_vec(&record).ok()?;
        Some(Self {
            record: Arc::new(bytes),
        })
    }
}

/// How Redis mode behaves when the centralized store cannot be consulted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RedisUnavailablePolicy {
    /// Refuse the request with 503 rather than making an ownership decision
    /// that only this process can see. Default: an operator who asked for
    /// centralized idempotency gets centralized idempotency or an error, never
    /// silently split per-process ownership.
    FailClosed,
    /// Explicitly accept process-local-only deduplication during a Redis
    /// outage. Availability is preserved at the cost of one execution per
    /// gateway process for the same idempotency key.
    LocalOnly,
}

enum RedisPayloadAdmission {
    Admitted(Vec<u8>),
    /// The response cannot be persisted: it does not fit the configured entry
    /// size, could not be serialized, or has incomplete replay provenance.
    /// Every case is handled identically by the caller — nothing is written and
    /// in-flight ownership is resolved by the existing storage-skip rules.
    Rejected,
}

enum LocalCompletionAction {
    Published {
        cached: CachedResponse,
        sequence: u64,
        completed_count: usize,
        inflight_count: usize,
    },
    Skipped {
        inflight_count: usize,
        reason: CompletionSkipReason,
        redis_candidate: Option<CachedResponse>,
    },
    Stale,
}

struct LocalCompletionCandidate<'a> {
    status_code: u16,
    headers: HashMap<String, String>,
    body: &'a [u8],
    publish_execution_barrier_on_skip: bool,
    retain_barrier_on_eviction: bool,
    /// See [`CachedResponse::retention`].
    retention: Duration,
    response_policy: ResponsePolicyProvenance,
}

enum CompletionSkipReason {
    EntryTooLarge {
        entry_size: usize,
    },
    TotalCapacity {
        entry_size: usize,
        current_total: usize,
    },
}

/// Request-private completion ownership for one configured plugin instance.
///
/// The values are hashed identities or opaque owner tokens, but they still do
/// not belong in public transaction metadata. `RequestContext` holds at most
/// one entry per deduplication instance attached to the matched proxy, so
/// multiple scoped instances (distinct headers / Redis prefixes) mark and
/// token-release independently without overwriting one another's lifecycle
/// state.
#[derive(Clone)]
pub(crate) struct RequestDeduplicationRequestState {
    key: String,
    fingerprint: String,
    local_inflight_owner_token: String,
    redis_lock_token: Option<RedisOwnership>,
}

impl fmt::Debug for RequestDeduplicationRequestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not delegate to any field or nested formatter. New fields stay
        // omitted by default until their diagnostic representation is reviewed.
        f.debug_struct("RequestDeduplicationRequestState")
            .field("key", &"<redacted>")
            .field("fingerprint", &"<redacted>")
            .field("local_inflight_owner_token", &"<redacted>")
            .field("redis_lock_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
pub(crate) fn set_request_state_for_test(
    plugin: &RequestDeduplication,
    ctx: &mut RequestContext,
    key: &str,
    fingerprint: &str,
    local_inflight_owner_token: &str,
    redis_lock_token: Option<&str>,
) {
    ctx.request_deduplication_states.insert(
        plugin.instance_id,
        RequestDeduplicationRequestState {
            key: key.to_string(),
            fingerprint: fingerprint.to_string(),
            local_inflight_owner_token: local_inflight_owner_token.to_string(),
            redis_lock_token: redis_lock_token
                .and_then(|token| RedisOwnership::new(fingerprint, token)),
        },
    );
}

/// Sorted logical keys acquired during `before_proxy` for external tests that
/// construct plugins through `PluginCache` / the production factory (trait
/// objects) rather than the concrete test helper.
#[allow(dead_code)]
pub(crate) fn logical_keys_from_request_context_for_test(ctx: &RequestContext) -> Vec<String> {
    let mut keys: Vec<String> = ctx
        .request_deduplication_states
        .values()
        .map(|state| state.key.clone())
        .collect();
    keys.sort();
    keys
}

static NEXT_REQUEST_DEDUPLICATION_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

pub struct RequestDeduplication {
    /// Process-unique ownership key for request-private completion state.
    instance_id: u64,
    /// Stable plugin-config identity shared by the same configured instance on
    /// every gateway. Included in logical keys so multiple Redis-backed
    /// instances cannot contend in one another's distributed key space.
    config_id: String,
    /// Header name to read the idempotency key from.
    header_name: String,
    /// Time-to-live for cached responses.
    ttl: Duration,
    /// How long an `InFlight` marker remains valid before being treated as
    /// stale and replaced by a new request. Must be set at or above the
    /// longest backend request that should be protected from concurrent
    /// duplicate execution; set too low, slow legitimate requests could have
    /// duplicate retries bypass the in-flight lock and re-execute side-effecting
    /// operations. Defaults to `ttl_seconds`.
    inflight_ttl: Duration,
    /// Maximum number of cached entries (local mode).
    max_entries: usize,
    /// Maximum retained size of one completed response entry.
    max_entry_size_bytes: usize,
    /// Maximum retained size across completed response entries.
    max_total_size_bytes: usize,
    /// HTTP methods to apply deduplication to.
    applicable_methods: Vec<String>,
    /// Whether to scope keys by authenticated consumer identity.
    scope_by_consumer: bool,
    /// Whether to require the idempotency header (reject if missing).
    enforce_required: bool,
    /// Behavior when `sync_mode: "redis"` is configured but Redis cannot be
    /// consulted. Only meaningful in Redis mode.
    on_redis_unavailable: RedisUnavailablePolicy,
    /// Local in-memory cache.
    local_cache: Arc<DashMap<String, DeduplicationEntry>>,
    completed_count: AtomicUsize,
    completed_size_bytes: AtomicUsize,
    inflight_count: AtomicUsize,
    /// Number of explicit per-key execution barriers. Unlike active in-flight
    /// work, this durable security state is hard-capped at `max_entries`.
    execution_barrier_count: AtomicUsize,
    /// Process-relative monotonic deadline for a single bounded fail-closed
    /// overflow barrier. When the per-key barrier budget is full, this one
    /// scalar protects every displaced key without retaining their identities.
    execution_barrier_overflow_until_ms: AtomicU64,
    local_inflight_sequence: AtomicU64,
    completed_sequence: AtomicU64,
    next_completed_evict_sequence: AtomicU64,
    completed_order: Arc<DashMap<u64, CompletedOrderEntry>>,
    accounting_lock: Mutex<()>,
    eviction_lock: Mutex<()>,
    /// Optional Redis client for centralized deduplication.
    redis_client: Option<Arc<RedisRateLimitClient>>,
    /// Monotonic-seconds timestamp (relative to `PROCESS_START`) of the last
    /// full cleanup scan, used to throttle scans to at most once per
    /// `CLEANUP_INTERVAL_SECS`. Initialized to `CLEANUP_NEVER` so the first
    /// applicable request runs a scan.
    last_cleanup: AtomicU64,
}

impl RequestDeduplication {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_instance_id(config, http_client, DEFAULT_INSTANCE_ID)
    }

    pub(crate) fn new_with_instance_id(
        config: &Value,
        http_client: PluginHttpClient,
        config_id: &str,
    ) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "request_deduplication: config must be an object".to_string())?;

        // Unknown root keys fail closed. A misspelled `enforce_required` would
        // otherwise leave the idempotency header optional, and a misspelled
        // `sync_mode` would leave centralized enforcement silently process-local
        // while admission reported the policy as loaded.
        crate::util::unknown_keys::reject_unknown_keys(
            object,
            "config",
            REQUEST_DEDUPLICATION_CONFIG_KEYS,
            "request_deduplication: ",
        )?;

        // Redis-only fields outside Redis mode are a configuration error rather
        // than inert data: the most common way to reach that state is a typo in
        // `sync_mode` itself, which is exactly the mistake that silently
        // downgrades cross-gateway enforcement to per-process state.
        let sync_mode = optional_string(config, "sync_mode")?.map(str::to_ascii_lowercase);
        if sync_mode.as_deref() != Some("redis") {
            let mut supplied: Vec<&str> = REDIS_ONLY_CONFIG_KEYS
                .iter()
                .copied()
                .filter(|key| object.contains_key(*key))
                .collect();
            if !supplied.is_empty() {
                supplied.sort_unstable();
                let rendered: Vec<String> = supplied
                    .into_iter()
                    .map(|key| format!("'config.{key}'"))
                    .collect();
                return Err(format!(
                    "request_deduplication: Redis-only configuration key(s) {} require \
                     sync_mode='redis' (did you mean to set sync_mode?)",
                    rendered.join(", ")
                ));
            }
        }

        // Stable plugin-config identity partitions Redis ownership across
        // sibling instances (global/proxy/proxy_group) that share a default or
        // explicit prefix. Reject blank IDs fail-closed so two miswired
        // constructors cannot collapse onto one distributed key space.
        // Process-local `instance_id` is intentionally not used here: it would
        // break intentional cross-gateway sharing for the same config.
        if config_id.trim().is_empty() {
            return Err(
                "request_deduplication: plugin config id must be a non-empty stable identity"
                    .to_string(),
            );
        }

        let header_name = parse_header_name(
            optional_string(config, "header_name")?.unwrap_or("Idempotency-Key"),
        )?;

        let ttl_seconds = optional_positive_u64(config, "ttl_seconds")?.unwrap_or(300);
        let ttl = Duration::from_secs(ttl_seconds);

        let inflight_ttl_seconds =
            optional_positive_u64(config, "inflight_ttl_seconds")?.unwrap_or(ttl_seconds);
        let inflight_ttl = Duration::from_secs(inflight_ttl_seconds);

        let max_entries = optional_positive_usize(config, "max_entries")?.unwrap_or(10_000);
        let max_entry_size_bytes = optional_positive_usize(config, "max_entry_size_bytes")?
            .unwrap_or(DEFAULT_MAX_ENTRY_SIZE_BYTES);
        let max_total_size_bytes = optional_positive_usize(config, "max_total_size_bytes")?
            .unwrap_or(DEFAULT_MAX_TOTAL_SIZE_BYTES);

        let applicable_methods = parse_applicable_methods(config)?;
        let scope_by_consumer = optional_bool(config, "scope_by_consumer")?.unwrap_or(true);
        let enforce_required = optional_bool(config, "enforce_required")?.unwrap_or(false);
        let on_redis_unavailable = match optional_string(config, "on_redis_unavailable")? {
            None => RedisUnavailablePolicy::FailClosed,
            Some("fail_closed") => RedisUnavailablePolicy::FailClosed,
            Some("local_only") => RedisUnavailablePolicy::LocalOnly,
            Some(_) => {
                // Value-redacted: the rejected string can be a mistyped secret.
                return Err(
                    "request_deduplication: 'on_redis_unavailable' must be exactly \
                     'fail_closed' or 'local_only'"
                        .to_string(),
                );
            }
        };
        let shard_amount = http_client.pool_shard_amount();

        // Build optional Redis client
        let default_prefix = default_redis_key_prefix(http_client.namespace());
        let redis_client =
            RedisConfig::from_plugin_config(config, &default_prefix)?.map(|redis_config| {
                let dns_cache = http_client.dns_cache();
                let tls_no_verify = http_client.tls_no_verify();
                let tls_ca_bundle_path = http_client.tls_ca_bundle_path();
                Arc::new(RedisRateLimitClient::new(
                    redis_config,
                    dns_cache.cloned(),
                    tls_no_verify,
                    tls_ca_bundle_path,
                ))
            });

        Ok(Self {
            instance_id: NEXT_REQUEST_DEDUPLICATION_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            // Preserve the configured resource identity byte-for-byte. Trimming
            // here would collapse distinct nonblank IDs onto one Redis keyspace.
            config_id: config_id.to_owned(),
            header_name,
            ttl,
            inflight_ttl,
            max_entries,
            max_entry_size_bytes,
            max_total_size_bytes,
            applicable_methods,
            scope_by_consumer,
            enforce_required,
            on_redis_unavailable,
            local_cache: Arc::new(DashMap::with_shard_amount(shard_amount)),
            completed_count: AtomicUsize::new(0),
            completed_size_bytes: AtomicUsize::new(0),
            inflight_count: AtomicUsize::new(0),
            execution_barrier_count: AtomicUsize::new(0),
            execution_barrier_overflow_until_ms: AtomicU64::new(0),
            local_inflight_sequence: AtomicU64::new(0),
            completed_sequence: AtomicU64::new(0),
            next_completed_evict_sequence: AtomicU64::new(0),
            completed_order: Arc::new(DashMap::with_shard_amount(shard_amount)),
            accounting_lock: Mutex::new(()),
            eviction_lock: Mutex::new(()),
            redis_client,
            last_cleanup: AtomicU64::new(CLEANUP_NEVER),
        })
    }

    /// Lifetime of a completion that exists only to refuse re-execution rather
    /// than to serve a representation of the real response: the non-replayable
    /// external-operation tombstone, and any Redis record published without a
    /// replay payload.
    ///
    /// Such a completion replaces an in-flight record that would otherwise have
    /// blocked duplicates for `inflight_ttl_seconds`, so it must never expire
    /// sooner than that. `inflight_ttl_seconds` may legitimately exceed
    /// `ttl_seconds` (a long-running backend with a short replay-retention
    /// window); publishing the barrier for only `ttl_seconds` there would make
    /// an already-performed billable operation executable again *earlier* than
    /// the bare marker did — the exposure GHSA-8cr6-rw38-7j59 closes.
    ///
    /// Ordinary replayable completions are unaffected and keep `ttl_seconds`:
    /// they answer a retry by replaying, and expiring on schedule is the
    /// documented meaning of `ttl_seconds`.
    fn execution_barrier_retention(&self) -> Duration {
        self.ttl.max(self.inflight_ttl)
    }

    fn try_reserve_execution_barrier(&self) -> bool {
        self.execution_barrier_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < self.max_entries).then_some(current + 1)
            })
            .is_ok()
    }

    fn release_execution_barrier(&self) {
        decrement_atomic(&self.execution_barrier_count);
    }

    /// Extend the one bounded overflow barrier to cover this completion's
    /// authoritative deadline.
    ///
    /// The deadline is derived from the original insertion instant, not from
    /// overflow detection time, so eviction cannot restart or shorten the
    /// completion clock. `fetch_max` composes concurrent displaced barriers
    /// without storing their keys.
    fn extend_execution_barrier_overflow(&self, inserted_at: Instant, retention: Duration) {
        let inserted_ms = inserted_at
            .checked_duration_since(*PROCESS_START)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let retention_ms = u64::try_from(retention.as_millis()).unwrap_or(u64::MAX);
        self.execution_barrier_overflow_until_ms
            .fetch_max(inserted_ms.saturating_add(retention_ms), Ordering::SeqCst);
    }

    fn execution_barrier_overflow_active(&self) -> bool {
        monotonic_millis()
            < self
                .execution_barrier_overflow_until_ms
                .load(Ordering::SeqCst)
    }

    fn accounting_guard(&self) -> MutexGuard<'_, ()> {
        self.accounting_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn add_completed_size_locked(&self, size: usize) {
        if size == 0 {
            return;
        }
        let current = self.completed_size_bytes.load(Ordering::Relaxed);
        self.completed_size_bytes
            .store(current.saturating_add(size), Ordering::Relaxed);
    }

    fn sub_completed_size_locked(&self, size: usize) {
        if size == 0 {
            return;
        }
        let current = self.completed_size_bytes.load(Ordering::Relaxed);
        self.completed_size_bytes
            .store(current.saturating_sub(size), Ordering::Relaxed);
    }

    fn next_local_inflight_owner_token(&self) -> String {
        self.local_inflight_sequence
            .fetch_add(1, Ordering::Relaxed)
            .to_string()
    }

    fn actual_completed_size_locked(&self) -> usize {
        self.local_cache
            .iter()
            .map(|entry| match entry.value() {
                DeduplicationEntry::Completed { cached, .. } => cached.retained_size(),
                DeduplicationEntry::InFlight { .. }
                | DeduplicationEntry::ExecutionBarrier { .. } => 0,
            })
            .sum()
    }

    #[allow(dead_code)]
    pub(crate) fn completed_size_snapshot_for_tests(&self) -> (usize, usize) {
        let _guard = self.accounting_guard();
        (
            self.completed_size_bytes.load(Ordering::Relaxed),
            self.actual_completed_size_locked(),
        )
    }

    #[allow(dead_code)]
    pub(crate) fn request_identity_for_tests(
        &self,
        ctx: &RequestContext,
    ) -> Option<(String, String)> {
        ctx.request_deduplication_states
            .get(&self.instance_id)
            .map(|state| (state.key.clone(), state.fingerprint.clone()))
    }

    #[allow(dead_code)]
    pub(crate) fn expire_completed_entries_for_tests(&self) {
        let _guard = self.accounting_guard();
        let now = Instant::now();
        for mut entry in self.local_cache.iter_mut() {
            if let DeduplicationEntry::Completed { cached, .. } = entry.value_mut() {
                // Per-entry retention: an execution-barrier tombstone outlives
                // `ttl_seconds`, so back-date past its own retention window.
                cached.inserted_at = now
                    .checked_sub(cached.retention.saturating_add(Duration::from_secs(1)))
                    .unwrap_or(now);
            }
        }
        self.last_cleanup.store(CLEANUP_NEVER, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn expire_inflight_entries_for_tests(&self) {
        let _guard = self.accounting_guard();
        let expired_at = Instant::now()
            .checked_sub(self.inflight_ttl.saturating_add(Duration::from_secs(1)))
            .unwrap_or_else(Instant::now);
        for mut entry in self.local_cache.iter_mut() {
            if let DeduplicationEntry::InFlight { started_at, .. } = entry.value_mut() {
                *started_at = expired_at;
            }
        }
        self.last_cleanup.store(CLEANUP_NEVER, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn expire_execution_barriers_for_tests(&self) {
        let _guard = self.accounting_guard();
        let now = Instant::now();
        for mut entry in self.local_cache.iter_mut() {
            if let DeduplicationEntry::ExecutionBarrier {
                inserted_at,
                retention,
                ..
            } = entry.value_mut()
            {
                *inserted_at = now
                    .checked_sub(retention.saturating_add(Duration::from_secs(1)))
                    .unwrap_or(now);
            }
        }
        self.execution_barrier_overflow_until_ms
            .store(0, Ordering::SeqCst);
        self.last_cleanup.store(CLEANUP_NEVER, Ordering::Relaxed);
    }

    /// Build the logical deduplication key from unambiguous framed fields.
    ///
    /// The returned key intentionally contains only a versioned digest so
    /// Redis keys and request metadata never expose idempotency values or
    /// authenticated identities.
    fn build_key(&self, ctx: &RequestContext, idempotency_value: &str) -> String {
        let mut hasher = Sha256::new();
        hash_framed(&mut hasher, "version", DEDUP_LOGICAL_KEY_VERSION.as_bytes());
        hash_framed(&mut hasher, "plugin_config_id", self.config_id.as_bytes());
        // The Redis prefix is operator-configurable and may deliberately be
        // shared across namespaces. Namespace therefore belongs in the
        // authenticated logical identity itself, not only in the default
        // prefix, so equal resource IDs in separate namespaces cannot claim or
        // replay one another's operation.
        if let Some(proxy) = ctx.matched_proxy.as_ref() {
            hash_framed(&mut hasher, "matched_proxy", b"1");
            hash_framed(&mut hasher, "proxy_namespace", proxy.namespace.as_bytes());
            hash_framed(&mut hasher, "proxy_id", proxy.id.as_bytes());
        } else {
            // Frame presence explicitly rather than reserving a sentinel that
            // could collide with a valid namespace/resource identifier.
            hash_framed(&mut hasher, "matched_proxy", b"0");
        }
        if self.scope_by_consumer
            && let Some(identity) = ctx.effective_identity()
        {
            hash_framed(&mut hasher, "principal", identity.as_bytes());
        }
        if let Some(peer_spiffe_id) = ctx.peer_spiffe_id.as_ref() {
            hash_framed(
                &mut hasher,
                "peer_spiffe_id",
                peer_spiffe_id.as_str().as_bytes(),
            );
        }
        hash_framed(&mut hasher, "idempotency_key", idempotency_value.as_bytes());

        let mut key = String::with_capacity(67);
        key.push_str("v4:");
        key.push_str(&hex::encode(hasher.finalize()));
        key
    }

    fn replay_response(&self, ctx: &mut RequestContext, cached: &CachedResponse) -> PluginResult {
        // The replay below suppresses ordinary presentation transforms, so it
        // is sound only while the stored bytes are provably the product of the
        // live response-side policy — both the RTDS gate content and the
        // effective static rules. Any difference retires the representation,
        // and so does an unprovable policy on either side: `admits_replay_of`
        // refuses two incomplete values rather than letting "unknown" match
        // "unknown". That is what fails a proxy carrying a
        // `ResponsePresentationPolicy::Dynamic` plugin closed on the local
        // path, where nothing else would have caught it.
        // 409 rather than a re-execution: the original backend side effect may
        // already have run under this idempotency key.
        let live_policy = ctx.response_policy_provenance();
        if !live_policy.admits_replay_of(&cached.response_policy) {
            // Distinguish the two refusals for operators: a policy that moved
            // is a transient, self-healing state, while an unestablished policy
            // means this proxy composes deduplication with a presentation
            // plugin whose rewrite cannot be witnessed and will never replay.
            let body = if live_policy.complete().is_none()
                || cached.response_policy.complete().is_none()
            {
                r#"{"error":"The response policy for this request could not be established, so a stored idempotent response cannot be replayed"}"#
            } else {
                r#"{"error":"The stored idempotent response was produced under a superseded response policy"}"#
            };
            return PluginResult::Reject {
                status_code: 409,
                body: body.to_string(),
                headers: HashMap::new(),
            };
        }
        // Stored bytes have already passed the final response-body lifecycle.
        // Suppress ordinary presentation transforms on this synthetic replay;
        // current inspection/final validation still runs, and a new redaction
        // decision can opt only its mandatory transform back in. Ordinary
        // rejection header hooks still run and cache headers are re-sanitized.
        ctx.finalized_response_replay = true;
        ctx.metadata.insert(
            "request_deduplication.replayed".to_string(),
            "true".to_string(),
        );
        let mut response_headers = sanitize_cached_headers(&cached.headers);
        response_headers.insert("x-idempotent-replayed".to_string(), "true".to_string());
        PluginResult::RejectBinary {
            status_code: cached.status_code,
            body: cached.body.clone(),
            headers: response_headers,
        }
    }

    fn build_request_fingerprint(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Result<String, PluginResult> {
        let mut hasher = Sha256::new();
        hash_framed(&mut hasher, "version", DEDUP_FINGERPRINT_VERSION.as_bytes());
        hash_framed(
            &mut hasher,
            "method",
            ctx.method.to_ascii_uppercase().as_bytes(),
        );
        hash_framed(
            &mut hasher,
            "authority",
            canonical_authority(headers).as_bytes(),
        );
        hash_framed(&mut hasher, "path", ctx.path.as_bytes());
        hash_framed(
            &mut hasher,
            "query",
            ctx.raw_query_string().unwrap_or("").as_bytes(),
        );
        let exclude_scoped_credentials =
            self.scope_by_consumer && ctx.effective_identity().is_some();
        for (header_name, value) in
            request_headers_for_fingerprint(headers, &self.header_name, exclude_scoped_credentials)
        {
            hash_framed(&mut hasher, "header_name", header_name.as_bytes());
            hash_framed(&mut hasher, "header_value", value.as_bytes());
        }
        let body_digest = request_body_digest(ctx, headers)?;
        hash_framed(&mut hasher, "body_digest", body_digest.as_bytes());

        Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
    }

    fn local_lookup_or_mark_inflight(
        &self,
        key: &str,
        fingerprint: &str,
        now: Instant,
        owner_token: &str,
    ) -> LocalDeduplicationAction {
        match self.local_cache.entry(key.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(DeduplicationEntry::InFlight {
                    started_at: now,
                    fingerprint: fingerprint.to_string(),
                    owner_token: owner_token.to_string(),
                });
                self.inflight_count.fetch_add(1, Ordering::Relaxed);
                LocalDeduplicationAction::Fresh
            }
            Entry::Occupied(mut entry) => {
                match entry.get() {
                    DeduplicationEntry::Completed {
                        cached,
                        fingerprint: cached_fingerprint,
                        ..
                    } => {
                        if now.duration_since(cached.inserted_at) < cached.retention {
                            if cached_fingerprint == fingerprint {
                                return LocalDeduplicationAction::Replay(cached.clone());
                            }
                            return LocalDeduplicationAction::Conflict(
                                DeduplicationConflict::FingerprintMismatch,
                            );
                        }
                    }
                    DeduplicationEntry::ExecutionBarrier {
                        inserted_at,
                        retention,
                        fingerprint: cached_fingerprint,
                        ..
                    } => {
                        if now.duration_since(*inserted_at) < *retention {
                            if cached_fingerprint == fingerprint {
                                return LocalDeduplicationAction::Conflict(
                                    DeduplicationConflict::InFlight,
                                );
                            }
                            return LocalDeduplicationAction::Conflict(
                                DeduplicationConflict::FingerprintMismatch,
                            );
                        }
                    }
                    DeduplicationEntry::InFlight {
                        started_at,
                        fingerprint: cached_fingerprint,
                        ..
                    } => {
                        if now.duration_since(*started_at) >= self.inflight_ttl {
                            entry.insert(DeduplicationEntry::InFlight {
                                started_at: now,
                                fingerprint: fingerprint.to_string(),
                                owner_token: owner_token.to_string(),
                            });
                            return LocalDeduplicationAction::Fresh;
                        }
                        if cached_fingerprint == fingerprint {
                            return LocalDeduplicationAction::Conflict(
                                DeduplicationConflict::InFlight,
                            );
                        }
                        return LocalDeduplicationAction::Conflict(
                            DeduplicationConflict::FingerprintMismatch,
                        );
                    }
                }
                drop(entry);
                self.replace_expired_entry_with_inflight(key, fingerprint, now, owner_token)
            }
        }
    }

    fn matching_local_completed(
        &self,
        key: &str,
        fingerprint: &str,
        now: Instant,
    ) -> Option<CachedResponse> {
        self.local_cache.get(key).and_then(|entry| {
            let DeduplicationEntry::Completed {
                cached,
                fingerprint: cached_fingerprint,
                ..
            } = entry.value()
            else {
                return None;
            };
            if cached_fingerprint == fingerprint
                && now.duration_since(cached.inserted_at) < cached.retention
            {
                Some(cached.clone())
            } else {
                None
            }
        })
    }

    fn replace_expired_entry_with_inflight(
        &self,
        key: &str,
        fingerprint: &str,
        now: Instant,
        owner_token: &str,
    ) -> LocalDeduplicationAction {
        let _guard = self.accounting_guard();
        match self.local_cache.entry(key.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(DeduplicationEntry::InFlight {
                    started_at: now,
                    fingerprint: fingerprint.to_string(),
                    owner_token: owner_token.to_string(),
                });
                self.inflight_count.fetch_add(1, Ordering::Relaxed);
                LocalDeduplicationAction::Fresh
            }
            Entry::Occupied(mut entry) => match entry.get() {
                DeduplicationEntry::Completed {
                    cached,
                    sequence,
                    fingerprint: cached_fingerprint,
                    ..
                } => {
                    if now.duration_since(cached.inserted_at) < cached.retention {
                        if cached_fingerprint == fingerprint {
                            LocalDeduplicationAction::Replay(cached.clone())
                        } else {
                            LocalDeduplicationAction::Conflict(
                                DeduplicationConflict::FingerprintMismatch,
                            )
                        }
                    } else {
                        let retained_size = cached.retained_size();
                        self.mark_completed_sequence_pruned(*sequence);
                        self.sub_completed_size_locked(retained_size);
                        decrement_atomic(&self.completed_count);
                        self.inflight_count.fetch_add(1, Ordering::Relaxed);
                        entry.insert(DeduplicationEntry::InFlight {
                            started_at: now,
                            fingerprint: fingerprint.to_string(),
                            owner_token: owner_token.to_string(),
                        });
                        LocalDeduplicationAction::Fresh
                    }
                }
                DeduplicationEntry::ExecutionBarrier {
                    inserted_at,
                    retention,
                    fingerprint: cached_fingerprint,
                    ..
                } => {
                    if now.duration_since(*inserted_at) < *retention {
                        if cached_fingerprint == fingerprint {
                            LocalDeduplicationAction::Conflict(DeduplicationConflict::InFlight)
                        } else {
                            LocalDeduplicationAction::Conflict(
                                DeduplicationConflict::FingerprintMismatch,
                            )
                        }
                    } else {
                        // A barrier is accounted with the in-flight/fixed-state
                        // counter. Replacing it in place preserves cardinality.
                        self.release_execution_barrier();
                        entry.insert(DeduplicationEntry::InFlight {
                            started_at: now,
                            fingerprint: fingerprint.to_string(),
                            owner_token: owner_token.to_string(),
                        });
                        LocalDeduplicationAction::Fresh
                    }
                }
                DeduplicationEntry::InFlight {
                    started_at,
                    fingerprint: cached_fingerprint,
                    ..
                } => {
                    if now.duration_since(*started_at) >= self.inflight_ttl {
                        entry.insert(DeduplicationEntry::InFlight {
                            started_at: now,
                            fingerprint: fingerprint.to_string(),
                            owner_token: owner_token.to_string(),
                        });
                        LocalDeduplicationAction::Fresh
                    } else if cached_fingerprint == fingerprint {
                        LocalDeduplicationAction::Conflict(DeduplicationConflict::InFlight)
                    } else {
                        LocalDeduplicationAction::Conflict(
                            DeduplicationConflict::FingerprintMismatch,
                        )
                    }
                }
            },
        }
    }

    /// Read and classify the single operation record for a logical key.
    ///
    /// Ownership and completion share one Redis key so that publishing a result
    /// *is* the ownership transition. A peer therefore never observes a state
    /// where both the in-flight marker and the completed response are missing,
    /// and never observes a completed response while a successor still owns the
    /// operation.
    async fn redis_read_record(
        &self,
        redis: &RedisRateLimitClient,
        redis_key: &str,
    ) -> RedisRecordState {
        let data = match redis.get_bytes(redis_key).await {
            Ok(Some(data)) => data,
            Ok(None) => return RedisRecordState::Absent,
            Err(()) => return RedisRecordState::Unavailable,
        };

        let Ok(record) = serde_json::from_slice::<SerializableDedupRecord>(&data) else {
            return RedisRecordState::Unreadable;
        };
        if !record.has_valid_current_shape() {
            return RedisRecordState::Unreadable;
        }
        match record.state.as_str() {
            DEDUP_RECORD_STATE_INFLIGHT => RedisRecordState::InFlight(record.fingerprint),
            DEDUP_RECORD_STATE_COMPLETED => {
                let fingerprint = record.fingerprint;
                let replay = match record.replay {
                    // A retained replay is only usable while its response-policy
                    // provenance decodes. Malformed digests can never be shown
                    // compatible with the live presentation policy, so the whole
                    // record fails closed rather than replaying on an assumed
                    // policy or being mistaken for a miss.
                    Some(replay) => {
                        let Some(response_policy) = replay.response_policy.decode() else {
                            debug!(
                                "request_deduplication: Redis idempotency record carries \
                                 malformed replay provenance; refusing replay"
                            );
                            return RedisRecordState::Unprovable;
                        };
                        Some(CachedResponse {
                            status_code: replay.status_code,
                            headers: replay.headers,
                            body: Bytes::from(replay.body),
                            // Neither field is meaningful for a Redis-sourced
                            // record: expiry is enforced by the key TTL, and
                            // this value is only ever replayed, never inserted
                            // into the local map.
                            inserted_at: Instant::now(),
                            retention: self.ttl,
                            response_policy,
                        })
                    }
                    // A deliberate non-replayable tombstone carries no bytes and
                    // therefore makes no presentation-policy claim.
                    None => None,
                };
                RedisRecordState::Completed(fingerprint, replay)
            }
            _ => RedisRecordState::Unreadable,
        }
    }

    /// Acquire the operation record for this request, or classify whoever
    /// currently owns or completed it.
    async fn redis_admit(&self, key: &str, fingerprint: &str) -> RedisAdmission {
        let Some(redis) = self.redis_client.as_ref() else {
            return RedisAdmission::Unavailable;
        };
        if !redis.is_available() {
            return RedisAdmission::Unavailable;
        }

        let redis_key = redis.make_key(&[key]);
        let inflight_ttl_seconds = self.inflight_ttl.as_secs().max(1);
        for _ in 0..REDIS_ADMISSION_ATTEMPTS {
            let token = uuid::Uuid::new_v4().to_string();
            let Some(ownership) = RedisOwnership::new(fingerprint, &token) else {
                return RedisAdmission::Unavailable;
            };

            match redis
                .set_bytes_nx_with_expire(&redis_key, &ownership.record, inflight_ttl_seconds)
                .await
            {
                Ok(true) => return RedisAdmission::Acquired(ownership),
                Ok(false) => {}
                Err(()) => return RedisAdmission::Unavailable,
            }

            match self.redis_read_record(redis, &redis_key).await {
                // Expired inside the acquire/observe window; try to take it.
                RedisRecordState::Absent => continue,
                RedisRecordState::InFlight(current) => {
                    return RedisAdmission::Conflict(if current == fingerprint {
                        DeduplicationConflict::InFlight
                    } else {
                        DeduplicationConflict::FingerprintMismatch
                    });
                }
                RedisRecordState::Completed(current, replay) => {
                    if current != fingerprint {
                        return RedisAdmission::Conflict(
                            DeduplicationConflict::FingerprintMismatch,
                        );
                    }
                    return match replay {
                        Some(cached) => RedisAdmission::Replay(cached),
                        None => RedisAdmission::CompletedNonReplayable,
                    };
                }
                // An unknown record format is another writer's state. Fail
                // closed rather than overwriting or ignoring it.
                RedisRecordState::Unreadable => {
                    return RedisAdmission::Conflict(DeduplicationConflict::InFlight);
                }
                // A completed record whose replay provenance cannot be decoded
                // is refused explicitly: it is neither replayable under the live
                // presentation policy nor safe to re-execute.
                RedisRecordState::Unprovable => return RedisAdmission::UnprovableRecord,
                RedisRecordState::Unavailable => return RedisAdmission::Unavailable,
            }
        }

        RedisAdmission::Conflict(DeduplicationConflict::InFlight)
    }

    /// Release this request's in-flight ownership, if and only if the record is
    /// still byte-for-byte this request's own in-flight record.
    ///
    /// A stale owner whose lease already expired — or whose record was replaced
    /// by a successor — deletes nothing.
    async fn redis_release_inflight(&self, key: &str, ownership: &RedisOwnership) {
        let Some(redis) = self.redis_client.as_ref() else {
            return;
        };
        if !redis.is_available() {
            return;
        }

        let redis_key = redis.make_key(&[key]);
        if let Err(()) = redis
            .delete_if_value_matches(&redis_key, &ownership.record)
            .await
        {
            debug!("request_deduplication: Redis in-flight lock release failed");
        }
    }

    /// Atomically transition this request's in-flight record into a completed
    /// record, fenced on the still-current ownership token.
    ///
    /// This is the fix for the stale-owner overwrite: an owner whose
    /// `inflight_ttl_seconds` lease expired can neither resurrect the key (the
    /// compare operand is absent) nor overwrite a successor's in-flight or
    /// completed record (the compare operand differs). Both completion orders
    /// therefore preserve the first authoritative completion.
    ///
    /// When `response` is absent, or its serialized payload exceeds
    /// `max_entry_size_bytes`, a small non-replayable completed tombstone is
    /// published instead. That still transitions ownership, so peers receive a
    /// deterministic conflict rather than being freed to re-execute the
    /// operation once the raw in-flight lease expires.
    ///
    /// `execution_barrier` marks a publication whose only purpose is refusing
    /// re-execution — the fixed external-operation tombstone. Together with a
    /// record that carries no replay payload at all, it selects
    /// [`Self::execution_barrier_retention`] as the record TTL so the barrier
    /// can never expire sooner than the in-flight lease it replaced.
    async fn redis_publish_completed(
        &self,
        key: &str,
        fingerprint: &str,
        ownership: &RedisOwnership,
        response: Option<&CachedResponse>,
        execution_barrier: bool,
    ) -> RedisPublication {
        let Some(redis) = self.redis_client.as_ref() else {
            return RedisPublication::Unavailable;
        };
        if !redis.is_available() {
            return RedisPublication::Unavailable;
        }

        let replay = response.and_then(|response| {
            // A retained replay must carry complete provenance: `Rejected`
            // already covers an incomplete value, and the digests are read from
            // the same provenance the admission check validated.
            let (gate, presentation) = response.response_policy.complete()?;
            match self.redis_payload_for_response(fingerprint, response) {
                RedisPayloadAdmission::Admitted(_) => Some(SerializableCachedResponse {
                    fingerprint: fingerprint.to_string(),
                    response_policy: SerializableResponsePolicyProvenance::encode(
                        gate,
                        presentation,
                    ),
                    status_code: response.status_code,
                    headers: response.headers.clone(),
                    body: response.body.to_vec(),
                }),
                RedisPayloadAdmission::Rejected => None,
            }
        });
        let replayable = replay.is_some();
        // A record with no replay payload, and the fixed external-operation
        // tombstone, exist only to refuse re-execution. Publishing either for
        // `ttl_seconds` when `inflight_ttl_seconds` is longer would free the key
        // earlier than the in-flight record it replaces.
        let record_ttl = if replayable && !execution_barrier {
            self.ttl
        } else {
            self.execution_barrier_retention()
        };
        let record = SerializableDedupRecord::completed(fingerprint, replay);
        let Ok(record_bytes) = serde_json::to_vec(&record) else {
            return RedisPublication::Unavailable;
        };

        let redis_key = redis.make_key(&[key]);
        match redis
            .set_bytes_with_expire_if_value_matches(
                &redis_key,
                &ownership.record,
                &record_bytes,
                record_ttl.as_secs().max(1),
            )
            .await
        {
            Ok(true) => RedisPublication::Published { replayable },
            Ok(false) => {
                debug!(
                    "request_deduplication: refusing stale-owner Redis publication; a successor \
                     or completed record owns this idempotency key"
                );
                RedisPublication::NotOwner
            }
            Err(()) => {
                debug!("request_deduplication: fenced Redis publication failed");
                RedisPublication::Unavailable
            }
        }
    }

    /// Whether this instance's ownership covers a synthetic response whose own
    /// execution already performed the protected external operation.
    ///
    /// This is the synthetic-response provenance contract: a short-circuit that
    /// merely fabricated a representation (mock, fault, cache hit) is safe to
    /// release, while a short-circuit that spent money or mutated remote state
    /// (`serverless_function` terminate mode, an `ai_federation` provider call)
    /// must leave a completion behind. See
    /// `EXTERNAL_OPERATION_COMPLETED_METADATA_KEY` in `src/plugins/mod.rs`.
    fn owns_completed_external_operation(&self, ctx: &RequestContext) -> bool {
        let key = super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY;
        let owns_state = ctx
            .request_deduplication_states
            .contains_key(&self.instance_id);
        let serverless_owner = ctx
            .serverless_external_side_effect_owners
            .contains(&self.instance_id);
        owns_state && (serverless_owner || ctx.metadata.contains_key(key))
    }

    /// Publish a durable, non-replayable completion for an external operation
    /// that has no safe replay value.
    ///
    /// The stored value is a small deterministic 409 so an identical retry is
    /// refused for [`Self::execution_barrier_retention`] instead of re-running
    /// the operation once the raw in-flight lease expires. Interrupted delivery
    /// of a synthetic externally-executed response therefore cannot silently
    /// repeat a charge.
    async fn publish_external_operation_tombstone(&self, ctx: &mut RequestContext) {
        let external_key = super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY;
        let synthetic_key = crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY;
        if !ctx
            .request_deduplication_states
            .contains_key(&self.instance_id)
        {
            return;
        }
        // Consume only this instance's provenance; sibling instances publish
        // their own tombstones from their own hooks.
        ctx.serverless_external_side_effect_owners
            .remove(&self.instance_id);
        // The publication path must run instead of the retain-and-return
        // synthetic guard, so the synthetic marker is cleared around the call
        // and restored for any later hook that observes it.
        let synthetic_marker = ctx.metadata.remove(synthetic_key);
        let had_external_marker = ctx.metadata.contains_key(external_key);
        if !had_external_marker {
            ctx.metadata
                .insert(external_key.to_string(), "true".to_string());
        }

        let headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
        ]);
        let body = NON_REPLAYABLE_COMPLETION_BODY.as_bytes();
        // Exempt this fixed refusal from the replay-provenance gates; see
        // `EXTERNAL_OPERATION_TOMBSTONE_PUBLICATION_KEY`.
        ctx.metadata.insert(
            EXTERNAL_OPERATION_TOMBSTONE_PUBLICATION_KEY.to_string(),
            self.instance_id.to_string(),
        );
        let _ = self.on_final_response_body(ctx, 409, &headers, body).await;
        ctx.metadata
            .remove(EXTERNAL_OPERATION_TOMBSTONE_PUBLICATION_KEY);

        if !had_external_marker {
            ctx.metadata.remove(external_key);
        }
        if let Some(marker) = synthetic_marker {
            ctx.metadata.insert(synthetic_key.to_string(), marker);
        }
    }

    /// Park the in-flight ownership `on_final_response_body` consumed back into
    /// the request so a durable execution barrier can still be published for it.
    ///
    /// `on_final_response_body` takes the request state before its first await,
    /// so a later refusal to persist a replayable representation — a straddled
    /// response-policy publication, or provenance that is incomplete/`Dynamic` —
    /// would otherwise leave an already-performed external operation protected by
    /// nothing but the raw `inflight_ttl_seconds` lease. Once that lease expires
    /// the operation becomes executable again, which is exactly the window
    /// GHSA-8cr6-rw38-7j59 closes.
    ///
    /// Parking the *same* ownership (same key, fingerprint, local token and Redis
    /// lock token) is the lifecycle signal the committed hook reads: state still
    /// present after a publication attempt means the representation was refused,
    /// and the fixed non-replayable 409 tombstone must take the key through the
    /// ordinary fenced transition instead. Nothing is published here, so sibling
    /// instances and successor-owner fencing are untouched.
    ///
    /// Only owners of an external operation park. An ordinary request that merely
    /// gives up its replay is safe to retry, and holding a barrier for it would
    /// turn unprovable provenance into a hard 409 lockout.
    fn park_ownership_for_execution_barrier(
        &self,
        ctx: &mut RequestContext,
        owns_external_operation: bool,
        state: RequestDeduplicationRequestState,
    ) {
        if !owns_external_operation {
            return;
        }
        ctx.request_deduplication_states
            .insert(self.instance_id, state);
    }

    /// Drop a completed entry this request published but that the distributed
    /// fence rejected, so a non-authoritative result is never replayed locally.
    fn remove_local_completed(&self, key: &str, fingerprint: &str, sequence: u64) {
        let _guard = self.accounting_guard();
        let Entry::Occupied(entry) = self.local_cache.entry(key.to_string()) else {
            return;
        };
        let retained_size = match entry.get() {
            DeduplicationEntry::Completed {
                cached,
                sequence: current,
                fingerprint: current_fingerprint,
                ..
            } if *current == sequence && current_fingerprint.as_str() == fingerprint => {
                cached.retained_size()
            }
            _ => return,
        };
        entry.remove();
        self.mark_completed_sequence_pruned(sequence);
        self.sub_completed_size_locked(retained_size);
        decrement_atomic(&self.completed_count);
    }

    fn redis_payload_for_response(
        &self,
        fingerprint: &str,
        response: &CachedResponse,
    ) -> RedisPayloadAdmission {
        // A representation persisted to Redis outlives this instance, this
        // cache generation, and this process, so it may only be written with
        // complete provenance. An incomplete value means the request never
        // observed the effective static presentation policy; recording it would
        // assert a compatibility claim that no later reader could check.
        let Some((gate, presentation)) = response.response_policy.complete() else {
            debug!(
                "request_deduplication: response-side presentation policy could not be \
                 established for this request; refusing to persist a replayable representation"
            );
            return RedisPayloadAdmission::Rejected;
        };

        let entry_size = response.retained_size();
        if entry_size > self.max_entry_size_bytes {
            debug!(
                entry_size,
                max_entry_size_bytes = self.max_entry_size_bytes,
                "request_deduplication: completed response exceeds Redis entry size limit, skipping store"
            );
            return RedisPayloadAdmission::Rejected;
        }

        let serializable = SerializableCachedResponse {
            fingerprint: fingerprint.to_string(),
            response_policy: SerializableResponsePolicyProvenance::encode(gate, presentation),
            status_code: response.status_code,
            headers: response.headers.clone(),
            body: response.body.to_vec(),
        };

        let data = match serde_json::to_vec(&serializable) {
            Ok(data) => data,
            Err(_) => return RedisPayloadAdmission::Rejected,
        };
        if data.len() > self.max_entry_size_bytes {
            debug!(
                payload_size = data.len(),
                max_entry_size_bytes = self.max_entry_size_bytes,
                "request_deduplication: serialized Redis response exceeds entry size limit, skipping store"
            );
            return RedisPayloadAdmission::Rejected;
        }
        RedisPayloadAdmission::Admitted(data)
    }

    fn remove_matching_local_inflight(
        &self,
        key: &str,
        fingerprint: &str,
        owner_token: &str,
    ) -> Option<usize> {
        self.local_cache
            .remove_if(key, |_, entry| {
                matches!(
                    entry,
                    DeduplicationEntry::InFlight {
                        fingerprint: current,
                        owner_token: current_owner_token,
                        ..
                    } if current == fingerprint && current_owner_token == owner_token
                )
            })
            .map(|_| decrement_atomic(&self.inflight_count))
    }

    /// Remove only the execution barrier published by this exact local owner.
    ///
    /// Used when Redis's compare-and-set reports that this publisher is stale.
    /// If the barrier expired and a successor acquired the key, the successor is
    /// an `InFlight` entry with a different token and is therefore untouched.
    fn remove_matching_local_execution_barrier(
        &self,
        key: &str,
        fingerprint: &str,
        owner_token: &str,
    ) -> Option<usize> {
        self.local_cache
            .remove_if(key, |_, entry| {
                matches!(
                    entry,
                    DeduplicationEntry::ExecutionBarrier {
                        fingerprint: current,
                        owner_token: current_owner_token,
                        ..
                    } if current == fingerprint && current_owner_token == owner_token
                )
            })
            .map(|_| {
                self.release_execution_barrier();
                decrement_atomic(&self.inflight_count)
            })
    }

    /// Build the Redis payload a completed response would produce.
    ///
    /// `presentation_digest` is the effective static response-presentation
    /// policy digest a real request would have copied from its plugin-cache
    /// view; `None` reproduces a request that never observed one, which must
    /// refuse to persist.
    #[allow(dead_code)]
    pub(crate) fn redis_payload_for_tests(
        &self,
        status_code: u16,
        headers: HashMap<String, String>,
        body: &[u8],
        presentation_digest: Option<[u8; 32]>,
    ) -> Option<Vec<u8>> {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/test".to_string(),
        );
        ctx.set_response_presentation_policy_digest(presentation_digest);
        let response = CachedResponse {
            status_code,
            headers,
            body: Bytes::copy_from_slice(body),
            inserted_at: Instant::now(),
            retention: self.ttl,
            response_policy: ctx.response_policy_provenance(),
        };
        match self.redis_payload_for_response("test-fingerprint", &response) {
            RedisPayloadAdmission::Admitted(payload) => Some(payload),
            RedisPayloadAdmission::Rejected => None,
        }
    }

    fn local_publish_completed(
        &self,
        key: &str,
        fingerprint: &str,
        owner_token: &str,
        candidate: LocalCompletionCandidate<'_>,
    ) -> LocalCompletionAction {
        let LocalCompletionCandidate {
            status_code,
            headers,
            body,
            publish_execution_barrier_on_skip,
            retain_barrier_on_eviction,
            retention,
            response_policy,
        } = candidate;
        let entry_size = cached_response_retained_size(body.len(), &headers);
        let _guard = self.accounting_guard();
        let mut entry = match self.local_cache.entry(key.to_string()) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return LocalCompletionAction::Stale,
        };

        match entry.get() {
            DeduplicationEntry::InFlight {
                fingerprint: current_fingerprint,
                owner_token: current_owner_token,
                ..
            } if current_fingerprint == fingerprint && current_owner_token == owner_token => {}
            _ => return LocalCompletionAction::Stale,
        }

        if entry_size > self.max_entry_size_bytes {
            let inflight_count = if publish_execution_barrier_on_skip {
                let inserted_at = Instant::now();
                if self.try_reserve_execution_barrier() {
                    entry.insert(DeduplicationEntry::ExecutionBarrier {
                        inserted_at,
                        retention,
                        fingerprint: fingerprint.to_string(),
                        owner_token: owner_token.to_string(),
                    });
                } else {
                    self.extend_execution_barrier_overflow(inserted_at, retention);
                }
                self.inflight_count.load(Ordering::Relaxed)
            } else {
                entry.remove();
                decrement_atomic(&self.inflight_count)
            };
            return LocalCompletionAction::Skipped {
                inflight_count,
                reason: CompletionSkipReason::EntryTooLarge { entry_size },
                redis_candidate: None,
            };
        }

        let current_total = self.completed_size_bytes.load(Ordering::Relaxed);
        if current_total.saturating_add(entry_size) > self.max_total_size_bytes {
            if publish_execution_barrier_on_skip {
                let inserted_at = Instant::now();
                if self.try_reserve_execution_barrier() {
                    entry.insert(DeduplicationEntry::ExecutionBarrier {
                        inserted_at,
                        retention,
                        fingerprint: fingerprint.to_string(),
                        owner_token: owner_token.to_string(),
                    });
                } else {
                    self.extend_execution_barrier_overflow(inserted_at, retention);
                }
            }
            let redis_candidate = if self.redis_client.is_some() {
                Some(CachedResponse {
                    status_code,
                    headers,
                    body: Bytes::copy_from_slice(body),
                    inserted_at: Instant::now(),
                    retention,
                    response_policy,
                })
            } else {
                if !publish_execution_barrier_on_skip {
                    entry.remove();
                }
                None
            };
            let inflight_count = if redis_candidate.is_some() || publish_execution_barrier_on_skip {
                self.inflight_count.load(Ordering::Relaxed)
            } else {
                decrement_atomic(&self.inflight_count)
            };
            return LocalCompletionAction::Skipped {
                inflight_count,
                reason: CompletionSkipReason::TotalCapacity {
                    entry_size,
                    current_total,
                },
                redis_candidate,
            };
        }

        let sequence = self.next_completed_sequence();
        self.completed_order
            .insert(sequence, CompletedOrderEntry::Pending);
        let cached = CachedResponse {
            status_code,
            headers,
            body: Bytes::copy_from_slice(body),
            inserted_at: Instant::now(),
            retention,
            response_policy,
        };
        let redis_copy = cached.clone();
        entry.insert(DeduplicationEntry::Completed {
            cached,
            sequence,
            fingerprint: fingerprint.to_string(),
            publisher_owner_token: owner_token.to_string(),
            retain_barrier_on_eviction,
        });
        self.add_completed_size_locked(entry_size);
        self.completed_order
            .insert(sequence, CompletedOrderEntry::Published(key.to_string()));
        LocalCompletionAction::Published {
            cached: redis_copy,
            sequence,
            completed_count: self.completed_count.fetch_add(1, Ordering::Relaxed) + 1,
            inflight_count: decrement_atomic(&self.inflight_count),
        }
    }

    fn set_completed_barrier_retention(
        &self,
        key: &str,
        fingerprint: &str,
        sequence: u64,
        retain: bool,
    ) {
        let Some(mut entry) = self.local_cache.get_mut(key) else {
            return;
        };
        if let DeduplicationEntry::Completed {
            sequence: current_sequence,
            fingerprint: current_fingerprint,
            retain_barrier_on_eviction,
            ..
        } = entry.value_mut()
            && *current_sequence == sequence
            && current_fingerprint.as_str() == fingerprint
        {
            *retain_barrier_on_eviction = retain;
        }
    }

    fn next_completed_sequence(&self) -> u64 {
        self.completed_sequence.fetch_add(1, Ordering::Relaxed)
    }

    /// Evict expired entries from local cache.
    ///
    /// Called from `before_proxy` on every applicable request, so the expensive
    /// part (an all-shard `DashMap::retain`) is throttled to at most once per
    /// cleanup interval. The throttle is
    /// unconditional: it is NOT bypassed by over-capacity. A cache saturated
    /// with active (non-stale) `InFlight` markers — which are never evicted by
    /// design — would otherwise stay over capacity indefinitely and force the
    /// full O(n), all-shard-locking scan on every request, an
    /// attacker-influenceable hot-path amplification (finding #12). The throttle
    /// clock is monotonic (finding #57).
    fn cleanup_local_cache(&self) {
        let now_secs = monotonic_secs();

        // Throttle full scans to once per interval. This gate is unconditional
        // (no over-capacity bypass), and because callers within the interval
        // return here, the compare_exchange below can never be a same-value
        // no-op: any thread that reaches it loaded a `last` at least
        // CLEANUP_INTERVAL_SECS older than `now_secs` (or the NEVER sentinel),
        // so exactly one thread per interval wins the CAS and runs the scan.
        let last = self.last_cleanup.load(Ordering::Relaxed);
        let cleanup_interval_secs = CLEANUP_INTERVAL_SECS.min(self.inflight_ttl.as_secs().max(1));
        if !cleanup_due(last, now_secs, cleanup_interval_secs) {
            return;
        }
        if self
            .last_cleanup
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread is doing cleanup this interval
        }

        let _guard = self.accounting_guard();
        let now = Instant::now();
        // Single all-shard pass: drop expired Completed entries and stale
        // InFlight markers. Decrement counters for entries actually removed
        // instead of storing a full-scan snapshot, so concurrent inserts cannot
        // be overwritten by stale counts from this cleanup pass.
        self.local_cache.retain(|_, entry| match entry {
            DeduplicationEntry::Completed {
                cached, sequence, ..
            } => {
                let keep = now.duration_since(cached.inserted_at) < cached.retention;
                if !keep {
                    let retained_size = cached.retained_size();
                    self.mark_completed_sequence_pruned(*sequence);
                    self.sub_completed_size_locked(retained_size);
                    decrement_atomic(&self.completed_count);
                }
                keep
            }
            DeduplicationEntry::ExecutionBarrier {
                inserted_at,
                retention,
                ..
            } => {
                let keep = now.duration_since(*inserted_at) < *retention;
                if !keep {
                    self.release_execution_barrier();
                    decrement_atomic(&self.inflight_count);
                }
                keep
            }
            // Drop in-flight markers that have exceeded inflight_ttl — the
            // originating request must have died (timeout, downstream reject,
            // connection drop) without ever reaching `on_final_response_body`.
            // Without this, duplicate requests would receive 409 Conflict
            // forever.
            DeduplicationEntry::InFlight { started_at, .. } => {
                let keep = now.duration_since(*started_at) < self.inflight_ttl;
                if !keep {
                    decrement_atomic(&self.inflight_count);
                }
                keep
            }
        });

        self.evict_completed_over_capacity_locked(
            self.completed_count.load(Ordering::Relaxed),
            self.inflight_count.load(Ordering::Relaxed),
            false,
        );
        self.advance_completed_evict_cursor_locked();
    }

    fn evict_completed_over_capacity(
        &self,
        completed_hint: usize,
        inflight_hint: usize,
        preserve_one_completed: bool,
    ) {
        let _guard = self.accounting_guard();
        self.evict_completed_over_capacity_locked(
            completed_hint,
            inflight_hint,
            preserve_one_completed,
        );
    }

    fn evict_completed_over_capacity_locked(
        &self,
        completed_hint: usize,
        inflight_hint: usize,
        preserve_one_completed: bool,
    ) {
        if completed_hint == 0 || completed_hint.saturating_add(inflight_hint) <= self.max_entries {
            return;
        }
        // Eviction is opportunistic on proxy paths; if another caller is
        // already trimming, skip instead of parking a Tokio worker.
        let Ok(_guard) = self.eviction_lock.try_lock() else {
            return;
        };
        self.evict_completed_over_capacity_guarded(
            self.completed_count.load(Ordering::Relaxed),
            self.inflight_count.load(Ordering::Relaxed),
            preserve_one_completed,
        );
    }

    fn evict_completed_over_capacity_guarded(
        &self,
        completed_hint: usize,
        inflight_hint: usize,
        preserve_one_completed: bool,
    ) {
        // Enforce max entries by removing oldest Completed entries first. Active
        // (non-stale) InFlight markers are NEVER evicted by LRU because evicting
        // them would release the in-flight lock while the original request is
        // still executing — a duplicate retry for that key would then bypass the
        // lock and re-execute side-effecting operations. Stale InFlight markers
        // are dropped by the throttled expiry scan. This means max_entries can
        // be temporarily exceeded if the cache is saturated with active
        // in-flight work; correctness is strictly preferred over hitting the
        // memory cap.
        let mut to_remove = completed_hint
            .saturating_add(inflight_hint)
            .saturating_sub(self.max_entries)
            .min(if preserve_one_completed {
                completed_hint.saturating_sub(1)
            } else {
                completed_hint
            });
        if to_remove == 0 {
            return;
        }

        let mut sequence = self.next_completed_evict_sequence.load(Ordering::Relaxed);
        let limit = self.completed_sequence.load(Ordering::Relaxed);
        while to_remove > 0 && sequence < limit {
            let current_sequence = sequence;
            match self.remove_completed_sequence_locked(sequence) {
                CompletedSequenceRemoval::Removed => {
                    to_remove -= 1;
                    sequence += 1;
                    self.next_completed_evict_sequence
                        .store(sequence, Ordering::Relaxed);
                    self.remove_pruned_completed_order(current_sequence);
                }
                CompletedSequenceRemoval::Tombstoned => {
                    // Replacing a byte-heavy completion with a fixed-size
                    // execution barrier releases the response-byte budget but
                    // not a map slot. Keep trimming so a later unprotected
                    // completion is removed and the cardinality target is met
                    // whenever doing so does not discard live security state.
                    sequence += 1;
                    self.next_completed_evict_sequence
                        .store(sequence, Ordering::Relaxed);
                    self.remove_pruned_completed_order(current_sequence);
                }
                CompletedSequenceRemoval::Stale => {
                    sequence += 1;
                    self.next_completed_evict_sequence
                        .store(sequence, Ordering::Relaxed);
                    self.remove_pruned_completed_order(current_sequence);
                }
                CompletedSequenceRemoval::NotPublished => {
                    break;
                }
            }
        }
        self.next_completed_evict_sequence
            .store(sequence, Ordering::Relaxed);
    }

    fn remove_completed_sequence_locked(&self, sequence: u64) -> CompletedSequenceRemoval {
        let Some(order_entry) = self.completed_order.get(&sequence) else {
            return CompletedSequenceRemoval::NotPublished;
        };
        let key = match order_entry.value() {
            CompletedOrderEntry::Pending => return CompletedSequenceRemoval::NotPublished,
            CompletedOrderEntry::Pruned => {
                drop(order_entry);
                self.completed_order.remove_if(&sequence, |_, entry| {
                    matches!(entry, CompletedOrderEntry::Pruned)
                });
                return CompletedSequenceRemoval::Stale;
            }
            CompletedOrderEntry::Published(key) => key.clone(),
        };
        drop(order_entry);

        let mut entry = match self.local_cache.entry(key.clone()) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => {
                self.remove_stale_completed_order(sequence, &key);
                return CompletedSequenceRemoval::Stale;
            }
        };
        let (
            retained_size,
            barrier_inserted_at,
            barrier_retention,
            fingerprint,
            publisher_owner_token,
            retain_barrier_on_eviction,
        ) = match entry.get() {
            DeduplicationEntry::Completed {
                cached,
                sequence: current,
                fingerprint,
                publisher_owner_token,
                retain_barrier_on_eviction,
            } if *current == sequence => (
                cached.retained_size(),
                cached.inserted_at,
                cached.retention,
                fingerprint.clone(),
                publisher_owner_token.clone(),
                *retain_barrier_on_eviction,
            ),
            _ => {
                drop(entry);
                self.remove_stale_completed_order(sequence, &key);
                return CompletedSequenceRemoval::Stale;
            }
        };

        self.sub_completed_size_locked(retained_size);
        decrement_atomic(&self.completed_count);
        let result = if retain_barrier_on_eviction {
            // A distributed lock may still be the only cross-gateway guard for
            // an externally executed response. If the replay cannot remain in
            // the bounded local cache, retain a small local tombstone so Redis
            // loss cannot turn an identical retry into another side effect.
            if self.try_reserve_execution_barrier() {
                entry.insert(DeduplicationEntry::ExecutionBarrier {
                    inserted_at: barrier_inserted_at,
                    retention: barrier_retention,
                    fingerprint,
                    owner_token: publisher_owner_token,
                });
                self.inflight_count.fetch_add(1, Ordering::Relaxed);
                CompletedSequenceRemoval::Tombstoned
            } else {
                // The per-key security-state budget is full. Collapse this
                // completion into the one bounded process-global refusal
                // deadline rather than allocating another attacker-influenced
                // map entry or reopening the operation.
                self.extend_execution_barrier_overflow(barrier_inserted_at, barrier_retention);
                entry.remove();
                CompletedSequenceRemoval::Removed
            }
        } else {
            entry.remove();
            CompletedSequenceRemoval::Removed
        };
        self.remove_stale_completed_order(sequence, &key);
        result
    }

    fn remove_stale_completed_order(&self, sequence: u64, key: &str) {
        self.completed_order
            .remove_if(&sequence, |_, entry| match entry {
                CompletedOrderEntry::Pending => false,
                CompletedOrderEntry::Published(published) => published.as_str() == key,
                CompletedOrderEntry::Pruned => true,
            });
    }

    fn mark_completed_sequence_pruned(&self, sequence: u64) {
        if sequence < self.next_completed_evict_sequence.load(Ordering::Relaxed) {
            self.completed_order.remove(&sequence);
            return;
        }
        self.completed_order
            .insert(sequence, CompletedOrderEntry::Pruned);
        if sequence < self.next_completed_evict_sequence.load(Ordering::Relaxed) {
            self.remove_pruned_completed_order(sequence);
        }
    }

    fn remove_pruned_completed_order(&self, sequence: u64) {
        self.completed_order.remove_if(&sequence, |_, entry| {
            matches!(entry, CompletedOrderEntry::Pruned)
        });
    }

    fn advance_completed_evict_cursor_locked(&self) {
        let Ok(_guard) = self.eviction_lock.try_lock() else {
            return;
        };
        self.advance_completed_evict_cursor_guarded();
    }

    fn advance_completed_evict_cursor_guarded(&self) {
        let mut sequence = self.next_completed_evict_sequence.load(Ordering::Relaxed);
        let limit = self.completed_sequence.load(Ordering::Relaxed);
        while sequence < limit {
            let current_sequence = sequence;
            let Some(order_entry) = self.completed_order.get(&sequence) else {
                break;
            };
            if !matches!(order_entry.value(), CompletedOrderEntry::Pruned) {
                break;
            }
            drop(order_entry);
            if self
                .completed_order
                .remove_if(&sequence, |_, entry| {
                    matches!(entry, CompletedOrderEntry::Pruned)
                })
                .is_some()
            {
                sequence += 1;
                self.next_completed_evict_sequence
                    .store(sequence, Ordering::Relaxed);
                self.remove_pruned_completed_order(current_sequence);
            } else {
                break;
            }
        }
        self.next_completed_evict_sequence
            .store(sequence, Ordering::Relaxed);
    }
}

enum CompletedOrderEntry {
    Pending,
    Published(String),
    Pruned,
}

enum CompletedSequenceRemoval {
    Removed,
    Tombstoned,
    Stale,
    NotPublished,
}

/// Serializable form of CachedResponse for Redis storage.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableCachedResponse {
    fingerprint: String,
    /// Replay provenance. Deliberately **required** with no serde default: a
    /// legacy record written before provenance existed fails to deserialize and
    /// is refused, instead of silently defaulting into a match.
    response_policy: SerializableResponsePolicyProvenance,
    status_code: u16,
    headers: HashMap<String, String>,
    #[serde(
        serialize_with = "serialize_cached_response_body",
        deserialize_with = "deserialize_cached_response_body"
    )]
    body: Vec<u8>,
}

/// Wire form of `ResponsePolicyProvenance`.
///
/// Both halves are fixed-length lowercase hex SHA-256 digests. Storing hex
/// rather than a byte array keeps the record compact and stable across
/// serializer versions, and a digest is all that is ever written: no rule text,
/// header value, scope name, or other configuration content reaches Redis.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableResponsePolicyProvenance {
    /// Content digest of the published RTDS response-side gate map.
    gate: String,
    /// Content digest of the effective static response-presentation rules.
    presentation: String,
}

impl SerializableResponsePolicyProvenance {
    fn encode(gate: [u8; 32], presentation: [u8; 32]) -> Self {
        Self {
            gate: hex::encode(gate),
            presentation: hex::encode(presentation),
        }
    }

    /// Decode both halves, or `None` when either is not exactly 32 hex-encoded
    /// bytes. A malformed record can never be replayed on an assumed policy.
    fn decode(&self) -> Option<ResponsePolicyProvenance> {
        Some(ResponsePolicyProvenance::from_persisted(
            decode_digest_hex(&self.gate)?,
            decode_digest_hex(&self.presentation)?,
        ))
    }
}

fn decode_digest_hex(value: &str) -> Option<[u8; 32]> {
    let mut digest = [0u8; 32];
    hex::decode_to_slice(value, &mut digest).ok()?;
    Some(digest)
}

/// The single Redis record that owns one logical idempotency key.
///
/// Ownership (`state = "inflight"`, with the owner token) and completion
/// (`state = "completed"`, with an optional replay payload) are the same key,
/// so publication and the ownership transition are one atomic compare-and-set.
///
/// Field order is the serialization order and `skip_serializing_if` keeps
/// absent fields out of the document, so the in-flight bytes a request writes
/// at acquisition are reproducible as the compare operand at completion.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableDedupRecord {
    record_version: u32,
    state: String,
    fingerprint: String,
    /// Owner token; present only while `state == "inflight"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_token: Option<String>,
    /// Replay payload; present only for a replayable completed record. A
    /// completed record without one is a deliberate non-replayable tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay: Option<SerializableCachedResponse>,
}

impl SerializableDedupRecord {
    /// Validate the state-dependent wire shape before any field is trusted.
    ///
    /// Serde defaults make forward-compatible parsing convenient, but they
    /// must not turn a partially written or attacker-controlled record into a
    /// valid ownership/completion state. In particular, an in-flight record
    /// always carries a nonempty fencing token and no replay, while a completed
    /// record carries no owner and any replay must bind to the outer request
    /// fingerprint.
    fn has_valid_current_shape(&self) -> bool {
        if self.record_version != DEDUP_REDIS_RECORD_VERSION || self.fingerprint.is_empty() {
            return false;
        }

        match self.state.as_str() {
            DEDUP_RECORD_STATE_INFLIGHT => {
                self.owner_token
                    .as_deref()
                    .is_some_and(|token| !token.is_empty())
                    && self.replay.is_none()
            }
            DEDUP_RECORD_STATE_COMPLETED => {
                self.owner_token.is_none()
                    && self
                        .replay
                        .as_ref()
                        .is_none_or(|replay| replay.fingerprint == self.fingerprint)
            }
            _ => false,
        }
    }

    fn inflight(fingerprint: &str, token: &str) -> Self {
        Self {
            record_version: DEDUP_REDIS_RECORD_VERSION,
            state: DEDUP_RECORD_STATE_INFLIGHT.to_string(),
            fingerprint: fingerprint.to_string(),
            owner_token: Some(token.to_string()),
            replay: None,
        }
    }

    fn completed(fingerprint: &str, replay: Option<SerializableCachedResponse>) -> Self {
        Self {
            record_version: DEDUP_REDIS_RECORD_VERSION,
            state: DEDUP_RECORD_STATE_COMPLETED.to_string(),
            fingerprint: fingerprint.to_string(),
            owner_token: None,
            replay,
        }
    }
}

fn serialize_cached_response_body<S>(body: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(body))
}

fn deserialize_cached_response_body<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct CachedResponseBodyVisitor;

    impl<'de> serde::de::Visitor<'de> for CachedResponseBodyVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a base64 response body string or legacy byte array")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(&value)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut body = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
            while let Some(byte) = sequence.next_element::<u8>()? {
                body.push(byte);
            }
            Ok(body)
        }
    }

    deserializer.deserialize_any(CachedResponseBodyVisitor)
}

fn hash_framed(hasher: &mut Sha256, label: &str, value: &[u8]) {
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn header_value_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

fn canonical_authority(headers: &HashMap<String, String>) -> String {
    header_value_case_insensitive(headers, ":authority")
        .or_else(|| header_value_case_insensitive(headers, "host"))
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn request_headers_for_fingerprint<'a>(
    headers: &'a HashMap<String, String>,
    idempotency_header: &str,
    exclude_scoped_credentials: bool,
) -> Vec<(String, &'a str)> {
    let mut values = Vec::new();
    for (name, value) in headers {
        let normalized = name.to_ascii_lowercase();
        if normalized == ":authority"
            || normalized == "host"
            || normalized.eq_ignore_ascii_case(idempotency_header)
            || HOP_BY_HOP_FINGERPRINT_EXCLUSIONS
                .iter()
                .any(|excluded| normalized == *excluded)
            || is_per_request_trace_header(&normalized)
            || (exclude_scoped_credentials
                && SCOPED_CREDENTIAL_FINGERPRINT_EXCLUSIONS
                    .iter()
                    .any(|excluded| normalized == *excluded))
        {
            continue;
        }
        values.push((normalized, value.as_str()));
    }
    values.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    values
}

fn request_declares_body(headers: &HashMap<String, String>) -> bool {
    if header_value_case_insensitive(headers, "transfer-encoding").is_some() {
        return true;
    }

    let Some(content_length) = header_value_case_insensitive(headers, "content-length") else {
        return false;
    };
    let trimmed = content_length.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.parse::<u64>().map_or(true, |length| length > 0)
}

fn supported_fingerprint_body_encoding(value: &str) -> Option<&'static str> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("gzip") {
        Some("gzip")
    } else if trimmed.eq_ignore_ascii_case("br") || trimmed.eq_ignore_ascii_case("brotli") {
        Some("br")
    } else {
        None
    }
}

fn decoded_body_digest_with_limit(
    reader: &mut dyn Read,
    algo_name: &str,
) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut decoded_len = 0usize;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("{algo_name} decompression failed: {e}"))?;
        if n == 0 {
            break;
        }
        decoded_len = decoded_len.saturating_add(n);
        if decoded_len > MAX_CANONICAL_DECODED_BODY_BYTES {
            return Err(format!(
                "{algo_name} decompressed body exceeds fingerprint limit"
            ));
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

fn request_body_digest(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> Result<String, PluginResult> {
    let body = match ctx.request_body_bytes.as_ref() {
        Some(body) => body.as_ref(),
        None if request_declares_body(headers) => {
            return Err(PluginResult::Reject {
                status_code: 400,
                body: serde_json::json!({
                    "error": "Request body unavailable for idempotency fingerprint"
                })
                .to_string(),
                headers: HashMap::new(),
            });
        }
        None => &[],
    };

    if let Some(content_encoding) = header_value_case_insensitive(headers, "content-encoding")
        && let Some(encoding) = supported_fingerprint_body_encoding(content_encoding)
    {
        let decoded = match encoding {
            "gzip" => {
                let mut decoder = flate2::read::MultiGzDecoder::new(body);
                decoded_body_digest_with_limit(&mut decoder, "gzip")
            }
            "br" => {
                let mut decoder = brotli::Decompressor::new(body, 4096);
                decoded_body_digest_with_limit(&mut decoder, "brotli")
            }
            _ => Err("unsupported body encoding".to_string()),
        };
        if let Ok(digest) = decoded {
            return Ok(digest);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(body);
    if let Some(encoding) = header_value_case_insensitive(headers, "content-encoding") {
        hash_framed(&mut hasher, "content_encoding", encoding.trim().as_bytes());
    }
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

// External tests reach this through `crate::_test_support`; the binary target
// still sees the crate-private helper itself as unused.
#[allow(dead_code)]
pub(crate) fn redis_cached_response_payload_is_valid_for_test(data: &[u8]) -> bool {
    // Mirrors the admission `redis_get` performs: a payload counts as valid
    // only when it both deserializes and carries decodable replay provenance.
    serde_json::from_slice::<SerializableCachedResponse>(data)
        .ok()
        .and_then(|stored| stored.response_policy.decode())
        .is_some()
}

// External tests reach this through `crate::_test_support`; the binary target
// still sees the crate-private helper itself as unused.
#[allow(dead_code)]
pub(crate) fn redis_record_payload_is_valid_for_test(data: &[u8]) -> bool {
    let Ok(record) = serde_json::from_slice::<SerializableDedupRecord>(data) else {
        return false;
    };
    if !record.has_valid_current_shape() {
        return false;
    }
    record
        .replay
        .as_ref()
        .is_none_or(|replay| replay.response_policy.decode().is_some())
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("request_deduplication: '{field}' must be a string"))
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "request_deduplication: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "request_deduplication: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_positive_u64(config, field)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("request_deduplication: '{field}' is too large for this platform"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("request_deduplication: '{field}' must be a boolean"))
}

fn parse_header_name(value: &str) -> Result<String, String> {
    HeaderName::from_bytes(value.as_bytes())
        .map(|name| name.as_str().to_string())
        .map_err(|_| {
            "request_deduplication: 'header_name' must be a valid HTTP header name".to_string()
        })
}

fn parse_applicable_methods(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("applicable_methods") else {
        return Ok(vec![
            "POST".to_string(),
            "PUT".to_string(),
            "PATCH".to_string(),
        ]);
    };
    let Some(methods) = value.as_array() else {
        return Err(
            "request_deduplication: 'applicable_methods' must be an array of method strings"
                .to_string(),
        );
    };
    if methods.is_empty() {
        return Err("request_deduplication: applicable_methods must not be empty".to_string());
    }

    let mut parsed = Vec::with_capacity(methods.len());
    for method in methods {
        let Some(method) = method.as_str() else {
            return Err(
                "request_deduplication: 'applicable_methods' must contain only strings".to_string(),
            );
        };
        let method = method.trim();
        if method.is_empty() || Method::from_bytes(method.as_bytes()).is_err() {
            return Err(
                "request_deduplication: 'applicable_methods' contains an invalid HTTP method"
                    .to_string(),
            );
        }
        parsed.push(method.to_ascii_uppercase());
    }

    Ok(parsed)
}

fn default_redis_key_prefix(namespace: &str) -> String {
    let mut prefix = String::with_capacity(namespace.len() + 6);
    prefix.push_str(namespace);
    prefix.push_str(":dedup");
    prefix
}

fn missing_idempotency_body(header_name: &str) -> String {
    let mut message = String::with_capacity(41 + header_name.len());
    message.push_str("Missing required idempotency header: ");
    message.push_str(header_name);
    serde_json::json!({ "error": message }).to_string()
}

#[async_trait]
impl Plugin for RequestDeduplication {
    fn name(&self) -> &str {
        "request_deduplication"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_DEDUPLICATION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.request_deduplication_states
            .contains_key(&self.instance_id)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        // Never hold a `text/event-stream` body: it cannot be cached for
        // idempotent replay (an incrementally-delivered stream has no final
        // body to store), so buffering it would only pin an unbounded response
        // on the buffered path with no benefit. Streaming it instead keeps the
        // `InFlight` marker active for the lifetime of the still-in-flight
        // stream — which is exactly the concurrent-duplicate protection this
        // plugin promises. `on_response_stream_terminated` then releases the
        // marker on clean completion (no replay body is stored), while an
        // interrupted stream (client disconnect or backend error) retains it
        // until `inflight_ttl` so a same-key retry cannot re-execute a
        // side-effecting operation that has no replay value.
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_event_stream_content_type)
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn needs_request_body_bytes(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.applicable_methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&ctx.method))
            && crate::proxy::request_may_have_body(&ctx.method, &ctx.headers)
            && (self.enforce_required
                || header_value_case_insensitive(&ctx.headers, &self.header_name).is_some())
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only apply to configured methods
        if !self
            .applicable_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&ctx.method))
        {
            return PluginResult::Continue;
        }

        // Idempotent responses are finalized representations. Pin the policy
        // before any response-side gate can be read so replay provenance can
        // be validated without reapplying non-idempotent transforms.
        let _ = ctx.pin_response_policy_stamp();

        let (key, fingerprint) = {
            // Get idempotency key from headers. Keep the borrow scoped so no
            // header-map borrow survives across Redis/cache awaits below.
            let idempotency_value = match header_value_case_insensitive(headers, &self.header_name)
            {
                Some(value) if !value.is_empty() => value,
                _ => {
                    if self.enforce_required {
                        return PluginResult::Reject {
                            status_code: 400,
                            body: missing_idempotency_body(&self.header_name),
                            headers: HashMap::new(),
                        };
                    }
                    return PluginResult::Continue;
                }
            };
            let key = self.build_key(ctx, idempotency_value);
            let fingerprint = match self.build_request_fingerprint(ctx, headers) {
                Ok(fingerprint) => fingerprint,
                Err(reject) => return reject,
            };
            (key, fingerprint)
        };

        // Periodic cleanup
        self.cleanup_local_cache();

        // Per-key execution barriers are hard-capped at `max_entries`. If
        // completed external operations overflowed that budget, one bounded
        // process-global deadline fails every applicable idempotency-key request
        // closed until the longest displaced completion deadline. Completed
        // replays are intentionally not consulted here: their key might not be
        // one of the displaced operations, and selecting by attacker-controlled
        // request order would make the overflow state unsafe.
        if self.execution_barrier_overflow_active() {
            return PluginResult::Reject {
                status_code: 503,
                body: EXECUTION_BARRIER_CAPACITY_BODY.to_string(),
                headers: HashMap::new(),
            };
        }

        // Check Redis first (centralized dedup across instances), then acquire
        // a Redis in-flight lock before any gateway instance can dispatch the
        // fresh request to the backend.
        let mut redis_lock_token = None;
        if self.redis_client.is_some() {
            // One atomic admission against the single operation record. There
            // is no read-then-lock-then-read window: acquisition and
            // observation are the same `SET NX` / `GET` pair on one key, so a
            // peer can never see the completed value and the ownership marker
            // disagree.
            match self.redis_admit(&key, &fingerprint).await {
                RedisAdmission::Acquired(ownership) => {
                    redis_lock_token = Some(ownership);
                }
                RedisAdmission::Replay(cached) => {
                    debug!("request_deduplication: Redis cache hit, replaying response");
                    // Defense-in-depth: re-sanitize on replay even though insert
                    // already strips. A stored entry written before this fix landed,
                    // or by a peer running an older binary against a shared Redis,
                    // could still carry session-bearing headers.
                    return self.replay_response(ctx, &cached);
                }
                RedisAdmission::CompletedNonReplayable => {
                    // The distributed record proves the operation completed but
                    // carries no safe replay — typically because the response
                    // exceeded the Redis payload cap. The publishing gateway
                    // still holds the real completion locally, so prefer that
                    // authoritative replay over the deterministic refusal.
                    // Peers without it stay refused for the completed TTL.
                    if let Some(cached) =
                        self.matching_local_completed(&key, &fingerprint, Instant::now())
                    {
                        return self.replay_response(ctx, &cached);
                    }
                    return PluginResult::Reject {
                        status_code: 409,
                        body: NON_REPLAYABLE_COMPLETION_BODY.to_string(),
                        headers: HashMap::new(),
                    };
                }
                RedisAdmission::UnprovableRecord => {
                    // GHSA-8cr6 / replay provenance: the record proves an
                    // operation under this key but cannot be shown compatible
                    // with the live response policy. Refuse deterministically
                    // rather than replaying a superseded representation or
                    // re-executing a possibly completed side effect.
                    return PluginResult::Reject {
                        status_code: 409,
                        body:
                            r#"{"error":"The stored idempotent response cannot be proven compatible with the current response policy"}"#
                                .to_string(),
                        headers: HashMap::new(),
                    };
                }
                RedisAdmission::Unavailable => match self.on_redis_unavailable {
                    // Refuse rather than fall back to an ownership decision only
                    // this process can see: a local-only decision during an
                    // outage lets one idempotency key execute once per gateway.
                    RedisUnavailablePolicy::FailClosed => {
                        return PluginResult::Reject {
                            status_code: 503,
                            body: REDIS_UNAVAILABLE_BODY.to_string(),
                            headers: HashMap::new(),
                        };
                    }
                    RedisUnavailablePolicy::LocalOnly => {}
                },
                RedisAdmission::Conflict(DeduplicationConflict::InFlight) => {
                    // An owned terminal response can fit the local cache while
                    // its base64 Redis representation exceeds the same entry
                    // limit. In that case publication deliberately retains the
                    // distributed lock so peers cannot re-execute the external
                    // side effect. This gateway still has the completed value:
                    // replay that matching entry before honoring its own
                    // retained Redis lock. Peers without the local entry remain
                    // blocked until the in-flight TTL.
                    if let Some(cached) =
                        self.matching_local_completed(&key, &fingerprint, Instant::now())
                    {
                        return self.replay_response(ctx, &cached);
                    }
                    return PluginResult::Reject {
                        status_code: 409,
                        body:
                            r#"{"error":"A request with this idempotency key is already in progress"}"#
                                .to_string(),
                        headers: HashMap::new(),
                    };
                }
                RedisAdmission::Conflict(DeduplicationConflict::FingerprintMismatch) => {
                    return PluginResult::Reject {
                        status_code: 409,
                        body: r#"{"error":"Idempotency key was reused for a different request"}"#
                            .to_string(),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        // Check local cache and mark fresh keys as in-flight atomically under
        // the DashMap entry lock. This prevents two concurrent first requests
        // with the same idempotency key from both reaching the backend.
        let local_inflight_owner_token = self.next_local_inflight_owner_token();
        match self.local_lookup_or_mark_inflight(
            &key,
            &fingerprint,
            Instant::now(),
            &local_inflight_owner_token,
        ) {
            LocalDeduplicationAction::Replay(cached) => {
                if let Some(ownership) = redis_lock_token.as_ref() {
                    self.redis_release_inflight(&key, ownership).await;
                }
                debug!("request_deduplication: local cache hit, replaying response");
                // Defense-in-depth: re-sanitize on replay even though insert
                // already strips. Cheap (single HashMap pass) and protects
                // against any future code path that populates the cache without
                // going through `on_final_response_body`.
                return self.replay_response(ctx, &cached);
            }
            LocalDeduplicationAction::Conflict(DeduplicationConflict::InFlight) => {
                if let Some(ownership) = redis_lock_token.as_ref() {
                    self.redis_release_inflight(&key, ownership).await;
                }
                return PluginResult::Reject {
                    status_code: 409,
                    body:
                        r#"{"error":"A request with this idempotency key is already in progress"}"#
                            .to_string(),
                    headers: HashMap::new(),
                };
            }
            LocalDeduplicationAction::Conflict(DeduplicationConflict::FingerprintMismatch) => {
                if let Some(ownership) = redis_lock_token.as_ref() {
                    self.redis_release_inflight(&key, ownership).await;
                }
                return PluginResult::Reject {
                    status_code: 409,
                    body: r#"{"error":"Idempotency key was reused for a different request"}"#
                        .to_string(),
                    headers: HashMap::new(),
                };
            }
            LocalDeduplicationAction::Fresh => {}
        }

        // Store completion state outside public metadata and key it by this
        // configured instance. Multiple instances may acquire independent keys
        // on the same request and must never consume one another's state.
        ctx.request_deduplication_states.insert(
            self.instance_id,
            RequestDeduplicationRequestState {
                key,
                fingerprint,
                local_inflight_owner_token,
                redis_lock_token,
            },
        );

        PluginResult::Continue
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        // A streamed response has no whole body to cache, so this hook cannot
        // transition the marker to a replayable `Completed` entry the way
        // `on_final_response_body` does on the buffered path. What it does with
        // the in-flight lock depends on how the stream ended:
        //
        // - Clean completion (`body_completed`): the full response reached the
        //   client, so there is normally nothing left to protect. Release the
        //   marker unless a terminate-mode serverless invocation already
        //   occurred and then fell through; that uncertain external side effect
        //   has no replayable response, so its marker must remain until TTL.
        // - Client disconnect or mid-stream error (`!body_completed`): the
        //   client did NOT receive the full response and is the case most
        //   likely to be retried with the same idempotency key. Releasing here
        //   would let that retry re-execute a side-effecting backend operation
        //   with no replay/tombstone protection, so keep the local marker and
        //   Redis lock until `inflight_ttl` expires as the backstop.
        //
        // The first case is stronger than a bare in-flight retention: an
        // external operation that already executed must not become re-executable
        // simply because `inflight_ttl_seconds` elapsed. Publish a durable
        // non-replayable completion tombstone instead, so an identical retry is
        // refused for the full `ttl_seconds` on this gateway and — in Redis mode
        // — on every peer, through the same fenced ownership transition the
        // buffered path uses.
        if self.owns_completed_external_operation(ctx) {
            self.publish_external_operation_tombstone(ctx).await;
            return;
        }
        if !outcome.body_completed {
            return;
        }

        let Some(state) = ctx.request_deduplication_states.remove(&self.instance_id) else {
            return;
        };

        self.remove_matching_local_inflight(
            &state.key,
            &state.fingerprint,
            &state.local_inflight_owner_token,
        );
        if let Some(ownership) = state.redis_lock_token.as_ref() {
            self.redis_release_inflight(&state.key, ownership).await;
        }
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Terminal serverless responses are finalized through the committed
        // hook below. That hook observes every rejection shape (including
        // empty 2xx, HEAD, and non-2xx responses) after body validators and
        // reject-path header hooks have settled the client response. Storage
        // still sanitizes per-request and credential-bearing headers.
        if ctx
            .serverless_external_side_effect_owners
            .contains(&self.instance_id)
        {
            return PluginResult::Continue;
        }
        // Publish a fixed-size execution barrier (rather than fail open) when
        // configured response-byte capacity is too small even to store an owned
        // terminal response or the 409 tombstone bytes. Serverless owns its
        // publication through the typed marker above; `ai_federation` signals
        // the same intent for its committed provider call through
        // `EXTERNAL_OPERATION_COMPLETED_METADATA_KEY`.
        let requires_execution_barrier = ctx.serverless_owned_dedup_publication
            == Some(self.instance_id)
            || ctx
                .metadata
                .contains_key(super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY);

        // Only cache if this instance acquired a completion state in
        // `before_proxy`. Take it before any await so a later hook cannot reuse
        // or consume it a second time.
        let state = match ctx.request_deduplication_states.remove(&self.instance_id) {
            Some(state) => state,
            None => return PluginResult::Continue,
        };
        let key = state.key;
        let fingerprint = state.fingerprint;
        let local_inflight_owner_token = state.local_inflight_owner_token;
        let redis_lock_token = state.redis_lock_token;

        // Synthetic short-circuit guard. When a *fresh* request that this plugin
        // marked in-flight is then short-circuited by a LATER `before_proxy`
        // plugin (e.g. a 2xx `fault_injection`/`mesh_route_dispatch` abort,
        // `response_mock`, `request_termination`, an
        // `ai_federation` synthetic response, or an `ai_semantic_cache` hit), the
        // synthetic body now flows back through the response-body hooks (the
        // generic 2xx short-circuit path) and would otherwise be cached and
        // replayed (`x-idempotent-replayed: true`) under the idempotency key for
        // every retry until TTL — turning, e.g., a probabilistic fault into a
        // deterministic cached replay. The body never came from the backend, so
        // there is nothing legitimate to store. We conservatively skip storing
        // (mirroring `response_caching`'s served-from-cache guard) but still
        // RELEASE the in-flight locks so the marker transitions to a clean state
        // instead of dangling until `inflight_ttl`, which keeps duplicate
        // detection accurate once the synthetic short-circuit returns. Empty 200
        // and 204/205 short-circuits skip this body-hook path entirely; the
        // shared reject finalizer's `FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY`
        // plus `on_response_committed` perform the equivalent token-matched
        // release. The exception is a synthetic short-circuit whose own
        // execution already performed an external side effect (for example an
        // `ai_federation` provider call, which marks
        // `EXTERNAL_OPERATION_COMPLETED_METADATA_KEY`): that operation has no
        // replayable response, so a same-key retry must not immediately
        // re-execute it. Park the exact ownership until the committed hook can
        // publish its authoritative completion barrier.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            if ctx
                .metadata
                .contains_key(super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY)
            {
                // A later plugin performed a committed/ambiguous external
                // operation (e.g. an `ai_federation` provider call) behind this
                // synthetic short-circuit. Its response has no safe replay, so
                // the in-flight locks must NOT be released here. Retain
                // ownership by re-parking the state consumed above so
                // `on_response_committed` can publish a non-replayable completed
                // tombstone once every response decision is final. Both the
                // local and Redis in-flight markers stay held until that
                // publication (or `inflight_ttl` as the backstop).
                ctx.request_deduplication_states.insert(
                    self.instance_id,
                    RequestDeduplicationRequestState {
                        key,
                        fingerprint,
                        local_inflight_owner_token,
                        redis_lock_token,
                    },
                );
                return PluginResult::Continue;
            }
            self.remove_matching_local_inflight(&key, &fingerprint, &local_inflight_owner_token);
            if let Some(ownership) = redis_lock_token.as_ref() {
                self.redis_release_inflight(&key, ownership).await;
            }
            return PluginResult::Continue;
        }

        // Replay provenance is checked only once a representation is actually
        // going to be retained. It must stay BELOW the synthetic guard above:
        // a synthetic short-circuit stores nothing either way, so failing it
        // closed here would hold both in-flight markers until `inflight_ttl`
        // for a request that never reached the backend — turning, e.g., a
        // probabilistic `fault_injection` abort into a hard 409 lockout for the
        // whole TTL — while buying no safety, because there are no bytes whose
        // producing policy could be misrepresented.
        //
        // `response_policy_stamp_stable()` compares the pinned publication
        // *identity*, not its content, so an A→B→A cycle observed during this
        // request is still treated as a straddle. The gate content read by the
        // transforms that shaped these bytes is then unknown, and the
        // representation belongs to no provable policy.
        //
        // The one exemption is the external-operation tombstone: its bytes are
        // a fixed refusal that claims no presentation policy, and withholding
        // it would restore the re-execution window GHSA-8cr6-rw38-7j59 closes.
        // See `EXTERNAL_OPERATION_TOMBSTONE_PUBLICATION_KEY`.
        let publishing_external_tombstone = ctx
            .metadata
            .get(EXTERNAL_OPERATION_TOMBSTONE_PUBLICATION_KEY)
            .and_then(|owner| owner.parse::<u64>().ok())
            == Some(self.instance_id);
        if !publishing_external_tombstone && !ctx.response_policy_stamp_stable() {
            // The final representation may have straddled a policy
            // publication, so it is unsafe to persist. Keep the in-flight
            // ownership rather than allowing a retry to repeat a possibly
            // completed external side effect. An owner of an already-performed
            // external operation parks that ownership so the committed hook can
            // replace the bounded lease with a durable execution barrier.
            self.park_ownership_for_execution_barrier(
                ctx,
                requires_execution_barrier,
                RequestDeduplicationRequestState {
                    key,
                    fingerprint,
                    local_inflight_owner_token,
                    redis_lock_token,
                },
            );
            return PluginResult::Continue;
        }
        let response_policy = ctx.response_policy_provenance();
        if !publishing_external_tombstone && response_policy.complete().is_none() {
            // The effective response-side presentation policy could not be
            // established — no plugin-cache view, or this proxy carries a
            // plugin whose response rewrite comes from live runtime state
            // (`ResponsePresentationPolicy::Dynamic`). These bytes belong to no
            // provable policy, so they are retained nowhere: not in Redis,
            // which `redis_payload_for_response` would refuse anyway, and not
            // in the local map, where a later request under an equally
            // unprovable policy would otherwise be served them.
            //
            // Concurrent-duplicate protection is unaffected — the in-flight
            // marking already happened and is kept, so a retry cannot repeat a
            // possibly completed external side effect. Only the finalized
            // *replay* is given up; an owner of an already-performed external
            // operation parks its ownership so the committed hook can replace
            // the bounded lease with a durable execution barrier.
            debug!(
                "request_deduplication: response-side presentation policy could not be \
                 established for this request; retaining no replayable representation"
            );
            self.park_ownership_for_execution_barrier(
                ctx,
                requires_execution_barrier,
                RequestDeduplicationRequestState {
                    key,
                    fingerprint,
                    local_inflight_owner_token,
                    redis_lock_token,
                },
            );
            return PluginResult::Continue;
        }

        // Strip session-bearing headers (Set-Cookie, Authorization, trace
        // IDs, rate-limit counters, etc.) before persisting. Replaying a
        // verbatim `Set-Cookie: session=...` to a second client sharing the
        // same idempotency key — possible when `scope_by_consumer=false`,
        // for anonymous traffic, or for any user whose session has rotated
        // since the cached response was captured — is a session-hijack /
        // pinned-stale-cookie vector. Mirrors `ai_semantic_cache`'s
        // sanitization on store. See [`super::utils::cache_headers`].
        let safe_headers = sanitize_cached_headers(response_headers);

        // The external-operation tombstone is an execution barrier, not a
        // representation of the real response: it replaces an in-flight marker
        // that blocked duplicates for `inflight_ttl_seconds`, so it must live at
        // least that long. Ordinary completions keep `ttl_seconds`.
        let retention = if publishing_external_tombstone {
            self.execution_barrier_retention()
        } else {
            self.ttl
        };

        let (cached, sequence, completed, inflight) = match self.local_publish_completed(
            &key,
            &fingerprint,
            &local_inflight_owner_token,
            LocalCompletionCandidate {
                status_code: response_status,
                headers: safe_headers,
                body,
                publish_execution_barrier_on_skip: requires_execution_barrier,
                retain_barrier_on_eviction: requires_execution_barrier
                    || redis_lock_token.is_some(),
                retention,
                response_policy,
            },
        ) {
            LocalCompletionAction::Published {
                cached,
                sequence,
                completed_count,
                inflight_count,
            } => (cached, sequence, completed_count, inflight_count),
            LocalCompletionAction::Skipped {
                inflight_count,
                reason,
                redis_candidate,
            } => {
                match reason {
                    CompletionSkipReason::EntryTooLarge { entry_size } => {
                        debug!(
                            entry_size,
                            max_entry_size_bytes = self.max_entry_size_bytes,
                            inflight_count,
                            "request_deduplication: completed response exceeds entry size limit, skipping store"
                        );
                    }
                    CompletionSkipReason::TotalCapacity {
                        entry_size,
                        current_total,
                    } => {
                        debug!(
                            entry_size,
                            current_total,
                            max_total_size_bytes = self.max_total_size_bytes,
                            inflight_count,
                            "request_deduplication: completed response would exceed total size limit, skipping store"
                        );
                    }
                }
                if let Some(ownership) = redis_lock_token.as_ref() {
                    // Transition the distributed ownership through the fence: a
                    // replayable record when the payload fits, otherwise a
                    // non-replayable tombstone. An external operation also keeps
                    // the fixed-size local barrier created above. Peers get a
                    // deterministic answer instead of being released to
                    // re-execute once the raw lease expires; a record with no
                    // replay is held for `execution_barrier_retention()`, so it
                    // never expires sooner than the lease it replaced.
                    match self
                        .redis_publish_completed(
                            &key,
                            &fingerprint,
                            ownership,
                            redis_candidate.as_ref(),
                            publishing_external_tombstone,
                        )
                        .await
                    {
                        // The completed Redis record now owns the distributed
                        // key. Remove only a raw local in-flight marker; an
                        // external operation's explicit local barrier survives.
                        RedisPublication::Published { .. } => {
                            self.remove_matching_local_inflight(
                                &key,
                                &fingerprint,
                                &local_inflight_owner_token,
                            );
                        }
                        RedisPublication::NotOwner => {
                            // A stale publisher must discard either provisional
                            // local state, but exact variant/token matching must
                            // not clear a successor that acquired after expiry.
                            self.remove_matching_local_inflight(
                                &key,
                                &fingerprint,
                                &local_inflight_owner_token,
                            );
                            self.remove_matching_local_execution_barrier(
                                &key,
                                &fingerprint,
                                &local_inflight_owner_token,
                            );
                        }
                        // Redis could not be reached. Keep the provisional local
                        // state — an ordinary in-flight lease or an external
                        // operation's execution barrier. The Redis record
                        // expires on its own lease.
                        RedisPublication::Unavailable => {}
                    }
                }
                return PluginResult::Continue;
            }
            LocalCompletionAction::Stale => {
                if let Some(ownership) = redis_lock_token.as_ref() {
                    self.redis_release_inflight(&key, ownership).await;
                }
                return PluginResult::Continue;
            }
        };
        // Publish to Redis through the ownership fence. There is no separate
        // "release the lock afterwards" step: the compare-and-set replaces this
        // request's in-flight record with the completed record in one
        // transaction, so peers never observe a completed value while a
        // successor owns the operation, and never observe the operation as
        // unowned-and-uncompleted in between.
        let mut preserve_local_completion =
            self.redis_client.is_none() && requires_execution_barrier;
        if let Some(ownership) = redis_lock_token.as_ref() {
            match self
                .redis_publish_completed(
                    &key,
                    &fingerprint,
                    ownership,
                    Some(&cached),
                    publishing_external_tombstone,
                )
                .await
            {
                RedisPublication::Published { replayable: true } => {
                    // Redis now carries the replay, so ordinary LRU eviction is
                    // safe even for an externally executing terminal response.
                    self.set_completed_barrier_retention(&key, &fingerprint, sequence, false);
                }
                // The response fits local retention but not the Redis payload
                // cap, so a non-replayable tombstone owns the distributed key.
                // Peers get a deterministic conflict; this gateway keeps the
                // richer local replay and protects it from eviction.
                RedisPublication::Published { replayable: false } => {
                    preserve_local_completion = true;
                }
                RedisPublication::NotOwner => {
                    // This owner's lease expired or a successor owns the
                    // operation. The completion is not authoritative: refusing
                    // the distributed write while keeping a local replay would
                    // make this gateway answer retries with a result the rest of
                    // the deployment does not recognize. Drop it and let the
                    // next request re-read the authoritative record.
                    self.remove_local_completed(&key, &fingerprint, sequence);
                    self.remove_matching_local_execution_barrier(
                        &key,
                        &fingerprint,
                        &local_inflight_owner_token,
                    );
                    return PluginResult::Continue;
                }
                RedisPublication::Unavailable => {
                    // No distributed replay is known to exist. Keep the local
                    // replay and retain a local tombstone if later capacity
                    // pressure must evict it. The Redis in-flight record is left
                    // to expire on its own lease, so peers stay blocked instead
                    // of splitting ownership.
                    preserve_local_completion = true;
                }
            }
        }

        // Admission to Redis is now settled. Until this point an owned
        // completion is already marked for tombstone conversion, so a
        // concurrent capacity trim cannot silently remove the last local
        // safety state. When no distributed replay exists, retain one completed
        // replay even if active in-flight requests temporarily push the cache
        // over max_entries; later pressure converts older protected replays to
        // fixed-size barriers with their original retention clocks rather than
        // dropping them or restarting `inflight_ttl`.
        self.evict_completed_over_capacity(completed, inflight, preserve_local_completion);

        PluginResult::Continue
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) {
        if ctx
            .serverless_pre_invocation_rejection_owners
            .remove(&self.instance_id)
        {
            let Some(state) = ctx.request_deduplication_states.remove(&self.instance_id) else {
                return;
            };
            self.remove_matching_local_inflight(
                &state.key,
                &state.fingerprint,
                &state.local_inflight_owner_token,
            );
            if let Some(ownership) = state.redis_lock_token.as_ref() {
                self.redis_release_inflight(&state.key, ownership).await;
            }
            return;
        }

        if ctx
            .serverless_external_side_effect_owners
            .remove(&self.instance_id)
        {
            // Consume only this instance's provenance before reusing the ordinary
            // publication path. Other instances retain their ownership and publish
            // into their own caches when their committed hooks run.
            let synthetic_marker = ctx
                .metadata
                .remove(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY);
            let previous_publication_owner = ctx
                .serverless_owned_dedup_publication
                .replace(self.instance_id);
            let _ = self
                .on_final_response_body(ctx, response_status, response_headers, body)
                .await;
            // The publication path refuses a replayable completion when this
            // response's policy provenance straddled a publication or could not
            // be established at all (no plugin-cache view, or a `Dynamic`
            // response-presentation policy). It parks this instance's exact
            // ownership back into the request to say so
            // (`park_ownership_for_execution_barrier`). The serverless operation
            // already ran, so leaving only the raw in-flight lease would make it
            // executable again once `inflight_ttl_seconds` elapsed. Transition
            // that same ownership through the fixed non-replayable 409
            // external-operation tombstone instead — the same fenced path, with
            // `execution_barrier_retention()` so the barrier outlives the lease
            // it replaces. A capacity or Redis rejection there still fails
            // closed on the retained in-flight markers.
            if ctx
                .request_deduplication_states
                .contains_key(&self.instance_id)
            {
                self.publish_external_operation_tombstone(ctx).await;
            }
            ctx.serverless_owned_dedup_publication = previous_publication_owner;
            if let Some(marker) = synthetic_marker {
                ctx.metadata.insert(
                    crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
                    marker,
                );
            }
            return;
        }

        // A synthetic response produced after a committed or ambiguous external
        // operation (an `ai_federation` provider call today) cannot be replayed:
        // re-running response transforms or re-issuing the side effect under the
        // same idempotency key is unsafe, while caching the synthetic body would
        // replay a representation that was never a backend response. Publish a
        // small non-replayable 409 tombstone instead, so an identical retry is
        // rejected deterministically for the cache TTL rather than re-executing
        // the operation once the raw in-flight marker expires.
        // `on_final_response_body`'s synthetic guard retained ownership for
        // exactly this. The synthetic marker is cleared around the re-entry so
        // the publication path runs instead of the retain-and-return synthetic
        // guard, then restored for any later hook that observes it. If capacity
        // is too small even for the tombstone, `local_publish_completed` keeps
        // the fixed-size execution barrier rather than failing open to an
        // immediate duplicate.
        if ctx
            .metadata
            .contains_key(super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY)
        {
            self.publish_external_operation_tombstone(ctx).await;
            return;
        }

        // Generic committed-hook release signals used by non-serverless ownership
        // producers (for example `ai_federation`, and the proxy/H3 commit paths)
        // and by finalized successful synthetic short-circuits (including empty
        // 200 and 204 shapes that skip the synthetic body-hook pipeline):
        // release this instance's exact in-flight token so a duplicate retry can
        // proceed. An external operation that completed is handled above and
        // never reaches here, so this path only releases requests that were
        // provably safe to retry (the `!EXTERNAL_OPERATION_COMPLETED` guard is
        // retained defensively against any future reordering). Token/fingerprint
        // matching in `remove_matching_local_inflight` / Redis lock release
        // ensures a late finalizer cannot clear a successor's marker.
        //
        // Non-2xx plugin rejects and downstream rejection replacements do not
        // set `FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY`; those intentionally
        // retain local and Redis in-flight ownership until `inflight_ttl`.
        if (ctx
            .metadata
            .contains_key(super::RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY))
            && !ctx
                .metadata
                .contains_key(super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY)
        {
            let Some(state) = ctx.request_deduplication_states.remove(&self.instance_id) else {
                return;
            };
            self.remove_matching_local_inflight(
                &state.key,
                &state.fingerprint,
                &state.local_inflight_owner_token,
            );
            if let Some(ownership) = state.redis_lock_token.as_ref() {
                self.redis_release_inflight(&state.key, ownership).await;
            }
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        if let Some(ref redis) = self.redis_client {
            redis.warmup_hostname().into_iter().collect()
        } else {
            Vec::new()
        }
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.local_cache.len())
    }
}
