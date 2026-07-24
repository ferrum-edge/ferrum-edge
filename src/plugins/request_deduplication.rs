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

const DEDUP_LOGICAL_KEY_VERSION: &str = "ferrum-dedup-logical-v3";
const DEDUP_FINGERPRINT_VERSION: &str = "ferrum-dedup-fingerprint-v2";
const REDIS_INFLIGHT_KEY_COMPONENT: &str = "inflight";
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
/// Monotonic seconds since process start. Immune to wall-clock steps, matching
/// the `Instant`-based entry expiry.
fn monotonic_secs() -> u64 {
    PROCESS_START.elapsed().as_secs()
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
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

/// A cached response stored for deduplication replay.
#[derive(Debug, Clone)]
struct CachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
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
    /// Response has been cached.
    Completed {
        cached: CachedResponse,
        sequence: u64,
        fingerprint: String,
        /// Replace this replay with a short-lived in-flight tombstone instead
        /// of removing it when capacity pressure makes retention impossible.
        /// This is set for externally executing terminal responses until a
        /// distributed replay is known to be visible.
        retain_inflight_on_eviction: bool,
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

enum RedisDeduplicationAction {
    Miss,
    Replay(CachedResponse),
    Conflict,
}

enum RedisInFlightAction {
    Acquired(String),
    Conflict(DeduplicationConflict),
    Unavailable,
}

enum RedisStoreAction {
    Stored,
    SkippedSize,
    Failed,
}

enum RedisPayloadAdmission {
    Admitted(Vec<u8>),
    RejectedBySize,
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
    redis_lock_token: Option<String>,
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
            redis_lock_token: redis_lock_token.map(str::to_string),
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
    /// Local in-memory cache.
    local_cache: Arc<DashMap<String, DeduplicationEntry>>,
    completed_count: AtomicUsize,
    completed_size_bytes: AtomicUsize,
    inflight_count: AtomicUsize,
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
        if !config.is_object() {
            return Err("request_deduplication: config must be an object".to_string());
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
            local_cache: Arc::new(DashMap::with_shard_amount(shard_amount)),
            completed_count: AtomicUsize::new(0),
            completed_size_bytes: AtomicUsize::new(0),
            inflight_count: AtomicUsize::new(0),
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
                DeduplicationEntry::InFlight { .. } => 0,
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
        let expired_at = Instant::now()
            .checked_sub(self.ttl.saturating_add(Duration::from_secs(1)))
            .unwrap_or_else(Instant::now);
        for mut entry in self.local_cache.iter_mut() {
            if let DeduplicationEntry::Completed { cached, .. } = entry.value_mut() {
                cached.inserted_at = expired_at;
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

    /// Build the logical deduplication key from unambiguous framed fields.
    ///
    /// The returned key intentionally contains only a versioned digest so
    /// Redis keys and request metadata never expose idempotency values or
    /// authenticated identities.
    fn build_key(&self, ctx: &RequestContext, idempotency_value: &str) -> String {
        let proxy_id = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("_");

        let mut hasher = Sha256::new();
        hash_framed(&mut hasher, "version", DEDUP_LOGICAL_KEY_VERSION.as_bytes());
        hash_framed(&mut hasher, "plugin_config_id", self.config_id.as_bytes());
        hash_framed(&mut hasher, "proxy_id", proxy_id.as_bytes());
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
        key.push_str("v3:");
        key.push_str(&hex::encode(hasher.finalize()));
        key
    }

    fn replay_response(&self, ctx: &mut RequestContext, cached: &CachedResponse) -> PluginResult {
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
                        if now.duration_since(cached.inserted_at) < self.ttl {
                            if cached_fingerprint == fingerprint {
                                return LocalDeduplicationAction::Replay(cached.clone());
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
                self.replace_expired_completed_with_inflight(key, fingerprint, now, owner_token)
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
                && now.duration_since(cached.inserted_at) < self.ttl
            {
                Some(cached.clone())
            } else {
                None
            }
        })
    }

    fn replace_expired_completed_with_inflight(
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
                    if now.duration_since(cached.inserted_at) < self.ttl {
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

    /// Try to retrieve a cached response from Redis.
    async fn redis_get(&self, key: &str, fingerprint: &str) -> RedisDeduplicationAction {
        let Some(redis) = self.redis_client.as_ref() else {
            return RedisDeduplicationAction::Miss;
        };
        if !redis.is_available() {
            return RedisDeduplicationAction::Miss;
        }

        let redis_key = redis.make_key(&[key]);
        let data = match redis.get_bytes(&redis_key).await {
            Ok(Some(d)) => d,
            Ok(None) => return RedisDeduplicationAction::Miss,
            Err(()) => return RedisDeduplicationAction::Miss,
        };

        match serde_json::from_slice::<SerializableCachedResponse>(&data) {
            Ok(s) if s.fingerprint == fingerprint => {
                RedisDeduplicationAction::Replay(CachedResponse {
                    status_code: s.status_code,
                    headers: s.headers,
                    body: Bytes::from(s.body),
                    inserted_at: Instant::now(), // Not meaningful for Redis entries
                })
            }
            Ok(_) => RedisDeduplicationAction::Conflict,
            Err(_) => RedisDeduplicationAction::Miss,
        }
    }

    async fn redis_mark_inflight(&self, key: &str, fingerprint: &str) -> RedisInFlightAction {
        let Some(redis) = self.redis_client.as_ref() else {
            return RedisInFlightAction::Unavailable;
        };
        if !redis.is_available() {
            return RedisInFlightAction::Unavailable;
        }

        let redis_key = redis.make_key(&[REDIS_INFLIGHT_KEY_COMPONENT, key]);
        for _ in 0..2 {
            let token = uuid::Uuid::new_v4().to_string();
            let lock = SerializableInFlightLock {
                fingerprint: fingerprint.to_string(),
                token: token.clone(),
            };
            let lock_bytes = match serde_json::to_vec(&lock) {
                Ok(bytes) => bytes,
                Err(_) => return RedisInFlightAction::Unavailable,
            };

            match redis
                .set_bytes_nx_with_expire(
                    &redis_key,
                    &lock_bytes,
                    self.inflight_ttl.as_secs().max(1),
                )
                .await
            {
                Ok(true) => return RedisInFlightAction::Acquired(token),
                Ok(false) => {}
                Err(()) => return RedisInFlightAction::Unavailable,
            }

            let existing = match redis.get_bytes(&redis_key).await {
                Ok(Some(existing)) => existing,
                Ok(None) => continue,
                Err(()) => return RedisInFlightAction::Unavailable,
            };

            return match serde_json::from_slice::<SerializableInFlightLock>(&existing) {
                Ok(existing_lock) if existing_lock.fingerprint == fingerprint => {
                    RedisInFlightAction::Conflict(DeduplicationConflict::InFlight)
                }
                Ok(_) => RedisInFlightAction::Conflict(DeduplicationConflict::FingerprintMismatch),
                Err(_) => RedisInFlightAction::Conflict(DeduplicationConflict::InFlight),
            };
        }

        RedisInFlightAction::Conflict(DeduplicationConflict::InFlight)
    }

    async fn redis_release_inflight(&self, key: &str, fingerprint: &str, token: &str) {
        let Some(redis) = self.redis_client.as_ref() else {
            return;
        };
        if !redis.is_available() {
            return;
        }

        let lock = SerializableInFlightLock {
            fingerprint: fingerprint.to_string(),
            token: token.to_string(),
        };
        let lock_bytes = match serde_json::to_vec(&lock) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let redis_key = redis.make_key(&[REDIS_INFLIGHT_KEY_COMPONENT, key]);
        if let Err(()) = redis.delete_if_value_matches(&redis_key, &lock_bytes).await {
            debug!("request_deduplication: Redis in-flight lock release failed");
        }
    }

    /// Store a cached response in Redis with TTL.
    async fn redis_set(
        &self,
        key: &str,
        fingerprint: &str,
        response: &CachedResponse,
    ) -> RedisStoreAction {
        let Some(redis) = self.redis_client.as_ref() else {
            return RedisStoreAction::Failed;
        };
        if !redis.is_available() {
            return RedisStoreAction::Failed;
        }

        let data = match self.redis_payload_for_response(fingerprint, response) {
            RedisPayloadAdmission::Admitted(data) => data,
            RedisPayloadAdmission::RejectedBySize => return RedisStoreAction::SkippedSize,
        };

        let redis_key = redis.make_key(&[key]);
        let ttl_seconds = self.ttl.as_secs().max(1);
        if let Err(()) = redis
            .set_bytes_with_expire(&redis_key, &data, ttl_seconds)
            .await
        {
            debug!("request_deduplication: Redis SET failed");
            return RedisStoreAction::Failed;
        }
        RedisStoreAction::Stored
    }

    fn redis_payload_for_response(
        &self,
        fingerprint: &str,
        response: &CachedResponse,
    ) -> RedisPayloadAdmission {
        let entry_size = response.retained_size();
        if entry_size > self.max_entry_size_bytes {
            debug!(
                entry_size,
                max_entry_size_bytes = self.max_entry_size_bytes,
                "request_deduplication: completed response exceeds Redis entry size limit, skipping store"
            );
            return RedisPayloadAdmission::RejectedBySize;
        }

        let serializable = SerializableCachedResponse {
            fingerprint: fingerprint.to_string(),
            status_code: response.status_code,
            headers: response.headers.clone(),
            body: response.body.to_vec(),
        };

        let data = match serde_json::to_vec(&serializable) {
            Ok(data) => data,
            Err(_) => return RedisPayloadAdmission::RejectedBySize,
        };
        if data.len() > self.max_entry_size_bytes {
            debug!(
                payload_size = data.len(),
                max_entry_size_bytes = self.max_entry_size_bytes,
                "request_deduplication: serialized Redis response exceeds entry size limit, skipping store"
            );
            return RedisPayloadAdmission::RejectedBySize;
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

    #[allow(dead_code)]
    pub(crate) fn redis_payload_for_tests(
        &self,
        status_code: u16,
        headers: HashMap<String, String>,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        let response = CachedResponse {
            status_code,
            headers,
            body: Bytes::copy_from_slice(body),
            inserted_at: Instant::now(),
        };
        match self.redis_payload_for_response("test-fingerprint", &response) {
            RedisPayloadAdmission::Admitted(payload) => Some(payload),
            RedisPayloadAdmission::RejectedBySize => None,
        }
    }

    fn local_publish_completed(
        &self,
        key: &str,
        fingerprint: &str,
        owner_token: &str,
        candidate: LocalCompletionCandidate<'_>,
        retain_inflight_on_skip: bool,
        retain_inflight_on_eviction: bool,
    ) -> LocalCompletionAction {
        let LocalCompletionCandidate {
            status_code,
            headers,
            body,
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
            let inflight_count = if retain_inflight_on_skip {
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
            let redis_candidate = if self.redis_client.is_some() {
                Some(CachedResponse {
                    status_code,
                    headers,
                    body: Bytes::copy_from_slice(body),
                    inserted_at: Instant::now(),
                })
            } else {
                if !retain_inflight_on_skip {
                    entry.remove();
                }
                None
            };
            let inflight_count = if redis_candidate.is_some() || retain_inflight_on_skip {
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
        };
        let redis_copy = cached.clone();
        entry.insert(DeduplicationEntry::Completed {
            cached,
            sequence,
            fingerprint: fingerprint.to_string(),
            retain_inflight_on_eviction,
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

    fn set_completed_inflight_retention(
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
            retain_inflight_on_eviction,
            ..
        } = entry.value_mut()
            && *current_sequence == sequence
            && current_fingerprint.as_str() == fingerprint
        {
            *retain_inflight_on_eviction = retain;
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
                let keep = now.duration_since(cached.inserted_at) < self.ttl;
                if !keep {
                    let retained_size = cached.retained_size();
                    self.mark_completed_sequence_pruned(*sequence);
                    self.sub_completed_size_locked(retained_size);
                    decrement_atomic(&self.completed_count);
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
                CompletedSequenceRemoval::Removed | CompletedSequenceRemoval::Tombstoned => {
                    to_remove -= 1;
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
        let (retained_size, fingerprint, retain_inflight_on_eviction) = match entry.get() {
            DeduplicationEntry::Completed {
                cached,
                sequence: current,
                fingerprint,
                retain_inflight_on_eviction,
            } if *current == sequence => (
                cached.retained_size(),
                fingerprint.clone(),
                *retain_inflight_on_eviction,
            ),
            _ => {
                drop(entry);
                self.remove_stale_completed_order(sequence, &key);
                return CompletedSequenceRemoval::Stale;
            }
        };

        self.sub_completed_size_locked(retained_size);
        decrement_atomic(&self.completed_count);
        let result = if retain_inflight_on_eviction {
            // A distributed lock may still be the only cross-gateway guard for
            // an externally executed response. If the replay cannot remain in
            // the bounded local cache, retain a small local tombstone so Redis
            // loss cannot turn an identical retry into another side effect.
            entry.insert(DeduplicationEntry::InFlight {
                started_at: Instant::now(),
                fingerprint,
                owner_token: self.next_local_inflight_owner_token(),
            });
            self.inflight_count.fetch_add(1, Ordering::Relaxed);
            CompletedSequenceRemoval::Tombstoned
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
    status_code: u16,
    headers: HashMap<String, String>,
    #[serde(
        serialize_with = "serialize_cached_response_body",
        deserialize_with = "deserialize_cached_response_body"
    )]
    body: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableInFlightLock {
    fingerprint: String,
    token: String,
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
    serde_json::from_slice::<SerializableCachedResponse>(data).is_ok()
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

        // Check Redis first (centralized dedup across instances), then acquire
        // a Redis in-flight lock before any gateway instance can dispatch the
        // fresh request to the backend.
        let mut redis_lock_token = None;
        if self.redis_client.is_some() {
            match self.redis_get(&key, &fingerprint).await {
                RedisDeduplicationAction::Replay(cached) => {
                    debug!("request_deduplication: Redis cache hit, replaying response");
                    // Defense-in-depth: re-sanitize on replay even though insert
                    // already strips. A stored entry written before this fix landed,
                    // or by a peer running an older binary against a shared Redis,
                    // could still carry session-bearing headers.
                    return self.replay_response(ctx, &cached);
                }
                RedisDeduplicationAction::Conflict => {
                    return PluginResult::Reject {
                        status_code: 409,
                        body: r#"{"error":"Idempotency key was reused for a different request"}"#
                            .to_string(),
                        headers: HashMap::new(),
                    };
                }
                RedisDeduplicationAction::Miss => {}
            }

            match self.redis_mark_inflight(&key, &fingerprint).await {
                RedisInFlightAction::Acquired(token) => {
                    match self.redis_get(&key, &fingerprint).await {
                        RedisDeduplicationAction::Replay(cached) => {
                            self.redis_release_inflight(&key, &fingerprint, &token)
                                .await;
                            return self.replay_response(ctx, &cached);
                        }
                        RedisDeduplicationAction::Conflict => {
                            self.redis_release_inflight(&key, &fingerprint, &token)
                                .await;
                            return PluginResult::Reject {
                                status_code: 409,
                                body:
                                    r#"{"error":"Idempotency key was reused for a different request"}"#
                                        .to_string(),
                                headers: HashMap::new(),
                            };
                        }
                        RedisDeduplicationAction::Miss => {}
                    }
                    redis_lock_token = Some(token);
                }
                RedisInFlightAction::Conflict(DeduplicationConflict::InFlight) => {
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
                RedisInFlightAction::Conflict(DeduplicationConflict::FingerprintMismatch) => {
                    return PluginResult::Reject {
                        status_code: 409,
                        body: r#"{"error":"Idempotency key was reused for a different request"}"#
                            .to_string(),
                        headers: HashMap::new(),
                    };
                }
                RedisInFlightAction::Unavailable => {}
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
                if let Some(token) = redis_lock_token.as_deref() {
                    self.redis_release_inflight(&key, &fingerprint, token).await;
                }
                debug!("request_deduplication: local cache hit, replaying response");
                // Defense-in-depth: re-sanitize on replay even though insert
                // already strips. Cheap (single HashMap pass) and protects
                // against any future code path that populates the cache without
                // going through `on_final_response_body`.
                return self.replay_response(ctx, &cached);
            }
            LocalDeduplicationAction::Conflict(DeduplicationConflict::InFlight) => {
                if let Some(token) = redis_lock_token.as_deref() {
                    self.redis_release_inflight(&key, &fingerprint, token).await;
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
                if let Some(token) = redis_lock_token.as_deref() {
                    self.redis_release_inflight(&key, &fingerprint, token).await;
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
        if ctx
            .serverless_external_side_effect_owners
            .contains(&self.instance_id)
            || !outcome.body_completed
        {
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
        if let Some(token) = state.redis_lock_token.as_deref() {
            self.redis_release_inflight(&state.key, &state.fingerprint, token)
                .await;
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
        // Retain both in-flight locks (rather than fail open) when configured
        // capacity is too small even to store an owned terminal response or a
        // non-replayable external-operation tombstone. Serverless owns its
        // publication through the typed marker above; `ai_federation` signals
        // the same intent for its committed provider call through
        // `EXTERNAL_OPERATION_COMPLETED_METADATA_KEY`, so a storage skip there
        // must keep the marker instead of letting a retry re-run the operation.
        let retain_inflight_on_storage_skip = ctx.serverless_owned_dedup_publication
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
        // re-execute it. Retain both in-flight locks until `inflight_ttl` in
        // that case, mirroring the terminate-mode serverless side-effect owner
        // handling above.
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
            if let Some(token) = redis_lock_token.as_deref() {
                self.redis_release_inflight(&key, &fingerprint, token).await;
            }
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

        let (cached, sequence, completed, inflight) = match self.local_publish_completed(
            &key,
            &fingerprint,
            &local_inflight_owner_token,
            LocalCompletionCandidate {
                status_code: response_status,
                headers: safe_headers,
                body,
            },
            retain_inflight_on_storage_skip,
            retain_inflight_on_storage_skip || redis_lock_token.is_some(),
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
                if let Some(cached) = redis_candidate {
                    match self.redis_set(&key, &fingerprint, &cached).await {
                        RedisStoreAction::Stored => {
                            self.remove_matching_local_inflight(
                                &key,
                                &fingerprint,
                                &local_inflight_owner_token,
                            );
                            if let Some(token) = redis_lock_token.as_deref() {
                                self.redis_release_inflight(&key, &fingerprint, token).await;
                            }
                        }
                        RedisStoreAction::SkippedSize if !retain_inflight_on_storage_skip => {
                            self.remove_matching_local_inflight(
                                &key,
                                &fingerprint,
                                &local_inflight_owner_token,
                            );
                            if let Some(token) = redis_lock_token.as_deref() {
                                self.redis_release_inflight(&key, &fingerprint, token).await;
                            }
                        }
                        // Nothing was retained locally. If Redis publication
                        // fails too (or an owned terminal response cannot fit
                        // the Redis payload limit), keep both in-flight locks
                        // until `inflight_ttl` so retries cannot immediately
                        // re-run an external side effect with no replay value.
                        RedisStoreAction::SkippedSize | RedisStoreAction::Failed => {}
                    }
                    return PluginResult::Continue;
                }
                if !retain_inflight_on_storage_skip && let Some(token) = redis_lock_token.as_deref()
                {
                    self.redis_release_inflight(&key, &fingerprint, token).await;
                }
                return PluginResult::Continue;
            }
            LocalCompletionAction::Stale => {
                if let Some(token) = redis_lock_token.as_deref() {
                    self.redis_release_inflight(&key, &fingerprint, token).await;
                }
                return PluginResult::Continue;
            }
        };
        // Also store in Redis if available. Release the distributed in-flight
        // lock only after the completed response is visible in Redis, so a peer
        // cannot miss both the lock and the replayable response.
        let mut preserve_local_completion =
            self.redis_client.is_none() && retain_inflight_on_storage_skip;
        if self.redis_client.is_some() {
            match self.redis_set(&key, &fingerprint, &cached).await {
                RedisStoreAction::Stored => {
                    // Redis now carries the replay, so ordinary LRU eviction is
                    // safe even for an externally executing terminal response.
                    self.set_completed_inflight_retention(&key, &fingerprint, sequence, false);
                    if let Some(token) = redis_lock_token.as_deref() {
                        self.redis_release_inflight(&key, &fingerprint, token).await;
                    }
                }
                // The local replay is available, but a peer cannot see it. For
                // an externally executing terminal response, retain the
                // distributed lock until its TTL instead of allowing a peer to
                // re-execute the side effect immediately.
                RedisStoreAction::SkippedSize if retain_inflight_on_storage_skip => {
                    preserve_local_completion = true;
                }
                RedisStoreAction::SkippedSize => {
                    self.set_completed_inflight_retention(&key, &fingerprint, sequence, false);
                    if let Some(token) = redis_lock_token.as_deref() {
                        self.redis_release_inflight(&key, &fingerprint, token).await;
                    }
                }
                RedisStoreAction::Failed => {
                    // If this response owns a terminal side effect or a Redis
                    // in-flight lock, no distributed replay is known to exist.
                    // Keep the local replay when possible and retain a local
                    // tombstone if later capacity pressure must evict it.
                    preserve_local_completion =
                        retain_inflight_on_storage_skip || redis_lock_token.is_some();
                    if !preserve_local_completion {
                        self.set_completed_inflight_retention(&key, &fingerprint, sequence, false);
                    }
                }
            }
        }

        // Admission to Redis is now settled. Until this point an owned
        // completion is already marked for tombstone conversion, so a
        // concurrent capacity trim cannot silently remove the last local
        // safety state. When no distributed replay exists, retain one completed
        // replay even if active in-flight requests temporarily push the cache
        // over max_entries; later pressure converts older protected replays to
        // bounded-TTL in-flight tombstones rather than dropping them.
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
            if let Some(token) = state.redis_lock_token.as_deref() {
                self.redis_release_inflight(&state.key, &state.fingerprint, token)
                    .await;
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
        // the in-flight locks (see `retain_inflight_on_storage_skip`) rather than
        // failing open to an immediate duplicate.
        if ctx
            .metadata
            .contains_key(super::EXTERNAL_OPERATION_COMPLETED_METADATA_KEY)
        {
            let synthetic_marker = ctx
                .metadata
                .remove(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY);
            let headers = HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
            ]);
            let body = br#"{"error":"This idempotency key already completed an external operation and cannot be replayed safely"}"#;
            let _ = self.on_final_response_body(ctx, 409, &headers, body).await;
            if let Some(marker) = synthetic_marker {
                ctx.metadata.insert(
                    crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
                    marker,
                );
            }
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
            if let Some(token) = state.redis_lock_token.as_deref() {
                self.redis_release_inflight(&state.key, &state.fingerprint, token)
                    .await;
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
