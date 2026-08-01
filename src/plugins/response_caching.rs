//! Response Caching Plugin
//!
//! Caches backend responses in-memory for cacheable endpoints, reducing
//! backend load for repeated identical requests. Supports Cache-Control,
//! ETag/Last-Modified revalidation, backend `Vary` awareness, binary bodies,
//! configurable TTL, entry size limits, and automatic eviction.
//!
//! ## Replay provenance
//!
//! A HIT / REVALIDATED reply is a *finalized* client representation: the
//! synthetic replay path deliberately skips presentation transforms
//! (`RequestContext::finalized_response_replay`) so non-idempotent
//! `response_transformer` header/body `add` sequences cannot run a second time
//! over an already-transformed entry.
//!
//! A `response_caching` instance can outlive the presentation policy that
//! produced its entries. Its own config is untouched by a
//! `response_transformer` edit, and a *global* instance is not even rebuilt when
//! the proxy carrying that transformer is (`rebuild_globals` is only set by a
//! global plugin change), so the same cache keeps serving across the change.
//! Without provenance, an entry stored while a redaction rule was disabled would
//! keep being replayed unredacted after an operator enabled it.
//!
//! Every entry therefore carries two independent provenance halves, and a
//! difference in **either** retires it:
//!
//! - The **published gate identity**, pinned by
//!   `RequestContext::pin_response_policy_stamp` from the same atomically
//!   published state as the response-side gate map.
//! - The **generation's effective presentation policy digest**
//!   (`RequestContext::response_presentation_policy_digest`), copied from this
//!   request's own plugin-cache view before any plugin ran.
//!
//! Both are needed. The gate map is published *after*
//! `ProxyState::update_config`, so the two are read from different generations
//! whenever a mesh apply lands between a request pinning its plugin cache and
//! that request reaching `before_proxy` (its authenticate/authorize phase can
//! span a whole apply). Since GHSA-83rc-23c9-3g9x a transformer's effective gate
//! is materialized into its configuration, so the digest — which covers the gate
//! *and* the static rules, per instance — is the exact witness of the policy
//! that shaped the stored bytes, while the gate identity remains the witness of
//! what the rest of the process currently publishes. Two rules keep them honest:
//!
//! - **Lookup**: an entry whose gate identity or generation digest differs from
//!   the current request's is invalidated and refetched — checked before
//!   freshness, for both HIT and REVALIDATED, so neither can serve a superseded
//!   policy.
//! - **Store**: a response whose request straddled a gate publication is not
//!   stored at all; its bytes belong to neither policy.
//!
//! The result is deterministic and fail-closed across arbitrarily many
//! enable/disable cycles: a replayed representation is always provably the
//! product of the live policy, so transforms are neither skipped when policy
//! tightened nor stacked when it did not change. Reapplying the identical live
//! map is a no-op; every real policy transition receives a fresh, collision-free
//! identity and retires entries from the preceding publication. A proxy whose
//! effective presentation policy is *unprovable* (an enrolled plugin rewrites
//! from live runtime state) never stores or replays an entry. Unknown policy is
//! not evidence that two requests shared one.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, NaiveDateTime, Utc};
use dashmap::DashMap;
use http::{HeaderName, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::debug;

use crate::util::body_limit::{ContentLength, parse_content_length};
use crate::util::unknown_keys::reject_unknown_keys;

use super::utils::replay_partition::{self, AnonymousCallerScope, PartitionHasher};
use super::utils::runtime_bool_gate::GatePolicyStamp;
use super::{Plugin, PluginResult, RequestContext};

/// Domain-separation tags for the canonical, length-framed cache-key digests.
///
/// Cache keys used to be raw `proxy:host:method:path:query:consumer` strings
/// with `name=value|name=value` Vary suffixes. Every one of those delimiters can
/// appear inside an attacker-supplied Vary value, so two structurally different
/// requests could serialize to one preimage (GHSA-v4g3-2r4f-f6pc). Keys are now
/// digests over typed, length-framed fields under these tags; the `v1` suffixes
/// make every pre-contract key unreachable, which is the intended fail-closed
/// outcome for entries stored under a partition that omitted caller
/// authorization, canonical caller context, or the effective destination
/// (GHSA-w27g-65rf-h7xm).
const RESPONSE_CACHING_BASE_KEY_DOMAIN: &str = "ferrum-response-caching-base-v1";
const RESPONSE_CACHING_VARY_DOMAIN: &str = "ferrum-response-caching-vary-v1";
const RESPONSE_CACHING_SCOPE_DOMAIN: &str = "ferrum-response-caching-scope-v1";

/// Separator between the base-key digest and the Vary digest inside a full
/// cache key. Both sides are fixed-length lowercase hex, so this byte can never
/// occur inside either component and the split is unambiguous by construction.
const CACHE_KEY_VARY_SEPARATOR: char = '.';

/// Bodyless retrieval methods a shared cache can key completely.
///
/// A cached representation is selected by method + target + Vary. For a
/// body-bearing method the *body* is part of what the origin answered, and this
/// plugin performs its lookup in `before_proxy` — before
/// `on_final_request_body`, and therefore before the exact backend-visible body
/// exists. Rather than key a pre-transform body that is not the one sent
/// upstream, body-bearing methods are refused outright at config admission and
/// again at runtime (GHSA-w27g-65rf-h7xm).
const BODYLESS_CACHEABLE_METHODS: [&str; 2] = ["GET", "HEAD"];

/// Authoritative closed set of top-level `response_caching` configuration keys.
///
/// Constructor admission, OpenAPI `ResponseCachingConfig`, and operator docs must
/// stay in lockstep with this list. Unknown root properties fail closed so a
/// misspelled Vary, consumer, query, Cache-Control, status/method, capacity, or
/// invalidation field cannot silently fall back to a weaker default partition
/// or retention policy.
pub const RESPONSE_CACHING_CONFIG_KEYS: &[&str] = &[
    "add_cache_status_header",
    "anonymous_caller_scope",
    "cache_key_include_consumer",
    "cache_key_include_query",
    "cacheable_methods",
    "cacheable_status_codes",
    "invalidate_on_unsafe_methods",
    "max_entries",
    "max_entry_size_bytes",
    "max_total_size_bytes",
    "respect_cache_control",
    "respect_no_cache",
    "ttl_seconds",
    "vary_by_headers",
];

/// The single response field `after_proxy` writes, in the bounded form
/// `Plugin::response_trailer_policy` hands to the plugin cache. Built once per
/// process; never allocated per request. (`age` is written only onto a
/// gateway-synthesized cache HIT, which carries no backend trailer section, so
/// it is deliberately not declared here.)
static CACHE_STATUS_POLICY_NAMES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| vec!["x-cache-status".to_string()]);

/// Maximum cache entries before triggering eviction of expired entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default TTL when no Cache-Control header is present (5 minutes).
const DEFAULT_TTL_SECONDS: u64 = 300;

/// Default maximum size of a single cached response body (1 MiB).
const DEFAULT_MAX_ENTRY_SIZE_BYTES: usize = 1_048_576;

/// Default maximum total cache size (100 MiB).
const DEFAULT_MAX_TOTAL_SIZE_BYTES: usize = 104_857_600;

/// Request-metadata namespace prefix. Each plugin instance appends its
/// process-unique [`ResponseCaching::instance_id`] so multiple
/// `response_caching` configs on one proxy cannot overwrite one another's
/// staged base key, status, predictor key, timing, header snapshot, lookup
/// path, or pending unsafe-method invalidation host partition.
const METADATA_NAMESPACE_PREFIX: &str = "response_caching.";
const CACHE_BASE_KEY_SUFFIX: &str = "cache_base_key";
const CACHE_STATUS_SUFFIX: &str = "cache_status";
const CACHE_PREDICT_KEY_SUFFIX: &str = "cache_predict_key";
const CACHE_REQUEST_STARTED_MONOTONIC_NANOS_SUFFIX: &str = "cache_request_started_monotonic_nanos";
/// JSON-serialized snapshot of the request header values `before_proxy` saw
/// while building the cache key. `on_final_response_body` reads it back to
/// build the storage cache key from the *same* header view, even when an
/// earlier plugin's `transform_request_headers` mutated the outbound
/// headers map — see [`ResponseCaching::stash_request_headers_snapshot`]
/// and the bug it fixes. The full metadata key is
/// `response_caching.<instance_id>.cache_request_headers_snapshot`.
const CACHE_REQUEST_HEADERS_SNAPSHOT_SUFFIX: &str = "cache_request_headers_snapshot";
/// Normalized Host/authority partition (`h-<sha256>` or empty) stashed when an
/// unsafe method may require RFC 9111 §4.4 invalidation after a non-error
/// response. Must match [`ResponseCaching::invalidation_scope`] used by
/// lookup/storage.
const CACHE_PENDING_INVALIDATE_HOST_SUFFIX: &str = "cache_pending_invalidate_host";
/// Client-facing path stashed alongside the authority partition above. The
/// proxy may replace `RequestContext::path` with a backend route rewrite before
/// `after_proxy`, so deferred invalidation must not read the then-current path.
const CACHE_PENDING_INVALIDATE_PATH_SUFFIX: &str = "cache_pending_invalidate_path";
/// Client-facing path observed at lookup, stashed for the storage side.
///
/// The base key binds `RequestContext::path` as it was during `before_proxy`,
/// and [`Self::stage_pending_invalidation`] stages the same client-facing value
/// for a later unsafe-method sweep. A route-dispatch rewrite
/// (`route_override_path`, set by `mesh_route_dispatch` / `request_transformer`
/// route overrides / `ai_stream_router`) is applied to `RequestContext::path`
/// *after* `before_proxy` returns, so reading the then-current path in
/// `on_final_response_body` would index the entry under the rewritten backend
/// path while invalidation looks it up under the client-facing one — RFC 9111
/// §4.4 invalidation would then silently match nothing.
///
/// [`Self::stage_pending_invalidation`]: ResponseCaching::stage_pending_invalidation
const CACHE_LOOKUP_PATH_SUFFIX: &str = "cache_lookup_path";

static CACHE_CLOCK_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
static NEXT_RESPONSE_CACHING_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn staging_metadata_key(instance_id: u64, suffix: &str) -> String {
    let mut key = String::with_capacity(METADATA_NAMESPACE_PREFIX.len() + 20 + 1 + suffix.len());
    key.push_str(METADATA_NAMESPACE_PREFIX);
    {
        use std::fmt::Write;
        let _ = write!(key, "{instance_id}");
    }
    key.push('.');
    key.push_str(suffix);
    key
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Credential/session headers that every cacheable response varies by.
///
/// The name and presence bit are always keyed; present values are SHA-256-hashed
/// by [`cache_key_vary_value`]. Keeping the names on anonymous retained
/// responses also prevents a cache HIT from presenting an unvaried anonymous
/// representation to a downstream shared cache.
/// Additional operator-configured or backend-supplied Vary headers are also
/// hashed when their header name matches the centralized log-redaction
/// sensitivity rules.
const SENSITIVE_VARY_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

/// Response fields that describe *this* hop rather than the representation and
/// must never survive into a shared-cache entry (RFC 9110 §7.6.1 connection
/// options, §11.7 proxy authentication). Retaining `Proxy-Authenticate` would
/// persist an intermediary's challenge and replay it to unrelated clients;
/// retaining `Transfer-Encoding` / `Connection` would replay framing the
/// buffered replay path does not use.
const NEVER_CACHED_RESPONSE_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Status codes a caller can steer a backend into emitting whose caching
/// semantics this plugin does not implement.
///
/// * `206 Partial Content` would need `Range` / `Content-Range` tracking,
///   strong-validator matching, completeness state, and per-request range
///   applicability (RFC 9111 §3.3, §3.4) before a stored partial could be
///   reused; without that, an attacker-selected byte range becomes the stored
///   representation for later unconditional full requests.
/// * `304 Not Modified` is validator metadata used to freshen an existing
///   stored representation (RFC 9111 §4.3.4), never a representation of its
///   own; storing one hands later callers an empty body under a `304` status.
/// * `1xx` are interim responses and never final.
///
/// These are rejected at configuration admission *and* refused again at store
/// time, so neither an operator config nor a backend can turn a validator-only
/// or partial payload into a reusable entry.
const UNSUPPORTED_CACHEABLE_STATUS_CODES: [u16; 2] = [206, 304];

fn is_supported_cacheable_status(status: u16) -> bool {
    status >= 200 && !UNSUPPORTED_CACHEABLE_STATUS_CODES.contains(&status)
}

/// Strip everything that must not be retained from the representation about to
/// be stored: connection-scoped and proxy-authentication fields, every field
/// nominated by this response's own `Connection` header, and every field the
/// origin qualified with `private="…"` / `no-cache="…"`.
///
/// The client-visible response for the miss that produced these bytes is
/// untouched — only the retained copy is narrowed, which is exactly the
/// RFC 9111 §5.2.2.4 / §5.2.2.7 requirement.
fn sanitize_cached_response_headers(
    headers: &mut HashMap<String, String>,
    directives: &CacheControlDirectives,
) {
    let mut connection_nominated: Vec<String> = Vec::new();
    if let Some(connection) = header_value(headers, "connection") {
        for token in connection.split(',') {
            let token = token.trim();
            if token.is_empty()
                || token.eq_ignore_ascii_case("close")
                || token.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            connection_nominated.push(token.to_ascii_lowercase());
        }
    }

    headers.retain(|name, _| {
        !NEVER_CACHED_RESPONSE_HEADERS
            .iter()
            .any(|hop_by_hop| name.eq_ignore_ascii_case(hop_by_hop))
            && !connection_nominated
                .iter()
                .any(|nominated| name.eq_ignore_ascii_case(nominated))
            && !directives
                .qualified_protected_fields()
                .any(|protected| name.eq_ignore_ascii_case(protected))
    });
}

/// Whether the request declares a body on the wire.
///
/// A shared cache selects a stored representation by method + target + Vary;
/// nothing in that selection witnesses a request body. This plugin looks up in
/// `before_proxy`, before `on_final_request_body`, so the exact backend-visible
/// bytes do not exist yet and a pre-transform digest would not describe what is
/// actually sent. Any declared body therefore bypasses lookup and storage
/// entirely (GHSA-w27g-65rf-h7xm).
fn request_declares_body(headers: &HashMap<String, String>) -> bool {
    if header_value(headers, "transfer-encoding").is_some() {
        return true;
    }
    let Some(content_length) = header_value(headers, "content-length") else {
        return false;
    };
    // Keep folded values on the fail-closed bypass path even when every member
    // is the same zero. This cache does not need to normalize request framing,
    // and a single authoritative field is the narrow proof its key exemption
    // is designed around.
    if content_length.contains(',') {
        return true;
    }
    // `parse::<u64>()` accepts a leading `+`, which is not valid HTTP
    // Content-Length syntax. Reuse the canonical 1*DIGIT parser so malformed,
    // overflowing, and non-zero values are never evidence of an empty body.
    !matches!(
        parse_content_length(content_length),
        ContentLength::Exact(0)
    )
}

fn is_auto_sensitive_vary_header(header: &str) -> bool {
    SENSITIVE_VARY_HEADERS
        .iter()
        .any(|sensitive| header.eq_ignore_ascii_case(sensitive))
}

fn should_hash_vary_header_value(header: &str) -> bool {
    is_auto_sensitive_vary_header(header)
        || super::utils::metadata_redaction::is_sensitive_metadata_key(header)
}

fn should_snapshot_header_value_as_cache_key_part(header: &str) -> bool {
    !header.eq_ignore_ascii_case("host") && should_hash_vary_header_value(header)
}

fn cache_key_vary_value(header: &str, value: &str) -> String {
    if should_hash_vary_header_value(header) {
        let digest = sha256_hex(value);
        let mut hashed = String::with_capacity(7 + digest.len());
        hashed.push_str("sha256-");
        hashed.push_str(&digest);
        hashed
    } else {
        value.to_string()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestHeaderSnapshotEntry {
    header: String,
    value: String,
    value_is_cache_key_part: bool,
}

struct RestoredRequestHeadersView {
    headers: HashMap<String, String>,
    cache_key_ready_headers: HashSet<String>,
}

fn merge_vary_header(vary_headers: &mut Vec<String>, header: &str) -> bool {
    if vary_headers.iter().any(|existing| existing == header) {
        return false;
    }
    vary_headers.push(header.to_string());
    true
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

/// Cache keys use `:` as a structural delimiter, but URL paths legitimately
/// contain `:` (e.g. `/users:1/details`, matrix params, FHIR `$everything`).
/// Encode path bytes into a cache-key-safe representation before joining so
/// path/query boundaries can be recovered unambiguously and invalidation
/// matches the full path rather than truncating at the first `:`.
///
/// The encoding must be bijective for raw URI paths. In particular, `%` must
/// be escaped before `:` so `/users:1/details` and `/users%3A1/details` remain
/// distinct cache keys.
fn encode_path_for_cache_key(path: &str) -> Cow<'_, str> {
    if !path.as_bytes().iter().any(|b| matches!(b, b'%' | b':')) {
        return Cow::Borrowed(path);
    }

    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'%' => encoded.push_str("%25"),
            b':' => encoded.push_str("%3A"),
            _ => encoded.push(char::from(byte)),
        }
    }
    Cow::Owned(encoded)
}

/// A cached response entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    stored_at: Duration,
    freshness_lifetime: Duration,
    corrected_initial_age: Duration,
    /// Byte length of the base-key prefix of this entry's full cache key.
    ///
    /// A full cache key is always its base key optionally followed by
    /// `:<vary dimensions>` (see [`ResponseCaching::build_cache_key`]), so
    /// `&key[..base_key_len]` recovers the base key without re-parsing the
    /// colon-delimited (and query-colon-bearing) structure.
    /// [`prune_vary_index_locked`] uses it to reclaim `vary_index` mappings
    /// whose base key has no surviving variant.
    ///
    /// [`prune_vary_index_locked`]: ResponseCaching::prune_vary_index_locked
    base_key_len: usize,
    /// Monotonic insertion sequence, paired with this entry's key in the FIFO
    /// eviction queue. A queued `(key, seq)` pair only evicts the entry that is
    /// still live under that exact sequence, so a replacement store can never
    /// be evicted by its predecessor's stale queue slot.
    insert_seq: u64,
    /// Authority partition (`proxy_id` + normalized Host) this entry is indexed
    /// under for RFC 9111 §4.4 invalidation.
    invalidation_scope: Arc<str>,
    /// Encoded client-facing path this entry is indexed under. Held so removal
    /// is an O(log n) index operation instead of a full-cache scan.
    invalidation_path: Arc<str>,
    /// Response-side runtime-overlay gate map this representation was produced
    /// under (`RequestContext::pin_response_policy_stamp`).
    ///
    /// A cached entry is a *finalized* client representation: the replay path
    /// deliberately skips presentation transforms so non-idempotent header /
    /// body rules cannot run twice. That contract is only sound while the
    /// stored bytes were produced by the same response-side policy that is
    /// live now. Runtime-overlay-gated rules (`response_transformer`'s
    /// `runtime_overlay_scope`) can be enabled or disabled without a config
    /// reload, so this stamp is the entry's provenance: a lookup whose pinned
    /// publication identity differs invalidates the entry and misses to the origin
    /// instead of replaying a representation from a superseded policy. It is
    /// opaque and carries no rule, header, or body content.
    response_policy_stamp: GatePolicyStamp,
    /// Effective static response-presentation policy digest of the plugin-cache
    /// generation that shaped this representation
    /// (`RequestContext::response_presentation_policy_digest`).
    ///
    /// The stamp above is published *after* `ProxyState::update_config`, so a
    /// request that pinned the previous plugin generation can still pin the new
    /// publication identity — its authenticate/authorize phase can span an
    /// entire mesh apply — and would otherwise store bytes shaped by the old
    /// policy under the new identity. Since GHSA-83rc-23c9-3g9x a transformer's
    /// effective RTDS gate is materialized into its configuration, so this
    /// generation-local digest covers the gate as well as the static rules and
    /// is the exact witness of what produced these bytes. `None` means this
    /// Unknown policy is never stored: every replay consumer must fail closed
    /// when the effective presentation policy cannot be established.
    response_presentation_digest: [u8; 32],
}

impl CacheEntry {
    fn current_age(&self, now: Duration) -> Duration {
        duration_saturating_add(
            self.corrected_initial_age,
            now.saturating_sub(self.stored_at),
        )
    }

    fn is_fresh_at(&self, now: Duration) -> bool {
        self.current_age(now) < self.freshness_lifetime
    }

    fn expires_at(&self) -> Duration {
        duration_saturating_add(
            self.stored_at,
            self.freshness_lifetime
                .saturating_sub(self.corrected_initial_age),
        )
    }

    /// Approximate memory footprint of this entry (for total size tracking).
    fn approx_size(&self) -> usize {
        self.body.len()
            + self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
            + self.invalidation_scope.len()
            + self.invalidation_path.len()
            + 96 // struct overhead estimate, including the policy digest
    }
}

/// Parsed Cache-Control directives relevant to proxy caching.
///
/// `private` and `no-cache` each have two RFC 9111 forms: the bare directive,
/// which covers the whole response, and the *qualified* form whose argument is
/// a quoted, comma-separated list of field names (`private="x-account"`).
/// Both forms are represented here — the bare flags refuse the response
/// outright, and the field lists name individual fields that must not survive
/// into a shared-cache entry (§5.2.2.4 / §5.2.2.7).
#[derive(Debug, Default, Clone)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    public: bool,
    must_revalidate: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    /// Lowercased field names carried by a qualified `private="…"` argument.
    private_fields: Vec<String>,
    /// Lowercased field names carried by a qualified `no-cache="…"` argument.
    no_cache_fields: Vec<String>,
}

impl CacheControlDirectives {
    /// Field names the origin refused to let a shared cache retain (qualified
    /// `private`) or reuse without successful revalidation (qualified
    /// `no-cache`). Ferrum revalidates only against its own stored validators,
    /// never the origin, so both are handled the same conservative way: the
    /// named fields are dropped before the representation is retained.
    fn qualified_protected_fields(&self) -> impl Iterator<Item = &str> {
        self.private_fields
            .iter()
            .chain(self.no_cache_fields.iter())
            .map(String::as_str)
    }

    /// A client `Cache-Control` request header asks to bypass the cache under
    /// either the bare or (non-standard, but observed) qualified `no-cache`
    /// spelling. Requests have no field-scoped semantics, so any occurrence
    /// bypasses.
    fn request_bypasses_cache(&self) -> bool {
        self.no_store || self.no_cache || !self.no_cache_fields.is_empty()
    }
}

/// Largest `delta-seconds` a recipient is required to represent (RFC 9111
/// §1.2.2). Values above it — including ones that overflow `u64` — are clamped
/// rather than discarded, so an absurd `max-age` cannot silently fall back to
/// the configured heuristic TTL.
const MAX_DELTA_SECONDS: u64 = 2_147_483_648;

/// The argument of one `Cache-Control` member, preserved with its grammar
/// shape so a qualified directive can be told apart from a malformed one.
enum CacheControlArgument<'a> {
    /// Bare token argument (`max-age=60`, or the malformed `private=x-a`).
    Token(&'a str),
    /// Quoted-string argument with quoted-pairs resolved.
    Quoted(Cow<'a, str>),
    /// Unterminated quoted string or non-OWS trailing junk — unusable and
    /// handled conservatively.
    Malformed,
}

/// Parse an RFC 9110 §5.6.4 quoted-string whose opening `"` sits at
/// `*position`, resolving quoted-pairs and leaving `*position` just past the
/// closing quote. Returns `None` for an unterminated string.
///
/// Scanning is byte-wise but only ever stops on the ASCII delimiters `"` and
/// `\`, so every slice boundary it takes is a UTF-8 character boundary; the
/// fallible slicing below keeps that an invariant rather than a panic.
fn parse_quoted_string<'a>(value: &'a str, position: &mut usize) -> Option<Cow<'a, str>> {
    let bytes = value.as_bytes();
    let mut index = position.checked_add(1)?;
    let mut segment_start = index;
    let mut unescaped: Option<String> = None;

    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => {
                let segment = value.get(segment_start..index)?;
                let parsed = match unescaped {
                    Some(mut owned) => {
                        owned.push_str(segment);
                        Cow::Owned(owned)
                    }
                    None => Cow::Borrowed(segment),
                };
                *position = index + 1;
                return Some(parsed);
            }
            b'\\' => {
                let escaped_start = index + 1;
                let escaped = value.get(escaped_start..)?.chars().next()?;
                let buffer = unescaped.get_or_insert_with(String::new);
                buffer.push_str(value.get(segment_start..index)?);
                buffer.push(escaped);
                index = escaped_start + escaped.len_utf8();
                segment_start = index;
            }
            _ => index += 1,
        }
    }

    None
}

/// Grammar-aware `Cache-Control` parser.
///
/// A naive `split(',')` cannot see qualified directives: it splits
/// `private="x-a, x-b"` in half and matches neither half against `private`,
/// so the origin's field protection is silently dropped. This walks members
/// with quoted-string awareness instead, so a comma inside a quoted argument
/// stays inside its member.
fn parse_cache_control(header_value: &str) -> CacheControlDirectives {
    let mut directives = CacheControlDirectives::default();
    let bytes = header_value.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        while matches!(bytes.get(index), Some(b',' | b' ' | b'\t')) {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let name_start = index;
        while !matches!(bytes.get(index), None | Some(b'=' | b',')) {
            index += 1;
        }
        let Some(name) = value_slice_trimmed(header_value, name_start, index) else {
            break;
        };

        let mut argument = None;
        if bytes.get(index) == Some(&b'=') {
            index += 1;
            while matches!(bytes.get(index), Some(b' ' | b'\t')) {
                index += 1;
            }
            if bytes.get(index) == Some(&b'"') {
                match parse_quoted_string(header_value, &mut index) {
                    Some(parsed) => {
                        // Only optional whitespace may follow a quoted-string
                        // before the member delimiter. Treat trailing junk as
                        // malformed instead of accepting a valid prefix such
                        // as `private="x-account"junk`.
                        while matches!(bytes.get(index), Some(b' ' | b'\t')) {
                            index += 1;
                        }
                        if matches!(bytes.get(index), None | Some(b',')) {
                            argument = Some(CacheControlArgument::Quoted(parsed));
                        } else {
                            argument = Some(CacheControlArgument::Malformed);
                        }
                    }
                    None => {
                        // Unterminated quote: the remainder of the header is
                        // uninterpretable, so stop after handling this member
                        // conservatively.
                        argument = Some(CacheControlArgument::Malformed);
                        index = bytes.len();
                    }
                }
            } else {
                let token_start = index;
                while !matches!(bytes.get(index), None | Some(b',')) {
                    index += 1;
                }
                argument = value_slice_trimmed(header_value, token_start, index)
                    .map(CacheControlArgument::Token);
            }
        }

        apply_cache_control_directive(&mut directives, name, argument.as_ref());

        // Discard any trailing junk between this member and the next comma.
        while !matches!(bytes.get(index), None | Some(b',')) {
            index += 1;
        }
    }

    directives
}

fn value_slice_trimmed(value: &str, start: usize, end: usize) -> Option<&str> {
    value.get(start..end).map(str::trim)
}

fn apply_cache_control_directive(
    directives: &mut CacheControlDirectives,
    name: &str,
    argument: Option<&CacheControlArgument<'_>>,
) {
    if name.eq_ignore_ascii_case("no-store") {
        directives.no_store = true;
    } else if name.eq_ignore_ascii_case("no-cache") {
        apply_qualified_directive(
            argument,
            &mut directives.no_cache,
            &mut directives.no_cache_fields,
        );
    } else if name.eq_ignore_ascii_case("private") {
        apply_qualified_directive(
            argument,
            &mut directives.private,
            &mut directives.private_fields,
        );
    } else if name.eq_ignore_ascii_case("public") {
        directives.public = true;
    } else if name.eq_ignore_ascii_case("must-revalidate") {
        directives.must_revalidate = true;
    } else if name.eq_ignore_ascii_case("s-maxage") {
        merge_delta_seconds(&mut directives.s_maxage, argument);
    } else if name.eq_ignore_ascii_case("max-age") {
        merge_delta_seconds(&mut directives.max_age, argument);
    }
}

/// Apply `private` / `no-cache` in either their bare or qualified form.
///
/// Fail closed: anything a shared cache cannot read as a well-formed quoted
/// field-name list — an unquoted argument, an unterminated quoted string, an
/// empty list, or a member that is not a valid field name — degrades to the
/// bare directive, which refuses the whole response. A duplicate bare
/// spelling alongside a qualified one therefore also wins regardless of order,
/// because the bare flag is checked before the field list is consulted.
fn apply_qualified_directive(
    argument: Option<&CacheControlArgument<'_>>,
    bare: &mut bool,
    fields: &mut Vec<String>,
) {
    match argument {
        None => *bare = true,
        Some(CacheControlArgument::Quoted(list)) => match parse_field_name_list(list) {
            Some(parsed) => fields.extend(parsed),
            None => *bare = true,
        },
        Some(CacheControlArgument::Token(_) | CacheControlArgument::Malformed) => *bare = true,
    }
}

/// Parse the quoted argument of a qualified directive into lowercased field
/// names. Returns `None` when the list is empty or holds a member that is not
/// a valid RFC 9110 field name, so the caller can fall back to the bare form.
fn parse_field_name_list(list: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    for member in list.split(',') {
        let member = member.trim();
        if member.is_empty() {
            continue;
        }
        HeaderName::from_bytes(member.as_bytes()).ok()?;
        fields.push(member.to_ascii_lowercase());
    }
    (!fields.is_empty()).then_some(fields)
}

fn merge_delta_seconds(slot: &mut Option<u64>, argument: Option<&CacheControlArgument<'_>>) {
    let raw = match argument {
        Some(CacheControlArgument::Token(token)) => *token,
        Some(CacheControlArgument::Quoted(value)) => &**value,
        Some(CacheControlArgument::Malformed) | None => return,
    };
    let Some(seconds) = parse_delta_seconds(raw) else {
        return;
    };
    // Conflicting duplicates are ambiguous; keep the most restrictive lifetime.
    *slot = Some(slot.map_or(seconds, |existing| existing.min(seconds)));
}

fn parse_delta_seconds(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        value
            .parse::<u64>()
            .unwrap_or(MAX_DELTA_SECONDS)
            .min(MAX_DELTA_SECONDS),
    )
}

fn duration_saturating_add(lhs: Duration, rhs: Duration) -> Duration {
    lhs.checked_add(rhs).unwrap_or(Duration::MAX)
}

fn duration_from_nanos_u128(nanos: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let secs = nanos / NANOS_PER_SECOND;
    if secs > u64::MAX as u128 {
        return Duration::MAX;
    }

    duration_saturating_add(
        Duration::from_secs(secs as u64),
        Duration::from_nanos((nanos % NANOS_PER_SECOND) as u64),
    )
}

fn duration_from_monotonic_nanos_str(value: &str) -> Option<Duration> {
    value
        .trim()
        .parse::<u128>()
        .ok()
        .map(duration_from_nanos_u128)
}

fn parse_age_header(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() || !value.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    match value.parse::<u64>() {
        Ok(seconds) => Some(Duration::from_secs(seconds)),
        Err(_) => Some(Duration::MAX),
    }
}

fn age_header_value(age: Duration) -> String {
    age.as_secs().to_string()
}

fn duration_since_http_date(now: DateTime<Utc>, date: DateTime<Utc>) -> Duration {
    now.signed_duration_since(date).to_std().unwrap_or_default()
}

/// Plugin configuration.
#[derive(Debug, Clone)]
struct ResponseCachingConfig {
    ttl_seconds: u64,
    max_entries: usize,
    max_entry_size_bytes: usize,
    max_total_size_bytes: usize,
    cacheable_methods: Vec<String>,
    cacheable_status_codes: Vec<u16>,
    respect_cache_control: bool,
    respect_no_cache: bool,
    vary_by_headers: Vec<String>,
    cache_key_include_query: bool,
    cache_key_include_consumer: bool,
    add_cache_status_header: bool,
    invalidate_on_unsafe_methods: bool,
    anonymous_caller_scope: AnonymousCallerScope,
}

impl ResponseCachingConfig {
    fn from_json(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "response_caching: config must be an object".to_string())?;
        reject_unknown_keys(
            object,
            "config",
            RESPONSE_CACHING_CONFIG_KEYS,
            "response_caching: ",
        )?;

        let cacheable_methods = parse_method_list(config, "cacheable_methods")?
            .unwrap_or_else(|| vec!["GET".to_string(), "HEAD".to_string()]);
        let cacheable_status_codes = parse_status_code_list(config, "cacheable_status_codes")?
            .unwrap_or_else(|| vec![200, 301, 404]);
        let vary_by_headers = parse_header_list(config, "vary_by_headers")?.unwrap_or_default();

        Ok(Self {
            ttl_seconds: optional_u64(config, "ttl_seconds")?.unwrap_or(DEFAULT_TTL_SECONDS),
            max_entries: optional_positive_usize(config, "max_entries")?
                .unwrap_or(DEFAULT_MAX_ENTRIES),
            max_entry_size_bytes: optional_positive_usize(config, "max_entry_size_bytes")?
                .unwrap_or(DEFAULT_MAX_ENTRY_SIZE_BYTES),
            max_total_size_bytes: optional_positive_usize(config, "max_total_size_bytes")?
                .unwrap_or(DEFAULT_MAX_TOTAL_SIZE_BYTES),
            cacheable_methods,
            cacheable_status_codes,
            respect_cache_control: optional_bool(config, "respect_cache_control")?.unwrap_or(true),
            respect_no_cache: optional_bool(config, "respect_no_cache")?.unwrap_or(true),
            vary_by_headers,
            cache_key_include_query: optional_bool(config, "cache_key_include_query")?
                .unwrap_or(true),
            cache_key_include_consumer: optional_bool(config, "cache_key_include_consumer")?
                .unwrap_or(false),
            add_cache_status_header: optional_bool(config, "add_cache_status_header")?
                .unwrap_or(true),
            invalidate_on_unsafe_methods: optional_bool(config, "invalidate_on_unsafe_methods")?
                .unwrap_or(true),
            anonymous_caller_scope: match optional_string(config, "anonymous_caller_scope")? {
                None => AnonymousCallerScope::default(),
                Some(value) => AnonymousCallerScope::parse("response_caching", value)?,
            },
        })
    }
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    match config.get(field) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("response_caching: '{field}' must be a boolean")),
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    match config.get(field) {
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("response_caching: '{field}' must be a string")),
    }
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    match config.get(field) {
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("response_caching: '{field}' must be an unsigned integer"))
            .map(Some),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "response_caching: '{field}' must be an unsigned integer"
        )),
    }
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_u64(config, field)? else {
        return Ok(None);
    };
    let value =
        usize::try_from(value).map_err(|_| format!("response_caching: '{field}' is too large"))?;
    if value == 0 {
        return Err(format!(
            "response_caching: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn parse_method_list(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("response_caching: '{field}' must be an array"));
    };
    if values.is_empty() {
        return Err(format!("response_caching: '{field}' must not be empty"));
    }

    let mut methods = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(method) = value.as_str() else {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be a string"
            ));
        };
        if method.is_empty() {
            return Err(format!(
                "response_caching: '{field}[{index}]' must not be empty"
            ));
        }
        Method::from_bytes(method.as_bytes()).map_err(|_| {
            format!("response_caching: '{field}[{index}]' is not a valid HTTP method")
        })?;
        let method = method.to_ascii_uppercase();
        // A shared cache selects a stored representation by method + target +
        // Vary. For a body-bearing method the request body is part of what the
        // origin answered, and this plugin looks up in `before_proxy` — before
        // the final backend-visible body exists. Keying a pre-transform body
        // (or no body at all) would let two POSTs with the same target and
        // different payloads share one entry, so body-bearing methods are
        // refused here and again at runtime.
        if !BODYLESS_CACHEABLE_METHODS.contains(&method.as_str()) {
            return Err(format!(
                "response_caching: '{field}[{index}]' ({method}) is not a bodyless retrieval \
                 method — a shared cache cannot key the exact backend-visible request body at \
                 lookup time, so only {} may be cached",
                BODYLESS_CACHEABLE_METHODS.join(" / ")
            ));
        }
        methods.push(method);
    }
    Ok(Some(methods))
}

fn parse_status_code_list(config: &Value, field: &'static str) -> Result<Option<Vec<u16>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("response_caching: '{field}' must be an array"));
    };
    if values.is_empty() {
        return Err(format!("response_caching: '{field}' must not be empty"));
    }

    let mut status_codes = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(code) = value.as_u64() else {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be an unsigned integer"
            ));
        };
        if !(100..=599).contains(&code) {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be an HTTP status code"
            ));
        }
        let code = code as u16;
        if !is_supported_cacheable_status(code) {
            return Err(format!(
                "response_caching: '{field}[{index}]' ({code}) has caching semantics this plugin \
                 does not implement and cannot be marked cacheable — 1xx responses are interim, \
                 206 requires range/validator/completeness tracking, and 304 is validator \
                 metadata for an existing stored representation rather than a representation"
            ));
        }
        status_codes.push(code);
    }
    Ok(Some(status_codes))
}

fn parse_header_list(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("response_caching: '{field}' must be an array"));
    };

    let mut headers = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(header) = value.as_str() else {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be a string"
            ));
        };
        if header.is_empty() {
            return Err(format!(
                "response_caching: '{field}[{index}]' must not be empty"
            ));
        }
        let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
            format!("response_caching: '{field}[{index}]' is not a valid HTTP header name")
        })?;
        headers.push(header_name.to_string());
    }
    Ok(Some(headers))
}

/// Bounded FIFO tracker of keys known to be uncacheable.
///
/// Prevents wasted cache lock acquisition for assets that were historically
/// uncacheable. Capacity is enforced with an insertion-ordered queue rather
/// than by cloning and sorting the whole map at capacity: request targets and
/// response eligibility are remotely influenced, so a caller able to mint
/// high-cardinality uncacheable keys could otherwise force a full clone + sort
/// on every admission (GHSA-37gg-v9m4-8445). Every operation here is O(1)
/// amortized.
struct UncacheablePredictor {
    /// Keys known to be uncacheable, mapped to the insertion sequence that owns
    /// the matching queue slot.
    keys: DashMap<String, u64>,
    /// Insertion order. A slot is authoritative only while its sequence still
    /// matches the live map entry, so re-marking a key simply supersedes its
    /// older slot instead of requiring a queue search.
    order: Mutex<VecDeque<(String, u64)>>,
    next_seq: AtomicU64,
    /// Maximum live entries before the oldest are evicted.
    max_entries: usize,
}

impl UncacheablePredictor {
    fn new(max_entries: usize, shard_amount: usize) -> Self {
        Self {
            keys: DashMap::with_capacity_and_shard_amount(max_entries / 4, shard_amount),
            order: Mutex::new(VecDeque::with_capacity(max_entries.min(1024))),
            next_seq: AtomicU64::new(1),
            max_entries,
        }
    }

    fn order_guard(&self) -> MutexGuard<'_, VecDeque<(String, u64)>> {
        self.order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns true if this key is predicted to be cacheable (not in the uncacheable set).
    fn is_predicted_cacheable(&self, key: &str) -> bool {
        !self.keys.contains_key(key)
    }

    /// Mark a key as uncacheable, evicting the oldest live entries when the
    /// bound is exceeded. Amortized O(1): at most one queue slot is appended
    /// per call, and each appended slot is popped at most once.
    fn mark_uncacheable(&self, key: &str) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.keys.insert(key.to_string(), seq);

        let mut order = self.order_guard();
        order.push_back((key.to_string(), seq));
        while self.keys.len() > self.max_entries {
            let Some((oldest_key, oldest_seq)) = order.pop_front() else {
                break;
            };
            self.keys
                .remove_if(&oldest_key, |_, live_seq| *live_seq == oldest_seq);
        }
        // Superseded slots accumulate only when the same key is re-marked.
        // Compact them in one amortized pass rather than searching on insert.
        if order.len() > self.max_entries.saturating_mul(4) {
            order.retain(|(queued_key, queued_seq)| {
                self.keys
                    .get(queued_key)
                    .is_some_and(|live_seq| *live_seq == *queued_seq)
            });
        }
    }

    /// Remove a key from the uncacheable set (it became cacheable). The stale
    /// queue slot is reclaimed by the next capacity pop or compaction.
    fn mark_cacheable(&self, key: &str) {
        self.keys.remove(key);
    }
}

/// Cache maintenance metadata protected by the single accounting mutex.
///
/// Everything here exists to keep admission, eviction, and invalidation bounded
/// while the mutex is held. The previous implementation cloned and sorted the
/// entire cache on every overflow and scanned the entire cache on every
/// qualifying unsafe-method request, so low-byte request churn could serialize
/// all concurrent writers behind superlinear maintenance
/// (GHSA-37gg-v9m4-8445).
#[derive(Default)]
struct CacheMaintenance {
    /// Insertion-ordered eviction queue. `stored_at` ordering and insertion
    /// ordering coincide, so FIFO reproduces the previous oldest-first policy
    /// without materializing or sorting the key set.
    eviction_queue: VecDeque<(String, u64)>,
    /// Expiration-ordered live-entry index. Freshness lifetime can vary per
    /// response, so insertion order cannot identify every expired entry: a
    /// short-lived response may expire behind an older long-lived one. Exact
    /// tuples are removed on replacement and eviction, keeping reclamation
    /// bounded to expired entries with O(log n) maintenance and no full-cache
    /// scan under the publication mutex.
    expiry_index: BTreeSet<(Duration, u64, String)>,
    /// `authority scope -> encoded path -> cache keys`. RFC 9111 §4.4
    /// invalidation is an exact `BTreeMap` lookup plus one ordered range over
    /// the `path/` descendants, so its cost is bounded by the number of entries
    /// it actually removes rather than by cache size.
    path_index: HashMap<Arc<str>, BTreeMap<Arc<str>, HashSet<String>>>,
    /// Live variant state per base key. `vary_index` mappings are reclaimed
    /// exactly when their last variant leaves, replacing the previous
    /// heuristic full-cache prune sweep, and the recorded index location makes
    /// base-key invalidation a direct bucket lookup instead of a scan.
    variant_counts: HashMap<String, BaseKeyVariants>,
    next_insert_seq: u64,
}

/// Live-variant bookkeeping for one base key.
///
/// Every variant of a base key shares its authority scope and path by
/// construction — both are inputs to the base key itself — so one recorded
/// location locates all of them.
struct BaseKeyVariants {
    count: usize,
    scope: Arc<str>,
    path: Arc<str>,
}

impl CacheMaintenance {
    fn next_seq(&mut self) -> u64 {
        self.next_insert_seq = self.next_insert_seq.wrapping_add(1);
        self.next_insert_seq
    }
}

pub struct ResponseCaching {
    /// Process-unique ownership key for request-private staging metadata.
    /// Fresh on every constructor call so reload generations and sibling
    /// instances never share `RequestContext.metadata` slots.
    instance_id: u64,
    /// Precomputed `response_caching.<id>.cache_base_key` (hot-path insert/get).
    meta_base_key: String,
    /// Precomputed `response_caching.<id>.cache_status`.
    meta_status: String,
    /// Precomputed `response_caching.<id>.cache_predict_key`.
    meta_predict_key: String,
    /// Precomputed `response_caching.<id>.cache_request_started_monotonic_nanos`.
    meta_request_started: String,
    /// Precomputed `response_caching.<id>.cache_request_headers_snapshot`.
    meta_headers_snapshot: String,
    /// Precomputed `response_caching.<id>.cache_pending_invalidate_host`.
    meta_pending_invalidate_host: String,
    /// Precomputed `response_caching.<id>.cache_pending_invalidate_path`.
    meta_pending_invalidate_path: String,
    /// Precomputed `response_caching.<id>.cache_lookup_path`.
    meta_lookup_path: String,
    /// Parsed configuration, including how anonymous callers are partitioned
    /// (`config.anonymous_caller_scope`, see [`AnonymousCallerScope`]). The
    /// scope is deliberately *not* mirrored onto a second field: one owner
    /// means a later edit cannot leave the two copies disagreeing about the
    /// partition contract.
    config: ResponseCachingConfig,
    cache: Arc<DashMap<String, CacheEntry>>,
    vary_index: Arc<DashMap<String, Vec<String>>>,
    total_size: Arc<AtomicUsize>,
    /// Single publication mutex. Holds the bounded maintenance metadata so
    /// admission, eviction, and invalidation never take a second lock and never
    /// perform an unbounded pass while it is held.
    accounting_lock: Arc<Mutex<CacheMaintenance>>,
    clock_offset_nanos: Arc<AtomicU64>,
    uncacheable_predictor: UncacheablePredictor,
    /// Effective shard count used for `cache`, `vary_index`, and the
    /// uncacheable predictor. Retained so tests can prove construction
    /// honored the gateway's configured `FERRUM_POOL_SHARD_AMOUNT`.
    shard_amount: usize,
}

impl ResponseCaching {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(config: &Value) -> Result<Self, String> {
        // Convenience constructor for tests/support tooling: `0` auto-derives
        // the shard amount from host topology. Production construction goes
        // through the plugin factory, which passes the gateway's normalized
        // `FERRUM_POOL_SHARD_AMOUNT` to `new_with_pool_shard_amount`.
        Self::new_with_pool_shard_amount(config, 0)
    }

    /// Construct the plugin with an explicit pool shard amount.
    ///
    /// `pool_shard_amount` follows the `FERRUM_POOL_SHARD_AMOUNT` contract:
    /// `0` auto-derives from host topology and any positive value is rounded
    /// up to a power of two (idempotent for already-normalized values such as
    /// [`PluginHttpClient::pool_shard_amount`]). All three hot-path maps
    /// (`cache`, `vary_index`, uncacheable predictor) use the resolved count.
    ///
    /// [`PluginHttpClient::pool_shard_amount`]: super::utils::http_client::PluginHttpClient::pool_shard_amount
    pub fn new_with_pool_shard_amount(
        config: &Value,
        pool_shard_amount: usize,
    ) -> Result<Self, String> {
        let config = ResponseCachingConfig::from_json(config)?;

        if config.cacheable_methods.is_empty() {
            return Err(
                "response_caching: no cacheable_methods configured — plugin will cache nothing"
                    .to_string(),
            );
        }

        let shard_amount = crate::util::sharding::pool_shard_amount(pool_shard_amount);
        let instance_id = NEXT_RESPONSE_CACHING_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        let predictor_size = config.max_entries / 10; // 10% of cache size
        Ok(Self {
            instance_id,
            meta_base_key: staging_metadata_key(instance_id, CACHE_BASE_KEY_SUFFIX),
            meta_status: staging_metadata_key(instance_id, CACHE_STATUS_SUFFIX),
            meta_predict_key: staging_metadata_key(instance_id, CACHE_PREDICT_KEY_SUFFIX),
            meta_request_started: staging_metadata_key(
                instance_id,
                CACHE_REQUEST_STARTED_MONOTONIC_NANOS_SUFFIX,
            ),
            meta_headers_snapshot: staging_metadata_key(
                instance_id,
                CACHE_REQUEST_HEADERS_SNAPSHOT_SUFFIX,
            ),
            meta_pending_invalidate_host: staging_metadata_key(
                instance_id,
                CACHE_PENDING_INVALIDATE_HOST_SUFFIX,
            ),
            meta_pending_invalidate_path: staging_metadata_key(
                instance_id,
                CACHE_PENDING_INVALIDATE_PATH_SUFFIX,
            ),
            meta_lookup_path: staging_metadata_key(instance_id, CACHE_LOOKUP_PATH_SUFFIX),
            config,
            cache: Arc::new(DashMap::with_shard_amount(shard_amount)),
            vary_index: Arc::new(DashMap::with_shard_amount(shard_amount)),
            total_size: Arc::new(AtomicUsize::new(0)),
            accounting_lock: Arc::new(Mutex::new(CacheMaintenance::default())),
            clock_offset_nanos: Arc::new(AtomicU64::new(0)),
            uncacheable_predictor: UncacheablePredictor::new(predictor_size.max(100), shard_amount),
            shard_amount,
        })
    }

    /// Effective shard count this instance's hot-path maps were built with.
    ///
    /// Routed through `_test_support` so external tests can assert the
    /// configured `FERRUM_POOL_SHARD_AMOUNT` reached every map.
    #[allow(dead_code)]
    pub(crate) fn shard_amount_for_tests(&self) -> usize {
        self.shard_amount
    }

    /// Process-unique staging namespace for this instance (tests / diagnostics).
    #[allow(dead_code)]
    pub(crate) fn instance_id_for_tests(&self) -> u64 {
        self.instance_id
    }

    /// Namespaced metadata key for `suffix` under this instance's staging
    /// namespace (tests assert isolation without hard-coding id digits).
    #[allow(dead_code)]
    pub(crate) fn staging_metadata_key_for_tests(&self, suffix: &str) -> String {
        staging_metadata_key(self.instance_id, suffix)
    }

    fn set_cache_status(&self, ctx: &mut RequestContext, status: &str) {
        ctx.metadata
            .insert(self.meta_status.clone(), status.to_string());
        if matches!(status, "HIT" | "REVALIDATED") {
            ctx.mark_response_cache_hit();
        }
    }

    fn cache_status<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        ctx.metadata.get(&self.meta_status).map(String::as_str)
    }

    /// Drop this instance's lookup/store staging inputs without touching
    /// sibling instances' namespaced keys. Used on method/SSE bypass and
    /// HIT/REVALIDATED so leftover base/snapshot/predict/timing from an
    /// earlier phase of this instance cannot leak into a later final hook.
    /// Pending unsafe-method invalidation host is intentionally retained
    /// unless [`Self::clear_pending_invalidation`] is also called.
    fn clear_lookup_staging(&self, ctx: &mut RequestContext) {
        ctx.metadata.remove(&self.meta_base_key);
        ctx.metadata.remove(&self.meta_predict_key);
        ctx.metadata.remove(&self.meta_request_started);
        ctx.metadata.remove(&self.meta_headers_snapshot);
        ctx.metadata.remove(&self.meta_lookup_path);
        ctx.clear_response_cache_request_header_delta(self.instance_id);
    }

    /// Drop a staged unsafe-method invalidation without applying it.
    ///
    /// Used when a cache HIT/REVALIDATED short-circuits before origin contact:
    /// serving a stored representation must not flush peer path variants.
    fn clear_pending_invalidation(&self, ctx: &mut RequestContext) {
        ctx.metadata.remove(&self.meta_pending_invalidate_host);
        ctx.metadata.remove(&self.meta_pending_invalidate_path);
    }

    fn accounting_guard(&self) -> MutexGuard<'_, CacheMaintenance> {
        self.accounting_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Current value of the running cache-size accountant.
    ///
    /// Exposed for tests so they can assert the size accounting never
    /// underflow-wraps under concurrent stores/invalidations (finding #62).
    #[allow(dead_code)]
    pub(crate) fn current_total_size_for_tests(&self) -> usize {
        self.total_size.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub(crate) fn size_accounting_snapshot_for_tests(&self) -> (usize, usize) {
        let _guard = self.accounting_guard();
        (
            self.total_size.load(Ordering::Relaxed),
            self.actual_total_size_locked(),
        )
    }

    #[allow(dead_code)]
    pub(crate) fn vary_index_snapshot_for_tests(&self) -> Vec<(String, Vec<String>)> {
        let _guard = self.accounting_guard();
        self.vary_index
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn cache_keys_for_tests(&self) -> Vec<String> {
        let _guard = self.accounting_guard();
        self.cache.iter().map(|entry| entry.key().clone()).collect()
    }

    fn actual_total_size_locked(&self) -> usize {
        self.cache
            .iter()
            .map(|entry| entry.value().approx_size())
            .sum()
    }

    fn add_total_size_locked(&self, n: usize) {
        if n == 0 {
            return;
        }
        let current = self.total_size.load(Ordering::Relaxed);
        self.total_size
            .store(current.saturating_add(n), Ordering::Relaxed);
    }

    fn sub_total_size_locked(&self, n: usize) {
        if n == 0 {
            return;
        }
        let current = self.total_size.load(Ordering::Relaxed);
        self.total_size
            .store(current.saturating_sub(n), Ordering::Relaxed);
    }

    /// Advance this plugin instance's clock without sleeping.
    ///
    /// Routed through `_test_support` so external tests can validate cache
    /// freshness and Age arithmetic deterministically without pausing the runtime.
    #[allow(dead_code)]
    pub(crate) fn advance_clock_for_tests(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let _ =
            self.clock_offset_nanos
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(nanos))
                });
    }

    fn clock_offset(&self) -> Duration {
        duration_from_nanos_u128(self.clock_offset_nanos.load(Ordering::Relaxed) as u128)
    }

    fn now_monotonic(&self) -> Duration {
        duration_saturating_add(CACHE_CLOCK_EPOCH.elapsed(), self.clock_offset())
    }

    fn now_wall(&self) -> DateTime<Utc> {
        match chrono::Duration::from_std(self.clock_offset()) {
            Ok(offset) => Utc::now() + offset,
            Err(_) => Utc::now(),
        }
    }

    /// Build the base cache key: a canonical, length-framed digest over every
    /// stable backend-visible dimension of this request.
    ///
    /// The partition is:
    ///
    /// * **effective destination** — proxy id/namespace, listen path, and the
    ///   post-routing upstream (or direct host/port/scheme) plus authority and
    ///   rewritten path. `response_caching` runs at
    ///   [`super::priority::RESPONSE_CACHING`], after every route-dispatch
    ///   plugin, so this is the destination that will actually serve a miss;
    /// * **request context** — original authority, `Host`, method, path, the
    ///   *effective outbound* query, so a `request_transformer` query rewrite
    ///   that ran before this plugin is part of the partition. The request
    ///   header dimension binds every backend-visible header except the
    ///   entry-operation headers whose semantics this plugin actually
    ///   implements (`If-None-Match` / `If-Modified-Since` revalidation,
    ///   pure honored bare request `Cache-Control: no-cache` / `no-store`
    ///   refreshes when `respect_no_cache` is enabled, and zero-length
    ///   `Content-Length` framing). This prevents replay across unannounced
    ///   tenant or policy headers even when an origin omits `Vary`. Unsupported
    ///   precondition / range / pragma dimensions and mixed / arbitrary
    ///   `Cache-Control` content remain bound. The complete `Vary` tuple is
    ///   additionally appended by [`Self::extend_base_key_with_vary`].
    ///
    ///   Supported entry-operation headers are excluded so revalidation,
    ///   pure no-cache/no-store replacement, and zero-length framing can still
    ///   address the stored entry. Unimplemented
    ///   precondition and pragma headers are *not* treated as operations: a
    ///   fresh HIT must not ignore a client `If-Match` /
    ///   `If-Unmodified-Since` / `If-Range` / `Range` / `Pragma` the plugin
    ///   does not gate. `Cache-Control` exclusion is value-aware and gated by
    ///   `respect_no_cache` — only a header whose every meaningful member is a
    ///   bare, argument-free refresh this plugin honors is omitted; mixed
    ///   recognized refresh plus any other member, argument-bearing refreshes,
    ///   and any `Cache-Control` when `respect_no_cache` is false stay in the
    ///   partition as backend-visible policy;
    /// * **complete `Vary` tuple** — appended to this base key by
    ///   [`Self::extend_base_key_with_vary`];
    /// * **caller authorization context** — see
    ///   [`replay_partition::append_caller_partition`]. Authenticated callers
    ///   bind a fingerprint of the credential material and mechanism, not a
    ///   display subject, so two tokens resolving to one `sub` with different
    ///   scopes cannot share an entry. Both the pristine inbound wire
    ///   credentials and the live backend-visible ones are bound under separate
    ///   provenance labels, so an earlier `ai_stream_router` credential rewrite
    ///   cannot erase the original caller distinction. Every caller also binds
    ///   its canonical peer address, which the origin observes through Ferrum's
    ///   regenerated `X-Forwarded-For`; only an *anonymous* caller's address
    ///   binding can be relaxed by operator attestation.
    ///
    /// Returns `Err` when no complete stable partition can be derived, in
    /// which case the caller must neither look up nor store. The refusal's
    /// `reason()` is a compiled-in static string safe to emit in a debug line.
    ///
    /// `request_headers` is supplied separately because in `before_proxy` the
    /// gateway may have temporarily moved `ctx.headers` out of the context to
    /// satisfy the borrow checker (zero-allocation hot path when no plugin
    /// modifies headers). Always pass the same `headers` map you got from the
    /// `before_proxy(ctx, headers)` parameter, or the restored view from
    /// post-proxy phases.
    ///
    /// The key is an opaque digest and carries no host, path, query, credential,
    /// identity, or address bytes.
    fn build_base_cache_key(
        &self,
        ctx: &RequestContext,
        request_headers: &HashMap<String, String>,
    ) -> Result<String, replay_partition::PartitionRefusal> {
        let mut hasher = PartitionHasher::new(RESPONSE_CACHING_BASE_KEY_DOMAIN);
        replay_partition::append_destination_partition(&mut hasher, ctx);

        // This legacy option no longer permits an origin-visible query to be
        // omitted from a replay key. Keep the setting in the digest so changing
        // it still rotates the keyspace, then bind the effective request target
        // unconditionally below.
        hasher.bool_value("include_query", self.config.cache_key_include_query);
        // `cache_key_include_consumer` no longer decides whether callers are
        // isolated — the caller partition below is unconditional. It is kept in
        // the digest so flipping it still produces a disjoint keyspace rather
        // than silently reusing entries minted under the other setting.
        hasher.bool_value("include_consumer", self.config.cache_key_include_consumer);
        replay_partition::append_response_cache_request_partition(
            &mut hasher,
            ctx,
            request_headers,
            self.config.respect_no_cache,
        );
        replay_partition::append_caller_partition(
            &mut hasher,
            ctx,
            request_headers,
            self.config.anonymous_caller_scope,
        )?;

        Ok(hasher.hex())
    }

    /// Append the Vary component to an already-derived base key.
    ///
    /// The complete Vary tuple is digested — every configured, auto-merged, and
    /// origin-nominated dimension, with its name, a framed presence flag, and
    /// its value — rather than only the subset classified as sensitive. The old
    /// `name=value|name=value` concatenation let a legal value containing `|`
    /// or `=` reproduce a different tuple's preimage
    /// (GHSA-v4g3-2r4f-f6pc); length framing makes that impossible.
    ///
    /// Values already reduced to their cache-key form by the request-header
    /// snapshot are framed verbatim so lookup and storage agree; every other
    /// value goes through [`cache_key_vary_value`] first, which keeps
    /// credentials and operator-redacted values out of memory in their raw form
    /// even before the outer digest.
    fn extend_base_key_with_vary(
        &self,
        base_key: String,
        vary_headers: &[String],
        request_headers: &HashMap<String, String>,
        cache_key_ready_headers: Option<&HashSet<String>>,
    ) -> String {
        if vary_headers.is_empty() {
            return base_key;
        }

        let mut hasher = PartitionHasher::new(RESPONSE_CACHING_VARY_DOMAIN);
        hasher.count("vary", vary_headers.len());
        for header in vary_headers {
            hasher.text("vary_name", header);
            match request_headers.get(header.as_str()) {
                None => hasher.bool_value("vary_present", false),
                Some(value) => {
                    hasher.bool_value("vary_present", true);
                    let ready = cache_key_ready_headers
                        .is_some_and(|ready_headers| ready_headers.contains(header));
                    if ready {
                        hasher.text("vary_value", value);
                    } else {
                        hasher.text("vary_value", &cache_key_vary_value(header, value));
                    }
                }
            }
        }

        let vary_digest = hasher.hex();
        let mut cache_key = base_key;
        cache_key.reserve(1 + vary_digest.len());
        cache_key.push(CACHE_KEY_VARY_SEPARATOR);
        cache_key.push_str(&vary_digest);
        cache_key
    }

    /// Authority partition an entry is indexed under for RFC 9111 §4.4
    /// invalidation: the same `(proxy id, normalized Host)` pair the base key
    /// binds, reduced to an opaque digest so no host bytes are retained.
    fn invalidation_scope(&self, ctx: &RequestContext, host: Option<&str>) -> Arc<str> {
        let mut hasher = PartitionHasher::new(RESPONSE_CACHING_SCOPE_DOMAIN);
        hasher.optional_text(
            "proxy_id",
            ctx.matched_proxy.as_ref().map(|proxy| proxy.id.as_str()),
        );
        hasher.optional_text(
            "host",
            host.map(|host| host.to_ascii_lowercase()).as_deref(),
        );
        Arc::from(hasher.hex().as_str())
    }

    /// Check if the request method is cacheable.
    fn is_cacheable_method(&self, method: &str) -> bool {
        self.config.cacheable_methods.iter().any(|m| m == method)
    }

    /// Check if the request method has unsafe (state-changing) semantics.
    ///
    /// RFC 9110 §9.2.1 safe methods (GET/HEAD/OPTIONS/TRACE) never invalidate
    /// cached entries, even when absent from `cacheable_methods` — being
    /// ineligible for storage is not the same as changing server state. Every
    /// other method (POST/PUT/PATCH/DELETE, and any extension/custom method)
    /// is treated as unsafe. Unknown methods fail closed: their semantics are
    /// unknown to the gateway, so `invalidate_on_unsafe_methods` applies after
    /// a non-error response (RFC 9111 §4.4).
    fn is_unsafe_method(method: &str) -> bool {
        !matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
    }

    /// RFC 9110 / RFC 9111: final status codes below 400 are non-error.
    ///
    /// Mandatory cache invalidation for unsafe methods is tied to receiving a
    /// non-error response, not merely forwarding the request.
    fn is_non_error_status(status: u16) -> bool {
        status < 400
    }

    fn cache_lookup_vary_headers(&self, base_key: &str) -> Vec<String> {
        self.vary_index
            .get(base_key)
            .map(|headers| headers.clone())
            .unwrap_or_else(|| self.config.vary_by_headers.clone())
    }

    fn merge_mandatory_sensitive_vary_headers(&self, vary_headers: &mut Vec<String>) -> bool {
        let mut added = false;
        for sensitive in SENSITIVE_VARY_HEADERS {
            added |= merge_vary_header(vary_headers, sensitive);
        }
        if added {
            vary_headers.sort();
        }
        added
    }

    fn merge_existing_vary_headers(&self, base_key: &str, vary_headers: &mut Vec<String>) -> bool {
        let Some(existing_headers) = self.vary_index.get(base_key).map(|headers| headers.clone())
        else {
            return false;
        };

        let mut added = false;
        for header in existing_headers {
            added |= merge_vary_header(vary_headers, &header);
        }
        if added {
            vary_headers.sort();
        }
        added
    }

    fn merged_vary_headers(
        &self,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        let mut vary_headers = self.config.vary_by_headers.clone();

        if let Some(vary) = response_headers.get("vary") {
            for header in vary.split(',') {
                let header = header.trim().to_ascii_lowercase();
                if header.is_empty() {
                    continue;
                }
                if header == "*" {
                    return None;
                }
                if !vary_headers.iter().any(|existing| existing == &header) {
                    vary_headers.push(header);
                }
            }
        }

        vary_headers.sort();
        Some(vary_headers)
    }

    fn is_fresh_conditional_hit(
        &self,
        request_headers: &HashMap<String, String>,
        entry: &CacheEntry,
    ) -> bool {
        if let Some(if_none_match) = request_headers.get("if-none-match") {
            return entry
                .headers
                .get("etag")
                .is_some_and(|etag| if_none_match_matches(if_none_match, etag));
        }

        if let Some(if_modified_since) = request_headers.get("if-modified-since") {
            return entry
                .headers
                .get("last-modified")
                .and_then(|last_modified| parse_http_date(last_modified))
                .zip(parse_http_date(if_modified_since))
                .is_some_and(|(last_modified, if_modified_since)| {
                    last_modified <= if_modified_since
                });
        }

        false
    }

    fn not_modified_headers(
        &self,
        entry: &CacheEntry,
        current_age: Duration,
    ) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for key in [
            "cache-control",
            "content-location",
            "date",
            "etag",
            "expires",
            "last-modified",
            "vary",
        ] {
            if let Some(value) = entry.headers.get(key) {
                headers.insert(key.to_string(), value.clone());
            }
        }

        self.add_age_header(&mut headers, current_age);
        if self.config.add_cache_status_header {
            headers.insert("x-cache-status".to_string(), "REVALIDATED".to_string());
        }

        headers
    }

    fn invalidate_base_key(&self, base_key: &str) {
        let mut guard = self.accounting_guard();
        self.invalidate_base_key_locked(&mut guard, base_key);
    }

    /// Remove every live variant of one base key.
    ///
    /// The recorded [`BaseKeyVariants`] location narrows the search to one
    /// `(authority scope, path)` bucket — every variant of a base key shares
    /// both by construction — instead of the previous scan over every entry in
    /// the map looking for a `base_key:` string prefix. The bucket can still
    /// hold sibling base keys (other callers at the same authority and path),
    /// so the cost is bounded by that bucket rather than by this base key's
    /// variant count; the per-item work is one prefix comparison.
    fn invalidate_base_key_locked(&self, maintenance: &mut CacheMaintenance, base_key: &str) {
        let doomed: Vec<String> = match maintenance.variant_counts.get(base_key) {
            Some(state) => maintenance
                .path_index
                .get(&state.scope)
                .and_then(|paths| paths.get(&state.path))
                .map(|keys| {
                    keys.iter()
                        .filter(|key| Self::cache_key_belongs_to_base(key.as_str(), base_key))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            None => Vec::new(),
        };
        for cache_key in doomed {
            self.remove_entry_locked(maintenance, &cache_key);
        }
        // Reclaim the dimension mapping even when no variant survived.
        maintenance.variant_counts.remove(base_key);
        self.vary_index.remove(base_key);
    }

    /// A full cache key is its base key, optionally followed by the fixed
    /// separator and a Vary digest. Both components are lowercase hex, so this
    /// test cannot be spoofed by key content.
    fn cache_key_belongs_to_base(cache_key: &str, base_key: &str) -> bool {
        cache_key == base_key
            || (cache_key.len() > base_key.len()
                && cache_key.starts_with(base_key)
                && cache_key.as_bytes().get(base_key.len())
                    == Some(&(CACHE_KEY_VARY_SEPARATOR as u8)))
    }

    fn invalidate_cache_key(&self, base_key: &str, cache_key: &str) {
        let mut guard = self.accounting_guard();
        self.invalidate_cache_key_locked(&mut guard, base_key, cache_key);
    }

    fn invalidate_cache_key_locked(
        &self,
        maintenance: &mut CacheMaintenance,
        base_key: &str,
        cache_key: &str,
    ) {
        if !self.remove_entry_locked(maintenance, cache_key) {
            return;
        }
        if cache_key == base_key && !maintenance.variant_counts.contains_key(base_key) {
            self.vary_index.remove(base_key);
        }
    }

    /// Admit one entry, keeping byte accounting, the eviction queue, the path
    /// index, and the per-base-key variant state exactly in step.
    ///
    /// Replacement of an existing key is not a new variant: the index and the
    /// variant state already describe it, and only the byte delta and a fresh
    /// eviction slot change. All work is O(1) plus one `BTreeMap` insert and
    /// one expiration-index `BTreeSet` update.
    fn insert_entry_locked(
        &self,
        maintenance: &mut CacheMaintenance,
        base_key: &str,
        cache_key: String,
        entry: CacheEntry,
    ) {
        let scope = Arc::clone(&entry.invalidation_scope);
        let path = Arc::clone(&entry.invalidation_path);
        let insert_seq = entry.insert_seq;
        let expires_at = entry.expires_at();
        let entry_size = entry.approx_size();

        match self.cache.insert(cache_key.clone(), entry) {
            Some(old) => {
                self.sub_total_size_locked(old.approx_size());
                maintenance.expiry_index.remove(&(
                    old.expires_at(),
                    old.insert_seq,
                    cache_key.clone(),
                ));
            }
            None => {
                maintenance
                    .variant_counts
                    .entry(base_key.to_string())
                    .and_modify(|state| state.count = state.count.saturating_add(1))
                    .or_insert_with(|| BaseKeyVariants {
                        count: 1,
                        scope: Arc::clone(&scope),
                        path: Arc::clone(&path),
                    });
                maintenance
                    .path_index
                    .entry(scope)
                    .or_default()
                    .entry(path)
                    .or_default()
                    .insert(cache_key.clone());
            }
        }
        self.add_total_size_locked(entry_size);
        maintenance
            .expiry_index
            .insert((expires_at, insert_seq, cache_key.clone()));
        maintenance
            .eviction_queue
            .push_back((cache_key, insert_seq));
    }

    /// Remove one entry and every piece of metadata that described it.
    /// Returns whether an entry was actually removed. O(1) plus ordered path-
    /// and expiration-index removals.
    fn remove_entry_locked(&self, maintenance: &mut CacheMaintenance, cache_key: &str) -> bool {
        let Some((_, entry)) = self.cache.remove(cache_key) else {
            return false;
        };
        self.sub_total_size_locked(entry.approx_size());
        maintenance.expiry_index.remove(&(
            entry.expires_at(),
            entry.insert_seq,
            cache_key.to_string(),
        ));

        // `base_key_len` is always a byte boundary of this key: the key is the
        // base-key hex, optionally followed by an ASCII separator and more hex.
        let base_key = cache_key
            .get(..entry.base_key_len)
            .unwrap_or(cache_key)
            .to_string();
        if let Some(state) = maintenance.variant_counts.get_mut(&base_key) {
            state.count = state.count.saturating_sub(1);
            if state.count == 0 {
                maintenance.variant_counts.remove(&base_key);
                // Exact reclamation: the dimension mapping outlives its last
                // variant by exactly zero requests, so a high-cardinality
                // principal stream cannot grow `vary_index` unboundedly and no
                // heuristic full-cache sweep is required.
                self.vary_index.remove(&base_key);
            }
        }

        if let Some(paths) = maintenance.path_index.get_mut(&entry.invalidation_scope) {
            if let Some(keys) = paths.get_mut(&entry.invalidation_path) {
                keys.remove(cache_key);
                if keys.is_empty() {
                    paths.remove(&entry.invalidation_path);
                }
            }
            if paths.is_empty() {
                maintenance.path_index.remove(&entry.invalidation_scope);
            }
        }
        true
    }

    fn invalidate_zero_freshness_response(
        &self,
        base_key: &str,
        predict_key: Option<&str>,
        response_headers: &HashMap<String, String>,
        lookup_headers: &RestoredRequestHeadersView,
    ) {
        if let Some(predict_key) = predict_key {
            self.invalidate_cache_key(base_key, predict_key);
        }

        match self.merged_vary_headers(response_headers) {
            Some(mut vary_headers) => {
                self.merge_existing_vary_headers(base_key, &mut vary_headers);
                self.merge_mandatory_sensitive_vary_headers(&mut vary_headers);
                let response_key = self.extend_base_key_with_vary(
                    base_key.to_string(),
                    &vary_headers,
                    &lookup_headers.headers,
                    Some(&lookup_headers.cache_key_ready_headers),
                );
                if predict_key != Some(response_key.as_str()) {
                    self.invalidate_cache_key(base_key, &response_key);
                }
            }
            None => self.invalidate_base_key(base_key),
        }
    }

    fn mark_uncacheable_if_no_cached_entry(&self, predict_key: Option<&str>) {
        let Some(predict_key) = predict_key else {
            return;
        };
        if !self.cache.contains_key(predict_key) {
            self.uncacheable_predictor.mark_uncacheable(predict_key);
        }
    }

    /// Enforce the entry-count cap with amortized O(1) work per admitted entry.
    ///
    /// The previous implementation cloned every key + timestamp, sorted the
    /// whole vector, and removed only the single-entry overflow — a full sort
    /// per insertion at a saturated default 10,000-entry cache, performed while
    /// holding the publication mutex, which any caller able to mint unique
    /// cacheable targets could drive continuously (GHSA-37gg-v9m4-8445).
    /// Insertion order and `stored_at` order coincide, so popping the FIFO
    /// reproduces the same oldest-first policy without materializing the key
    /// set.
    fn evict_if_needed_locked(&self, maintenance: &mut CacheMaintenance) {
        while self.cache.len() > self.config.max_entries {
            let Some((oldest_key, oldest_seq)) = maintenance.eviction_queue.pop_front() else {
                break;
            };
            // A slot is authoritative only while it still names the live entry;
            // a replaced entry's older slot is dropped here for free.
            let is_current = self
                .cache
                .get(&oldest_key)
                .is_some_and(|entry| entry.insert_seq == oldest_seq);
            if is_current {
                self.remove_entry_locked(maintenance, &oldest_key);
            }
        }
        self.compact_eviction_queue_locked(maintenance);
    }

    /// Reclaim *expired* retained bytes in expiration order so a stale working set
    /// cannot trap the byte budget (#2400).
    ///
    /// `max_total_size_bytes` is a hard cap on retained bytes, not an LRU
    /// trigger: a store that still does not fit once every reclaimable expired
    /// entry is gone is refused, and a *fresh* representation is never dropped
    /// to make room for a new one. Freshness lifetimes differ per response, so
    /// the expiry index—not insertion FIFO—selects candidates. The walk stops
    /// at the earliest live future expiry and is bounded by expired entries it
    /// actually retires rather than by cache size.
    fn reclaim_expired_for_byte_budget_locked(
        &self,
        maintenance: &mut CacheMaintenance,
        now: Duration,
    ) {
        while let Some((expires_at, insert_seq, cache_key)) =
            maintenance.expiry_index.iter().next().cloned()
        {
            if expires_at > now {
                break;
            }
            let is_current = self
                .cache
                .get(&cache_key)
                .is_some_and(|entry| entry.insert_seq == insert_seq);
            if is_current {
                self.remove_entry_locked(maintenance, &cache_key);
            } else {
                // Defensive stale-index retirement: normal replacement and
                // removal paths delete the exact tuple, but never let an
                // inconsistent tuple spin this bounded reclaim loop.
                maintenance
                    .expiry_index
                    .remove(&(expires_at, insert_seq, cache_key));
            }
        }
        self.compact_eviction_queue_locked(maintenance);
    }

    /// Drop superseded queue slots in one amortized pass. Slots accumulate only
    /// when a key is re-stored, so this runs rarely and is bounded by the queue
    /// length it is about to shrink.
    fn compact_eviction_queue_locked(&self, maintenance: &mut CacheMaintenance) {
        let bound = self.config.max_entries.saturating_mul(4).max(1024);
        if maintenance.eviction_queue.len() <= bound {
            return;
        }
        let cache = Arc::clone(&self.cache);
        maintenance
            .eviction_queue
            .retain(|(key, seq)| cache.get(key).is_some_and(|entry| entry.insert_seq == *seq));
    }

    /// Invalidate cache entries matching a path under one authority partition.
    ///
    /// Called only after a non-error response to an unsafe method (see
    /// [`Self::is_unsafe_method`] and RFC 9111 §4.4). `scope` must be the same
    /// authority partition [`Self::invalidation_scope`] produced at lookup, so
    /// a mutation on authority A cannot evict authority B on a shared proxy.
    ///
    /// Cost is one hash lookup, one `BTreeMap` point lookup, and one ordered
    /// range over the mutated path's descendants — bounded by the entries
    /// actually removed, not by cache size. The previous implementation scanned
    /// and re-parsed every cache key under the publication mutex for every
    /// qualifying unsafe-method request (GHSA-37gg-v9m4-8445).
    fn invalidate_path(&self, scope: &str, path: &str) {
        let encoded = encode_path_for_cache_key(path);
        let mut guard = self.accounting_guard();
        let maintenance = &mut *guard;

        let descendant_prefix: Arc<str> = {
            let mut prefix = String::with_capacity(encoded.len() + 1);
            prefix.push_str(encoded.as_ref());
            prefix.push('/');
            prefix.into()
        };

        let mut doomed: Vec<String> = Vec::new();
        if let Some(paths) = maintenance.path_index.get(scope) {
            if let Some(keys) = paths.get(encoded.as_ref()) {
                doomed.extend(keys.iter().cloned());
            }
            for (indexed_path, keys) in paths.range(Arc::clone(&descendant_prefix)..) {
                if !indexed_path.starts_with(descendant_prefix.as_ref()) {
                    break;
                }
                doomed.extend(keys.iter().cloned());
            }
        }

        let removed = doomed.len();
        for cache_key in doomed {
            self.remove_entry_locked(maintenance, &cache_key);
        }
        if removed > 0 {
            // Content-free: never emits the cache key, path, or authority.
            debug!(
                removed = removed,
                "response_caching: invalidated cache entries after an unsafe method"
            );
        }
    }

    /// Stage RFC 9111 §4.4 invalidation for an unsafe method using the same
    /// transformed Host view that cache lookup would use. Actual eviction runs
    /// in [`Self::after_proxy`] only after a non-error response.
    fn stage_pending_invalidation(
        &self,
        ctx: &mut RequestContext,
        request_headers: &HashMap<String, String>,
    ) {
        let scope = self.invalidation_scope(ctx, request_headers.get("host").map(String::as_str));
        ctx.metadata
            .insert(self.meta_pending_invalidate_host.clone(), scope.to_string());
        ctx.metadata
            .insert(self.meta_pending_invalidate_path.clone(), ctx.path.clone());
    }

    /// Apply a previously staged unsafe-method invalidation when the origin
    /// produced a non-error status.
    ///
    /// Prefers private typed origin provenance
    /// ([`RequestContext::origin_http_response_status`]) when present so an
    /// earlier `after_proxy` rejection that replaces the client-visible status
    /// cannot suppress eviction after a successful mutation. Falls back to
    /// `response_status` for direct `after_proxy` calls (unit tests) that never
    /// went through `run_after_proxy_hooks`. Consumes the staged scope exactly
    /// once so observe + after_proxy cannot double-invalidate.
    fn maybe_apply_pending_invalidation(&self, ctx: &mut RequestContext, response_status: u16) {
        let Some(scope) = ctx.metadata.remove(&self.meta_pending_invalidate_host) else {
            return;
        };
        let Some(path) = ctx.metadata.remove(&self.meta_pending_invalidate_path) else {
            return;
        };
        let status = ctx.origin_http_response_status().unwrap_or(response_status);
        if Self::is_non_error_status(status) {
            self.invalidate_path(&scope, &path);
        }
    }

    fn add_cache_status_header(&self, headers: &mut HashMap<String, String>, value: &str) {
        if self.config.add_cache_status_header {
            headers.insert("x-cache-status".to_string(), value.to_string());
        }
    }

    fn add_age_header(&self, headers: &mut HashMap<String, String>, current_age: Duration) {
        headers.insert("age".to_string(), age_header_value(current_age));
    }

    fn stash_request_started_at(&self, ctx: &mut RequestContext, request_time: Duration) {
        ctx.metadata.insert(
            self.meta_request_started.clone(),
            request_time.as_nanos().to_string(),
        );
    }

    fn response_delay(&self, ctx: &RequestContext, response_time: Duration) -> Duration {
        ctx.metadata
            .get(&self.meta_request_started)
            .and_then(|value| duration_from_monotonic_nanos_str(value))
            .map(|request_time| response_time.saturating_sub(request_time))
            .unwrap_or_default()
    }

    fn freshness_lifetime(&self, directives: &CacheControlDirectives) -> Duration {
        if let Some(s_maxage) = directives.s_maxage {
            Duration::from_secs(s_maxage)
        } else if let Some(max_age) = directives.max_age {
            Duration::from_secs(max_age)
        } else {
            Duration::from_secs(self.config.ttl_seconds)
        }
    }

    fn corrected_initial_age(
        &self,
        ctx: &RequestContext,
        response_headers: &HashMap<String, String>,
        response_time_monotonic: Duration,
        response_time_wall: DateTime<Utc>,
    ) -> Duration {
        let apparent_age = header_value(response_headers, "date")
            .and_then(parse_http_date)
            .map(|date| duration_since_http_date(response_time_wall, date))
            .unwrap_or_default();

        let age_value = header_value(response_headers, "age")
            .and_then(parse_age_header)
            .unwrap_or_default();
        let corrected_age_value =
            duration_saturating_add(age_value, self.response_delay(ctx, response_time_monotonic));
        apparent_age.max(corrected_age_value)
    }

    /// RFC 9111 §3.5: a shared cache MUST NOT store a response to a request
    /// bearing `Authorization` unless the response explicitly permits it with
    /// `public`, `must-revalidate`, or `s-maxage`.
    ///
    /// The predicate is the *request credential*, not whether Ferrum minted an
    /// identity for it. A gateway that forwards `Authorization` to a backend
    /// which authenticates it itself creates no `effective_identity` at all, so
    /// keying on identity alone treats those requests as anonymous and stores a
    /// protected response the origin never authorized a shared cache to keep.
    /// Hashing the token into a Vary dimension isolates *credentials* from one
    /// another but does not satisfy the protocol rule: the entry keeps serving
    /// the protected representation for the rest of its TTL even after the
    /// backend would revoke, expire, or narrow that token.
    ///
    /// `request_headers` is the live/restored backend-visible view the cache key
    /// was derived from (`before_proxy`'s `headers` parameter as replayed by
    /// [`Self::restore_request_headers_view`]). Admission deliberately checks
    /// both that view and the pristine inbound `ctx.headers`: a request-side
    /// transformer may add or remove the credential, but visibility in either
    /// provenance is sufficient to refuse storage without origin opt-in.
    ///
    /// `Proxy-Authorization` is deliberately not part of this predicate: it is
    /// an intermediary credential consumed at this hop and says nothing about
    /// origin authorization. It is still an auto-Vary dimension (so sessions
    /// never share an entry) and never survives into a stored entry — see
    /// [`NEVER_CACHED_RESPONSE_HEADERS`] and
    /// [`Self::stash_request_headers_snapshot`], which stores it only hashed.
    fn shared_cache_allows_authorized_response(
        ctx: &RequestContext,
        request_headers: &HashMap<String, String>,
        directives: &CacheControlDirectives,
    ) -> bool {
        let authorized_request = ctx.effective_identity().is_some()
            || header_value(&ctx.headers, "authorization").is_some()
            || header_value(request_headers, "authorization").is_some();
        if !authorized_request {
            return true;
        }

        directives.public || directives.must_revalidate || directives.s_maxage.is_some()
    }

    /// Stash the transformed-header values `before_proxy` saw for every
    /// key that can land in the cache key — `host`, the sensitive
    /// credential/session headers in [`SENSITIVE_VARY_HEADERS`]
    /// (`authorization`, `proxy-authorization`, `cookie`), and each configured
    /// `vary_by_headers` entry. `on_final_response_body` reads it back via
    /// [`Self::restore_request_headers_view`] so the storage cache key is
    /// derived from the same header view as the lookup. Without this, a
    /// request-side transformer that touches one of these headers (e.g.
    /// injecting `X-Tenant` from a consumer property, or rewriting `cookie`)
    /// would make the storage key disagree with the lookup key and the cache
    /// would never hit.
    ///
    /// Non-Host values that match the centralized metadata-redaction
    /// sensitivity rules are stashed as the same SHA-256 cache-key component
    /// [`cache_key_vary_value`] would produce. The restore path marks those
    /// headers as cache-key-ready so storage does not hash them a second time.
    /// This keeps raw cookies, credentials, and operator-redacted Vary header
    /// values out of `ctx.metadata`, which is copied into transaction log
    /// metadata. Host stays raw in the snapshot because it feeds the base-key
    /// host hash, not a Vary dimension.
    ///
    /// The auto-sensitive headers are stashed unconditionally because the
    /// storage path auto-Varies them (see `on_final_response_body`), so they are
    /// load-bearing cache-key dimensions even when the operator never lists them
    /// in `vary_by_headers`.
    ///
    /// The complete live view is represented separately by a delta from
    /// `ctx.headers` in RequestContext's private response-cache provenance map.
    /// That private delta covers arbitrary origin-supplied `Vary` fields without
    /// duplicating an unchanged header map or exposing raw values to transaction
    /// metadata. This serialized snapshot remains intentionally narrow and
    /// reduced so direct compatibility contexts that do not carry private
    /// staging can still rebuild configured and auto-sensitive dimensions
    /// without logging secrets.
    fn stash_request_headers_snapshot(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
    ) {
        ctx.stage_response_cache_request_header_delta(self.instance_id, headers);
        let mut snapshot: Vec<RequestHeaderSnapshotEntry> = Vec::with_capacity(
            self.config.vary_by_headers.len() + 1 + SENSITIVE_VARY_HEADERS.len(),
        );
        let mut push_if_present = |key: &str| {
            if let Some(value) = headers.get(key) {
                let value_is_cache_key_part = should_snapshot_header_value_as_cache_key_part(key);
                let value = if value_is_cache_key_part {
                    cache_key_vary_value(key, value)
                } else {
                    value.clone()
                };
                snapshot.push(RequestHeaderSnapshotEntry {
                    header: key.to_string(),
                    value,
                    value_is_cache_key_part,
                });
            }
        };
        push_if_present("host");
        for header in SENSITIVE_VARY_HEADERS {
            push_if_present(header);
        }
        for header in &self.config.vary_by_headers {
            // Skip duplicates that match the always-stashed keys above.
            if header == "host" || is_auto_sensitive_vary_header(header) {
                continue;
            }
            push_if_present(header);
        }
        if snapshot.is_empty() {
            // Nothing to remember — the cache key only contains route
            // metadata, which we can rebuild from `ctx` alone.
            return;
        }
        if let Ok(serialized) = serde_json::to_string(&snapshot) {
            ctx.metadata
                .insert(self.meta_headers_snapshot.clone(), serialized);
        }
    }

    /// Rebuild the request-headers view used to derive the storage cache key.
    /// Prefer the private backend-visible delta so an arbitrary origin-supplied
    /// `Vary` field reflects the value that actually reached the backend. The
    /// reduced public-metadata snapshot remains a fail-closed compatibility
    /// fallback for direct hook contexts that do not carry private staging.
    fn restore_request_headers_view(&self, ctx: &RequestContext) -> RestoredRequestHeadersView {
        if let Some(delta) = ctx.response_cache_request_header_delta(self.instance_id) {
            let mut headers = ctx.headers.clone();
            for (name, value) in delta {
                match value {
                    Some(value) => {
                        headers.insert(name.clone(), value.clone());
                    }
                    None => {
                        headers.remove(name);
                    }
                }
            }
            return RestoredRequestHeadersView {
                headers,
                cache_key_ready_headers: HashSet::new(),
            };
        }
        let mut headers = ctx.headers.clone();
        let mut cache_key_ready_headers = HashSet::new();
        if let Some(serialized) = ctx.metadata.get(&self.meta_headers_snapshot)
            && let Ok(snapshot) =
                serde_json::from_str::<Vec<RequestHeaderSnapshotEntry>>(serialized)
        {
            for entry in snapshot {
                if entry.value_is_cache_key_part
                    && should_snapshot_header_value_as_cache_key_part(&entry.header)
                {
                    cache_key_ready_headers.insert(entry.header.clone());
                }
                headers.insert(entry.header, entry.value);
            }
        }
        RestoredRequestHeadersView {
            headers,
            cache_key_ready_headers,
        }
    }
}

fn skip_etag_ows(bytes: &[u8], position: &mut usize) {
    while matches!(bytes.get(*position), Some(b' ' | b'\t')) {
        *position += 1;
    }
}

/// Parse one entity-tag and return its opaque-tag contents.
///
/// RFC 9110 entity tags do not use quoted-string escaping: a backslash is an
/// ordinary opaque byte and a quote always terminates the tag. `etagc` permits
/// visible ASCII other than `"`, plus obs-text bytes.
fn parse_entity_tag<'a>(value: &'a str, position: &mut usize) -> Option<&'a str> {
    let bytes = value.as_bytes();
    if bytes.get(*position..)?.starts_with(b"W/") {
        *position += 2;
    }
    if bytes.get(*position) != Some(&b'"') {
        return None;
    }
    *position += 1;
    let opaque_start = *position;
    while let Some(&byte) = bytes.get(*position) {
        match byte {
            b'"' => {
                let opaque = &value[opaque_start..*position];
                *position += 1;
                return Some(opaque);
            }
            0x21 | 0x23..=0x7e | 0x80..=0xff => *position += 1,
            _ => return None,
        }
    }
    None
}

fn parse_single_entity_tag(value: &str) -> Option<&str> {
    let mut position = 0;
    skip_etag_ows(value.as_bytes(), &mut position);
    let opaque = parse_entity_tag(value, &mut position)?;
    skip_etag_ows(value.as_bytes(), &mut position);
    (position == value.len()).then_some(opaque)
}

fn if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    let bytes = if_none_match.as_bytes();
    let mut position = 0;
    skip_etag_ows(bytes, &mut position);

    // `*` is an alternative to the entity-tag list, not a list member.
    if bytes.get(position) == Some(&b'*') {
        position += 1;
        skip_etag_ows(bytes, &mut position);
        return position == bytes.len();
    }

    let Some(current_opaque) = parse_single_entity_tag(etag) else {
        return false;
    };
    let mut matched = false;
    loop {
        skip_etag_ows(bytes, &mut position);
        let Some(candidate_opaque) = parse_entity_tag(if_none_match, &mut position) else {
            return false;
        };
        matched |= candidate_opaque == current_opaque;
        skip_etag_ows(bytes, &mut position);
        if position == bytes.len() {
            return matched;
        }
        if bytes.get(position) != Some(&b',') {
            return false;
        }
        position += 1;
        skip_etag_ows(bytes, &mut position);
        if position == bytes.len() {
            return false;
        }
    }
}

/// Parse an HTTP-date for conditional-request handling.
///
/// RFC 9110 §5.6.7 requires recipients to accept all three historic date
/// formats. `parse_from_rfc2822` covers the dominant IMF-fixdate form
/// (`Sun, 06 Nov 1994 08:49:37 GMT`), but rejects the two obsolete forms a
/// recipient must still accept: RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`)
/// and asctime (`Sun Nov  6 08:49:37 1994`). Falling back across all three
/// keeps conditional revalidation (`If-Modified-Since` → `304`) working
/// against legacy origins and clients instead of silently serving a full
/// `200` from cache. Each fixed-offset format is interpreted as UTC, matching
/// the obsolete `GMT` zone these formats always use.
pub(crate) fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc2822(value) {
        return Some(dt.with_timezone(&Utc));
    }
    // IMF-fixdate (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850
    // (`Sunday, 06-Nov-94 08:49:37 GMT`), then asctime
    // (`Sun Nov  6 08:49:37 1994`). asctime has no zone; the dashed/comma
    // forms always carry `GMT`, which these patterns consume literally.
    const FORMATS: [&str; 3] = [
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ];
    for format in FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc());
        }
    }
    None
}

#[async_trait]
impl Plugin for ResponseCaching {
    fn name(&self) -> &str {
        "response_caching"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_CACHING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.is_cacheable_method(&ctx.method)
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Skip body buffering for SSE requests (`Accept: text/event-stream`).
        // Buffering an unbounded event stream would collect frames until the
        // configured `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` ceiling is hit and
        // then 502, instead of streaming events to the client. SSE responses
        // are not cacheable anyway — `before_proxy` will see no cache hit and
        // `on_final_response_body` will not be invoked, so the cache state
        // stays correct without any other code paths needing to special-case
        // SSE.
        !super::utils::sse::is_sse_request(ctx)
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Pin the response-side gate provenance before anything on this
        // request can read a gate. Both directions of the cached-representation
        // provenance contract read this single pinned value: the lookup below
        // compares it against the stored entry, and `on_final_response_body`
        // refuses to store a representation produced across a publication.
        // One ArcSwap load, memoized on the context for sibling instances.
        let policy_stamp = ctx.pin_response_policy_stamp().clone();
        // The other provenance half, and the only one that is generation-local:
        // it was copied from this request's own plugin-cache view before any
        // plugin ran, so unlike the stamp above it cannot describe a generation
        // other than the one whose transformer instances shape this response.
        let presentation_digest = ctx.response_presentation_policy_digest;

        // Method safety is independent of storage eligibility (RFC 9111 §4.4 /
        // RFC 9110 §9.2.1). An unsafe method listed in `cacheable_methods`
        // (e.g. POST) must still stage authority-scoped invalidation; a safe
        // method merely absent from that set must not. Staging uses the live
        // `headers` view so a rewritten Host partitions identically to lookup.
        // HIT/REVALIDATED paths clear this staging below — a served cache HIT
        // never contacted the origin and must not flush peer variants.
        let stage_unsafe_invalidation =
            self.config.invalidate_on_unsafe_methods && Self::is_unsafe_method(&ctx.method);
        if stage_unsafe_invalidation {
            self.stage_pending_invalidation(ctx, headers);
        }

        if !self.is_cacheable_method(&ctx.method) {
            // Clear only this instance's lookup staging so a sibling cache keeps
            // its independently staged base/snapshot/status. Pending
            // invalidation host is intentionally retained until origin success
            // is observed (or cleared on a later HIT of a cacheable sibling).
            self.clear_lookup_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
            return PluginResult::Continue;
        }

        if super::utils::sse::headers_accept_sse(headers) {
            self.clear_lookup_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
            return PluginResult::Continue;
        }

        // Use the `headers` parameter (not `ctx.headers`) — the gateway hot
        // path may have temporarily moved `ctx.headers` out of the context
        // before invoking `before_proxy` (zero-alloc when no plugin modifies
        // headers). The `headers` parameter is the single source of truth
        // during this phase.
        // A request that carries a body has no complete partition here. The
        // proxy must first observe the entire H1/H2/H3 upload and publish a
        // private empty-body proof; method and framing headers alone cannot
        // establish emptiness because H2/H3 GET/HEAD streams may carry DATA
        // without Content-Length. The header check remains defense in depth
        // for inconsistent or malformed framing views.
        if !ctx.replay_request_body_empty_proven() || request_declares_body(headers) {
            self.clear_lookup_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
            return PluginResult::Continue;
        }

        let base_key = match self.build_base_cache_key(ctx, headers) {
            Ok(base_key) => base_key,
            Err(refusal) => {
                // Fail closed: without a complete, stable partition there is no
                // key under which a retained representation can be proven to
                // belong to this caller, so nothing is looked up and nothing is
                // stored. The refusal's reason is a compiled-in static string
                // and carries no caller, credential, or key material.
                debug!(
                    reason = refusal.reason(),
                    "response_caching: bypassing without a complete replay partition for this \
                     caller"
                );
                self.clear_lookup_staging(ctx);
                self.set_cache_status(ctx, "BYPASS");
                return PluginResult::Continue;
            }
        };
        ctx.metadata
            .insert(self.meta_base_key.clone(), base_key.clone());
        // Stage the client-facing path this key was derived from. A
        // route-dispatch rewrite is folded into `ctx.path` only after
        // `before_proxy` returns, so the storage side must index the entry
        // under this value rather than the then-current path — see
        // `CACHE_LOOKUP_PATH_SUFFIX`.
        ctx.metadata
            .insert(self.meta_lookup_path.clone(), ctx.path.clone());
        self.stash_request_started_at(ctx, self.now_monotonic());
        // Preserve the complete backend-visible header view privately so
        // `on_final_response_body` can key arbitrary origin-supplied Vary
        // fields from the same values that reached the backend. A reduced,
        // redaction-safe metadata snapshot also supports direct compatibility
        // hook contexts. By storage time `ctx.headers` alone is the original,
        // untransformed map.
        self.stash_request_headers_snapshot(ctx, headers);

        let mut vary_headers = self.cache_lookup_vary_headers(&base_key);
        // Every internal key and every retained response uses the same fixed
        // credential/session presence tuple. Ferrum's caller partition is not
        // visible to downstream shared caches, so only adding a Vary name when
        // the current request carries it would let an anonymous response omit
        // `Vary` and be replayed downstream to a credentialed request.
        self.merge_mandatory_sensitive_vary_headers(&mut vary_headers);
        let cache_key =
            self.extend_base_key_with_vary(base_key.clone(), &vary_headers, headers, None);
        // Store the full cache key (with Vary dimensions) so on_final_response_body
        // can mark the correct variant-specific key in the uncacheable predictor.
        ctx.metadata
            .insert(self.meta_predict_key.clone(), cache_key.clone());

        if self.config.respect_no_cache
            && let Some(cc) = headers.get("cache-control")
        {
            let directives = parse_cache_control(cc);
            if directives.request_bypasses_cache() {
                // Keep this instance's staged base/snapshot/predict so a
                // no-cache refresh can still store the replacement response
                // under the same instance-owned key inputs. Pending unsafe
                // invalidation (if any) is retained — the request contacts
                // the origin.
                self.set_cache_status(ctx, "BYPASS");
                return PluginResult::Continue;
            }
        }

        // Fast-path: skip cache lookup if this specific variant is predicted uncacheable.
        // Uses the full cache_key (including Vary dimensions) so that one uncacheable
        // variant does not suppress lookups for other variants of the same route.
        if !self
            .uncacheable_predictor
            .is_predicted_cacheable(&cache_key)
        {
            self.set_cache_status(ctx, "PREDICTED-BYPASS");
            return PluginResult::Continue;
        }

        if let Some(entry) = self.cache.get(&cache_key) {
            let now = self.now_monotonic();
            let current_age = entry.current_age(now);
            // Provenance gate, ahead of freshness: a stored entry is replayed
            // as a finalized representation with presentation transforms
            // skipped, so it may only be served while the response-side
            // runtime-overlay policy that produced it is still the live one.
            // Every real gate publication carries a fresh, atomically paired
            // identity. Pointer identity cannot collide or wrap, so a
            // representation is either provably current or refetched, never
            // stacked with a second pass of non-idempotent rules.
            //
            // The generation digest is checked alongside it because the two are
            // published at different points: an entry can carry the current
            // publication identity yet have been shaped by an older plugin
            // generation's rules/gate (GHSA-83rc-23c9-3g9x). Either half
            // differing retires the entry.
            let stale_policy = entry.response_policy_stamp != policy_stamp
                || presentation_digest != Some(entry.response_presentation_digest);
            // Belt-and-braces companion to the store-side refusal: an entry
            // whose status has semantics this plugin does not implement is
            // never replayed, whatever produced it.
            let unsupported_status = !is_supported_cacheable_status(entry.status_code);
            if stale_policy || unsupported_status || !entry.is_fresh_at(now) {
                drop(entry);
                self.invalidate_cache_key(&base_key, &cache_key);
                if stale_policy {
                    // Content-free by construction: no key, policy identity,
                    // header, or body material is recorded.
                    debug!(
                        "response_caching: cached representation predates the current \
                         runtime-overlay response policy, refetching"
                    );
                }
            } else {
                // Never log the cache key: it is the replay partition itself.
                debug!("response_caching: cache HIT");

                if self.is_fresh_conditional_hit(headers, &entry) {
                    self.set_cache_status(ctx, "REVALIDATED");
                    // HIT/REVALIDATED will not store; drop this instance's
                    // lookup staging so a later final hook cannot mix it with
                    // another instance's store path. Also drop pending
                    // invalidation — this representation was served without
                    // contacting the origin.
                    self.clear_lookup_staging(ctx);
                    self.clear_pending_invalidation(ctx);
                    // Stored validators/headers are already the final
                    // post-transform representation. Mark the private finalized
                    // replay capability so synthetic presentation transforms
                    // (body + response_transformer header rules) do not mutate
                    // them again while inspection/final hooks still run.
                    ctx.finalized_response_replay = true;
                    return PluginResult::RejectBinary {
                        status_code: 304,
                        body: Bytes::new(),
                        headers: self.not_modified_headers(&entry, current_age),
                    };
                }

                let mut headers = entry.headers.clone();
                self.add_age_header(&mut headers, current_age);
                self.add_cache_status_header(&mut headers, "HIT");
                self.set_cache_status(ctx, "HIT");
                self.clear_lookup_staging(ctx);
                self.clear_pending_invalidation(ctx);
                // Same finalized-replay contract as REVALIDATED / idempotent
                // replay: the entry was stored after transform_response_body
                // and after_proxy header rules on the miss path.
                ctx.finalized_response_replay = true;

                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: entry.body.clone(),
                    headers,
                };
            }
        }

        self.set_cache_status(ctx, "MISS");
        PluginResult::Continue
    }

    fn observe_origin_http_response_status(&self, ctx: &mut RequestContext, status: u16) {
        // RFC 9111 §4.4: mandatory invalidation runs on a non-error origin
        // response, not on successful client presentation. This hook is
        // invoked by proxy core before any `after_proxy` plugin can reject,
        // so an earlier response-size / OpenAPI rejection cannot suppress
        // eviction after a successful mutation.
        self.maybe_apply_pending_invalidation(ctx, status);
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Safety net for direct `after_proxy` calls (unit tests) and any path
        // that reached this hook with staging still pending. When
        // `observe_origin_http_response_status` already consumed the staging
        // key, this is a no-op.
        self.maybe_apply_pending_invalidation(ctx, response_status);

        let Some(status) = self.cache_status(ctx) else {
            // A preceding sibling may already have short-circuited with a HIT
            // before this instance reached `before_proxy`. Do not invent MISS
            // state and overwrite that instance's client-visible header.
            return PluginResult::Continue;
        };
        self.add_cache_status_header(response_headers, status);
        PluginResult::Continue
    }

    /// `x-cache-status` is an unconditional gateway `insert`, so a backend that
    /// sends the identical value (`MISS` is trivially guessable) hides the write
    /// from net-diff mutation tracking — and a later body/committed hook that
    /// exhausts the gRPC deadline would then rebuild the DEADLINE_EXCEEDED
    /// response without it. Declared owned only when the header is actually
    /// configured to be written.
    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        self.config.add_cache_status_header
            && self.cache_status(ctx).is_some()
            && name.eq_ignore_ascii_case("x-cache-status")
    }

    /// Config-time form of the same ownership: a backend echoing the guessable
    /// `MISS` value hides the gateway write from observed-mutation
    /// reconciliation, so only this declaration stops a backend `x-cache-status`
    /// TRAILER from overwriting the gateway's cache telemetry after
    /// `after_proxy` set it. Empty — and therefore no trailer governance — when
    /// the header is not configured to be written at all.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        if self.config.add_cache_status_header {
            super::ResponseTrailerPolicy::Names(&CACHE_STATUS_POLICY_NAMES)
        } else {
            super::ResponseTrailerPolicy::None
        }
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Synthetic short-circuit guard. When a request was short-circuited by a
        // `before_proxy` plugin (including this plugin's own cache HIT/REVALIDATED
        // surfaced via `RejectBinary`, an `ai_semantic_cache` hit, a
        // `fault_injection`/`response_mock`/`serverless` abort, etc.), the
        // synthetic body now flows back through the response-body hooks (the
        // generic 2xx short-circuit path). Re-running the entire store path over a
        // body that never came from the backend would take `accounting_guard()`,
        // do a full body copy on every hit (a hot-path regression), and needlessly
        // churn the vary index / uncacheable predictor — and for a served cache
        // HIT the entry is already cached and unchanged, so there is nothing to
        // store. `apply_synthetic_response_body_hooks` sets this marker only for
        // the duration of the synthetic body-hook phase, so its presence is a
        // precise signal; a genuine backend response (the only legitimate store /
        // replacement path) never carries it and falls through to store normally.
        // Mirrors `request_deduplication`'s synthetic short-circuit guard and
        // `ai_semantic_cache`'s miss-only buffering key.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            return PluginResult::Continue;
        }

        let base_key = match ctx.metadata.get(&self.meta_base_key) {
            Some(base_key) => base_key.clone(),
            None => return PluginResult::Continue,
        };

        // Provenance stamp for this representation. `before_proxy` pinned the
        // stamp before any gate read on this request; this hook runs after
        // every response-side transform, so an unchanged atomic publication
        // identity proves the whole response pipeline saw one policy. If a
        // publication landed in between, the bytes belong to neither policy —
        // drop the store rather than cache a representation of unknown provenance.
        // Not an uncacheable-response signal, so the predictor is left alone.
        let policy_stamp = ctx.pin_response_policy_stamp().clone();
        if !ctx.response_policy_stamp_stable() {
            debug!(
                "response_caching: runtime-overlay policy changed mid-request, \
                 skipping store of an unattributable representation"
            );
            return PluginResult::Continue;
        }
        // Record the generation that actually shaped these bytes alongside the
        // publication identity — the request kept its pinned plugin cache for
        // its whole lifetime, so this digest is exact even when the stamp above
        // belongs to a newer publication (GHSA-83rc-23c9-3g9x).
        let Some(presentation_digest) = ctx.response_presentation_policy_digest else {
            debug!(
                "response_caching: presentation policy is unprovable, \
                 skipping store of an unattributable representation"
            );
            return PluginResult::Continue;
        };
        // Use the variant-specific predict key (set during before_proxy) for
        // predictor marking so that uncacheability of one Vary variant does not
        // suppress cache lookups for other variants of the same route.
        let predict_key = ctx.metadata.get(&self.meta_predict_key).cloned();

        if !self
            .config
            .cacheable_status_codes
            .contains(&response_status)
        {
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        // Second, independent gate on the statuses whose caching semantics this
        // plugin does not implement. Configuration admission already rejects
        // them, but the runtime refusal is what makes the guarantee
        // status-driven rather than config-driven, and it also covers a partial
        // representation that arrives under an allowed status: a caller-chosen
        // `Range` answered with `Content-Range` describes bytes, not the
        // resource, and must never become the reusable entry for later
        // unconditional requests. Neither is an uncacheable *resource* signal —
        // the very next unconditional request may store the full
        // representation — so the predictor is deliberately left alone.
        if !is_supported_cacheable_status(response_status)
            || response_headers.contains_key("content-range")
        {
            debug!(
                response_status = response_status,
                "response_caching: refusing to store a partial or validator-only response as a \
                 reusable representation"
            );
            return PluginResult::Continue;
        }

        let directives = if self.config.respect_cache_control {
            response_headers
                .get("cache-control")
                .map(|cc| parse_cache_control(cc))
                .unwrap_or_default()
        } else {
            CacheControlDirectives::default()
        };

        if directives.no_store || directives.private || directives.no_cache {
            self.invalidate_base_key(&base_key);
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        // Restore the same header view `before_proxy` used so the
        // shared-cache authorization check and the storage cache key
        // both see the transformed values, not the untransformed
        // `ctx.headers`. See `restore_request_headers_view` for why.
        let lookup_headers = self.restore_request_headers_view(ctx);
        let freshness_lifetime = self.freshness_lifetime(&directives);

        if freshness_lifetime.is_zero() {
            self.invalidate_zero_freshness_response(
                &base_key,
                predict_key.as_deref(),
                response_headers,
                &lookup_headers,
            );
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        // Never cache responses with Set-Cookie headers. These are
        // per-client and replaying them from a shared cache would leak
        // session cookies to other users (RFC 7234 §8).
        if response_headers.contains_key("set-cookie") {
            debug!("response_caching: skipping cache — response contains Set-Cookie header");
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        let request_view = &lookup_headers.headers;
        if !Self::shared_cache_allows_authorized_response(ctx, request_view, &directives) {
            debug!(
                "response_caching: refusing to store a response to an authorized request without \
                 an explicit shared-cache opt-in"
            );
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        let response_time_monotonic = self.now_monotonic();
        let response_time_wall = self.now_wall();
        let corrected_initial_age = self.corrected_initial_age(
            ctx,
            response_headers,
            response_time_monotonic,
            response_time_wall,
        );

        if corrected_initial_age >= freshness_lifetime {
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        let mut vary_headers = match self.merged_vary_headers(response_headers) {
            Some(vary_headers) => vary_headers,
            None => {
                self.invalidate_base_key(&base_key);
                self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
                return PluginResult::Continue;
            }
        };

        // Per RFC 7234 §3.2 / §8, a shared cache MUST NOT serve a stored
        // response to a request other than the one that produced it when the
        // original request carried credentials — unless the response
        // explicitly opted in via `Cache-Control: public` / `must-revalidate`
        // / `s-maxage`. `shared_cache_allows_authorized_response` gates that
        // decision above. Once we've decided to cache, we MUST also key the
        // entry by the credential so two clients presenting different
        // credentials land on different cache entries.
        //
        // Unconditionally merge every credential/session header name
        // (`authorization`, `proxy-authorization`, `cookie`) into the keyed
        // Vary list. Presence remains a keyed bit, and present values remain
        // hashed. Operators don't need to remember to set
        // `cache_key_include_consumer: true` or list these in
        // `vary_by_headers` — the safe default is to never share a cached
        // response across distinct credentials or sessions. Keeping the names
        // on anonymous responses is also load-bearing: downstream shared caches
        // cannot observe Ferrum's private caller partition and must receive the
        // same `Vary` contract. The merged list is sorted and re-stored in
        // `vary_index` so the same dimension applies to every subsequent lookup
        // at this base key.
        //
        // This is complementary to the per-principal `consumer_part` in
        // `build_base_cache_key`: that isolates *authenticated* principals
        // (API key / mTLS / JWT) even when the credential rides a non-standard
        // header; this isolates the raw credential/session headers themselves,
        // including anonymous `Cookie`-only sessions that have no
        // `effective_identity`.
        //
        // `lookup_headers` was built above from
        // `restore_request_headers_view`: it layers `before_proxy`'s header
        // snapshot on top of `ctx.headers`, so configured `vary_by_headers`
        // / `host` / the sensitive headers and arbitrary response-added Vary
        // fields all reflect the complete backend-visible view staged during
        // lookup.
        self.merge_mandatory_sensitive_vary_headers(&mut vary_headers);
        // The base key is *read back* from this instance's staging, never
        // recomputed here. `stash_request_headers_snapshot` deliberately stores
        // credential/session values in their reduced `sha256-…` cache-key form
        // so raw secrets never reach `ctx.metadata` (which is copied into
        // transaction-log metadata), and the caller-authorization partition is
        // derived from the *raw* credential material. Recomputing the base key
        // from the restored view would therefore digest the reduced form and
        // silently store under a key no lookup can ever produce. Staging the key
        // at lookup time is what keeps the two provably identical.

        if body.len() > self.config.max_entry_size_bytes {
            // Never emits the key: it is the replay partition itself.
            debug!(
                body_size = body.len(),
                max_size = self.config.max_entry_size_bytes,
                "response_caching: response body exceeds max_entry_size_bytes, skipping cache"
            );
            return PluginResult::Continue;
        }

        let invalidation_scope =
            self.invalidation_scope(ctx, lookup_headers.headers.get("host").map(String::as_str));
        // Index under the client-facing path staged at lookup, which is the
        // same value the base key bound and the same value an unsafe method
        // stages for the RFC 9111 §4.4 sweep. `ctx.path` may already carry a
        // post-`before_proxy` route rewrite by now; indexing under that would
        // make invalidation match nothing. Falls back to `ctx.path` only for
        // direct hook contexts that never ran this instance's lookup.
        let lookup_path = match ctx.metadata.get(&self.meta_lookup_path) {
            Some(path) => path.as_str(),
            None => ctx.path.as_str(),
        };
        let encoded_lookup_path = encode_path_for_cache_key(lookup_path);
        let invalidation_path: Arc<str> = Arc::from(encoded_lookup_path.as_ref());

        // Copy the potentially large body before entering the publication
        // critical section. The final key and response Vary header cannot be
        // built yet: another concurrent store may widen `vary_index` before
        // this store acquires `accounting_lock`.
        let mut cached_response_headers = response_headers.clone();
        // Narrow the retained copy only: hop-by-hop / proxy-authentication
        // fields and every field the origin qualified as `private` or
        // `no-cache` are dropped before the entry exists, so no later replay
        // path can emit them. The client that produced this miss still receives
        // the untouched `response_headers`.
        sanitize_cached_response_headers(&mut cached_response_headers, &directives);
        let cached_body = Bytes::copy_from_slice(body);

        let (cache_key, entry_size) = {
            // Lock ordering: acquire `accounting_lock` before mutating
            // `cache`, `vary_index`, `total_size`, or any maintenance
            // structure, and never acquire it while holding a DashMap entry
            // guard. Cache-hit reads do not take this lock. Every operation
            // performed under it is bounded: no full-map clone, sort, or scan.
            let mut guard = self.accounting_guard();
            let maintenance = &mut *guard;

            // Merge against the latest published dimensions while holding the
            // same lock that protects cache-key publication. A pre-lock
            // snapshot permits concurrent stores to overwrite one another's
            // newly discovered dimensions.
            let previous_vary_headers = self
                .vary_index
                .get(&base_key)
                .map(|headers| headers.clone());
            if let Some(existing_headers) = &previous_vary_headers {
                let mut added = false;
                for header in existing_headers {
                    added |= merge_vary_header(&mut vary_headers, header);
                }
                if added {
                    vary_headers.sort();
                }
            }

            // A dimension increase changes the shape of every lookup key for
            // this base key. Existing narrow variants cannot be migrated: the
            // request values for newly introduced headers were never stored.
            // Remove them deliberately so no retained entry becomes stranded
            // behind the wider index.
            if previous_vary_headers
                .as_ref()
                .is_some_and(|previous| previous != &vary_headers)
            {
                self.invalidate_base_key_locked(maintenance, &base_key);
            }

            let cache_key = self.extend_base_key_with_vary(
                base_key.clone(),
                &vary_headers,
                &lookup_headers.headers,
                Some(&lookup_headers.cache_key_ready_headers),
            );

            // Mirror the final keyed Vary list onto the cached response so
            // downstream caches and clients observe the same dimensions.
            if !vary_headers.is_empty() {
                cached_response_headers.insert("vary".to_string(), vary_headers.join(", "));
            }

            let entry = CacheEntry {
                status_code: response_status,
                headers: cached_response_headers,
                body: cached_body,
                stored_at: response_time_monotonic,
                freshness_lifetime,
                corrected_initial_age,
                // `cache_key` is `base_key` plus an optional separator + Vary
                // digest, so `base_key.len()` recovers this entry's base key.
                base_key_len: base_key.len(),
                insert_seq: maintenance.next_seq(),
                invalidation_scope,
                invalidation_path,
                response_policy_stamp: policy_stamp,
                response_presentation_digest: presentation_digest,
            };
            let entry_size = entry.approx_size();
            let mut old_size = self
                .cache
                .get(&cache_key)
                .map(|old_entry| old_entry.approx_size())
                .unwrap_or(0);
            let mut current_total = self.total_size.load(Ordering::Relaxed);
            let mut next_total = current_total
                .saturating_sub(old_size)
                .saturating_add(entry_size);

            if next_total > self.config.max_total_size_bytes
                && entry_size <= self.config.max_total_size_bytes
            {
                // The byte cap is the limiting dimension: reclaim *expired*
                // entries before refusing an otherwise eligible store. Stale
                // entries must not trap the byte budget when the entry count
                // never exceeded `max_entries` — the count-gated sweep in
                // `evict_if_needed_locked` never runs for them. The reclaim may
                // also collect the entry being replaced, so recompute both
                // accounting inputs under the same lock.
                self.reclaim_expired_for_byte_budget_locked(maintenance, response_time_monotonic);
                old_size = self
                    .cache
                    .get(&cache_key)
                    .map(|old_entry| old_entry.approx_size())
                    .unwrap_or(0);
                current_total = self.total_size.load(Ordering::Relaxed);
                next_total = current_total
                    .saturating_sub(old_size)
                    .saturating_add(entry_size);
            }

            if entry_size > self.config.max_total_size_bytes
                || next_total > self.config.max_total_size_bytes
            {
                debug!(
                    current_total = current_total,
                    old_size = old_size,
                    entry_size = entry_size,
                    next_total = next_total,
                    max_total = self.config.max_total_size_bytes,
                    "response_caching: total cache size would exceed limit, skipping cache"
                );
                return PluginResult::Continue;
            }

            self.insert_entry_locked(maintenance, &base_key, cache_key.clone(), entry);
            self.vary_index.insert(base_key, vary_headers);
            self.evict_if_needed_locked(maintenance);
            (cache_key, entry_size)
        };
        // Response was cacheable; remove the exact cache key from the predictor
        // even for client no-cache bypass refreshes, which return before
        // this instance's predict-key metadata is available.
        self.uncacheable_predictor.mark_cacheable(&cache_key);

        // Never emits the cache key: it is the replay partition itself and
        // encodes caller authorization and canonical caller context.
        debug!(
            entry_size = entry_size,
            freshness_lifetime_secs = freshness_lifetime.as_secs(),
            corrected_initial_age_secs = corrected_initial_age.as_secs(),
            "response_caching: cached response"
        );

        PluginResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plugin_with_config(config: serde_json::Value) -> ResponseCaching {
        match ResponseCaching::new(&config) {
            Ok(plugin) => plugin,
            Err(error) => panic!("response_caching config should be valid: {error}"),
        }
    }

    fn make_ctx(method: &str, path: &str) -> RequestContext {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            path.to_string(),
        );
        ctx.set_replay_request_body_empty_proven(true);
        // Protocol entry paths copy the selected plugin-cache generation's
        // presentation digest before any plugin runs. These inline cache tests
        // exercise ordinary provable generations, so give every shared fixture
        // the same deterministic witness instead of accidentally testing the
        // fail-closed `None` path.
        ctx.set_response_presentation_policy_digest(Some([0x51; 32]));
        ctx
    }

    #[tokio::test]
    async fn cache_hit_does_not_restore_over_served_body() {
        // Regression: synthetic 2xx short-circuit bodies (cache HITs surfaced
        // via `RejectBinary{200}`) now flow back through the response-body
        // hooks. Without the synthetic short-circuit guard in
        // `on_final_response_body` every fresh hit would re-run the full store
        // path over the body it just served (a lock + body copy hot-path
        // regression). This asserts a HIT leaves the cached entry untouched.
        let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

        // 1) MISS: store an entry.
        let mut miss_ctx = make_ctx("GET", "/cached");
        let mut miss_headers = miss_ctx.headers.clone();
        let miss_result = plugin.before_proxy(&mut miss_ctx, &mut miss_headers).await;
        assert!(matches!(miss_result, PluginResult::Continue));
        assert_eq!(plugin.cache_status(&miss_ctx), Some("MISS"));
        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut miss_ctx, 200, &response_headers, b"cached-A")
            .await;
        assert_eq!(plugin.cache.len(), 1, "miss should store exactly one entry");
        let cache_key = plugin
            .cache
            .iter()
            .next()
            .map(|e| e.key().clone())
            .expect("entry stored");
        let stored_at_before = plugin
            .cache
            .get(&cache_key)
            .map(|e| e.stored_at)
            .expect("entry present");

        // 2) HIT: a second request short-circuits with the cached body.
        let mut hit_ctx = make_ctx("GET", "/cached");
        let mut hit_headers = hit_ctx.headers.clone();
        let hit_result = plugin.before_proxy(&mut hit_ctx, &mut hit_headers).await;
        assert!(
            matches!(
                hit_result,
                PluginResult::RejectBinary {
                    status_code: 200,
                    ..
                }
            ),
            "second request should be served from cache"
        );
        assert_eq!(plugin.cache_status(&hit_ctx), Some("HIT"));

        // 3) The synthetic-response-body path now re-runs on_final_response_body
        // over the HIT body. In production `apply_synthetic_response_body_hooks`
        // sets the synthetic short-circuit marker for the duration of this phase;
        // replicate that here so the guard sees the same precise signal it does at
        // runtime. Feed a DIFFERENT body to prove the guard prevents a re-store:
        // if the entry were re-stored it would now hold the tampered body and a
        // new stored_at.
        hit_ctx.metadata.insert(
            crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        let store_result = plugin
            .on_final_response_body(&mut hit_ctx, 200, &response_headers, b"tampered-B")
            .await;
        assert!(matches!(store_result, PluginResult::Continue));

        assert_eq!(
            plugin.cache.len(),
            1,
            "HIT must not create or duplicate cache entries"
        );
        let entry = plugin.cache.get(&cache_key).expect("entry still present");
        assert_eq!(
            &entry.body[..],
            b"cached-A".as_slice(),
            "HIT must not overwrite the cached body"
        );
        assert_eq!(
            entry.stored_at, stored_at_before,
            "HIT must not advance stored_at (no re-store)"
        );
    }

    #[tokio::test]
    async fn sensitive_vary_values_are_hashed_in_predict_and_storage_keys() {
        let plugin = plugin_with_config(json!({
            "ttl_seconds": 60,
            "vary_by_headers": ["authorization"]
        }));
        let bearer = "Bearer reviewer-secret-token";

        let mut ctx = make_ctx("GET", "/api/public-auth");
        ctx.headers
            .insert("authorization".to_string(), bearer.to_string());
        let mut request_headers = ctx.headers.clone();

        let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
        assert!(matches!(result, PluginResult::Continue));

        let Some(predict_key) = ctx.metadata.get(&plugin.meta_predict_key) else {
            panic!("before_proxy should store variant predict key");
        };
        assert!(!predict_key.contains(bearer));
        assert!(!predict_key.contains("reviewer-secret-token"));
        // Keys are opaque, fixed-length hex digests: a base-key digest, and for
        // a varied variant a separator plus a Vary-tuple digest.
        assert!(
            predict_key
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == CACHE_KEY_VARY_SEPARATOR),
            "cache key must be opaque hex"
        );
        let credential_free_predict_key = predict_key.clone();

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"authorized-body")
            .await;

        let cache_keys: Vec<String> = plugin
            .cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(cache_keys.len(), 1);
        let stored_key = &cache_keys[0];
        assert!(!stored_key.contains(bearer));
        assert!(!stored_key.contains("reviewer-secret-token"));
        assert_eq!(
            stored_key, &credential_free_predict_key,
            "lookup and storage must derive the same Vary-framed key"
        );

        // A different credential for the same target must not reach that entry.
        let mut other = make_ctx("GET", "/api/public-auth");
        other.headers.insert(
            "authorization".to_string(),
            "Bearer a-different-token".to_string(),
        );
        let mut other_headers = other.headers.clone();
        let other_result = plugin.before_proxy(&mut other, &mut other_headers).await;
        assert!(
            matches!(other_result, PluginResult::Continue),
            "a different credential must MISS, not replay"
        );
    }

    #[tokio::test]
    async fn cookie_is_auto_varied_and_hashed_without_explicit_config() {
        // No `vary_by_headers` configured and no authenticated identity: the
        // storage path must still auto-Vary `cookie` so distinct sessions
        // never share one `public` entry, and the raw cookie value must be
        // SHA-256-hashed out of the key. (finding #15)
        let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

        let mut ctx = make_ctx("GET", "/dashboard");
        ctx.headers
            .insert("cookie".to_string(), "session=top-secret".to_string());
        let mut request_headers = ctx.headers.clone();
        let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
        assert!(matches!(result, PluginResult::Continue));

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"dashboard-body")
            .await;

        let cache_keys: Vec<String> = plugin
            .cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(cache_keys.len(), 1);
        let stored_key = &cache_keys[0];
        assert!(
            !stored_key.contains("top-secret"),
            "raw cookie leaked into cache key: {stored_key}"
        );
        assert!(
            stored_key.contains(CACHE_KEY_VARY_SEPARATOR),
            "cookie was not auto-varied into the cache key"
        );

        // A different session must not reach the stored entry.
        let mut other = make_ctx("GET", "/dashboard");
        other
            .headers
            .insert("cookie".to_string(), "session=other-secret".to_string());
        let mut other_headers = other.headers.clone();
        assert!(
            matches!(
                plugin.before_proxy(&mut other, &mut other_headers).await,
                PluginResult::Continue
            ),
            "a different session cookie must MISS, not replay"
        );
    }

    #[tokio::test]
    async fn authenticated_principal_keyed_into_base_key_without_consumer_flag() {
        // Default config (`cache_key_include_consumer: false`). An identity
        // authenticated by a non-`Authorization` scheme must still be bound
        // into the cache key (SHA-256-hashed), so a `public` per-user response
        // is never shared across principals. (finding #1)
        let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

        let mut ctx = make_ctx("GET", "/api/profile");
        ctx.authenticated_identity = Some("alice@example.com".to_string());
        let mut request_headers = ctx.headers.clone();
        plugin.before_proxy(&mut ctx, &mut request_headers).await;

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"alice-body")
            .await;

        let cache_keys: Vec<String> = plugin
            .cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(cache_keys.len(), 1);
        let stored_key = &cache_keys[0];
        assert!(
            !stored_key.contains("alice@example.com"),
            "raw identity leaked into cache key"
        );

        // A different principal on the same target must MISS: the caller
        // partition is bound unconditionally, without `cache_key_include_consumer`.
        let mut bob = make_ctx("GET", "/api/profile");
        bob.authenticated_identity = Some("bob@example.com".to_string());
        let mut bob_headers = bob.headers.clone();
        assert!(
            matches!(
                plugin.before_proxy(&mut bob, &mut bob_headers).await,
                PluginResult::Continue
            ),
            "a different principal must MISS, not replay"
        );
    }

    #[tokio::test]
    async fn vary_index_is_reclaimed_exactly_under_high_principal_cardinality() {
        // The caller partition gives each distinct identity its own base key,
        // and `vary_index` is keyed by base key. Reclamation is now exact:
        // a mapping is dropped the moment its last live variant is removed, so
        // `vary_index.len()` can never exceed the number of live base keys —
        // no heuristic slack, no full-cache prune sweep.
        let max_entries = 4;
        let plugin = plugin_with_config(json!({
            "ttl_seconds": 60,
            "max_entries": max_entries,
        }));

        let principals = 40;
        for i in 0..principals {
            let mut ctx = make_ctx("GET", "/api/profile");
            ctx.authenticated_identity = Some(format!("user-{i}"));
            ctx.headers
                .insert("cookie".to_string(), "session=shared".to_string());
            let mut request_headers = ctx.headers.clone();
            plugin.before_proxy(&mut ctx, &mut request_headers).await;

            let mut response_headers = HashMap::new();
            response_headers.insert(
                "cache-control".to_string(),
                "public, max-age=60".to_string(),
            );
            plugin
                .on_final_response_body(&mut ctx, 200, &response_headers, b"profile-body")
                .await;
        }

        assert_eq!(
            plugin.cache.len(),
            max_entries,
            "expected the cache pinned at max_entries; got {}",
            plugin.cache.len()
        );
        assert!(
            plugin.vary_index.len() <= plugin.cache.len(),
            "vary_index ({}) must never exceed the live base-key count ({})",
            plugin.vary_index.len(),
            plugin.cache.len()
        );
    }

    #[test]
    fn host_snapshot_values_are_not_marked_cache_key_ready() {
        assert!(!should_snapshot_header_value_as_cache_key_part("host"));
        assert!(!should_snapshot_header_value_as_cache_key_part("Host"));
        assert!(should_snapshot_header_value_as_cache_key_part("cookie"));
        assert!(should_snapshot_header_value_as_cache_key_part("x-api-key"));
    }

    #[test]
    fn encode_path_for_cache_key_passes_through_paths_without_colons() {
        let plain = encode_path_for_cache_key("/users/42/details");
        assert!(matches!(plain, Cow::Borrowed(_)));
        assert_eq!(plain.as_ref(), "/users/42/details");
    }

    #[test]
    fn encode_path_for_cache_key_percent_encodes_colons() {
        let encoded = encode_path_for_cache_key("/users:1/details");
        assert_eq!(encoded.as_ref(), "/users%3A1/details");
    }

    #[test]
    fn encode_path_for_cache_key_percent_encodes_literal_percent() {
        let encoded = encode_path_for_cache_key("/users%3A1/details");
        assert_eq!(encoded.as_ref(), "/users%253A1/details");
    }

    #[test]
    fn encode_path_for_cache_key_is_bijective_for_colon_and_percent_forms() {
        let colon = encode_path_for_cache_key("/users:1/details");
        let pct = encode_path_for_cache_key("/users%3A1/details");
        assert_ne!(colon.as_ref(), pct.as_ref());
    }

    #[tokio::test]
    async fn unsafe_method_invalidates_cached_path_containing_colon() {
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut get_ctx = make_ctx("GET", "/users:1/details");
        get_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut get_headers = get_ctx.headers.clone();
        plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
        plugin
            .on_final_response_body(&mut get_ctx, 200, &HashMap::new(), b"body")
            .await;
        assert_eq!(plugin.cache.len(), 1);

        let mut post_ctx = make_ctx("POST", "/users:1/details");
        post_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut post_headers = post_ctx.headers.clone();
        plugin.before_proxy(&mut post_ctx, &mut post_headers).await;
        assert_eq!(
            plugin.cache.len(),
            1,
            "unsafe method must not invalidate before a non-error response"
        );
        let mut resp_headers = HashMap::new();
        plugin
            .after_proxy(&mut post_ctx, 200, &mut resp_headers)
            .await;

        assert!(
            plugin.cache.is_empty(),
            "unsafe method on same colon-containing path should invalidate the cached entry"
        );
    }

    #[tokio::test]
    async fn unsafe_method_does_not_invalidate_unrelated_path_with_colon_prefix_clash() {
        // GET /users:1/details cached.
        // POST /users (unrelated) must NOT invalidate it.
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut get_ctx = make_ctx("GET", "/users:1/details");
        get_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut get_headers = get_ctx.headers.clone();
        plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
        plugin
            .on_final_response_body(&mut get_ctx, 200, &HashMap::new(), b"body")
            .await;
        assert_eq!(plugin.cache.len(), 1);

        let mut post_ctx = make_ctx("POST", "/users");
        post_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut post_headers = post_ctx.headers.clone();
        plugin.before_proxy(&mut post_ctx, &mut post_headers).await;
        let mut resp_headers = HashMap::new();
        plugin
            .after_proxy(&mut post_ctx, 200, &mut resp_headers)
            .await;

        assert_eq!(
            plugin.cache.len(),
            1,
            "unsafe method on unrelated /users must NOT invalidate /users:1/details"
        );
    }

    #[tokio::test]
    async fn cache_key_uses_transformed_headers_when_vary_header_modified_by_earlier_plugin() {
        // Regression test: when an earlier `before_proxy` plugin
        // (request_transformer-style) injects or rewrites a vary header,
        // the storage and lookup cache keys must agree on the
        // transformed value. Otherwise the cache stores under one key
        // and the next identical request looks up under another — every
        // request misses and entries pile up.
        let plugin = plugin_with_config(json!({
            "ttl_seconds": 60,
            "vary_by_headers": ["x-tenant"]
        }));

        let mut ctx = make_ctx("GET", "/api/items");
        ctx.headers
            .insert("host".to_string(), "example.com".to_string());
        // ctx.headers does NOT carry x-tenant — the originating request
        // doesn't have it.
        let mut transformed_headers = ctx.headers.clone();
        // Simulate a request_transformer injecting the vary header.
        transformed_headers.insert("x-tenant".to_string(), "acme".to_string());

        let result = plugin
            .before_proxy(&mut ctx, &mut transformed_headers)
            .await;
        assert!(matches!(result, PluginResult::Continue));

        let predict_key = ctx
            .metadata
            .get(&plugin.meta_predict_key)
            .expect("predict_key stored")
            .clone();
        // The key is an opaque digest, so the binding is proven by behavior:
        // the same request without the injected tenant must derive a different
        // key (asserted below against the stored key).
        let baseline = {
            let mut plain_ctx = make_ctx("GET", "/api/items");
            let mut plain_headers = plain_ctx.headers.clone();
            plugin
                .before_proxy(&mut plain_ctx, &mut plain_headers)
                .await;
            plain_ctx
                .metadata
                .get(&plugin.meta_predict_key)
                .expect("predict_key stored")
                .clone()
        };
        assert_ne!(
            predict_key, baseline,
            "lookup key must carry the transformer-injected tenant"
        );

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"tenant-acme")
            .await;

        let cache_keys: Vec<String> = plugin.cache.iter().map(|e| e.key().clone()).collect();
        assert_eq!(cache_keys.len(), 1);
        assert_eq!(
            predict_key, cache_keys[0],
            "lookup and storage keys must be identical when no Vary \
             header is added by the response"
        );
    }

    #[tokio::test]
    async fn origin_vary_uses_complete_backend_visible_header_view() {
        // The origin can name a header the operator did not preconfigure in
        // `vary_by_headers`. Storage must still use the transformed value sent
        // upstream, never the original client value retained in `ctx.headers`.
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut store_ctx = make_ctx("GET", "/api/origin-vary");
        store_ctx
            .headers
            .insert("x-origin-vary".to_string(), "client-a".to_string());
        let mut store_headers = store_ctx.headers.clone();
        store_headers.insert("x-origin-vary".to_string(), "backend-tenant-a".to_string());
        assert!(matches!(
            plugin
                .before_proxy(&mut store_ctx, &mut store_headers)
                .await,
            PluginResult::Continue
        ));

        let response_headers = HashMap::from([
            (
                "cache-control".to_string(),
                "public, max-age=60".to_string(),
            ),
            ("vary".to_string(), "X-Origin-Vary".to_string()),
        ]);
        plugin
            .on_final_response_body(&mut store_ctx, 200, &response_headers, b"tenant-a-response")
            .await;

        // If storage incorrectly used the original `client-a` value, this
        // request would replay tenant A even though its backend-visible value
        // belongs to a different partition.
        let mut cross_ctx = make_ctx("GET", "/api/origin-vary");
        cross_ctx
            .headers
            .insert("x-origin-vary".to_string(), "different-client".to_string());
        let mut cross_headers = cross_ctx.headers.clone();
        cross_headers.insert("x-origin-vary".to_string(), "client-a".to_string());
        assert!(
            matches!(
                plugin
                    .before_proxy(&mut cross_ctx, &mut cross_headers)
                    .await,
                PluginResult::Continue
            ),
            "a transformed value matching another request's original value must not cross-hit"
        );

        let mut hit_ctx = make_ctx("GET", "/api/origin-vary");
        hit_ctx
            .headers
            .insert("x-origin-vary".to_string(), "third-client".to_string());
        let mut hit_headers = hit_ctx.headers.clone();
        hit_headers.insert("x-origin-vary".to_string(), "backend-tenant-a".to_string());
        let hit = plugin.before_proxy(&mut hit_ctx, &mut hit_headers).await;
        assert!(
            matches!(
                hit,
                PluginResult::RejectBinary {
                    status_code: 200,
                    ref body,
                    ..
                } if body.as_ref() == b"tenant-a-response"
            ),
            "the same backend-visible value must select the stored representation"
        );
    }

    #[tokio::test]
    async fn cache_key_uses_transformed_host_header_when_rewritten_by_earlier_plugin() {
        // Equivalent regression for the `Host` rewrite case. The base
        // cache key hashes the Host value; if the lookup uses the
        // transformed Host and storage uses the original, the cache
        // permanently misses across requests that share the same path.
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut ctx = make_ctx("GET", "/api/items");
        ctx.headers
            .insert("host".to_string(), "client.example.com".to_string());
        let mut transformed_headers = ctx.headers.clone();
        transformed_headers.insert("host".to_string(), "backend.internal".to_string());

        let result = plugin
            .before_proxy(&mut ctx, &mut transformed_headers)
            .await;
        assert!(matches!(result, PluginResult::Continue));
        let predict_key = ctx
            .metadata
            .get(&plugin.meta_predict_key)
            .expect("predict_key stored")
            .clone();

        plugin
            .on_final_response_body(&mut ctx, 200, &HashMap::new(), b"host-acme")
            .await;

        let cache_keys: Vec<String> = plugin.cache.iter().map(|e| e.key().clone()).collect();
        assert_eq!(cache_keys.len(), 1);
        assert_eq!(
            predict_key, cache_keys[0],
            "lookup and storage cache keys must be identical when Host \
             is rewritten by an earlier before_proxy plugin"
        );
    }

    #[tokio::test]
    async fn unsafe_method_invalidates_cached_hosts_with_ports_and_ipv6_literals() {
        for host in ["Example.com:8443", "[::1]:8443"] {
            let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

            let mut get_ctx = make_ctx("GET", "/api/items");
            get_ctx.headers.insert("host".to_string(), host.to_string());
            let mut get_headers = get_ctx.headers.clone();
            plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
            plugin
                .on_final_response_body(&mut get_ctx, 200, &HashMap::new(), b"cached-items")
                .await;

            let cache_keys: Vec<String> = plugin
                .cache
                .iter()
                .map(|entry| entry.key().clone())
                .collect();
            assert_eq!(cache_keys.len(), 1);
            assert!(!cache_keys[0].contains(host));

            let mut post_ctx = make_ctx("POST", "/api/items");
            post_ctx
                .headers
                .insert("host".to_string(), host.to_string());
            let mut post_headers = post_ctx.headers.clone();
            plugin.before_proxy(&mut post_ctx, &mut post_headers).await;
            let mut resp_headers = HashMap::new();
            plugin
                .after_proxy(&mut post_ctx, 200, &mut resp_headers)
                .await;

            assert!(
                plugin.cache.is_empty(),
                "unsafe method should invalidate cached key for host {host}"
            );
        }
    }
}
