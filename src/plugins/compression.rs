//! Compression plugin — compresses response bodies and decompresses request bodies.
//!
//! Supports gzip and brotli algorithms. Response compression is negotiated via
//! the client's `Accept-Encoding` header (RFC 9110 §12.5.3). Request
//! decompression is opt-in: when enabled, `Content-Encoding` is parsed as an
//! ordered coding list (OWS-tolerant), supported chains are decoded in reverse
//! application order under per-layer/cumulative/amplification limits, and
//! malformed or unsupported members fail closed. Decoding runs in the shared
//! pre-`before_proxy` normalization phase so earlier body consumers (for
//! example `soap_ws_security`) inspect validated plaintext. The same plaintext
//! is forwarded to the backend after encoding/length headers are stripped only
//! on successful decode. Rare buffered fallback paths that strip headers without
//! a mutable body view stage the validated plaintext onto the request context
//! so the later transform emits those bytes instead of re-decoding.
//!
//! Gzip/Brotli codec CPU runs on a bounded `spawn_blocking` pool guarded by an
//! admission semaphore so Tokio workers are not monopolized. Queue saturation
//! and worker-join failures are exported on the authenticated Prometheus
//! `/metrics` surface. When a committed gateway `Content-Encoding` cannot be
//! produced, shared H1/H2/H3 buffered transforms restore an identity response
//! with matching headers rather than emitting a mislabeled body.
//!
//! Response compression reserves separate buffer admission in `before_proxy`,
//! ahead of the response-buffer decision, while codec admission is acquired only
//! immediately before CPU work. This bounds collected bodies without allowing
//! slow backend requests to starve request decompression. A request that
//! negotiates a supported coding but cannot obtain a bounded permit streams
//! identity instead of pinning a (possibly unbounded) body onto the
//! compression-only buffered path; `after_proxy` consumes the reserved permit
//! and never reacquires once a streaming/identity path is chosen, failing closed
//! with 406 only when identity is prohibited. The buffer permit is held across
//! the encode (the collected body stays resident), while the codec permit is
//! taken only for the `spawn_blocking` worker itself; codec saturation there
//! aborts the encode and the shared transform loops restore identity when
//! acceptable or replace with 406 when identity was refused. When one instance
//! declines to encode an already-admitted body it clears ownership but leaves
//! the buffer permit on the context so a later sibling can take the same slot.
//! Response compression is also disabled when the gateway response-body limit is
//! unlimited or exceeds the 32 MiB compression safety ceiling, so every body
//! admitted to compression buffering has a hard per-response byte bound.
//!
//! Multiple effective instances compose with first-wins ownership: one instance
//! owns request decode and one owns response encode per request so Content-
//! Encoding stays 1:1 with body coding layers across the shared H1/H2/H3
//! transform loops.
//!
//! Modeled after Envoy's compressor filter: content-type whitelist, minimum
//! content length, ETag awareness, no double-compression, and `Vary` header
//! injection.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, warn};

use crate::util::http_headers::{headers_have_cache_control_directive, headers_have_strong_etag};
use crate::util::unknown_keys::reject_unknown_keys;

use super::utils::content_encoding::{
    DecodeLimits, decode_content_encoding, parse_content_codings,
};
use super::{Plugin, PluginResult, RequestContext};

/// Accepted top-level `compression` config keys.
///
/// Constructor admission, OpenAPI `CompressionConfig` (`additionalProperties:
/// false`), and operator docs must stay in lockstep with this list.
pub const COMPRESSION_CONFIG_KEYS: &[&str] = &[
    "algorithms",
    "brotli_quality",
    "content_types",
    "decompress_request",
    "gzip_level",
    "max_decompressed_request_size",
    "min_content_length",
    "remove_accept_encoding",
];

/// Deployment-safe hard ceiling for `max_decompressed_request_size` (32 MiB).
///
/// Configuration above this value is rejected. The effective limit is further
/// capped by `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` when that wire limit is set.
pub const HARD_MAX_DECOMPRESSED_REQUEST_SIZE: usize = 32 * 1024 * 1024;

/// Response fields `after_proxy` owns, in the bounded form
/// `Plugin::response_trailer_policy` hands to the plugin cache. Built once per
/// process; never allocated per request.
static COMPRESSION_RESPONSE_POLICY_NAMES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        vec![
            "content-encoding".to_string(),
            "content-length".to_string(),
            "vary".to_string(),
        ]
    });

/// Default `max_decompressed_request_size` (10 MiB).
const DEFAULT_MAX_DECOMPRESSED_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Hard ceiling for a response that compression may force onto the buffered
/// path. The shared response collector enforces the configured gateway limit;
/// compression is disabled when that limit is `0` (unlimited) or above this
/// ceiling so the plugin cannot introduce an unbounded full-body allocation.
pub const HARD_MAX_COMPRESSIBLE_RESPONSE_SIZE: usize = 32 * 1024 * 1024;

/// Maximum stacked request content-coding layers decoded for one upload.
const REQUEST_DECODE_MAX_CODINGS: usize = 4;

/// Abort early when a decoded layer (or the final plaintext) expands more than
/// this multiple of its coded input. Absolute size caps still apply.
const MAX_RAW_TO_DECODED_AMPLIFICATION_RATIO: u32 = 1024;

/// Maximum concurrent gzip/Brotli codec jobs across all compression instances.
pub const MAX_CONCURRENT_CODEC_JOBS: usize = 32;

/// Maximum concurrent response bodies admitted onto the compression buffered
/// path. Independent of [`MAX_CONCURRENT_CODEC_JOBS`] so operators can reason
/// about retained-body population separately from codec CPU concurrency; the
/// values match today but must not share a single constant (changing one budget
/// must not silently resize the other).
pub const MAX_CONCURRENT_RESPONSE_BUFFERS: usize = 32;

static NEXT_COMPRESSION_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
static CODEC_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_CODEC_JOBS)));
// Response buffering is admitted separately from codec CPU work. A client may
// hold this permit while the backend is slow, so sharing it with CODEC_BUDGET
// would let network latency starve unrelated request decompression.
static RESPONSE_BUFFER_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_RESPONSE_BUFFERS)));
static CODEC_ADMITTED: AtomicU64 = AtomicU64::new(0);
static CODEC_SATURATED: AtomicU64 = AtomicU64::new(0);
static RESPONSE_BUFFER_ADMITTED: AtomicU64 = AtomicU64::new(0);
static RESPONSE_BUFFER_SATURATED: AtomicU64 = AtomicU64::new(0);
static CODEC_JOIN_FAILURES: AtomicU64 = AtomicU64::new(0);
static CODEC_WORKER_FAILURES: AtomicU64 = AtomicU64::new(0);

tokio::task_local! {
    /// Test-only injected codec budget. When set, admission uses this semaphore
    /// instead of the process-global pool so saturation tests cannot starve
    /// unrelated parallel codec work.
    static TEST_CODEC_BUDGET: Arc<Semaphore>;
    /// Test-only injected response-buffer budget, for the same isolation reason
    /// as `TEST_CODEC_BUDGET`. The two seams nest so a test can pin buffer
    /// admission and codec CPU admission independently.
    static TEST_RESPONSE_BUFFER_BUDGET: Arc<Semaphore>;
}

/// Run `f` with an isolated response-buffer admission budget of `permits` slots.
#[allow(dead_code)]
pub async fn with_test_response_buffer_budget<F, Fut, T>(permits: usize, f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let budget = Arc::new(Semaphore::new(permits));
    TEST_RESPONSE_BUFFER_BUDGET.scope(budget, f()).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Gzip,
    Brotli,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.content_encoding())
    }
}

impl Algorithm {
    fn content_encoding(&self) -> &'static str {
        match self {
            Algorithm::Gzip => "gzip",
            Algorithm::Brotli => "br",
        }
    }
}

/// Outcome of `Accept-Encoding` negotiation for one response (RFC 9110
/// §12.5.3). Compared against every representation Ferrum can produce —
/// each configured algorithm and the uncoded (identity) representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodingSelection {
    /// Compress the backend's identity response with the selected algorithm.
    Compress(Algorithm),
    /// Send the representation without a content coding: identity is the
    /// most preferred acceptable representation, or the only acceptable one.
    Identity,
    /// Every available representation, including identity, has quality zero —
    /// the client refused all of them (for example `identity;q=0` combined
    /// with `gzip;q=0, br;q=0`, or `*;q=0` without an identity override).
    NotAcceptable,
}

/// Default MIME types eligible for compression (matches Envoy's defaults + common API types).
const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
    "text/html",
    "text/plain",
    "text/css",
    "text/xml",
    "text/javascript",
    "image/svg+xml",
];

/// HTTP status codes that should never be compressed (no body or cache-only).
///
/// Includes `205 Reset Content` (RFC 9110 §15.3.6 forbids response content)
/// alongside the classic `204` / `304` no-body statuses.
const UNCOMPRESSIBLE_STATUS_CODES: &[u16] = &[204, 205, 304];

const REJECTION_RESPONSE_METADATA_KEY: &str = "ferrum:rejection_response";
const REQUEST_NO_TRANSFORM_METADATA_KEY: &str = "compression:request_no_transform";
const RESPONSE_ALGORITHM_METADATA_KEY: &str = "compression:algorithm";

/// The client's original `Accept-Encoding`, saved in `before_proxy` before
/// `remove_accept_encoding` can strip it from the backend-bound request.
///
/// Response-side readers must prefer this over `ctx.headers["accept-encoding"]`:
/// the `before_proxy` header map *is* `ctx.headers` (taken and restored around
/// the hook), so a strip here is visible to every later phase, and only this
/// snapshot still describes what the client actually negotiated.
pub(crate) const REQUEST_ACCEPT_ENCODING_METADATA_KEY: &str = "compression:accept_encoding";

/// Set when configured request decompression replaced the buffered body with
/// validated plaintext before `before_proxy`. Later transforms must not decode
/// again; the backend already receives the normalized bytes.
pub(crate) const REQUEST_DECODED_METADATA_KEY: &str = "compression:request_decoded";
const NOT_ACCEPTABLE_RESPONSE_BODY: &str = "{\"error\":\"not acceptable: no available content coding matches the request Accept-Encoding\"}";

/// Process-wide compression codec admission metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionCodecMetrics {
    pub admitted: u64,
    pub saturated: u64,
    pub join_failures: u64,
    pub worker_failures: u64,
    /// Response-buffer admissions granted (independent of codec CPU admission).
    pub response_buffer_admitted: u64,
    /// Response-buffer admission refusals when the buffer budget is saturated.
    pub response_buffer_saturated: u64,
}

/// Snapshot process-wide codec admission counters (also scraped via Prometheus).
pub fn compression_codec_metrics() -> CompressionCodecMetrics {
    CompressionCodecMetrics {
        admitted: CODEC_ADMITTED.load(Ordering::Relaxed),
        saturated: CODEC_SATURATED.load(Ordering::Relaxed),
        join_failures: CODEC_JOIN_FAILURES.load(Ordering::Relaxed),
        worker_failures: CODEC_WORKER_FAILURES.load(Ordering::Relaxed),
        response_buffer_admitted: RESPONSE_BUFFER_ADMITTED.load(Ordering::Relaxed),
        response_buffer_saturated: RESPONSE_BUFFER_SATURATED.load(Ordering::Relaxed),
    }
}

/// Run `f` with an isolated codec admission budget of `permits` slots.
///
/// Saturation tests must use this seam instead of draining the process-global
/// semaphore, which would nondeterministically force unrelated parallel codec
/// work onto 503/identity paths.
#[allow(dead_code)]
pub async fn with_test_codec_budget<F, Fut, T>(permits: usize, f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let budget = Arc::new(Semaphore::new(permits));
    TEST_CODEC_BUDGET.scope(budget, f()).await
}

fn active_codec_budget() -> Arc<Semaphore> {
    TEST_CODEC_BUDGET
        .try_with(Arc::clone)
        .unwrap_or_else(|_| Arc::clone(&CODEC_BUDGET))
}

fn try_acquire_codec_permit() -> Result<OwnedSemaphorePermit, ()> {
    match active_codec_budget().try_acquire_owned() {
        Ok(permit) => {
            CODEC_ADMITTED.fetch_add(1, Ordering::Relaxed);
            Ok(permit)
        }
        Err(_) => {
            CODEC_SATURATED.fetch_add(1, Ordering::Relaxed);
            Err(())
        }
    }
}

fn try_acquire_response_buffer_permit() -> Result<OwnedSemaphorePermit, ()> {
    let budget = TEST_RESPONSE_BUFFER_BUDGET
        .try_with(Arc::clone)
        .unwrap_or_else(|_| Arc::clone(&RESPONSE_BUFFER_BUDGET));
    match budget.try_acquire_owned() {
        Ok(permit) => {
            RESPONSE_BUFFER_ADMITTED.fetch_add(1, Ordering::Relaxed);
            Ok(permit)
        }
        Err(_) => {
            RESPONSE_BUFFER_SATURATED.fetch_add(1, Ordering::Relaxed);
            Err(())
        }
    }
}

/// Recover when a committed gateway content coding cannot be produced. Shared
/// H1/H2/H3 buffered transform loops call this after a transform returns `None`.
/// Identity-acceptable requests regain matching identity headers; requests that
/// excluded identity become a terminal 406. Returns `true` for that terminal
/// replacement so callers stop later transforms/final-body hooks.
pub(crate) fn reconcile_aborted_gateway_response_encoding(
    ctx: &mut RequestContext,
    response_status: &mut u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut bytes::Bytes,
) -> bool {
    if !ctx.take_compression_response_encode_aborted() {
        return false;
    }
    ctx.metadata.remove(RESPONSE_ALGORITHM_METADATA_KEY);
    ctx.clear_gateway_response_compression();
    let identity_unacceptable = ctx
        .metadata
        .get(REQUEST_ACCEPT_ENCODING_METADATA_KEY)
        .is_some_and(|value| identity_coding_quality(value) == 0.0);
    if identity_unacceptable {
        *response_status = 406;
        response_headers.clear();
        response_headers.insert("content-type".to_string(), "application/json".to_string());
        ensure_vary_accept_encoding(response_headers);
        *response_body = bytes::Bytes::from_static(NOT_ACCEPTABLE_RESPONSE_BODY.as_bytes());
        response_headers.insert(
            "content-length".to_string(),
            response_body.len().to_string(),
        );
        warn!(
            "compression: replaced failed gateway content coding with 406 because identity is unacceptable"
        );
        return true;
    }
    response_headers.remove("content-encoding");
    response_headers.insert(
        "content-length".to_string(),
        response_body.len().to_string(),
    );
    warn!(
        "compression: restored identity response after failed gateway content coding \
         (body_len={})",
        response_body.len()
    );
    false
}

struct CompressionConfig {
    /// Enabled algorithms in server-preference order (used to break q-value ties).
    algorithms: Vec<Algorithm>,
    /// Process-wide codec gates. These apply to response compression and
    /// opt-in request decompression.
    gzip_enabled: bool,
    brotli_enabled: bool,

    // -- Response compression --
    min_content_length: usize,
    content_types: Vec<String>,
    /// Remove `Accept-Encoding` from the backend request so the backend always
    /// sends an uncompressed response for us to compress.
    remove_accept_encoding: bool,

    // -- Request decompression --
    decompress_request: bool,
    /// Zip-bomb protection: reject decompressed request bodies exceeding this.
    max_decompressed_request_size: usize,

    // -- Algorithm tuning --
    gzip_level: u32,
    brotli_quality: u32,
}

pub struct CompressionPlugin {
    config: CompressionConfig,
    /// Process-unique id for multi-instance ownership tokens.
    instance_id: u64,
}

impl CompressionPlugin {
    // Public for the library and external integration tests; the binary target
    // compiles this module independently and does not construct it directly.
    #[allow(dead_code)]
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_algorithm_support_and_body_limit(config, true, true, 0)
    }

    /// Construct a compression plugin under the process-wide codec policy.
    ///
    /// The configured `algorithms` order remains the per-instance response
    /// preference, while disabled codecs are removed before the instance is
    /// published. Request decompression observes the same gates.
    #[allow(dead_code)]
    pub fn new_with_algorithm_support(
        config: &Value,
        gzip_enabled: bool,
        brotli_enabled: bool,
    ) -> Result<Self, String> {
        Self::new_with_algorithm_support_and_body_limit(config, gzip_enabled, brotli_enabled, 0)
    }

    /// Construct under process-wide codec gates and the gateway request-body
    /// ceiling used to cross-check `max_decompressed_request_size`.
    pub fn new_with_algorithm_support_and_body_limit(
        config: &Value,
        gzip_enabled: bool,
        brotli_enabled: bool,
        max_request_body_size_bytes: usize,
    ) -> Result<Self, String> {
        let default_config = Value::Object(serde_json::Map::new());
        let config = if config.is_null() {
            &default_config
        } else if config.is_object() {
            config
        } else {
            return Err("compression: config must be an object".to_string());
        };

        // Removed keys keep their dedicated diagnostic ahead of the generic
        // unknown-key gate so operators still see an explicit migration hint.
        if config.get("disable_on_etag").is_some() {
            return Err(
                "compression: 'disable_on_etag' has been removed; strong ETag responses are always preserved"
                    .to_string(),
            );
        }

        let config_object = config
            .as_object()
            .ok_or_else(|| "compression: config must be an object".to_string())?;
        reject_unknown_keys(
            config_object,
            "config",
            COMPRESSION_CONFIG_KEYS,
            "compression: ",
        )?;

        // Parse `algorithms` strictly. Unknown values are rejected (no silent
        // skip) so configuration typos surface immediately at load time
        // instead of producing a partially-functional plugin.
        let mut algorithms: Vec<Algorithm> = match config.get("algorithms") {
            Some(Value::Array(arr)) => {
                let mut algos = Vec::with_capacity(arr.len());
                for (idx, v) in arr.iter().enumerate() {
                    match v.as_str() {
                        Some("gzip") => algos.push(Algorithm::Gzip),
                        Some("br") | Some("brotli") => algos.push(Algorithm::Brotli),
                        Some(other) => {
                            return Err(format!(
                                "compression: algorithms[{idx}]: unknown algorithm '{other}' (expected 'gzip' or 'br')"
                            ));
                        }
                        None => {
                            return Err(format!("compression: algorithms[{idx}] must be a string"));
                        }
                    }
                }
                algos
            }
            Some(Value::Null) | None => vec![Algorithm::Gzip, Algorithm::Brotli],
            Some(_) => {
                return Err("compression: 'algorithms' must be an array of strings".to_string());
            }
        };
        if algorithms.is_empty() {
            return Err(
                "compression: no valid algorithms configured — plugin will have no effect"
                    .to_string(),
            );
        }
        algorithms.retain(|algorithm| match algorithm {
            Algorithm::Gzip => gzip_enabled,
            Algorithm::Brotli => brotli_enabled,
        });
        // Revalidate after process-wide gates so an instance with no usable
        // codec fails admission instead of remaining effectful-but-inert.
        if algorithms.is_empty() {
            return Err(
                "compression: no usable algorithms after applying process-wide codec gates — plugin would have no effect"
                    .to_string(),
            );
        }

        let content_types = parse_content_types(config)?;

        let min_content_length = optional_usize(config, "min_content_length")?.unwrap_or(256);

        let remove_accept_encoding =
            optional_bool(config, "remove_accept_encoding")?.unwrap_or(true);

        let decompress_request = optional_bool(config, "decompress_request")?.unwrap_or(false);

        let configured_max_decompressed_request_size =
            optional_positive_usize(config, "max_decompressed_request_size")?
                .unwrap_or(DEFAULT_MAX_DECOMPRESSED_REQUEST_SIZE);
        // Preserve strict field/hard-cap validation even when request
        // decompression is disabled, but do not reject a response-only plugin
        // because an unused decompression default exceeds the wire-body limit.
        let decompression_body_limit = if decompress_request {
            max_request_body_size_bytes
        } else {
            0
        };
        let max_decompressed_request_size = resolve_max_decompressed_request_size(
            configured_max_decompressed_request_size,
            decompression_body_limit,
        )?;

        let gzip_level = optional_u64(config, "gzip_level")?
            .map(|value| {
                if value > 9 {
                    Err("compression: 'gzip_level' must be between 0 and 9".to_string())
                } else {
                    Ok(value as u32)
                }
            })
            .transpose()?
            .unwrap_or(6);

        let brotli_quality = optional_u64(config, "brotli_quality")?
            .map(|value| {
                if value > 11 {
                    Err("compression: 'brotli_quality' must be between 0 and 11".to_string())
                } else {
                    Ok(value as u32)
                }
            })
            .transpose()?
            .unwrap_or(4);

        let instance_id = NEXT_COMPRESSION_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            config: CompressionConfig {
                algorithms,
                gzip_enabled,
                brotli_enabled,
                min_content_length,
                content_types,
                remove_accept_encoding,
                decompress_request,
                max_decompressed_request_size,
                gzip_level,
                brotli_quality,
            },
            instance_id,
        })
    }

    fn has_response_codec(&self) -> bool {
        !self.config.algorithms.is_empty()
    }

    fn request_decode_limits(&self, route_limit: Option<usize>) -> DecodeLimits {
        // The construction-time ceiling is already folded with the active
        // process-wide request-body limit. Narrow it once more for the matched
        // route so compressed bytes cannot inflate and retain plaintext above
        // a stricter request_size_limiting policy before the final body hook
        // gets a chance to reject it.
        let max_decoded_bytes = route_limit
            .filter(|limit| *limit > 0)
            .map_or(self.config.max_decompressed_request_size, |limit| {
                self.config.max_decompressed_request_size.min(limit)
            });
        DecodeLimits {
            max_decoded_bytes,
            max_cumulative_bytes: max_decoded_bytes,
            max_codings: REQUEST_DECODE_MAX_CODINGS,
            max_amplification_ratio: MAX_RAW_TO_DECODED_AMPLIFICATION_RATIO,
        }
    }

    /// Classify a request `Content-Encoding` value under the configured codec
    /// gates. Fail closed on malformed/unsupported lists when decompression is
    /// enabled; identity-only lists need no body rewrite.
    fn classify_request_content_encoding(&self, value: &str) -> Result<RequestCodingPlan, String> {
        let codings = parse_content_codings(value)?;
        if codings.len() > REQUEST_DECODE_MAX_CODINGS {
            return Err(format!(
                "content-encoding has more than {REQUEST_DECODE_MAX_CODINGS} coding layers"
            ));
        }
        if codings.iter().all(|coding| coding == "identity") {
            return Ok(RequestCodingPlan::IdentityOnly);
        }
        if codings.iter().any(|coding| coding == "identity") {
            return Err(
                "identity content-encoding cannot be combined with other codings".to_string(),
            );
        }
        for coding in &codings {
            match coding.as_str() {
                "gzip" if self.config.gzip_enabled => {}
                "br" if self.config.brotli_enabled => {}
                "gzip" => return Err("unsupported content-encoding 'gzip'".to_string()),
                "br" => return Err("unsupported content-encoding 'br'".to_string()),
                other => return Err(format!("unsupported content-encoding '{other}'")),
            }
        }
        // Preserve the original member spelling only for the single-coding case
        // used by legacy observability markers; chains record the full list.
        let marker = if codings.len() == 1 {
            codings[0].clone()
        } else {
            codings.join(", ")
        };
        Ok(RequestCodingPlan::Decode(marker))
    }

    fn is_request_decode_owner(&self, ctx: &RequestContext) -> bool {
        ctx.owns_compression_request_decode(self.instance_id)
    }

    fn is_response_encode_owner(&self, ctx: &RequestContext) -> bool {
        ctx.owns_compression_response_encode(self.instance_id)
    }

    /// Validate/decode a supported request coding list, claim ownership, and
    /// strip public encoding metadata only after success.
    ///
    /// When `body` is provided (pre-`before_proxy` normalization), successful
    /// decode replaces it with plaintext so later `before_proxy` consumers see
    /// the same bytes the backend will receive. When `body` is `None`, this
    /// validates `ctx.request_body_bytes` (legacy buffered `before_proxy` path /
    /// rare unbuffered fallback), stages the validated plaintext on the request
    /// context, and strips encoding headers only after that staging so a later
    /// transform can emit the plaintext without re-acquiring the codec budget.
    async fn try_claim_and_decode_request(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        body: Option<&mut Vec<u8>>,
    ) -> PluginResult {
        if !self.config.decompress_request || ctx.has_compression_request_decode_owner() {
            return PluginResult::Continue;
        }
        let Some(ce) = headers.get("content-encoding").cloned() else {
            return PluginResult::Continue;
        };

        let plan = match self.classify_request_content_encoding(&ce) {
            Ok(plan) => plan,
            Err(e) => {
                warn!("compression: rejecting request with invalid Content-Encoding '{ce}': {e}");
                return PluginResult::Reject {
                    status_code: 400,
                    body: r#"{"error":"Malformed or unsupported Content-Encoding"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        match plan {
            RequestCodingPlan::IdentityOnly => {
                let claimed = ctx.claim_compression_request_decode(self.instance_id);
                debug_assert!(
                    claimed,
                    "request decode owner changed within a sequential hook chain"
                );
                ctx.metadata.insert(
                    "compression:request_encoding".to_string(),
                    "identity".to_string(),
                );
                headers.remove("content-encoding");
                headers.insert(
                    "x-ferrum-original-content-encoding".to_string(),
                    "identity".to_string(),
                );
                headers.remove("content-length");
                PluginResult::Continue
            }
            RequestCodingPlan::Decode(marker) => {
                let decode_source: Option<Vec<u8>> = if let Some(body) = body.as_deref() {
                    Some(body.to_vec())
                } else {
                    ctx.request_body_bytes.as_ref().map(|bytes| bytes.to_vec())
                };
                let Some(decode_source) = decode_source else {
                    // Unbuffered path (e.g. HBONE CONNECT): without a rejectable body
                    // view, decompression cannot safely strip representation metadata.
                    // Preserve both bytes and headers unchanged for the backend.
                    return PluginResult::Continue;
                };

                if decode_source.is_empty() {
                    warn!("compression: rejecting request with empty compressed body ({marker})");
                    return PluginResult::Reject {
                        status_code: 400,
                        body: r#"{"error":"Malformed compressed request body"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }

                let Ok(permit) = try_acquire_codec_permit() else {
                    warn!("compression: codec admission saturated while decoding request body");
                    return PluginResult::Reject {
                        status_code: 503,
                        body: r#"{"error":"Compression workers unavailable"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                };

                let limits = self.request_decode_limits(ctx.route_request_body_limit());
                let header_for_decode = ce.clone();
                let decode_result = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    decode_content_encoding(
                        Some(header_for_decode.as_str()),
                        &decode_source,
                        limits,
                    )
                    .map(|decoded| decoded.into_owned())
                })
                .await;

                let decompressed = match decode_result {
                    Ok(Ok(plain)) => plain,
                    Ok(Err(e)) => {
                        CODEC_WORKER_FAILURES.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "compression: rejecting request with undecodable Content-Encoding '{ce}': {e}"
                        );
                        return PluginResult::Reject {
                            status_code: 400,
                            body: r#"{"error":"Malformed compressed request body"}"#.to_string(),
                            headers: HashMap::new(),
                        };
                    }
                    Err(_) => {
                        CODEC_JOIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                        warn!("compression: request decode worker join failed");
                        return PluginResult::Reject {
                            status_code: 503,
                            body: r#"{"error":"Compression workers unavailable"}"#.to_string(),
                            headers: HashMap::new(),
                        };
                    }
                };

                let claimed = ctx.claim_compression_request_decode(self.instance_id);
                debug_assert!(
                    claimed,
                    "request decode owner changed within a sequential hook chain"
                );
                ctx.metadata
                    .insert("compression:request_encoding".to_string(), marker.clone());
                headers.remove("content-encoding");
                headers.insert(
                    "x-ferrum-original-content-encoding".to_string(),
                    marker.clone(),
                );
                headers.remove("content-length");

                if let Some(body) = body {
                    debug!(
                        "compression: normalized request body from {} to {} bytes ({})",
                        body.len(),
                        decompressed.len(),
                        marker
                    );
                    *body = decompressed;
                } else {
                    // Fallback path: headers are stripped only after staging the
                    // validated plaintext for the later body transform.
                    debug!(
                        "compression: staged decoded request body ({} bytes, {}) for transform handoff",
                        decompressed.len(),
                        marker
                    );
                    ctx.set_compression_staged_request_plaintext(decompressed);
                }
                ctx.metadata
                    .insert(REQUEST_DECODED_METADATA_KEY.to_string(), marker);

                PluginResult::Continue
            }
        }
    }

    /// Parse `Accept-Encoding` and negotiate the representation coding among
    /// the configured algorithms and `identity` (RFC 9110 §12.5.3).
    ///
    /// Selection: highest q-value wins across every representation Ferrum can
    /// produce, including the uncoded (identity) representation. Ties are
    /// broken by server preference order (the `algorithms` config array), so
    /// an algorithm tied with identity still compresses. Wildcard `*` matches
    /// every *configured algorithm* not explicitly listed at whatever q-value
    /// `*` carries, and a more specific algorithm entry takes precedence — so
    /// an explicit `gzip;q=0` excludes gzip even when `*` is present with
    /// `q>0`.
    ///
    /// Identity is special per RFC 9110 §12.5.3 and is ranked via
    /// [`identity_coding_quality`]: acceptable by default at q=1; a nonzero
    /// wildcard does **not** lower that default; only `identity;q=0` or
    /// `*;q=0` without a more-specific identity entry makes identity
    /// unacceptable. An unlisted configured algorithm is instead unacceptable
    /// (q=0) unless the wildcard assigns it a quality.
    ///
    /// This is a two-pass parse rather than a single fused loop: pass 1 records
    /// each codec's explicit q-value (when its exact token appears, capturing
    /// `q=0` refusals) and the wildcard q-value; pass 2 resolves each
    /// candidate's effective q (explicit wins over wildcard), compares it
    /// against identity's effective q, and applies the `q <= 0`
    /// not-acceptable gate and the highest-q / server-preference tie-break.
    fn select_algorithm(&self, accept_encoding: &str) -> CodingSelection {
        // Pass 1: scan every token once, recording the explicit q-value for
        // each configured codec and the wildcard q-value. `None` means "no
        // explicit entry for this codec". Later duplicate algorithm/wildcard
        // tokens overwrite earlier ones (last value wins), matching the
        // previous single-loop behaviour. Identity duplicates are handled by
        // [`identity_coding_quality`] (first identity entry wins).
        let mut explicit_gzip: Option<f32> = None;
        let mut explicit_br: Option<f32> = None;
        let mut wildcard: Option<f32> = None;

        for part in accept_encoding.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let encoding = part.split(';').next().unwrap_or("").trim();
            let Some(quality) = rfc9110_entry_quality(part) else {
                // Malformed qvalues do not express a usable preference or a
                // refusal. Ignore the member and keep evaluating the field.
                continue;
            };
            if encoding.eq_ignore_ascii_case("gzip") || encoding.eq_ignore_ascii_case("x-gzip") {
                explicit_gzip = Some(quality);
            } else if encoding.eq_ignore_ascii_case("br") {
                explicit_br = Some(quality);
            } else if encoding == "*" {
                wildcard = Some(quality);
            }
        }

        let identity_q = identity_coding_quality(accept_encoding);

        // Pass 2: resolve each configured algorithm's effective q (its explicit
        // entry wins over the wildcard; unlisted without wildcard means
        // unacceptable) and pick the best one.
        let mut best: Option<(Algorithm, f32, usize)> = None; // (algo, q, server_pref_index)
        for (pref_idx, &algo) in self.config.algorithms.iter().enumerate() {
            let explicit = match algo {
                Algorithm::Gzip => explicit_gzip,
                Algorithm::Brotli => explicit_br,
            };
            // Explicit entry takes precedence over the wildcard fallback.
            let effective_q = explicit.or(wildcard).unwrap_or(0.0);
            if effective_q <= 0.0 {
                continue;
            }

            let dominated = best.is_some_and(|(_, best_q, best_pref)| {
                effective_q < best_q || (effective_q == best_q && pref_idx >= best_pref)
            });
            if !dominated {
                best = Some((algo, effective_q, pref_idx));
            }
        }

        match best {
            // A configured algorithm beats or ties identity: server preference
            // keeps compressing on ties, preserving prior behavior.
            Some((algo, q, _)) if q >= identity_q => CodingSelection::Compress(algo),
            // Identity is the most preferred acceptable representation, or the
            // only acceptable one.
            _ if identity_q > 0.0 => CodingSelection::Identity,
            // Every representation Ferrum can produce — every configured
            // algorithm and identity — has quality zero.
            _ => CodingSelection::NotAcceptable,
        }
    }

    /// The client's negotiated `Accept-Encoding` for response compression.
    ///
    /// Prefers the snapshot saved in `before_proxy` (the live header may then be
    /// stripped by `remove_accept_encoding`, and `ctx.headers` may be empty on
    /// the zero-clone request fast path). Falls back to the live request header
    /// for the rare paths where no snapshot was staged. Response-buffer,
    /// reservation, and `after_proxy` negotiation all read through here so the
    /// three decisions stay consistent for one request.
    fn negotiated_accept_encoding(ctx: &RequestContext) -> Option<&str> {
        ctx.metadata
            .get(REQUEST_ACCEPT_ENCODING_METADATA_KEY)
            .map(String::as_str)
            .or_else(|| ctx.headers.get("accept-encoding").map(String::as_str))
    }

    fn response_body_limit_allows_compression(ctx: &RequestContext) -> bool {
        // Effective ceiling (global narrowed by any active route ceiling) so a
        // strict route limit governs compression admission the same way a strict
        // global limit does (`GHSA-xrfj-852f-645j`).
        (1..=HARD_MAX_COMPRESSIBLE_RESPONSE_SIZE)
            .contains(&ctx.effective_max_response_body_size_bytes())
    }

    /// Reserve one response-buffer permit for this request when this
    /// instance can select a supported nonzero coding for the client's
    /// `Accept-Encoding`. Runs in `before_proxy`, ahead of the response-buffer
    /// decision, so the buffered population is bounded independently of codec
    /// CPU admission.
    ///
    /// `HEAD` carries no re-encodable wire body, so it never reserves. First
    /// success across sibling instances wins, keeping this to one response
    /// permit per request. On admission pressure the request is marked
    /// declined so the response streams identity (or fails closed with 406 when
    /// identity is prohibited) rather than buffering for a compression it cannot
    /// run; `after_proxy` must not reacquire on that path.
    fn reserve_response_compression_admission(&self, ctx: &mut RequestContext) {
        if !self.has_response_codec()
            || ctx.method.eq_ignore_ascii_case("HEAD")
            || ctx.has_compression_response_admission_owner()
        {
            return;
        }
        let selects_coding = Self::negotiated_accept_encoding(ctx)
            .is_some_and(|ae| matches!(self.select_algorithm(ae), CodingSelection::Compress(_)));
        if !selects_coding {
            return;
        }
        if !Self::response_body_limit_allows_compression(ctx) {
            ctx.mark_compression_response_admission_declined();
            return;
        }
        match try_acquire_response_buffer_permit() {
            Ok(permit) => {
                let claimed = ctx.claim_compression_response_admission(self.instance_id);
                debug_assert!(
                    claimed,
                    "response admission owner changed within a sequential hook chain"
                );
                ctx.set_compression_response_buffer_permit(permit);
            }
            Err(()) => {
                ctx.mark_compression_response_admission_declined();
                warn!(
                    "compression: response buffer admission saturated at reservation; \
                     response will stream identity (or 406 when identity is unacceptable) \
                     instead of buffering for compression"
                );
            }
        }
    }

    /// Whether this response can be gateway-compressed (content-type whitelist
    /// and optional Content-Length minimum). Protocol-hard skips (no-body
    /// statuses, ranges, already-encoded upstream) are checked separately.
    fn is_compression_eligible(&self, response_headers: &HashMap<String, String>) -> bool {
        let compressible = response_headers
            .get("content-type")
            .is_some_and(|ct| self.is_compressible_content_type(ct));
        if !compressible {
            return false;
        }
        if let Some(cl) = response_headers.get("content-length")
            && let Ok(len) = cl.parse::<usize>()
            && len < self.config.min_content_length
        {
            return false;
        }
        true
    }

    /// Whether `Accept-Encoding` can select a different representation for this
    /// response. Identity/default variants must nominate `Vary: Accept-Encoding`
    /// in those cases so shared caches do not replay them for later clients
    /// that prefer (or require) a coded representation (#2355).
    ///
    /// Permanently ineligible statuses/content/transforms are excluded: a later
    /// request cannot obtain a different coding for the same response shape.
    fn should_nominate_accept_encoding_vary(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        on_rejection: bool,
    ) -> bool {
        !on_rejection
            && !Self::is_protocol_hard_skip(ctx, response_status, response_headers)
            && !Self::is_non_transformable_range_or_delta(ctx, response_status, response_headers)
            && !Self::response_forbids_transform(ctx, response_headers)
            && self.is_compression_eligible(response_headers)
    }

    fn response_forbids_transform(
        ctx: &RequestContext,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        ctx.metadata.contains_key(REQUEST_NO_TRANSFORM_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::NO_TRANSFORM_REQUEST_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::NO_TRANSFORM_RESPONSE_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::LATER_NO_TRANSFORM_RESPONSE_METADATA_KEY)
            || headers_have_cache_control_directive(response_headers, "no-transform")
            || ctx
                .metadata
                .contains_key(crate::proxy::STRONG_ETAG_RESPONSE_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::LATER_STRONG_ETAG_RESPONSE_METADATA_KEY)
            || headers_have_strong_etag(response_headers)
    }

    /// Hard protocol cases where Ferrum must not rewrite the representation
    /// and must not invent a negotiation failure for an absent payload or an
    /// already-coded upstream response.
    ///
    /// `HEAD` is included because the wire body is always empty: gateway
    /// compression cannot derive the encoded length of the corresponding GET
    /// representation without encoding that body, so inventing
    /// `Content-Encoding` / an encoded-empty `Content-Length` would violate
    /// RFC 9110 §9.3.2 / §8.6. Preserve valid backend representation
    /// metadata instead.
    ///
    /// Identity range/delta responses are *not* hard skips: they are
    /// non-transformable (see [`Self::is_non_transformable_range_or_delta`])
    /// and still subject to identity-acceptability / 406 negotiation.
    fn is_protocol_hard_skip(
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        Self::is_bodyless_for_compression(ctx, response_status)
            || response_headers.contains_key("content-encoding")
    }

    /// Statuses / methods that never carry a compressible message body on
    /// the wire. Used by protocol hard-skips and response-buffer refinement.
    #[inline]
    fn is_bodyless_for_compression(ctx: &RequestContext, response_status: u16) -> bool {
        UNCOMPRESSIBLE_STATUS_CODES.contains(&response_status)
            || ctx.method.eq_ignore_ascii_case("HEAD")
    }

    /// Range/delta representations Ferrum must not re-encode, but which remain
    /// identity when they lack `Content-Encoding`. Forward unchanged when
    /// identity is acceptable; fail closed with 406 when it is not.
    fn is_non_transformable_range_or_delta(
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        !super::response_body_rewrite_allowed(response_status)
            || response_headers.contains_key("content-range")
            || ctx
                .metadata
                .contains_key(crate::proxy::RANGE_RESPONSE_METADATA_KEY)
    }

    /// Reject-path 406 replacement is reserved for `response_caching` HITs of
    /// identity variants. Other synthetic/auth/policy rejections keep their
    /// original status so negotiation does not mask security denials.
    fn is_response_cache_hit(ctx: &RequestContext) -> bool {
        ctx.response_cache_hit()
    }

    /// Emit 406 on the reject path only for cache-HIT identity variants; on the
    /// ordinary backend path always fail closed when identity is unacceptable.
    fn should_fail_closed_not_acceptable(ctx: &RequestContext, on_rejection: bool) -> bool {
        !on_rejection || Self::is_response_cache_hit(ctx)
    }

    /// Check if the content type is eligible for compression.
    ///
    /// Matches only the trimmed media-type token before the first semicolon,
    /// ASCII case-insensitively, against the validated configured
    /// `content_types` (stored lowercased at construction). This avoids lexical
    /// near-misses such as `application/jsonp` matching `application/json`, and
    /// parameter-only occurrences such as
    /// `application/octet-stream; profile="application/json"`.
    ///
    /// An empty or whitespace-only media-type token (e.g. `; charset=utf-8` or
    /// an empty `Content-Type`) fails closed: it matches nothing.
    fn is_compressible_content_type(&self, content_type: &str) -> bool {
        let media_type = content_type.split(';').next().unwrap_or("").trim();
        if media_type.is_empty() {
            return false;
        }
        self.config
            .content_types
            .iter()
            .any(|rule| media_type.eq_ignore_ascii_case(rule))
    }

    async fn compress_response_body(
        &self,
        body: &[u8],
        encoding: &str,
        permit: OwnedSemaphorePermit,
        ceiling: usize,
    ) -> Option<Vec<u8>> {
        let algo = match encoding {
            "gzip" => Algorithm::Gzip,
            "br" => Algorithm::Brotli,
            _ => {
                drop(permit);
                return None;
            }
        };
        let gzip_level = self.config.gzip_level;
        let brotli_quality = self.config.brotli_quality;
        let data = body.to_vec();
        let encoding_owned = encoding.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            match algo {
                Algorithm::Gzip => compress_gzip_blocking(&data, gzip_level, ceiling),
                Algorithm::Brotli => compress_brotli_blocking(&data, brotli_quality, ceiling),
            }
        })
        .await;

        match result {
            Ok(Ok(compressed)) => {
                debug!(
                    "compression: compressed response body from {} to {} bytes ({}, {:.1}% reduction)",
                    body.len(),
                    compressed.len(),
                    encoding_owned,
                    if body.is_empty() {
                        0.0
                    } else {
                        (1.0 - compressed.len() as f64 / body.len() as f64) * 100.0
                    },
                );
                Some(compressed)
            }
            Ok(Err(e)) => {
                CODEC_WORKER_FAILURES.fetch_add(1, Ordering::Relaxed);
                error!(
                    "compression: encoder failure for committed Content-Encoding '{}' — \
                     aborting encode for identity restore or 406 recovery: {e}",
                    encoding_owned
                );
                None
            }
            Err(_) => {
                CODEC_JOIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                error!(
                    "compression: encoder worker join failed for committed Content-Encoding '{}' — \
                     aborting encode for identity restore or 406 recovery",
                    encoding_owned
                );
                None
            }
        }
    }

    async fn decompress_request_body_transform(
        &self,
        body: &[u8],
        encoding_header: &str,
        route_limit: Option<usize>,
    ) -> Option<Vec<u8>> {
        let Ok(permit) = try_acquire_codec_permit() else {
            warn!("compression: codec admission saturated in request body transform");
            return None;
        };
        let limits = self.request_decode_limits(route_limit);
        let header = encoding_header.to_string();
        let data = body.to_vec();
        match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            decode_content_encoding(Some(header.as_str()), &data, limits)
                .map(|decoded| decoded.into_owned())
        })
        .await
        {
            Ok(Ok(decompressed)) => {
                debug!(
                    "compression: decompressed request body from {} to {} bytes ({})",
                    body.len(),
                    decompressed.len(),
                    encoding_header
                );
                Some(decompressed)
            }
            Ok(Err(e)) => {
                CODEC_WORKER_FAILURES.fetch_add(1, Ordering::Relaxed);
                warn!("compression: request decompression failed: {e}");
                None
            }
            Err(_) => {
                CODEC_JOIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                warn!("compression: request decompression worker join failed");
                None
            }
        }
    }
}

enum RequestCodingPlan {
    IdentityOnly,
    Decode(String),
}

fn resolve_max_decompressed_request_size(
    configured: usize,
    max_request_body_size_bytes: usize,
) -> Result<usize, String> {
    if configured > HARD_MAX_DECOMPRESSED_REQUEST_SIZE {
        return Err(format!(
            "compression: 'max_decompressed_request_size' exceeds hard maximum of {HARD_MAX_DECOMPRESSED_REQUEST_SIZE} bytes"
        ));
    }
    let mut limit = configured.min(HARD_MAX_DECOMPRESSED_REQUEST_SIZE);
    if max_request_body_size_bytes > 0 {
        if configured > max_request_body_size_bytes {
            return Err(format!(
                "compression: 'max_decompressed_request_size' ({configured}) exceeds FERRUM_MAX_REQUEST_BODY_SIZE_BYTES ({max_request_body_size_bytes})"
            ));
        }
        limit = limit.min(max_request_body_size_bytes);
    }
    Ok(limit)
}

/// Encode into a sink bounded by this response's retained ceiling.
///
/// The encoder writes THROUGH the bound, so an expanding encode (incompressible
/// or hostile input) is refused mid-stream instead of materialising a buffer
/// larger than the window the transform phase reserved for it
/// (GHSA-pwcm-6rh8-f2gh). A refusal surfaces as an encoder error, which the
/// caller already handles by aborting the encode so the shared transform loop
/// restores identity (or answers 406 when identity is barred) — never mislabeled
/// plaintext.
fn compress_gzip_blocking(data: &[u8], gzip_level: u32, ceiling: usize) -> Result<Vec<u8>, String> {
    use crate::proxy::response_buffer_budget::BoundedResponseBodySink;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let sink = BoundedResponseBodySink::with_ceiling(ceiling);
    let mut encoder = GzEncoder::new(sink, Compression::new(gzip_level));
    encoder
        .write_all(data)
        .map_err(|e| format!("gzip compression write failed: {e}"))?;
    encoder
        .finish()
        .map_err(|e| format!("gzip compression finish failed: {e}"))?
        .finish()
        .ok_or_else(|| "gzip compression exceeded the retained response ceiling".to_string())
}

fn compress_brotli_blocking(
    data: &[u8],
    brotli_quality: u32,
    ceiling: usize,
) -> Result<Vec<u8>, String> {
    use crate::proxy::response_buffer_budget::BoundedResponseBodySink;

    let mut output = BoundedResponseBodySink::with_ceiling(ceiling);
    let params = brotli::enc::BrotliEncoderParams {
        quality: brotli_quality as i32,
        ..Default::default()
    };
    brotli::BrotliCompress(&mut &data[..], &mut output, &params)
        .map_err(|e| format!("brotli compression failed: {e}"))?;
    output
        .finish()
        .ok_or_else(|| "brotli compression exceeded the retained response ceiling".to_string())
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    match config.get(field) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("compression: '{field}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    match config.get(field) {
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("compression: '{field}' must be an unsigned integer"))
            .map(Some),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "compression: '{field}' must be an unsigned integer"
        )),
    }
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_u64(config, field)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("compression: '{field}' is too large"))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_usize(config, field)? else {
        return Ok(None);
    };
    if value == 0 {
        return Err(format!("compression: '{field}' must be greater than zero"));
    }
    Ok(Some(value))
}

fn parse_content_types(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("content_types") else {
        return Ok(DEFAULT_CONTENT_TYPES
            .iter()
            .map(|content_type| (*content_type).to_string())
            .collect());
    };
    let Some(values) = value.as_array() else {
        return Err("compression: 'content_types' must be an array".to_string());
    };
    if values.is_empty() {
        return Err("compression: 'content_types' must not be empty".to_string());
    }

    let mut content_types = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(content_type) = value.as_str() else {
            return Err(format!(
                "compression: 'content_types[{index}]' must be a string"
            ));
        };
        if content_type.is_empty() {
            return Err(format!(
                "compression: 'content_types[{index}]' must not be empty"
            ));
        }
        if !content_type.is_ascii() {
            return Err(format!(
                "compression: 'content_types[{index}]' must contain only ASCII"
            ));
        }
        content_types.push(content_type.to_ascii_lowercase());
    }

    Ok(content_types)
}

fn comma_header_contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

/// Nominate `Accept-Encoding` in `Vary` so shared caches key identity and
/// compressed representations separately (RFC 9110 §12.5.5 / RFC 9111 §4.1).
///
/// Preserves an existing `Vary: *` (already varies on every request header) and
/// case-insensitively de-duplicates an existing `Accept-Encoding` member.
fn ensure_vary_accept_encoding(response_headers: &mut HashMap<String, String>) {
    match response_headers.get("vary") {
        Some(existing) => {
            let trimmed = existing.trim();
            if trimmed.is_empty() {
                response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
                return;
            }
            // `*` already implies every request header, including Accept-Encoding.
            if trimmed == "*" || comma_header_contains_token(trimmed, "*") {
                return;
            }
            if comma_header_contains_token(existing, "accept-encoding") {
                return;
            }
            let mut updated = String::with_capacity(existing.len() + 18);
            updated.push_str(existing);
            updated.push_str(", Accept-Encoding");
            response_headers.insert("vary".to_string(), updated);
        }
        None => {
            response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
        }
    }
}

/// Parse one `Accept-Encoding` member's qvalue under the RFC 9110 §12.4.2
/// grammar (`qvalue = ( "0" [ "." *3DIGIT ] ) / ( "1" [ "." *3"0" ] )`).
///
/// Returns the member's effective quality, defaulting to 1.0 when no `q`
/// parameter is present. Returns `None` when a `q` parameter is present but
/// malformed, so callers can ignore the entry rather than read it as a
/// refusal: only a well-formed `q=0` weight may forbid a coding. Reading
/// unparseable input as `q=0` would turn otherwise-servable traffic into a
/// negotiation error — the same fail-safe posture as the shared
/// identity-acceptability predicate in `response_representation`.
fn rfc9110_entry_quality(token: &str) -> Option<f32> {
    let Some(semi_idx) = token.find(';') else {
        return Some(1.0);
    };
    for param in token[semi_idx + 1..].split(';') {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        let value = value.trim();
        // Grammar check before numeric conversion: `0[.0*3DIGIT]` or
        // `1[.0*3("0")]` — anything else (extra fraction digits, signs,
        // exponents, out-of-range weights) is malformed.
        let (units, fraction) = value.split_once('.').unwrap_or((value, ""));
        let well_formed = fraction.len() <= 3
            && match units {
                "0" => fraction.bytes().all(|b| b.is_ascii_digit()),
                "1" => fraction.bytes().all(|b| b == b'0'),
                _ => false,
            };
        if !well_formed {
            return None;
        }
        return value.parse::<f32>().ok().filter(|q| q.is_finite());
    }
    Some(1.0)
}

/// Effective quality of the identity (uncoded) representation for
/// `Accept-Encoding` negotiation (RFC 9110 §12.5.3).
///
/// Shared by compression selection and
/// `response_representation::identity_coding_is_acceptable` so first/last
/// duplicate handling and invalid-q behavior stay aligned:
///
/// - The **first** `identity` entry settles the question (more-specific match).
///   A well-formed qvalue is that entry's quality; a malformed qvalue is not a
///   refusal and keeps the default weight of `1.0`.
/// - A nonzero wildcard does **not** lower identity below its default of `1.0`.
/// - Only a well-formed `*;q=0` without a more-specific identity entry makes
///   identity unacceptable (`0.0`). The **last** wildcard wins when several
///   `*` entries appear.
/// - Absent identity and non-forbidding wildcard → default `1.0`.
pub(crate) fn identity_coding_quality(accept_encoding: &str) -> f32 {
    let mut wildcard_forbids_identity = false;
    for entry in accept_encoding.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let coding = entry.split(';').next().unwrap_or("").trim();
        if coding.is_empty() {
            continue;
        }
        if coding.eq_ignore_ascii_case("identity") {
            // First identity entry wins — including "malformed q ⇒ default 1.0".
            return rfc9110_entry_quality(entry).unwrap_or(1.0);
        }
        if coding == "*" {
            // Last wildcard wins; only a well-formed zero weight forbids identity.
            wildcard_forbids_identity = matches!(rfc9110_entry_quality(entry), Some(q) if q == 0.0);
        }
    }
    if wildcard_forbids_identity { 0.0 } else { 1.0 }
}

fn not_acceptable_reject() -> PluginResult {
    PluginResult::Reject {
        status_code: 406,
        body: NOT_ACCEPTABLE_RESPONSE_BODY.to_string(),
        headers: HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("vary".to_string(), "Accept-Encoding".to_string()),
        ]),
    }
}

fn request_no_transform(ctx: &RequestContext, headers: &HashMap<String, String>) -> bool {
    ctx.metadata
        .contains_key(crate::proxy::NO_TRANSFORM_REQUEST_METADATA_KEY)
        || ctx.metadata.contains_key(REQUEST_NO_TRANSFORM_METADATA_KEY)
        || headers_have_cache_control_directive(headers, "no-transform")
}

fn ensure_cache_control_no_transform(headers: &mut HashMap<String, String>) {
    if headers_have_cache_control_directive(headers, "no-transform") {
        return;
    }

    match headers.get_mut("cache-control") {
        Some(value) if value.trim().is_empty() => {
            *value = "no-transform".to_string();
        }
        Some(value) => {
            value.push_str(", no-transform");
        }
        None => {
            headers.insert("cache-control".to_string(), "no-transform".to_string());
        }
    }
}

#[async_trait]
impl Plugin for CompressionPlugin {
    fn name(&self) -> &str {
        "compression"
    }

    fn priority(&self) -> u16 {
        super::priority::COMPRESSION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        (self.config.remove_accept_encoding && self.has_response_codec())
            || self.config.decompress_request
    }

    fn modifies_request_body(&self) -> bool {
        self.config.decompress_request
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.config.decompress_request {
            return false;
        }
        let Some(ce) = ctx.headers.get("content-encoding") else {
            return false;
        };
        matches!(
            self.classify_request_content_encoding(ce),
            Ok(RequestCodingPlan::Decode(_))
        )
    }

    /// Buffer the request body before `before_proxy` runs so the decompression
    /// can be validated (and a malformed body cleanly rejected) in the shared
    /// pre-`before_proxy` normalization phase before Content-Encoding /
    /// Content-Length headers are stripped. This stays gated by
    /// `should_buffer_request_body`, so only requests that carry a decodable
    /// `Content-Encoding` header buffer early.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.config.decompress_request
    }

    fn normalizes_buffered_request_body_before_before_proxy(&self) -> bool {
        self.config.decompress_request
    }

    fn final_request_body_matches_pre_before_proxy_normalization(&self) -> bool {
        self.config.decompress_request
    }

    /// The validation in `before_proxy` / early normalization decompresses
    /// arbitrary (possibly non-UTF-8) bytes, so it reads
    /// `ctx.request_body_bytes` rather than the UTF-8
    /// `ctx.metadata["request_body"]` view.
    fn needs_request_body_bytes(&self) -> bool {
        self.config.decompress_request
    }

    async fn normalize_buffered_request_body_before_before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        body: &mut Vec<u8>,
    ) -> PluginResult {
        // Strip client-spoofed values of the gateway-internal marker only
        // before any compression instance has claimed request-decode ownership.
        if !ctx.has_compression_request_decode_owner() {
            headers.remove("x-ferrum-original-content-encoding");
        }
        self.try_claim_and_decode_request(ctx, headers, Some(body))
            .await
    }

    fn requires_response_body_buffering(&self) -> bool {
        !self.config.algorithms.is_empty()
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // HEAD never carries a wire body the gateway can re-encode, and request
        // no-transform opts out of gateway response compression; neither pins
        // the body onto the buffered path (preserving backend representation
        // metadata / RFC 9111).
        if ctx.method.eq_ignore_ascii_case("HEAD")
            || ctx.metadata.contains_key(REQUEST_NO_TRANSFORM_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::NO_TRANSFORM_REQUEST_METADATA_KEY)
            || !Self::response_body_limit_allows_compression(ctx)
        {
            return false;
        }
        // `before_proxy` negotiated a compressible coding but could not obtain a
        // bounded response-buffer permit: stream identity instead of buffering
        // for a compression that cannot run (and never enter the buffered path
        // on the strength of admission it does not hold).
        if ctx.compression_response_admission_declined() {
            return false;
        }
        // Negotiate the original client Accept-Encoding: buffer only when this
        // instance can actually select a supported nonzero coding. Identity,
        // unsupported-only, and `gzip;q=0, br;q=0` requests have nothing to
        // compress, so they stream instead of forcing a full-body collection.
        self.has_response_codec()
            && Self::negotiated_accept_encoding(ctx)
                .is_some_and(|ae| matches!(self.select_algorithm(ae), CodingSelection::Compress(_)))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // Mirror the `after_proxy` skip checks that are knowable from the
        // response headers so we never pin a body onto the buffered path that
        // we are going to decline to compress. Preserved representation
        // statuses (`206` and `226`) and any `Content-Range` response are
        // skipped there, so they must stream instead of being fully collected
        // (which would also risk tripping the response body size limit).
        //
        // On paths that run `after_proxy` *before* this refine decision (e.g.
        // the H3 cross-protocol path stamps `RANGE_RESPONSE_METADATA_KEY` from
        // the pristine headers, then runs `after_proxy`, then refines), an
        // earlier-ordered hook such as `response_transformer` (ordering 4000)
        // can strip `Content-Range` from a non-206 response before this check
        // sees it. `after_proxy` already honors the stamped marker, so honor it
        // here too; otherwise the partial body stays pinned on the buffered path
        // (uncompressed, since `transform_response_body` is buffered-only) and
        // can trip the response body size limit instead of streaming.
        //
        // `204` / `205` / `304` and `HEAD` are bodyless for compression: never
        // buffer them for a transform that cannot legally rewrite the wire body.
        if Self::is_bodyless_for_compression(ctx, response_status)
            || !super::response_body_rewrite_allowed(response_status)
            || response_headers.contains_key("content-range")
            || ctx
                .metadata
                .contains_key(crate::proxy::RANGE_RESPONSE_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::NO_TRANSFORM_RESPONSE_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::STRONG_ETAG_RESPONSE_METADATA_KEY)
            || headers_have_cache_control_directive(response_headers, "no-transform")
            || headers_have_strong_etag(response_headers)
        {
            return false;
        }
        self.should_buffer_response_body(ctx)
            && content_type.is_some_and(|ct| self.is_compressible_content_type(ct))
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        Self::is_bodyless_for_compression(ctx, response_status)
            || !super::response_body_rewrite_allowed(response_status)
            || response_headers.contains_key("content-range")
            || ctx
                .metadata
                .contains_key(crate::proxy::RANGE_RESPONSE_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::NO_TRANSFORM_RESPONSE_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::STRONG_ETAG_RESPONSE_METADATA_KEY)
            || headers_have_cache_control_directive(response_headers, "no-transform")
            || headers_have_strong_etag(response_headers)
    }

    fn should_release_response_body_for_later_no_transform(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        true
    }

    fn needs_later_response_cache_control_no_transform(&self) -> bool {
        true
    }

    fn should_release_response_body_for_later_strong_etag(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        true
    }

    fn needs_later_response_strong_etag(&self) -> bool {
        true
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    /// Content-coding negotiation is representation metadata, and all three
    /// fields can be governed without a visible initial-map mutation:
    /// `content-length` is REMOVED after coding (a no-op when the backend sent
    /// the field only as a trailer, yet forwarding that trailer gives the client
    /// the uncompressed length for a compressed body), `vary` is an idempotent
    /// token merge that no-ops whenever the backend already nominated
    /// `Accept-Encoding`, and `content-encoding` is a gateway write a trailer
    /// copy would contradict.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&COMPRESSION_RESPONSE_POLICY_NAMES)
    }

    fn may_replace_rejection_response(&self) -> bool {
        // Opt in so a required 406 can replace an uncommitted `response_caching`
        // HIT of an identity variant. `after_proxy` only returns that Reject when
        // the monotonic request-global cache-HIT marker is present and identity
        // is explicitly unacceptable — auth/policy rejections are left unchanged.
        true
    }

    fn warn_on_rejection_response_replacement(&self) -> bool {
        // Replacing a cache HIT identity variant with a standards-required 406
        // is expected negotiation behavior, not an anomalous overwrite.
        false
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Strip client-spoofed values of the gateway-internal marker only
        // before any compression instance has claimed request-decode ownership.
        // Once claimed, siblings must leave the owner's handoff intact —
        // deleting the marker here is what previously left encoded uploads
        // with no Content-Encoding and no decoder.
        if !ctx.has_compression_request_decode_owner() {
            headers.remove("x-ferrum-original-content-encoding");
        }

        // RFC 9111 no-transform on requests opts out of gateway response
        // compression, but it must not disable request decompression when
        // `decompress_request` is enabled. Cache-Control is client-controlled;
        // honoring it for request-body normalization would let compressed
        // uploads bypass downstream body-inspection hooks.
        let has_request_no_transform = request_no_transform(ctx, headers);
        if has_request_no_transform {
            ensure_cache_control_no_transform(headers);
            ctx.metadata.insert(
                REQUEST_NO_TRANSFORM_METADATA_KEY.to_string(),
                "true".to_string(),
            );
        }

        // Save original Accept-Encoding before we potentially strip it.
        // Read from `headers` param — ctx.headers may be empty when the handler
        // uses the zero-clone fast path (std::mem::take).
        if !has_request_no_transform {
            if let Some(ae) = headers.get("accept-encoding") {
                ctx.metadata
                    .entry(REQUEST_ACCEPT_ENCODING_METADATA_KEY.to_string())
                    .or_insert_with(|| ae.clone());
            }

            // Strip Accept-Encoding from the backend request so the backend
            // sends an uncompressed response (we'll compress it ourselves).
            // Only mutate when this instance still has a usable response codec.
            if self.config.remove_accept_encoding && self.has_response_codec() {
                headers.remove("accept-encoding");
            }

            // Reserve response-compression buffer admission now, before the
            // response-buffer decision, so a request that cannot obtain a
            // bounded permit never pins a (potentially unbounded) response body
            // onto the compression-only buffered path. Negotiate against the
            // just-saved client Accept-Encoding: buffering only pays off when
            // this instance can select a supported nonzero coding. First-wins
            // across sibling instances keeps it to one response permit per
            // request; `after_proxy` consumes this reserved permit instead of
            // acquiring a fresh one on the hot path.
            self.reserve_response_compression_admission(ctx);
        }

        // For request decompression: when the shared pre-`before_proxy`
        // normalization phase already claimed/decoded, skip. Otherwise validate
        // (and claim/strip) here so malformed bodies still fail closed on the
        // rare path where early normalization did not run with a body view.
        //
        // Stripping is gated on successful decompression so we never forward a
        // body whose headers and contents disagree (RFC 9110 §8.4).
        self.try_claim_and_decode_request(ctx, headers, None).await
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Synthetic / rejection responses re-run `after_proxy` without body
        // transforms. Do not commit Content-Encoding there. Fail-closed 406 on
        // this path is scoped to `response_caching` HITs of identity variants
        // (the monotonic request-global HIT marker) — including legacy identity
        // responses that omit `Vary: Accept-Encoding` (#2355) — so auth/policy
        // rejections keep their original status.
        let on_rejection = ctx.metadata.contains_key(REJECTION_RESPONSE_METADATA_KEY);

        // No-body statuses (`204`/`205`/`304`), HEAD, and already-coded
        // upstream responses are protocol-correct as-is; negotiation does not
        // invent a 406 for them or rewrite representation metadata. A permit
        // reserved in `before_proxy` for such a response produces no coding, so
        // release it promptly rather than idling the slot until request end.
        if Self::is_protocol_hard_skip(ctx, response_status, response_headers) {
            ctx.release_compression_response_admission_if_owner(self.instance_id);
            return PluginResult::Continue;
        }

        let range_or_delta =
            Self::is_non_transformable_range_or_delta(ctx, response_status, response_headers);

        // Same source precedence as the buffer decision and the reservation:
        // the saved snapshot wins over the (possibly stripped) live header.
        let accept_encoding = Self::negotiated_accept_encoding(ctx);

        let selection = accept_encoding.map(|ae| self.select_algorithm(ae));
        match selection {
            // No Accept-Encoding field, or identity is the most preferred /
            // only acceptable representation: forward the uncoded response.
            // Eligible identity/default variants still nominate Vary so shared
            // caches do not reuse them for later clients that prefer gzip/br.
            Some(CodingSelection::Identity) | None => {
                if self.should_nominate_accept_encoding_vary(
                    ctx,
                    response_status,
                    response_headers,
                    on_rejection,
                ) {
                    ensure_vary_accept_encoding(response_headers);
                }
                PluginResult::Continue
            }
            // Client refused identity and every configured algorithm.
            Some(CodingSelection::NotAcceptable) => {
                if Self::should_fail_closed_not_acceptable(ctx, on_rejection) {
                    return not_acceptable_reject();
                }
                PluginResult::Continue
            }
            Some(CodingSelection::Compress(algo)) => {
                // Resolve identity acceptability into an owned flag before any
                // mutable `ctx` access below so the `accept_encoding` borrow ends
                // here (the reserved-permit take/set otherwise conflicts with it).
                let identity_unacceptable =
                    accept_encoding.is_some_and(|ae| identity_coding_quality(ae) == 0.0);

                let can_encode = !on_rejection
                    && !range_or_delta
                    && !ctx.has_compression_response_encode_owner()
                    && Self::response_body_limit_allows_compression(ctx)
                    && !Self::response_forbids_transform(ctx, response_headers)
                    && self.is_compression_eligible(response_headers);
                if can_encode {
                    // Consume the response-buffer reservation for this coding.
                    // Codec CPU admission is intentionally acquired only by the
                    // body transform, immediately before spawn_blocking, so slow
                    // backend requests cannot starve request decompression. The
                    // reservation in `before_proxy` is what bounded entry onto
                    // the buffered path, so a request that chose to stream must
                    // never reacquire:
                    //   * this instance reserved it -> consume the held permit
                    //     (the common path; no reacquire on the hot path);
                    //   * admission was declined under pressure -> do NOT
                    //     reacquire; the request already chose to stream, so fall
                    //     through to identity (or 406 when identity is barred);
                    //   * a sibling still owns the reservation -> it owns the one
                    //     coding layer; do not open a second permit for the same
                    //     request;
                    //   * otherwise take an orphaned reservation left by an
                    //     earlier sibling that declined to encode this
                    //     representation, or acquire once. The orphaned path is
                    //     how a later sibling with a broader config compresses an
                    //     already-admitted body without dropping the slot between
                    //     after_proxy hooks (which would let retained bodies
                    //     briefly exceed the response-buffer budget).
                    let buffer_permit = if ctx.owns_compression_response_admission(self.instance_id)
                    {
                        ctx.take_compression_response_buffer_permit()
                    } else if ctx.compression_response_admission_declined()
                        || ctx.has_compression_response_admission_owner()
                    {
                        None
                    } else if let Some(orphaned) = ctx.take_compression_response_buffer_permit() {
                        Some(orphaned)
                    } else {
                        try_acquire_response_buffer_permit().ok()
                    };

                    let Some(buffer_permit) = buffer_permit else {
                        // No bounded admission for the negotiated coding (declined
                        // at reservation, or owned by a sibling). Do not commit
                        // Content-Encoding: serve identity, or 406 when identity
                        // is unacceptable. Saturation already warned at the
                        // `before_proxy` reservation, so keep this at debug.
                        debug!(
                            "compression: no reserved response-buffer admission for negotiated coding; \
                             serving identity response"
                        );
                        if identity_unacceptable
                            && Self::should_fail_closed_not_acceptable(ctx, on_rejection)
                        {
                            return not_acceptable_reject();
                        }
                        if self.should_nominate_accept_encoding_vary(
                            ctx,
                            response_status,
                            response_headers,
                            on_rejection,
                        ) {
                            ensure_vary_accept_encoding(response_headers);
                        }
                        return PluginResult::Continue;
                    };

                    // Record authoritative ownership outside public plugin metadata so
                    // response security hooks can distinguish gateway-planned compression
                    // from an encoded origin response without trusting a spoofable key.
                    ctx.mark_gateway_response_compression(algo.content_encoding());

                    // First instance to commit Content-Encoding owns the single
                    // coding layer. Sibling transforms must not compress again.
                    let claimed = ctx.claim_compression_response_encode(self.instance_id);
                    debug_assert!(
                        claimed,
                        "response encode owner changed within a sequential hook chain"
                    );
                    ctx.set_compression_response_buffer_permit(buffer_permit);

                    // Retain the existing observable decision metadata.
                    ctx.metadata.insert(
                        RESPONSE_ALGORITHM_METADATA_KEY.to_string(),
                        algo.content_encoding().to_string(),
                    );

                    // Set Content-Encoding. Remove Content-Length (it's stale after compression).
                    response_headers.insert(
                        "content-encoding".to_string(),
                        algo.content_encoding().to_string(),
                    );
                    response_headers.remove("content-length");

                    // Compressed variants nominate the same Vary dimension as
                    // eligible identity/default responses above.
                    ensure_vary_accept_encoding(response_headers);

                    return PluginResult::Continue;
                }

                // Cannot produce the selected coded representation (range/delta,
                // size / content-type eligibility, no-transform / strong ETag, or
                // reject-path without body transforms). If identity is also
                // unacceptable, drop the reservation and fail closed rather than
                // forwarding an excluded identity body — and never partially
                // mutate compression headers. On the reject path, only
                // `response_caching` HITs are replaced. Otherwise relinquish
                // ownership but keep the buffer permit on the context: the body
                // was already admitted/collected, and a later sibling with a
                // broader config may still encode it under the same slot.
                if identity_unacceptable
                    && Self::should_fail_closed_not_acceptable(ctx, on_rejection)
                {
                    ctx.release_compression_response_admission_if_owner(self.instance_id);
                    return not_acceptable_reject();
                }
                ctx.relinquish_compression_response_admission_ownership_if_owner(self.instance_id);
                PluginResult::Continue
            }
        }
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.config.decompress_request || body.is_empty() {
            return None;
        }

        // Check Content-Encoding to decide how to decompress. The original
        // header was removed in before_proxy and saved under the private key
        // x-ferrum-original-content-encoding so the backend doesn't see it.
        let encoding_header = request_headers
            .get("x-ferrum-original-content-encoding")
            .or_else(|| request_headers.get("content-encoding"))?;
        match self.classify_request_content_encoding(encoding_header) {
            Ok(RequestCodingPlan::Decode(_)) => {
                self.decompress_request_body_transform(body, encoding_header, None)
                    .await
            }
            Ok(RequestCodingPlan::IdentityOnly) | Err(_) => None,
        }
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        _content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Production H1/H2/H3 loops call this context-aware path. Only the
        // instance that claimed decode ownership may rewrite the body —
        // siblings return None so the bytes are decoded exactly once.
        if !self.is_request_decode_owner(ctx) {
            return None;
        }
        // Fallback path staged validated plaintext when headers were stripped
        // without a mutable body view. Emit those bytes; never re-decode.
        if let Some(plaintext) = ctx.take_compression_staged_request_plaintext() {
            return Some(plaintext);
        }
        // Early normalization already replaced the buffered body with validated
        // plaintext; re-decoding would corrupt the backend-visible bytes.
        if ctx.metadata.contains_key(REQUEST_DECODED_METADATA_KEY) {
            return None;
        }
        let encoding_header = request_headers
            .get("x-ferrum-original-content-encoding")
            .or_else(|| request_headers.get("content-encoding"))?;
        match self.classify_request_content_encoding(encoding_header) {
            Ok(RequestCodingPlan::Decode(_)) => {
                self.decompress_request_body_transform(
                    body,
                    encoding_header,
                    ctx.route_request_body_limit(),
                )
                .await
            }
            Ok(RequestCodingPlan::IdentityOnly) | Err(_) => None,
        }
    }

    async fn transform_response_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        // Compression needs the `after_proxy` decision in request metadata to
        // distinguish a gateway-committed encoding from an origin-supplied
        // `Content-Encoding`. Production proxy paths call the context-aware
        // variant below.
        crate::plugins::ResponseBodyTransformOutcome::Unchanged
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        _content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        use crate::plugins::ResponseBodyTransformOutcome;
        // HEAD never transfers content bytes. Even if an earlier phase
        // incorrectly committed a Content-Encoding, refuse to synthesize an
        // encoded-empty body / Content-Length (RFC 9110 §9.3.2 / §8.6).
        if ctx.method.eq_ignore_ascii_case("HEAD") {
            return ResponseBodyTransformOutcome::Unchanged;
        }

        // The algorithm decision was made in `after_proxy` and recorded in
        // private request-context state. Its presence proves the gateway, not
        // the origin, committed a response encoding. Only the owning instance
        // may emit the coding layer so Content-Encoding stays 1:1 with body
        // layers across multi-instance transform loops.
        let Some(encoding) = response_headers.get("content-encoding") else {
            return ResponseBodyTransformOutcome::Unchanged;
        };
        if ctx.gateway_response_compression_algorithm().is_none() {
            return ResponseBodyTransformOutcome::Unchanged;
        }
        if !self.is_response_encode_owner(ctx) {
            return ResponseBodyTransformOutcome::Unchanged;
        }
        let encoding = if encoding.eq_ignore_ascii_case("gzip") {
            "gzip"
        } else if encoding.eq_ignore_ascii_case("br") {
            "br"
        } else {
            return ResponseBodyTransformOutcome::Unchanged;
        };

        // The buffer permit is what admitted this body onto the compression-only
        // buffered path. Hold it until the encode finishes: the collected body
        // (and the compressed copy derived from it) stay resident for the whole
        // transform, so releasing early would let the retained-bytes population
        // exceed the response-buffer semaphore it is supposed to bound.
        let Some(buffer_permit) = ctx.take_compression_response_buffer_permit() else {
            error!(
                "compression: missing response-buffer admission permit for committed Content-Encoding '{encoding}'"
            );
            ctx.mark_compression_response_encode_aborted();
            return ResponseBodyTransformOutcome::Unchanged;
        };
        // Codec CPU admission is acquired only here, immediately before the
        // blocking worker, so a slow backend holding a buffer slot never pins a
        // codec permit and cannot starve request decompression. Saturation after
        // `Content-Encoding` was committed aborts the encode; shared H1/H2/H3
        // transform loops then restore identity when acceptable, or replace with
        // 406 when the client excluded identity — never plaintext under a coded
        // header or against `identity;q=0`.
        let Ok(permit) = try_acquire_codec_permit() else {
            drop(buffer_permit);
            warn!("compression: codec admission saturated while encoding response body");
            ctx.mark_compression_response_encode_aborted();
            return ResponseBodyTransformOutcome::Unchanged;
        };

        // Once `after_proxy` set `Content-Encoding`, the response is committed
        // to that encoding. We MUST NOT short-circuit here on body size — doing
        // so would leave the client with a body labelled `Content-Encoding:
        // gzip` that is actually plaintext, which every conformant client will
        // reject as a decoding error.
        //
        // The minimum-length gate runs in `after_proxy` for the known-CL case.
        // When CL is unknown (chunked / streamed responses), we accept that the
        // rare tiny chunked body will be compressed needlessly
        // — far cheaper than serving a malformed response.
        //
        // Encoder / join failure marks abort so shared transform loops restore
        // identity (or 406 when identity is barred) with correct headers instead
        // of emitting mislabeled or explicitly refused plaintext.
        // The encoder writes into a sink sized to this response's retained
        // ceiling — the same size as the window the transform phase reserved —
        // so an expanding encode is refused during construction rather than
        // after a larger buffer is resident (GHSA-pwcm-6rh8-f2gh).
        let compressed = self
            .compress_response_body(body, encoding, permit, ctx.retained_response_body_ceiling())
            .await;
        // Release the buffer slot only once the compressed copy exists (or the
        // encode failed): from here on nothing further is retained under this
        // request's compression admission.
        drop(buffer_permit);
        match compressed {
            Some(compressed) => ResponseBodyTransformOutcome::Replaced(compressed),
            None => {
                ctx.mark_compression_response_encode_aborted();
                ResponseBodyTransformOutcome::Unchanged
            }
        }
    }
}
