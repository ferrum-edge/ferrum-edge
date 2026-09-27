//! Gateway-owned diagnostic references (issue #5767).
//!
//! `X-Gateway-Error` is a closed, coarse, eight-token public vocabulary: one
//! token (`connection_failure`, say) covers DNS, TCP, TLS, pool, and egress
//! policy failures, and the precise `error_class` behind it reaches only the
//! operator's logs. This module adds an additive, opt-in bridge between the
//! two without widening the public surface:
//!
//! * With `FERRUM_DIAGNOSTIC_REFS=errors`, every HTTP-family response that
//!   carries the gateway's own `X-Gateway-Error` token (HTTP/1.1, HTTP/2, and
//!   HTTP/3) also carries `X-Ferrum-Diagnostic-Ref: fd1_<32 lowercase hex>`.
//!   The reference is 128 bits read from the process CSPRNG and embeds
//!   nothing: no cause, route, backend, tenant, time, or counter.
//! * The detail behind a reference lives only in this process, in a bounded,
//!   TTL-limited, sharded in-memory store ([`DiagnosticRefStore`]). It is
//!   readable only through the authenticated admin lookup
//!   `GET /diagnostics/v1/refs/{ref}`, which requires an admin JWT carrying the
//!   `diagnostics:read` scope and an `ns` claim; a reference outside the
//!   token's namespaces is indistinguishable from an unknown one (`404`).
//! * The header is gateway-owned: a backend (or serverless function) copy is
//!   stripped at every backend response boundary through
//!   `proxy::headers::GATEWAY_OWNED_DIAGNOSTIC_RESPONSE_HEADERS`, and every
//!   stamp strips any copy a plugin or hook left before writing its own, so a
//!   client never sees a reference the gateway did not mint.
//!
//! Hot-path cost: with the default `off`, one `OnceLock` load per HTTP-family
//! request and nothing else. When enabled, one `Arc` slot per request, and only
//! on a response that carries `X-Gateway-Error`, one CSPRNG read and one short
//! critical section on one of [`SHARD_COUNT`] shard mutexes. Detail is copied
//! into the slot from the terminal transaction summary, and only for a summary
//! that can carry `X-Gateway-Error` (5xx or a classified dispatch error).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::fips::backend::rand::{SecureRandom, SystemRandom};
use crate::plugins::TransactionSummary;

/// Wire name of the gateway-owned diagnostic reference response header.
pub const DIAGNOSTIC_REF_HEADER: &str = "x-ferrum-diagnostic-ref";

/// Version prefix of every reference. A future format changes the prefix.
pub const DIAGNOSTIC_REF_PREFIX: &str = "fd1_";

/// Random bytes behind one reference (128 bits).
const DIAGNOSTIC_REF_RANDOM_BYTES: usize = 16;

/// Lowercase hex digits encoding those bytes.
const DIAGNOSTIC_REF_HEX_LEN: usize = DIAGNOSTIC_REF_RANDOM_BYTES * 2;

/// Exact length of a well-formed reference: the prefix plus 32 hex digits.
pub const DIAGNOSTIC_REF_LEN: usize = DIAGNOSTIC_REF_PREFIX.len() + DIAGNOSTIC_REF_HEX_LEN;

/// Admin JWT `scope` value that authorizes a diagnostic reference lookup.
pub const DIAGNOSTICS_READ_SCOPE: &str = "diagnostics:read";

/// `schema_version` of the lookup response body.
pub const DIAGNOSTIC_REF_SCHEMA_VERSION: &str = "ferrum.diagnostic_ref.v1";

/// Default reference lifetime (`FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`).
pub const DEFAULT_TTL_SECONDS: u64 = 900;
/// Lower clamp for `FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`.
pub const MIN_TTL_SECONDS: u64 = 1;
/// Upper clamp for `FERRUM_DIAGNOSTIC_REF_TTL_SECONDS` (one day).
pub const MAX_TTL_SECONDS: u64 = 86_400;

/// Default retained-reference ceiling (`FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;
/// Lower clamp for `FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`: one entry per shard.
pub const MIN_MAX_ENTRIES: usize = SHARD_COUNT;
/// Upper clamp for `FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`.
pub const MAX_MAX_ENTRIES: usize = 1_000_000;

/// Default admin lookup budget
/// (`FERRUM_DIAGNOSTIC_REF_LOOKUP_RATE_PER_SECOND`).
pub const DEFAULT_LOOKUP_RATE_PER_SECOND: u32 = 10;
/// Lower clamp for `FERRUM_DIAGNOSTIC_REF_LOOKUP_RATE_PER_SECOND`.
pub const MIN_LOOKUP_RATE_PER_SECOND: u32 = 1;
/// Upper clamp for `FERRUM_DIAGNOSTIC_REF_LOOKUP_RATE_PER_SECOND`.
pub const MAX_LOOKUP_RATE_PER_SECOND: u32 = 10_000;

/// Number of independently locked store shards. The first random byte of a
/// reference selects its shard, so load spreads uniformly and one shard's
/// critical section never serializes the others.
pub const SHARD_COUNT: usize = 16;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const MODE_PARSE_ERROR: &str = "FERRUM_DIAGNOSTIC_REFS must be `off` or `errors`";

/// `FERRUM_DIAGNOSTIC_REFS`: which gateway responses carry a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiagnosticRefMode {
    /// No references are minted and no store is allocated (default).
    #[default]
    Off,
    /// Responses carrying the gateway's own `X-Gateway-Error` token.
    Errors,
}

impl DiagnosticRefMode {
    /// Parse a configured value. Unknown values fail closed at startup rather
    /// than silently disabling (or widening) the feature.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "errors" => Ok(Self::Errors),
            _ => Err(MODE_PARSE_ERROR.to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Errors => "errors",
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Client-facing protocol of the response a reference was minted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticProtocol {
    Http1,
    Http2,
    Http3,
}

impl DiagnosticProtocol {
    /// HTTP/2 and HTTP/3 map to themselves; every HTTP/1.x version is `http1`.
    pub fn from_http_version(version: http::Version) -> Self {
        if version == http::Version::HTTP_2 {
            Self::Http2
        } else if version == http::Version::HTTP_3 {
            Self::Http3
        } else {
            Self::Http1
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
        }
    }
}

/// Bounds of one [`DiagnosticRefStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticRefStoreConfig {
    pub ttl: Duration,
    pub max_entries: usize,
    pub lookup_rate_per_second: u32,
}

impl Default for DiagnosticRefStoreConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            max_entries: DEFAULT_MAX_ENTRIES,
            lookup_rate_per_second: DEFAULT_LOOKUP_RATE_PER_SECOND,
        }
    }
}

/// Operator-only detail behind a reference, copied from the request's
/// terminal transaction summary.
///
/// Every string-typed field is either a closed compiled-in vocabulary
/// (`&'static str`) or operator configuration (`proxy_id`, and the backend
/// origin reduced to `scheme://host:port`). Request and response bodies,
/// headers, paths, query strings, credentials, client addresses, and raw error
/// text are never recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticDetail {
    /// Granular `error_class` of the backend dispatch, as the access log names
    /// it (`dns_lookup_error`, `connection_refused`, `tls_error`, ...).
    pub error_class: Option<&'static str>,
    /// Classification of a failure while streaming the response body.
    pub body_error_class: Option<&'static str>,
    /// Gateway rejection phase (`overload`, `circuit_breaker_open`,
    /// `adaptive_concurrency` reads `concurrency_limit`, `config_stale`).
    pub rejection_phase: Option<&'static str>,
    /// Phase of a route rule's total request deadline that produced a
    /// gateway-authored `504` (`before_dispatch`, `dispatch`,
    /// `retry_backoff`).
    pub route_timeout_phase: Option<&'static str>,
    /// Whether and how far the request reached a backend: `not_dispatched`,
    /// `pre_wire_failure`, `ambiguous_failure`, or `backend_response`.
    pub backend_dispatch: &'static str,
    /// ID of the matched proxy, when routing matched one.
    pub proxy_id: Option<String>,
    /// Backend origin (`scheme://host:port`) the request was dispatched to.
    /// Userinfo, path, query, and fragment are removed.
    pub backend_target: Option<String>,
    /// Coarse total-duration bucket (`lt_10ms` .. `ge_10s`, or `unknown`).
    pub duration_bucket: &'static str,
}

impl DiagnosticDetail {
    /// Build the detail from a terminal transaction summary plus the two
    /// request-context facts the summary does not carry.
    pub fn from_summary(
        summary: &TransactionSummary,
        backend_dispatch: &'static str,
        route_timeout_phase: Option<&'static str>,
    ) -> Self {
        Self {
            error_class: crate::retry::http_log_error_class(summary.error_class),
            body_error_class: summary.body_error_class.map(|class| class.as_str()),
            rejection_phase: summary
                .rejection_phase()
                .and_then(crate::retry::token_for_rejection_phase),
            route_timeout_phase,
            backend_dispatch,
            proxy_id: summary.proxy_id.clone(),
            backend_target: summary.backend_target.as_deref().and_then(backend_origin),
            duration_bucket: duration_bucket(summary.latency_total_ms),
        }
    }
}

/// Reduce a transaction-summary backend target to its origin.
///
/// `scheme://[userinfo@]host[:port][/path][?query][#fragment]` becomes
/// `scheme://host:port`; a bare `host:port` is kept as is. Anything else
/// (an empty authority, an over-long value, a non-origin shape) is dropped
/// rather than echoed.
pub fn backend_origin(target: &str) -> Option<String> {
    const MAX_ORIGIN_LEN: usize = 300;
    let (scheme, authority) = match target.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            (Some(scheme), &rest[..end])
        }
        None => (None, target),
    };
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    let host_port_ok = !host_port.is_empty()
        && host_port.len() <= MAX_ORIGIN_LEN
        && host_port.bytes().all(is_origin_authority_byte);
    if !host_port_ok {
        return None;
    }
    match scheme {
        Some(scheme) => {
            let scheme_ok = !scheme.is_empty()
                && scheme.len() <= 16
                && scheme.bytes().all(is_origin_scheme_byte);
            if !scheme_ok {
                return None;
            }
            Some(format!("{}://{}", scheme.to_ascii_lowercase(), host_port))
        }
        None => Some(host_port.to_string()),
    }
}

/// A byte an origin's `host:port` may carry: printable, non-space, and none
/// of the delimiters that would begin userinfo, a path, a query, or a
/// fragment.
fn is_origin_authority_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'/' | b'?' | b'#' | b'@')
}

/// RFC 3986 `scheme` characters after the first.
fn is_origin_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

/// Coarse bucket for a total request duration in milliseconds. A negative or
/// non-finite value (the summary's "unknown" sentinel) is `unknown`.
pub fn duration_bucket(latency_ms: f64) -> &'static str {
    if !latency_ms.is_finite() || latency_ms < 0.0 {
        "unknown"
    } else if latency_ms < 10.0 {
        "lt_10ms"
    } else if latency_ms < 100.0 {
        "lt_100ms"
    } else if latency_ms < 1_000.0 {
        "lt_1s"
    } else if latency_ms < 10_000.0 {
        "lt_10s"
    } else {
        "ge_10s"
    }
}

/// Closed label for a request's backend dispatch state.
pub(crate) fn backend_dispatch_label(state: crate::plugins::BackendDispatchState) -> &'static str {
    use crate::plugins::BackendDispatchState;
    match state {
        BackendDispatchState::NotDispatched => "not_dispatched",
        BackendDispatchState::BackendResponse => "backend_response",
        BackendDispatchState::PreWireFailure => "pre_wire_failure",
        BackendDispatchState::AmbiguousFailure => "ambiguous_failure",
    }
}

/// Per-request rendezvous between the response stamp (which mints the
/// reference) and the terminal transaction log (which knows the detail).
/// Either may happen first: a buffered response logs before hyper receives
/// it, a streamed one after its body ends. The store keeps the slot, so a
/// lookup always reads whatever detail has been recorded by then.
#[derive(Debug, Default)]
pub struct DiagnosticSlot {
    detail: OnceLock<DiagnosticDetail>,
    minted: OnceLock<String>,
}

impl DiagnosticSlot {
    /// A fresh, shareable slot for one request.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record the request's detail. The first record wins, so a later summary
    /// for the same request (a mirror, a retry bookkeeping pass) cannot
    /// replace the one that described the client-visible response.
    pub fn record_detail(&self, detail: DiagnosticDetail) {
        let _ = self.detail.set(detail);
    }

    pub fn detail(&self) -> Option<&DiagnosticDetail> {
        self.detail.get()
    }

    /// The reference already minted for this request, if any.
    pub fn minted_ref(&self) -> Option<&str> {
        self.minted.get().map(String::as_str)
    }
}

/// Copy the request's detail into its slot from the terminal summary.
///
/// Only a summary that can accompany an `X-Gateway-Error` token (a 5xx or a
/// classified dispatch error) is recorded, so the enabled feature does not
/// copy strings for every successful request.
pub(crate) fn record_request_detail(
    slot: &DiagnosticSlot,
    summary: &TransactionSummary,
    ctx: &crate::plugins::RequestContext,
) {
    if slot.detail.get().is_some()
        || (summary.response_status_code < 500 && summary.error_class.is_none())
    {
        return;
    }
    slot.record_detail(DiagnosticDetail::from_summary(
        summary,
        backend_dispatch_label(ctx.backend_dispatch_state()),
        ctx.route_request_timeout_phase(),
    ));
}

fn rfc3339_millis(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Encode 16 random bytes as a reference.
fn encode_ref(key: &[u8; DIAGNOSTIC_REF_RANDOM_BYTES]) -> String {
    let mut out = String::with_capacity(DIAGNOSTIC_REF_LEN);
    out.push_str(DIAGNOSTIC_REF_PREFIX);
    for byte in key {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Decode a reference into its random key. Only the exact
/// `fd1_<32 lowercase hex>` shape is accepted.
fn parse_ref(reference: &str) -> Option<[u8; DIAGNOSTIC_REF_RANDOM_BYTES]> {
    if reference.len() != DIAGNOSTIC_REF_LEN {
        return None;
    }
    let hex = reference.strip_prefix(DIAGNOSTIC_REF_PREFIX)?.as_bytes();
    let mut key = [0u8; DIAGNOSTIC_REF_RANDOM_BYTES];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        *key.get_mut(index)? = (high << 4) | low;
    }
    Some(key)
}

/// Whether `reference` has the exact `fd1_<32 lowercase hex>` shape.
pub fn is_well_formed_ref(reference: &str) -> bool {
    parse_ref(reference).is_some()
}

#[derive(Debug)]
struct Entry {
    created_at: DateTime<Utc>,
    expires_at_wall: DateTime<Utc>,
    expires_at: Instant,
    protocol: DiagnosticProtocol,
    status: u16,
    gateway_error: &'static str,
    slot: Option<Arc<DiagnosticSlot>>,
}

type RefKey = [u8; DIAGNOSTIC_REF_RANDOM_BYTES];

/// One independently locked partition. `order` is insertion order, which is
/// also expiry order because every entry shares the store's TTL.
#[derive(Debug, Default)]
struct Shard {
    entries: HashMap<RefKey, Entry>,
    order: VecDeque<(RefKey, Instant)>,
}

impl Shard {
    /// Drop every entry whose TTL has elapsed. Returns how many were removed.
    fn purge_expired(&mut self, now: Instant) -> u64 {
        let mut purged = 0;
        while let Some(&(key, expires_at)) = self.order.front() {
            if expires_at > now {
                break;
            }
            self.order.pop_front();
            if self.entries.remove(&key).is_some() {
                purged += 1;
            }
        }
        purged
    }

    /// Drop the oldest live entry. Returns whether one was removed.
    fn evict_oldest(&mut self) -> bool {
        while let Some((key, _)) = self.order.pop_front() {
            if self.entries.remove(&key).is_some() {
                return true;
            }
        }
        false
    }
}

/// Bounded result label of one admin lookup, for
/// `ferrum_diagnostic_ref_lookups_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticRefLookupResult {
    Found,
    NotFound,
    Forbidden,
    RateLimited,
}

impl DiagnosticRefLookupResult {
    pub const ALL: [Self; 4] = [
        Self::Found,
        Self::NotFound,
        Self::Forbidden,
        Self::RateLimited,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::RateLimited => "rate_limited",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Found => 0,
            Self::NotFound => 1,
            Self::Forbidden => 2,
            Self::RateLimited => 3,
        }
    }
}

/// Versioned lookup body (`schema_version` = [`DIAGNOSTIC_REF_SCHEMA_VERSION`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticRefView {
    pub schema_version: &'static str,
    #[serde(rename = "ref")]
    pub reference: String,
    pub namespace: String,
    pub created_at: String,
    pub expires_at: String,
    pub protocol: DiagnosticProtocol,
    pub status: u16,
    pub gateway_error: &'static str,
    /// `false` until the request's terminal transaction summary has been
    /// recorded (a streamed response records it when its body ends), and
    /// for gateway fences that answer before a request context exists.
    pub detail_available: bool,
    pub detail: Option<DiagnosticDetail>,
}

/// Bounded, TTL-limited, sharded in-memory reference store for one gateway
/// process. Every reference it holds was minted for this process's data-plane
/// namespace.
#[derive(Debug)]
pub struct DiagnosticRefStore {
    namespace: Arc<str>,
    ttl: Duration,
    ttl_wall: chrono::Duration,
    per_shard_capacity: usize,
    lookup_rate_per_second: u32,
    shards: Box<[Mutex<Shard>]>,
    epoch: Instant,
    /// Fixed one-second lookup window: high 32 bits are the window's second
    /// since `epoch`, low 32 bits the lookups admitted in it.
    rate_window: AtomicU64,
    minted_total: AtomicU64,
    evicted_capacity_total: AtomicU64,
    evicted_expired_total: AtomicU64,
    lookups_total: [AtomicU64; 4],
}

impl DiagnosticRefStore {
    /// Build a store. Out-of-range bounds are clamped to the documented
    /// limits, so a store can never be unbounded.
    pub fn new(namespace: impl Into<Arc<str>>, config: DiagnosticRefStoreConfig) -> Self {
        let ttl = config.ttl.clamp(
            Duration::from_secs(MIN_TTL_SECONDS),
            Duration::from_secs(MAX_TTL_SECONDS),
        );
        let max_entries = config.max_entries.clamp(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES);
        Self {
            namespace: namespace.into(),
            ttl,
            ttl_wall: chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero()),
            per_shard_capacity: (max_entries / SHARD_COUNT).max(1),
            lookup_rate_per_second: config
                .lookup_rate_per_second
                .clamp(MIN_LOOKUP_RATE_PER_SECOND, MAX_LOOKUP_RATE_PER_SECOND),
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(Shard::default()))
                .collect(),
            epoch: Instant::now(),
            rate_window: AtomicU64::new(0),
            minted_total: AtomicU64::new(0),
            evicted_capacity_total: AtomicU64::new(0),
            evicted_expired_total: AtomicU64::new(0),
            lookups_total: Default::default(),
        }
    }

    /// Namespace every reference in this store belongs to.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Effective reference lifetime.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Effective retained-reference ceiling (never above the configured one).
    pub fn capacity(&self) -> usize {
        self.per_shard_capacity * SHARD_COUNT
    }

    fn lock_shard(&self, key: &RefKey) -> MutexGuard<'_, Shard> {
        let index = usize::from(key[0]) % self.shards.len();
        // A panic while holding a shard lock cannot leave a half-written
        // entry the next caller could misread (every mutation is a single
        // map/deque operation), so recovering the guard is safe and keeps the
        // store serving instead of propagating the poison into request paths.
        self.shards[index]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Mint and retain a reference for a response carrying `gateway_error`.
    pub fn mint(
        &self,
        protocol: DiagnosticProtocol,
        status: u16,
        gateway_error: &'static str,
        slot: Option<&Arc<DiagnosticSlot>>,
    ) -> Option<String> {
        self.mint_at(Instant::now(), protocol, status, gateway_error, slot)
    }

    /// [`Self::mint`] against an explicit monotonic clock.
    ///
    /// A request that already minted a reference gets the same one back, so a
    /// response is never described by two references. A CSPRNG failure mints
    /// nothing: the response simply carries no reference.
    pub fn mint_at(
        &self,
        now: Instant,
        protocol: DiagnosticProtocol,
        status: u16,
        gateway_error: &'static str,
        slot: Option<&Arc<DiagnosticSlot>>,
    ) -> Option<String> {
        if let Some(existing) = slot.and_then(|slot| slot.minted.get()) {
            return Some(existing.clone());
        }
        let mut key = [0u8; DIAGNOSTIC_REF_RANDOM_BYTES];
        if SystemRandom::new().fill(&mut key).is_err() {
            return None;
        }
        let reference = encode_ref(&key);
        if let Some(slot) = slot
            && slot.minted.set(reference.clone()).is_err()
        {
            // A concurrent stamp of the same request won the slot.
            return slot.minted.get().cloned();
        }
        let created_at = Utc::now();
        let entry = Entry {
            created_at,
            expires_at_wall: created_at
                .checked_add_signed(self.ttl_wall)
                .unwrap_or(created_at),
            // An unrepresentable deadline expires immediately (fail closed).
            expires_at: now.checked_add(self.ttl).unwrap_or(now),
            protocol,
            status,
            gateway_error,
            slot: slot.cloned(),
        };
        let expires_at = entry.expires_at;
        let (expired, evicted) = {
            let mut shard = self.lock_shard(&key);
            let expired = shard.purge_expired(now);
            let mut evicted = 0u64;
            while shard.entries.len() >= self.per_shard_capacity {
                if !shard.evict_oldest() {
                    break;
                }
                evicted += 1;
            }
            shard.order.push_back((key, expires_at));
            shard.entries.insert(key, entry);
            (expired, evicted)
        };
        self.minted_total.fetch_add(1, Ordering::Relaxed);
        if expired > 0 {
            self.evicted_expired_total
                .fetch_add(expired, Ordering::Relaxed);
        }
        if evicted > 0 {
            self.evicted_capacity_total
                .fetch_add(evicted, Ordering::Relaxed);
        }
        Some(reference)
    }

    /// Resolve a reference. `None` for a malformed, unknown, expired, or
    /// evicted reference. Callers authorize the returned namespace.
    pub fn lookup_at(&self, now: Instant, reference: &str) -> Option<DiagnosticRefView> {
        let key = parse_ref(reference)?;
        let (expired, view) = {
            let mut shard = self.lock_shard(&key);
            let expired = shard.purge_expired(now);
            let view = match shard.entries.get(&key) {
                Some(entry) if entry.expires_at > now => Some(self.view(reference, entry)),
                _ => None,
            };
            (expired, view)
        };
        if expired > 0 {
            self.evicted_expired_total
                .fetch_add(expired, Ordering::Relaxed);
        }
        view
    }

    fn view(&self, reference: &str, entry: &Entry) -> DiagnosticRefView {
        let detail = entry.slot.as_ref().and_then(|slot| slot.detail().cloned());
        DiagnosticRefView {
            schema_version: DIAGNOSTIC_REF_SCHEMA_VERSION,
            reference: reference.to_string(),
            namespace: self.namespace.to_string(),
            created_at: rfc3339_millis(entry.created_at),
            expires_at: rfc3339_millis(entry.expires_at_wall),
            protocol: entry.protocol,
            status: entry.status,
            gateway_error: entry.gateway_error,
            detail_available: detail.is_some(),
            detail,
        }
    }

    /// Admit one admin lookup against the fixed one-second window.
    pub fn try_acquire_lookup_at(&self, now: Instant) -> bool {
        let window = now.saturating_duration_since(self.epoch).as_secs() & 0xFFFF_FFFF;
        let limit = u64::from(self.lookup_rate_per_second);
        let mut current = self.rate_window.load(Ordering::Relaxed);
        loop {
            let current_window = current >> 32;
            let count = current & 0xFFFF_FFFF;
            let next = if current_window != window {
                (window << 32) | 1
            } else if count >= limit {
                return false;
            } else {
                current + 1
            };
            match self.rate_window.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Count one admin lookup outcome.
    pub fn record_lookup(&self, result: DiagnosticRefLookupResult) {
        self.lookups_total[result.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// References currently retained (expired ones are counted until the next
    /// operation on their shard purges them).
    pub fn len(&self) -> usize {
        let mut total = 0;
        for shard in self.shards.iter() {
            let guard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            total += guard.entries.len();
        }
        total
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn minted_total(&self) -> u64 {
        self.minted_total.load(Ordering::Relaxed)
    }

    pub fn evicted_capacity_total(&self) -> u64 {
        self.evicted_capacity_total.load(Ordering::Relaxed)
    }

    pub fn evicted_expired_total(&self) -> u64 {
        self.evicted_expired_total.load(Ordering::Relaxed)
    }

    pub fn lookups_total(&self, result: DiagnosticRefLookupResult) -> u64 {
        self.lookups_total[result.index()].load(Ordering::Relaxed)
    }

    /// Prometheus exposition for this store. Cold path (scrape only).
    pub fn render_prometheus(&self) -> String {
        let mut output = String::with_capacity(1_536);
        output.push_str(
            "# HELP ferrum_diagnostic_ref_lookups_total Authenticated admin diagnostic reference lookups, by bounded result.\n\
# TYPE ferrum_diagnostic_ref_lookups_total counter\n",
        );
        for result in DiagnosticRefLookupResult::ALL {
            output.push_str(&format!(
                "ferrum_diagnostic_ref_lookups_total{{result=\"{}\"}} {}\n",
                result.as_str(),
                self.lookups_total(result)
            ));
        }
        output.push_str(
            "# HELP ferrum_diagnostic_refs_entries Diagnostic references currently retained in the bounded in-memory store.\n\
# TYPE ferrum_diagnostic_refs_entries gauge\n",
        );
        output.push_str(&format!("ferrum_diagnostic_refs_entries {}\n", self.len()));
        output.push_str(
            "# HELP ferrum_diagnostic_refs_evicted_total Diagnostic references removed from the store before lookup, by bounded reason.\n\
# TYPE ferrum_diagnostic_refs_evicted_total counter\n",
        );
        output.push_str(&format!(
            "ferrum_diagnostic_refs_evicted_total{{reason=\"capacity\"}} {}\n",
            self.evicted_capacity_total()
        ));
        output.push_str(&format!(
            "ferrum_diagnostic_refs_evicted_total{{reason=\"expired\"}} {}\n",
            self.evicted_expired_total()
        ));
        output.push_str(
            "# HELP ferrum_diagnostic_refs_minted_total Diagnostic references minted on gateway-authored error responses.\n\
# TYPE ferrum_diagnostic_refs_minted_total counter\n",
        );
        output.push_str(&format!(
            "ferrum_diagnostic_refs_minted_total {}\n",
            self.minted_total()
        ));
        output
    }
}

/// Strip every client-bound copy of the reference header, then stamp a fresh
/// reference when the response carries a gateway-authored `X-Gateway-Error`
/// token from the closed vocabulary. Returns the stamped reference.
///
/// `http::HeaderMap` normalizes field names to lowercase, so the one `remove`
/// drops every spelling and every repeated value a plugin or hook left.
pub fn stamp_response_headers(
    store: &DiagnosticRefStore,
    slot: Option<&Arc<DiagnosticSlot>>,
    protocol: DiagnosticProtocol,
    status: u16,
    headers: &mut http::HeaderMap,
) -> Option<String> {
    headers.remove(DIAGNOSTIC_REF_HEADER);
    let token = headers
        .get(crate::proxy::headers::X_GATEWAY_ERROR_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::retry::intern_http_observability_error_class)?;
    let reference = store.mint(protocol, status, token, slot)?;
    let value = http::HeaderValue::from_str(&reference).ok()?;
    // `DIAGNOSTIC_REF_HEADER` is a compile-time lowercase field-name literal,
    // the documented invariant `IntoHeaderName` for `&'static str` requires.
    headers.insert(DIAGNOSTIC_REF_HEADER, value);
    Some(reference)
}

/// Outcome of an authorized admin lookup.
#[derive(Debug)]
pub enum DiagnosticRefLookup {
    Found(Box<DiagnosticRefView>),
    /// Malformed, unknown, expired, evicted, outside the caller's namespaces,
    /// or the feature is off: one answer, so references cannot be probed.
    NotFound,
    /// The admin JWT lacks the `diagnostics:read` scope.
    MissingScope,
    /// The admin JWT carries no `ns` claim, so it is not namespace-bound.
    MissingNamespaceBinding,
    RateLimited,
}

impl DiagnosticRefLookup {
    /// Bounded metric / audit label.
    pub fn result(&self) -> DiagnosticRefLookupResult {
        match self {
            Self::Found(_) => DiagnosticRefLookupResult::Found,
            Self::NotFound => DiagnosticRefLookupResult::NotFound,
            Self::MissingScope | Self::MissingNamespaceBinding => {
                DiagnosticRefLookupResult::Forbidden
            }
            Self::RateLimited => DiagnosticRefLookupResult::RateLimited,
        }
    }
}

/// Authorize and resolve one admin lookup.
///
/// Order is fixed and independent of the reference: the scope and namespace
/// binding are checked first (they depend only on the credential), then the
/// rate limit, then the store. A reference that exists but belongs to a
/// namespace the token does not name answers exactly like an unknown one.
pub fn authorize_lookup(
    store: Option<&DiagnosticRefStore>,
    scope_granted: bool,
    allowed_namespaces: &crate::grpc::auth::AllowedNamespaces,
    reference: &str,
    now: Instant,
) -> DiagnosticRefLookup {
    let outcome = if !scope_granted {
        DiagnosticRefLookup::MissingScope
    } else if !allowed_namespaces.is_present() {
        DiagnosticRefLookup::MissingNamespaceBinding
    } else if let Some(store) = store {
        if !store.try_acquire_lookup_at(now) {
            DiagnosticRefLookup::RateLimited
        } else {
            match store.lookup_at(now, reference) {
                Some(view) if allowed_namespaces.allows(&view.namespace) => {
                    DiagnosticRefLookup::Found(Box::new(view))
                }
                _ => DiagnosticRefLookup::NotFound,
            }
        }
    } else {
        DiagnosticRefLookup::NotFound
    };
    if let Some(store) = store {
        store.record_lookup(outcome.result());
    }
    outcome
}

static ACTIVE_STORE: OnceLock<DiagnosticRefStore> = OnceLock::new();

/// Publish the process store from the accepted configuration. `off` installs
/// nothing. Called once at startup, before any listener accepts traffic.
pub fn install(
    mode: DiagnosticRefMode,
    namespace: &str,
    config: DiagnosticRefStoreConfig,
) -> Result<(), String> {
    if !mode.is_enabled() {
        return Ok(());
    }
    let store = DiagnosticRefStore::new(namespace, config);
    ACTIVE_STORE
        .set(store)
        .map_err(|_| ALREADY_INSTALLED_ERROR.to_string())
}

const ALREADY_INSTALLED_ERROR: &str =
    "diagnostic reference store is already installed for this process";

/// [`install`] from an accepted [`crate::config::EnvConfig`].
pub fn install_from_env_config(env_config: &crate::config::EnvConfig) -> Result<(), String> {
    install(
        env_config.diagnostic_refs,
        &env_config.namespace,
        DiagnosticRefStoreConfig {
            ttl: Duration::from_secs(env_config.diagnostic_ref_ttl_seconds),
            max_entries: env_config.diagnostic_ref_max_entries,
            lookup_rate_per_second: env_config.diagnostic_ref_lookup_rate_per_second,
        },
    )
}

/// The process store, or `None` when references are off.
pub fn active_store() -> Option<&'static DiagnosticRefStore> {
    ACTIVE_STORE.get()
}

/// `/metrics` families; empty when references are off.
pub fn render_prometheus() -> String {
    active_store()
        .map(DiagnosticRefStore::render_prometheus)
        .unwrap_or_default()
}

/// HTTP/1.1 and HTTP/2 per-request handle, created at the frontend service
/// boundary and applied to the response that boundary returns.
pub(crate) struct RequestDiagnostic {
    store: &'static DiagnosticRefStore,
    slot: Arc<DiagnosticSlot>,
    protocol: DiagnosticProtocol,
}

impl RequestDiagnostic {
    /// `None` (one `OnceLock` load, no allocation) when references are off.
    pub(crate) fn begin(protocol: DiagnosticProtocol) -> Option<Self> {
        active_store().map(|store| Self {
            store,
            slot: DiagnosticSlot::shared(),
            protocol,
        })
    }

    pub(crate) fn slot(&self) -> Arc<DiagnosticSlot> {
        Arc::clone(&self.slot)
    }

    pub(crate) fn stamp(&self, status: u16, headers: &mut http::HeaderMap) {
        let _ = stamp_response_headers(
            self.store,
            Some(&self.slot),
            self.protocol,
            status,
            headers,
        );
    }
}

tokio::task_local! {
    /// The HTTP/3 request's slot. HTTP/3 writes response heads from many
    /// helpers deep inside the request task, so the slot rides the task
    /// instead of every helper signature. Set only when references are on.
    static H3_REQUEST_SLOT: Arc<DiagnosticSlot>;
}

/// Drive an HTTP/3 request future with a fresh diagnostic slot as its
/// task-local when references are on, and directly when they are off.
///
/// The request future is taken by pinned reference, never by value, so the
/// wrapper adds a pointer and the slot to the request task instead of a second
/// copy of the (large) `handle_h3_request` future. Tokio swaps the slot into
/// the task-local on each poll; nothing is cloned or allocated per poll.
pub(crate) async fn run_h3_request<F: Future>(request: Pin<&mut F>) -> F::Output {
    if active_store().is_none() {
        return request.await;
    }
    let slot = DiagnosticSlot::shared();
    H3_REQUEST_SLOT.scope(slot, request).await
}

/// The current HTTP/3 request's slot. `None` when references are off or
/// outside a scoped request task.
pub(crate) fn current_h3_slot() -> Option<Arc<DiagnosticSlot>> {
    active_store()?;
    H3_REQUEST_SLOT.try_with(Arc::clone).ok()
}

/// Final stamp for an HTTP/3 response head, applied at every `send_response`
/// site. Identity (no work beyond one `OnceLock` load) when references are
/// off.
pub(crate) fn stamp_h3_response(mut response: http::Response<()>) -> http::Response<()> {
    if let Some(store) = active_store() {
        let slot = H3_REQUEST_SLOT.try_with(Arc::clone).ok();
        let status = response.status().as_u16();
        let _ = stamp_response_headers(
            store,
            slot.as_ref(),
            DiagnosticProtocol::Http3,
            status,
            response.headers_mut(),
        );
    }
    response
}
