//! Istio `AuthorizationPolicy` `action: CUSTOM` external authorization
//! execution (issue #3235).
//!
//! This module owns everything between "a CUSTOM rule matched" and "the request
//! is allowed or denied". It is deliberately separate from `mesh_authz`'s
//! matcher so the delegation contract can be reasoned about (and tested) on its
//! own.
//!
//! ## Where it runs
//!
//! Inside the `mesh_authz` plugin's `authorize` phase (priority
//! [`crate::plugins::priority::MESH_AUTHZ`], step 3 of the plugin lifecycle),
//! i.e. after authentication and before `before_proxy`. Every HTTP-family
//! ingress path that runs the plugin chain reaches it identically — HTTP/1.1,
//! HTTP/2, native gRPC, and HTTP/3 — because they all funnel through the same
//! `authorize` ladder.
//!
//! Layer-4 sessions (`on_stream_connect`: raw TCP, TLS passthrough, UDP, DTLS)
//! have no HTTP request to check and therefore CANNOT run a provider check.
//! They do not silently skip it: `evaluate_mesh_authorization_policies` turns a
//! matched-but-unexecutable CUSTOM delegation into a denial. A CUSTOM policy
//! whose rules match an L4 connection closes it rather than serving it
//! unchecked. A mesh/HBONE CONNECT relay is treated the same way: the requests
//! inside the tunnel are opaque bytes, so `mesh_authz` refuses a matched
//! delegation instead of asking the provider about the CONNECT itself.
//!
//! ## Fail-closed contract
//!
//! Unless the provider explicitly sets `failOpen`, EVERY non-allow outcome
//! denies with the provider's configured `statusOnError`:
//!
//! * connect / TLS / transport failure
//! * timeout (bounded per provider, ceiling
//!   [`crate::modes::mesh::config::MESH_EXT_AUTHZ_MAX_TIMEOUT_MS`])
//! * concurrency ceiling reached (refused immediately; never queued)
//! * an unreadable response, or a `200` allow response larger than the fixed
//!   read bound
//! * an HTTP `5xx` from the provider (it could not decide)
//! * a body that could not be materialized for a provider that requires one
//! * task cancellation (the future is dropped without producing an allow)
//!
//! Outcome classification follows the Istio/Envoy HTTP ext-auth protocol
//! exactly: HTTP `200` — and only `200` — allows; `5xx` (like a transport
//! failure) is a FAILED CHECK subject to `failOpen`, resolving to
//! `statusOnError` when fail-closed; every other status (3xx / 4xx, and any
//! non-`200` 2xx) is an explicit provider denial carrying the provider's own
//! status — except one that cannot frame the gateway-authored error body
//! (`1xx`, a non-`200` 2xx such as `204`, and `304`), which is emitted as a
//! plain `403` (see `client_visible_denial_status`).
//! Because Ferrum never uses or forwards the provider response body,
//! an unreadable or oversized body cannot turn an explicit denial into a
//! failed check that `failOpen` would admit.
//!
//! THREE refusals are decided WITHOUT contacting a provider and are therefore
//! NOT subject to `failOpen`: a request to which two DIFFERENT extension
//! providers would apply (Istio permits at most one per workload), a matched
//! delegation on a path with no HTTP request to check, and a request body over
//! the SELECTED provider's own `maxRequestBytes` (see below).
//!
//! Nothing is retried. The shared plugin HTTP client's transport-retry policy
//! is explicitly suppressed through a single-attempt seam: an ext-authz check
//! is usually a `GET`, so inheriting the shared policy would turn one client
//! request into several authorization decisions.
//!
//! ## Request-body contract
//!
//! `includeRequestBodyInCheck.maxRequestBytes` is folded into the proxy's
//! pre-`authorize` body ceiling, so an over-cap request is refused with `413`
//! before a check is dispatched. That shared ceiling is the MAXIMUM
//! `maxRequestBytes` across the generation's providers, because ONE prebuffer
//! serves whichever provider the matched CUSTOM rule selects — it is NOT
//! necessarily the selected provider's own cap. A generation carrying a
//! higher-cap provider therefore lets a body over a LOWER-cap provider's
//! `maxRequestBytes` reach [`MeshExtAuthzExecutor::check`].
//!
//! The per-provider cap is what actually decides the request, and it is
//! enforced here as an UNCONDITIONAL client-facing `413` refusal, before any
//! provider I/O and before a concurrency permit is taken. It is never subject
//! to `failOpen`: `allowPartialMessage: true` is refused at every admission
//! boundary (see `MeshExtAuthzProvider::validate`), so a strict provider must
//! decide on the complete body or not decide at all — allowing an oversize
//! request because the provider opted into `failOpen` for FAILED CHECKS would
//! admit exactly the request the operator's cap excluded. A body that is
//! missing (rather than too large) remains a failed check and keeps honouring
//! `failOpen`, as do transport failures.
//!
//! That ceiling applies only to requests a body-inspecting CUSTOM rule could
//! actually reach: `MeshAuthz::should_buffer_request_body` gates it, so an
//! unrelated request on the same workload keeps its ordinary accepted body
//! size.
//!
//! ## What never leaves the process
//!
//! No request body, `authorization`/`cookie` value, provider credential, or
//! resolved provider URL is ever logged. Diagnostics carry a fixed-cardinality
//! reason token only. The process-wide series are labelled by that reason and
//! by nothing else. The per-provider series add exactly one more label, the
//! OPERATOR-ADMITTED provider name (bounded per generation by
//! `MAX_MESH_EXT_AUTHZ_PROVIDERS` and per process by
//! [`MAX_PROVIDER_STATS_ENTRIES`]) — never a namespace, route, host,
//! principal, status string, or any other request-supplied value.
//!
//! ## What the check carries about the caller
//!
//! Besides the headers the operator names, every check carries the
//! GATEWAY-ASSERTED identity the local rules were evaluated against:
//! `x-ferrum-source-principal` (the authenticated source SPIFFE ID, after a
//! trusted HBONE assertor's baggage rewrite), `x-ferrum-source-namespace` and
//! `x-ferrum-source-service-account` (its Kubernetes components), and
//! `x-ferrum-request-principal` (the validated JWT `iss/sub`). A client cannot
//! forge them: provider admission refuses every `x-ferrum-*` name in
//! `includeRequestHeadersInCheck` / `includeAdditionalHeadersInCheck`, and the
//! executor removes the names before stamping them, so the provider only ever
//! sees the gateway's own value — or no header at all when the identity is
//! unknown.
//!
//! ## Allowed-request mutations
//!
//! `headersToUpstreamOnAllow` / `headersToDownstreamOnAllow` are honoured on an
//! allowed check: the named provider response headers are returned on
//! [`MeshExtAuthzOutcome::Allow`] and `mesh_authz` applies them in its own
//! `before_proxy` / `after_proxy` hooks (see `docs/mesh.md`). A provider's
//! response body is still never consumed.

use crate::plugins::utils::log_sampling::warn_sampled;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use tokio::sync::Semaphore;

use crate::identity::SpiffeId;
use crate::modes::mesh::config::{
    MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES, MESH_EXT_AUTHZ_PROCESS_CONCURRENT_CALLS,
    MeshExtAuthzBodyCheck, MeshExtAuthzProvider,
};
use crate::plugins::PluginHttpClient;
use crate::plugins::utils::response_body::{BoundedReadError, read_response_body_bounded};

/// Fixed-cardinality outcome classes. These are the ONLY metric label values
/// this module ever emits, and the only tokens that reach a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshExtAuthzReason {
    Allowed,
    DeniedByProvider,
    ProviderUnbound,
    /// The provider answered, but with an HTTP 5xx. Istio/Envoy treat this as
    /// a failed check (subject to `failOpen`), NOT as a provider denial.
    ProviderError,
    /// Two DIFFERENT extension providers were applicable to one request.
    /// Istio permits at most one per workload, so this is refused rather than
    /// resolved by iteration order.
    ProviderConflict,
    /// A matched CUSTOM delegation on a path that has no HTTP request to
    /// check (an L4 TCP/TLS/UDP session), or in a generation with no
    /// executor. Always a denial.
    Unexecutable,
    Timeout,
    TransportError,
    ResponseTooLarge,
    ResponseReadFailed,
    /// A body-inspecting provider had no body to inspect. A FAILED CHECK: the
    /// provider could not decide, so `failOpen` still applies.
    BodyUnavailable,
    /// The request body exceeded the SELECTED provider's `maxRequestBytes`.
    /// Decided without contacting the provider and never subject to
    /// `failOpen` — `allowPartialMessage` is refused at admission, so there is
    /// no truncated representation the provider could have decided on.
    BodyTooLarge,
    ConcurrencyExhausted,
    RequestBuildFailed,
}

/// Every reason, in a fixed order. Indexes the per-provider outcome counters.
const ALL_REASONS: [MeshExtAuthzReason; 14] = [
    MeshExtAuthzReason::Allowed,
    MeshExtAuthzReason::DeniedByProvider,
    MeshExtAuthzReason::ProviderUnbound,
    MeshExtAuthzReason::ProviderError,
    MeshExtAuthzReason::ProviderConflict,
    MeshExtAuthzReason::Unexecutable,
    MeshExtAuthzReason::Timeout,
    MeshExtAuthzReason::TransportError,
    MeshExtAuthzReason::ResponseTooLarge,
    MeshExtAuthzReason::ResponseReadFailed,
    MeshExtAuthzReason::BodyUnavailable,
    MeshExtAuthzReason::BodyTooLarge,
    MeshExtAuthzReason::ConcurrencyExhausted,
    MeshExtAuthzReason::RequestBuildFailed,
];

impl MeshExtAuthzReason {
    /// Position in [`ALL_REASONS`].
    fn index(self) -> usize {
        match self {
            MeshExtAuthzReason::Allowed => 0,
            MeshExtAuthzReason::DeniedByProvider => 1,
            MeshExtAuthzReason::ProviderUnbound => 2,
            MeshExtAuthzReason::ProviderError => 3,
            MeshExtAuthzReason::ProviderConflict => 4,
            MeshExtAuthzReason::Unexecutable => 5,
            MeshExtAuthzReason::Timeout => 6,
            MeshExtAuthzReason::TransportError => 7,
            MeshExtAuthzReason::ResponseTooLarge => 8,
            MeshExtAuthzReason::ResponseReadFailed => 9,
            MeshExtAuthzReason::BodyUnavailable => 10,
            MeshExtAuthzReason::BodyTooLarge => 11,
            MeshExtAuthzReason::ConcurrencyExhausted => 12,
            MeshExtAuthzReason::RequestBuildFailed => 13,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MeshExtAuthzReason::Allowed => "allowed",
            MeshExtAuthzReason::DeniedByProvider => "denied_by_provider",
            MeshExtAuthzReason::ProviderUnbound => "provider_unbound",
            MeshExtAuthzReason::ProviderError => "provider_error",
            MeshExtAuthzReason::ProviderConflict => "provider_conflict",
            MeshExtAuthzReason::Unexecutable => "unexecutable",
            MeshExtAuthzReason::Timeout => "timeout",
            MeshExtAuthzReason::TransportError => "transport_error",
            MeshExtAuthzReason::ResponseTooLarge => "response_too_large",
            MeshExtAuthzReason::ResponseReadFailed => "response_read_failed",
            MeshExtAuthzReason::BodyUnavailable => "body_unavailable",
            MeshExtAuthzReason::BodyTooLarge => "body_too_large",
            MeshExtAuthzReason::ConcurrencyExhausted => "concurrency_exhausted",
            MeshExtAuthzReason::RequestBuildFailed => "request_build_failed",
        }
    }

    /// Whether the outcome represents a failed check (as opposed to a clean
    /// allow or an explicit provider denial). Only these are subject to
    /// `failOpen`.
    ///
    /// `ProviderConflict`, `Unexecutable`, and `BodyTooLarge` are deliberately
    /// excluded: they are configuration/contract refusals decided WITHOUT
    /// contacting a provider, so no provider's `failOpen` opinion applies to
    /// them. They are still counted, once, in the check-outcome series.
    fn is_check_failure(self) -> bool {
        !matches!(
            self,
            MeshExtAuthzReason::Allowed
                | MeshExtAuthzReason::DeniedByProvider
                | MeshExtAuthzReason::ProviderConflict
                | MeshExtAuthzReason::Unexecutable
                | MeshExtAuthzReason::BodyTooLarge
        )
    }
}

/// The result of one external authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshExtAuthzOutcome {
    /// The request may continue.
    ///
    /// `upstream_headers` / `downstream_headers` are the provider response
    /// headers named by `headersToUpstreamOnAllow` /
    /// `headersToDownstreamOnAllow`, as `(lowercase name, value)` pairs (one
    /// pair per name; repeated field lines are folded, `Set-Cookie`
    /// newline-joined). Both are empty unless the provider ANSWERED `200` — a
    /// `failOpen` allow carries nothing, because no provider vouched for
    /// anything.
    Allow {
        reason: MeshExtAuthzReason,
        upstream_headers: Vec<(String, String)>,
        downstream_headers: Vec<(String, String)>,
    },
    Deny {
        status: u16,
        headers: Vec<(String, String)>,
        reason: MeshExtAuthzReason,
    },
}

// ── Process-static, fixed-cardinality counters ────────────────────────────

static CHECKS_ALLOWED: AtomicU64 = AtomicU64::new(0);
static CHECKS_DENIED_BY_PROVIDER: AtomicU64 = AtomicU64::new(0);
static CHECKS_FAILED_CLOSED: AtomicU64 = AtomicU64::new(0);
static CHECKS_FAILED_OPEN: AtomicU64 = AtomicU64::new(0);
static CHECKS_UNBOUND_PROVIDER: AtomicU64 = AtomicU64::new(0);
static CHECKS_PROVIDER_ERROR: AtomicU64 = AtomicU64::new(0);
static CHECKS_PROVIDER_CONFLICT: AtomicU64 = AtomicU64::new(0);
static CHECKS_UNEXECUTABLE: AtomicU64 = AtomicU64::new(0);
static CHECKS_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static CHECKS_TRANSPORT_ERROR: AtomicU64 = AtomicU64::new(0);
static CHECKS_RESPONSE_REFUSED: AtomicU64 = AtomicU64::new(0);
static CHECKS_BODY_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
static CHECKS_BODY_TOO_LARGE: AtomicU64 = AtomicU64::new(0);
static CHECKS_CONCURRENCY_EXHAUSTED: AtomicU64 = AtomicU64::new(0);

/// Record exactly one outcome for one matched CUSTOM delegation.
///
/// Every terminal path — including the ones decided WITHOUT contacting a
/// provider (unbound name, no executor, an L4 session, two applicable
/// providers) — funnels through here, so a matched delegation is never
/// invisible in the metrics and never counted twice. Labels stay a closed
/// enum: never a provider name, policy name, namespace, route, host, or
/// principal.
pub(crate) fn record(reason: MeshExtAuthzReason, failed_open: bool) {
    match reason {
        MeshExtAuthzReason::Allowed => CHECKS_ALLOWED.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::DeniedByProvider => {
            CHECKS_DENIED_BY_PROVIDER.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::ProviderUnbound => {
            CHECKS_UNBOUND_PROVIDER.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::ProviderError => CHECKS_PROVIDER_ERROR.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::ProviderConflict => {
            CHECKS_PROVIDER_CONFLICT.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::Unexecutable => CHECKS_UNEXECUTABLE.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::Timeout => CHECKS_TIMEOUT.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::TransportError | MeshExtAuthzReason::RequestBuildFailed => {
            CHECKS_TRANSPORT_ERROR.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::ResponseTooLarge | MeshExtAuthzReason::ResponseReadFailed => {
            CHECKS_RESPONSE_REFUSED.fetch_add(1, Ordering::Relaxed)
        }
        // Deliberately separate series: `body_unavailable` is a failed check
        // that still honours `failOpen`, while `body_too_large` is the
        // unconditional over-cap refusal. Folding them together would hide
        // which of the two an operator is actually seeing.
        MeshExtAuthzReason::BodyUnavailable => {
            CHECKS_BODY_UNAVAILABLE.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::BodyTooLarge => CHECKS_BODY_TOO_LARGE.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::ConcurrencyExhausted => {
            CHECKS_CONCURRENCY_EXHAUSTED.fetch_add(1, Ordering::Relaxed)
        }
    };
    if reason.is_check_failure() {
        if failed_open {
            CHECKS_FAILED_OPEN.fetch_add(1, Ordering::Relaxed);
        } else {
            CHECKS_FAILED_CLOSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Snapshot of the ext-authz counters, for `/metrics` rendering and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct MeshExtAuthzMetricsSnapshot {
    pub allowed: u64,
    pub denied_by_provider: u64,
    pub failed_closed: u64,
    pub failed_open: u64,
    pub provider_unbound: u64,
    pub provider_error: u64,
    pub provider_conflict: u64,
    pub unexecutable: u64,
    pub timeout: u64,
    pub transport_error: u64,
    pub response_refused: u64,
    pub body_unavailable: u64,
    pub body_too_large: u64,
    pub concurrency_exhausted: u64,
}

pub fn snapshot() -> MeshExtAuthzMetricsSnapshot {
    MeshExtAuthzMetricsSnapshot {
        allowed: CHECKS_ALLOWED.load(Ordering::Relaxed),
        denied_by_provider: CHECKS_DENIED_BY_PROVIDER.load(Ordering::Relaxed),
        failed_closed: CHECKS_FAILED_CLOSED.load(Ordering::Relaxed),
        failed_open: CHECKS_FAILED_OPEN.load(Ordering::Relaxed),
        provider_unbound: CHECKS_UNBOUND_PROVIDER.load(Ordering::Relaxed),
        provider_error: CHECKS_PROVIDER_ERROR.load(Ordering::Relaxed),
        provider_conflict: CHECKS_PROVIDER_CONFLICT.load(Ordering::Relaxed),
        unexecutable: CHECKS_UNEXECUTABLE.load(Ordering::Relaxed),
        timeout: CHECKS_TIMEOUT.load(Ordering::Relaxed),
        transport_error: CHECKS_TRANSPORT_ERROR.load(Ordering::Relaxed),
        response_refused: CHECKS_RESPONSE_REFUSED.load(Ordering::Relaxed),
        body_unavailable: CHECKS_BODY_UNAVAILABLE.load(Ordering::Relaxed),
        body_too_large: CHECKS_BODY_TOO_LARGE.load(Ordering::Relaxed),
        concurrency_exhausted: CHECKS_CONCURRENCY_EXHAUSTED.load(Ordering::Relaxed),
    }
}

/// Append the ext-authz series to a `/metrics` render.
///
/// Every series is fixed-cardinality: the only label is the gateway namespace
/// the caller supplies plus a closed `outcome` enum. Provider name, policy
/// name, route, host, and principal are deliberately absent — an ext-authz
/// deny is attacker-triggerable, so labelling by any of them would be an
/// unbounded-cardinality lever.
pub fn render_prometheus(output: &mut String, gateway_ns_label: &str) {
    let snap = snapshot();
    if snap == MeshExtAuthzMetricsSnapshot::default() {
        return;
    }
    output.push_str(
        "# HELP ferrum_mesh_ext_authz_checks_total Istio AuthorizationPolicy CUSTOM external authorization check outcomes.\n",
    );
    output.push_str("# TYPE ferrum_mesh_ext_authz_checks_total counter\n");
    for (outcome, value) in [
        ("allowed", snap.allowed),
        ("denied_by_provider", snap.denied_by_provider),
        ("provider_unbound", snap.provider_unbound),
        ("provider_error", snap.provider_error),
        ("provider_conflict", snap.provider_conflict),
        ("unexecutable", snap.unexecutable),
        ("timeout", snap.timeout),
        ("transport_error", snap.transport_error),
        ("response_refused", snap.response_refused),
        ("body_unavailable", snap.body_unavailable),
        ("body_too_large", snap.body_too_large),
        ("concurrency_exhausted", snap.concurrency_exhausted),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_ext_authz_checks_total{{outcome=\"{outcome}\"{gateway_ns_label}}} {value}\n"
        ));
    }
    output.push_str(
        "# HELP ferrum_mesh_ext_authz_check_failures_total Failed CUSTOM external authorization checks by how the failure was resolved.\n",
    );
    output.push_str("# TYPE ferrum_mesh_ext_authz_check_failures_total counter\n");
    for (disposition, value) in [
        ("fail_closed", snap.failed_closed),
        ("fail_open", snap.failed_open),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_ext_authz_check_failures_total{{disposition=\"{disposition}\"{gateway_ns_label}}} {value}\n"
        ));
    }
    render_provider_prometheus(output, gateway_ns_label);
}

// ── Per-provider attribution (bounded) ────────────────────────────────────

/// Upper bound on distinct provider names that get their own per-provider
/// series for the life of the process. One generation admits at most
/// `MAX_MESH_EXT_AUTHZ_PROVIDERS`; this leaves room for renames across reloads
/// while keeping the label set bounded no matter how many generations publish.
/// Names past the cap share the [`PROVIDER_STATS_OVERFLOW_LABEL`] series.
pub const MAX_PROVIDER_STATS_ENTRIES: usize = 64;

/// Shared per-provider series label once [`MAX_PROVIDER_STATS_ENTRIES`]
/// distinct names have been seen.
pub const PROVIDER_STATS_OVERFLOW_LABEL: &str = "__overflow__";

/// Check-duration histogram bounds, as `(microseconds, rendered seconds)`.
/// The provider timeout ceiling is 30 s, so the top finite bucket covers it.
const CHECK_DURATION_BUCKETS: [(u64, &str); 14] = [
    (1_000, "0.001"),
    (2_500, "0.0025"),
    (5_000, "0.005"),
    (10_000, "0.01"),
    (25_000, "0.025"),
    (50_000, "0.05"),
    (100_000, "0.1"),
    (250_000, "0.25"),
    (500_000, "0.5"),
    (1_000_000, "1"),
    (2_500_000, "2.5"),
    (5_000_000, "5"),
    (10_000_000, "10"),
    (30_000_000, "30"),
];

/// Outcome counters and a check-duration histogram for ONE admitted provider
/// name. Shared by every executor generation that carries the name, so a
/// reload does not reset the series. The request path only touches relaxed
/// atomics through the `Arc` its `PreparedProvider` holds — never the
/// registry lock.
#[derive(Debug)]
struct ProviderStats {
    outcomes: [AtomicU64; ALL_REASONS.len()],
    /// Non-cumulative bucket counts: one per [`CHECK_DURATION_BUCKETS`] bound,
    /// plus a final overflow slot for observations above the largest bound.
    /// There is deliberately NO separate count: [`render_provider_prometheus`]
    /// derives every cumulative bucket, `+Inf`, and `_count` from ONE pass over
    /// these slots, so a scrape racing live observations can never emit a
    /// finite bucket above `+Inf` / `_count`.
    duration_buckets: [AtomicU64; CHECK_DURATION_BUCKETS.len() + 1],
    duration_sum_micros: AtomicU64,
}

impl Default for ProviderStats {
    fn default() -> Self {
        Self {
            outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_sum_micros: AtomicU64::new(0),
        }
    }
}

impl ProviderStats {
    fn record(&self, reason: MeshExtAuthzReason) {
        self.outcomes[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record the time from dispatch to the provider's response headers (or
    /// to the transport failure / timeout that ended the attempt).
    fn observe_duration(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        // An observation past the largest bound lands in the overflow slot.
        let index = CHECK_DURATION_BUCKETS
            .iter()
            .position(|(bound, _)| micros <= *bound)
            .unwrap_or(CHECK_DURATION_BUCKETS.len());
        self.duration_buckets[index].fetch_add(1, Ordering::Relaxed);
        self.duration_sum_micros
            .fetch_add(micros, Ordering::Relaxed);
    }

    /// One consistent read of every duration slot (finite buckets, then the
    /// overflow slot).
    fn duration_snapshot(&self) -> [u64; CHECK_DURATION_BUCKETS.len() + 1] {
        std::array::from_fn(|index| self.duration_buckets[index].load(Ordering::Relaxed))
    }

    /// Number of timed checks: the sum of every duration slot.
    fn duration_total(&self) -> u64 {
        self.duration_snapshot()
            .iter()
            .fold(0u64, |total, count| total.saturating_add(*count))
    }

    fn outcome_total(&self) -> u64 {
        self.outcomes
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }
}

/// Process-wide provider-name → stats registry. Touched only on the cold
/// paths: executor construction (get-or-insert) and `/metrics` rendering.
static PROVIDER_STATS: std::sync::Mutex<Vec<(String, Arc<ProviderStats>)>> =
    std::sync::Mutex::new(Vec::new());

/// The shared stats for `name`, registering it on first sight. Past
/// [`MAX_PROVIDER_STATS_ENTRIES`] distinct names every new name shares the
/// overflow series, so no sequence of reloads can grow the label set.
fn provider_stats(name: &str) -> Arc<ProviderStats> {
    let mut registry = PROVIDER_STATS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, stats)) = registry.iter().find(|(existing, _)| existing == name) {
        return Arc::clone(stats);
    }
    let label = if registry.len() < MAX_PROVIDER_STATS_ENTRIES {
        name
    } else {
        PROVIDER_STATS_OVERFLOW_LABEL
    };
    if let Some((_, stats)) = registry.iter().find(|(existing, _)| existing == label) {
        return Arc::clone(stats);
    }
    let stats = Arc::new(ProviderStats::default());
    registry.push((label.to_string(), Arc::clone(&stats)));
    stats
}

/// One provider's per-provider counters, for tests and diagnostics: the
/// non-zero `(outcome, count)` pairs and the number of timed checks. `None`
/// when the name was never registered.
#[allow(dead_code)] // external integration-test seam; unused in the binary target
pub fn provider_snapshot(name: &str) -> Option<(Vec<(&'static str, u64)>, u64)> {
    let registry = PROVIDER_STATS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_, stats) = registry.iter().find(|(existing, _)| existing == name)?;
    let outcomes = ALL_REASONS
        .iter()
        .filter_map(|reason| {
            let value = stats.outcomes[reason.index()].load(Ordering::Relaxed);
            (value > 0).then_some((reason.as_str(), value))
        })
        .collect();
    Some((outcomes, stats.duration_total()))
}

/// Append the per-provider series. Emitted only for providers that have
/// recorded something, labelled by the admitted provider name only.
fn render_provider_prometheus(output: &mut String, gateway_ns_label: &str) {
    let entries: Vec<(String, Arc<ProviderStats>)> = {
        let registry = PROVIDER_STATS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .iter()
            .map(|(name, stats)| (name.clone(), Arc::clone(stats)))
            .collect()
    };
    if entries.iter().all(|(_, stats)| stats.outcome_total() == 0) {
        return;
    }
    output.push_str(
        "# HELP ferrum_mesh_ext_authz_provider_checks_total CUSTOM external authorization check outcomes per admitted extension provider.\n",
    );
    output.push_str("# TYPE ferrum_mesh_ext_authz_provider_checks_total counter\n");
    for (name, stats) in &entries {
        let provider = crate::plugins::prometheus_metrics::escape_label_value(name);
        for reason in ALL_REASONS {
            let value = stats.outcomes[reason.index()].load(Ordering::Relaxed);
            if value == 0 {
                continue;
            }
            output.push_str(&format!(
                "ferrum_mesh_ext_authz_provider_checks_total{{provider=\"{provider}\",outcome=\"{}\"{gateway_ns_label}}} {value}\n",
                reason.as_str()
            ));
        }
    }
    // One read of every provider's slots, reused below, so each provider's
    // buckets, `+Inf`, and `_count` all describe the same set of observations.
    let durations: Vec<[u64; CHECK_DURATION_BUCKETS.len() + 1]> = entries
        .iter()
        .map(|(_, stats)| stats.duration_snapshot())
        .collect();
    if durations
        .iter()
        .all(|slots| slots.iter().all(|count| *count == 0))
    {
        return;
    }
    output.push_str(
        "# HELP ferrum_mesh_ext_authz_check_duration_seconds Time from dispatching a CUSTOM external authorization check to the provider's response headers (or the failure that ended it), per admitted extension provider.\n",
    );
    output.push_str("# TYPE ferrum_mesh_ext_authz_check_duration_seconds histogram\n");
    for ((name, stats), slots) in entries.iter().zip(&durations) {
        let count = slots
            .iter()
            .fold(0u64, |total, slot| total.saturating_add(*slot));
        if count == 0 {
            continue;
        }
        let provider = crate::plugins::prometheus_metrics::escape_label_value(name);
        let mut cumulative = 0u64;
        for ((_, le), slot) in CHECK_DURATION_BUCKETS.iter().zip(slots.iter()) {
            cumulative = cumulative.saturating_add(*slot);
            output.push_str(&format!(
                "ferrum_mesh_ext_authz_check_duration_seconds_bucket{{provider=\"{provider}\",le=\"{le}\"{gateway_ns_label}}} {cumulative}\n"
            ));
        }
        output.push_str(&format!(
            "ferrum_mesh_ext_authz_check_duration_seconds_bucket{{provider=\"{provider}\",le=\"+Inf\"{gateway_ns_label}}} {count}\n"
        ));
        let sum_seconds = stats.duration_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        output.push_str(&format!(
            "ferrum_mesh_ext_authz_check_duration_seconds_sum{{provider=\"{provider}\"{gateway_ns_label}}} {sum_seconds}\n"
        ));
        output.push_str(&format!(
            "ferrum_mesh_ext_authz_check_duration_seconds_count{{provider=\"{provider}\"{gateway_ns_label}}} {count}\n"
        ));
    }
}

// ── Prepared provider state ───────────────────────────────────────────────

/// One provider, with every per-request cost precomputed at config
/// publication: the check URL base, parsed header names/values, and the
/// timeout. The request path performs no formatting of provider identity and
/// no header-name parsing.
#[derive(Debug)]
struct PreparedProvider {
    check_url_base: String,
    redacted_url: String,
    timeout: Duration,
    fail_open: bool,
    status_on_error: u16,
    include_request_headers: Vec<HeaderName>,
    additional_headers: Vec<(HeaderName, HeaderValue)>,
    body: Option<MeshExtAuthzBodyCheck>,
    /// Provider response headers copied onto the gateway-authored DENIAL only.
    headers_to_downstream_on_deny: Vec<HeaderName>,
    /// `headersToUpstreamOnAllow`: provider response headers that replace the
    /// backend-bound request's same-named headers on an allowed check.
    headers_to_upstream_on_allow: Vec<HeaderName>,
    /// `headersToDownstreamOnAllow`: provider response headers added to the
    /// client-visible response of an allowed request.
    headers_to_downstream_on_allow: Vec<HeaderName>,
    /// Per-provider attribution, shared across generations by name.
    stats: Arc<ProviderStats>,
}

impl PreparedProvider {
    fn build(provider: &MeshExtAuthzProvider) -> Result<Self, String> {
        provider.validate()?;
        let scheme = if provider.tls { "https" } else { "http" };
        let host = if provider.service.contains(':') && !provider.service.starts_with('[') {
            // A bare IPv6 literal must be bracketed before it can be a URL
            // authority. `validate()` already refused embedded '/' and
            // whitespace, so this is the only remaining ambiguity.
            format!("[{}]", provider.service)
        } else {
            provider.service.clone()
        };
        let mut check_url_base = format!("{scheme}://{host}:{}", provider.port);
        if let Some(prefix) = provider.path_prefix.as_deref() {
            check_url_base.push_str(prefix.trim_end_matches('/'));
        }
        // Prove the composed base URL is what the operator's fields say it is.
        // `validate()` already refuses every value shape that could move the
        // remainder into another URL component; this is the independent proof
        // that the composition itself did not, so a mis-parse can never be
        // discovered per request (where it would deny every delegated decision
        // — or, under `failOpen`, allow one).
        let parsed = url::Url::parse(&check_url_base)
            .map_err(|_| "external authorization check URL does not parse".to_string())?;
        if parsed.scheme() != scheme
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.port_or_known_default() != Some(provider.port)
        {
            return Err(
                "external authorization check URL must carry only scheme, host, port, and path"
                    .to_string(),
            );
        }
        // The redacted rendering is what reaches every log line the shared
        // plugin HTTP client emits. It carries scheme/host/port only: a
        // `pathPrefix` is operator-authored and may embed a shared secret.
        let redacted_url = format!("{scheme}://{host}:{}", provider.port);

        Ok(Self {
            check_url_base,
            redacted_url,
            timeout: Duration::from_millis(provider.timeout_ms),
            fail_open: provider.fail_open,
            status_on_error: provider.status_on_error,
            include_request_headers: parse_header_names(
                &provider.include_request_headers_in_check,
            )?,
            additional_headers: provider
                .include_additional_headers_in_check
                .iter()
                .map(|header| {
                    let name = HeaderName::from_bytes(header.name.as_bytes())
                        .map_err(|_| "invalid additional check header name".to_string())?;
                    let value = HeaderValue::from_str(&header.value)
                        .map_err(|_| "invalid additional check header value".to_string())?;
                    Ok((name, value))
                })
                .collect::<Result<Vec<_>, String>>()?,
            body: provider.include_request_body_in_check.clone(),
            headers_to_downstream_on_deny: parse_header_names(
                &provider.headers_to_downstream_on_deny,
            )?,
            headers_to_upstream_on_allow: parse_header_names(
                &provider.headers_to_upstream_on_allow,
            )?,
            headers_to_downstream_on_allow: parse_header_names(
                &provider.headers_to_downstream_on_allow,
            )?,
            stats: provider_stats(&provider.name),
        })
    }

    /// Count one terminal outcome for this provider: once in the process-wide
    /// fixed-cardinality series and once in this provider's own series.
    fn record_outcome(&self, reason: MeshExtAuthzReason, failed_open: bool) {
        record(reason, failed_open);
        self.stats.record(reason);
    }

    /// Refuse a request whose body exceeds THIS provider's `maxRequestBytes`.
    ///
    /// Unconditional and client-facing (`413`), decided before any provider
    /// I/O: `failOpen` governs FAILED CHECKS — a provider that could not
    /// decide — and this is not one. The strict `allowPartialMessage: false`
    /// contract means there is no truncated body the provider could have
    /// decided on, so honouring `failOpen` here would admit precisely the
    /// oversize request the operator's cap excluded. `statusOnError` is
    /// likewise not consulted: no error occurred, and `413` is the same
    /// client-facing status the proxy's pre-`authorize` ceiling returns.
    ///
    /// Counted exactly once, in the same fixed-cardinality series as every
    /// other outcome (`body_too_large`), and never as a `failOpen`/fail-closed
    /// disposition.
    fn body_too_large_refusal(&self) -> MeshExtAuthzOutcome {
        self.record_outcome(MeshExtAuthzReason::BodyTooLarge, false);
        warn_sampled!(
            plugin = "mesh_authz",
            reason = MeshExtAuthzReason::BodyTooLarge.as_str(),
            "Mesh external authorization request body exceeds the selected provider's maxRequestBytes; refusing without dispatching a check"
        );
        MeshExtAuthzOutcome::Deny {
            status: 413,
            headers: Vec::new(),
            reason: MeshExtAuthzReason::BodyTooLarge,
        }
    }

    fn failure(&self, reason: MeshExtAuthzReason) -> MeshExtAuthzOutcome {
        self.record_outcome(reason, self.fail_open);
        if self.fail_open {
            warn_sampled!(
                plugin = "mesh_authz",
                reason = reason.as_str(),
                "Mesh external authorization check failed; provider is configured failOpen so the request continues"
            );
            // No provider vouched for anything, so no provider-asserted header
            // is carried. `mesh_authz` still strips the client's copies of the
            // provider-owned `headersToUpstreamOnAllow` names.
            MeshExtAuthzOutcome::Allow {
                reason,
                upstream_headers: Vec::new(),
                downstream_headers: Vec::new(),
            }
        } else {
            MeshExtAuthzOutcome::Deny {
                status: self.status_on_error,
                headers: Vec::new(),
                reason,
            }
        }
    }
}

fn parse_header_names(names: &[String]) -> Result<Vec<HeaderName>, String> {
    names
        .iter()
        .map(|name| {
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| "invalid ext-authz header name".to_string())
        })
        .collect()
}

/// The request-side inputs one check needs.
///
/// Borrowed, so the caller never clones the client's header map onto the hot
/// path for a request that matches no CUSTOM rule.
pub struct MeshExtAuthzCheckRequest<'a> {
    pub method: &'a str,
    /// Already-normalized request path (no query string: the query is NOT
    /// forwarded, so a credential in it cannot reach the provider).
    pub path: &'a str,
    /// Lowercased client request headers.
    pub headers: &'a HashMap<String, String>,
    /// The ORIGINAL request authority (`Host` / `:authority`) as the proxy
    /// validated it, when one is present.
    ///
    /// The HTTP ext-auth protocol carries the original `Host` to the provider
    /// so a policy can be written against the service the client addressed.
    /// It is a HEADER only: the dial destination stays the provider's own
    /// configured `service`/`port`, so a client-controlled authority can never
    /// re-target the provider connection.
    pub authority: Option<&'a str>,
    /// The authenticated source identity the local rules were evaluated
    /// against (after a trusted HBONE assertor's baggage rewrite). Stamped as
    /// `x-ferrum-source-principal` / `-namespace` / `-service-account`.
    pub source_principal: Option<&'a SpiffeId>,
    /// The validated JWT request principal (`iss/sub`), when one was
    /// established. Stamped as `x-ferrum-request-principal`.
    pub request_principal: Option<&'a str>,
    /// Buffered request body, when the proxy retained one.
    pub body: Option<&'a [u8]>,
    /// Whether the transport PROVED the request body is empty. Distinguishes
    /// "no body" from "a body exists but was not buffered", which must fail
    /// closed for a provider that inspects bodies.
    pub body_proven_empty: bool,
    /// The request's gateway hop count
    /// ([`crate::proxy::hop_limit::plugin_call_proxy_hops`]), carried as
    /// `X-Ferrum-Hops` on the check so a provider that resolves back to the
    /// gateway is refused at the proxy hop limit. `None` when the limit is
    /// disabled.
    pub proxy_hops: Option<u8>,
}

/// The PROCESS-WIDE in-flight CUSTOM check budget.
///
/// Deliberately NOT owned by an executor generation. `docs/mesh.md` advertises
/// this ceiling as process-wide, and it is a resource bound — every permit
/// holder occupies one socket, one buffered check body, and one task for the
/// duration of a provider round trip. A per-executor pool made the real
/// ceiling `(enabled mesh_authz instances + overlapping reload generations) ×
/// the constant`: N namespaces each opened their own budget, and a reload
/// published a replacement with a FULL pool while the retiring generation's
/// in-flight checks were still running on their own.
///
/// Sharing the pool also makes reload accounting exact for free: a check that
/// started on the previous generation keeps its permit until it finishes,
/// because the permit follows the REQUEST, not the config version.
static MESH_EXT_AUTHZ_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MESH_EXT_AUTHZ_PROCESS_CONCURRENT_CALLS)));

/// Executes CUSTOM authorization checks for one plugin generation.
///
/// Built once per accepted mesh slice. Providers and clients are owned here, so
/// retiring a generation drops them — there is no background task and no
/// detached queue to leak. The concurrency permit pool is the deliberate
/// exception: it is the process-wide [`MESH_EXT_AUTHZ_PERMITS`] every executor
/// shares.
pub struct MeshExtAuthzExecutor {
    http_client: PluginHttpClient,
    providers: HashMap<String, PreparedProvider>,
    permits: Arc<Semaphore>,
}

impl MeshExtAuthzExecutor {
    /// Prepare an executor from the generation's admitted provider set.
    ///
    /// Returns `Err` when a provider cannot be prepared, which rejects the
    /// whole plugin generation and keeps the previous (valid) one serving —
    /// preferable to publishing a generation whose CUSTOM policies would all
    /// deny.
    pub fn new(
        providers: &[MeshExtAuthzProvider],
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        crate::modes::mesh::config::validate_mesh_ext_authz_providers(providers)?;
        let mut prepared = HashMap::with_capacity(providers.len());
        for provider in providers {
            prepared.insert(provider.name.clone(), PreparedProvider::build(provider)?);
        }
        Ok(Self {
            http_client,
            providers: prepared,
            permits: Arc::clone(&MESH_EXT_AUTHZ_PERMITS),
        })
    }

    /// The process-wide in-flight check budget this executor draws from.
    ///
    /// Every executor — every enabled `mesh_authz` instance and every reload
    /// generation — returns the SAME `Arc`. Exposed so tests can prove that
    /// aggregate contract, and observe the ceiling, without opening the whole
    /// budget's worth of live provider connections. Production code touches
    /// the pool only inside [`Self::check`].
    #[allow(dead_code)] // external integration-test seam; unused in the binary target
    pub fn check_budget(&self) -> &Arc<Semaphore> {
        &self.permits
    }

    /// Whether any provider in this generation asks for the request body.
    /// Drives `mesh_authz`'s body-buffering declarations.
    pub fn requires_request_body(&self) -> bool {
        self.providers
            .values()
            .any(|provider| provider.body.is_some())
    }

    /// The largest `maxRequestBytes` any provider declares, used as the
    /// plugin's SHARED request-body buffer ceiling.
    ///
    /// One prebuffer serves whichever provider the matched CUSTOM rule
    /// selects, and which rule matches is not known when the ceiling is
    /// declared, so this is the maximum rather than the selected provider's
    /// own cap. It is therefore a PREBUFFER bound, not the authorization
    /// contract: a generation carrying a higher-cap provider lets a body over
    /// a lower-cap provider's `maxRequestBytes` through to
    /// [`Self::check`], which refuses it unconditionally with `413` before any
    /// provider I/O (never subject to `failOpen`). Raising this to the maximum
    /// can only over-buffer, never under-enforce.
    pub fn max_request_body_bytes(&self) -> Option<usize> {
        self.providers
            .values()
            .filter_map(|provider| provider.body.as_ref())
            .map(|body| body.max_request_bytes)
            .max()
    }

    /// Whether this generation carries `provider_name` at all.
    #[allow(dead_code)] // external integration-test seam; unused in the binary target
    pub fn binds(&self, provider_name: &str) -> bool {
        self.providers.contains_key(provider_name)
    }

    /// The exact client request header names a provider asked to see.
    ///
    /// Returned so the caller materializes ONLY those values — a check never
    /// receives the full client header map, and a credential header reaches
    /// the provider only because the operator named it.
    pub fn required_header_names(&self, provider_name: &str) -> &[HeaderName] {
        self.providers
            .get(provider_name)
            .map(|provider| provider.include_request_headers.as_slice())
            .unwrap_or(&[])
    }

    /// Whether the named provider inspects the request body.
    pub fn provider_requires_request_body(&self, provider_name: &str) -> bool {
        self.providers
            .get(provider_name)
            .is_some_and(|provider| provider.body.is_some())
    }

    /// The `headersToUpstreamOnAllow` names the named provider owns. On an
    /// allowed check `mesh_authz` removes the client's copies of every one of
    /// them from the backend-bound request and installs the provider's value
    /// where it returned one.
    pub fn upstream_allow_header_names(&self, provider_name: &str) -> &[HeaderName] {
        self.providers
            .get(provider_name)
            .map(|provider| provider.headers_to_upstream_on_allow.as_slice())
            .unwrap_or(&[])
    }

    /// The union of every provider's `headersToUpstreamOnAllow` names, sorted
    /// and deduplicated — the fixed set of request headers this generation may
    /// change (`Plugin::modified_request_header_names`).
    pub fn upstream_allow_header_union(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .providers
            .values()
            .flat_map(|provider| provider.headers_to_upstream_on_allow.iter())
            .map(|name| name.as_str().to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Whether any provider declares `headersToDownstreamOnAllow`.
    pub fn mutates_downstream_on_allow(&self) -> bool {
        self.providers
            .values()
            .any(|provider| !provider.headers_to_downstream_on_allow.is_empty())
    }

    /// Hostnames the gateway should warm DNS for.
    pub fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .providers
            .values()
            .filter_map(|provider| {
                provider
                    .check_url_base
                    .split("://")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .and_then(|authority| authority.rsplit_once(':'))
                    .map(|(host, _)| host.trim_matches(|c| c == '[' || c == ']').to_string())
            })
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Run the check for `provider_name`.
    ///
    /// An unknown provider name is NOT an allow: the delegation named something
    /// this generation cannot reach, so it denies with a fixed 403 (there is no
    /// provider whose `statusOnError` could be honoured).
    pub async fn check(
        &self,
        provider_name: &str,
        request: MeshExtAuthzCheckRequest<'_>,
        latency_accumulator: &AtomicU64,
    ) -> MeshExtAuthzOutcome {
        let Some(provider) = self.providers.get(provider_name) else {
            record(MeshExtAuthzReason::ProviderUnbound, false);
            warn_sampled!(
                plugin = "mesh_authz",
                reason = MeshExtAuthzReason::ProviderUnbound.as_str(),
                "Mesh CUSTOM authorization policy names a provider this configuration generation does not carry; denying"
            );
            return MeshExtAuthzOutcome::Deny {
                status: 403,
                headers: Vec::new(),
                reason: MeshExtAuthzReason::ProviderUnbound,
            };
        };

        // Resolve the check body BEFORE taking a permit so an oversize or
        // unavailable body cannot occupy concurrency capacity.
        //
        // The two failures are deliberately NOT the same: an over-cap body is
        // an unconditional `413` refusal of the request (never `failOpen`),
        // while a body that could not be materialized is an ordinary failed
        // check the provider's `failOpen` still governs.
        let body = match resolve_check_body(provider, &request) {
            Ok(body) => body,
            Err(MeshExtAuthzReason::BodyTooLarge) => return provider.body_too_large_refusal(),
            Err(reason) => return provider.failure(reason),
        };

        // Bounded concurrency with NO queue: at capacity the check is refused
        // immediately rather than parking the request behind a growing waiter
        // list (which would convert provider slowness into gateway memory
        // growth and unbounded latency).
        let Ok(_permit) = self.permits.clone().try_acquire_owned() else {
            return provider.failure(MeshExtAuthzReason::ConcurrencyExhausted);
        };

        let Ok(method) = http::Method::from_bytes(request.method.as_bytes()) else {
            return provider.failure(MeshExtAuthzReason::RequestBuildFailed);
        };
        let Ok(client) = self.http_client.get() else {
            return provider.failure(MeshExtAuthzReason::RequestBuildFailed);
        };
        let url = build_check_url(&provider.check_url_base, request.path);
        // Header assembly is ONE map with insert (replace) semantics, not a
        // chain of appends. `includeAdditionalHeadersInCheck` is the operator's
        // FIXED value and must WIN over both a same-named client header and a
        // same-named `includeRequestHeadersInCheck` entry — appending would let
        // an attacker-controlled value ride to the provider beside the fixed
        // one, where which value the provider reads is its own parser's choice.
        // `HeaderName` comparison is already case-insensitive, and admission
        // refuses case-variant duplicates, so the winner is deterministic.
        let mut check_headers = http::HeaderMap::with_capacity(
            provider.include_request_headers.len() + provider.additional_headers.len() + 1,
        );
        for name in &provider.include_request_headers {
            if let Some(value) = request.headers.get(name.as_str())
                && let Ok(header_value) = HeaderValue::from_str(value)
            {
                check_headers.insert(name.clone(), header_value);
            }
        }
        for (name, value) in &provider.additional_headers {
            check_headers.insert(name.clone(), value.clone());
        }
        // The HTTP ext-auth protocol carries the ORIGINAL request authority.
        // Setting `Host` changes only what the provider is told the client
        // addressed; the connection is still dialed at `check_url_base`, so
        // this cannot route the provider connection anywhere. A malformed or
        // unrepresentable authority is dropped rather than forwarded.
        if let Some(authority) = request.authority
            && let Ok(authority) = authority.parse::<http::uri::Authority>()
            && let Ok(value) = HeaderValue::from_str(authority.as_str())
        {
            check_headers.insert(http::header::HOST, value);
        }
        // The check carries exactly the gateway's hop count (issue #6128).
        // Provider admission refuses every `x-ferrum-*` name (either `_` or
        // `-` spelling) in `includeRequestHeadersInCheck` and
        // `includeAdditionalHeadersInCheck`, so no forwarded or fixed copy can
        // reach this map; the remove is defence-in-depth, one cheap lookup,
        // so the stamp below can never sit beside a second field line.
        if request.proxy_hops.is_some() {
            check_headers.remove(crate::proxy::hop_limit::PROXY_HOPS_HEADER);
        }
        stamp_identity_check_headers(
            &mut check_headers,
            request.source_principal,
            request.request_principal,
        );
        let mut builder = client
            .request(method, url.as_str())
            .timeout(provider.timeout)
            .headers(check_headers);
        builder =
            crate::proxy::hop_limit::stamp_plugin_call_proxy_hops(builder, request.proxy_hops);
        // `Content-Length` is set by reqwest from the body, matching the
        // protocol's automatic fields (Host, Method, Path, Content-Length).
        if let Some(body) = body {
            builder = builder.body(body);
        }

        // `execute_redacted_tracked_classified_single_attempt` returns a TYPED
        // failure class and logs only `redacted_url`, so the resolved provider
        // URL (which may embed a shared secret in its path prefix) can never
        // reach a log line. The classification is mapped onto this module's
        // closed reason enum — the `reqwest::Error` itself is never rendered.
        //
        // SINGLE ATTEMPT, deliberately: a check is a decision, not a report.
        // The shared client's transport-retry policy replays GET/HEAD/OPTIONS
        // when `FERRUM_PLUGIN_HTTP_MAX_RETRIES` is set, and an ext-authz check
        // is usually a GET, so the ordinary seam would silently turn one
        // client request into several authorization decisions.
        let dispatched_at = std::time::Instant::now();
        let result = self
            .http_client
            .execute_redacted_tracked_classified_single_attempt(
                builder,
                "mesh_authz_ext_authz",
                &provider.redacted_url,
                latency_accumulator,
            )
            .await;
        provider.stats.observe_duration(dispatched_at.elapsed());
        let response = match result {
            Ok(response) => response,
            Err(failure) => {
                let reason = match failure.error_class {
                    crate::retry::ErrorClass::ConnectionTimeout
                    | crate::retry::ErrorClass::ReadWriteTimeout => MeshExtAuthzReason::Timeout,
                    _ => MeshExtAuthzReason::TransportError,
                };
                return provider.failure(reason);
            }
        };

        let status = response.status();
        // Istio/Envoy HTTP ext-auth outcome classification:
        //
        // * EXACTLY `200` allows. No other 2xx does — a `204` (or any other
        //   success code) is not the protocol's allow signal, and reading one
        //   as an allow would let a misconfigured or partially deployed
        //   authorizer admit traffic it never authorized.
        // * `5xx` is a FAILED CHECK, not a denial: the provider could not
        //   decide, so it follows `failOpen` and, when fail-closed, uses
        //   `statusOnError` — never the provider's own 5xx.
        // * Everything else (3xx / 4xx) is an EXPLICIT provider denial and
        //   keeps the provider's own status.
        let outcome_class = classify_provider_status(status.as_u16());
        if outcome_class == ProviderStatusClass::Error {
            // Drain the connection under the fixed bound before failing, so a
            // 5xx-emitting provider does not strand pooled connections.
            let _ = read_response_body_bounded(response, MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES).await;
            return provider.failure(MeshExtAuthzReason::ProviderError);
        }
        let allowed = outcome_class == ProviderStatusClass::Allow;
        let (deny_headers, upstream_headers, downstream_headers) = if allowed {
            (
                Vec::new(),
                collect_headers(response.headers(), &provider.headers_to_upstream_on_allow),
                collect_headers(response.headers(), &provider.headers_to_downstream_on_allow),
            )
        } else {
            (
                collect_headers(response.headers(), &provider.headers_to_downstream_on_deny),
                Vec::new(),
                Vec::new(),
            )
        };
        // The provider response body is never consumed by the authorization
        // contract or forwarded to the client. Drain it under the fixed bound
        // only to keep an ordinary pooled connection reusable. A malformed or
        // oversized body on a `200` remains a failed check, but once the
        // provider has returned an EXPLICIT denial its status is authoritative:
        // a body error must never reclassify that denial as a failed check that
        // `failOpen` could turn into an allow.
        let declared_oversize = response
            .content_length()
            .is_some_and(|length| length > MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES as u64);
        if declared_oversize && allowed {
            return provider.failure(MeshExtAuthzReason::ResponseTooLarge);
        }
        if !declared_oversize {
            match read_response_body_bounded(response, MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES).await {
                Ok(_) => {}
                Err(BoundedReadError::LimitExceeded { .. }) if allowed => {
                    return provider.failure(MeshExtAuthzReason::ResponseTooLarge);
                }
                Err(BoundedReadError::Stream(_)) if allowed => {
                    return provider.failure(MeshExtAuthzReason::ResponseReadFailed);
                }
                // The fixed denial status was already received. The discarded
                // body is not an input to that decision, so its failure cannot
                // weaken the denial.
                Err(_) => {}
            }
        }

        if allowed {
            provider.record_outcome(MeshExtAuthzReason::Allowed, false);
            MeshExtAuthzOutcome::Allow {
                reason: MeshExtAuthzReason::Allowed,
                upstream_headers,
                downstream_headers,
            }
        } else {
            provider.record_outcome(MeshExtAuthzReason::DeniedByProvider, false);
            MeshExtAuthzOutcome::Deny {
                // Envoy forwards the provider's own status on a denial; Ferrum
                // does the same, but deliberately does NOT forward the provider
                // response BODY. Provider bytes are unvalidated and would be
                // rendered into a gateway-authored client response. A status
                // that cannot carry that gateway-authored body at all becomes a
                // plain 403 — see `client_visible_denial_status`.
                status: client_visible_denial_status(status.as_u16()),
                headers: deny_headers,
                reason: MeshExtAuthzReason::DeniedByProvider,
            }
        }
    }
}

/// How one provider HTTP status resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderStatusClass {
    /// Exactly `200`.
    Allow,
    /// `5xx`: the provider could not decide. Subject to `failOpen`.
    Error,
    /// Anything else: an explicit denial carrying the provider's own status.
    Denied,
}

fn classify_provider_status(status: u16) -> ProviderStatusClass {
    match status {
        200 => ProviderStatusClass::Allow,
        500..=599 => ProviderStatusClass::Error,
        _ => ProviderStatusClass::Denied,
    }
}

/// The client-visible status for an explicit provider denial.
///
/// A denial is a gateway-AUTHORED response: it carries a fixed JSON error body,
/// so it must be emitted with a status whose framing allows content. The
/// classification above deliberately treats every non-`200`, non-`5xx` status
/// as an explicit denial, which admits `1xx`, a non-`200` `2xx` such as `204`,
/// and `304` — all of which forbid a body. Forwarding one verbatim would put
/// `Content-Length` on a response the client is required not to read a body
/// for, leaving those bytes in an HTTP/1.1 keep-alive stream to be misparsed as
/// the head of the next response.
///
/// `3xx` (except `304`) and `4xx` pass through unchanged: a redirect-to-login
/// denial is an ordinary ext-authz pattern and pairs with
/// `headersToDownstreamOnDeny`. Everything else becomes a plain `403` — the
/// decision (deny) is unchanged and the outcome is still counted as
/// `denied_by_provider`; only the unrepresentable status is replaced.
fn client_visible_denial_status(status: u16) -> u16 {
    if status < 300 || status == 304 {
        403
    } else {
        status
    }
}

fn build_check_url(base: &str, path: &str) -> String {
    let mut url = String::with_capacity(base.len() + path.len() + 1);
    url.push_str(base);
    if !path.starts_with('/') {
        url.push('/');
    }
    url.push_str(path);
    url
}

/// Copy the allowlisted provider response headers, ONE `(name, value)` pair
/// per name with EVERY field line of that name preserved.
///
/// `HeaderMap::get` returns only the first field line, which silently dropped
/// a second `Set-Cookie` (a login redirect that sets a state cookie AND a nonce
/// cookie could never complete) and every `WWW-Authenticate` challenge after
/// the first. Lines are folded into the proxy's own multi-value
/// representation: `Set-Cookie` newline-joined (every protocol's response
/// builder splits it back into separate fields — see
/// `crate::proxy::headers::apply_response_headers`), `Cookie` joined with
/// `; `, and every other (list-valued) field joined with `, `. A field line
/// that is not visible ASCII is skipped, as before.
pub(crate) fn collect_headers(
    headers: &http::HeaderMap,
    allowed: &[HeaderName],
) -> Vec<(String, String)> {
    let mut selected = Vec::new();
    for name in allowed {
        let separator = if *name == http::header::SET_COOKIE {
            "\n"
        } else if *name == http::header::COOKIE {
            "; "
        } else {
            ", "
        };
        let mut folded: Option<String> = None;
        for value in headers.get_all(name) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            if let Some(existing) = folded.as_mut() {
                existing.push_str(separator);
                existing.push_str(value);
            } else {
                folded = Some(value.to_string());
            }
        }
        if let Some(value) = folded {
            selected.push((name.as_str().to_string(), value));
        }
    }
    selected
}

/// One allowed check's staged `headersToUpstreamOnAllow` result: one
/// `(lowercase name, value)` pair per provider-owned name, `None` meaning
/// "strip the client's copy, install nothing".
pub(crate) type StagedUpstreamHeaders = Vec<(String, Option<String>)>;

/// One allowed check's staged `headersToDownstreamOnAllow` result.
pub(crate) type StagedDownstreamHeaders = Vec<(String, String)>;

/// Gateway-asserted caller-identity headers stamped on every check.
pub const SOURCE_PRINCIPAL_CHECK_HEADER: &str = "x-ferrum-source-principal";
pub const SOURCE_NAMESPACE_CHECK_HEADER: &str = "x-ferrum-source-namespace";
pub const SOURCE_SERVICE_ACCOUNT_CHECK_HEADER: &str = "x-ferrum-source-service-account";
pub const REQUEST_PRINCIPAL_CHECK_HEADER: &str = "x-ferrum-request-principal";

/// Stamp the authenticated caller identity onto the check request.
///
/// The names are removed first, unconditionally, so the provider can only
/// ever see the gateway's own value: admission already refuses every
/// `x-ferrum-*` name in `includeRequestHeadersInCheck` and
/// `includeAdditionalHeadersInCheck`, and this keeps that true even if a
/// future admission path forgot to. An identity the gateway does not hold is
/// ABSENT, never empty.
fn stamp_identity_check_headers(
    check_headers: &mut http::HeaderMap,
    source_principal: Option<&SpiffeId>,
    request_principal: Option<&str>,
) {
    for name in [
        SOURCE_PRINCIPAL_CHECK_HEADER,
        SOURCE_NAMESPACE_CHECK_HEADER,
        SOURCE_SERVICE_ACCOUNT_CHECK_HEADER,
        REQUEST_PRINCIPAL_CHECK_HEADER,
    ] {
        check_headers.remove(name);
    }
    let mut stamp = |name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            check_headers.insert(HeaderName::from_static(name), value);
        }
    };
    if let Some(principal) = source_principal {
        stamp(SOURCE_PRINCIPAL_CHECK_HEADER, principal.as_str());
        if let Some(namespace) = principal.namespace() {
            stamp(SOURCE_NAMESPACE_CHECK_HEADER, namespace);
        }
        if let Some(service_account) = principal.service_account() {
            stamp(SOURCE_SERVICE_ACCOUNT_CHECK_HEADER, service_account);
        }
    }
    if let Some(request_principal) = request_principal {
        stamp(REQUEST_PRINCIPAL_CHECK_HEADER, request_principal);
    }
}

/// Materialize the check request body under the provider's declared bound.
fn resolve_check_body(
    provider: &PreparedProvider,
    request: &MeshExtAuthzCheckRequest<'_>,
) -> Result<Option<Vec<u8>>, MeshExtAuthzReason> {
    let Some(policy) = provider.body.as_ref() else {
        return Ok(None);
    };
    match request.body {
        Some(body) if body.len() <= policy.max_request_bytes => Ok(Some(body.to_vec())),
        // The authoritative per-provider cap. The proxy's pre-`authorize`
        // ceiling is the MAXIMUM `maxRequestBytes` across the generation's
        // providers (one prebuffer, many possible providers), so a body within
        // that shared ceiling but over THIS provider's cap arrives here
        // routinely — it is not merely defence in depth. The caller turns this
        // into an unconditional `413` before any provider I/O, so an unrelated
        // high-cap provider can never raise the ceiling a low-cap provider
        // enforces, and no `failOpen` opinion applies. `allowPartialMessage` is
        // refused at admission, so there is no truncating branch to fall into.
        Some(_) => Err(MeshExtAuthzReason::BodyTooLarge),
        // The transport proved there is no body at all: an empty check body is
        // the faithful representation, not a missing one.
        None if request.body_proven_empty => Ok(Some(Vec::new())),
        // A provider that inspects bodies cannot decide without one.
        None => Err(MeshExtAuthzReason::BodyUnavailable),
    }
}

#[cfg(test)]
mod tests {
    //! Inline coverage is deliberately limited to genuinely PRIVATE helpers
    //! (`PreparedProvider`, `build_check_url`, `classify_provider_status`,
    //! `resolve_check_body`). Everything reachable through a public seam —
    //! `MeshAuthz::authorize`, the plugin body-phase declarations, and the
    //! provider wire contract — is covered externally in
    //! `tests/integration/mesh_ext_authz_custom_tests.rs`.
    use super::*;

    fn provider(name: &str) -> MeshExtAuthzProvider {
        MeshExtAuthzProvider {
            name: name.to_string(),
            service: "authz.istio-system.svc.cluster.local".to_string(),
            port: 9000,
            tls: true,
            path_prefix: Some("/check".to_string()),
            timeout_ms: 250,
            fail_open: false,
            status_on_error: 403,
            include_request_headers_in_check: vec!["x-request-id".to_string()],
            include_additional_headers_in_check: Vec::new(),
            include_request_body_in_check: None,
            headers_to_upstream_on_allow: Vec::new(),
            headers_to_downstream_on_deny: Vec::new(),
            headers_to_downstream_on_allow: Vec::new(),
        }
    }

    fn body_request<'a>(
        headers: &'a HashMap<String, String>,
        body: Option<&'a [u8]>,
        body_proven_empty: bool,
    ) -> MeshExtAuthzCheckRequest<'a> {
        MeshExtAuthzCheckRequest {
            method: "POST",
            path: "/",
            headers,
            authority: None,
            source_principal: None,
            request_principal: None,
            body,
            body_proven_empty,
            proxy_hops: None,
        }
    }

    #[test]
    fn check_url_joins_prefix_and_path_without_double_slash() {
        let prepared = PreparedProvider::build(&provider("p")).expect("provider prepares");
        assert_eq!(
            build_check_url(&prepared.check_url_base, "/api/v1"),
            "https://authz.istio-system.svc.cluster.local:9000/check/api/v1"
        );
    }

    #[test]
    fn redacted_url_never_carries_the_operator_path_prefix() {
        let mut source = provider("p");
        source.path_prefix = Some("/check/s3cr3t-token".to_string());
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        assert!(
            !prepared.redacted_url.contains("s3cr3t-token"),
            "a pathPrefix may embed a shared secret and must never reach a log line"
        );
    }

    #[test]
    fn only_two_hundred_allows_and_five_hundreds_are_errors_not_denials() {
        assert_eq!(classify_provider_status(200), ProviderStatusClass::Allow);
        // A non-200 success is NOT the protocol's allow signal.
        assert_eq!(classify_provider_status(204), ProviderStatusClass::Denied);
        assert_eq!(classify_provider_status(302), ProviderStatusClass::Denied);
        assert_eq!(classify_provider_status(403), ProviderStatusClass::Denied);
        assert_eq!(classify_provider_status(500), ProviderStatusClass::Error);
        assert_eq!(classify_provider_status(503), ProviderStatusClass::Error);
    }

    #[test]
    fn a_denial_status_that_cannot_carry_a_body_becomes_a_plain_forbidden() {
        // The denial response is gateway-AUTHORED and carries a JSON body, so a
        // no-content status would frame content the client must not read — on
        // an HTTP/1.1 keep-alive connection those bytes are then parsed as the
        // head of the next response.
        assert_eq!(client_visible_denial_status(204), 403);
        assert_eq!(client_visible_denial_status(205), 403);
        assert_eq!(client_visible_denial_status(304), 403);
        assert_eq!(client_visible_denial_status(101), 403);
        // A redirect-to-login denial is an ordinary ext-authz pattern and pairs
        // with `headersToDownstreamOnDeny`, so 3xx (except 304) and 4xx keep the
        // provider's own status.
        assert_eq!(client_visible_denial_status(302), 302);
        assert_eq!(client_visible_denial_status(401), 401);
        assert_eq!(client_visible_denial_status(403), 403);
    }

    #[test]
    fn a_five_hundred_is_a_check_failure_and_a_denial_is_not() {
        assert!(MeshExtAuthzReason::ProviderError.is_check_failure());
        assert!(!MeshExtAuthzReason::DeniedByProvider.is_check_failure());
        assert!(!MeshExtAuthzReason::Allowed.is_check_failure());
        // Decided without contacting a provider, so no failOpen applies.
        assert!(!MeshExtAuthzReason::ProviderConflict.is_check_failure());
        assert!(!MeshExtAuthzReason::Unexecutable.is_check_failure());
        assert!(!MeshExtAuthzReason::BodyTooLarge.is_check_failure());
        // A body that could not be materialized IS a failed check: the
        // provider could not decide, so failOpen still governs it.
        assert!(MeshExtAuthzReason::BodyUnavailable.is_check_failure());
    }

    #[test]
    fn oversize_body_fails_closed_and_there_is_no_truncating_branch() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 4,
            allow_partial_message: false,
        });
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        let headers = HashMap::new();
        assert_eq!(
            resolve_check_body(
                &prepared,
                &body_request(&headers, Some(b"0123456789"), false)
            ),
            Err(MeshExtAuthzReason::BodyTooLarge)
        );
    }

    #[test]
    fn a_partial_message_provider_is_refused_at_preparation() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 4,
            allow_partial_message: true,
        });
        let error = PreparedProvider::build(&source)
            .expect_err("allowPartialMessage is not a supported contract");
        assert!(
            error.contains("allowPartialMessage"),
            "the refusal must name the field, got: {error}"
        );
    }

    #[test]
    fn unbuffered_body_fails_closed_for_a_body_inspecting_provider() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 16,
            allow_partial_message: false,
        });
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        let headers = HashMap::new();
        assert_eq!(
            resolve_check_body(&prepared, &body_request(&headers, None, false)),
            Err(MeshExtAuthzReason::BodyUnavailable)
        );
    }

    #[test]
    fn transport_proven_empty_body_is_a_representable_empty_check_body() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 16,
            allow_partial_message: false,
        });
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        let headers = HashMap::new();
        assert_eq!(
            resolve_check_body(&prepared, &body_request(&headers, None, true)),
            Ok(Some(Vec::new()))
        );
    }
}
