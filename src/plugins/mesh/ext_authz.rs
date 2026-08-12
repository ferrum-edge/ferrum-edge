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
//! HTTP/2, native gRPC, HTTP/3, and HTTP relayed inside a mesh/HBONE CONNECT —
//! because they all funnel through the same `authorize` ladder.
//!
//! Layer-4 sessions (`on_stream_connect`: raw TCP, TLS passthrough, UDP, DTLS)
//! have no HTTP request to check and therefore CANNOT run a provider check.
//! They do not silently skip it: `evaluate_mesh_authorization_policies` turns a
//! matched-but-unexecutable CUSTOM delegation into a denial. A CUSTOM policy
//! whose rules match an L4 connection closes it rather than serving it
//! unchecked.
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
//! reason token only. Metrics are labelled by that reason and by nothing else —
//! never by provider, namespace, route, host, principal, or a status string.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use tokio::sync::Semaphore;

use crate::modes::mesh::config::{
    MESH_EXT_AUTHZ_DEFAULT_CONCURRENT_CALLS, MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES,
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

impl MeshExtAuthzReason {
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
    /// The check allowed the request. Nothing is copied out of the provider
    /// response: `headersToUpstreamOnAllow` / `headersToDownstreamOnAllow` are
    /// refused at admission, so an allowed request reaches the backend exactly
    /// as the client sent it.
    Allow { reason: MeshExtAuthzReason },
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
        })
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
        record(MeshExtAuthzReason::BodyTooLarge, false);
        tracing::warn!(
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
        record(reason, self.fail_open);
        if self.fail_open {
            tracing::warn!(
                plugin = "mesh_authz",
                reason = reason.as_str(),
                "Mesh external authorization check failed; provider is configured failOpen so the request continues"
            );
            MeshExtAuthzOutcome::Allow { reason }
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
    /// Buffered request body, when the proxy retained one.
    pub body: Option<&'a [u8]>,
    /// Whether the transport PROVED the request body is empty. Distinguishes
    /// "no body" from "a body exists but was not buffered", which must fail
    /// closed for a provider that inspects bodies.
    pub body_proven_empty: bool,
}

/// Executes CUSTOM authorization checks for one plugin generation.
///
/// Built once per accepted mesh slice. Providers, clients, and the concurrency
/// permit pool are owned here, so retiring a generation drops them — there is
/// no background task and no detached queue to leak.
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
            permits: Arc::new(Semaphore::new(MESH_EXT_AUTHZ_DEFAULT_CONCURRENT_CALLS)),
        })
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
            tracing::warn!(
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
        let mut builder = self
            .http_client
            .get()
            .request(method, url.as_str())
            .timeout(provider.timeout)
            .headers(check_headers);
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
        let response = match self
            .http_client
            .execute_redacted_tracked_classified_single_attempt(
                builder,
                "mesh_authz_ext_authz",
                &provider.redacted_url,
                latency_accumulator,
            )
            .await
        {
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
        let deny_headers = if allowed {
            Vec::new()
        } else {
            collect_headers(response.headers(), &provider.headers_to_downstream_on_deny)
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
            record(MeshExtAuthzReason::Allowed, false);
            MeshExtAuthzOutcome::Allow {
                reason: MeshExtAuthzReason::Allowed,
            }
        } else {
            record(MeshExtAuthzReason::DeniedByProvider, false);
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

fn collect_headers(headers: &http::HeaderMap, allowed: &[HeaderName]) -> Vec<(String, String)> {
    let mut selected = Vec::new();
    for name in allowed {
        if let Some(value) = headers.get(name)
            && let Ok(value) = value.to_str()
        {
            selected.push((name.as_str().to_string(), value.to_string()));
        }
    }
    selected
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
            body,
            body_proven_empty,
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
