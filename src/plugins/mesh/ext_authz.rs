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
//! * response larger than the fixed read bound
//! * a request body that exceeds `maxRequestBytes` without
//!   `allowPartialMessage`
//! * a body that could not be materialized for a provider that requires one
//! * task cancellation (the future is dropped without producing an allow)
//!
//! A `2xx` provider status allows; any other status denies with that status.
//! Nothing is retried: a check request may carry a partially sent body, and
//! replaying an authorization decision is never safe.
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
    Timeout,
    TransportError,
    ResponseTooLarge,
    ResponseReadFailed,
    BodyUnavailable,
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
    fn is_check_failure(self) -> bool {
        !matches!(
            self,
            MeshExtAuthzReason::Allowed | MeshExtAuthzReason::DeniedByProvider
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
static CHECKS_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static CHECKS_TRANSPORT_ERROR: AtomicU64 = AtomicU64::new(0);
static CHECKS_RESPONSE_REFUSED: AtomicU64 = AtomicU64::new(0);
static CHECKS_BODY_REFUSED: AtomicU64 = AtomicU64::new(0);
static CHECKS_CONCURRENCY_EXHAUSTED: AtomicU64 = AtomicU64::new(0);

fn record(reason: MeshExtAuthzReason, failed_open: bool) {
    match reason {
        MeshExtAuthzReason::Allowed => CHECKS_ALLOWED.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::DeniedByProvider => {
            CHECKS_DENIED_BY_PROVIDER.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::ProviderUnbound => {
            CHECKS_UNBOUND_PROVIDER.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::Timeout => CHECKS_TIMEOUT.fetch_add(1, Ordering::Relaxed),
        MeshExtAuthzReason::TransportError | MeshExtAuthzReason::RequestBuildFailed => {
            CHECKS_TRANSPORT_ERROR.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::ResponseTooLarge | MeshExtAuthzReason::ResponseReadFailed => {
            CHECKS_RESPONSE_REFUSED.fetch_add(1, Ordering::Relaxed)
        }
        MeshExtAuthzReason::BodyUnavailable | MeshExtAuthzReason::BodyTooLarge => {
            CHECKS_BODY_REFUSED.fetch_add(1, Ordering::Relaxed)
        }
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
    pub timeout: u64,
    pub transport_error: u64,
    pub response_refused: u64,
    pub body_refused: u64,
    pub concurrency_exhausted: u64,
}

pub fn snapshot() -> MeshExtAuthzMetricsSnapshot {
    MeshExtAuthzMetricsSnapshot {
        allowed: CHECKS_ALLOWED.load(Ordering::Relaxed),
        denied_by_provider: CHECKS_DENIED_BY_PROVIDER.load(Ordering::Relaxed),
        failed_closed: CHECKS_FAILED_CLOSED.load(Ordering::Relaxed),
        failed_open: CHECKS_FAILED_OPEN.load(Ordering::Relaxed),
        provider_unbound: CHECKS_UNBOUND_PROVIDER.load(Ordering::Relaxed),
        timeout: CHECKS_TIMEOUT.load(Ordering::Relaxed),
        transport_error: CHECKS_TRANSPORT_ERROR.load(Ordering::Relaxed),
        response_refused: CHECKS_RESPONSE_REFUSED.load(Ordering::Relaxed),
        body_refused: CHECKS_BODY_REFUSED.load(Ordering::Relaxed),
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
        ("timeout", snap.timeout),
        ("transport_error", snap.transport_error),
        ("response_refused", snap.response_refused),
        ("body_refused", snap.body_refused),
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
            include_request_headers: parse_header_names(&provider.include_request_headers_in_check)?,
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
    /// plugin's request-body buffer ceiling.
    pub fn max_request_body_bytes(&self) -> Option<usize> {
        self.providers
            .values()
            .filter_map(|provider| provider.body.as_ref())
            .map(|body| body.max_request_bytes)
            .max()
    }

    /// Whether this generation carries `provider_name` at all.
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
        let body = match resolve_check_body(provider, &request) {
            Ok(body) => body,
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
        let mut builder = self
            .http_client
            .get()
            .request(method, url.as_str())
            .timeout(provider.timeout);
        for name in &provider.include_request_headers {
            if let Some(value) = request.headers.get(name.as_str())
                && let Ok(header_value) = HeaderValue::from_str(value)
            {
                builder = builder.header(name.clone(), header_value);
            }
        }
        for (name, value) in &provider.additional_headers {
            builder = builder.header(name.clone(), value.clone());
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }

        // `execute_redacted_tracked_classified` returns a TYPED failure class
        // and logs only `redacted_url`, so the resolved provider URL (which may
        // embed a shared secret in its path prefix) can never reach a log line.
        // The classification is mapped onto this module's closed reason enum —
        // the `reqwest::Error` itself is never rendered.
        let response = match self
            .http_client
            .execute_redacted_tracked_classified(
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
        if response
            .content_length()
            .is_some_and(|length| length > MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES as u64)
        {
            return provider.failure(MeshExtAuthzReason::ResponseTooLarge);
        }
        let allowed = status.is_success();
        let deny_headers = if allowed {
            Vec::new()
        } else {
            collect_headers(response.headers(), &provider.headers_to_downstream_on_deny)
        };
        // Drain the body under the fixed bound even when nothing is forwarded:
        // an unbounded provider response must be refused rather than read, and
        // reading it bounded keeps the pooled connection reusable.
        match read_response_body_bounded(response, MESH_EXT_AUTHZ_MAX_RESPONSE_BYTES).await {
            Ok(_) => {}
            Err(BoundedReadError::LimitExceeded { .. }) => {
                return provider.failure(MeshExtAuthzReason::ResponseTooLarge);
            }
            Err(BoundedReadError::Stream(_)) => {
                return provider.failure(MeshExtAuthzReason::ResponseReadFailed);
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
                // rendered into a gateway-authored client response.
                status: status.as_u16(),
                headers: deny_headers,
                reason: MeshExtAuthzReason::DeniedByProvider,
            }
        }
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
        Some(body) if policy.allow_partial_message => {
            Ok(Some(body[..policy.max_request_bytes].to_vec()))
        }
        // Istio/Envoy refuse an oversize body when partial messages are not
        // allowed. Refusing here (rather than truncating anyway) is what keeps
        // the provider's decision a decision about the real request.
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
    fn oversize_body_without_partial_messages_fails_closed() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 4,
            allow_partial_message: false,
        });
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        let headers = HashMap::new();
        let request = MeshExtAuthzCheckRequest {
            method: "POST",
            path: "/",
            headers: &headers,
            body: Some(b"0123456789"),
            body_proven_empty: false,
        };
        assert_eq!(
            resolve_check_body(&prepared, &request),
            Err(MeshExtAuthzReason::BodyTooLarge)
        );
    }

    #[test]
    fn oversize_body_with_partial_messages_truncates_to_the_declared_bound() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 4,
            allow_partial_message: true,
        });
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        let headers = HashMap::new();
        let request = MeshExtAuthzCheckRequest {
            method: "POST",
            path: "/",
            headers: &headers,
            body: Some(b"0123456789"),
            body_proven_empty: false,
        };
        assert_eq!(
            resolve_check_body(&prepared, &request),
            Ok(Some(b"0123".to_vec()))
        );
    }

    #[test]
    fn unbuffered_body_fails_closed_for_a_body_inspecting_provider() {
        let mut source = provider("p");
        source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
            max_request_bytes: 16,
            allow_partial_message: true,
        });
        let prepared = PreparedProvider::build(&source).expect("provider prepares");
        let headers = HashMap::new();
        let request = MeshExtAuthzCheckRequest {
            method: "POST",
            path: "/",
            headers: &headers,
            body: None,
            body_proven_empty: false,
        };
        assert_eq!(
            resolve_check_body(&prepared, &request),
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
        let request = MeshExtAuthzCheckRequest {
            method: "GET",
            path: "/",
            headers: &headers,
            body: None,
            body_proven_empty: true,
        };
        assert_eq!(resolve_check_body(&prepared, &request), Ok(Some(Vec::new())));
    }
}
