//! Load Testing Plugin
//!
//! Enables on-demand load testing of a proxy's backend by sending concurrent
//! requests through the gateway's own proxy listener. Triggered when a request
//! includes an `X-Loadtesting-Key` header matching the configured secret key.
//!
//! ## How it works
//!
//! In `before_proxy`, the plugin strips both reserved load-testing control
//! headers from the effective request before later deferred transforms (notably
//! `request_mirror`) or backends can observe them. A matching key then spawns a
//! background load test that sends concurrent requests back through the
//! gateway's local listener (`127.0.0.1:{gateway_port}`). Synthetic requests
//! omit the trigger key, so they flow through the full proxy pipeline without
//! re-triggering the load test. Native transaction logging captures every
//! synthetic request.
//!
//! The triggering request itself proceeds normally through the proxy pipeline
//! and is not blocked by the load test.
//!
//! ## Multi-node fan-out
//!
//! When `gateway_addresses` is configured, the originating controller fans out
//! once with `X-Loadtesting-Fanout: 1`. Peer nodes that accept a fan-out
//! trigger start a local cohort only — they never re-fanout — and terminate
//! the control request before backend dispatch.
//!
//! ## HTTPS loopback
//!
//! For deployments that disable the HTTP listener and only expose HTTPS,
//! set `gateway_tls: true` to send synthetic requests to the HTTPS port.
//! Since the gateway's frontend TLS cert is typically issued for an external
//! domain (not `127.0.0.1`), `gateway_tls_no_verify` (default `true` when
//! `gateway_tls` is enabled) skips certificate verification for the loopback
//! connection only.
//!
//! ## Caveats
//!
//! - **Auth forwarding**: Synthetic requests forward the triggering request's
//!   headers (minus the trigger key, hop-by-hop / Connection-listed headers,
//!   and client-supplied forwarding identity). For auth schemes with
//!   short-lived tokens, tokens may expire during long-duration tests.
//! - **Rate limiting**: Synthetic requests pass through rate limiting plugins
//!   on the proxy. High `concurrent_clients` values may trigger rate limits.
//!
//! Unknown top-level keys are rejected with path-qualified diagnostics.
//! Serving-mode publication uses `KeepLastKnownGood`.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::info;
use url::Url;

use super::utils::auth_flow::constant_time_eq;
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::dns::DnsCacheResolver;
use crate::proxy::headers::{SecondaryRequestHostPolicy, filter_secondary_request_headers};
use crate::retry::classify_reqwest_error;
use crate::util::unknown_keys::reject_unknown_keys;

/// Authoritative closed set of top-level `load_testing` configuration keys.
pub const LOAD_TESTING_CONFIG_KEYS: &[&str] = &[
    "concurrent_clients",
    "duration_seconds",
    "gateway_addresses",
    "gateway_port",
    "gateway_tls",
    "gateway_tls_no_verify",
    "key",
    "max_response_body_bytes",
    "ramp",
    "request_timeout_ms",
];

/// Minimum accepted trigger-key length. Keys are additionally restricted to a
/// stable printable-ASCII HTTP field value so they can traverse every frontend
/// and the reqwest fan-out path without normalization or rejection.
pub const MIN_TRIGGER_KEY_LEN: usize = 32;

/// Hard ceiling for per-request timeout (independent of run duration).
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;

/// Maximum accepted one-hop fan-out peer addresses. Bounds controller fan-out
/// work and config size while remaining large enough for typical mesh cohorts.
pub const MAX_GATEWAY_ADDRESSES: usize = 32;

/// Process-wide admission budget across every effective load_testing instance.
const MAX_PROCESS_ACTIVE_CLIENTS: u64 = 10_000;

/// A matching trigger may retain one shared request body for its local cohort
/// and bounded fan-out work. Keep that body bounded even when the global
/// request-body limit is configured as unlimited, and cap aggregate retained
/// replay bodies across plugin instances.
pub const MAX_REPLAY_REQUEST_BODY_BYTES: usize = 10_485_760;
const MAX_PROCESS_RETAINED_BODY_BYTES: u64 = 67_108_864;

pub(crate) const HEADER_TRIGGER_KEY: &str = "x-loadtesting-key";
pub(crate) const HEADER_FANOUT: &str = "x-loadtesting-fanout";
const FANOUT_MARKER: &str = "1";
const INVALID_ADDRESS_LABEL: &str = "invalid-gateway-address";

static PROCESS_ACTIVE_CLIENTS: AtomicU64 = AtomicU64::new(0);
static PROCESS_RETAINED_BODY_BYTES: AtomicU64 = AtomicU64::new(0);
static SHARED_STATES: OnceLock<Mutex<HashMap<String, Vec<Weak<LoadTestingState>>>>> =
    OnceLock::new();

/// Effective policy fields that determine whether a reload generation may
/// safely inherit an in-flight cohort. Deliberately has no `Debug` or
/// serialization implementation because `key` is secret-bearing.
#[derive(Clone, PartialEq, Eq)]
struct LoadTestingCompatibility {
    key: String,
    concurrent_clients: u32,
    duration_seconds: u64,
    request_timeout_ms: u64,
    ramp: bool,
    max_response_body_bytes: u64,
    gateway_base_url: String,
    gateway_addresses: Vec<String>,
    gateway_tls_no_verify: bool,
}

enum LoadTestingStateSelection {
    Isolated,
    Identity(String),
    #[cfg(test)]
    Replacement(Arc<LoadTestingState>),
}

const MIN_WORKER_ERROR_BACKOFF: Duration = Duration::from_millis(10);
const MAX_WORKER_ERROR_BACKOFF: Duration = Duration::from_millis(250);

/// Stable run-admission state shared across compatible plugin-cache generations
/// for one plugin-config identity.
///
/// Detached cohort tasks may hold `Arc<Self>` without counting as plugin
/// owners. Cancellation on plugin removal is driven by [`LoadTestingOwner`].
pub(crate) struct LoadTestingState {
    compatibility: LoadTestingCompatibility,
    is_running: AtomicBool,
    run_cancel: Mutex<CancellationToken>,
    last_result: Mutex<Option<RunResult>>,
    live_owners: AtomicU64,
}

impl LoadTestingState {
    fn new(compatibility: LoadTestingCompatibility) -> Arc<Self> {
        Arc::new(Self {
            compatibility,
            is_running: AtomicBool::new(false),
            run_cancel: Mutex::new(CancellationToken::new()),
            last_result: Mutex::new(None),
            live_owners: AtomicU64::new(0),
        })
    }

    fn begin_run(&self) -> Option<CancellationToken> {
        if self
            .is_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return None;
        }
        let token = CancellationToken::new();
        let mut guard = self
            .run_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Cancel any residual token from a prior generation edge case.
        guard.cancel();
        *guard = token.clone();
        Some(token)
    }

    fn end_run(&self, result: RunResult) {
        let mut guard = self
            .last_result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(result);
        self.is_running.store(false, Ordering::Release);
    }

    fn cancel_active_run(&self) {
        let guard = self
            .run_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.cancel();
    }
}

impl Drop for LoadTestingState {
    fn drop(&mut self) {
        self.cancel_active_run();
        self.is_running.store(false, Ordering::Release);
    }
}

/// Plugin-instance ownership of a shared [`LoadTestingState`].
///
/// Task-held `Arc` clones do not create owners. When the last live plugin
/// instance for a policy identity is dropped, any active cohort is cancelled.
/// A compatible replacement generation that shares the same state does not
/// cancel the existing cohort.
struct LoadTestingOwner {
    state: Arc<LoadTestingState>,
}

impl LoadTestingOwner {
    fn acquire(state: Arc<LoadTestingState>) -> Self {
        state.live_owners.fetch_add(1, Ordering::SeqCst);
        Self { state }
    }
}

impl Drop for LoadTestingOwner {
    fn drop(&mut self) {
        // fetch_sub returns the previous value; 1 means we were the last owner.
        let previous = self.state.live_owners.fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            self.state.cancel_active_run();
        }
    }
}

/// Aggregated completion counters for one load-test cohort.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunResult {
    pub outcome: RunOutcome,
    pub attempted_requests: u64,
    pub responses_received: u64,
    pub responses_completed: u64,
    pub responses_truncated: u64,
    pub response_body_errors: u64,
    pub request_timeouts: u64,
    pub transport_errors: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub status_other: u64,
    pub worker_failures: u64,
    pub cancelled_workers: u64,
    pub aggregation_saturated: bool,
    pub elapsed_ms: u64,
}

impl RunResult {
    /// Throughput helper for operators/tests reading a completed cohort result.
    #[allow(dead_code)] // used only by tests/; dead code in the bin target
    pub fn completed_requests_per_second(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        self.responses_completed as f64 / (self.elapsed_ms as f64 / 1000.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunOutcome {
    #[default]
    Success,
    Degraded,
    Failed,
    Cancelled,
}

#[derive(Debug, Default)]
struct WorkerCounters {
    attempted_requests: u64,
    responses_received: u64,
    responses_completed: u64,
    responses_truncated: u64,
    response_body_errors: u64,
    request_timeouts: u64,
    transport_errors: u64,
    status_2xx: u64,
    status_3xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    status_other: u64,
}

impl WorkerCounters {
    fn saturating_add_into(&self, total: &mut Self) -> bool {
        let mut saturated = false;
        saturated |= saturating_add_assign(&mut total.attempted_requests, self.attempted_requests);
        saturated |= saturating_add_assign(&mut total.responses_received, self.responses_received);
        saturated |=
            saturating_add_assign(&mut total.responses_completed, self.responses_completed);
        saturated |=
            saturating_add_assign(&mut total.responses_truncated, self.responses_truncated);
        saturated |=
            saturating_add_assign(&mut total.response_body_errors, self.response_body_errors);
        saturated |= saturating_add_assign(&mut total.request_timeouts, self.request_timeouts);
        saturated |= saturating_add_assign(&mut total.transport_errors, self.transport_errors);
        saturated |= saturating_add_assign(&mut total.status_2xx, self.status_2xx);
        saturated |= saturating_add_assign(&mut total.status_3xx, self.status_3xx);
        saturated |= saturating_add_assign(&mut total.status_4xx, self.status_4xx);
        saturated |= saturating_add_assign(&mut total.status_5xx, self.status_5xx);
        saturated |= saturating_add_assign(&mut total.status_other, self.status_other);
        saturated
    }
}

struct WorkerResult {
    counters: WorkerCounters,
    cancelled: bool,
}

fn next_worker_error_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        MIN_WORKER_ERROR_BACKOFF
    } else {
        current.saturating_mul(2).min(MAX_WORKER_ERROR_BACKOFF)
    }
}

fn record_worker_completion(
    completion: Result<WorkerResult, tokio::task::JoinError>,
    totals: &mut WorkerCounters,
    worker_failures: &mut u64,
    cancelled_workers: &mut u64,
    aggregation_saturated: &mut bool,
) {
    match completion {
        Ok(worker) => {
            *aggregation_saturated |= worker.counters.saturating_add_into(totals);
            if worker.cancelled {
                *cancelled_workers = (*cancelled_workers).saturating_add(1);
            }
        }
        Err(join_err) => {
            if join_err.is_cancelled() {
                *cancelled_workers = (*cancelled_workers).saturating_add(1);
            } else {
                *worker_failures = (*worker_failures).saturating_add(1);
            }
        }
    }
}

fn saturating_add_assign(dst: &mut u64, src: u64) -> bool {
    let (sum, overflow) = dst.overflowing_add(src);
    *dst = if overflow { u64::MAX } else { sum };
    overflow
}

enum BodyConsumeOutcome {
    Completed,
    Truncated,
    StreamError,
}

pub struct LoadTesting {
    http_client: PluginHttpClient,
    load_test_client: reqwest::Client,
    key: String,
    concurrent_clients: u32,
    duration_seconds: u64,
    request_timeout_ms: u64,
    ramp: bool,
    max_response_body_bytes: u64,
    gateway_base_url: String,
    gateway_addresses: Vec<String>,
    request_headers_to_redact: Vec<String>,
    state: Arc<LoadTestingState>,
    /// Keeps plugin-instance ownership alive; must outlive task-only state refs.
    _owner: LoadTestingOwner,
}

impl LoadTesting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::from_parts(config, http_client, LoadTestingStateSelection::Isolated)
    }

    /// Construct with state shared across reload generations for one plugin
    /// config identity (`namespace` + `id`).
    pub(crate) fn new_with_instance_id(
        config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
        plugin_config_id: &str,
    ) -> Result<Self, String> {
        let identity = format!("{namespace}\0{plugin_config_id}");
        Self::from_parts(
            config,
            http_client,
            LoadTestingStateSelection::Identity(identity),
        )
    }

    #[cfg(test)]
    fn with_shared_state(
        config: &Value,
        http_client: PluginHttpClient,
        state: Arc<LoadTestingState>,
    ) -> Result<Self, String> {
        Self::from_parts(
            config,
            http_client,
            LoadTestingStateSelection::Replacement(state),
        )
    }

    /// Whether a cohort is currently admitted on this plugin identity.
    #[allow(dead_code)] // used only by tests/; dead code in the bin target
    pub fn is_running(&self) -> bool {
        self.state.is_running.load(Ordering::Acquire)
    }

    /// Most recent completed cohort result for this plugin identity, if any.
    #[allow(dead_code)] // used only by tests/; dead code in the bin target
    pub fn last_run_result(&self) -> Option<RunResult> {
        self.state
            .last_result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn from_parts(
        config: &Value,
        http_client: PluginHttpClient,
        state_selection: LoadTestingStateSelection,
    ) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| "load_testing: config must be an object".to_string())?;
        reject_unknown_keys(
            config_obj,
            "config",
            LOAD_TESTING_CONFIG_KEYS,
            "load_testing: ",
        )?;

        let key = optional_string(config, "key")?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "load_testing: 'key' is required and must be a non-empty string".to_string()
            })?;
        if key.chars().count() < MIN_TRIGGER_KEY_LEN {
            return Err(format!(
                "load_testing: 'key' must be at least {MIN_TRIGGER_KEY_LEN} characters"
            ));
        }
        if key.as_bytes().first() == Some(&b' ')
            || key.as_bytes().last() == Some(&b' ')
            || !key.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        {
            return Err(
                "load_testing: 'key' must contain only printable ASCII HTTP header-value characters and must not start or end with a space"
                    .to_string(),
            );
        }

        let concurrent_clients = optional_u64(config, "concurrent_clients")?
            .ok_or_else(|| "load_testing: 'concurrent_clients' is required".to_string())?;
        if concurrent_clients == 0 || concurrent_clients > 10_000 {
            return Err(format!(
                "load_testing: 'concurrent_clients' must be 1–10000 (got {})",
                concurrent_clients
            ));
        }

        let duration_seconds = optional_u64(config, "duration_seconds")?
            .ok_or_else(|| "load_testing: 'duration_seconds' is required".to_string())?;
        if duration_seconds == 0 || duration_seconds > 3600 {
            return Err(format!(
                "load_testing: 'duration_seconds' must be 1–3600 (got {})",
                duration_seconds
            ));
        }

        let ramp = optional_bool(config, "ramp")?.unwrap_or(false);

        let request_timeout_ms = optional_u64(config, "request_timeout_ms")?.unwrap_or(30_000);
        if request_timeout_ms == 0 {
            return Err("load_testing: 'request_timeout_ms' must be greater than 0".to_string());
        }
        if request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(format!(
                "load_testing: 'request_timeout_ms' must be <= {MAX_REQUEST_TIMEOUT_MS} (got {request_timeout_ms})"
            ));
        }

        let max_response_body_bytes =
            optional_u64(config, "max_response_body_bytes")?.unwrap_or(1_048_576);
        if max_response_body_bytes == 0 {
            return Err(
                "load_testing: 'max_response_body_bytes' must be greater than 0".to_string(),
            );
        }

        let gateway_tls = optional_bool(config, "gateway_tls")?.unwrap_or(false);
        let gateway_tls_no_verify =
            optional_bool(config, "gateway_tls_no_verify")?.unwrap_or(gateway_tls);

        let default_env_var = if gateway_tls {
            "FERRUM_PROXY_HTTPS_PORT"
        } else {
            "FERRUM_PROXY_HTTP_PORT"
        };
        let default_port: u16 = if gateway_tls { 8443 } else { 8000 };
        let listener_name = if gateway_tls {
            "HTTPS (FERRUM_PROXY_HTTPS_PORT)"
        } else {
            "HTTP (FERRUM_PROXY_HTTP_PORT)"
        };

        let gateway_port = optional_u64(config, "gateway_port")?
            .map(|p| {
                if p == 0 || p > 65535 {
                    Err(format!(
                        "load_testing: 'gateway_port' must be 1–65535 (got {})",
                        p
                    ))
                } else {
                    Ok(p as u16)
                }
            })
            .transpose()?
            .unwrap_or_else(|| {
                std::env::var(default_env_var)
                    .ok()
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(default_port)
            });

        if gateway_port == 0 {
            return Err(format!(
                "load_testing: resolved gateway port is 0 because the selected {listener_name} \
listener is disabled; set gateway_tls to select an enabled listener and/or set an explicit \
gateway_port in 1–65535"
            ));
        }

        let scheme = if gateway_tls { "https" } else { "http" };
        let gateway_base_url = format!("{}://127.0.0.1:{}", scheme, gateway_port);

        let mut load_test_builder = reqwest::Client::builder()
            // Ignore ambient HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY process
            // state so self-directed load traffic cannot be relayed off-box by
            // inherited proxy environment (matches the shared PluginHttpClient
            // builders).
            .no_proxy()
            .danger_accept_invalid_certs(gateway_tls_no_verify)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(request_timeout_ms));
        if let Some(dns_cache) = http_client.dns_cache() {
            load_test_builder =
                load_test_builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())));
        }
        let load_test_client = load_test_builder
            .build()
            .map_err(|_| "load_testing: failed to build HTTP client".to_string())?;

        let gateway_addresses = parse_gateway_addresses(config, &http_client, &gateway_base_url)?;
        let compatibility = LoadTestingCompatibility {
            key: key.clone(),
            concurrent_clients: concurrent_clients as u32,
            duration_seconds,
            request_timeout_ms,
            ramp,
            max_response_body_bytes,
            gateway_base_url: gateway_base_url.clone(),
            gateway_addresses: gateway_addresses.clone(),
            gateway_tls_no_verify,
        };
        let state = match state_selection {
            LoadTestingStateSelection::Isolated => LoadTestingState::new(compatibility),
            LoadTestingStateSelection::Identity(identity) => {
                retain_shared_state(&identity, compatibility)
            }
            #[cfg(test)]
            LoadTestingStateSelection::Replacement(existing) => {
                if existing.compatibility == compatibility {
                    existing
                } else {
                    LoadTestingState::new(compatibility)
                }
            }
        };
        let owner = LoadTestingOwner::acquire(Arc::clone(&state));

        Ok(Self {
            http_client,
            load_test_client,
            key,
            concurrent_clients: concurrent_clients as u32,
            duration_seconds,
            request_timeout_ms,
            ramp,
            max_response_body_bytes,
            gateway_base_url,
            gateway_addresses,
            request_headers_to_redact: vec![HEADER_TRIGGER_KEY.to_string()],
            state,
            _owner: owner,
        })
    }

    fn trigger_key_present_and_matches(&self, headers: &HashMap<String, String>) -> bool {
        headers
            .get(HEADER_TRIGGER_KEY)
            .map(|k| constant_time_eq(k.as_bytes(), self.key.as_bytes()))
            .unwrap_or(false)
    }

    fn is_fanout_control_request(headers: &HashMap<String, String>) -> bool {
        headers
            .get(HEADER_FANOUT)
            .is_some_and(|value| value == FANOUT_MARKER)
    }
}

fn retain_shared_state(
    identity: &str,
    compatibility: LoadTestingCompatibility,
) -> Arc<LoadTestingState> {
    let registry = SHARED_STATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Preserve all still-live semantic generations for one identity. This is
    // required for A -> B -> A reloads: if A still owns an active cohort, the
    // reverted generation must recover A's admission flag rather than start a
    // second run from fresh state.
    guard.retain(|_, states| {
        states.retain(|weak| weak.strong_count() > 0);
        !states.is_empty()
    });
    if let Some(existing) = guard.get(identity).and_then(|states| {
        states
            .iter()
            .filter_map(Weak::upgrade)
            .find(|state| state.compatibility == compatibility)
    }) {
        return existing;
    }
    let state = LoadTestingState::new(compatibility);
    guard
        .entry(identity.to_string())
        .or_default()
        .push(Arc::downgrade(&state));
    state
}

fn parse_gateway_addresses(
    config: &Value,
    http_client: &PluginHttpClient,
    local_base_url: &str,
) -> Result<Vec<String>, String> {
    match config.get("gateway_addresses") {
        Some(Value::Array(addresses)) => {
            if addresses.is_empty() {
                return Err(
                    "load_testing: 'gateway_addresses' must not be empty when provided".to_string(),
                );
            }
            if addresses.len() > MAX_GATEWAY_ADDRESSES {
                return Err(format!(
                    "load_testing: 'gateway_addresses' must have at most {MAX_GATEWAY_ADDRESSES} entries (got {})",
                    addresses.len()
                ));
            }
            let local = Url::parse(local_base_url).map_err(|_| {
                "load_testing: internal local gateway base URL is invalid".to_string()
            })?;
            let mut urls = Vec::with_capacity(addresses.len());
            let mut seen = HashSet::new();
            for addr in addresses {
                let url = addr.as_str().ok_or_else(|| {
                    "load_testing: each 'gateway_addresses' entry must be a string".to_string()
                })?;
                if url.is_empty() {
                    return Err(
                        "load_testing: 'gateway_addresses' entries must not be empty".to_string(),
                    );
                }
                let parsed = validate_gateway_address(url)?;
                crate::plugins::utils::log_helpers::screen_url_host_egress(
                    "load_testing",
                    "gateway_addresses",
                    &parsed,
                    http_client.backend_allow_ips(),
                )?;
                let normalized = url.trim_end_matches('/').to_string();
                let label = sanitize_gateway_label(&normalized);
                if is_local_loopback_alias(&parsed, &local) {
                    return Err(format!(
                        "load_testing: 'gateway_addresses' must not include this node's local loopback target ({label})"
                    ));
                }
                if !seen.insert(label.clone()) {
                    return Err(format!(
                        "load_testing: duplicate 'gateway_addresses' entry for {label}"
                    ));
                }
                urls.push(normalized);
            }
            Ok(urls)
        }
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err("load_testing: 'gateway_addresses' must be an array".to_string()),
    }
}

fn validate_gateway_address(url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url)
        .map_err(|_| format!("load_testing: invalid gateway address ({INVALID_ADDRESS_LABEL})"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !has_non_empty_authority(url)
        || parsed.host_str().is_none()
    {
        return Err(format!(
            "load_testing: gateway address must be an http(s) URL with a host ({INVALID_ADDRESS_LABEL})"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        let label = sanitize_gateway_label(url);
        return Err(format!(
            "load_testing: gateway address must not include URL userinfo (credentials); got {label}"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        let label = sanitize_gateway_label(url);
        return Err(format!(
            "load_testing: gateway address must not include a query or fragment ({label})"
        ));
    }
    Ok(parsed)
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

/// Scheme/host/port label suitable for logs — never path, query, fragment,
/// userinfo, or raw parser diagnostics.
fn sanitize_gateway_label(url: &str) -> String {
    match Url::parse(url) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            let host = parsed.host_str().unwrap_or("invalid-host");
            match parsed.port_or_known_default() {
                Some(port) => format!("{scheme}://{host}:{port}"),
                None => format!("{scheme}://{host}"),
            }
        }
        Err(_) => INVALID_ADDRESS_LABEL.to_string(),
    }
}

/// Reject local-loopback aliases of the selected local target so delayed
/// self-fanout cannot start another cohort (127/8, `::1`, `localhost` when
/// scheme and effective port match).
fn is_local_loopback_alias(candidate: &Url, local: &Url) -> bool {
    if candidate.scheme() != local.scheme() {
        return false;
    }
    if candidate.port_or_known_default() != local.port_or_known_default() {
        return false;
    }
    match candidate.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => {
            addr.is_loopback()
                || addr
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        Some(url::Host::Domain(name)) => {
            let normalized = name.trim_end_matches('.').to_ascii_lowercase();
            normalized == "localhost" || normalized.ends_with(".localhost")
        }
        None => false,
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("load_testing: '{key}' must be a boolean")),
    }
}

fn optional_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("load_testing: '{key}' must be a string")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("load_testing: '{key}' must be an unsigned integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("load_testing: '{key}' must be an unsigned integer")),
    }
}

fn try_reserve_process_clients(count: u64) -> bool {
    loop {
        let current = PROCESS_ACTIVE_CLIENTS.load(Ordering::Relaxed);
        if current.saturating_add(count) > MAX_PROCESS_ACTIVE_CLIENTS {
            return false;
        }
        if PROCESS_ACTIVE_CLIENTS
            .compare_exchange_weak(
                current,
                current + count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return true;
        }
    }
}

fn release_process_clients(count: u64) {
    PROCESS_ACTIVE_CLIENTS.fetch_sub(count, Ordering::SeqCst);
}

fn try_reserve_process_body_bytes(count: u64) -> bool {
    loop {
        let current = PROCESS_RETAINED_BODY_BYTES.load(Ordering::Relaxed);
        if current.saturating_add(count) > MAX_PROCESS_RETAINED_BODY_BYTES {
            return false;
        }
        if PROCESS_RETAINED_BODY_BYTES
            .compare_exchange_weak(
                current,
                current + count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return true;
        }
    }
}

#[async_trait]
impl Plugin for LoadTesting {
    fn name(&self) -> &str {
        "load_testing"
    }

    fn priority(&self) -> u16 {
        super::priority::LOAD_TESTING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn needs_request_body_bytes(&self) -> bool {
        true
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn request_body_buffer_limit(&self) -> Option<usize> {
        Some(MAX_REPLAY_REQUEST_BODY_BYTES)
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // Preserve the ordinary and wrong-key hot paths: an unauthenticated
        // caller must not force body retention merely by naming the header.
        self.trigger_key_present_and_matches(&ctx.headers)
    }

    fn request_headers_to_redact(&self) -> &[String] {
        &self.request_headers_to_redact
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Authentication is anchored to the original ingress map used by the
        // request-body admission decision. Requiring the effective map to match
        // as well prevents an earlier transformer from manufacturing the
        // administrative trigger or changing it after admission.
        let key_matches = self.trigger_key_present_and_matches(&ctx.headers)
            && self.trigger_key_present_and_matches(headers);
        // The one-hop marker is likewise ingress provenance: a transformer may
        // not manufacture it, and removing it must not re-enable peer fan-out.
        let is_fanout = Self::is_fanout_control_request(&ctx.headers);

        // These names are reserved control-plane inputs. Strip them on every
        // path, including a wrong key, so attacker-chosen lookalikes never reach
        // later plugins or application backends.
        headers.retain(|name, _| {
            !name.eq_ignore_ascii_case(HEADER_TRIGGER_KEY)
                && !name.eq_ignore_ascii_case(HEADER_FANOUT)
        });

        if !key_matches {
            return PluginResult::Continue;
        }

        let Some(run_cancel) = self.state.begin_run() else {
            tracing::warn!("load_testing: test already in progress, ignoring trigger");
            return if is_fanout {
                fanout_ack_result()
            } else {
                PluginResult::Continue
            };
        };

        if !try_reserve_process_clients(u64::from(self.concurrent_clients)) {
            tracing::warn!(
                requested = self.concurrent_clients,
                "load_testing: process-wide active client budget exhausted; ignoring trigger"
            );
            self.state.end_run(RunResult {
                outcome: RunOutcome::Failed,
                ..RunResult::default()
            });
            return if is_fanout {
                fanout_ack_result()
            } else {
                PluginResult::Continue
            };
        }
        let client_budget = ProcessClientBudget::new(u64::from(self.concurrent_clients));
        let Some(request_body) = RetainedRequestBody::try_new(ctx.request_body_bytes.clone())
        else {
            tracing::warn!(
                requested_bytes = ctx.request_body_bytes.as_ref().map_or(0, Bytes::len),
                "load_testing: process-wide retained request-body budget exhausted; ignoring trigger"
            );
            self.state.end_run(RunResult {
                outcome: RunOutcome::Failed,
                ..RunResult::default()
            });
            return if is_fanout {
                fanout_ack_result()
            } else {
                PluginResult::Continue
            };
        };

        let proxy_name = ctx
            .matched_proxy
            .as_ref()
            .and_then(|p| p.name.as_deref())
            .unwrap_or("unknown")
            .to_string();

        let path = ctx.path.clone();
        let raw_query = ctx.raw_query_string().map(str::to_owned);
        let method = ctx.method.clone();

        let synthetic_headers = filter_outbound_headers(headers);
        // Fan-out starts from the same fully sanitized snapshot and appends one
        // canonical key/marker pair below. Never preserve a transformed alias
        // of either reserved control header.
        let fanout_headers = synthetic_headers.clone();

        let concurrent_clients = self.concurrent_clients;
        let duration = Duration::from_secs(self.duration_seconds);
        let duration_secs = self.duration_seconds;
        let ramp = self.ramp;
        let max_response_body_bytes = self.max_response_body_bytes;
        let request_timeout_ms = self.request_timeout_ms;
        let gateway_base_url = self.gateway_base_url.clone();
        let load_test_client = self.load_test_client.clone();
        let state = Arc::clone(&self.state);
        let gateway_addresses = self.gateway_addresses.clone();
        let http_client = self.http_client.clone();
        let trigger_key = self.key.clone();

        // Originating controllers fan out once. Peer fan-out receivers never
        // re-forward, which collapses the previous quadratic mesh amplification.
        if !is_fanout && !gateway_addresses.is_empty() {
            for addr in &gateway_addresses {
                let fanout_url = build_url(addr, &path, raw_query.as_deref());
                let fanout_method = method.clone();
                let mut fanout_hdrs = fanout_headers.clone();
                fanout_hdrs.push((HEADER_TRIGGER_KEY.to_string(), trigger_key.clone()));
                fanout_hdrs.push((HEADER_FANOUT.to_string(), FANOUT_MARKER.to_string()));
                let client = http_client.clone();
                let remote_label = sanitize_gateway_label(addr);
                let body = Arc::clone(&request_body);

                tokio::spawn(async move {
                    let Ok(mut req) =
                        build_request(client.get(), &fanout_method, &fanout_url, &fanout_hdrs)
                    else {
                        tracing::warn!(
                            remote = %remote_label,
                            "load_testing: failed to build fan-out request"
                        );
                        return;
                    };
                    if let Some(bytes) = &body.bytes {
                        req = req.body(bytes.clone());
                    }
                    if let Err(err) = client
                        .execute_redacted(req, "load_testing_fanout", &remote_label)
                        .await
                    {
                        tracing::warn!(
                            remote = %remote_label,
                            error = %err,
                            "load_testing: failed to fan out trigger to remote node"
                        );
                    }
                });
            }
        }

        // Every local worker replays the same immutable request. Share one URL,
        // method, sanitized header snapshot, and retained body across the cohort
        // instead of cloning attacker-sized metadata up to 10,000 times.
        let replay_request = Arc::new(ReplayRequest {
            url: build_url(&gateway_base_url, &path, raw_query.as_deref()),
            method,
            headers: synthetic_headers,
            body: request_body,
        });

        info!(
            proxy = %proxy_name,
            concurrent_clients = concurrent_clients,
            duration_seconds = duration_secs,
            ramp = ramp,
            fanout_control = is_fanout,
            "load_testing: starting load test"
        );

        tokio::spawn(async move {
            // Move the already-created guard into the future. If the runtime
            // drops this future before its first poll, the reservation is still
            // released by `Drop`.
            let _client_budget = client_budget;
            let start = Instant::now();
            let deadline = start + duration;
            let mut handles = Vec::with_capacity(concurrent_clients as usize);

            for i in 0..concurrent_clients {
                let ramp_delay = if ramp {
                    duration * i / concurrent_clients
                } else {
                    Duration::ZERO
                };

                let client = load_test_client.clone();
                let replay_request = Arc::clone(&replay_request);
                let worker_cancel = run_cancel.clone();
                let per_request_timeout = Duration::from_millis(request_timeout_ms);

                let handle = tokio::spawn(async move {
                    if !ramp_delay.is_zero() {
                        tokio::select! {
                            _ = worker_cancel.cancelled() => {
                                return WorkerResult {
                                    counters: WorkerCounters::default(),
                                    cancelled: true,
                                };
                            }
                            _ = tokio::time::sleep(ramp_delay) => {}
                        }
                    }

                    let mut counters = WorkerCounters::default();
                    let mut cancelled = false;
                    let mut error_backoff = Duration::ZERO;

                    while Instant::now() < deadline {
                        if worker_cancel.is_cancelled() {
                            cancelled = true;
                            break;
                        }

                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        let attempt_timeout = per_request_timeout.min(remaining);
                        counters.attempted_requests = counters.attempted_requests.saturating_add(1);

                        let mut req = match build_request(
                            &client,
                            &replay_request.method,
                            &replay_request.url,
                            &replay_request.headers,
                        ) {
                            Ok(req) => req,
                            Err(()) => {
                                counters.transport_errors =
                                    counters.transport_errors.saturating_add(1);
                                error_backoff = next_worker_error_backoff(error_backoff);
                                let remaining = deadline.saturating_duration_since(Instant::now());
                                let delay = error_backoff.min(remaining);
                                if delay.is_zero() {
                                    break;
                                }
                                tokio::select! {
                                    _ = worker_cancel.cancelled() => {
                                        cancelled = true;
                                        break;
                                    }
                                    _ = tokio::time::sleep(delay) => {}
                                }
                                continue;
                            }
                        };
                        if let Some(bytes) = &replay_request.body.bytes {
                            req = req.body(bytes.clone());
                        }

                        let send_fut = async {
                            match req.send().await {
                                Ok(resp) => {
                                    counters.responses_received =
                                        counters.responses_received.saturating_add(1);
                                    record_status(&mut counters, resp.status().as_u16());
                                    match consume_response_with_cap(resp, max_response_body_bytes)
                                        .await
                                    {
                                        BodyConsumeOutcome::Completed => {
                                            counters.responses_completed =
                                                counters.responses_completed.saturating_add(1);
                                            false
                                        }
                                        BodyConsumeOutcome::Truncated => {
                                            counters.responses_truncated =
                                                counters.responses_truncated.saturating_add(1);
                                            false
                                        }
                                        BodyConsumeOutcome::StreamError => {
                                            counters.response_body_errors =
                                                counters.response_body_errors.saturating_add(1);
                                            true
                                        }
                                    }
                                }
                                Err(err) => {
                                    // Classify without logging the raw reqwest error (URL/query
                                    // credentials must never reach structured logs).
                                    let _ = classify_reqwest_error(&err);
                                    if err.is_timeout() {
                                        counters.request_timeouts =
                                            counters.request_timeouts.saturating_add(1);
                                    } else {
                                        counters.transport_errors =
                                            counters.transport_errors.saturating_add(1);
                                    }
                                    true
                                }
                            }
                        };

                        let attempt_failed = tokio::select! {
                            _ = worker_cancel.cancelled() => {
                                cancelled = true;
                                break;
                            }
                            result = tokio::time::timeout(attempt_timeout, send_fut) => {
                                match result {
                                    Ok(attempt_failed) => attempt_failed,
                                    Err(_) => {
                                        counters.request_timeouts =
                                            counters.request_timeouts.saturating_add(1);
                                        true
                                    }
                                }
                            }
                        };

                        if attempt_failed {
                            error_backoff = next_worker_error_backoff(error_backoff);
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            let delay = error_backoff.min(remaining);
                            if delay.is_zero() {
                                break;
                            }
                            tokio::select! {
                                _ = worker_cancel.cancelled() => {
                                    cancelled = true;
                                    break;
                                }
                                _ = tokio::time::sleep(delay) => {}
                            }
                        } else {
                            error_backoff = Duration::ZERO;
                        }
                    }

                    WorkerResult {
                        counters,
                        cancelled,
                    }
                });

                handles.push(handle);
            }

            let mut totals = WorkerCounters::default();
            let mut worker_failures = 0u64;
            let mut cancelled_workers = 0u64;
            let mut aggregation_saturated = false;

            for handle in handles {
                record_worker_completion(
                    handle.await,
                    &mut totals,
                    &mut worker_failures,
                    &mut cancelled_workers,
                    &mut aggregation_saturated,
                );
            }

            let elapsed = start.elapsed();
            let cancelled = run_cancel.is_cancelled();
            let outcome = if cancelled {
                RunOutcome::Cancelled
            } else if totals.responses_completed == 0 || worker_failures > 0 {
                RunOutcome::Failed
            } else if totals.transport_errors > 0
                || totals.request_timeouts > 0
                || totals.response_body_errors > 0
                || totals.responses_truncated > 0
                || cancelled_workers > 0
                || aggregation_saturated
                || totals.status_4xx > 0
                || totals.status_5xx > 0
                || totals.status_other > 0
            {
                RunOutcome::Degraded
            } else {
                RunOutcome::Success
            };

            let completed_rps = if elapsed.as_secs_f64() > 0.0 {
                totals.responses_completed as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };
            let attempted_rps = if elapsed.as_secs_f64() > 0.0 {
                totals.attempted_requests as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            let result = RunResult {
                outcome,
                attempted_requests: totals.attempted_requests,
                responses_received: totals.responses_received,
                responses_completed: totals.responses_completed,
                responses_truncated: totals.responses_truncated,
                response_body_errors: totals.response_body_errors,
                request_timeouts: totals.request_timeouts,
                transport_errors: totals.transport_errors,
                status_2xx: totals.status_2xx,
                status_3xx: totals.status_3xx,
                status_4xx: totals.status_4xx,
                status_5xx: totals.status_5xx,
                status_other: totals.status_other,
                worker_failures,
                cancelled_workers,
                aggregation_saturated,
                elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
            };

            info!(
                proxy = %proxy_name,
                outcome = ?result.outcome,
                attempted_requests = result.attempted_requests,
                responses_received = result.responses_received,
                responses_completed = result.responses_completed,
                responses_truncated = result.responses_truncated,
                response_body_errors = result.response_body_errors,
                request_timeouts = result.request_timeouts,
                transport_errors = result.transport_errors,
                status_2xx = result.status_2xx,
                status_3xx = result.status_3xx,
                status_4xx = result.status_4xx,
                status_5xx = result.status_5xx,
                status_other = result.status_other,
                worker_failures = result.worker_failures,
                cancelled_workers = result.cancelled_workers,
                aggregation_saturated = result.aggregation_saturated,
                elapsed_seconds = %format_args!("{:.2}", elapsed.as_secs_f64()),
                completed_requests_per_second = %format_args!("{:.1}", completed_rps),
                attempted_requests_per_second = %format_args!("{:.1}", attempted_rps),
                max_response_body_bytes = max_response_body_bytes,
                "load_testing: load test finished"
            );

            state.end_run(result);
        });

        if is_fanout {
            fanout_ack_result()
        } else {
            PluginResult::Continue
        }
    }
}

struct ProcessClientBudget {
    count: u64,
}

struct ReplayRequest {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Arc<RetainedRequestBody>,
}

struct RetainedRequestBody {
    bytes: Option<Bytes>,
    reserved_bytes: u64,
}

impl RetainedRequestBody {
    fn try_new(bytes: Option<Bytes>) -> Option<Arc<Self>> {
        let reserved_bytes = bytes.as_ref().map_or(0, |body| body.len() as u64);
        if !try_reserve_process_body_bytes(reserved_bytes) {
            return None;
        }
        Some(Arc::new(Self {
            bytes,
            reserved_bytes,
        }))
    }
}

impl Drop for RetainedRequestBody {
    fn drop(&mut self) {
        PROCESS_RETAINED_BODY_BYTES.fetch_sub(self.reserved_bytes, Ordering::SeqCst);
    }
}

impl ProcessClientBudget {
    fn new(count: u64) -> Self {
        Self { count }
    }
}

impl Drop for ProcessClientBudget {
    fn drop(&mut self) {
        release_process_clients(self.count);
    }
}

fn fanout_ack_result() -> PluginResult {
    PluginResult::Reject {
        status_code: 204,
        body: String::new(),
        headers: HashMap::new(),
    }
}

fn filter_outbound_headers(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    // Same canonical secondary-request boundary as primary backend dispatch and
    // request_mirror. Preserve Host for host-based routing on synthetic/fan-out
    // re-entry; drop the reserved load-testing controls from the shared snapshot
    // (fan-out re-attaches the canonical key/marker pair explicitly).
    filter_secondary_request_headers(
        headers,
        SecondaryRequestHostPolicy::Preserve,
        &[HEADER_TRIGGER_KEY, HEADER_FANOUT],
    )
}

fn record_status(counters: &mut WorkerCounters, status: u16) {
    match status {
        200..=299 => counters.status_2xx = counters.status_2xx.saturating_add(1),
        300..=399 => counters.status_3xx = counters.status_3xx.saturating_add(1),
        400..=499 => counters.status_4xx = counters.status_4xx.saturating_add(1),
        500..=599 => counters.status_5xx = counters.status_5xx.saturating_add(1),
        _ => counters.status_other = counters.status_other.saturating_add(1),
    }
}

/// Build a full URL from a base URL, path, and the original raw query string.
fn build_url(base: &str, path: &str, raw_query: Option<&str>) -> String {
    let query_len = raw_query.map(|q| q.len() + 1).unwrap_or(0);
    let mut url = String::with_capacity(base.len() + path.len() + query_len);
    url.push_str(base);
    url.push_str(path);
    if let Some(query) = raw_query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    url
}

fn build_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
) -> Result<reqwest::RequestBuilder, ()> {
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| ())?;
    let mut req = client.request(method, url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    Ok(req)
}

async fn consume_response_with_cap(resp: reqwest::Response, max_bytes: u64) -> BodyConsumeOutcome {
    let mut stream = resp.bytes_stream();
    let mut consumed: u64 = 0;
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                let chunk_len = chunk.len() as u64;
                // Bytes beyond the cap are truncated; exactly-at-cap plus EOF
                // remains a completed response (no unbounded read).
                match consumed.checked_add(chunk_len) {
                    Some(next) if next > max_bytes => return BodyConsumeOutcome::Truncated,
                    Some(next) => consumed = next,
                    None => return BodyConsumeOutcome::Truncated,
                }
            }
            Err(_) => return BodyConsumeOutcome::StreamError,
        }
    }
    BodyConsumeOutcome::Completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_KEY: &str = "test-load-key-0123456789abcdef!!";

    fn test_config(key: &str) -> Value {
        json!({
            "key": key,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9,
            "request_timeout_ms": 100
        })
    }

    #[test]
    fn replacement_state_shares_only_compatible_policy_and_cancels_on_last_owner() {
        let config = test_config(TEST_KEY);
        let first = LoadTesting::new(&config, PluginHttpClient::default()).expect("first plugin");
        let shared_state = Arc::clone(&first.state);
        let second = LoadTesting::with_shared_state(
            &config,
            PluginHttpClient::default(),
            Arc::clone(&shared_state),
        )
        .expect("compatible replacement");
        assert!(Arc::ptr_eq(&shared_state, &second.state));
        assert_eq!(shared_state.live_owners.load(Ordering::SeqCst), 2);

        let shared_token = shared_state.begin_run().expect("first admission");
        assert!(shared_state.begin_run().is_none());
        drop(first);
        assert!(!shared_token.is_cancelled());
        drop(second);
        assert!(shared_token.is_cancelled());
        shared_state.end_run(RunResult::default());

        let original = LoadTesting::new(&config, PluginHttpClient::default()).expect("original");
        let original_state = Arc::clone(&original.state);
        let original_token = original_state.begin_run().expect("original admission");
        let replacement = LoadTesting::with_shared_state(
            &test_config("replacement-load-key-0123456789abc!"),
            PluginHttpClient::default(),
            Arc::clone(&original_state),
        )
        .expect("incompatible replacement");
        assert!(!Arc::ptr_eq(&original_state, &replacement.state));
        drop(original);
        assert!(original_token.is_cancelled());
        assert!(!replacement.state.run_cancel.lock().unwrap().is_cancelled());
    }

    #[test]
    fn worker_error_backoff_is_bounded_and_exponential() {
        let mut backoff = Duration::ZERO;
        for expected_ms in [10, 20, 40, 80, 160, 250, 250] {
            backoff = next_worker_error_backoff(backoff);
            assert_eq!(backoff, Duration::from_millis(expected_ms));
        }
    }

    #[tokio::test]
    async fn worker_completion_counts_cooperative_cancel_join_cancel_and_join_failure() {
        let mut totals = WorkerCounters::default();
        let mut failures = 0;
        let mut cancelled = 0;
        let mut saturated = false;

        record_worker_completion(
            Ok(WorkerResult {
                counters: WorkerCounters::default(),
                cancelled: true,
            }),
            &mut totals,
            &mut failures,
            &mut cancelled,
            &mut saturated,
        );

        let cancelled_task = tokio::spawn(std::future::pending::<WorkerResult>());
        cancelled_task.abort();
        record_worker_completion(
            cancelled_task.await,
            &mut totals,
            &mut failures,
            &mut cancelled,
            &mut saturated,
        );

        let failed_task = tokio::spawn(async {
            panic!("intentional worker failure classification test");
            #[allow(unreachable_code)]
            WorkerResult {
                counters: WorkerCounters::default(),
                cancelled: false,
            }
        });
        record_worker_completion(
            failed_task.await,
            &mut totals,
            &mut failures,
            &mut cancelled,
            &mut saturated,
        );

        assert_eq!(cancelled, 2);
        assert_eq!(failures, 1);
        assert!(!saturated);
    }
}
