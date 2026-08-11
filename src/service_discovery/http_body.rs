//! Bounded HTTP response-body collection for Kubernetes and Consul discovery.
//!
//! Discovery pollers must never call unbounded `Response::{text,json,bytes}`:
//! a registry, intermediary, or hostile payload can otherwise force arbitrary
//! process memory. This module:
//!
//! * rejects an oversized declared `Content-Length` before reading chunks
//! * streams chunked / unknown-length bodies and aborts before retaining
//!   `limit + 1` bytes
//! * applies a tighter independent ceiling to error responses
//! * charges retained bytes against a process-wide concurrent budget whose
//!   permits release on every error and drop path (including cancellation)
//! * grows the shared charge incrementally so a small body does not reserve
//!   the full per-response maximum and never pre-allocates from an untrusted
//!   `Content-Length` outside that budget
//!
//! Diagnostics stay fixed-cardinality: oversized / budget / read failures never
//! carry provider URLs, tokens, headers, or body bytes.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_LENGTH;
use tracing::warn;

use crate::config::env_config::{DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES, DiscoveryBodyLimits};
use crate::util::body_limit::{ContentLength, parse_content_length};

/// Role of the response body being collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryBodyRole {
    /// Successful registry snapshot (EndpointSliceList / Consul health array).
    Success,
    /// Non-success registry response. Uses the tighter error ceiling and is
    /// never logged or surfaced to operators.
    Error,
}

impl DiscoveryBodyLimits {
    fn ceiling_for(self, role: DiscoveryBodyRole) -> usize {
        match role {
            DiscoveryBodyRole::Success => self.max_response_bytes,
            DiscoveryBodyRole::Error => self.max_error_bytes,
        }
    }
}

/// Why bounded discovery body collection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryBodyError {
    /// Declared or streamed body exceeded the per-response ceiling.
    Oversized,
    /// Concurrent discovery-body budget could not admit the next byte range.
    BudgetExhausted,
    /// Transport failed while reading body chunks.
    ReadFailed,
    /// `Content-Length` was present but ambiguous / unusable as a bound.
    AmbiguousContentLength,
}

impl DiscoveryBodyError {
    /// Fixed reason label for logs/metrics (never derived from body contents).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Oversized => "response_oversized",
            Self::BudgetExhausted => "body_budget_rejected",
            Self::ReadFailed => "body_read_failed",
            Self::AmbiguousContentLength => "ambiguous_content_length",
        }
    }

    pub fn as_anyhow(self, provider: &'static str) -> anyhow::Error {
        match self {
            Self::Oversized => {
                anyhow::anyhow!("{provider} discovery response body exceeds configured byte limit")
            }
            Self::BudgetExhausted => anyhow::anyhow!(
                "{provider} discovery response rejected: concurrent body budget exhausted"
            ),
            Self::ReadFailed => {
                anyhow::anyhow!("{provider} discovery response body read failed")
            }
            Self::AmbiguousContentLength => {
                anyhow::anyhow!("{provider} discovery response rejected: ambiguous Content-Length")
            }
        }
    }
}

/// Collected discovery body bytes paired with a shared-budget permit.
///
/// Dropping this value (including cancellation of the owning task) releases the
/// charged budget. Callers should parse from [`as_slice`](Self::as_slice) and
/// drop promptly so the budget is not held across poll intervals.
pub struct ChargedDiscoveryBody {
    bytes: Vec<u8>,
    _permit: DiscoveryBodyBudgetPermit,
}

impl ChargedDiscoveryBody {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Move the bytes out while keeping the permit alive until the returned
    /// [`Bytes`] (and any clones) drop.
    #[allow(dead_code)] // available to callers / tests that need Bytes ownership
    pub fn into_bytes(self) -> Bytes {
        Bytes::from_owner(ChargedDiscoveryBodyOwner {
            bytes: self.bytes,
            _permit: self._permit,
        })
    }
}

struct ChargedDiscoveryBodyOwner {
    bytes: Vec<u8>,
    _permit: DiscoveryBodyBudgetPermit,
}

impl AsRef<[u8]> for ChargedDiscoveryBodyOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Cancellation-safe shared-budget lease for one in-flight discovery body.
struct DiscoveryBodyBudgetPermit {
    charged: usize,
    test_budget: Option<std::sync::Arc<TestDiscoveryBodyBudget>>,
}

impl DiscoveryBodyBudgetPermit {
    fn empty() -> Self {
        Self {
            charged: 0,
            test_budget: active_test_budget(),
        }
    }

    fn try_grow(&mut self, additional: usize) -> Result<(), DiscoveryBodyError> {
        if additional == 0 {
            return Ok(());
        }
        match &self.test_budget {
            Some(budget) => {
                try_charge_counter(&budget.used, budget.limits.body_budget_bytes, additional)?
            }
            None => try_charge_budget(additional)?,
        }
        self.charged = self.charged.saturating_add(additional);
        Ok(())
    }
}

impl Drop for DiscoveryBodyBudgetPermit {
    fn drop(&mut self) {
        match &self.test_budget {
            Some(budget) => release_budget_counter(&budget.used, self.charged),
            None => release_budget(self.charged),
        }
        self.charged = 0;
    }
}

static INSTALLED_LIMITS: OnceLock<DiscoveryBodyLimits> = OnceLock::new();
static BUDGET_USED: AtomicUsize = AtomicUsize::new(0);
static BUDGET_MAX: AtomicUsize = AtomicUsize::new(DEFAULT_SERVICE_DISCOVERY_BODY_BUDGET_BYTES);

/// Test-only limits and budget counter owned by one test thread.
///
/// The permit keeps this allocation alive if an async body is later dropped on
/// another thread, while unrelated parallel tests never inherit its ceilings or
/// contribute bytes to its budget.
struct TestDiscoveryBodyBudget {
    limits: DiscoveryBodyLimits,
    used: AtomicUsize,
}

std::thread_local! {
    static TEST_OVERRIDE_LIMITS: std::cell::RefCell<
        Option<std::sync::Arc<TestDiscoveryBodyBudget>>
    > = const { std::cell::RefCell::new(None) };
}

fn active_test_budget() -> Option<std::sync::Arc<TestDiscoveryBodyBudget>> {
    TEST_OVERRIDE_LIMITS.with(|slot| slot.borrow().clone())
}

/// Install process discovery body ceilings (EnvConfig / production path).
///
/// Identical reinstall is accepted. A conflicting value fails closed so the
/// runtime ceiling cannot silently diverge from the parsed `EnvConfig` field.
pub fn install_discovery_body_limits(limits: DiscoveryBodyLimits) -> Result<(), String> {
    crate::config::env_config::parse_discovery_body_limits(
        Some(&limits.max_response_bytes.to_string()),
        Some(&limits.max_error_bytes.to_string()),
        Some(&limits.body_budget_bytes.to_string()),
    )?;
    match INSTALLED_LIMITS.set(limits) {
        Ok(()) => {
            BUDGET_MAX.store(limits.body_budget_bytes, Ordering::Release);
            Ok(())
        }
        Err(_) => match INSTALLED_LIMITS.get() {
            Some(existing) if *existing == limits => Ok(()),
            Some(_) => Err(
                "service discovery body ceilings are already installed with a different value \
                 for this process"
                    .to_string(),
            ),
            None => Err(
                "service discovery body ceiling install raced and left no installed value"
                    .to_string(),
            ),
        },
    }
}

/// Test-only override that replaces effective ceilings and the budget counter
/// for the calling test thread without touching production process state.
/// Restored by [`clear_discovery_body_limits_override_for_test`].
///
/// Callers must clear the override on the same thread after every owned permit
/// has dropped. A permit retains the override-owned counter itself, so a drop on
/// another thread still releases the correct budget.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub fn override_discovery_body_limits_for_test(limits: DiscoveryBodyLimits) -> Result<(), String> {
    crate::config::env_config::parse_discovery_body_limits(
        Some(&limits.max_response_bytes.to_string()),
        Some(&limits.max_error_bytes.to_string()),
        Some(&limits.body_budget_bytes.to_string()),
    )?;
    TEST_OVERRIDE_LIMITS.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| {
            "service discovery body limit test override is already borrowed".to_string()
        })?;
        *slot = Some(std::sync::Arc::new(TestDiscoveryBodyBudget {
            limits,
            used: AtomicUsize::new(0),
        }));
        Ok(())
    })
}

/// Clear the calling thread's test override without changing production state.
/// Existing permits retain and release their own override-owned counter.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub fn clear_discovery_body_limits_override_for_test() {
    TEST_OVERRIDE_LIMITS.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            *slot = None;
        }
    });
}

/// Effective ceilings: test override → installed EnvConfig snapshot → defaults.
pub fn effective_discovery_body_limits() -> DiscoveryBodyLimits {
    if let Some(budget) = active_test_budget() {
        return budget.limits;
    }
    installed_or_default_limits()
}

fn installed_or_default_limits() -> DiscoveryBodyLimits {
    INSTALLED_LIMITS
        .get()
        .copied()
        .unwrap_or_else(DiscoveryBodyLimits::defaults)
}

fn try_charge_budget(additional: usize) -> Result<(), DiscoveryBodyError> {
    let max = BUDGET_MAX.load(Ordering::Acquire);
    try_charge_counter(&BUDGET_USED, max, additional)
}

fn try_charge_counter(
    used_counter: &AtomicUsize,
    max: usize,
    additional: usize,
) -> Result<(), DiscoveryBodyError> {
    match used_counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
        used.checked_add(additional).filter(|next| *next <= max)
    }) {
        Ok(_) => Ok(()),
        Err(_) => Err(DiscoveryBodyError::BudgetExhausted),
    }
}

fn release_budget(bytes: usize) {
    release_budget_counter(&BUDGET_USED, bytes);
}

fn release_budget_counter(used_counter: &AtomicUsize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let _ = used_counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
        Some(used.saturating_sub(bytes))
    });
}

/// Observation seam for tests: bytes currently charged against the shared budget.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub fn discovery_body_budget_used_for_test() -> usize {
    if let Some(budget) = active_test_budget() {
        return budget.used.load(Ordering::Acquire);
    }
    BUDGET_USED.load(Ordering::Acquire)
}

/// Observation seam for tests: configured shared budget ceiling.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub fn discovery_body_budget_max_for_test() -> usize {
    if let Some(budget) = active_test_budget() {
        return budget.limits.body_budget_bytes;
    }
    BUDGET_MAX.load(Ordering::Acquire)
}

/// Reduce every `Content-Length` header value (including repeated field lines
/// and comma-folded members) to one agreed length, or fail closed.
///
/// [`HeaderMap::get`] only examines one `HeaderValue`. The security contract
/// requires every present value to parse and agree before the oversized
/// declaration fast path can accept or reject the response.
fn discovery_declared_content_length(headers: &HeaderMap) -> Option<ContentLength> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let first = values.next()?;
    let mut agreed: Option<u64> = None;
    for value in std::iter::once(first).chain(values) {
        let Ok(raw) = value.to_str() else {
            return Some(ContentLength::Ambiguous);
        };
        match parse_content_length(raw) {
            ContentLength::Exact(parsed) => match agreed {
                None => agreed = Some(parsed),
                Some(previous) if previous != parsed => return Some(ContentLength::Ambiguous),
                Some(_) => {}
            },
            ContentLength::Ambiguous => return Some(ContentLength::Ambiguous),
        }
    }
    Some(match agreed {
        Some(value) => ContentLength::Exact(value),
        None => ContentLength::Ambiguous,
    })
}

/// Collect a discovery HTTP response body under the configured ceilings and
/// shared concurrent budget.
///
/// On success the returned [`ChargedDiscoveryBody`] holds the budget permit
/// until dropped. On every error path the permit is released before returning.
///
/// Allocator capacity is never reserved from an untrusted `Content-Length`
/// before a shared-budget charge. Retained byte ranges are charged immediately
/// before append; cancellation, error, and drop release the charge.
pub async fn collect_discovery_response_body(
    response: reqwest::Response,
    role: DiscoveryBodyRole,
) -> Result<ChargedDiscoveryBody, DiscoveryBodyError> {
    let limits = effective_discovery_body_limits();
    let max_bytes = limits.ceiling_for(role);

    if let Some(declared) = discovery_declared_content_length(response.headers()) {
        match declared {
            ContentLength::Exact(declared) => {
                if declared > max_bytes as u64 {
                    record_body_failure(DiscoveryBodyError::Oversized, role);
                    return Err(DiscoveryBodyError::Oversized);
                }
            }
            ContentLength::Ambiguous => {
                record_body_failure(DiscoveryBodyError::AmbiguousContentLength, role);
                return Err(DiscoveryBodyError::AmbiguousContentLength);
            }
        }
    }

    let mut permit = DiscoveryBodyBudgetPermit::empty();
    // Grow only with retained, budget-charged chunks. Do not `reserve` from
    // attacker-controlled Content-Length: that would allocate outside
    // FERRUM_SERVICE_DISCOVERY_BODY_BUDGET_BYTES before any permit exists.
    let mut buf = Vec::new();

    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(None) => break,
            Ok(Some(chunk)) => {
                if chunk.is_empty() {
                    continue;
                }
                let added = chunk.len();
                let new_total = buf.len().saturating_add(added);
                // Abort before retaining limit+1 bytes.
                if new_total > max_bytes {
                    record_body_failure(DiscoveryBodyError::Oversized, role);
                    return Err(DiscoveryBodyError::Oversized);
                }
                if let Err(err) = permit.try_grow(added) {
                    record_body_failure(err, role);
                    return Err(err);
                }
                buf.extend_from_slice(&chunk);
            }
            Err(_) => {
                record_body_failure(DiscoveryBodyError::ReadFailed, role);
                return Err(DiscoveryBodyError::ReadFailed);
            }
        }
    }

    Ok(ChargedDiscoveryBody {
        bytes: buf,
        _permit: permit,
    })
}

fn record_body_failure(error: DiscoveryBodyError, role: DiscoveryBodyRole) {
    let registry = crate::plugins::prometheus_metrics::global_registry();
    match error {
        DiscoveryBodyError::Oversized | DiscoveryBodyError::AmbiguousContentLength => {
            registry.record_service_discovery_response_oversized();
        }
        DiscoveryBodyError::BudgetExhausted => {
            registry.record_service_discovery_body_budget_rejected();
        }
        DiscoveryBodyError::ReadFailed => {}
    }
    warn!(
        role = ?role,
        reason = error.reason(),
        "Service discovery: bounded response body collection failed"
    );
}
