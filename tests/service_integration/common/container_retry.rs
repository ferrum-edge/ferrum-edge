//! Bounded retry for transient container image-pull/registry failures,
//! shared by every Docker-backed test fixture.
//!
//! A registry pull can fail for reasons that have nothing to do with the
//! fixture: Docker Hub cutting a layer short (`bytes remaining on stream`,
//! main CI run 36370971003), a reset connection, a TLS handshake timeout, rate
//! limiting, or a registry 5xx. [`start_within_deadline`] retries only those,
//! a bounded number of times inside one phase deadline; every other start
//! failure (wait conditions, a wrong image reference, a host-port collision)
//! is returned after the first attempt so a broken fixture still hard-fails in
//! CI.
//!
//! Compiled into both container suites: `tests/service_integration/` owns it
//! next to [`super::host_ports`], and the Vault/LocalStack fixtures in
//! `tests/secrets_functional/common/` include it through `#[path]` rather than
//! reimplementing it. Its Docker-free unit tests live in
//! `tests/service_integration/container_start_retry.rs`.

use std::future::Future;
use std::time::{Duration, Instant};

use super::host_ports::{BoxError, is_host_port_collision};

/// Wall-clock bound on one container `start()` phase (image pull + create +
/// start), including every transient-pull retry and backoff inside it. A cold
/// runner pulling a multi-hundred-megabyte image is slow, but it is not
/// unbounded — 5 minutes is well past the observed worst case (~1 min) and far
/// short of the 60-minute job budget.
pub const CONTAINER_START_TIMEOUT: Duration = Duration::from_secs(300);

/// Attempts [`start_within_deadline`] makes when a start fails with a
/// transient image-pull/registry error (see [`is_transient_image_pull_error`]).
/// Any other failure is returned after the first attempt.
pub const CONTAINER_START_ATTEMPTS: u32 = 3;

/// Backoff unit between those attempts: the wait after attempt `n` is `n`
/// units, and it is only taken while the phase deadline still has room.
pub const CONTAINER_START_BACKOFF: Duration = Duration::from_secs(2);

/// Retry policy for one container `start()` phase. [`start_within_deadline`]
/// uses [`ContainerStartRetry::DEFAULT`]; tests inject short bounds.
#[derive(Clone, Copy, Debug)]
pub struct ContainerStartRetry {
    /// Total attempts, including the first.
    pub attempts: u32,
    /// Wall-clock bound on the whole phase, across attempts and backoff.
    pub budget: Duration,
    /// Backoff unit; the wait after attempt `n` is `n` units.
    pub backoff: Duration,
}

impl ContainerStartRetry {
    pub const DEFAULT: Self = Self {
        attempts: CONTAINER_START_ATTEMPTS,
        budget: CONTAINER_START_TIMEOUT,
        backoff: CONTAINER_START_BACKOFF,
    };
}

/// Error text that marks a start failure as a deterministic answer rather than
/// a transfer fault: a wrong image reference or credentials, and
/// testcontainers' own wait-condition failures. Checked before
/// [`TRANSIENT_START_MARKERS`], so e.g. `container startup timeout` is never
/// retried as a "timeout".
const NON_TRANSIENT_START_MARKERS: &[&str] = &[
    "manifest unknown",
    "not found",
    "denied",
    "unauthorized",
    "invalid reference format",
    "container startup timeout",
    "container is not ready",
    "container is unhealthy",
    "container exited with unexpected code",
    "failed to wait for container log",
    "healthcheck is not configured",
];

/// Error text of a transient image-pull or registry fault: testcontainers'
/// `failed to pull the image` wrapper, a truncated or reset transfer, a
/// network timeout, registry rate limiting, or a registry 5xx.
const TRANSIENT_START_MARKERS: &[&str] = &[
    "failed to pull",
    "bytes remaining on stream",
    "connection reset",
    "unexpected eof",
    "timeout",
    "timed out",
    "context deadline exceeded",
    "tls handshake",
    "toomanyrequests",
    "too many requests",
    "unexpected http status: 5",
    "500 internal server error",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
];

/// True when a container-start error is a transient image-pull or registry
/// failure worth another attempt (e.g. Docker Hub cutting a `postgres:17` layer
/// short with `bytes remaining on stream`, main CI run 36370971003).
///
/// Deliberately conservative. Host-port bind collisions are excluded so they
/// reach [`super::host_ports::retry_on_host_port_collision`] and get a fresh
/// port; wait-condition failures and deterministic registry answers (unknown
/// manifest, denied pull) are excluded so a broken fixture still fails on its
/// first attempt.
pub fn is_transient_image_pull_error(error: &str) -> bool {
    if is_host_port_collision(error) {
        return false;
    }
    let lower = error.to_ascii_lowercase();
    if NON_TRANSIENT_START_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return false;
    }
    TRANSIENT_START_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Bound one container `start()` (image pull + create + start) by
/// [`CONTAINER_START_TIMEOUT`], retrying transient image-pull/registry errors
/// up to [`CONTAINER_START_ATTEMPTS`] times inside that same deadline.
///
/// `start` builds and starts a fresh request on every call (a
/// `ContainerRequest` is consumed by `start()` and is not `Clone`). Every
/// other error, including a host-port collision, is returned after the attempt
/// that produced it with its text intact, so callers keep their existing error
/// handling and [`super::host_ports::retry_on_host_port_collision`] still sees
/// collisions.
pub async fn start_within_deadline<F, Fut, T, E>(service: &str, start: F) -> Result<T, BoxError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    start_with_retry(service, ContainerStartRetry::DEFAULT, start).await
}

/// [`start_within_deadline`] with an explicit [`ContainerStartRetry`] policy.
pub async fn start_with_retry<F, Fut, T, E>(
    service: &str,
    policy: ContainerStartRetry,
    mut start: F,
) -> Result<T, BoxError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let attempts = policy.attempts.max(1);
    let started = Instant::now();
    let deadline = started + policy.budget;
    let mut attempt = 1;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let error = match tokio::time::timeout(remaining, start()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) => error.to_string(),
            Err(_) => {
                return Err(format!(
                    "{service} image pull/start exceeded its {:.0}s deadline \
                     (elapsed {:.1}s, attempt {attempt}/{attempts})",
                    policy.budget.as_secs_f64(),
                    started.elapsed().as_secs_f64()
                )
                .into());
            }
        };
        let backoff = policy.backoff.saturating_mul(attempt);
        let has_budget = deadline.saturating_duration_since(Instant::now()) > backoff;
        if attempt >= attempts || !has_budget || !is_transient_image_pull_error(&error) {
            let message = if attempt == 1 {
                format!("{service} image pull/start failed: {error}")
            } else {
                format!("{service} image pull/start failed after {attempt} attempts: {error}")
            };
            return Err(message.into());
        }
        eprintln!(
            "{service} image pull/start attempt {attempt}/{attempts} failed with a transient \
             image-pull/registry error after {:.1}s; retrying in {:.0}s: {error}",
            started.elapsed().as_secs_f64(),
            backoff.as_secs_f64()
        );
        tokio::time::sleep(backoff).await;
        attempt += 1;
    }
}
