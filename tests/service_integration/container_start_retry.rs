//! Unit coverage for the shared container-start retry (main CI run
//! 36370971003: a Docker Hub pull of `postgres:17` failed with
//! `bytes remaining on stream` and hard-failed the job).
//!
//! These tests do not start Docker. They pin which start errors count as
//! transient image-pull/registry faults, and that the retry stays bounded, so
//! a wait-condition failure or a real setup error still fails on its first
//! attempt.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::common::containers::{
    CONTAINER_START_ATTEMPTS, ContainerStartRetry, is_transient_image_pull_error, start_with_retry,
};
use crate::common::host_ports::retry_on_host_port_collision;

const OBSERVED_PULL_FLAKE: &str =
    "failed to pull the image 'postgres:17', error: bytes remaining on stream";
const PORT_COLLISION: &str = "Bind for 0.0.0.0:42887 failed: port is already allocated";

fn fast_policy() -> ContainerStartRetry {
    ContainerStartRetry {
        attempts: CONTAINER_START_ATTEMPTS,
        budget: Duration::from_secs(30),
        backoff: Duration::from_millis(1),
    }
}

#[test]
fn classifies_the_observed_docker_hub_pull_flake_as_transient() {
    assert!(is_transient_image_pull_error(OBSERVED_PULL_FLAKE));
}

#[test]
fn classifies_transient_transfer_and_registry_faults() {
    for error in [
        "failed to pull the image 'mysql:8.4', error: Docker stream error: \
         error pulling image configuration: download failed after attempts=6",
        "Docker stream error: read tcp 10.1.0.4:40120->104.16.100.207:443: \
         read: connection reset by peer",
        "failed to create a container: Docker responded with status code 500: \
         Get \"https://registry-1.docker.io/v2/\": net/http: TLS handshake timeout",
        "Get \"https://registry-1.docker.io/v2/\": dial tcp: i/o timeout",
        "Timeout error",
        "Get \"https://auth.docker.io/token\": context deadline exceeded",
        "toomanyrequests: You have reached your pull rate limit",
        "received unexpected HTTP status: 503 Service Unavailable",
        "Error in the hyper legacy client: unexpected EOF during chunk size line",
    ] {
        assert!(
            is_transient_image_pull_error(error),
            "must be retried as transient: {error}"
        );
    }
}

#[test]
fn does_not_retry_wait_condition_failures() {
    for error in [
        "container startup timeout",
        "container is not ready: container exited with unexpected code: expected Some(0), \
         actual Some(1)",
        "container is unhealthy",
        "failed to wait for container log: log stream ended",
    ] {
        assert!(
            !is_transient_image_pull_error(error),
            "wait-condition failure must not be retried: {error}"
        );
    }
}

#[test]
fn does_not_retry_deterministic_registry_answers() {
    for error in [
        "failed to pull the image 'postgres:17x', error: Docker stream error: \
         manifest for postgres:17x not found: manifest unknown",
        "failed to pull the image 'ferrum/private:1', error: pull access denied for \
         ferrum/private, repository does not exist or may require 'docker login'",
        "failed to pull the image 'ferrum/private:1', error: unauthorized: \
         authentication required",
        "failed to pull the image 'Bad:Tag', error: invalid reference format",
    ] {
        assert!(
            !is_transient_image_pull_error(error),
            "deterministic registry answer must not be retried: {error}"
        );
    }
}

#[test]
fn does_not_retry_host_port_collisions_or_setup_errors() {
    for error in [
        "failed to start a container: Docker responded with status code 500: \
         driver failed programming external connectivity on endpoint x: \
         Bind for 0.0.0.0:42887 failed: port is already allocated",
        "failed to start a container: Docker responded with status code 500: \
         failed to set up container networking: iptables failed",
        "failed to create a container: Docker responded with status code 400: \
         invalid mount config",
        "failed to upload data to container: file too large",
        "Consul did not elect a leader within 30s",
    ] {
        assert!(
            !is_transient_image_pull_error(error),
            "setup failure must not be retried: {error}"
        );
    }
}

#[tokio::test]
async fn retries_a_transient_pull_failure_then_succeeds() {
    let attempts = AtomicU32::new(0);
    let value = start_with_retry("Postgres", fast_policy(), || {
        let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            if attempt == 1 {
                Err(io::Error::other(OBSERVED_PULL_FLAKE))
            } else {
                Ok(attempt)
            }
        }
    })
    .await
    .expect("a transient pull failure must be retried");
    assert_eq!(value, 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn returns_non_transient_errors_on_the_first_attempt() {
    let attempts = AtomicU32::new(0);
    let result: Result<(), _> = start_with_retry("Postgres", fast_policy(), || {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err(io::Error::other("container startup timeout")) }
    })
    .await;
    let err = result.expect_err("a wait-condition failure must stay a hard error");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        err.to_string(),
        "Postgres image pull/start failed: container startup timeout"
    );
}

#[tokio::test]
async fn exhausts_the_attempt_budget_without_masking_the_error() {
    let attempts = AtomicU32::new(0);
    let result: Result<(), _> = start_with_retry("Postgres", fast_policy(), || {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err(io::Error::other(OBSERVED_PULL_FLAKE)) }
    })
    .await;
    let err = result.expect_err("exhausted retries must fail loudly");
    assert_eq!(attempts.load(Ordering::SeqCst), CONTAINER_START_ATTEMPTS);
    let message = err.to_string();
    assert!(
        message.contains(&format!("after {CONTAINER_START_ATTEMPTS} attempts")),
        "exhaustion must report the attempt count: {message}"
    );
    assert!(
        message.contains("bytes remaining on stream"),
        "exhaustion must keep the last error visible: {message}"
    );
}

#[tokio::test]
async fn phase_deadline_bounds_a_stalled_start_and_is_not_retried() {
    let attempts = AtomicU32::new(0);
    let policy = ContainerStartRetry {
        budget: Duration::from_millis(50),
        ..fast_policy()
    };
    let result: Result<(), _> = start_with_retry("Postgres", policy, || {
        attempts.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<(), io::Error>>()
    })
    .await;
    let err = result.expect_err("a stalled start must breach the phase deadline");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(
        err.to_string().contains("image pull/start exceeded its"),
        "deadline breach must name the phase: {err}"
    );
}

#[tokio::test]
async fn backoff_is_not_taken_past_the_phase_deadline() {
    let attempts = AtomicU32::new(0);
    let policy = ContainerStartRetry {
        budget: Duration::from_millis(50),
        backoff: Duration::from_secs(60),
        ..fast_policy()
    };
    let result: Result<(), _> = start_with_retry("Postgres", policy, || {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err(io::Error::other(OBSERVED_PULL_FLAKE)) }
    })
    .await;
    assert!(result.is_err());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a backoff longer than the remaining budget must end the phase"
    );
}

#[tokio::test]
async fn composes_with_the_host_port_collision_retry() {
    // Outer attempt 1: collision (not retried inside, re-allocated outside).
    // Outer attempt 2: transient pull failure, then success inside.
    let starts = AtomicU32::new(0);
    let outer = AtomicU32::new(0);
    let value = retry_on_host_port_collision(|| async {
        outer.fetch_add(1, Ordering::SeqCst);
        start_with_retry("Postgres", fast_policy(), || {
            let start = starts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                match start {
                    1 => Err(io::Error::other(PORT_COLLISION)),
                    2 => Err(io::Error::other(OBSERVED_PULL_FLAKE)),
                    _ => Ok(start),
                }
            }
        })
        .await
    })
    .await
    .expect("collision then transient pull failure must both be recovered");
    assert_eq!(value, 3);
    assert_eq!(outer.load(Ordering::SeqCst), 2);
    assert_eq!(starts.load(Ordering::SeqCst), 3);
}
