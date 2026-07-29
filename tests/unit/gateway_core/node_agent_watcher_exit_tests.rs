//! External coverage for node-agent watcher exit reasons (#2369).
//!
//! Uses an injected finite/pending watcher stream (no live Kubernetes API) to
//! verify that both explicit shutdown and unexpected watcher exhaustion run
//! BPF cleanup exactly once, then return `Ok` only for requested shutdown.
//!
//! The classification is a race between two select! arms, so the streams below
//! are built to land on a *specific* branch of the production loop rather than
//! on whichever branch happens to win: a watch channel that already holds
//! `true` short-circuits at the loop-top check and proves nothing about the
//! race. Each test documents which branch it pins.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;

use ferrum_edge::_test_support::run_with_pod_stream_for_test;
use ferrum_edge::capture::{CaptureConfig, CaptureMode};
use ferrum_edge::ebpf::{
    CaptureContract, FallbackMode, MockEbpfBackend, NodeAgentMetrics, PodAttachmentState,
};
use ferrum_edge::modes::node_agent::NodeAgentConfig;
use futures::stream;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher::{Error as WatcherError, Event};

type WatchItem = Result<Event<Pod>, WatcherError>;

fn test_config() -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    NodeAgentConfig {
        node_name: "test-node".to_string(),
        capture_config,
        cgroup_root: "/nonexistent".to_string(),
        bpf_fs_path: "/nonexistent".to_string(),
        fallback_mode: FallbackMode::Fail,
        excluded_namespaces: HashSet::new(),
        capture_contract: CaptureContract::local_pod_defaults(),
        trust_domain: "cluster.local".to_string(),
        node_waypoint_pod_registry_dir: None,
    }
}

fn seeded_attached_pod(uid: &str) -> PodAttachmentState {
    PodAttachmentState {
        pod_uid: uid.to_string(),
        pod_name: "seeded".to_string(),
        namespace: "default".to_string(),
        pod_ip: None,
        pod_ip6: None,
        cgroup_path: None,
        veth_iface: Some("veth-mock".to_string()),
        attached: true,
        include_ports_cgroup_ids: Vec::new(),
        include_ports_policy: None,
        workload_identity_cgroup_ids: Vec::new(),
        node_probe_ports: vec![8080],
        inbound_redirect_ports: Vec::new(),
    }
}

#[tokio::test]
async fn shutdown_requested_cleans_up_and_returns_ok() {
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    // Already requested: the loop breaks before selecting on the pending stream.
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(true);
    let pending = stream::pending::<WatchItem>();

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        pending,
        [seeded_attached_pod("pod-shutdown")],
    )
    .await;

    assert!(
        result.is_ok(),
        "explicit shutdown must return Ok, got {result:?}"
    );
    assert!(
        *shutdown_tx.borrow(),
        "shutdown path must leave the watch signalled for CNI/admin teardown"
    );
    assert!(
        backend.cleaned_up,
        "shutdown path must run backend.cleanup_all"
    );
    assert_eq!(
        backend.cleanup_all_calls, 1,
        "the borrowed cleanup owner must clean up exactly once (shutdown_pods latches Drop)"
    );
    assert_eq!(backend.detached_pods, vec!["pod-shutdown".to_string()]);
}

#[tokio::test]
async fn shutdown_signalled_while_parked_returns_ok() {
    // Pins the `shutdown_rx.changed()` select arm: the watch starts un-signalled
    // so the loop-top check falls through, the stream never yields, and the only
    // path out of the loop is the shutdown arm waking on the watch notification.
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown_tx = Arc::new(tx);

    let stream_tx = Arc::clone(&shutdown_tx);
    // Signals shutdown from inside the stream poll, i.e. *after* the shutdown
    // arm already registered its waker and returned Pending. The send wakes that
    // waker; the stream itself never becomes ready, so the only way out is the
    // `changed()` arm. Re-sending on a hypothetical second poll is idempotent.
    let parked = stream::poll_fn(move |_cx| {
        let _ = stream_tx.send(true);
        Poll::<Option<WatchItem>>::Pending
    });

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        parked,
        [seeded_attached_pod("pod-parked")],
    )
    .await;

    assert!(
        result.is_ok(),
        "shutdown observed via the watch-changed arm must return Ok, got {result:?}"
    );
    assert!(backend.cleaned_up);
    assert_eq!(backend.cleanup_all_calls, 1);
    assert_eq!(backend.detached_pods, vec!["pod-parked".to_string()]);
}

#[tokio::test]
async fn shutdown_requested_wins_over_a_racing_exhausted_stream() {
    // Pins the `None`-arm re-read of the watch value, which is the only guard
    // for the genuine race: the watch starts un-signalled (so the loop-top check
    // and the shutdown arm both fall through) and only flips to `true`
    // during the very poll that reports the stream exhausted. Without the
    // re-read this would misclassify an operator shutdown as watcher failure
    // and exit nonzero.
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown_tx = Arc::new(tx);

    let stream_tx = Arc::clone(&shutdown_tx);
    let racing = stream::poll_fn(move |_cx| {
        let _ = stream_tx.send(true);
        Poll::Ready(None::<WatchItem>)
    });

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        racing,
        [seeded_attached_pod("pod-shutdown-race")],
    )
    .await;

    assert!(
        result.is_ok(),
        "requested shutdown must win over stream exhaustion, got {result:?}"
    );
    assert!(*shutdown_tx.borrow());
    assert!(backend.cleaned_up);
    assert_eq!(backend.cleanup_all_calls, 1);
    assert_eq!(backend.detached_pods, vec!["pod-shutdown-race".to_string()]);
}

#[tokio::test]
async fn watcher_exhaustion_cleans_up_and_returns_err() {
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    // Finite empty stream: first poll yields None → unexpected exhaustion.
    let empty = stream::empty::<WatchItem>();

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        empty,
        [seeded_attached_pod("pod-exhausted")],
    )
    .await;

    let err = result.expect_err("watcher exhaustion must return Err");
    assert!(
        err.to_string().contains("Pod watcher ended unexpectedly"),
        "unexpected error text: {err}"
    );
    assert!(
        *shutdown_tx.borrow(),
        "exhaustion must signal shutdown so the CNI listener join cannot hang"
    );
    assert!(
        backend.cleaned_up,
        "watcher-exhaustion path must still run backend.cleanup_all"
    );
    assert_eq!(
        backend.cleanup_all_calls, 1,
        "the error path must not double-clean via Drop after shutdown_pods"
    );
    assert_eq!(backend.detached_pods, vec!["pod-exhausted".to_string()]);
}

#[tokio::test]
async fn transient_watcher_errors_do_not_exit_the_loop() {
    // Documented contract in docs/node_agent.md: watcher *errors* are logged and
    // retried by kube-rs, only end-of-stream classifies as exhaustion. The error
    // item must therefore be consumed and counted, and the loop must keep going
    // until the stream actually ends.
    let mut backend = MockEbpfBackend::default();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let metrics_view = Arc::clone(&metrics);
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    let items: Vec<WatchItem> = vec![
        Err(WatcherError::NoResourceVersion),
        Err(WatcherError::NoResourceVersion),
    ];
    let with_error = stream::iter(items);

    let result = run_with_pod_stream_for_test(
        &mut backend,
        &test_config(),
        metrics,
        &shutdown_tx,
        with_error,
        [seeded_attached_pod("pod-transient")],
    )
    .await;

    let err = result.expect_err("the stream still ends, so the run must fail");
    assert!(
        err.to_string().contains("Pod watcher ended unexpectedly"),
        "a transient watcher error must not become the exit error: {err}"
    );
    assert_eq!(
        metrics_view.attach_errors.load(Ordering::Relaxed),
        2,
        "both transient watcher errors must be consumed and counted, not exit the loop"
    );
    assert!(backend.cleaned_up);
    assert_eq!(backend.cleanup_all_calls, 1);
}
