//! Multi-namespace CP polls load their namespaces concurrently (bounded) while
//! keeping the boundary-before-load phase barrier, namespace-ordered merges and
//! per-namespace failure isolation (#2983).
//!
//! The two-namespace tests make every scripted call wait at a barrier sized to
//! the namespace count, so a phase can only finish when all of its namespace
//! calls are in flight at once. The old serial loops parked on the first call
//! forever; the timeout turns that into a test failure. The counting tests pin
//! the per-phase budget with more namespaces than it allows.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use ferrum_edge::config::db_backend::{FullConfigLoadPurpose, IncrementalResult};
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::modes::control_plane::{
    CpFullLoadSource, CpIncrementalLoadSource, cp_namespace_load_concurrency,
    load_full_config_multi_with_sequence_for_test, load_incremental_config_multi_for_test,
};
use tokio::sync::{Barrier, Notify};

const GATE_TIMEOUT: Duration = Duration::from_secs(10);

fn ts(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().expect("timestamp")
}

fn proxy(namespace: &str, suffix: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": format!("{namespace}-{suffix}"),
        "namespace": namespace,
        "listen_path": "/svc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
    }))
    .expect("proxy")
}

fn proxy_ids(proxies: &[Proxy]) -> Vec<&str> {
    proxies.iter().map(|proxy| proxy.id.as_str()).collect()
}

/// Two-namespace scripted source. Each call parks at `gate` until the other
/// namespace's call arrives, and `alpha` then also waits for `beta` to finish,
/// so completion order is the reverse of namespace order.
struct GatedSource {
    gate: Barrier,
    beta_done: Notify,
    failing: Option<&'static str>,
    loaded_at: HashMap<&'static str, i64>,
    events: Mutex<Vec<String>>,
}

impl GatedSource {
    fn new(failing: Option<&'static str>) -> Self {
        Self {
            gate: Barrier::new(2),
            beta_done: Notify::new(),
            failing,
            loaded_at: HashMap::from([("alpha", 50), ("beta", 40)]),
            events: Mutex::new(Vec::new()),
        }
    }

    fn push(&self, event: String) {
        self.events.lock().expect("events lock").push(event);
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events lock").clone()
    }

    fn position(&self, event: &str) -> usize {
        self.events()
            .iter()
            .position(|recorded| recorded == event)
            .unwrap_or_else(|| panic!("missing event {event}: {:?}", self.events()))
    }

    /// Park until the other namespace's call of this phase is in flight; the
    /// `alpha` call then also waits for `beta` to finish first.
    async fn rendezvous(&self, phase: &str, namespace: &str) {
        self.push(format!("{phase}:{namespace}:start"));
        self.gate.wait().await;
        if namespace == "alpha" {
            self.beta_done.notified().await;
        }
        self.push(format!("{phase}:{namespace}:done"));
        if namespace == "beta" {
            self.beta_done.notify_one();
        }
    }

    fn scripted_failure(&self, phase: &str, namespace: &str) -> Result<(), anyhow::Error> {
        if self.failing == Some(namespace) {
            anyhow::bail!("scripted {phase} connectivity failure for {namespace}");
        }
        Ok(())
    }
}

#[async_trait]
impl CpFullLoadSource for GatedSource {
    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        assert_eq!(purpose, FullConfigLoadPurpose::ControlPlane);
        self.rendezvous("load", namespace).await;
        self.scripted_failure("load", namespace)?;
        Ok(GatewayConfig {
            proxies: vec![proxy(namespace, "fresh")],
            loaded_at: ts(self.loaded_at[namespace]),
            ..Default::default()
        })
    }

    async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error> {
        // Boundaries always succeed so both namespaces reach the load phase.
        self.rendezvous("boundary", namespace).await;
        Ok(if namespace == "alpha" { 1 } else { 2 })
    }

    async fn latest_global_change_sequence(&self) -> Result<u64, anyhow::Error> {
        Ok(3)
    }
}

#[async_trait]
impl CpIncrementalLoadSource for GatedSource {
    async fn load_incremental_config(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<IncrementalResult, anyhow::Error> {
        self.rendezvous("delta", namespace).await;
        self.scripted_failure("delta", namespace)?;
        Ok(IncrementalResult {
            added_or_modified_proxies: vec![proxy(namespace, "changed")],
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: Vec::new(),
            sequence_cursor: after_sequence + 1,
            poll_timestamp: ts(self.loaded_at[namespace]),
        })
    }
}

fn namespaces() -> Vec<String> {
    vec!["alpha".to_string(), "beta".to_string()]
}

fn scope() -> CpScope {
    CpScope::Set(namespaces().into_iter().collect::<HashSet<_>>())
}

#[tokio::test]
async fn full_reload_overlaps_each_phase_and_merges_in_namespace_order() {
    let source = GatedSource::new(None);
    let outcome = tokio::time::timeout(
        GATE_TIMEOUT,
        load_full_config_multi_with_sequence_for_test(
            &source,
            &namespaces(),
            &GatewayConfig::default(),
            &scope(),
            None,
            0,
        ),
    )
    .await
    .expect("boundary reads and full loads must each be in flight together")
    .expect("full reload");

    assert!(
        source.position("load:beta:done") < source.position("load:alpha:done"),
        "beta's load completes first in this script"
    );
    assert_eq!(
        outcome.refreshed_namespaces,
        namespaces(),
        "outcomes apply in namespace order, not completion order"
    );
    assert_eq!(
        proxy_ids(&outcome.config.proxies),
        vec!["alpha-fresh", "beta-fresh"]
    );
    assert_eq!(
        outcome.sequences,
        HashMap::from([("alpha".to_string(), 1), ("beta".to_string(), 2)])
    );
    assert_eq!(
        outcome.config.loaded_at,
        ts(40),
        "the combined stamp is the earliest namespace stamp, not the first in namespace order"
    );
    let last_boundary_done = source
        .position("boundary:alpha:done")
        .max(source.position("boundary:beta:done"));
    let first_load_start = source
        .position("load:alpha:start")
        .min(source.position("load:beta:start"));
    assert!(
        last_boundary_done < first_load_start,
        "every pre-load boundary must be captured before any resource load starts: {:?}",
        source.events()
    );
}

#[tokio::test]
async fn full_reload_failure_stays_isolated_to_its_namespace() {
    let source = GatedSource::new(Some("alpha"));
    let previous = GatewayConfig {
        proxies: vec![proxy("alpha", "last-good"), proxy("beta", "stale")],
        loaded_at: ts(10),
        ..Default::default()
    };
    let outcome = tokio::time::timeout(
        GATE_TIMEOUT,
        load_full_config_multi_with_sequence_for_test(
            &source,
            &namespaces(),
            &previous,
            &scope(),
            None,
            0,
        ),
    )
    .await
    .expect("loads must be in flight together")
    .expect("a healthy namespace keeps the reload alive");

    assert_eq!(outcome.refreshed_namespaces, vec!["beta"]);
    assert_eq!(outcome.failed_namespaces, vec!["alpha"]);
    assert_eq!(
        proxy_ids(&outcome.config.proxies),
        vec!["alpha-last-good", "beta-fresh"],
        "the failed namespace retains last-known-good resources"
    );
    assert_eq!(
        outcome.sequences,
        HashMap::from([("beta".to_string(), 2)]),
        "only the refreshed namespace advances its cursor"
    );
    assert_eq!(outcome.config.loaded_at, ts(40));
}

#[tokio::test]
async fn incremental_poll_overlaps_namespaces_and_merges_in_namespace_order() {
    let source = GatedSource::new(None);
    let after = HashMap::from([("alpha".to_string(), 10), ("beta".to_string(), 20)]);
    let outcome = tokio::time::timeout(
        GATE_TIMEOUT,
        load_incremental_config_multi_for_test(&source, &namespaces(), &after, 4),
    )
    .await
    .expect("namespace delta loads must be in flight together")
    .expect("incremental poll");

    assert!(
        source.position("delta:beta:done") < source.position("delta:alpha:done"),
        "beta's delta completes first in this script"
    );
    assert_eq!(
        proxy_ids(&outcome.result.added_or_modified_proxies),
        vec!["alpha-changed", "beta-changed"],
        "deltas merge in namespace order, not completion order"
    );
    assert_eq!(
        outcome.next_sequences,
        HashMap::from([("alpha".to_string(), 11), ("beta".to_string(), 21)])
    );
    assert_eq!(outcome.result.sequence_cursor, 21);
    assert_eq!(outcome.result.poll_timestamp, ts(40));
    assert!(outcome.load_failures.is_empty());
}

#[tokio::test]
async fn incremental_poll_failure_stays_isolated_to_its_namespace() {
    let source = GatedSource::new(Some("alpha"));
    let after = HashMap::from([("alpha".to_string(), 10), ("beta".to_string(), 20)]);
    let outcome = tokio::time::timeout(
        GATE_TIMEOUT,
        load_incremental_config_multi_for_test(&source, &namespaces(), &after, 4),
    )
    .await
    .expect("namespace delta loads must be in flight together")
    .expect("a healthy namespace keeps the poll alive");

    assert_eq!(
        outcome
            .load_failures
            .iter()
            .map(|(namespace, _)| namespace.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha"]
    );
    assert_eq!(
        outcome.next_sequences,
        HashMap::from([("beta".to_string(), 21)]),
        "the failed namespace keeps its prior cursor"
    );
    assert_eq!(
        proxy_ids(&outcome.result.added_or_modified_proxies),
        vec!["beta-changed"]
    );
}

#[test]
fn sql_budget_is_a_quarter_of_the_pool_between_one_and_four() {
    for (pool, expected) in [
        (1, 1),
        (3, 1),
        (7, 1),
        (8, 2),
        (11, 2),
        (12, 3),
        (15, 3),
        (16, 4),
        (32, 4),
        (u32::MAX, 4),
    ] {
        for db_type in ["postgres", "mysql", "sqlite"] {
            assert_eq!(
                cp_namespace_load_concurrency(db_type, pool),
                expected,
                "{db_type} pool of {pool}"
            );
        }
    }
}

#[test]
fn mongodb_budget_ignores_the_sql_pool_setting() {
    for pool in [1, 8, 32] {
        assert_eq!(cp_namespace_load_concurrency("mongodb", pool), 4);
    }
}

/// Records the peak number of scripted calls in flight at once. Each call
/// yields a few times before finishing, so every call the poll admits is
/// pending at the same time.
#[derive(Default)]
struct CountingSource {
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
}

impl CountingSource {
    async fn track(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CpFullLoadSource for CountingSource {
    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        _purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        self.track().await;
        Ok(GatewayConfig {
            proxies: vec![proxy(namespace, "fresh")],
            loaded_at: ts(100),
            ..Default::default()
        })
    }

    async fn latest_change_sequence(&self, _namespace: &str) -> Result<u64, anyhow::Error> {
        self.track().await;
        Ok(1)
    }

    async fn latest_global_change_sequence(&self) -> Result<u64, anyhow::Error> {
        Ok(1)
    }
}

#[async_trait]
impl CpIncrementalLoadSource for CountingSource {
    async fn load_incremental_config(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<IncrementalResult, anyhow::Error> {
        self.track().await;
        Ok(IncrementalResult {
            added_or_modified_proxies: vec![proxy(namespace, "changed")],
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: Vec::new(),
            sequence_cursor: after_sequence + 1,
            poll_timestamp: ts(100),
        })
    }
}

fn many_namespaces() -> Vec<String> {
    (0..7).map(|index| format!("ns-{index}")).collect()
}

#[tokio::test]
async fn full_reload_never_exceeds_the_maximum_budget() {
    let source = CountingSource::default();
    let namespaces = many_namespaces();
    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &namespaces,
        &GatewayConfig::default(),
        &CpScope::Set(namespaces.iter().cloned().collect()),
        None,
        0,
    )
    .await
    .expect("full reload");

    assert_eq!(outcome.refreshed_namespaces, namespaces);
    assert_eq!(
        source.calls(),
        2 * namespaces.len(),
        "one boundary and one load per namespace"
    );
    assert_eq!(
        source.peak(),
        4,
        "boundaries and loads run four at a time, never more"
    );
}

#[tokio::test]
async fn incremental_poll_honours_the_pool_derived_budget() {
    let namespaces = many_namespaces();
    for (pool, expected_peak) in [(32, 4), (8, 2), (1, 1)] {
        let budget = cp_namespace_load_concurrency("postgres", pool);
        let source = CountingSource::default();
        let outcome =
            load_incremental_config_multi_for_test(&source, &namespaces, &HashMap::new(), budget)
                .await
                .expect("incremental poll");

        assert_eq!(outcome.next_sequences.len(), namespaces.len());
        assert_eq!(source.calls(), namespaces.len());
        assert_eq!(
            source.peak(),
            expected_peak,
            "pool of {pool} must cap in-flight namespace loads at {expected_peak}"
        );
    }
}
