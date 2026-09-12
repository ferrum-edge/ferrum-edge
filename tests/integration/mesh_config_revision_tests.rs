//! Authoritative mesh config-revision ordering (issue #2473).
//!
//! Native multi-CP failover must never move a data plane backwards. A fallback
//! control plane that missed a poll or is partitioned from the config store
//! still serves a structurally valid slice; installing it would reinstate
//! deleted routes, endpoints, policies, or trust material until failback. The
//! slice `version` cannot arbitrate that — it renders the serving CP's local
//! wall clock.
//!
//! Six layers of coverage:
//!
//! 1. The pure comparison contract (`MeshConfigRevision::compare`) and the
//!    stateful gate (`MeshRevisionGate`), including the time-dependent
//!    foreign-authority adoption and the operator reset.
//! 2. The consumer/runtime seam: a data plane whose stream rotates between two
//!    control planes at different revisions (N-1, N, N+1, clock skew, CP
//!    restart, intentional rollback published as N+1, failback after a stale
//!    fallback was quarantined).
//! 3. A live two-CP `MeshSubscribe` run: a stale primary is quarantined, the
//!    stream is torn down, and the data plane converges on the fresher
//!    fallback without ever serving the stale slice.
//! 4. The candidate LIFECYCLE across the freshness gate and the proxy runtime:
//!    admission is provisional, so a candidate the runtime later refuses must
//!    return the watermark to the last applied generation — without a late
//!    rejection disturbing a newer candidate received meanwhile.
//! 5. Full-load boundary ordering: namespace and store-global cursors are
//!    captured before resources, and one failed namespace preserves its LKG
//!    without blocking healthy explicit-scope namespaces.
//! 6. Bounding of the control-plane-supplied `authority` on every copy that
//!    leaves the gate (diagnostics, the operator reset, and the log lines built
//!    from them), while ordering keeps the raw value.
//! 7. The Kubernetes ordering domain (issue #3611): a CRD-controller control
//!    plane sequences from a `resourceVersion` convergence watermark instead of
//!    a change-log cursor. Covers the domain separation, the evidence rules
//!    (boundary adoption, buffered lists, deletion advancing rather than
//!    rewinding, unparsable versions), the minimum-across-scopes coherence
//!    point, retain-last-good on incomplete convergence, two replicas failing
//!    over, and native/xDS parity — including a run of the production watcher
//!    task over scripted reflector generations.
//! 8. The equal-revision CONTENT BINDING (issue #3611): a `Same` revision
//!    installs only for identical semantic content. The Kubernetes producer
//!    binds mesh to the scalar at `publish_k8s_reconcile` (retaining the last
//!    accepted mesh under an equal sequence); the data-plane gate remains the
//!    cross-replica defense so a lagging peer at an equal sequence cannot roll
//!    a data plane back. Covers the local runtime and xDS paths, the
//!    exact-content replay that must keep installing, revision/identity pairing
//!    across rollback and reset, and the multi-scope Kubernetes counterexample.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::_test_support::{K8sWatchScopeForTest, k8s_watch_scope_with_revision_for_test};
use ferrum_edge::config::db_backend::FullConfigLoadPurpose;
use ferrum_edge::config::types::{Consumer, GatewayConfig};
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::grpc::dp_client::GrpcJwtSecret;
use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::k8s_controller::revision::{
    K8sConfigRevisionTracker, K8sWatchScopeKey, parse_resource_version, watch_scope_key,
};
use ferrum_edge::modes::control_plane::{
    CpFullLoadSource, load_full_config_multi_with_sequence_for_test,
};
use ferrum_edge::modes::mesh::config::MeshService;
use ferrum_edge::modes::mesh::config_consumer::native_client::{
    NativeMeshClientConfig, NativeMeshConfigConsumer, start_native_mesh_client_with_shutdown,
};
use ferrum_edge::modes::mesh::config_consumer::stream_lifecycle::MeshStreamTimings;
use ferrum_edge::modes::mesh::config_consumer::update_validation::{
    MeshUpdateConsumer, MeshUpdateExpectation, MeshUpdateRejectReason, validate_mesh_config_update,
};
use ferrum_edge::modes::mesh::config_consumer::xds_client::{XdsClientConfig, XdsConfigConsumer};
use ferrum_edge::modes::mesh::initial_config_wait_test_seams::{
    PROBE_NAMESPACE, PROBE_NODE_ID, wait_for_initial_mesh_config_for_test,
};
use ferrum_edge::modes::mesh::revision::{
    KUBERNETES_AUTHORITY_DOMAIN, MeshConfigRevision, MeshRevisionContentIdentity, MeshRevisionGate,
    MeshRevisionOrder, MeshRevisionPolicy, MeshRevisionRejectReason, is_kubernetes_authority,
    kubernetes_authority,
};
use ferrum_edge::modes::mesh::runtime::{
    MeshRuntimeState, MeshSliceInstall, MeshSliceRuntimeOutcome, MeshSliceRuntimeRejectReason,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;
use kube::runtime::watcher::Event;

const NODE_ID: &str = "dp-node-a";
const NAMESPACE: &str = "alpha";
const JWT_SECRET: &str = "mesh-config-revision-secret-00000000";

// ── Fixtures ───────────────────────────────────────────────────────────────

fn revision(authority: &str, sequence: u64) -> MeshConfigRevision {
    MeshConfigRevision::new(authority, sequence)
}

/// A distinct, stable content identity per `tag`. Direct `MeshRevisionGate`
/// tests exercise the ORDERING contract, so they pass one identity unless the
/// case under test is specifically about divergent content at an equal
/// revision — where two different tags stand in for two producers' snapshots.
fn cid(tag: u8) -> MeshRevisionContentIdentity {
    MeshRevisionContentIdentity::from_digest([tag; 32])
}

/// A slice bound to the test subscription at a given authoritative revision.
///
/// `version` is deliberately decoupled from `sequence` so the tests can prove
/// ordering follows the revision and NOT the CP-local wall clock rendering.
fn slice_at(version: &str, revision: Option<MeshConfigRevision>) -> MeshSlice {
    MeshSlice {
        node_id: NODE_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        version: version.to_string(),
        revision,
        ..MeshSlice::default()
    }
}

/// A slice whose semantic CONTENT varies with `marker`.
///
/// `version` cannot stand in for a content difference: the canonical content
/// identity clears it (it renders the serving CP's local wall clock and is
/// observability-only), which is precisely what lets a replay served by a
/// different replica still count as identical. A real slice field has to
/// differ — `labels` is the smallest one that rides every producer path.
fn slice_with_content(
    version: &str,
    revision: Option<MeshConfigRevision>,
    marker: &str,
) -> MeshSlice {
    let mut slice = slice_at(version, revision);
    slice.labels = BTreeMap::from([("mesh-content".to_string(), marker.to_string())]);
    slice
}

fn update_for(slice: &MeshSlice) -> MeshConfigUpdate {
    MeshConfigUpdate {
        version: slice.version.clone(),
        timestamp: 1,
        mesh_slice_json: serde_json::to_string(slice).expect("slice serializes"),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        heartbeat: false,
        config_authority: slice
            .revision
            .as_ref()
            .map(|revision| revision.authority.clone())
            .unwrap_or_default(),
        config_sequence: slice
            .revision
            .as_ref()
            .map_or(0, |revision| revision.sequence),
        session_token: "test-session".to_string(),
    }
}

fn client_config() -> NativeMeshClientConfig {
    NativeMeshClientConfig {
        node_id: NODE_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        workload_spiffe_id: None,
        waypoint_name: None,
        labels: HashMap::new(),
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
        primary_retry_secs: 0,
        timings: MeshStreamTimings::production(),
    }
}

/// A consumer bound to exactly what `client_config` subscribes with. Each
/// control-plane stream builds its own consumer over the SAME runtime state,
/// which is precisely the multi-CP failover shape.
fn consumer_for(state: MeshRuntimeState) -> NativeMeshConfigConsumer {
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    NativeMeshConfigConsumer::new(
        state,
        MeshUpdateExpectation::from_subscribe_request(&request),
    )
}

fn installed_version(state: &MeshRuntimeState) -> Option<String> {
    state
        .snapshot()
        .as_ref()
        .as_ref()
        .map(|slice| slice.version.clone())
}

fn rendered_counter(series: &str) -> u64 {
    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(series))
        .and_then(|rest| rest.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

// ── Full-snapshot boundary ordering ────────────────────────────────────────

#[derive(Clone, Copy)]
struct SequenceAdvance {
    namespace: u64,
    global: u64,
}

struct ScriptedFullLoadSource {
    snapshots: HashMap<String, GatewayConfig>,
    namespace_sequences: Mutex<HashMap<String, u64>>,
    sequence_failures: HashSet<String>,
    global_sequence: AtomicU64,
    advance_on_load: Mutex<HashMap<String, SequenceAdvance>>,
    events: Mutex<Vec<String>>,
}

impl ScriptedFullLoadSource {
    fn new(
        snapshots: HashMap<String, GatewayConfig>,
        namespace_sequences: HashMap<String, u64>,
        global_sequence: u64,
    ) -> Self {
        Self {
            snapshots,
            namespace_sequences: Mutex::new(namespace_sequences),
            sequence_failures: HashSet::new(),
            global_sequence: AtomicU64::new(global_sequence),
            advance_on_load: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
        }
    }

    fn fail_sequence_for(mut self, namespace: &str) -> Self {
        self.sequence_failures.insert(namespace.to_string());
        self
    }

    fn advance_during_load(
        self,
        namespace: &str,
        namespace_sequence: u64,
        global_sequence: u64,
    ) -> Self {
        self.advance_on_load
            .lock()
            .expect("advance script lock")
            .insert(
                namespace.to_string(),
                SequenceAdvance {
                    namespace: namespace_sequence,
                    global: global_sequence,
                },
            );
        self
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events lock").clone()
    }

    fn namespace_sequence(&self, namespace: &str) -> u64 {
        *self
            .namespace_sequences
            .lock()
            .expect("namespace sequences lock")
            .get(namespace)
            .expect("scripted namespace sequence")
    }
}

#[async_trait]
impl CpFullLoadSource for ScriptedFullLoadSource {
    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        assert_eq!(purpose, FullConfigLoadPurpose::ControlPlane);
        self.events
            .lock()
            .expect("events lock")
            .push(format!("load:{namespace}:snapshot"));
        let snapshot = self
            .snapshots
            .get(namespace)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing scripted snapshot for {namespace}"))?;

        // Deterministic race: the resource snapshot has already been selected,
        // then an admin write commits before the full-load future completes.
        // Returning `snapshot` models SQL / replica-set Mongo ending their
        // snapshot transaction while the newer change is already durable.
        if let Some(advance) = self
            .advance_on_load
            .lock()
            .expect("advance script lock")
            .remove(namespace)
        {
            self.namespace_sequences
                .lock()
                .expect("namespace sequences lock")
                .insert(namespace.to_string(), advance.namespace);
            self.global_sequence
                .store(advance.global, Ordering::Release);
            self.events
                .lock()
                .expect("events lock")
                .push(format!("write:{namespace}:{}", advance.namespace));
        }
        self.events
            .lock()
            .expect("events lock")
            .push(format!("load:{namespace}:complete"));
        Ok(snapshot)
    }

    async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error> {
        self.events
            .lock()
            .expect("events lock")
            .push(format!("boundary:{namespace}"));
        if self.sequence_failures.contains(namespace) {
            anyhow::bail!("scripted boundary failure for {namespace}");
        }
        Ok(self.namespace_sequence(namespace))
    }

    async fn latest_global_change_sequence(&self) -> Result<u64, anyhow::Error> {
        self.events
            .lock()
            .expect("events lock")
            .push("boundary:global".to_string());
        Ok(self.global_sequence.load(Ordering::Acquire))
    }
}

fn full_load_consumer_config(namespace: &str, generation: &str, timestamp: i64) -> GatewayConfig {
    GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        consumers: vec![Consumer {
            id: format!("{namespace}-{generation}"),
            username: format!("{namespace}-{generation}"),
            namespace: namespace.to_string(),
            custom_id: None,
            credentials: HashMap::new(),
            acl_groups: Vec::new(),
            created_at: Utc.timestamp_opt(timestamp, 0).single().expect("timestamp"),
            updated_at: Utc.timestamp_opt(timestamp, 0).single().expect("timestamp"),
        }],
        loaded_at: Utc.timestamp_opt(timestamp, 0).single().expect("timestamp"),
        ..GatewayConfig::default()
    }
}

#[tokio::test]
async fn explicit_full_load_captures_cursor_before_snapshot_can_complete() {
    let source = ScriptedFullLoadSource::new(
        HashMap::from([(
            "alpha".to_string(),
            full_load_consumer_config("alpha", "snapshot-41", 41),
        )]),
        HashMap::from([("alpha".to_string(), 41)]),
        41,
    )
    .advance_during_load("alpha", 42, 42);

    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &["alpha".to_string()],
        &GatewayConfig::default(),
        &CpScope::Single("alpha".to_string()),
        Some("db"),
        0,
    )
    .await
    .expect("full load");

    assert_eq!(
        outcome
            .config
            .mesh_revision
            .as_ref()
            .expect("mesh revision")
            .sequence,
        41,
        "the older resource snapshot must not claim the concurrently committed sequence 42"
    );
    assert_eq!(outcome.sequences.get("alpha"), Some(&41));
    assert_eq!(source.namespace_sequence("alpha"), 42);
    assert_eq!(outcome.config.consumers[0].id, "alpha-snapshot-41");
    assert_eq!(
        source.events(),
        vec![
            "boundary:alpha",
            "load:alpha:snapshot",
            "write:alpha:42",
            "load:alpha:complete",
        ],
        "the production orchestration must capture the incremental cursor before loading resources"
    );
}

#[tokio::test]
async fn all_scope_captures_global_watermark_before_any_resource_snapshot() {
    let source = ScriptedFullLoadSource::new(
        HashMap::from([(
            "alpha".to_string(),
            full_load_consumer_config("alpha", "snapshot-90", 90),
        )]),
        HashMap::from([("alpha".to_string(), 40)]),
        90,
    )
    .advance_during_load("alpha", 41, 91);

    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &["alpha".to_string()],
        &GatewayConfig::default(),
        &CpScope::All,
        Some("db"),
        0,
    )
    .await
    .expect("full load");

    assert_eq!(
        outcome
            .config
            .mesh_revision
            .as_ref()
            .expect("mesh revision")
            .sequence,
        90,
        "All scope must publish the pre-load global watermark, not the concurrent write's 91"
    );
    assert_eq!(outcome.sequences.get("alpha"), Some(&40));
    assert_eq!(
        source.events(),
        vec![
            "boundary:global",
            "boundary:alpha",
            "load:alpha:snapshot",
            "write:alpha:41",
            "load:alpha:complete",
        ],
        "the store-global revision boundary must precede every namespace resource load"
    );
}

#[tokio::test]
async fn all_scope_boundary_failure_retains_the_whole_prior_snapshot() {
    let source = ScriptedFullLoadSource::new(
        HashMap::from([
            (
                "alpha".to_string(),
                full_load_consumer_config("alpha", "must-not-load", 20),
            ),
            (
                "beta".to_string(),
                full_load_consumer_config("beta", "must-not-load", 20),
            ),
        ]),
        HashMap::from([("alpha".to_string(), 20), ("beta".to_string(), 30)]),
        30,
    )
    .fail_sequence_for("beta");

    let result = load_full_config_multi_with_sequence_for_test(
        &source,
        &["alpha".to_string(), "beta".to_string()],
        &full_load_consumer_config("alpha", "last-good", 10),
        &CpScope::All,
        Some("db"),
        10,
    )
    .await;

    assert!(
        result.is_err(),
        "All scope must retain its entire prior snapshot when any namespace lacks a safe boundary"
    );
    assert_eq!(
        source.events(),
        vec!["boundary:global", "boundary:alpha", "boundary:beta"],
        "no resource load may begin after an All-scope boundary failure"
    );
}

#[tokio::test]
async fn unsequenced_all_scope_boundary_failure_demotes_only_that_namespace() {
    let previous = full_load_consumer_config("beta", "last-good", 10);
    let source = ScriptedFullLoadSource::new(
        HashMap::from([
            (
                "alpha".to_string(),
                full_load_consumer_config("alpha", "fresh", 20),
            ),
            (
                "beta".to_string(),
                full_load_consumer_config("beta", "must-not-load", 20),
            ),
        ]),
        HashMap::from([("alpha".to_string(), 20), ("beta".to_string(), 30)]),
        30,
    )
    .fail_sequence_for("beta");

    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &["alpha".to_string(), "beta".to_string()],
        &previous,
        &CpScope::All,
        None,
        0,
    )
    .await
    .expect("healthy namespace must continue without a global mesh revision");

    let consumer_ids: HashSet<&str> = outcome
        .config
        .consumers
        .iter()
        .map(|consumer| consumer.id.as_str())
        .collect();
    assert_eq!(
        consumer_ids,
        HashSet::from(["alpha-fresh", "beta-last-good"]),
        "the failed namespace retains LKG while the healthy namespace refreshes"
    );
    assert!(
        outcome.config.mesh_revision.is_none(),
        "an unsequenced authority must not publish a mesh revision"
    );
    assert_eq!(
        outcome.sequences,
        HashMap::from([("alpha".to_string(), 20)]),
        "only the successfully refreshed namespace may advance its cursor"
    );
    assert_eq!(outcome.refreshed_namespaces, vec!["alpha"]);
    assert_eq!(outcome.failed_namespaces, vec!["beta"]);
    assert_eq!(
        source.events(),
        vec![
            "boundary:alpha",
            "boundary:beta",
            "load:alpha:snapshot",
            "load:alpha:complete",
        ],
        "unsequenced All scope must preserve pre-load boundaries and skip the failed tenant load"
    );
}

#[tokio::test]
async fn explicit_scope_boundary_failure_demotes_only_that_namespace() {
    let previous = full_load_consumer_config("beta", "last-good", 10);
    let source = ScriptedFullLoadSource::new(
        HashMap::from([
            (
                "alpha".to_string(),
                full_load_consumer_config("alpha", "fresh", 20),
            ),
            (
                "beta".to_string(),
                full_load_consumer_config("beta", "must-not-load", 20),
            ),
        ]),
        HashMap::from([("alpha".to_string(), 20), ("beta".to_string(), 30)]),
        30,
    )
    .fail_sequence_for("beta");
    let scope = CpScope::Set(HashSet::from(["alpha".to_string(), "beta".to_string()]));

    let outcome = load_full_config_multi_with_sequence_for_test(
        &source,
        &["alpha".to_string(), "beta".to_string()],
        &previous,
        &scope,
        Some("db"),
        0,
    )
    .await
    .expect("healthy namespace must continue");

    let consumer_ids: HashSet<&str> = outcome
        .config
        .consumers
        .iter()
        .map(|consumer| consumer.id.as_str())
        .collect();
    assert_eq!(
        consumer_ids,
        HashSet::from(["alpha-fresh", "beta-last-good"]),
        "the failed namespace retains LKG while the healthy namespace refreshes"
    );
    assert_eq!(
        outcome.sequences,
        HashMap::from([("alpha".to_string(), 20)])
    );
    assert_eq!(outcome.refreshed_namespaces, vec!["alpha"]);
    assert_eq!(outcome.failed_namespaces, vec!["beta"]);
    assert_eq!(
        source.events(),
        vec![
            "boundary:alpha",
            "boundary:beta",
            "load:alpha:snapshot",
            "load:alpha:complete",
        ],
        "a failed namespace boundary must prevent its resource load without aborting alpha"
    );
}

// ── Comparison contract ────────────────────────────────────────────────────

#[test]
fn compare_orders_within_one_authority_and_refuses_across_authorities() {
    let accepted = revision("db", 100);

    assert_eq!(
        MeshConfigRevision::compare(None, Some(&accepted)),
        MeshRevisionOrder::Bootstrap,
        "the first slice installs regardless of revision"
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db", 101))),
        MeshRevisionOrder::Newer
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db", 100))),
        MeshRevisionOrder::Same,
        "a reconnect replays the same revision and must stay installable"
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db", 99))),
        MeshRevisionOrder::Older
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&revision("db-restored", 1_000_000))),
        MeshRevisionOrder::Incomparable,
        "a foreign authority is never ordered by sequence, however large"
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), None),
        MeshRevisionOrder::Unversioned
    );

    assert!(MeshRevisionOrder::Bootstrap.installs());
    assert!(MeshRevisionOrder::Newer.installs());
    assert!(MeshRevisionOrder::Same.installs());
    assert!(!MeshRevisionOrder::Older.installs());
    assert!(!MeshRevisionOrder::Incomparable.installs());
    assert!(!MeshRevisionOrder::Unversioned.installs());
}

/// A blank or over-long authority is ill-formed. `compare` still excludes it
/// from the ordering table (so a poisoned accepted watermark cannot lock the
/// data plane), but that is comparison-only — [`MeshRevisionGate::admit`]
/// refuses a *present* ill-formed candidate before Bootstrap can install it.
#[test]
fn malformed_authorities_are_treated_as_absent() {
    let accepted = revision("db", 100);
    let blank = revision("   ", 500);
    let oversized = revision(&"a".repeat(129), 500);

    assert!(!blank.is_well_formed());
    assert!(!oversized.is_well_formed());
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&blank)),
        MeshRevisionOrder::Unversioned
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&accepted), Some(&oversized)),
        MeshRevisionOrder::Unversioned
    );
    // A malformed ACCEPTED revision cannot lock the data plane out either.
    assert_eq!(
        MeshConfigRevision::compare(Some(&blank), Some(&accepted)),
        MeshRevisionOrder::Bootstrap
    );
}

/// A present but ill-formed revision must never bootstrap: `compare` would
/// classify it as Bootstrap against an empty watermark, but `admit` refuses
/// with `malformed_revision` and installs nothing. A genuinely absent revision
/// still bootstraps (unsequenced authorities).
#[test]
fn admit_refuses_present_malformed_revision_even_on_bootstrap() {
    let gate = MeshRevisionGate::new();
    let now = Utc::now();

    assert_eq!(
        gate.admit(None, cid(1), now),
        Ok(MeshRevisionOrder::Bootstrap),
        "a genuinely absent revision still bootstraps"
    );
    assert!(gate.accepted().is_none());

    for (label, forged) in [
        ("blank", revision("   ", 1)),
        ("overlong", revision(&"a".repeat(129), 1)),
        (
            "control-character",
            revision("db\n2026-07-26 WARN forged", 1),
        ),
    ] {
        let rejection = gate.admit(Some(&forged), cid(1), now).unwrap_err();
        assert_eq!(
            rejection.reason(),
            MeshRevisionRejectReason::MalformedRevision,
            "{label} must be refused as malformed_revision, not bootstrapped"
        );
        assert!(
            gate.accepted().is_none(),
            "{label}: a refused malformed candidate must leave no watermark"
        );
    }
}

#[test]
fn maximum_sequence_orders_without_wrapping() {
    let gate = MeshRevisionGate::new();
    let now = Utc::now();

    gate.admit(Some(&revision("db", u64::MAX - 1)), cid(1), now)
        .expect("the penultimate sequence establishes the baseline");
    assert_eq!(
        gate.admit(Some(&revision("db", u64::MAX)), cid(2), now),
        Ok(MeshRevisionOrder::Newer)
    );
    assert_eq!(
        gate.admit(Some(&revision("db", u64::MAX)), cid(2), now),
        Ok(MeshRevisionOrder::Same),
        "a replay at the maximum sequence remains installable"
    );
    assert_eq!(
        gate.admit(Some(&revision("db", u64::MAX - 1)), cid(1), now)
            .expect_err("the maximum sequence must not wrap to a lower value")
            .reason(),
        MeshRevisionRejectReason::StaleRevision
    );
}

// ── Gate state machine ─────────────────────────────────────────────────────

#[test]
fn gate_quarantines_stale_and_keeps_accepting_forward_progress() {
    let gate = MeshRevisionGate::new();
    let now = Utc
        .with_ymd_and_hms(2026, 7, 26, 12, 0, 0)
        .single()
        .expect("fixture time");

    gate.admit(Some(&revision("db", 100)), cid(1), now)
        .expect("bootstrap installs");

    let rejection = gate
        .admit(Some(&revision("db", 99)), cid(2), now)
        .expect_err("an older revision is quarantined");
    assert_eq!(rejection.reason(), MeshRevisionRejectReason::StaleRevision);
    assert!(
        rejection.terminates_stream(),
        "a lagging CP's whole view is behind; the stream must fail over"
    );
    assert_eq!(
        gate.accepted().map(|revision| revision.sequence),
        Some(100),
        "a quarantine must not move the accepted revision"
    );

    // Repeated quarantines of the same pair accumulate, and the diagnostics
    // never echo raw slice content.
    gate.admit(Some(&revision("db", 98)), cid(3), now)
        .expect_err("still stale");
    let diagnostics = gate.diagnostics();
    assert!(diagnostics.quarantine_active);
    assert_eq!(diagnostics.rejected_total, 2);
    let quarantined = diagnostics.quarantined.expect("quarantine recorded");
    assert_eq!(quarantined.reason, "stale_revision");

    // Failback: the primary catches up and installs, clearing the quarantine.
    gate.admit(Some(&revision("db", 101)), cid(4), now)
        .expect("a newer revision installs");
    assert_eq!(gate.accepted().map(|r| r.sequence), Some(101));
    let diagnostics = gate.diagnostics();
    assert!(!diagnostics.quarantine_active);
    assert!(diagnostics.quarantined.is_none());
    assert_eq!(
        diagnostics.rejected_total, 2,
        "the total is cumulative; only the active quarantine clears"
    );
}

/// A foreign authority is quarantined until it has been observed continuously
/// for the configured grace period, then adopted. This is the no-permanent-
/// lockout path for control-plane state loss and deliberate source resets.
#[test]
fn gate_adopts_a_persistent_foreign_authority_after_the_grace_period() {
    let monotonic_t0 = std::time::Instant::now();
    let gate = MeshRevisionGate::new();
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 300,
    });
    let t0 = Utc
        .with_ymd_and_hms(2026, 7, 26, 12, 0, 0)
        .single()
        .expect("fixture time");

    gate.admit(Some(&revision("db", 100)), cid(1), t0)
        .expect("bootstrap installs");

    let rejection = gate
        .admit_at(Some(&revision("db-restored", 1)), cid(2), t0, monotonic_t0)
        .expect_err("a foreign authority is quarantined on first sight");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::IncomparableAuthority
    );

    // Still inside the grace window.
    gate.admit_at(
        Some(&revision("db-restored", 2)),
        cid(2),
        t0 + chrono::Duration::days(30),
        monotonic_t0 + std::time::Duration::from_secs(299),
    )
    .expect_err("a forward wall-clock jump cannot expire the monotonic grace window");
    assert_eq!(gate.accepted().map(|r| r.authority), Some("db".to_string()));

    // A DIFFERENT foreign authority restarts the observation window, so a
    // flapping set of foreign CPs cannot accumulate grace.
    gate.admit_at(
        Some(&revision("db-other", 7)),
        cid(3),
        t0 + chrono::Duration::seconds(300),
        monotonic_t0 + std::time::Duration::from_secs(300),
    )
    .expect_err("a different foreign authority restarts the window");
    gate.admit_at(
        Some(&revision("db-restored", 3)),
        cid(2),
        t0 + chrono::Duration::seconds(301),
        monotonic_t0 + std::time::Duration::from_secs(301),
    )
    .expect_err("the original foreign authority also restarts its window");

    let order = gate
        .admit_at(
            Some(&revision("db-restored", 4)),
            cid(2),
            t0 + chrono::Duration::seconds(601),
            monotonic_t0 + std::time::Duration::from_secs(601),
        )
        .expect("a continuously observed foreign authority is adopted");
    assert_eq!(order, MeshRevisionOrder::Incomparable);
    assert_eq!(
        gate.accepted(),
        Some(revision("db-restored", 4)),
        "adoption restarts ordering from the adopted revision"
    );
    assert_eq!(gate.diagnostics().adopted_total, 1);
}

#[test]
fn adoption_can_be_disabled_and_reset_is_the_operator_escape_hatch() {
    let gate = MeshRevisionGate::new();
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 0,
    });
    let t0 = Utc
        .with_ymd_and_hms(2026, 7, 26, 12, 0, 0)
        .single()
        .expect("fixture time");

    gate.admit(Some(&revision("db", 100)), cid(1), t0)
        .expect("bootstrap installs");
    gate.admit(
        Some(&revision("db-restored", 1)),
        cid(2),
        t0 + chrono::Duration::days(30),
    )
    .expect_err("adoption disabled: a foreign authority stays quarantined forever");

    // A sequence rewind INSIDE one authority is never auto-adopted, however
    // long it persists — it is indistinguishable from the rollback the gate
    // exists to prevent.
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 1,
    });
    gate.admit(
        Some(&revision("db", 5)),
        cid(3),
        t0 + chrono::Duration::days(60),
    )
    .expect_err("a same-authority rewind is never auto-adopted");

    // The operator reset clears the accepted revision, and the next slice from
    // any authority establishes a new baseline.
    let cleared = gate.reset().expect("the accepted revision is returned");
    assert_eq!(cleared, revision("db", 100));
    assert!(gate.diagnostics().quarantined.is_none());
    gate.admit(
        Some(&revision("db", 5)),
        cid(3),
        t0 + chrono::Duration::days(61),
    )
    .expect("after a reset the rewound revision installs");
    assert_eq!(gate.accepted(), Some(revision("db", 5)));
}

// ── Runtime install seam ───────────────────────────────────────────────────

#[test]
fn install_slice_quarantines_a_stale_slice_without_touching_live_state() {
    let state = MeshRuntimeState::new();

    assert_eq!(
        state.install_slice(slice_at("v-100", Some(revision("db", 100)))),
        MeshSliceInstall::Installed
    );
    let installed_at = state.last_install_at().expect("first install stamps");

    let outcome = state.install_slice(slice_at("v-99", Some(revision("db", 99))));
    let rejection = outcome
        .rejection()
        .expect("an older revision must be quarantined");
    assert_eq!(rejection.reason(), MeshRevisionRejectReason::StaleRevision);

    assert_eq!(installed_version(&state).as_deref(), Some("v-100"));
    assert_eq!(
        state.last_install_at(),
        Some(installed_at),
        "a quarantined slice must not advance the receive timestamp"
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 100)));
    assert!(state.revision_diagnostics().quarantine_active);
}

#[test]
fn xds_consumer_surfaces_stale_revision_as_stream_terminal() {
    let state = MeshRuntimeState::new();
    let consumer = XdsConfigConsumer::new(
        XdsClientConfig {
            cp_urls: vec![
                "http://cp-a:50051".to_string(),
                "http://cp-b:50051".to_string(),
            ],
            node_id: NODE_ID.to_string(),
            cluster: "default".to_string(),
            namespace: NAMESPACE.to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
            stream_channel_capacity: 32,
            primary_retry_secs: 300,
            connect_timeout_seconds: 10,
            labels: BTreeMap::new(),
        },
        state.clone(),
    );

    consumer
        .apply_slice(slice_at("xds-v100", Some(revision("db", 100))))
        .expect("the fresh xDS baseline installs");
    let rejection = consumer
        .apply_slice(slice_at("xds-v99", Some(revision("db", 99))))
        .expect_err("a stale xDS slice must close ADS for multi-CP failover");

    assert_eq!(rejection.reason(), MeshRevisionRejectReason::StaleRevision);
    assert!(rejection.terminates_stream());
    assert_eq!(installed_version(&state).as_deref(), Some("xds-v100"));
}

/// Unversioned sources (Kubernetes CRD controller, file source) keep working:
/// with no accepted revision the gate is inert. But once a REVISIONED slice is
/// accepted, an unrevisioned one can no longer displace it — otherwise a stale
/// or hostile control plane could downgrade simply by dropping the field.
#[test]
fn unversioned_slices_are_inert_until_a_revision_is_accepted() {
    let state = MeshRuntimeState::new();

    assert!(state.install_slice(slice_at("v1", None)).installed());
    assert!(state.install_slice(slice_at("v2", None)).installed());
    assert!(state.accepted_revision().is_none());

    assert!(
        state
            .install_slice(slice_at("v3", Some(revision("db", 10))))
            .installed()
    );
    let outcome = state.install_slice(slice_at("v4", None));
    assert_eq!(
        outcome
            .rejection()
            .expect("an unrevisioned slice cannot displace a revisioned one")
            .reason(),
        MeshRevisionRejectReason::MissingRevision
    );
    assert_eq!(installed_version(&state).as_deref(), Some("v3"));
}

#[test]
fn revision_rejections_increment_a_bounded_reason_labelled_metric() {
    let series = "ferrum_mesh_config_revision_rejections_total{reason=\"stale_revision\"}";
    let before = rendered_counter(series);

    let state = MeshRuntimeState::new();
    state.install_slice(slice_at("v-100", Some(revision("db", 100))));
    state.install_slice(slice_at("v-99", Some(revision("db", 99))));

    let after = rendered_counter(series);
    assert!(
        after > before,
        "the quarantine must increment {series} (before={before}, after={after})"
    );

    // The CP-supplied authority/sequence must never reach /metrics.
    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);
    for line in rendered
        .lines()
        .filter(|line| line.starts_with("ferrum_mesh_config_revision_"))
    {
        assert!(
            !line.contains("authority=\"db\"") && !line.contains("sequence="),
            "revision metrics must carry no control-plane-supplied value: {line}"
        );
    }
}

// ── Multi-CP failover matrix (consumer seam) ───────────────────────────────

/// Simulate a data plane whose stream rotates between control planes: each
/// control plane's stream builds its own consumer over the SAME runtime state.
///
/// Covers the acceptance criteria matrix in one place so the relationship
/// between the cases stays visible: primary N → fallback N-1 / N / N+1, a CP
/// whose wall clock and restart make `version` useless, an intentional rollback
/// published as N+1, and failback after a stale fallback was quarantined.
#[test]
fn multi_cp_failover_never_moves_the_data_plane_backwards() {
    let state = MeshRuntimeState::new();
    let primary = consumer_for(state.clone());
    let fallback = consumer_for(state.clone());

    // Primary publishes N.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-2026-07-26T12:00:00Z",
            Some(revision("db", 100)),
        )))
        .expect("the first slice installs");
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-2026-07-26T12:00:00Z")
    );

    // Fallback at N-1: quarantined. Note its `version` renders a LATER wall
    // clock than the primary's — a timestamp comparison would have accepted
    // this rollback.
    let stale = slice_at("cp-b-2026-07-26T13:00:00Z", Some(revision("db", 99)));
    let error = fallback
        .apply_update(&update_for(&stale))
        .expect_err("a lagging fallback must not roll the data plane back");
    assert_eq!(
        error.reason_label(),
        MeshRevisionRejectReason::StaleRevision.as_metric_label()
    );
    assert!(
        error.terminates_stream(),
        "the data plane drops the stale CP's stream and keeps failing over"
    );
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-2026-07-26T12:00:00Z"),
        "the last-good slice keeps serving"
    );

    // Fallback at N: the same generation, rendered by a different CP with a
    // different clock. Installs (it is not a rollback) and does not flap.
    fallback
        .apply_update(&update_for(&slice_at(
            "cp-b-2026-07-26T11:59:00Z",
            Some(revision("db", 100)),
        )))
        .expect("an equal revision from another replica installs");
    assert_eq!(state.accepted_revision(), Some(revision("db", 100)));

    // Fallback at N+1: forward progress from the fallback is accepted.
    fallback
        .apply_update(&update_for(&slice_at(
            "cp-b-2026-07-26T11:59:30Z",
            Some(revision("db", 101)),
        )))
        .expect("a newer revision from the fallback installs");
    assert_eq!(state.accepted_revision(), Some(revision("db", 101)));

    // CP restart / clock skew: the primary comes back with a wall clock BEHIND
    // the fallback's and a version string that sorts earlier, but a higher
    // durable sequence. Ordering follows the sequence, so it installs.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-2026-07-26T09:00:00Z",
            Some(revision("db", 102)),
        )))
        .expect("a restarted CP with a skewed clock still orders by sequence");
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-2026-07-26T09:00:00Z")
    );

    // Intentional operator rollback: the old content is republished as a WRITE,
    // so it arrives at a HIGHER sequence and installs.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-rollback-to-2026-07-20",
            Some(revision("db", 103)),
        )))
        .expect("an intentional rollback is a higher revision and installs");
    assert_eq!(
        installed_version(&state).as_deref(),
        Some("cp-a-rollback-to-2026-07-20")
    );

    // Failback after the stale fallback was quarantined: the primary is
    // authoritative again and forward progress resumes with no reset needed.
    primary
        .apply_update(&update_for(&slice_at(
            "cp-a-after-failback",
            Some(revision("db", 104)),
        )))
        .expect("failback resumes forward progress");
    assert_eq!(state.accepted_revision(), Some(revision("db", 104)));
    assert!(
        !state.revision_diagnostics().quarantine_active,
        "an accepted slice clears the active quarantine"
    );
}

/// The envelope carries a duplicate of the slice's own revision; a frame whose
/// two copies disagree is internally inconsistent and refused before install.
#[test]
fn envelope_revision_must_match_the_slice_revision() {
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    let expected = MeshUpdateExpectation::from_subscribe_request(&request);
    let slice = slice_at("v1", Some(revision("db", 100)));

    validate_mesh_config_update(&update_for(&slice), &expected, MeshUpdateConsumer::Native)
        .expect("a faithful envelope is accepted");

    let forged_sequence = MeshConfigUpdate {
        config_sequence: 1_000,
        ..update_for(&slice)
    };
    let rejection =
        validate_mesh_config_update(&forged_sequence, &expected, MeshUpdateConsumer::Native)
            .expect_err("an envelope claiming a different sequence is refused");
    assert_eq!(
        rejection.reason(),
        MeshUpdateRejectReason::EnvelopeRevisionMismatch
    );

    let dropped_authority = MeshConfigUpdate {
        config_authority: String::new(),
        config_sequence: 0,
        ..update_for(&slice)
    };
    assert_eq!(
        validate_mesh_config_update(&dropped_authority, &expected, MeshUpdateConsumer::Native)
            .expect_err("dropping the envelope revision is a mismatch, not an exemption")
            .reason(),
        MeshUpdateRejectReason::EnvelopeRevisionMismatch
    );

    // An unrevisioned source is consistent when BOTH copies are absent.
    let unversioned = slice_at("v1", None);
    validate_mesh_config_update(
        &update_for(&unversioned),
        &expected,
        MeshUpdateConsumer::Native,
    )
    .expect("both copies absent is consistent");

    let sequence_without_authority = MeshConfigUpdate {
        config_sequence: 42,
        ..update_for(&unversioned)
    };
    assert_eq!(
        validate_mesh_config_update(
            &sequence_without_authority,
            &expected,
            MeshUpdateConsumer::Native,
        )
        .expect_err("a sequence without its ordering domain is malformed")
        .reason(),
        MeshUpdateRejectReason::EnvelopeRevisionMismatch
    );
}

/// Hostile smuggling shape: empty envelope revision + present but ill-formed
/// embedded slice revision. Filtering the embedded revision to "absent" would
/// make both sides look consistently unversioned, pass validation, and then
/// bootstrap through the freshness gate with no watermark. Both native and
/// remote-discovery consumers must refuse before install/import; `install_slice`
/// must also refuse if the frame somehow reaches the shared gate (xDS).
#[test]
fn malformed_embedded_revision_cannot_smuggle_past_validation_or_bootstrap() {
    let _overlay_guard = overlay_consumer_guard();
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    let expected = MeshUpdateExpectation::from_subscribe_request(&request);

    let cases = [
        ("blank", revision("   ", 7)),
        ("surrounding-whitespace", revision(" db", 7)),
        ("overlong", revision(&"a".repeat(129), 7)),
        (
            "control-character",
            revision("db\n2026-07-26 WARN forged-by-the-control-plane", 7),
        ),
    ];

    for (label, forged) in cases {
        let slice = slice_at(&format!("v-{label}"), Some(forged));
        // Empty envelope stamps — the smuggling shape from the root finding —
        // while the embedded JSON still carries the ill-formed revision.
        let smuggled = MeshConfigUpdate {
            config_authority: String::new(),
            config_sequence: 0,
            mesh_slice_json: serde_json::to_string(&slice).expect("slice serializes"),
            ..update_for(&slice_at(&format!("v-{label}"), None))
        };

        for consumer in [
            MeshUpdateConsumer::Native,
            MeshUpdateConsumer::RemoteDiscovery,
        ] {
            let rejection = validate_mesh_config_update(&smuggled, &expected, consumer)
                .expect_err("present but ill-formed embedded revision must be refused");
            assert_eq!(
                rejection.reason(),
                MeshUpdateRejectReason::MalformedRevision,
                "{label}/{}: dedicated malformed_revision reason",
                consumer.as_metric_label()
            );
            assert!(
                rejection.terminates_stream(),
                "{label}/{}: a malformed ordering domain must force CP failover",
                consumer.as_metric_label()
            );
            assert!(
                !rejection.detail().contains('\n'),
                "{label}: diagnostics must not echo raw hostile authority text"
            );
            assert!(
                !rejection.detail().contains("forged-by-the-control-plane"),
                "{label}: diagnostics must not echo raw hostile authority text"
            );
        }

        // Shared gate (xDS / any installer that bypasses update validation).
        let state = MeshRuntimeState::new();
        let outcome = state.install_slice(slice);
        assert!(
            !outcome.installed(),
            "{label}: install_slice must quarantine, not bootstrap"
        );
        assert_eq!(
            outcome.rejection().expect("quarantine recorded").reason(),
            MeshRevisionRejectReason::MalformedRevision
        );
        assert!(
            state.snapshot().as_ref().is_none(),
            "{label}: no slice may become live"
        );
        assert!(
            state.accepted_revision().is_none(),
            "{label}: no watermark may be retained"
        );
    }

    // Genuinely absent revisions remain valid for unsequenced authorities.
    let unversioned = slice_at("v-unversioned", None);
    validate_mesh_config_update(
        &update_for(&unversioned),
        &expected,
        MeshUpdateConsumer::Native,
    )
    .expect("both copies absent is still consistent");
    let state = MeshRuntimeState::new();
    assert!(
        state.install_slice(unversioned).installed(),
        "a genuinely absent revision still bootstraps"
    );
}

/// Raw non-empty whitespace-only envelope authority is *present but ill-formed*,
/// not proto-absent. Filtering on `.trim().is_empty()` would silently treat
/// `config_authority="   "` + `config_sequence=0` with an absent embedded
/// revision as consistently unversioned and let it pass.
#[test]
fn whitespace_only_envelope_authority_is_malformed_not_absent() {
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    let expected = MeshUpdateExpectation::from_subscribe_request(&request);
    let unversioned = slice_at("v-blank-envelope", None);

    let whitespace_envelope = MeshConfigUpdate {
        config_authority: "   ".to_string(),
        config_sequence: 0,
        ..update_for(&unversioned)
    };

    for consumer in [
        MeshUpdateConsumer::Native,
        MeshUpdateConsumer::RemoteDiscovery,
    ] {
        let rejection = validate_mesh_config_update(&whitespace_envelope, &expected, consumer)
            .expect_err("whitespace-only envelope authority must be refused");
        assert_eq!(
            rejection.reason(),
            MeshUpdateRejectReason::MalformedRevision,
            "{}: dedicated malformed_revision reason",
            consumer.as_metric_label()
        );
        assert!(
            rejection.terminates_stream(),
            "{}: a whitespace-only ordering domain must force CP failover",
            consumer.as_metric_label()
        );
        // Static diagnostic only — do not echo the raw authority bytes.
        assert!(
            !rejection.detail().contains("   "),
            "{}: diagnostics must not echo the blank authority text",
            consumer.as_metric_label()
        );
        assert!(
            rejection.detail().contains("ill-formed"),
            "{}: diagnostic should name the ill-formed envelope class",
            consumer.as_metric_label()
        );
    }

    // Contrast: genuinely empty envelope + absent slice remains valid.
    validate_mesh_config_update(
        &update_for(&unversioned),
        &expected,
        MeshUpdateConsumer::Native,
    )
    .expect("raw-empty envelope with absent slice remains unrevisioned");
}

/// Full-load revision stamping is scope-domained (issue #2473 / #4130):
/// - Explicit Single/Set: saturating sum of scoped namespace cursors (same
///   domain incremental polling advances). An unrelated namespace's global
///   sequence must not make a restarted replica jump ahead of its identical
///   running peer. Sum (not max) stays strictly monotonic when any scoped
///   namespace advances under per-namespace sequence locks.
/// - All: store-wide sum of per-namespace high-water marks so a deleted
///   namespace cannot rewind a restarted CP. In-process floor is preserved
///   for both.
#[test]
fn explicit_scope_full_load_sequence_ignores_unrelated_global_high_water() {
    use ferrum_edge::grpc::cp_server::CpScope;
    use std::collections::HashSet;

    let mut scoped = HashMap::new();
    scoped.insert("alpha".to_string(), 10);
    // Store-global advanced by an unrelated namespace the explicit scope never
    // polls. Running Single/Set CP stays at 10 (no delta); restarted peer must
    // also stamp 10, not 50.
    let store_global = 50;

    assert_eq!(
        CpScope::Single("alpha".to_string()).mesh_full_load_sequence(&scoped, store_global, 0),
        10,
        "Single-scope restart must not jump to an unrelated global sequence"
    );

    let set = CpScope::Set(HashSet::from(["alpha".to_string(), "beta".to_string()]));
    let mut set_scoped = scoped.clone();
    set_scoped.insert("beta".to_string(), 12);
    assert_eq!(
        set.mesh_full_load_sequence(&set_scoped, store_global, 0),
        22,
        "Set-scope full load uses the sum of explicit namespace cursors only"
    );

    // All-scope retains the store-global watermark when discovery shrinks.
    let mut remaining = HashMap::new();
    remaining.insert("alpha".to_string(), 10);
    assert_eq!(
        CpScope::All.mesh_full_load_sequence(&remaining, store_global, 0),
        50,
        "All-scope restart must keep store-global monotonicity after namespace loss"
    );

    // In-process floor protects full reload for both domains.
    assert_eq!(
        CpScope::Single("alpha".to_string()).mesh_full_load_sequence(&scoped, store_global, 20),
        20
    );
    assert_eq!(CpScope::All.mesh_full_load_sequence(&remaining, 15, 40), 40);
}

/// `content_eq` ignores revision (ordering metadata). Existing MeshSubscribe
/// subscribers must not receive a revision-only frame when content is unchanged —
/// the CP dedupe path relies on this so scoped sequence convergence does not
/// imply hot-path broadcast spam.
#[test]
fn content_eq_ignores_revision_so_unchanged_frames_stay_suppressed() {
    let mut left = slice_at("v-content", Some(revision("db", 10)));
    let mut right = left.clone();
    right.revision = Some(revision("db", 50));
    right.version = "different-wall-clock".to_string();

    assert!(
        left.content_eq(&right),
        "revision/version-only differences must not count as content changes"
    );

    left.labels_ambiguous = true;
    assert!(
        !left.content_eq(&right),
        "real content changes must still be detected"
    );
}

// ── Live two-CP MeshSubscribe stream ───────────────────────────────────────

/// An in-process control plane that replays a fixed script of frames and then
/// holds the stream open.
#[derive(Clone)]
struct ScriptedMeshCp {
    updates: Arc<Vec<MeshConfigUpdate>>,
    subscribe_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl MeshConfigSync for ScriptedMeshCp {
    type MeshSubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

    async fn mesh_subscribe(
        &self,
        _request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        self.subscribe_count.fetch_add(1, Ordering::Relaxed);
        let items: Vec<Result<MeshConfigUpdate, Status>> =
            self.updates.iter().cloned().map(Ok).collect();
        let scripted = tokio_stream::iter(items);
        let held_open = tokio_stream::pending::<Result<MeshConfigUpdate, Status>>();
        let stream: Self::MeshSubscribeStream = Box::pin(scripted.chain(held_open));
        Ok(Response::new(stream))
    }

    async fn report_mesh_slice_status(
        &self,
        _request: Request<ferrum_edge::grpc::proto::MeshSliceStatusReport>,
    ) -> Result<Response<ferrum_edge::grpc::proto::MeshSliceStatusResponse>, Status> {
        Ok(Response::new(
            ferrum_edge::grpc::proto::MeshSliceStatusResponse {},
        ))
    }
}

struct CpHandle {
    url: String,
    subscribe_count: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl CpHandle {
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
    }
}

async fn start_cp(updates: Vec<MeshConfigUpdate>) -> CpHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub CP");
    let addr = listener.local_addr().expect("stub CP addr");
    let subscribe_count = Arc::new(AtomicUsize::new(0));
    let cp = ScriptedMeshCp {
        updates: Arc::new(updates),
        subscribe_count: subscribe_count.clone(),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let incoming = TcpListenerStream::new(listener);
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(MeshConfigSyncServer::new(cp))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    CpHandle {
        url: format!("http://{addr}"),
        subscribe_count,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

/// Live multi-CP failover: the primary control plane is serving an OLDER
/// authoritative revision than the one this data plane already accepted. It
/// must be quarantined (never installed), the stream torn down, and the client
/// must rotate to the fresher fallback and converge there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_stale_primary_is_quarantined_and_the_client_converges_on_the_fresh_fallback() {
    let stale = slice_at("cp-stale", Some(revision("db", 99)));
    let fresh = slice_at("cp-fresh", Some(revision("db", 101)));
    let stale_cp = start_cp(vec![update_for(&stale)]).await;
    let fresh_cp = start_cp(vec![update_for(&fresh)]).await;

    // Seed the accepted revision the way a previously accepted update would.
    let state = MeshRuntimeState::new();
    assert!(
        state
            .install_slice(slice_at("last-good", Some(revision("db", 100))))
            .installed()
    );

    let (shutdown_tx, handle) = {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(start_native_mesh_client_with_shutdown(
            vec![stale_cp.url.clone(), fresh_cp.url.clone()],
            GrpcJwtSecret::new(JWT_SECRET.to_string()),
            client_config(),
            state.clone(),
            shutdown_rx,
            None,
            None,
        ));
        (shutdown_tx, handle)
    };

    // The client backs off ~1s (±25%) between control planes, so allow a few
    // seconds for the rotation without pinning an exact schedule.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if installed_version(&state).as_deref() == Some("cp-fresh") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the client must converge on the fresher fallback; installed={:?}",
            installed_version(&state)
        );
        assert_ne!(
            installed_version(&state).as_deref(),
            Some("cp-stale"),
            "the stale slice must never become live"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(state.accepted_revision(), Some(revision("db", 101)));
    assert!(
        stale_cp.subscribe_count.load(Ordering::Relaxed) >= 1,
        "the client must actually have subscribed to the stale CP"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
    stale_cp.shutdown().await;
    fresh_cp.shutdown().await;
}

// ── Candidate lifecycle: received → applied, or rolled back ────────────────
//
// Passing the freshness gate only makes a slice the RECEIVED candidate. The
// mesh proxy runtime is a second, independent gate: slice→config preparation
// or `ProxyState::update_config` can still refuse it, leaving the previous
// generation serving. These tests drive the runtime seam
// (`install_slice` → `record_applied_slice_with_token` / `record_rejected_slice`) that the
// mesh apply loop uses, rather than `MeshRevisionGate::admit` in isolation,
// because the defect they cover lives in the relationship between the two
// gates and not in the comparison contract.

/// `record_applied_slice_with_token` fans the accepted slice's (here empty) runtime
/// overlay out to process-global RTDS consumers, so every lifecycle test below
/// serialises against `mesh_runtime_overlay_consumers_tests` through the
/// documented process-wide guard. Integration tests share one process per
/// shard, and an empty overlay still REPLACES those consumers' state.
fn overlay_consumer_guard() -> std::sync::MutexGuard<'static, ()> {
    ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock()
}

/// A candidate the proxy runtime refuses must not keep the authoritative
/// watermark. Otherwise a hostile or buggy control plane publishes ONE
/// runtime-invalid slice at a far-future sequence and permanently quarantines
/// every valid revision beneath it — with a slice that never served a request.
#[test]
fn a_runtime_rejected_candidate_rolls_the_watermark_back_and_reopens_recovery() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();

    // The proxy is serving revision N.
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    let token = state.begin_revision_apply(&applied);
    state.record_applied_slice_with_token(&applied, token);
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // N+10 passes wire binding and freshness admission and becomes the
    // received candidate...
    assert!(
        state
            .install_slice(slice_at("v-20", Some(revision("db", 20))))
            .installed()
    );
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 20)),
        "admission is provisional but still advances the received watermark"
    );

    // ...and the proxy runtime then refuses it (preparation error, or
    // `update_config` rejecting the candidate config). The proxy keeps N.
    assert!(
        state.record_rejected_slice(&state.snapshot()),
        "the refused candidate owns the watermark, so it must roll back"
    );
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 10)),
        "the watermark returns to the last PROXY-APPLIED revision"
    );
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // Every revision the poisoned watermark would have locked out is eligible
    // again, so a control plane can still recover the data plane.
    let recovery = slice_at("v-11", Some(revision("db", 11)));
    assert!(state.install_slice(recovery.clone()).installed());
    let token = state.begin_revision_apply(&recovery);
    state.record_applied_slice_with_token(&recovery, token);
    assert_eq!(installed_version(&state).as_deref(), Some("v-11"));
    assert_eq!(state.applied_revision(), Some(revision("db", 11)));

    // The rollback is not a general relaxation: genuinely stale revisions are
    // still quarantined against the restored watermark.
    assert_eq!(
        state
            .install_slice(slice_at("v-9", Some(revision("db", 9))))
            .rejection()
            .expect("an older revision stays quarantined after a rollback")
            .reason(),
        MeshRevisionRejectReason::StaleRevision
    );
}

/// A rejection that lands after a NEWER candidate has already been received
/// must not roll that newer candidate's watermark back — the apply task and the
/// config consumer run concurrently, so this ordering is ordinary, not
/// exceptional.
#[test]
fn a_late_rejection_cannot_roll_back_a_newer_candidate() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    let token = state.begin_revision_apply(&applied);
    state.record_applied_slice_with_token(&applied, token);

    // The apply task picks up N+10 and starts preparing it.
    assert!(
        state
            .install_slice(slice_at("v-20", Some(revision("db", 20))))
            .installed()
    );
    let mid_apply = state.snapshot();

    // N+11 arrives while N+10 is still mid-apply and supersedes it.
    assert!(
        state
            .install_slice(slice_at("v-21", Some(revision("db", 21))))
            .installed()
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 21)));

    assert!(
        !state.record_rejected_slice(&mid_apply),
        "a superseded candidate must not finalize the watermark"
    );
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 21)),
        "the newer candidate keeps the watermark it legitimately advanced"
    );
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // The newer candidate still finalizes normally when the runtime rules on it.
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));
}

/// A candidate refused before ANYTHING has been applied must return the gate to
/// no baseline, not pin it to a revision the proxy never served — otherwise a
/// single bad first slice poisons startup and every subsequent fallback.
#[test]
fn a_runtime_rejected_bootstrap_candidate_returns_to_no_baseline() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();

    assert!(
        state
            .install_slice(slice_at("v-9000", Some(revision("db", 9000))))
            .installed()
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 9000)));

    assert!(state.record_rejected_slice(&state.snapshot()));
    assert!(
        state.accepted_revision().is_none(),
        "nothing was ever applied, so there is no baseline to hold"
    );
    assert!(state.applied_revision().is_none());
    assert!(state.revision_diagnostics().accepted.is_none());

    // Bootstrap is open again — including from a lower sequence and from a
    // different ordering domain.
    let recovery = slice_at("v-1", Some(revision("db", 1)));
    assert!(state.install_slice(recovery.clone()).installed());
    let token = state.begin_revision_apply(&recovery);
    state.record_applied_slice_with_token(&recovery, token);
    assert_eq!(state.applied_revision(), Some(revision("db", 1)));
}

/// The commit half has to remember equal-revision replays too: a reconnect
/// replays the CP's initial slice at the unchanged revision and the runtime
/// accepts it with no config delta. If that did not commit, a later rollback
/// would drop to a stale baseline (or to none at all).
#[test]
fn an_equal_revision_replay_commits_the_applied_watermark() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let first = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(first.clone()).installed());
    let token = state.begin_revision_apply(&first);
    state.record_applied_slice_with_token(&first, token);

    let replay = slice_at("v-10-replay", Some(revision("db", 10)));
    assert!(
        state.install_slice(replay.clone()).installed(),
        "an equal revision MUST install — every ordinary reconnect replays one"
    );
    let token = state.begin_revision_apply(&replay);
    state.record_applied_slice_with_token(&replay, token);
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));

    // A later runtime rejection rolls back to the replayed generation.
    assert!(
        state
            .install_slice(slice_at("v-50", Some(revision("db", 50))))
            .installed()
    );
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));
}

// ── Startup: the initial-config wait is a runtime gate too (issue #4041) ────
//
// The localized `file` source converts BEFORE `install_slice`, so an invalid
// document refuses startup outright. Every control-plane-driven source —
// native `MeshSubscribe`, xDS ADS, and the stock-xDS discovery half — installs
// FIRST and converts inside `wait_for_initial_mesh_config`. That conversion is
// the runtime gate for the first slice, so it owes the watermark the same
// rollback the steady-state apply task performs: a candidate refused there
// never served a request, and pinning the accepted revision to it quarantines
// every corrected slice at or below its sequence.

/// A slice the probe node would materialize, carrying an authoritative
/// change-log revision at `sequence`.
fn startup_slice(version: &str, sequence: u64) -> MeshSlice {
    MeshSlice {
        node_id: PROBE_NODE_ID.to_string(),
        namespace: PROBE_NAMESPACE.to_string(),
        version: version.to_string(),
        revision: Some(revision("db", sequence)),
        ..MeshSlice::default()
    }
}

/// A candidate that passes the freshness gate and then fails CONVERSION.
///
/// A blank `MeshService.name` is refused by `MeshConfig::validate` for every
/// namespace, so the failure is a property of the slice rather than of the
/// probe node's namespace — and it is reached inside the startup wait, after
/// `install_slice` has already admitted the revision.
fn conversion_invalid_startup_slice(version: &str, sequence: u64) -> MeshSlice {
    MeshSlice {
        services: vec![MeshService {
            name: String::new(),
            namespace: PROBE_NAMESPACE.to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
            uid: None,
        }],
        ..startup_slice(version, sequence)
    }
}

/// Wait, bounded, for the startup wait to finalize its refusal of the received
/// candidate. Bounded rather than open-ended so the pre-fix behaviour fails an
/// assertion instead of hanging the shard.
async fn await_accepted_revision_cleared(state: &MeshRuntimeState) -> bool {
    for _ in 0..200 {
        if state.accepted_revision().is_none() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// The reporter's central case: a control plane that fixes a bad snapshot IN
/// PLACE republishes the corrected slice at the SAME sequence. Before the fix
/// the conversion refusal left `accepted` pinned at that sequence, so the
/// corrected slice was quarantined as `divergent_content`, the wait never
/// returned, and the data plane stayed NotReady until a strictly higher
/// sequence arrived or an operator called `POST /mesh/config-revision/reset`.
#[tokio::test(flavor = "current_thread")]
async fn a_conversion_invalid_first_slice_does_not_pin_the_startup_watermark() {
    let state = MeshRuntimeState::new();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let wait = tokio::spawn(wait_for_initial_mesh_config_for_test(
        state.clone(),
        shutdown_rx,
    ));

    assert!(
        state
            .install_slice(conversion_invalid_startup_slice("v-bad", 100))
            .installed(),
        "the freshness gate admits the candidate — conversion is the stage that refuses it"
    );

    assert!(
        await_accepted_revision_cleared(&state).await,
        "a candidate the startup wait refused never served, so it must not keep the watermark"
    );
    assert!(
        state.applied_revision().is_none(),
        "nothing was ever applied, so the rollback target is no baseline"
    );
    assert!(
        !wait.is_finished(),
        "the wait must still be waiting for a slice that actually converts"
    );

    // The corrected slice, republished at the SAME sequence with different
    // content. That is `divergent_content` against a pinned watermark and
    // `Bootstrap` against a rolled-back one.
    let corrected = startup_slice("v-good", 100);
    assert!(
        state.install_slice(corrected.clone()).installed(),
        "the same-sequence correction is eligible once the refusal rolled back"
    );

    let accepted = tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("the startup wait converges on the corrected slice")
        .expect("wait task joins")
        .expect("the corrected slice converts");
    assert_eq!(accepted, "v-good");
    assert_eq!(
        state.accepted_revision(),
        Some(revision("db", 100)),
        "a candidate the wait passed keeps its provisional admission"
    );

    // `serve_mesh_runtime` commits the generation once it is actually live.
    {
        let _overlay_guard = overlay_consumer_guard();
        let token = state.begin_revision_apply(&corrected);
        state.record_applied_slice_with_token(&corrected, token);
    }
    assert_eq!(state.applied_revision(), Some(revision("db", 100)));

    // The reopening is bounded by the last-good guarantee, not a general
    // relaxation: once a generation is applied, both a lower sequence and
    // divergent content at the applied sequence are quarantined again.
    assert_eq!(
        state
            .install_slice(startup_slice("v-older", 99))
            .rejection()
            .expect("a lower sequence is stale against the applied generation")
            .reason(),
        MeshRevisionRejectReason::StaleRevision
    );
    assert_eq!(
        state
            .install_slice(conversion_invalid_startup_slice("v-bad-again", 100))
            .rejection()
            .expect("divergent content at the applied sequence stays quarantined")
            .reason(),
        MeshRevisionRejectReason::DivergentContent
    );
    assert_eq!(state.applied_revision(), Some(revision("db", 100)));
}

/// The lower-sequence half of the same recovery, at the hostile bound: a
/// conversion-invalid slice published at `u64::MAX` must not lock the ordering
/// domain, because no sequence can ever beat it. A control plane that reverts
/// its bad snapshot republishes BELOW the refused sequence, and that recovery
/// is eligible only because the refusal returned the gate to no baseline.
#[tokio::test(flavor = "current_thread")]
async fn a_lower_sequence_slice_recovers_startup_after_a_conversion_refusal() {
    let state = MeshRuntimeState::new();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let wait = tokio::spawn(wait_for_initial_mesh_config_for_test(
        state.clone(),
        shutdown_rx,
    ));

    assert!(
        state
            .install_slice(conversion_invalid_startup_slice("v-bad-max", u64::MAX))
            .installed()
    );
    assert!(
        await_accepted_revision_cleared(&state).await,
        "a far-future refused candidate must not become an unbeatable watermark"
    );
    assert!(!wait.is_finished());

    assert!(
        state
            .install_slice(startup_slice("v-recovery", 7))
            .installed(),
        "the lower-sequence recovery is eligible again"
    );

    let accepted = tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("the startup wait converges on the recovery slice")
        .expect("wait task joins")
        .expect("the recovery slice converts");
    assert_eq!(accepted, "v-recovery");
    assert_eq!(state.accepted_revision(), Some(revision("db", 7)));
}

// ── Equal-revision content binding (issue #3611) ────────────────────────────
//
// A scalar revision only orders snapshots if one `(authority, sequence)` names
// exactly one content. The Kubernetes domain does not guarantee that on its own
// (see the multi-scope counterexample at the end of this section), so the gate
// binds a semantic content identity to every accepted and applied revision.

/// The core invariant: an equal revision carrying DIFFERENT content is
/// quarantined with a bounded reason, and the last-good slice keeps serving.
#[test]
fn equal_revision_with_divergent_content_is_quarantined_and_last_good_retained() {
    let state = MeshRuntimeState::new();
    let accepted = slice_with_content("v-100", Some(revision("db", 100)), "authz-withdrawn");
    assert!(state.install_slice(accepted).installed());
    let installed_at = state.last_install_at().expect("first install stamps");

    let divergent = slice_with_content("v-100-b", Some(revision("db", 100)), "authz-live");
    let outcome = state.install_slice(divergent);
    let rejection = outcome
        .rejection()
        .expect("divergent content at an equal revision must not install");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::DivergentContent
    );
    assert_eq!(rejection.reason().as_metric_label(), "divergent_content");
    assert!(
        rejection.terminates_stream(),
        "an inconsistent producer's whole view is suspect; the stream must fail over"
    );
    assert!(
        !rejection.detail().contains("authz"),
        "the diagnostic must never echo slice content: {}",
        rejection.detail()
    );

    assert_eq!(installed_version(&state).as_deref(), Some("v-100"));
    assert_eq!(
        state.last_install_at(),
        Some(installed_at),
        "a quarantined candidate must not advance the receive timestamp"
    );
    assert_eq!(state.accepted_revision(), Some(revision("db", 100)));
    assert!(state.revision_diagnostics().quarantine_active);
}

/// The behavior the binding must NOT break: an exact-content replay at the same
/// revision is every ordinary reconnect, so it still installs — even when the
/// observability-only `version` differs, which is exactly the case of a replay
/// served by a DIFFERENT replica of the same control plane.
#[test]
fn equal_revision_exact_content_replay_still_installs() {
    let state = MeshRuntimeState::new();
    let first = slice_with_content("v-10-cp-a", Some(revision("db", 10)), "same-content");
    assert!(state.install_slice(first).installed());

    // Same content, same revision, different `version` — a replay served by
    // another replica of the same control plane.
    let replay = slice_with_content("v-10-cp-b", Some(revision("db", 10)), "same-content");
    assert!(
        state.install_slice(replay).installed(),
        "identical semantic content at an equal revision is a replay, not a rollback"
    );
    assert_eq!(installed_version(&state).as_deref(), Some("v-10-cp-b"));
    assert!(!state.revision_diagnostics().quarantine_active);
}

/// xDS installs through the same `MeshRuntimeState` gate, so it inherits the
/// binding — and, like every revision quarantine there, must close ADS so
/// multi-CP rotation moves off the inconsistent control plane.
#[test]
fn xds_consumer_surfaces_divergent_equal_revision_content_as_stream_terminal() {
    let state = MeshRuntimeState::new();
    let consumer = XdsConfigConsumer::new(
        XdsClientConfig {
            cp_urls: vec![
                "http://cp-a:50051".to_string(),
                "http://cp-b:50051".to_string(),
            ],
            node_id: NODE_ID.to_string(),
            cluster: "default".to_string(),
            namespace: NAMESPACE.to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
            stream_channel_capacity: 32,
            primary_retry_secs: 300,
            connect_timeout_seconds: 10,
            labels: BTreeMap::new(),
        },
        state.clone(),
    );

    let baseline = slice_with_content("xds-v100", Some(revision("k8s", 100)), "authz-withdrawn");
    consumer
        .apply_slice(baseline)
        .expect("the fresh xDS baseline installs");

    let divergent = slice_with_content("xds-v100-b", Some(revision("k8s", 100)), "authz-live");
    let rejection = consumer
        .apply_slice(divergent)
        .expect_err("divergent equal-revision content must close ADS");

    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::DivergentContent
    );
    assert!(rejection.terminates_stream());
    assert_eq!(installed_version(&state).as_deref(), Some("xds-v100"));

    // The exact-content replay an ordinary reconnect produces still installs.
    let replay = slice_with_content("xds-replay", Some(revision("k8s", 100)), "authz-withdrawn");
    consumer
        .apply_slice(replay)
        .expect("an exact-content replay is not a rollback");
    assert_eq!(installed_version(&state).as_deref(), Some("xds-replay"));
}

/// The received/applied slots keep revision and content identity PAIRED across
/// the whole lifecycle: a runtime rejection restores the applied revision
/// together with the identity it was applied with, so the equal-revision check
/// afterwards is evaluated against the last-good content, not the refused one.
#[test]
fn rollback_restores_the_applied_revision_and_its_bound_content_together() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let applied = slice_with_content("v-10", Some(revision("db", 10)), "good");
    assert!(state.install_slice(applied.clone()).installed());
    let token = state.begin_revision_apply(&applied);
    state.record_applied_slice_with_token(&applied, token);
    assert_eq!(state.applied_revision(), Some(revision("db", 10)));

    // A newer candidate is received and then REFUSED by the proxy runtime.
    let refused = slice_with_content("v-20", Some(revision("db", 20)), "bad");
    assert!(state.install_slice(refused).installed());
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), Some(revision("db", 10)));

    // The restored pair is the APPLIED one: divergent content at revision 10 is
    // still quarantined, and the exact applied content still replays.
    let divergent = slice_with_content("v-10-x", Some(revision("db", 10)), "other");
    assert_eq!(
        state
            .install_slice(divergent)
            .rejection()
            .expect("the rolled-back slot must still bind the applied content")
            .reason(),
        MeshRevisionRejectReason::DivergentContent
    );
    let replay = slice_with_content("v-10-replay", Some(revision("db", 10)), "good");
    assert!(
        state.install_slice(replay).installed(),
        "the identity restored by the rollback must be the one that was applied"
    );

    // An operator reset drops both slots, so any content installs at any
    // revision afterwards.
    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned for the audit log");
    assert_eq!(cleared, revision("db", 10));
    let post_reset = slice_with_content("v-10-new", Some(revision("db", 10)), "new");
    assert!(
        state.install_slice(post_reset).installed(),
        "a reset clears the bound identity along with the watermarks"
    );
}

/// The Kubernetes counterexample this repair exists for. A controller CP
/// publishes the MINIMUM per-scope convergence watermark, but serves a
/// latest-only reflector snapshot — so replica A at scope watermarks
/// `[110, 100]` and replica B at `[100, 100]` BOTH publish sequence 100 while
/// only A's snapshot carries the change made at 110. Without the content
/// binding a data plane that accepted A could fail over to B and install the
/// older content at the same sequence: the exact rollback #3611 closes.
#[test]
fn kubernetes_minimum_scope_watermark_cannot_displace_accepted_content() {
    let policies = watch_scope_key("security.istio.io/v1beta1", "AuthorizationPolicy", "all");
    let gateways = watch_scope_key("gateway.networking.k8s.io/v1", "Gateway", "all");

    let converged = |policy_revision: &str| {
        let tracker = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
        for scope in [&policies, &gateways] {
            tracker.begin_generation(scope, Some(100));
            tracker.observe_listed(scope, Some("100"));
            tracker.commit_list(scope);
        }
        tracker.observe_applied(&policies, Some(policy_revision));
        tracker
    };
    let publish = |tracker: &K8sConfigRevisionTracker| {
        let watermark = tracker.converged_watermark([&policies, &gateways]);
        tracker.publish(watermark).expect("an authority is set")
    };

    // A has applied the AuthorizationPolicy withdrawal at 110; B has not. The
    // published sequence is the minimum over scopes, so both advertise 100.
    let replica_a = converged("110");
    let replica_b = converged("100");
    assert_eq!(publish(&replica_a), revision("k8s", 100));
    assert_eq!(
        publish(&replica_b),
        revision("k8s", 100),
        "equal sequences from divergent snapshots are the whole problem"
    );

    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let from_a = slice_with_content("cp-a", Some(publish(&replica_a)), "authz-withdrawn");
    assert!(state.install_slice(from_a.clone()).installed());
    let token = state.begin_revision_apply(&from_a);
    state.record_applied_slice_with_token(&from_a, token);

    let from_b = slice_with_content("cp-b", Some(publish(&replica_b)), "authz-still-live");
    let install = state.install_slice(from_b);
    let rejection = install
        .rejection()
        .expect("a lagging replica must not displace accepted content at an equal sequence");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::DivergentContent
    );
    assert!(rejection.terminates_stream());
    assert_eq!(installed_version(&state).as_deref(), Some("cp-a"));
    assert_eq!(state.applied_revision(), Some(revision("k8s", 100)));

    // B observes the same withdrawal. Its published sequence is UNCHANGED — the
    // minimum was never the lagging scope — but its content now matches, so the
    // reconnect replay installs. Recovery does not depend on the sequence
    // moving, which is what makes the binding safe to fail closed on.
    replica_b.observe_applied(&policies, Some("110"));
    assert_eq!(publish(&replica_b), revision("k8s", 100));
    let caught_up = slice_with_content("cp-b-ok", Some(publish(&replica_b)), "authz-withdrawn");
    assert!(
        state.install_slice(caught_up).installed(),
        "once B carries the same content, its equal-revision slice is a replay"
    );
    assert_eq!(installed_version(&state).as_deref(), Some("cp-b-ok"));
}

/// The operator reset clears the APPLIED watermark as well. Leaving it would
/// let the next runtime-refused candidate roll the gate straight back onto the
/// generation the operator just released, silently undoing the reset.
#[test]
fn reset_clears_the_applied_watermark_so_a_rejection_cannot_resurrect_it() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    let token = state.begin_revision_apply(&applied);
    state.record_applied_slice_with_token(&applied, token);

    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned for the audit log");
    assert_eq!(cleared, revision("db", 10));
    assert!(state.accepted_revision().is_none());
    assert!(state.applied_revision().is_none());

    // The store was restored from backup, so the next slice rewinds to a lower
    // sequence and installs on the cleared baseline.
    assert!(
        state
            .install_slice(slice_at("v-3", Some(revision("db", 3))))
            .installed()
    );
    assert!(
        state.record_rejected_slice(&state.snapshot()),
        "the rewound candidate owns the post-reset watermark"
    );
    assert!(
        state.accepted_revision().is_none(),
        "a rejection must not resurrect the pre-reset generation"
    );
}

// ── Diagnostic bounding of control-plane-supplied authorities ──────────────

/// A control-character-bearing authority is refused as malformed at the
/// boundary, so it can never reach the accepted watermark, the reset audit log,
/// or the admin surface. The quarantine record that DOES echo it is sanitized.
#[test]
fn control_character_authorities_are_refused_and_never_reach_a_watermark() {
    let _overlay_guard = overlay_consumer_guard();
    let forged = revision("db\n2026-07-26 WARN forged-by-the-control-plane", 100);
    assert!(!forged.is_well_formed());
    assert_eq!(
        MeshConfigRevision::compare(Some(&revision("db", 10)), Some(&forged)),
        MeshRevisionOrder::Unversioned
    );
    assert_eq!(
        MeshConfigRevision::compare(Some(&forged), Some(&revision("db", 10))),
        MeshRevisionOrder::Bootstrap,
        "a malformed ACCEPTED revision cannot lock the data plane out either"
    );

    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    let token = state.begin_revision_apply(&applied);
    state.record_applied_slice_with_token(&applied, token);

    assert_eq!(
        state
            .install_slice(slice_at("v-forged", Some(forged)))
            .rejection()
            .expect("a malformed authority is refused, not downgraded to absent")
            .reason(),
        MeshRevisionRejectReason::MalformedRevision
    );

    let diagnostics = state.revision_diagnostics();
    let quarantined = diagnostics
        .quarantined
        .expect("the refusal is recorded for operators");
    assert_eq!(quarantined.reason, "malformed_revision");
    assert!(
        !quarantined.authority.chars().any(char::is_control),
        "the echoed authority must not be able to forge a log line: {:?}",
        quarantined.authority
    );
    assert_eq!(diagnostics.accepted, Some(revision("db", 10)));
    assert_eq!(diagnostics.applied, Some(revision("db", 10)));

    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned");
    assert!(!cleared.authority.chars().any(char::is_control));
}

/// Every copy of an authority that LEAVES the gate — diagnostics, the reset
/// response, and the log lines built from them — is length-bounded, while the
/// raw value stays inside for exact ordering.
#[test]
fn output_copies_of_the_authority_are_bounded_but_ordering_stays_exact() {
    let _overlay_guard = overlay_consumer_guard();
    // Well formed (within `MAX_AUTHORITY_LEN`) but longer than the 64-character
    // diagnostic bound.
    let long = revision(&"d".repeat(100), 7);
    assert!(long.is_well_formed());
    let bounded = format!("{}(truncated)", "d".repeat(64));

    let state = MeshRuntimeState::new();
    let applied = slice_at("v-7", Some(long.clone()));
    assert!(state.install_slice(applied.clone()).installed());
    let token = state.begin_revision_apply(&applied);
    state.record_applied_slice_with_token(&applied, token);

    // Ordering keeps the RAW value: a different authority that shares the
    // first 64 characters must not be mistaken for the accepted one.
    assert_eq!(state.accepted_revision(), Some(long));
    let sibling = revision(&format!("{}x", "d".repeat(99)), 9);
    assert_eq!(
        state
            .install_slice(slice_at("v-9", Some(sibling)))
            .rejection()
            .expect("a distinct authority is a distinct ordering domain")
            .reason(),
        MeshRevisionRejectReason::IncomparableAuthority
    );

    let diagnostics = state.revision_diagnostics();
    assert_eq!(
        diagnostics
            .accepted
            .expect("accepted watermark is reported")
            .authority,
        bounded
    );
    assert_eq!(
        diagnostics
            .applied
            .expect("applied watermark is reported")
            .authority,
        bounded
    );

    let cleared = state
        .reset_accepted_revision()
        .expect("the accepted revision is returned");
    assert_eq!(cleared.authority, bounded);
    assert_eq!(cleared.sequence, 7);
}

// ── Kubernetes ordering domain (issue #3611) ───────────────────────────────

/// A Kubernetes-controller control plane sequences from `resourceVersion` —
/// etcd's cluster-global revision counter — while a database-backed one
/// sequences from its `config_changes` change log. The two number spaces are
/// unrelated, so the domains must never be able to claim comparability.
///
/// The separation is structural, not advisory: the authority carries the
/// domain, and the ONE seam through which a change-log cursor can reach a
/// revision refuses a Kubernetes-domain one.
#[test]
fn the_kubernetes_domain_is_never_comparable_with_the_change_log_domain() {
    assert_eq!(kubernetes_authority(""), KUBERNETES_AUTHORITY_DOMAIN);
    assert_eq!(kubernetes_authority("east-2"), "k8s:east-2");

    assert!(is_kubernetes_authority("k8s"));
    assert!(is_kubernetes_authority("k8s:east-2"));
    // A prefix match would be wrong: these are ordinary operator authority ids.
    assert!(!is_kubernetes_authority("k8sconfig"));
    assert!(!is_kubernetes_authority("db"));
    assert!(!is_kubernetes_authority("my-k8s"));

    // A change-log cursor may advance a change-log revision...
    let mut change_log = revision("db", 10);
    assert!(change_log.advance_change_log_sequence(42));
    assert_eq!(change_log.sequence, 42);
    // ...never moves backwards when a peer sends no cursor...
    assert!(!change_log.advance_change_log_sequence(0));
    assert_eq!(change_log.sequence, 42);
    // ...and can never touch a Kubernetes-domain revision, in either direction.
    let mut kubernetes = revision("k8s", 5_000_000);
    assert!(!kubernetes.advance_change_log_sequence(42));
    assert_eq!(kubernetes.sequence, 5_000_000);
    let mut fresh_cluster = revision("k8s:east-2", 3);
    assert!(!fresh_cluster.advance_change_log_sequence(9_000));
    assert_eq!(
        fresh_cluster.sequence, 3,
        "a database write must never advertise a Kubernetes snapshot as newer, \
         even on a cluster whose revisions are still small"
    );

    // And the data plane needs no new rule: distinct authorities are already
    // incomparable, so a mixed fleet cannot silently order across domains.
    let state = MeshRuntimeState::new();
    assert!(
        state
            .install_slice(slice_at("k8s-1", Some(revision("k8s", 5_000_000))))
            .installed()
    );
    assert_eq!(
        state
            .install_slice(slice_at("db-1", Some(revision("db", 5_000_001))))
            .rejection()
            .expect("a change-log slice cannot displace a Kubernetes one")
            .reason(),
        MeshRevisionRejectReason::IncomparableAuthority
    );
    assert_eq!(installed_version(&state).as_deref(), Some("k8s-1"));
}

/// `resourceVersion` is documented as opaque. Ferrum orders on it only when it
/// parses as an unsigned integer (the etcd revision every supported API server
/// mints); anything else is NO EVIDENCE, never zero and never a guess.
#[test]
fn only_numeric_resource_versions_are_evidence() {
    assert_eq!(parse_resource_version("12345"), Some(12_345));
    assert_eq!(parse_resource_version("0"), Some(0));

    for rejected in [
        "",
        " 12",
        "12 ",
        "+12",
        "-12",
        "1.2",
        "abc",
        "12a",
        // 21 digits: cannot be a `u64` revision.
        "123456789012345678901",
        // `u64::MAX + 1`.
        "18446744073709551616",
    ] {
        assert_eq!(
            parse_resource_version(rejected),
            None,
            "{rejected:?} must not be accepted as an orderable revision"
        );
    }

    // A scope whose versions never parse establishes no evidence at all, so the
    // control plane publishes nothing rather than ordering on a value it cannot
    // interpret.
    let tracker = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
    let scope = watch_scope_key("gateway.networking.k8s.io/v1", "Gateway", "all");
    tracker.begin_generation(&scope, None);
    tracker.observe_listed(&scope, Some("not-a-revision"));
    tracker.commit_list(&scope);

    assert_eq!(tracker.converged_watermark([&scope]), None);
    assert_eq!(tracker.publish(None), None);
    assert_eq!(tracker.stats().unparsable_resource_versions, 1);
    assert_eq!(tracker.stats().unsequenced_publications, 1);
}

/// The published sequence is the MINIMUM across watched scopes, because a
/// reconcile snapshot is the union of independently converging reflectors: the
/// strongest true statement is that it contains every change up to the least
/// converged scope. A maximum would advertise a resource type's staleness away.
#[test]
fn the_kubernetes_sequence_is_the_minimum_across_watched_resource_types() {
    let tracker = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
    let gateways = watch_scope_key("gateway.networking.k8s.io/v1", "Gateway", "all");
    let policies = watch_scope_key(
        "security.istio.io/v1beta1",
        "AuthorizationPolicy",
        "namespace:alpha",
    );
    let pods = watch_scope_key("v1", "Pod", "namespace:alpha");

    for scope in [&gateways, &policies, &pods] {
        tracker.begin_generation(scope, Some(5_000));
    }
    // Only two of the three have finished their initial list. A snapshot
    // missing a whole resource type must not be stamped as complete.
    tracker.commit_list(&gateways);
    tracker.commit_list(&policies);
    assert_eq!(
        tracker.converged_watermark([&gateways, &policies, &pods]),
        None,
        "a registered scope with no evidence withholds the whole watermark"
    );
    assert_eq!(
        tracker.publish(None),
        None,
        "nothing has ever been established, so the CP publishes no revision"
    );

    tracker.commit_list(&pods);
    assert_eq!(
        tracker.converged_watermark([&gateways, &policies, &pods]),
        Some(5_000)
    );

    // A busy scope races ahead; the minimum stays on the quiet one.
    tracker.observe_applied(&pods, Some("9000"));
    tracker.observe_applied(&gateways, Some("7000"));
    assert_eq!(
        tracker.converged_watermark([&gateways, &policies, &pods]),
        Some(5_000),
        "the least converged scope bounds the snapshot"
    );

    // An empty scope set is not a fully converged snapshot; it is no snapshot.
    let none: [&K8sWatchScopeKey; 0] = [];
    assert_eq!(tracker.converged_watermark(none.into_iter()), None);
}

/// Deleting the highest-versioned object must ADVANCE the watermark. This is
/// the case that rules out ordering on live object metadata: a max over the
/// surviving objects would drop, and a replica that restarted after the
/// deletion would publish below its still-running peer — a rewind inside one
/// authority, which the gate never auto-adopts.
#[test]
fn deleting_the_highest_versioned_object_advances_the_kubernetes_watermark() {
    let tracker = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
    let scope = watch_scope_key("gateway.networking.k8s.io/v1", "Gateway", "all");

    tracker.begin_generation(&scope, Some(100));
    tracker.observe_listed(&scope, Some("100"));
    tracker.observe_listed(&scope, Some("200"));
    tracker.commit_list(&scope);
    let watermark = tracker.converged_watermark([&scope]);
    assert_eq!(watermark, Some(200));

    // The object stamped 200 is deleted; the DELETED watch event carries the
    // deletion revision, not the object's old one.
    tracker.observe_applied(&scope, Some("300"));
    let watermark = tracker.converged_watermark([&scope]);
    assert_eq!(watermark, Some(300), "a withdrawal advances the watermark");

    // A replica restarting after that deletion sees only the surviving object
    // (100) — but its boundary read returns a CURRENT cluster revision, which
    // is at or above everything already observed. No rewind.
    let restarted = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
    restarted.begin_generation(&scope, Some(301));
    restarted.observe_listed(&scope, Some("100"));
    restarted.commit_list(&scope);
    let watermark = restarted.converged_watermark([&scope]);
    assert_eq!(
        watermark,
        Some(301),
        "a restarted replica must not publish below its running peer"
    );
}

/// Two replicas of one control plane deployment converge on the SAME sequence
/// as soon as both have observed the same change, because event revisions are
/// cluster-minted. A replica that has NOT seen it stays behind — and that is
/// exactly what the data-plane gate is for: failing over to it must not roll
/// the mesh back.
#[test]
fn two_kubernetes_replicas_order_by_the_shared_resource_version() {
    let scope = watch_scope_key("security.istio.io/v1beta1", "AuthorizationPolicy", "all");
    let converge = |boundary: u64| {
        let tracker = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
        tracker.begin_generation(&scope, Some(boundary));
        tracker.observe_listed(&scope, Some("4000"));
        tracker.commit_list(&scope);
        tracker
    };
    // The two replicas started at different times, so their boundaries differ.
    let replica_a = converge(4_100);
    let replica_b = converge(4_050);
    let publish = |tracker: &K8sConfigRevisionTracker| {
        let watermark = tracker.converged_watermark([&scope]);
        tracker.publish(watermark).expect("an authority is set")
    };

    // A policy is withdrawn at revision 9000. Only replica A observes it.
    replica_a.observe_applied(&scope, Some("9000"));
    let fresh = publish(&replica_a);
    let lagging = publish(&replica_b);
    assert_eq!(fresh, revision("k8s", 9_000));
    assert_eq!(lagging, revision("k8s", 4_050));

    // The data plane accepts the fresh replica, then fails over to the lagging
    // one: its slice is quarantined and the last-good keeps serving.
    let state = MeshRuntimeState::new();
    assert!(
        state
            .install_slice(slice_at("cp-a", Some(fresh.clone())))
            .installed()
    );
    let install = state.install_slice(slice_at("cp-b", Some(lagging)));
    let rejection = install
        .rejection()
        .expect("a lagging Kubernetes replica must be quarantined");
    assert_eq!(rejection.reason(), MeshRevisionRejectReason::StaleRevision);
    assert!(
        rejection.terminates_stream(),
        "the data plane must leave the lagging control plane"
    );
    assert_eq!(installed_version(&state).as_deref(), Some("cp-a"));
    assert!(state.revision_diagnostics().quarantine_active);

    // Replica B observes the same withdrawal and publishes the IDENTICAL
    // sequence — cluster-minted event revisions are what make replicas
    // convergent, not their independent boundary reads.
    replica_b.observe_applied(&scope, Some("9000"));
    assert_eq!(publish(&replica_b), fresh);

    // A reconnect replays that same revision, which MUST install.
    assert!(
        state
            .install_slice(slice_at("cp-b-replay", Some(fresh)))
            .installed(),
        "an equal revision is a reconnect replay, not a rollback"
    );
    assert_eq!(installed_version(&state).as_deref(), Some("cp-b-replay"));
}

/// Incomplete convergence retains the last published sequence rather than
/// publishing an unsequenced (which a data plane would quarantine as
/// `missing_revision`) or an optimistic frame. Publication is also monotonic
/// against a scope set that GROWS, which is the one way the aggregate minimum
/// can dip. Divergent mesh under that retained scalar is withheld at the
/// reconciler publication boundary (see `k8s_mesh_revision_binding_tests`).
#[test]
fn incomplete_convergence_retains_the_last_kubernetes_revision() {
    let tracker = K8sConfigRevisionTracker::new(Some("k8s".to_string()));
    let gateways = watch_scope_key("gateway.networking.k8s.io/v1", "Gateway", "all");

    tracker.begin_generation(&gateways, Some(8_000));
    tracker.commit_list(&gateways);
    let watermark = tracker.converged_watermark([&gateways]);
    let established = tracker
        .publish(watermark)
        .expect("the first convergence establishes a sequence");
    assert_eq!(established, revision("k8s", 8_000));

    // A watcher restarts: its scope has no evidence for the new generation's
    // store until `InitDone`. The published sequence holds.
    assert_eq!(tracker.publish(None), Some(revision("k8s", 8_000)));
    assert_eq!(tracker.stats().withheld_advances, 1);

    // A CRD installed later registers a new scope whose evidence is younger, so
    // the aggregate minimum dips. The in-process floor keeps publication
    // monotonic; the scalar never rewinds. Divergent mesh under that retained
    // scalar is withheld at the reconciler publication boundary.
    let backend_tls = watch_scope_key("gateway.networking.k8s.io/v1", "BackendTLSPolicy", "all");
    tracker.begin_generation(&backend_tls, Some(6_000));
    tracker.commit_list(&backend_tls);
    assert_eq!(
        tracker.converged_watermark([&gateways, &backend_tls]),
        Some(6_000)
    );
    assert_eq!(
        tracker.publish(Some(6_000)),
        Some(revision("k8s", 8_000)),
        "publication never emits a sequence below one it already published"
    );

    // Once the new scope catches up, the sequence advances again.
    tracker.observe_applied(&backend_tls, Some("9500"));
    let watermark = tracker.converged_watermark([&gateways, &backend_tls]);
    assert_eq!(
        tracker.publish(watermark),
        Some(revision("k8s", 8_000)),
        "the gateways scope is now the minimum"
    );
    tracker.observe_applied(&gateways, Some("9500"));
    let watermark = tracker.converged_watermark([&gateways, &backend_tls]);
    assert_eq!(tracker.publish(watermark), Some(revision("k8s", 9_500)));
}

/// With publication disabled (`FERRUM_MESH_CONFIG_AUTHORITY_ID=`) the tracker
/// still gathers evidence but stamps nothing, restoring the pre-#3611 posture
/// deliberately rather than by accident.
#[test]
fn a_disabled_authority_publishes_no_kubernetes_revision() {
    let tracker = K8sConfigRevisionTracker::new(None);
    assert!(!tracker.is_enabled());
    let scope = watch_scope_key("v1", "Service", "all");
    tracker.begin_generation(&scope, Some(1_000));
    tracker.commit_list(&scope);

    let watermark = tracker.converged_watermark([&scope]);
    assert_eq!(watermark, Some(1_000));
    assert_eq!(tracker.publish(Some(1_000)), None);
}

/// A Kubernetes revision rides the SAME envelope and the SAME centralized
/// update validation as a change-log one — there is no separate data-plane
/// gate for it. Native and xDS therefore stay at parity by construction.
#[test]
fn kubernetes_revisions_flow_through_the_shared_envelope_and_xds_paths() {
    let request = client_config().subscribe_request(ferrum_edge::FERRUM_VERSION);
    let expected = MeshUpdateExpectation::from_subscribe_request(&request);
    let slice = slice_at("k8s-4711000", Some(revision("k8s:east-2", 4_711_000)));

    // Native: envelope↔slice agreement is enforced for this domain too.
    validate_mesh_config_update(&update_for(&slice), &expected, MeshUpdateConsumer::Native)
        .expect("a well-formed Kubernetes revision passes update validation");
    let mismatched = MeshConfigUpdate {
        config_sequence: 4_711_001,
        ..update_for(&slice)
    };
    assert_eq!(
        validate_mesh_config_update(&mismatched, &expected, MeshUpdateConsumer::Native)
            .expect_err("a disagreeing envelope must be refused")
            .reason(),
        MeshUpdateRejectReason::EnvelopeRevisionMismatch
    );

    // xDS: the same gate, reached without update validation, terminates ADS on
    // a stale Kubernetes revision exactly as it does on a stale change-log one.
    let state = MeshRuntimeState::new();
    let consumer = XdsConfigConsumer::new(
        XdsClientConfig {
            cp_urls: vec![
                "http://cp-a:50051".to_string(),
                "http://cp-b:50051".to_string(),
            ],
            node_id: NODE_ID.to_string(),
            cluster: "default".to_string(),
            namespace: NAMESPACE.to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
            stream_channel_capacity: 32,
            primary_retry_secs: 300,
            connect_timeout_seconds: 10,
            labels: BTreeMap::new(),
        },
        state.clone(),
    );
    consumer
        .apply_slice(slice)
        .expect("the fresh Kubernetes xDS baseline installs");
    let stale = slice_at("k8s-4710000", Some(revision("k8s:east-2", 4_710_000)));
    let rejection = consumer
        .apply_slice(stale)
        .expect_err("a stale Kubernetes xDS slice must close ADS");
    assert_eq!(rejection.reason(), MeshRevisionRejectReason::StaleRevision);
    assert!(rejection.terminates_stream());
    assert_eq!(installed_version(&state).as_deref(), Some("k8s-4711000"));
}

// ── Kubernetes evidence through the production watcher task ────────────────

const K8S_GROUP: &str = "gateway.networking.k8s.io";
const K8S_VERSION: &str = "v1";
const K8S_KIND: &str = "Gateway";
const K8S_PLURAL: &str = "gateways";
const K8S_SCOPE: &str = "namespace:alpha";
const K8S_IDLE_RELIST_SECS: u64 = 60;

fn k8s_scope(
    generations: usize,
    boundaries: Vec<Option<u64>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> (K8sWatchScopeForTest, impl std::future::Future<Output = ()>) {
    k8s_watch_scope_with_revision_for_test(
        K8S_GROUP,
        K8S_VERSION,
        K8S_KIND,
        K8S_PLURAL,
        K8S_SCOPE,
        K8S_IDLE_RELIST_SECS,
        generations,
        Some("k8s".to_string()),
        boundaries,
        shutdown,
    )
}

/// Drive the PRODUCTION watcher task (`run_watcher_generations`) with scripted
/// reflector generations and assert the evidence contract end to end:
///
/// * nothing is published before the initial list completes — the store is
///   empty then, and a snapshot missing a resource type must not be stamped;
/// * the pre-list boundary is adopted at `InitDone`, together with the listed
///   objects the reflector publishes to its store at that same moment;
/// * a `Delete` advances the watermark;
/// * a make-before-break replacement generation does NOT advance the live
///   watermark until its store is swapped in.
#[tokio::test(start_paused = true)]
async fn watch_evidence_is_only_adopted_when_the_store_can_serve_it() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Generation 0 reads boundary 1000; the relisted generation 1 reads 7000.
    let (harness, task) = k8s_scope(2, vec![Some(1_000), Some(7_000)], shutdown_rx);
    let watcher = tokio::spawn(task);
    let settle = Duration::from_millis(50);

    tokio::time::sleep(settle).await;
    assert_eq!(
        harness.revision_watermark().await,
        None,
        "the registered store is still empty; nothing may be stamped"
    );
    assert_eq!(
        harness.publish_revision().await,
        None,
        "no sequence has ever been established"
    );

    // Initial list: objects are buffered by the reflector until `InitDone`.
    harness.emit(0, Event::Init);
    let edge = harness.object_at("alpha", "edge", "900");
    harness.emit(0, Event::InitApply(edge));
    tokio::time::sleep(settle).await;
    assert_eq!(
        harness.revision_watermark().await,
        None,
        "a list in flight is not convergence"
    );

    harness.emit(0, Event::InitDone);
    tokio::time::sleep(settle).await;
    assert_eq!(
        harness.revision_watermark().await,
        Some(1_000),
        "the pre-list boundary is adopted at InitDone, above the listed objects"
    );
    assert_eq!(harness.visible_names().await, vec!["edge".to_string()]);

    // A deletion carries the DELETION revision and advances the watermark.
    let withdrawn = harness.object_at("alpha", "edge", "4200");
    harness.emit(0, Event::Delete(withdrawn));
    tokio::time::sleep(settle).await;
    assert_eq!(harness.revision_watermark().await, Some(4_200));
    assert!(harness.visible_names().await.is_empty());
    assert_eq!(
        harness.publish_revision().await,
        Some(MeshConfigRevision::new("k8s", 4_200))
    );

    // Go idle past the relist window: generation 1 starts and reads its own
    // boundary, but the OLD store stays registered until `InitDone`.
    tokio::time::sleep(Duration::from_secs(K8S_IDLE_RELIST_SECS * 2)).await;
    harness.emit(1, Event::Init);
    let relisted = harness.object_at("alpha", "relisted", "6500");
    harness.emit(1, Event::InitApply(relisted));
    tokio::time::sleep(settle).await;
    assert_eq!(
        harness.revision_watermark().await,
        Some(4_200),
        "a replacement generation must not advance the live watermark"
    );
    assert!(
        harness.visible_names().await.is_empty(),
        "the previous store is still the registered one"
    );

    harness.emit(1, Event::InitDone);
    tokio::time::sleep(settle).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["relisted".to_string()],
        "make-before-break swap"
    );
    assert_eq!(
        harness.revision_watermark().await,
        Some(7_000),
        "the replacement's boundary is adopted only once its store is live"
    );
    assert_eq!(harness.revision_stats().unparsable_resource_versions, 0);

    let _ = shutdown_tx.send(true);
    let _ = watcher.await;
}

/// A watcher generation whose boundary read fails (or times out) yields no
/// boundary. That only UNDERSTATES convergence: the scope still establishes
/// evidence from the objects and events it actually processed, and the
/// in-process floor keeps publication monotonic.
#[tokio::test(start_paused = true)]
async fn a_failed_boundary_read_understates_but_never_overstates() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (harness, task) = k8s_scope(1, vec![None], shutdown_rx);
    let watcher = tokio::spawn(task);
    let settle = Duration::from_millis(50);

    harness.emit(0, Event::Init);
    let edge = harness.object_at("alpha", "edge", "2600");
    harness.emit(0, Event::InitApply(edge));
    harness.emit(0, Event::InitDone);
    tokio::time::sleep(settle).await;

    assert_eq!(
        harness.revision_watermark().await,
        Some(2_600),
        "listed object revisions are a sound lower bound on the list revision"
    );
    assert_eq!(
        harness.publish_revision().await,
        Some(MeshConfigRevision::new("k8s", 2_600))
    );

    let _ = shutdown_tx.send(true);
    let _ = watcher.await;
}

/// The aggregate sequence is a MINIMUM over scopes, so a quiet scope pins it
/// until its next generation adopts a fresh boundary. Left to the idle relist
/// alone, a change in one busy scope therefore cannot advance the sequence and
/// the publication boundary withholds the changed mesh for up to a whole
/// `FERRUM_K8S_WATCH_IDLE_RELIST_SECS` window — a mesh config outage on a
/// single, healthy control-plane replica (the NodeWaypoint eBPF live suite saw
/// ~350 s of ambient proxies serving a pre-workload slice).
///
/// A withheld publication therefore REQUESTS convergence evidence, and a
/// requested refresh must start a new generation promptly — well inside the
/// idle window — while still proving the same thing the idle relist proves:
/// the boundary is read before the list and adopted only at `InitDone`.
#[tokio::test(start_paused = true)]
async fn a_withheld_publication_can_refresh_evidence_without_waiting_for_the_idle_window() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (harness, task) = k8s_scope(2, vec![Some(1_000), Some(7_000)], shutdown_rx);
    let watcher = tokio::spawn(task);
    let settle = Duration::from_millis(50);

    harness.emit(0, Event::Init);
    let edge = harness.object_at("alpha", "edge", "900");
    harness.emit(0, Event::InitApply(edge));
    harness.emit(0, Event::InitDone);
    tokio::time::sleep(settle).await;
    assert_eq!(harness.revision_watermark().await, Some(1_000));

    // Script the replacement generation up front. It cannot be consumed until a
    // new generation actually starts, so it doubles as the observable for
    // whether one did.
    harness.emit(1, Event::Init);
    let relisted = harness.object_at("alpha", "relisted", "6500");
    harness.emit(1, Event::InitApply(relisted));
    harness.emit(1, Event::InitDone);

    // Far short of the idle window: with no request, nothing relists and the
    // quiet scope keeps pinning the watermark.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        harness.revision_watermark().await,
        Some(1_000),
        "no relist without a request — this is the stall the repair addresses"
    );
    assert_eq!(harness.visible_names().await, vec!["edge".to_string()]);

    harness.request_evidence_refresh();
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert_eq!(
        harness.revision_watermark().await,
        Some(7_000),
        "the requested generation read a fresh boundary and adopted it at InitDone"
    );
    assert_eq!(
        harness.visible_names().await,
        vec!["relisted".to_string()],
        "still make-before-break: the replacement store is swapped in whole"
    );
    assert_eq!(
        harness.publish_revision().await,
        Some(MeshConfigRevision::new("k8s", 7_000)),
        "the sequence can now advance, so the withheld mesh is released"
    );
    assert_eq!(harness.revision_stats().evidence_refresh_requests, 1);
    assert_eq!(harness.revision_stats().unparsable_resource_versions, 0);
    assert_eq!(
        harness.watch_idle_relists(),
        0,
        "a demand-driven evidence refresh must not be reported as an idle relist"
    );

    let _ = shutdown_tx.send(true);
    let _ = watcher.await;
}

// ── issue #4812: the proxy-runtime verdict reaches the status-report path ──
//
// The control plane's slice-drift surface used to ACK at install time only, so
// a data plane whose runtime refused a slice still read as `converged`. These
// contracts pin the data-plane half: the runtime verdict is published on a
// bounded side channel, bound to the version it judged, and observable by the
// configuration consumer that has to report it.

/// A runtime ACCEPTANCE is published by the single commit point every accepting
/// path funnels through, so no apply stage can forget to report success.
#[test]
fn recording_an_applied_slice_publishes_an_applied_runtime_verdict() {
    let state = MeshRuntimeState::new();
    let mut verdicts = state.subscribe_runtime_verdict();
    assert!(
        verdicts.borrow_and_update().is_none(),
        "a fresh subscriber starts with no verdict to replay"
    );

    let slice = MeshSlice {
        version: "v1".to_string(),
        ..MeshSlice::default()
    };
    state.install_slice(slice.clone());
    let token = state.begin_revision_apply(&slice);
    state.record_applied_slice_with_token(&slice, token);

    assert!(verdicts.has_changed().expect("publisher is alive"));
    let verdict = verdicts
        .borrow_and_update()
        .clone()
        .expect("an applied slice publishes a verdict");
    assert_eq!(verdict.version, "v1");
    assert_eq!(verdict.outcome, MeshSliceRuntimeOutcome::Applied);
    assert!(verdict.outcome.accepted());
    assert!(verdict.outcome.reject_reason().is_none());
}

/// A runtime REFUSAL carries a closed, non-sensitive reason category bound to
/// the exact version it judged — that binding is what stops a late verdict from
/// being reported against a newer generation.
#[test]
fn a_runtime_refusal_publishes_a_bounded_reason_bound_to_its_version() {
    let state = MeshRuntimeState::new();
    let mut verdicts = state.subscribe_runtime_verdict();

    state.publish_runtime_verdict(
        "v2",
        MeshSliceRuntimeOutcome::Rejected(MeshSliceRuntimeRejectReason::ProxyRefused),
    );

    let verdict = verdicts
        .borrow_and_update()
        .clone()
        .expect("a refusal publishes a verdict");
    assert_eq!(verdict.version, "v2");
    assert!(!verdict.outcome.accepted());
    let reason = verdict.outcome.reject_reason().expect("reason category");
    assert_eq!(reason.as_metric_label(), "runtime_proxy_refused");
    for reason in [
        MeshSliceRuntimeRejectReason::ConfigBuild,
        MeshSliceRuntimeRejectReason::ProxyRefused,
        MeshSliceRuntimeRejectReason::TrustUnusable,
        MeshSliceRuntimeRejectReason::TlsReload,
        MeshSliceRuntimeRejectReason::DtlsCandidate,
    ] {
        assert!(reason.as_metric_label().is_ascii());
        assert!(reason.as_metric_label().len() < 64);
    }
}

/// The channel is a single slot, not a queue: a superseded verdict is replaced
/// rather than retained, so a flapping control plane cannot grow data-plane
/// state or add work to the request path. The consumer always observes the
/// latest verdict.
#[test]
fn runtime_verdicts_supersede_rather_than_queue() {
    let state = MeshRuntimeState::new();
    let mut verdicts = state.subscribe_runtime_verdict();

    state.publish_runtime_verdict(
        "v1",
        MeshSliceRuntimeOutcome::Rejected(MeshSliceRuntimeRejectReason::ConfigBuild),
    );
    state.publish_runtime_verdict("v2", MeshSliceRuntimeOutcome::Applied);

    let verdict = verdicts
        .borrow_and_update()
        .clone()
        .expect("latest verdict");
    assert_eq!(verdict.version, "v2");
    assert_eq!(verdict.outcome, MeshSliceRuntimeOutcome::Applied);
    assert!(
        !verdicts.has_changed().expect("publisher is alive"),
        "the slot holds exactly one verdict, not a backlog"
    );
}

/// A subscriber attaching after a verdict was published starts clean: a new
/// MeshSubscribe stream must never report a verdict for a slice a previous
/// stream delivered.
#[test]
fn a_new_subscriber_does_not_replay_an_earlier_verdict() {
    let state = MeshRuntimeState::new();
    state.publish_runtime_verdict("v1", MeshSliceRuntimeOutcome::Applied);

    let mut verdicts = state.subscribe_runtime_verdict();
    assert!(
        !verdicts.has_changed().expect("publisher is alive"),
        "the pre-existing verdict is marked seen at subscribe time"
    );

    state.publish_runtime_verdict("v2", MeshSliceRuntimeOutcome::Applied);
    assert!(verdicts.has_changed().expect("publisher is alive"));
    assert_eq!(
        verdicts
            .borrow_and_update()
            .clone()
            .expect("verdict")
            .version,
        "v2"
    );
}
