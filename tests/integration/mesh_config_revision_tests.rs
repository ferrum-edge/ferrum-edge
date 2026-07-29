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

use ferrum_edge::config::db_backend::FullConfigLoadPurpose;
use ferrum_edge::config::types::{Consumer, GatewayConfig};
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::grpc::dp_client::GrpcJwtSecret;
use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::modes::control_plane::{
    CpFullLoadSource, load_full_config_multi_with_sequence_for_test,
};
use ferrum_edge::modes::mesh::config_consumer::native_client::{
    NativeMeshClientConfig, NativeMeshConfigConsumer, start_native_mesh_client_with_shutdown,
};
use ferrum_edge::modes::mesh::config_consumer::update_validation::{
    MeshUpdateConsumer, MeshUpdateExpectation, MeshUpdateRejectReason, validate_mesh_config_update,
};
use ferrum_edge::modes::mesh::config_consumer::xds_client::{XdsClientConfig, XdsConfigConsumer};
use ferrum_edge::modes::mesh::revision::{
    MeshConfigRevision, MeshRevisionGate, MeshRevisionOrder, MeshRevisionPolicy,
    MeshRevisionRejectReason,
};
use ferrum_edge::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;

const NODE_ID: &str = "dp-node-a";
const NAMESPACE: &str = "alpha";
const JWT_SECRET: &str = "mesh-config-revision-secret-00000000";

// ── Fixtures ───────────────────────────────────────────────────────────────

fn revision(authority: &str, sequence: u64) -> MeshConfigRevision {
    MeshConfigRevision::new(authority, sequence)
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
        gate.admit(None, now),
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
        let rejection = gate.admit(Some(&forged), now).unwrap_err();
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

    gate.admit(Some(&revision("db", u64::MAX - 1)), now)
        .expect("the penultimate sequence establishes the baseline");
    assert_eq!(
        gate.admit(Some(&revision("db", u64::MAX)), now),
        Ok(MeshRevisionOrder::Newer)
    );
    assert_eq!(
        gate.admit(Some(&revision("db", u64::MAX)), now),
        Ok(MeshRevisionOrder::Same),
        "a replay at the maximum sequence remains installable"
    );
    assert_eq!(
        gate.admit(Some(&revision("db", u64::MAX - 1)), now)
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

    gate.admit(Some(&revision("db", 100)), now)
        .expect("bootstrap installs");

    let rejection = gate
        .admit(Some(&revision("db", 99)), now)
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
    gate.admit(Some(&revision("db", 98)), now)
        .expect_err("still stale");
    let diagnostics = gate.diagnostics();
    assert!(diagnostics.quarantine_active);
    assert_eq!(diagnostics.rejected_total, 2);
    let quarantined = diagnostics.quarantined.expect("quarantine recorded");
    assert_eq!(quarantined.reason, "stale_revision");

    // Failback: the primary catches up and installs, clearing the quarantine.
    gate.admit(Some(&revision("db", 101)), now)
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

    gate.admit(Some(&revision("db", 100)), t0)
        .expect("bootstrap installs");

    let rejection = gate
        .admit_at(Some(&revision("db-restored", 1)), t0, monotonic_t0)
        .expect_err("a foreign authority is quarantined on first sight");
    assert_eq!(
        rejection.reason(),
        MeshRevisionRejectReason::IncomparableAuthority
    );

    // Still inside the grace window.
    gate.admit_at(
        Some(&revision("db-restored", 2)),
        t0 + chrono::Duration::days(30),
        monotonic_t0 + std::time::Duration::from_secs(299),
    )
    .expect_err("a forward wall-clock jump cannot expire the monotonic grace window");
    assert_eq!(gate.accepted().map(|r| r.authority), Some("db".to_string()));

    // A DIFFERENT foreign authority restarts the observation window, so a
    // flapping set of foreign CPs cannot accumulate grace.
    gate.admit_at(
        Some(&revision("db-other", 7)),
        t0 + chrono::Duration::seconds(300),
        monotonic_t0 + std::time::Duration::from_secs(300),
    )
    .expect_err("a different foreign authority restarts the window");
    gate.admit_at(
        Some(&revision("db-restored", 3)),
        t0 + chrono::Duration::seconds(301),
        monotonic_t0 + std::time::Duration::from_secs(301),
    )
    .expect_err("the original foreign authority also restarts its window");

    let order = gate
        .admit_at(
            Some(&revision("db-restored", 4)),
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

    gate.admit(Some(&revision("db", 100)), t0)
        .expect("bootstrap installs");
    gate.admit(
        Some(&revision("db-restored", 1)),
        t0 + chrono::Duration::days(30),
    )
    .expect_err("adoption disabled: a foreign authority stays quarantined forever");

    // A sequence rewind INSIDE one authority is never auto-adopted, however
    // long it persists — it is indistinguishable from the rollback the gate
    // exists to prevent.
    gate.set_policy(MeshRevisionPolicy {
        foreign_authority_adopt_secs: 1,
    });
    gate.admit(Some(&revision("db", 5)), t0 + chrono::Duration::days(60))
        .expect_err("a same-authority rewind is never auto-adopted");

    // The operator reset clears the accepted revision, and the next slice from
    // any authority establishes a new baseline.
    let cleared = gate.reset().expect("the accepted revision is returned");
    assert_eq!(cleared, revision("db", 100));
    assert!(gate.diagnostics().quarantined.is_none());
    gate.admit(Some(&revision("db", 5)), t0 + chrono::Duration::days(61))
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

/// Full-load revision stamping is scope-domained (issue #2473):
/// - Explicit Single/Set: max of scoped namespace cursors (same domain incremental
///   polling advances). An unrelated namespace's global sequence must not make a
///   restarted replica jump ahead of its identical running peer.
/// - All: store-global high-water mark so a deleted namespace cannot rewind a
///   restarted CP. In-process floor is preserved for both.
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
        12,
        "Set-scope full load uses max of explicit namespace cursors only"
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
// (`install_slice` → `record_applied_slice` / `record_rejected_slice`) that the
// mesh apply loop uses, rather than `MeshRevisionGate::admit` in isolation,
// because the defect they cover lives in the relationship between the two
// gates and not in the comparison contract.

/// `record_applied_slice` fans the accepted slice's (here empty) runtime
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
    state.record_applied_slice(&applied);
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
    state.record_applied_slice(&recovery);
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
    state.record_applied_slice(&applied);

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
    state.record_applied_slice(&recovery);
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
    state.record_applied_slice(&first);

    let replay = slice_at("v-10-replay", Some(revision("db", 10)));
    assert!(
        state.install_slice(replay.clone()).installed(),
        "an equal revision MUST install — every ordinary reconnect replays one"
    );
    state.record_applied_slice(&replay);
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

/// The operator reset clears the APPLIED watermark as well. Leaving it would
/// let the next runtime-refused candidate roll the gate straight back onto the
/// generation the operator just released, silently undoing the reset.
#[test]
fn reset_clears_the_applied_watermark_so_a_rejection_cannot_resurrect_it() {
    let _overlay_guard = overlay_consumer_guard();
    let state = MeshRuntimeState::new();
    let applied = slice_at("v-10", Some(revision("db", 10)));
    assert!(state.install_slice(applied.clone()).installed());
    state.record_applied_slice(&applied);

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
    state.record_applied_slice(&applied);

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
    state.record_applied_slice(&applied);

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
