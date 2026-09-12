//! Apply-begin capabilities must keep the serving generation as the rollback floor.

use std::io;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use ferrum_edge::modes::mesh::revision::{
    MeshConfigRevision, MeshRevisionContentIdentity, MeshRevisionGate, MeshRevisionOrder,
    MeshRevisionRejectReason,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;
use tracing_subscriber::fmt::MakeWriter;

fn slice(sequence: u64) -> MeshSlice {
    MeshSlice {
        version: format!("v-{sequence}"),
        revision: Some(MeshConfigRevision::new("db", sequence)),
        ..MeshSlice::default()
    }
}

#[derive(Clone, Default)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn missing_token_rejections() -> u64 {
    let mut metrics = String::new();
    render_mesh_observability_metrics(&mut metrics);
    metrics
        .lines()
        .find(|line| {
            line.starts_with("ferrum_mesh_config_revision_rejections_total{")
                && line.contains("reason=\"missing_apply_token\"")
        })
        .map(|line| line.split_whitespace().last().unwrap().parse().unwrap())
        .unwrap_or(0)
}

#[test]
fn initial_apply_commits_its_baseline_after_a_newer_admission() {
    let _overlay_guard = test_lock();
    let state = MeshRuntimeState::new();
    let initial = slice(20);
    assert!(state.install_slice(initial.clone()).installed());
    let token = state.begin_revision_apply(&initial).unwrap();

    // Startup is preparing A when B arrives. Permission was captured for A,
    // so B cannot prevent the generation that starts serving from committing.
    assert!(state.install_slice(slice(30)).installed());
    assert!(state.begin_revision_apply(&initial).is_none());
    assert!(state.record_applied_slice_with_token(&initial, Some(token)));
    assert_eq!(state.applied_revision(), initial.revision);
    assert_eq!(state.accepted_revision(), slice(30).revision);

    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), initial.revision);
    assert_eq!(state.applied_revision(), initial.revision);
    let older = slice(19);
    assert_eq!(
        MeshConfigRevision::compare(state.accepted_revision().as_ref(), older.revision.as_ref()),
        MeshRevisionOrder::Older
    );
    assert_eq!(
        state.install_slice(older).rejection().unwrap().reason(),
        MeshRevisionRejectReason::StaleRevision
    );
}

#[test]
fn a_missing_commit_token_is_loud_and_preserves_the_serving_baseline() {
    let _overlay_guard = test_lock();
    let state = MeshRuntimeState::new();
    let serving = slice(10);
    assert!(state.install_slice(serving.clone()).installed());
    let token = state.begin_revision_apply(&serving).unwrap();
    assert!(state.record_applied_slice_with_token(&serving, Some(token)));

    let candidate = slice(20);
    assert!(state.install_slice(candidate.clone()).installed());
    let token = state.begin_revision_apply(&candidate).unwrap();
    assert!(state.install_slice(slice(30)).installed());
    let late_token = state.begin_revision_apply(&candidate);
    assert!(late_token.is_none());

    let before = missing_token_rejections();
    let writer = LogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        assert!(!state.record_applied_slice_with_token(&candidate, late_token));
    });
    let log = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("ERROR"));
    assert!(log.contains("Mesh revision commit has no apply token"));
    for field in [
        "candidate_revision",
        "accepted_revision",
        "applied_revision",
    ] {
        assert!(log.contains(field), "missing revision identity: {log}");
    }
    assert!(missing_token_rejections() > before);
    assert_eq!(state.applied_revision(), serving.revision);
    assert_eq!(
        state.applied_snapshot().as_ref().as_ref().unwrap().revision,
        serving.revision
    );

    // A subsequent refusal still has a committed rollback target. It must not
    // turn the missing-token error into permission to bootstrap an older slice.
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), serving.revision);
    assert_eq!(
        MeshConfigRevision::compare(
            state.accepted_revision().as_ref(),
            slice(9).revision.as_ref()
        ),
        MeshRevisionOrder::Older
    );

    // The original begin token remains valid even after that rollback. When A
    // actually finishes, both watermarks must cover the generation now serving.
    assert!(state.record_applied_slice_with_token(&candidate, Some(token)));
    assert_eq!(state.applied_revision(), candidate.revision);
    assert_eq!(state.accepted_revision(), candidate.revision);
    assert!(state.install_slice(slice(40)).installed());
    assert!(state.record_rejected_slice(&state.snapshot()));
    assert_eq!(state.accepted_revision(), candidate.revision);
    assert_eq!(state.applied_revision(), candidate.revision);
}

#[test]
fn a_missing_initial_token_cannot_publish_a_serving_snapshot() {
    let state = MeshRuntimeState::new();
    let initial = slice(20);
    assert!(state.install_slice(initial.clone()).installed());
    let updates = state.subscribe_applied();
    assert!(!state.record_applied_slice_with_token(&initial, None));
    assert!(state.applied_snapshot().as_ref().is_none());
    assert!(state.last_applied_at().is_none());
    assert!(!updates.has_changed().unwrap());
    assert_eq!(state.accepted_revision(), initial.revision);
}

#[test]
fn overlay_refresh_permission_binds_the_applied_content_and_respects_reset() {
    let gate = MeshRevisionGate::new();
    let serving = MeshConfigRevision::new("db", 20);
    let pending = MeshConfigRevision::new("db", 30);
    let content = MeshRevisionContentIdentity::from_digest([1; 32]);
    let divergent = MeshRevisionContentIdentity::from_digest([2; 32]);
    gate.admit(Some(&serving), content, Utc::now()).unwrap();
    let token = gate.begin_apply(Some(&serving), content).unwrap();
    assert!(gate.commit_applied(Some(&serving), content, token));
    gate.admit(Some(&pending), divergent, Utc::now()).unwrap();

    assert!(gate.begin_apply(Some(&serving), divergent).is_none());
    let token = gate.begin_apply(Some(&serving), content).unwrap();
    assert!(gate.commit_applied(Some(&serving), content, token));
    assert_eq!(gate.accepted(), Some(pending.clone()));
    assert!(gate.rollback_rejected(Some(&pending), divergent));
    assert_eq!(gate.accepted(), Some(serving.clone()));
    assert_eq!(gate.applied(), Some(serving.clone()));

    // Operator reset is the explicit exception to the serving-baseline rule.
    assert_eq!(gate.reset(), Some(serving.clone()));
    assert!(gate.begin_apply(Some(&serving), content).is_none());
    assert!(!gate.commit_applied(Some(&serving), content, token));
    assert!(gate.applied().is_none());
    assert!(gate.accepted().is_none());
}
