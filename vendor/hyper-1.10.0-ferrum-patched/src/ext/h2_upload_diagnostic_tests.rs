use super::{Counters, H2UploadBranch, Http2UploadDiagnosticSnapshot, Ordering};

#[test]
fn fixed_branches_are_counted_once_and_non_post_is_excluded() {
    let counters = Counters::new();
    for branch in [
        H2UploadBranch::Eos,
        H2UploadBranch::ReadyOk,
        H2UploadBranch::ReadyErr,
        H2UploadBranch::Pending,
    ] {
        counters.record(false, branch);
    }
    assert_eq!(
        counters.snapshot(),
        Http2UploadDiagnosticSnapshot::default()
    );
    for branch in [
        H2UploadBranch::Eos,
        H2UploadBranch::ReadyOk,
        H2UploadBranch::ReadyErr,
        H2UploadBranch::Pending,
    ] {
        counters.record(true, branch);
    }
    let expected = Http2UploadDiagnosticSnapshot {
        post_eos: 1,
        post_ready_ok: 1,
        post_ready_err: 1,
        post_pending: 1,
        overflow: false,
    };
    assert_eq!(counters.snapshot(), expected);
    assert_eq!(counters.snapshot(), expected, "scrapes never reset counts");
}

#[test]
fn overflow_is_sticky_and_invalidates_the_receipt() {
    let counters = Counters::new();
    counters.pending.store(u64::MAX, Ordering::Relaxed);
    counters.record(true, H2UploadBranch::Pending);
    assert!(counters.snapshot().overflow);
    counters.record(true, H2UploadBranch::ReadyOk);
    assert!(counters.snapshot().overflow);
}
