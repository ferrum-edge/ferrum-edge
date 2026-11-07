//! Kernel-free bookkeeping for failed per-pod cgroup program detaches
//! (`AyaEbpfBackend::detach_pod`, #7025), compiled on every host test lane.

use super::*;

#[test]
fn cgroup_path_may_exist_reports_present_and_missing_paths() {
    let root = tempfile::tempdir().unwrap();
    let present = root.path().join("kubepods").join("podpod-uid-1");
    std::fs::create_dir_all(&present).unwrap();
    let missing = root.path().join("kubepods").join("podpod-uid-2");

    assert!(cgroup_path_may_exist(present.to_str().unwrap()));
    assert!(!cgroup_path_may_exist(missing.to_str().unwrap()));
}

#[test]
fn failed_cgroup_detach_is_retained_until_the_cgroup_is_gone() {
    let root = tempfile::tempdir().unwrap();
    let cgroup = root.path().join("kubepods").join("podpod-uid-1");
    std::fs::create_dir_all(&cgroup).unwrap();
    let cgroup_path = cgroup.to_str().unwrap().to_string();

    let mut unconfirmed = UnconfirmedCgroupDetaches::default();
    assert!(unconfirmed.is_empty());

    // A failed detach consumed the link: record it (idempotently per path).
    unconfirmed.record(cgroup_path.clone());
    unconfirmed.record(cgroup_path.clone());
    assert!(!unconfirmed.is_empty());

    // Retry while the cgroup still exists: still an error, still retained,
    // so the pending detach retry cannot succeed vacuously.
    let errors = unconfirmed.recheck(cgroup_path_may_exist);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("earlier detach failed"));
    assert!(!unconfirmed.is_empty());

    // The kernel releases the attachment with the cgroup: the next retry
    // succeeds and nothing is retained.
    std::fs::remove_dir(&cgroup).unwrap();
    assert!(unconfirmed.recheck(cgroup_path_may_exist).is_empty());
    assert!(unconfirmed.is_empty());
}

#[test]
fn recheck_keeps_only_cgroups_that_may_still_exist() {
    let mut unconfirmed = UnconfirmedCgroupDetaches::default();
    unconfirmed.record("/cgroup/gone".to_string());
    unconfirmed.record("/cgroup/live".to_string());

    // Anything not reported gone (including an unreadable path) fails closed.
    let errors = unconfirmed.recheck(|path| path != "/cgroup/gone");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("/cgroup/live"));
    assert!(!unconfirmed.is_empty());

    assert!(unconfirmed.recheck(|_| false).is_empty());
    assert!(unconfirmed.is_empty());
}
