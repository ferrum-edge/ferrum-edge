//! Issue #2409: a DNS-01 hook must not outlive the renewal claim it runs under.
//!
//! `RenewalLeaseKeeper::guarded` cancels by dropping the future it was handed.
//! For an in-process future that is enough. For a DNS-01 provider hook it is
//! not: the hook is a *child process*, and a dropped future does not by itself
//! stop one. That matters because the hook's entire job is to publish or
//! retract `_acme-challenge` records, and the instance that took the claim over
//! is relying on exactly those records — a surviving child can retract them
//! after takeover, which is precisely the failure the lease exists to prevent.
//!
//! These tests exercise the real pair: a real lease table, a real
//! `RenewalLeaseKeeper` heartbeat, and a real hook process whose only
//! observable is a file it creates *after* a delay. The claim is lost while the
//! hook is mid-flight, and the assertion is that the marker never appears.
//!
//! Unix-only, because the hook is a shell script with a shebang. The behaviour
//! under test (`kill_on_drop` on the direct child) is not platform-specific;
//! the fixture is.

#![cfg(all(feature = "acme", unix))]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::tls::acme::{AcmeDns01ChallengeRecord, run_dns01_hook_for_tests};
use ferrum_edge::tls::lease::{RenewalLeaseKeeper, TlsLeaseStore, acme_renewal_lease_name};

/// How long the hook runs before producing its side effect. Long enough that a
/// cancellation landing anywhere in the first second still precedes it.
const HOOK_DELAY_SECONDS: u64 = 6;

/// A challenge record with no real material in it. The hook never inspects the
/// values; it only needs to be handed something well formed.
fn challenge() -> AcmeDns01ChallengeRecord {
    AcmeDns01ChallengeRecord {
        identifier: "example.test".to_string(),
        token: "test-token".to_string(),
        key_authorization: "test-token.test-thumbprint".to_string(),
    }
}

/// Write an executable hook that sleeps and *then* creates `marker`.
///
/// The marker is the side effect under test: if it exists, the hook ran to
/// completion. Its path is baked into the script rather than passed through the
/// environment, because Ferrum controls the hook's environment and the test
/// must not depend on adding to it.
fn write_delayed_hook(dir: &Path, marker: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = dir.join("dns01-hook.sh");
    let body = format!(
        "#!/bin/sh\nsleep {HOOK_DELAY_SECONDS}\n: > '{}'\n",
        marker.display()
    );
    std::fs::write(&script, body).expect("write hook script");
    let mut permissions = std::fs::metadata(&script)
        .expect("stat hook script")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&script, permissions).expect("make hook script executable");
    script
}

/// Make the shared lease table unreadable so the next heartbeat fails closed.
///
/// This is the honest way to force a mid-operation loss without a test-only
/// back door into the keeper: an unparseable shared document is exactly the
/// "ownership can no longer be asserted" condition `heartbeat_loop` treats as
/// loss, and it reaches the keeper through the same published signal a real
/// takeover would. The store's lock is advisory, so a plain write races
/// nothing that matters here — a writer either parsed the old document already
/// or is about to fail on this one.
fn break_the_lease_table(dir: &Path) {
    std::fs::write(dir.join("tls-leases.json"), b"{ not json").expect("corrupt the lease table");
}

/// The hook's side effect must not land after the claim is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns01_hook_cannot_complete_after_the_renewal_claim_is_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("hook-completed.marker");
    let hook = write_delayed_hook(dir.path(), &marker);

    let store = Arc::new(
        TlsLeaseStore::open_with_holder(dir.path(), "instance-a".to_string())
            .expect("open lease store"),
    );
    let name = acme_renewal_lease_name("cert-under-renewal");
    let guard = store
        .try_acquire(&name, Duration::from_secs(2))
        .expect("acquire must not error")
        .expect("an unclaimed lease must be acquirable");
    let keeper = RenewalLeaseKeeper::start(guard, Duration::from_secs(2));

    // Start the hook under the claim, then take the claim away from underneath
    // it while it is still sleeping.
    let hook_command = hook.to_string_lossy().to_string();
    let challenge = challenge();
    let guarded = keeper.guarded(run_dns01_hook_for_tests(
        &hook_command,
        "present",
        &challenge,
    ));

    break_the_lease_table(dir.path());

    let outcome = guarded.await;
    assert!(
        outcome.is_err(),
        "a lost claim must cancel the hook rather than returning its result"
    );

    // The hook was still sleeping when it was cancelled. Wait past the point at
    // which it would have produced its side effect had it survived.
    tokio::time::sleep(Duration::from_secs(HOOK_DELAY_SECONDS + 2)).await;
    assert!(
        !marker.exists(),
        "a cancelled DNS-01 hook must not perform its side effect after the claim was lost"
    );

    drop(keeper);
}

/// The same guarantee for an ordinary cancellation: dropping the hook future
/// kills the child, whether or not a lease was involved.
///
/// Separate from the lease test on purpose — this is the primitive
/// (`kill_on_drop`) the lease guarantee is built on, and pinning it directly
/// means a regression is attributed to the process handling rather than to the
/// lease machinery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_dns01_hook_future_terminates_the_child() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("hook-completed.marker");
    let hook = write_delayed_hook(dir.path(), &marker);
    let hook_command = hook.to_string_lossy().to_string();
    let challenge = challenge();

    {
        let running = run_dns01_hook_for_tests(&hook_command, "cleanup", &challenge);
        tokio::pin!(running);
        // Poll it once so the child is actually spawned, then drop it.
        let started = tokio::time::timeout(Duration::from_millis(250), &mut running).await;
        assert!(
            started.is_err(),
            "the delayed hook must still be running when it is cancelled"
        );
    }

    tokio::time::sleep(Duration::from_secs(HOOK_DELAY_SECONDS + 2)).await;
    assert!(
        !marker.exists(),
        "a dropped DNS-01 hook future must not leave a child that completes its side effect"
    );
}
