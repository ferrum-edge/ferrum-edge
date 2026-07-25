//! External regression coverage for DTLS demux identity-aware session removal
//! (issue #2959).
//!
//! A stale generation-1 cleanup for a peer address must not evict a newer
//! generation-2 live session inserted at that same address. Counters must stay
//! balanced when the stale path no-ops and when the matching path wins once.

#[test]
fn dtls_stale_generation_cleanup_cannot_remove_newer_session() {
    ferrum_edge::_test_support::dtls_stale_session_removal_preserves_newer_generation_for_test()
        .expect("generation-1 cleanup must not evict generation-2 demux entry");
}
