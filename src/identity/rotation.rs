//! SVID rotation timing helpers.
//!
//! The internal mesh CA's rotation loop
//! (`run_internal_mesh_svid_rotation_loop` in `src/modes/mesh/mod.rs`) uses
//! these to decide when the current [`SvidBundle`] has crossed its rotation
//! threshold and how long to sleep before checking again. The **SPIRE-agent
//! flow** uses [`crate::identity::workload_api::fetch_loop`] instead: the
//! agent handles rotation and pushes new SVIDs through its streaming RPC.

use crate::time_compat::UtcTimestamp;
use std::time::Duration;
use x509_parser::prelude::*;

use crate::identity::SvidBundle;

/// Minimum interval between rotation checks. Even when an SVID has only
/// seconds left to live we don't want to busy-loop.
const MIN_TICK: Duration = Duration::from_secs(5);
/// Maximum interval between rotation checks. Long-lived SVIDs (24h) get
/// re-checked once per minute to handle clock-skew gracefully.
const MAX_TICK: Duration = Duration::from_secs(60);

/// Inspect the leaf certificate of a bundle and decide how long to sleep
/// before checking rotation again. The result is bounded by
/// [`MIN_TICK`]/[`MAX_TICK`].
pub fn decide_next_tick(bundle: &SvidBundle, rotate_at_fraction: f64) -> Duration {
    let (not_before, not_after) = match leaf_validity(bundle) {
        Some(v) => v,
        None => return MIN_TICK,
    };
    let Some(rotate_at) = rotation_threshold(not_before, not_after, rotate_at_fraction) else {
        return MIN_TICK;
    };
    let until_rotate = (rotate_at - UtcTimestamp::now()).whole_seconds();
    let next_tick = if until_rotate <= 0 {
        MIN_TICK
    } else {
        Duration::from_secs(until_rotate as u64)
    };
    next_tick.clamp(MIN_TICK, MAX_TICK)
}

/// `true` iff the bundle's leaf is past its rotation threshold.
pub fn is_due_for_rotation(bundle: &SvidBundle, rotate_at_fraction: f64) -> bool {
    let (not_before, not_after) = match leaf_validity(bundle) {
        Some(v) => v,
        None => return true,
    };
    let Some(rotate_at) = rotation_threshold(not_before, not_after, rotate_at_fraction) else {
        // An unrepresentable threshold cannot be waited out: rotate now.
        return true;
    };
    UtcTimestamp::now() >= rotate_at
}

/// `not_before + (not_after - not_before) * rotate_at_fraction`, in whole
/// seconds like the previous chrono arithmetic. `None` only where that
/// arithmetic would have panicked (a threshold outside the supported range).
fn rotation_threshold(
    not_before: UtcTimestamp,
    not_after: UtcTimestamp,
    rotate_at_fraction: f64,
) -> Option<UtcTimestamp> {
    let total = (not_after - not_before).whole_seconds().max(1);
    let offset =
        crate::time_compat::chrono_try_seconds((total as f64 * rotate_at_fraction) as i64)?;
    not_before.checked_add(offset)
}

fn leaf_validity(bundle: &SvidBundle) -> Option<(UtcTimestamp, UtcTimestamp)> {
    let leaf = bundle.cert_chain_der.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf).ok()?;
    let validity = parsed.validity();
    let not_before = UtcTimestamp::from_unix_timestamp(validity.not_before.timestamp()).ok()?;
    let not_after = UtcTimestamp::from_unix_timestamp(validity.not_after.timestamp()).ok()?;
    Some((not_before, not_after))
}
