//! SVID rotation timing helpers.
//!
//! The internal mesh CA's rotation loop
//! (`run_internal_mesh_svid_rotation_loop` in `src/modes/mesh/mod.rs`) uses
//! these to decide when the current [`SvidBundle`] has crossed its rotation
//! threshold and how long to sleep before checking again. The **SPIRE-agent
//! flow** uses [`crate::identity::workload_api::fetch_loop`] instead: the
//! agent handles rotation and pushes new SVIDs through its streaming RPC.

use chrono::{DateTime, Utc};
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
    let total = (not_after - not_before).num_seconds().max(1);
    let rotate_at =
        not_before + chrono::Duration::seconds((total as f64 * rotate_at_fraction) as i64);
    let now = Utc::now();
    let until_rotate = (rotate_at - now).num_seconds();
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
    let total = (not_after - not_before).num_seconds().max(1);
    let rotate_at =
        not_before + chrono::Duration::seconds((total as f64 * rotate_at_fraction) as i64);
    Utc::now() >= rotate_at
}

fn leaf_validity(bundle: &SvidBundle) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let leaf = bundle.cert_chain_der.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf).ok()?;
    let validity = parsed.validity();
    let not_before = DateTime::<Utc>::from_timestamp(validity.not_before.timestamp(), 0)?;
    let not_after = DateTime::<Utc>::from_timestamp(validity.not_after.timestamp(), 0)?;
    Some((not_before, not_after))
}
