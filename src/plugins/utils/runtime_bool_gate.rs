//! Shared process-global boolean gate storage for RTDS overlay consumers.
//!
//! Plugins own their static store and key namespace, but the cold-path
//! mechanics are identical: rebuild a `HashMap<String, bool>` from a
//! [`MeshRuntimeOverlay`], publish it through `ArcSwap`, and let hot paths read
//! a cheap snapshot.
//!
//! ## Gate provenance
//!
//! A consumer whose gate decision shapes a representation that outlives the
//! request (`response_caching` storing a `response_transformer` output, or
//! `request_deduplication` persisting an idempotent replay) must know which
//! exact publication produced those bytes. The gate map and an opaque
//! [`GatePolicyStamp`] are therefore published together in one ArcSwap state. A
//! reader can never observe a new map paired with an old stamp (or the
//! inverse), and pointer identity cannot collide or wrap like an integer
//! generation counter.
//!
//! The stamp carries two distinct identities for two distinct questions:
//!
//! - [`GatePolicyStamp`] equality is **allocation identity**. Two publications
//!   are never equal, so an in-process consumer that must retire anything
//!   produced before *any* republication (including an A→B→A cycle observed
//!   mid-request) gets a conservative answer.
//! - `GatePolicyStamp::fingerprint` is a **content** digest of the published
//!   map. Two processes that published equivalent gate content derive the same
//!   value, which is what a representation persisted to a shared store
//!   (Redis) must be compared against — a pointer identity is meaningless
//!   outside the process that minted it.

use std::collections::HashMap;
use std::sync::Arc;

use crate::fips::approved::Sha256;
use arc_swap::ArcSwap;

use crate::modes::mesh::config::MeshRuntimeOverlay;

use super::transformer_gate;

pub type BoolGateMap = HashMap<String, bool>;

/// Opaque identity of one atomically published gate-map state.
///
/// The token carries no gate, rule, header, or body content in the clear.
/// Equality uses allocation identity, so two different publications can never
/// compare equal; `fingerprint()` exposes the separate content identity
/// for cross-process provenance.
#[derive(Clone)]
pub struct GatePolicyStamp(Arc<GatePublication>);

#[derive(Debug)]
struct GatePublication {
    fingerprint: [u8; 32],
}

/// Domain separator so a gate-map digest can never collide with an unrelated
/// SHA-256 over similar bytes that is compared in the same provenance record.
const GATE_FINGERPRINT_DOMAIN: &[u8] = b"ferrum.runtime-bool-gate.fingerprint.v1";

impl GatePolicyStamp {
    /// Derive the publication identity for one gate map.
    ///
    /// Scopes are hashed in sorted order with explicit length framing, so the
    /// digest is independent of `HashMap` iteration order (and therefore of the
    /// process-random hash seed) and no scope-name/value pair can be confused
    /// with a different split of the same bytes.
    fn new(gates: &BoolGateMap) -> Self {
        let mut scopes: Vec<&str> = gates.keys().map(String::as_str).collect();
        scopes.sort_unstable();
        let mut digest = Sha256::new();
        digest.update(GATE_FINGERPRINT_DOMAIN);
        digest.update((scopes.len() as u64).to_be_bytes());
        for scope in scopes {
            digest.update((scope.len() as u64).to_be_bytes());
            digest.update(scope.as_bytes());
            // `scopes` is built from `gates`, so the lookup always resolves;
            // a defaulted `false` would still be a well-defined digest input
            // rather than a panic on the cold publication path.
            digest.update([u8::from(gates.get(scope).copied().unwrap_or(false))]);
        }
        Self(Arc::new(GatePublication {
            fingerprint: digest.finalize(),
        }))
    }

    /// Stable, content-only identity suitable for provenance stored outside
    /// this process. It is a fixed-size one-way digest: it reveals no scope
    /// names or gate values, and two processes publishing equivalent gate
    /// content derive the same value.
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.0.fingerprint
    }
}

impl std::fmt::Debug for GatePolicyStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatePolicyStamp(<opaque>)")
    }
}

impl PartialEq for GatePolicyStamp {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for GatePolicyStamp {}

/// One atomically published gate map and its unforgeable publication identity.
pub struct BoolGateState {
    gates: BoolGateMap,
    stamp: GatePolicyStamp,
}

impl BoolGateState {
    fn new(gates: BoolGateMap) -> Self {
        let stamp = GatePolicyStamp::new(&gates);
        Self { gates, stamp }
    }
}

pub type BoolGateStore = ArcSwap<BoolGateState>;

#[derive(Clone)]
pub struct BoolGateSnapshot {
    inner: Arc<BoolGateState>,
}

impl BoolGateSnapshot {
    /// Look up one scope's published gate.
    ///
    /// No plugin phase calls this: a transformer's effective gate is bound into
    /// its configuration on the cold path and resolved at construction
    /// (GHSA-83rc-23c9-3g9x). Retained for the published-state assertions in
    /// `tests/`, which the binary build path does not consume.
    pub fn gate(&self, scope: &str) -> Option<bool> {
        self.inner.gates.get(scope).copied()
    }
}

pub fn new_store() -> BoolGateStore {
    ArcSwap::new(Arc::new(BoolGateState::new(HashMap::new())))
}

pub fn current_snapshot(store: &BoolGateStore) -> BoolGateSnapshot {
    BoolGateSnapshot {
        inner: store.load_full(),
    }
}

/// Return the identity paired atomically with the currently published map.
pub fn current_policy_stamp(store: &BoolGateStore) -> GatePolicyStamp {
    store.load().stamp.clone()
}

/// Publish a rebuilt gate map and a fresh identity in one atomic store.
///
/// Reapplying the identical current map is a no-op, avoiding needless cache
/// invalidation for repeated equivalent RTDS updates. A real A→B→A cycle still
/// receives a fresh *allocation* identity on the final A, so an identity-based
/// consumer conservatively retires entries that survived from the first A. A
/// content-based consumer sees the final A's fingerprint equal the first A's
/// and keeps them, which is correct rather than merely permissive: the retained
/// bytes were produced under gate content identical to the live content, so no
/// transform the live policy requires is being skipped. A cycle observed
/// *within* one request is still a straddle in both models — the pinned
/// identity moved, so that request's output is not persisted at all.
pub fn apply_overlay(
    store: &BoolGateStore,
    overlay: &MeshRuntimeOverlay,
    key_prefix: &str,
    enabled_suffix: &str,
) {
    let mut next = HashMap::new();
    transformer_gate::collect_gates(overlay, key_prefix, enabled_suffix, &mut next);
    if store.load().gates.eq(&next) {
        return;
    }
    store.store(Arc::new(BoolGateState::new(next)));
}

/// Clear a gate store. Already-empty state is left untouched.
pub fn reset(store: &BoolGateStore) {
    if store.load().gates.is_empty() {
        return;
    }
    store.store(Arc::new(BoolGateState::new(HashMap::new())));
}
