//! Bounded per-data-plane mesh-slice convergence state (issue #3265).
//!
//! The control plane tracks desired/published, sent, acknowledged/applied, and
//! rejected slice versions per authenticated mesh identity (`node_id`). State
//! survives disconnects for a documented retention window so reconnecting DPs
//! do not look brand-new, and identity count / reason length are hard-capped so
//! hostile peers cannot grow memory or `/metrics` cardinality.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Hard ceiling on retained mesh identities (connected + retained).
pub const MESH_SLICE_CONVERGENCE_MAX_IDENTITIES: usize = 4096;

/// Maximum retained rejection-reason bytes after redaction.
pub const MESH_SLICE_CONVERGENCE_MAX_REASON_BYTES: usize = 128;

/// Maximum retained version-string bytes.
pub const MESH_SLICE_CONVERGENCE_MAX_VERSION_BYTES: usize = 128;

/// How long convergence state survives after a MeshSubscribe stream drops.
///
/// Online registry entries are removed immediately on stream drop; this tracker
/// keeps the last desired/sent/ack/reject metadata for reconnect correlation.
/// Fifteen minutes covers ordinary reconnect/backoff windows without retaining
/// abandoned identities indefinitely.
pub const MESH_SLICE_CONVERGENCE_RETENTION_SECS: i64 = 900;

/// Outcome of a DP status report against the exact last-sent version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSliceStatusOutcome {
    Applied,
    Rejected,
    /// Report named a version that is not the current sent version.
    StaleVersion,
    /// No sent version exists for this identity (forged / never published).
    UnknownVersion,
    /// Identity is not tracked (evicted or never subscribed).
    UnknownIdentity,
    /// Identity subject did not match the authenticated JWT `sub`.
    IdentityMismatch,
}

impl MeshSliceStatusOutcome {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::StaleVersion => "stale_version",
            Self::UnknownVersion => "unknown_version",
            Self::UnknownIdentity => "unknown_identity",
            Self::IdentityMismatch => "identity_mismatch",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MeshSliceConvergenceSnapshot {
    pub node_id: String,
    pub namespace: String,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_at: Option<DateTime<Utc>>,
    pub desired_age_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<DateTime<Utc>>,
    pub sent_age_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_age_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<DateTime<Utc>>,
    pub rejected_age_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_reason: Option<String>,
    /// True when an acknowledgement matches the last sent version.
    pub converged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_deadline_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct MeshSliceConvergenceEntry {
    namespace: String,
    connected: bool,
    connected_generation: u64,
    desired_version: Option<String>,
    desired_at: Option<DateTime<Utc>>,
    sent_version: Option<String>,
    sent_at: Option<DateTime<Utc>>,
    acknowledged_version: Option<String>,
    acknowledged_at: Option<DateTime<Utc>>,
    rejected_version: Option<String>,
    rejected_at: Option<DateTime<Utc>>,
    rejected_reason: Option<String>,
    last_activity_at: DateTime<Utc>,
    disconnected_at: Option<DateTime<Utc>>,
}

impl MeshSliceConvergenceEntry {
    fn new(namespace: String, now: DateTime<Utc>, generation: u64) -> Self {
        Self {
            namespace,
            connected: true,
            connected_generation: generation,
            desired_version: None,
            desired_at: None,
            sent_version: None,
            sent_at: None,
            acknowledged_version: None,
            acknowledged_at: None,
            rejected_version: None,
            rejected_at: None,
            rejected_reason: None,
            last_activity_at: now,
            disconnected_at: None,
        }
    }

    fn to_snapshot(&self, node_id: &str, now: DateTime<Utc>) -> MeshSliceConvergenceSnapshot {
        let retention_deadline_at = self
            .disconnected_at
            .map(|at| at + chrono::Duration::seconds(MESH_SLICE_CONVERGENCE_RETENTION_SECS));
        let converged = match (
            self.sent_version.as_deref(),
            self.acknowledged_version.as_deref(),
        ) {
            (Some(sent), Some(acked)) => sent == acked,
            _ => false,
        };
        MeshSliceConvergenceSnapshot {
            node_id: node_id.to_string(),
            namespace: self.namespace.clone(),
            connected: self.connected,
            desired_version: self.desired_version.clone(),
            desired_at: self.desired_at,
            desired_age_seconds: age_seconds(self.desired_at, now),
            sent_version: self.sent_version.clone(),
            sent_at: self.sent_at,
            sent_age_seconds: age_seconds(self.sent_at, now),
            acknowledged_version: self.acknowledged_version.clone(),
            acknowledged_at: self.acknowledged_at,
            acknowledged_age_seconds: age_seconds(self.acknowledged_at, now),
            rejected_version: self.rejected_version.clone(),
            rejected_at: self.rejected_at,
            rejected_age_seconds: age_seconds(self.rejected_at, now),
            rejected_reason: self.rejected_reason.clone(),
            converged,
            disconnected_at: self.disconnected_at,
            retention_deadline_at,
        }
    }
}

/// Per-identity mesh-slice convergence tracker.
#[derive(Default)]
pub struct MeshSliceConvergenceTracker {
    entries: DashMap<String, MeshSliceConvergenceEntry>,
    published_version: std::sync::RwLock<Option<String>>,
    published_at: std::sync::RwLock<Option<DateTime<Utc>>>,
    generation: AtomicU64,
}

impl MeshSliceConvergenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Latest CP-wide published mesh config version (observability stamp).
    pub fn published_version(&self) -> Option<String> {
        self.published_version
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub fn published_at(&self) -> Option<DateTime<Utc>> {
        self.published_at.read().ok().and_then(|guard| *guard)
    }

    fn publish_gauges(&self) {
        crate::plugins::mesh::prometheus_helpers::set_mesh_slice_convergence_gauges(
            self.entries.len() as u64,
            self.diverged_count(),
        );
    }

    /// Record a CP config publish and advance desired versions for all tracked
    /// identities (connected and retained). Does not advance `sent`.
    pub fn note_published(&self, version: &str, now: DateTime<Utc>) {
        let version = bound_version(version);
        if let Ok(mut guard) = self.published_version.write() {
            *guard = Some(version.clone());
        }
        if let Ok(mut guard) = self.published_at.write() {
            *guard = Some(now);
        }
        for mut entry in self.entries.iter_mut() {
            entry.desired_version = Some(version.clone());
            entry.desired_at = Some(now);
            entry.last_activity_at = now;
        }
        self.publish_gauges();
    }

    /// Register or refresh a connected MeshSubscribe identity.
    ///
    /// Returns `false` when the identity could not be admitted under the
    /// cardinality ceiling (no retained victim to evict).
    pub fn note_connected(&self, node_id: &str, namespace: &str, now: DateTime<Utc>) -> bool {
        let node_id = node_id.trim();
        if node_id.is_empty() {
            return false;
        }
        if let Some(mut entry) = self.entries.get_mut(node_id) {
            let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
            entry.namespace = namespace.to_string();
            entry.connected = true;
            entry.connected_generation = generation;
            entry.disconnected_at = None;
            entry.last_activity_at = now;
            drop(entry);
            self.publish_gauges();
            return true;
        }
        if self.entries.len() >= MESH_SLICE_CONVERGENCE_MAX_IDENTITIES
            && !self.evict_one_for_capacity(now)
        {
            return false;
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.entries.insert(
            node_id.to_string(),
            MeshSliceConvergenceEntry::new(namespace.to_string(), now, generation),
        );
        self.publish_gauges();
        true
    }

    /// Mark a stream generation disconnected. Retains metadata until TTL.
    pub fn note_disconnected(
        &self,
        node_id: &str,
        expected_generation: Option<u64>,
        now: DateTime<Utc>,
    ) {
        let Some(mut entry) = self.entries.get_mut(node_id) else {
            return;
        };
        if let Some(expected) = expected_generation
            && entry.connected_generation != expected
        {
            return;
        }
        entry.connected = false;
        entry.disconnected_at = Some(now);
        entry.last_activity_at = now;
        drop(entry);
        self.publish_gauges();
    }

    /// Current connected generation for `node_id`, if tracked and online.
    pub fn connected_generation(&self, node_id: &str) -> Option<u64> {
        self.entries.get(node_id).and_then(|entry| {
            if entry.connected {
                Some(entry.connected_generation)
            } else {
                None
            }
        })
    }

    /// Record that a non-heartbeat slice frame was handed to a DP stream.
    pub fn note_sent(&self, node_id: &str, version: &str, now: DateTime<Utc>) {
        let Some(mut entry) = self.entries.get_mut(node_id) else {
            return;
        };
        let version = bound_version(version);
        entry.desired_version = Some(version.clone());
        entry.desired_at = Some(now);
        entry.sent_version = Some(version);
        entry.sent_at = Some(now);
        entry.last_activity_at = now;
        drop(entry);
        self.publish_gauges();
    }

    /// Record an applied/rejected report bound to authenticated identity and
    /// the exact last-sent version.
    pub fn note_status_report(
        &self,
        authenticated_subject: &str,
        node_id: &str,
        version: &str,
        rejected_reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> MeshSliceStatusOutcome {
        if authenticated_subject != node_id {
            return MeshSliceStatusOutcome::IdentityMismatch;
        }
        let Some(mut entry) = self.entries.get_mut(node_id) else {
            return MeshSliceStatusOutcome::UnknownIdentity;
        };
        let Some(sent) = entry.sent_version.as_deref() else {
            return MeshSliceStatusOutcome::UnknownVersion;
        };
        if sent != version {
            return MeshSliceStatusOutcome::StaleVersion;
        }
        entry.last_activity_at = now;
        let outcome = match rejected_reason {
            None => {
                entry.acknowledged_version = Some(bound_version(version));
                entry.acknowledged_at = Some(now);
                // A successful apply clears the last rejection for this version.
                if entry.rejected_version.as_deref() == Some(version) {
                    entry.rejected_version = None;
                    entry.rejected_at = None;
                    entry.rejected_reason = None;
                }
                MeshSliceStatusOutcome::Applied
            }
            Some(reason) => {
                entry.rejected_version = Some(bound_version(version));
                entry.rejected_at = Some(now);
                entry.rejected_reason = Some(redact_reason(reason));
                MeshSliceStatusOutcome::Rejected
            }
        };
        drop(entry);
        self.publish_gauges();
        outcome
    }

    /// Drop identities whose disconnect retention window has elapsed.
    pub fn reap_expired(&self, now: DateTime<Utc>) -> usize {
        let ttl = chrono::Duration::seconds(MESH_SLICE_CONVERGENCE_RETENTION_SECS);
        let mut removed = 0usize;
        self.entries.retain(|_, entry| {
            if entry.connected {
                return true;
            }
            let Some(disconnected_at) = entry.disconnected_at else {
                return true;
            };
            let keep = now - disconnected_at < ttl;
            if !keep {
                removed += 1;
            }
            keep
        });
        if removed > 0 {
            self.publish_gauges();
        }
        removed
    }

    pub fn snapshot(&self, now: DateTime<Utc>) -> Vec<MeshSliceConvergenceSnapshot> {
        let mut out: Vec<_> = self
            .entries
            .iter()
            .map(|entry| entry.value().to_snapshot(entry.key(), now))
            .collect();
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        out
    }

    pub fn snapshot_for(&self, node_id: &str, now: DateTime<Utc>) -> Option<MeshSliceConvergenceSnapshot> {
        self.entries
            .get(node_id)
            .map(|entry| entry.value().to_snapshot(node_id, now))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn diverged_count(&self) -> u64 {
        self.entries
            .iter()
            .filter(|entry| {
                let sent = entry.sent_version.as_deref();
                let acked = entry.acknowledged_version.as_deref();
                match (sent, acked) {
                    (Some(s), Some(a)) => s != a,
                    (Some(_), None) => true,
                    _ => false,
                }
            })
            .count() as u64
    }

    fn evict_one_for_capacity(&self, now: DateTime<Utc>) -> bool {
        // Prefer expired retained entries, then oldest disconnected, then oldest
        // overall by last activity. Never panic; return false if empty.
        let _ = self.reap_expired(now);
        if self.entries.len() < MESH_SLICE_CONVERGENCE_MAX_IDENTITIES {
            return true;
        }

        let mut best: Option<(String, DateTime<Utc>, u8)> = None;
        for entry in self.entries.iter() {
            let rank = if entry.connected {
                2u8
            } else if entry.disconnected_at.is_some() {
                0u8
            } else {
                1u8
            };
            let activity = entry.last_activity_at;
            let replace = match &best {
                None => true,
                Some((_, best_activity, best_rank)) => {
                    rank < *best_rank || (rank == *best_rank && activity < *best_activity)
                }
            };
            if replace {
                best = Some((entry.key().clone(), activity, rank));
            }
        }
        if let Some((node_id, _, _)) = best {
            self.entries.remove(&node_id);
            true
        } else {
            false
        }
    }
}

fn age_seconds(at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> u64 {
    let Some(at) = at else {
        return 0;
    };
    let delta = now.signed_duration_since(at);
    if delta.num_seconds() <= 0 {
        0
    } else {
        delta.num_seconds() as u64
    }
}

fn bound_version(version: &str) -> String {
    truncate_control_stripped(version, MESH_SLICE_CONVERGENCE_MAX_VERSION_BYTES)
}

fn redact_reason(reason: &str) -> String {
    truncate_control_stripped(reason, MESH_SLICE_CONVERGENCE_MAX_REASON_BYTES)
}

fn truncate_control_stripped(input: &str, max_bytes: usize) -> String {
    let stripped: String = input
        .chars()
        .filter(|ch| !ch.is_control())
        .collect();
    if stripped.len() <= max_bytes {
        return stripped;
    }
    let mut end = max_bytes;
    while end > 0 && !stripped.is_char_boundary(end) {
        end -= 1;
    }
    stripped[..end].to_string()
}
