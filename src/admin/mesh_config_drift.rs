//! Response builder for `GET /mesh/config-drift` (MESH-T6-C).
//!
//! The admin endpoint surfaces a DP-local "have we drifted behind the CP?"
//! view. Because the CP→DP gRPC stream is one-way (DPs cannot synchronously
//! query the CP's latest published slice from the DP side), drift here means:
//!
//!   - When did this DP last install a slice? Compared across DPs, a
//!     significantly older `last_received_at` flags a DP that is missing
//!     updates the others received.
//!   - What's the stable content fingerprint of the slice? Two DPs in the
//!     same namespace expecting the same slice should produce the same
//!     fingerprint; divergence flags split brain.
//!   - What does the RTDS overlay carry? PR #883 ships overlay knobs (fault
//!     injection percentages, log level, transformer gates) without a fresh
//!     slice version, so the overlay needs its own surface.
//!
//! Cross-checking the DP's view against the CP's "latest published" notion
//! (Option B in the plan) is a follow-on — that needs a CP-side endpoint
//! or external tooling to walk DPs in parallel.
//!
//! See [docs/mesh.md](../../../docs/mesh.md) "Config drift introspection"
//! for the operator playbook.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::modes::mesh::config::MeshRuntimeOverlay;
use crate::modes::mesh::revision::MeshRevisionDiagnostics;
use crate::modes::mesh::runtime::XdsConvergenceSnapshot;
use crate::modes::mesh::slice::MeshSlice;

/// Per-resource-kind counts shipped on the `slice.resources` block. Each
/// field corresponds to a `Vec` on [`MeshSlice`] so operators can spot the
/// kind that drifted (e.g. "we lost all our DestinationRules").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshResourceCounts {
    pub workloads: usize,
    pub services: usize,
    pub mesh_policies: usize,
    pub peer_authentications: usize,
    pub service_entries: usize,
    pub request_authentications: usize,
    pub destination_rules: usize,
    pub virtual_service_cors_policies: usize,
    pub mesh_telemetry: usize,
    pub mesh_proxy_configs: usize,
    pub extension_configs: usize,
}

impl MeshResourceCounts {
    /// Build a counts block from a slice, naming each field after the slice
    /// `Vec` it shadows so a translation drift (slice field rename / split)
    /// is caught at compile time.
    pub fn from_slice(slice: &MeshSlice) -> Self {
        Self {
            workloads: slice.workloads.len(),
            services: slice.services.len(),
            mesh_policies: slice.mesh_policies.len(),
            peer_authentications: slice.peer_authentications.len(),
            service_entries: slice.service_entries.len(),
            request_authentications: slice.request_authentications.len(),
            destination_rules: slice.destination_rules.len(),
            virtual_service_cors_policies: slice.virtual_service_cors_policies.len(),
            mesh_telemetry: slice.telemetry_resources.len(),
            mesh_proxy_configs: slice.proxy_configs.len(),
            extension_configs: slice.extension_configs.len(),
        }
    }
}

/// Slice-block surface returned by `/mesh/config-drift`.
///
/// `last_received_at` and `age_seconds` are derived from
/// [`crate::modes::mesh::runtime::MeshRuntimeState::last_applied_at`]
/// rather than from any in-slice timestamp, because slices don't carry an
/// accepted-by-proxy-runtime wall-clock — only a CP-generated `version` string.
#[derive(Debug, Clone, Serialize)]
pub struct MeshSliceDriftView {
    /// Wall-clock timestamp of the most recent slice accepted by the proxy
    /// runtime. `None` when no slice has been accepted yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_received_at: Option<DateTime<Utc>>,
    /// `now - last_received_at` in seconds. `None` when `last_received_at`
    /// is `None`. Operators alert on this exceeding a threshold (typically
    /// 2-3× `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
    /// CP-generated slice version string. Stable across no-op republishes
    /// (the CP can re-stamp this on every push or only on content change —
    /// the drift signal is the fingerprint, not the version).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Slice's `namespace` field (always present when a slice has been
    /// accepted). Surfaced here as well so the response is self-describing
    /// for cross-DP comparison without a separate `/cluster` call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Per-resource-kind counts. Defaults to all zeros when no slice has
    /// been accepted so the shape is stable for dashboards.
    pub resources: MeshResourceCounts,
    /// Stable content hash of the accepted slice. Two DPs in the same
    /// namespace with the same hash agree on every byte. Format:
    /// `sha256-<64 lowercase hex chars>`. `None` when no slice is
    /// accepted. The hash is computed over the slice serialized as
    /// canonical JSON (BTreeMap-ordered keys, `version` and
    /// `MeshRuntimeOverlay` fields stripped — drift in the overlay surfaces
    /// under `runtime_overlay`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Configured mesh config source: `native` (Ferrum MeshSubscribe) or
    /// `xds` (Envoy ADS). Read from `FERRUM_MESH_CONFIG_PROTOCOL`. Passed
    /// in by the handler rather than derived from the slice so the field
    /// is populated even when no slice has been accepted.
    pub source_protocol: String,
    /// First configured CP URL (priority 0). Empty string when none is
    /// configured (test or detached runs). Listed individually rather than
    /// as a `Vec` so the field's shape stays stable on the wire; the full
    /// list is on the operator's env.
    pub source_cp_url: String,
}

/// Runtime overlay summary on `/mesh/config-drift`. Distinct from the full
/// `/mesh/runtime-overlay` payload — this one is a compact "is anything
/// overlay-driven?" view, with key names included so operators can see
/// which knobs are live without correlating to the dashboards.
#[derive(Debug, Clone, Serialize)]
pub struct MeshRuntimeOverlayDriftView {
    /// Number of overlay keys currently in effect.
    pub key_count: usize,
    /// Sorted list of overlay keys. Always sorted so two DPs with the same
    /// overlay produce byte-identical responses and split-brain diffs are
    /// trivial.
    pub keys: Vec<String>,
    /// Stable hash of the full typed overlay values. The key list is useful for
    /// quick inspection, while this catches same-key/different-value RTDS drift.
    pub fingerprint: String,
}

impl MeshRuntimeOverlayDriftView {
    pub fn from_overlay(overlay: &MeshRuntimeOverlay) -> Self {
        let mut keys: Vec<String> = overlay.fields.keys().cloned().collect();
        keys.sort();
        let fingerprint = fingerprint_value(
            serde_json::to_value(&overlay.fields)
                .unwrap_or_else(|err| Value::String(format!("serialization-error:{err}"))),
        );
        Self {
            key_count: keys.len(),
            keys,
            fingerprint,
        }
    }
}

/// Top-level response shape. The handler in `admin/mod.rs` is a thin
/// wrapper that builds this struct and serializes it.
#[derive(Debug, Clone, Serialize)]
pub struct MeshConfigDriftResponse {
    pub slice: MeshSliceDriftView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_overlay: Option<MeshRuntimeOverlayDriftView>,
    /// xDS resource-warming convergence (per-type `version_info`, still-missing
    /// required types, `converged`/`version_skew` flags). Present only in xDS
    /// mode after the first ADS response; omitted in native mode. Surfaced here
    /// (JWT-authenticated) rather than on `/metrics` because the per-type
    /// version strings embed config-change timestamps and content digests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence: Option<XdsConvergenceSnapshot>,
    /// Authoritative config-revision state (issue #2473): the accepted
    /// `(authority, sequence)`, the most recent quarantine (stale fallback,
    /// foreign authority, or missing revision), and the counters behind them.
    ///
    /// JWT-authenticated by construction — this block carries CP-supplied
    /// authority strings and sequence numbers, which is exactly why they stay
    /// off the unauthenticated `/metrics` surface (that gets only the
    /// fixed-cardinality `ferrum_mesh_config_revision_rejections_total{reason}`
    /// counter).
    pub revision: MeshRevisionDiagnostics,
}

/// Inputs for the response builder. Kept as a struct so the unit tests
/// can stage state without touching `MeshRuntimeState`'s ArcSwap
/// internals, and so the handler in `admin/mod.rs` is one
/// `MeshConfigDriftInputs { ... }` literal away from a JSON response.
pub struct MeshConfigDriftInputs<'a> {
    /// `None` when no slice has been accepted yet — produces a `slice`
    /// block with `resources: 0`, `last_received_at: None`, etc.
    pub slice: Option<&'a MeshSlice>,
    /// Most recent slice-install timestamp from
    /// [`crate::modes::mesh::runtime::MeshRuntimeState::last_applied_at`].
    pub last_install_at: Option<DateTime<Utc>>,
    /// Wall-clock "now" used to compute `age_seconds`. Injected so unit
    /// tests are deterministic.
    pub now: DateTime<Utc>,
    /// Operator-configured mesh source protocol from
    /// `FERRUM_MESH_CONFIG_PROTOCOL`.
    pub source_protocol: &'a str,
    /// First configured CP URL (priority 0) or empty when none. Borrowed
    /// from the runtime; the handler does not need to allocate.
    pub source_cp_url: &'a str,
    /// When `true`, include the `runtime_overlay` block. When `false`,
    /// the block is omitted regardless of slice content.
    pub include_overlay: bool,
    /// xDS warming-convergence snapshot from
    /// [`crate::modes::mesh::runtime::MeshRuntimeState::xds_convergence`].
    /// `None` in native mode / before the first ADS response — the
    /// `convergence` block is then omitted from the response.
    pub convergence: Option<Arc<XdsConvergenceSnapshot>>,
    /// Config-revision diagnostics from
    /// [`crate::modes::mesh::runtime::MeshRuntimeState::revision_diagnostics`].
    pub revision: MeshRevisionDiagnostics,
}

/// Build the response from staged inputs. Pure function — no I/O, no
/// allocation beyond the JSON-bearing fields, no clock reads. Unit-tested
/// directly to lock down the shape.
pub fn build_response(inputs: MeshConfigDriftInputs<'_>) -> MeshConfigDriftResponse {
    let (last_received_at, age_seconds) = inputs.last_install_at.map_or((None, None), |ts| {
        // `signed_duration_since` returns a `chrono::Duration`. Clamp the
        // signed seconds to a non-negative `u64`: a slice accepted in the
        // future (clock skew on the gRPC sender) maps to `0` rather than a
        // huge underflow.
        let seconds = inputs.now.signed_duration_since(ts).num_seconds().max(0) as u64;
        (Some(ts), Some(seconds))
    });

    let slice_view = match inputs.slice {
        Some(slice) => MeshSliceDriftView {
            last_received_at,
            age_seconds,
            version: Some(slice.version.clone()),
            namespace: Some(slice.namespace.clone()),
            resources: MeshResourceCounts::from_slice(slice),
            fingerprint: Some(fingerprint(slice)),
            source_protocol: inputs.source_protocol.to_string(),
            source_cp_url: inputs.source_cp_url.to_string(),
        },
        None => MeshSliceDriftView {
            last_received_at,
            age_seconds,
            version: None,
            namespace: None,
            resources: MeshResourceCounts::default(),
            fingerprint: None,
            source_protocol: inputs.source_protocol.to_string(),
            source_cp_url: inputs.source_cp_url.to_string(),
        },
    };

    let overlay_view = if inputs.include_overlay {
        inputs
            .slice
            .map(|slice| MeshRuntimeOverlayDriftView::from_overlay(&slice.runtime_overlay))
    } else {
        None
    };

    MeshConfigDriftResponse {
        slice: slice_view,
        runtime_overlay: overlay_view,
        convergence: inputs.convergence.map(|snapshot| snapshot.as_ref().clone()),
        revision: inputs.revision,
    }
}

/// Parse the optional `?include_overlay=...` query param. Defaults to
/// `true` per the plan so the most useful payload requires no client-side
/// opt-in. Any non-`true`/`false` value falls back to the default — admin
/// query parsing should not 400 on a typo, the overlay block is cheap.
pub fn parse_include_overlay(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == "include_overlay"
        {
            return match val {
                "true" | "1" => true,
                "false" | "0" => false,
                // Tolerate operator typos — the default-on shape is the
                // safer call than rejecting the request.
                _ => true,
            };
        }
    }
    true
}

/// Stable content fingerprint over the slice excluding `version` and
/// `runtime_overlay`.
///
/// Two DPs in the same namespace expecting the same slice produce the
/// same fingerprint. Per-DP identity/projection metadata is stripped because
/// node IDs, workload identities, waypoint names, and labels can differ across
/// DPs that otherwise agree on the accepted resources. The transport version
/// is stripped because CPs may re-stamp no-op publishes, and the overlay is
/// stripped because RTDS-driven knobs (fault injection percentages, log level)
/// intentionally hot-swap without a new slice version — drift in the overlay
/// surfaces under `runtime_overlay` instead.
///
/// Algorithm: SHA-256 over a canonical JSON encoding (recursively
/// `BTreeMap`-sorted keys, preserving array order — slices are
/// translator-built and order is significant). Output is
/// `sha256-<64 lowercase hex chars>`.
///
/// Determinism: `serde_json::to_value` is used to round-trip into
/// `Value`, which is then walked through `canonical_json_value` to swap
/// every `Map` for a `BTreeMap` of sorted keys before the final
/// `to_string`. `serde_json::Map` is not sorted by default, so a direct
/// `to_string` on the slice would produce different bytes depending on
/// insertion order across runs.
fn fingerprint(slice: &MeshSlice) -> String {
    let mut value = match serde_json::to_value(slice) {
        Ok(value) => value,
        Err(err) => {
            // `serde_json::to_value` only fails on map-key types that are
            // not strings; every map in `MeshSlice` is keyed by `String`.
            // Fall back to a recognisable sentinel rather than
            // `.unwrap()`-ing on the hot-path-adjacent admin handler.
            return format!("sha256-error-{}", hex_digest(err.to_string().as_bytes()));
        }
    };
    if let Value::Object(map) = &mut value {
        // Strip transport/runtime fields that legitimately vary per DP or
        // publish even when the effective accepted resources are identical.
        map.remove("node_id");
        map.remove("workload_spiffe_id");
        map.remove("waypoint_name");
        map.remove("labels");
        map.remove("version");
        map.remove("runtime_overlay");
    }
    fingerprint_value(value)
}

fn fingerprint_value(value: Value) -> String {
    let canonical = canonical_json_value(value);
    let serialized = canonical.to_string();
    format!("sha256-{}", hex_digest(serialized.as_bytes()))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Recursively rewrite `serde_json::Value::Object` maps as a `BTreeMap`-backed
/// `Map` so `Value::to_string()` produces a key-sorted, deterministic byte
/// stream. Array order is preserved (slice translation emits ordered arrays;
/// re-sorting them here would hide real drift).
fn canonical_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, canonical_json_value(v)))
                .collect();
            let mut canonical = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                canonical.insert(k, v);
            }
            Value::Object(canonical)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonical_json_value).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{
        FractionalPercentDenominator, MeshPolicy, PolicyScope, RuntimeFractionalPercent,
        RuntimeValue,
    };
    use crate::modes::mesh::slice::MeshSlice;
    use chrono::TimeZone;
    use std::collections::HashMap;

    fn test_revision_diagnostics() -> MeshRevisionDiagnostics {
        MeshRevisionDiagnostics {
            accepted: None,
            applied: None,
            quarantined: None,
            rejected_total: 0,
            adopted_total: 0,
            foreign_authority_adopt_secs: 300,
            quarantine_active: false,
        }
    }

    fn install_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 18, 19, 32, 11).unwrap()
    }

    fn now_after_install(seconds: i64) -> DateTime<Utc> {
        install_time() + chrono::Duration::seconds(seconds)
    }

    fn slice_with(namespace: &str, version: &str) -> MeshSlice {
        MeshSlice {
            namespace: namespace.to_string(),
            version: version.to_string(),
            mesh_policies: vec![MeshPolicy {
                name: "deny-all".to_string(),
                namespace: namespace.to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![],
            }],
            ..MeshSlice::default()
        }
    }

    fn overlay_with_one_key() -> MeshRuntimeOverlay {
        let mut fields = HashMap::new();
        fields.insert(
            "ferrum.log.level".to_string(),
            RuntimeValue::String("warn".to_string()),
        );
        fields.insert(
            "ferrum.fault.sample".to_string(),
            RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
                numerator: 25,
                denominator: FractionalPercentDenominator::Hundred,
            }),
        );
        MeshRuntimeOverlay { fields }
    }

    #[test]
    fn build_response_empty_when_no_slice_installed() {
        let resp = build_response(MeshConfigDriftInputs {
            slice: None,
            last_install_at: None,
            now: install_time(),
            source_protocol: "native",
            source_cp_url: "grpc://cp.local:50051",
            include_overlay: true,
            convergence: None,
            revision: test_revision_diagnostics(),
        });

        assert!(resp.slice.last_received_at.is_none());
        assert!(resp.slice.age_seconds.is_none());
        assert!(resp.slice.version.is_none());
        assert!(resp.slice.namespace.is_none());
        assert!(resp.slice.fingerprint.is_none());
        assert_eq!(resp.slice.resources, MeshResourceCounts::default());
        assert_eq!(resp.slice.source_protocol, "native");
        assert_eq!(resp.slice.source_cp_url, "grpc://cp.local:50051");
        // No slice means no overlay surface even when `include_overlay=true`.
        assert!(resp.runtime_overlay.is_none());
    }

    #[test]
    fn build_response_populates_counts_and_fingerprint() {
        let mut slice = slice_with("alpha", "v1");
        slice.runtime_overlay = overlay_with_one_key();
        let resp = build_response(MeshConfigDriftInputs {
            slice: Some(&slice),
            last_install_at: Some(install_time()),
            now: now_after_install(45),
            source_protocol: "xds",
            source_cp_url: "grpcs://cp.svc:50051",
            include_overlay: true,
            convergence: None,
            revision: test_revision_diagnostics(),
        });

        assert_eq!(resp.slice.namespace.as_deref(), Some("alpha"));
        assert_eq!(resp.slice.version.as_deref(), Some("v1"));
        assert_eq!(resp.slice.age_seconds, Some(45));
        assert_eq!(resp.slice.last_received_at, Some(install_time()));
        assert_eq!(resp.slice.resources.mesh_policies, 1);
        assert_eq!(resp.slice.resources.services, 0);
        let fp = resp.slice.fingerprint.as_deref().expect("fingerprint set");
        assert!(fp.starts_with("sha256-"), "fingerprint prefix: {fp}");
        assert_eq!(fp.len(), "sha256-".len() + 64);

        let overlay = resp.runtime_overlay.as_ref().expect("overlay present");
        assert_eq!(overlay.key_count, 2);
        // Sorted-keys contract — `ferrum.fault.sample` < `ferrum.log.level`.
        assert_eq!(overlay.keys[0], "ferrum.fault.sample");
        assert_eq!(overlay.keys[1], "ferrum.log.level");
        assert!(overlay.fingerprint.starts_with("sha256-"));
        assert_eq!(overlay.fingerprint.len(), "sha256-".len() + 64);
    }

    #[test]
    fn fingerprint_strips_runtime_overlay() {
        // Two slices with identical resources but different overlays must
        // produce the same fingerprint, because overlay drift is surfaced
        // separately under `runtime_overlay`. Without this guarantee, every
        // RTDS layer update would invalidate the per-DP fingerprint and
        // operators couldn't tell content drift apart from knob drift.
        let mut a = slice_with("alpha", "v1");
        let mut b = slice_with("alpha", "v1");
        a.runtime_overlay = overlay_with_one_key();
        b.runtime_overlay = MeshRuntimeOverlay::default();

        let fp_a = fingerprint(&a);
        let fp_b = fingerprint(&b);
        assert_eq!(fp_a, fp_b);
    }

    #[test]
    fn fingerprint_strips_transport_version() {
        let mut a = slice_with("alpha", "v1");
        let mut b = slice_with("alpha", "v2");
        a.runtime_overlay = overlay_with_one_key();
        b.runtime_overlay = overlay_with_one_key();

        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_strips_per_dp_identity_metadata() {
        let mut a = slice_with("alpha", "v1");
        a.node_id = "dp-a".to_string();
        a.workload_spiffe_id = Some("spiffe://cluster.local/ns/alpha/sa/api-a".to_string());
        a.waypoint_name = Some("waypoint-a".to_string());
        a.labels.insert("app".to_string(), "api-a".to_string());

        let mut b = slice_with("alpha", "v1");
        b.node_id = "dp-b".to_string();
        b.workload_spiffe_id = Some("spiffe://cluster.local/ns/alpha/sa/api-b".to_string());
        b.waypoint_name = Some("waypoint-b".to_string());
        b.labels.insert("app".to_string(), "api-b".to_string());

        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn overlay_fingerprint_changes_when_values_differ() {
        let mut a = overlay_with_one_key();
        let mut b = overlay_with_one_key();
        b.fields.insert(
            "ferrum.log.level".to_string(),
            RuntimeValue::String("debug".to_string()),
        );

        let fp_a = MeshRuntimeOverlayDriftView::from_overlay(&a).fingerprint;
        let fp_b = MeshRuntimeOverlayDriftView::from_overlay(&b).fingerprint;
        assert_ne!(fp_a, fp_b);

        a.fields.clear();
        b.fields.clear();
        assert_eq!(
            MeshRuntimeOverlayDriftView::from_overlay(&a).fingerprint,
            MeshRuntimeOverlayDriftView::from_overlay(&b).fingerprint
        );
    }

    #[test]
    fn fingerprint_differs_when_resources_differ() {
        // A second MeshPolicy with a different name must change the
        // fingerprint — this is the actual drift signal.
        let a = slice_with("alpha", "v1");
        let mut b = a.clone();
        b.mesh_policies.push(MeshPolicy {
            name: "allow-foo".to_string(),
            namespace: "alpha".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![],
        });
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_is_deterministic_across_runs() {
        // Repeated fingerprint calls on the same slice must produce the
        // same byte string. Without `canonical_json_value` the underlying
        // `serde_json::Map` (`IndexMap`) is insertion-ordered, which makes
        // serialized output non-deterministic for structs whose serde
        // output goes through `Map`s in non-trivial order.
        let slice = slice_with("alpha", "v1");
        assert_eq!(fingerprint(&slice), fingerprint(&slice));
    }

    #[test]
    fn include_overlay_false_omits_block() {
        let slice = slice_with("alpha", "v1");
        let resp = build_response(MeshConfigDriftInputs {
            slice: Some(&slice),
            last_install_at: Some(install_time()),
            now: now_after_install(5),
            source_protocol: "native",
            source_cp_url: "",
            include_overlay: false,
            convergence: None,
            revision: test_revision_diagnostics(),
        });
        assert!(resp.runtime_overlay.is_none());
        // Slice block is still populated — the overlay flag only gates
        // the secondary block.
        assert!(resp.slice.fingerprint.is_some());
    }

    #[test]
    fn empty_overlay_still_serializes_as_block_when_included() {
        // Slice accepted with no RTDS layers — overlay key map empty.
        // The block should still appear (with `key_count: 0`, `keys: []`)
        // so dashboards can distinguish "no slice yet" (block absent)
        // from "slice but no overlay layers" (block present, empty).
        let slice = slice_with("alpha", "v1");
        let resp = build_response(MeshConfigDriftInputs {
            slice: Some(&slice),
            last_install_at: Some(install_time()),
            now: now_after_install(0),
            source_protocol: "native",
            source_cp_url: "",
            include_overlay: true,
            convergence: None,
            revision: test_revision_diagnostics(),
        });
        let overlay = resp
            .runtime_overlay
            .as_ref()
            .expect("overlay block present");
        assert_eq!(overlay.key_count, 0);
        assert!(overlay.keys.is_empty());
        assert!(overlay.fingerprint.starts_with("sha256-"));
    }

    #[test]
    fn future_install_timestamps_clamp_age_to_zero() {
        // Clock skew on the gRPC sender could push `last_install_at` past
        // `now`; without clamping, the unsigned cast underflows to a huge
        // number that would page operators.
        let slice = slice_with("alpha", "v1");
        let resp = build_response(MeshConfigDriftInputs {
            slice: Some(&slice),
            last_install_at: Some(install_time()),
            now: install_time() - chrono::Duration::seconds(10),
            source_protocol: "native",
            source_cp_url: "",
            include_overlay: true,
            convergence: None,
            revision: test_revision_diagnostics(),
        });
        assert_eq!(resp.slice.age_seconds, Some(0));
    }

    #[test]
    fn parse_include_overlay_defaults_true() {
        assert!(parse_include_overlay(None));
        assert!(parse_include_overlay(Some("")));
        assert!(parse_include_overlay(Some("foo=bar")));
    }

    #[test]
    fn parse_include_overlay_honors_explicit_values() {
        assert!(parse_include_overlay(Some("include_overlay=true")));
        assert!(parse_include_overlay(Some("include_overlay=1")));
        assert!(!parse_include_overlay(Some("include_overlay=false")));
        assert!(!parse_include_overlay(Some("include_overlay=0")));
        // Unknown values fall back to default (true) rather than 400ing.
        assert!(parse_include_overlay(Some("include_overlay=maybe")));
        // Last value wins per query-string convention — but our naive
        // parser returns the first match, which is the documented
        // behaviour. Lock it down so a refactor doesn't silently flip it.
        assert!(!parse_include_overlay(Some(
            "include_overlay=false&include_overlay=true"
        )));
    }

    #[test]
    fn convergence_block_included_when_provided() {
        let slice = slice_with("alpha", "v1");
        let snapshot = XdsConvergenceSnapshot {
            per_type_versions: BTreeMap::from([
                ("cds".to_string(), "v1".to_string()),
                ("ecds".to_string(), "v2".to_string()),
            ]),
            missing_required_types: Vec::new(),
            converged: true,
            version_skew: true,
        };
        let resp = build_response(MeshConfigDriftInputs {
            slice: Some(&slice),
            last_install_at: Some(install_time()),
            now: now_after_install(1),
            source_protocol: "xds",
            source_cp_url: "",
            include_overlay: false,
            convergence: Some(Arc::new(snapshot)),
            revision: test_revision_diagnostics(),
        });

        let convergence = resp.convergence.expect("convergence block present");
        assert!(convergence.converged);
        assert!(convergence.version_skew);
        assert!(convergence.missing_required_types.is_empty());
        assert_eq!(
            convergence
                .per_type_versions
                .get("ecds")
                .map(String::as_str),
            Some("v2")
        );
    }

    #[test]
    fn convergence_block_omitted_when_absent() {
        // Native mode (no xDS convergence) → the block is omitted entirely, not
        // serialized as null, so dashboards can distinguish xDS from native DPs.
        let slice = slice_with("alpha", "v1");
        let resp = build_response(MeshConfigDriftInputs {
            slice: Some(&slice),
            last_install_at: Some(install_time()),
            now: now_after_install(1),
            source_protocol: "native",
            source_cp_url: "",
            include_overlay: false,
            convergence: None,
            revision: test_revision_diagnostics(),
        });
        assert!(resp.convergence.is_none());
        let value = serde_json::to_value(&resp).expect("serialize");
        assert!(
            value.get("convergence").is_none(),
            "convergence key must be absent when None"
        );
    }
}
