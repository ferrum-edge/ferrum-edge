//! Status sub-resource patcher for Istio CRDs (T2-B).
//!
//! Operators run `kubectl describe authorizationpolicy <name>` (and the
//! sibling commands for `PeerAuthentication` / `DestinationRule`) to see
//! how Ferrum interpreted their policy. Without a `status.conditions[]`
//! block, those commands return only the operator-supplied `spec`, with
//! no visible signal that Ferrum accepted/rejected the policy or what it
//! actually programmed. This module fills that gap.
//!
//! Three CRDs are covered in this PR:
//!
//! - `AuthorizationPolicy` — status confirms `ALLOW` with no rules
//!   compiles to a synthetic never-match rule (Istio allow-nothing
//!   semantics), or that the policy was rejected with a translator error.
//! - `PeerAuthentication` — status confirms the resolved mTLS mode
//!   (UNSET → PERMISSIVE in Istio) and surfaces port-level overrides.
//! - `DestinationRule` — status reports whether the rule's host could be
//!   matched and which `connectionPool` knobs landed vs. were deferred.
//!
//! The other Istio CRDs (`VirtualService`, `ServiceEntry`,
//! `RequestAuthentication`, `Sidecar`, `Telemetry`, `WorkloadEntry`) are
//! deliberately deferred to a follow-on so this PR stays reviewable.
//! Adding them follows the exact same pattern as the three CRDs covered
//! here.
//!
//! ## Subresource availability
//!
//! Istio's own CRD manifests include `subresources: { status: {} }` on the
//! three CRDs above, so `patch_status` works against any standard Istio
//! install. If a cluster has stripped the subresource (rare; usually an
//! intentional admission-policy decision), `patch_status` returns
//! `kube::Error::Api(_)` with `code: 404` — the writer logs a single warn
//! and otherwise no-ops, never panics, never aborts reconcile. The
//! Gateway API path uses the same defensive pattern; see [`status.rs`].
//!
//! ## Field manager
//!
//! All patches use `field_manager = "ferrum.io/istio-controller"` so the
//! Kubernetes API server's server-side-apply conflict detector sees
//! Ferrum as a distinct owner from Istio itself
//! (`istio.io/galley`/`pilot-discovery`) and from any other controller
//! that might write to the same `status.conditions[]` array. JSON Merge
//! Patch (RFC 7396) replaces the whole `conditions[]` array, so the
//! writer reads the live status first and merges its `Ferrum*` condition
//! types into whatever already exists.

use futures_util::future::join_all;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use serde_json::{Value, json};
use tracing::warn;

use crate::config_sources::k8s::{
    K8sObject, K8sTranslateError, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects_with_filter,
};

/// Field manager used on every `patch_status` call. Kubernetes uses this
/// for server-side-apply ownership tracking; distinct from the Gateway API
/// writer's controller name so the two writers can update the same
/// resource without stepping on each other's owned condition types (which
/// also don't overlap by construction).
pub const FERRUM_ISTIO_CONTROLLER_NAME: &str = "ferrum.io/istio-controller";

/// One Istio CRD status patch. Built by [`plan_istio_status_updates`] and
/// applied to the API server by [`IstioStatusWriter::patch_updates`].
#[derive(Debug, Clone, PartialEq)]
pub struct IstioStatusUpdate {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    /// Desired `status` sub-object. The writer extracts
    /// `status.conditions[]` from this and merges it into the live status.
    pub status: Value,
    /// Optional translator detail block. Surfaces as
    /// `status.ferrum.translation = {...}` so operators can grep for it
    /// in `kubectl describe`/`kubectl get -o json`.
    pub ferrum_detail: Option<Value>,
}

#[derive(Clone)]
pub struct IstioStatusWriter {
    client: Client,
}

impl IstioStatusWriter {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Apply each update via `Api::patch_status`. Failures on individual
    /// resources (most commonly: the cluster's CRD definition has no
    /// `status` subresource, or a transient API-server hiccup) are
    /// logged and skipped — they never abort reconcile. Returns the
    /// first error so callers can metric / alert on the failure rate
    /// without losing the rest of the batch.
    pub async fn patch_updates(&self, updates: Vec<IstioStatusUpdate>) -> Result<(), kube::Error> {
        // Take `updates` by value and consume via `into_iter` so the per-
        // update closure / async block owns its `update` rather than
        // capturing `&IstioStatusUpdate`. Otherwise the spawned reconciler
        // future fails rustc's HRTB Send check on `&IstioStatusUpdate`.
        let client = self.client.clone();
        let futures = updates.into_iter().filter_map(move |update| {
            let Some(ar) = istio_api_resource(&update) else {
                warn!(
                    api_version = %update.api_version,
                    kind = %update.kind,
                    namespace = %update.namespace,
                    name = %update.name,
                    "Skipping Istio status update for unsupported resource version"
                );
                return None;
            };
            // All Istio CRDs we patch in this PR are namespaced.
            let api: Api<DynamicObject> =
                Api::namespaced_with(client.clone(), &update.namespace, &ar);
            let name = update.name.clone();
            let kind = update.kind.clone();
            let namespace = update.namespace.clone();
            Some(async move {
                let result = async {
                    let live = api.get_status(&name).await?;
                    let patch = istio_status_patch(&update, live.data.get("status"));
                    // JSON Merge Patch over server-side apply: matches the
                    // Gateway API path. See [`status.rs`] for the SSA TODO.
                    let params = PatchParams {
                        field_manager: Some(FERRUM_ISTIO_CONTROLLER_NAME.to_string()),
                        ..PatchParams::default()
                    };
                    api.patch_status(&name, &params, &Patch::Merge(&patch))
                        .await
                        .map(|_| ())
                }
                .await;
                (kind, namespace, name, result)
            })
        });
        let mut first_error: Option<kube::Error> = None;
        for (kind, namespace, name, result) in join_all(futures).await {
            if let Err(error) = result {
                warn!(
                    %kind,
                    %namespace,
                    %name,
                    error = %error,
                    "Istio status patch failed (CRD may not have a status subresource enabled)"
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Map the update's `apiVersion + kind` onto the [`ApiResource`] that
/// `kube-rs` needs for `Api::namespaced_with`. Returns `None` for
/// unknown versions so the writer can skip them with a warn instead of
/// panicking — the alternative is propagating an `Option<ApiResource>`
/// through the whole pipeline.
fn istio_api_resource(update: &IstioStatusUpdate) -> Option<ApiResource> {
    let (group, version) = update.api_version.split_once('/')?;
    let plural = match (update.kind.as_str(), group, version) {
        ("AuthorizationPolicy", "security.istio.io", _) => "authorizationpolicies",
        ("PeerAuthentication", "security.istio.io", _) => "peerauthentications",
        ("DestinationRule", "networking.istio.io", _) => "destinationrules",
        _ => return None,
    };
    Some(ApiResource {
        group: group.to_string(),
        version: version.to_string(),
        api_version: update.api_version.clone(),
        kind: update.kind.clone(),
        plural: plural.to_string(),
    })
}

/// Plan a batch of [`IstioStatusUpdate`]s for the supported Istio CRDs in
/// `objects`. The plan is computed cheaply over the same `objects` slice
/// the reconciler already snapshotted; each entry re-runs translation
/// filtered to a single object so it can report per-resource accept /
/// reject without re-walking the whole cluster's CRDs.
pub fn plan_istio_status_updates(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> Vec<IstioStatusUpdate> {
    objects
        .iter()
        .filter(|object| is_supported_istio_kind(&object.kind))
        .filter_map(|object| {
            let result = translate_k8s_objects_with_filter(objects, options.clone(), |candidate| {
                same_resource(candidate, object)
                // Translation of any Istio CRD that produces routing
                // resources needs the Service collection so port-name
                // lookups succeed (matches the Gateway API path).
                    || candidate.kind == "Service"
            });
            let (status, ferrum_detail) = match object.kind.as_str() {
                "AuthorizationPolicy" => authorization_policy_status(object, result.as_ref()),
                "PeerAuthentication" => peer_authentication_status(
                    object,
                    result.as_ref(),
                    &options.istio_root_namespace,
                ),
                "DestinationRule" => destination_rule_status(object, result.as_ref()),
                _ => return None,
            };
            if status == object.status && ferrum_detail_matches(&object.status, &ferrum_detail) {
                return None;
            }
            Some(IstioStatusUpdate {
                api_version: object.api_version.clone(),
                kind: object.kind.clone(),
                namespace: object.metadata.namespace.clone(),
                name: object.metadata.name.clone(),
                status,
                ferrum_detail,
            })
        })
        .collect()
}

fn ferrum_detail_matches(status: &Value, desired: &Option<Value>) -> bool {
    desired
        .as_ref()
        .is_none_or(|detail| status.get("ferrum") == Some(detail))
}

fn is_supported_istio_kind(kind: &str) -> bool {
    matches!(
        kind,
        "AuthorizationPolicy" | "PeerAuthentication" | "DestinationRule"
    )
}

fn same_resource(left: &K8sObject, right: &K8sObject) -> bool {
    left.api_version == right.api_version
        && left.kind == right.kind
        && left.metadata.namespace == right.metadata.namespace
        && left.metadata.name == right.metadata.name
}

/// Build the final `status` sub-object to PATCH onto an Istio CRD.
///
/// The Istio CRDs' `status` is freeform — Istio writes
/// `status.observedGeneration` and `status.validationMessages[]`. We
/// stamp our own `status.conditions[]` (K8s standard `Condition` shape)
/// next to whatever Istio wrote, plus a `status.ferrum.translation`
/// block carrying translator detail. The live status is merged
/// condition-by-condition so we don't clobber Istio's own fields.
fn istio_status_patch(update: &IstioStatusUpdate, live_status: Option<&Value>) -> Value {
    let mut status_patch = serde_json::Map::new();

    // Owned conditions from `update.status`, merged with the live array
    // so we don't accidentally remove or duplicate non-Ferrum-owned
    // conditions.
    let desired_conditions =
        update
            .status
            .get("conditions")
            .and_then(Value::as_array)
            .map(|conditions| {
                conditions
                    .iter()
                    .filter(|condition| {
                        condition.get("type").and_then(Value::as_str).is_some_and(
                            |condition_type| condition_type.starts_with(FERRUM_CONDITION_PREFIX),
                        )
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
    let live_conditions = live_status
        .and_then(|status| status.get("conditions"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let merged = merge_owned_conditions(live_conditions, desired_conditions);
    status_patch.insert("conditions".to_string(), Value::Array(merged));

    if let Some(detail) = &update.ferrum_detail {
        // Pin the Ferrum-specific block under `status.ferrum` so the
        // existing `status` fields Istio writes stay untouched. This is
        // a JSON Merge Patch so `null` would delete; only insert when
        // Some.
        status_patch.insert("ferrum".to_string(), detail.clone());
    }

    let mut patch = serde_json::Map::new();
    patch.insert("status".to_string(), Value::Object(status_patch));
    Value::Object(patch)
}

/// Merge owned (`Ferrum*`) conditions into the live conditions list,
/// preserving any conditions written by other controllers (Istio
/// itself, Gateway API translator, etc.). A condition is considered
/// owned by Ferrum iff its `type` starts with the
/// [`FERRUM_CONDITION_PREFIX`] sentinel.
fn merge_owned_conditions(
    live_conditions: Vec<Value>,
    desired_conditions: Vec<Value>,
) -> Vec<Value> {
    let desired_types: std::collections::HashSet<String> = desired_conditions
        .iter()
        .filter_map(|c| c.get("type").and_then(Value::as_str).map(ToOwned::to_owned))
        .collect();
    let mut merged: Vec<Value> = live_conditions
        .into_iter()
        .filter(|existing| {
            let Some(condition_type) = existing.get("type").and_then(Value::as_str) else {
                // Preserve non-conformant conditions verbatim — they may
                // belong to a controller we don't know about.
                return true;
            };
            if condition_type.starts_with(FERRUM_CONDITION_PREFIX)
                && desired_types.contains(condition_type)
            {
                // Our owned condition: drop the stale copy; the desired
                // replacement is appended below.
                return false;
            }
            true
        })
        .collect();
    merged.extend(desired_conditions);
    merged
}

const FERRUM_CONDITION_PREFIX: &str = "Ferrum";

fn authorization_policy_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
) -> (Value, Option<Value>) {
    let action = object
        .spec
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("ALLOW")
        .to_string();
    let has_rules = object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .is_some_and(|rules| !rules.is_empty());

    let (accepted, reason, message, detail) = match result {
        Ok(_translation) => {
            // T1-A status — translation succeeded. Spell out the
            // Istio-empty-rules semantics so operators know whether
            // their ALLOW with no rules was treated as allow-nothing.
            if action == "ALLOW" && !has_rules {
                let message = "AuthorizationPolicy ALLOW with no rules: \
                    Istio allow-nothing semantics preserved \
                    (synthesised never-match ALLOW rule). \
                    Add `rules:` entries to grant access.";
                let detail = json!({
                    "translation": {
                        "action": action,
                        "rules_translated": 0,
                        "empty_rules_semantics": "allow_nothing",
                    }
                });
                (true, "AllowNothing", message.to_string(), Some(detail))
            } else if (action == "DENY" || action == "AUDIT") && !has_rules {
                // Istio: DENY/AUDIT with no rules is a no-op.
                let message = format!(
                    "{action} AuthorizationPolicy with no rules is a no-op \
                    (Istio semantics). Add `rules:` entries to enforce."
                );
                let detail = json!({
                    "translation": {
                        "action": action,
                        "rules_translated": 0,
                        "empty_rules_semantics": "noop",
                    }
                });
                (true, "NoOp", message, Some(detail))
            } else {
                let rule_count = object
                    .spec
                    .get("rules")
                    .and_then(Value::as_array)
                    .map(|v| v.len())
                    .unwrap_or(0);
                let message =
                    format!("Ferrum accepted this AuthorizationPolicy ({rule_count} rule(s))");
                let detail = json!({
                    "translation": {
                        "action": action,
                        "rules_translated": rule_count,
                    }
                });
                (true, "Accepted", message, Some(detail))
            }
        }
        Err(error) => {
            let message = format!("Ferrum rejected this AuthorizationPolicy: {error}");
            let detail = json!({
                "translation": {
                    "action": action,
                    "error": format!("{error}"),
                }
            });
            (false, "Invalid", message, Some(detail))
        }
    };

    let conditions = vec![condition(
        object,
        Some(&object.status),
        "FerrumAccepted",
        accepted,
        reason,
        &message,
    )];

    let mut status = object.status.clone();
    merge_status_conditions(&mut status, &["FerrumAccepted"], conditions);
    (status, detail)
}

fn peer_authentication_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
    istio_root_namespace: &str,
) -> (Value, Option<Value>) {
    let resolved_mode = object
        .spec
        .get("mtls")
        .and_then(|m| m.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("UNSET")
        .to_string();
    let scope = if object.spec.get("selector").is_some() {
        "WorkloadSelector"
    } else if object.metadata.namespace == istio_root_namespace
        || object.metadata.namespace.is_empty()
    {
        "MeshWide"
    } else {
        "Namespace"
    };
    let port_overrides: Vec<String> = object
        .spec
        .get("portLevelMtls")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(port, value)| {
                    let mode = value.get("mode").and_then(Value::as_str).unwrap_or("UNSET");
                    format!("port {port} -> {mode}")
                })
                .collect()
        })
        .unwrap_or_default();

    let (accepted, reason, message, detail) = match result {
        Ok(_translation) => {
            // T1-A: PeerAuthentication is single-winner per workload
            // (WorkloadSelector > Namespace > MeshWide). Surface the
            // resolved mode so operators can confirm without grepping
            // Ferrum-side state.
            let effective_mode = if resolved_mode == "UNSET" {
                "PERMISSIVE (Istio default for UNSET)"
            } else {
                resolved_mode.as_str()
            };
            let message = format!(
                "Ferrum accepted this PeerAuthentication (scope: {scope}; resolved mTLS mode: {effective_mode})"
            );
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "configured_mtls_mode": resolved_mode,
                    "port_level_overrides": port_overrides,
                }
            });
            (true, "Accepted", message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this PeerAuthentication: {error}");
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "configured_mtls_mode": resolved_mode,
                    "error": format!("{error}"),
                }
            });
            (false, "Invalid", message, Some(detail))
        }
    };

    let conditions = vec![condition(
        object,
        Some(&object.status),
        "FerrumAccepted",
        accepted,
        reason,
        &message,
    )];

    let mut status = object.status.clone();
    merge_status_conditions(&mut status, &["FerrumAccepted"], conditions);
    (status, detail)
}

fn destination_rule_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
) -> (Value, Option<Value>) {
    let host = object
        .spec
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let (accepted, reason, message, detail) = match result {
        Ok(_translation) => {
            // T1-C deferred fields: portLevelSettings.tls (parsed but
            // not enforced), per-subset connectionPool.tcp.connectTimeout,
            // per-subset outlierDetection. Surface them so operators see
            // the gap in `kubectl describe`.
            let mut deferred: Vec<&'static str> = Vec::new();
            if has_port_level_tls(&object.spec) {
                deferred.push("portLevelSettings[].tls (parsed but not enforced)");
            }
            if has_subset_port_overrides(&object.spec) {
                deferred.push("subsets[].trafficPolicy.connectionPool.tcp.connectTimeout");
            }
            if has_subset_outlier_detection(&object.spec) {
                deferred.push("subsets[].trafficPolicy.outlierDetection");
            }
            let message = if deferred.is_empty() {
                format!("Ferrum accepted this DestinationRule (host: {host})")
            } else {
                format!(
                    "Ferrum accepted this DestinationRule (host: {host}); \
                     deferred fields: {}",
                    deferred.join(", ")
                )
            };
            let detail = json!({
                "translation": {
                    "host": host,
                    "subsets_translated": object
                        .spec
                        .get("subsets")
                        .and_then(Value::as_array)
                        .map(|v| v.len())
                        .unwrap_or(0),
                    "deferred_fields": deferred,
                }
            });
            (true, "Accepted", message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this DestinationRule: {error}");
            let detail = json!({
                "translation": {
                    "host": host,
                    "error": format!("{error}"),
                }
            });
            (false, "Invalid", message, Some(detail))
        }
    };

    let conditions = vec![condition(
        object,
        Some(&object.status),
        "FerrumAccepted",
        accepted,
        reason,
        &message,
    )];

    let mut status = object.status.clone();
    merge_status_conditions(&mut status, &["FerrumAccepted"], conditions);
    (status, detail)
}

fn has_port_level_tls(spec: &Value) -> bool {
    spec.get("trafficPolicy")
        .and_then(|tp| tp.get("portLevelSettings"))
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(|e| e.get("tls").is_some()))
}

fn has_subset_port_overrides(spec: &Value) -> bool {
    spec.get("subsets")
        .and_then(Value::as_array)
        .is_some_and(|subsets| {
            subsets.iter().any(|subset| {
                subset
                    .get("trafficPolicy")
                    .and_then(|tp| tp.get("connectionPool"))
                    .and_then(|cp| cp.get("tcp"))
                    .and_then(|tcp| tcp.get("connectTimeout"))
                    .is_some()
            })
        })
}

fn has_subset_outlier_detection(spec: &Value) -> bool {
    spec.get("subsets")
        .and_then(Value::as_array)
        .is_some_and(|subsets| {
            subsets.iter().any(|subset| {
                subset
                    .get("trafficPolicy")
                    .and_then(|tp| tp.get("outlierDetection"))
                    .is_some()
            })
        })
}

/// Build a K8s-standard `Condition` value. Mirrors the shape used by the
/// Gateway API writer (`Accepted`, `Programmed`, etc.) so operators don't
/// have to learn two formats.
fn condition(
    object: &K8sObject,
    existing_status: Option<&Value>,
    condition_type: &str,
    value: bool,
    reason: &str,
    message: &str,
) -> Value {
    let status = if value { "True" } else { "False" };
    let existing_conditions = existing_status
        .and_then(|s| s.get("conditions"))
        .and_then(Value::as_array);
    let last_transition_time = existing_conditions
        .and_then(|conditions| {
            conditions.iter().find(|condition| {
                condition.get("type").and_then(Value::as_str) == Some(condition_type)
            })
        })
        .and_then(|condition| {
            let unchanged = condition.get("status").and_then(Value::as_str) == Some(status)
                && condition.get("reason").and_then(Value::as_str) == Some(reason)
                && condition.get("message").and_then(Value::as_str) == Some(message);
            if unchanged {
                condition
                    .get("lastTransitionTime")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            } else {
                None
            }
        })
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

    let observed_generation = object.metadata.generation.unwrap_or(1);

    json!({
        "type": condition_type,
        "status": status,
        "observedGeneration": observed_generation,
        "reason": reason,
        "message": message,
        "lastTransitionTime": last_transition_time,
    })
}

fn merge_status_conditions(status: &mut Value, owned_types: &[&str], desired: Vec<Value>) {
    if !status.is_object() {
        *status = Value::Object(Default::default());
    }
    let Value::Object(map) = status else {
        unreachable!("normalised above")
    };
    let mut conditions = map
        .get("conditions")
        .and_then(Value::as_array)
        .map(|existing| {
            existing
                .iter()
                .filter(|condition| {
                    let Some(condition_type) = condition.get("type").and_then(Value::as_str) else {
                        return true;
                    };
                    !owned_types.contains(&condition_type)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    conditions.extend(desired);
    map.insert("conditions".to_string(), Value::Array(conditions));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions};
    use crate::identity::spiffe::TrustDomain;
    use serde_json::json;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                namespace: "default".to_string(),
                generation: Some(11),
                labels: Default::default(),
                annotations: Default::default(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec,
            status: Value::Object(Default::default()),
        }
    }

    fn find_condition<'a>(conditions: &'a [Value], condition_type: &str) -> &'a Value {
        conditions
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some(condition_type))
            .unwrap_or_else(|| panic!("missing condition {condition_type}"))
    }

    // ── AuthorizationPolicy ────────────────────────────────────────────────

    #[test]
    fn auth_policy_allow_with_no_rules_reports_allow_nothing() {
        // Istio: ALLOW + no `rules` means allow-nothing. The translator
        // synthesises a never-match rule; status surfaces that to operators.
        let obj = object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "lock-down",
            json!({ "action": "ALLOW" }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        let update = &updates[0];
        let conditions = update.status["conditions"].as_array().unwrap();
        let c = find_condition(conditions, "FerrumAccepted");
        assert_eq!(c["status"].as_str(), Some("True"));
        assert_eq!(c["reason"].as_str(), Some("AllowNothing"));
        assert!(
            c["message"].as_str().unwrap().contains("allow-nothing"),
            "message should explain Istio allow-nothing semantics: {}",
            c["message"]
        );
        let detail = update.ferrum_detail.as_ref().expect("translation detail");
        assert_eq!(detail["translation"]["action"].as_str(), Some("ALLOW"));
        assert_eq!(
            detail["translation"]["empty_rules_semantics"].as_str(),
            Some("allow_nothing")
        );
    }

    #[test]
    fn auth_policy_deny_with_no_rules_reports_noop() {
        let obj = object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "noop-deny",
            json!({ "action": "DENY" }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let conditions = update.status["conditions"].as_array().unwrap();
        let c = find_condition(conditions, "FerrumAccepted");
        assert_eq!(c["reason"].as_str(), Some("NoOp"));
        assert!(c["message"].as_str().unwrap().contains("no-op"));
    }

    #[test]
    fn auth_policy_with_rules_reports_accepted_with_rule_count() {
        let obj = object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "api-rules",
            json!({
                "action": "ALLOW",
                "rules": [
                    { "to": [{ "operation": { "paths": ["/healthz"], "methods": ["GET"] } }] },
                    { "to": [{ "operation": { "paths": ["/api/*"] } }] },
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let c = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        assert_eq!(c["reason"].as_str(), Some("Accepted"));
        let detail = update.ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["rules_translated"].as_u64(), Some(2));
    }

    #[test]
    fn auth_policy_invalid_action_reports_invalid() {
        // The translator rejects `action: HACK` — status should reflect
        // the rejection, not a silent acceptance.
        let obj = object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "bad-action",
            json!({ "action": "HACK" }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let c = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
        assert!(
            c["message"].as_str().unwrap().contains("rejected"),
            "message should mention rejection: {}",
            c["message"]
        );
    }

    // ── PeerAuthentication ─────────────────────────────────────────────────

    #[test]
    fn peer_auth_unset_mode_reports_permissive() {
        // Istio: UNSET mode resolves to PERMISSIVE — operators often
        // miss this and end up with surprise non-mTLS traffic.
        let obj = object(
            "security.istio.io/v1",
            "PeerAuthentication",
            "default",
            json!({}),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let c = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        assert!(
            c["message"].as_str().unwrap().contains("PERMISSIVE"),
            "message should surface PERMISSIVE default: {}",
            c["message"]
        );
        let detail = update.ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["configured_mtls_mode"].as_str(),
            Some("UNSET")
        );
    }

    #[test]
    fn peer_auth_strict_mode_reports_strict() {
        let obj = object(
            "security.istio.io/v1",
            "PeerAuthentication",
            "strict-default",
            json!({ "mtls": { "mode": "STRICT" } }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let c = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert!(
            c["message"].as_str().unwrap().contains("STRICT"),
            "message should surface STRICT mode: {}",
            c["message"]
        );
        let detail = update.ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["configured_mtls_mode"].as_str(),
            Some("STRICT")
        );
    }

    #[test]
    fn peer_auth_with_selector_reports_workload_selector_scope() {
        let obj = object(
            "security.istio.io/v1",
            "PeerAuthentication",
            "api-strict",
            json!({
                "selector": { "matchLabels": { "app": "api" } },
                "mtls": { "mode": "STRICT" },
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let detail = update.ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["scope"].as_str(),
            Some("WorkloadSelector")
        );
    }

    #[test]
    fn peer_auth_root_namespace_without_selector_reports_mesh_wide_scope() {
        let obj = object(
            "security.istio.io/v1",
            "PeerAuthentication",
            "mesh-default",
            json!({ "mtls": { "mode": "STRICT" } }),
        );
        let updates = plan_istio_status_updates(
            &[obj],
            options().with_istio_root_namespace("default".to_string()),
        );
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["scope"].as_str(), Some("MeshWide"));
    }

    #[test]
    fn peer_auth_port_level_overrides_appear_in_detail() {
        let obj = object(
            "security.istio.io/v1",
            "PeerAuthentication",
            "mixed-modes",
            json!({
                "mtls": { "mode": "STRICT" },
                "portLevelMtls": {
                    "8080": { "mode": "PERMISSIVE" },
                    "9090": { "mode": "DISABLE" },
                }
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let overrides = detail["translation"]["port_level_overrides"]
            .as_array()
            .expect("port_level_overrides should be an array");
        // Map iteration order is unstable; check membership instead.
        let labels: Vec<&str> = overrides.iter().filter_map(Value::as_str).collect();
        assert!(
            labels
                .iter()
                .any(|l| l.contains("8080") && l.contains("PERMISSIVE")),
            "expected 8080 -> PERMISSIVE in overrides, got {labels:?}"
        );
        assert!(
            labels
                .iter()
                .any(|l| l.contains("9090") && l.contains("DISABLE")),
            "expected 9090 -> DISABLE in overrides, got {labels:?}"
        );
    }

    // ── DestinationRule ────────────────────────────────────────────────────

    #[test]
    fn destination_rule_with_only_host_reports_accepted() {
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "reviews-default",
            json!({ "host": "reviews.default.svc.cluster.local" }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let c = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        assert_eq!(c["reason"].as_str(), Some("Accepted"));
        let detail = update.ferrum_detail.as_ref().unwrap();
        let deferred = detail["translation"]["deferred_fields"]
            .as_array()
            .expect("deferred_fields array");
        assert!(
            deferred.is_empty(),
            "no deferred fields expected for simple DR"
        );
    }

    #[test]
    fn destination_rule_with_port_level_tls_surfaces_deferred_field() {
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "secure-dr",
            json!({
                "host": "secure.default.svc.cluster.local",
                "trafficPolicy": {
                    "portLevelSettings": [
                        { "port": { "number": 443 }, "tls": { "mode": "SIMPLE" } }
                    ]
                }
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred
                .iter()
                .any(|f| f.contains("portLevelSettings[].tls")),
            "deferred_fields should mention portLevelSettings[].tls, got {deferred:?}"
        );
    }

    #[test]
    fn destination_rule_missing_host_is_rejected() {
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "bad-dr",
            json!({}), // no host
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let update = &updates[0];
        let c = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    // ── Patch shape ────────────────────────────────────────────────────────

    #[test]
    fn patch_status_preserves_existing_non_ferrum_conditions() {
        let live_status = json!({
            "conditions": [
                {
                    "type": "Reconciled",
                    "status": "True",
                    "reason": "Istio",
                    "message": "Istio reconciled this AuthorizationPolicy",
                    "lastTransitionTime": "2026-01-01T00:00:00Z",
                    "observedGeneration": 1,
                }
            ]
        });
        let desired = json!({
            "conditions": [
                {
                    "type": "Reconciled",
                    "status": "True",
                    "reason": "Istio",
                    "message": "Istio reconciled this AuthorizationPolicy",
                    "lastTransitionTime": "2026-01-01T00:00:00Z",
                    "observedGeneration": 1,
                },
                {
                    "type": "FerrumAccepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "Ferrum accepted",
                    "lastTransitionTime": "2026-05-19T12:00:00Z",
                    "observedGeneration": 5,
                }
            ]
        });
        let update = IstioStatusUpdate {
            api_version: "security.istio.io/v1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
            status: desired,
            ferrum_detail: None,
        };
        let patch = istio_status_patch(&update, Some(&live_status));
        let conditions = patch["status"]["conditions"].as_array().unwrap();
        // Istio's `Reconciled` condition must be preserved.
        assert!(
            conditions
                .iter()
                .any(|c| c["type"].as_str() == Some("Reconciled"))
        );
        assert_eq!(
            conditions
                .iter()
                .filter(|c| c["type"].as_str() == Some("Reconciled"))
                .count(),
            1,
            "non-Ferrum conditions from update.status must not duplicate live status"
        );
        // Ferrum's `FerrumAccepted` condition must be present.
        assert!(
            conditions
                .iter()
                .any(|c| c["type"].as_str() == Some("FerrumAccepted"))
        );
    }

    #[test]
    fn patch_status_replaces_stale_ferrum_condition() {
        // If the live status already had an outdated FerrumAccepted condition,
        // we replace it instead of appending a duplicate.
        let live_status = json!({
            "conditions": [
                {
                    "type": "FerrumAccepted",
                    "status": "False",
                    "reason": "Invalid",
                    "message": "old failure message",
                    "lastTransitionTime": "2026-01-01T00:00:00Z",
                    "observedGeneration": 1,
                },
                {
                    "type": "Reconciled",
                    "status": "True",
                    "reason": "Istio",
                    "message": "preserved",
                    "lastTransitionTime": "2026-01-01T00:00:00Z",
                    "observedGeneration": 1,
                }
            ]
        });
        let desired = json!({
            "conditions": [
                {
                    "type": "FerrumAccepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "fresh success",
                    "lastTransitionTime": "2026-05-19T12:00:00Z",
                    "observedGeneration": 5,
                }
            ]
        });
        let update = IstioStatusUpdate {
            api_version: "security.istio.io/v1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
            status: desired,
            ferrum_detail: None,
        };
        let patch = istio_status_patch(&update, Some(&live_status));
        let conditions = patch["status"]["conditions"].as_array().unwrap();
        let ferrum: Vec<&Value> = conditions
            .iter()
            .filter(|c| c["type"].as_str() == Some("FerrumAccepted"))
            .collect();
        assert_eq!(ferrum.len(), 1, "should have exactly one FerrumAccepted");
        assert_eq!(ferrum[0]["message"].as_str(), Some("fresh success"));
        // Non-Ferrum conditions still present.
        assert!(
            conditions
                .iter()
                .any(|c| c["type"].as_str() == Some("Reconciled"))
        );
    }

    #[test]
    fn patch_status_includes_ferrum_detail_block_when_supplied() {
        let update = IstioStatusUpdate {
            api_version: "security.istio.io/v1".to_string(),
            kind: "PeerAuthentication".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
            status: json!({ "conditions": [] }),
            ferrum_detail: Some(json!({
                "translation": { "scope": "Namespace", "configured_mtls_mode": "STRICT" }
            })),
        };
        let patch = istio_status_patch(&update, None);
        assert_eq!(
            patch["status"]["ferrum"]["translation"]["scope"].as_str(),
            Some("Namespace")
        );
    }

    #[test]
    fn supported_kind_filter_skips_unknown_kinds() {
        let obj = object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "jwt-req",
            json!({}),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert!(
            updates.is_empty(),
            "RequestAuthentication is deferred; planner should skip it"
        );
    }

    #[test]
    fn api_resource_returns_none_for_unsupported_kind() {
        let update = IstioStatusUpdate {
            api_version: "networking.istio.io/v1".to_string(),
            kind: "VirtualService".to_string(),
            namespace: "default".to_string(),
            name: "vs".to_string(),
            status: Value::Null,
            ferrum_detail: None,
        };
        assert!(
            istio_api_resource(&update).is_none(),
            "VirtualService not in this PR's scope; planner already filters it"
        );
    }

    #[test]
    fn api_resource_for_authorization_policy_v1() {
        let update = IstioStatusUpdate {
            api_version: "security.istio.io/v1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            namespace: "default".to_string(),
            name: "policy".to_string(),
            status: Value::Null,
            ferrum_detail: None,
        };
        let ar = istio_api_resource(&update).expect("known kind");
        assert_eq!(ar.group, "security.istio.io");
        assert_eq!(ar.version, "v1");
        assert_eq!(ar.plural, "authorizationpolicies");
    }

    #[test]
    fn merge_owned_conditions_preserves_unknown_typed_entries() {
        // Defensive: a condition entry with no `type` is preserved verbatim
        // — we have no basis for deciding it's ours.
        let live = vec![json!({ "message": "weird entry without type" })];
        let desired = vec![json!({
            "type": "FerrumAccepted",
            "status": "True",
        })];
        let merged = merge_owned_conditions(live, desired);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|c| c.get("type").is_none()
            && c["message"].as_str() == Some("weird entry without type")));
    }

    #[test]
    fn planner_skips_resource_when_status_and_detail_are_current() {
        let obj = object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "already-current",
            json!({ "action": "ALLOW", "rules": [{"to": [{"operation": {"methods": ["GET"]}}]}] }),
        );
        let first = plan_istio_status_updates(std::slice::from_ref(&obj), options());
        assert_eq!(first.len(), 1);

        let mut current = obj;
        current.status = first[0].status.clone();
        current.status.as_object_mut().unwrap().insert(
            "ferrum".to_string(),
            first[0].ferrum_detail.clone().expect("translation detail"),
        );

        let second = plan_istio_status_updates(&[current], options());
        assert!(
            second.is_empty(),
            "already-current status should not be patched again"
        );
    }

    #[test]
    fn planner_updates_resource_when_detail_is_stale() {
        let obj = object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "stale-detail",
            json!({ "action": "ALLOW", "rules": [{"to": [{"operation": {"methods": ["GET"]}}]}] }),
        );
        let first = plan_istio_status_updates(std::slice::from_ref(&obj), options());
        assert_eq!(first.len(), 1);

        let mut stale = obj;
        stale.status = first[0].status.clone();
        stale.status.as_object_mut().unwrap().insert(
            "ferrum".to_string(),
            json!({"translation": {"action": "STALE"}}),
        );

        let second = plan_istio_status_updates(&[stale], options());
        assert_eq!(
            second.len(),
            1,
            "stale Ferrum detail must be refreshed even when conditions match"
        );
    }
}
