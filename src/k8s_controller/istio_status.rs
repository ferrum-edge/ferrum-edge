//! Status sub-resource patcher for Istio CRDs.
//!
//! Operators run `kubectl describe authorizationpolicy <name>` (and the
//! sibling commands for the other Istio CRDs) to see how Ferrum
//! interpreted their policy. Without a `status.conditions[]` block, those
//! commands return only the operator-supplied `spec`, with no visible
//! signal that Ferrum accepted/rejected the policy or what it actually
//! programmed. This module fills that gap.
//!
//! All ten translated Istio CRDs are covered:
//!
//! - `AuthorizationPolicy` — status confirms `ALLOW` with no rules
//!   compiles to a synthetic never-match rule (Istio allow-nothing
//!   semantics), or that the policy was rejected with a translator error.
//! - `PeerAuthentication` — status confirms the resolved mTLS mode
//!   (UNSET → PERMISSIVE in Istio) and surfaces port-level overrides.
//! - `DestinationRule` — status reports whether the rule's host could be
//!   matched and which `connectionPool` knobs landed vs. were deferred.
//! - `VirtualService` — status reports host/HTTP-route counts. `tcp`/`tls` L4
//!   route blocks are translated to stream proxies (port / SNI-passthrough);
//!   HTTP `mirror`/`rewrite`/`redirect`/`corsPolicy` are translated. Unsupported
//!   L4 match predicates (source/CIDR/gateways) and weighted splitting are
//!   rejected fail-closed (`Invalid`).
//! - `ServiceEntry` — status reports the resolved `resolution`/`location`
//!   and host/endpoint/port counts.
//! - `RequestAuthentication` — status reports the resolved scope and the
//!   number of JWT rules (permissive-by-default semantics).
//! - `Sidecar` — status reports the egress scope and the modeled `ingress[]`
//!   listener count. Only ingress entries Ferrum cannot model (Unix-socket /
//!   non-loopback `defaultEndpoint`, non-HTTP-family protocol) remain in
//!   `deferred_fields`; resolvable listeners are materialized.
//! - `Telemetry` — status reports which sections (tracing / metrics /
//!   accessLogging) are present.
//! - `WorkloadEntry` — status reports the derived SPIFFE service account
//!   and service binding.
//! - `ProxyConfig` — status reports resolved scope plus concurrency / image /
//!   environment / tracing.sampling translation outcome. Istio's
//!   `proxyconfigs.networking.istio.io` CRD declares `subresources.status`
//!   (authoritative Istio API manifests), so FerrumAccepted is writable.
//!   Only `selector`, `concurrency`, `image`, and `environmentVariables`
//!   exist in that CRD's structural spec schema, so cluster-sourced objects
//!   always report `tracing.sampling: <unset>` — the API server prunes
//!   `spec.tracing`, which arrives over native/file/xDS mesh config instead.
//!
//! For each kind a rejection (`K8sTranslateError`) flips `FerrumAccepted`
//! to `False`/`Invalid` with the translator's reason, so a hard rejection
//! is never silent to operators.
//!
//! ## Subresource availability
//!
//! Istio's own CRD manifests include `subresources: { status: {} }` on the
//! Istio CRDs, so `patch_status` works against any standard Istio install.
//! If a cluster has stripped the subresource (rare; usually an intentional
//! admission-policy decision), `patch_status` returns
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
    route_local_fault_delay_for_rule, service_entry_port_protocol_is_udp,
    sidecar_selector_from_istio, translate_k8s_objects_collecting_skips,
    workload_selector_from_istio,
};
use crate::k8s_controller::status::StatusTranslationReuse;
use crate::k8s_controller::status_plan::{
    StatusPlanBudget, fair_work_window_iter, select_fair_work_window,
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
    // Keep the plural/group mapping in lock-step with `ISTIO_CRDS` in
    // `src/k8s_controller/watcher.rs` — that array is the source of truth for
    // which kinds the controller actually watches.
    let plural = match (update.kind.as_str(), group, version) {
        ("AuthorizationPolicy", "security.istio.io", _) => "authorizationpolicies",
        ("PeerAuthentication", "security.istio.io", _) => "peerauthentications",
        ("RequestAuthentication", "security.istio.io", _) => "requestauthentications",
        ("DestinationRule", "networking.istio.io", _) => "destinationrules",
        ("VirtualService", "networking.istio.io", _) => "virtualservices",
        ("ServiceEntry", "networking.istio.io", _) => "serviceentries",
        ("WorkloadEntry", "networking.istio.io", _) => "workloadentries",
        ("Sidecar", "networking.istio.io", _) => "sidecars",
        ("Telemetry", "telemetry.istio.io", _) => "telemetries",
        ("ProxyConfig", "networking.istio.io", "v1beta1") => "proxyconfigs",
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
/// `objects`.
///
/// Reuses one shared translation/materialization (or the primary reconcile
/// reuse bundle) instead of retranslating a filtered snapshot once per CRD
/// (#2397). Fail-closed accept/reject parity is preserved via the skip-error
/// map collected while producing that translation.
pub fn plan_istio_status_updates(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> Vec<IstioStatusUpdate> {
    plan_istio_status_updates_budgeted(objects, options, None, StatusPlanBudget::unlimited(0))
        .updates
}

/// Outcome of a budgeted Istio status planning pass.
#[derive(Debug, Clone, PartialEq)]
pub struct IstioStatusPlanOutcome {
    pub updates: Vec<IstioStatusUpdate>,
    pub next_cursor: usize,
    pub eligible_candidates: usize,
    pub planned_candidates: usize,
}

/// Plan Istio status updates with translation reuse and an optional fair work
/// budget applied before expensive per-object status construction.
pub fn plan_istio_status_updates_budgeted(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    translation_reuse: Option<&StatusTranslationReuse>,
    budget: StatusPlanBudget,
) -> IstioStatusPlanOutcome {
    let owned_reuse;
    let reuse = match translation_reuse {
        Some(reuse) => reuse,
        None => {
            let Some((translation, errors)) =
                translate_k8s_objects_collecting_skips(objects, options.clone())
            else {
                return IstioStatusPlanOutcome {
                    updates: Vec::new(),
                    next_cursor: budget.cursor,
                    eligible_candidates: 0,
                    planned_candidates: 0,
                };
            };
            owned_reuse = StatusTranslationReuse::from_owned(translation, errors);
            &owned_reuse
        }
    };

    let mut eligible: Vec<&K8sObject> = objects
        .iter()
        .filter(|object| is_supported_istio_kind(&object.kind))
        .collect();
    eligible.sort_by(|left, right| {
        (
            left.kind.as_str(),
            left.metadata.namespace.as_str(),
            left.metadata.name.as_str(),
        )
            .cmp(&(
                right.kind.as_str(),
                right.metadata.namespace.as_str(),
                right.metadata.name.as_str(),
            ))
    });

    let window = select_fair_work_window(eligible.len(), budget);
    let mut updates = Vec::new();
    for (_, object) in fair_work_window_iter(&eligible, window) {
        let result = reuse.result_for(object);
        let (status, ferrum_detail) = match object.kind.as_str() {
            "AuthorizationPolicy" => authorization_policy_status(object, result),
            "PeerAuthentication" => peer_authentication_status(
                object,
                result,
                &options.istio_root_namespace,
            ),
            "DestinationRule" => destination_rule_status(object, result),
            "VirtualService" => virtual_service_status(object, result),
            "ServiceEntry" => service_entry_status(object, result),
            "RequestAuthentication" => request_authentication_status(
                object,
                result,
                &options.istio_root_namespace,
            ),
            "WorkloadEntry" => workload_entry_status(object, result),
            "Sidecar" => sidecar_status(
                object,
                result,
                &options.istio_root_namespace,
                options.mesh_sidecar_ingress_enforced,
            ),
            "Telemetry" => telemetry_status(object, result),
            "ProxyConfig" => {
                proxy_config_status(object, result, &options.istio_root_namespace)
            }
            _ => continue,
        };
        if status == object.status && ferrum_detail_matches(&object.status, &ferrum_detail) {
            continue;
        }
        updates.push(IstioStatusUpdate {
            api_version: object.api_version.clone(),
            kind: object.kind.clone(),
            namespace: object.metadata.namespace.clone(),
            name: object.metadata.name.clone(),
            status,
            ferrum_detail,
        });
    }

    IstioStatusPlanOutcome {
        updates,
        next_cursor: window.next_cursor,
        eligible_candidates: eligible.len(),
        planned_candidates: window.take,
    }
}

fn ferrum_detail_matches(status: &Value, desired: &Option<Value>) -> bool {
    desired
        .as_ref()
        .is_none_or(|detail| status.get("ferrum") == Some(detail))
}

fn is_supported_istio_kind(kind: &str) -> bool {
    matches!(
        kind,
        "AuthorizationPolicy"
            | "PeerAuthentication"
            | "RequestAuthentication"
            | "DestinationRule"
            | "VirtualService"
            | "ServiceEntry"
            | "WorkloadEntry"
            | "Sidecar"
            | "Telemetry"
            | "ProxyConfig"
    )
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
    // Index the LIVE conditions by type so a value-unchanged desired condition
    // can carry the live `lastTransitionTime` forward. `condition()` computes
    // the timestamp against the planning snapshot (the watch cache, which can
    // lag the live status); without this second, live-status preservation layer
    // a value-unchanged `FerrumAccepted` condition would be stamped with
    // `now()` whenever the cache and live status diverge, making the
    // K8s-standard `lastTransitionTime` flap (it should change only on a real
    // status transition). The Gateway API writer already guards this via the
    // same shared `preserve_unchanged_transition_time` helper.
    let live_by_type: std::collections::HashMap<String, Value> = live_conditions
        .iter()
        .filter_map(|c| {
            c.get("type")
                .and_then(Value::as_str)
                .map(|condition_type| (condition_type.to_owned(), c.clone()))
        })
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
    merged.extend(desired_conditions.into_iter().map(|desired| {
        match desired
            .get("type")
            .and_then(Value::as_str)
            .and_then(|condition_type| live_by_type.get(condition_type))
        {
            Some(live) => super::status::preserve_unchanged_transition_time(desired, live),
            None => desired,
        }
    }));
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

    accepted_status(object, accepted, reason, &message, detail)
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
    let scope = istio_policy_scope_label(object, istio_root_namespace);
    let configured_port_overrides: Vec<String> = object
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
    let has_workload_selector = scope == "WorkloadSelector";
    let port_overrides_ignored_without_nonempty_selector =
        !has_workload_selector && !configured_port_overrides.is_empty();
    let port_overrides = if has_workload_selector {
        configured_port_overrides
    } else {
        Vec::new()
    };

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
            let ignored_suffix = if port_overrides_ignored_without_nonempty_selector {
                "; portLevelMtls ignored because no non-empty workload selector is specified"
            } else {
                ""
            };
            let message = format!(
                "Ferrum accepted this PeerAuthentication (scope: {scope}; resolved mTLS mode: {effective_mode}{ignored_suffix})"
            );
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "configured_mtls_mode": resolved_mode,
                    "port_level_overrides": port_overrides,
                    "port_level_overrides_ignored_without_nonempty_selector": port_overrides_ignored_without_nonempty_selector,
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

    accepted_status(object, accepted, reason, &message, detail)
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
            // Deferred fields: the parsed-but-dropped connectionPool.http knobs
            // the translator only warns on. `maxRequestsPerConnection` is
            // universally deferred because Ferrum does not enforce
            // close-after-N backend requests. The other top-level/port
            // connectionPool.http knobs are projected/enforced as documented.
            // Subset-scoped deferred (codex round-1 Finding 4): h2UpgradePolicy +
            // maxRetries + http1MaxPendingRequests set inside a
            // `subsets[].trafficPolicy` are applied at top-level/port but NOT for
            // subsets (subset -> SubsetTrafficPolicy has no connectionPool.http),
            // so they are surfaced as deferred there.
            // Now APPLIED (no longer deferred): per-subset
            // connectionPool.tcp.connectTimeout (overrides backend_connect_timeout_ms
            // for subset-bound proxies), portLevelSettings[].tls (per-port backend
            // TLS projected onto the effective proxy's resolved_tls), and the full
            // per-subset outlierDetection — both the *thresholds* (consecutive
            // errors / interval / base-ejection / min-health) and the
            // *maxEjectionPercent cap*, the latter resolved by
            // `LoadBalancerCache::max_ejection_percent_resolved_from` with the
            // same per-port > per-subset > upstream precedence as the thresholds.
            // Surface the rest so operators see the gap in `kubectl describe`.
            let mut deferred: Vec<&'static str> = Vec::new();
            deferred.extend(deferred_connection_pool_http_fields(&object.spec));
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

    accepted_status(object, accepted, reason, &message, detail)
}

/// `connectionPool.http` knobs the translator parses but drops with an
/// operator-visible warning IN EVERY SCOPE (top-level / `portLevelSettings` /
/// subset) — see `translate_connection_pool_http` in
/// `src/config_sources/k8s/istio.rs`. Keep this list in sync with the
/// translator's always-deferred loop.
///
/// `maxRequestsPerConnection` is universally deferred: it is parsed and
/// validated, but not projected because the backend pools do not support
/// close-after-N-request semantics. `idleTimeout`, `http2MaxRequests`,
/// `maxRetries`, `h2UpgradePolicy`, and `http1MaxPendingRequests` are
/// projected/enforced at top-level/port scope. The three of those that a
/// subset's `SubsetTrafficPolicy` cannot carry
/// (`h2UpgradePolicy` / `maxRetries` / `http1MaxPendingRequests`) are deferred
/// ONLY for subsets — see `SUBSET_DEFERRED_CONNECTION_POOL_HTTP_FIELDS`.
const DEFERRED_CONNECTION_POOL_HTTP_FIELDS: &[(&str, &str)] = &[(
    "maxRequestsPerConnection",
    "connectionPool.http.maxRequestsPerConnection (not applied: backend close-after-N-requests is unsupported)",
)];

/// `connectionPool.http` knobs that ARE applied at top-level /
/// `portLevelSettings` but are deferred ONLY when set inside a
/// `subsets[].trafficPolicy` — the mesh apply path turns subsets into a
/// `SubsetTrafficPolicy` (LB / TLS / connectTimeout / passive-health only),
/// which carries no `connectionPool.http`, so these are silently ignored for
/// subsets (codex round-1 Finding 4). Keep this list in sync with the
/// translator's subset-scoped warning loop.
const SUBSET_DEFERRED_CONNECTION_POOL_HTTP_FIELDS: &[(&str, &str)] = &[
    (
        "h2UpgradePolicy",
        "subsets[].trafficPolicy.connectionPool.http.h2UpgradePolicy (not applied for subsets)",
    ),
    (
        "maxRetries",
        "subsets[].trafficPolicy.connectionPool.http.maxRetries (not applied for subsets)",
    ),
    (
        "http1MaxPendingRequests",
        "subsets[].trafficPolicy.connectionPool.http.http1MaxPendingRequests (not applied for subsets)",
    ),
];

/// Collect the deferred `connectionPool.http.*` field labels. Two layers:
/// 1. `DEFERRED_CONNECTION_POOL_HTTP_FIELDS` — deferred in EVERY scope; scanned
///    under the top-level `trafficPolicy`, each `trafficPolicy.portLevelSettings[]`,
///    and each subset's `trafficPolicy`.
/// 2. `SUBSET_DEFERRED_CONNECTION_POOL_HTTP_FIELDS` — applied at top-level/port
///    but deferred ONLY inside a `subsets[].trafficPolicy`; scanned under
///    subsets only.
///
/// Mirrors the translator's warning emission so the same gap shows up in
/// `kubectl describe`.
fn deferred_connection_pool_http_fields(spec: &Value) -> Vec<&'static str> {
    let top_level = spec.get("trafficPolicy");
    let port_level_policies = top_level
        .and_then(|policy| policy.get("portLevelSettings"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let subset_policies: Vec<&Value> = spec
        .get("subsets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|subset| subset.get("trafficPolicy"))
        .collect();

    let all_scope_policies: Vec<&Value> = top_level
        .into_iter()
        .chain(port_level_policies)
        .chain(subset_policies.iter().copied())
        .collect();

    let http_has = |policy: &Value, field: &str| {
        policy
            .get("connectionPool")
            .and_then(|cp| cp.get("http"))
            .and_then(|http| http.get(field))
            .is_some()
    };

    let mut deferred: Vec<&'static str> = DEFERRED_CONNECTION_POOL_HTTP_FIELDS
        .iter()
        .filter(|(field, _)| {
            all_scope_policies
                .iter()
                .any(|policy| http_has(policy, field))
        })
        .map(|(_, label)| *label)
        .collect();

    // Subset-only deferred knobs (applied at top-level/port, ignored for subsets).
    deferred.extend(
        SUBSET_DEFERRED_CONNECTION_POOL_HTTP_FIELDS
            .iter()
            .filter(|(field, _)| subset_policies.iter().any(|policy| http_has(policy, field)))
            .map(|(_, label)| *label),
    );

    deferred
}

/// Shared tail for the per-kind status builders: stamp a single
/// `FerrumAccepted` condition onto a clone of the object's existing status
/// and return it alongside the optional translator-detail block. Mirrors
/// the inline tail the original three CRDs used so every kind produces an
/// identical condition shape.
fn accepted_status(
    object: &K8sObject,
    accepted: bool,
    reason: &str,
    message: &str,
    detail: Option<Value>,
) -> (Value, Option<Value>) {
    let conditions = vec![condition(
        object,
        Some(&object.status),
        "FerrumAccepted",
        accepted,
        reason,
        message,
    )];
    let mut status = object.status.clone();
    merge_status_conditions(&mut status, &["FerrumAccepted"], conditions);
    (status, detail)
}

/// Status for `VirtualService`. The translator consumes `spec.http` routes
/// (incl. `mirror` / `rewrite` / `redirect` / `corsPolicy`) and `spec.tcp` /
/// `spec.tls` L4 route blocks (translated to stream proxies: port / SNI
/// passthrough). Unsupported L4 match predicates / weighted splitting and any
/// other `K8sTranslateError` (bad backend, etc.) surface through the `Invalid`
/// arm. `corsPolicy` is deferred only for a policy combination Ferrum cannot
/// represent faithfully (a malformed/unknown origin matcher, an over-budget
/// matcher list or value, an un-compilable/over-complex regex, an unparseable
/// `maxAge`, or credentialed exact `*`); exact/prefix/regex origin matchers are
/// otherwise translated.
fn virtual_service_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
) -> (Value, Option<Value>) {
    let host_count = object
        .spec
        .get("hosts")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);
    let http_route_count = object
        .spec
        .get("http")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);

    match result {
        Ok(_translation) => {
            let deferred = virtual_service_deferred_fields(&object.spec);
            let clamped = virtual_service_clamped_fields(&object.spec);
            let message = if deferred.is_empty() && clamped.is_empty() {
                format!(
                    "Ferrum accepted this VirtualService ({host_count} host(s), {http_route_count} HTTP route(s))"
                )
            } else {
                let mut notes = Vec::new();
                if !deferred.is_empty() {
                    notes.push(format!("deferred fields: {}", deferred.join(", ")));
                }
                if !clamped.is_empty() {
                    notes.push(format!("clamped fields: {}", clamped.join(", ")));
                }
                format!(
                    "Ferrum accepted this VirtualService ({host_count} host(s), {http_route_count} HTTP route(s)); {}",
                    notes.join("; ")
                )
            };
            let detail = json!({
                "translation": {
                    "hosts": host_count,
                    "http_routes_translated": http_route_count,
                    "deferred_fields": deferred,
                    "clamped_fields": clamped,
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this VirtualService: {error}");
            let detail = json!({
                "translation": {
                    "hosts": host_count,
                    "http_routes_translated": http_route_count,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// VirtualService HTTP-route fields the translator parses past but never
/// projects. `tcp` / `tls` route arrays are not listed here: they are
/// translated to stream proxies (unsupported matches / weighted splitting
/// surface via the `Invalid` arm, not as deferred). `corsPolicy` is translated
/// to a `cors` plugin when the complete source combination is representable;
/// otherwise it is deferred.
fn virtual_service_deferred_fields(spec: &Value) -> Vec<&'static str> {
    let mut deferred: Vec<&'static str> = Vec::new();
    // `spec.tcp[]` / `spec.tls[]` are NOT listed as deferred: the translator
    // materializes them as stream proxies, and unsupported matches surface via
    // the `Invalid` arm of `virtual_service_status`. `mirror` /
    // `mirrorPercentage` / `redirect` / `rewrite` are translated, and
    // `corsPolicy` is translated to a proxy-scoped `cors` plugin when its
    // origins are representable — `allowOrigins[]` `exact`/`prefix`/`regex`
    // `StringMatch` (exact projected LITERALLY, so a wildcard-shaped or
    // non-canonical exact is representable rather than deferred — issue #3254;
    // regex must compile within the shared byte/complexity bounds — issue
    // #3253) or the legacy `allowOrigin` exact list, plus a parseable maxAge. It
    // remains a deferred field when an origin matcher is malformed/unknown, a
    // matcher list or value exceeds its bound, a `regex` does not compile or is
    // too complex, maxAge is unparseable, or credentials are combined with
    // exact `*` (the native wildcard representation cannot preserve that source
    // behavior). The shared `cors_policy_translatable` predicate keeps the
    // translator and this report in lockstep.
    let http_routes = spec.get("http").and_then(Value::as_array);
    if http_routes.is_some_and(|routes| {
        routes.iter().any(|route| {
            route
                .get("corsPolicy")
                .is_some_and(|cors| !crate::config_sources::k8s::cors_policy_translatable(cors))
        })
    }) {
        deferred.push(
            "http[].corsPolicy with an unrepresentable policy combination \
             (not projected; use the cors plugin)",
        );
    }
    deferred
}

/// VirtualService values that are valid in Istio but exceed a Ferrum runtime
/// limit and are therefore translated with an operator-visible clamp.
fn virtual_service_clamped_fields(spec: &Value) -> Vec<&'static str> {
    let has_clamped_fault_delay =
        spec.get("http")
            .and_then(Value::as_array)
            .is_some_and(|routes| {
                routes.iter().any(|route| {
                    route
                        .get("fault")
                        .and_then(route_local_fault_delay_for_rule)
                        .is_some_and(|delay| delay.was_clamped())
                })
            });
    if has_clamped_fault_delay {
        vec!["http[].fault.delay.fixedDelay above 60s (clamped to 60s)"]
    } else {
        Vec::new()
    }
}

/// Status for `ServiceEntry`. Reports the resolved `resolution`/`location`
/// (both default when omitted, matching Istio) and host/endpoint/port
/// counts so operators can confirm Ferrum's view of an external service.
///
/// A `protocol: UDP` port is ACCEPTED (it translates to `AppProtocol::Udp`) but
/// its EgressGateway egress lane is INERT: the EgressGateway materializer skips
/// UDP ports because ServiceEntry/egress-external UDP is out of scope (east-west
/// UDP capture/egress shipped in F3 §3.3, but external-UDP egress did not), so
/// the resource would
/// otherwise show as fully accepted in `kubectl describe` while no
/// proxy/listener/upstream is produced. Surface that gap as a `deferred_fields`
/// entry (keeping `FerrumAccepted=True` — it IS accepted/translated, just
/// inert), detected via the SHARED `service_entry_port_protocol_is_udp` predicate
/// so the status report can never diverge from the translator's classification or
/// the materializer's skip.
fn service_entry_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
) -> (Value, Option<Value>) {
    let resolution = object
        .spec
        .get("resolution")
        .and_then(Value::as_str)
        .unwrap_or("NONE")
        .to_string();
    let location = object
        .spec
        .get("location")
        .and_then(Value::as_str)
        .unwrap_or("MESH_EXTERNAL")
        .to_string();
    let host_count = object
        .spec
        .get("hosts")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);
    let endpoint_count = object
        .spec
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);
    let port_count = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);

    // A `protocol: UDP` ServiceEntry is accepted (it translates to
    // `AppProtocol::Udp`) but the EgressGateway materializer skips UDP ports as
    // inert (ServiceEntry/egress-external UDP is out of scope; east-west UDP
    // capture/egress shipped in F3 §3.3 — see `build_egress_proxies_and_upstreams`
    // in `src/modes/mesh/mod.rs`, which keys its one-time deferral warning off
    // `AppProtocol::Udp`). Surface that gap as a deferred field so the resource
    // does not appear fully accepted while no proxy/listener/upstream is produced.
    // Detect UDP ports on the raw spec via the SHARED predicate the translator's
    // classifier feeds, so this report stays in lock-step with the materializer's
    // skip.
    let has_udp_port = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|port| {
            service_entry_port_protocol_is_udp(port.get("protocol").and_then(Value::as_str))
        });
    let mut deferred: Vec<&'static str> = Vec::new();
    if has_udp_port {
        deferred.push(
            "spec.ports[].protocol: UDP — egress materialization deferred \
             (ServiceEntry/egress-external UDP is out of scope; east-west UDP \
             capture/egress shipped in F3 §3.3)",
        );
    }

    match result {
        Ok(_translation) => {
            let message = if deferred.is_empty() {
                format!(
                    "Ferrum accepted this ServiceEntry ({host_count} host(s), resolution: {resolution}, location: {location})"
                )
            } else {
                format!(
                    "Ferrum accepted this ServiceEntry ({host_count} host(s), resolution: {resolution}, \
                     location: {location}); deferred fields: {}",
                    deferred.join(", ")
                )
            };
            let detail = json!({
                "translation": {
                    "hosts": host_count,
                    "endpoints": endpoint_count,
                    "ports": port_count,
                    "resolution": resolution,
                    "location": location,
                    "deferred_fields": deferred,
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this ServiceEntry: {error}");
            let detail = json!({
                "translation": {
                    "hosts": host_count,
                    "resolution": resolution,
                    "location": location,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// Status for `RequestAuthentication`. Surfaces the resolved scope and JWT
/// rule count, plus a reminder of Istio's permissive-by-default semantics
/// (RequestAuthentication only declares which JWTs are *valid*, not which
/// are *required*).
fn request_authentication_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
    istio_root_namespace: &str,
) -> (Value, Option<Value>) {
    let scope = istio_policy_scope_label(object, istio_root_namespace);
    let jwt_rule_count = object
        .spec
        .get("jwtRules")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);

    match result {
        Ok(_translation) => {
            let message = format!(
                "Ferrum accepted this RequestAuthentication (scope: {scope}; {jwt_rule_count} JWT rule(s); \
                 permissive by default — a request with no JWT passes, an invalid JWT is rejected, \
                 require a JWT via AuthorizationPolicy)"
            );
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "jwt_rules": jwt_rule_count,
                    "enforcement": "permissive",
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this RequestAuthentication: {error}");
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "jwt_rules": jwt_rule_count,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// Status for `WorkloadEntry`. Reports the derived SPIFFE service-account
/// identity and the service the entry binds to so operators can confirm
/// the workload's mesh identity without inspecting slice state.
fn workload_entry_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
) -> (Value, Option<Value>) {
    let service_account = object
        .spec
        .get("serviceAccount")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("default")
        .to_string();
    let address = object
        .spec
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    match result {
        Ok(_translation) => {
            let message = format!(
                "Ferrum accepted this WorkloadEntry (service account: {service_account}; address: {})",
                if address.is_empty() {
                    "<none>"
                } else {
                    &address
                }
            );
            let detail = json!({
                "translation": {
                    "service_account": service_account,
                    "address": address,
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this WorkloadEntry: {error}");
            let detail = json!({
                "translation": {
                    "service_account": service_account,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// Status for `Sidecar`. Ferrum models the egress scope AND (F6 §6.2) the
/// `ingress[]` custom inbound listeners. Egress narrowing is gated by
/// `FERRUM_MESH_SIDECAR_ENFORCED` (Sidecars are always parsed/persisted).
/// Ingress entries that Ferrum cannot represent (Unix-socket / non-loopback
/// `defaultEndpoint`, non-HTTP-family protocol) stay in `deferred_fields`;
/// resolvable listeners are materialized and reported via `ingress_modeled`.
///
/// `ingress_enforced` is the EFFECTIVE ingress materialization gate
/// (`FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`),
/// mirroring the slice builder's `sidecar_enforced && !sidecar_dry_run` ingress
/// predicate. Ingress is materialized ONLY when it is true, so `ingress_modeled`
/// is reported as `0` otherwise — the `FerrumAccepted` status must never claim a
/// listener is modeled while the data plane is still serving the default inbound
/// behavior in the default dry-run / disabled posture (keeps the translator and
/// the status writer in lock-step on what is actually applied).
fn sidecar_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
    istio_root_namespace: &str,
    ingress_enforced: bool,
) -> (Value, Option<Value>) {
    let egress_entry_count = object
        .spec
        .get("egress")
        .and_then(Value::as_array)
        .map(|v| v.len())
        .unwrap_or(0);
    let has_workload_selector = object
        .spec
        .get("workloadSelector")
        .is_some_and(|selector| !sidecar_selector_from_istio(Some(selector)).is_empty());
    let scope = if has_workload_selector {
        "WorkloadSelector"
    } else if object.metadata.namespace == istio_root_namespace
        || object.metadata.namespace.is_empty()
    {
        "MeshWide"
    } else {
        "Namespace"
    };

    match result {
        Ok(_translation) => {
            let (ingress_modelable, ingress_deferred) =
                classify_sidecar_ingress_entries(&object.spec);
            // Ingress is MATERIALIZED only under the enforcement gate
            // (`FERRUM_MESH_SIDECAR_ENFORCED && !dry_run`), exactly like the slice
            // builder. Report the shape-modelable count as `ingress_modeled` only
            // when the gate is on; otherwise report `0` so an operator using the
            // `FerrumAccepted` status to verify rollout never sees a false positive
            // while the data plane is still serving the default inbound behavior.
            let ingress_modeled = if ingress_enforced {
                ingress_modelable
            } else {
                0
            };
            let mut deferred: Vec<String> = Vec::new();
            for reason in &ingress_deferred {
                deferred.push(format!("ingress[] {reason}"));
            }
            // When ingress modeling is gated off, surface the modelable-but-not-
            // applied count so operators still see the shapes Ferrum WOULD model
            // once they enable enforcement (the gate, not the resource, is why
            // `ingress_modeled` is 0).
            let ingress_clause = if ingress_enforced {
                format!("{ingress_modeled} ingress listener(s) modeled")
            } else {
                format!(
                    "ingress listeners not materialized (FERRUM_MESH_SIDECAR_ENFORCED off / dry-run; \
                     {ingress_modelable} modelable when enabled)"
                )
            };
            let message = if deferred.is_empty() {
                format!(
                    "Ferrum accepted this Sidecar (scope: {scope}; {egress_entry_count} egress entry/entries; \
                     {ingress_clause}; egress narrowing gated by FERRUM_MESH_SIDECAR_ENFORCED)"
                )
            } else {
                format!(
                    "Ferrum accepted this Sidecar (scope: {scope}; {egress_entry_count} egress entry/entries; \
                     {ingress_clause}); deferred fields: {}",
                    deferred.join(", ")
                )
            };
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "egress_entries": egress_entry_count,
                    "ingress_modeled": ingress_modeled,
                    "deferred_fields": deferred,
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this Sidecar: {error}");
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "egress_entries": egress_entry_count,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// Classify a Sidecar's `spec.ingress[]` entries into (modeled_count,
/// deferred_reasons) so the status writer reports which listeners Ferrum
/// materialized and which it left deferred. Mirrors
/// `MeshSidecarIngress::resolve` and the slice resolver's fail-closed semantics
/// on the raw spec so the translator predicate and the status writer stay in
/// lock-step: an entry is modeled iff its protocol is HTTP-family AND its
/// `defaultEndpoint` is a loopback / instance-IP `host:port` AND its listener
/// port has not already been claimed by an earlier modeled entry. Unix-socket
/// and non-loopback endpoints, non-HTTP-family protocols, unparseable shapes,
/// and DUPLICATE listener ports are deferred (the translator still accepts the
/// resource; only the unmodeled entries surface here).
///
/// The duplicate-port dedup mirrors `resolve_applicable_sidecar_ingress` in
/// `src/modes/mesh/slice.rs`, which reserves a listener port only for the FIRST
/// successfully resolved entry on that port and warns + drops later entries with
/// the same port. Counting each supported entry would over-report `ingress_modeled`
/// (more listeners than Ferrum actually materializes) and mislead `kubectl`
/// rollout verification, so a supported entry on an already-claimed port is
/// reported as a deferred duplicate instead of inflating the modeled count.
fn classify_sidecar_ingress_entries(spec: &Value) -> (usize, Vec<&'static str>) {
    let Some(entries) = spec.get("ingress").and_then(Value::as_array) else {
        return (0, Vec::new());
    };
    let mut modeled = 0usize;
    let mut deferred: Vec<&'static str> = Vec::new();
    // Listener ports already claimed by a modeled entry. Mirrors the slice
    // resolver's `seen_ports` (reserved only on a SUCCESSFUL resolve, so a
    // deferred entry never consumes a port a later valid entry could use).
    let mut seen_modeled_ports: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let push_unique = |deferred: &mut Vec<&'static str>, reason: &'static str| {
        if !deferred.contains(&reason) {
            deferred.push(reason);
        }
    };
    for entry in entries {
        let protocol = entry
            .get("port")
            .and_then(|p| p.get("protocol"))
            .and_then(Value::as_str);
        // Classify through the SAME shared predicate `MeshSidecarIngress::resolve`
        // uses (raw string → `sidecar_ingress_app_protocol` →
        // `is_http_family_app_protocol`), so resolution and this deferred-field
        // report never disagree. `https` is recognized HTTP-family and IS
        // materialized — counted as modeled below — while a MISSING or
        // UNRECOGNIZED protocol (e.g. a `HTPS` typo) maps to a non-HTTP
        // `AppProtocol` and is reported as a deferred non-HTTP listener (it is
        // NOT routed onto the HTTP request path), matching resolution.
        let http_family =
            crate::config_sources::k8s::sidecar_ingress_protocol_is_http_family(protocol);
        let endpoint = entry
            .get("defaultEndpoint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if !http_family {
            push_unique(
                &mut deferred,
                "non-HTTP-family listener (raw-TCP inbound not modeled)",
            );
            continue;
        }
        if endpoint.starts_with("unix://") {
            push_unique(
                &mut deferred,
                "unix:// defaultEndpoint not representable (host:port backends only)",
            );
            continue;
        }
        let endpoint_ok = matches!(
            endpoint.parse::<std::net::SocketAddr>(),
            Ok(addr) if addr.port() != 0 && (addr.ip().is_loopback() || addr.ip().is_unspecified())
        );
        if !endpoint_ok {
            push_unique(
                &mut deferred,
                "defaultEndpoint must be a loopback/instance-IP host:port",
            );
            continue;
        }
        // The entry would resolve. Reserve its listener port; a later supported
        // entry on the same port is dropped by the slice resolver, so report it
        // as a deferred duplicate rather than counting a listener Ferrum does not
        // materialize. `port.number` is present and valid here — the translator
        // rejects a missing/out-of-range `port.number` before this classifier
        // runs (it only runs on an accepted resource).
        let listener_port = entry
            .get("port")
            .and_then(|p| p.get("number"))
            .and_then(Value::as_u64);
        match listener_port {
            Some(port) if !seen_modeled_ports.insert(port) => {
                push_unique(
                    &mut deferred,
                    "duplicate listener port (only the first entry is modeled)",
                );
            }
            _ => modeled += 1,
        }
    }
    (modeled, deferred)
}

/// Status for `Telemetry`. Reports which top-level sections (tracing /
/// metrics / accessLogging) the resource declares. Unsupported tracing
/// provider references are dropped with a translator warning rather than a
/// hard error, so the condition stays `Accepted` in that case.
fn telemetry_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
) -> (Value, Option<Value>) {
    let has_tracing = object
        .spec
        .get("tracing")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty());
    let has_metrics = object
        .spec
        .get("metrics")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty());
    let has_access_logging = object
        .spec
        .get("accessLogging")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty());

    let mut sections: Vec<&'static str> = Vec::new();
    if has_tracing {
        sections.push("tracing");
    }
    if has_metrics {
        sections.push("metrics");
    }
    if has_access_logging {
        sections.push("accessLogging");
    }

    match result {
        Ok(_translation) => {
            let message = if sections.is_empty() {
                "Ferrum accepted this Telemetry (no tracing/metrics/accessLogging sections)"
                    .to_string()
            } else {
                format!(
                    "Ferrum accepted this Telemetry (sections: {})",
                    sections.join(", ")
                )
            };
            let detail = json!({
                "translation": {
                    "sections": sections,
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this Telemetry: {error}");
            let detail = json!({
                "translation": {
                    "sections": sections,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// Status for `ProxyConfig`. Surfaces resolved policy scope plus the
/// translated concurrency / image / environment / tracing.sampling fields.
///
/// Authoritative evidence: Istio's `proxyconfigs.networking.istio.io` CRD
/// (istio/api `customresourcedefinitions.gen.yaml`) declares
/// `subresources: { status: {} }` on the served `v1beta1` version with a
/// conditions-shaped status schema, so `FerrumAccepted` is writable the same
/// way as the other watched Istio kinds.
///
/// That CRD's structural spec schema admits only `selector`, `concurrency`,
/// `image`, and `environmentVariables`; `spec.tracing` is pruned by the API
/// server, so `tracing_sampling` reads `<unset>` for every cluster-sourced
/// object. It is reported anyway to stay in lock-step with the translator's
/// field set for non-pruned object feeds.
fn proxy_config_status(
    object: &K8sObject,
    result: Result<&K8sTranslation, &K8sTranslateError>,
    istio_root_namespace: &str,
) -> (Value, Option<Value>) {
    let scope = istio_policy_scope_label(object, istio_root_namespace);
    let concurrency = object
        .spec
        .get("concurrency")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());
    let image = object
        .spec
        .get("image")
        .and_then(|img| img.get("imageType"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let environment_count = object
        .spec
        .get("environmentVariables")
        .and_then(Value::as_object)
        .map(|m| m.len())
        .unwrap_or(0);
    let tracing_sampling = object
        .spec
        .get("tracing")
        .and_then(|tracing| tracing.get("sampling"))
        .and_then(Value::as_f64);

    match result {
        Ok(_translation) => {
            let message = format!(
                "Ferrum accepted this ProxyConfig (scope: {scope}; concurrency: {}; image: {}; \
                 environment vars: {environment_count}; tracing.sampling: {})",
                concurrency
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "<unset>".to_string()),
                image.as_deref().unwrap_or("<unset>"),
                tracing_sampling
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "<unset>".to_string()),
            );
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "concurrency": concurrency,
                    "image": image,
                    "environment_vars": environment_count,
                    "tracing_sampling": tracing_sampling,
                }
            });
            accepted_status(object, true, "Accepted", &message, Some(detail))
        }
        Err(error) => {
            let message = format!("Ferrum rejected this ProxyConfig: {error}");
            let detail = json!({
                "translation": {
                    "scope": scope,
                    "concurrency": concurrency,
                    "image": image,
                    "environment_vars": environment_count,
                    "tracing_sampling": tracing_sampling,
                    "error": format!("{error}"),
                }
            });
            accepted_status(object, false, "Invalid", &message, Some(detail))
        }
    }
}

/// Resolve the Istio policy scope label for selector-driven CRDs
/// (`RequestAuthentication`, etc.) the same way the translator's
/// `istio_policy_scope` does: a non-empty selector means `WorkloadSelector`,
/// the root namespace means `MeshWide`, otherwise `Namespace`.
fn istio_policy_scope_label(object: &K8sObject, istio_root_namespace: &str) -> &'static str {
    if workload_selector_from_istio(object.spec.get("selector"), None).is_some() {
        "WorkloadSelector"
    } else if object.metadata.namespace == istio_root_namespace
        || object.metadata.namespace.is_empty()
    {
        "MeshWide"
    } else {
        "Namespace"
    }
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

    /// Options with the Sidecar ingress materialization gate ON, mirroring
    /// `FERRUM_MESH_SIDECAR_ENFORCED=true` (not dry-run). The status writer
    /// reports `ingress_modeled` as materialized only under this gate, so the
    /// ingress-modeling tests use it; the default `options()` leaves the gate
    /// off (the default dry-run/disabled posture, where modeling is not applied).
    fn options_ingress_enforced() -> K8sTranslationOptions {
        options().with_mesh_sidecar_ingress_enforced(true)
    }

    fn object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
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

    // ── lastTransitionTime preservation (vs live status) ───────────────────

    #[test]
    fn merge_owned_conditions_preserves_last_transition_time_for_unchanged_value() {
        // Live status carries FerrumAccepted=True/Accepted/msg @ T1. The planning
        // pass recomputed the SAME value but stamped @ T2 (the watch cache lagged
        // the live write). The merge must carry T1 forward so lastTransitionTime
        // does not flap on a value-unchanged reconcile (K8s Condition semantics).
        let live = vec![json!({
            "type": "FerrumAccepted",
            "status": "True",
            "reason": "Accepted",
            "message": "translated",
            "lastTransitionTime": "2026-01-01T00:00:00Z"
        })];
        let desired = vec![json!({
            "type": "FerrumAccepted",
            "status": "True",
            "reason": "Accepted",
            "message": "translated",
            "lastTransitionTime": "2026-05-30T12:00:00Z"
        })];
        let merged = merge_owned_conditions(live, desired);
        let c = find_condition(&merged, "FerrumAccepted");
        assert_eq!(
            c["lastTransitionTime"].as_str(),
            Some("2026-01-01T00:00:00Z"),
            "unchanged condition value must keep the live lastTransitionTime"
        );
    }

    #[test]
    fn merge_owned_conditions_advances_last_transition_time_on_changed_value() {
        // A genuine transition (True/Accepted -> False/Invalid) must adopt the
        // new timestamp.
        let live = vec![json!({
            "type": "FerrumAccepted",
            "status": "True",
            "reason": "Accepted",
            "message": "translated",
            "lastTransitionTime": "2026-01-01T00:00:00Z"
        })];
        let desired = vec![json!({
            "type": "FerrumAccepted",
            "status": "False",
            "reason": "Invalid",
            "message": "rejected",
            "lastTransitionTime": "2026-05-30T12:00:00Z"
        })];
        let merged = merge_owned_conditions(live, desired);
        let c = find_condition(&merged, "FerrumAccepted");
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(
            c["lastTransitionTime"].as_str(),
            Some("2026-05-30T12:00:00Z"),
            "a real status transition must advance lastTransitionTime"
        );
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
                "selector": { "matchLabels": { "app": "api" } },
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
    fn destination_rule_with_port_level_tls_is_applied_not_deferred() {
        // portLevelSettings[].tls is now applied per-port (resolved onto the
        // effective proxy's resolved_tls at dispatch), so it must NOT be
        // reported as a deferred field.
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
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            !deferred
                .iter()
                .any(|f| f.contains("portLevelSettings[].tls")),
            "portLevelSettings[].tls is applied now and must not be deferred, got {deferred:?}"
        );
    }

    #[test]
    fn destination_rule_threshold_only_subset_outlier_not_deferred() {
        // A subset outlierDetection that sets only thresholds (no
        // maxEjectionPercent) is applied per-subset, so the status must NOT
        // surface the maxEjectionPercent deferred field.
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "outlier-thresholds-dr",
            json!({
                "host": "reviews.default.svc.cluster.local",
                "subsets": [{
                    "name": "v1",
                    "labels": {"version": "v1"},
                    "trafficPolicy": {
                        "outlierDetection": {"consecutive5xxErrors": 3, "interval": "5s"}
                    }
                }]
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
            !deferred.iter().any(|f| f.contains("maxEjectionPercent")),
            "threshold-only subset outlierDetection must not surface a maxEjectionPercent deferred field, got {deferred:?}"
        );
    }

    #[test]
    fn destination_rule_subset_outlier_max_ejection_percent_not_deferred() {
        // The maxEjectionPercent *cap* is now applied per-subset (resolved with
        // the same per-port > per-subset > upstream precedence as the
        // thresholds), so a subset that sets it must NOT surface any deferred
        // field — neither the cap nor the thresholds are deferred.
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "outlier-cap-dr",
            json!({
                "host": "reviews.default.svc.cluster.local",
                "subsets": [{
                    "name": "v1",
                    "labels": {"version": "v1"},
                    "trafficPolicy": {
                        "outlierDetection": {"consecutive5xxErrors": 3, "maxEjectionPercent": 50}
                    }
                }]
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
            !deferred.iter().any(|f| f.contains("maxEjectionPercent")),
            "subset maxEjectionPercent is applied per-subset now and must not be deferred, got {deferred:?}"
        );
    }

    #[test]
    fn destination_rule_port_level_http1_max_pending_requests_is_applied_not_deferred() {
        // F5.1 final knob: `http1MaxPendingRequests` is now PROJECTED and
        // ENFORCED at top-level / `portLevelSettings` (per-`(host,port)` pending
        // gate on the reqwest/H1 path), so it must NOT appear in
        // `deferred_fields` at port level. `maxRequestsPerConnection` remains
        // the only universally deferred connectionPool.http knob.
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "port-http-dr",
            json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    "portLevelSettings": [
                        {
                            "port": { "number": 8080 },
                            "connectionPool": {
                                "http": { "http1MaxPendingRequests": 64 }
                            }
                        }
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
            !deferred
                .iter()
                .any(|f| f.contains("http1MaxPendingRequests")),
            "port-level http1MaxPendingRequests is applied now and must NOT be deferred, got {deferred:?}"
        );
        assert!(
            deferred.is_empty(),
            "a port-level connectionPool.http with only applied knobs must defer nothing, got {deferred:?}"
        );
    }

    #[test]
    fn destination_rule_max_requests_per_connection_surfaces_as_deferred_all_scopes() {
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "max-reqs-dr",
            json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    "connectionPool": { "http": { "maxRequestsPerConnection": 2 } },
                    "portLevelSettings": [{
                        "port": { "number": 8080 },
                        "connectionPool": { "http": { "maxRequestsPerConnection": 3 } }
                    }]
                },
                "subsets": [{
                    "name": "v1",
                    "labels": { "version": "v1" },
                    "trafficPolicy": {
                        "connectionPool": { "http": { "maxRequestsPerConnection": 4 } }
                    }
                }]
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
                .any(|f| { f.contains("maxRequestsPerConnection") && f.contains("not applied") }),
            "maxRequestsPerConnection must be operator-visible as deferred, got {deferred:?}"
        );
    }

    #[test]
    fn destination_rule_subset_scoped_http_connection_pool_knobs_surface_as_deferred() {
        // codex round-1 Finding 4 (+ F5.1 final knob): h2UpgradePolicy /
        // maxRetries / http1MaxPendingRequests are APPLIED at top-level (must
        // NOT be deferred there), but the same fields inside a SUBSET
        // trafficPolicy are not applied (subset -> SubsetTrafficPolicy carries
        // no connectionPool.http), so the status writer must list them as
        // deferred.
        let obj = object(
            "networking.istio.io/v1",
            "DestinationRule",
            "subset-http-dr",
            json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    // Top-level: applied — must NOT appear as deferred.
                    "connectionPool": { "http": { "h2UpgradePolicy": "UPGRADE", "maxRetries": 4, "http1MaxPendingRequests": 32 } }
                },
                "subsets": [{
                    "name": "v1",
                    "labels": { "version": "v1" },
                    // Subset: ignored — must appear as deferred.
                    "trafficPolicy": {
                        "connectionPool": { "http": { "h2UpgradePolicy": "DO_NOT_UPGRADE", "maxRetries": 9, "http1MaxPendingRequests": 16 } }
                    }
                }]
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
        // All three subset-scoped knobs are listed, tagged as subset-scoped.
        for field in ["h2UpgradePolicy", "maxRetries", "http1MaxPendingRequests"] {
            assert!(
                deferred
                    .iter()
                    .any(|f| f.contains("subsets[]") && f.contains(field)),
                "deferred_fields should mention subset-scoped {field}, got {deferred:?}"
            );
        }
        // The top-level (applied) values must NOT appear as deferred. The only
        // deferred entries should be the subset-scoped ones.
        assert!(
            !deferred
                .iter()
                .any(|f| f.starts_with("trafficPolicy.connectionPool.http")),
            "top-level applied h2UpgradePolicy/maxRetries/http1MaxPendingRequests must not be deferred, got {deferred:?}"
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
    fn supported_kind_filter_accepts_proxy_config() {
        // ProxyConfig is watched (`ISTIO_CRDS`) and the status writer surfaces
        // FerrumAccepted — Istio's CRD declares subresources.status.
        let obj = object(
            "networking.istio.io/v1beta1",
            "ProxyConfig",
            "default-pc",
            json!({
                "concurrency": 4,
                "tracing": { "sampling": 12.5 }
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].kind, "ProxyConfig");
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["scope"].as_str(), Some("Namespace"));
        assert_eq!(detail["translation"]["concurrency"].as_u64(), Some(4));
        assert_eq!(
            detail["translation"]["tracing_sampling"].as_f64(),
            Some(12.5)
        );
    }

    #[test]
    fn api_resource_returns_proxy_config_v1beta1() {
        let update = IstioStatusUpdate {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "ProxyConfig".to_string(),
            namespace: "default".to_string(),
            name: "pc".to_string(),
            status: Value::Null,
            ferrum_detail: None,
        };
        let ar = istio_api_resource(&update).expect("ProxyConfig is a status-writer kind");
        assert_eq!(ar.group, "networking.istio.io");
        assert_eq!(ar.version, "v1beta1");
        assert_eq!(ar.plural, "proxyconfigs");
    }

    #[test]
    fn api_resource_returns_none_for_unsupported_kind() {
        let update = IstioStatusUpdate {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "EnvoyFilter".to_string(),
            namespace: "default".to_string(),
            name: "ef".to_string(),
            status: Value::Null,
            ferrum_detail: None,
        };
        assert!(
            istio_api_resource(&update).is_none(),
            "EnvoyFilter is not a status-writer kind"
        );
    }

    #[test]
    fn proxy_config_rejection_surfaces_invalid_condition() {
        let obj = object(
            "networking.istio.io/v1beta1",
            "ProxyConfig",
            "bad-pc",
            json!({ "concurrency": -1 }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    #[test]
    fn proxy_config_unusable_tracing_sampling_surfaces_invalid_condition() {
        // An out-of-range sampling value must land as
        // FerrumAccepted=False/Invalid rather than Accepted with a silently
        // dropped or unvalidated percentage. Note that Istio's v1beta1
        // ProxyConfig CRD has no `tracing` property in its structural spec
        // schema, so the API server prunes this field on a real cluster; this
        // pins the planner contract for non-pruned object feeds.
        let obj = object(
            "networking.istio.io/v1beta1",
            "ProxyConfig",
            "bad-sampling",
            json!({ "tracing": { "sampling": 5000.0 } }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
        assert!(
            c["message"]
                .as_str()
                .unwrap_or_default()
                .contains("tracing.sampling"),
            "status message must name the offending field: {:?}",
            c["message"]
        );
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["tracing_sampling"].as_f64(),
            Some(5000.0),
            "detail should retain the rejected numeric sampling for operators"
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

    // ── VirtualService ─────────────────────────────────────────────────────

    #[test]
    fn virtual_service_valid_routes_report_accepted() {
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "reviews-vs",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    { "route": [
                        { "destination": { "host": "reviews.default.svc.cluster.local" } }
                    ] }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        assert_eq!(c["reason"].as_str(), Some("Accepted"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["hosts"].as_u64(), Some(1));
        assert_eq!(
            detail["translation"]["http_routes_translated"].as_u64(),
            Some(1)
        );
    }

    #[test]
    fn virtual_service_clamped_fault_delay_is_operator_visible() {
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "slow-vs",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{
                    "route": [{
                        "destination": {
                            "host": "reviews.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }
                    }],
                    "fault": {
                        "delay": {
                            "fixedDelay": "61s",
                            "percentage": {"value": 100.0}
                        }
                    }
                }]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        let condition = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(condition["status"].as_str(), Some("True"));
        assert_eq!(condition["reason"].as_str(), Some("Accepted"));
        assert!(condition["message"].as_str().is_some_and(|message| {
            message.contains("clamped fields") && message.contains("fixedDelay")
        }));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["clamped_fields"],
            json!(["http[].fault.delay.fixedDelay above 60s (clamped to 60s)"])
        );
        assert_eq!(detail["translation"]["deferred_fields"], json!([]));
    }

    #[test]
    fn virtual_service_missing_destination_host_is_rejected() {
        // A route with a destination but no host fails translation.
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "bad-vs",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    { "route": [ { "destination": { "subset": "v1" } } ] }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        assert_eq!(updates.len(), 1);
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
        assert!(c["message"].as_str().unwrap().contains("rejected"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert!(detail["translation"]["error"].is_string());
    }

    #[test]
    fn virtual_service_tcp_unsupported_match_rejected() {
        // `spec.tcp[]` / `spec.tls[]` are translated to Ferrum stream proxies
        // (port / SNI-passthrough routing), but match predicates the stream
        // layer cannot express (here `sourceLabels`) fail closed as `Invalid`
        // rather than mis-routing.
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "tcp-vs",
            json!({
                "hosts": ["db.default.svc.cluster.local"],
                "tcp": [ {
                    "match": [ { "port": 3306, "sourceLabels": { "app": "billing" } } ],
                    "route": [ { "destination": { "host": "db.default.svc.cluster.local", "port": { "number": 3306 } } } ]
                } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let error = detail["translation"]["error"].as_str().unwrap();
        assert!(
            error.contains("sourceLabels"),
            "rejection error should mention the unsupported match, got: {error}"
        );
    }

    #[test]
    fn virtual_service_supported_tcp_route_is_accepted() {
        // A plain port-routed `spec.tcp[]` block translates to a stream proxy
        // and is accepted.
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "tcp-ok-vs",
            json!({
                "hosts": ["db.default.svc.cluster.local"],
                "tcp": [ {
                    "match": [ { "port": 3306 } ],
                    "route": [ { "destination": { "host": "db.default.svc.cluster.local", "port": { "number": 3306 } } } ]
                } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
    }

    #[test]
    fn virtual_service_cors_policy_exact_origin_not_deferred() {
        // `mirror` and an exact-origin `corsPolicy` are both translated now, so
        // neither is reported as deferred.
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "cors-vs",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "route": [ { "destination": { "host": "reviews.default.svc.cluster.local" } } ],
                        "mirror": { "host": "reviews-canary.default.svc.cluster.local" },
                        "corsPolicy": { "allowOrigins": [ { "exact": "https://example.com" } ] }
                    }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            !deferred.iter().any(|f| f.contains("corsPolicy")),
            "exact-origin http[].corsPolicy is translated and must not be deferred, got {deferred:?}"
        );
        assert!(
            !deferred.iter().any(|f| f.contains("mirror")),
            "http[].mirror is translated and must not be deferred, got {deferred:?}"
        );
    }

    #[test]
    fn virtual_service_cors_policy_regex_and_prefix_origins_translated_not_deferred() {
        // `regex` / `prefix` origin matchers now project onto the extended
        // `cors` plugin, so the policy is translated and must NOT be reported as
        // a deferred field (FerrumAccepted=True, routing applies).
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "cors-vs-regex",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "route": [ { "destination": { "host": "reviews.default.svc.cluster.local" } } ],
                        "corsPolicy": { "allowOrigins": [
                            { "regex": "https://.*\\.example\\.com" },
                            { "prefix": "https://app." }
                        ] }
                    }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            !deferred.iter().any(|f| f.contains("corsPolicy")),
            "regex/prefix-origin http[].corsPolicy is now translated and must not be deferred, got {deferred:?}"
        );
    }

    #[test]
    fn virtual_service_cors_policy_uncompilable_regex_origin_deferred() {
        // A `regex` matcher that does not compile cannot be projected into a
        // valid `cors` plugin, so the translator leaves the policy unprojected
        // and the status writer still reports it as deferred (fail-closed —
        // routing applies, FerrumAccepted=True).
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "cors-vs-bad-regex",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "route": [ { "destination": { "host": "reviews.default.svc.cluster.local" } } ],
                        // Unbalanced group → invalid RE2.
                        "corsPolicy": { "allowOrigins": [ { "regex": "https://(example" } ] }
                    }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.iter().any(|f| f.contains("corsPolicy")),
            "uncompilable-regex http[].corsPolicy should still be flagged as deferred, got {deferred:?}"
        );
    }

    #[test]
    fn virtual_service_cors_policy_credentialed_wildcard_is_deferred() {
        let obj = object(
            "networking.istio.io/v1",
            "VirtualService",
            "cors-vs-credentialed-star",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "route": [ { "destination": { "host": "reviews.default.svc.cluster.local" } } ],
                        "corsPolicy": {
                            "allowOrigins": [ { "exact": "*" } ],
                            "allowCredentials": true
                        }
                    }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.iter().any(|f| f.contains("corsPolicy")),
            "credentialed wildcard http[].corsPolicy must remain deferred, got {deferred:?}"
        );
    }

    /// Helper: the `corsPolicy`-related `deferred_fields` entries for one VS.
    fn cors_deferred_fields(spec: Value) -> Vec<String> {
        let obj = object("networking.istio.io/v1", "VirtualService", "cors-vs", spec);
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        updates[0].ferrum_detail.as_ref().unwrap()["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .filter(|field| field.contains("corsPolicy"))
            .map(str::to_string)
            .collect()
    }

    fn cors_vs_spec(cors: Value) -> Value {
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [
                {
                    "route": [ { "destination": { "host": "reviews.default.svc.cluster.local" } } ],
                    "corsPolicy": cors
                }
            ]
        })
    }

    /// Issue #3254: an exact origin that merely LOOKS like native wildcard
    /// syntax, and a non-canonical exact, are projected literally now — the
    /// status report must stop calling them deferred.
    #[test]
    fn virtual_service_cors_policy_literal_exact_origins_not_deferred() {
        for cors in [
            json!({ "allowOrigins": [ { "exact": "*.example.com" } ] }),
            json!({ "allowOrigins": [ { "exact": "https://Example.com:443" } ] }),
            json!({ "allowOrigin": ["*.example.com"] }),
        ] {
            let deferred = cors_deferred_fields(cors_vs_spec(cors.clone()));
            assert!(
                deferred.is_empty(),
                "literal exact corsPolicy {cors} must be translated, got {deferred:?}"
            );
        }
    }

    /// Issue #3253: matchers outside the explicit bounds stay fail-closed
    /// (deferred + unprojected), never silently truncated or approximated.
    #[test]
    fn virtual_service_cors_policy_out_of_bounds_matchers_stay_deferred() {
        let oversized = "a".repeat(crate::plugins::cors::MAX_ORIGIN_MATCHER_BYTES + 1);
        let too_many: Vec<Value> = (0..=crate::plugins::cors::MAX_ALLOWED_ORIGIN_ENTRIES)
            .map(|i| json!({ "exact": format!("https://app{i}.example.com") }))
            .collect();
        for cors in [
            json!({ "allowOrigins": [ { "exact": oversized } ] }),
            json!({ "allowOrigins": [ { "regex": format!("https://{}", "a".repeat(crate::plugins::cors::MAX_ORIGIN_MATCHER_BYTES)) } ] }),
            json!({ "allowOrigins": [ { "regex": "((((((((((((((((((((((((((((a))))))))))))))))))))))))))))" } ] }),
            json!({ "allowOrigins": too_many }),
        ] {
            let deferred = cors_deferred_fields(cors_vs_spec(cors.clone()));
            assert!(
                !deferred.is_empty(),
                "out-of-bounds corsPolicy {cors} must remain deferred, got {deferred:?}"
            );
        }
    }

    // ── ServiceEntry ───────────────────────────────────────────────────────

    #[test]
    fn service_entry_valid_reports_accepted_with_resolution_and_location() {
        let obj = object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "external-api",
            json!({
                "hosts": ["api.example.com"],
                "resolution": "DNS",
                "location": "MESH_EXTERNAL",
                "ports": [ { "number": 443, "name": "https", "protocol": "TLS" } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        assert!(c["message"].as_str().unwrap().contains("DNS"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["resolution"].as_str(), Some("DNS"));
        assert_eq!(
            detail["translation"]["location"].as_str(),
            Some("MESH_EXTERNAL")
        );
        assert_eq!(detail["translation"]["ports"].as_u64(), Some(1));
        // A TLS-only (non-UDP) ServiceEntry must NOT surface the UDP egress
        // deferral — its egress lane is fully materialized.
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.is_empty(),
            "TLS-only ServiceEntry must surface no deferred fields, got {deferred:?}"
        );
    }

    #[test]
    fn service_entry_udp_port_surfaces_egress_deferral_but_stays_accepted() {
        // F3 §3.3 stage 1: a `protocol: UDP` ServiceEntry translates fine
        // (`AppProtocol::Udp`) but the EgressGateway materializer skips UDP ports
        // as inert — so `kubectl describe` must show it ACCEPTED yet flag the
        // deferred egress lane in `deferred_fields`, never silently fully-accepted
        // while no proxy/listener/upstream is produced.
        let obj = object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "udp-dns",
            json!({
                "hosts": ["dns.external.com"],
                "resolution": "DNS",
                "location": "MESH_EXTERNAL",
                "ports": [ { "number": 53, "name": "dns", "protocol": "UDP" } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        // Still accepted (deferral, not rejection — rejecting would break the CRD).
        assert_eq!(c["status"].as_str(), Some("True"));
        assert_eq!(c["reason"].as_str(), Some("Accepted"));
        assert!(
            c["message"].as_str().unwrap().contains("deferred"),
            "message should flag the deferral, got {:?}",
            c["message"].as_str()
        );
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
                .any(|f| f.contains("UDP") && f.contains("egress materialization deferred")),
            "deferred_fields should mention the deferred UDP egress lane, got {deferred:?}"
        );
    }

    #[test]
    fn service_entry_mixed_tcp_udp_ports_surface_udp_egress_deferral() {
        // A DNS-like ServiceEntry exposing BOTH TCP/53 and UDP/53: the UDP port
        // alone is enough to surface the deferral (the TCP lane materializes; the
        // UDP lane is inert), and the resource stays accepted. Mirrors the
        // materializer test `egress_materializes_tcp_but_not_udp_for_dual_protocol_service`.
        let obj = object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "dual-dns",
            json!({
                "hosts": ["dns.external.com"],
                "resolution": "DNS",
                "location": "MESH_EXTERNAL",
                "ports": [
                    { "number": 53, "name": "dns-tcp", "protocol": "TCP" },
                    { "number": 53, "name": "dns-udp", "protocol": "UDP" }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.iter().any(|f| f.contains("UDP")),
            "a UDP port among TCP ports must still surface the UDP egress deferral, got {deferred:?}"
        );
    }

    #[test]
    fn service_entry_without_hosts_is_rejected() {
        let obj = object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "no-hosts",
            json!({ "resolution": "DNS" }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    // ── RequestAuthentication ────────────────────────────────────────────────

    #[test]
    fn request_authentication_valid_reports_accepted_and_permissive() {
        let obj = object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "jwt-req",
            json!({
                "selector": { "matchLabels": { "app": "api" } },
                "jwtRules": [ { "issuer": "https://issuer.example.com" } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        assert!(c["message"].as_str().unwrap().contains("permissive"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["jwt_rules"].as_u64(), Some(1));
        assert_eq!(
            detail["translation"]["scope"].as_str(),
            Some("WorkloadSelector")
        );
        assert_eq!(
            detail["translation"]["enforcement"].as_str(),
            Some("permissive")
        );
    }

    #[test]
    fn request_authentication_missing_issuer_is_rejected() {
        // jwtRules[].issuer is required; an entry without it fails translation.
        let obj = object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "bad-jwt",
            json!({ "jwtRules": [ { "audiences": ["aud"] } ] }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    // ── WorkloadEntry ─────────────────────────────────────────────────────────

    #[test]
    fn workload_entry_valid_reports_accepted_with_service_account() {
        let obj = object(
            "networking.istio.io/v1",
            "WorkloadEntry",
            "vm-1",
            json!({
                "address": "10.0.0.5",
                "serviceAccount": "payments",
                "labels": { "app": "payments" }
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["service_account"].as_str(),
            Some("payments")
        );
        assert_eq!(detail["translation"]["address"].as_str(), Some("10.0.0.5"));
    }

    #[test]
    fn workload_entry_cross_namespace_service_is_rejected() {
        // A `service` host pointing at a different namespace is rejected by
        // the translator; status must surface the rejection.
        let obj = object(
            "networking.istio.io/v1",
            "WorkloadEntry",
            "vm-cross",
            json!({
                "address": "10.0.0.6",
                "serviceAccount": "payments",
                "service": "payments.other-ns.svc.cluster.local"
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    // ── Sidecar ────────────────────────────────────────────────────────────

    #[test]
    fn sidecar_valid_egress_reports_accepted() {
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "default-sidecar",
            json!({
                "workloadSelector": { "labels": { "app": "frontend" } },
                "egress": [ { "hosts": ["./*", "istio-system/*"] } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["egress_entries"].as_u64(), Some(1));
        assert_eq!(
            detail["translation"]["scope"].as_str(),
            Some("WorkloadSelector")
        );
    }

    #[test]
    fn sidecar_empty_selector_reports_namespace_scope() {
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "empty-selector",
            json!({
                "workloadSelector": { "labels": {} },
                "egress": [ { "hosts": ["./*"] } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["scope"].as_str(), Some("Namespace"));
    }

    #[test]
    fn sidecar_root_namespace_default_reports_mesh_wide_scope() {
        let mut obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "root-default",
            json!({ "egress": [{ "hosts": ["*/*"] }] }),
        );
        obj.metadata.namespace = "istio-config".to_string();

        let updates = plan_istio_status_updates(
            &[obj],
            options().with_istio_root_namespace("istio-config".to_string()),
        );
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(detail["translation"]["scope"].as_str(), Some("MeshWide"));
    }

    #[test]
    fn sidecar_supported_ingress_is_modeled_not_deferred() {
        // A loopback HTTP listener is modeled (F6 §6.2): reported via
        // `ingress_modeled`, NOT flagged deferred.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "ingress-sidecar",
            json!({
                "ingress": [ { "port": { "number": 9080, "protocol": "HTTP", "name": "http" }, "defaultEndpoint": "127.0.0.1:8080" } ],
                "egress": [ { "hosts": ["./*"] } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options_ingress_enforced());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(1),
            "a loopback HTTP listener is modeled"
        );
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.is_empty(),
            "a fully supported ingress listener is not deferred, got {deferred:?}"
        );
    }

    #[test]
    fn sidecar_unsupported_ingress_surfaces_deferred_field() {
        // Unix-socket and non-HTTP-family listeners stay deferred even though
        // the resource is accepted; a supported sibling is still counted as
        // modeled.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "ingress-sidecar",
            json!({
                "ingress": [
                    { "port": { "number": 9080, "protocol": "HTTP" }, "defaultEndpoint": "127.0.0.1:8080" },
                    { "port": { "number": 7000, "protocol": "GRPC" }, "defaultEndpoint": "unix:///var/run/grpc.sock" },
                    { "port": { "number": 6000, "protocol": "TCP" }, "defaultEndpoint": "127.0.0.1:6000" }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options_ingress_enforced());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(1),
            "only the loopback HTTP listener is modeled"
        );
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.iter().any(|f| f.contains("unix://")),
            "unix-socket listener must be deferred, got {deferred:?}"
        );
        assert!(
            deferred.iter().any(|f| f.contains("non-HTTP-family")),
            "TCP listener must be deferred, got {deferred:?}"
        );
    }

    #[test]
    fn sidecar_https_ingress_is_modeled_not_deferred() {
        // F6 §6.2 (round-1 Finding 5, preserved by round-2): an HTTPS ingress
        // listener is a recognized HTTP-family protocol (mapped to a routable
        // `AppProtocol` by `sidecar_ingress_app_protocol`), which resolution
        // MATERIALIZES. The status classifier must agree (it routes the protocol
        // through the same shared predicate), so the live listener is reported as
        // modeled — NOT falsely reported as a deferred non-HTTP-family listener.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "ingress-sidecar",
            json!({
                "ingress": [ { "port": { "number": 8443, "protocol": "HTTPS", "name": "https" }, "defaultEndpoint": "127.0.0.1:8080" } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options_ingress_enforced());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(1),
            "an HTTPS listener (recognized HTTP-family) is modeled"
        );
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            !deferred.iter().any(|f| f.contains("non-HTTP-family")),
            "an HTTPS listener must NOT be reported as a deferred non-HTTP listener, got {deferred:?}"
        );
    }

    #[test]
    fn sidecar_mistyped_ingress_protocol_is_deferred_not_modeled() {
        // Codex round-2 P2: a mistyped protocol (`HTPS`) must NOT be reported as
        // modeled — the status writer must keep it in deferred_fields (matching
        // resolution, which now defers it as a non-HTTP listener) rather than
        // counting a non-HTTP listener as a live HTTP route.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "typo-sidecar",
            json!({
                "ingress": [ { "port": { "number": 8443, "protocol": "HTPS" }, "defaultEndpoint": "127.0.0.1:8080" } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options_ingress_enforced());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(0),
            "a mistyped protocol must not be counted as a modeled listener (even when enforced)"
        );
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.iter().any(|f| f.contains("non-HTTP-family")),
            "a mistyped protocol must be reported as a deferred non-HTTP listener, got {deferred:?}"
        );
    }

    #[test]
    fn sidecar_duplicate_ingress_port_counts_one_modeled() {
        // Codex round-3 P3: two supported `ingress[]` entries on the SAME listener
        // port. The slice resolver keeps only the first (reserves the port, warns
        // + drops the second), so the status writer must report ONE modeled
        // listener (not two) and surface the duplicate as a deferred field —
        // otherwise `kubectl` reports more modeled listeners than Ferrum
        // materializes, misleading rollout verification.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "dup-port-sidecar",
            json!({
                "ingress": [
                    { "port": { "number": 8443, "protocol": "HTTP" }, "defaultEndpoint": "127.0.0.1:8080" },
                    { "port": { "number": 8443, "protocol": "HTTP2" }, "defaultEndpoint": "127.0.0.1:9090" }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options_ingress_enforced());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(1),
            "two entries on the same listener port model only one listener"
        );
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred
                .iter()
                .any(|f| f.contains("duplicate listener port")),
            "the duplicate listener port must be reported as deferred, got {deferred:?}"
        );
    }

    #[test]
    fn sidecar_deferred_entry_does_not_reserve_port_for_later_valid_entry() {
        // A DEFERRED entry (non-HTTP) on a port must NOT reserve that port: a
        // later VALID entry on the same port number is still modeled — mirroring
        // the slice resolver, which reserves a port only on a SUCCESSFUL resolve.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "deferred-then-valid-sidecar",
            json!({
                "ingress": [
                    { "port": { "number": 8443, "protocol": "TCP" }, "defaultEndpoint": "127.0.0.1:8080" },
                    { "port": { "number": 8443, "protocol": "HTTP" }, "defaultEndpoint": "127.0.0.1:9090" }
                ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options_ingress_enforced());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(1),
            "the valid entry is modeled even though a deferred entry shares its port"
        );
        let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            deferred.iter().any(|f| f.contains("non-HTTP-family")),
            "the TCP entry is deferred as non-HTTP, got {deferred:?}"
        );
        assert!(
            !deferred
                .iter()
                .any(|f| f.contains("duplicate listener port")),
            "a deferred entry must not make a later valid entry a duplicate, got {deferred:?}"
        );
    }

    /// Codex round-4 P2: in the DEFAULT posture (`FERRUM_MESH_SIDECAR_ENFORCED`
    /// off / dry-run) the slice builder materializes NO ingress listeners, so the
    /// status writer must report `ingress_modeled == 0` even for a shape-modelable
    /// loopback HTTP listener — never a false positive while the data plane is
    /// still serving the default inbound behavior. The message makes the gated-off
    /// state explicit (and surfaces the modelable-when-enabled count).
    #[test]
    fn sidecar_ingress_not_modeled_when_enforcement_gate_off() {
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "ingress-sidecar-dry-run",
            json!({
                "ingress": [ { "port": { "number": 9080, "protocol": "HTTP", "name": "http" }, "defaultEndpoint": "127.0.0.1:8080" } ],
                "egress": [ { "hosts": ["./*"] } ]
            }),
        );
        // Default options() leaves mesh_sidecar_ingress_enforced = false.
        let updates = plan_istio_status_updates(&[obj], options());
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            detail["translation"]["ingress_modeled"].as_u64(),
            Some(0),
            "with the enforcement gate off the data plane materializes no ingress, so \
             ingress_modeled must be 0 even for a shape-modelable listener"
        );
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        // Still accepted (the resource is valid); only materialization is gated.
        assert_eq!(c["status"].as_str(), Some("True"));
        let message = c["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("not materialized") && message.contains("1 modelable when enabled"),
            "the message must surface that ingress is gated off and the modelable count, got: {message}"
        );

        // Flipping the gate on materializes the same listener and reports it.
        let obj_enforced = object(
            "networking.istio.io/v1",
            "Sidecar",
            "ingress-sidecar-dry-run",
            json!({
                "ingress": [ { "port": { "number": 9080, "protocol": "HTTP", "name": "http" }, "defaultEndpoint": "127.0.0.1:8080" } ],
                "egress": [ { "hosts": ["./*"] } ]
            }),
        );
        let enforced = plan_istio_status_updates(&[obj_enforced], options_ingress_enforced());
        let enforced_detail = enforced[0].ferrum_detail.as_ref().unwrap();
        assert_eq!(
            enforced_detail["translation"]["ingress_modeled"].as_u64(),
            Some(1),
            "the same listener is reported modeled once the enforcement gate is on"
        );
    }

    #[test]
    fn sidecar_invalid_egress_is_rejected() {
        // egress[].hosts must be a non-empty array; an empty array is rejected.
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            "bad-sidecar",
            json!({ "egress": [ { "hosts": [] } ] }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    // ── Telemetry ──────────────────────────────────────────────────────────

    #[test]
    fn telemetry_valid_reports_accepted_with_sections() {
        let obj = object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "mesh-default",
            json!({
                "metrics": [ { "providers": [ { "name": "prometheus" } ] } ],
                "accessLogging": [ { "disabled": false } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("True"));
        let detail = updates[0].ferrum_detail.as_ref().unwrap();
        let sections: Vec<&str> = detail["translation"]["sections"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(sections.contains(&"metrics"));
        assert!(sections.contains(&"accessLogging"));
    }

    #[test]
    fn telemetry_invalid_environment_custom_tag_is_rejected() {
        let obj = object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "bad-env-tag",
            json!({
                "tracing": [{
                    "customTags": {
                        "cluster": {
                            "environment": {
                                "name": "BAD-NAME"
                            }
                        }
                    }
                }]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
        let message = c["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("invalid environment variable name"),
            "expected visible env-tag rejection, got {message}"
        );
    }

    #[test]
    fn telemetry_invalid_tracing_mode_is_rejected() {
        // tracing.match.mode of an unknown value is rejected by the translator.
        let obj = object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "bad-telemetry",
            json!({
                "tracing": [ { "match": { "mode": "NONSENSE" } } ]
            }),
        );
        let updates = plan_istio_status_updates(&[obj], options());
        let c = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(c["status"].as_str(), Some("False"));
        assert_eq!(c["reason"].as_str(), Some("Invalid"));
    }

    // ── api_resource mapping for newly-covered kinds ─────────────────────────

    #[test]
    fn api_resource_maps_all_translated_istio_kinds() {
        let cases = [
            (
                "security.istio.io/v1",
                "RequestAuthentication",
                "security.istio.io",
                "requestauthentications",
            ),
            (
                "networking.istio.io/v1",
                "VirtualService",
                "networking.istio.io",
                "virtualservices",
            ),
            (
                "networking.istio.io/v1",
                "ServiceEntry",
                "networking.istio.io",
                "serviceentries",
            ),
            (
                "networking.istio.io/v1",
                "WorkloadEntry",
                "networking.istio.io",
                "workloadentries",
            ),
            (
                "networking.istio.io/v1",
                "Sidecar",
                "networking.istio.io",
                "sidecars",
            ),
            (
                "telemetry.istio.io/v1",
                "Telemetry",
                "telemetry.istio.io",
                "telemetries",
            ),
        ];
        for (api_version, kind, group, plural) in cases {
            let update = IstioStatusUpdate {
                api_version: api_version.to_string(),
                kind: kind.to_string(),
                namespace: "default".to_string(),
                name: "x".to_string(),
                status: Value::Null,
                ferrum_detail: None,
            };
            let ar = istio_api_resource(&update)
                .unwrap_or_else(|| panic!("expected ApiResource for {kind}"));
            assert_eq!(ar.group, group, "group mismatch for {kind}");
            assert_eq!(ar.plural, plural, "plural mismatch for {kind}");
            assert_eq!(ar.kind, kind);
        }
    }
}
