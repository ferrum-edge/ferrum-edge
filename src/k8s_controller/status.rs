use futures_util::StreamExt;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use serde_json::{Value, json};
use std::collections::HashSet;
use tracing::warn;

use crate::config_sources::k8s::{
    GatewayApiRouteConflict, GatewayApiRouteConflictKey, K8sObject, K8sResourceKey,
    K8sTranslateError, K8sTranslationOptions, gateway_api_route_conflict_keys, resource_id,
    translate_k8s_objects_with_filter,
};

pub const FERRUM_GATEWAY_CONTROLLER_NAME: &str = "ferrum.io/gateway-controller";
const GATEWAY_API_STATUS_PATCH_PARALLELISM: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayApiStatusUpdate {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub status: Value,
}

#[derive(Clone)]
pub struct GatewayApiStatusWriter {
    client: Client,
}

impl GatewayApiStatusWriter {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn patch_updates(
        &self,
        updates: Vec<GatewayApiStatusUpdate>,
    ) -> Result<(), kube::Error> {
        // Build one future per update that captures its identity by *move* so
        // partial failures can be logged with the resource they failed on,
        // and so the resulting futures stay `Send + 'static` for
        // `tokio::spawn` (no `&GatewayApiStatusUpdate` borrows held across
        // awaits — that would trip rustc's HRTB Send check).
        let client = self.client.clone();
        let futures = updates.into_iter().filter_map(move |update| {
            let Some(ar) = api_resource_for_update(&update) else {
                warn!(
                    api_version = %update.api_version,
                    kind = %update.kind,
                    namespace = %update.namespace,
                    name = %update.name,
                    "Skipping Gateway API status update for unsupported resource version"
                );
                return None;
            };
            let api: Api<DynamicObject> = if update.kind == "GatewayClass" {
                Api::all_with(client.clone(), &ar)
            } else {
                Api::namespaced_with(client.clone(), &update.namespace, &ar)
            };
            let name = update.name.clone();
            let kind = update.kind.clone();
            let namespace = update.namespace.clone();
            Some(async move {
                let result = async {
                    let live_status = match api.get_status(&name).await {
                        Ok(live) => live.data.get("status").cloned(),
                        Err(error) => {
                            warn!(
                                api_version = %update.api_version,
                                kind = %update.kind,
                                namespace = %update.namespace,
                                name = %update.name,
                                error = %error,
                                "Gateway API status read failed; attempting status patch from planned state"
                            );
                            None
                        }
                    };
                    let patch = status_patch_for_update(&update, live_status.as_ref());
                    // TODO(ssa): switch to Patch::Apply once the chart guarantees the
                    // status subresource accepts server-side apply. JSON Merge Patch
                    // (RFC 7396) replaces arrays wholesale, leaving a narrow TOCTOU
                    // window between `get_status` and `patch_status` against other
                    // controllers writing the same `parents[]` array.
                    let params = PatchParams {
                        field_manager: Some(FERRUM_GATEWAY_CONTROLLER_NAME.to_string()),
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
        // Patch Gateway API status updates with bounded concurrency so bursty
        // reconcile rounds cannot fan out unbounded API requests.
        let mut stream = futures_util::stream::iter(futures)
            .buffer_unordered(GATEWAY_API_STATUS_PATCH_PARALLELISM);
        while let Some((kind, namespace, name, result)) = stream.next().await {
            if let Err(error) = result {
                warn!(
                    %kind,
                    %namespace,
                    %name,
                    error = %error,
                    "Gateway API status patch failed"
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

pub fn plan_gateway_api_status_updates(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    route_conflicts: &[GatewayApiRouteConflict],
) -> Vec<GatewayApiStatusUpdate> {
    objects
        .iter()
        .filter(|object| is_status_kind(&object.kind))
        .filter_map(|object| {
            let managed_parent_refs = if matches!(object.kind.as_str(), "HTTPRoute" | "GRPCRoute") {
                managed_route_parent_refs(objects, object)
            } else {
                Vec::new()
            };
            if !status_target_is_managed_by_ferrum(objects, object, &managed_parent_refs) {
                return None;
            }
            let resource_key = K8sResourceKey::from_object(object);
            let managed_parent_ref_keys: HashSet<String> = managed_parent_refs
                .iter()
                .map(|parent_ref| route_parent_ref_key(object, parent_ref))
                .collect();
            let object_conflicts: Vec<&GatewayApiRouteConflict> = route_conflicts
                .iter()
                .filter(|conflict| {
                    conflict.loser == resource_key
                        && (managed_parent_ref_keys.is_empty()
                            || managed_parent_ref_keys.contains(&conflict.key.parent_ref))
                })
                .collect();
            let route_keys = if matches!(object.kind.as_str(), "HTTPRoute" | "GRPCRoute") {
                gateway_api_route_conflict_keys(object)
                    .into_iter()
                    .filter(|key| managed_parent_ref_keys.contains(&key.parent_ref))
                    .collect()
            } else {
                Vec::new()
            };
            let status = desired_status_for_object(
                objects,
                object,
                options.clone(),
                &object_conflicts,
                &route_keys,
                &managed_parent_refs,
            );
            if status == object.status {
                return None;
            }
            Some(GatewayApiStatusUpdate {
                api_version: object.api_version.clone(),
                kind: object.kind.clone(),
                namespace: object.metadata.namespace.clone(),
                name: object.metadata.name.clone(),
                status,
            })
        })
        .collect()
}

fn desired_status_for_object(
    objects: &[K8sObject],
    object: &K8sObject,
    options: K8sTranslationOptions,
    route_conflicts: &[&GatewayApiRouteConflict],
    route_keys: &[GatewayApiRouteConflictKey],
    managed_parent_refs: &[Value],
) -> Value {
    if object.kind == "GatewayClass" {
        return gateway_class_status(object);
    }

    let result = translate_k8s_objects_with_filter(objects, options, |candidate| {
        same_resource(candidate, object)
            || candidate.kind == "ReferenceGrant"
            || candidate.kind == "Service"
    });

    match object.kind.as_str() {
        "Gateway" => gateway_status(object, result.as_ref()),
        "HTTPRoute" | "GRPCRoute" => route_status(
            object,
            result.as_ref(),
            managed_parent_refs,
            route_conflicts,
            route_keys,
        ),
        _ => Value::Object(Default::default()),
    }
}

fn gateway_class_status(object: &K8sObject) -> Value {
    let conditions = vec![
        condition(
            object,
            &object.status,
            "Accepted",
            true,
            "Accepted",
            "Ferrum accepted this GatewayClass",
        ),
        condition(
            object,
            &object.status,
            "SupportedVersion",
            true,
            "SupportedVersion",
            "Ferrum supports Gateway API v1",
        ),
    ];

    let mut status = object.status.clone();
    merge_status_conditions(&mut status, &["Accepted", "SupportedVersion"], conditions);
    status
}

fn gateway_status(
    object: &K8sObject,
    result: Result<&crate::config_sources::k8s::K8sTranslation, &K8sTranslateError>,
) -> Value {
    let (accepted, programmed, message) = match result {
        Ok(translation) => (
            true,
            gateway_programmed(object, &translation.config),
            "Ferrum accepted this Gateway".to_string(),
        ),
        Err(error) => (
            false,
            false,
            format!("Ferrum rejected this Gateway: {error}"),
        ),
    };

    let conditions = vec![
        condition(
            object,
            &object.status,
            "Accepted",
            accepted,
            if accepted { "Accepted" } else { "Invalid" },
            &message,
        ),
        condition(
            object,
            &object.status,
            "ResolvedRefs",
            accepted,
            if accepted {
                "ResolvedRefs"
            } else {
                "TranslationFailed"
            },
            if accepted {
                "All Gateway references accepted by Ferrum"
            } else {
                &message
            },
        ),
        condition(
            object,
            &object.status,
            "Programmed",
            programmed,
            if programmed {
                "Programmed"
            } else if accepted {
                "NoListeners"
            } else {
                "TranslationFailed"
            },
            if programmed {
                "Ferrum programmed this Gateway"
            } else if accepted {
                "Ferrum accepted this Gateway but found no materialized listeners"
            } else {
                &message
            },
        ),
        condition(
            object,
            &object.status,
            "Conflicted",
            false,
            "NoConflicts",
            "No Gateway API conflicts detected by Ferrum",
        ),
    ];

    let mut status = object.status.clone();
    merge_status_conditions(
        &mut status,
        &["Accepted", "ResolvedRefs", "Programmed", "Conflicted"],
        conditions,
    );
    status
}

fn route_conflict_message(conflict: &GatewayApiRouteConflict) -> String {
    format!(
        "Ferrum rejected part of this route because it conflicts on parent={} host={} path={}; winner is {}/{}",
        conflict.key.parent_ref,
        conflict.key.hostname,
        conflict.key.listen_path,
        conflict.winner.namespace,
        conflict.winner.name
    )
}

fn ensure_status_object(status: &mut Value) -> &mut serde_json::Map<String, Value> {
    if !status.is_object() {
        *status = Value::Object(Default::default());
    }
    match status {
        Value::Object(map) => map,
        _ => unreachable!("status was normalized to an object"),
    }
}

fn merge_status_conditions(status: &mut Value, owned_types: &[&str], desired: Vec<Value>) {
    let status_object = ensure_status_object(status);
    let mut conditions = status_object
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
    status_object.insert("conditions".to_string(), Value::Array(conditions));
}

fn route_status(
    object: &K8sObject,
    result: Result<&crate::config_sources::k8s::K8sTranslation, &K8sTranslateError>,
    managed_parent_refs: &[Value],
    route_conflicts: &[&GatewayApiRouteConflict],
    route_keys: &[GatewayApiRouteConflictKey],
) -> Value {
    let (accepted, resolved_refs, programmed, accepted_reason, resolved_refs_reason, message) =
        match result {
            Ok(translation) => {
                let programmed = route_programmed(object, &translation.config);
                (
                    true,
                    true,
                    programmed,
                    if programmed { "Accepted" } else { "NoRules" },
                    "ResolvedRefs",
                    if programmed {
                        "Ferrum accepted and programmed this route".to_string()
                    } else {
                        "Ferrum accepted this route but no materialized rule was produced"
                            .to_string()
                    },
                )
            }
            Err(error) => {
                if error_is_reference_resolution(error) {
                    (
                        true,
                        false,
                        false,
                        "Accepted",
                        "RefNotPermitted",
                        format!(
                            "Ferrum accepted this route but could not resolve all backendRefs: {error}"
                        ),
                    )
                } else if error_is_parent_ref_not_allowed(error) {
                    (
                        false,
                        true,
                        false,
                        "NotAllowedByListeners",
                        "ResolvedRefs",
                        format!("Ferrum rejected this route attachment: {error}"),
                    )
                } else {
                    (
                        false,
                        false,
                        false,
                        "Invalid",
                        "Invalid",
                        format!("Ferrum rejected this route: {error}"),
                    )
                }
            }
        };

    let mut parents = retained_existing_parent_statuses(&object.status);
    for parent_ref in managed_parent_refs {
        let existing_parent_status = existing_parent_status(&object.status, object, parent_ref);
        let parent_ref_key = route_parent_ref_key(object, parent_ref);
        let parent_conflicts: Vec<&GatewayApiRouteConflict> = route_conflicts
            .iter()
            .copied()
            .filter(|conflict| conflict.key.parent_ref == parent_ref_key)
            .collect();
        let parent_conflict_keys: HashSet<&GatewayApiRouteConflictKey> = parent_conflicts
            .iter()
            .map(|conflict| &conflict.key)
            .collect();
        let parent_route_keys: Vec<&GatewayApiRouteConflictKey> = route_keys
            .iter()
            .filter(|key| key.parent_ref == parent_ref_key)
            .collect();
        let has_conflict = !parent_conflicts.is_empty();
        let all_parent_matches_conflicted = has_conflict
            && !parent_route_keys.is_empty()
            && parent_route_keys
                .iter()
                .all(|key| parent_conflict_keys.contains(key));
        let conflict_message = parent_conflicts
            .first()
            .map(|conflict| route_conflict_message(conflict));
        let accepted_for_parent = accepted && !all_parent_matches_conflicted;
        let accepted_reason = if all_parent_matches_conflicted {
            "Conflicted"
        } else {
            accepted_reason
        };
        let accepted_message = if all_parent_matches_conflicted {
            conflict_message.as_deref().unwrap_or(&message)
        } else {
            &message
        };
        let programmed_for_parent = programmed && !all_parent_matches_conflicted;
        let programmed_reason = if programmed_for_parent {
            "Programmed"
        } else if all_parent_matches_conflicted {
            "Conflicted"
        } else if !resolved_refs {
            resolved_refs_reason
        } else if accepted_for_parent {
            accepted_reason
        } else {
            "TranslationFailed"
        };
        let programmed_message = if programmed_for_parent {
            "Ferrum programmed this route"
        } else if all_parent_matches_conflicted {
            conflict_message.as_deref().unwrap_or(&message)
        } else {
            &message
        };
        let conflicted_message = conflict_message
            .as_deref()
            .unwrap_or("No Gateway API conflicts detected by Ferrum");
        let conditions = vec![
            condition_at(
                object,
                existing_parent_status,
                "Accepted",
                accepted_for_parent,
                accepted_reason,
                accepted_message,
            ),
            condition_at(
                object,
                existing_parent_status,
                "ResolvedRefs",
                resolved_refs,
                if resolved_refs {
                    "ResolvedRefs"
                } else {
                    resolved_refs_reason
                },
                if resolved_refs {
                    "All backendRefs accepted by Ferrum"
                } else {
                    &message
                },
            ),
            condition_at(
                object,
                existing_parent_status,
                "Programmed",
                programmed_for_parent,
                programmed_reason,
                programmed_message,
            ),
            condition_at(
                object,
                existing_parent_status,
                "Conflicted",
                has_conflict,
                if has_conflict {
                    "Conflicted"
                } else {
                    "NoConflicts"
                },
                conflicted_message,
            ),
        ];
        let conditions = merge_condition_entries(existing_parent_status, conditions);
        parents.push(json!({
            "parentRef": parent_ref,
            "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
            "conditions": conditions,
        }));
    }

    let mut status = object.status.clone();
    ensure_status_object(&mut status).insert("parents".to_string(), Value::Array(parents));
    status
}

fn status_patch_for_update(update: &GatewayApiStatusUpdate, live_status: Option<&Value>) -> Value {
    let fallback_status = &update.status;
    let live_status_for_merge = live_status.unwrap_or(fallback_status);
    let mut status_patch = serde_json::Map::new();

    match update.kind.as_str() {
        "GatewayClass" | "Gateway" => {
            let desired_conditions =
                desired_owned_conditions(&update.status, owned_condition_types(&update.kind));
            let condition_source = match live_status {
                Some(status) => existing_conditions(status),
                None => existing_conditions(fallback_status),
            };
            let merged_conditions = merge_condition_entries(condition_source, desired_conditions);
            status_patch.insert("conditions".to_string(), Value::Array(merged_conditions));
        }
        "HTTPRoute" | "GRPCRoute" => {
            status_patch.insert(
                "parents".to_string(),
                Value::Array(merge_parent_statuses(
                    live_status_for_merge,
                    desired_ferrum_parent_statuses(&update.status),
                )),
            );
        }
        _ => {
            status_patch = update.status.as_object().cloned().unwrap_or_default();
        }
    }

    let mut patch = serde_json::Map::new();
    patch.insert("status".to_string(), Value::Object(status_patch));
    Value::Object(patch)
}

fn owned_condition_types(kind: &str) -> &'static [&'static str] {
    match kind {
        "GatewayClass" => &["Accepted", "SupportedVersion"],
        "Gateway" => &["Accepted", "ResolvedRefs", "Programmed", "Conflicted"],
        _ => &[],
    }
}

fn desired_owned_conditions(status: &Value, owned_types: &[&str]) -> Vec<Value> {
    existing_conditions(status)
        .into_iter()
        .flatten()
        .filter(|condition| {
            condition_type(condition)
                .is_some_and(|condition_type| owned_types.contains(&condition_type))
        })
        .cloned()
        .collect()
}

fn existing_conditions(status: &Value) -> Option<&[Value]> {
    status
        .get("conditions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn condition(
    object: &K8sObject,
    status: &Value,
    condition_type: &str,
    value: bool,
    reason: &str,
    message: &str,
) -> Value {
    condition_at(
        object,
        existing_conditions(status),
        condition_type,
        value,
        reason,
        message,
    )
}

fn condition_at(
    object: &K8sObject,
    existing_conditions: Option<&[Value]>,
    condition_type: &str,
    value: bool,
    reason: &str,
    message: &str,
) -> Value {
    let status = if value { "True" } else { "False" };
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
        .unwrap_or_else(|| {
            // Match the Kubernetes API server's `Z`-suffixed RFC 3339 form so a
            // re-emitted, value-unchanged condition compares equal to what the
            // server persisted on the previous reconcile and the existing
            // `lastTransitionTime` can be preserved.
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
        });

    let observed_generation = match object.metadata.generation {
        Some(generation) => generation,
        None => {
            warn!(
                kind = %object.kind,
                namespace = %object.metadata.namespace,
                name = %object.metadata.name,
                "Gateway API resource missing metadata.generation; reporting observedGeneration=1"
            );
            1
        }
    };

    json!({
        "type": condition_type,
        "status": status,
        "observedGeneration": observed_generation,
        "reason": reason,
        "message": message,
        "lastTransitionTime": last_transition_time,
    })
}

fn merge_condition_entries(
    existing_conditions: Option<&[Value]>,
    desired_conditions: Vec<Value>,
) -> Vec<Value> {
    let desired_types: HashSet<String> = desired_conditions
        .iter()
        .filter_map(condition_type)
        .map(ToOwned::to_owned)
        .collect();
    let mut inserted_types = HashSet::new();
    let mut merged = Vec::new();

    for existing_condition in existing_conditions.into_iter().flatten() {
        let Some(existing_type) = condition_type(existing_condition) else {
            merged.push(existing_condition.clone());
            continue;
        };
        if !desired_types.contains(existing_type) {
            merged.push(existing_condition.clone());
            continue;
        }
        if inserted_types.insert(existing_type.to_string())
            && let Some(desired_condition) = desired_conditions
                .iter()
                .find(|condition| condition_type(condition) == Some(existing_type))
        {
            // If the desired condition's value matches the existing one,
            // preserve the existing `lastTransitionTime` — the merge target may
            // be a freshly re-read live status whose timestamp is fresher than
            // (or differently formatted from) the snapshot value we computed
            // earlier in the planning pass.
            merged.push(preserve_unchanged_transition_time(
                desired_condition.clone(),
                existing_condition,
            ));
        }
    }

    for desired_condition in desired_conditions {
        let Some(desired_type) = condition_type(&desired_condition) else {
            merged.push(desired_condition);
            continue;
        };
        if inserted_types.insert(desired_type.to_string()) {
            merged.push(desired_condition);
        }
    }

    merged
}

fn preserve_unchanged_transition_time(mut desired: Value, existing: &Value) -> Value {
    let same_value = desired.get("status").and_then(Value::as_str)
        == existing.get("status").and_then(Value::as_str)
        && desired.get("reason").and_then(Value::as_str)
            == existing.get("reason").and_then(Value::as_str)
        && desired.get("message").and_then(Value::as_str)
            == existing.get("message").and_then(Value::as_str);
    if !same_value {
        return desired;
    }
    let Some(existing_time) = existing.get("lastTransitionTime").cloned() else {
        return desired;
    };
    if let Value::Object(map) = &mut desired {
        map.insert("lastTransitionTime".to_string(), existing_time);
    }
    desired
}

fn condition_type(condition: &Value) -> Option<&str> {
    condition.get("type").and_then(Value::as_str)
}

fn existing_parent_status<'a>(
    status: &'a Value,
    object: &K8sObject,
    parent_ref: &Value,
) -> Option<&'a [Value]> {
    let parent_ref_key = route_parent_ref_key(object, parent_ref);
    status
        .get("parents")
        .and_then(Value::as_array)
        .and_then(|parents| {
            parents.iter().find(|parent| {
                parent.get("controllerName").and_then(Value::as_str)
                    == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                    && parent.get("parentRef").is_some_and(|existing_ref| {
                        route_parent_ref_key(object, existing_ref) == parent_ref_key
                    })
            })
        })
        .and_then(|parent| parent.get("conditions"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn merge_parent_statuses(status: &Value, desired_ferrum_parents: Vec<Value>) -> Vec<Value> {
    retained_existing_parent_statuses(status)
        .into_iter()
        .chain(desired_ferrum_parents)
        .collect()
}

fn desired_ferrum_parent_statuses(status: &Value) -> Vec<Value> {
    status
        .get("parents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|parent| is_ferrum_parent_status(parent))
        .cloned()
        .collect()
}

fn retained_existing_parent_statuses(status: &Value) -> Vec<Value> {
    status
        .get("parents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|parent| !is_ferrum_parent_status(parent))
        .cloned()
        .collect()
}

fn is_ferrum_parent_status(parent: &Value) -> bool {
    parent.get("controllerName").and_then(Value::as_str) == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
}

fn has_ferrum_parent_status(status: &Value) -> bool {
    status
        .get("parents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        })
}

fn route_parent_refs(object: &K8sObject) -> Vec<Value> {
    object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .filter(|refs| !refs.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn status_target_is_managed_by_ferrum(
    objects: &[K8sObject],
    object: &K8sObject,
    managed_parent_refs: &[Value],
) -> bool {
    match object.kind.as_str() {
        "GatewayClass" => gateway_class_is_managed_by_ferrum(object),
        "Gateway" => gateway_is_managed_by_ferrum(objects, object),
        "HTTPRoute" | "GRPCRoute" => {
            !managed_parent_refs.is_empty() || has_ferrum_parent_status(&object.status)
        }
        _ => false,
    }
}

fn gateway_is_managed_by_ferrum(objects: &[K8sObject], gateway: &K8sObject) -> bool {
    let Some(class_name) = gateway.spec.get("gatewayClassName").and_then(Value::as_str) else {
        return false;
    };
    objects.iter().any(|object| {
        object.kind == "GatewayClass"
            && object.metadata.name == class_name
            && gateway_class_is_managed_by_ferrum(object)
    })
}

fn managed_route_parent_refs(objects: &[K8sObject], route: &K8sObject) -> Vec<Value> {
    route_parent_refs(route)
        .into_iter()
        .filter(|parent_ref| parent_ref_targets_managed_gateway(objects, route, parent_ref))
        .collect()
}

fn parent_ref_targets_managed_gateway(
    objects: &[K8sObject],
    route: &K8sObject,
    parent_ref: &Value,
) -> bool {
    let group = parent_ref
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or("gateway.networking.k8s.io");
    let kind = parent_ref
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Gateway");
    let Some(name) = parent_ref.get("name").and_then(Value::as_str) else {
        return false;
    };
    if group != "gateway.networking.k8s.io" || kind != "Gateway" {
        return false;
    }
    let namespace = parent_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    objects.iter().any(|object| {
        object.kind == "Gateway"
            && object.metadata.namespace == namespace
            && object.metadata.name == name
            && gateway_is_managed_by_ferrum(objects, object)
    })
}

fn route_parent_ref_key(route: &K8sObject, parent_ref: &Value) -> String {
    let group = parent_ref
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or("gateway.networking.k8s.io");
    let kind = parent_ref
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Gateway");
    let namespace = parent_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    let name = parent_ref
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("*");
    let section = parent_ref
        .get("sectionName")
        .and_then(Value::as_str)
        .unwrap_or("*");
    let port = parent_ref
        .get("port")
        .and_then(Value::as_u64)
        .map_or_else(|| "*".to_string(), |port| port.to_string());
    format!("{group}/{kind}/{namespace}/{name}/{section}/{port}")
}

fn gateway_programmed(object: &K8sObject, config: &crate::config::types::GatewayConfig) -> bool {
    // Mesh services derived from this Gateway are named `{gateway.name}-{listener.name}`
    // (see `mesh_services_from_gateway` in `gateway_api.rs`). Use exact match against
    // each listener name to avoid a false positive when another Gateway's name is a
    // prefix of this one (e.g. `edge` matching `edge-internal-http`).
    let Some(mesh) = config.mesh.as_ref() else {
        return false;
    };
    let Some(listeners) = object.spec.get("listeners").and_then(Value::as_array) else {
        return false;
    };
    listeners.iter().any(|listener| {
        let listener_name = listener
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("listener");
        let expected = format!("{}-{}", object.metadata.name, listener_name);
        mesh.services.iter().any(|service| {
            service.namespace == object.metadata.namespace && service.name == expected
        })
    })
}

fn route_programmed(object: &K8sObject, config: &crate::config::types::GatewayConfig) -> bool {
    // Route proxy IDs follow `gwapi-route-{ns}-{name}-{route_kind}-{rule_idx}[-{match_idx}][-host{host_idx}]`
    // (see `gateway_api::http_route_resources`). Requiring the route_kind segment
    // to be immediately followed by a digit disambiguates routes whose names
    // start with another route's name (e.g. `api` vs `api-httproute`, where both
    // proxy IDs share `gwapi-route-{ns}-api-httproute-`). This avoids
    // materialising O(rules × matches × hostnames) candidate strings per route
    // and per reconcile — the previous HashSet approach generated ~1500 strings
    // for a 5-rule × 5-match × 50-hostname route just to membership-test them.
    // TODO: replace this naming-convention reconstruction with a typed
    // back-reference on `Proxy` (e.g., `Proxy.metadata.k8s_source`) populated by
    // the translator. Until then, any change to `gateway_api::http_route_resources`
    // proxy-id format must be mirrored here.
    let route_kind = object.kind.to_ascii_lowercase();
    let prefix = format!(
        "{}-",
        resource_id(
            "gwapi-route",
            &object.metadata.namespace,
            &object.metadata.name,
            &route_kind,
        )
    );
    config.proxies.iter().any(|proxy| {
        if proxy.namespace != object.metadata.namespace {
            return false;
        }
        let Some(remainder) = proxy.id.strip_prefix(&prefix) else {
            return false;
        };
        remainder
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
    })
}

fn error_is_reference_resolution(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("ReferenceGrant") || message.contains("only core Service")
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn error_is_parent_ref_not_allowed(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("parentRef.namespace")
                && message.contains("only same-namespace Gateway attachments are accepted")
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn same_resource(left: &K8sObject, right: &K8sObject) -> bool {
    left.api_version == right.api_version
        && left.kind == right.kind
        && left.metadata.namespace == right.metadata.namespace
        && left.metadata.name == right.metadata.name
}

fn is_status_kind(kind: &str) -> bool {
    matches!(kind, "GatewayClass" | "Gateway" | "HTTPRoute" | "GRPCRoute")
}

fn api_resource_for_update(update: &GatewayApiStatusUpdate) -> Option<ApiResource> {
    let (group, version) = update.api_version.split_once('/')?;
    let plural = match (update.kind.as_str(), version) {
        ("GatewayClass", "v1" | "v1beta1") => "gatewayclasses",
        ("Gateway", "v1" | "v1beta1") => "gateways",
        ("HTTPRoute", "v1" | "v1beta1") => "httproutes",
        ("GRPCRoute", "v1") => "grpcroutes",
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

fn gateway_class_is_managed_by_ferrum(object: &K8sObject) -> bool {
    object.spec.get("controllerName").and_then(Value::as_str)
        == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{
        K8sMetadata, K8sTranslationOptions, gateway_api_route_conflicts,
    };
    use crate::identity::spiffe::TrustDomain;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    /// Convenience wrapper that recomputes conflicts over the supplied
    /// `objects`. In production the reconciler instead threads the
    /// translator's filtered conflict list through, but the existing tests
    /// don't exercise the invalid-route case and the full-set computation
    /// gives them the same answer.
    fn plan_status_updates(
        objects: &[K8sObject],
        options: K8sTranslationOptions,
    ) -> Vec<GatewayApiStatusUpdate> {
        let conflicts = gateway_api_route_conflicts(objects, &options);
        plan_gateway_api_status_updates(objects, options, &conflicts)
    }

    fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                namespace: "default".to_string(),
                generation: Some(7),
                labels: Default::default(),
                annotations: Default::default(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec,
            status: Value::Object(Default::default()),
        }
    }

    fn ferrum_gateway_class() -> K8sObject {
        object(
            "GatewayClass",
            "ferrum",
            json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
        )
    }

    fn other_gateway_class() -> K8sObject {
        object(
            "GatewayClass",
            "other",
            json!({ "controllerName": "example.com/other-controller" }),
        )
    }

    fn ferrum_gateway(name: &str) -> K8sObject {
        object(
            "Gateway",
            name,
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        )
    }

    fn update_for<'a>(
        updates: &'a [GatewayApiStatusUpdate],
        kind: &str,
        name: &str,
    ) -> &'a GatewayApiStatusUpdate {
        updates
            .iter()
            .find(|update| update.kind == kind && update.name == name)
            .unwrap_or_else(|| panic!("missing status update for {kind}/{name}"))
    }

    #[test]
    fn status_writer_supports_gateway_api_v1beta1_status_resources() {
        for (kind, plural) in [
            ("GatewayClass", "gatewayclasses"),
            ("Gateway", "gateways"),
            ("HTTPRoute", "httproutes"),
        ] {
            let update = GatewayApiStatusUpdate {
                api_version: "gateway.networking.k8s.io/v1beta1".to_string(),
                kind: kind.to_string(),
                namespace: "default".to_string(),
                name: "example".to_string(),
                status: json!({}),
            };

            let resource = api_resource_for_update(&update)
                .expect("v1beta1 Gateway API status resource should be supported");

            assert_eq!(resource.group, "gateway.networking.k8s.io");
            assert_eq!(resource.version, "v1beta1");
            assert_eq!(resource.api_version, "gateway.networking.k8s.io/v1beta1");
            assert_eq!(resource.kind, kind);
            assert_eq!(resource.plural, plural);
        }
    }

    fn route_with_created_at(name: &str, created_at: &str) -> K8sObject {
        let mut route = object(
            "HTTPRoute",
            name,
            json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        route.metadata.creation_timestamp = Some(created_at.to_string());
        route
    }

    #[test]
    fn gateway_class_status_reports_accepted_for_ferrum_controller() {
        let gateway_class = ferrum_gateway_class();

        let updates = plan_status_updates(&[gateway_class], options());

        assert_eq!(updates.len(), 1);
        let conditions = updates[0].status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "SupportedVersion", "True");
    }

    #[test]
    fn gateway_class_status_skips_other_controllers() {
        let gateway_class = other_gateway_class();

        let updates = plan_status_updates(&[gateway_class], options());

        assert!(updates.is_empty());
    }

    #[test]
    fn gateway_status_skips_gateway_for_other_controller() {
        let gateway_class = other_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "other",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        assert!(updates.is_empty());
    }

    #[test]
    fn route_status_skips_route_without_ferrum_parent() {
        let gateway_class = other_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "other",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        assert!(updates.is_empty());
    }

    #[test]
    fn route_status_skips_route_without_parent_refs() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("api");
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        assert!(updates.iter().all(|update| update.kind != "HTTPRoute"));
    }

    #[test]
    fn gateway_status_reports_accepted_and_programmed() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_condition(conditions, "Conflicted", "False");
    }

    #[test]
    fn gateway_status_updates_v1beta1_conformance_base_gateway_conditions() {
        let mut gateway_class = ferrum_gateway_class();
        gateway_class.metadata.namespace = String::new();
        let mut gateway = object(
            "Gateway",
            "all-namespaces",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": { "namespaces": { "from": "All" } }
                }]
            }),
        );
        gateway.api_version = "gateway.networking.k8s.io/v1beta1".to_string();
        gateway.metadata.namespace = "gateway-conformance-infra".to_string();
        gateway.metadata.generation = Some(1);
        gateway.status = json!({
            "conditions": [
                {
                    "type": "Accepted",
                    "status": "False",
                    "observedGeneration": 0,
                    "reason": "Pending",
                    "message": "waiting for controller",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                },
                {
                    "type": "Programmed",
                    "status": "False",
                    "observedGeneration": 0,
                    "reason": "Pending",
                    "message": "waiting for controller",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }
            ]
        });

        let updates = plan_status_updates(
            &[gateway_class, gateway],
            options().with_source_namespaces(Vec::new()),
        );

        let gateway_update = update_for(&updates, "Gateway", "all-namespaces");
        assert_eq!(
            gateway_update.api_version,
            "gateway.networking.k8s.io/v1beta1"
        );
        assert_eq!(gateway_update.namespace, "gateway-conformance-infra");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_eq!(
            find_condition(conditions, "Accepted")["observedGeneration"].as_i64(),
            Some(1)
        );
        assert_eq!(
            find_condition(conditions, "Programmed")["observedGeneration"].as_i64(),
            Some(1)
        );
    }

    #[test]
    fn gateway_status_preserves_non_owned_conditions() {
        let gateway_class = ferrum_gateway_class();
        let mut gateway = ferrum_gateway("edge");
        gateway.status = json!({
            "conditions": [
                {
                    "type": "example.com/CustomReady",
                    "status": "True",
                    "observedGeneration": 6,
                    "reason": "CustomReady",
                    "message": "owned by another status extension",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                },
                {
                    "type": "Accepted",
                    "status": "False",
                    "observedGeneration": 6,
                    "reason": "Old",
                    "message": "old status",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }
            ]
        });

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_eq!(
            find_condition(conditions, "example.com/CustomReady")["message"].as_str(),
            Some("owned by another status extension")
        );
    }

    #[test]
    fn gateway_class_status_preserves_non_owned_conditions() {
        let mut gateway_class = ferrum_gateway_class();
        gateway_class.status = json!({
            "conditions": [{
                "type": "example.com/PolicyReady",
                "status": "True",
                "observedGeneration": 6,
                "reason": "PolicyReady",
                "message": "custom condition",
                "lastTransitionTime": "2026-01-01T00:00:00Z"
            }]
        });

        let updates = plan_status_updates(&[gateway_class], options());

        let conditions = updates[0].status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "SupportedVersion", "True");
        assert_eq!(
            find_condition(conditions, "example.com/PolicyReady")["message"].as_str(),
            Some("custom condition")
        );
    }

    #[test]
    fn http_route_status_reports_parent_conditions() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(
            parents[0]["controllerName"].as_str(),
            Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        );
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_condition(conditions, "Conflicted", "False");
    }

    #[test]
    fn route_status_reports_unresolved_cross_namespace_backend_ref() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("Accepted")
        );
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("RefNotPermitted")
        );
    }

    #[test]
    fn route_status_reports_cross_namespace_parent_ref_not_allowed_with_resolved_refs_true() {
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": "edge",
                    "namespace": "gateway-conformance-infra"
                }],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        route.metadata.namespace = "gateway-conformance-web-backend".to_string();

        let gateway_class = ferrum_gateway_class();
        let mut gateway = ferrum_gateway("edge");
        gateway.metadata.namespace = "gateway-conformance-infra".to_string();
        let updates = plan_status_updates(
            &[gateway_class, gateway, route],
            options().with_source_namespaces(vec![]),
        );

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 1);
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "False");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("NotAllowedByListeners")
        );
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("ResolvedRefs")
        );
    }

    #[test]
    fn route_status_reports_unresolved_non_service_backend_ref() {
        // Guards the second prong of `error_is_reference_resolution` against
        // wording drift in the translator's "only core Service backendRefs are
        // supported" error. A change to that message would silently flip this
        // route from `Accepted=True, ResolvedRefs=False` to `Accepted=False`.
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{
                        "group": "example.com",
                        "kind": "ExternalService",
                        "name": "api",
                        "port": 8080
                    }]
                }]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("RefNotPermitted")
        );
    }

    #[test]
    fn route_status_rejects_invalid_backend_ref_weight() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "port": 8080,
                        "weight": 65536
                    }]
                }]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "False");
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("Invalid")
        );
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("Invalid")
        );
    }

    #[test]
    fn route_status_uses_no_rules_programmed_reason_for_empty_route() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("NoRules")
        );
        assert_eq!(
            find_condition(conditions, "Programmed")["reason"].as_str(),
            Some("NoRules")
        );
    }

    #[test]
    fn route_status_does_not_match_overlapping_route_name_prefix() {
        let empty_route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}]
            }),
        );
        let programmed_overlap = object(
            "HTTPRoute",
            "api-httproute",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(
            &[gateway_class, gateway, empty_route, programmed_overlap],
            options(),
        );

        let empty_update = update_for(&updates, "HTTPRoute", "api");
        let parents = empty_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "Programmed")["reason"].as_str(),
            Some("NoRules")
        );
    }

    #[test]
    fn newer_conflicting_route_reports_conflicted() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let older = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        let newer = route_with_created_at("api-b", "2026-01-02T00:00:00Z");

        let updates = plan_status_updates(&[gateway_class, gateway, newer, older], options());
        let newer_update = updates
            .iter()
            .find(|update| update.name == "api-b")
            .expect("newer route status");
        let parents = newer_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();

        assert_condition(conditions, "Accepted", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_condition(conditions, "Conflicted", "True");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("Conflicted")
        );
    }

    #[test]
    fn newer_conflicting_route_with_parent_ref_port_reports_conflicted() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut older = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        older.spec["parentRefs"] = json!([{"name": "edge", "port": 80}]);
        let mut newer = route_with_created_at("api-b", "2026-01-02T00:00:00Z");
        newer.spec["parentRefs"] = json!([{"name": "edge", "port": 80}]);

        let updates = plan_status_updates(&[gateway_class, gateway, newer, older], options());
        let newer_update = updates
            .iter()
            .find(|update| update.name == "api-b")
            .expect("newer route status");
        let parents = newer_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();

        assert_condition(conditions, "Accepted", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_condition(conditions, "Conflicted", "True");
    }

    #[test]
    fn partially_conflicting_route_reports_accepted_and_conflicted() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let older = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        let mut mixed = object(
            "HTTPRoute",
            "api-b",
            json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [
                    {
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    },
                    {
                        "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                        "backendRefs": [{"name": "admin", "port": 9090}]
                    }
                ]
            }),
        );
        mixed.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let updates = plan_status_updates(&[gateway_class, gateway, mixed, older], options());
        let mixed_update = updates
            .iter()
            .find(|update| update.name == "api-b")
            .expect("partially conflicting route status");
        let parents = mixed_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();

        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_condition(conditions, "Conflicted", "True");
    }

    #[test]
    fn translator_filtered_conflicts_keep_valid_route_unconflicted() {
        // When the translator drops an older sibling for invalid backendRefs,
        // its conflict list excludes that route. The status planner should
        // honour that filtered view rather than recomputing conflicts over
        // the full object set — otherwise a valid, materialized route ends
        // up with `Conflicted=True` against a sibling the data plane never
        // saw.
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut invalid_older = object(
            "HTTPRoute",
            "api-old",
            json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080, "weight": 65536}]
                }]
            }),
        );
        invalid_older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut valid_newer = object(
            "HTTPRoute",
            "api-new",
            json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        valid_newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let objects = vec![gateway_class, gateway, valid_newer, invalid_older];
        // Simulate the translator's filtered conflict list: with the invalid
        // route skipped, the only surviving route has no peers to conflict
        // with, so the list is empty.
        let updates = plan_gateway_api_status_updates(&objects, options(), &[]);

        let valid_update = updates
            .iter()
            .find(|update| update.name == "api-new")
            .expect("valid route status");
        let parents = valid_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_condition(conditions, "Conflicted", "False");
    }

    #[test]
    fn conflict_tie_breaker_uses_route_name_when_timestamps_match() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let left = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        let right = route_with_created_at("api-b", "2026-01-01T00:00:00Z");

        let updates = plan_status_updates(&[gateway_class, gateway, right, left], options());
        let loser = updates
            .iter()
            .find(|update| update.name == "api-b")
            .expect("name loser status");
        let parents = loser.status["parents"].as_array().unwrap();

        assert_condition(
            parents[0]["conditions"].as_array().unwrap(),
            "Conflicted",
            "True",
        );
    }

    #[test]
    fn unchanged_status_does_not_emit_update() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        let first = plan_status_updates(
            &[gateway_class.clone(), gateway.clone(), route.clone()],
            options(),
        );
        route.status = update_for(&first, "HTTPRoute", "api").status.clone();

        let second = plan_status_updates(&[gateway_class, gateway, route], options());

        assert!(second.iter().all(|update| update.kind != "HTTPRoute"));
    }

    #[test]
    fn status_updates_preserve_unknown_status_fields() {
        let gateway_class = ferrum_gateway_class();
        let mut gateway = ferrum_gateway("edge");
        gateway.status = json!({
            "addresses": [{"type": "IPAddress", "value": "10.0.0.10"}]
        });

        let updates = plan_status_updates(&[gateway_class, gateway], options());
        let gateway_update = update_for(&updates, "Gateway", "edge");

        assert_eq!(
            gateway_update.status["addresses"][0]["value"].as_str(),
            Some("10.0.0.10")
        );
        assert!(gateway_update.status["conditions"].is_array());
    }

    #[test]
    fn gateway_status_preserves_non_ferrum_conditions() {
        let gateway_class = ferrum_gateway_class();
        let mut gateway = ferrum_gateway("edge");
        gateway.status = json!({
            "conditions": [
                {
                    "type": "example.com/ExternalReady",
                    "status": "True",
                    "observedGeneration": 7,
                    "reason": "ExternalReady",
                    "message": "owned by another controller",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                },
                {
                    "type": "Accepted",
                    "status": "False",
                    "observedGeneration": 1,
                    "reason": "OldValue",
                    "message": "stale Ferrum condition",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }
            ]
        });

        let updates = plan_status_updates(&[gateway_class, gateway], options());
        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();

        assert_condition(conditions, "example.com/ExternalReady", "True");
        assert_condition(conditions, "Accepted", "True");
        assert_eq!(
            conditions
                .iter()
                .filter(
                    |condition| condition.get("type").and_then(Value::as_str) == Some("Accepted")
                )
                .count(),
            1
        );
    }

    #[test]
    fn route_status_preserves_non_ferrum_parent_entries() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        route.status = json!({
            "parents": [{
                "parentRef": {"name": "edge"},
                "controllerName": "example.com/other-controller",
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 3,
                    "reason": "Accepted",
                    "message": "owned by another controller",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }]
            }]
        });

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 2);
        assert!(parents.iter().any(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                == Some("example.com/other-controller")
        }));
        assert!(parents.iter().any(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        }));
    }

    #[test]
    fn route_status_preserves_non_owned_parent_conditions() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        route.status = json!({
            "parents": [{
                "parentRef": {"name": "edge"},
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": [{
                    "type": "example.com/CustomParentReady",
                    "status": "True",
                    "observedGeneration": 6,
                    "reason": "CustomParentReady",
                    "message": "custom parent condition",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }]
            }]
        });

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_eq!(
            find_condition(conditions, "example.com/CustomParentReady")["message"].as_str(),
            Some("custom parent condition")
        );
    }

    #[test]
    fn route_status_drops_stale_ferrum_parent_entries() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        route.status = json!({
            "parents": [
                {
                    "parentRef": {"name": "old-edge"},
                    "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                    "conditions": []
                },
                {
                    "parentRef": {"name": "edge"},
                    "controllerName": "example.com/other-controller",
                    "conditions": []
                }
            ]
        });

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        assert!(!parents.iter().any(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                && parent.get("parentRef") == Some(&json!({"name": "old-edge"}))
        }));
        assert!(parents.iter().any(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                && parent.get("parentRef") == Some(&json!({"name": "edge"}))
        }));
        assert!(parents.iter().any(|parent| {
            parent.get("controllerName").and_then(Value::as_str)
                == Some("example.com/other-controller")
        }));
    }

    #[test]
    fn detached_route_status_clears_ferrum_parent_entries() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        route.status = json!({
            "parents": [{
                "parentRef": {"name": "edge"},
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": []
            }]
        });

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        assert!(parents.is_empty());
    }

    #[test]
    fn route_status_matches_existing_parent_refs_after_defaulting() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        route.status = json!({
            "parents": [{
                "parentRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "default",
                    "name": "edge"
                },
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 7,
                    "reason": "Accepted",
                    "message": "Ferrum accepted and programmed this route",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }]
            }]
        });

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_eq!(
            find_condition(conditions, "Accepted")["lastTransitionTime"].as_str(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn emitted_conditions_include_observed_generation() {
        let gateway_class = ferrum_gateway_class();

        let updates = plan_status_updates(&[gateway_class], options());

        let conditions = updates[0].status["conditions"].as_array().unwrap();
        assert_eq!(
            find_condition(conditions, "Accepted")["observedGeneration"].as_i64(),
            Some(7)
        );
    }

    #[test]
    fn status_patch_for_gateway_updates_only_owned_conditions_from_live_status() {
        let update = GatewayApiStatusUpdate {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "Gateway".to_string(),
            namespace: "default".to_string(),
            name: "edge".to_string(),
            status: json!({
                "addresses": [{"type": "IPAddress", "value": "stale"}],
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 7,
                    "reason": "Accepted",
                    "message": "Ferrum accepted this Gateway",
                    "lastTransitionTime": "2026-02-01T00:00:00Z"
                }]
            }),
        };
        let live_status = json!({
            "addresses": [{"type": "IPAddress", "value": "10.0.0.10"}],
            "conditions": [{
                "type": "example.com/CustomReady",
                "status": "True",
                "observedGeneration": 8,
                "reason": "CustomReady",
                "message": "fresh custom status",
                "lastTransitionTime": "2026-03-01T00:00:00Z"
            }]
        });

        let patch = status_patch_for_update(&update, Some(&live_status));

        assert!(patch["status"].get("addresses").is_none());
        let conditions = patch["status"]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_eq!(
            find_condition(conditions, "example.com/CustomReady")["message"].as_str(),
            Some("fresh custom status")
        );
    }

    #[test]
    fn status_patch_for_route_merges_ferrum_parents_into_live_status() {
        let update = GatewayApiStatusUpdate {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            namespace: "default".to_string(),
            name: "api".to_string(),
            status: json!({
                "parents": [
                    {
                        "parentRef": {"name": "edge"},
                        "controllerName": "example.com/stale-controller",
                        "conditions": []
                    },
                    {
                        "parentRef": {"name": "edge"},
                        "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                        "conditions": [{"type": "Accepted", "status": "True"}]
                    }
                ]
            }),
        };
        let live_status = json!({
            "parents": [
                {
                    "parentRef": {"name": "edge"},
                    "controllerName": "example.com/fresh-controller",
                    "conditions": [{"type": "Accepted", "status": "True"}]
                },
                {
                    "parentRef": {"name": "old-edge"},
                    "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                    "conditions": []
                }
            ]
        });

        let patch = status_patch_for_update(&update, Some(&live_status));

        let parents = patch["status"]["parents"].as_array().unwrap();
        assert!(parents.iter().any(|parent| {
            parent["controllerName"].as_str() == Some("example.com/fresh-controller")
        }));
        assert!(!parents.iter().any(|parent| {
            parent["controllerName"].as_str() == Some("example.com/stale-controller")
        }));
        assert!(!parents.iter().any(|parent| {
            parent["controllerName"].as_str() == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                && parent["parentRef"]["name"].as_str() == Some("old-edge")
        }));
        assert!(parents.iter().any(|parent| {
            parent["controllerName"].as_str() == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                && parent["parentRef"]["name"].as_str() == Some("edge")
        }));
    }

    fn assert_condition(conditions: &[Value], condition_type: &str, status: &str) {
        assert_eq!(
            find_condition(conditions, condition_type)["status"].as_str(),
            Some(status),
            "unexpected status for {condition_type}"
        );
    }

    fn find_condition<'a>(conditions: &'a [Value], condition_type: &str) -> &'a Value {
        conditions
            .iter()
            .find(|condition| condition["type"].as_str() == Some(condition_type))
            .unwrap_or_else(|| panic!("missing condition {condition_type}"))
    }
}
