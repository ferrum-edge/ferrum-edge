use futures_util::StreamExt;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

use crate::config::types::GatewayConfig;
use crate::config_sources::k8s::{
    GatewayApiAllowedRoutesNamespaces, GatewayApiMaterializedRouteParent, GatewayApiRouteConflict,
    GatewayApiRouteConflictKey, K8sObject, K8sResourceKey, K8sTranslateError, K8sTranslation,
    K8sTranslationOptions, gateway_api_route_conflict_keys_with_acc,
    gateway_api_status_conflict_context, namespace_selector_matches,
    parse_gateway_listener_allowed_route_namespaces, secret_object_is_valid_tls_certificate,
    translate_k8s_objects_collecting_skips, validate_gateway_listener_allowed_routes,
};
use crate::k8s_controller::status_plan::{
    StatusPlanBudget, fair_work_window_iter, select_fair_work_window,
};

pub use crate::k8s_controller::status_plan::DEFAULT_STATUS_PLAN_WORK_BUDGET;

pub const FERRUM_GATEWAY_CONTROLLER_NAME: &str = "ferrum.io/gateway-controller";
/// Stable server-side-apply owner shared by every Ferrum controller replica.
/// Using the Gateway API controller name keeps ownership stable across restarts
/// and replicas without inventing a pod- or process-specific identity.
const GATEWAY_API_STATUS_FIELD_MANAGER: &str = FERRUM_GATEWAY_CONTROLLER_NAME;
const DEFAULT_FERRUM_GATEWAY_CLASS_NAME: &str = "ferrum";
const GATEWAY_API_STATUS_PATCH_PARALLELISM: usize = 32;
const ROUTE_STATUS_PATCH_MAX_ATTEMPTS: usize = 5;
const ROUTE_STATUS_PATCH_RETRY_BASE_MS: u64 = 10;

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayApiStatusUpdate {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub status: Value,
    pub patch_gateway_addresses: bool,
    pub patch_gateway_listeners: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayApiStatusContext {
    pub data_plane_ready: bool,
    pub status_address: Option<String>,
}

impl Default for GatewayApiStatusContext {
    fn default() -> Self {
        Self {
            data_plane_ready: true,
            status_address: None,
        }
    }
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
                let result = if route_status_kind(&update.kind) {
                    patch_route_status_with_retry(&api, &update).await
                } else {
                    patch_gateway_status_with_apply(&api, &update).await
                };
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

async fn patch_gateway_status_with_apply(
    api: &Api<DynamicObject>,
    update: &GatewayApiStatusUpdate,
) -> Result<(), kube::Error> {
    let live_status = match api.get_status(&update.name).await {
        Ok(live) => live.data.get("status").cloned(),
        Err(error) => {
            warn!(
                api_version = %update.api_version,
                kind = %update.kind,
                namespace = %update.namespace,
                name = %update.name,
                error = %error,
                "Gateway API status read failed; applying planned Gateway status"
            );
            None
        }
    };
    let patch = gateway_status_apply_patch_for_update(update, live_status.as_ref());

    // Gateway/GatewayClass condition and listener arrays are structural
    // list-maps, so SSA can own Ferrum's keyed entries without copying fields
    // owned by another manager. Force adopts Ferrum's legacy merge-patch fields;
    // the apply document remains limited to the status fields Ferrum reconciles.
    let params = gateway_api_status_apply_params();
    api.patch_status(&update.name, &params, &Patch::Apply(&patch))
        .await
        .map(|_| ())
}

async fn patch_route_status_with_retry(
    api: &Api<DynamicObject>,
    update: &GatewayApiStatusUpdate,
) -> Result<(), kube::Error> {
    for attempt in 1..=ROUTE_STATUS_PATCH_MAX_ATTEMPTS {
        let live = api.get_status(&update.name).await?;
        let Some(resource_version) = live.metadata.resource_version.as_deref() else {
            warn!(
                api_version = %update.api_version,
                kind = %update.kind,
                namespace = %update.namespace,
                name = %update.name,
                "Gateway API route status read returned no resourceVersion; leaving resource for the next reconcile"
            );
            return Ok(());
        };
        let patch =
            route_status_merge_patch_for_update(update, live.data.get("status"), resource_version);
        let params = route_status_patch_params();
        match api
            .patch_status(&update.name, &params, &Patch::Merge(&patch))
            .await
        {
            Ok(_) => return Ok(()),
            Err(error)
                if kube_error_is_conflict(&error) && attempt < ROUTE_STATUS_PATCH_MAX_ATTEMPTS =>
            {
                tokio::time::sleep(route_status_retry_delay(attempt)).await;
            }
            Err(error) if kube_error_is_conflict(&error) => {
                warn!(
                    api_version = %update.api_version,
                    kind = %update.kind,
                    namespace = %update.namespace,
                    name = %update.name,
                    attempts = ROUTE_STATUS_PATCH_MAX_ATTEMPTS,
                    error = %error,
                    "Gateway API route status remained conflicted; leaving resource for the next reconcile"
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn route_status_kind(kind: &str) -> bool {
    matches!(kind, "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute")
}

fn kube_error_is_conflict(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == 409)
}

fn route_status_retry_delay(attempt: usize) -> Duration {
    let exponent = attempt.saturating_sub(1).min(6) as u32;
    let base_ms = ROUTE_STATUS_PATCH_RETRY_BASE_MS
        .saturating_mul(1_u64 << exponent)
        .min(100);
    let jitter_window_ms = (base_ms / 2).max(1);
    let jitter_ms = crate::util::backoff::random_backoff_entropy() % jitter_window_ms;
    Duration::from_millis(base_ms.saturating_sub(base_ms / 4) + jitter_ms)
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayApiStatusPlanOutcome {
    pub updates: Vec<GatewayApiStatusUpdate>,
    /// Cursor to persist so the next reconcile rotates the fair window.
    pub next_cursor: usize,
    /// Eligible managed status-bearing objects before the work budget.
    pub eligible_candidates: usize,
    /// Candidates that received expensive status computation this pass.
    pub planned_candidates: usize,
}

/// Optional primary-translate reuse for status planning (#2397).
///
/// When present, planners avoid a second full materialization and map
/// per-object accept/reject from the skip errors collected while producing
/// the primary translation.
#[derive(Debug, Clone)]
pub struct StatusTranslationReuse {
    pub translation: Arc<K8sTranslation>,
    pub errors: Arc<HashMap<K8sResourceKey, K8sTranslateError>>,
}

impl StatusTranslationReuse {
    pub fn from_owned(
        translation: K8sTranslation,
        errors: HashMap<K8sResourceKey, K8sTranslateError>,
    ) -> Self {
        Self {
            translation: Arc::new(translation),
            errors: Arc::new(errors),
        }
    }

    /// Look up the primary translate outcome for a live object.
    ///
    /// Exact `(api_version, kind, namespace, name)` hits first. When the skip
    /// map still carries a versionless key from [`K8sResourceKey::from_error`],
    /// a second O(1) get preserves that fallback. Never linearly scans the
    /// error map (#2397).
    pub fn result_for<'a>(
        &'a self,
        object: &K8sObject,
    ) -> Result<&'a K8sTranslation, &'a K8sTranslateError> {
        let exact = K8sResourceKey::from_object(object);
        if let Some(error) = self.errors.get(&exact) {
            return Err(error);
        }
        if !exact.api_version.is_empty() {
            let versionless = K8sResourceKey {
                api_version: String::new(),
                kind: exact.kind,
                namespace: exact.namespace,
                name: exact.name,
            };
            if let Some(error) = self.errors.get(&versionless) {
                return Err(error);
            }
        }
        Ok(self.translation.as_ref())
    }
}

/// Named-or-wildcard allow set for one ReferenceGrant `(from × to kind)` cell.
///
/// Built once per reconcile; lookups are allocation-free (#2397).
struct ReferenceGrantNameAllow<'a> {
    wildcard: bool,
    names: HashSet<&'a str>,
}

impl<'a> Default for ReferenceGrantNameAllow<'a> {
    fn default() -> Self {
        Self {
            wildcard: false,
            names: HashSet::new(),
        }
    }
}

impl<'a> ReferenceGrantNameAllow<'a> {
    fn insert(&mut self, to_name: Option<&'a str>) {
        match to_name {
            None => {
                self.wildcard = true;
                self.names.clear();
            }
            Some(name) if !self.wildcard => {
                self.names.insert(name);
            }
            Some(_) => {}
        }
    }

    fn allows(&self, to_name: Option<&str>) -> bool {
        if self.wildcard {
            return true;
        }
        to_name.is_some_and(|name| self.names.contains(name))
    }
}

/// Immutable per-reconcile ReferenceGrant permission index.
///
/// Every valid `from × to` combination is recorded once under the grant's
/// target namespace. Lookups are O(1)-average and borrow `&str` keys — never
/// scan or reparse grant objects per certificate/backend reference (#2397).
struct ReferenceGrantPermissionIndex<'a> {
    /// to_namespace → (from_ns, from_group, from_kind) → (to_group, to_kind) → names
    entries: HashMap<
        &'a str,
        HashMap<
            (&'a str, &'a str, &'a str),
            HashMap<(&'a str, &'a str), ReferenceGrantNameAllow<'a>>,
        >,
    >,
}

impl<'a> Default for ReferenceGrantPermissionIndex<'a> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

/// Optional ReferenceGrant `to.name` without allocating.
///
/// - absent → `Some(None)` (Gateway API wildcard)
/// - string → `Some(Some(name))` (named grant)
/// - present non-string → `None` (malformed; caller skips the `to` entry)
fn reference_grant_optional_to_name(to: &Value) -> Option<Option<&str>> {
    match to.get("name") {
        None => Some(None),
        Some(Value::String(name)) => Some(Some(name.as_str())),
        Some(_) => None,
    }
}

impl<'a> ReferenceGrantPermissionIndex<'a> {
    fn ingest(&mut self, grant: &'a K8sObject) {
        let to_namespace = grant.metadata.namespace.as_str();
        let Some(from_entries) = grant.spec.get("from").and_then(Value::as_array) else {
            return;
        };
        let Some(to_entries) = grant.spec.get("to").and_then(Value::as_array) else {
            return;
        };
        for from in from_entries {
            let Some(from_namespace) = from.get("namespace").and_then(Value::as_str) else {
                continue;
            };
            let Some(from_kind) = from.get("kind").and_then(Value::as_str) else {
                continue;
            };
            // Required: only an explicit string (including "") may be indexed.
            // Missing or non-string `group` must not collapse to core "".
            let Some(from_group) = from.get("group").and_then(Value::as_str) else {
                continue;
            };
            for to in to_entries {
                let Some(to_kind) = to.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let Some(to_group) = to.get("group").and_then(Value::as_str) else {
                    continue;
                };
                let Some(to_name) = reference_grant_optional_to_name(to) else {
                    continue;
                };
                self.entries
                    .entry(to_namespace)
                    .or_default()
                    .entry((from_namespace, from_group, from_kind))
                    .or_default()
                    .entry((to_group, to_kind))
                    .or_default()
                    .insert(to_name);
            }
        }
    }

    fn allows(
        &self,
        from_namespace: &str,
        from_group: &str,
        from_kind: &str,
        to_namespace: &str,
        to_group: &str,
        to_kind: &str,
        to_name: Option<&str>,
    ) -> bool {
        self.entries
            .get(to_namespace)
            .and_then(|by_from| by_from.get(&(from_namespace, from_group, from_kind)))
            .and_then(|by_to| by_to.get(&(to_group, to_kind)))
            .is_some_and(|allow| allow.allows(to_name))
    }
}

/// Immutable per-reconcile indexes for Gateway API status planning.
struct GatewayApiStatusIndexes<'a> {
    gateway_classes_by_name: HashMap<&'a str, &'a K8sObject>,
    gateways_by_ns_name: HashMap<(&'a str, &'a str), &'a K8sObject>,
    managed_gateways: HashSet<(&'a str, &'a str)>,
    secrets_by_ns_name: HashMap<(&'a str, &'a str), &'a K8sObject>,
    services_by_ns_name: HashMap<(&'a str, &'a str), &'a K8sObject>,
    namespaces_by_name: HashMap<&'a str, &'a K8sObject>,
    /// Routes that parentRef a Gateway, keyed by `(gateway_ns, gateway_name)`.
    /// Built once so attachedRoutes and listener evaluation never rescan the
    /// full snapshot per listener (#2397).
    routes_by_gateway: HashMap<(&'a str, &'a str), Vec<&'a K8sObject>>,
    /// Precomputed ReferenceGrant from×to permissions (not raw grant vectors).
    reference_grant_permissions: ReferenceGrantPermissionIndex<'a>,
    has_any_service: bool,
    conflicts_by_loser: HashMap<K8sResourceKey, Vec<&'a GatewayApiRouteConflict>>,
}

impl<'a> GatewayApiStatusIndexes<'a> {
    fn build(objects: &'a [K8sObject], route_conflicts: &'a [GatewayApiRouteConflict]) -> Self {
        let mut gateway_classes_by_name = HashMap::new();
        let mut gateways_by_ns_name = HashMap::new();
        let mut secrets_by_ns_name = HashMap::new();
        let mut services_by_ns_name = HashMap::new();
        let mut namespaces_by_name = HashMap::new();
        let mut routes_by_gateway: HashMap<(&str, &str), Vec<&K8sObject>> = HashMap::new();
        let mut reference_grant_permissions = ReferenceGrantPermissionIndex::default();
        let mut has_any_service = false;

        for object in objects {
            match object.kind.as_str() {
                "GatewayClass" => {
                    gateway_classes_by_name.insert(object.metadata.name.as_str(), object);
                }
                "Gateway" => {
                    gateways_by_ns_name.insert(
                        (
                            object.metadata.namespace.as_str(),
                            object.metadata.name.as_str(),
                        ),
                        object,
                    );
                }
                "Secret" => {
                    secrets_by_ns_name.insert(
                        (
                            object.metadata.namespace.as_str(),
                            object.metadata.name.as_str(),
                        ),
                        object,
                    );
                }
                "Service" => {
                    has_any_service = true;
                    services_by_ns_name.insert(
                        (
                            object.metadata.namespace.as_str(),
                            object.metadata.name.as_str(),
                        ),
                        object,
                    );
                }
                "Namespace" => {
                    namespaces_by_name.insert(object.metadata.name.as_str(), object);
                }
                "ReferenceGrant" => {
                    reference_grant_permissions.ingest(object);
                }
                "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute" => {
                    let mut seen_parents = HashSet::new();
                    for parent_ref in route_parent_refs_borrowed(object) {
                        let Some((namespace, name)) = parent_ref_gateway_target(object, parent_ref)
                        else {
                            continue;
                        };
                        if !seen_parents.insert((namespace, name)) {
                            continue;
                        }
                        routes_by_gateway
                            .entry((namespace, name))
                            .or_default()
                            .push(object);
                    }
                }
                _ => {}
            }
        }

        let mut managed_gateways = HashSet::new();
        for ((namespace, name), gateway) in &gateways_by_ns_name {
            if gateway_is_managed_by_ferrum_indexed(gateway, &gateway_classes_by_name) {
                managed_gateways.insert((*namespace, *name));
            }
        }

        let mut conflicts_by_loser: HashMap<K8sResourceKey, Vec<&GatewayApiRouteConflict>> =
            HashMap::new();
        for conflict in route_conflicts {
            conflicts_by_loser
                .entry(conflict.loser.clone())
                .or_default()
                .push(conflict);
        }

        Self {
            gateway_classes_by_name,
            gateways_by_ns_name,
            managed_gateways,
            secrets_by_ns_name,
            services_by_ns_name,
            namespaces_by_name,
            routes_by_gateway,
            reference_grant_permissions,
            has_any_service,
            conflicts_by_loser,
        }
    }
}

fn gateway_is_managed_by_ferrum_indexed(
    gateway: &K8sObject,
    gateway_classes_by_name: &HashMap<&str, &K8sObject>,
) -> bool {
    let Some(class_name) = gateway.spec.get("gatewayClassName").and_then(Value::as_str) else {
        return false;
    };
    if let Some(class) = gateway_classes_by_name.get(class_name) {
        return gateway_class_is_managed_by_ferrum(class);
    }
    class_name == DEFAULT_FERRUM_GATEWAY_CLASS_NAME
}

pub fn plan_gateway_api_status_updates(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    route_conflicts: &[GatewayApiRouteConflict],
) -> Vec<GatewayApiStatusUpdate> {
    plan_gateway_api_status_updates_with_context(
        objects,
        options,
        route_conflicts,
        GatewayApiStatusContext::default(),
    )
}

pub fn plan_gateway_api_status_updates_with_context(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    route_conflicts: &[GatewayApiRouteConflict],
    status_context: GatewayApiStatusContext,
) -> Vec<GatewayApiStatusUpdate> {
    plan_gateway_api_status_updates_budgeted(
        objects,
        options,
        route_conflicts,
        status_context,
        None,
        StatusPlanBudget::unlimited(0),
    )
    .updates
}

/// Plan Gateway API status updates with shared indexes, translation reuse, and
/// a fair work budget applied *before* expensive per-object computation.
pub fn plan_gateway_api_status_updates_budgeted(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    route_conflicts: &[GatewayApiRouteConflict],
    status_context: GatewayApiStatusContext,
    translation_reuse: Option<&StatusTranslationReuse>,
    budget: StatusPlanBudget,
) -> GatewayApiStatusPlanOutcome {
    let indexes = GatewayApiStatusIndexes::build(objects, route_conflicts);
    let conflict_context = gateway_api_status_conflict_context(objects, options.clone());

    let owned_reuse;
    let reuse = match translation_reuse {
        Some(reuse) => reuse,
        None => {
            let Some((translation, errors)) =
                translate_k8s_objects_collecting_skips(objects, options.clone())
            else {
                return GatewayApiStatusPlanOutcome {
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
        .filter(|object| is_status_kind(&object.kind))
        .filter(|object| status_candidate_is_eligible(object, &indexes))
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
        // Materialize borrowed parent-ref slices only for the selected window.
        let managed_parent_refs = if route_status_kind(&object.kind) {
            managed_route_parent_refs_indexed(object, &indexes)
        } else {
            Vec::new()
        };
        let resource_key = K8sResourceKey::from_object(object);
        let managed_parent_ref_keys: HashSet<String> = managed_parent_refs
            .iter()
            .map(|parent_ref| route_parent_ref_key(object, parent_ref))
            .collect();
        let object_conflicts: Vec<&GatewayApiRouteConflict> = indexes
            .conflicts_by_loser
            .get(&resource_key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|conflict| {
                managed_parent_ref_keys.is_empty()
                    || managed_parent_ref_keys.contains(&conflict.key.parent_ref)
            })
            .collect();
        let route_keys = if route_status_kind(&object.kind) {
            gateway_api_route_conflict_keys_with_acc(object, &conflict_context)
                .into_iter()
                .filter(|key| managed_parent_ref_keys.contains(&key.parent_ref))
                .collect()
        } else {
            Vec::new()
        };
        let translation_result = reuse.result_for(object);
        let status = desired_status_for_object(
            objects,
            object,
            &indexes,
            &status_context,
            translation_result,
            &object_conflicts,
            &route_keys,
            &managed_parent_refs,
        );
        if status == object.status {
            continue;
        }
        updates.push(GatewayApiStatusUpdate {
            api_version: object.api_version.clone(),
            kind: object.kind.clone(),
            namespace: object.metadata.namespace.clone(),
            name: object.metadata.name.clone(),
            status,
            patch_gateway_addresses: object.kind == "Gateway"
                && status_context.status_address.is_some(),
            patch_gateway_listeners: object.kind == "Gateway",
        });
    }

    GatewayApiStatusPlanOutcome {
        updates,
        next_cursor: window.next_cursor,
        eligible_candidates: eligible.len(),
        planned_candidates: window.take,
    }
}

fn desired_status_for_object(
    objects: &[K8sObject],
    object: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
    status_context: &GatewayApiStatusContext,
    translation_result: Result<&K8sTranslation, &K8sTranslateError>,
    route_conflicts: &[&GatewayApiRouteConflict],
    route_keys: &[GatewayApiRouteConflictKey],
    managed_parent_refs: &[&Value],
) -> Value {
    if object.kind == "GatewayClass" {
        return gateway_class_status(object);
    }

    match object.kind.as_str() {
        "Gateway" => gateway_status(objects, object, indexes, translation_result, status_context),
        "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute" => route_status(
            objects,
            object,
            indexes,
            translation_result,
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

#[derive(Debug, Clone, Copy)]
struct ListenerReferenceStatus {
    resolved: bool,
    reason: &'static str,
    message: &'static str,
}

#[derive(Debug, Clone)]
struct ListenerRouteKindStatus {
    protocol_supported: bool,
    route_kinds_valid: bool,
    supported_kinds: Vec<Value>,
}

impl ListenerReferenceStatus {
    const RESOLVED: Self = Self {
        resolved: true,
        reason: "ResolvedRefs",
        message: "All listener references accepted by Ferrum",
    };

    const REF_NOT_PERMITTED: Self = Self {
        resolved: false,
        reason: "RefNotPermitted",
        message: "Ferrum could not resolve this listener because a cross-namespace reference is not permitted",
    };

    const INVALID_CERTIFICATE_REF: Self = Self {
        resolved: false,
        reason: "InvalidCertificateRef",
        message: "Ferrum could not resolve this listener certificateRef",
    };

    const UNSUPPORTED_CERTIFICATE_REFS: Self = Self {
        resolved: false,
        reason: "UnsupportedValue",
        message: "Ferrum currently supports one Gateway TLS certificateRef per data plane",
    };
}

fn gateway_reference_status(
    objects: &[K8sObject],
    gateway: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> ListenerReferenceStatus {
    gateway
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|listener| listener_reference_status(objects, gateway, listener, indexes))
        .find(|status| !status.resolved)
        .unwrap_or(ListenerReferenceStatus::RESOLVED)
}

fn listener_reference_status(
    objects: &[K8sObject],
    gateway: &K8sObject,
    listener: &Value,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> ListenerReferenceStatus {
    let certificate_refs = listener
        .get("tls")
        .and_then(|tls| tls.get("certificateRefs"))
        .and_then(Value::as_array);
    if listener_is_terminating_tls(listener) && certificate_refs.is_none_or(|refs| refs.is_empty())
    {
        return ListenerReferenceStatus::INVALID_CERTIFICATE_REF;
    }
    let Some(certificate_refs) = certificate_refs else {
        return ListenerReferenceStatus::RESOLVED;
    };

    for certificate_ref in certificate_refs {
        let group = certificate_ref
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let kind = certificate_ref
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Secret");
        let Some(name) = certificate_ref.get("name").and_then(Value::as_str) else {
            return ListenerReferenceStatus::INVALID_CERTIFICATE_REF;
        };
        if !group.is_empty() || kind != "Secret" {
            return ListenerReferenceStatus::INVALID_CERTIFICATE_REF;
        }
        let namespace = certificate_ref
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(&gateway.metadata.namespace);
        if namespace != gateway.metadata.namespace
            && !reference_grant_allows_secret_indexed(
                indexes,
                &gateway.metadata.namespace,
                namespace,
                name,
            )
        {
            return ListenerReferenceStatus::REF_NOT_PERMITTED;
        }
        let Some(secret) = indexes.secrets_by_ns_name.get(&(namespace, name)).copied() else {
            return ListenerReferenceStatus::INVALID_CERTIFICATE_REF;
        };
        if !secret_object_is_valid_tls_certificate(secret) {
            return ListenerReferenceStatus::INVALID_CERTIFICATE_REF;
        }
    }

    if listener_is_terminating_tls(listener)
        && gateway_has_multiple_distinct_tls_certificate_refs(objects, gateway, indexes)
    {
        return ListenerReferenceStatus::UNSUPPORTED_CERTIFICATE_REFS;
    }

    ListenerReferenceStatus::RESOLVED
}

fn listener_is_terminating_tls(listener: &Value) -> bool {
    let Some(protocol) = listener.get("protocol").and_then(Value::as_str) else {
        return false;
    };
    if !protocol.eq_ignore_ascii_case("HTTPS") && !protocol.eq_ignore_ascii_case("TLS") {
        return false;
    }
    listener
        .get("tls")
        .and_then(|tls| tls.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("Terminate")
        .eq_ignore_ascii_case("Terminate")
}

fn gateway_has_multiple_distinct_tls_certificate_refs(
    objects: &[K8sObject],
    gateway: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> bool {
    let Some(listeners) = gateway.spec.get("listeners").and_then(Value::as_array) else {
        return false;
    };
    let mut selected: Option<(String, String)> = None;
    for identity in listeners
        .iter()
        .filter(|listener| listener_is_terminating_tls(listener))
        .flat_map(|listener| {
            listener_tls_certificate_ref_identities(objects, gateway, listener, indexes)
        })
    {
        if selected
            .as_ref()
            .is_some_and(|existing| existing != &identity)
        {
            return true;
        }
        selected.get_or_insert(identity);
    }
    false
}

fn listener_tls_certificate_ref_identities(
    _objects: &[K8sObject],
    gateway: &K8sObject,
    listener: &Value,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> Vec<(String, String)> {
    listener
        .get("tls")
        .and_then(|tls| tls.get("certificateRefs"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|certificate_ref| {
            let group = certificate_ref
                .get("group")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let kind = certificate_ref
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Secret");
            if !group.is_empty() || kind != "Secret" {
                return None;
            }
            let name = certificate_ref.get("name").and_then(Value::as_str)?;
            let namespace = certificate_ref
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or(&gateway.metadata.namespace);
            if namespace != gateway.metadata.namespace
                && !reference_grant_allows_secret_indexed(
                    indexes,
                    &gateway.metadata.namespace,
                    namespace,
                    name,
                )
            {
                return None;
            }
            let secret = indexes
                .secrets_by_ns_name
                .get(&(namespace, name))
                .copied()?;
            secret_object_is_valid_tls_certificate(secret)
                .then(|| (namespace.to_string(), name.to_string()))
        })
        .collect()
}

fn reference_grant_allows_secret_indexed(
    indexes: &GatewayApiStatusIndexes<'_>,
    from_namespace: &str,
    to_namespace: &str,
    secret_name: &str,
) -> bool {
    indexes.reference_grant_permissions.allows(
        from_namespace,
        "gateway.networking.k8s.io",
        "Gateway",
        to_namespace,
        "",
        "Secret",
        Some(secret_name),
    )
}

fn gateway_status(
    objects: &[K8sObject],
    object: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
    result: Result<&crate::config_sources::k8s::K8sTranslation, &K8sTranslateError>,
    status_context: &GatewayApiStatusContext,
) -> Value {
    let references = gateway_reference_status(objects, object, indexes);
    let (accepted, materialized, resolved_refs, programmed, message) = match result {
        Ok(translation) => {
            let materialized = gateway_programmed(object, &translation.config);
            (
                true,
                materialized,
                references.resolved,
                materialized && status_context.data_plane_ready && references.resolved,
                "Ferrum accepted this Gateway".to_string(),
            )
        }
        Err(error) => {
            let message = format!("Ferrum rejected this Gateway: {error}");
            (false, false, false, false, message)
        }
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
            accepted && resolved_refs,
            if accepted && resolved_refs {
                "ResolvedRefs"
            } else if accepted {
                references.reason
            } else {
                "TranslationFailed"
            },
            if accepted && resolved_refs {
                "All Gateway references accepted by Ferrum"
            } else if accepted {
                references.message
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
            } else if accepted && materialized && !resolved_refs {
                references.reason
            } else if accepted && materialized {
                "DataPlaneNotReady"
            } else if accepted {
                "NoListeners"
            } else {
                "TranslationFailed"
            },
            if programmed {
                "Ferrum programmed this Gateway"
            } else if accepted && materialized && !resolved_refs {
                references.message
            } else if accepted && materialized {
                "Ferrum accepted this Gateway, but the serving Ferrum data plane is not ready"
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
    if let Some(address) = status_context.status_address.as_deref() {
        ensure_status_object(&mut status).insert(
            "addresses".to_string(),
            Value::Array(vec![gateway_status_address(address)]),
        );
    }
    ensure_status_object(&mut status).insert(
        "listeners".to_string(),
        Value::Array(gateway_listener_statuses(
            objects,
            object,
            indexes,
            result.ok().map(|translation| &translation.config),
            accepted,
            status_context.data_plane_ready,
        )),
    );
    status
}

fn gateway_status_address(address: &str) -> Value {
    let address_type = if address.parse::<std::net::IpAddr>().is_ok() {
        "IPAddress"
    } else {
        "Hostname"
    };
    json!({
        "type": address_type,
        "value": address,
    })
}

fn gateway_listener_statuses(
    objects: &[K8sObject],
    gateway: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
    config: Option<&GatewayConfig>,
    gateway_accepted: bool,
    data_plane_ready: bool,
) -> Vec<Value> {
    gateway
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|listener| {
            let references = listener_reference_status(objects, gateway, listener, indexes);
            let listener_name = listener
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("listener");
            let existing_listener_conditions =
                existing_listener_status(gateway, listener_name).and_then(existing_conditions);
            let protocol = listener
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("HTTP");
            let route_kinds = listener_route_kind_status(protocol, listener);
            let listener_validation_error =
                validate_gateway_listener_allowed_routes(listener).err();
            let accepted = gateway_accepted
                && route_kinds.protocol_supported
                && listener_validation_error.is_none();
            let resolved_refs = accepted && references.resolved && route_kinds.route_kinds_valid;
            let materialized = config
                .is_some_and(|config| gateway_listener_programmed(gateway, listener, config));
            let programmed = resolved_refs && materialized && data_plane_ready;
            let unresolved_reason = if listener_validation_error.is_some() {
                "Invalid"
            } else if !route_kinds.route_kinds_valid {
                "InvalidRouteKinds"
            } else {
                references.reason
            };
            let validation_message = listener_validation_error.map(|error| error.to_string());
            let unresolved_message = if let Some(message) = validation_message.as_deref() {
                message
            } else if !route_kinds.route_kinds_valid {
                "Listener allowedRoutes.kinds contains route kinds Ferrum does not support for this listener protocol"
            } else {
                references.message
            };
            let accepted_reason = if !gateway_accepted {
                "TranslationFailed"
            } else if !route_kinds.protocol_supported {
                "UnsupportedProtocol"
            } else if listener_validation_error.is_some() {
                "Invalid"
            } else {
                "Accepted"
            };
            let accepted_message = if !gateway_accepted {
                "Ferrum rejected this Gateway"
            } else if !route_kinds.protocol_supported {
                "Ferrum does not support this listener protocol"
            } else {
                validation_message
                    .as_deref()
                    .unwrap_or("Ferrum accepted this listener")
            };
            let conditions = vec![
                condition_at(
                    gateway,
                    existing_listener_conditions,
                    "Accepted",
                    accepted,
                    accepted_reason,
                    accepted_message,
                ),
                condition_at(
                    gateway,
                    existing_listener_conditions,
                    "ResolvedRefs",
                    resolved_refs,
                    if resolved_refs {
                        "ResolvedRefs"
                    } else if accepted {
                        unresolved_reason
                    } else if listener_validation_error.is_some() {
                        "Invalid"
                    } else {
                        "UnsupportedProtocol"
                    },
                    if resolved_refs {
                        "All listener references accepted by Ferrum"
                    } else if accepted || listener_validation_error.is_some() {
                        unresolved_message
                    } else {
                        "Ferrum could not resolve this listener"
                    },
                ),
                condition_at(
                    gateway,
                    existing_listener_conditions,
                    "Programmed",
                    programmed,
                    if programmed {
                        "Programmed"
                    } else if accepted && !resolved_refs {
                        unresolved_reason
                    } else if listener_validation_error.is_some() {
                        "Invalid"
                    } else if accepted && !materialized {
                        "NoListeners"
                    } else if accepted {
                        "DataPlaneNotReady"
                    } else {
                        "UnsupportedProtocol"
                    },
                    if programmed {
                        "Ferrum programmed this listener"
                    } else if (accepted && !resolved_refs)
                        || listener_validation_error.is_some()
                    {
                        unresolved_message
                    } else if accepted && !materialized {
                        "Ferrum accepted this listener but found no materialized listener"
                    } else if accepted {
                        "Ferrum accepted this listener, but the serving Ferrum data plane is not ready"
                    } else {
                        "Ferrum did not program this listener"
                    },
                ),
                condition_at(
                    gateway,
                    existing_listener_conditions,
                    "Conflicted",
                    false,
                    "NoConflicts",
                    "No Gateway API listener conflicts detected by Ferrum",
                ),
            ];
            json!({
                "name": listener_name,
                "attachedRoutes": attached_route_count(indexes, gateway, listener),
                "supportedKinds": route_kinds.supported_kinds,
                "conditions": conditions,
            })
        })
        .collect()
}

fn existing_listener_status<'a>(gateway: &'a K8sObject, listener_name: &str) -> Option<&'a Value> {
    gateway
        .status
        .get("listeners")
        .and_then(Value::as_array)?
        .iter()
        .find(|listener| listener.get("name").and_then(Value::as_str) == Some(listener_name))
}

fn listener_route_kind_status(protocol: &str, listener: &Value) -> ListenerRouteKindStatus {
    let protocol_kinds = listener_protocol_route_kinds(protocol);
    if protocol_kinds.is_empty() {
        return ListenerRouteKindStatus {
            protocol_supported: false,
            route_kinds_valid: false,
            supported_kinds: Vec::new(),
        };
    }

    let Some(kinds) = listener
        .get("allowedRoutes")
        .and_then(|allowed_routes| allowed_routes.get("kinds"))
        .and_then(Value::as_array)
    else {
        return ListenerRouteKindStatus {
            protocol_supported: true,
            route_kinds_valid: true,
            supported_kinds: protocol_kinds
                .iter()
                .map(|kind| route_group_kind(kind))
                .collect(),
        };
    };

    let mut route_kinds_valid = true;
    let mut supported_kinds = Vec::new();
    for kind in kinds {
        if let Some(route_kind) = listener_allowed_route_kind(kind, &protocol_kinds) {
            let group_kind = route_group_kind(route_kind);
            if !supported_kinds.contains(&group_kind) {
                supported_kinds.push(group_kind);
            }
        } else {
            route_kinds_valid = false;
        }
    }

    ListenerRouteKindStatus {
        protocol_supported: true,
        route_kinds_valid,
        supported_kinds,
    }
}

fn listener_protocol_route_kinds(protocol: &str) -> Vec<&'static str> {
    match protocol.to_ascii_uppercase().as_str() {
        "HTTP" | "HTTPS" => vec!["HTTPRoute", "GRPCRoute"],
        "GRPC" | "GRPCS" => vec!["GRPCRoute"],
        "TCP" => vec!["TCPRoute"],
        "TLS" => vec!["TLSRoute"],
        _ => Vec::new(),
    }
}

fn route_group_kind(kind: &str) -> Value {
    json!({
        "group": "gateway.networking.k8s.io",
        "kind": kind,
    })
}

fn listener_allowed_route_kind<'a>(kind: &Value, protocol_kinds: &'a [&str]) -> Option<&'a str> {
    let group = kind
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or("gateway.networking.k8s.io");
    let kind = kind.get("kind").and_then(Value::as_str)?;
    if group != "gateway.networking.k8s.io" {
        return None;
    }
    protocol_kinds
        .iter()
        .copied()
        .find(|allowed| *allowed == kind)
}

fn attached_route_count(
    indexes: &GatewayApiStatusIndexes<'_>,
    gateway: &K8sObject,
    listener: &Value,
) -> usize {
    let gateway_key = (
        gateway.metadata.namespace.as_str(),
        gateway.metadata.name.as_str(),
    );
    indexes
        .routes_by_gateway
        .get(&gateway_key)
        .into_iter()
        .flatten()
        .filter(|route| {
            route_parent_refs_borrowed(route).iter().any(|parent_ref| {
                parent_ref_targets_gateway(route, parent_ref, gateway)
                    && parent_ref_matches_listener(parent_ref, listener)
                    && route_allowed_by_listener(indexes, route, gateway, listener)
                    && route_kind_allowed_by_listener(route, listener)
                    && route_intersects_listener_hostname(route, listener)
            })
        })
        .count()
}

fn route_kind_allowed_by_listener(route: &K8sObject, listener: &Value) -> bool {
    let protocol_kinds = listener_protocol_route_kinds(
        listener
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    if protocol_kinds.is_empty() {
        return false;
    }
    if !protocol_kinds.contains(&route.kind.as_str()) {
        return false;
    }
    let Some(kinds) = listener
        .get("allowedRoutes")
        .and_then(|allowed_routes| allowed_routes.get("kinds"))
        .and_then(Value::as_array)
    else {
        return true;
    };
    kinds
        .iter()
        .any(|kind| listener_allowed_route_kind(kind, &protocol_kinds) == Some(route.kind.as_str()))
}

fn route_allowed_by_listener(
    indexes: &GatewayApiStatusIndexes<'_>,
    route: &K8sObject,
    gateway: &K8sObject,
    listener: &Value,
) -> bool {
    let Ok(namespaces) = parse_gateway_listener_allowed_route_namespaces(listener) else {
        return false;
    };
    match namespaces {
        GatewayApiAllowedRoutesNamespaces::Same => {
            route.metadata.namespace == gateway.metadata.namespace
        }
        GatewayApiAllowedRoutesNamespaces::All => true,
        GatewayApiAllowedRoutesNamespaces::Selector(selector) => indexes
            .namespaces_by_name
            .get(route.metadata.namespace.as_str())
            .copied()
            .is_some_and(|namespace| {
                namespace_selector_matches(&namespace.metadata.labels, &selector)
            }),
        GatewayApiAllowedRoutesNamespaces::Invalid => false,
    }
}

fn route_intersects_listener_hostname(route: &K8sObject, listener: &Value) -> bool {
    let Some(listener_hostname) = listener
        .get("hostname")
        .and_then(Value::as_str)
        .map(normalize_hostname)
    else {
        return true;
    };
    route_hostnames(route).into_iter().any(|route_hostname| {
        hostnames_intersect(route_hostname.as_str(), listener_hostname.as_str())
    })
}

fn route_hostnames(route: &K8sObject) -> Vec<String> {
    let hostnames: Vec<String> = route
        .spec
        .get("hostnames")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(normalize_hostname)
        .collect();
    if hostnames.is_empty() {
        vec!["*".to_string()]
    } else {
        hostnames
    }
}

fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn hostnames_intersect(route_hostname: &str, listener_hostname: &str) -> bool {
    if route_hostname == "*" || listener_hostname == "*" {
        return true;
    }
    match (
        wildcard_hostname_suffix(route_hostname),
        wildcard_hostname_suffix(listener_hostname),
    ) {
        (None, None) => route_hostname == listener_hostname,
        (Some(route_suffix), None) => hostname_matches_wildcard(listener_hostname, route_suffix),
        (None, Some(listener_suffix)) => hostname_matches_wildcard(route_hostname, listener_suffix),
        (Some(route_suffix), Some(listener_suffix)) => {
            route_suffix == listener_suffix
                || suffix_is_within(route_suffix, listener_suffix)
                || suffix_is_within(listener_suffix, route_suffix)
        }
    }
}

fn wildcard_hostname_suffix(hostname: &str) -> Option<&str> {
    hostname.strip_prefix("*.")
}

fn hostname_matches_wildcard(hostname: &str, suffix: &str) -> bool {
    hostname != suffix && suffix_is_within(hostname, suffix)
}

fn suffix_is_within(hostname: &str, suffix: &str) -> bool {
    hostname
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn route_conflict_message(conflict: &GatewayApiRouteConflict) -> String {
    // Gateway API v1.5.1 forbids merging between HTTPRoutes and GRPCRoutes, so
    // a cross-kind overlap on a shared listener rejects the whole losing Route,
    // not just the colliding match — and because the materialized route is
    // port-agnostic, the rejection covers every listener that parentRef claim
    // reaches, not only the shared one. Say which case happened.
    if conflict.loser.kind != conflict.winner.kind {
        return format!(
            "Ferrum rejected this entire route on parent={} because Gateway API forbids merging {} and {} rules on a shared listener and host={} overlaps; winner is {} {}/{}",
            conflict.key.parent_ref,
            conflict.loser.kind,
            conflict.winner.kind,
            conflict.key.hostname,
            conflict.winner.kind,
            conflict.winner.namespace,
            conflict.winner.name
        );
    }
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
    objects: &[K8sObject],
    object: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
    result: Result<&crate::config_sources::k8s::K8sTranslation, &K8sTranslateError>,
    managed_parent_refs: &[&Value],
    route_conflicts: &[&GatewayApiRouteConflict],
    route_keys: &[GatewayApiRouteConflictKey],
) -> Value {
    // The translator records this typed route -> parentRef relationship at
    // the point where it emits HTTP, gRPC, TCP, or TLS proxies. Keep that
    // forward mapping authoritative here: proxy IDs are operational names,
    // not a status back-reference contract, and must never be parsed to
    // reconstruct their source route.
    let materialized_parent_refs: HashSet<String> = match result {
        Ok(translation) => materialized_route_parent_refs_for_route(
            &translation.materialized_route_parents,
            object,
        ),
        Err(_) => HashSet::new(),
    };
    let (accepted, resolved_refs, programmed, accepted_reason, resolved_refs_reason, message) =
        match result {
            Ok(_) => {
                let programmed = !materialized_parent_refs.is_empty();
                let unresolved_refs_reason =
                    route_unresolved_backend_ref_reason(objects, object, indexes);
                let resolved_refs = unresolved_refs_reason.is_none();
                let resolved_refs_reason = unresolved_refs_reason.unwrap_or("ResolvedRefs");
                (
                    true,
                    resolved_refs,
                    programmed,
                    if programmed { "Accepted" } else { "NoRules" },
                    resolved_refs_reason,
                    if !resolved_refs {
                        format!(
                            "Ferrum accepted this route but could not resolve all backendRefs: {resolved_refs_reason}"
                        )
                    } else if programmed {
                        "Ferrum accepted and programmed this route".to_string()
                    } else {
                        "Ferrum accepted this route but no materialized rule was produced"
                            .to_string()
                    },
                )
            }
            Err(error) => {
                if error_is_reference_resolution(error) {
                    let resolved_refs_reason = reference_resolution_reason(error);
                    (
                        true,
                        false,
                        false,
                        "Accepted",
                        resolved_refs_reason,
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
                } else if error_is_parent_ref_no_matching(error) {
                    (
                        false,
                        true,
                        false,
                        "NoMatchingParent",
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
        let not_allowed_by_listener = accepted
            && !all_parent_matches_conflicted
            && route_parent_ref_not_allowed_by_listener(objects, object, parent_ref, indexes);
        let no_matching_parent = accepted
            && !not_allowed_by_listener
            && !route_parent_ref_has_matching_parent(objects, object, parent_ref, indexes);
        let no_matching_listener_hostname = accepted
            && !no_matching_parent
            && !not_allowed_by_listener
            && !route_parent_ref_has_matching_listener(objects, object, parent_ref, indexes);
        let accepted_for_parent = accepted
            && !all_parent_matches_conflicted
            && !not_allowed_by_listener
            && !no_matching_parent
            && !no_matching_listener_hostname;
        let accepted_reason = if all_parent_matches_conflicted {
            "Conflicted"
        } else if not_allowed_by_listener {
            "NotAllowedByListeners"
        } else if no_matching_parent {
            "NoMatchingParent"
        } else if no_matching_listener_hostname {
            "NoMatchingListenerHostname"
        } else {
            accepted_reason
        };
        let accepted_message = if all_parent_matches_conflicted {
            conflict_message.as_deref().unwrap_or(&message)
        } else if not_allowed_by_listener {
            "Ferrum rejected this route attachment because it is not permitted by the target Gateway listener"
        } else if no_matching_parent {
            "Ferrum rejected this route attachment because no matching parent listener was found"
        } else if no_matching_listener_hostname {
            "Ferrum rejected this route attachment because no matching listener hostname was found"
        } else {
            &message
        };
        let parent_materialized = materialized_parent_refs.contains(&parent_ref_key);
        let programmed_for_parent = programmed
            && parent_materialized
            && !all_parent_matches_conflicted
            && !not_allowed_by_listener
            && !no_matching_parent
            && !no_matching_listener_hostname;
        let programmed_reason = if programmed_for_parent {
            "Programmed"
        } else if all_parent_matches_conflicted {
            "Conflicted"
        } else if not_allowed_by_listener {
            "NotAllowedByListeners"
        } else if no_matching_parent {
            "NoMatchingParent"
        } else if no_matching_listener_hostname {
            "NoMatchingListenerHostname"
        } else if !resolved_refs {
            resolved_refs_reason
        } else if accepted_for_parent && !parent_materialized {
            "NoRules"
        } else if accepted_for_parent {
            accepted_reason
        } else {
            "TranslationFailed"
        };
        let programmed_message = if programmed_for_parent {
            "Ferrum programmed this route"
        } else if all_parent_matches_conflicted {
            conflict_message.as_deref().unwrap_or(&message)
        } else if not_allowed_by_listener {
            "Ferrum did not program this route because it is not permitted by the target Gateway listener"
        } else if no_matching_listener_hostname {
            "Ferrum did not program this route because no matching listener hostname was found"
        } else if accepted_for_parent && !parent_materialized {
            "Ferrum accepted this route but no materialized rule was produced for this parentRef"
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

fn materialized_route_parent_refs_for_route(
    materialized_route_parents: &HashSet<GatewayApiMaterializedRouteParent>,
    route: &K8sObject,
) -> HashSet<String> {
    let route_key = K8sResourceKey::from_object(route);
    materialized_route_parents
        .iter()
        .filter(|entry| entry.route == route_key)
        .map(|entry| entry.parent_ref.clone())
        .collect()
}

fn gateway_api_status_apply_params() -> PatchParams {
    PatchParams::apply(GATEWAY_API_STATUS_FIELD_MANAGER).force()
}

fn route_status_patch_params() -> PatchParams {
    PatchParams {
        field_manager: Some(GATEWAY_API_STATUS_FIELD_MANAGER.to_string()),
        ..PatchParams::default()
    }
}

fn gateway_status_apply_patch_for_update(
    update: &GatewayApiStatusUpdate,
    live_status: Option<&Value>,
) -> Value {
    let mut status_patch = serde_json::Map::new();

    match update.kind.as_str() {
        "GatewayClass" | "Gateway" => {
            let desired_conditions = preserve_live_condition_transition_times(
                desired_owned_conditions(&update.status, owned_condition_types(&update.kind)),
                live_status.and_then(existing_conditions),
            );
            status_patch.insert("conditions".to_string(), Value::Array(desired_conditions));
            if update.kind == "Gateway" {
                if update.patch_gateway_addresses
                    && let Some(addresses) = update.status.get("addresses").cloned()
                {
                    status_patch.insert("addresses".to_string(), addresses);
                }
                if update.patch_gateway_listeners
                    && let Some(listeners) = update.status.get("listeners").cloned()
                {
                    status_patch.insert("listeners".to_string(), listeners);
                }
            }
        }
        _ => {
            status_patch = update.status.as_object().cloned().unwrap_or_default();
        }
    }

    // Apply requests identify the target in the document as well as in the
    // request URL. Keep namespace absent for the cluster-scoped GatewayClass.
    let mut metadata = serde_json::Map::new();
    metadata.insert("name".to_string(), Value::String(update.name.clone()));
    if update.kind != "GatewayClass" {
        metadata.insert(
            "namespace".to_string(),
            Value::String(update.namespace.clone()),
        );
    }

    let mut patch = serde_json::Map::new();
    patch.insert(
        "apiVersion".to_string(),
        Value::String(update.api_version.clone()),
    );
    patch.insert("kind".to_string(), Value::String(update.kind.clone()));
    patch.insert("metadata".to_string(), Value::Object(metadata));
    patch.insert("status".to_string(), Value::Object(status_patch));
    Value::Object(patch)
}

fn route_status_merge_patch_for_update(
    update: &GatewayApiStatusUpdate,
    live_status: Option<&Value>,
    resource_version: &str,
) -> Value {
    let desired_parents = desired_ferrum_parent_statuses(&update.status)
        .into_iter()
        .map(|parent| preserve_live_parent_condition_transition_times(update, parent, live_status))
        .collect();
    let parents = match live_status {
        Some(status) => merge_parent_statuses(status, desired_parents),
        None => desired_parents,
    };

    json!({
        "metadata": {
            "resourceVersion": resource_version,
        },
        "status": {
            "parents": parents,
        },
    })
}

fn preserve_live_condition_transition_times(
    desired_conditions: Vec<Value>,
    live_conditions: Option<&[Value]>,
) -> Vec<Value> {
    desired_conditions
        .into_iter()
        .map(|desired| {
            let Some(desired_type) = condition_type(&desired) else {
                return desired;
            };
            let Some(existing) = live_conditions
                .into_iter()
                .flatten()
                .find(|condition| condition_type(condition) == Some(desired_type))
            else {
                return desired;
            };
            preserve_unchanged_transition_time(desired, existing)
        })
        .collect()
}

fn preserve_live_parent_condition_transition_times(
    update: &GatewayApiStatusUpdate,
    mut desired_parent: Value,
    live_status: Option<&Value>,
) -> Value {
    let Some(desired_parent_ref) = desired_parent.get("parentRef") else {
        return desired_parent;
    };
    let desired_key = route_parent_ref_key_for_namespace(&update.namespace, desired_parent_ref);
    let live_conditions = live_status
        .and_then(|status| status.get("parents"))
        .and_then(Value::as_array)
        .and_then(|parents| {
            parents.iter().find(|parent| {
                parent.get("controllerName").and_then(Value::as_str)
                    == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                    && parent.get("parentRef").is_some_and(|parent_ref| {
                        route_parent_ref_key_for_namespace(&update.namespace, parent_ref)
                            == desired_key
                    })
            })
        })
        .and_then(|parent| parent.get("conditions"))
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let desired_conditions = desired_parent
        .get("conditions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let conditions = preserve_live_condition_transition_times(desired_conditions, live_conditions);
    if let Value::Object(parent) = &mut desired_parent {
        parent.insert("conditions".to_string(), Value::Array(conditions));
    }
    desired_parent
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

pub(crate) fn preserve_unchanged_transition_time(mut desired: Value, existing: &Value) -> Value {
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

fn route_parent_refs_borrowed(object: &K8sObject) -> &[Value] {
    object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .filter(|refs| !refs.is_empty())
        .unwrap_or(&[])
}

fn status_candidate_is_eligible(object: &K8sObject, indexes: &GatewayApiStatusIndexes<'_>) -> bool {
    match object.kind.as_str() {
        "GatewayClass" => gateway_class_is_managed_by_ferrum(object),
        "Gateway" => indexes.managed_gateways.contains(&(
            object.metadata.namespace.as_str(),
            object.metadata.name.as_str(),
        )),
        "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute" => {
            // Borrowed predicate only — do not deep-clone parentRefs before the
            // fair work budget selects the expensive status window (#2397).
            route_has_managed_parent_ref_indexed(object, indexes)
                || has_ferrum_parent_status(&object.status)
        }
        _ => false,
    }
}

fn route_has_managed_parent_ref_indexed(
    route: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> bool {
    route_parent_refs_borrowed(route)
        .iter()
        .any(|parent_ref| parent_ref_targets_managed_gateway_indexed(route, parent_ref, indexes))
}

fn managed_route_parent_refs_indexed<'a>(
    route: &'a K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> Vec<&'a Value> {
    route_parent_refs_borrowed(route)
        .iter()
        .filter(|parent_ref| parent_ref_targets_managed_gateway_indexed(route, parent_ref, indexes))
        .collect()
}

fn parent_ref_gateway_target<'a>(
    route: &'a K8sObject,
    parent_ref: &'a Value,
) -> Option<(&'a str, &'a str)> {
    let group = parent_ref
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or("gateway.networking.k8s.io");
    let kind = parent_ref
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Gateway");
    let name = parent_ref.get("name").and_then(Value::as_str)?;
    if group != "gateway.networking.k8s.io" || kind != "Gateway" {
        return None;
    }
    let namespace = parent_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    Some((namespace, name))
}

fn parent_ref_targets_managed_gateway_indexed(
    route: &K8sObject,
    parent_ref: &Value,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> bool {
    let Some((namespace, name)) = parent_ref_gateway_target(route, parent_ref) else {
        return false;
    };
    indexes.managed_gateways.contains(&(namespace, name))
}

fn parent_ref_targets_gateway(route: &K8sObject, parent_ref: &Value, gateway: &K8sObject) -> bool {
    let Some((namespace, name)) = parent_ref_gateway_target(route, parent_ref) else {
        return false;
    };
    namespace == gateway.metadata.namespace && name == gateway.metadata.name
}

fn route_parent_ref_has_matching_listener(
    _objects: &[K8sObject],
    route: &K8sObject,
    parent_ref: &Value,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> bool {
    let namespace = parent_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    let Some(name) = parent_ref.get("name").and_then(Value::as_str) else {
        return true;
    };
    let Some(gateway) = indexes.gateways_by_ns_name.get(&(namespace, name)).copied() else {
        return true;
    };
    if !parent_ref_targets_gateway(route, parent_ref, gateway) {
        return true;
    }
    gateway
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|listener| {
            route_kind_allowed_by_listener(route, listener)
                && parent_ref_matches_listener(parent_ref, listener)
                && route_allowed_by_listener(indexes, route, gateway, listener)
                && route_intersects_listener_hostname(route, listener)
        })
}

fn route_parent_ref_not_allowed_by_listener(
    _objects: &[K8sObject],
    route: &K8sObject,
    parent_ref: &Value,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> bool {
    let namespace = parent_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    let Some(name) = parent_ref.get("name").and_then(Value::as_str) else {
        return false;
    };
    let Some(gateway) = indexes.gateways_by_ns_name.get(&(namespace, name)).copied() else {
        return false;
    };
    if !parent_ref_targets_gateway(route, parent_ref, gateway) {
        return false;
    }

    let mut saw_matching_listener = false;
    for listener in gateway
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_matches_listener(parent_ref, listener) {
            continue;
        }
        saw_matching_listener = true;
        if route_kind_allowed_by_listener(route, listener)
            && route_allowed_by_listener(indexes, route, gateway, listener)
        {
            return false;
        }
    }
    saw_matching_listener
}

fn route_parent_ref_has_matching_parent(
    _objects: &[K8sObject],
    route: &K8sObject,
    parent_ref: &Value,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> bool {
    let namespace = parent_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    let Some(name) = parent_ref.get("name").and_then(Value::as_str) else {
        return false;
    };
    let Some(gateway) = indexes.gateways_by_ns_name.get(&(namespace, name)).copied() else {
        return false;
    };
    if !parent_ref_targets_gateway(route, parent_ref, gateway) {
        return false;
    }
    gateway
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|listener| {
            route_kind_allowed_by_listener(route, listener)
                && parent_ref_matches_listener(parent_ref, listener)
                && route_allowed_by_listener(indexes, route, gateway, listener)
        })
}

fn parent_ref_matches_listener(parent_ref: &Value, listener: &Value) -> bool {
    if let Some(section_name) = parent_ref.get("sectionName").and_then(Value::as_str) {
        let listener_name = listener
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("listener");
        if section_name != listener_name {
            return false;
        }
    }
    if let Some(parent_port) = parent_ref.get("port").and_then(Value::as_u64)
        && listener.get("port").and_then(Value::as_u64) != Some(parent_port)
    {
        return false;
    }
    true
}

pub fn gateway_api_data_plane_service_ready(
    objects: &[K8sObject],
    namespace: &str,
    name: &str,
) -> bool {
    objects.iter().any(|object| {
        object.kind == "EndpointSlice"
            && object.metadata.namespace == namespace
            && object
                .metadata
                .labels
                .get("kubernetes.io/service-name")
                .is_some_and(|service_name| service_name == name)
            && endpoint_slice_has_ready_endpoint(object)
    })
}

fn endpoint_slice_has_ready_endpoint(object: &K8sObject) -> bool {
    object
        .spec
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(endpoint_ready)
}

fn endpoint_ready(endpoint: &Value) -> bool {
    let Some(conditions) = endpoint.get("conditions") else {
        return true;
    };
    if conditions
        .get("terminating")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let ready = conditions.get("ready").and_then(Value::as_bool);
    let serving = conditions
        .get("serving")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| ready.unwrap_or(true));
    ready.unwrap_or(true) && serving
}

fn route_parent_ref_key(route: &K8sObject, parent_ref: &Value) -> String {
    route_parent_ref_key_for_namespace(&route.metadata.namespace, parent_ref)
}

fn route_parent_ref_key_for_namespace(route_namespace: &str, parent_ref: &Value) -> String {
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
        .unwrap_or(route_namespace);
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

fn gateway_programmed(object: &K8sObject, config: &GatewayConfig) -> bool {
    let Some(listeners) = object.spec.get("listeners").and_then(Value::as_array) else {
        return false;
    };
    listeners
        .iter()
        .any(|listener| gateway_listener_programmed(object, listener, config))
}

fn gateway_listener_programmed(
    object: &K8sObject,
    listener: &Value,
    config: &GatewayConfig,
) -> bool {
    // Mesh services derived from this Gateway are named `{gateway.name}-{listener.name}`
    // (see `mesh_services_from_gateway` in `gateway_api.rs`). Use exact match against
    // the listener name to avoid a false positive when another Gateway's name is a
    // prefix of this one (e.g. `edge` matching `edge-internal-http`).
    let Some(mesh) = config.mesh.as_ref() else {
        return false;
    };
    let listener_name = listener
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("listener");
    let expected = format!("{}-{}", object.metadata.name, listener_name);
    mesh.services
        .iter()
        .any(|service| service.namespace == object.metadata.namespace && service.name == expected)
}

fn route_unresolved_backend_ref_reason(
    _objects: &[K8sObject],
    route: &K8sObject,
    indexes: &GatewayApiStatusIndexes<'_>,
) -> Option<&'static str> {
    let services_observed = indexes.has_any_service;
    for backend_ref in route
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| rule.get("backendRefs").and_then(Value::as_array))
        .flatten()
    {
        if backend_ref.get("weight").and_then(Value::as_u64) == Some(0) {
            continue;
        }
        let to_group = backend_ref
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let to_kind = backend_ref
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Service");
        if !to_group.is_empty() || to_kind != "Service" {
            return Some("InvalidKind");
        }

        let backend_namespace = backend_ref
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(&route.metadata.namespace);
        let backend_name = backend_ref.get("name").and_then(Value::as_str);
        if backend_namespace != route.metadata.namespace
            && !reference_grant_allows_backend_ref(
                indexes,
                route,
                backend_namespace,
                to_group,
                to_kind,
                backend_name,
            )
        {
            return Some("RefNotPermitted");
        }
        if services_observed && let Some(backend_name) = backend_name {
            if !indexes
                .services_by_ns_name
                .contains_key(&(backend_namespace, backend_name))
            {
                return Some("BackendNotFound");
            }
            let backend_port = backend_ref
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or(if route.kind == "GRPCRoute" { 50051 } else { 80 });
            if !service_has_port_indexed(indexes, backend_namespace, backend_name, backend_port) {
                return Some("BackendNotFound");
            }
        }
    }

    None
}

fn service_has_port_indexed(
    indexes: &GatewayApiStatusIndexes<'_>,
    namespace: &str,
    name: &str,
    port: u16,
) -> bool {
    indexes
        .services_by_ns_name
        .get(&(namespace, name))
        .and_then(|service| service.spec.get("ports"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| entry.get("port").and_then(Value::as_u64) == Some(u64::from(port)))
}

fn reference_grant_allows_backend_ref(
    indexes: &GatewayApiStatusIndexes<'_>,
    route: &K8sObject,
    to_namespace: &str,
    to_group: &str,
    to_kind: &str,
    to_name: Option<&str>,
) -> bool {
    indexes.reference_grant_permissions.allows(
        route.metadata.namespace.as_str(),
        api_group(&route.api_version),
        route.kind.as_str(),
        to_namespace,
        to_group,
        to_kind,
        to_name,
    )
}

fn api_group(api_version: &str) -> &str {
    api_version
        .split_once('/')
        .map(|(group, _version)| group)
        .unwrap_or_default()
}

fn error_is_reference_resolution(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("ReferenceGrant")
                || message.contains("only core Service")
                || message.contains("backendRef Service")
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn reference_resolution_reason(error: &K8sTranslateError) -> &'static str {
    match error {
        K8sTranslateError::InvalidResource { message, .. }
            if message.contains("backendRef Service") =>
        {
            "BackendNotFound"
        }
        K8sTranslateError::InvalidResource { message, .. }
            if message.contains("only core Service") =>
        {
            "InvalidKind"
        }
        _ => "RefNotPermitted",
    }
}

fn error_is_parent_ref_not_allowed(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("parentRef.namespace")
                && message.contains("not permitted by the target Gateway listener")
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn error_is_parent_ref_no_matching(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("parentRef")
                && message.contains("does not match any known Gateway listener")
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn is_status_kind(kind: &str) -> bool {
    matches!(
        kind,
        "GatewayClass" | "Gateway" | "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute"
    )
}

fn api_resource_for_update(update: &GatewayApiStatusUpdate) -> Option<ApiResource> {
    let (group, version) = update.api_version.split_once('/')?;
    let plural = match (update.kind.as_str(), version) {
        ("GatewayClass", "v1" | "v1beta1") => "gatewayclasses",
        ("Gateway", "v1" | "v1beta1") => "gateways",
        ("HTTPRoute", "v1" | "v1beta1") => "httproutes",
        ("GRPCRoute", "v1") => "grpcroutes",
        ("TCPRoute", "v1alpha2") => "tcproutes",
        ("TLSRoute", "v1alpha2") => "tlsroutes",
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

    fn plan_status_updates_with_context(
        objects: &[K8sObject],
        options: K8sTranslationOptions,
        status_context: GatewayApiStatusContext,
    ) -> Vec<GatewayApiStatusUpdate> {
        let conflicts = gateway_api_route_conflicts(objects, &options);
        plan_gateway_api_status_updates_with_context(objects, options, &conflicts, status_context)
    }

    fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
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

    fn namespace(name: &str, labels: &[(&str, &str)]) -> K8sObject {
        let mut namespace = object("Namespace", name, json!({}));
        namespace.api_version = "v1".to_string();
        namespace.metadata.namespace = String::new();
        namespace.metadata.labels = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        namespace
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
                patch_gateway_addresses: false,
                patch_gateway_listeners: false,
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
    fn gateway_status_uses_builtin_ferrum_class_when_unobserved() {
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );

        let updates = plan_status_updates(&[gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "True");
    }

    #[test]
    fn gateway_status_honors_observed_ferrum_class_controller() {
        let gateway_class = object(
            "GatewayClass",
            "ferrum",
            json!({ "controllerName": "example.com/other-controller" }),
        );
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        assert!(updates.is_empty());
    }

    #[test]
    fn route_status_uses_builtin_ferrum_class_when_unobserved() {
        let gateway = ferrum_gateway("edge");
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );

        let updates = plan_status_updates(&[gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "True");
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
    fn gateway_status_honors_custom_ferrum_gateway_class_name() {
        let gateway_class = object(
            "GatewayClass",
            "edge-class",
            json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
        );
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "edge-class",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "Programmed", "True");
    }

    #[test]
    fn gateway_listener_status_preserves_unchanged_listener_condition_transition_time() {
        let gateway_class = ferrum_gateway_class();
        let mut gateway = ferrum_gateway("edge");
        gateway.status = json!({
            "listeners": [{
                "name": "http",
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 7,
                    "reason": "Accepted",
                    "message": "Ferrum accepted this listener",
                    "lastTransitionTime": "2026-01-01T00:00:00Z"
                }]
            }]
        });

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listeners = gateway_update.status["listeners"].as_array().unwrap();
        let listener = listener_status_by_name(listeners, "http");
        let conditions = listener["conditions"].as_array().unwrap();
        assert_eq!(
            find_condition(conditions, "Accepted")["lastTransitionTime"].as_str(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn gateway_status_waits_for_ready_data_plane_before_programmed_true() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");

        let updates = plan_status_updates_with_context(
            &[gateway_class, gateway],
            options(),
            GatewayApiStatusContext {
                data_plane_ready: false,
                status_address: Some("127.0.0.1".to_string()),
            },
        );

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "Programmed")["reason"].as_str(),
            Some("DataPlaneNotReady")
        );
        assert_eq!(
            gateway_update.status["addresses"],
            json!([{"type": "IPAddress", "value": "127.0.0.1"}])
        );
    }

    #[test]
    fn gateway_listener_status_reports_invalid_route_kinds() {
        let gateway_class = ferrum_gateway_class();
        let only_invalid = object(
            "Gateway",
            "gateway-only-invalid-route-kind",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": { "from": "All" },
                        "kinds": [{ "kind": "InvalidRoute" }]
                    }
                }]
            }),
        );
        let mixed = object(
            "Gateway",
            "gateway-supported-and-invalid-route-kind",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": { "from": "All" },
                        "kinds": [{ "kind": "InvalidRoute" }, { "kind": "HTTPRoute" }]
                    }
                }]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, only_invalid, mixed], options());

        let only_invalid_update =
            update_for(&updates, "Gateway", "gateway-only-invalid-route-kind");
        let only_invalid_listener = listener_status_by_name(
            only_invalid_update.status["listeners"].as_array().unwrap(),
            "http",
        );
        assert_eq!(
            only_invalid_listener["supportedKinds"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let conditions = only_invalid_listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("InvalidRouteKinds")
        );

        let mixed_update = update_for(
            &updates,
            "Gateway",
            "gateway-supported-and-invalid-route-kind",
        );
        let mixed_listener =
            listener_status_by_name(mixed_update.status["listeners"].as_array().unwrap(), "http");
        assert_eq!(
            mixed_listener["supportedKinds"],
            json!([{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}])
        );
        let conditions = mixed_listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("InvalidRouteKinds")
        );
    }

    #[test]
    fn gateway_http_listener_status_allows_grpc_route_kind() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": { "from": "All" },
                        "kinds": [{ "kind": "GRPCRoute" }]
                    }
                }]
            }),
        );
        let route = object(
            "GRPCRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 50051}]}]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "http",
        );
        assert_eq!(
            listener["supportedKinds"],
            json!([{"group": "gateway.networking.k8s.io", "kind": "GRPCRoute"}])
        );
        assert_eq!(listener["attachedRoutes"].as_u64(), Some(1));
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "True");
    }

    #[test]
    fn gateway_listener_attached_routes_require_hostname_intersection() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "httproute-hostname-intersection",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "listener-1",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "very.specific.com",
                        "allowedRoutes": { "namespaces": { "from": "Same" } }
                    },
                    {
                        "name": "listener-2",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "*.wildcard.io",
                        "allowedRoutes": { "namespaces": { "from": "Same" } }
                    },
                    {
                        "name": "listener-3",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "*.anotherwildcard.io",
                        "allowedRoutes": { "namespaces": { "from": "Same" } }
                    }
                ]
            }),
        );
        let routes = [
            object(
                "HTTPRoute",
                "specific-host-matches-listener-specific-host",
                json!({
                    "parentRefs": [{"name": "httproute-hostname-intersection"}],
                    "hostnames": [
                        "non.matching.com",
                        "*.nonmatchingwildcard.io",
                        "very.specific.com"
                    ],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s1"}}],
                        "backendRefs": [{"name": "infra-backend-v1", "port": 8080}]
                    }]
                }),
            ),
            object(
                "HTTPRoute",
                "specific-host-matches-listener-wildcard-host",
                json!({
                    "parentRefs": [{"name": "httproute-hostname-intersection"}],
                    "hostnames": [
                        "non.matching.com",
                        "wildcard.io",
                        "foo.wildcard.io",
                        "bar.wildcard.io",
                        "foo.bar.wildcard.io"
                    ],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s2"}}],
                        "backendRefs": [{"name": "infra-backend-v2", "port": 8080}]
                    }]
                }),
            ),
            object(
                "HTTPRoute",
                "wildcard-host-matches-listener-specific-host",
                json!({
                    "parentRefs": [{"name": "httproute-hostname-intersection"}],
                    "hostnames": ["non.matching.com", "*.specific.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s3"}}],
                        "backendRefs": [{"name": "infra-backend-v3", "port": 8080}]
                    }]
                }),
            ),
            object(
                "HTTPRoute",
                "wildcard-host-matches-listener-wildcard-host",
                json!({
                    "parentRefs": [{"name": "httproute-hostname-intersection"}],
                    "hostnames": ["*.anotherwildcard.io"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s4"}}],
                        "backendRefs": [{"name": "infra-backend-v1", "port": 8080}]
                    }]
                }),
            ),
            object(
                "HTTPRoute",
                "no-intersecting-hosts",
                json!({
                    "parentRefs": [{"name": "httproute-hostname-intersection"}],
                    "hostnames": ["specific.but.wrong.com", "wildcard.io"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s5"}}],
                        "backendRefs": [{"name": "infra-backend-v2", "port": 8080}]
                    }]
                }),
            ),
        ];
        let mut objects = vec![gateway_class, gateway];
        objects.extend(routes);

        let updates = plan_status_updates(&objects, options());

        let gateway_update = update_for(&updates, "Gateway", "httproute-hostname-intersection");
        let listeners = gateway_update.status["listeners"].as_array().unwrap();
        assert_eq!(
            listener_status_by_name(listeners, "listener-1")["attachedRoutes"].as_u64(),
            Some(2)
        );
        assert_eq!(
            listener_status_by_name(listeners, "listener-2")["attachedRoutes"].as_u64(),
            Some(1)
        );
        assert_eq!(
            listener_status_by_name(listeners, "listener-3")["attachedRoutes"].as_u64(),
            Some(1)
        );

        let route_update = update_for(&updates, "HTTPRoute", "no-intersecting-hosts");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("NoMatchingListenerHostname")
        );
        assert_condition(conditions, "Programmed", "False");
    }

    #[test]
    fn gateway_listener_namespace_selector_empty_selector_matches_all_namespaces() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {
                            "from": "Selector",
                            "selector": {}
                        }
                    }
                }]
            }),
        );
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        route.metadata.namespace = "tenant-a".to_string();
        let tenant = namespace("tenant-a", &[]);

        let updates = plan_status_updates(&[gateway_class, gateway, tenant, route], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listeners = gateway_update.status["listeners"].as_array().unwrap();
        assert_eq!(
            listener_status_by_name(listeners, "http")["attachedRoutes"].as_u64(),
            Some(1)
        );
    }

    #[test]
    fn gateway_listener_namespace_selector_matches_expressions_without_match_labels() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {
                            "from": "Selector",
                            "selector": {
                                "matchExpressions": [
                                    {"key": "env", "operator": "In", "values": ["prod"]},
                                    {"key": "team", "operator": "Exists"}
                                ]
                            }
                        }
                    }
                }]
            }),
        );
        let mut selected_route = object(
            "HTTPRoute",
            "selected",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        selected_route.metadata.namespace = "selected".to_string();
        let mut rejected_route = object(
            "HTTPRoute",
            "rejected",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        rejected_route.metadata.namespace = "rejected".to_string();
        let selected_namespace = namespace("selected", &[("env", "prod"), ("team", "payments")]);
        let rejected_namespace = namespace("rejected", &[("env", "dev"), ("team", "payments")]);

        let updates = plan_status_updates(
            &[
                gateway_class,
                gateway,
                selected_namespace,
                rejected_namespace,
                selected_route,
                rejected_route,
            ],
            options(),
        );

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listeners = gateway_update.status["listeners"].as_array().unwrap();
        assert_eq!(
            listener_status_by_name(listeners, "http")["attachedRoutes"].as_u64(),
            Some(1)
        );
    }

    #[test]
    fn gateway_listener_certificate_ref_requires_reference_grant_for_cross_namespace_secret() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [{
                            "group": "",
                            "kind": "Secret",
                            "name": "certificate",
                            "namespace": "backend"
                        }]
                    }
                }]
            }),
        );
        let secret = tls_secret("certificate", "backend", true);

        let updates = plan_status_updates(
            &[gateway_class.clone(), gateway.clone(), secret.clone()],
            options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]),
        );

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "https",
        );
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("RefNotPermitted")
        );
        assert_condition(conditions, "Programmed", "False");

        let grant = reference_grant_for_gateway_secret("default", "backend", "certificate");
        let updates = plan_status_updates(
            &[gateway_class, gateway, secret, grant],
            options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]),
        );

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "https",
        );
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
    }

    #[test]
    fn gateway_listener_certificate_ref_reports_invalid_for_missing_or_malformed_secret() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [{
                            "name": "malformed-certificate"
                        }]
                    }
                }]
            }),
        );
        let malformed = tls_secret("malformed-certificate", "default", false);

        let updates = plan_status_updates(&[gateway_class.clone(), gateway.clone()], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "https",
        );
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("InvalidCertificateRef")
        );
        assert_condition(conditions, "Programmed", "False");

        let updates = plan_status_updates(
            &[gateway_class.clone(), gateway.clone(), malformed],
            options(),
        );

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "https",
        );
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("InvalidCertificateRef")
        );
        assert_condition(conditions, "Programmed", "False");

        let mismatched = tls_secret_with_mismatched_key("malformed-certificate", "default");
        let updates = plan_status_updates(&[gateway_class, gateway, mismatched], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "https",
        );
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("InvalidCertificateRef")
        );
        assert_condition(conditions, "Programmed", "False");
    }

    #[test]
    fn gateway_listener_without_certificate_refs_reports_invalid() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {}
                }]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "https",
        );
        let conditions = listener["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("InvalidCertificateRef")
        );
        assert_condition(conditions, "Programmed", "False");
    }

    #[test]
    fn gateway_listener_status_reports_multiple_certificate_refs_unsupported() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https-a",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "certificate-a"}]}
                    },
                    {
                        "name": "https-b",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "certificate-b"}]}
                    }
                ]
            }),
        );
        let secret_a = tls_secret("certificate-a", "default", true);
        let secret_b = tls_secret("certificate-b", "default", true);

        let updates = plan_status_updates(&[gateway_class, gateway, secret_a, secret_b], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let conditions = gateway_update.status["conditions"].as_array().unwrap();
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("UnsupportedValue")
        );
        let listeners = gateway_update.status["listeners"].as_array().unwrap();
        let listener = listener_status_by_name(listeners, "https-a");
        let listener_conditions = listener["conditions"].as_array().unwrap();
        assert_condition(listener_conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(listener_conditions, "ResolvedRefs")["reason"].as_str(),
            Some("UnsupportedValue")
        );
    }

    #[test]
    fn same_namespace_gateway_tls_conflict_resolves_refs_and_keeps_status_programming() {
        let gateway_class = ferrum_gateway_class();
        let gateway_a = object(
            "Gateway",
            "edge-a",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https-a",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "certificate-a"}]}
                }]
            }),
        );
        let gateway_b = object(
            "Gateway",
            "edge-b",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https-b",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "certificate-b"}]}
                }]
            }),
        );
        let secret_a = tls_secret("certificate-a", "default", true);
        let secret_b = tls_secret("certificate-b", "default", true);

        let updates = plan_status_updates(
            &[gateway_class, gateway_a, gateway_b, secret_a, secret_b],
            options(),
        );

        for gateway_name in ["edge-a", "edge-b"] {
            let gateway_update = update_for(&updates, "Gateway", gateway_name);
            let conditions = gateway_update.status["conditions"].as_array().unwrap();
            assert_condition(conditions, "ResolvedRefs", "True");
            assert_condition(conditions, "Programmed", "True");

            let listeners = gateway_update.status["listeners"].as_array().unwrap();
            let listener = listener_status_by_name(
                listeners,
                if gateway_name == "edge-a" {
                    "https-a"
                } else {
                    "https-b"
                },
            );
            let listener_conditions = listener["conditions"].as_array().unwrap();
            assert_condition(listener_conditions, "ResolvedRefs", "True");
            assert_condition(listener_conditions, "Programmed", "True");
        }
    }

    #[test]
    fn gateway_listener_programmed_is_per_listener_when_sibling_refs_fail() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {"name": "http", "port": 80, "protocol": "HTTP"},
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "missing-cert"}]}
                    }
                ]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listeners = gateway_update.status["listeners"].as_array().unwrap();
        let http = listener_status_by_name(listeners, "http");
        let http_conditions = http["conditions"].as_array().unwrap();
        assert_condition(http_conditions, "ResolvedRefs", "True");
        assert_condition(http_conditions, "Programmed", "True");
        let https = listener_status_by_name(listeners, "https");
        let https_conditions = https["conditions"].as_array().unwrap();
        assert_condition(https_conditions, "ResolvedRefs", "False");
        assert_condition(https_conditions, "Programmed", "False");
        assert_eq!(
            find_condition(https_conditions, "Programmed")["reason"].as_str(),
            Some("InvalidCertificateRef")
        );
    }

    #[test]
    fn route_status_attaches_to_unmaterialized_tls_listener_and_reports_backend_ref() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tls",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "does-not-exist"}]}
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge", "sectionName": "tls"}],
                "rules": [{"backendRefs": [{"name": "does-not-exist", "port": 8080}]}]
            }),
        );
        let service = {
            let mut service = object(
                "Service",
                "observed",
                json!({"ports": [{"name": "http", "port": 8080}]}),
            );
            service.api_version = "v1".to_string();
            service
        };

        let updates = plan_status_updates(&[gateway_class, gateway, route, service], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "tls",
        );
        assert_eq!(listener["attachedRoutes"].as_u64(), Some(1));

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("BackendNotFound")
        );
    }

    #[test]
    fn route_status_programmed_is_scoped_to_each_parent_ref() {
        let gateway_class = ferrum_gateway_class();
        let http_gateway = ferrum_gateway("edge-http");
        let tls_gateway = object(
            "Gateway",
            "edge-tls",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "missing-cert"}]}
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [
                    {"name": "edge-http"},
                    {"name": "edge-tls", "sectionName": "https"}
                ],
                "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
            }),
        );
        let mut service = object(
            "Service",
            "api",
            json!({"ports": [{"name": "http", "port": 8080}]}),
        );
        service.api_version = "v1".to_string();

        let updates = plan_status_updates(
            &[gateway_class, http_gateway, tls_gateway, route, service],
            options(),
        );

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let http_parent = parents
            .iter()
            .find(|parent| parent["parentRef"]["name"].as_str() == Some("edge-http"))
            .expect("HTTP parent status");
        let tls_parent = parents
            .iter()
            .find(|parent| parent["parentRef"]["name"].as_str() == Some("edge-tls"))
            .expect("TLS parent status");

        assert_condition(
            http_parent["conditions"].as_array().unwrap(),
            "Programmed",
            "True",
        );
        let tls_conditions = tls_parent["conditions"].as_array().unwrap();
        assert_condition(tls_conditions, "Accepted", "True");
        assert_condition(tls_conditions, "ResolvedRefs", "True");
        assert_condition(tls_conditions, "Programmed", "False");
        assert_eq!(
            find_condition(tls_conditions, "Programmed")["reason"].as_str(),
            Some("NoRules")
        );
    }

    #[test]
    fn gateway_api_data_plane_service_ready_requires_ready_endpoint_slice_endpoint() {
        let mut endpoint_slice = object(
            "EndpointSlice",
            "ferrum-dp-abc",
            json!({
                "endpoints": [{
                    "conditions": {"ready": true}
                }]
            }),
        );
        endpoint_slice.metadata.namespace = "ferrum".to_string();
        endpoint_slice.metadata.labels.insert(
            "kubernetes.io/service-name".to_string(),
            "ferrum-gateway".to_string(),
        );

        assert!(gateway_api_data_plane_service_ready(
            &[endpoint_slice.clone()],
            "ferrum",
            "ferrum-gateway"
        ));

        endpoint_slice.spec = json!({
            "endpoints": [{
                "conditions": {"ready": false}
            }]
        });
        assert!(!gateway_api_data_plane_service_ready(
            &[endpoint_slice],
            "ferrum",
            "ferrum-gateway"
        ));
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
    fn route_status_reports_no_matching_parent_for_missing_section_name() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge", "sectionName": "http1"}],
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
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("NoMatchingParent")
        );
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "False");
    }

    #[test]
    fn route_status_reports_no_matching_parent_for_missing_parent_ref_port() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge", "port": 81}],
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
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "False");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("NoMatchingParent")
        );
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "False");
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
        assert_condition(conditions, "Programmed", "True");
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
    fn route_status_scopes_not_allowed_to_disallowed_parent_ref() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "web",
                        "port": 80,
                        "protocol": "HTTP",
                        "allowedRoutes": {
                            "namespaces": {"from": "All"},
                            "kinds": [{"kind": "HTTPRoute"}]
                        }
                    },
                    {
                        "name": "grpc",
                        "port": 8080,
                        "protocol": "HTTP",
                        "allowedRoutes": {
                            "namespaces": {"from": "All"},
                            "kinds": [{"kind": "GRPCRoute"}]
                        }
                    }
                ]
            }),
        );
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [
                    {"name": "edge", "sectionName": "web"},
                    {"name": "edge", "sectionName": "grpc"}
                ],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let web_parent = parents
            .iter()
            .find(|parent| parent["parentRef"]["sectionName"].as_str() == Some("web"))
            .expect("web parent status");
        let grpc_parent = parents
            .iter()
            .find(|parent| parent["parentRef"]["sectionName"].as_str() == Some("grpc"))
            .expect("grpc parent status");

        let web_conditions = web_parent["conditions"].as_array().unwrap();
        assert_condition(web_conditions, "Accepted", "True");
        assert_condition(web_conditions, "Programmed", "True");

        let grpc_conditions = grpc_parent["conditions"].as_array().unwrap();
        assert_condition(grpc_conditions, "Accepted", "False");
        assert_condition(grpc_conditions, "Programmed", "False");
        assert_eq!(
            find_condition(grpc_conditions, "Accepted")["reason"].as_str(),
            Some("NotAllowedByListeners")
        );
        assert_eq!(
            find_condition(grpc_conditions, "Programmed")["reason"].as_str(),
            Some("NotAllowedByListeners")
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
            Some("InvalidKind")
        );
    }

    #[test]
    fn route_status_reports_unresolved_backend_ref_to_missing_service_port() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "port": 9090
                    }]
                }]
            }),
        );
        let service = object(
            "Service",
            "api",
            json!({
                "ports": [{"name": "http", "port": 8080}]
            }),
        );

        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let updates = plan_status_updates(&[gateway_class, gateway, route, service], options());

        let route_update = update_for(&updates, "HTTPRoute", "api");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("BackendNotFound")
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
    fn tcp_route_status_reports_programmed_after_l4_materialization() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tcp",
                    "port": 5432,
                    "protocol": "TCP",
                    "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
                }]
            }),
        );
        let route = object(
            "TCPRoute",
            "db",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "db", "port": 5432}]
                }]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "TCPRoute", "db");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
    }

    #[test]
    fn tcp_route_status_programmed_when_l4_listener_port_differs_from_backend_port() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "web",
                        "port": 5432,
                        "protocol": "HTTP"
                    },
                    {
                        "name": "tcp",
                        "port": 15432,
                        "protocol": "TCP",
                        "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
                    }
                ]
            }),
        );
        let route = object(
            "TCPRoute",
            "db",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "db", "port": 5432}]
                }]
            }),
        );

        let updates = plan_status_updates(&[gateway_class, gateway, route], options());

        let route_update = update_for(&updates, "TCPRoute", "db");
        let parents = route_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
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
    fn gateway_listener_attached_routes_counts_conflicted_attached_routes() {
        let gateway_class = ferrum_gateway_class();
        let gateway = ferrum_gateway("edge");
        let older = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        let newer = route_with_created_at("api-b", "2026-01-02T00:00:00Z");

        let updates = plan_status_updates(&[gateway_class, gateway, newer, older], options());

        let gateway_update = update_for(&updates, "Gateway", "edge");
        let listener = listener_status_by_name(
            gateway_update.status["listeners"].as_array().unwrap(),
            "http",
        );
        assert_eq!(listener["attachedRoutes"].as_u64(), Some(2));
    }

    #[test]
    fn hostless_route_conflict_status_uses_listener_intersected_hostname() {
        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "api.example.com"
                }]
            }),
        );
        let mut older = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        older.spec.as_object_mut().unwrap().remove("hostnames");
        let mut newer = route_with_created_at("api-b", "2026-01-02T00:00:00Z");
        newer.spec.as_object_mut().unwrap().remove("hostnames");

        let updates = plan_status_updates(&[gateway_class, gateway, newer, older], options());
        let newer_update = update_for(&updates, "HTTPRoute", "api-b");
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
    fn status_apply_patch_for_gateway_contains_only_ferrum_owned_fields() {
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
            patch_gateway_addresses: false,
            patch_gateway_listeners: false,
        };
        let live_status = json!({
            "addresses": [{"type": "IPAddress", "value": "10.0.0.10"}],
            "conditions": [
                {
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 7,
                    "reason": "Accepted",
                    "message": "Ferrum accepted this Gateway",
                    "lastTransitionTime": "2026-03-01T00:00:00Z"
                },
                {
                    "type": "example.com/CustomReady",
                    "status": "True",
                    "observedGeneration": 8,
                    "reason": "CustomReady",
                    "message": "fresh custom status",
                    "lastTransitionTime": "2026-03-01T00:00:00Z"
                }
            ]
        });

        let patch = gateway_status_apply_patch_for_update(&update, Some(&live_status));

        assert_eq!(
            patch["apiVersion"].as_str(),
            Some("gateway.networking.k8s.io/v1")
        );
        assert_eq!(patch["kind"].as_str(), Some("Gateway"));
        assert_eq!(patch["metadata"]["name"].as_str(), Some("edge"));
        assert_eq!(patch["metadata"]["namespace"].as_str(), Some("default"));
        assert!(patch["status"].get("addresses").is_none());
        let conditions = patch["status"]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_eq!(conditions.len(), 1);
        assert_eq!(
            conditions[0]["lastTransitionTime"].as_str(),
            Some("2026-03-01T00:00:00Z")
        );
        assert!(conditions.iter().all(|condition| {
            condition.get("type").and_then(Value::as_str) != Some("example.com/CustomReady")
        }));
    }

    #[test]
    fn route_status_merge_patch_uses_live_parents_and_resource_version() {
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
            patch_gateway_addresses: false,
            patch_gateway_listeners: false,
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

        let patch = route_status_merge_patch_for_update(&update, Some(&live_status), "42");

        let parents = patch["status"]["parents"].as_array().unwrap();
        assert_eq!(patch["metadata"]["resourceVersion"].as_str(), Some("42"));
        assert_eq!(parents.len(), 2);
        assert!(!parents.iter().any(|parent| {
            parent["controllerName"].as_str() == Some("example.com/stale-controller")
        }));
        assert!(parents.iter().any(|parent| {
            parent["controllerName"].as_str() == Some("example.com/fresh-controller")
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

    #[test]
    fn status_apply_uses_stable_forced_field_manager() {
        let params = gateway_api_status_apply_params();

        assert_eq!(
            params.field_manager.as_deref(),
            Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        );
        assert!(params.force);
    }

    #[test]
    fn gateway_class_apply_identity_is_cluster_scoped() {
        let update = GatewayApiStatusUpdate {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "GatewayClass".to_string(),
            namespace: String::new(),
            name: "ferrum".to_string(),
            status: json!({"conditions": []}),
            patch_gateway_addresses: false,
            patch_gateway_listeners: false,
        };

        let patch = gateway_status_apply_patch_for_update(&update, None);

        assert_eq!(patch["metadata"]["name"].as_str(), Some("ferrum"));
        assert!(patch["metadata"].get("namespace").is_none());
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

    fn listener_status_by_name<'a>(listeners: &'a [Value], name: &str) -> &'a Value {
        listeners
            .iter()
            .find(|listener| listener["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing listener status {name}"))
    }

    fn tls_secret(name: &str, namespace: &str, valid: bool) -> K8sObject {
        use base64::Engine as _;

        let (cert, key) = if valid {
            (
                include_str!("../../tests/certs/server.crt"),
                include_str!("../../tests/certs/server.key"),
            )
        } else {
            ("Hello world", "Hello world")
        };
        let mut secret = object(
            "Secret",
            name,
            json!({
                "type": "kubernetes.io/tls",
                "data": {
                    "tls.crt": base64::engine::general_purpose::STANDARD.encode(cert),
                    "tls.key": base64::engine::general_purpose::STANDARD.encode(key),
                }
            }),
        );
        secret.api_version = "v1".to_string();
        secret.metadata.namespace = namespace.to_string();
        secret
    }

    fn tls_secret_with_mismatched_key(name: &str, namespace: &str) -> K8sObject {
        use base64::Engine as _;

        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let mut secret = tls_secret(name, namespace, true);
        secret.spec["data"]["tls.key"] =
            json!(base64::engine::general_purpose::STANDARD.encode(key_pair.serialize_pem()));
        secret
    }

    fn reference_grant_for_gateway_secret(
        from_namespace: &str,
        to_namespace: &str,
        secret_name: &str,
    ) -> K8sObject {
        let mut grant = object(
            "ReferenceGrant",
            "allow-gateway-secret",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": from_namespace
                }],
                "to": [{
                    "group": "",
                    "kind": "Secret",
                    "name": secret_name
                }]
            }),
        );
        grant.metadata.namespace = to_namespace.to_string();
        grant
    }
}
