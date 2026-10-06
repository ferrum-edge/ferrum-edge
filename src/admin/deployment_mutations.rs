//! Dependency-fenced partial deployment operations. No compensation or fresh-token retry.

use super::audit::{self, AuditActor};
use super::crud::{self, NamespaceConfigAdmissionGuard};
use super::preconditions;
use super::{AdminState, json_response};
use crate::config::db_backend::{
    ApiSpecSnapshotView, ConditionalNamespaceSnapshot, DatabaseBackend, DbWriteTopologyPermit,
    NamespacePreconditionFailed, NamespaceSnapshotTooLarge, SnapshotDigest,
    is_namespace_snapshot_too_large,
};
use crate::config::deployment_mutation::{
    DeploymentGraphInvalid, DeploymentPrecondition, ExternalSpecUpstreamConflict,
    is_deployment_commit_outcome_unknown,
};
use crate::config::types::ApiSpec;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode};
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

const PREFIX: &str = "deployment-v1-";

/// MAC domain for deployment tokens. The `deployment-v1-` wire prefix is kept
/// so tokens issued before stored content was digested still parse and then
/// fail closed with `412` instead of being reinterpreted.
const DEPLOYMENT_SNAPSHOT_TAG_KIND: &str = "deployment_snapshot.v2";

/// Upper bound, in base64 bytes, on `api_spec_contents` in
/// `GET /deployment-snapshot`: one base64 copy of every stored gzip spec
/// document and external-reference snapshot, carried outside the digested
/// evidence. A namespace past it returns `507` without disclosing evidence.
///
/// Peak memory for the member is about twice this bound: its base64 strings
/// and the serialized response body coexist until the body is built, on top
/// of the stored bytes (about three quarters of the bound) already loaded.
pub(crate) const MAX_DEPLOYMENT_SNAPSHOT_CONTENT_BASE64_BYTES: usize = 256 * 1024 * 1024;

const SNAPSHOT_CONTENT_TOO_LARGE: &str =
    "Deployment snapshot stored API-spec content exceeds the 256 MiB response limit";

pub(super) fn requested(query: Option<&str>, headers: &HeaderMap) -> bool {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .any(|(key, _)| key == "conditional")
        || headers
            .get_all(hyper::header::IF_MATCH)
            .iter()
            .any(|v| v.to_str().is_ok_and(|v| v.contains(PREFIX)))
}

/// Exactly one discriminator and one quoted strong deployment token. Lists,
/// wildcards, weak tags, duplicate fields and missing modes all fail closed.
pub(super) fn parse_request(
    query: Option<&str>,
    headers: &HeaderMap,
    removal: bool,
) -> Result<Option<String>, &'static str> {
    if !requested(query, headers) {
        if headers.contains_key(hyper::header::IF_MATCH) && !removal {
            return Err("API-spec If-Match requires conditional=true and deployment authority");
        }
        return Ok(None);
    }
    let mut conditional = 0;
    let mut cleanup = 0;
    let mut apply = 0;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "conditional" if value == "true" => conditional += 1,
            "cleanup_orphaned_upstream" if removal && value == "false" => cleanup += 1,
            "apply" if value == "sync" => apply += 1,
            _ => return Err("Unsupported deployment mutation query parameter or value"),
        }
    }
    if conditional != 1 || (removal && cleanup != 1) || cleanup > 1 || apply > 1 {
        return Err(
            "Deployment mutation requires one conditional=true; removal also requires \
             cleanup_orphaned_upstream=false",
        );
    }
    let mut values = headers.get_all(hyper::header::IF_MATCH).iter();
    let value = values
        .next()
        .ok_or("Deployment mutation requires original If-Match")?;
    if values.next().is_some() {
        return Err("Deployment mutation requires exactly one If-Match field");
    }
    let text = value.to_str().map_err(|_| "Invalid deployment If-Match")?;
    let token = text
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or("Deployment If-Match must be one quoted strong token")?;
    let digest = token
        .strip_prefix(PREFIX)
        .ok_or("Original deployment snapshot token required")?;
    if digest.len() != 32
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid deployment snapshot token");
    }
    Ok(Some(token.to_string()))
}

fn tag(state: &AdminState, namespace: &str, digest: &SnapshotDigest) -> Option<String> {
    let key = state.jwt_manager.resource_etag_key()?;
    let tag = preconditions::snapshot_etag(&key, DEPLOYMENT_SNAPSHOT_TAG_KIND, namespace, digest);
    Some(format!("{PREFIX}{tag}"))
}

pub(super) fn refusal(message: &'static str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({
            "error": message, "durable": "not_started", "live": "unconfirmed",
            "recovery_cleanup_authorized": false,
        }),
    )
}

pub(super) fn unavailable(durable: &str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({
            "error": "Deployment mutation acknowledgement unavailable",
            "durable": durable, "live": "unconfirmed", "recovery_cleanup_authorized": false,
        }),
    )
}

/// `507`: the namespace is too large to fence or return. `durable` is
/// `not_started` before any mutation transaction opens and `not_committed`
/// once one was opened and rolled back.
fn snapshot_too_large(error: &str, durable: &str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::INSUFFICIENT_STORAGE,
        &json!({
            "error": error, "durable": durable, "live": "unconfirmed",
            "recovery_cleanup_authorized": false,
        }),
    )
}

/// Map a failed mutation. Only a commit whose outcome the store could not
/// confirm (`DeploymentCommitOutcomeUnknown`) reports `durable: unknown`.
/// Every other error was raised before commit was attempted: either before the
/// mutation transaction opened (a read or mTLS admission refusal ahead of it)
/// or inside it (lease loss, a statement or admission failure), where it
/// rolled back. Those report `not_committed`.
pub(super) fn store_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
    if is_namespace_snapshot_too_large(error) {
        return snapshot_too_large(&NamespaceSnapshotTooLarge.to_string(), "not_committed");
    }
    if is_deployment_commit_outcome_unknown(error) {
        // The store may have committed despite a transport or acknowledgement error.
        return unavailable("unknown");
    }
    let status = if error.chain().any(|e| e.is::<NamespacePreconditionFailed>()) {
        StatusCode::PRECONDITION_FAILED
    } else if error
        .chain()
        .any(|e| e.is::<DeploymentGraphInvalid>() || e.is::<ExternalSpecUpstreamConflict>())
    {
        StatusCode::CONFLICT
    } else if crate::config::db_backend::atomic_batch_unsupported(error).is_some() {
        StatusCode::NOT_IMPLEMENTED
    } else {
        // Never expose driver messages, credentials, or tokens.
        return unavailable("not_committed");
    };
    json_response(
        status,
        &json!({
            "error": if status == StatusCode::PRECONDITION_FAILED {
                "Deployment snapshot is stale"
            } else { "Deployment authority or dependency graph is unsupported" },
            "durable": "not_committed", "live": "unconfirmed",
            "recovery_cleanup_authorized": false,
        }),
    )
}

fn read_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
    if is_namespace_snapshot_too_large(error) {
        snapshot_too_large(&NamespaceSnapshotTooLarge.to_string(), "not_started")
    } else if crate::config::db_backend::atomic_batch_unsupported(error).is_some() {
        store_error(error)
    } else {
        unavailable("not_started")
    }
}

#[allow(clippy::result_large_err)]
pub(super) async fn expected(
    state: &AdminState,
    db: &dyn DatabaseBackend,
    namespace: &str,
    original: &str,
) -> Result<SnapshotDigest, Response<Full<Bytes>>> {
    let digest = db
        .load_deployment_snapshot(namespace)
        .await
        .and_then(|snapshot| snapshot.digest())
        .map_err(|e| read_error(&e))?;
    let current = tag(state, namespace, &digest).ok_or_else(|| unavailable("not_started"))?;
    if current != original {
        return Err(store_error(&NamespacePreconditionFailed.into()));
    }
    Ok(digest)
}

pub(super) async fn snapshot(
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    request_ctx: &audit::AuditRequestContext,
) -> Response<Full<Bytes>> {
    let Some(db) = state.db.as_ref() else {
        return unavailable("not_started");
    };
    let snapshot = match db.load_deployment_snapshot(namespace).await {
        Ok(snapshot) => snapshot,
        Err(error) => return read_error(&error),
    };
    // Bound the snapshot before materializing any evidence for the response.
    let digest = match snapshot.digest() {
        Ok(digest) => digest,
        Err(error) => return read_error(&error),
    };
    let Some(tag) = tag(state, namespace, &digest) else {
        return unavailable("not_started");
    };
    // Bound the one base64 copy of stored spec content before encoding any.
    let mut content_len = 0usize;
    for spec in &snapshot.snapshot.api_specs {
        let external = spec.external_ref_snapshot.as_ref().map_or(0, Vec::len);
        content_len = content_len
            .saturating_add(base64_len(spec.spec_content.len()))
            .saturating_add(base64_len(external));
    }
    if content_len > MAX_DEPLOYMENT_SNAPSHOT_CONTENT_BASE64_BYTES {
        return snapshot_too_large(SNAPSHOT_CONTENT_TOO_LARGE, "not_started");
    }
    // Moves the raw evidence into the response instead of deep-cloning it.
    let (representation, snapshot) = match snapshot.into_representation() {
        Ok(parts) => parts,
        Err(_) => return unavailable("not_started"),
    };
    // Sorted by id in byte order, exactly as `evidence.resources[5]`, whatever
    // order or collation the store returned them in.
    let mut specs: Vec<&ApiSpec> = snapshot.api_specs.iter().collect();
    specs.sort_by(|a, b| a.id.cmp(&b.id));
    let Ok([proxies, plugin_configs, upstreams, api_specs]) = typed_lists(&snapshot, &specs) else {
        return unavailable("not_started");
    };
    let event = audit::AuditEvent::new(
        actor,
        "deployment_snapshot",
        "gateway_config",
        namespace,
        namespace,
        json!({"profile": "deployment-v1", "credential_complete": true}),
    )
    .with_request_context(request_ctx)
    .with_outcome(audit::outcome::SUCCESS);
    if audit::admit_security_sensitive_event(
        state.db.as_ref(),
        &event,
        state.admin_audit_fallback_dir.as_deref(),
    )
    .await
    .is_err()
    {
        return unavailable("not_started");
    }
    let api_spec_contents = specs.into_iter().map(api_spec_content).collect();
    let mut body = serde_json::Map::with_capacity(9);
    body.insert("profile".to_string(), Value::from("deployment-v1"));
    body.insert("namespace".to_string(), Value::from(namespace));
    body.insert(
        "namespace_etag".to_string(),
        Value::from(preconditions::quoted(&tag)),
    );
    body.insert("evidence".to_string(), representation);
    body.insert("proxies".to_string(), proxies);
    body.insert("plugin_configs".to_string(), plugin_configs);
    body.insert("upstreams".to_string(), upstreams);
    body.insert("api_specs".to_string(), api_specs);
    body.insert(
        "api_spec_contents".to_string(),
        Value::Array(api_spec_contents),
    );
    let mut response = json_response(StatusCode::OK, &Value::Object(body));
    let Ok(value) = hyper::header::HeaderValue::from_str(&preconditions::quoted(&tag)) else {
        return unavailable("not_started");
    };
    response.headers_mut().insert(hyper::header::ETAG, value);
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

/// The response's typed inspection lists. `api_specs` repeats the evidence
/// view, stored documents as digests; `api_spec_contents` carries their bytes
/// once, outside the evidence.
fn typed_lists(
    snapshot: &ConditionalNamespaceSnapshot,
    specs: &[&ApiSpec],
) -> Result<[Value; 4], serde_json::Error> {
    let api_specs = specs
        .iter()
        .map(|spec| serde_json::to_value(ApiSpecSnapshotView::from(*spec)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok([
        serde_json::to_value(&snapshot.config.proxies)?,
        serde_json::to_value(&snapshot.config.plugin_configs)?,
        serde_json::to_value(&snapshot.config.upstreams)?,
        Value::Array(api_specs),
    ])
}

/// Encoded length of `bytes` bytes in padded base64.
fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3).saturating_mul(4)
}

/// One base64 copy of a spec's stored gzip document and external-reference
/// snapshot, outside the digested evidence. They decode to the bytes whose
/// SHA-256 and length the evidence fences.
fn api_spec_content(spec: &ApiSpec) -> Value {
    use base64::Engine as _;
    let engine = &base64::engine::general_purpose::STANDARD;
    let external = match &spec.external_ref_snapshot {
        Some(bytes) => Value::String(engine.encode(bytes)),
        None => Value::Null,
    };
    let mut content = serde_json::Map::with_capacity(3);
    content.insert("id".to_string(), Value::String(spec.id.clone()));
    content.insert(
        "spec_content_base64".to_string(),
        Value::String(engine.encode(&spec.spec_content)),
    );
    content.insert("external_ref_snapshot_base64".to_string(), external);
    Value::Object(content)
}

pub(super) async fn admit_mutation_audit(
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    id: &str,
    action: &str,
) -> bool {
    let event = audit::AuditEvent::new(
        actor,
        action,
        "deployment",
        id,
        namespace,
        json!({"profile": "deployment-v1", "phase": "admitted", "outcome": "unknown"}),
    )
    .with_current_request_context();
    audit::admit_security_sensitive_event(
        state.db.as_ref(),
        &event,
        state.admin_audit_fallback_dir.as_deref(),
    )
    .await
    .is_ok()
}

// Construct this large future behind a heap boundary, including at opt-level=0.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn finish_boxed(
    state: AdminState,
    actor: AuditActor,
    db: Arc<dyn DatabaseBackend>,
    namespace: String,
    id: String,
    guard: NamespaceConfigAdmissionGuard,
    permit: DbWriteTopologyPermit,
    expected: SnapshotDigest,
    replacement: Option<(
        super::api_specs::ExtractedBundle,
        crate::config::types::ApiSpec,
    )>,
) -> Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send>> {
    Box::pin(finish(
        state,
        actor,
        db,
        namespace,
        id,
        guard,
        permit,
        expected,
        replacement,
    ))
}

/// Own persistence, pins, audit and completion independently of HTTP cancellation.
/// No late compensation and no replay under a newly acquired lease.
#[allow(clippy::too_many_arguments)]
async fn finish(
    state: AdminState,
    actor: AuditActor,
    db: Arc<dyn DatabaseBackend>,
    namespace: String,
    id: String,
    mut guard: NamespaceConfigAdmissionGuard,
    permit: DbWriteTopologyPermit,
    expected: SnapshotDigest,
    replacement: Option<(
        super::api_specs::ExtractedBundle,
        crate::config::types::ApiSpec,
    )>,
) -> Response<Full<Bytes>> {
    if guard.hand_off_to_restore_transaction().await.is_err() {
        return unavailable("not_started");
    }
    let validation_http_client = super::plugin_validation_http_client(&state);
    let precondition = DeploymentPrecondition {
        namespace: &namespace,
        expected,
        lease: guard.lease_ref(),
        validation_http_client: &validation_http_client,
    };
    let result = match &replacement {
        Some((bundle, spec)) => {
            db.replace_deployment_conditionally(bundle, spec, &precondition)
                .await
        }
        None => db.remove_deployment_conditionally(&id, &precondition).await,
    };
    if let Err(error) = result {
        return store_error(&error);
    }
    let commit_event = audit::AuditEvent::new(
        &actor,
        if replacement.is_some() {
            "deployment_replace"
        } else {
            "deployment_remove"
        },
        "deployment",
        &id,
        &namespace,
        json!({"profile": "deployment-v1", "durable": "committed", "live": "unconfirmed"}),
    )
    .with_current_request_context()
    .with_outcome(audit::outcome::SUCCESS);
    let audit_commit = audit::record(state.admin_audit_enabled, db, commit_event).await;
    let prepared = state
        .prepare_live_apply_after_commit(&namespace, permit.topology_epoch())
        .await;
    // Owner-qualified release is part of the acknowledgement. Failure leaves
    // a committed operation without replay or journal-cleanup authorization.
    if guard.release_after_deployment().await.is_err() {
        return unavailable("committed");
    }
    drop(permit);
    if audit_commit.is_err() {
        return unavailable("committed");
    }
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(_) => return unavailable("committed"),
    };
    let applicable = prepared.covering_cursor().is_some();
    if state.await_prepared_live_apply(&prepared).await.is_err() {
        return unavailable("committed");
    }
    let live = if applicable {
        "applied"
    } else {
        "not_applicable"
    };
    let body = json!({
        "profile": "deployment-v1", "id": id, "durable": "committed",
        "live": live, "recovery_cleanup_authorized": applicable,
    });
    let event = audit::AuditEvent::new(
        &actor,
        if replacement.is_some() {
            "deployment_replace"
        } else {
            "deployment_remove"
        },
        "deployment",
        &id,
        &namespace,
        json!({"durable": "committed", "live": live}),
    )
    .with_current_request_context()
    .with_outcome(audit::outcome::SUCCESS);
    if audit::admit_security_sensitive_event(
        state.db.as_ref(),
        &event,
        state.admin_audit_fallback_dir.as_deref(),
    )
    .await
    .is_err()
    {
        return unavailable("committed");
    }
    let response = json_response(StatusCode::OK, &body);
    match prepared.covering_cursor() {
        Some(cursor) => super::attach_config_cursor_header(response, cursor),
        None => response,
    }
}

pub(super) async fn remove(
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    id: &str,
    original: String,
) -> Response<Full<Bytes>> {
    let permit = match state.admit_write().await {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let Some(db) = state.db.as_ref().cloned() else {
        return unavailable("not_started");
    };
    let guard = match crud::lock_namespace_config_admission(db.clone(), namespace).await {
        Ok(guard) => guard,
        Err(_) => return unavailable("not_started"),
    };
    let expected = match expected(state, db.as_ref(), namespace, &original).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !admit_mutation_audit(state, actor, namespace, id, "deployment_remove").await {
        return unavailable("not_started");
    }
    match audit::spawn_with_request_slot(finish_boxed(
        state.clone(),
        actor.clone(),
        db,
        namespace.to_string(),
        id.to_string(),
        guard,
        permit,
        expected,
        None,
    ))
    .await
    {
        Ok(response) => response,
        Err(_) => unavailable("unknown"),
    }
}
