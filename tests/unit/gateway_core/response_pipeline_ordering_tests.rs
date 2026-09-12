//! Ordering contract of the authoritative final client-visible response phases
//! (`GHSA-62jg-v563-4q23`, `GHSA-4vqr-427g-5cg7`).
//!
//! Every test here drives a PRODUCTION shared funnel — the buffered transform
//! phase (`transform_buffered_response_body_with_deadline`), the ordinary
//! `after_proxy` chain (`run_after_proxy_hooks`), or the synthetic /
//! short-circuit finalizer (`apply_reject_after_proxy_and_synthetic_body_hooks`)
//! — rather than calling a plugin hook directly. Calling the hook directly
//! proves only that the plugin can decide; these prove that the pipeline gives
//! it the last word.
//!
//! Plugin slices are supplied in configured priority order, exactly as the
//! plugin cache builds them, so "later" below means literally later in the
//! chain: `body_validator` 2950 and `waf` 2930 before `response_transformer`
//! 4000 and `compression` 4050.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrum_edge::_test_support::{
    finalize_synthetic_response_for_test, gateway_capacity_response_selected_for_test,
    mark_buffered_response_capacity_refusal_pending_for_test, mark_native_grpc_request_for_test,
    retain_grpc_web_client_content_type_for_test, run_after_proxy_hooks_reject_for_test,
    set_original_response_content_encoding_for_test, stamp_original_response_metadata_for_test,
    take_buffered_response_capacity_refusal_pending_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, RequestContext, ResponseBodyProduction,
    ai_response_guard::AiResponseGuard, body_validator::BodyValidator,
    compression::CompressionPlugin, response_transformer::ResponseTransformer,
    spec_expose::SpecExpose, waf::Waf,
};
use serde_json::json;

/// The token an operator's WAF response-body rule blocks.
const BLOCKED_TOKEN: &str = "leak-secret";

/// The protected header name an operator's WAF response-header rule blocks.
const PROTECTED_HEADER: &str = "x-public-secret";

/// Final-body policy test double that reports the same one-shot bounded-scratch
/// refusal used by production response inspectors. It deliberately has no body
/// transform or transport encoder after it, covering the escape window where a
/// pending signal previously reached publication unconsumed.
struct FinalPolicyCapacityRefusal;

/// Final-body policy that deterministically rejects, used to assert that the
/// shared funnel installs protocol-correct terminals rather than bare JSON.
struct RejectingFinalBodyPolicy;

/// Header policy whose own first rejection recreates the refused field. The
/// second decision must collapse to the fixed terminal rather than publishing
/// that plugin-controlled rejection shape.
struct SelfRefusingFinalHeaderPolicy;

/// Successful-response-only decorator. It cannot be reconstructed by the
/// rejection hook chain, so survival proves line-aware provenance is retained.
struct OneShotGatewayDecorator;

/// Later ordinary `after_proxy` rejection whose gateway-owned replacement
/// exposes a rename source to the still-later response transformer.
struct LateHeaderBearingReject;

/// Late reject-path replacement that changes only the HTTP status. Its body is
/// byte-identical to the representation accepted before the chain ran.
struct LateIdenticalBodyStatusReject;

/// Final-body policy that applies only after the late chain changes the status.
struct StatusScopedFinalBodyPolicy {
    calls: Arc<AtomicUsize>,
}

const STATUS_SCOPED_BODY: &str = r#"{"same":"bytes"}"#;

#[async_trait::async_trait]
impl Plugin for FinalPolicyCapacityRefusal {
    fn name(&self) -> &str {
        "final_policy_capacity_refusal"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> ferrum_edge::plugins::PluginResult {
        mark_buffered_response_capacity_refusal_pending_for_test(ctx);
        ferrum_edge::plugins::PluginResult::Continue
    }
}

#[async_trait::async_trait]
impl Plugin for RejectingFinalBodyPolicy {
    fn name(&self) -> &str {
        "rejecting_final_body_policy"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> ferrum_edge::plugins::PluginResult {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"blocked"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for SelfRefusingFinalHeaderPolicy {
    fn name(&self) -> &str {
        "self_refusing_final_header_policy"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn enforces_final_client_visible_response_headers(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_headers(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> ferrum_edge::plugins::PluginResult {
        if !header_names_contain(response_headers, "x-refused") {
            return ferrum_edge::plugins::PluginResult::Continue;
        }
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 418,
            body: "plugin-controlled rejection".to_string(),
            headers: HashMap::from([("x-refused".to_string(), "again".to_string())]),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for OneShotGatewayDecorator {
    fn name(&self) -> &str {
        "one_shot_gateway_decorator"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> ferrum_edge::plugins::PluginResult {
        response_headers.insert("x-request-id".to_string(), "gateway-request-id".to_string());
        ferrum_edge::plugins::PluginResult::Continue
    }

    fn owns_deadline_response_header(&self, _ctx: &RequestContext, name: &str) -> bool {
        name.eq_ignore_ascii_case("x-request-id")
    }
}

/// Counts how many times the authoritative final BODY phase asked it about a
/// response, and refuses only JSON. Used to prove both halves of the synthetic
/// re-decision contract: a late relabel into its scope must reach it, and a late
/// change outside its scope must not cost a second sweep.
struct ScopedCountingFinalBodyPolicy {
    calls: Arc<AtomicUsize>,
    seen_content_types: Arc<std::sync::Mutex<Vec<String>>>,
}

/// Refuses JSON with a rejection that carries its OWN representation field, so
/// the rebuilt rejection no longer has the shape the decision was made under.
struct RepresentationBearingRejectFinalBodyPolicy;

/// Reject-path `after_proxy` decorator carrying state it can emit only once —
/// the shape of the `oidc_relying_party` rotated session cookie. It consumes the
/// staged metadata, so a second chain run would silently drop the cookie.
struct OneShotRotatedSessionCookie {
    runs: Arc<AtomicUsize>,
}

/// Metadata key `OneShotRotatedSessionCookie` stages its cookie under.
const ROTATED_COOKIE_METADATA_KEY: &str = "test.rotated_session_cookie";

/// The rotated cookie value that must reach the client exactly once.
const ROTATED_COOKIE_VALUE: &str = "sid=rotated; HttpOnly";

#[async_trait::async_trait]
impl Plugin for ScopedCountingFinalBodyPolicy {
    fn name(&self) -> &str {
        "scoped_counting_final_body_policy"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> ferrum_edge::plugins::PluginResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let content_type = response_headers
            .get("content-type")
            .cloned()
            .unwrap_or_default();
        self.seen_content_types
            .lock()
            .expect("content-type log")
            .push(content_type.clone());
        if !content_type.starts_with("application/json") {
            return ferrum_edge::plugins::PluginResult::Continue;
        }
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 502,
            body: r#"{"error":"json representation refused"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for RepresentationBearingRejectFinalBodyPolicy {
    fn name(&self) -> &str {
        "representation_bearing_reject_final_body_policy"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> ferrum_edge::plugins::PluginResult {
        let is_json = response_headers
            .get("content-type")
            .is_some_and(|value| value.starts_with("application/json"));
        if !is_json {
            return ferrum_edge::plugins::PluginResult::Continue;
        }
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 502,
            body: r#"{"error":"json representation refused"}"#.to_string(),
            headers: HashMap::from([("content-disposition".to_string(), "attachment".to_string())]),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for OneShotRotatedSessionCookie {
    fn name(&self) -> &str {
        "one_shot_rotated_session_cookie"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> ferrum_edge::plugins::PluginResult {
        self.runs.fetch_add(1, Ordering::SeqCst);
        if let Some(cookie) = ctx.metadata.remove(ROTATED_COOKIE_METADATA_KEY) {
            response_headers.insert("set-cookie".to_string(), cookie);
        }
        ferrum_edge::plugins::PluginResult::Continue
    }
}

#[async_trait::async_trait]
impl Plugin for LateHeaderBearingReject {
    fn name(&self) -> &str {
        "late_header_bearing_reject"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn priority(&self) -> u16 {
        3500
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> ferrum_edge::plugins::PluginResult {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 502,
            body: r#"{"error":"upstream rejected"}"#.to_string(),
            headers: HashMap::from([("x-pending-secret".to_string(), "value".to_string())]),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for LateIdenticalBodyStatusReject {
    fn name(&self) -> &str {
        "late_identical_body_status_reject"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn may_replace_rejection_response(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> ferrum_edge::plugins::PluginResult {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 418,
            body: STATUS_SCOPED_BODY.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for StatusScopedFinalBodyPolicy {
    fn name(&self) -> &str {
        "status_scoped_final_body_policy"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn enforces_final_client_visible_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn may_enforce_response_body_policy(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_body(
        &self,
        _ctx: &mut RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> ferrum_edge::plugins::PluginResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if response_status != 418 {
            return ferrum_edge::plugins::PluginResult::Continue;
        }
        ferrum_edge::plugins::PluginResult::Reject {
            status_code: 502,
            body: r#"{"error":"status-scoped representation refused"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

fn ctx_for(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "203.0.113.7".to_string(),
        method.to_string(),
        path.to_string(),
    );
    // These fixtures carry only small synthetic bodies. Keep each transform
    // window to one budget block so parallel coverage tests do not contend for
    // the process-wide retained-response budget and mask the policy outcome.
    ctx.max_response_body_size_bytes = 64 * 1024;
    ctx
}

/// Run the real `before_proxy` and `after_proxy` hooks of a chain, exactly as
/// the proxy does before the buffered body phase. `compression` decides its
/// response encoding across those two hooks, so a transport-encoding test that
/// skipped them would never reach the encoder at all.
async fn run_request_and_response_header_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
) {
    let mut request_headers = HashMap::new();
    for plugin in plugins {
        let _ = plugin.before_proxy(ctx, &mut request_headers).await;
    }
    // The pristine snapshot is taken from the BACKEND map, before any response
    // hook can add a gateway content coding to it.
    stamp_original_response_metadata_for_test(ctx, 200, response_headers);
    for plugin in plugins {
        let _ = plugin.after_proxy(ctx, 200, response_headers).await;
    }
}

fn json_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .expect("gzip round-trip");
    out
}

/// A WAF whose only enforcing rule blocks `BLOCKED_TOKEN` in the response body.
fn waf_blocking_response_body() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "response_body_inspection": true,
            "custom_rules": [{
                "id": "CUSTOM-RESP-BODY-LEAK",
                "name": "blocked response payload",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "contains",
                "pattern": BLOCKED_TOKEN,
                "action": "enforce"
            }]
        }))
        .expect("waf response-body config"),
    )
}

/// A WAF whose only enforcing rule blocks the protected response header.
fn waf_blocking_protected_header(rule_id: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "custom_rules": [{
                "id": rule_id,
                "name": "protected response header",
                "category": "custom",
                "severity": "high",
                "target": "response_headers",
                "match_kind": "contains",
                "pattern": PROTECTED_HEADER,
                "action": "enforce"
            }]
        }))
        .expect("waf response-header config"),
    )
}

/// A WAF configured against a header nothing in these tests ever produces.
fn waf_blocking_unrelated_header(rule_id: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "custom_rules": [{
                "id": rule_id,
                "name": "unrelated response header",
                "category": "custom",
                "severity": "high",
                "target": "response_headers",
                "match_kind": "contains",
                "pattern": "x-never-emitted-header",
                "action": "enforce"
            }]
        }))
        .expect("waf unrelated response-header config"),
    )
}

/// A WAF rule over a header name authored only by the late transport stage.
fn waf_blocking_content_encoding_header() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "custom_rules": [{
                "id": "CUSTOM-LATE-CONTENT-ENCODING",
                "name": "late content encoding",
                "category": "custom",
                "severity": "high",
                "target": "response_headers",
                "match_kind": "contains",
                "pattern": "content-encoding",
                "action": "enforce"
            }]
        }))
        .expect("waf late content-encoding config"),
    )
}

/// A `body_validator` that requires `approved` on every JSON response.
fn body_validator_requiring_approved() -> Arc<dyn Plugin> {
    Arc::new(
        BodyValidator::new(&json!({
            "response_required_fields": ["approved"],
            "response_content_types": ["application/json"],
        }))
        .expect("body_validator response config"),
    )
}

/// A later `response_transformer` that renames the field the validator requires.
fn response_transformer_renaming_body_field() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "rename", "target": "body",
                 "key": "approved", "new_key": "was_approved"}
            ]
        }))
        .expect("response_transformer body rename config"),
    )
}

/// A later `response_transformer` that adds the blocked token into the body.
fn response_transformer_adding_blocked_body_field() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "body",
                 "key": "note", "value": format!("contains {BLOCKED_TOKEN} value")}
            ]
        }))
        .expect("response_transformer body add config"),
    )
}

/// A later `response_transformer` that renames a benign header into the
/// protected one — the exact advisory shape.
fn response_transformer_renaming_header() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "rename", "target": "header",
                 "key": "x-pending-secret", "new_key": PROTECTED_HEADER}
            ]
        }))
        .expect("response_transformer header rename config"),
    )
}

/// A later `response_transformer` that RELABELS the representation — the exact
/// synthetic-lifecycle advisory shape, since its header rules run in the
/// reject-path `after_proxy` chain the finalizer defers to last.
fn response_transformer_relabeling_content_type() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "update", "target": "header",
                 "key": "content-type", "value": "application/json"}
            ]
        }))
        .expect("response_transformer content-type relabel config"),
    )
}

/// A later `response_transformer` that adds a header no body policy scope reads.
fn response_transformer_adding_unrelated_header() -> Arc<dyn Plugin> {
    Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "header",
                 "key": "x-gateway-note", "value": "decorated"}
            ]
        }))
        .expect("response_transformer unrelated header config"),
    )
}

fn compression_plugin() -> Arc<dyn Plugin> {
    let plugin =
        CompressionPlugin::new(&json!({"min_content_length": 10})).expect("compression config");
    Arc::new(plugin)
}

/// Drive the production buffered transform funnel over a backend response.
///
/// The caller must already have stamped the pristine pre-`after_proxy` snapshot
/// (`stamp_original_response_metadata_for_test`): that snapshot IS the
/// production precondition the shared representation gate reads.
async fn run_buffered_transform(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> (bool, u16, HashMap<String, String>, Vec<u8>) {
    let mut status = status;
    let mut headers = headers;
    let mut body = bytes::Bytes::from(body);
    let (replaced, _rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        plugins,
        ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    (replaced, status, headers, body.to_vec())
}

fn header_names_contain(headers: &HashMap<String, String>, name: &str) -> bool {
    headers.keys().any(|key| key.eq_ignore_ascii_case(name))
}

/// A one-shot capacity refusal raised by the authoritative final body policy
/// must install the shared terminal immediately even when no transport encoder
/// follows. Otherwise the original protected bytes could be published while the
/// refusal marker merely lingered on the request context.
#[tokio::test]
async fn final_body_policy_capacity_refusal_cannot_escape_without_transport_stage() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(FinalPolicyCapacityRefusal)];
    let mut ctx = ctx_for("GET", "/synthetic-capacity");
    let mut status = 200u16;
    let mut headers = json_headers();
    let mut body = bytes::Bytes::from_static(br#"{"secret":"must-not-publish"}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 503);
    assert!(gateway_capacity_response_selected_for_test(&ctx));
    assert!(!take_buffered_response_capacity_refusal_pending_for_test(
        &mut ctx
    ));
    assert!(!String::from_utf8_lossy(&body).contains("must-not-publish"));
}

// ─────────────── 1. late body rewrites cannot bypass body policy ───────────────

/// A later `response_transformer` body `rename` must not be able to remove the
/// field `body_validator` requires: the validator decides after every semantic
/// transform, over the exact plaintext the client would receive.
#[tokio::test]
async fn late_body_rename_cannot_bypass_body_validator() {
    let plugins = vec![
        body_validator_requiring_approved(),
        response_transformer_renaming_body_field(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let headers = json_headers();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let body_in = br#"{"approved":true}"#.to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(
        replaced,
        "the renamed representation must not be published as-is"
    );
    assert_eq!(status, 502, "response validation failure is a 502");
    let published = String::from_utf8_lossy(&body);
    assert!(
        !published.contains("was_approved"),
        "the renamed document must not reach the client: {published}"
    );
}

/// The same funnel, from the WAF's side: a later `add` rule that injects the
/// blocked token into the body cannot land behind the response-body scan.
#[tokio::test]
async fn late_body_add_cannot_bypass_waf_response_body_rule() {
    let plugins = vec![
        waf_blocking_response_body(),
        response_transformer_adding_blocked_body_field(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let headers = json_headers();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let body_in = br#"{"ok":true}"#.to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(replaced, "the injected token must not be published");
    assert_eq!(status, 403, "waf default reject status");
    assert!(
        !String::from_utf8_lossy(&body).contains(BLOCKED_TOKEN),
        "the blocked token must not survive into the client-visible body"
    );
}

/// A final body-policy rejection on native gRPC must become a trailers-only
/// gRPC error. A bare HTTP 403 JSON body is not a valid RPC terminal.
#[tokio::test]
async fn final_body_policy_rejection_is_native_grpc_terminal() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RejectingFinalBodyPolicy)];
    let mut ctx = ctx_for("POST", "/grpc.Service/Method");
    mark_native_grpc_request_for_test(&mut ctx);
    let mut headers = HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let mut status = 200u16;
    let mut body = bytes::Bytes::from_static(b"backend data");

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 200);
    assert!(
        body.is_empty(),
        "native gRPC rejection must be trailers-only"
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("7"));
    assert!(!header_names_contain(&headers, "content-length"));
}

/// The same rejection for a translated gRPC-Web client must put terminal
/// metadata in a trailer frame, not in the initial HTTP header block.
#[tokio::test]
async fn final_body_policy_rejection_is_grpc_web_trailer_frame() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RejectingFinalBodyPolicy)];
    let mut ctx = ctx_for("POST", "/grpc.Service/Method");
    let client_content_type = "application/grpc-web+proto";
    retain_grpc_web_client_content_type_for_test(&mut ctx, client_content_type);
    let mut headers = HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let mut status = 200u16;
    let mut body = bytes::Bytes::from_static(b"backend data");

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        Some(client_content_type),
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some(client_content_type)
    );
    assert!(!header_names_contain(&headers, "grpc-status"));
    assert_eq!(body.first().copied(), Some(0x80));
    assert!(String::from_utf8_lossy(&body).contains("grpc-status: 7"));
}

/// Gateway decorations already authored by the accepted after_proxy chain must
/// survive a later body-policy rejection, while an untouched backend cookie is
/// shed even though it has the same trusted-looking name as a gateway cookie.
#[tokio::test]
async fn final_body_policy_rejection_preserves_only_gateway_header_provenance() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(RejectingFinalBodyPolicy),
        Arc::new(OneShotGatewayDecorator),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert(
        "set-cookie".to_string(),
        "backend-session=must-not-cross".to_string(),
    );
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    assert!(
        run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
            .await
            .is_none()
    );
    let mut status = 200u16;
    let mut body = bytes::Bytes::from_static(br#"{"ok":true}"#);

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 403);
    assert_eq!(
        headers.get("x-request-id").map(String::as_str),
        Some("gateway-request-id")
    );
    assert!(!header_names_contain(&headers, "set-cookie"));
}

/// The control: with no later rewrite, an untouched clean response still passes.
#[tokio::test]
async fn clean_response_is_published_unchanged() {
    let plugins = vec![
        waf_blocking_response_body(),
        body_validator_requiring_approved(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let headers = json_headers();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    let body_in = br#"{"approved":true}"#.to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"approved":true}"#.to_vec());
}

// ─────────── 2. late header rewrites cannot bypass WAF header policy ───────────

/// The advisory scenario. On a synthetic / short-circuit response the reject-path
/// `after_proxy` chain runs deliberately LAST, after the synthetic body hooks —
/// so a `response_transformer` header `rename` used to create the protected
/// header after the only enforcing pass. It must not survive.
#[tokio::test]
async fn late_header_rename_cannot_bypass_waf_on_synthetic_response() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-SYNTHETIC"),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = json_headers();
    headers.insert("x-pending-secret".to_string(), "value".to_string());
    // One-shot gateway session state staged onto the synthetic response.
    headers.insert(
        "set-cookie".to_string(),
        "sid=rotated; HttpOnly".to_string(),
    );
    let mut body = bytes::Bytes::from_static(br#"{"ok":true}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 403, "the protected header must be refused");
    assert!(
        !header_names_contain(&headers, PROTECTED_HEADER),
        "the refused header must not be resurrected by the rejection rebuild: {headers:?}"
    );
    assert!(
        !header_names_contain(&headers, "x-pending-secret"),
        "the synthetic representation header must not survive the rejection"
    );
    assert!(
        header_names_contain(&headers, "set-cookie"),
        "one-shot session state must survive the rejection rebuild: {headers:?}"
    );
}

/// The same late rename on the ORDINARY backend lifecycle, where the header
/// rules run inside the `after_proxy` chain. `run_after_proxy_hooks` is the one
/// funnel H1/H2, native gRPC, gRPC-Web, and both H3 paths share, and it covers
/// streaming responses too.
#[tokio::test]
async fn late_header_rename_cannot_bypass_waf_on_backend_response() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-BACKEND"),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert("x-pending-secret".to_string(), "value".to_string());
    headers.insert(
        "set-cookie".to_string(),
        "backend-session=must-not-cross-rejection".to_string(),
    );

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
        .await
        .expect("the late rename must be refused by the final header phase");

    assert_eq!(reject.0, 403);
    assert!(
        !header_names_contain(&reject.2, PROTECTED_HEADER),
        "the refused header must not survive onto the rejection: {:?}",
        reject.2
    );
    assert!(
        !header_names_contain(&reject.2, "set-cookie"),
        "an untouched backend cookie must not cross onto a gateway-authored rejection: {:?}",
        reject.2
    );
}

/// A later ordinary `after_proxy` hook can replace the backend response, after
/// which reject-path response transforms still run. The authoritative header
/// phase must close that replacement too; otherwise the early return from the
/// ordinary chain leaves this lifecycle behind the synthetic fix.
#[tokio::test]
async fn late_header_rename_cannot_bypass_waf_on_backend_rejection_replacement() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-BACKEND-REJECT"),
        Arc::new(LateHeaderBearingReject),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
        .await
        .expect("the transformed rejection header must be refused");

    assert_eq!(reject.0, 403);
    assert!(!header_names_contain(&reject.2, PROTECTED_HEADER));
    assert!(!header_names_contain(&reject.2, "x-pending-secret"));
}

/// Both shared funnels must reach the same conclusion for the same chain — the
/// ordering contract is a property of the pipeline, not of one lifecycle.
#[tokio::test]
async fn backend_and_synthetic_funnels_agree_on_late_header_rename() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-PARITY"),
        response_transformer_renaming_header(),
    ];

    let mut backend_ctx = ctx_for("GET", "/orders");
    let mut backend_headers = json_headers();
    backend_headers.insert("x-pending-secret".to_string(), "value".to_string());
    let backend = run_after_proxy_hooks_reject_for_test(
        &plugins,
        &mut backend_ctx,
        200,
        &mut backend_headers,
    )
    .await
    .expect("backend lifecycle must refuse");

    let mut synthetic_ctx = ctx_for("GET", "/cache-hit");
    let mut synthetic_status = 200u16;
    let mut synthetic_headers = json_headers();
    synthetic_headers.insert("x-pending-secret".to_string(), "value".to_string());
    let mut synthetic_body = bytes::Bytes::from_static(br#"{"ok":true}"#);
    finalize_synthetic_response_for_test(
        &plugins,
        &mut synthetic_ctx,
        &mut synthetic_status,
        &mut synthetic_headers,
        &mut synthetic_body,
    )
    .await;

    assert_eq!(backend.0, synthetic_status);
    assert!(!header_names_contain(&backend.2, PROTECTED_HEADER));
    assert!(!header_names_contain(&synthetic_headers, PROTECTED_HEADER));
}

/// A chain whose late rules touch nothing protected must be untouched: the phase
/// is gated on the header map actually having changed into a refused shape.
#[tokio::test]
async fn unrelated_late_header_rules_do_not_reject() {
    let plugins = vec![
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-BENIGN"),
        Arc::new(
            ResponseTransformer::new(&json!({
                "rules": [
                    {"operation": "add", "target": "header",
                     "key": "x-benign", "value": "1"}
                ]
            }))
            .expect("benign response_transformer config"),
        ) as Arc<dyn Plugin>,
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers).await;

    assert!(reject.is_none(), "a benign header add must not be refused");
    assert!(header_names_contain(&headers, "x-benign"));
}

/// The transport stage can author headers after the ordinary after_proxy map
/// closes. Buffered publication therefore needs a final header-policy decision
/// after compression, not only at the end of after_proxy.
#[tokio::test]
async fn transport_encoding_header_cannot_bypass_final_header_policy() {
    let plugins = vec![waf_blocking_content_encoding_header(), compression_plugin()];
    let mut ctx = ctx_for("GET", "/orders");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let payload = r#"{"note":"padding padding padding padding padding padding"}"#;
    let mut headers = json_headers();
    headers.insert("content-length".to_string(), payload.len().to_string());
    run_request_and_response_header_hooks(&plugins, &mut ctx, &mut headers).await;

    let (replaced, status, headers, body) = run_buffered_transform(
        &plugins,
        &mut ctx,
        200,
        headers,
        payload.as_bytes().to_vec(),
    )
    .await;

    assert!(replaced, "the late Content-Encoding header must be refused");
    assert_eq!(status, 403);
    assert!(!header_names_contain(&headers, "content-encoding"));
    assert!(!body.is_empty());
}

/// A rejection shape that the policy itself still refuses cannot be used as
/// the second terminal. The fixed body and empty plugin header set are the
/// bounded fail-closed outcome.
#[tokio::test]
async fn repeated_final_header_refusal_collapses_to_fixed_terminal() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(SelfRefusingFinalHeaderPolicy)];
    let mut ctx = ctx_for("GET", "/orders");
    let mut status = 200u16;
    let mut headers = json_headers();
    headers.insert("x-refused".to_string(), "first".to_string());
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let mut body = bytes::Bytes::from_static(br#"{"ok":true}"#);

    let (replaced, _) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(replaced);
    assert_eq!(status, 500);
    assert!(!header_names_contain(&headers, "x-refused"));
    assert_eq!(
        body.as_ref(),
        br#"{"error":"response policy could not be applied"}"#
    );
}

/// A WAF refusal must not memoize the rejected digest. The rejection rebuild
/// can reproduce the exact same map when a preserved decorator is the refused
/// field and the discarded response already has the rejection's representation
/// headers; the mandatory second decision must still scan and fail closed.
#[tokio::test]
async fn identical_rebuilt_waf_rejection_is_rescanned() {
    let waf: Arc<dyn Plugin> = Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "custom_rules": [{
                "id": "CUSTOM-REFUSED-PRESERVED-COOKIE",
                "name": "refused preserved cookie",
                "category": "custom",
                "severity": "high",
                "target": "response_headers",
                "match_kind": "contains",
                "pattern": "set-cookie",
                "action": "enforce"
            }]
        }))
        .expect("WAF preserved-cookie config"),
    );
    let late_cookie: Arc<dyn Plugin> = Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "set-cookie",
                "value": "sid=attacker; HttpOnly"
            }]
        }))
        .expect("late cookie response_transformer config"),
    );
    let plugins = vec![waf, late_cookie];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), "21".to_string()),
    ]);
    let mut body = bytes::Bytes::from_static(br#"{"original":"value"}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 500);
    assert!(!header_names_contain(&headers, "set-cookie"));
    assert_eq!(
        body.as_ref(),
        br#"{"error":"response policy could not be applied"}"#
    );
}

// ───────────────────── 3. transport encoding runs last ─────────────────────

/// Gateway compression is deferred behind every semantic transform AND behind
/// the final body policy phase: the WAF must match the plaintext, not gzip
/// octets (`GHSA-4vqr-427g-5cg7`).
#[tokio::test]
async fn gateway_compression_runs_after_final_body_policy() {
    let plugins = vec![waf_blocking_response_body(), compression_plugin()];
    let mut ctx = ctx_for("GET", "/orders");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());

    let payload = format!(r#"{{"note":"padding padding padding {BLOCKED_TOKEN} padding"}}"#);
    let mut headers = json_headers();
    headers.insert("content-length".to_string(), payload.len().to_string());
    run_request_and_response_header_hooks(&plugins, &mut ctx, &mut headers).await;
    let (replaced, status, headers_out, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, payload.into_bytes()).await;

    assert!(replaced, "the plaintext scan must have refused this body");
    assert_eq!(status, 403);
    assert!(
        !header_names_contain(&headers_out, "content-encoding"),
        "a refused response must not ship a gateway content coding: {headers_out:?}"
    );
    assert!(!String::from_utf8_lossy(&body).contains(BLOCKED_TOKEN));
}

/// The passing half of the same contract: validators see plaintext while the
/// published wire bytes are still correctly encoded.
#[tokio::test]
async fn gateway_compression_still_encodes_an_admitted_response() {
    let plugins = vec![waf_blocking_response_body(), compression_plugin()];
    let mut ctx = ctx_for("GET", "/orders");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());

    let payload = r#"{"note":"padding padding padding padding padding padding"}"#;
    let mut headers = json_headers();
    headers.insert("content-length".to_string(), payload.len().to_string());
    run_request_and_response_header_hooks(&plugins, &mut ctx, &mut headers).await;
    let body_in = payload.as_bytes().to_vec();
    let (replaced, status, headers_out, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, body_in).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(
        headers_out.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "the admitted response must still be transport encoded"
    );
    assert_eq!(
        gunzip(&body),
        payload.as_bytes(),
        "the wire body must decode back to the inspected plaintext"
    );
    assert_eq!(
        headers_out.get("content-length").map(String::as_str),
        Some(body.len().to_string().as_str()),
        "the published length must describe the encoded bytes"
    );
}

// ──────────── 4. origin content codings are decoded or fail closed ────────────

/// An origin gzip response claimed by an enforcing WAF response-body rule is
/// decoded boundedly before the scan, so the rule matches the document.
#[tokio::test]
async fn origin_gzip_response_is_decoded_for_the_waf_scan() {
    let plugins = vec![waf_blocking_response_body()];
    let mut ctx = ctx_for("GET", "/orders");
    let payload = format!(r#"{{"note":"{BLOCKED_TOKEN}"}}"#);
    let encoded = gzip(payload.as_bytes());
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);

    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, encoded).await;

    assert!(
        replaced,
        "a compressed body carrying the blocked token must be refused"
    );
    assert_eq!(status, 403);
    assert!(!String::from_utf8_lossy(&body).contains(BLOCKED_TOKEN));
}

/// An unsupported origin coding on a claimed response can never be reduced to
/// plaintext, so it fails closed rather than passing through unscanned.
#[tokio::test]
async fn unsupported_origin_coding_fails_closed_for_a_claiming_policy() {
    let plugins = vec![waf_blocking_response_body()];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "compress".to_string());
    // The pristine origin stamp is what the gate reads; force it so the
    // unsupported coding is judged as the ORIGIN's, not a gateway coding.
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    set_original_response_content_encoding_for_test(&mut ctx, "compress");

    let opaque = b"\x00\x01opaque".to_vec();
    let (replaced, status, _headers, body) =
        run_buffered_transform(&plugins, &mut ctx, 200, headers, opaque.clone()).await;

    assert!(replaced, "an uninspectable representation must be replaced");
    assert_ne!(status, 200);
    assert_ne!(
        body, opaque,
        "the unscanned octets must not reach the client"
    );
}

// ──────────────────── 5. sibling instances stay independent ────────────────────

/// Two `waf` instances keep independent header-scan state. The one configured
/// against an unrelated header must not consume the digest marker — or the
/// decision — of the one that actually protects the header.
#[tokio::test]
async fn sibling_waf_instances_do_not_suppress_each_other() {
    for order in 0..2 {
        let protecting = waf_blocking_protected_header("CUSTOM-RESP-HEADER-SIBLING");
        let unrelated = waf_blocking_unrelated_header("CUSTOM-RESP-HEADER-SIBLING-OTHER");
        let mut plugins: Vec<Arc<dyn Plugin>> = if order == 0 {
            vec![protecting, unrelated]
        } else {
            vec![unrelated, protecting]
        };
        plugins.push(response_transformer_renaming_header());

        let mut ctx = ctx_for("GET", "/orders");
        let mut headers = json_headers();
        headers.insert("x-pending-secret".to_string(), "value".to_string());

        let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
            .await
            .unwrap_or_else(|| {
                panic!("sibling order {order}: the protected header must still be refused")
            });

        assert_eq!(reject.0, 403);
        assert!(!header_names_contain(&reject.2, PROTECTED_HEADER));
    }
}

// ───── 6. late header relabels cannot bypass BODY policy on the synthetic path ─────
//
// Every test below drives `finalize_synthetic_response_for_test`, i.e. the real
// shared H1/H2/H3 synthetic finalizer
// (`apply_reject_after_proxy_and_synthetic_body_hooks`), so the reject-path
// `after_proxy` chain really does run after the body-hook phase.

/// The synthetic-lifecycle body half of the advisory. A `response_transformer`
/// header rule relabels a `text/plain` body as `application/json` inside the
/// deliberately-late reject-path chain — after `body_validator`'s only pass,
/// which correctly declined the unmatched media type. The published response is
/// now governed by the JSON rule, so the rule has to decide it.
#[tokio::test]
async fn late_content_type_relabel_cannot_bypass_body_validator_on_synthetic_response() {
    let plugins = vec![
        body_validator_requiring_approved(),
        response_transformer_relabeling_content_type(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    // No `approved` field: refused the moment the JSON rule applies.
    let mut body = bytes::Bytes::from_static(br#"{"was_approved":true}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(
        status, 502,
        "the relabelled representation must be validated: {headers:?}"
    );
    assert!(
        !String::from_utf8_lossy(&body).contains("was_approved"),
        "the refused representation must not reach the client"
    );
}

/// The control for the same pair: a body that SATISFIES the rule the relabel
/// activates is still published. Closing the window must not turn every late
/// relabel into a rejection.
#[tokio::test]
async fn late_content_type_relabel_admits_a_conforming_body() {
    let plugins = vec![
        body_validator_requiring_approved(),
        response_transformer_relabeling_content_type(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    let mut body = bytes::Bytes::from_static(br#"{"approved":true}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 200);
    assert_eq!(&body[..], br#"{"approved":true}"#);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json"),
        "the relabel itself still applies"
    );
}

/// One-shot reject-path `after_proxy` state — the `oidc_relying_party` rotated
/// session cookie shape — must survive the response the re-decision replaces,
/// and its hook must still have run exactly once. That is the contract the late
/// chain exists to protect; closing the body window may not weaken it.
#[tokio::test]
async fn post_policy_body_rejection_preserves_one_shot_session_state() {
    let runs = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        body_validator_requiring_approved(),
        Arc::new(OneShotRotatedSessionCookie {
            runs: Arc::clone(&runs),
        }),
        response_transformer_relabeling_content_type(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    ctx.metadata.insert(
        ROTATED_COOKIE_METADATA_KEY.to_string(),
        ROTATED_COOKIE_VALUE.to_string(),
    );
    let mut status = 200u16;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "text/plain".to_string()),
        // A synthetic-producer field with no gateway provenance.
        ("x-synthetic-secret".to_string(), "value".to_string()),
        // Stale representation metadata for the discarded body.
        ("etag".to_string(), "\"synthetic\"".to_string()),
    ]);
    let mut body = bytes::Bytes::from_static(br#"{"was_approved":true}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 502, "the relabelled representation must be refused");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "the reject-path after_proxy chain must still run exactly once"
    );
    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(ROTATED_COOKIE_VALUE),
        "one-shot session state must survive the post-policy rejection: {headers:?}"
    );
    assert!(
        !header_names_contain(&headers, "x-synthetic-secret"),
        "a synthetic-producer field must not cross onto the rejection: {headers:?}"
    );
    assert!(
        !header_names_contain(&headers, "etag"),
        "stale representation metadata must not describe the rejection: {headers:?}"
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json"),
        "the rejection authors its own representation"
    );
}

/// The generic contract, stated without any built-in: a policy is asked again
/// only when the late chain moved something its scope depends on.
#[tokio::test]
async fn body_policy_is_re_decided_only_when_the_late_chain_changes_policy_scope() {
    for (label, late_transform, expected_calls, expected_status) in [
        (
            "unrelated header",
            response_transformer_adding_unrelated_header(),
            1usize,
            200u16,
        ),
        (
            "content-type relabel",
            response_transformer_relabeling_content_type(),
            2usize,
            502u16,
        ),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            Arc::new(ScopedCountingFinalBodyPolicy {
                calls: Arc::clone(&calls),
                seen_content_types: Arc::clone(&seen),
            }),
            late_transform,
        ];
        let mut ctx = ctx_for("GET", "/cache-hit");
        let mut status = 200u16;
        let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
        let mut body = bytes::Bytes::from_static(b"plain synthetic payload");

        finalize_synthetic_response_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
        )
        .await;

        let seen = seen.lock().expect("content-type log").clone();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            expected_calls,
            "{label}: unexpected number of policy decisions (saw {seen:?})"
        );
        assert_eq!(status, expected_status, "{label}: unexpected final status");
        assert_eq!(
            seen.first().map(String::as_str),
            Some("text/plain"),
            "{label}: the first decision reads the pre-chain representation"
        );
    }
}

/// A status transition is part of a body policy's applicability just as much
/// as representation headers are. Byte-identical replacement must not suppress
/// re-decision when a late reject-path hook changes only the status.
#[tokio::test]
async fn body_policy_is_re_decided_when_the_late_chain_changes_only_status() {
    let calls = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(StatusScopedFinalBodyPolicy {
            calls: Arc::clone(&calls),
        }),
        Arc::new(LateIdenticalBodyStatusReject),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = json_headers();
    let mut body = bytes::Bytes::from_static(STATUS_SCOPED_BODY.as_bytes());

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 502, "the newly applicable policy must fail closed");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one pre-chain decision and one status-triggered re-decision"
    );
    assert_ne!(
        &body[..],
        STATUS_SCOPED_BODY.as_bytes(),
        "the status-scoped refusal must replace the byte-identical late body"
    );
}

/// Gateway transport encoding is not a policy-scope change. `compression` adds
/// `Content-Encoding` and rewrites `Content-Length` after the policy phase by
/// design, and the re-decision normalizes that back out — so an unchanged
/// document is never inspected, called out to, or charged a second time.
#[tokio::test]
async fn gateway_transport_encoding_does_not_trigger_a_second_body_decision() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(ScopedCountingFinalBodyPolicy {
            calls: Arc::clone(&calls),
            seen_content_types: Arc::clone(&seen),
        }),
        compression_plugin(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut request_headers = HashMap::new();
    for plugin in &plugins {
        let _ = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    }
    let payload = b"plain synthetic payload padded padded padded padded".to_vec();
    let mut status = 200u16;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "text/plain".to_string()),
        ("content-length".to_string(), payload.len().to_string()),
    ]);
    let mut body = bytes::Bytes::from(payload.clone());

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 200);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "an unchanged document must be decided exactly once (saw {:?})",
        seen.lock().expect("content-type log")
    );
    if headers.get("content-encoding").map(String::as_str) == Some("gzip") {
        assert_eq!(
            gunzip(&body),
            payload,
            "the wire body must still decode to the inspected plaintext"
        );
    } else {
        assert_eq!(&body[..], &payload[..]);
    }
}

/// A rejection whose own headers re-open a representation scope the decision was
/// not made under must fail closed onto the fixed, decorator-free gateway
/// terminal rather than being published on the strength of that decision.
///
/// The gateway terminal is deliberately NOT re-swept through the policies — a
/// gateway-authored error payload is never re-decided against itself — so the
/// rebuild is checked structurally instead.
#[tokio::test]
async fn post_policy_rejection_reopening_a_representation_scope_collapses_to_fixed_terminal() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(RepresentationBearingRejectFinalBodyPolicy),
        response_transformer_relabeling_content_type(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "text/plain".to_string()),
        ("set-cookie".to_string(), ROTATED_COOKIE_VALUE.to_string()),
    ]);
    let mut body = bytes::Bytes::from_static(b"plain synthetic payload");

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 500, "the rebuilt shape must fail closed");
    assert!(
        String::from_utf8_lossy(&body).contains("response policy could not be applied"),
        "unexpected terminal body: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        !header_names_contain(&headers, "content-disposition"),
        "the plugin-supplied representation field must not survive: {headers:?}"
    );
    assert!(
        !header_names_contain(&headers, "set-cookie"),
        "the fixed terminal keeps no decorators at all: {headers:?}"
    );
}

/// The ordinary half of the same path: a rejection whose rebuild carries only
/// the gateway's own representation is published as-is, and its decorators
/// survive. Failing closed must be reserved for the anomalous shape above.
#[tokio::test]
async fn post_policy_body_rejection_is_published_when_the_rebuild_is_gateway_shaped() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(ScopedCountingFinalBodyPolicy {
            calls: Arc::clone(&calls),
            seen_content_types: Arc::clone(&seen),
        }),
        response_transformer_relabeling_content_type(),
    ];
    let mut ctx = ctx_for("GET", "/cache-hit");
    let mut status = 200u16;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "text/plain".to_string()),
        ("set-cookie".to_string(), ROTATED_COOKIE_VALUE.to_string()),
    ]);
    let mut body = bytes::Bytes::from_static(b"plain synthetic payload");

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(status, 502);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one pre-chain decision and exactly one re-decision, never a third"
    );
    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(ROTATED_COOKIE_VALUE),
        "gateway decorators survive an ordinary rebuild: {headers:?}"
    );
}

/// A sibling that scanned an identical map must not stop the other from
/// rescanning a map that CHANGED. The digest is per instance, and the two
/// instances observe different points in the chain.
#[tokio::test]
async fn sibling_instances_recheck_independently_after_a_change() {
    let plugins = vec![
        waf_blocking_unrelated_header("CUSTOM-RESP-HEADER-A"),
        waf_blocking_protected_header("CUSTOM-RESP-HEADER-B"),
        response_transformer_renaming_header(),
    ];
    let mut ctx = ctx_for("GET", "/orders");
    let mut headers = json_headers();
    headers.insert("x-pending-secret".to_string(), "value".to_string());

    let reject = run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
        .await
        .expect("the second instance must recheck the changed map");

    assert_eq!(reject.0, 403);
}

// ─────── 7. claiming an origin-encoded response is DISPOSITION-AWARE ────────
//
// `enforces_response_body_policy` is a fail-closed assertion: a claimed
// representation the gateway cannot decode becomes a `502`. A configuration
// whose configured outcome is observe-only could never have refused anything, so
// an undecodable origin coding costs it an observation and must not cost the
// client the response. These drive the production buffered transform funnel, so
// they assert what is published rather than what a predicate returns.

/// The coding this gateway does not implement, so no codec or budget accident
/// can decide these cases instead of the claim.
const UNDECODABLE_ORIGIN_CODING: &str = "zstd";

fn origin_encoded_headers() -> HashMap<String, String> {
    let mut headers = json_headers();
    headers.insert(
        "content-encoding".to_string(),
        UNDECODABLE_ORIGIN_CODING.to_string(),
    );
    headers
}

/// A WAF that OBSERVES response bodies: `monitor` globally, so no rule of its
/// can refuse a response.
fn waf_monitoring_response_body() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "monitor",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "response_body_inspection": true,
            "custom_rules": [{
                "id": "CUSTOM-RESP-BODY-MONITOR",
                "name": "observed response payload",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "contains",
                "pattern": BLOCKED_TOKEN,
                "action": "enforce"
            }]
        }))
        .expect("monitor waf response-body config"),
    )
}

/// Globally monitoring with a response-body rule that is itself `monitor` and no
/// anomaly scoring can promote it — the rule-level half of the same question.
fn waf_with_monitor_only_response_rule() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "monitor",
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "response_body_inspection": true,
            "custom_rules": [{
                "id": "CUSTOM-RESP-BODY-RULE-MONITOR",
                "name": "observed response payload",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "contains",
                "pattern": BLOCKED_TOKEN,
                "action": "monitor"
            }]
        }))
        .expect("monitor-rule waf response-body config"),
    )
}

/// A response posture whose ONLY blocking disposition is the strict size cap:
/// globally enforcing, one monitor-only response-body rule, and
/// `on_body_too_large: block`. The request side has claimed this shape since
/// #4006; the response side did not, so the cap was applied to the ENCODED
/// origin bytes and a compressed body slipped under a cap its plaintext
/// exceeds (`GHSA-v8p4-f3c9-g3w4`).
fn waf_size_only_enforcing_response_body(mode: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": mode,
            "include_default_rules": false,
            "scan_budget_ms": 0,
            "response_inspection": true,
            "response_body_inspection": true,
            "on_body_too_large": "block",
            "max_scan_bytes": 64,
            "custom_rules": [{
                "id": "CUSTOM-RESP-BODY-SIZE-ONLY",
                "name": "observed response payload",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "contains",
                "pattern": BLOCKED_TOKEN,
                "action": "monitor"
            }]
        }))
        .expect("size-only enforcing waf response-body config"),
    )
}

async fn publish_origin_encoded_response(
    plugins: &[Arc<dyn Plugin>],
) -> (bool, u16, HashMap<String, String>, Vec<u8>) {
    let mut ctx = ctx_for("GET", "/origin-encoded");
    let headers = origin_encoded_headers();
    // The pristine origin stamp is what the gate reads; force it so the coding
    // is judged as the ORIGIN's rather than as a gateway coding.
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    set_original_response_content_encoding_for_test(&mut ctx, UNDECODABLE_ORIGIN_CODING);
    run_buffered_transform(plugins, &mut ctx, 200, headers, b"opaque-octets".to_vec()).await
}

/// The fail-closed baseline the two observe-only cases are measured against.
#[tokio::test]
async fn an_enforcing_waf_refuses_an_undecodable_origin_encoded_response() {
    let (replaced, status, _, body) =
        publish_origin_encoded_response(&[waf_blocking_response_body()]).await;

    assert!(
        replaced,
        "a claimed representation must not be served opaque"
    );
    assert_ne!(status, 200);
    assert_ne!(
        body,
        b"opaque-octets".to_vec(),
        "the unscanned octets must not reach the client"
    );
}

#[tokio::test]
async fn a_monitor_mode_waf_does_not_refuse_an_undecodable_origin_encoded_response() {
    let (replaced, status, headers, body) =
        publish_origin_encoded_response(&[waf_monitoring_response_body()]).await;

    assert!(
        !replaced,
        "an observe-only WAF loses an observation on an unscannable response; \
         it must not cost the client the response"
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"opaque-octets".to_vec());
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some(UNDECODABLE_ORIGIN_CODING),
        "the origin representation is forwarded untouched"
    );
}

#[tokio::test]
async fn a_monitor_only_response_rule_does_not_refuse_an_undecodable_response() {
    let (replaced, status, _, body) =
        publish_origin_encoded_response(&[waf_with_monitor_only_response_rule()]).await;

    assert!(
        !replaced,
        "a rule that can only log is not a protection mechanism to fail closed"
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"opaque-octets".to_vec());
}

#[tokio::test]
async fn a_size_only_enforcing_response_policy_refuses_an_undecodable_response() {
    // Nothing in this configuration can refuse a response except the strict
    // size cap, so the cap is the protection mechanism: an origin coding the
    // gateway cannot decode must not be measured as-is.
    let (replaced, status, _, body) =
        publish_origin_encoded_response(&[waf_size_only_enforcing_response_body("enforce")]).await;

    assert!(
        replaced,
        "a size-only enforcing response posture must claim the decoded representation"
    );
    assert_ne!(status, 200);
    assert_ne!(body, b"opaque-octets".to_vec());
}

#[tokio::test]
async fn a_monitor_mode_size_only_response_policy_does_not_refuse() {
    // `on_body_too_large: block` only rejects while globally enforcing, so the
    // new claim stays exactly as narrow as the request-side one.
    let (replaced, status, headers, body) =
        publish_origin_encoded_response(&[waf_size_only_enforcing_response_body("monitor")]).await;

    assert!(!replaced);
    assert_eq!(status, 200);
    assert_eq!(body, b"opaque-octets".to_vec());
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some(UNDECODABLE_ORIGIN_CODING)
    );
}

/// `ai_response_guard` in `warn` passes every finding through, exactly as its
/// own uninspectable-response answer already concedes. Claiming on its behalf
/// would turn an origin coding this gateway cannot decode into a gateway error
/// for a configuration that was never allowed to refuse anything.
#[tokio::test]
async fn a_warn_only_ai_response_guard_does_not_refuse_an_undecodable_response() {
    let warner: Arc<dyn Plugin> = Arc::new(
        AiResponseGuard::new(&json!({
            "pii_patterns": ["email"],
            "action": "warn",
        }))
        .expect("warn ai_response_guard config"),
    );
    let rejecter: Arc<dyn Plugin> = Arc::new(
        AiResponseGuard::new(&json!({
            "pii_patterns": ["email"],
            "action": "reject",
        }))
        .expect("reject ai_response_guard config"),
    );

    let (replaced, status, _, body) = publish_origin_encoded_response(&[warner]).await;
    assert!(
        !replaced,
        "a warn-only guard is pass-through by construction"
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"opaque-octets".to_vec());

    let (replaced, status, _, _) = publish_origin_encoded_response(&[rejecter]).await;
    assert!(
        replaced,
        "an enforcing guard must still fail an unreadable representation closed"
    );
    assert_ne!(status, 200);
}

// ─────── 8. a late GATEWAY-authored rejection replacement is not rejudged ────
//
// The synthetic lifecycle re-decides its body policy after the deliberately-late
// reject-path `after_proxy` chain, because that chain can relabel a BACKEND or
// synthetic producer's representation. A hook that opted into
// `may_replace_rejection_response` and actually replaced the response is a
// different thing: that replacement is the final answer for an already-rejected
// request, and `.claude/rules/plugins.md` 10b keeps gateway terminals and an
// earlier rejection out of the re-decision.

/// The `spec_expose` HEAD marker: its reject-path `after_proxy` strips the wire
/// body while retaining the GET status and representation metadata.
const SPEC_EXPOSE_HEAD_MARKER: &str = "ferrum:spec_expose_head_response";

fn spec_expose_plugin() -> Arc<dyn Plugin> {
    Arc::new(
        SpecExpose::new(
            &json!({ "spec_url": "https://example.com/openapi.yaml" }),
            PluginHttpClient::default(),
        )
        .expect("spec_expose config"),
    )
}

#[tokio::test]
async fn a_late_rejection_replacement_is_not_rejudged_by_the_body_policy() {
    // Configured priority order: spec_expose (210) before body_validator (2950).
    let plugins = vec![spec_expose_plugin(), body_validator_requiring_approved()];
    // The marker `spec_expose` stages for its own HEAD reply, set directly so
    // this exercises the shared finalizer rather than the plugin's spec fetch.
    // The request method is deliberately GET: HTTP's own bodyless exemption for
    // HEAD would otherwise excuse the emptied body and prove nothing.
    let mut ctx = ctx_for("GET", "/specz");
    ctx.metadata
        .insert(SPEC_EXPOSE_HEAD_MARKER.to_string(), "true".to_string());
    let mut status = 200u16;
    let mut headers = json_headers();
    // Conforming under the schema: the first, authoritative pass accepts it.
    let mut body = bytes::Bytes::from_static(br#"{"approved":true}"#);

    finalize_synthetic_response_for_test(&plugins, &mut ctx, &mut status, &mut headers, &mut body)
        .await;

    assert_eq!(
        status, 200,
        "the gateway-authored replacement must survive: {headers:?}"
    );
    assert!(
        body.is_empty(),
        "the replacement is published as authored, not re-decided against a \
         response schema no bodyless envelope can satisfy"
    );
}
