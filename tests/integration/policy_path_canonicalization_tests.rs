//! One canonical policy path across every consumer (private advisory
//! GHSA-69xf-42xm-4w4f).
//!
//! The frontend handlers canonicalize `ctx.path` once at the boundary; these
//! tests assert that each policy surface then reaches the *same* decision for
//! `/%61dmin` as it does for `/admin`, and that routing, listen-path
//! stripping, and the assembled backend request line agree with it.
//!
//! Boundary rejection (the encoded-separator / invalid-escape / invalid-UTF-8
//! cases) and per-protocol parity are covered end-to-end by
//! `tests/functional/functional_policy_path_canonicalization_test.rs`; the
//! canonicalizer's own contract is covered by
//! `tests/unit/gateway_core/policy_path_tests.rs`.

use ferrum_edge::RouterCache;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::plugins::openapi_validator::OpenapiValidator;
use ferrum_edge::plugins::request_termination::RequestTermination;
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use ferrum_edge::policy_path::canonicalize_policy_path;
use ferrum_edge::proxy::build_backend_url;
use serde_json::json;
use std::collections::HashMap;

/// Exactly what the H1/H2/H3 handlers do at the boundary: build the request
/// context on the canonical path, keeping the client's spelling only as the
/// raw target.
fn boundary_ctx(method: &str, raw_path: &str) -> RequestContext {
    let canonical = canonicalize_policy_path(raw_path)
        .unwrap_or_else(|rejection| panic!("{raw_path:?} rejected at boundary: {rejection:?}"));
    RequestContext::new("203.0.113.10".into(), method.into(), canonical.into_owned())
}

/// Spellings a client can choose for the same backend resource: plain, one
/// encoded legal character, and fully encoded. Every policy surface below must
/// treat all three identically.
const RAW_SPELLINGS: [&str; 3] = ["/admin", "/%61dmin", "/%61%64%6D%69%6E"];

// ── WAF: url_path rules and rule path conditions ───────────────────────────

fn waf_url_path_rule(match_kind: &str, pattern: &str) -> Waf {
    Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-ADMIN-PATH",
            "name": "protect admin path",
            "category": "custom",
            "severity": "high",
            "target": "url_path",
            "match_kind": match_kind,
            "pattern": pattern,
            "action": "enforce"
        }]
    }))
    .expect("waf config")
}

#[tokio::test]
async fn waf_url_path_rule_cannot_be_dodged_by_encoding_a_legal_character() {
    for match_kind in ["contains", "regex"] {
        let pattern = if match_kind == "regex" {
            "^/admin"
        } else {
            "/admin"
        };
        let plugin = waf_url_path_rule(match_kind, pattern);
        for raw in RAW_SPELLINGS {
            let mut ctx = boundary_ctx("GET", raw);
            let result = plugin.authorize(&mut ctx).await;
            assert!(
                matches!(result, PluginResult::Reject { .. }),
                "{match_kind} rule must enforce for spelling {raw:?}, got {result:?}"
            );
        }
        // Negative control: an unrelated path is still allowed, so the rule is
        // matching the path rather than everything.
        let mut ctx = boundary_ctx("GET", "/public");
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
    }
}

fn waf_scoped_rule(path_condition: &str) -> Waf {
    Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-SCOPED-QUERY",
            "name": "scoped query marker",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "conditions": { "paths": [path_condition] },
            "action": "enforce"
        }]
    }))
    .expect("waf config")
}

#[tokio::test]
async fn waf_exact_prefix_and_regex_path_conditions_scope_on_the_canonical_path() {
    // `conditions.paths` supports exact (`/admin`), prefix (`/admin*`), and
    // regex (`~admin`) forms. All three scope on `ctx.path`, so all three must
    // engage for every spelling of the same path.
    for condition in ["/admin", "/admin*", "~^/admin$"] {
        let plugin = waf_scoped_rule(condition);
        for raw in RAW_SPELLINGS {
            let mut ctx = boundary_ctx("GET", raw);
            ctx.set_raw_query_string("q=needle".into());
            let result = plugin.authorize(&mut ctx).await;
            assert!(
                matches!(result, PluginResult::Reject { .. }),
                "condition {condition:?} must scope in for spelling {raw:?}, got {result:?}"
            );
        }

        // Out of scope stays out of scope.
        let mut ctx = boundary_ctx("GET", "/public");
        ctx.set_raw_query_string("q=needle".into());
        assert!(
            matches!(plugin.authorize(&mut ctx).await, PluginResult::Continue),
            "condition {condition:?} must not scope in /public"
        );
    }
}

// ── openapi_validator: literal-versus-parameter operation selection ────────

fn overlapping_openapi_validator() -> OpenapiValidator {
    // A restrictive literal operation and a permissive parameterized one that
    // both match `/admin`. Selection must land on the literal operation
    // regardless of how the client spelled the path — the advisory's
    // scenario 2, where the parameterized schema accepted a body the literal
    // operation forbids.
    // Media entries must be bare JSON Schema (or `{schema, encoding}` when an
    // Encoding Object is present). A lone `{"schema": {...}}` wrapper is not
    // unwrapped: `schema` is treated as an ordinary/custom keyword and ignored,
    // so the body would vacuously pass and this advisory check would be inert.
    OpenapiValidator::new(&json!({
        "fail_on_unknown_operation": true,
        "operations": [
            {
                "method": "POST",
                "path_template": "/{slug}",
                "path_regex": "^/[^/]+$",
                "request_body": {
                    "content": {
                        "application/json": { "type": "object" }
                    }
                }
            },
            {
                "method": "POST",
                "path_template": "/admin",
                "path_regex": "^/admin$",
                "request_body": {
                    "content": {
                        "application/json": {
                            "type": "object",
                            "required": ["confirm"],
                            "additionalProperties": false,
                            "properties": { "confirm": { "const": true } }
                        }
                    }
                }
            }
        ]
    }))
    .expect("openapi_validator config")
}

fn json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".into(), "application/json".into());
    headers
}

#[tokio::test]
async fn openapi_operation_selection_prefers_the_literal_path_for_every_spelling() {
    let plugin = overlapping_openapi_validator();
    for raw in RAW_SPELLINGS {
        let mut ctx = boundary_ctx("POST", raw);
        let mut headers = json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{raw:?} should match an operation, got {result:?}"
        );
        let matched = ctx
            .metadata
            .get("openapi_validator.matched_operation")
            .cloned()
            .unwrap_or_default();
        assert!(
            matched.contains("/admin"),
            "{raw:?} selected {matched:?} instead of the literal /admin operation"
        );
    }

    // The parameterized operation still serves paths the literal one does not.
    let mut ctx = boundary_ctx("POST", "/anything-else");
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let matched = ctx
        .metadata
        .get("openapi_validator.matched_operation")
        .cloned()
        .unwrap_or_default();
    assert!(
        matched.contains("{slug}"),
        "unmatched literal path should fall to the parameterized operation, got {matched:?}"
    );
}

#[tokio::test]
async fn openapi_request_body_is_validated_against_the_literal_operation_schema() {
    let plugin = overlapping_openapi_validator();
    for raw in RAW_SPELLINGS {
        // A body that only the permissive `/{slug}` schema would accept must be
        // rejected, because the canonical path selects the strict operation.
        let mut ctx = boundary_ctx("POST", raw);
        let headers = json_headers();
        let mut before_headers = headers.clone();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut before_headers).await,
            PluginResult::Continue
        ));
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, br#"{"anything":1}"#)
            .await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "{raw:?} must be validated against the strict schema, got {result:?}"
        );

        // The body the strict operation demands is accepted for every spelling.
        let mut ctx = boundary_ctx("POST", raw);
        let mut before_headers = headers.clone();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut before_headers).await,
            PluginResult::Continue
        ));
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, br#"{"confirm":true}"#)
            .await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{raw:?} valid strict body must pass, got {result:?}"
        );
    }
}

// ── request_termination: path prefixes ─────────────────────────────────────

#[tokio::test]
async fn request_termination_prefix_fires_for_every_spelling_of_the_prefix() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 403,
        "content_type": "application/json",
        "message": "blocked",
        "trigger": { "path_prefix": "/admin" }
    }))
    .expect("request_termination config");

    for raw in RAW_SPELLINGS {
        let mut ctx = boundary_ctx("GET", raw);
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "termination must fire for spelling {raw:?}, got {result:?}"
        );
    }

    // Sibling paths outside the prefix are untouched.
    let mut ctx = boundary_ctx("GET", "/public");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn request_termination_rejects_a_prefix_that_could_never_match() {
    // A prefix written in a non-canonical spelling is not a stricter rule, it
    // is a dead one — admission refuses it rather than letting it silently
    // never fire.
    for prefix in [
        "/%61dmin",
        "/api%2Fadmin",
        "/api%2",
        "/api%20name",
        // Literal dot segments and backslashes cannot appear in a canonical
        // request path either, so a prefix carrying one is equally dead.
        "/api/../admin",
        "/api/./admin",
        "/api\\admin",
    ] {
        // Match instead of expect_err: RequestTermination does not implement
        // Debug, and Result::expect_err requires Debug on the Ok type.
        let error = match RequestTermination::new(&json!({
            "status_code": 403,
            "trigger": { "path_prefix": prefix }
        })) {
            Err(error) => error,
            Ok(_) => panic!("non-canonical prefix must be rejected: {prefix:?}"),
        };
        assert!(
            error.contains("canonical policy path"),
            "unexpected error for {prefix:?}: {error}"
        );
    }

    // Canonical prefixes stay valid: no percent escape (none survives
    // canonicalization), no literal `\`, and no literal `.`/`..` segment. A `.`
    // inside a segment is an ordinary path character. The asterisk-form OPTIONS
    // target is canonical too.
    for prefix in ["/admin", "*", "/api/v1/reports", "/v1.0/reports"] {
        RequestTermination::new(&json!({
            "status_code": 403,
            "trigger": { "path_prefix": prefix }
        }))
        .unwrap_or_else(|error| panic!("{prefix:?} should be accepted: {error}"));
    }
}

// ── Routing, listen-path stripping, and the backend request line ───────────

fn admin_router(strip_listen_path: bool) -> RouterCache {
    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "admin",
            "listen_path": "/admin",
            "backend_scheme": "http",
            "backend_host": "backend.example.com",
            "backend_port": 3000,
            "strip_listen_path": strip_listen_path,
        }],
        "consumers": [],
        "plugin_configs": [],
    }))
    .expect("gateway config");
    // Resolves `dispatch_kind`, which the backend-URL builder reads for the
    // wire scheme.
    config.normalize_fields();
    RouterCache::new(&config, 1024)
}

#[tokio::test]
async fn routing_and_backend_forwarding_use_the_same_canonical_path() {
    for strip_listen_path in [true, false] {
        let router = admin_router(strip_listen_path);
        let expected = if strip_listen_path {
            "http://backend.example.com:3000/reports"
        } else {
            "http://backend.example.com:3000/admin/reports"
        };

        for raw in ["/admin/reports", "/%61dmin/reports", "/admin/%72eports"] {
            let canonical = canonicalize_policy_path(raw).expect("accepted at boundary");
            let matched = router
                .find_proxy(None, &canonical)
                .unwrap_or_else(|| panic!("{raw:?} must route to the admin proxy"));
            assert_eq!(matched.proxy.id, "admin");

            // The backend request line is built from the same canonical
            // coordinate the router measured `matched_prefix_len` in, so the
            // stripped remainder can never desync from the routing decision.
            let url = build_backend_url(&matched.proxy, &canonical, "", matched.matched_prefix_len);
            assert_eq!(
                url, expected,
                "spelling {raw:?} (strip={strip_listen_path}) forwarded {url}"
            );
        }
    }
}

#[tokio::test]
async fn encoded_separators_never_reach_routing() {
    // The boundary refuses them, so the router is never asked to decide
    // whether `/admin%2Freports` has two segments or three — the question that
    // let a folded route decision disagree with a non-decoding backend.
    for raw in ["/admin%2Freports", "/admin%5Creports", "/admin%252Freports"] {
        assert!(
            canonicalize_policy_path(raw).is_err(),
            "{raw:?} must be rejected before routing"
        );
    }
}

#[tokio::test]
async fn dot_segments_and_backslashes_never_reach_routing_or_backend_dispatch() {
    // Rejection happens at the canonicalizer, which the frontends run before
    // `find_proxy` and before any backend URL is built — so for these targets
    // there is no route decision and no request line at all.
    let router = admin_router(false);
    for raw in [
        "/admin/../public",
        "/admin/./reports",
        "/admin/reports/..",
        "/admin\\reports",
        // Also when the target carries an otherwise-decodable escape, so this
        // is not a property of the escape-free scan alone.
        "/%61dmin/../public",
        "/%61dmin\\reports",
    ] {
        let rejection = canonicalize_policy_path(raw)
            .err()
            .unwrap_or_else(|| panic!("{raw:?} must be rejected before routing"));
        assert!(
            matches!(
                rejection.reason(),
                "literal_dot_segment" | "literal_backslash"
            ),
            "{raw:?} rejected for the wrong reason: {}",
            rejection.reason()
        );
        // The router is never consulted for a rejected target; asserting the
        // proxy exists for the *accepted* spelling shows the route was
        // otherwise reachable, so rejection — not a routing miss — is what
        // stopped it.
        assert!(router.find_proxy(None, "/admin/reports").is_some());
    }
}

#[tokio::test]
async fn a_dot_segment_or_backslash_would_desync_policy_from_the_forwarded_request_line() {
    // Why these must be refused rather than passed through: the backend URL
    // Ferrum hands to reqwest (`client.request(method, backend_url)`) is parsed
    // by the `url` crate, which removes dot segments per RFC 3986 / WHATWG and
    // treats `\` as a path separator for special HTTP(S) schemes. Passing the
    // target through would leave policy evaluating one path while the request
    // line resolves another — the exact divergence this module removes.
    let router = admin_router(false);
    let matched = router
        .find_proxy(None, "/admin/reports")
        .expect("admin route");

    for (raw_tail, resolved) in [
        ("/admin/../public", "/public"),
        ("/admin/reports/../../public", "/public"),
        ("/admin\\reports", "/admin/reports"),
    ] {
        let assembled = build_backend_url(&matched.proxy, raw_tail, "", 0);
        let parsed = url::Url::parse(&assembled).expect("backend URL parses");
        assert_eq!(
            parsed.path(),
            resolved,
            "{raw_tail:?} would be forwarded as {resolved:?}, not as written"
        );
        // Which is why the boundary never lets it get this far.
        assert!(
            canonicalize_policy_path(raw_tail).is_err(),
            "{raw_tail:?} must be rejected at the boundary"
        );
    }
}

#[tokio::test]
async fn escapes_that_cannot_be_forwarded_literally_never_reach_routing() {
    // If the gateway kept `%20` / `%7B` / `%C3%A9` escaped it would forward that
    // spelling to a backend that commonly decodes it, so policy would evaluate
    // `/admin%20reports` while the application resolved `/admin reports`. The
    // boundary refuses them instead of shipping two coordinates.
    for raw in [
        "/admin%20reports",
        "/admin/%7Bid%7D",
        "/admin/caf%C3%A9",
        "/admin%5Bid%5D",
    ] {
        assert!(
            canonicalize_policy_path(raw).is_err(),
            "{raw:?} must be rejected before routing"
        );
    }
}
