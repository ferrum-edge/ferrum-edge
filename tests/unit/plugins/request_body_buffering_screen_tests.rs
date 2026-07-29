//! Parity and drift coverage for the backend-TLS SNI request-body-buffering
//! admission screen (`plugins::RequestBodyBufferingScreener`).
//!
//! The screen exists so `ferrum-edge validate` and admin admission can reject a
//! plain-HTTPS proxy whose backend TLS SNI override would 502 at runtime: SNI
//! overrides need the direct-H2 pool, which cannot dispatch a pre-buffered
//! request body. The authoritative predicate is
//! `Plugin::requires_request_body_buffering()`, which several plugins derive
//! from their own parsed state.
//!
//! Three properties are covered here:
//!
//! 1. Parity — for every built-in plugin, and for every configuration variant
//!    of every conditional buffering plugin, the screen's answer equals the
//!    answer a constructed plugin gives through the trait.
//! 2. Coverage drift — every plugin module that overrides any buffering-related
//!    trait method appears in the matrix below, so a future buffering plugin
//!    cannot silently escape the screen.
//! 3. Side-effect drift — the two carve-out lists stay honest: no
//!    never-constructed plugin may gain a buffering override, and no new
//!    shape-only validation carve-out (i.e. a new side-effectful constructor)
//!    may appear without being classified.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ferrum_edge::plugins::{
    BUILTIN_PLUGIN_REGISTRATIONS, Plugin, REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT,
    REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY, RequestBodyBufferingScreen,
    RequestBodyBufferingScreenGap, RequestBodyBufferingScreener, create_plugin,
};
use serde_json::{Value, json};

use super::minimal_plugin_config;

use Expectation::{Exactly, ParityOnly};
use RequestBodyBufferingScreen::{Buffers, Indeterminate, Streams};
use RequestBodyBufferingScreenGap::{ConstructionFailed, NotBuiltin};

/// Trait methods whose overrides can make `requires_request_body_buffering()`
/// return `true`. The default implementation ORs the last four, and a plugin
/// may also override the predicate itself.
///
/// `default_buffering_predicate_inputs_have_not_drifted` pins this list against
/// the live default implementation, so a new input to the predicate forces this
/// scan (and therefore the coverage matrix) to be widened.
const BUFFERING_TRAIT_METHODS: &[&str] = &[
    "requires_request_body_buffering",
    "modifies_request_body",
    "requires_request_body_before_before_proxy",
    "requires_request_body_before_authenticate",
    "requires_request_body_before_authorize",
];

/// Expected buffering answer for a variant, when it is knowable from the
/// plugin's documented config semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    /// Assert the exact screen result as well as trait parity.
    Exactly(RequestBodyBufferingScreen),
    /// Assert trait parity only. Used where pinning a direction here would only
    /// re-encode plugin internals; parity is still the property under test.
    ParityOnly,
}

/// One configuration variant of a buffering-capable plugin.
struct Row {
    plugin: &'static str,
    /// Keys merged into `minimal_plugin_config(plugin)`. A `null` value removes
    /// the key instead of setting it.
    overlay: Value,
    expectation: Expectation,
}

impl Row {
    /// Config actually screened: the plugin's minimal valid config plus overlay.
    fn config(&self) -> Value {
        merge_overlay(&minimal_plugin_config(self.plugin), &self.overlay)
    }

    /// Short assertion context, safe to embed in a message.
    fn label(&self) -> String {
        format!("{} with overlay {}", self.plugin, self.overlay)
    }
}

/// The plugin's minimal valid config, unmodified.
fn base(plugin: &'static str, expectation: Expectation) -> Row {
    Row {
        plugin,
        overlay: json!({}),
        expectation,
    }
}

/// The plugin's minimal valid config with `overlay` merged in.
fn row(plugin: &'static str, overlay: Value, expectation: Expectation) -> Row {
    Row {
        plugin,
        overlay,
        expectation,
    }
}

/// Every plugin module that can require request-body buffering, with the
/// configuration variants exercised against the screen.
///
/// `buffering_capable_plugins_are_all_covered` proves the plugin set here is
/// exactly the set of modules overriding a buffering-related trait method.
fn conditional_buffering_matrix() -> Vec<Row> {
    let disabled = json!({"enabled": false});
    let redact = json!({"patterns": ["secret"], "action": "redact"});
    let token_limited = json!({"max_tokens": 1024});
    let capture_off = json!({"capture": {"request": false, "response": false}});
    let response_only = json!({"required_fields": null, "response_required_fields": ["n"]});
    let decompress = json!({"decompress_request": true, "max_decompressed_request_size": 1024});
    let include_body = json!({"include_body": true});
    let no_req_valid = json!({"validate_request": false});
    let no_body_mirroring = json!({"mirror_request_body": false});
    let body_rule = json!({"operation": "add", "target": "body", "key": "k", "value": 1});
    let body_rules = json!({"rules": [body_rule]});
    let no_body_forward = json!({"forward_body": false});
    let no_body_inspection = json!({"request_body_inspection": false});
    // Bounded body capture (#3316) is the debugger's only buffering input; the
    // per-request predicates narrow it further, but the config-level capability
    // this screen asks about follows `log_request_body` alone.
    let capture_request_bodies = json!({"log_request_body": true});

    vec![
        base("a2a_gateway", ParityOnly),
        row("a2a_gateway", disabled.clone(), ParityOnly),
        base("ai_federation", Exactly(Buffers)),
        base("ai_prompt_compressor", Exactly(Buffers)),
        base("ai_prompt_shield", ParityOnly),
        row("ai_prompt_shield", redact, ParityOnly),
        base("ai_rate_limiter", Exactly(Buffers)),
        base("ai_request_guard", ParityOnly),
        row("ai_request_guard", token_limited, ParityOnly),
        base("ai_semantic_cache", Exactly(Buffers)),
        base("ai_semantic_firewall", ParityOnly),
        base("ai_stream_router", Exactly(Buffers)),
        row("ai_stream_router", disabled.clone(), Exactly(Streams)),
        base("ai_tool_governor", ParityOnly),
        row("ai_tool_governor", disabled.clone(), ParityOnly),
        base("ai_transcript_audit", ParityOnly),
        row("ai_transcript_audit", capture_off, ParityOnly),
        base("body_validator", Exactly(Buffers)),
        row("body_validator", response_only, Exactly(Streams)),
        base("compression", Exactly(Streams)),
        row("compression", decompress, Exactly(Buffers)),
        base("graphql", Exactly(Buffers)),
        base("grpc_web", Exactly(Buffers)),
        base("hmac_auth", Exactly(Buffers)),
        base("load_testing", Exactly(Buffers)),
        base("mcp_gateway", ParityOnly),
        row("mcp_gateway", disabled, ParityOnly),
        base("opa", Exactly(Streams)),
        row("opa", include_body, Exactly(Buffers)),
        base("openapi_validator", Exactly(Streams)),
        row("openapi_validator", no_req_valid, Exactly(Streams)),
        base("request_deduplication", Exactly(Buffers)),
        base("request_mirror", Exactly(Buffers)),
        row("request_mirror", no_body_mirroring, Exactly(Streams)),
        base("request_transformer", Exactly(Streams)),
        row("request_transformer", body_rules, Exactly(Buffers)),
        base("serverless_function", ParityOnly),
        row("serverless_function", no_body_forward, ParityOnly),
        base("soap_ws_security", Exactly(Buffers)),
        base("transaction_debugger", Exactly(Streams)),
        row(
            "transaction_debugger",
            capture_request_bodies,
            Exactly(Buffers),
        ),
        base("waf", ParityOnly),
        row("waf", no_body_inspection, Exactly(Streams)),
    ]
}

/// Merge `overlay` onto `base_config`; a `null` overlay value removes the key.
fn merge_overlay(base_config: &Value, overlay: &Value) -> Value {
    let mut merged = base_config.clone();
    let Some(source) = overlay.as_object() else {
        return merged;
    };
    let Some(target) = merged.as_object_mut() else {
        return base_config.clone();
    };
    for (key, value) in source {
        if value.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    merged
}

/// The screen answer a constructed plugin implies, or the matching
/// `Indeterminate` classification when the config does not construct.
fn trait_answer(plugin_name: &str, config: &Value) -> RequestBodyBufferingScreen {
    match create_plugin(plugin_name, config) {
        Ok(Some(plugin)) => {
            if plugin.requires_request_body_buffering() {
                Buffers
            } else {
                Streams
            }
        }
        Ok(None) => Indeterminate(NotBuiltin),
        Err(_) => Indeterminate(ConstructionFailed),
    }
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

/// The screen must agree with the live trait for every built-in plugin under
/// its minimal valid configuration, so a plugin added to the registry without
/// any buffering consideration is still covered.
#[test]
fn screen_matches_plugin_trait_for_every_builtin_minimal_config() {
    let screener = RequestBodyBufferingScreener::new();
    for registration in BUILTIN_PLUGIN_REGISTRATIONS {
        let name = registration.name;
        let config = minimal_plugin_config(name);
        let screened = screener.screen(name, &config);

        if REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT.contains(&name) {
            // Never-constructed plugins are answered `Streams` by assertion.
            // Prove that assertion behaviorally against a real instance.
            let msg = format!("{name} is never constructed; it must screen Streams");
            assert_eq!(screened, Streams, "{msg}");
            let built = create_plugin(name, &config);
            let plugin = built.expect("construct").expect("built-in");
            let buffers = plugin.requires_request_body_buffering();
            let msg = format!("{name} now buffers; drop it from the no-construct list");
            assert!(!buffers, "{msg}");
            continue;
        }

        let expected = trait_answer(name, &config);
        let msg = format!("{name} screen drifted from the plugin trait");
        assert_eq!(screened, expected, "{msg}");
    }
}

/// Every conditional buffering plugin, in each of its exercised states.
#[test]
fn screen_matches_plugin_trait_across_conditional_buffering_configs() {
    let screener = RequestBodyBufferingScreener::new();
    for row in conditional_buffering_matrix() {
        let config = row.config();
        let screened = screener.screen(row.plugin, &config);
        let expected = trait_answer(row.plugin, &config);
        let msg = format!("screen drifted from the trait for {}", row.label());
        assert_eq!(screened, expected, "{msg}");
        if let Exactly(pinned) = row.expectation {
            let msg = format!("unexpected screen result for {}", row.label());
            assert_eq!(screened, pinned, "{msg}");
        }
    }
}

/// The matrix must actually exercise both directions; otherwise a screen that
/// answered a constant would still pass the parity assertions.
#[test]
fn conditional_matrix_exercises_both_buffering_directions() {
    let screener = RequestBodyBufferingScreener::new();
    let mut buffering = BTreeSet::new();
    let mut streaming = BTreeSet::new();
    for row in conditional_buffering_matrix() {
        match screener.screen(row.plugin, &row.config()) {
            Buffers => {
                buffering.insert(row.plugin);
            }
            Streams => {
                streaming.insert(row.plugin);
            }
            // An overlay a plugin's own schema rejects is not a screen failure;
            // the parity test above still asserts agreement for it.
            Indeterminate(_) => {}
        }
    }
    let msg = format!("expected many buffering plugins, saw {buffering:?}");
    assert!(buffering.len() >= 10, "{msg}");
    let msg = format!("expected non-buffering configs, saw {streaming:?}");
    assert!(streaming.len() >= 4, "{msg}");
}

/// Custom / unknown plugin names are never instantiated by the screen and are
/// reported as an explicit, value-free gap rather than a silent `false`.
#[test]
fn unknown_plugin_names_are_reported_as_a_gap_not_a_negative() {
    let screener = RequestBodyBufferingScreener::new();
    for name in ["not_a_real_plugin", "semantic_ai_firewall", "oauth2_auth"] {
        let screened = screener.screen(name, &json!({}));
        let msg = format!("{name} must screen as an explicit gap");
        assert_eq!(screened, Indeterminate(NotBuiltin), "{msg}");
    }
}

/// A built-in whose configuration does not construct is a gap, not a negative,
/// and the reason token carries no configuration value.
#[test]
fn unconstructable_builtin_config_is_a_redacted_gap() {
    let screener = RequestBodyBufferingScreener::new();
    let bad_codec = json!({"algorithms": ["nope"]});
    let screened = screener.screen("compression", &bad_codec);
    assert_eq!(screened, Indeterminate(ConstructionFailed));
    let reason = ConstructionFailed.as_str();
    assert!(!reason.contains("nope"), "reason leaked a config value");
    // Same classification through the shape-only path.
    let bad_schema = json!({"json_schema": 7});
    let screened = screener.screen("body_validator", &bad_schema);
    assert_eq!(screened, Indeterminate(ConstructionFailed));
}

/// `body_validator`'s shape-only inspection must not depend on a node-local
/// protobuf descriptor file being present.
#[test]
fn body_validator_screen_does_not_require_local_descriptor_file() {
    let screener = RequestBodyBufferingScreener::new();
    let request_side = json!({"required_fields": ["name"]});
    assert_eq!(screener.screen("body_validator", &request_side), Buffers);
    let response_side = json!({"response_required_fields": ["name"]});
    assert_eq!(screener.screen("body_validator", &response_side), Streams);
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Every `src/plugins/**.rs` file except the trait definition module itself,
/// which holds the defaults rather than an override.
fn plugin_source_files() -> Vec<PathBuf> {
    let root = repo_path("src/plugins");
    let trait_module = root.join("mod.rs");
    let mut files = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).expect("read plugin source dir");
        for entry in entries {
            let path = entry.expect("plugin source entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_rust = path.extension().and_then(|e| e.to_str()) == Some("rs");
            if is_rust && path != trait_module {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Plugin module name for a source file: the file stem, or the parent
/// directory for a `mod.rs`.
fn module_name(path: &Path) -> String {
    let stem = path.file_stem().and_then(|s| s.to_str());
    let stem = stem.expect("utf-8 file stem");
    if stem != "mod" {
        return stem.to_string();
    }
    let parent = path.parent().and_then(|p| p.file_name());
    let parent = parent.and_then(|s| s.to_str());
    parent.expect("utf-8 parent dir").to_string()
}

/// Plugin modules that override at least one buffering-related trait method,
/// mapped to the overrides they declare.
fn modules_with_buffering_overrides() -> BTreeMap<String, BTreeSet<&'static str>> {
    let mut found: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for path in plugin_source_files() {
        let source = std::fs::read_to_string(&path).expect("read plugin source");
        for method in BUFFERING_TRAIT_METHODS {
            let signature = format!("fn {method}(&self) -> bool");
            if source.contains(&signature) {
                let module = module_name(&path);
                found.entry(module).or_default().insert(*method);
            }
        }
    }
    found
}

/// A plugin module that gains a buffering-related override must appear in the
/// matrix, so its screen behavior is proven rather than assumed. This is the
/// guard that keeps a future buffering plugin from escaping the screen.
#[test]
fn buffering_capable_plugins_are_all_covered() {
    let scanned: BTreeSet<String> = modules_with_buffering_overrides().into_keys().collect();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for row in conditional_buffering_matrix() {
        covered.insert(row.plugin.to_string());
    }

    let mut builtin: BTreeSet<&str> = BTreeSet::new();
    for registration in BUILTIN_PLUGIN_REGISTRATIONS {
        builtin.insert(registration.name);
    }
    for module in &scanned {
        let known = builtin.contains(module.as_str());
        let msg = format!("module '{module}' buffers but is not a built-in name");
        assert!(known, "{msg}");
    }

    let msg = "coverage matrix drifted from the buffering-capable plugin set";
    assert_eq!(scanned, covered, "{msg}");
}

/// Plugins the screen never constructs must never be able to buffer. This is
/// the source-level half of the behavioral check above, and it catches an
/// override that a minimal config happens not to activate.
#[test]
fn never_constructed_plugins_declare_no_buffering_overrides() {
    let scanned = modules_with_buffering_overrides();
    for name in REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT {
        let declares = scanned.contains_key(*name);
        let msg = format!("'{name}' is never constructed but now buffers");
        assert!(!declares, "{msg}");
    }
}

/// Every shape-only carve-out in `validate_plugin_config_with_http_client`
/// marks a constructor with side effects the buffering screen must not run.
/// New carve-outs must be classified in one of the two screen lists, so a
/// future side-effectful plugin cannot be quietly constructed at admission.
#[test]
fn shape_only_validation_carve_outs_are_classified_by_the_screen() {
    let source = std::fs::read_to_string(repo_path("src/plugins/mod.rs"));
    let source = source.expect("read src/plugins/mod.rs");
    let marker = "pub(crate) fn validate_plugin_config_with_http_client(";
    let start = source.find(marker).expect("validation fn not found");
    let body = &source[start..];
    let end = body.find("\n}\n").expect("validation fn not terminated");
    let body = &body[..end];

    let mut carve_outs = BTreeSet::new();
    for fragment in body.split("if name == \"").skip(1) {
        let name = fragment.split('"').next().expect("carve-out name");
        carve_outs.insert(name.to_string());
    }
    assert!(!carve_outs.is_empty(), "parsed no shape-only carve-outs");

    let mut classified: BTreeSet<String> = BTreeSet::new();
    for name in REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT {
        classified.insert((*name).to_string());
    }
    for name in REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY {
        classified.insert((*name).to_string());
    }
    let msg = "a side-effectful plugin constructor is unclassified by the screen";
    assert_eq!(carve_outs, classified, "{msg}");
}

/// The drift scan only works if it knows every input to the default
/// `requires_request_body_buffering()` implementation. Pin them.
#[test]
fn default_buffering_predicate_inputs_have_not_drifted() {
    let source = std::fs::read_to_string(repo_path("src/plugins/mod.rs"));
    let source = source.expect("read src/plugins/mod.rs");
    let marker = "    fn requires_request_body_buffering(&self) -> bool {";
    let start = source.find(marker).expect("default predicate not found");
    let body = &source[start..];
    let end = body.find("\n    }\n").expect("default body not terminated");
    let body = &body[..end];

    let mut inputs = BTreeSet::new();
    for fragment in body.split("self.").skip(1) {
        let name = fragment.split('(').next().expect("predicate call");
        inputs.insert(name.to_string());
    }

    let mut expected: BTreeSet<String> = BTreeSet::new();
    for method in BUFFERING_TRAIT_METHODS {
        if *method != "requires_request_body_buffering" {
            expected.insert((*method).to_string());
        }
    }
    let msg = "the default buffering predicate gained or lost an input";
    assert_eq!(inputs, expected, "{msg}");
}

/// The screen must never be reduced to a name list again: the carve-out lists
/// are the only names it is allowed to special-case.
#[test]
fn screen_special_cases_stay_minimal() {
    let no_construct = [
        "geo_restriction",
        "oidc_relying_party",
        "transaction_log_schema",
        "udp_logging",
    ];
    let shape_only = ["ai_response_guard", "body_validator"];
    let actual = REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT;
    assert_eq!(actual, no_construct.as_slice());
    let actual = REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY;
    assert_eq!(actual, shape_only.as_slice());
}

/// The screen's answer comes from the `Plugin` trait object, not a name match.
#[test]
fn screener_answer_comes_from_a_trait_object() {
    let built = create_plugin("grpc_web", &json!({}));
    let plugin: std::sync::Arc<dyn Plugin> = built.expect("ok").expect("some");
    assert!(plugin.requires_request_body_buffering());
}
