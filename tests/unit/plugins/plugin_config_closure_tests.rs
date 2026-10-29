//! Framework-level plugin config contract sweep (issue #6616).
//!
//! `plugin_unknown_key_registry_tests.rs` proves every built-in rejects an
//! unknown ROOT key. This module extends the same guarantee to every nested
//! object, and pins the validate-by-construction contract, for built-ins and
//! compiled custom plugins alike:
//!
//! - **Closure at every depth (M-20).** For each plugin, every example in its
//!   [`PluginConfigContract`] must validate on its own. A probe key is then
//!   injected into each object (the root, object members, and array elements,
//!   at any depth) and validation must fail. Only objects the contract declares
//!   free-form (operator-chosen key names) or opaque (embedded foreign
//!   documents) are exempt, and every declaration must match a node in the
//!   examples so a stale exemption cannot outlive the schema it described.
//! - **Side-effect-free validation (M-21).** Admin, CP, and the runtime-less
//!   `ferrum-edge validate` construct the plugin and drop it. Construction
//!   must therefore neither need a tokio runtime nor spawn onto one; runtime
//!   work belongs in `start_background_tasks` / `commit_background_tasks`.
//!   This pin is deliberately narrow: it observes tokio task spawns
//!   (`num_alive_tasks`) and anything that panics without a runtime. It does
//!   not observe `spawn_blocking`, OS threads, synchronous dials, file
//!   writes, or process-global registration; those remain a documented
//!   constructor contract (`CUSTOM_PLUGINS.md`, the `Plugin` trait docs)
//!   enforced by review.
//!
//! Both checks go through `validate_plugin_config`, the admission entry
//! point. For the few plugins it validates shape-only (`geo_restriction`,
//! `body_validator`, `ai_response_guard`, `ai_transcript_audit`,
//! `udp_logging`, `oidc_relying_party`, `transaction_log_schema`,
//! `serverless_function`) the sweep therefore proves the shape validator,
//! which is what admission enforces; their full constructors are covered by
//! each plugin's own tests.
//!
//! Built-in contracts live in [`super::plugin_config_corpus`]; custom plugins
//! export `config_contract()` (see `custom_plugins/mod.rs`).

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ferrum_edge::plugins::{BUILTIN_PLUGIN_REGISTRATIONS, PluginConfigContract};
use serde_json::{Map, Value};

use super::plugin_config_corpus::builtin_config_contract;
use super::plugin_utils::{basic_auth_test_secret_guard, log_schema_registry_guard};

/// Key injected into nested objects. Deliberately ugly so it cannot collide
/// with a real schema field or a near-miss suggestion.
const PROBE_KEY: &str = "__ferrum_nested_unknown_key_probe__";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    Key(String),
    Index(usize),
}

/// Pattern form of a concrete path: keys by name, array elements as `[]`.
fn render(path: &[Segment]) -> String {
    let mut out = String::new();
    for segment in path {
        match segment {
            Segment::Key(key) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(key);
            }
            Segment::Index(_) => out.push_str("[]"),
        }
    }
    out
}

fn pattern_tokens(pattern: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for part in pattern.split('.') {
        let mut base = part;
        let mut elements = 0;
        while let Some(stripped) = base.strip_suffix("[]") {
            base = stripped;
            elements += 1;
        }
        if !base.is_empty() {
            tokens.push(base.to_string());
        }
        tokens.extend(std::iter::repeat_n("[]".to_string(), elements));
    }
    tokens
}

fn path_tokens(path: &[Segment]) -> Vec<String> {
    path.iter()
        .map(|segment| match segment {
            Segment::Key(key) => key.clone(),
            Segment::Index(_) => "[]".to_string(),
        })
        .collect()
}

fn matches(pattern: &str, path: &[Segment]) -> bool {
    let pattern = pattern_tokens(pattern);
    let path = path_tokens(path);
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(&path)
            .all(|(want, have)| want == have || (want == "*" && have != "[]"))
}

/// Every object node reachable from `value`, the root included, excluding
/// opaque subtrees. Returned with the free-form flag for the node itself. The
/// root is probed here too: `plugin_unknown_key_registry_tests.rs` covers
/// built-in roots, but a custom plugin's root is only covered by this sweep.
fn nested_objects(
    value: &Value,
    contract: &PluginConfigContract,
    path: &mut Vec<Segment>,
    out: &mut Vec<(Vec<Segment>, bool)>,
    matched: &mut BTreeSet<&'static str>,
) {
    if !path.is_empty() && mark_matching(contract.opaque_documents, path, matched) {
        return;
    }
    match value {
        Value::Object(object) => {
            let free_form =
                !path.is_empty() && mark_matching(contract.free_form_objects, path, matched);
            out.push((path.clone(), free_form));
            for (key, child) in object {
                path.push(Segment::Key(key.clone()));
                nested_objects(child, contract, path, out, matched);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(Segment::Index(index));
                nested_objects(child, contract, path, out, matched);
                path.pop();
            }
        }
        _ => {}
    }
}

/// Marks every declaration matching `path`, so overlapping patterns (`a.*`
/// and `a.b`) never leave one reported stale. Returns whether any matched.
fn mark_matching(
    patterns: &'static [&'static str],
    path: &[Segment],
    matched: &mut BTreeSet<&'static str>,
) -> bool {
    let mut any = false;
    for pattern in patterns.iter().filter(|pattern| matches(pattern, path)) {
        matched.insert(*pattern);
        any = true;
    }
    any
}

fn object_at<'a>(value: &'a mut Value, path: &[Segment]) -> &'a mut Map<String, Value> {
    let mut node = value;
    for segment in path {
        node = match segment {
            Segment::Key(key) => node.get_mut(key.as_str()),
            Segment::Index(index) => node.get_mut(*index),
        }
        .expect("path was collected from this value");
    }
    node.as_object_mut().expect("path names an object node")
}

/// Run plugin validation the way offline / admin validation does: ambient
/// `FERRUM_*` isolated (with the `basic_auth` fixture secret), and the
/// log-schema reload bracket held so validation stays a staging no-op. The
/// env lock is taken before the registry guard, as `testing.md` requires.
fn validate(name: &str, config: &Value) -> Result<(), String> {
    let _env = basic_auth_test_secret_guard();
    let _schema = log_schema_registry_guard();
    ferrum_edge::plugins::validate_plugin_config(name, config)
}

fn swept_plugins() -> Vec<(&'static str, PluginConfigContract)> {
    let mut plugins: Vec<_> = BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|registration| {
            (
                registration.name,
                builtin_config_contract(registration.name),
            )
        })
        .collect();
    for name in ferrum_edge::custom_plugins::custom_plugin_names() {
        let contract = ferrum_edge::custom_plugins::custom_plugin_config_contract(name)
            .unwrap_or_else(|| panic!("custom plugin {name:?} has no config contract"));
        plugins.push((name, contract));
    }
    plugins
}

#[test]
fn every_plugin_rejects_unknown_nested_config_keys() {
    let mut invalid_examples = Vec::new();
    let mut accepted = Vec::new();
    let mut stale = Vec::new();
    let mut probes = 0usize;

    for (name, contract) in swept_plugins() {
        assert!(
            !contract.examples.is_empty(),
            "{name}: config contract has no examples"
        );
        let mut matched = BTreeSet::new();
        let mut accepted_here = BTreeSet::new();
        for (index, example) in contract.examples.iter().enumerate() {
            if let Err(error) = validate(name, example) {
                invalid_examples.push(format!("{name} example #{index}: {error}"));
                continue;
            }
            let mut nodes = Vec::new();
            nested_objects(
                example,
                &contract,
                &mut Vec::new(),
                &mut nodes,
                &mut matched,
            );
            for (path, free_form) in nodes {
                if free_form {
                    continue;
                }
                let mut probed = example.clone();
                let object = object_at(&mut probed, &path);
                // Probe with a sibling-shaped value when there is one, so a
                // rejection proves the KEY is refused rather than a
                // value-type check on a map that never validates its keys.
                let value = object.values().next().cloned().unwrap_or(Value::Bool(true));
                object.insert(PROBE_KEY.to_string(), value);
                probes += 1;
                if validate(name, &probed).is_ok() {
                    let rendered = render(&path);
                    accepted_here.insert(if rendered.is_empty() {
                        "<root>".to_string()
                    } else {
                        rendered
                    });
                }
            }
        }
        accepted.extend(
            accepted_here
                .into_iter()
                .map(|path| format!("{name}: {path}")),
        );
        for pattern in contract
            .free_form_objects
            .iter()
            .chain(contract.opaque_documents)
        {
            if !matched.contains(pattern) {
                stale.push(format!("{name}: {pattern}"));
            }
        }
    }

    assert!(
        invalid_examples.is_empty(),
        "config contract examples must validate on their own:\n  {}",
        invalid_examples.join("\n  ")
    );
    assert!(
        accepted.is_empty(),
        "these nested config objects accept an unknown key (close them with \
         `reject_unknown_keys`, or declare an operator-named map free-form):\n  {}",
        accepted.join("\n  ")
    );
    assert!(
        stale.is_empty(),
        "free-form / opaque declarations that match no example node:\n  {}",
        stale.join("\n  ")
    );
    assert!(probes > 0, "the closure sweep injected no probes");
}

/// Offline `ferrum-edge validate` constructs plugins before any tokio runtime
/// exists, and admin / CP validation constructs and drops them on a serving
/// runtime. A constructor that spawns would panic in the first case and leak
/// a worker that outlives its dropped instance in the second.
#[test]
fn plugin_validation_needs_no_runtime_and_spawns_no_tasks() {
    let mut panicked = Vec::new();
    let mut spawned = Vec::new();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");

    for (name, contract) in swept_plugins() {
        for (index, example) in contract.examples.iter().enumerate() {
            // Under a `panic = "abort"` test profile this aborts the binary
            // instead of collecting the list below; still a failure.
            if catch_unwind(AssertUnwindSafe(|| validate(name, example))).is_err() {
                panicked.push(format!("{name} example #{index}"));
                continue;
            }
            let delta = runtime.block_on(async {
                let metrics = tokio::runtime::Handle::current().metrics();
                let before = metrics.num_alive_tasks();
                let _ = validate(name, example);
                metrics.num_alive_tasks().saturating_sub(before)
            });
            if delta != 0 {
                spawned.push(format!("{name} example #{index}: {delta} task(s)"));
            }
        }
    }

    assert!(
        panicked.is_empty(),
        "plugin validation panicked without a tokio runtime (constructor needs one):\n  {}",
        panicked.join("\n  ")
    );
    assert!(
        spawned.is_empty(),
        "plugin validation spawned runtime tasks (move them to \
         `start_background_tasks`):\n  {}",
        spawned.join("\n  ")
    );
}

#[test]
fn path_patterns_match_array_elements_and_wildcards() {
    let path = [
        Segment::Key("rules".to_string()),
        Segment::Index(3),
        Segment::Key("match".to_string()),
    ];
    assert_eq!(render(&path), "rules[].match");
    assert!(matches("rules[].match", &path));
    assert!(!matches("rules.match", &path));
    assert!(!matches("rules[]", &path));

    let map_value = [
        Segment::Key("servers".to_string()),
        Segment::Key("tools".to_string()),
    ];
    assert!(matches("servers.*", &map_value));
    let element = [Segment::Key("servers".to_string()), Segment::Index(0)];
    assert!(!matches("servers.*", &element));

    let nested = [
        Segment::Key("matrix".to_string()),
        Segment::Index(0),
        Segment::Index(1),
    ];
    assert!(matches("matrix[][]", &nested));
}
