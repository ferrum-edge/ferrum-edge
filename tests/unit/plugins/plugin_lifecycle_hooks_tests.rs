//! `Plugin::lifecycle_hooks` declarations and the dispatchers that honour them
//! (issue #6615).
//!
//! Dispatchers skip `on_request_received`, `before_proxy`, `after_proxy`, and
//! `log` for a plugin whose declaration omits the hook, instead of awaiting a
//! boxed no-op. That is sound only while a declaration names every one of
//! those hooks the plugin overrides, so the drift guard below re-derives each
//! built-in's overridden hooks from its source and requires an exact match.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::Utc;
use ferrum_edge::_test_support::{
    run_after_proxy_hooks_reject_for_test, run_before_proxy_hooks_for_test,
    set_grpc_deadline_budget_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::{
    BUILTIN_PLUGIN_REGISTRATIONS, Plugin, PluginHooks, PluginResult, RequestContext,
    TransactionSummary, create_plugin, log_with_mirror,
};
use serde_json::json;

use super::{make_plugin_config_with_json, make_proxy, minimal_plugin_config};

/// Trait methods covered by [`PluginHooks`], with the flag each one needs.
/// `log_with_mesh_key`'s default calls `log`, so either override needs `LOG`.
const GATED_HOOKS: &[(&str, &str)] = &[
    ("on_request_received", "ON_REQUEST_RECEIVED"),
    ("before_proxy", "BEFORE_PROXY"),
    ("after_proxy", "AFTER_PROXY"),
    ("log", "LOG"),
    ("log_with_mesh_key", "LOG"),
];

const ALL_FLAGS: &[&str] = &["ON_REQUEST_RECEIVED", "BEFORE_PROXY", "AFTER_PROXY", "LOG"];

/// Registered built-ins whose implementation overrides all four hooks, so a
/// runtime `PluginHooks::ALL` is their exact declaration rather than a
/// missing one.
const BUILTINS_IMPLEMENTING_EVERY_GATED_HOOK: &[&str] =
    &["otel_tracing", "transaction_debugger", "workload_metrics"];

struct PluginImplBlock {
    label: String,
    body: String,
    /// Built-ins must declare. Cache-internal composition plugins may keep the
    /// `ALL` default, but a declaration they do make must be exact.
    requires_declaration: bool,
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("plugin source directory is readable") {
        let path = entry.expect("plugin source entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every column-zero `impl Plugin for` block and every `impl_auth_plugin!`
/// invocation under `src/plugins/`, plus the cache-internal composition
/// plugins and instance wrapper in `src/plugin_cache.rs`. Only column-zero
/// blocks are production implementations; test modules indent theirs.
fn production_plugin_impl_blocks() -> Vec<PluginImplBlock> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_sources(&manifest.join("src/plugins"), &mut files);
    files.sort();
    let mut sources: Vec<(PathBuf, bool)> = files.into_iter().map(|file| (file, true)).collect();
    sources.push((manifest.join("src/plugin_cache.rs"), false));

    let mut blocks = Vec::new();
    for (file, requires_declaration) in sources {
        let source = std::fs::read_to_string(&file).expect("plugin source is readable");
        let relative = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&file)
            .display()
            .to_string();
        for marker in [
            "\nimpl Plugin for ",
            "\nimpl super::Plugin for ",
            "\nimpl crate::plugins::Plugin for ",
        ] {
            for (start, _) in source.match_indices(marker) {
                let header_end = source[start + 1..]
                    .find('\n')
                    .map(|offset| start + 1 + offset)
                    .expect("impl header line ends");
                let header = &source[start + 1..header_end];
                let body_end = source[header_end..]
                    .find("\n}\n")
                    .map(|offset| header_end + offset)
                    .unwrap_or_else(|| {
                        panic!("{relative}: `{header}` is not closed by a column-zero `}}`")
                    });
                blocks.push(PluginImplBlock {
                    label: format!("{relative}: {header}"),
                    body: source[header_end..body_end].to_string(),
                    requires_declaration,
                });
            }
        }
        for (start, _) in source.match_indices("\nauth_flow::impl_auth_plugin!(\n") {
            let body_start = start + "\nauth_flow::impl_auth_plugin!(\n".len();
            let body_end = source[body_start..]
                .find("\n);\n")
                .map(|offset| body_start + offset)
                .unwrap_or_else(|| panic!("{relative}: impl_auth_plugin! is not closed"));
            blocks.push(PluginImplBlock {
                label: format!("{relative}: impl_auth_plugin!"),
                body: source[body_start..body_end].to_string(),
                requires_declaration,
            });
        }
    }
    blocks
}

/// Methods defined directly in the block (four-space-indented items).
fn block_method_names(block: &PluginImplBlock) -> BTreeSet<String> {
    block
        .body
        .lines()
        .filter_map(|line| {
            line.strip_prefix("    fn ")
                .or_else(|| line.strip_prefix("    async fn "))
        })
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect()
}

/// The flags named in the block's `fn lifecycle_hooks` body, or `None` when
/// the block does not declare one.
fn declared_flags(block: &PluginImplBlock) -> Option<BTreeSet<String>> {
    let start = block.body.find("    fn lifecycle_hooks(&self)")?;
    let rest = &block.body[start..];
    let end = rest
        .find("\n    }")
        .unwrap_or_else(|| panic!("{}: unterminated lifecycle_hooks", block.label));
    let declaration = &rest[..end];
    let mut flags = BTreeSet::new();
    for (index, _) in declaration.match_indices("PluginHooks::") {
        let flag: String = declaration[index + "PluginHooks::".len()..]
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || *c == '_')
            .collect();
        match flag.as_str() {
            "NONE" => {}
            "ALL" => flags.extend(ALL_FLAGS.iter().map(|flag| (*flag).to_string())),
            _ => {
                assert!(
                    ALL_FLAGS.contains(&flag.as_str()),
                    "{}: unknown PluginHooks flag {flag}",
                    block.label
                );
                flags.insert(flag);
            }
        }
    }
    Some(flags)
}

#[test]
fn every_builtin_plugin_impl_declares_exactly_the_lifecycle_hooks_it_overrides() {
    let blocks = production_plugin_impl_blocks();
    let builtin_blocks = blocks
        .iter()
        .filter(|block| block.requires_declaration)
        .count();
    assert!(
        builtin_blocks >= 80 && blocks.len() > builtin_blocks,
        "the source scan found {builtin_blocks} built-in and {} cache-internal plugin impls; it \
         no longer sees the plugin tree",
        blocks.len() - builtin_blocks
    );

    for block in &blocks {
        // A macro expanded inside the block could define a gated hook this
        // scan cannot see, leaving it out of the declaration and never run.
        for line in block.body.lines() {
            let trimmed = line.trim_start();
            let is_item_macro = line.starts_with("    ")
                && !line.starts_with("     ")
                && trimmed.split_once('!').is_some_and(|(path, rest)| {
                    !path.is_empty()
                        && path
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
                        && rest.trim_start().starts_with(['(', '{', '['])
                });
            assert!(
                !is_item_macro,
                "{}: item macro `{trimmed}` inside a Plugin impl hides its methods from the \
                 lifecycle-hook drift guard",
                block.label
            );
        }

        let methods = block_method_names(block);
        let overridden: BTreeSet<String> = GATED_HOOKS
            .iter()
            .filter(|(hook, _)| methods.contains(*hook))
            .map(|(_, flag)| (*flag).to_string())
            .collect();
        let Some(declared) = declared_flags(block) else {
            // The `ALL` default runs every hook, so an undeclared
            // cache-internal plugin is safe (merely unoptimized).
            assert!(
                !block.requires_declaration,
                "{}: built-in plugins must override `lifecycle_hooks` so dispatchers skip the \
                 hooks they do not implement; it overrides {overridden:?}",
                block.label
            );
            continue;
        };
        assert_eq!(
            declared, overridden,
            "{}: `lifecycle_hooks` must name exactly the gated hooks this impl overrides. A \
             missing flag means that hook is never called.",
            block.label
        );
    }
}

#[tokio::test]
async fn every_registered_builtin_reports_a_narrow_declaration_at_runtime() {
    // Covers built-ins whose `impl Plugin` lives in a shape the source scan
    // does not read: an undeclared one still runs every hook (safe), but
    // silently forgoes the skipped boxed calls.
    // Same guards (and lock order) as the doc-parity registration sweeps.
    let _basic_auth_secret = super::plugin_utils::basic_auth_test_secret_guard();
    let _registry = super::plugin_utils::log_schema_registry_guard();
    for registration in BUILTIN_PLUGIN_REGISTRATIONS {
        let name = registration.name;
        let mut config = minimal_plugin_config(name);
        if name == "proxy_alerts" {
            // Mirrors the doc-parity sweep: a stream rule selects the
            // stream-hook capability; the gated-hook declaration is fixed.
            config["rules"] = json!([{
                "name": "disconnects",
                "type": "stream_disconnect_cause",
                "causes": ["backend_error"],
                "threshold_count": 1,
                "channels": ["ops"]
            }]);
        }
        let plugin = create_plugin(name, &config)
            .unwrap_or_else(|e| panic!("create_plugin({name}) failed: {e}"))
            .unwrap_or_else(|| panic!("create_plugin({name}) returned None"));
        let hooks = plugin.lifecycle_hooks();
        if BUILTINS_IMPLEMENTING_EVERY_GATED_HOOK.contains(&name) {
            assert_eq!(
                hooks,
                PluginHooks::ALL,
                "{name} implements every gated hook"
            );
        } else {
            assert_ne!(
                hooks,
                PluginHooks::ALL,
                "{name} reports PluginHooks::ALL: declare the hooks it implements, or list it \
                 in BUILTINS_IMPLEMENTING_EVERY_GATED_HOOK"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test plugins
// ---------------------------------------------------------------------------

/// Implements every gated hook: each rejects (or counts, for `log`). The
/// declaration is configurable so tests can prove that dispatchers honour it.
struct ProbePlugin {
    declared: Option<PluginHooks>,
    logs: AtomicUsize,
}

impl ProbePlugin {
    fn declaring(declared: PluginHooks) -> Arc<Self> {
        Arc::new(Self {
            declared: Some(declared),
            logs: AtomicUsize::new(0),
        })
    }

    fn undeclared() -> Arc<Self> {
        Arc::new(Self {
            declared: None,
            logs: AtomicUsize::new(0),
        })
    }
}

fn reject(status_code: u16) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body: "probe".to_string(),
        headers: HashMap::new(),
    }
}

#[async_trait]
impl Plugin for ProbePlugin {
    fn name(&self) -> &str {
        "lifecycle_hook_probe"
    }

    fn lifecycle_hooks(&self) -> PluginHooks {
        self.declared.unwrap_or(PluginHooks::ALL)
    }

    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        reject(418)
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        reject(451)
    }

    async fn log(&self, _summary: &TransactionSummary) {
        self.logs.fetch_add(1, Ordering::SeqCst);
    }
}

/// A custom plugin that overrides nothing, including the declaration.
struct UndeclaredNoopPlugin;

#[async_trait]
impl Plugin for UndeclaredNoopPlugin {
    fn name(&self) -> &str {
        "undeclared_noop"
    }
}

fn request() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    )
}

#[test]
fn a_plugin_without_a_declaration_keeps_every_hook() {
    assert_eq!(UndeclaredNoopPlugin.lifecycle_hooks(), PluginHooks::ALL);
    for flag in [
        PluginHooks::ON_REQUEST_RECEIVED,
        PluginHooks::BEFORE_PROXY,
        PluginHooks::AFTER_PROXY,
        PluginHooks::LOG,
    ] {
        assert!(PluginHooks::ALL.contains(flag));
        assert!(!PluginHooks::NONE.contains(flag));
    }
    assert!(PluginHooks::NONE.contains(PluginHooks::NONE));
}

// ---------------------------------------------------------------------------
// Dispatchers honour the declaration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn before_proxy_dispatch_skips_a_plugin_that_does_not_declare_it() {
    for (plugin, expected_reject) in [
        (ProbePlugin::undeclared(), true),
        (ProbePlugin::declaring(PluginHooks::BEFORE_PROXY), true),
        (ProbePlugin::declaring(PluginHooks::AFTER_PROXY), false),
        (ProbePlugin::declaring(PluginHooks::NONE), false),
    ] {
        let declared = plugin.lifecycle_hooks();
        let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];
        let mut ctx = request();
        let mut headers = HashMap::new();
        let result = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut headers).await;
        assert_eq!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 418,
                    ..
                }
            ),
            expected_reject,
            "before_proxy dispatch for a plugin declaring {declared:?}"
        );
    }
}

#[tokio::test]
async fn after_proxy_dispatch_skips_a_plugin_that_does_not_declare_it() {
    for (plugin, expected_reject) in [
        (ProbePlugin::undeclared(), true),
        (ProbePlugin::declaring(PluginHooks::AFTER_PROXY), true),
        (ProbePlugin::declaring(PluginHooks::BEFORE_PROXY), false),
        (ProbePlugin::declaring(PluginHooks::NONE), false),
    ] {
        let declared = plugin.lifecycle_hooks();
        let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];
        let mut ctx = request();
        let mut headers = HashMap::new();
        let rejection =
            run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers).await;
        assert_eq!(
            rejection.is_some_and(|(status, _, _)| status == 451),
            expected_reject,
            "after_proxy dispatch for a plugin declaring {declared:?}"
        );
    }
}

/// A skipped `after_proxy` must still refuse an elapsed pre-commitment bound,
/// exactly as awaiting the default no-op did: the bound is checked before the
/// hook is polled.
#[tokio::test]
async fn a_skipped_after_proxy_hook_still_observes_an_elapsed_deadline() {
    async fn outcome(plugin: Arc<dyn Plugin>) -> Option<(u16, HashMap<String, String>)> {
        let plugins = vec![plugin];
        let mut ctx = request();
        set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
        let mut headers = HashMap::new();
        run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut headers)
            .await
            .map(|(status, _, headers)| (status, headers))
    }

    let awaited_noop = outcome(Arc::new(UndeclaredNoopPlugin)).await;
    let skipped = outcome(ProbePlugin::declaring(PluginHooks::NONE)).await;
    assert!(
        awaited_noop.is_some(),
        "awaiting a default no-op after_proxy at an elapsed RPC deadline selects the deadline \
         terminal"
    );
    assert_eq!(
        skipped, awaited_noop,
        "skipping an undeclared after_proxy must select the same terminal as awaiting the no-op"
    );
}

#[tokio::test]
async fn log_dispatch_skips_a_plugin_that_does_not_declare_it() {
    let undeclared = ProbePlugin::undeclared();
    let declared = ProbePlugin::declaring(PluginHooks::LOG);
    let omitted = ProbePlugin::declaring(PluginHooks::BEFORE_PROXY | PluginHooks::AFTER_PROXY);
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        undeclared.clone(),
        declared.clone(),
        omitted.clone(),
        Arc::new(UndeclaredNoopPlugin),
    ];
    let ctx = request();
    let summary = TransactionSummary {
        response_status_code: 200,
        ..Default::default()
    };
    log_with_mirror(&plugins, &summary, &ctx).await;
    assert_eq!(undeclared.logs.load(Ordering::SeqCst), 1);
    assert_eq!(declared.logs.load(Ordering::SeqCst), 1);
    assert_eq!(
        omitted.logs.load(Ordering::SeqCst),
        0,
        "a plugin whose declaration omits LOG is not logged to"
    );
}

// ---------------------------------------------------------------------------
// Instance wrapper (priority_override / trigger)
// ---------------------------------------------------------------------------

const NS: &str = "ferrum";

fn published_request_transformer(
    priority_override: Option<u16>,
    trigger: Option<serde_json::Value>,
) -> Arc<dyn Plugin> {
    let mut plugin_config = make_plugin_config_with_json(
        "stamp",
        "request_transformer",
        json!({"rules": [{
            "operation": "add", "target": "header", "key": "x-stamp", "value": "1"
        }]}),
        PluginScope::Proxy,
        Some("api"),
    );
    plugin_config.priority_override = priority_override;
    plugin_config.trigger =
        trigger.map(|trigger| serde_json::from_value(trigger).expect("trigger parses"));
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy("api", "/api", vec!["stamp"])],
        plugin_configs: vec![plugin_config],
        loaded_at: Utc::now(),
        ..Default::default()
    };
    let cache = PluginCache::new(&config).expect("plugin cache builds");
    let plugins = cache.get_plugins(NS, "api");
    assert_eq!(plugins.len(), 1, "one published instance");
    Arc::clone(&plugins[0])
}

#[tokio::test]
async fn a_priority_only_wrapper_reports_the_wrapped_plugins_declaration() {
    let wrapped = published_request_transformer(Some(3001), None);
    assert_eq!(wrapped.priority(), 3001, "the instance is wrapped");
    assert_eq!(
        wrapped.lifecycle_hooks(),
        PluginHooks::BEFORE_PROXY,
        "a priority override forwards every hook unchanged"
    );
}

#[tokio::test]
async fn a_triggered_wrapper_keeps_every_hook_dispatched() {
    // The trigger decision is taken and memoized inside the wrapper's own
    // hooks (normally `on_request_received`), which `request_transformer`
    // does not implement, so a triggered instance must not be skipped.
    let triggered = published_request_transformer(
        None,
        Some(json!({"when": {"all": [{"match": {"method": ["POST"]}}]}})),
    );
    assert_eq!(triggered.lifecycle_hooks(), PluginHooks::ALL);
}

#[tokio::test]
async fn builtin_declarations_are_shared_across_instances_of_a_type() {
    let mut by_name: BTreeMap<&str, PluginHooks> = BTreeMap::new();
    for name in ["cors", "http_logging", "key_auth", "rate_limiting"] {
        let config = minimal_plugin_config(name);
        let plugin = create_plugin(name, &config)
            .unwrap_or_else(|e| panic!("create_plugin({name}) failed: {e}"))
            .unwrap_or_else(|| panic!("create_plugin({name}) returned None"));
        by_name.insert(name, plugin.lifecycle_hooks());
    }
    assert_eq!(
        by_name["cors"],
        PluginHooks::ON_REQUEST_RECEIVED | PluginHooks::AFTER_PROXY
    );
    assert_eq!(by_name["http_logging"], PluginHooks::LOG);
    assert_eq!(by_name["key_auth"], PluginHooks::BEFORE_PROXY);
    assert!(!by_name["rate_limiting"].contains(PluginHooks::LOG));
}
