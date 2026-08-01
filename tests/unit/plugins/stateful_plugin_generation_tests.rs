//! Stable ownership of stateful plugin protections across plugin-cache
//! generations and duplicate effective instances (GHSA-wmqm-6mxj-gm9p).
//!
//! The protections covered here are owned by a stable policy identity
//! (`namespace` + plugin-config id) rather than by whichever plugin instance a
//! rebuild happened to construct:
//!
//! * `tcp_connection_throttle` live-connection accounting;
//! * local-mode `request_deduplication` active leases and retained completions;
//! * `load_testing` run admission.
//!
//! Every test uses a policy id unique to that test, because the registries are
//! process-scoped and the unit suite runs tests in parallel.

use chrono::Utc;
use ferrum_edge::_test_support::{
    load_testing_with_policy_identity_for_test, request_deduplication_backdate_inflight_for_test,
    request_deduplication_with_instance_id_for_test,
    request_deduplication_with_policy_identity_for_test,
    set_response_presentation_policy_digest_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{
    BackendScheme, GatewayConfig, PluginConfig, PluginScope, Proxy, default_namespace,
};
use ferrum_edge::plugins::load_testing::LoadTesting;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, StreamConnectionContext,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// ── shared config scaffolding ───────────────────────────────────────────────

fn associations(plugin_ids: &[&str]) -> Vec<Value> {
    plugin_ids
        .iter()
        .map(|plugin_config_id| json!({"plugin_config_id": plugin_config_id}))
        .collect()
}

fn http_proxy(id: &str, plugin_ids: &[&str]) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "name": format!("proxy {id}"),
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http",
        "plugins": associations(plugin_ids),
    }))
    .expect("http proxy fixture must deserialize")
}

fn tcp_proxy(id: &str, plugin_ids: &[&str]) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "name": format!("proxy {id}"),
        "listen_port": 15432,
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "tcp",
        "plugins": associations(plugin_ids),
    }))
    .expect("tcp proxy fixture must deserialize")
}

fn plugin_config(
    id: &str,
    plugin_name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    config: Value,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn gateway_config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    let mut config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        plugin_configs,
        loaded_at: Utc::now(),
        ..Default::default()
    };
    config.resolve_dispatch_kind();
    config
}

fn plugin_named(cache: &PluginCache, proxy_id: &str, plugin_name: &str) -> Arc<dyn Plugin> {
    let plugins = cache.get_plugins(&default_namespace(), proxy_id);
    plugins
        .iter()
        .find(|plugin| plugin.name() == plugin_name)
        .cloned()
        .unwrap_or_else(|| panic!("cache generation must expose a {plugin_name} instance"))
}

fn plugin_count(cache: &PluginCache, proxy_id: &str, plugin_name: &str) -> usize {
    cache
        .get_plugins(&default_namespace(), proxy_id)
        .iter()
        .filter(|plugin| plugin.name() == plugin_name)
        .count()
}

fn reject_status(result: &PluginResult) -> Option<u16> {
    match result {
        PluginResult::Reject { status_code, .. } => Some(*status_code),
        _ => None,
    }
}

fn replay_status(result: &PluginResult) -> Option<u16> {
    match result {
        PluginResult::RejectBinary { status_code, .. } => Some(*status_code),
        _ => None,
    }
}

// ── tcp_connection_throttle ─────────────────────────────────────────────────

fn throttle_config(id: &str, proxy_id: &str, max_connections_per_key: u64) -> PluginConfig {
    plugin_config(
        id,
        "tcp_connection_throttle",
        PluginScope::Proxy,
        Some(proxy_id),
        json!({"max_connections_per_key": max_connections_per_key}),
    )
}

fn throttle(cache: &PluginCache, proxy_id: &str) -> Arc<dyn Plugin> {
    plugin_named(cache, proxy_id, "tcp_connection_throttle")
}

fn stream_ctx(proxy_id: &str, ip: &str) -> StreamConnectionContext {
    StreamConnectionContext::new(
        ip.to_string(),
        ip.to_string(),
        proxy_id.to_string(),
        Some(format!("TCP Proxy {proxy_id}")),
        15432,
        BackendScheme::Tcp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    )
}

/// Admit one connection through `plugin`, returning the context that owns the
/// permit. Dropping (or explicitly releasing) that context releases the slot.
async fn admit(
    plugin: &Arc<dyn Plugin>,
    proxy_id: &str,
    ip: &str,
) -> Option<StreamConnectionContext> {
    let mut ctx = stream_ctx(proxy_id, ip);
    let verdict = plugin.on_stream_connect(&mut ctx).await;
    match verdict {
        PluginResult::Continue => Some(ctx),
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 429, "throttle refusal must be 429");
            None
        }
        other => panic!("unexpected throttle verdict: {other:?}"),
    }
}

#[tokio::test]
async fn tcp_throttle_live_connection_survives_a_compatible_reload() {
    let ip = "10.1.0.7";
    let config = gateway_config(
        vec![tcp_proxy("tcp-live", &["thr-live"])],
        vec![throttle_config("thr-live", "tcp-live", 1)],
    );
    let cache = PluginCache::new(&config).expect("baseline throttle generation must admit");
    let held = admit(&throttle(&cache, "tcp-live"), "tcp-live", ip).await;
    assert!(held.is_some(), "first connection must be admitted");

    // A byte-identical reload rebuilds the instance; the accounting must not.
    cache
        .rebuild(&config)
        .expect("identical throttle config must reload");
    let replacement = throttle(&cache, "tcp-live");
    let refused = admit(&replacement, "tcp-live", ip).await;
    assert!(
        refused.is_none(),
        "a replacement generation must still see the live permit and refuse the excess connection"
    );

    // The retired generation's permit releases against the same shared state,
    // so the replacement immediately regains the slot.
    drop(held);
    let readmitted = admit(&replacement, "tcp-live", ip).await;
    assert!(
        readmitted.is_some(),
        "a late release from the retired generation must free the slot for the replacement"
    );
}

#[tokio::test]
async fn tcp_throttle_limit_increase_admits_more_and_decrease_admits_none_until_below() {
    let ip = "10.2.0.9";
    let start = gateway_config(
        vec![tcp_proxy("tcp-limit", &["thr-limit"])],
        vec![throttle_config("thr-limit", "tcp-limit", 1)],
    );
    let cache = PluginCache::new(&start).expect("baseline throttle generation must admit");
    let first = admit(&throttle(&cache, "tcp-limit"), "tcp-limit", ip).await;
    assert!(first.is_some(), "first connection must be admitted");

    // Raising the limit counts the already-live permit rather than restarting.
    let raised = gateway_config(
        vec![tcp_proxy("tcp-limit", &["thr-limit"])],
        vec![throttle_config("thr-limit", "tcp-limit", 3)],
    );
    cache.rebuild(&raised).expect("raised limit must reload");
    let raised_plugin = throttle(&cache, "tcp-limit");
    let second = admit(&raised_plugin, "tcp-limit", ip).await;
    assert!(second.is_some(), "second connection fits the raised limit");
    let third = admit(&raised_plugin, "tcp-limit", ip).await;
    assert!(third.is_some(), "third connection fits the raised limit");
    let fourth = admit(&raised_plugin, "tcp-limit", ip).await;
    assert!(
        fourth.is_none(),
        "the raised limit is still a limit: the fourth connection must be refused"
    );

    // Lowering the limit below the live count admits nothing new; it does not
    // reset the accounting and it does not tear down live connections.
    cache.rebuild(&start).expect("lowered limit must reload");
    let lowered = throttle(&cache, "tcp-limit");
    let over_limit = admit(&lowered, "tcp-limit", ip).await;
    assert!(
        over_limit.is_none(),
        "no new connection may be admitted while the live count exceeds the lowered limit"
    );

    drop(third);
    let still_over = admit(&lowered, "tcp-limit", ip).await;
    assert!(
        still_over.is_none(),
        "still above the lowered limit after one release"
    );
    drop(second);
    let at_limit = admit(&lowered, "tcp-limit", ip).await;
    assert!(
        at_limit.is_none(),
        "still at the lowered limit after two releases"
    );
    drop(first);
    let below_limit = admit(&lowered, "tcp-limit", ip).await;
    assert!(
        below_limit.is_some(),
        "once below the lowered limit a new connection is admitted"
    );
}

#[tokio::test]
async fn tcp_throttle_moved_policy_scope_keeps_its_accounting() {
    let ip = "10.3.0.4";
    let scoped = gateway_config(
        vec![tcp_proxy("tcp-move", &["thr-move"])],
        vec![throttle_config("thr-move", "tcp-move", 1)],
    );
    let cache = PluginCache::new(&scoped).expect("proxy-scoped throttle must admit");
    let held = admit(&throttle(&cache, "tcp-move"), "tcp-move", ip).await;
    assert!(held.is_some(), "first connection must be admitted");

    // Same resource id, moved from proxy scope to global scope.
    let moved = gateway_config(
        vec![tcp_proxy("tcp-move", &[])],
        vec![plugin_config(
            "thr-move",
            "tcp_connection_throttle",
            PluginScope::Global,
            None,
            json!({"max_connections_per_key": 1}),
        )],
    );
    cache
        .rebuild(&moved)
        .expect("moved throttle scope must reload");
    let after_move = admit(&throttle(&cache, "tcp-move"), "tcp-move", ip).await;
    assert!(
        after_move.is_none(),
        "a scope move that keeps the resource id must keep the live-connection accounting"
    );
    drop(held);
}

#[tokio::test]
async fn tcp_throttle_removed_policy_late_release_cannot_corrupt_a_replacement() {
    let ip = "10.4.0.2";
    let before = gateway_config(
        vec![tcp_proxy("tcp-swap", &["thr-old"])],
        vec![throttle_config("thr-old", "tcp-swap", 1)],
    );
    let cache = PluginCache::new(&before).expect("baseline throttle generation must admit");
    let retired = admit(&throttle(&cache, "tcp-swap"), "tcp-swap", ip).await;
    assert!(retired.is_some(), "first connection must be admitted");

    // The old policy is removed and a different policy takes its place.
    let after = gateway_config(
        vec![tcp_proxy("tcp-swap", &["thr-new"])],
        vec![throttle_config("thr-new", "tcp-swap", 1)],
    );
    cache
        .rebuild(&after)
        .expect("replacement policy must reload");
    let replacement = throttle(&cache, "tcp-swap");

    // The replacement owns an independent domain, so its own budget applies.
    let live = admit(&replacement, "tcp-swap", ip).await;
    assert!(
        live.is_some(),
        "the replacement policy starts with its own empty accounting"
    );
    let excess = admit(&replacement, "tcp-swap", ip).await;
    assert!(
        excess.is_none(),
        "the replacement policy still enforces its own limit"
    );

    // The removed policy's late release must not credit the replacement.
    drop(retired);
    let after_late_release = admit(&replacement, "tcp-swap", ip).await;
    assert!(
        after_late_release.is_none(),
        "a late release from a removed policy must not free a slot in another policy"
    );
    drop(live);
    let after_own_release = admit(&replacement, "tcp-swap", ip).await;
    assert!(
        after_own_release.is_some(),
        "the replacement's own release frees its own slot"
    );
}

#[tokio::test]
async fn tcp_throttle_same_name_policies_on_one_proxy_stay_independent() {
    let ip = "10.5.0.1";
    let config = gateway_config(
        vec![tcp_proxy("tcp-dual", &["thr-a", "thr-b"])],
        vec![
            throttle_config("thr-a", "tcp-dual", 1),
            throttle_config("thr-b", "tcp-dual", 5),
        ],
    );
    let cache = PluginCache::new(&config).expect("two throttle policies must admit");
    assert_eq!(
        plugin_count(&cache, "tcp-dual", "tcp_connection_throttle"),
        2,
        "two distinct throttle policies remain two effective instances"
    );
    let plugins = cache.get_plugins(&default_namespace(), "tcp-dual");
    let throttles: Vec<Arc<dyn Plugin>> = plugins
        .iter()
        .filter(|plugin| plugin.name() == "tcp_connection_throttle")
        .cloned()
        .collect();

    // Distinct policy ids are distinct protection domains, and the chain is
    // conjunctive: the strictest policy decides.
    let mut ctx = stream_ctx("tcp-dual", ip);
    for plugin in &throttles {
        let verdict = plugin.on_stream_connect(&mut ctx).await;
        assert!(matches!(verdict, PluginResult::Continue));
    }
    let mut second = stream_ctx("tcp-dual", ip);
    let mut refusals = 0usize;
    for plugin in &throttles {
        let verdict = plugin.on_stream_connect(&mut second).await;
        if let Some(status) = reject_status(&verdict) {
            assert_eq!(status, 429);
            refusals += 1;
            break;
        }
    }
    assert_eq!(
        refusals, 1,
        "the stricter of two same-name policies must refuse the second connection"
    );
}

#[tokio::test]
async fn tcp_throttle_unrelated_proxies_keep_separate_budgets_across_reload() {
    let ip = "10.6.0.1";
    let config = gateway_config(
        vec![
            tcp_proxy("tcp-x", &["thr-x"]),
            tcp_proxy("tcp-y", &["thr-y"]),
        ],
        vec![
            throttle_config("thr-x", "tcp-x", 1),
            throttle_config("thr-y", "tcp-y", 1),
        ],
    );
    let cache = PluginCache::new(&config).expect("two proxies must admit");
    let held_x = admit(&throttle(&cache, "tcp-x"), "tcp-x", ip).await;
    assert!(held_x.is_some(), "proxy x admits its connection");

    cache
        .rebuild(&config)
        .expect("identical config must reload");
    let on_y = admit(&throttle(&cache, "tcp-y"), "tcp-y", ip).await;
    assert!(
        on_y.is_some(),
        "an unrelated proxy's policy must not inherit another proxy's live count"
    );
    let on_x = admit(&throttle(&cache, "tcp-x"), "tcp-x", ip).await;
    assert!(
        on_x.is_none(),
        "the original proxy's policy still counts its own live connection"
    );
    drop(held_x);
}

// ── request_deduplication (local mode) ──────────────────────────────────────

const DEDUP_PRESENTATION_DIGEST: Option<[u8; 32]> = Some([0x5a; 32]);
const DEDUP_HEADER: &str = "idempotency-key";

fn dedup_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/payments".to_string(),
    );
    set_response_presentation_policy_digest_for_test(&mut ctx, DEDUP_PRESENTATION_DIGEST);
    ctx
}

fn dedup_without_identity(config_id: &str) -> RequestDeduplication {
    request_deduplication_with_instance_id_for_test(
        &json!({}),
        PluginHttpClient::default(),
        config_id,
    )
    .expect("identityless construction must succeed")
}

fn dedup_generation(namespace: &str, config_id: &str, config: Value) -> RequestDeduplication {
    request_deduplication_with_policy_identity_for_test(
        &config,
        PluginHttpClient::default(),
        namespace,
        config_id,
    )
    .expect("request_deduplication generation must construct")
}

/// Run one lookup and return the verdict plus the context that owns any lease
/// the lookup acquired.
async fn dedup_lookup(
    plugin: &dyn Plugin,
    header_name: &str,
    key: &str,
) -> (PluginResult, RequestContext) {
    let mut ctx = dedup_ctx();
    let mut headers = HashMap::new();
    headers.insert(header_name.to_string(), key.to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    (result, ctx)
}

async fn dedup_complete(plugin: &dyn Plugin, ctx: &mut RequestContext, body: &[u8], status: u16) {
    let headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(ctx, status, &headers, body)
        .await;
}

#[tokio::test]
async fn dedup_in_progress_lease_survives_a_compatible_reload() {
    let first = dedup_generation("ns-dedup-inflight", "dedup-inflight", json!({}));
    let (leased, _ctx) = dedup_lookup(&first, DEDUP_HEADER, "lease-key").await;
    assert!(matches!(leased, PluginResult::Continue));

    // A rebuild constructs a replacement instance while the original request is
    // still executing. It must observe the lease, not an empty map.
    let replacement = dedup_generation("ns-dedup-inflight", "dedup-inflight", json!({}));
    assert!(
        replacement.shares_local_state_with(&first),
        "a compatible reload generation must inherit the protection domain"
    );
    let (duplicate, _) = dedup_lookup(&replacement, DEDUP_HEADER, "lease-key").await;
    assert_eq!(
        reject_status(&duplicate),
        Some(409),
        "a duplicate of the in-flight request must conflict, not re-execute"
    );
}

#[tokio::test]
async fn dedup_completed_entry_replays_on_the_replacement_generation() {
    let first = dedup_generation("ns-dedup-done", "dedup-done", json!({}));
    let (leased, mut ctx) = dedup_lookup(&first, DEDUP_HEADER, "completed-key").await;
    assert!(matches!(leased, PluginResult::Continue));
    dedup_complete(&first, &mut ctx, b"charged once", 200).await;

    let replacement = dedup_generation("ns-dedup-done", "dedup-done", json!({}));
    let (replay, _) = dedup_lookup(&replacement, DEDUP_HEADER, "completed-key").await;
    match replay {
        PluginResult::RejectBinary { body, .. } => assert_eq!(&body[..], b"charged once"),
        other => panic!("expected a retained replay across the reload, got {other:?}"),
    }
}

#[tokio::test]
async fn dedup_compatible_ttl_and_capacity_changes_keep_retained_state() {
    let wide = json!({
        "ttl_seconds": 300,
        "max_entries": 1000,
        "max_total_size_bytes": 1_048_576
    });
    let first = dedup_generation("ns-dedup-caps", "dedup-caps", wide);
    let (leased, mut ctx) = dedup_lookup(&first, DEDUP_HEADER, "caps-key").await;
    assert!(matches!(leased, PluginResult::Continue));
    dedup_complete(&first, &mut ctx, b"kept", 201).await;

    // Retention and capacity changes are compatible rather than resetting the
    // protection domain. Existing operations retain the window under which
    // they were admitted; new operations use the replacement settings.
    let narrow = json!({
        "ttl_seconds": 60,
        "max_entries": 10,
        "max_total_size_bytes": 65_536
    });
    let tightened = dedup_generation("ns-dedup-caps", "dedup-caps", narrow);
    assert!(
        tightened.shares_local_state_with(&first),
        "capacity/TTL changes must not isolate the protection domain"
    );
    let (replay, _) = dedup_lookup(&tightened, DEDUP_HEADER, "caps-key").await;
    assert_eq!(
        replay_status(&replay),
        Some(201),
        "the retained completion must survive a compatible capacity change"
    );
}

#[tokio::test]
async fn dedup_reload_cannot_shorten_an_existing_inflight_lease() {
    let first = dedup_generation(
        "ns-dedup-inflight-retention",
        "dedup-inflight-retention",
        json!({"inflight_ttl_seconds": 300}),
    );
    let (leased, _ctx) = dedup_lookup(&first, DEDUP_HEADER, "retention-key").await;
    assert!(matches!(leased, PluginResult::Continue));

    // Make the existing lease older than the replacement's timeout while it
    // remains well inside the 300-second window under which it was admitted.
    // This is deterministic and does not depend on wall-clock sleeps.
    request_deduplication_backdate_inflight_for_test(&first, Duration::from_secs(120));

    let replacement = dedup_generation(
        "ns-dedup-inflight-retention",
        "dedup-inflight-retention",
        json!({"inflight_ttl_seconds": 60}),
    );
    assert!(replacement.shares_local_state_with(&first));
    let (duplicate, _) = dedup_lookup(&replacement, DEDUP_HEADER, "retention-key").await;
    assert_eq!(
        reject_status(&duplicate),
        Some(409),
        "a reload must not evaluate an existing lease with its shorter timeout"
    );
}

#[tokio::test]
async fn dedup_header_name_change_isolates_instead_of_reusing_retained_keys() {
    let first = dedup_generation("ns-dedup-hdr", "dedup-hdr", json!({}));
    let (leased, mut ctx) = dedup_lookup(&first, DEDUP_HEADER, "shared-value").await;
    assert!(matches!(leased, PluginResult::Continue));
    dedup_complete(&first, &mut ctx, b"old policy body", 200).await;

    // `header_name` is not bound into the logical key, so the same value read
    // from a different header is a different operator-visible input. The
    // replacement must isolate rather than replay the old representation.
    let renamed = json!({"header_name": "X-Request-Id"});
    let replacement = dedup_generation("ns-dedup-hdr", "dedup-hdr", renamed);
    assert!(
        !replacement.shares_local_state_with(&first),
        "a semantic change must isolate onto fresh state"
    );
    let (fresh, _) = dedup_lookup(&replacement, "x-request-id", "shared-value").await;
    assert!(
        matches!(fresh, PluginResult::Continue),
        "the isolated generation must not replay the superseded policy's entry"
    );

    // The retired generation still answers against the state it leased from.
    let (retired, _) = dedup_lookup(&first, DEDUP_HEADER, "shared-value").await;
    assert_eq!(
        replay_status(&retired),
        Some(200),
        "the retired policy's own domain stays intact"
    );
}

#[tokio::test]
async fn dedup_policy_revert_recovers_a_still_live_semantic_generation() {
    let first = dedup_generation("ns-dedup-aba", "dedup-aba", json!({}));
    let (leased, _ctx) = dedup_lookup(&first, DEDUP_HEADER, "aba-key").await;
    assert!(matches!(leased, PluginResult::Continue));

    let changed = dedup_generation(
        "ns-dedup-aba",
        "dedup-aba",
        json!({"header_name": "X-Request-Id"}),
    );
    assert!(
        !changed.shares_local_state_with(&first),
        "the incompatible middle generation must stay isolated"
    );

    let reverted = dedup_generation("ns-dedup-aba", "dedup-aba", json!({}));
    assert!(
        reverted.shares_local_state_with(&first),
        "A -> B -> A must recover A while its operation is still live"
    );
    let (duplicate, _) = dedup_lookup(&reverted, DEDUP_HEADER, "aba-key").await;
    assert_eq!(
        reject_status(&duplicate),
        Some(409),
        "the reverted generation must not re-execute A's in-flight operation"
    );
}

#[tokio::test]
async fn dedup_distinct_policies_tenants_and_identityless_instances_never_share() {
    let base = dedup_generation("ns-dedup-iso", "dedup-iso-a", json!({}));
    let (leased, _ctx) = dedup_lookup(&base, DEDUP_HEADER, "iso-key").await;
    assert!(matches!(leased, PluginResult::Continue));

    // Different plugin-config id in the same namespace.
    let sibling = dedup_generation("ns-dedup-iso", "dedup-iso-b", json!({}));
    assert!(!sibling.shares_local_state_with(&base));
    let (sibling_result, _) = dedup_lookup(&sibling, DEDUP_HEADER, "iso-key").await;
    assert!(
        matches!(sibling_result, PluginResult::Continue),
        "a sibling policy must not see another policy's lease"
    );

    // Same bare plugin-config id in a different namespace.
    let other_tenant = dedup_generation("ns-dedup-iso-other", "dedup-iso-a", json!({}));
    assert!(
        !other_tenant.shares_local_state_with(&base),
        "two tenants reusing one bare resource id must stay isolated"
    );

    // Construction without a stable policy identity is isolated by design.
    let anon_a = dedup_without_identity("dedup-iso-a");
    let anon_b = dedup_without_identity("dedup-iso-a");
    assert!(!anon_a.shares_local_state_with(&base));
    assert!(!anon_a.shares_local_state_with(&anon_b));
}

#[tokio::test]
async fn dedup_removed_policy_releases_its_state_and_a_readd_starts_clean() {
    let removed = dedup_generation("ns-dedup-churn", "dedup-churn", json!({}));
    let (leased, ctx) = dedup_lookup(&removed, DEDUP_HEADER, "churn-key").await;
    assert!(matches!(leased, PluginResult::Continue));
    drop(ctx);

    // Removing the policy drops the last owner, so the registry entry dies and
    // retention does not accumulate across churn.
    drop(removed);
    let readded = dedup_generation("ns-dedup-churn", "dedup-churn", json!({}));
    let (result, _) = dedup_lookup(&readded, DEDUP_HEADER, "churn-key").await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a re-added policy with no surviving holder starts from clean state"
    );
}

#[tokio::test]
async fn dedup_lease_survives_a_real_plugin_cache_rebuild() {
    let config = gateway_config(
        vec![http_proxy("dedup-proxy", &["dedup-cache"])],
        vec![plugin_config(
            "dedup-cache",
            "request_deduplication",
            PluginScope::Proxy,
            Some("dedup-proxy"),
            json!({}),
        )],
    );
    let cache = PluginCache::new(&config).expect("dedup generation must admit");
    let first = plugin_named(&cache, "dedup-proxy", "request_deduplication");
    let key = "cache-lease";
    let (leased, _ctx) = dedup_lookup(first.as_ref(), DEDUP_HEADER, key).await;
    assert!(matches!(leased, PluginResult::Continue));

    // Change an unrelated, compatible attribute of the same policy so the
    // rebuild really constructs a replacement instance.
    let reloaded = gateway_config(
        vec![http_proxy("dedup-proxy", &["dedup-cache"])],
        vec![plugin_config(
            "dedup-cache",
            "request_deduplication",
            PluginScope::Proxy,
            Some("dedup-proxy"),
            json!({"ttl_seconds": 120}),
        )],
    );
    cache.rebuild(&reloaded).expect("dedup reload must apply");
    let replacement = plugin_named(&cache, "dedup-proxy", "request_deduplication");
    let (duplicate, _) = dedup_lookup(replacement.as_ref(), DEDUP_HEADER, key).await;
    assert_eq!(
        reject_status(&duplicate),
        Some(409),
        "the retry must conflict rather than re-dispatch the side effect"
    );
}

#[tokio::test]
async fn dedup_unaffected_config_keeps_its_ordinary_behavior() {
    // A single generation with no reload at all must behave exactly as before:
    // first request continues, retained completion replays, an unrelated key is
    // untouched.
    let plugin = dedup_generation("ns-dedup-plain", "dedup-plain", json!({}));
    let (leased, mut ctx) = dedup_lookup(&plugin, DEDUP_HEADER, "plain-key").await;
    assert!(matches!(leased, PluginResult::Continue));
    dedup_complete(&plugin, &mut ctx, b"plain", 200).await;

    let (replay, _) = dedup_lookup(&plugin, DEDUP_HEADER, "plain-key").await;
    assert_eq!(replay_status(&replay), Some(200));
    let (fresh, _) = dedup_lookup(&plugin, DEDUP_HEADER, "another-key").await;
    assert!(matches!(fresh, PluginResult::Continue));
}

// ── load_testing ────────────────────────────────────────────────────────────

const LOAD_TEST_KEY: &str = "stateful-generation-key-0123456789";

fn load_testing_config(duration_seconds: u64) -> Value {
    json!({
        "key": LOAD_TEST_KEY,
        "concurrent_clients": 1,
        "duration_seconds": duration_seconds,
        // Discard port: the cohort fails fast without touching a real backend.
        "gateway_port": 9,
        "request_timeout_ms": 200
    })
}

fn load_testing_generation(namespace: &str, config_id: &str, config: &Value) -> LoadTesting {
    load_testing_with_policy_identity_for_test(
        config,
        PluginHttpClient::default(),
        namespace,
        config_id,
    )
    .expect("load_testing generation must construct")
}

fn load_testing_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "lt-proxy",
        "name": "lt-proxy",
        "listen_path": "/api",
        "backend_host": "backend.local",
        "backend_port": 8080,
        "backend_scheme": "http"
    }))
    .expect("load_testing proxy fixture must deserialize");
    ctx.matched_proxy = Some(Arc::new(proxy));
    ctx
}

async fn trigger_load_test(plugin: &LoadTesting) {
    let mut ctx = load_testing_ctx();
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), LOAD_TEST_KEY.to_string());
    ctx.headers = headers.clone();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "the triggering request itself always proceeds"
    );
}

async fn wait_until_idle(plugin: &LoadTesting) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while plugin.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !plugin.is_running(),
        "timed out waiting for the load_testing cohort to stop"
    );
}

#[tokio::test]
async fn load_testing_active_run_blocks_a_replacement_generation_trigger() {
    let config = load_testing_config(3);
    let first = load_testing_generation("ns-lt-active", "lt-active", &config);
    trigger_load_test(&first).await;
    assert!(first.is_running(), "the first cohort must be admitted");

    let replacement = load_testing_generation("ns-lt-active", "lt-active", &config);
    assert!(
        replacement.is_running(),
        "a replacement generation must observe the still-active cohort"
    );
    // A trigger on the replacement is admitted as a request but must not start
    // a second cohort.
    trigger_load_test(&replacement).await;
    assert!(replacement.is_running());

    wait_until_idle(&replacement).await;
    assert!(
        !first.is_running(),
        "both generations observe the same completion"
    );
}

#[tokio::test]
async fn load_testing_policy_revert_recovers_a_still_live_semantic_generation() {
    let original_config = load_testing_config(1);
    let first = load_testing_generation("ns-lt-aba", "lt-aba", &original_config);
    trigger_load_test(&first).await;
    assert!(first.is_running(), "the A cohort must be active");

    let mut changed_config = original_config.clone();
    changed_config["max_response_body_bytes"] = json!(2048);
    let changed = load_testing_generation("ns-lt-aba", "lt-aba", &changed_config);
    assert!(
        !changed.is_running(),
        "the incompatible B generation has an isolated admission domain"
    );

    let reverted = load_testing_generation("ns-lt-aba", "lt-aba", &original_config);
    assert!(
        reverted.is_running(),
        "A -> B -> A must recover A's still-active cohort guard"
    );
    wait_until_idle(&reverted).await;
}

#[tokio::test]
async fn load_testing_completed_run_lets_the_replacement_generation_run_again() {
    let config = load_testing_config(1);
    let first = load_testing_generation("ns-lt-again", "lt-again", &config);
    trigger_load_test(&first).await;
    wait_until_idle(&first).await;

    let replacement = load_testing_generation("ns-lt-again", "lt-again", &config);
    assert!(
        !replacement.is_running(),
        "a completed run must not leave the shared guard latched"
    );
    trigger_load_test(&replacement).await;
    assert!(
        replacement.is_running(),
        "a later run is admitted once the previous cohort completed"
    );
    wait_until_idle(&replacement).await;
}

#[tokio::test]
async fn load_testing_distinct_identities_do_not_share_run_admission() {
    let config = load_testing_config(3);
    let running = load_testing_generation("ns-lt-iso", "lt-iso-a", &config);
    trigger_load_test(&running).await;
    assert!(running.is_running());

    let sibling = load_testing_generation("ns-lt-iso", "lt-iso-b", &config);
    assert!(
        !sibling.is_running(),
        "an unrelated policy must not inherit another policy's run admission"
    );
    let other_tenant = load_testing_generation("ns-lt-iso-other", "lt-iso-a", &config);
    assert!(
        !other_tenant.is_running(),
        "two tenants reusing one bare resource id must stay isolated"
    );

    wait_until_idle(&running).await;
}

#[tokio::test]
async fn load_testing_removed_policy_cancels_before_readd_can_start_again() {
    let config = load_testing_config(1);
    let removed = load_testing_generation("ns-lt-churn", "lt-churn", &config);
    trigger_load_test(&removed).await;
    assert!(removed.is_running());

    // Dropping the last owner requests cancellation. The detached cohort still
    // holds the state while it winds down, so an immediate re-add must recover
    // that guard and remain blocked instead of overlapping the old workers.
    drop(removed);
    let readded = load_testing_generation("ns-lt-churn", "lt-churn", &config);
    assert!(
        readded.is_running(),
        "an immediate re-add must observe the cancelling cohort"
    );
    wait_until_idle(&readded).await;

    trigger_load_test(&readded).await;
    assert!(
        readded.is_running(),
        "a new cohort is admitted after cancellation has completed"
    );
    wait_until_idle(&readded).await;
}

#[test]
fn load_testing_rejects_two_effective_instances_on_one_proxy() {
    let config = gateway_config(
        vec![http_proxy("lt-dup", &["lt-1", "lt-2"])],
        vec![
            plugin_config(
                "lt-1",
                "load_testing",
                PluginScope::Proxy,
                Some("lt-dup"),
                load_testing_config(1),
            ),
            plugin_config(
                "lt-2",
                "load_testing",
                PluginScope::Proxy,
                Some("lt-dup"),
                load_testing_config(1),
            ),
        ],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("two effective load_testing instances must be rejected");
    assert!(
        error.contains("load_testing permits at most one effective instance per proxy"),
        "unexpected composition error: {error}"
    );
}

#[test]
fn load_testing_single_effective_instance_per_proxy_still_admits() {
    // The uniqueness rule must not regress an ordinary single-instance config,
    // including one global instance shared by several proxies.
    let scoped = gateway_config(
        vec![http_proxy("lt-ok", &["lt-only"])],
        vec![plugin_config(
            "lt-only",
            "load_testing",
            PluginScope::Proxy,
            Some("lt-ok"),
            load_testing_config(1),
        )],
    );
    let cache = PluginCache::new(&scoped).expect("one scoped instance must admit");
    assert_eq!(plugin_count(&cache, "lt-ok", "load_testing"), 1);

    let global = gateway_config(
        vec![http_proxy("lt-g1", &[]), http_proxy("lt-g2", &[])],
        vec![plugin_config(
            "lt-global",
            "load_testing",
            PluginScope::Global,
            None,
            load_testing_config(1),
        )],
    );
    let cache = PluginCache::new(&global).expect("one global instance must admit");
    for proxy_id in ["lt-g1", "lt-g2"] {
        assert_eq!(
            plugin_count(&cache, proxy_id, "load_testing"),
            1,
            "each proxy sees exactly one effective global instance"
        );
    }
}
