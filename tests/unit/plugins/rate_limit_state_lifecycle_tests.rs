//! Stable-policy-identity lifecycle for local rate-limit enforcement state
//! (issue #4268).
//!
//! Six plugins (`rate_limiting`, `ai_rate_limiter`, `graphql`,
//! `grpc_method_router`, `ws_rate_limiting`, `udp_rate_limiting`) keep their
//! local budgets in a `RateLimitBackend`. Those budgets are owned by the stable
//! `(namespace, plugin kind, plugin-config id)` policy identity, never by the
//! plugin instance a cache generation happened to construct: a compatible
//! rebuild inherits the live counters, a semantic policy change isolates onto
//! fresh state.
//!
//! Every assertion here is deterministic — fixed `Instant` values and 60-second
//! windows, no sleeps.

use chrono::Utc;
use ferrum_edge::_test_support::{
    ai_rate_limiter_shares_local_state_for_test, graphql_shares_local_state_for_test,
    grpc_method_router_shares_local_state_for_test, plugin_cache_full_reload_for_test,
    rate_limiting_shares_across_client_namespaces_for_test,
    rate_limiting_shares_local_state_for_test, shared_local_rate_limit_generations_for_test,
    standalone_rate_limiting_shares_state_for_test, udp_rate_limiting_shares_local_state_for_test,
    ws_rate_limiting_charge_frame_for_test, ws_rate_limiting_contains_connection_for_test,
    ws_rate_limiting_shares_local_state_for_test, ws_rate_limiting_with_policy_identity_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::config_delta::ConfigDelta;
use ferrum_edge::plugins::graphql::GraphqlPlugin;
use ferrum_edge::plugins::rate_limiting::RateLimiting;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult};
use serde_json::{Value, json};
use std::time::Instant;

use super::make_proxy;
use super::plugin_utils::create_test_context;

const NS: &str = "ferrum";

fn rate_limiting_policy(max_requests: u64, window_seconds: u64, limit_by: &str) -> Value {
    json!({
        "limit_by": limit_by,
        "limits": [{
            "scope": "default",
            "window_seconds": window_seconds,
            "max_requests": max_requests,
        }],
    })
}

fn global_plugin_config(id: &str, plugin_name: &str, config: Value) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        namespace: NS.to_string(),
        plugin_name: plugin_name.to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn gateway_config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

/// One namespace with a global `rate_limiting` budget plus an unrelated global
/// policy whose config the test can churn.
///
/// `request_size_limiting` shares nothing with the limiter — it is purely the
/// lever that makes `ConfigDelta` mark every proxy for a plugin rebuild.
/// `policy_id` must be unique per test: the enforcement state is process-wide
/// and keyed by policy identity, so two tests reusing one id would share a
/// budget and race.
fn config_with(policy_id: &str, protected: Value, noise_max_bytes: u64) -> GatewayConfig {
    gateway_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![
            global_plugin_config(policy_id, "rate_limiting", protected),
            global_plugin_config(
                "unrelated-noise",
                "request_size_limiting",
                json!({"max_bytes": noise_max_bytes}),
            ),
        ],
    )
}

/// Drive one request through the published `rate_limiting` instance and report
/// whether it was refused.
async fn request_refused(cache: &PluginCache) -> bool {
    let plugins = cache.get_plugins(NS, "p1");
    let limiter = plugins
        .iter()
        .find(|plugin| plugin.name() == "rate_limiting")
        .expect("the published chain must carry the global rate_limiting policy");
    let mut ctx = create_test_context();
    matches!(
        limiter.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    )
}

/// Drive one request through a directly constructed instance and report
/// whether it was refused.
async fn instance_refused(limiter: &RateLimiting) -> bool {
    let mut ctx = create_test_context();
    matches!(
        limiter.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    )
}

async fn exhaust(cache: &PluginCache, budget: usize) {
    for attempt in 0..budget {
        assert!(
            !request_refused(cache).await,
            "request {attempt} must be admitted while the budget has room"
        );
    }
    assert!(
        request_refused(cache).await,
        "the request after the budget is consumed must be refused"
    );
}

type Identity<'a> = (&'a str, &'a str, &'a Value);

fn rl_shares(left: Identity<'_>, right: Identity<'_>) -> bool {
    rate_limiting_shares_local_state_for_test(left, right).expect("rate_limiting constructs")
}

fn gql_shares(left: Identity<'_>, right: Identity<'_>) -> bool {
    graphql_shares_local_state_for_test(left, right).expect("graphql constructs")
}

fn grpc_shares(left: Identity<'_>, right: Identity<'_>) -> bool {
    grpc_method_router_shares_local_state_for_test(left, right).expect("grpc_method_router builds")
}

fn ai_shares(left: Identity<'_>, right: Identity<'_>) -> bool {
    ai_rate_limiter_shares_local_state_for_test(left, right).expect("ai_rate_limiter constructs")
}

fn udp_shares(left: Identity<'_>, right: Identity<'_>) -> bool {
    udp_rate_limiting_shares_local_state_for_test(left, right).expect("udp_rate_limiting builds")
}

fn ws_shares(left: Identity<'_>, right: Identity<'_>) -> bool {
    let first = ws_rate_limiting_with_policy_identity_for_test(left.2, left.0, left.1)
        .expect("ws_rate_limiting constructs");
    let second = ws_rate_limiting_with_policy_identity_for_test(right.2, right.0, right.1)
        .expect("ws_rate_limiting constructs");
    ws_rate_limiting_shares_local_state_for_test(&first, &second)
}

// Two configs on ONE policy identity: the question every compatibility case
// below asks. `id` must be unique per test — enforcement state is process-wide,
// so two tests reusing an id would share a budget and race.
fn rl_pair(id: &str, left: &Value, right: &Value) -> bool {
    rl_shares((NS, id, left), (NS, id, right))
}

fn gql_pair(id: &str, left: &Value, right: &Value) -> bool {
    gql_shares((NS, id, left), (NS, id, right))
}

fn grpc_pair(id: &str, left: &Value, right: &Value) -> bool {
    grpc_shares((NS, id, left), (NS, id, right))
}

fn ai_pair(id: &str, left: &Value, right: &Value) -> bool {
    ai_shares((NS, id, left), (NS, id, right))
}

fn udp_pair(id: &str, left: &Value, right: &Value) -> bool {
    udp_shares((NS, id, left), (NS, id, right))
}

fn ws_pair(id: &str, left: &Value, right: &Value) -> bool {
    ws_shares((NS, id, left), (NS, id, right))
}

/// A `rate_limiting` policy with `sync_mode: redis` pointed at an endpoint that
/// is never dialed: construction is offline, and only the effective posture
/// matters here.
fn redis_backed_policy() -> Value {
    let mut config = rate_limiting_policy(10, 60, "ip");
    config["sync_mode"] = json!("redis");
    config["redis_url"] = json!("redis://cache.internal:6379/0");
    config
}

#[tokio::test]
async fn unrelated_global_plugin_change_does_not_reset_a_consumed_rate_limit_budget() {
    let id = "budget-global-churn";
    let initial = config_with(id, rate_limiting_policy(2, 60, "ip"), 1_048_576);
    let cache = PluginCache::new(&initial).expect("initial plugin cache");
    exhaust(&cache, 2).await;

    // Churn an unrelated global plugin config. `ConfigDelta` marks every proxy
    // for a plugin rebuild, so every global instance is reconstructed.
    let churned = config_with(id, rate_limiting_policy(2, 60, "ip"), 2_097_152);
    let delta = ConfigDelta::compute(&initial, &churned);
    assert!(
        delta.global_plugin_configs_changed,
        "the fixture must exercise the global rebuild path"
    );
    let rebuild_ids = delta.proxy_ids_needing_plugin_rebuild(&initial, &churned);
    cache
        .apply_delta(
            &churned,
            &rebuild_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .expect("delta reload must succeed");

    assert!(
        request_refused(&cache).await,
        "an unrelated global plugin-config change must not hand the caller a fresh budget"
    );
}

#[tokio::test]
async fn full_cache_reload_with_an_identical_policy_preserves_the_budget() {
    let id = "budget-full-reload";
    let initial = config_with(id, rate_limiting_policy(2, 60, "ip"), 1_048_576);
    let cache = PluginCache::new(&initial).expect("initial plugin cache");
    exhaust(&cache, 2).await;

    // Same production path as a file-mode SIGHUP, a DP full CP snapshot, and
    // the database-mode fallback after a rejected delta.
    let identical = config_with(id, rate_limiting_policy(2, 60, "ip"), 1_048_576);
    plugin_cache_full_reload_for_test(&cache, &identical).expect("full reload must succeed");

    assert!(
        request_refused(&cache).await,
        "a full rebuild of a semantically identical policy must keep the consumed budget"
    );
}

#[tokio::test]
async fn a_semantic_max_requests_change_starts_a_fresh_budget() {
    let id = "budget-semantic-change";
    let initial = config_with(id, rate_limiting_policy(2, 60, "ip"), 1_048_576);
    let cache = PluginCache::new(&initial).expect("initial plugin cache");
    exhaust(&cache, 2).await;

    let widened = config_with(id, rate_limiting_policy(5, 60, "ip"), 1_048_576);
    plugin_cache_full_reload_for_test(&cache, &widened).expect("full reload must succeed");

    assert!(
        !request_refused(&cache).await,
        "a changed max_requests is a different policy and must not inherit the old counters"
    );
}

#[tokio::test]
async fn a_rejected_candidate_generation_leaves_the_live_budget_enforcing() {
    let id = "budget-rejected-candidate";
    let initial = config_with(id, rate_limiting_policy(2, 60, "ip"), 1_048_576);
    let cache = PluginCache::new(&initial).expect("initial plugin cache");
    exhaust(&cache, 2).await;

    // `max_requests: 0` is refused by policy validation, so the candidate
    // generation never publishes.
    let invalid = config_with(
        id,
        json!({
            "limit_by": "ip",
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 0}],
        }),
        1_048_576,
    );
    assert!(
        plugin_cache_full_reload_for_test(&cache, &invalid).is_err(),
        "the fixture must actually be rejected"
    );

    assert!(
        request_refused(&cache).await,
        "a rejected config must leave the currently published budget enforcing"
    );
}

#[test]
fn compatible_reloads_share_state_and_semantic_changes_do_not() {
    let base = rate_limiting_policy(10, 60, "ip");

    assert!(
        rl_shares((NS, "share-a", &base), (NS, "share-a", &base)),
        "an identical policy on one identity must inherit the live limiter"
    );

    // Presentation-only field: never a reason to discard live counters.
    let mut expose = base.clone();
    expose["expose_headers"] = json!(true);
    assert!(
        rl_shares((NS, "share-a", &base), (NS, "share-a", &expose)),
        "expose_headers does not change enforcement and must inherit"
    );

    for (label, changed) in [
        ("max_requests", rate_limiting_policy(11, 60, "ip")),
        ("window_seconds", rate_limiting_policy(10, 61, "ip")),
        ("limit_by", rate_limiting_policy(10, 60, "consumer")),
    ] {
        assert!(
            !rl_shares((NS, "share-b", &base), (NS, "share-b", &changed)),
            "a changed {label} must isolate onto fresh state"
        );
    }

    // With `sync_mode: local` there is no centralized store to lose, so the
    // outage posture changes nothing that is enforced and must not discard a
    // live budget. `a_redis_backed_policy_isolates_a_changed_failure_posture`
    // covers the Redis-enabled case, where it does isolate.
    let mut fallback = base.clone();
    fallback["redis_failure_policy"] = json!("local_fallback");
    assert!(
        rl_shares((NS, "share-c", &base), (NS, "share-c", &fallback)),
        "redis_failure_policy is not enforcement-relevant for a local-only policy"
    );

    assert!(
        !standalone_rate_limiting_shares_state_for_test(&base).expect("construction"),
        "standalone construction has no policy identity and must stay isolated"
    );
}

#[test]
fn redis_default_prefix_does_not_make_local_state_depend_on_the_constructing_client() {
    let default_prefix = redis_backed_policy();
    assert!(
        rate_limiting_shares_across_client_namespaces_for_test(
            &default_prefix,
            NS,
            "redis-default-prefix-client",
            "validation-client",
            "runtime-client",
        )
        .expect("rate_limiting constructs"),
        "the identity-derived default prefix must not make the fingerprint client-dependent"
    );

    let mut explicit_left = default_prefix.clone();
    explicit_left["redis_key_prefix"] = json!("shared-budget-a");
    let mut explicit_right = default_prefix;
    explicit_right["redis_key_prefix"] = json!("shared-budget-b");
    assert!(
        !rl_pair(
            "redis-explicit-prefix-isolates",
            &explicit_left,
            &explicit_right,
        ),
        "different explicit Redis prefixes must still isolate local fallback budgets"
    );
}

#[test]
fn policy_identity_isolates_namespaces_and_plugin_config_ids() {
    let base = rate_limiting_policy(10, 60, "ip");

    assert!(
        !rl_shares(("tenant-a", "iso-id", &base), ("tenant-b", "iso-id", &base)),
        "the same bare plugin-config id in two namespaces must never share a budget"
    );
    assert!(
        !rl_shares((NS, "iso-left", &base), (NS, "iso-right", &base)),
        "two sibling policies in one namespace must never share a budget"
    );
}

#[tokio::test]
async fn two_limiter_plugin_kinds_sharing_one_id_do_not_share_state() {
    // `rate_limiting` and `graphql` are enforced by the same algorithm type, so
    // only the plugin kind carried in the policy identity keeps them apart.
    let limiter = RateLimiting::new_with_policy_identity(
        &rate_limiting_policy(10, 60, "ip"),
        PluginHttpClient::default(),
        NS,
        "kind-collision",
    )
    .expect("rate_limiting constructs");

    let mut ctx = create_test_context();
    assert!(matches!(
        limiter.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(limiter.tracked_keys_count(), Some(1));

    let graphql = GraphqlPlugin::new_with_policy_identity(
        &json!({
            "limit_by": "ip",
            "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 60}},
        }),
        PluginHttpClient::default(),
        NS,
        "kind-collision",
    )
    .expect("graphql constructs");

    assert_eq!(
        graphql.tracked_keys_count(),
        Some(0),
        "a different limiter plugin kind on the same id must start with its own empty state"
    );
    assert_eq!(
        limiter.tracked_keys_count(),
        Some(1),
        "and must not disturb the original policy's counters"
    );
}

#[test]
fn every_local_rate_limit_constructor_binds_its_policy_identity() {
    let graphql = json!({
        "limit_by": "ip",
        "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 60}},
    });
    let graphql_changed = json!({
        "limit_by": "ip",
        "type_rate_limits": {"query": {"max_requests": 11, "window_seconds": 60}},
    });
    assert!(gql_shares(
        (NS, "ch-gql", &graphql),
        (NS, "ch-gql", &graphql)
    ));
    assert!(!gql_shares(
        (NS, "ch-gql", &graphql),
        (NS, "ch-gql", &graphql_changed)
    ));

    let grpc = json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 60}},
    });
    let grpc_changed = json!({
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 11, "window_seconds": 60}},
    });
    assert!(grpc_shares((NS, "ch-grpc", &grpc), (NS, "ch-grpc", &grpc)));
    assert!(!grpc_shares(
        (NS, "ch-grpc", &grpc),
        (NS, "ch-grpc", &grpc_changed)
    ));

    let ai = json!({"token_limit": 1000, "window_seconds": 60});
    let ai_changed = json!({"token_limit": 2000, "window_seconds": 60});
    assert!(ai_shares((NS, "ch-ai", &ai), (NS, "ch-ai", &ai)));
    assert!(!ai_shares((NS, "ch-ai", &ai), (NS, "ch-ai", &ai_changed)));

    let udp = json!({"datagrams_per_second": 10, "window_seconds": 1});
    let udp_changed = json!({"datagrams_per_second": 11, "window_seconds": 1});
    assert!(udp_shares((NS, "ch-udp", &udp), (NS, "ch-udp", &udp)));
    assert!(!udp_shares(
        (NS, "ch-udp", &udp),
        (NS, "ch-udp", &udp_changed)
    ));
    assert!(!udp_shares(
        ("tenant-a", "ch-udp-ns", &udp),
        ("tenant-b", "ch-udp-ns", &udp)
    ));
}

#[test]
fn websocket_frame_budgets_survive_a_compatible_rebuild() {
    let policy = json!({"frames_per_second": 1, "burst_size": 1});
    // One fixed instant for every charge: the token bucket never refills, so
    // the assertions need no sleep.
    let now = Instant::now();

    let first = ws_rate_limiting_with_policy_identity_for_test(&policy, NS, "ws-budget")
        .expect("ws_rate_limiting constructs");
    assert!(
        ws_rate_limiting_charge_frame_for_test(&first, 7, now),
        "the first frame consumes the single-token burst"
    );
    assert!(
        !ws_rate_limiting_charge_frame_for_test(&first, 7, now),
        "the second frame exhausts the connection's budget"
    );

    let rebuilt = ws_rate_limiting_with_policy_identity_for_test(&policy, NS, "ws-budget")
        .expect("ws_rate_limiting constructs");
    assert!(
        ws_rate_limiting_shares_local_state_for_test(&first, &rebuilt),
        "a compatible rebuild must inherit the live frame state"
    );
    assert!(
        ws_rate_limiting_contains_connection_for_test(&rebuilt, 7),
        "the connection's retained bucket must still be visible after the rebuild"
    );
    assert!(
        !ws_rate_limiting_charge_frame_for_test(&rebuilt, 7, now),
        "the rebuilt instance must keep refusing the exhausted connection"
    );

    let widened = json!({"frames_per_second": 1, "burst_size": 2});
    let changed = ws_rate_limiting_with_policy_identity_for_test(&widened, NS, "ws-budget")
        .expect("ws_rate_limiting constructs");
    assert!(
        !ws_rate_limiting_shares_local_state_for_test(&first, &changed),
        "a changed burst_size is a different policy"
    );
    assert!(
        ws_rate_limiting_charge_frame_for_test(&changed, 7, now),
        "a semantic change must start the connection on fresh state"
    );
}

#[test]
fn a_retired_generation_is_recovered_and_a_removed_policy_is_reclaimed() {
    let policy_a = json!({"frames_per_second": 1, "burst_size": 1});
    let policy_b = json!({"frames_per_second": 1, "burst_size": 2});
    let identity = "ws-generations";
    let now = Instant::now();

    assert_eq!(
        shared_local_rate_limit_generations_for_test("ws_rate_limiting", NS, identity),
        Some(0),
        "the identity starts with no retained state"
    );

    let a1 = ws_rate_limiting_with_policy_identity_for_test(&policy_a, NS, identity)
        .expect("ws_rate_limiting constructs");
    assert!(ws_rate_limiting_charge_frame_for_test(&a1, 1, now));

    let b = ws_rate_limiting_with_policy_identity_for_test(&policy_b, NS, identity)
        .expect("ws_rate_limiting constructs");
    assert_eq!(
        shared_local_rate_limit_generations_for_test("ws_rate_limiting", NS, identity),
        Some(2),
        "a semantic change retains the still-live retired generation alongside the new one"
    );

    // With A and B both live, another A construction must recover A's budget,
    // not mint a third empty domain.
    let a2 = ws_rate_limiting_with_policy_identity_for_test(&policy_a, NS, identity)
        .expect("ws_rate_limiting constructs");
    assert!(ws_rate_limiting_shares_local_state_for_test(&a1, &a2));
    assert!(
        !ws_rate_limiting_charge_frame_for_test(&a2, 1, now),
        "the recovered generation must still be exhausted"
    );
    assert_eq!(
        shared_local_rate_limit_generations_for_test("ws_rate_limiting", NS, identity),
        Some(2)
    );

    // Removing the policy releases its state: nothing stale is left for a later
    // incompatible policy to inherit.
    drop(a1);
    drop(a2);
    drop(b);
    assert_eq!(
        shared_local_rate_limit_generations_for_test("ws_rate_limiting", NS, identity),
        Some(0),
        "dropping every instance for an identity reclaims its state"
    );

    let revived = ws_rate_limiting_with_policy_identity_for_test(&policy_a, NS, identity)
        .expect("ws_rate_limiting constructs");
    assert!(
        ws_rate_limiting_charge_frame_for_test(&revived, 1, now),
        "a policy re-added after removal starts fresh"
    );
}

#[tokio::test]
async fn a_rebuilt_instance_keeps_the_exhausted_windows_despite_a_fresh_spec_arc() {
    // Sharing the limiter is only half the fix. A compatible rebuild also
    // constructs a brand-new `DynamicRateLimitOp`, so the dynamic HTTP
    // algorithm sees a different `Arc<[RateLimitWindowSpec]>` on the first
    // request through the rebuilt instance. Keying the window reset on pointer
    // identity would discard the inherited counters right there and hand the
    // caller a fresh budget anyway.
    let first = RateLimiting::new_with_policy_identity(
        &rate_limiting_policy(1, 60, "ip"),
        PluginHttpClient::default(),
        NS,
        "arc-retarget",
    )
    .expect("rate_limiting constructs");

    assert!(!instance_refused(&first).await, "the budget admits once");
    assert!(instance_refused(&first).await, "and refuses afterwards");

    let rebuilt = RateLimiting::new_with_policy_identity(
        &rate_limiting_policy(1, 60, "ip"),
        PluginHttpClient::default(),
        NS,
        "arc-retarget",
    )
    .expect("rate_limiting constructs");

    assert!(
        instance_refused(&rebuilt).await,
        "a semantically identical rebuild must enforce on the inherited windows, not reset them"
    );

    // Two live generations alternating on one key is the steady state during a
    // reload: neither may reset the other's counters.
    assert!(
        instance_refused(&first).await,
        "the original generation must not be reset by the rebuilt one"
    );
    assert!(
        instance_refused(&rebuilt).await,
        "and alternating equal-spec generations must keep refusing"
    );
}

#[test]
fn a_local_policy_shares_state_across_redis_failure_postures() {
    let base = rate_limiting_policy(10, 60, "ip");
    let mut explicit_default = base.clone();
    explicit_default["redis_failure_policy"] = json!("fail_closed");
    let mut fallback = base.clone();
    fallback["redis_failure_policy"] = json!("local_fallback");

    assert!(
        rl_pair("posture-local", &base, &explicit_default),
        "the omitted posture and its explicit default spelling are one policy"
    );
    assert!(
        rl_pair("posture-local", &base, &fallback),
        "with no centralized store to lose the posture changes nothing enforced"
    );
}

#[test]
fn a_redis_backed_policy_isolates_a_changed_failure_posture() {
    let base = redis_backed_policy();
    let mut explicit_default = base.clone();
    explicit_default["redis_failure_policy"] = json!("fail_closed");
    let mut fallback = base.clone();
    fallback["redis_failure_policy"] = json!("local_fallback");

    assert!(
        rl_pair("posture-redis", &base, &explicit_default),
        "the effective posture is unchanged, so the live budget is inherited"
    );
    assert!(
        !rl_pair("posture-redis-b", &base, &fallback),
        "with Redis enabled the posture decides whether the local map may admit at all"
    );
    assert!(
        !rl_pair("posture-mode", &rate_limiting_policy(10, 60, "ip"), &base),
        "enabling the centralized store is a different enforcement domain"
    );
}

#[test]
fn rate_limiting_defaults_and_normalized_spellings_share_state() {
    let explicit = rate_limiting_policy(60, 60, "ip");
    let mut omitted = explicit.clone();
    omitted
        .as_object_mut()
        .expect("the policy fixture is an object")
        .remove("limit_by");

    assert!(
        rl_pair("norm-rl", &explicit, &omitted),
        "an omitted limit_by is the 'ip' default and must not reset the budget"
    );
    assert!(
        rl_pair("norm-rl", &explicit, &rate_limiting_policy(60, 60, "IP")),
        "the parser lower-cases limit_by, so the case spelling is not a policy change"
    );

    let spiffe = rate_limiting_policy(60, 60, "spiffe");
    let spiffe_identity = rate_limiting_policy(60, 60, "spiffe_identity");
    assert!(
        rl_pair("norm-rl-spiffe", &spiffe, &spiffe_identity),
        "both accepted spellings parse to one limit dimension"
    );

    // A preset window and its explicit window_seconds/max_requests spelling
    // build the same single window: 60 requests per 60 seconds.
    let preset = json!({
        "limit_by": "ip",
        "limits": [{"scope": "default", "requests_per_minute": 60}],
    });
    assert!(
        rl_pair("norm-rl-preset", &explicit, &preset),
        "two accepted spellings of one window describe one budget"
    );

    let widened = rate_limiting_policy(61, 60, "ip");
    assert!(
        !rl_pair("norm-rl-change", &explicit, &widened),
        "a real ceiling change must still isolate onto fresh state"
    );
}

#[test]
fn graphql_defaults_and_empty_rate_maps_share_state() {
    let base = json!({
        "max_depth": 5,
        "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 60}},
    });
    let explicit_empty = json!({
        "max_depth": 5,
        "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 60}},
        "operation_rate_limits": {},
    });
    assert!(
        gql_pair("norm-gql", &base, &explicit_empty),
        "an omitted rate map and an explicit empty one enforce identically"
    );

    let stateless_changed = json!({
        "max_depth": 9,
        "max_aliases": 3,
        "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 60}},
    });
    assert!(
        gql_pair("norm-gql", &base, &stateless_changed),
        "depth and alias caps are stateless checks that never consult a counter"
    );

    let real_change = json!({
        "max_depth": 5,
        "type_rate_limits": {"query": {"max_requests": 10, "window_seconds": 61}},
    });
    assert!(
        !gql_pair("norm-gql-change", &base, &real_change),
        "a changed window must still isolate onto fresh state"
    );
}

#[test]
fn grpc_method_router_normalized_paths_and_stateless_lists_share_state() {
    let base = json!({
        "limit_by": "ip",
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 60}},
    });
    let normalized = json!({
        "limit_by": "IP",
        "method_rate_limits": {" pkg.Svc/M ": {"max_requests": 10, "window_seconds": 60}},
    });
    assert!(
        grpc_pair("norm-grpc", &base, &normalized),
        "the parser trims, strips the leading slash, and lower-cases limit_by"
    );

    let with_lists = json!({
        "limit_by": "ip",
        "deny_methods": ["pkg.Svc/Other"],
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 60}},
    });
    assert!(
        grpc_pair("norm-grpc", &base, &with_lists),
        "allow and deny lists are stateless checks that never consult a counter"
    );

    let real_change = json!({
        "limit_by": "consumer",
        "method_rate_limits": {"/pkg.Svc/M": {"max_requests": 10, "window_seconds": 60}},
    });
    assert!(
        !grpc_pair("norm-grpc-change", &base, &real_change),
        "a changed limit dimension must still isolate onto fresh state"
    );
}

#[test]
fn ai_rate_limiter_defaults_and_normalized_provider_share_state() {
    let base = json!({"token_limit": 1000});
    let explicit_defaults = json!({
        "token_limit": 1000,
        "window_seconds": 60,
        "count_mode": "total_tokens",
        "limit_by": "consumer",
        "provider": "auto",
        "on_unmetered_response": "charge_estimate",
    });
    assert!(
        ai_pair("norm-ai", &base, &explicit_defaults),
        "every omitted field spelled out at its effective default is one policy"
    );

    let expose = json!({"token_limit": 1000, "expose_headers": true});
    assert!(
        ai_pair("norm-ai", &base, &expose),
        "expose_headers is response presentation only and never resets a budget"
    );

    let padded = json!({"token_limit": 1000, "provider": "  OpenAI  "});
    let plain = json!({"token_limit": 1000, "provider": "openai"});
    assert!(
        ai_pair("norm-ai-provider", &padded, &plain),
        "the parser trims and lower-cases the configured provider"
    );

    let real_change = json!({"token_limit": 1000, "count_mode": "prompt_tokens"});
    assert!(
        !ai_pair("norm-ai-change", &base, &real_change),
        "a changed count_mode charges different tokens and must still isolate"
    );
}

#[test]
fn ws_rate_limiting_defaults_and_presentation_share_state() {
    let omitted = json!({});
    let explicit_defaults = json!({"frames_per_second": 100, "burst_size": 100});
    assert!(
        ws_pair("norm-ws", &omitted, &explicit_defaults),
        "the omitted rate defaults to 100 and the omitted burst to that rate"
    );

    let close_reason = json!({"close_reason": "slow down"});
    assert!(
        ws_pair("norm-ws", &omitted, &close_reason),
        "close_reason is client-visible presentation only"
    );

    let real_change = json!({"frames_per_second": 100, "burst_size": 200});
    assert!(
        !ws_pair("norm-ws-change", &omitted, &real_change),
        "a changed burst capacity must still isolate onto fresh state"
    );
}

#[test]
fn udp_rate_limiting_defaults_and_unset_axes_share_state() {
    let omitted_window = json!({"datagrams_per_second": 10});
    let explicit_window = json!({"datagrams_per_second": 10, "window_seconds": 1});
    assert!(
        udp_pair("norm-udp", &omitted_window, &explicit_window),
        "an omitted window_seconds is the effective one-second default"
    );

    let with_bytes = json!({"datagrams_per_second": 10, "bytes_per_second": 1_000});
    assert!(
        !udp_pair("norm-udp-axis", &omitted_window, &with_bytes),
        "an unbounded byte axis is not the same policy as a bounded one"
    );
}
