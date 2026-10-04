//! Issues #6008/#6009: shared matcher, captured clock/owner and actual retained collector.

use std::collections::HashMap;
use std::future::{Future, pending, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::PluginCache;
use ferrum_edge::_test_support::{
    EarlyRouteTotalPlanForTest, RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT,
    RequestBufferBudgetProbe, RetainedRequestOutcomeForTest,
    capture_early_route_upload_bound_for_test, capture_route_upload_bound_for_test,
    collect_h3_early_route_upload_for_test, early_upload_unresolved_result_for_test,
    finalize_plugin_rejection_for_test, gateway_deadline_response_selected_for_test,
    mark_early_upload_terminal_for_test, set_grpc_deadline_budget_for_test,
    set_request_credential_deadline_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};
use futures_util::StreamExt;
use serde_json::json;

fn request() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".into(),
        "POST".into(),
        "/upload".into(),
    );
    ctx.headers.insert("host".into(), "original.example".into());
    ctx
}

fn route(rules: serde_json::Value) -> Arc<dyn Plugin> {
    Arc::new(MeshRouteDispatch::new(&json!({"rules": rules})).unwrap())
}

fn timed_rule(ms: Option<u64>) -> serde_json::Value {
    let mut rule = json!({
        "match": {"methods": ["POST"]},
        "destination": {"backend_host": "backend.example", "backend_port": 80}
    });
    if let Some(ms) = ms {
        rule["request_timeout_ms"] = json!(ms);
    }
    rule
}

#[tokio::test]
async fn pure_selection_agrees_with_first_rule_and_later_untimed_replacement() {
    for later in [timed_rule(None), timed_rule(Some(200))] {
        let expected = if later.get("request_timeout_ms").is_some() {
            "timed"
        } else {
            "untimed"
        };
        let plugins = vec![
            route(json!([timed_rule(Some(10)), timed_rule(Some(1))])),
            route(json!([later])),
        ];
        let mut ctx = request();
        let mut headers = ctx.headers.clone();
        let plan = EarlyRouteTotalPlanForTest::new(&plugins);
        let selection = plan.selection(&ctx, &headers, false);
        assert_eq!(selection.0, expected);
        assert_eq!(ctx.route_override_request_timeout_ms, None);
        assert_eq!(ctx.route_request_deadline_at(), None);
        for plugin in plugins {
            assert!(matches!(
                plugin.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ));
        }
        assert_eq!(
            selection.1,
            ctx.route_override_request_timeout_ms.filter(|ms| *ms > 0)
        );
    }
}

#[test]
fn zero_route_total_remains_invalid_rather_than_an_untimed_profile() {
    let config = json!({"rules": [timed_rule(Some(0))]});
    assert!(MeshRouteDispatch::new(&config).is_err());
}

#[test]
fn nonmatch_preserves_timed_selection_and_is_distinct_from_an_untimed_match() {
    let mut nonmatch = timed_rule(Some(1));
    nonmatch["match"] = json!({"methods": ["GET"]});
    let ctx = request();
    let first = route(json!([timed_rule(Some(50))]));
    let second = route(json!([nonmatch]));
    let plan = EarlyRouteTotalPlanForTest::new(&[first, second.clone()]);
    assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("timed", Some(50)));
    let plan = EarlyRouteTotalPlanForTest::new(&[second]);
    assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("no_match", None));
}

#[tokio::test]
async fn host_projection_and_canonical_query_share_the_live_matcher() {
    let mut first = timed_rule(Some(10));
    first["rewrite"] = json!({"authority": "rewritten.example"});
    let mut second = timed_rule(Some(40));
    second["match"] = json!({
        "headers": {"host": "rewritten.example"}, "query_params": {"tenant": "a b"}
    });
    let plugins = vec![route(json!([first])), route(json!([second]))];
    let mut ctx = request();
    ctx.set_raw_query_string("tenant=a%20b".into());
    let mut headers = ctx.headers.clone();
    let plan = EarlyRouteTotalPlanForTest::new(&plugins);
    assert_eq!(plan.selection(&ctx, &headers, false), ("timed", Some(40)));
    assert_eq!(headers["host"], "original.example");
    for plugin in plugins {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }
    assert_eq!(ctx.route_override_request_timeout_ms, Some(40));
    ctx.set_raw_query_string("tenant=a&tenant=b".into());
    assert_eq!(plan.selection(&ctx, &ctx.headers, false).0, "terminal");
}

#[test]
fn terminals_veto_prior_timing_and_stochastic_faults_are_unresolved() {
    let ctx = request();
    for action in [
        json!({"redirect": {"uri": "/new", "redirect_code": 302}}),
        json!({"fault": {"abort": {"status_code": 503, "percentage": 100.0}}}),
    ] {
        let mut terminal = timed_rule(Some(100));
        terminal
            .as_object_mut()
            .unwrap()
            .extend(action.as_object().unwrap().clone());
        let plan = EarlyRouteTotalPlanForTest::new(&[
            route(json!([timed_rule(Some(5))])),
            route(json!([terminal])),
        ]);
        assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("terminal", None));
    }
    let mut stochastic = timed_rule(Some(100));
    stochastic["fault"] = json!({"abort": {"status_code": 503, "percentage": 50.0}});
    let plan = EarlyRouteTotalPlanForTest::new(&[route(json!([stochastic]))]);
    assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("unresolved", None));
    let mut waypoint = timed_rule(Some(100));
    waypoint["destination"]["requires_node_waypoint_authz"] = json!(true);
    let plan = EarlyRouteTotalPlanForTest::new(&[route(json!([waypoint]))]);
    let mut ctx = request();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_scoped_authz_active".into(),
        "true".into(),
    );
    assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("unresolved", None));
    assert_eq!(plan.selection(&ctx, &ctx.headers, true), ("terminal", None));
}

#[test]
fn pending_waypoint_stamps_are_cached_and_distinct_from_authenticated_identity() {
    let authz: Arc<dyn Plugin> = Arc::new(
        MeshAuthz::new(&json!({
            "per_pod_policy_scoping": true,
            "mesh_policies": [{
                "name": "scoped", "namespace": "default",
                "scope": {"kind": "namespace", "namespace": "default"},
                "rules": [{"action": "deny"}]
            }]
        }))
        .unwrap(),
    );
    assert!(authz.may_publish_route_authorization());
    let plugins = [route(json!([timed_rule(Some(100))])), authz];
    let plan = EarlyRouteTotalPlanForTest::new(&plugins);
    let mut ctx = request();
    assert!(!ctx.metadata.contains_key("mesh_authz.node_waypoint_scoped_authz_active"));
    assert_eq!(
        plan.selection_at_boundary(&ctx, &ctx.headers, false, false),
        ("unresolved", None)
    );
    assert_eq!(
        plan.selection_at_boundary(&ctx, &ctx.headers, true, false),
        ("unresolved", None)
    );
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend".into(),
        "backend.example|80".into(),
    );
    assert_eq!(
        plan.selection_at_boundary(&ctx, &ctx.headers, true, true),
        ("timed", Some(100))
    );
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend".into(),
        "other.example|80".into(),
    );
    assert_eq!(
        plan.selection_at_boundary(&ctx, &ctx.headers, true, true),
        ("terminal", None)
    );
    let mut redirect = timed_rule(Some(100));
    redirect["redirect"] = json!({"uri": "/new", "redirect_code": 302});
    let plan = EarlyRouteTotalPlanForTest::new(&[
        route(json!([redirect])),
        plugins[1].clone(),
    ]);
    assert_eq!(
        plan.selection_at_boundary(&ctx, &ctx.headers, true, false),
        ("terminal", None)
    );
}

struct DeferredDestinationPublisher;

impl Plugin for DeferredDestinationPublisher {
    fn name(&self) -> &str {
        "test_deferred_destination"
    }

    fn modifies_request_destination(&self) -> bool {
        true
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }
}

#[test]
fn possible_deferred_destination_replacement_on_either_side_is_explicit() {
    let ctx = request();
    let mesh = route(json!([timed_rule(Some(50))]));
    let mutator: Arc<dyn Plugin> = Arc::new(DeferredDestinationPublisher);
    for plugins in [vec![mesh.clone(), mutator.clone()], vec![mutator, mesh]] {
        let plan = EarlyRouteTotalPlanForTest::new(&plugins);
        assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("unresolved", None));
        assert_eq!(ctx.route_override_request_timeout_ms, None);
    }
}

#[tokio::test(start_paused = true)]
async fn receipt_anchor_and_read_zero_bound_pending_and_trickling_bodies() {
    for read_ms in [0, 1000] {
        let ctx = request();
        tokio::time::advance(Duration::from_millis(20)).await;
        let bound = capture_route_upload_bound_for_test(&ctx, Some(50), read_ms, None);
        let count = AtomicUsize::new(0);
        let trickle = async {
            loop {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        assert!(matches!(bound.collect(trickle).await, Err("route")));
        assert!(count.load(Ordering::SeqCst) < 10);
    }
    let ctx = request();
    let bound = capture_route_upload_bound_for_test(&ctx, Some(10), 0, None);
    assert_eq!(bound.collect(pending::<()>()).await, Err("route"));
}

#[tokio::test(start_paused = true)]
async fn elapsed_ready_upload_is_never_polled_and_late_wake_keeps_owner_and_ties() {
    for (read_ms, route_ms, owner) in [(5, 10, "read"), (10, 5, "route"), (5, 5, "route")] {
        let ctx = request();
        let bound = capture_route_upload_bound_for_test(&ctx, Some(route_ms), read_ms, None);
        assert_eq!(bound.owner(), Some(owner));
        tokio::time::advance(Duration::from_millis(100)).await;
        let polls = AtomicUsize::new(0);
        let ready = poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(())
        });
        assert_eq!(bound.collect(ready).await, Err(owner));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn accepted_authorization_and_rpc_ties_keep_the_established_owner() {
    for (auth_ms, owner) in [(5, "authorization"), (10, "authorization"), (15, "rpc")] {
        let mut ctx = request();
        set_grpc_deadline_budget_for_test(&mut ctx, Some(10));
        let auth = StreamAuthDeadline {
            at: tokio::time::Instant::now() + Duration::from_millis(auth_ms),
            termination: StreamAuthTermination::CredentialExpired,
        };
        let bound = capture_route_upload_bound_for_test(&ctx, Some(10), 10, Some(auth));
        assert_eq!(bound.owner(), Some(owner));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(bound.collect(async {}).await, Err(owner));
        assert_eq!(ctx.route_request_deadline_at(), None, "selection is read-only");
    }
}

fn cache_config(timeout: u64, trigger: Option<serde_json::Value>) -> GatewayConfig {
    let rule = timed_rule((timeout > 0).then_some(timeout));
    let mut plugin = json!({
        "id": "route", "plugin_name": "mesh_route_dispatch", "scope": "proxy",
        "proxy_id": "upload", "enabled": true, "priority_override": 2995,
        "config": {"rules": [rule]},
        "created_at": chrono::Utc::now(), "updated_at": chrono::Utc::now()
    });
    if let Some(trigger) = trigger {
        plugin["trigger"] = trigger;
    }
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "upload", "listen_path": "/upload", "backend_host": "backend.example",
            "backend_port": 80, "plugins": [{"plugin_config_id": "route"}]
        }],
        "plugin_configs": [plugin]
    }))
    .unwrap()
}

#[test]
fn effective_cache_scope_protocol_and_priority_match_the_normal_hook_chain() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let mut config = cache_config(50, None);
    let mut earlier = config.plugin_configs[0].clone();
    earlier.id = "earlier".into();
    earlier.priority_override = Some(2994);
    earlier.config = json!({"rules": [timed_rule(Some(5))]});
    let mut global = earlier.clone();
    global.id = "global".into();
    global.scope = PluginScope::Global;
    global.proxy_id = None;
    global.priority_override = Some(2993);
    global.config = json!({"rules": [timed_rule(Some(1))]});
    let mut reference = config.proxies[0].plugins[0].clone();
    reference.plugin_config_id = "earlier".into();
    config.proxies[0].plugins.push(reference);
    config.plugin_configs.extend([global, earlier]);
    let cache = PluginCache::new(&config).unwrap();
    let ctx = request();
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
        let view = cache.request_view("ferrum", "upload", protocol);
        let bound = capture_early_route_upload_bound_for_test(
            &view,
            &ctx,
            &ctx.headers,
            false,
            0,
        )
        .unwrap();
        assert_eq!(bound.owner(), Some("route"));
    }
    let plugins = cache.get_plugins("ferrum", "upload");
    assert_eq!(
        plugins.len(),
        2,
        "proxy-scoped same-name instances replace the global"
    );
    let plan = EarlyRouteTotalPlanForTest::new(&plugins);
    assert_eq!(plan.selection(&ctx, &ctx.headers, false), ("timed", Some(50)));
    let tcp = cache.request_view("ferrum", "upload", ProxyProtocol::Tcp);
    let bound = capture_early_route_upload_bound_for_test(
        &tcp,
        &ctx,
        &ctx.headers,
        false,
        0,
    )
    .unwrap();
    assert_eq!(bound.owner(), None);
}

#[tokio::test(start_paused = true)]
async fn pinned_reload_and_identity_trigger_refusal() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let cache = PluginCache::new(&cache_config(10, None)).unwrap();
    let pinned = cache.request_view("ferrum", "upload", ProxyProtocol::Http);
    cache.rebuild(&cache_config(500, None)).unwrap();
    let live = cache.request_view("ferrum", "upload", ProxyProtocol::Http);
    let ctx = request();
    let old = capture_early_route_upload_bound_for_test(
        &pinned,
        &ctx,
        &ctx.headers,
        false,
        0,
    )
    .unwrap();
    let new = capture_early_route_upload_bound_for_test(
        &live,
        &ctx,
        &ctx.headers,
        false,
        0,
    )
    .unwrap();
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(old.collect(async {}).await, Err("route"));
    assert_eq!(new.collect(async {}).await, Ok(()));
    let config = cache_config(
        10,
        Some(json!({"when": {"match": {"consumer": {"presence": "present"}}}})),
    );
    let cache = PluginCache::new(&config).unwrap();
    let view = cache.request_view("ferrum", "upload", ProxyProtocol::Http);
    assert!(matches!(
        capture_early_route_upload_bound_for_test(&view, &ctx, &ctx.headers, false, 0),
        Err("unresolved")
    ));
    let refusal = early_upload_unresolved_result_for_test();
    let PluginResult::Reject {
        status_code, body, ..
    } = refusal
    else {
        panic!("refusal");
    };
    assert_eq!(status_code, 503);
    assert_eq!(body, r#"{"error":"Request body policy cannot be resolved"}"#);
    assert!(!body.contains("timeout") && !body.contains("authentication"));
    let bound = capture_early_route_upload_bound_for_test(
        &view,
        &ctx,
        &ctx.headers,
        true,
        0,
    )
    .unwrap();
    assert_eq!(
        bound.owner(),
        None,
        "nonmatching post-auth gate preserves no-match"
    );
}

#[tokio::test(start_paused = true)]
async fn actual_h3_seam_refuses_unresolved_without_polling_admission_or_body() {
    let view = {
        let _env = crate::unit::env_lock::EnvGuard::new(&[]);
        let config = cache_config(
            10,
            Some(json!({"when": {"match": {"consumer": {"presence": "present"}}}})),
        );
        PluginCache::new(&config)
            .unwrap()
            .request_view("ferrum", "upload", ProxyProtocol::Http)
    };
    let ctx = request();
    let budget = RequestBufferBudgetProbe::new(UNIT, UNIT);
    let polls = AtomicUsize::new(0);
    let source = futures_util::stream::poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Bytes::new())))
    });
    let result = collect_h3_early_route_upload_for_test(
        &view,
        &ctx,
        false,
        false,
        0,
        budget.collect_retained_chunks(source, 0),
    )
    .await;
    assert!(matches!(result, Err("unresolved")));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available_bytes(), UNIT);
    assert_eq!(ctx.route_override_request_timeout_ms, None);
    assert_eq!(ctx.grpc_deadline_at(), None);
}

#[tokio::test(start_paused = true)]
async fn actual_h3_seam_keeps_untimed_read_zero_and_folds_grpc_without_an_early_arm() {
    for (timeout, grpc, expected) in [(0, false, None), (10, true, Some("rpc"))] {
        let view = {
            let _env = crate::unit::env_lock::EnvGuard::new(&[]);
            PluginCache::new(&cache_config(timeout, None))
                .unwrap()
                .request_view("ferrum", "upload", ProxyProtocol::Http)
        };
        let ctx = request();
        tokio::time::advance(Duration::from_millis(20)).await;
        let polls = AtomicUsize::new(0);
        let body = poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok::<_, ()>(()))
        });
        let result = collect_h3_early_route_upload_for_test(
            &view,
            &ctx,
            false,
            grpc,
            0,
            body,
        )
        .await;
        assert_eq!(result.err(), expected);
        assert_eq!(polls.load(Ordering::SeqCst), usize::from(expected.is_none()));
        assert_eq!(ctx.grpc_deadline_at(), None, "no RPC or attempt policy is armed");
        assert_eq!(ctx.route_request_deadline_at(), None);
        assert_eq!(ctx.route_override_request_timeout_ms, None);
    }
}

struct TerminalHeaderPolicy(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Plugin for TerminalHeaderPolicy {
    fn name(&self) -> &str {
        "test_terminal_header_policy"
    }

    fn enforces_final_client_visible_response_headers(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_headers(
        &self,
        _ctx: &mut RequestContext,
        _status: u16,
        _headers: &HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: "must not replace the captured terminal".into(),
            headers: HashMap::new(),
        }
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _status: u16,
        _headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn actual_rejection_seam_closes_headers_and_keeps_the_earlier_owner_on_late_wake() {
    for later_authorization in [false, true] {
        let mut ctx = request();
        let now = tokio::time::Instant::now();
        if later_authorization {
            ctx.authenticated_identity = Some("test-admitted-principal".into());
            set_request_credential_deadline_for_test(
                &mut ctx,
                Some(now + Duration::from_millis(10)),
            );
        } else {
            set_grpc_deadline_budget_for_test(&mut ctx, Some(10));
        }
        let bound = capture_route_upload_bound_for_test(&ctx, Some(5), 0, None);
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(bound.collect(async {}).await, Err("route"));
        mark_early_upload_terminal_for_test(&mut ctx);
        let observed = Arc::new(AtomicUsize::new(0));
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(TerminalHeaderPolicy(observed.clone()))];
        let result = finalize_plugin_rejection_for_test(
            &plugins,
            &mut ctx,
            PluginResult::Reject {
                status_code: 504,
                body: r#"{"error":"Request timeout"}"#.into(),
                headers: HashMap::from([("x-test-refused".into(), "private".into())]),
            },
        )
        .await;
        let PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } = result
        else {
            panic!("fixed route terminal");
        };
        assert_eq!(status_code, 504);
        assert_eq!(body, Bytes::from_static(br#"{"error":"Request timeout"}"#));
        assert_eq!(headers["x-gateway-error"], "request_timeout");
        assert!(!headers.contains_key("x-test-refused"));
        assert!(!headers.contains_key("grpc-status"));
        assert!(!gateway_deadline_response_selected_for_test(&ctx));
        assert_eq!(
            observed.load(Ordering::SeqCst),
            usize::from(!later_authorization)
        );
    }
}

#[tokio::test]
async fn actual_retained_collector_failure_cancellation_and_last_clone_lifetime() {
    let budget = RequestBufferBudgetProbe::new(UNIT, 2 * UNIT);
    let source = futures_util::stream::iter([Ok(Bytes::from_static(b"partial"))])
        .chain(futures_util::stream::pending());
    let mut collect = Box::pin(budget.collect_retained_chunks(source, 0));
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(collect.as_mut().poll(&mut cx).is_pending());
    assert_eq!(budget.available_bytes(), UNIT);
    drop(collect);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
    let too_large = futures_util::stream::iter([Ok(Bytes::from(vec![0; UNIT + 1]))]);
    assert!(matches!(
        budget.collect_retained_chunks(too_large, 0).await,
        Ok(RetainedRequestOutcomeForTest::TooLarge)
    ));
    assert_eq!(budget.available_bytes(), 2 * UNIT);
    let disconnect = futures_util::stream::iter([Ok(Bytes::from_static(b"partial")), Err(())]);
    assert!(budget.collect_retained_chunks(disconnect, 0).await.is_err());
    assert_eq!(budget.available_bytes(), 2 * UNIT);
    let source = futures_util::stream::iter([Ok(Bytes::from_static(b"success"))]);
    let Ok(RetainedRequestOutcomeForTest::Collected(body)) =
        budget.collect_retained_chunks(source, 0).await
    else {
        panic!("collected");
    };
    let retry = body.clone();
    let metadata = body.clone();
    assert_eq!(budget.available_bytes(), UNIT);
    drop(body);
    drop(retry);
    assert_eq!(budget.available_bytes(), UNIT);
    drop(metadata);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

#[tokio::test(start_paused = true)]
async fn actual_collector_route_cancellation_and_admission_before_poll() {
    let ctx = request();
    let budget = RequestBufferBudgetProbe::new(UNIT, UNIT);
    let bound = capture_route_upload_bound_for_test(&ctx, Some(10), 0, None);
    let source = futures_util::stream::iter([Ok(Bytes::from_static(b"partial"))])
        .chain(futures_util::stream::pending());
    assert!(matches!(
        bound.collect(budget.collect_retained_chunks(source, 0)).await,
        Err("route")
    ));
    assert_eq!(budget.available_bytes(), UNIT);
    let permit = budget.try_reserve(UNIT).unwrap();
    let polls = AtomicUsize::new(0);
    let source = futures_util::stream::poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Bytes::new())))
    });
    assert!(matches!(
        budget.collect_retained_chunks(source, 0).await,
        Ok(RetainedRequestOutcomeForTest::CapacityExceeded)
    ));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(permit);
}
