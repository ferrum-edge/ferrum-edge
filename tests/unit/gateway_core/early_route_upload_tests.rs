//! Issues #6008/#6009: shared matcher, captured clock/owner and actual retained collector.

use std::collections::HashMap;
use std::future::{Future, pending, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    EarlyRouteTotalPlanForTest, RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT,
    RequestBufferBudgetProbe, RetainedRequestCollectErrorForTest, RetainedRequestOutcomeForTest,
    capture_early_route_upload_bound_for_test, capture_route_upload_bound_for_test,
    collect_h3_early_route_upload_for_test, early_upload_unresolved_result_for_test,
    finalize_plugin_rejection_for_test, gateway_deadline_response_selected_for_test,
    mark_early_upload_terminal_for_test, retain_native_grpc_rejection_metadata_for_test,
    set_grpc_deadline_budget_for_test, set_request_credential_deadline_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};
use futures_util::StreamExt;
use serde_json::json;

fn request() -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/upload".into());
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
    assert_eq!(
        plan.selection(&ctx, &ctx.headers, false),
        ("timed", Some(50))
    );
    let plan = EarlyRouteTotalPlanForTest::new(&[second]);
    assert_eq!(
        plan.selection(&ctx, &ctx.headers, false),
        ("no_match", None)
    );
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
        assert_eq!(
            plan.selection(&ctx, &ctx.headers, false),
            ("terminal", None)
        );
    }
    let mut stochastic = timed_rule(Some(100));
    stochastic["fault"] = json!({"abort": {"status_code": 503, "percentage": 50.0}});
    let plan = EarlyRouteTotalPlanForTest::new(&[route(json!([stochastic]))]);
    assert_eq!(
        plan.selection(&ctx, &ctx.headers, false),
        ("unresolved", None)
    );
    let mut waypoint = timed_rule(Some(100));
    waypoint["destination"]["requires_node_waypoint_authz"] = json!(true);
    let plan = EarlyRouteTotalPlanForTest::new(&[route(json!([waypoint]))]);
    let mut ctx = request();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_scoped_authz_active".into(),
        "true".into(),
    );
    assert_eq!(
        plan.selection(&ctx, &ctx.headers, false),
        ("unresolved", None)
    );
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
    assert!(
        !ctx.metadata
            .contains_key("mesh_authz.node_waypoint_scoped_authz_active")
    );
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
    let plan = EarlyRouteTotalPlanForTest::new(&[route(json!([redirect])), plugins[1].clone()]);
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
        assert_eq!(
            plan.selection(&ctx, &ctx.headers, false),
            ("unresolved", None)
        );
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
        assert_eq!(
            ctx.route_request_deadline_at(),
            None,
            "selection is read-only"
        );
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

#[tokio::test]
async fn effective_cache_scope_protocol_and_priority_match_the_normal_hook_chain() {
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
    let plugins = cache.get_plugins("ferrum", "upload");
    let expected_chain = [
        ("mesh_route_dispatch", 2994),
        ("mesh_route_dispatch", 2995),
        ("__mesh_route_dispatch_finalizer", 2995),
    ];
    assert_eq!(
        plugins
            .iter()
            .map(|plugin| (plugin.name(), plugin.priority()))
            .collect::<Vec<_>>(),
        expected_chain,
        "scoped instances replace the global and retain the aggregate finalizer"
    );
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
        let view = cache.request_view("ferrum", "upload", protocol);
        let plugins = view.plugins();
        assert_eq!(
            plugins
                .iter()
                .map(|plugin| (plugin.name(), plugin.priority()))
                .collect::<Vec<_>>(),
            expected_chain
        );
        let mut ctx = request();
        let mut headers = ctx.headers.clone();
        let selection = EarlyRouteTotalPlanForTest::new(&plugins).selection(&ctx, &headers, false);
        assert_eq!(selection, ("timed", Some(50)));
        let bound =
            capture_early_route_upload_bound_for_test(&view, &ctx, &headers, false, 0).unwrap();
        assert_eq!(bound.owner(), Some("route"));
        assert_eq!(ctx.route_override_request_timeout_ms, None);
        for plugin in plugins.iter() {
            assert!(matches!(
                plugin.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ));
        }
        assert_eq!(ctx.route_override_request_timeout_ms, selection.1);
    }
    let fallback = cache.request_view("ferrum", "unconfigured", ProxyProtocol::Http);
    let fallback_plugins = fallback.plugins();
    assert_eq!(
        fallback_plugins
            .iter()
            .map(|plugin| (plugin.name(), plugin.priority()))
            .collect::<Vec<_>>(),
        [
            ("mesh_route_dispatch", 2993),
            ("__mesh_route_dispatch_finalizer", 2993),
        ]
    );
    let mut ctx = request();
    let mut headers = ctx.headers.clone();
    let selection =
        EarlyRouteTotalPlanForTest::new(&fallback_plugins).selection(&ctx, &headers, false);
    assert_eq!(selection, ("timed", Some(1)));
    let bound =
        capture_early_route_upload_bound_for_test(&fallback, &ctx, &headers, false, 0).unwrap();
    assert_eq!(bound.owner(), Some("route"));
    for plugin in fallback_plugins.iter() {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }
    assert_eq!(ctx.route_override_request_timeout_ms, selection.1);
    let tcp = cache.request_view("ferrum", "upload", ProxyProtocol::Tcp);
    assert!(tcp.plugins().is_empty());
    let ctx = request();
    let plan = EarlyRouteTotalPlanForTest::new(&tcp.plugins());
    assert_eq!(
        plan.selection(&ctx, &ctx.headers, false),
        ("no_match", None)
    );
    let bound =
        capture_early_route_upload_bound_for_test(&tcp, &ctx, &ctx.headers, false, 0).unwrap();
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
    let old =
        capture_early_route_upload_bound_for_test(&pinned, &ctx, &ctx.headers, false, 0).unwrap();
    let new =
        capture_early_route_upload_bound_for_test(&live, &ctx, &ctx.headers, false, 0).unwrap();
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
    assert_eq!(
        body,
        r#"{"error":"Request body policy cannot be resolved"}"#
    );
    assert!(!body.contains("timeout") && !body.contains("authentication"));
    let bound =
        capture_early_route_upload_bound_for_test(&view, &ctx, &ctx.headers, true, 0).unwrap();
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
        let result =
            collect_h3_early_route_upload_for_test(&view, &ctx, false, grpc, 0, body).await;
        assert_eq!(result.err(), expected);
        assert_eq!(
            polls.load(Ordering::SeqCst),
            usize::from(expected.is_none())
        );
        assert_eq!(
            ctx.grpc_deadline_at(),
            None,
            "no RPC or attempt policy is armed"
        );
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
    assert!(matches!(
        budget.collect_retained_chunks(disconnect, 0).await,
        Err(RetainedRequestCollectErrorForTest::ChunkReadFailed)
    ));
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
        bound
            .collect(budget.collect_retained_chunks(source, 0))
            .await,
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

#[tokio::test]
async fn established_correlation_headers_preserve_timed_and_untimed_method_routes() {
    use ferrum_edge::plugins::correlation_id::CorrelationId;

    for inbound in [None, Some("client-request-17")] {
        for timeout in [None, Some(50)] {
            let correlation: Arc<dyn Plugin> = Arc::new(CorrelationId::new(&json!({})).unwrap());
            let mut ctx = request();
            if let Some(id) = inbound {
                ctx.headers.insert("x-request-id".into(), id.into());
            }
            assert!(matches!(
                correlation.on_request_received(&mut ctx).await,
                PluginResult::Continue
            ));
            for header_match in [false, true] {
                let mut rule = timed_rule(timeout);
                if header_match {
                    rule["match"]["headers"] = json!({"x-request-id": ctx.headers["x-request-id"]});
                }
                let plugins = vec![correlation.clone(), route(json!([rule]))];
                let plan = EarlyRouteTotalPlanForTest::new(&plugins);
                let original_headers = ctx.headers.clone();
                let expected = match timeout {
                    Some(ms) => ("timed", Some(ms)),
                    None => ("untimed", None),
                };
                assert_eq!(plan.selection(&ctx, &ctx.headers, false), expected);
                assert_eq!(ctx.headers, original_headers);
                assert_eq!(ctx.route_request_deadline_at(), None);
                let mut headers = ctx.headers.clone();
                for plugin in &plugins {
                    assert!(matches!(
                        plugin.before_proxy(&mut ctx, &mut headers).await,
                        PluginResult::Continue
                    ));
                }
                assert_eq!(ctx.route_override_request_timeout_ms, timeout);
            }
        }
    }
}

#[tokio::test]
async fn correlation_projection_cannot_hide_an_intervening_header_mutation() {
    use ferrum_edge::plugins::correlation_id::CorrelationId;

    let correlation: Arc<dyn Plugin> = Arc::new(CorrelationId::new(&json!({})).unwrap());
    let mut ctx = request();
    correlation.on_request_received(&mut ctx).await;
    let plan =
        EarlyRouteTotalPlanForTest::new(&[correlation, route(json!([timed_rule(Some(50))]))]);
    let mut mutated = ctx.headers.clone();
    mutated.insert("x-request-id".into(), "intervening-value".into());
    assert_eq!(plan.selection(&ctx, &mutated, false), ("unresolved", None));
}

async fn retained_body(budget: &RequestBufferBudgetProbe) -> Bytes {
    let chunks = futures_util::stream::iter([Ok(Bytes::from_static(b"retained request body"))]);
    match budget.collect_retained_chunks(chunks, 0).await.unwrap() {
        RetainedRequestOutcomeForTest::Collected(body) => body,
        _ => panic!("retained collector admission"),
    }
}

#[tokio::test]
async fn actual_noop_bridge_hooks_and_cross_protocol_retry_keep_one_allocation_charged() {
    use ferrum_edge::_test_support::replay_retained_request_body_for_test;
    use ferrum_edge::plugins::correlation_id::CorrelationId;

    let budget = RequestBufferBudgetProbe::new(UNIT, UNIT);
    let body = retained_body(&budget).await;
    let original_address = body.as_ptr();
    let mut ctx = request();
    ctx.request_body_bytes = Some(body.clone());
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(CorrelationId::new(&json!({})).unwrap())];
    let headers = ctx.headers.clone();
    let backend = budget
        .prepare_retained_body(&plugins, &mut ctx, &headers, body, 0)
        .await
        .unwrap_or_else(|_| panic!("no-op hooks require no additional admission"));
    assert_eq!(backend.as_ptr(), original_address);
    let h1_retry = replay_retained_request_body_for_test(&backend);
    let h3_retry = replay_retained_request_body_for_test(&backend);
    assert_eq!(h1_retry.as_ptr(), original_address);
    assert_eq!(h3_retry.as_ptr(), original_address);
    assert_eq!(budget.available_bytes(), 0);
    drop(backend);
    drop(h1_retry);
    drop(ctx);
    assert_eq!(budget.available_bytes(), 0);
    drop(h3_retry);
    assert_eq!(budget.available_bytes(), UNIT);
}

struct RetainedProducer {
    budget: Arc<RequestBufferBudgetProbe>,
    calls: Arc<AtomicUsize>,
    stall: bool,
    output_capacity: Option<usize>,
    expected_available_before_hook: usize,
    inner: Option<Arc<dyn Plugin>>,
}

#[async_trait::async_trait]
impl Plugin for RetainedProducer {
    fn name(&self) -> &str {
        self.inner
            .as_ref()
            .map_or("test_retained_producer", |inner| inner.name())
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    fn enforces_finalized_request_policy(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.enforces_finalized_request_policy())
    }

    fn needs_final_request_body_context(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.needs_final_request_body_context())
    }

    fn may_transform_request_body(&self, ctx: &RequestContext, content_type: Option<&str>) -> bool {
        self.inner
            .as_ref()
            .is_none_or(|inner| inner.may_transform_request_body(ctx, content_type))
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        match &self.inner {
            Some(inner) => {
                inner
                    .on_final_request_body_with_context(ctx, headers, body)
                    .await
            }
            None => PluginResult::Continue,
        }
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            self.budget.available_bytes(),
            self.expected_available_before_hook,
            "output admitted before the hook"
        );
        if self.stall {
            pending::<()>().await;
        }
        if let Some(inner) = &self.inner {
            return inner
                .transform_request_body_with_context(ctx, body, content_type, headers)
                .await;
        }
        let mut output = Vec::with_capacity(self.output_capacity.unwrap_or(body.len()));
        output.extend_from_slice(body);
        Some(output)
    }
}

#[tokio::test]
async fn actual_transform_output_has_its_own_retained_allocation_lifetime() {
    use ferrum_edge::_test_support::replay_retained_request_body_for_test;

    let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, 2 * UNIT));
    let body = retained_body(&budget).await;
    let original = body.clone();
    let mut ctx = request();
    ctx.request_body_bytes = Some(body.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RetainedProducer {
        budget: budget.clone(),
        calls: calls.clone(),
        stall: false,
        output_capacity: None,
        expected_available_before_hook: 0,
        inner: None,
    })];
    let headers = ctx.headers.clone();
    let output = budget
        .prepare_retained_body(&plugins, &mut ctx, &headers, body, 0)
        .await
        .unwrap_or_else(|_| panic!("independently admitted output"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_ne!(output.as_ptr(), original.as_ptr());
    assert_eq!(budget.available_bytes(), 0);
    let retry = replay_retained_request_body_for_test(&output);
    drop(output);
    drop(original);
    assert_eq!(budget.available_bytes(), 0, "metadata retains the original");
    drop(ctx);
    assert_eq!(budget.available_bytes(), UNIT);
    drop(retry);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

#[tokio::test]
async fn actual_transform_refusal_and_cancellation_release_only_their_own_admission() {
    for stall in [false, true] {
        let total = if stall { 2 * UNIT } else { UNIT };
        let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, total));
        let body = retained_body(&budget).await;
        let mut ctx = request();
        ctx.request_body_bytes = Some(body.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RetainedProducer {
            budget: budget.clone(),
            calls: calls.clone(),
            stall,
            output_capacity: None,
            expected_available_before_hook: 0,
            inner: None,
        })];
        let headers = ctx.headers.clone();
        let mut prepare =
            Box::pin(budget.prepare_retained_body(&plugins, &mut ctx, &headers, body, 0));
        if stall {
            let waker = futures_util::task::noop_waker();
            assert!(
                prepare
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(budget.available_bytes(), 0);
            drop(prepare);
            assert_eq!(budget.available_bytes(), UNIT);
        } else {
            let PluginResult::Reject {
                status_code, body, ..
            } = prepare.await.unwrap_err()
            else {
                panic!("capacity refusal");
            };
            assert_eq!(status_code, 503);
            assert_eq!(
                body,
                ferrum_edge::_test_support::REQUEST_BUFFER_OVERLOAD_BODY
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(budget.available_bytes(), 0);
        }
        drop(ctx);
        assert_eq!(budget.available_bytes(), total);
    }
}

#[tokio::test]
async fn actual_normalization_copy_admission_preserves_both_allocation_owners() {
    let budget = RequestBufferBudgetProbe::new(UNIT, 2 * UNIT);
    let body = retained_body(&budget).await;
    let copy = budget.copy_retained_body(&body, 0).unwrap();
    assert_ne!(body.as_ptr(), copy.as_ptr());
    assert_eq!(budget.available_bytes(), 0);
    assert!(budget.copy_retained_body(&body, 0).is_none());
    drop(body);
    assert_eq!(budget.available_bytes(), UNIT);
    drop(copy);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

struct FinalizedEgressProbe {
    final_calls: Arc<AtomicUsize>,
    egress_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Plugin for FinalizedEgressProbe {
    fn name(&self) -> &str {
        "test_finalized_egress"
    }

    async fn on_final_request_body(
        &self,
        _headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        self.final_calls.fetch_add(1, Ordering::SeqCst);
        PluginResult::Continue
    }

    fn dispatches_finalized_request_egress(&self) -> bool {
        true
    }

    async fn dispatch_finalized_request_egress(
        &self,
        _ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        _body: &[u8],
        _backend_header_overlay: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.egress_calls.fetch_add(1, Ordering::SeqCst);
        PluginResult::Continue
    }
}

#[tokio::test]
async fn small_transform_with_uncovered_capacity_is_refused_before_final_egress() {
    let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, 2 * UNIT));
    let body = retained_body(&budget).await;
    assert!(body.len() < UNIT);
    let original = body.clone();
    let mut ctx = request();
    ctx.request_body_bytes = Some(body.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let final_calls = Arc::new(AtomicUsize::new(0));
    let egress_calls = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(RetainedProducer {
            budget: budget.clone(),
            calls: calls.clone(),
            stall: false,
            output_capacity: Some(UNIT + 1),
            expected_available_before_hook: 0,
            inner: None,
        }),
        Arc::new(FinalizedEgressProbe {
            final_calls: final_calls.clone(),
            egress_calls: egress_calls.clone(),
        }),
    ];
    let headers = ctx.headers.clone();
    let result = budget
        .prepare_retained_body(&plugins, &mut ctx, &headers, body, UNIT)
        .await;
    assert!(matches!(
        result,
        Err(PluginResult::Reject {
            status_code: 503,
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(final_calls.load(Ordering::SeqCst), 0);
    assert_eq!(egress_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available_bytes(), UNIT);
    assert_eq!(
        ctx.request_body_bytes.as_ref().unwrap().as_ptr(),
        original.as_ptr()
    );
    drop(ctx);
    assert_eq!(budget.available_bytes(), UNIT);
    drop(original);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

#[tokio::test]
async fn memoized_false_producer_needs_no_window_but_eligible_and_undecided_do() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let mut config = cache_config(50, None);
    let producer = &mut config.plugin_configs[0];
    producer.plugin_name = "request_transformer".into();
    producer.config = json!({"rules": [{
        "operation": "add", "target": "body", "key": "gated", "value": "yes"
    }]});
    producer.trigger = Some(
        serde_json::from_value(json!({
            "when": {"match": {"path": {"prefix": ["/eligible"]}}}
        }))
        .unwrap(),
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins_for_protocol("ferrum", "upload", ProxyProtocol::Http);
    assert!(plugins[0].modifies_request_body());
    for decision in [Some(false), Some(true), None] {
        for total in [UNIT, 2 * UNIT] {
            let budget = RequestBufferBudgetProbe::new(UNIT, total);
            let chunks = futures_util::stream::iter([Ok(Bytes::from_static(b"{}"))]);
            let collected = budget.collect_retained_chunks(chunks, UNIT).await.unwrap();
            let RetainedRequestOutcomeForTest::Collected(body) = collected else {
                panic!("admitted JSON body");
            };
            let original = body.clone();
            let mut ctx = request();
            ctx.headers
                .insert("content-type".into(), "application/json".into());
            if decision != Some(false) {
                ctx.path = "/eligible".into();
            }
            if decision.is_some() {
                assert!(matches!(
                    plugins[0].on_request_received(&mut ctx).await,
                    PluginResult::Continue
                ));
            }
            ctx.request_body_bytes = Some(body.clone());
            let headers = ctx.headers.clone();
            let result = budget
                .prepare_retained_body(&plugins, &mut ctx, &headers, body, UNIT)
                .await;
            if decision == Some(false) || total == 2 * UNIT {
                let output = result.unwrap_or_else(|_| panic!("admitted or skipped producer"));
                if decision == Some(false) {
                    assert_eq!(output.as_ptr(), original.as_ptr());
                    assert_eq!(output.as_ref(), b"{}");
                    assert_eq!(budget.available_bytes(), total - UNIT);
                } else {
                    assert_ne!(output.as_ptr(), original.as_ptr());
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
                        json!({"gated": "yes"})
                    );
                    assert_eq!(budget.available_bytes(), 0);
                }
                drop(output);
            } else {
                assert!(matches!(
                    result,
                    Err(PluginResult::Reject {
                        status_code: 503,
                        ..
                    })
                ));
            }
            assert_eq!(budget.available_bytes(), total - UNIT);
            drop(ctx);
            assert_eq!(budget.available_bytes(), total - UNIT);
            drop(original);
            assert_eq!(budget.available_bytes(), total);
        }
    }
}

#[tokio::test]
async fn exhausted_retained_xml_skips_only_the_proven_outbound_noop_transformer() {
    use ferrum_edge::_test_support::replay_retained_request_body_for_test;
    use ferrum_edge::plugins::request_transformer::RequestTransformer;

    let xml = b"<Envelope><Body>original</Body></Envelope>";
    for content_type in [
        "text/xml",
        "application/xml",
        "application/soap+xml; charset=utf-8",
    ] {
        let transformer = Arc::new(
            RequestTransformer::new(&json!({"rules": [
                {"operation": "update", "target": "header", "key": "content-type",
                 "value": content_type},
                {"operation": "add", "target": "body", "key": "added", "value": "yes"}
            ]}))
            .unwrap(),
        );
        let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, UNIT));
        let chunks = futures_util::stream::iter([Ok(Bytes::copy_from_slice(xml))]);
        let collected = budget.collect_retained_chunks(chunks, UNIT).await.unwrap();
        let RetainedRequestOutcomeForTest::Collected(body) = collected else {
            panic!("admitted XML body");
        };
        let original = body.clone();
        let mut ctx = request();
        // The inbound view is deliberately stale after the actual header hook.
        ctx.headers
            .insert("content-type".into(), "application/json".into());
        ctx.request_body_bytes = Some(body.clone());
        let mut headers = ctx.headers.clone();
        assert!(matches!(
            transformer.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert_eq!(ctx.headers["content-type"], "application/json");
        assert_eq!(headers["content-type"], content_type);
        assert!(
            transformer
                .transform_request_body(&body, Some(content_type), &headers)
                .await
                .is_none()
        );
        assert_eq!(budget.available_bytes(), 0);
        let final_calls = Arc::new(AtomicUsize::new(0));
        let egress_calls = Arc::new(AtomicUsize::new(0));
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            transformer.clone(),
            Arc::new(FinalizedEgressProbe {
                final_calls: final_calls.clone(),
                egress_calls: egress_calls.clone(),
            }),
        ];
        let output = budget
            .prepare_retained_body(&plugins, &mut ctx, &headers, body, UNIT)
            .await
            .unwrap_or_else(|_| panic!("proven XML no-op needs no output reservation"));
        assert_eq!(output.as_ref(), xml);
        assert_eq!(output.as_ptr(), original.as_ptr());
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(egress_calls.load(Ordering::SeqCst), 1);
        let retry = replay_retained_request_body_for_test(&output);
        assert_eq!(retry.as_ptr(), original.as_ptr());
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let mut producer_plugins = plugins.clone();
        producer_plugins.insert(
            1,
            Arc::new(RetainedProducer {
                budget: budget.clone(),
                calls: producer_calls.clone(),
                stall: false,
                output_capacity: None,
                expected_available_before_hook: 0,
                inner: None,
            }),
        );
        let result = budget
            .prepare_retained_body(&producer_plugins, &mut ctx, &headers, output.clone(), UNIT)
            .await;
        assert!(matches!(
            result,
            Err(PluginResult::Reject {
                status_code: 503,
                ..
            })
        ));
        assert_eq!(producer_calls.load(Ordering::SeqCst), 0);
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(egress_calls.load(Ordering::SeqCst), 1);
        drop(output);
        drop(ctx);
        drop(original);
        assert_eq!(budget.available_bytes(), 0);
        drop(retry);
        assert_eq!(budget.available_bytes(), UNIT);
    }
}

#[tokio::test]
async fn transformer_admission_preserves_unknown_types_and_undecided_triggers() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let mut config = cache_config(50, None);
    let producer = &mut config.plugin_configs[0];
    producer.plugin_name = "request_transformer".into();
    producer.config = json!({"rules": [{
        "operation": "add", "target": "body", "key": "added", "value": "yes"
    }]});
    producer.trigger = Some(
        serde_json::from_value(json!({
            "when": {"match": {"path": {"prefix": ["/upload"]}}}
        }))
        .unwrap(),
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins_for_protocol("ferrum", "upload", ProxyProtocol::Http);
    for decided in [false, true] {
        for content_type in [
            None,
            Some("unknown"),
            Some("application/*"),
            Some("application/xml; charset=\"unterminated"),
            Some("application/json"),
            Some("application/problem+json"),
            Some("application/soap+xml"),
        ] {
            let budget = RequestBufferBudgetProbe::new(UNIT, UNIT);
            let chunks = futures_util::stream::iter([Ok(Bytes::from_static(b"{}"))]);
            let collected = budget.collect_retained_chunks(chunks, UNIT).await.unwrap();
            let RetainedRequestOutcomeForTest::Collected(body) = collected else {
                panic!("admitted JSON body");
            };
            let original = body.clone();
            let mut ctx = request();
            // A stale inbound XML type cannot suppress an actual JSON producer.
            ctx.headers
                .insert("content-type".into(), "application/xml".into());
            ctx.request_body_bytes = Some(body.clone());
            if decided {
                assert!(matches!(
                    plugins[0].on_request_received(&mut ctx).await,
                    PluginResult::Continue
                ));
            }
            let mut headers = ctx.headers.clone();
            headers.remove("content-type");
            if let Some(content_type) = content_type {
                headers.insert("content-type".into(), content_type.into());
            }
            let result = budget
                .prepare_retained_body(&plugins, &mut ctx, &headers, body, UNIT)
                .await;
            if decided && content_type == Some("application/soap+xml") {
                let output = result.unwrap_or_else(|_| panic!("memoized eligible XML no-op"));
                assert_eq!(output.as_ptr(), original.as_ptr());
                assert_eq!(output.as_ref(), b"{}");
                drop(output);
            } else {
                assert!(matches!(
                    result,
                    Err(PluginResult::Reject {
                        status_code: 503,
                        ..
                    })
                ));
            }
            assert_eq!(budget.available_bytes(), 0);
            assert_eq!(
                ctx.request_body_bytes.as_ref().unwrap().as_ptr(),
                original.as_ptr()
            );
            drop(ctx);
            assert_eq!(budget.available_bytes(), 0);
            drop(original);
            assert_eq!(budget.available_bytes(), UNIT);
        }
    }
}

enum NormalizerOutcome {
    Rewrite,
    Reject,
    Stall,
    Uncovered,
}

struct RetainedNormalizer {
    budget: Arc<RequestBufferBudgetProbe>,
    calls: Arc<AtomicUsize>,
    outcome: NormalizerOutcome,
}

#[async_trait::async_trait]
impl Plugin for RetainedNormalizer {
    fn name(&self) -> &str {
        "test_retained_normalizer"
    }

    fn normalizes_buffered_request_body_before_before_proxy(&self) -> bool {
        true
    }

    async fn normalize_buffered_request_body_before_before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        body: &mut Vec<u8>,
    ) -> PluginResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(self.budget.available_bytes(), 0);
        match self.outcome {
            NormalizerOutcome::Reject => {
                return PluginResult::Reject {
                    status_code: 400,
                    headers: HashMap::new(),
                    body: "normalization refused".into(),
                };
            }
            NormalizerOutcome::Stall => pending::<()>().await,
            NormalizerOutcome::Uncovered => *body = Vec::with_capacity(UNIT + 1),
            NormalizerOutcome::Rewrite => body.clear(),
        }
        body.extend_from_slice(b"normalized body");
        ctx.metadata
            .insert("compression:request_decoded".into(), "true".into());
        headers.remove("content-encoding");
        PluginResult::Continue
    }
}

#[tokio::test]
async fn complete_normalization_refreshes_views_and_preserves_independent_owners() {
    let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, 2 * UNIT));
    let body = retained_body(&budget).await;
    let original = body.clone();
    let mut ctx = request();
    ctx.request_body_bytes = Some(body.clone());
    ctx.metadata
        .insert("request_body".into(), "original body".into());
    let calls = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RetainedNormalizer {
        budget: budget.clone(),
        calls: calls.clone(),
        outcome: NormalizerOutcome::Rewrite,
    })];
    let mut headers = ctx.headers.clone();
    headers.insert("content-encoding".into(), "gzip".into());
    let output = budget
        .normalize_retained_body(&plugins, &mut ctx, &mut headers, body, UNIT, true, true)
        .await
        .unwrap_or_else(|_| panic!("admitted normalization"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(output.as_ref(), b"normalized body");
    assert_ne!(output.as_ptr(), original.as_ptr());
    assert_eq!(
        ctx.request_body_bytes.as_ref().unwrap().as_ptr(),
        output.as_ptr()
    );
    assert_eq!(ctx.metadata["request_body"], "normalized body");
    assert_eq!(
        ctx.metadata["request_body_size_bytes"],
        output.len().to_string()
    );
    assert!(!headers.contains_key("content-encoding"));
    assert_eq!(budget.available_bytes(), 0);
    let retry = output.clone();
    drop(output);
    drop(ctx);
    assert_eq!(budget.available_bytes(), 0);
    drop(retry);
    assert_eq!(budget.available_bytes(), UNIT);
    drop(original);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

#[tokio::test]
async fn complete_normalization_rejection_and_cancellation_keep_original_owners_charged() {
    for outcome in [
        NormalizerOutcome::Reject,
        NormalizerOutcome::Stall,
        NormalizerOutcome::Uncovered,
    ] {
        let stall = matches!(outcome, NormalizerOutcome::Stall);
        let expected_status = if matches!(outcome, NormalizerOutcome::Reject) {
            400
        } else {
            503
        };
        let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, 2 * UNIT));
        let body = retained_body(&budget).await;
        let original = body.clone();
        let mut ctx = request();
        ctx.request_body_bytes = Some(body.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RetainedNormalizer {
            budget: budget.clone(),
            calls: calls.clone(),
            outcome,
        })];
        let mut headers = ctx.headers.clone();
        let mut normalize = Box::pin(budget.normalize_retained_body(
            &plugins,
            &mut ctx,
            &mut headers,
            body,
            UNIT,
            true,
            true,
        ));
        if stall {
            let waker = futures_util::task::noop_waker();
            assert!(
                normalize
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(budget.available_bytes(), 0);
            drop(normalize);
        } else {
            let PluginResult::Reject { status_code, .. } = normalize.await.unwrap_err() else {
                panic!("normalization rejection");
            };
            assert_eq!(status_code, expected_status);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(budget.available_bytes(), UNIT);
        assert_eq!(
            ctx.request_body_bytes.as_ref().unwrap().as_ptr(),
            original.as_ptr()
        );
        drop(ctx);
        assert_eq!(budget.available_bytes(), UNIT);
        drop(original);
        assert_eq!(budget.available_bytes(), 2 * UNIT);
    }
}

#[tokio::test]
async fn complete_normalization_admission_refusal_precedes_the_hook() {
    let budget = Arc::new(RequestBufferBudgetProbe::new(UNIT, UNIT));
    let body = retained_body(&budget).await;
    let original = body.clone();
    let mut ctx = request();
    ctx.request_body_bytes = Some(body.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RetainedNormalizer {
        budget: budget.clone(),
        calls: calls.clone(),
        outcome: NormalizerOutcome::Rewrite,
    })];
    let mut headers = ctx.headers.clone();
    let result = budget
        .normalize_retained_body(&plugins, &mut ctx, &mut headers, body, UNIT, true, true)
        .await;
    assert!(matches!(
        result,
        Err(PluginResult::Reject {
            status_code: 503,
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available_bytes(), 0);
    drop(ctx);
    assert_eq!(budget.available_bytes(), 0);
    drop(original);
    assert_eq!(budget.available_bytes(), UNIT);
}

#[tokio::test]
async fn h3_replacements_use_grpc_and_grpc_web_ceilings_including_route_caps() {
    use base64::Engine;
    use ferrum_edge::_test_support::{
        replay_retained_request_body_for_test, retained_h3_request_body_limit_for_test,
    };
    use ferrum_edge::config::types::HttpFlavor;
    use ferrum_edge::plugins::grpc_web::GrpcWebPlugin;

    const MIB: usize = 1024 * 1024;
    let mut frames = vec![0; 2 * MIB];
    let message_len = (frames.len() - 5) as u32;
    frames[1..5].copy_from_slice(&message_len.to_be_bytes());
    for (flavor, grpc_web) in [
        (HttpFlavor::Grpc, false),
        (HttpFlavor::Plain, true),
        (HttpFlavor::Plain, false),
    ] {
        for route_limit in [None, Some(3 * MIB), Some(MIB)] {
            let mut ctx = request();
            ctx.route_request_body_limit_bytes = route_limit.map(|limit| limit as u64);
            let content_type = if grpc_web {
                "application/grpc-web-text"
            } else {
                "application/grpc"
            };
            ctx.headers
                .insert("content-type".into(), content_type.into());
            let translator: Arc<dyn Plugin> = Arc::new(GrpcWebPlugin::new(&json!({})).unwrap());
            if grpc_web {
                assert!(matches!(
                    translator.on_request_received(&mut ctx).await,
                    PluginResult::Continue
                ));
            }
            let limit = retained_h3_request_body_limit_for_test(flavor, &ctx, MIB, 4 * MIB);
            let expected = if matches!(flavor, HttpFlavor::Grpc) || grpc_web {
                route_limit.unwrap_or(4 * MIB)
            } else {
                MIB
            };
            assert_eq!(limit, expected);
            let requested_total = if grpc_web { 8 * MIB } else { limit + 2 * MIB };
            let budget = Arc::new(RequestBufferBudgetProbe::new(4 * MIB, requested_total));
            // The shared budget floors its total at the fallback. A 1 MiB
            // route cap therefore leaves 1 MiB free even while input and output
            // are both fully admitted; exhaustion is not the admission proof.
            let total = requested_total.max(4 * MIB);
            assert_eq!(budget.available_bytes(), total);
            let wire = if grpc_web {
                base64::engine::general_purpose::STANDARD
                    .encode(&frames)
                    .into_bytes()
            } else {
                frames.clone()
            };
            let input_charge = wire.len().div_ceil(UNIT) * UNIT;
            let chunks = futures_util::stream::iter([Ok(Bytes::from(wire))]);
            let collect_limit = if grpc_web { 4 * MIB } else { 2 * MIB };
            let collected = budget
                .collect_retained_chunks(chunks, collect_limit)
                .await
                .unwrap();
            let RetainedRequestOutcomeForTest::Collected(body) = collected else {
                panic!("admitted wire body");
            };
            assert_eq!(budget.available_bytes(), total - input_charge);
            let original = body.clone();
            ctx.request_body_bytes = Some(body.clone());
            let mut headers = ctx.headers.clone();
            if grpc_web {
                assert!(matches!(
                    translator.before_proxy(&mut ctx, &mut headers).await,
                    PluginResult::Continue
                ));
            } else {
                // Exercise the full normalization path with the same selected
                // ceiling before testing a distinct post-before_proxy output.
                let normalized = budget
                    .normalize_retained_body(
                        &[],
                        &mut ctx,
                        &mut headers,
                        body.clone(),
                        limit,
                        false,
                        false,
                    )
                    .await;
                assert_eq!(normalized.is_ok(), limit >= frames.len());
                if let Ok(normalized) = &normalized {
                    assert_eq!(normalized.as_ref(), frames.as_slice());
                    assert_ne!(normalized.as_ptr(), original.as_ptr());
                    assert_eq!(budget.available_bytes(), total - input_charge - 2 * MIB);
                }
                drop(normalized);
                assert_eq!(budget.available_bytes(), total - input_charge);
            }
            let final_calls = Arc::new(AtomicUsize::new(0));
            let egress_calls = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            let output_window = budget.buffered_request_body_ceiling(limit);
            let producer: Arc<dyn Plugin> = Arc::new(RetainedProducer {
                budget: budget.clone(),
                calls: calls.clone(),
                stall: false,
                output_capacity: None,
                expected_available_before_hook: total - input_charge - output_window,
                inner: grpc_web.then_some(translator),
            });
            let plugins: Vec<Arc<dyn Plugin>> = vec![
                producer,
                Arc::new(FinalizedEgressProbe {
                    final_calls: final_calls.clone(),
                    egress_calls: egress_calls.clone(),
                }),
            ];
            let result = budget
                .prepare_retained_body(&plugins, &mut ctx, &headers, body, limit)
                .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if limit >= frames.len() {
                let output = result.unwrap_or_else(|_| panic!("valid 2 MiB replacement"));
                assert_eq!(output.as_ref(), frames.as_slice());
                assert_ne!(
                    output.as_ptr(),
                    ctx.request_body_bytes.as_ref().unwrap().as_ptr()
                );
                assert_eq!(final_calls.load(Ordering::SeqCst), 1);
                assert_eq!(egress_calls.load(Ordering::SeqCst), 1);
                assert_eq!(budget.available_bytes(), total - input_charge - 2 * MIB);
                let retry = replay_retained_request_body_for_test(&output);
                assert_eq!(retry.as_ptr(), output.as_ptr());
                drop(output);
                assert_eq!(budget.available_bytes(), total - input_charge - 2 * MIB);
                drop(ctx);
                assert_eq!(budget.available_bytes(), total - input_charge - 2 * MIB);
                drop(original);
                assert_eq!(budget.available_bytes(), total - 2 * MIB);
                drop(retry);
            } else {
                assert!(matches!(
                    result,
                    Err(PluginResult::Reject {
                        status_code: 503,
                        ..
                    })
                ));
                assert_eq!(final_calls.load(Ordering::SeqCst), 0);
                assert_eq!(egress_calls.load(Ordering::SeqCst), 0);
                assert_eq!(budget.available_bytes(), total - input_charge);
                drop(ctx);
                assert_eq!(budget.available_bytes(), total - input_charge);
                drop(original);
            }
            assert_eq!(budget.available_bytes(), total);
        }
    }
}

/// Both H1/H2 rejection handoffs preserve the existing snapshot's identity
/// and admission through every clone, without reserving under saturation.
#[tokio::test]
async fn completed_h1_rejection_snapshot_keeps_admission_until_its_last_owner() {
    for native_grpc_final in [false, true] {
        let budget = RequestBufferBudgetProbe::new(UNIT, UNIT);
        let permit = budget.try_reserve(UNIT).expect("collector admission");
        let mut ctx = request();
        ctx.request_body_bytes = Some(Bytes::from(vec![0xff; 32]));
        let pointer = ctx.request_body_bytes.as_ref().unwrap().as_ptr();
        if native_grpc_final {
            let collected = permit.into_charged_bytes(vec![0xff; 32]);
            retain_native_grpc_rejection_metadata_for_test(&mut ctx, collected);
        } else {
            permit.retain_rejection_metadata(&mut ctx);
        }
        let final_owner = ctx.request_body_bytes.as_ref().unwrap().clone();
        assert_eq!(final_owner.as_ptr(), pointer);
        assert_eq!(budget.available_bytes(), 0);
        finalize_plugin_rejection_for_test(
            &[],
            &mut ctx,
            PluginResult::RejectBinary {
                status_code: 400,
                body: Bytes::new(),
                headers: HashMap::new(),
            },
        )
        .await;
        assert!(ctx.request_body_bytes.is_none());
        assert_eq!(
            budget.available_bytes(),
            0,
            "the external snapshot still owns its charge"
        );
        drop(final_owner);
        assert_eq!(budget.available_bytes(), UNIT);
    }
}
