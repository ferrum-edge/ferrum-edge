//! Proxy-core contract for a route rule's total request deadline
//! (`mesh_route_dispatch` `request_timeout_ms`, Gateway API
//! `HTTPRoute.rules[].timeouts.request`, #5646).
//!
//! These run on a paused Tokio clock, so the deadline arithmetic is exact and
//! no wall-clock window can flake. They pin:
//!
//! * the attempt wrapper: a spent budget refuses an attempt WITHOUT polling it,
//!   an in-flight attempt is cancelled (dropped) at the deadline, and no
//!   deadline leaves the attempt unbounded;
//! * health attribution: only an attempt the backend actually held is charged
//!   to it — expiry during gateway/client-side work is health-neutral;
//! * framing: the route cut keeps a known response length exact, so it cannot
//!   silently turn a `Content-Length` response into a chunked one;
//! * HTTP/3 steering: `Alt-Svc` is withheld on every frontend port that serves
//!   a timed rule, because the native HTTP/3 relays refuse such a request.
//!
//! Data-plane behavior through the real gateway is covered by
//! `tests/integration/k8s_controller_gateway_status_tests.rs`.

use bytes::Bytes;
use ferrum_edge::_test_support::{
    await_route_request_deadline_for_test, proxy_body_streaming_for_test,
    proxy_body_with_client_grpc_deadline_for_test, proxy_body_with_route_request_deadline_for_test,
    route_request_deadline_outcome_for_test, route_timeout_withholds_alt_svc_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, PluginAssociation, PluginConfig, Proxy};
use ferrum_edge::proxy::body::ProxyBodyError;
use ferrum_edge::retry::ErrorClass;
use http_body::{Body, Frame, SizeHint};
use serde_json::{Value, json};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

// ── The attempt wrapper ─────────────────────────────────────────────────────

/// Sets its flag when dropped, standing in for the admission permits, upload,
/// and pooled stream a cancelled backend attempt must release.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn a_spent_budget_refuses_the_attempt_without_polling_it() {
    let polled = Arc::new(AtomicBool::new(false));
    let attempt = {
        let polled = Arc::clone(&polled);
        std::future::poll_fn(move |_| {
            polled.store(true, Ordering::SeqCst);
            Poll::Ready("dispatched")
        })
    };
    // Exactly at the deadline counts as spent: the paused clock cannot move
    // between arming and the first poll.
    let deadline = Instant::now();

    let outcome = await_route_request_deadline_for_test(Some(deadline), attempt).await;

    assert_eq!(outcome, Err("not_started"));
    assert!(
        !polled.load(Ordering::SeqCst),
        "a spent budget must refuse the attempt before it does any work"
    );
}

#[tokio::test(start_paused = true)]
async fn an_in_flight_attempt_is_cancelled_at_the_deadline() {
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(Arc::clone(&dropped));
    let attempt = async move {
        let _guard = guard;
        std::future::pending::<&'static str>().await
    };
    let started = Instant::now();
    let deadline = started + Duration::from_millis(700);

    let outcome = await_route_request_deadline_for_test(Some(deadline), attempt).await;

    assert_eq!(outcome, Err("in_flight"));
    let elapsed = Instant::now().duration_since(started);
    assert!(
        elapsed >= Duration::from_millis(700) && elapsed < Duration::from_millis(710),
        "the attempt must be cancelled at the deadline, not before or long after: {elapsed:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "cancelling the attempt must drop it, releasing what it held"
    );
}

#[tokio::test(start_paused = true)]
async fn an_attempt_that_answers_first_is_returned_unchanged() {
    let attempt = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        "answered"
    };
    let deadline = Instant::now() + Duration::from_millis(700);

    let outcome = await_route_request_deadline_for_test(Some(deadline), attempt).await;

    assert_eq!(outcome, Ok("answered"));
}

#[tokio::test(start_paused = true)]
async fn no_deadline_leaves_the_attempt_unbounded() {
    let attempt = async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        "answered"
    };

    let outcome = await_route_request_deadline_for_test(None, attempt).await;

    assert_eq!(outcome, Ok("answered"));
}

// ── Health attribution ──────────────────────────────────────────────────────

#[test]
fn only_an_attempt_the_backend_held_is_charged_to_it() {
    // `(in_flight, handed_to_backend)` -> `(logged phase, dispatch class)`.
    let outcome = route_request_deadline_outcome_for_test;
    let neutral = ("before_dispatch", ErrorClass::DispatchPolicyRejected);
    // The budget was spent before the attempt started: nothing was dialed.
    assert_eq!(outcome(false, false), neutral);
    assert_eq!(outcome(false, true), neutral);
    // Cancelled while the gateway was still collecting a stalled client
    // upload, running request-body hooks, resolving DNS, or waiting for
    // admission: the backend was never asked, so nothing is charged to it.
    assert_eq!(outcome(true, false), neutral);
    // Cancelled while the backend held the request: a backend-health signal.
    assert_eq!(
        outcome(true, true),
        ("dispatch", ErrorClass::ReadWriteTimeout)
    );
}

// ── Response framing ────────────────────────────────────────────────────────

/// A streaming response whose length is known (a backend `Content-Length`)
/// and whose frames have not arrived yet.
struct KnownLengthBody {
    len: u64,
}

impl Body for KnownLengthBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}

#[tokio::test]
async fn a_route_deadline_keeps_a_known_response_length_exact() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let body = proxy_body_streaming_for_test(Box::pin(KnownLengthBody { len: 4_096 }));
    assert_eq!(body.size_hint().exact(), Some(4_096));

    // Hyper rebuilds the stripped `Content-Length` from an exact hint. The
    // route terminal only ever ends the body with an error, so the length
    // stays advertised and a cut reads as a short body, never as a response
    // silently re-framed as chunked.
    let body = proxy_body_with_route_request_deadline_for_test(body, deadline);
    assert_eq!(body.size_hint().exact(), Some(4_096));

    // Contrast: the gRPC deadline may substitute a terminal frame, so it still
    // withholds the hint.
    let grpc = proxy_body_streaming_for_test(Box::pin(KnownLengthBody { len: 4_096 }));
    let grpc = proxy_body_with_client_grpc_deadline_for_test(grpc, deadline, None);
    assert_eq!(grpc.size_hint().exact(), None);
}

// ── HTTP/3 steering (`Alt-Svc`) ─────────────────────────────────────────────

// Gateway listener ports clear of every default gateway/admin port.
const TIMED_PORT: u16 = 18_443;
const OTHER_PORT: u16 = 18_444;

fn proxy(id: &str, listen_port: Option<u16>) -> Proxy {
    let mut proxy: Proxy = serde_json::from_value(json!({
        "id": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture");
    proxy.listen_port = listen_port;
    proxy
}

fn dispatch_plugin(scope: &str, proxy_id: Option<&str>, rule: Value) -> PluginConfig {
    serde_json::from_value(json!({
        "id": "route-dispatch",
        "plugin_name": "mesh_route_dispatch",
        "scope": scope,
        "proxy_id": proxy_id,
        "config": {"rules": [rule]}
    }))
    .expect("plugin fixture")
}

fn timed_rule() -> Value {
    json!({
        "match": {},
        "destination": {"backend_host": "v1.svc", "backend_port": 8080},
        "request_timeout_ms": 500
    })
}

fn config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        proxies,
        plugin_configs,
        ..GatewayConfig::default()
    }
}

fn withholds(config: &GatewayConfig, port: Option<u16>) -> bool {
    route_timeout_withholds_alt_svc_for_test(config, port)
}

#[test]
fn alt_svc_is_withheld_only_where_a_timed_rule_is_served() {
    // No timed rule anywhere: HTTP/3 stays advertised.
    let untimed_rule = json!({
        "match": {},
        "destination": {"backend_host": "v1.svc", "backend_port": 8080},
        "timeout_ms": 500
    });
    let untimed = config(
        vec![proxy("api", None)],
        vec![dispatch_plugin("proxy", Some("api"), untimed_rule)],
    );
    for port in [None, Some(TIMED_PORT), Some(OTHER_PORT)] {
        assert!(!withholds(&untimed, port), "{port:?}");
    }

    // A timed rule on a listener-scoped route withholds on that listener only.
    // `Alt-Svc` is origin-wide, so every response on that port withholds it,
    // not just the timed route's own.
    let scoped = config(
        vec![
            proxy("api", Some(TIMED_PORT)),
            proxy("web", Some(OTHER_PORT)),
        ],
        vec![dispatch_plugin("proxy", Some("api"), timed_rule())],
    );
    assert!(withholds(&scoped, Some(TIMED_PORT)));
    assert!(!withholds(&scoped, Some(OTHER_PORT)));
    // A response whose frontend port is unknown withholds conservatively.
    assert!(withholds(&scoped, None));

    // A port-agnostic route is reachable on every frontend port.
    let agnostic = config(
        vec![proxy("api", None)],
        vec![dispatch_plugin("proxy", Some("api"), timed_rule())],
    );
    for port in [None, Some(TIMED_PORT), Some(OTHER_PORT)] {
        assert!(withholds(&agnostic, port), "{port:?}");
    }

    // A global instance can select its timed rule on any route.
    let global = config(
        vec![proxy("api", Some(TIMED_PORT))],
        vec![dispatch_plugin("global", None, timed_rule())],
    );
    assert!(withholds(&global, Some(OTHER_PORT)));

    // A proxy-group instance applies through the proxy's association.
    let mut grouped_proxy = proxy("api", Some(TIMED_PORT));
    grouped_proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "route-dispatch".to_string(),
    }];
    let grouped = config(
        vec![grouped_proxy, proxy("web", Some(OTHER_PORT))],
        vec![dispatch_plugin("proxy_group", None, timed_rule())],
    );
    assert!(withholds(&grouped, Some(TIMED_PORT)));
    assert!(!withholds(&grouped, Some(OTHER_PORT)));

    // A disabled instance serves nothing.
    let mut disabled_plugin = dispatch_plugin("proxy", Some("api"), timed_rule());
    disabled_plugin.enabled = false;
    let disabled = config(vec![proxy("api", None)], vec![disabled_plugin]);
    assert!(!withholds(&disabled, Some(TIMED_PORT)));
}

#[tokio::test]
async fn the_gateway_stops_advertising_http3_where_a_timed_rule_is_served() {
    use ferrum_edge::config::env_config::EnvConfig;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

    let env_config = EnvConfig {
        enable_http3: true,
        ..Default::default()
    };
    let https_port = env_config.proxy_https_port;
    let timed = config(
        vec![proxy("api", None)],
        vec![dispatch_plugin("proxy", Some("api"), timed_rule())],
    );
    let (state, _) = ProxyState::new(
        timed,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("test proxy state should build");

    // HTTP/3 is enabled, but the only route carries a total request deadline
    // the native HTTP/3 relays cannot enforce, so it is never advertised.
    assert_eq!(state.alt_svc_for_frontend_port(Some(https_port)), None);
    assert_eq!(state.alt_svc_for_frontend_port(None), None);

    // Removing the deadline restores the advertisement on the next response:
    // the decision is re-derived for each published configuration generation.
    let mut untimed = state.config.load_full().as_ref().clone();
    untimed.plugin_configs.clear();
    assert_eq!(state.update_config(untimed), ConfigApplyOutcome::Applied);
    assert!(state.alt_svc_for_frontend_port(Some(https_port)).is_some());

    // A timed rule scoped to one Gateway listener withholds only that
    // listener's advertisement; a sibling listener and the global port keep it.
    let mut scoped = state.config.load_full().as_ref().clone();
    scoped.proxies[0].listen_port = Some(TIMED_PORT);
    scoped.proxies.push(proxy("web", Some(OTHER_PORT)));
    let timed_plugin = dispatch_plugin("proxy", Some("api"), timed_rule());
    scoped.plugin_configs.push(timed_plugin);
    assert_eq!(state.update_config(scoped), ConfigApplyOutcome::Applied);
    state.publish_gateway_h3_alt_svc(&[TIMED_PORT, OTHER_PORT]);
    assert_eq!(state.alt_svc_for_frontend_port(Some(TIMED_PORT)), None);
    assert!(state.alt_svc_for_frontend_port(Some(OTHER_PORT)).is_some());
    assert!(state.alt_svc_for_frontend_port(Some(https_port)).is_some());
}
