//! Issue #6008 — an HTTPRoute total deadline (`mesh_route_dispatch`
//! `request_timeout_ms`) bounds body collection that runs BEFORE
//! `before_proxy` selects the rule (SOAP WS-Security, `hmac_auth`, `waf`).
//!
//! * The preview runs the compiled matchers of one pinned generation. It runs
//!   no hook and arms nothing.
//! * A rule that cannot be decided early (an earlier plugin may still rewrite
//!   an input it matches on) contributes a candidate. The bound is the MAXIMUM
//!   candidate total, and if any candidate is untimed there is no early route
//!   bound at all.
//! * The real H1/H2 collector refuses an elapsed route budget before polling a
//!   ready body, and stops a stalled or trickling upload at the route instant
//!   even when the read timeout is `0`.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::http2 as h2_client;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use ferrum_edge::_test_support::{
    EarlyBodyCollectOutcomeForTest as Outcome, H3UploadWaitOutcomeForTest,
    buffer_early_request_body_for_test, collect_h3_upload_under_authorization_for_test,
    early_route_total_ms_for_test, early_upload_deadlines_for_test,
};
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use ferrum_edge::proxy::auth_lifetime::{
    ComposedAuthBound, StreamAuthDeadline, StreamAuthTermination,
};

// ---------------------------------------------------------------------------
// Preview fixtures
// ---------------------------------------------------------------------------

/// A plugin that may rewrite request inputs before route dispatch runs.
struct InputMutator {
    headers: bool,
    query: bool,
    destination: bool,
}

impl Plugin for InputMutator {
    fn name(&self) -> &str {
        "test_early_route_input_mutator"
    }

    fn modifies_request_headers(&self) -> bool {
        self.headers
    }

    fn modifies_request_query(&self) -> bool {
        self.query
    }

    fn modifies_request_destination(&self) -> bool {
        self.destination
    }
}

fn header_mutator() -> Arc<dyn Plugin> {
    Arc::new(InputMutator {
        headers: true,
        query: false,
        destination: false,
    })
}

fn destination_mutator() -> Arc<dyn Plugin> {
    Arc::new(InputMutator {
        headers: false,
        query: false,
        destination: true,
    })
}

fn dispatch(rules: serde_json::Value) -> Arc<dyn Plugin> {
    let plugin = MeshRouteDispatch::new(&json!({ "rules": rules })).expect("valid config");
    Arc::new(plugin)
}

fn dispatch_rejecting_unmatched(rules: serde_json::Value) -> Arc<dyn Plugin> {
    let config = json!({ "rules": rules, "reject_unmatched": true });
    Arc::new(MeshRouteDispatch::new(&config).expect("valid config"))
}

fn rule(matcher: serde_json::Value, timeout_ms: Option<u64>) -> serde_json::Value {
    let mut rule = json!({
        "match": matcher,
        "destination": {"backend_host": "127.0.0.1", "backend_port": 8080},
    });
    if let Some(ms) = timeout_ms {
        rule["request_timeout_ms"] = json!(ms);
    }
    rule
}

fn path_rule(prefix: &str, timeout_ms: Option<u64>) -> serde_json::Value {
    rule(json!({"uri": {"prefix": prefix}}), timeout_ms)
}

fn header_rule(name: &str, value: &str, timeout_ms: Option<u64>) -> serde_json::Value {
    rule(json!({"headers": {name: value}}), timeout_ms)
}

fn request(path: &str, headers: &[(&str, &str)]) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        path.to_string(),
    );
    for (name, value) in [("host", "edge.example")].iter().chain(headers) {
        ctx.headers.insert(name.to_string(), value.to_string());
    }
    ctx
}

fn preview(plugins: &[Arc<dyn Plugin>], ctx: &RequestContext) -> Option<u64> {
    early_route_total_ms_for_test(plugins, ctx, false)
}

// ---------------------------------------------------------------------------
// Deterministic selection
// ---------------------------------------------------------------------------

#[test]
fn a_deterministic_match_previews_its_total() {
    let plugins = [dispatch(json!([path_rule("/soap", Some(1500))]))];
    assert_eq!(preview(&plugins, &request("/soap/order", &[])), Some(1500));
    assert_eq!(preview(&plugins, &request("/rest/order", &[])), None);
}

#[test]
fn first_match_order_is_preserved() {
    let plugins = [dispatch(json!([
        path_rule("/soap/admin", None),
        path_rule("/soap", Some(1500)),
    ]))];
    assert_eq!(
        preview(&plugins, &request("/soap/admin/x", &[])), None,
        "the first matching rule is untimed, so no later sibling's total applies"
    );
    assert_eq!(preview(&plugins, &request("/soap/x", &[])), Some(1500));
}

#[test]
fn a_later_matched_untimed_instance_replaces_an_earlier_total() {
    let plugins = [
        dispatch(json!([path_rule("/soap", Some(1500))])),
        dispatch(json!([path_rule("/soap/bulk", None)])),
    ];
    assert_eq!(preview(&plugins, &request("/soap/bulk", &[])), None);
    assert_eq!(
        preview(&plugins, &request("/soap/order", &[])), Some(1500),
        "a non-matching later instance leaves the earlier total in force"
    );
}

#[test]
fn a_later_matched_instance_replaces_with_its_own_total() {
    let plugins = [
        dispatch(json!([path_rule("/soap", Some(9000))])),
        dispatch(json!([path_rule("/soap/fast", Some(250))])),
    ];
    assert_eq!(preview(&plugins, &request("/soap/fast", &[])), Some(250));
}

#[test]
fn an_authority_rewrite_feeds_the_next_instance() {
    let first = json!([{
        "match": {"uri": {"prefix": "/soap"}},
        "destination": {"backend_host": "127.0.0.1", "backend_port": 8080},
        "rewrite": {"authority": "soap.internal"}
    }]);
    let authority = json!({"authority": {"exact": "soap.internal"}});
    let second = json!([rule(authority, Some(700))]);
    let plugins = [dispatch(first), dispatch(second)];
    assert_eq!(preview(&plugins, &request("/soap/x", &[])), Some(700));
}

#[test]
fn a_redirect_publishes_no_total() {
    let plugins = [dispatch(json!([{
        "match": {"uri": {"prefix": "/old"}},
        "redirect": {"uri": "/new", "redirect_code": 308}
    }]))];
    assert_eq!(preview(&plugins, &request("/old/x", &[])), None);
}

#[test]
fn an_unmatched_rejection_publishes_no_total() {
    let plugins = [dispatch_rejecting_unmatched(json!([path_rule("/soap", Some(1500))]))];
    assert_eq!(preview(&plugins, &request("/other", &[])), None);
}

#[test]
fn a_chain_without_route_dispatch_has_no_early_bound() {
    let plugins = [header_mutator()];
    assert_eq!(preview(&plugins, &request("/soap", &[])), None);
}

#[test]
fn header_matches_are_decided_early_when_nothing_rewrites_headers() {
    let plugins = [dispatch(json!([
        header_rule("x-soap-tier", "gold", Some(800)),
        path_rule("/", Some(5000)),
    ]))];
    let gold = request("/soap", &[("x-soap-tier", "gold")]);
    assert_eq!(preview(&plugins, &gold), Some(800));
    assert_eq!(preview(&plugins, &request("/soap", &[])), Some(5000));
}

// ---------------------------------------------------------------------------
// Candidate-max for undetermined selection
// ---------------------------------------------------------------------------

#[test]
fn an_undetermined_rule_takes_the_maximum_candidate_total() {
    // A header rewrite ahead of dispatch makes the header rule undecidable.
    // The path rule is still decided and definitely matches, so the request
    // gets one of the two totals: the bound is the larger.
    let plugins = [
        header_mutator(),
        dispatch(json!([
            header_rule("x-soap-tier", "gold", Some(800)),
            path_rule("/", Some(5000)),
        ])),
    ];
    assert_eq!(preview(&plugins, &request("/soap", &[])), Some(5000));

    let plugins = [
        header_mutator(),
        dispatch(json!([
            header_rule("x-soap-tier", "gold", Some(9000)),
            path_rule("/", Some(5000)),
        ])),
    ];
    assert_eq!(preview(&plugins, &request("/soap", &[])), Some(9000));
}

#[test]
fn an_untimed_candidate_keeps_the_read_and_rpc_bounds() {
    let plugins = [
        header_mutator(),
        dispatch(json!([
            header_rule("x-soap-tier", "gold", Some(800)),
            header_rule("x-soap-tier", "free", None),
            path_rule("/", Some(5000)),
        ])),
    ];
    assert_eq!(
        preview(&plugins, &request("/soap", &[])), None,
        "one candidate is untimed, so no early route bound may apply"
    );
}

#[test]
fn an_undetermined_rule_that_may_fall_through_counts_the_unselected_outcome() {
    // No decided catch-all: the header rule may not match, and then the
    // request carries no total at all.
    let plugins = [
        header_mutator(),
        dispatch(json!([header_rule("x-soap-tier", "gold", Some(800))])),
    ];
    assert_eq!(preview(&plugins, &request("/soap", &[])), None);

    // An earlier instance's decided total is the fall-through outcome.
    let plugins = [
        dispatch(json!([path_rule("/", Some(3000))])),
        header_mutator(),
        dispatch(json!([header_rule("x-soap-tier", "gold", Some(800))])),
    ];
    assert_eq!(preview(&plugins, &request("/soap", &[])), Some(3000));
}

#[test]
fn identity_headers_are_never_decided_before_authentication() {
    let plugins = [dispatch(json!([
        header_rule("x-consumer-username", "alice", Some(800)),
        path_rule("/", Some(5000)),
    ]))];
    let spoofed = request("/soap", &[("x-consumer-username", "alice")]);
    assert_eq!(
        preview(&plugins, &spoofed), Some(5000),
        "a gateway-owned identity header is published only after authentication"
    );
}

#[test]
fn a_destination_claim_ahead_of_dispatch_may_skip_the_instance() {
    let plugins = [
        destination_mutator(),
        dispatch(json!([path_rule("/", Some(5000))])),
    ];
    assert_eq!(
        preview(&plugins, &request("/soap", &[])), None,
        "a router may claim the request and leave it untimed"
    );
    let plugins = [
        dispatch(json!([path_rule("/", Some(2000))])),
        destination_mutator(),
        dispatch(json!([path_rule("/", Some(5000))])),
    ];
    assert_eq!(preview(&plugins, &request("/soap", &[])), Some(5000));
}

#[test]
fn query_rules_are_undecided_behind_a_query_rewrite() {
    let query_mutator: Arc<dyn Plugin> = Arc::new(InputMutator {
        headers: false,
        query: true,
        destination: false,
    });
    let rules = json!([
        rule(json!({"query_params": {"op": "bulk"}}), Some(9000)),
        path_rule("/", Some(1000)),
    ]);
    let plugins = [query_mutator, dispatch(rules)];
    assert_eq!(preview(&plugins, &request("/soap", &[])), Some(9000));
}

// ---------------------------------------------------------------------------
// Preview / before_proxy parity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_preview_agrees_with_before_proxy_for_deterministic_requests() {
    let config = json!({ "rules": [
        header_rule("x-soap-tier", "gold", Some(800)),
        path_rule("/soap/admin", None),
        {
            "match": {"uri": {"prefix": "/old"}},
            "redirect": {"uri": "/new", "redirect_code": 308}
        },
        path_rule("/soap", Some(1500)),
        rule(json!({"methods": ["PUT"]}), Some(400)),
    ]});
    let plugin = MeshRouteDispatch::new(&config).expect("valid config");
    let previewed: Arc<dyn Plugin> = Arc::new(MeshRouteDispatch::new(&config).expect("valid"));
    let plugins = [previewed];
    let fixtures: [(&str, &[(&str, &str)]); 5] = [
        ("/soap/order", &[("x-soap-tier", "gold")]),
        ("/soap/admin/users", &[]),
        ("/old/page", &[]),
        ("/soap/order", &[]),
        ("/rest", &[]),
    ];
    for (path, headers) in fixtures {
        let ctx = request(path, headers);
        let previewed = preview(&plugins, &ctx);
        let mut live = request(path, headers);
        let mut live_headers = live.headers.clone();
        let result = plugin.before_proxy(&mut live, &mut live_headers).await;
        let published = match result {
            PluginResult::Continue => live.route_override_request_timeout_ms,
            _ => None,
        };
        assert_eq!(
            previewed, published,
            "preview drifted from before_proxy for {path}"
        );
    }
}

// ---------------------------------------------------------------------------
// H1/H2 early collector
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CollectBounds {
    max_bytes: usize,
    read_timeout_ms: u64,
    rpc_at: Option<Instant>,
    route_at: Option<Instant>,
}

type CollectReport = oneshot::Receiver<(Outcome, Instant)>;
type ReportSlot = Arc<Mutex<Option<oneshot::Sender<(Outcome, Instant)>>>>;

/// Run the production early collector on the first request a connection
/// serves and report its outcome and completion instant.
async fn collect_once(
    request: Request<Incoming>,
    bounds: CollectBounds,
    slot: ReportSlot,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    let outcome = buffer_early_request_body_for_test(
        request,
        bounds.max_bytes,
        bounds.read_timeout_ms,
        bounds.rpc_at,
        bounds.route_at,
    )
    .await;
    if let Some(tx) = slot.lock().expect("report lock").take() {
        let _ = tx.send((outcome, Instant::now()));
    }
    Ok(Response::new(Empty::new()))
}

fn report_slot() -> (ReportSlot, CollectReport) {
    let (tx, rx) = oneshot::channel();
    (Arc::new(Mutex::new(Some(tx))), rx)
}

fn serve_h1(io: DuplexStream, bounds: CollectBounds) -> CollectReport {
    let (slot, report) = report_slot();
    let service = service_fn(move |request| collect_once(request, bounds, Arc::clone(&slot)));
    tokio::spawn(async move {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .await;
    });
    report
}

fn serve_h2(io: DuplexStream, bounds: CollectBounds) -> CollectReport {
    let (slot, report) = report_slot();
    let service = service_fn(move |request| collect_once(request, bounds, Arc::clone(&slot)));
    tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    });
    report
}

fn bounds(read_timeout_ms: u64, route_at: Option<Instant>) -> CollectBounds {
    CollectBounds {
        max_bytes: 64 * 1024,
        read_timeout_ms,
        rpc_at: None,
        route_at,
    }
}

async fn report(report: CollectReport) -> (Outcome, Instant) {
    report.await.expect("the collector reports an outcome")
}

const H1_HEAD: &[u8] = b"POST /soap HTTP/1.1\r\nhost: edge.example\r\ncontent-length: 64\r\n\r\n";

#[tokio::test(start_paused = true)]
async fn h1_a_stalled_upload_ends_at_the_route_instant() {
    let start = Instant::now();
    let route_at = start + Duration::from_millis(450);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let report_rx = serve_h1(server, bounds(30_000, Some(route_at)));
    client.write_all(H1_HEAD).await.expect("head");
    client.write_all(b"<soap:Envelope>").await.expect("partial");
    let (outcome, at) = report(report_rx).await;
    assert_eq!(outcome, Outcome::RouteDeadlineExceeded);
    assert_eq!(
        at, route_at,
        "the route total, not the 30s read timeout, ends it"
    );
    drop(client);
}

#[tokio::test(start_paused = true)]
async fn h1_a_trickling_upload_ends_at_the_route_instant() {
    let start = Instant::now();
    let route_at = start + Duration::from_millis(450);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let report_rx = serve_h1(server, bounds(30_000, Some(route_at)));
    client.write_all(H1_HEAD).await.expect("head");
    let trickle = tokio::spawn(async move {
        for _ in 0..64 {
            if client.write_all(b"x").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let (outcome, at) = report(report_rx).await;
    assert_eq!(outcome, Outcome::RouteDeadlineExceeded);
    assert_eq!(at, route_at);
    trickle.abort();
}

#[tokio::test(start_paused = true)]
async fn h1_a_zero_read_timeout_is_still_bounded_by_the_route_total() {
    let start = Instant::now();
    let route_at = start + Duration::from_millis(700);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let report_rx = serve_h1(server, bounds(0, Some(route_at)));
    client.write_all(H1_HEAD).await.expect("head");
    let (outcome, at) = report(report_rx).await;
    assert_eq!(outcome, Outcome::RouteDeadlineExceeded);
    assert_eq!(at, route_at);
    drop(client);
}

#[tokio::test(start_paused = true)]
async fn h1_an_elapsed_route_budget_refuses_a_ready_body_without_polling_it() {
    let start = Instant::now();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    client.write_all(H1_HEAD).await.expect("head");
    client.write_all(&[b'x'; 64]).await.expect("complete body");
    tokio::time::advance(Duration::from_millis(20)).await;
    let route_at = start + Duration::from_millis(10);
    let report_rx = serve_h1(server, bounds(30_000, Some(route_at)));
    let (outcome, _) = report(report_rx).await;
    assert_eq!(
        outcome, Outcome::RouteDeadlineExceeded,
        "a complete body must not be accepted once the route budget is spent"
    );
    drop(client);
}

#[tokio::test(start_paused = true)]
async fn h1_a_complete_body_within_the_route_budget_is_collected() {
    let start = Instant::now();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    client.write_all(H1_HEAD).await.expect("head");
    client.write_all(&[b'x'; 64]).await.expect("complete body");
    let route_at = start + Duration::from_secs(5);
    let report_rx = serve_h1(server, bounds(0, Some(route_at)));
    let (outcome, _) = report(report_rx).await;
    assert_eq!(outcome, Outcome::Collected(64));
    drop(client);
}

#[tokio::test(start_paused = true)]
async fn h1_owner_ties_follow_the_captured_composition() {
    // A strictly earlier read timeout keeps its own terminal.
    let start = Instant::now();
    let route_at = start + Duration::from_millis(500);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let report_rx = serve_h1(server, bounds(200, Some(route_at)));
    client.write_all(H1_HEAD).await.expect("head");
    let (outcome, at) = report(report_rx).await;
    assert_eq!(outcome, Outcome::TimedOut);
    assert_eq!(at, start + Duration::from_millis(200));
    drop(client);

    // A read timeout tying the route total yields to the absolute route bound.
    let route_at = Instant::now() + Duration::from_millis(300);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let report_rx = serve_h1(server, bounds(300, Some(route_at)));
    client.write_all(H1_HEAD).await.expect("head");
    assert_eq!(report(report_rx).await.0, Outcome::RouteDeadlineExceeded);
    drop(client);

    // A client RPC deadline wins a tie with the route total.
    let tie = Instant::now() + Duration::from_millis(300);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let mut tied = bounds(0, Some(tie));
    tied.rpc_at = Some(tie);
    let report_rx = serve_h1(server, tied);
    client.write_all(H1_HEAD).await.expect("head");
    assert_eq!(report(report_rx).await.0, Outcome::DeadlineExceeded);
    drop(client);
}

#[tokio::test(start_paused = true)]
async fn h1_without_a_route_total_the_read_timeout_still_applies() {
    let start = Instant::now();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let report_rx = serve_h1(server, bounds(250, None));
    client.write_all(H1_HEAD).await.expect("head");
    let (outcome, at) = report(report_rx).await;
    assert_eq!(outcome, Outcome::TimedOut);
    assert_eq!(at, start + Duration::from_millis(250));
    drop(client);
}

/// An HTTP/2 request body whose DATA frames come from a channel and which
/// never ends while the sender is alive.
struct ChannelBody(mpsc::Receiver<Bytes>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let polled = self.0.poll_recv(cx);
        polled.map(|chunk| chunk.map(|data| Ok(Frame::data(data))))
    }
}

/// Open an HTTP/2 request with no `Content-Length` whose DATA stays open
/// while the returned sender is alive.
async fn h2_open_upload(method: &str, client: DuplexStream) -> mpsc::Sender<Bytes> {
    let io = TokioIo::new(client);
    let handshake = h2_client::handshake::<_, _, ChannelBody>(TokioExecutor::new(), io);
    let (mut sender, connection) = handshake.await.expect("h2 handshake");
    tokio::spawn(connection);
    let (tx, rx) = mpsc::channel(8);
    let request = Request::builder()
        .method(method)
        .uri("http://edge.example/soap")
        .body(ChannelBody(rx))
        .expect("request");
    tokio::spawn(async move {
        let _ = sender.send_request(request).await;
    });
    tx
}

#[tokio::test(start_paused = true)]
async fn h2_open_data_without_content_length_ends_at_the_route_instant() {
    for method in ["POST", "GET"] {
        let start = Instant::now();
        let route_at = start + Duration::from_millis(600);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let report_rx = serve_h2(server, bounds(0, Some(route_at)));
        let tx = h2_open_upload(method, client).await;
        tx.send(Bytes::from_static(b"<soap:Envelope>"))
            .await
            .expect("first DATA frame");
        let (outcome, at) = report(report_rx).await;
        assert_eq!(outcome, Outcome::RouteDeadlineExceeded, "{method}");
        assert_eq!(at, route_at, "{method}");
        drop(tx);
    }
}

// ---------------------------------------------------------------------------
// Native H3 early bound and the gRPC fold
// ---------------------------------------------------------------------------

#[test]
fn grpc_folds_the_previewed_total_into_its_rpc_deadline() {
    let now = Instant::now();
    let rpc = Some(now + Duration::from_secs(9));
    let route = Some(now + Duration::from_secs(2));
    let folded = early_upload_deadlines_for_test(rpc, route, true);
    assert_eq!(folded, (route, None));
    let split = early_upload_deadlines_for_test(rpc, route, false);
    assert_eq!(split, (rpc, route));
    let none = early_upload_deadlines_for_test(None, None, true);
    assert_eq!(none, (None, None));
}

#[test]
fn the_h3_route_owner_keeps_rpc_and_authorization_tie_precedence() {
    let now = Instant::now();
    let at = now + Duration::from_secs(1);
    let route_only = ComposedAuthBound::compose(None, None).with_route_total(Some(at));
    assert_eq!(route_only.deadline(), Some(at));
    assert!(route_only.route_wins());

    let rpc_tie = ComposedAuthBound::compose(Some(at), None).with_route_total(Some(at));
    assert!(!rpc_tie.route_wins(), "an RPC deadline wins a route tie");

    let plan = StreamAuthDeadline {
        at,
        termination: StreamAuthTermination::CredentialExpired,
    };
    let auth_tie = ComposedAuthBound::compose(None, Some(plan)).with_route_total(Some(at));
    assert!(!auth_tie.route_wins(), "authorization wins every tie");
    assert_eq!(auth_tie.deadline(), Some(at));

    let earlier = now + Duration::from_millis(400);
    let route_first =
        ComposedAuthBound::compose(Some(at), Some(plan)).with_route_total(Some(earlier));
    assert!(route_first.route_wins());
    assert_eq!(route_first.deadline(), Some(earlier));
    assert_eq!(route_first.authorization_deadline_at(), Some(at));
}

#[tokio::test(start_paused = true)]
async fn an_h3_drain_owned_by_the_route_total_ends_at_that_instant() {
    let start = Instant::now();
    let route_at = start + Duration::from_millis(350);
    let bound = ComposedAuthBound::compose(None, None).with_route_total(Some(route_at));
    let stalled = std::future::pending::<Result<(), ()>>();
    let outcome = collect_h3_upload_under_authorization_for_test(stalled, bound, 0).await;
    assert_eq!(outcome, H3UploadWaitOutcomeForTest::DeadlineExceeded);
    assert!(
        bound.route_wins(),
        "the finalizer selects the route timeout"
    );
    assert_eq!(Instant::now(), route_at);

    // A strictly earlier operator read timeout keeps its own terminal.
    let later = Instant::now() + Duration::from_millis(900);
    let bound = ComposedAuthBound::compose(None, None).with_route_total(Some(later));
    let stalled = std::future::pending::<Result<(), ()>>();
    let outcome = collect_h3_upload_under_authorization_for_test(stalled, bound, 100).await;
    assert_eq!(outcome, H3UploadWaitOutcomeForTest::TimedOut);
}

#[test]
fn every_early_collector_takes_the_previewed_route_total() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let server = include_str!("../../../src/http3/server.rs");
    assert_eq!(
        proxy.matches("plugin_cache_view.early_route_total_at(&ctx,").count(),
        3,
        "the H1/H2 pre-authenticate, authorize and pre-before_proxy collectors"
    );
    assert_eq!(
        proxy
            .matches("Err(RequestBodyBufferError::RouteDeadlineExceeded) => {")
            .count(),
        3
    );
    assert_eq!(
        server.matches("let upload_bound = h3_early_upload_bound(").count(),
        3,
        "the native-H3 pre-authenticate, authorize and pre-before_proxy drains"
    );
    assert_eq!(server.matches("upload_bound.route_wins(),").count(), 3);
}

#[test]
fn early_routes_are_never_armed_on_the_request_context() {
    let ctx = request("/soap", &[]);
    let plugins = [dispatch(json!([path_rule("/", Some(1500))]))];
    assert_eq!(preview(&plugins, &ctx), Some(1500));
    assert_eq!(ctx.route_request_deadline_at(), None);
    assert_eq!(ctx.route_override_request_timeout_ms, None);
}
