//! Black-box compatibility checks for DestinationRule connectionPool semantics.
//!
//! These tests intentionally observe real backend sockets instead of only
//! asserting serialized projection. They pin the unsupported cases that must be
//! reported as deferred rather than represented as effective resource limits.

use crate::scaffolding::port_registry::TestSocket;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::backend_conn_limit::{
    BackendConnectionLimiter, ReqwestConnectionAdmission, is_backend_connection_limit_error,
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResolvedPortOverride,
};
use ferrum_edge::config::{EnvConfig, PoolConfig};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

fn proxy_for_backend(port: u16) -> Proxy {
    Proxy {
        id: "dr-connection-pool-audit".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: Some(60),
        pool_enable_http_keep_alive: Some(true),
        pool_enable_http2: Some(false),
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn reqwest_pool() -> ConnectionPool {
    ConnectionPool::new(
        PoolConfig::default(),
        EnvConfig::default(),
        DnsCache::new(DnsConfig::default()),
        None,
        Arc::new(Vec::new()),
    )
}

async fn start_counting_h1_backend(
    response_delay: Duration,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind counting backend");
    let addr = listener.local_addr().expect("backend addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = accepted.clone();

    let handle = tokio::spawn(async move {
        while let Ok((socket, _peer)) = listener.accept().await {
            accepted_for_task.fetch_add(1, Ordering::SeqCst);
            let delay = response_delay;
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });

    (addr, accepted, handle)
}

#[tokio::test]
async fn max_requests_per_connection_does_not_close_h1_backend_after_n_requests() {
    let (backend, accepted, _backend_task) = start_counting_h1_backend(Duration::ZERO).await;
    let mut proxy = proxy_for_backend(backend.port());
    proxy.pool_max_requests_per_connection = Some(2);

    let pool = reqwest_pool();
    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/audit", backend.ip(), backend.port());

    for _ in 0..5 {
        let response = client.get(&url).send().await.expect("backend response");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let _ = response.bytes().await.expect("body");
    }

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "five sequential requests with pool_max_requests_per_connection=2 stayed on one reusable backend socket; close-after-N is not implemented"
    );
}

/// A reqwest client built WITHOUT the admission hook is socket-unbounded. This
/// is the control for the tests below: it proves the ceiling comes from the
/// connector hook, not from pool keys or client configuration, and it pins the
/// behavior that made a request-lifetime approximation wrong (issue #3290).
#[tokio::test]
async fn reqwest_client_without_admission_hook_is_socket_unbounded() {
    let (backend, accepted, _backend_task) =
        start_counting_h1_backend(Duration::from_millis(150)).await;
    let mut proxy = proxy_for_backend(backend.port());
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        backend.port(),
        ResolvedPortOverride {
            max_connections: Some(1),
            ..ResolvedPortOverride::default()
        },
    )]));

    let pool = reqwest_pool();
    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/slow", backend.ip(), backend.port());

    let (first, second) = tokio::join!(client.get(&url).send(), client.get(&url).send());
    assert_eq!(
        first.expect("first response").status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        second.expect("second response").status(),
        reqwest::StatusCode::OK
    );

    assert!(
        accepted.load(Ordering::SeqCst) >= 2,
        "a client with no admission hook applies no per-destination socket ceiling of its own"
    );
}

// ============================================================================
// DestinationRule `connectionPool.tcp.maxConnections` on the reqwest transports
// (issue #3290).
//
// Every assertion below is on sockets the BACKEND accepted, not on gateway
// bookkeeping, so a limiter that merely counts requests cannot pass them.
// ============================================================================

/// Build a pool whose clients all share one admission hook, plus the limiter
/// and hook so tests can publish lanes and read the live socket count.
fn admitted_reqwest_pool() -> (
    ConnectionPool,
    Arc<BackendConnectionLimiter>,
    Arc<ReqwestConnectionAdmission>,
) {
    let limiter = Arc::new(BackendConnectionLimiter::new());
    let admission = Arc::new(ReqwestConnectionAdmission::new(Arc::clone(&limiter), 8));
    let pool = reqwest_pool();
    pool.attach_reqwest_connection_admission(Arc::clone(&admission));
    (pool, limiter, admission)
}

fn capped_proxy(port: u16, cap: u32) -> Proxy {
    let mut proxy = proxy_for_backend(port);
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        port,
        ResolvedPortOverride {
            max_connections: Some(cap),
            ..ResolvedPortOverride::default()
        },
    )]));
    proxy
}

/// The defect a request-lifetime slot could not catch: after a request
/// completes, reqwest keeps the socket OPEN and idle. A second, strictly
/// sequential request must therefore either reuse that socket (no new slot) or
/// be refused — never open a second socket past `maxConnections: 1`.
#[tokio::test]
async fn sequential_requests_never_exceed_the_cap_while_a_socket_sits_idle() {
    let (backend, accepted, _backend_task) = start_counting_h1_backend(Duration::ZERO).await;
    let (pool, limiter, admission) = admitted_reqwest_pool();
    let proxy = capped_proxy(backend.port(), 1);
    let _lane = admission.lease_lane(1, "127.0.0.1", backend.port(), backend.port(), 1);

    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/audit", backend.ip(), backend.port());

    for _ in 0..5 {
        let response = client.get(&url).send().await.expect("sequential response");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        // Drain so the socket returns to the idle pool.
        let _ = response.bytes().await.expect("body");
    }

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "sequential requests must reuse the one admitted socket"
    );
    assert_eq!(
        limiter.current("127.0.0.1", backend.port()),
        1,
        "the slot must still be held while the socket sits idle in reqwest's pool — releasing it at request completion is exactly the bug this enforces against"
    );
}

/// Cap exhaustion is decided before the second physical dial: with the one
/// admitted socket busy, a concurrent request that needs a NEW socket is
/// refused rather than opening one.
#[tokio::test]
async fn cap_exhaustion_refuses_the_second_physical_dial() {
    let (backend, accepted, _backend_task) =
        start_counting_h1_backend(Duration::from_millis(300)).await;
    let (pool, limiter, admission) = admitted_reqwest_pool();
    let proxy = capped_proxy(backend.port(), 1);
    let _lane = admission.lease_lane(1, "127.0.0.1", backend.port(), backend.port(), 1);

    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/slow", backend.ip(), backend.port());

    let (first, second) = tokio::join!(client.get(&url).send(), client.get(&url).send());
    let outcomes = [first, second];
    let refused = outcomes
        .iter()
        .filter(|outcome| match outcome {
            Ok(_) => false,
            Err(error) => is_backend_connection_limit_error(error),
        })
        .count();

    assert_eq!(refused, 1, "one request must be refused at the ceiling");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the refused request must not have opened a second backend socket"
    );
    drop(outcomes);
    drop(client);
    pool.clear();
    // Dropping the client drops its pooled connection, which drops the token.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if limiter.current("127.0.0.1", backend.port()) == 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        limiter.current("127.0.0.1", backend.port()),
        0,
        "the slot must retire when the physical connection is dropped"
    );
}

/// Divergent reqwest pool keys for the same destination each get their own
/// `reqwest::Client` (and therefore their own socket pool). They must still
/// share ONE ceiling, which is what a per-client counter could not do.
#[tokio::test]
async fn distinct_reqwest_pool_keys_share_one_destination_ceiling() {
    let (backend, accepted, _backend_task) =
        start_counting_h1_backend(Duration::from_millis(300)).await;
    let (pool, _limiter, admission) = admitted_reqwest_pool();
    let _lane = admission.lease_lane(1, "127.0.0.1", backend.port(), backend.port(), 1);

    let first_proxy = capped_proxy(backend.port(), 1);
    let mut second_proxy = capped_proxy(backend.port(), 1);
    // A different `upstream_subset` is a pool-key partition, so this proxy gets
    // a DIFFERENT client with its own connection pool.
    second_proxy.upstream_subset = Some("v2".to_string());

    let first_client = pool.get_client(&first_proxy).await.expect("first client");
    let second_client = pool.get_client(&second_proxy).await.expect("second client");
    assert_ne!(
        pool.pool_key_for_warmup(&first_proxy),
        pool.pool_key_for_warmup(&second_proxy),
        "test precondition: the two proxies must land on distinct reqwest pool keys"
    );

    let url = format!("http://{}:{}/slow", backend.ip(), backend.port());
    let (first, second) = tokio::join!(
        first_client.get(&url).send(),
        second_client.get(&url).send()
    );
    let refused = [first, second]
        .iter()
        .filter(|outcome| match outcome {
            Ok(_) => false,
            Err(error) => is_backend_connection_limit_error(error),
        })
        .count();

    assert_eq!(refused, 1, "both clients share one slot");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "only one physical socket may exist across both clients"
    );
}

/// HTTP/2 streams multiplex onto one physical connection and must take no
/// additional slot, so `maxConnections: 1` never sheds an h2 backend.
#[tokio::test]
async fn h2_streams_multiplex_without_consuming_extra_slots() {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind h2c backend");
    let addr = listener.local_addr().expect("backend addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = Arc::clone(&accepted);
    let _task = tokio::spawn(async move {
        while let Ok((socket, _peer)) = listener.accept().await {
            accepted_for_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let executor = hyper_util::rt::TokioExecutor::new();
                let _ = hyper::server::conn::http2::Builder::new(executor)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });

    let (_pool, limiter, admission) = admitted_reqwest_pool();
    let _lane = admission.lease_lane(1, "127.0.0.1", addr.port(), addr.port(), 1);
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .connection_admission(Arc::clone(&admission) as Arc<dyn reqwest::ConnectionAdmission>)
        .build()
        .expect("h2c client");

    let url = format!("http://{}:{}/h2", addr.ip(), addr.port());
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let url = url.clone();
        tasks.push(tokio::spawn(async move { client.get(url).send().await }));
    }
    for task in tasks {
        let response = task
            .await
            .expect("join")
            .expect("multiplexed h2 streams must not be shed by a CONNECTION cap");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "8 concurrent h2 requests must share one physical connection"
    );
    assert_eq!(
        limiter.current("127.0.0.1", addr.port()),
        1,
        "multiplexed streams must not each consume a connection slot"
    );
}

/// A `maxConnections` an operator REMOVED must stop shedding traffic once the
/// dispatches that ran under it have drained — the lane exists only while a
/// capped dispatch holds a lease, so nothing has to be swept and nothing lingers.
#[tokio::test]
async fn a_removed_cap_stops_applying_once_its_dispatches_drain() {
    let (backend, accepted, _backend_task) =
        start_counting_h1_backend(Duration::from_millis(300)).await;
    let (pool, _limiter, admission) = admitted_reqwest_pool();
    let proxy = capped_proxy(backend.port(), 1);
    {
        let _lane = admission.lease_lane(1, "127.0.0.1", backend.port(), backend.port(), 1);
        assert!(admission.lane_for("127.0.0.1", backend.port()).is_some());
    }
    // The operator removed the cap, so no later dispatch leases this lane.
    assert_eq!(
        admission.live_lane_count(),
        0,
        "the lane must not outlive the dispatches that were governed by it"
    );

    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/slow", backend.ip(), backend.port());
    let (first, second) = tokio::join!(client.get(&url).send(), client.get(&url).send());
    assert_eq!(
        first.expect("first response").status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        second.expect("second response").status(),
        reqwest::StatusCode::OK
    );
    assert!(
        accepted.load(Ordering::SeqCst) >= 2,
        "with the cap removed both requests must be free to open their own socket"
    );
}

/// The lane is keyed by the DIAL port but counts on the DestinationRule POLICY
/// port, so a `targetPort` remap shares one ceiling with every other transport
/// to that destination instead of getting a second one.
#[tokio::test]
async fn target_port_remap_counts_on_the_policy_port() {
    let (backend, _accepted, _backend_task) = start_counting_h1_backend(Duration::ZERO).await;
    let (pool, limiter, admission) = admitted_reqwest_pool();
    let proxy = capped_proxy(backend.port(), 2);

    // Service port 8080 remapped onto the workload/dial port.
    let _lane = admission.lease_lane(1, "127.0.0.1", backend.port(), 8080, 2);

    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/audit", backend.ip(), backend.port());
    let response = client.get(&url).send().await.expect("response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let _ = response.bytes().await.expect("body");

    assert_eq!(
        limiter.current("127.0.0.1", 8080),
        1,
        "the socket must be counted on the policy port"
    );
    assert_eq!(
        limiter.current("127.0.0.1", backend.port()),
        0,
        "the dial port must not become a second counter lane"
    );
}

// ---------------------------------------------------------------------------
// Lane binding under conflicting policy and across a config reload.
//
// `maxConnections` is deliberately NOT reqwest pool-key material, so two
// logically distinct upstreams (different proxies, subsets, or `targetPort`
// remaps) can resolve DIFFERENT `(policy port, cap)` for the SAME dial address
// and share one `reqwest::Client` — one physical socket pool. Which lane a
// connect attempt is admitted against must therefore be deterministic and
// fail-closed, never last-writer-wins.
// ---------------------------------------------------------------------------

fn admission_only() -> Arc<ReqwestConnectionAdmission> {
    Arc::new(ReqwestConnectionAdmission::new(
        Arc::new(BackendConnectionLimiter::new()),
        8,
    ))
}

/// Two concurrently in-flight dispatches resolve conflicting policy for one dial
/// address. The strictest lane must govern regardless of which leased first —
/// under the previous last-writer-wins publication this assertion fails in one
/// of the two orders.
#[test]
fn conflicting_reqwest_lanes_resolve_to_the_strictest_in_either_order() {
    for (first, second) in [((8080u16, 4u32), (80u16, 1u32)), ((80, 1), (8080, 4))] {
        let admission = admission_only();
        let _a = admission.lease_lane(1, "backend", 9000, first.0, first.1);
        let _b = admission.lease_lane(1, "backend", 9000, second.0, second.1);
        let lane = admission
            .lane_for("backend", 9000)
            .expect("a lane must be live while both dispatches hold leases");
        assert_eq!(
            (lane.policy_port(), lane.cap()),
            (80, 1),
            "the strictest live lane must govern regardless of lease order \
             (leased {first:?} then {second:?})"
        );
    }
}

/// A newer configuration generation replaces the lane wholesale. "Strictest
/// wins" resolves conflicts WITHIN one generation; it must never pin an operator
/// to a ceiling they already raised or retired.
#[test]
fn a_newer_config_generation_replaces_a_retired_reqwest_lane_wholesale() {
    let admission = admission_only();
    let _old = admission.lease_lane(1, "backend", 8080, 8080, 1);
    let _new = admission.lease_lane(2, "backend", 8080, 8080, 4);
    let lane = admission.lane_for("backend", 8080).expect("live lane");
    assert_eq!(
        lane.cap(),
        4,
        "the newest published generation must govern, not the strictest generation"
    );
}

/// The publish-to-admit race across a reload: a request pinned to a retired
/// generation reaches dispatch after the new configuration published. It keeps
/// the destination governed but must not weaken the live policy back — the
/// fail-closed direction.
#[test]
fn a_retired_generation_cannot_weaken_a_live_reqwest_lane() {
    let admission = admission_only();
    let _current = admission.lease_lane(2, "backend", 8080, 8080, 4);
    let _retired = admission.lease_lane(1, "backend", 8080, 8080, 1);
    let lane = admission.lane_for("backend", 8080).expect("live lane");
    assert_eq!(
        (lane.policy_port(), lane.cap()),
        (8080, 4),
        "a request pinned to a retired generation must not replace the live lane"
    );
}

/// The lane registry is bounded by in-flight capped dispatches, not by every
/// host a proxy ever dialed: it drains to empty, so a reload cannot leak retired
/// policy, and a sibling dispatch keeps the lane alive while it is still needed.
#[test]
fn a_reqwest_lane_lives_exactly_as_long_as_its_leases() {
    let admission = admission_only();
    assert_eq!(admission.live_lane_count(), 0);

    let first = admission.lease_lane(1, "backend", 8080, 8080, 1);
    let second = admission.lease_lane(1, "backend", 8080, 8080, 1);
    assert_eq!(admission.live_lane_count(), 1);

    drop(first);
    assert!(
        admission.lane_for("backend", 8080).is_some(),
        "a sibling in-flight dispatch must keep the lane live"
    );

    drop(second);
    assert_eq!(
        admission.live_lane_count(),
        0,
        "the registry must drain rather than retain retired policy"
    );
    assert_eq!(admission.lane_for("backend", 8080), None);
}

/// The lane key normalizes the host the same way on both sides, so the
/// dispatch-side `UpstreamTarget.host` and the bracketed, URL-normalized
/// authority reqwest hands the connector land on ONE lane.
#[test]
fn reqwest_lane_lookup_normalizes_host_case_and_ipv6_brackets() {
    let admission = admission_only();
    let _upper = admission.lease_lane(1, "Backend.Example", 8443, 443, 3);
    let _v6 = admission.lease_lane(1, "[::1]", 8443, 443, 3);

    let normalized = admission.lane_for("backend.example", 8443);
    assert_eq!(normalized.map(|lane| lane.cap()), Some(3));
    let bracketed_v6 = admission.lane_for("::1", 8443);
    assert_eq!(bracketed_v6.map(|lane| lane.cap()), Some(3));
}

#[test]
fn subset_http1_pending_admission_lanes_do_not_leak() {
    use ferrum_edge::backend_pending_limit::{BackendPendingLimiter, BackendPendingScopeBase};

    let limiter = BackendPendingLimiter::new();
    let stable = BackendPendingScopeBase::new("default", "reviews", None, Some("stable"));
    let canary = BackendPendingScopeBase::new("default", "reviews", None, Some("canary"));
    let unmatched = BackendPendingScopeBase::new("default", "reviews", None, None);

    let stable_guard = limiter
        .try_acquire(&stable, 8080, Some(1))
        .expect("stable first slot")
        .expect("stable guard");
    limiter
        .try_acquire(&stable, 8080, Some(1))
        .expect_err("stable lane is full");

    let canary_guard = limiter
        .try_acquire(&canary, 8080, Some(1))
        .expect("canary has an independent slot")
        .expect("canary guard");
    let unmatched_guard = limiter
        .try_acquire(&unmatched, 8080, Some(1))
        .expect("unmatched destination has an independent slot")
        .expect("unmatched guard");

    assert_eq!(limiter.current(&stable, 8080), 1);
    assert_eq!(limiter.current(&canary, 8080), 1);
    assert_eq!(limiter.current(&unmatched, 8080), 1);

    drop((stable_guard, canary_guard, unmatched_guard));
    assert_eq!(limiter.current(&stable, 8080), 0);
    assert_eq!(limiter.current(&canary, 8080), 0);
    assert_eq!(limiter.current(&unmatched, 8080), 0);
}

#[tokio::test]
async fn subset_http1_pending_guard_releases_on_cancellation() {
    use ferrum_edge::backend_pending_limit::{BackendPendingLimiter, BackendPendingScopeBase};

    let limiter = Arc::new(BackendPendingLimiter::new());
    let scope = Arc::new(BackendPendingScopeBase::new(
        "default",
        "reviews",
        None,
        Some("stable"),
    ));
    let task_limiter = Arc::clone(&limiter);
    let task_scope = Arc::clone(&scope);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = task_limiter
            .try_acquire(&task_scope, 8080, Some(1))
            .expect("slot")
            .expect("guard");
        let _ = ready_tx.send(());
        std::future::pending::<()>().await;
    });
    ready_rx.await.expect("guard acquired");
    assert_eq!(limiter.current(&scope, 8080), 1);

    task.abort();
    let error = task.await.expect_err("task cancelled");
    assert!(error.is_cancelled());
    assert_eq!(
        limiter.current(&scope, 8080),
        0,
        "RAII drop on cancellation must release the subset lane"
    );
}

// ============================================================================
// DestinationRule `connectionPool.http.http2MaxRequests` — destination-wide
// ACTIVE-REQUEST breaker (issue #3775).
//
// Istio: "Maximum number of active requests to a destination. Applicable to
// both HTTP1.1 and HTTP2." Envoy: cluster circuit breaker `max_requests`. It is
// NOT an HTTP/2 stream setting — a per-connection SETTINGS value cannot express
// it (HTTP/1.1 has no streams, every connection and pool shard gets its own
// allowance, and a peer's SETTINGS frame can replace the local bound).
// ============================================================================

/// The permit must survive a full request/response exchange, so it can only be
/// released by RAII drop — including on task cancellation (client disconnect,
/// deadline, shutdown). A release at response headers would leave a streaming
/// or long-lived gRPC response occupying backend capacity while uncounted.
#[tokio::test]
async fn destination_active_request_permit_releases_on_task_cancellation() {
    use ferrum_edge::backend_active_request_limit::{
        BackendActiveRequestLimiter, DestinationScope,
    };

    let scope = || DestinationScope {
        namespace: "default",
        destination: "reviews-u",
        policy_port: 8080,
        subset: Some("stable"),
    };
    let limiter = Arc::new(BackendActiveRequestLimiter::new());
    let task_limiter = Arc::clone(&limiter);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _permit = task_limiter
            .try_acquire(scope(), Some(1))
            .expect("admitted")
            .expect("permit");
        let _ = ready_tx.send(());
        std::future::pending::<()>().await;
    });
    ready_rx.await.expect("permit acquired");
    assert_eq!(limiter.current(scope()), 1);
    limiter
        .try_acquire(scope(), Some(1))
        .expect_err("the destination is saturated while the exchange is active");

    task.abort();
    let error = task.await.expect_err("task cancelled");
    assert!(error.is_cancelled());
    assert_eq!(
        limiter.current(scope()),
        0,
        "RAII drop on cancellation must release the destination budget"
    );
}

/// Wiring contract: the breaker is consulted inside backend admission — the one
/// funnel every HTTP-family upstream attempt passes through before dispatch
/// (reqwest H1, reqwest-negotiated H2, direct H2, native gRPC, HBONE/mesh-mTLS,
/// Unix sidecar ingress, and the H3 bridges) — and it runs BEFORE the admission
/// plugins so a shed request never reaches a backend socket. Anchoring it here
/// instead of at each transport is what makes one logical destination have one
/// budget; a per-transport copy is how the pre-#3775 behavior diverged.
#[test]
fn destination_active_request_breaker_is_wired_into_backend_admission() {
    let source = include_str!("../../src/proxy/backend_dispatch.rs");
    let admission = source
        .find("pub(crate) fn run_backend_admission_plugins(")
        .expect("backend admission funnel");
    let body = &source[admission..];
    let plugin_loop = body.find("for plugin in plugins {").expect("plugin loop");
    let acquisition = body
        .find("backend_active_request_limit")
        .expect("destination breaker acquisition");
    assert!(
        acquisition < plugin_loop,
        "the destination active-request breaker must be consulted before admission plugins run"
    );
    let gate = &body[..plugin_loop];
    assert!(
        gate.contains("resolve_backend_http2_max_requests"),
        "the cap must come from the DestinationRule http2MaxRequests slot"
    );
    assert!(
        gate.contains("dispatch_policy_port_for_target"),
        "the lane must be keyed by the DR policy port, not a dial address"
    );
    assert!(
        gate.contains("destination_active_request_scope"),
        "the lane must be keyed by the effective policy identity"
    );
    assert!(
        gate.contains("record_rejection_warning") && gate.contains("suppressed_rejections"),
        "destination saturation warnings must be rate-limited and report suppressed rejections"
    );
    assert!(
        gate.contains("status_code: 503"),
        "a saturated destination must shed with a 503 before any backend attempt"
    );
}

/// The permit rides the backend-admission permit set, which the client-visible
/// response body owns — that is what holds it through streamed bodies, gRPC
/// trailers, disconnects, and errors instead of releasing at response headers.
#[test]
fn destination_active_request_permit_is_held_for_the_response_lifetime() {
    let limiter_source = include_str!("../../src/backend_active_request_limit.rs");
    assert!(
        limiter_source.contains(
            "impl crate::plugins::BackendAdmissionPermit for DestinationActiveRequestPermit"
        ),
        "the guard must be carried by the backend-admission permit set"
    );
    let body_source = include_str!("../../src/proxy/body.rs");
    assert!(
        body_source.contains(
            "_backend_admission_permits: Option<crate::plugins::BackendAdmissionPermitSet>"
        ),
        "ProxyBody must own the permit set so it drops at body completion"
    );
}

/// Istio's per-connection `maxConcurrentStreams` remains the transport knob and
/// must not be re-fused to the destination budget: only it may program the
/// hyper H2 builder.
#[test]
fn per_connection_stream_cap_stays_separate_from_the_destination_budget() {
    let mesh_source = include_str!("../../src/modes/mesh/mod.rs");
    let projection = mesh_source
        .find("fn apply_connection_pool_http_to_port_override(")
        .expect("per-port connectionPool.http projection");
    let body = &mesh_source[projection..];
    let end = body.find("\nfn ").unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        body.contains("slot.http2_max_requests = Some(max_active);"),
        "http2MaxRequests must project onto the destination active-request budget"
    );
    assert!(
        body.contains("if let Some(max_streams) = http.max_concurrent_streams {"),
        "only maxConcurrentStreams may program the per-connection H2 stream cap"
    );
    assert!(
        !body.contains("slot.h2_max_concurrent_streams = Some(max_active)"),
        "http2MaxRequests must never be projected as an H2 stream setting"
    );
}
