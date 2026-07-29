//! Black-box functional regression for Gateway API GRPCRoute pathless
//! method-only dispatch (issue #3271).
//!
//! There is no Kubernetes CRD / live-translator functional harness yet, so this
//! test starts the real `ferrum-edge` binary in file mode with the
//! **translator-equivalent** proxy + `mesh_route_dispatch` config that
//! `translate_k8s_objects` emits for:
//!
//! ```yaml
//! apiVersion: gateway.networking.k8s.io/v1
//! kind: GRPCRoute
//! spec:
//!   rules:
//!     - matches:
//!         - method:
//!             method: SayHello
//!       backendRefs:
//!         - name: grpc-api
//!           port: <backend>
//! ```
//!
//! That shape materializes as a `/` listener, URI regex `/[^/]+/SayHello`, the
//! canonical native-gRPC `content-type` gate regex, `reject_unmatched: true`,
//! and a rule destination pointing at the gRPC Service (see
//! `grpc_route_method_only_match_uses_grpc_uri_predicate` and
//! `GRPC_CONTENT_TYPE_GATE_REGEX` in `src/config_sources/k8s/gateway_api.rs`).
//! Destination host/port are wired to a local counting h2c backend instead of a
//! cluster DNS name so the request path can be observed.
//!
//! Proves through the live request path that:
//! - a native gRPC call to `/{service}/SayHello` reaches the intended backend;
//! - a different method fails closed via `reject_unmatched` (never reaches it);
//! - an ordinary non-gRPC request on the same two-segment path never reaches it.
//!
//! Ignored by default. Hosted CI runs it via the `Functional Tests
//! (application)` shard (`test-functional` / `application` in
//! `.github/workflows/ci.yml`). Locally:
//!   cargo test --test functional_tests functional_grpcroute_pathless_dispatch -- --ignored --nocapture

use crate::common::TestGateway;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Canonical native-gRPC content-type gate emitted for every GRPCRoute match.
const GRPC_CONTENT_TYPE_GATE_REGEX: &str = r"(?is)application/grpc(?:[+;].*|[ \t]+(?:;.*)?)?";

struct CountingGrpcBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl CountingGrpcBackend {
    async fn start() -> Self {
        let reservation = reserve_port()
            .await
            .expect("reserve counting gRPC backend port");
        let port = reservation.port;
        let listener = reservation.into_listener();
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let hits_task = Arc::clone(&hits);
        let paths_task = Arc::clone(&paths);
        let task = tokio::spawn(async move {
            run_counting_grpc_backend(listener, hits_task, paths_task).await;
        });
        Self {
            port,
            hits,
            paths,
            task,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    async fn paths(&self) -> Vec<String> {
        self.paths.lock().await.clone()
    }
}

impl Drop for CountingGrpcBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run_counting_grpc_backend(
    listener: TcpListener,
    hits: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let hits = Arc::clone(&hits);
        let paths = Arc::clone(&paths);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let builder = Http2ServerBuilder::new(TokioExecutor::new());
            let service = service_fn(move |req: Request<Incoming>| {
                let hits = Arc::clone(&hits);
                let paths = Arc::clone(&paths);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    paths.lock().await.push(req.uri().path().to_string());
                    let _ = req.into_body().collect().await;
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "0")
                            .header("grpc-message", "OK")
                            .body(Full::new(Bytes::new()))
                            .expect("build counting gRPC response"),
                    )
                }
            });
            let _ = builder.serve_connection(io, service).await;
        });
    }
}

/// File-mode YAML matching the translator-emitted method-only GRPCRoute shape.
///
/// Proxy default backend is an unused loopback port so a broken
/// `reject_unmatched` cannot silently succeed by falling through to the
/// counting gRPC backend.
fn pathless_method_only_config(grpc_backend_port: u16, blackhole_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "grpcroute-pathless"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {blackhole_port}
    strip_listen_path: false
    plugins:
      - plugin_config_id: "grpcroute-pathless-dispatch"
consumers: []
plugin_configs:
  - id: "grpcroute-pathless-dispatch"
    plugin_name: "mesh_route_dispatch"
    scope: "proxy"
    proxy_id: "grpcroute-pathless"
    enabled: true
    config:
      reject_unmatched: true
      rules:
        - match:
            uri:
              regex: "/[^/]+/SayHello"
            headers:
              content-type:
                regex: '{gate}'
          destination:
            backend_host: "127.0.0.1"
            backend_port: {grpc_backend_port}
"#,
        gate = GRPC_CONTENT_TYPE_GATE_REGEX,
        grpc_backend_port = grpc_backend_port,
        blackhole_port = blackhole_port,
    )
}

async fn send_h2_request(
    gateway_addr: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", content_type)
        .header("te", "trailers")
        .body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();
    Ok((status, headers, body_bytes))
}

#[ignore]
#[tokio::test]
async fn functional_grpcroute_pathless_method_only_dispatch_on_live_gateway() {
    let backend = CountingGrpcBackend::start().await;
    let blackhole = reserve_port()
        .await
        .expect("reserve unused blackhole proxy default port");
    let blackhole_port = blackhole.port;
    // Drop the reservation so nothing is listening; unmatched fall-through
    // would fail closed at connect time rather than look like success.
    drop(blackhole);

    let gateway = TestGateway::builder()
        .mode_file(pathless_method_only_config(backend.port, blackhole_port))
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway with translator-equivalent GRPCRoute pathless config");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let gateway_addr = format!("127.0.0.1:{}", gateway.proxy_port);

    // Positive: native gRPC to /{service}/SayHello reaches the intended backend.
    let (status, headers, _body) = send_h2_request(
        &gateway_addr,
        "/helloworld.Greeter/SayHello",
        "application/grpc",
        b"",
    )
    .await
    .expect("matching gRPC request should complete");
    assert_eq!(status, 200, "matching RPC must return HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(String::as_str),
        Some("0"),
        "matching RPC must be grpc-status OK; headers={headers:?}"
    );
    assert_eq!(
        backend.hits(),
        1,
        "matching SayHello must reach the gRPC backend exactly once"
    );
    assert_eq!(
        backend.paths().await,
        vec!["/helloworld.Greeter/SayHello".to_string()]
    );

    // Negative: a different method fails closed via reject_unmatched.
    let (status, headers, body) = send_h2_request(
        &gateway_addr,
        "/helloworld.Greeter/SayBye",
        "application/grpc",
        b"",
    )
    .await
    .expect("unmatched gRPC method request should complete");
    assert_eq!(
        status, 200,
        "gRPC reject_unmatched is trailers-only over HTTP 200"
    );
    assert!(
        body.is_empty(),
        "reject_unmatched gRPC rejection must be trailers-only"
    );
    assert_eq!(
        headers.get("grpc-status").map(String::as_str),
        Some("5"),
        "HTTP 404 reject_unmatched maps to grpc-status NOT_FOUND(5); headers={headers:?}"
    );
    assert_eq!(
        backend.hits(),
        1,
        "unrelated gRPC method must not reach the backend"
    );

    // Negative: ordinary non-gRPC traffic on the same two-segment path.
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");
    let resp = client
        .post(gateway.proxy_url("/helloworld.Greeter/SayHello"))
        .header("content-type", "text/html")
        .body("not-grpc")
        .send()
        .await
        .expect("non-gRPC request should complete");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "plain HTTP on a pathless GRPCRoute listener must reject_unmatched with 404"
    );
    assert_eq!(
        backend.hits(),
        1,
        "plain HTTP must not reach the gRPC backend"
    );
}
