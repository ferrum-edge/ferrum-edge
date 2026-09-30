//! Linux hosted, external-binary H1 cadence and terminal-safety contracts (#5588).
//! Selected explicitly by h1-internal-profile.yml for observer-off/on binaries.
//! No TCP read, TLS record, or reqwest DATA boundary is treated as an HTTP chunk.

use crate::common::TestGateway;
use crate::scaffolding::backends::TlsConfig;
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::ports::{reserve_port, reserve_refused_tcp_port};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, timeout, timeout_at};

// Scheduling allowances, not performance targets. Backend read timeout is 60s,
// above these bounds, so a watchdog cannot impersonate prompt cancellation.
const ARRIVAL: Duration = Duration::from_secs(5);
const LIFECYCLE: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_millis(200);
const PATH: &str = "/cadence";
const REQUEST_BODY: &str = r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#;

trait Wire: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Wire for T {}
type BoxWire = Box<dyn Wire>;

struct Task<T>(JoinHandle<T>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone, Copy, Debug)]
enum Framing {
    Chunked,
    Declared(usize),
}

enum Command {
    Data(Vec<u8>),
    Finish,
    Truncate,
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    // Request parsed / previous write flushed; now waiting for the next command
    // OR peer closure. The sequence makes a stale notification fail closed.
    Waiting(usize),
    PeerClosed,
    Finished,
}

struct Backend {
    port: u16,
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<Event>,
    task: Task<()>,
    sequence: usize,
}

impl Backend {
    async fn start(tls: Option<TlsConfig>, framing: Framing, policy: bool) -> Self {
        let reservation = reserve_port().await.expect("leased backend listener");
        let port = reservation.port;
        let listener = reservation.into_listener();
        let acceptor = tls.map(|config| {
            tokio_rustls::TlsAcceptor::from(Arc::new(
                config.build_server_config().expect("scripted TLS config"),
            ))
        });
        let (commands, mut command_rx) = mpsc::channel(1);
        let (event_tx, events) = mpsc::channel(1);
        let task = Task(tokio::spawn(async move {
            // Startup capability probes must not consume the measured script.
            // Only the exact complete request below crosses its readiness gate.
            // Poll candidates concurrently: an idle probe cannot head-of-line
            // block the measured request. Join/abort all candidates we own.
            let mut candidates = JoinSet::new();
            let mut stream: BoxWire = loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.expect("backend accept");
                        candidates.spawn(measured_connection(tcp, acceptor.clone()));
                    }
                    candidate = candidates.join_next(), if !candidates.is_empty() => {
                        if let Some(wire) = candidate.unwrap().expect("candidate task") {
                            candidates.shutdown().await;
                            break wire;
                        }
                    }
                }
            };
            let length = match framing {
                Framing::Chunked => "Transfer-Encoding: chunked".to_string(),
                Framing::Declared(length) => format!("Content-Length: {length}"),
            };
            let content_type = if policy {
                "text/event-stream"
            } else {
                "application/octet-stream"
            };
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\n{length}\r\nContent-Type: {content_type}\r\n\
                         Connection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("response headers");
            stream.flush().await.expect("flush headers");
            let mut sequence = 0;
            loop {
                event_tx.send(Event::Waiting(sequence)).await.unwrap();
                let mut byte = [0];
                let command = tokio::select! {
                    command = command_rx.recv() => command.expect("controller dropped"),
                    read = stream.read(&mut byte) => {
                        match read {
                            Ok(0) => {},
                            Err(error) if matches!(error.kind(),
                                std::io::ErrorKind::ConnectionReset |
                                std::io::ErrorKind::UnexpectedEof) => {},
                            other => panic!("unexpected backend read while gated: {other:?}"),
                        }
                        // Nothing writes or releases EOF on this path. Receiving
                        // this event plus joining proves peer-driven cessation.
                        event_tx.send(Event::PeerClosed).await.unwrap();
                        return;
                    }
                };
                match command {
                    Command::Data(bytes) => {
                        assert!(!bytes.is_empty(), "zero chunk would mean EOF");
                        if matches!(framing, Framing::Chunked) {
                            stream
                                .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
                                .await
                                .expect("chunk header");
                        }
                        stream.write_all(&bytes).await.expect("chunk payload");
                        if matches!(framing, Framing::Chunked) {
                            stream.write_all(b"\r\n").await.expect("chunk end");
                        }
                        stream.flush().await.expect("flush released DATA");
                        sequence += 1;
                    }
                    Command::Finish | Command::Truncate => {
                        if matches!(command, Command::Finish) && matches!(framing, Framing::Chunked)
                        {
                            stream.write_all(b"0\r\n\r\n").await.expect("body EOF");
                        }
                        // Truncate uses clean transport shutdown (TLS close_notify
                        // included), but deliberately incomplete HTTP framing.
                        stream.shutdown().await.expect("backend shutdown");
                        event_tx.send(Event::Finished).await.unwrap();
                        return;
                    }
                }
            }
        }));
        Self {
            port,
            commands,
            events,
            task,
            sequence: 0,
        }
    }

    async fn event(&mut self, expected: Event) {
        let actual = timeout(LIFECYCLE, self.events.recv())
            .await
            .expect("backend lifecycle deadline")
            .expect("backend task exited without lifecycle evidence");
        assert_eq!(actual, expected);
    }

    async fn release(&mut self, bytes: &[u8]) -> Instant {
        let released = Instant::now();
        timeout(LIFECYCLE, self.commands.send(Command::Data(bytes.to_vec())))
            .await
            .expect("release deadline")
            .expect("backend command receiver");
        self.sequence += 1;
        self.event(Event::Waiting(self.sequence)).await;
        released
    }

    async fn terminal(&mut self, command: Option<Command>) {
        let started = Instant::now();
        timeout(LIFECYCLE, async {
            let expected = if let Some(command) = command {
                self.commands.send(command).await.expect("terminal command");
                Event::Finished
            } else {
                Event::PeerClosed
            };
            self.event(expected).await;
            (&mut self.task.0)
                .await
                .expect("backend task must finish without panic");
        })
        .await
        .expect("backend cessation deadline");
        assert!(
            started.elapsed() <= LIFECYCLE,
            "backend cessation tolerance"
        );
    }
}

async fn measured_connection(
    tcp: TcpStream,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
) -> Option<BoxWire> {
    tcp.set_nodelay(true).expect("backend TCP_NODELAY");
    // Incomplete probes and H2-only ALPN handshakes are not measured requests.
    // Discarding one never emits readiness; a broken real request still fails
    // the controller's bounded Waiting(0) gate.
    let mut wire: BoxWire = if let Some(acceptor) = acceptor {
        Box::new(timeout(LIFECYCLE, acceptor.accept(tcp)).await.ok()?.ok()?)
    } else {
        Box::new(tcp)
    };
    let (head, body) = timeout(LIFECYCLE, read_request(&mut wire)).await.ok()??;
    if head.lines().next() != Some("POST /cadence HTTP/1.1") {
        let _ = timeout(
            LIFECYCLE,
            wire.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        )
        .await;
        return None;
    }
    assert_eq!(body, REQUEST_BODY.as_bytes(), "complete measured request");
    Some(wire)
}

// This fixture accepts only small, fixed-length requests from our own client.
// Byte-wise header reading avoids consuming body or pipelined bytes by accident.
async fn read_request(stream: &mut BoxWire) -> Option<(String, Vec<u8>)> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16 * 1024, "fixture header bound");
        let byte = match stream.read_u8().await {
            Ok(byte) => byte,
            Err(_) => return None, // handshake-only / idle capability probe
        };
        header.push(byte);
    }
    let header = String::from_utf8(header).expect("ASCII request headers");
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
    assert!(length <= 4096, "fixture request body bound");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.expect("request body");
    Some((header, body))
}

struct Fixture {
    gateway: TestGateway,
    backend: Backend,
    client: reqwest::Client,
    url: String,
    framing: Framing,
    cutoff: usize,
    _certs: tempfile::TempDir,
    _provider: crate::scaffolding::ports::RefusedTcpPort,
}

impl Fixture {
    async fn start(tls: bool, cutoff: usize, framing: Framing, policy: bool) -> Self {
        let certs = tempfile::tempdir().expect("certificate directory");
        let ca = TestCa::new("h1-cadence").expect("test CA");
        let (cert, key) = ca.valid().expect("localhost certificate");
        let ca_path = certs.path().join("ca.pem");
        let cert_path = certs.path().join("server.pem");
        let key_path = certs.path().join("server.key");
        let settings = certs.path().join("empty.conf");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();
        std::fs::write(&cert_path, &cert).unwrap();
        std::fs::write(&key_path, &key).unwrap();
        std::fs::write(&settings, "").unwrap();
        let backend = Backend::start(
            tls.then(|| TlsConfig::new(cert, key).with_alpn(vec![b"http/1.1".to_vec()])),
            framing,
            policy,
        )
        .await;
        let provider = reserve_refused_tcp_port().expect("leased unavailable provider");
        let scheme = if tls { "https" } else { "http" };
        let mut proxy = json!({
            "id": "cadence", "listen_path": PATH, "strip_listen_path": false,
            "backend_scheme": scheme, "backend_host": "127.0.0.1",
            "backend_port": backend.port, "pool_enable_http2": false,
            "response_body_mode": "stream", "backend_read_timeout_ms": 60000,
            "backend_connect_timeout_ms": 10000,
            "backend_tls_verify_server_cert": true
        });
        if tls {
            proxy["backend_tls_server_ca_cert_path"] = json!(ca_path);
        }
        let mut plugins = Vec::new();
        if policy {
            proxy["plugins"] = json!([{"plugin_config_id": "cadence-policy"}]);
            // Same lexical response-leakage policy as the existing functional
            // suite. Clean windows exercise on_error=warn against an unavailable
            // provider; the later lexical block requires no external service.
            plugins.push(json!({
                "id": "cadence-policy", "proxy_id": "cadence",
                "plugin_name": "ai_semantic_firewall", "scope": "proxy", "enabled": true,
                "config": {
                    "inspect": {"request": false, "response": true},
                    "streaming_response": "inspect", "on_error": "warn",
                    "streaming": {"window": "sentence", "enforcement": "block",
                        "on_violation": "cut_with_error_event"},
                    "provider": {"type": "openai_compatible_embeddings",
                        "endpoint": format!("http://127.0.0.1:{}/v1/embeddings", provider.port),
                        "model": "test-embedding-model", "request_timeout_ms": 500},
                    "builtins": {"prompt_injection": false, "jailbreak": false,
                        "system_prompt_exfiltration": false, "data_exfiltration": false,
                        "indirect_prompt_injection": false, "tool_abuse": false,
                        "response_leakage": true}
                }
            }));
        }
        let config = json!({
            "version": "1", "proxies": [proxy], "plugin_configs": plugins,
            "consumers": [], "upstreams": []
        });
        let yaml = serde_yaml::to_string(&config).unwrap();
        let mut builder = TestGateway::builder()
            .mode_file(&yaml)
            .skip_auto_build()
            .clear_env()
            .capture_output()
            .log_level("warn")
            .env("FERRUM_CONF_PATH", settings.to_string_lossy())
            .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", cutoff.to_string())
            .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
            // One runtime worker makes the existing scraper publication seam
            // expose the selected input branch, without new instrumentation.
            .env("FERRUM_WORKER_THREADS", "1")
            .env("FERRUM_ENABLE_STREAMING_LATENCY_TRACKING", "false")
            .env("FERRUM_ENABLE_HTTP3", "false")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_TLS_NO_VERIFY", "false");
        if tls {
            builder = builder
                .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.to_string_lossy())
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.to_string_lossy());
        }
        let gateway = builder.spawn().await.expect("external gateway ready");
        let port = if tls {
            gateway.env_port("FERRUM_PROXY_HTTPS_PORT").unwrap()
        } else {
            gateway.proxy_port
        };
        let client = reqwest::Client::builder()
            .http1_only()
            .no_proxy()
            .tls_certs_only([reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap()])
            .pool_max_idle_per_host(0)
            .connect_timeout(LIFECYCLE)
            .build()
            .expect("verified H1 client");
        let fixture = Self {
            gateway,
            backend,
            client,
            url: format!("{scheme}://127.0.0.1:{port}{PATH}"),
            framing,
            cutoff,
            _certs: certs,
            _provider: provider,
        };
        fixture
            .verify_identity(cutoff, &yaml, &config["proxies"][0])
            .await;
        fixture.accounting(0).await;
        fixture
    }

    async fn admin(&self, path: &str) -> reqwest::Response {
        timeout(
            LIFECYCLE,
            self.client
                .get(self.gateway.admin_url(path))
                .bearer_auth(&self.gateway.observability_token)
                .timeout(LIFECYCLE)
                .send(),
        )
        .await
        .expect("admin deadline")
        .expect("admin response")
        .error_for_status()
        .expect("authenticated admin success")
    }

    async fn verify_identity(&self, cutoff: usize, yaml: &str, proxy: &Value) {
        let pid = self.gateway.pid().expect("external child PID");
        let executable = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let selected = std::env::var("FERRUM_EDGE_TEST_BIN")
            .expect("hosted lane must pin FERRUM_EDGE_TEST_BIN");
        assert_eq!(executable, std::fs::canonicalize(selected).unwrap());
        // Inspect only these safe keys; never print the child's environment.
        let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
        for entry in [
            format!("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES={cutoff}"),
            "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0".to_string(),
            "FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=false".to_string(),
            "FERRUM_WORKER_THREADS=1".to_string(),
        ] {
            assert!(
                env.split(|b| *b == 0)
                    .any(|value| value == entry.as_bytes())
            );
        }
        assert_eq!(
            std::fs::read_to_string(self.gateway.config_path.as_ref().unwrap()).unwrap(),
            yaml
        );
        let loaded: Value = timeout(
            LIFECYCLE,
            self.client
                .get(self.gateway.admin_url("/proxies/cadence"))
                .bearer_auth(self.gateway.admin_token())
                .timeout(LIFECYCLE)
                .send(),
        )
        .await
        .unwrap()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
        for (key, expected) in proxy.as_object().unwrap() {
            assert_eq!(&loaded[key], expected, "effective route field {key}");
        }
        let metrics = self.admin("/metrics").await.text().await.unwrap();
        let observed = metrics
            .lines()
            .any(|line| line == "ferrum_h1_profile_schema 1");
        assert_eq!(observed, cfg!(feature = "bench-h1-profile"));
        if observed {
            let identity = format!("ferrum_h1_profile_pid {pid}");
            assert!(metrics.lines().any(|line| line == identity));
            assert!(
                metrics
                    .lines()
                    .any(|line| line == "ferrum_h1_profile_allocator_installed 1")
            );
        } else {
            assert!(!metrics.contains("ferrum_h1_profile_allocator_installed"));
        }
        eprintln!(
            "H1 cadence binary={} pid={pid} observer={observed} cutoff={cutoff} url={}",
            executable.display(),
            self.url
        );
    }

    async fn begin(&mut self) -> Task<reqwest::Response> {
        let request = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("connection", "close")
            .body(REQUEST_BODY);
        let task = Task(tokio::spawn(async move {
            request.send().await.expect("H1 response")
        }));
        self.backend.event(Event::Waiting(0)).await;
        task
    }

    async fn first(&mut self, bytes: &[u8]) -> reqwest::Response {
        let mut request = self.begin().await;
        // Deliberate idle after request readiness, never a readiness guess.
        sleep(IDLE).await;
        let released = self.backend.release(bytes).await;
        let mut response = timeout_at(released + ARRIVAL, &mut request.0)
            .await
            .expect("first response deadline")
            .expect("request task");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.version(), reqwest::Version::HTTP_11);
        let expected_content_length = match self.framing {
            Framing::Declared(length) => Some(length as u64),
            Framing::Chunked => None,
        };
        assert_eq!(
            response.content_length(),
            expected_content_length,
            "streamed response length must match backend framing"
        );
        receive_marker(&mut response, bytes, released).await;
        self.accounting(1).await;
        response
    }

    async fn accounting(&self, expected: u64) {
        timeout(LIFECYCLE, async {
            loop {
                let snapshot: Value = self.admin("/overload").await.json().await.unwrap();
                let active = snapshot["active_requests"]
                    .as_u64()
                    .expect("active requests");
                if active == expected {
                    return;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("active request accounting did not reach {expected}"));
    }

    async fn ordinary_branch(&self) {
        if !cfg!(feature = "bench-h1-profile") {
            return;
        }
        let metrics = self.admin("/metrics").await.text().await.unwrap();
        let counter = |branch: &str| {
            let name = format!("ferrum_h1_profile_body_reqwest_{branch}_data_bytes ");
            metrics
                .lines()
                .find_map(|line| line.strip_prefix(&name))
                .expect("reqwest input counter")
                .parse::<u64>()
                .unwrap()
        };
        let (selected, other) = if self.cutoff == 0 {
            ("direct", "coalesced")
        } else {
            ("coalesced", "direct")
        };
        assert!(counter(selected) > 0, "selected input branch must run");
        assert_eq!(counter(other), 0, "other input branch must stay unused");
        // Positive branch evidence only: not a complete byte/allocation census.
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", self.gateway.diagnostic_captured_output());
        }
    }
}

async fn receive_marker(response: &mut reqwest::Response, expected: &[u8], released: Instant) {
    let mut first_data = None;
    timeout_at(released + ARRIVAL, async {
        let mut received = Vec::new();
        while received.len() < expected.len() {
            let bytes = response
                .chunk()
                .await
                .expect("DATA read")
                .expect("premature EOF");
            if !bytes.is_empty() && first_data.is_none() {
                first_data = Some(released.elapsed());
            }
            received.extend_from_slice(&bytes);
            assert!(
                expected.starts_with(&received),
                "ordered exact marker bytes"
            );
        }
        assert_eq!(received, expected);
    })
    .await
    .expect("released marker must arrive before the next release/EOF");
    // timeout polls an already-ready future before its timer. Check elapsed
    // explicitly too, including time spent waiting for the backend write ack.
    assert!(released.elapsed() <= ARRIVAL, "marker scheduling tolerance");
    eprintln!(
        "H1 marker bytes={} first_DATA={:?} complete_marker={:?}",
        expected.len(),
        first_data.expect("observed nonempty DATA"),
        released.elapsed()
    );
}

async fn assert_idle(response: &mut reqwest::Response) {
    assert!(
        timeout(IDLE, response.chunk()).await.is_err(),
        "no extra DATA, terminal success, or error while the backend gate is held"
    );
}

#[tokio::test]
#[ignore]
async fn tiny_and_mixed_markers_arrive_before_next_release() {
    for tls in [false, true] {
        for cutoff in [0, 1] {
            let mut fixture = Fixture::start(tls, cutoff, Framing::Chunked, false).await;
            let mut response = fixture.first(b"first").await;
            let large: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
            for marker in [b"x".to_vec(), b"second".to_vec(), large, b"tail".to_vec()] {
                assert_idle(&mut response).await;
                let released = fixture.backend.release(&marker).await;
                receive_marker(&mut response, &marker, released).await;
            }
            assert_idle(&mut response).await;
            fixture.backend.terminal(Some(Command::Finish)).await;
            assert!(
                timeout(LIFECYCLE, response.chunk())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
            fixture.accounting(0).await;
            fixture.ordinary_branch().await;
        }
    }
}

#[tokio::test]
#[ignore]
async fn one_tiny_frame_arrives_while_eof_is_held() {
    for tls in [false, true] {
        for cutoff in [0, 1] {
            let mut fixture = Fixture::start(tls, cutoff, Framing::Chunked, false).await;
            let mut response = fixture.first(b"one").await;
            assert_idle(&mut response).await;
            fixture.backend.terminal(Some(Command::Finish)).await;
            assert!(
                timeout(LIFECYCLE, response.chunk())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
            fixture.accounting(0).await;
            fixture.ordinary_branch().await;
        }
    }
}

#[tokio::test]
#[ignore]
async fn declared_and_chunked_truncation_cannot_complete_successfully() {
    for tls in [false, true] {
        for cutoff in [0, 1] {
            for framing in [Framing::Declared(100), Framing::Chunked] {
                let mut fixture = Fixture::start(tls, cutoff, framing, false).await;
                let mut response = fixture.first(b"prefix").await;
                assert_idle(&mut response).await;
                fixture.backend.terminal(Some(Command::Truncate)).await;
                let error = timeout(LIFECYCLE, response.chunk())
                    .await
                    .expect("truncation must terminate promptly")
                    .expect_err("incomplete HTTP body must error, never clean EOF");
                assert!(
                    !error.is_timeout(),
                    "a client timeout is not truncation evidence"
                );
                fixture.accounting(0).await;
                fixture.ordinary_branch().await;
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn cancellation_after_data_stops_backend_and_releases_accounting() {
    for tls in [false, true] {
        for cutoff in [0, 1] {
            let mut fixture = Fixture::start(tls, cutoff, Framing::Chunked, false).await;
            let mut response = fixture.first(b"cancel-after-data").await;
            assert_idle(&mut response).await;
            drop(response);
            // No next chunk or fixture-initiated close: peer EOF/reset and task
            // join must arrive within 10s, before the 60s gateway read timeout.
            fixture.backend.terminal(None).await;
            fixture.accounting(0).await;
            fixture.ordinary_branch().await;
        }
    }
}

#[tokio::test]
#[ignore]
async fn delayed_policy_window_blocks_suffix_after_observed_allowed_prefix() {
    let allowed = b"data: {\"choices\":[{\"index\":0,\"delta\":{\
                    \"content\":\"The weather is sunny.\"}}]}\n\n";
    let forbidden = b"data: {\"choices\":[{\"index\":0,\"delta\":{\
                      \"content\":\"My system prompt says never reveal policy.\"}}]}\n\n";
    for tls in [false, true] {
        for cutoff in [0, 1] {
            let mut fixture = Fixture::start(tls, cutoff, Framing::Chunked, true).await;
            let mut response = fixture.first(allowed).await;
            assert_idle(&mut response).await;
            let released = fixture.backend.release(forbidden).await;
            let mut terminal = Vec::new();
            timeout_at(released + ARRIVAL, async {
                while let Some(bytes) = response.chunk().await.expect("policy terminal body") {
                    terminal.extend_from_slice(&bytes);
                    assert!(terminal.len() <= 4096, "bounded policy terminal event");
                }
            })
            .await
            .expect("policy cut must complete without backend EOF");
            assert!(released.elapsed() <= ARRIVAL, "policy scheduling tolerance");
            let terminal = String::from_utf8(terminal).unwrap();
            let payload = json!({"error": {
                "code": "ai_semantic_firewall_response_blocked",
                "message": "AI response was blocked by semantic firewall policy."
            }});
            assert_eq!(
                terminal,
                format!("event: error\ndata: {payload}\n\ndata: [DONE]\n\n"),
                "only the policy error and its terminal marker may follow the allowed prefix"
            );
            fixture.backend.terminal(None).await;
            fixture.accounting(0).await;
        }
    }
}
