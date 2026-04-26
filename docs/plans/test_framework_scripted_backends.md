# Scripted-Backend Test Framework Plan

**Goal**: give ferrum-edge a reusable, deterministic harness for exercising gateway behavior across every protocol + failure-mode combination that matters in production. Replace the current gap where we can only assert "happy-path traffic works" with a library of scripted backends that can produce refused connections, mid-stream resets, ALPN downgrades, QUIC silence, read/write timeouts, slow trickles, premature closes, and bad frames — on demand, reproducibly, in < 100 LOC per scenario test.

## Context: what exists today

Directories:
- `tests/common/` — `config_builder.rs`, cert helpers, shared utilities.
- `tests/integration/` — component-level tests (`http2_pool_tests.rs`, `http3_integration_tests.rs`, etc.). Run in-process with `ProxyState::new`.
- `tests/functional/` — full-binary E2E tests, `#[ignore]`, run with `cargo test --test functional_tests -- --ignored` after `cargo build --bin ferrum-edge`.
- `tests/performance/` — wrk/bombardier harnesses for throughput, not for failure modes.

Patterns already established (per `CLAUDE.md`):
- `Stdio::null()` on the gateway binary unless stdout is read (else deadlock).
- Port allocation must retry on bind races (other parallel tests can steal ports between drop+rebind).
- `try_new()` retry wrapper pattern for test harnesses.
- Pre-bound `TcpListener` pattern for echo servers (don't drop+rebind).
- Fresh temp dirs / DBs per retry (SQLite WAL corruption).

What's missing: **programmable backends**. Every failure-mode test today either mocks at the `ProxyState` level (integration) or points at a stock echo server (functional). Neither reproduces the network timing / protocol-level edges that matter.

## Design principles

1. **Scripted, not chaotic.** Every backend behavior is a data-driven sequence. Tests are deterministic and re-readable. No `rand` in the failure path.
2. **Composable.** A backend is `Backend<Transport, Script>`. Swap the transport (TCP / TLS / QUIC / UDP / DTLS) independently of the script (accept-then-reset, slow-write, bad-frame).
3. **Observable.** Every scripted backend records what it received (bytes, frames, headers, cert SNI) so the test can assert the gateway sent the right thing.
4. **Fast.** All scripted backends live in the test process; no extra binaries, no docker. Full matrix should run in seconds.
5. **One harness for integration and functional.** `ProxyState::new(...)` variant for fast in-process tests; full-binary variant for E2E that verifies the whole CLI / config path. Both share the backend scaffolding.
6. **Time control.** Where semantically safe, use `tokio::time::pause`. Where the test exercises real kernel timers (e.g., TCP keepalive), use millisecond budgets and assert with tolerances.

## Directory layout

```
tests/
  scaffolding/
    mod.rs                    # Re-exports, harness builders
    harness.rs                # GatewayHarness: in-process + binary variants
    ports.rs                  # Retry-aware port allocation
    certs.rs                  # rcgen test cert factory (CA, leaf, expired, SAN-mismatch)
    backends/
      mod.rs                  # ScriptedBackend trait + Script enum
      tcp.rs                  # ScriptedTcpBackend: raw byte-level script
      tls.rs                  # ScriptedTlsBackend: tokio-rustls wrapping of tcp.rs
      http1.rs                # ScriptedHttp1Backend: request-response scripts
      http2.rs                # ScriptedH2Backend: frame-level via `h2` crate
      http3.rs                # ScriptedH3Backend: quinn + h3 with QUIC-level refusal
      grpc.rs                 # ScriptedGrpcBackend: wraps http2 with trailer scripts
      websocket.rs            # ScriptedWsBackend: wraps http1 with upgrade scripts
      udp.rs                  # ScriptedUdpBackend: per-packet script
      dtls.rs                 # ScriptedDtlsBackend: wraps udp.rs
    clients/
      mod.rs                  # Unified client enum for frontend-side requests
      http1.rs  http2.rs  http3.rs  ws.rs  grpc.rs  tcp.rs  udp.rs
    network/
      latency.rs              # tokio stream wrapper with configurable delay / bandwidth
      truncate.rs             # Force close after N bytes — for mid-stream tests
  scenarios/
    catalog.rs                # Pre-built scripts used across many tests
  functional/
    (existing + new scripted-backend-driven tests)
```

## Phase-by-phase deliverables

### Phase 1 — TCP + TLS + HTTP/1.1 scripted backend (~1 week)

**Goal**: fully scripted backend for the HTTP/1.1 protocol, with TLS termination and observability. Unlocks ~60% of the failure-mode surface (read/write/connect timeouts, mid-stream close, ALPN behavior, cert edge cases).

Deliverables:

- `tests/scaffolding/certs.rs` — `TestCa` with `.issue(leaf_with_sans, not_before, not_after)` → `(cert_pem, key_pem)`. Presets: `valid()`, `expired()`, `not_yet_valid()`, `wrong_san()`, `self_signed()`.
- `tests/scaffolding/ports.rs` — `reserve_port()` that returns a held `TcpListener` + port, with retry-on-EADDRINUSE + drop-guard. A caller passes the held listener into the backend constructor so there's no drop-rebind race.
- `tests/scaffolding/backends/tcp.rs`:
  ```rust
  pub enum TcpStep {
      Accept,
      ReadExact(usize),           // absorb N bytes
      ReadUntil(Vec<u8>),         // absorb until delimiter (e.g. CRLFCRLF)
      Write(Bytes),
      Sleep(Duration),            // force read/write timeout triggers
      Drop,                        // close cleanly (FIN)
      Reset,                       // abort (RST) via SO_LINGER=0 or equivalent
      RefuseNextConnect,           // close the listener briefly
  }

  pub struct ScriptedTcpBackend {
      pub addr: SocketAddr,
      pub recorded: Arc<Mutex<Vec<RecordedFrame>>>,
      // ...
  }

  impl ScriptedTcpBackend {
      pub async fn start(script: Vec<TcpStep>) -> Result<Self>;
      pub async fn start_with_listener(listener: TcpListener, script: Vec<TcpStep>) -> Result<Self>;
      pub async fn received_bytes(&self) -> Bytes;
      pub async fn shutdown(self);
  }
  ```
  Two script execution modes: `repeat_each_connection` (same script for every accept — good for stateless error injection) and `once` (script runs once total; subsequent connects get `Drop`).

- `tests/scaffolding/backends/tls.rs`: identical API but takes `TlsConfig { cert, key, alpn: Vec<Vec<u8>>, handshake_delay: Option<Duration>, request_client_cert: bool }`. Supports **ALPN scripting** — advertise `h2` + `http/1.1` but always select `http/1.1` (to test H2 pool downgrade).
- `tests/scaffolding/backends/http1.rs`:
  ```rust
  pub enum HttpStep {
      ExpectRequest(MatchRequest),           // assertions on method/path/headers/body
      RespondStatus(u16),
      RespondHeader(&'static str, String),
      RespondBodyChunk(Bytes),
      RespondBodyEnd,
      CloseBeforeStatus,
      CloseAfterHeaders,
      CloseMidBody { after_bytes: usize },
      TrickleBody { chunk: Bytes, pause: Duration, count: usize },
      SendMalformedHeader(String),           // protocol-level bad frames
  }
  ```
  Tracked separately from TCP-level to avoid conflating e.g. "close the socket" with "send a truncated body".

- `tests/scaffolding/harness.rs`:
  ```rust
  pub struct GatewayHarness {
      pub proxy_http_port: u16,
      pub proxy_https_port: u16,
      pub admin_port: u16,
      pub mode: HarnessMode,  // InProcess(Arc<ProxyState>) | Binary(Child)
      _scratch: TempDir,
  }

  impl GatewayHarness {
      pub fn builder() -> GatewayHarnessBuilder;
      pub async fn reload(&self, new_config: GatewayConfig) -> Result<()>;
      pub async fn metrics(&self) -> Metrics;
      pub fn http_client(&self) -> HttpClient;  // reqwest pointed at the gateway
  }

  impl GatewayHarnessBuilder {
      pub fn with_proxy(self, proxy: Proxy) -> Self;
      pub fn with_upstream(self, upstream: Upstream) -> Self;
      pub fn with_env(self, key: &str, value: &str) -> Self;
      pub fn mode_in_process(self) -> Self;   // spawn ProxyState + per-protocol listeners in-process (fast)
      pub fn mode_binary(self) -> Self;       // cargo build --bin ferrum-edge, spawn with Stdio::null()
      pub async fn start(self) -> Result<GatewayHarness>;
  }
  ```
  `try_new()` retry with fresh ports on bind race. Reuses the existing config_builder.

**Phase-1 acceptance tests** (write these as the agent completes Phase 1):
- `backend_refuses_connect_maps_to_502_with_ConnectionRefused` — `ScriptedTcpBackend` closes its listener; gateway returns 502, `error_class = ConnectionRefused`.
- `backend_accepts_then_resets_maps_to_ConnectionReset` — accept → `TcpStep::Reset`.
- `backend_read_timeout_fires_after_backend_read_timeout_ms` — backend accepts then `Sleep(10s)`; proxy has `backend_read_timeout_ms=500`; assert 502 at ~500ms ± 100ms.
- `backend_close_mid_body_populates_body_error_class` — `CloseMidBody { after_bytes: 100 }` with streaming response; assert `body_error_class = ConnectionClosed` in the transaction summary.
- `tls_expired_cert_produces_TlsError_not_generic_502`.
- `h2_alpn_fallback_downgrades_capability` — `ScriptedTlsBackend { alpn: vec![b"http/1.1"] }`; first request via direct H2 pool returns `BackendSelectedHttp1`, second request goes straight to reqwest (capability registry says `h2_tls = Unsupported`).

### Phase 2 — HTTP/2 scripted backend (~1 week)

**Goal**: frame-level H2 control for testing gRPC trailers, GOAWAY, stream resets, flow-control stalls.

Deliverables:

- `tests/scaffolding/backends/http2.rs` using the `h2` crate server API:
  ```rust
  pub enum H2Step {
      AcceptConnection { settings: h2::server::Builder },
      ExpectHeaders(MatchHeaders),
      RespondHeaders(Vec<(&'static str, String)>),
      RespondData(Bytes),
      RespondTrailers(Vec<(&'static str, String)>),
      SendGoaway { error_code: u32 },
      SendRstStream { error_code: u32 },
      StallWindowFor(Duration),   // do not send WINDOW_UPDATE, force flow-control block
      DropConnection,              // close TCP without GOAWAY
  }
  ```

- gRPC wrapper layer (`backends/grpc.rs`) that speaks the gRPC framing (5-byte length-prefix messages, `grpc-status` trailer).

**Phase-2 acceptance tests**:
- `h2_goaway_mid_request_handled_gracefully` — backend sends GOAWAY after receiving request headers; gateway must surface a clean 502 with `error_class = ProtocolError`, and `mark_h3_unsupported` must NOT fire (H3 is unrelated).
- `h2_stream_reset_classified_as_protocol_error`.
- `grpc_trailers_missing_produces_non_ok_status` (spec-canonical UNKNOWN(2) per the HTTP-to-gRPC mapping doc; rejects a gateway regression that would surface grpc-status=0 on missing trailers).
- `grpc_deadline_exceeded_propagates_as_DEADLINE_EXCEEDED_not_UNAVAILABLE`.
- `h2_window_stall_triggers_backend_read_timeout_on_grpc` (gRPC proxy path honors `backend_read_timeout_ms` for body-upload + TTFB stalls; `backend_write_timeout_ms` is TCP-proxy-only).

### Phase 3 — HTTP/3 scripted backend (~2 weeks, hardest)

**Goal**: QUIC-level control to test H3 capability registry and stale-cache invalidation — this is the original testing gap.

Deliverables:

- `tests/scaffolding/backends/http3.rs` using `quinn` + `h3`:
  ```rust
  pub enum H3Step {
      // QUIC-level
      RejectHandshake,              // close UDP socket briefly
      DropInitialPacket,             // set up endpoint but ignore first packet (simulate UDP block)
      AcceptHandshake,
      CloseConnectionWithCode(u64),  // CONNECTION_CLOSE
      // H3-level
      AcceptStream,
      RespondHeaders(Vec<(&'static str, String)>),
      RespondData(Bytes),
      SendStreamReset(u64),
      SendGoaway(u64),
      StallFor(Duration),
  }
  ```

- A `QuicRefuser` helper that binds a UDP socket, accepts the datagram, and immediately sends a QUIC `CONNECTION_CLOSE` with `NO_ERROR` — mimics a backend that stopped serving H3 but still has the UDP port open. This is the key fixture for testing `mark_h3_unsupported`.

- A **TCP-only** variant of `ScriptedTlsBackend` that advertises `h2` in ALPN but has NO QUIC listener on the same port. Lets us test "initial capability probe classifies H3 as Unsupported".

**Phase-3 acceptance tests** (these close the existing gap):
- `h3_probe_classifies_backend_without_quic_as_h3_unsupported` — initial capability refresh completes; `h3 = Unsupported`, `h2_tls = Supported`. Subsequent H3 frontend requests route via cross-protocol bridge, not 502.
- `h3_backend_CONNECTION_CLOSE_mid_request_downgrades_capability` — registry pre-populated with `h3 = Supported`, backend sends CONNECTION_CLOSE; gateway 502s this request, next request sees `h3 = Unsupported` and goes via cross-protocol bridge.
- `h3_protocol_error_downgrades_via_connection_error_false_path` — backend sends H3 GOAWAY; classify_h3_error returns `connection_error=false, ProtocolError`; assert the downgrade still fires (regression test for the Codex P2 fix).
- `h3_backend_recovers_after_periodic_refresh` — start with backend that rejects QUIC → registry downgrades → swap backend for one that accepts QUIC → trigger admin-side refresh → assert `h3 = Supported` restored → next request uses native H3 pool.
- `h3_frontend_to_h3_backend_failure_downgrades_from_server_path` — exercises the `http3/server.rs` downgrade wiring that was missing before the self-audit.

### Phase 4 — UDP + DTLS (~3 days)

**Goal**: per-datagram scripting for testing UDP session handling, DTLS handshake, passthrough SNI, GSO batching.

Deliverables:

- `tests/scaffolding/backends/udp.rs` — `UdpStep { ExpectDatagram(matcher), Reply(bytes), Silence, DropSocket }`.
- `tests/scaffolding/backends/dtls.rs` — wraps UDP with DTLS 1.2/1.3 termination.

**Phase-4 tests**:
- `udp_session_idle_timeout_cleans_session_map`.
- `udp_amplification_bound_enforced`.
- `dtls_passthrough_sni_routes_to_correct_backend`.

### Phase 5 — Network simulation wrappers (~3 days)

**Goal**: apply latency, bandwidth limits, jitter, packet loss — without relying on `tc`/netem (portable, reproducible).

Deliverables:

- `tests/scaffolding/network/latency.rs` — `DelayedStream<T>` that pauses reads/writes by `Duration` before forwarding. Used in front of any backend.
- `tests/scaffolding/network/truncate.rs` — `TruncatedStream<T>` that closes after N bytes, optionally with a delay.
- Documented combinator: `backend.with_latency(ms).with_bandwidth(kbps).with_jitter(±ms)`.

**Phase-5 tests**:
- `slow_backend_within_read_timeout_completes` — 500 ms per-chunk latency vs 1 s `backend_read_timeout_ms`; should succeed.
- `backend_bandwidth_below_budget_triggers_write_timeout` (when configured).
- `high_latency_preserves_first_byte_latency_metrics`.

### Phase 6 — Cross-protocol matrix macro (~3 days) — **DONE** (PR forthcoming)

**Goal**: one scenario, N protocol combinations.

Deliverables (shipped):

- `tests/scaffolding/matrix.rs` — `gateway_matrix!` macro plus
  `FrontendKind` (H1/H2/H3/WS/Grpc) and `BackendKind`
  (H1/H2/H3/Grpc/Tcp/Udp) enums with helper methods (`spawn_refuse_connect`,
  `spawn_accept_then_rst`, `send_get`, `assert_status`, `file_mode_yaml`,
  `request_path`, `listen_path`).
- Two demo invocations in
  `tests/functional/scripted_backend_matrix_tests.rs`:
  `backend_refuses_returns_502` and `backend_accepts_then_rst_returns_502`,
  each generating one `#[tokio::test] #[ignore]` per
  `(frontend, backend)` combination not in the supplied skip list.
- Skip filter is implemented as a runtime gate inside each generated
  test (rather than a tt-muncher comparison) — the macro_rules!
  language can't compare two metavariables for equality, and the
  runtime gate is one-line and deterministic. Skipped combinations
  appear in `cargo test --list` as near-instant passes.

Original plan example:

- `gateway_matrix!` macro:
  ```rust
  gateway_matrix! {
      name = backend_refuses_returns_502,
      frontend = [H1, H2, H3, WS, Grpc],
      backend  = [H1, H2, H3, Grpc],
      skip     = [(WS, H3), (Grpc, H1)],  // RFC 9220, protocol mismatch
      scenario = |frontend, backend| async move {
          let backend = ScriptedBackend::refuse_connect(backend);
          let gateway = GatewayHarness::builder().with_upstream(backend).start().await?;
          let response = frontend.client(&gateway).get("/any").send().await?;
          assert_eq!(response.status(), 502);
          assert_eq!(response.error_class(), ErrorClass::ConnectionRefused);
          Ok(())
      }
  }
  ```
  Expands to ~15 tests, each with its own `#[tokio::test]` function (for clean test-runner output).

### Phase 7 — Scenario catalog (~ongoing) — **DONE** (PR forthcoming)

**Goal**: populate `tests/scenarios/catalog.rs` with the ~30 pre-built failure scripts so tests are short.

Shipped catalog (each entry is a small constructor returning the most
ergonomic shape — `Vec<TcpStep>` / `Vec<HttpStep>` / `TlsConfig` /
backend-builder / `Result<ScriptedXxxBackend, _>` etc.):

- **Connection-level**: `refuse_connect`, `accept_then_rst`,
  `accept_then_fin_before_response`, `handshake_timeout`,
  `handshake_then_close`.
- **HTTP/1**: `slow_header_trickle`, `raw_status_trickle`,
  `slow_body_trickle`, `respond_partial_body`,
  `respond_with_wrong_content_length`, `send_malformed_chunked_encoding`,
  `send_duplicate_content_length`, `respond_but_close_before_trailer`.
- **TLS / cert**: `cert_expired`, `cert_san_mismatch`, `cert_self_signed`,
  `cert_not_yet_valid`, `alpn_downgrade_h2_to_h1`, `alpn_only_http_1_1`.
- **HTTP/2**: `h2_goaway_immediately`, `h2_stream_reset_mid_response`,
  `h2_window_stall`.
- **HTTP/3 / QUIC**: `quic_refuse`, `quic_drop_initial`,
  `quic_connection_close`, `quic_stream_reset`.
- **UDP / DTLS**: `udp_silent_backend`, `udp_amplification_attempt`,
  `dtls_handshake_timeout`.
- **Network conditions** (Phase-5 wrappers): `slow_link`, `bandwidth_limited`.
- **Built-backend constructors**: `spawn_refusing_tcp_backend`,
  `spawn_resetting_tcp_backend`, `spawn_close_before_status_backend`,
  `spawn_h2_goaway_backend`, `spawn_grpc_missing_trailer_backend`,
  `spawn_silent_udp_backend`.

Plan-original list:

- `refuse_connect()`, `accept_then_rst()`, `accept_then_fin_before_response()`
- `slow_header_trickle(chunk_size, pause)`, `slow_body_trickle(...)`
- `respond_but_close_before_trailer()` (gRPC)
- `respond_partial_body(after_bytes)`, `respond_with_wrong_content_length(claimed, actual)`
- `send_malformed_chunked_encoding()`
- `send_duplicate_content_length()` (CL+TE smuggling attempt)
- `handshake_timeout(duration)`, `handshake_then_close()`
- `alpn_downgrade_h2_to_h1()`, `alpn_only_http_1_1()`
- `cert_expired()`, `cert_san_mismatch()`, `cert_self_signed()`
- `quic_refuse()`, `quic_drop_initial()`, `quic_connection_close()`, `quic_stream_reset()`

Each returns a `Script` suitable for whichever backend it targets.

### Phase 8 — Plug capability-registry + retry + overload gaps (~1 week)

**Goal**: use the new scaffolding to close every gap flagged in the PR reviews.

- `tests/functional/functional_capability_registry_test.rs`:
  - **H3 downgrade end-to-end**: backend rejects QUIC, first H3 request 502, second routes via cross-protocol bridge. Admin `GET /status` (or similar) surfaces `h3 = Unsupported`.
  - **H2 ALPN downgrade**: ALPN-h1 backend, first request via direct H2 pool returns h1 fallback, second skips the pool.
  - **Initial refresh when warmup is off**: `FERRUM_POOL_WARMUP_ENABLED=false`, H3-capable backend, assert first H3 request within 5 s uses the native H3 pool (not fall-through). Before the fix, this would wait 24 h.
  - **Refresh coalescer under rapid reload**: apply 50 config updates in 100 ms; assert exactly one or two refresh tasks ran (not 50), and the final config's capability entries are present.
- `tests/functional/functional_retry_test.rs`:
  - `retry_respects_retry_on_methods` — backend sends connection_reset; POST with `retry_on_methods = [GET]` must NOT retry; GET must.
  - `post_h3_downgrade_subsequent_requests_route_via_cross_protocol_bridge` — first H3 request fails and downgrades the cached capability; the SECOND request routes via reqwest. Pins the next-request half of the per-target dispatch contract.
  - `retry_attempts_within_same_request_stay_on_h3_pool` — same-target retries: once a request dispatches via H3 against a target, every retry attempt against that same target stays on H3 even after `mark_h3_unsupported` fires.
  - `retry_rotation_across_mixed_capability_targets_recomputes_dispatch` — cross-target retries: when the LB rotates from a reqwest-only target to an H3-only target, the dispatch decision recomputes against the registry and switches transports correctly.
- `tests/functional/functional_overload_test.rs`:
  - FD pressure → keepalive disabled; assert `Connection: close` on responses.
  - Request ceiling → 503 with correct `overload_reason`.
- `tests/functional/functional_plugins_network_test.rs`:
  - rate_limiting survives backend slow-response.
  - request_mirror fires even when primary backend 502s.
  - compression handles mid-stream backend close without corrupting output.

## Key API contracts the agent should honor

**1. Observability is a first-class concern.** Every scripted backend exposes:
```rust
pub fn received_requests(&self) -> Vec<RecordedRequest>;
pub fn accepted_connections(&self) -> usize;
pub fn completed_scripts(&self) -> usize;
```
Tests that merely check the gateway's response are half-tests; we need to know the gateway sent the right thing to the backend.

**2. Timeouts are tunable from the gateway side, not the backend.** The script produces predictable latency; the *test* asserts the gateway's timeout behavior at its configured threshold. Don't bake absolute `timeout=30s` into scripts — accept `Duration` parameters.

**3. Retry pattern on flaky bring-up.** `GatewayHarness::builder().start().await` must retry up to 3 × on `wait_for_health` failure, with fresh ports / temp dirs each retry, per the CLAUDE.md rules. Existing functional harness is the reference.

**4. Parallel test safety.** Each test gets its own gateway + backends. No shared state between `#[tokio::test]` functions. Use `rstest` or equivalent for parameterized tests where helpful.

**5. Two test execution tiers**:
- **Fast tier** (`cargo test --test unit_tests` / `integration_tests`): in-process `ProxyState::new` variant. Runs in seconds. Catches ~80% of gateway logic bugs.
- **Full tier** (`cargo test --test functional_tests -- --ignored`): binary variant. Validates CLI, config loading, SIGHUP reload, admin API, kernel-level behaviors (splice, kTLS). Runs in minutes. Gate Phase-8 acceptance tests here because they exercise the full runtime.

**Status**: `HarnessMode::InProcess` is now live (PR for `feature/in-process-harness-mode`). It calls `ferrum_edge::modes::file::serve(...)` with pre-bound TCP listeners reserved by `tests/scaffolding/ports.rs`, returning the real `ProxyState` + JoinHandles. End-to-end harness setup runs in <100ms vs. ~2-3s for binary mode (one cargo build + process bootstrap). Tests that don't need log capture, CLI parsing, or kernel-level features (splice/kTLS/io_uring) should default to `mode_in_process()` for a 10-15× speedup. See `tests/scaffolding/harness.rs` rustdoc for the migration checklist and the three caveats (pool warmup default, file-mode YAML strict-loading still applies, captured logs binary-only).

## What to explicitly NOT build

- **Chaos / property testing frameworks.** Keep scripts data, not randomization. Property tests can be a later Phase-N if needed.
- **Docker/k8s integration tests.** Deployment-shape tests belong in a separate CI pipeline; this scaffolding is for gateway-behavior tests.
- **Real-network integration against 3rd-party services.** Flaky, slow, untestable in CI. The scripted backend covers all the same protocol surface deterministically.

## Acceptance criteria for the whole effort

The framework is done when a contributor can write:

```rust
#[tokio::test]
async fn h3_downgrade_after_quic_connection_close() {
    let backend = ScriptedH3Backend::start(vec![
        H3Step::AcceptHandshake,
        H3Step::AcceptStream,
        H3Step::CloseConnectionWithCode(0),  // CONNECTION_CLOSE mid-request
    ]).await.unwrap();

    let gateway = GatewayHarness::builder()
        .with_proxy(Proxy::https("/api", backend.addr()))
        .mode_in_process()
        .start().await.unwrap();

    // Pre-populate: backend IS H3-capable at probe time.
    gateway.capability_registry().mark_h3_supported(&backend.target()).await;

    // First H3 request: transport failure, capability downgrades.
    let first = gateway.h3_client().get("/api/test").send().await.unwrap();
    assert_eq!(first.status(), 502);
    assert_eq!(first.error_class(), ErrorClass::ProtocolError);
    assert!(!gateway.capability_registry().get(&backend.target()).plain_http.h3.is_supported());

    // Second request: routes via cross-protocol bridge.
    let second = gateway.h3_client().get("/api/test").send().await.unwrap();
    assert_eq!(second.status(), 200);
    assert_eq!(backend.received_requests().len(), 2);  // both reached backend — via different paths
}
```

… in ~20 lines. The 99% of gateway network scenarios become unit-test-cheap to reproduce.

## Sequencing recommendation for the agent

Tackle in order. Do NOT start Phase 2 before Phase 1 acceptance tests pass — the harness contract needs to stabilize first.

1. Phase 1 (TCP / TLS / HTTP/1) — 1 week — highest ROI, unblocks ~60% of scenarios.
2. Phase 3 (H3) — 2 weeks — closes the original stated gap; uses the Phase-1 harness.
3. Phase 2 (H2) — 1 week — gRPC tests depend on it.
4. Phase 4 (UDP/DTLS) — 3 days.
5. Phase 5 (network sim) — 3 days.
6. Phase 6 (matrix macro) — 3 days.
7. Phase 7 (catalog) — rolling, alongside each phase.
8. Phase 8 (fill the gaps) — 1 week after Phase 3 lands.

Budget: ~5–6 weeks of focused work. Every phase has an acceptance test list; merge per phase.
