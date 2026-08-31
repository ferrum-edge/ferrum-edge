//! Functional tests for `a2a_gateway` unary gRPC Agent Card rewriting
//! (issue #3297).
//!
//! Issue #3297 asks for evidence on the LIVE data path, not just at the plugin
//! hook boundary: the rewrite changes what a discovery client is told to connect
//! to, and it re-frames a native gRPC response, so the framing, headers, and
//! terminal trailers have to be right on the wire.
//!
//! These tests:
//! 1. Start a local gRPC echo backend (h2c HTTP/2) that returns the request body
//!    as the response body, so the test controls the exact protobuf Agent Card
//!    payload the gateway sees. It emits `grpc-status: 0` as a real TRAILERS
//!    frame after the DATA frame, which is what the gateway's merged
//!    header+trailer plugin view is built from.
//! 2. Start the gateway binary in file mode with an `a2a_gateway` config whose
//!    `discovery.public_base_url` and `endpoint.protocol_versions` drive the
//!    rewrite and the version gate.
//! 3. Assert the rewritten frame, the preserved non-JSONRPC interfaces, the
//!    removed signatures, protocol-correct headers/trailers, and fail-closed
//!    behaviour for malformed / mis-versioned / compressed cards — all end to
//!    end over the real native gRPC data path.
//! 4. Assert reload behaviour: a changed public base and a withdrawn
//!    `rewrite_agent_card_urls` both take effect on a SIGHUP'd running gateway,
//!    so the feature is not merely correct at first construction.
//! 5. Assert the service/payload pairing is the OFFICIAL one: the canonical A2A
//!    0.3 service `a2a.v1.A2AService` carries the 0.3 card layout and is the
//!    default, while A2A 1.0's `lf.a2a.v1.A2AService` can never be decoded or
//!    rewritten as 0.3.
//!
//! The harness is deliberately the bounded one `functional_grpc_plugins_test` /
//! `functional_websocket_test` use: one echo backend holding its own pre-bound
//! listener, and one gateway child spawned onto simultaneously-held proxy/admin
//! port reservations that are released only at the spawn call, with readiness
//! proven by the authenticated `/health` detail tier for that attempt's own
//! bearer token — never by a bare TCP accept or a sleep. No unbounded servers.
//!
//! Two harness properties are load-bearing and covered by their own plain
//! (non-`#[ignore]`) guards at the bottom of this file:
//!
//! - **Retry is positive.** The child's stdout/stderr are captured to files and
//!   a spawn attempt is retried ONLY when those diagnostics demonstrate an
//!   address-in-use bind race. A config parse error, a child panic, or a failed
//!   readiness/authentication check fails immediately with the captured tail
//!   (bearer token redacted) rather than being re-rolled into "did not start".
//! - **Every live call is bounded.** `send_grpc_request` carries a per-call
//!   timeout, and the reload poll loop hands each call the smaller of that
//!   ceiling and its own remaining deadline, so a wedged gateway fails
//!   diagnostically instead of hanging.
//!
//! Run with:
//! `cargo test --test functional_tests functional_a2a_gateway_grpc_card -- --ignored --nocapture`

use crate::scaffolding::ports::{PortReservation, reserve_port, reserve_port_pair};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};
use tokio_stream::wrappers::ReceiverStream;

const PUBLIC_BASE: &str = "https://agents.example.com";
// Reload coverage is Unix-only: file-mode SIGHUP reload is not supported by the
// gateway on Windows.
#[cfg_attr(not(unix), allow(dead_code))]
const ALTERNATE_PUBLIC_BASE: &str = "https://agents-2.example.com";
/// The canonical A2A **0.3** gRPC service: `a2aproject/A2A` at tag `v0.3.0`,
/// `specification/grpc/a2a.proto`, declares `package a2a.v1; service
/// A2AService`. It is the identity whose `AgentCard` layout these fixtures
/// encode and whose `protocol_version` the gateway is configured to admit, so
/// the live path exercises a real, self-consistent A2A 0.3 pairing.
const A2A_SERVICE: &str = "/a2a.v1.A2AService";
/// A2A **1.0**'s gRPC service (`package lf.a2a.v1`), whose `AgentCard` is
/// renumbered. Used only to prove this identity is never fed to the 0.3
/// decoder — never as a stand-in for the 0.3 service above.
const A2A_10_SERVICE: &str = "/lf.a2a.v1.A2AService";
/// `endpoint.grpc_services` as the default resolves it.
const DEFAULT_GRPC_SERVICES: &str = r#"["a2a.v1.A2AService"]"#;

// ============================================================================
// A2A 0.3 protobuf fixtures
//
// Hand-encoded rather than descriptor-driven: the gateway performs wire surgery
// against these exact field numbers, so the fixture must be the wire and not a
// generated view of it.
//   AgentCard: name=1 description=2 url=3 preferred_transport=14
//              additional_interfaces=15 protocol_version=16 signatures=17
//   AgentInterface: url=1 transport=2
// ============================================================================

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_len_field(field: u32, value: &[u8], out: &mut Vec<u8>) {
    encode_varint(u64::from(field) << 3 | 2, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn encode_string_field(field: u32, value: &str, out: &mut Vec<u8>) {
    encode_len_field(field, value.as_bytes(), out);
}

fn encode_agent_interface(url: &str, transport: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string_field(1, url, &mut out);
    encode_string_field(2, transport, &mut out);
    out
}

/// A complete A2A 0.3 Agent Card: JSON-RPC preferred, one JSON-RPC interface,
/// one gRPC interface, and a signature block.
fn encode_agent_card(protocol_version: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string_field(1, "planner", &mut out);
    encode_string_field(2, "planning agent", &mut out);
    encode_string_field(3, "https://planner.internal/a2a", &mut out);
    encode_string_field(14, "JSONRPC", &mut out);
    encode_len_field(
        15,
        &encode_agent_interface("https://planner.internal/a2a", "JSONRPC"),
        &mut out,
    );
    encode_len_field(
        15,
        &encode_agent_interface("https://planner.internal/grpc", "GRPC"),
        &mut out,
    );
    encode_string_field(16, protocol_version, &mut out);
    let mut signature = Vec::new();
    encode_string_field(1, "eyJhbGciOiJFUzI1NiJ9", &mut signature);
    encode_string_field(2, "stale-signature", &mut signature);
    encode_len_field(17, &signature, &mut out);
    out
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Split one identity-framed gRPC message out of a response body, verifying the
/// declared length matches what actually arrived.
fn single_frame_payload(body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() >= 5,
        "expected a framed gRPC message, got {} bytes",
        body.len()
    );
    assert_eq!(body[0], 0, "rewritten frames must be uncompressed identity");
    let declared = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert_eq!(
        declared,
        body.len() - 5,
        "the frame length prefix must describe exactly the bytes on the wire"
    );
    body[5..].to_vec()
}

/// Minimal reader for the fields these assertions inspect.
fn walk_fields(message: &[u8], mut visit: impl FnMut(u32, u8, &[u8])) {
    let mut buf = message;
    while !buf.is_empty() {
        let mut key = 0u64;
        let mut shift = 0;
        loop {
            let Some(&byte) = buf.first() else { return };
            buf = &buf[1..];
            key |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                loop {
                    let Some(&byte) = buf.first() else { return };
                    buf = &buf[1..];
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                visit(field, wire, &[]);
            }
            1 => {
                if buf.len() < 8 {
                    return;
                }
                let (value, rest) = buf.split_at(8);
                buf = rest;
                visit(field, wire, value);
            }
            2 => {
                let mut len = 0usize;
                let mut shift = 0;
                loop {
                    let Some(&byte) = buf.first() else { return };
                    buf = &buf[1..];
                    len |= usize::from(byte & 0x7f) << shift;
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                if buf.len() < len {
                    return;
                }
                let (value, rest) = buf.split_at(len);
                buf = rest;
                visit(field, wire, value);
            }
            5 => {
                if buf.len() < 4 {
                    return;
                }
                let (value, rest) = buf.split_at(4);
                buf = rest;
                visit(field, wire, value);
            }
            _ => return,
        }
    }
}

fn string_field(message: &[u8], target: u32) -> Option<String> {
    let mut found = None;
    walk_fields(message, |field, wire, value| {
        if field == target && wire == 2 {
            found = String::from_utf8(value.to_vec()).ok();
        }
    });
    found
}

fn repeated_messages(message: &[u8], target: u32) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    walk_fields(message, |field, wire, value| {
        if field == target && wire == 2 {
            found.push(value.to_vec());
        }
    });
    found
}

fn has_field(message: &[u8], target: u32) -> bool {
    let mut found = false;
    walk_fields(message, |field, _wire, _value| {
        if field == target {
            found = true;
        }
    });
    found
}

// ============================================================================
// Harness
// ============================================================================

/// Per-spawn-attempt observability credential.
///
/// The authenticated `/health` detail tier is the only thing that proves the
/// listener answering on an admin port is THIS child rather than a parallel
/// test's gateway that happened to inherit the port. A fresh token per attempt
/// means a retry can never be satisfied by the corpse of the previous one.
fn mint_observability_token() -> String {
    format!(
        "ferrum-edge-a2a-grpc-card-probe-{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// Echo backend: returns the request body as the gRPC response body, mirrors
/// `x-set-grpc-encoding` into the response `grpc-encoding`, and mirrors
/// `x-set-grpc-status` into the terminal trailer so a test can drive a non-OK
/// upstream reply that still carries a DATA frame.
///
/// The terminal status always rides an HTTP/2 TRAILERS frame after the DATA
/// frame(s). Putting it in the initial HEADERS block is protocol-invalid for a
/// message-carrying response, and the gateway treats that field as
/// transport-managed rather than as a success signal.
async fn start_grpc_echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let listener = reservation.into_listener();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());
                let service = service_fn(|req: Request<Incoming>| async move {
                    let header = |name: &str| {
                        req.headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string)
                    };
                    let encoding = header("x-set-grpc-encoding");
                    let status = header("x-set-grpc-status").unwrap_or_else(|| "0".to_string());
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();

                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                    let _ = tx.send(Ok(Frame::data(body_bytes))).await;
                    let mut trailers = hyper::HeaderMap::new();
                    if let Ok(value) = hyper::header::HeaderValue::from_str(&status) {
                        trailers.insert("grpc-status", value);
                    }
                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    drop(tx);

                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc");
                    if let Some(encoding) = encoding {
                        builder = builder.header("grpc-encoding", encoding);
                    }
                    let response = builder
                        .body(StreamBody::new(ReceiverStream::new(rx)))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });
                if let Err(e) = builder.serve_connection(io, service).await
                    && !format!("{}", e).contains("connection closed")
                {
                    eprintln!("gRPC echo backend error: {}", e);
                }
            });
        }
    });

    (port, handle)
}

fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Upper bound on the child output surfaced in a failure message.
///
/// The child runs at `ferrum_edge=debug`, so its log can be large; only the
/// TAIL is read (the file is seeked, not slurped) because the fault that ended
/// startup is always the last thing written.
const MAX_DIAGNOSTIC_BYTES: u64 = 4096;

/// Per-attempt capture files for the gateway child's stdout and stderr.
///
/// Files rather than `Stdio::piped()` on purpose: a pipe nobody reads while the
/// child is still starting deadlocks once the pipe buffer fills, which is
/// exactly the window this harness spends polling for readiness. Files never
/// block the writer, and they can be read after the child is reaped.
struct AttemptLogs {
    stdout: PathBuf,
    stderr: PathBuf,
}

/// Bounded, secret-free child output for one failed attempt.
struct ChildDiagnostics {
    stdout: String,
    stderr: String,
}

impl AttemptLogs {
    fn create(dir: &Path, attempt: u32) -> Self {
        Self {
            stdout: dir.join(format!("gateway-attempt-{attempt}.out")),
            stderr: dir.join(format!("gateway-attempt-{attempt}.err")),
        }
    }

    fn stdio(&self) -> std::io::Result<(std::process::Stdio, std::process::Stdio)> {
        Ok((
            std::process::Stdio::from(std::fs::File::create(&self.stdout)?),
            std::process::Stdio::from(std::fs::File::create(&self.stderr)?),
        ))
    }

    /// Read the tail of both captures with the attempt's bearer token removed.
    ///
    /// That token is the only secret this harness injects, and it unlocks the
    /// authenticated admin detail tier, so it must not reach a CI log even
    /// though the attempt that minted it is already void.
    fn read_bounded(&self, secret: &str) -> ChildDiagnostics {
        ChildDiagnostics {
            stdout: read_tail_redacted(&self.stdout, secret),
            stderr: read_tail_redacted(&self.stderr, secret),
        }
    }
}

fn read_tail_redacted(path: &Path, secret: &str) -> String {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return format!("<unavailable: {error}>"),
    };
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if len > MAX_DIAGNOSTIC_BYTES {
        let tail = SeekFrom::End(-(MAX_DIAGNOSTIC_BYTES as i64));
        if file.seek(tail).is_err() {
            return "<unavailable: could not seek to the log tail>".to_string();
        }
    }
    let mut buffer = Vec::new();
    if let Err(error) = file.read_to_end(&mut buffer) {
        return format!("<unavailable: {error}>");
    }
    let text = String::from_utf8_lossy(&buffer);
    redact_secret(&text, secret)
}

/// Replace every occurrence of the attempt's bearer token. An empty `secret`
/// would otherwise make `replace` splice the marker between every character.
fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "<redacted-probe-token>")
}

/// Substrings that DEMONSTRATE the child lost a race for a port it was handed,
/// which is the one startup failure a fresh-port retry can actually fix.
///
/// Both the platform-independent `std::io::Error` text and the raw errno
/// spellings are listed, because the message a failed bind surfaces depends on
/// whether it was formatted with `Display` or `Debug` and on the OS.
const ADDRESS_IN_USE_MARKERS: &[&str] = &[
    "address already in use",
    "addrinuse",
    // EADDRINUSE: macOS/BSD 48, Linux 98, Windows WSAEADDRINUSE 10048.
    "os error 48",
    "os error 98",
    "os error 10048",
];

/// Whether the captured child output proves an address-in-use bind race.
///
/// Everything else — a config parse error, a rejected plugin composition, a
/// panic, an authentication mismatch, a child that simply never became ready —
/// is DETERMINISTIC: the next attempt would reproduce it on fresh ports, so
/// retrying only converts an actionable failure into "did not start after 3
/// attempts". Classification is positive: an unrecognized failure is not a bind
/// race.
fn bind_race_diagnosed(stdout: &str, stderr: &str) -> bool {
    let haystack = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    ADDRESS_IN_USE_MARKERS
        .iter()
        .any(|marker| haystack.contains(marker))
}

/// Spawn the gateway on two ports this attempt still HOLDS.
///
/// Both reservations stay live while the environment is prepared, which is what
/// makes the proxy and admin ports distinct (two live listeners cannot share a
/// port) and unstealable in the interval between selecting them and using them.
/// They are released on the last statement before `spawn`, because the child has
/// to bind them itself; that residual window is what
/// [`wait_for_owned_gateway`] then closes by proving identity rather than
/// trusting a bare accept.
fn start_gateway(
    config_path: &str,
    gateway: PortReservation,
    admin: PortReservation,
    observability_token: &str,
    logs: &AttemptLogs,
) -> Result<(std::process::Child, u16, u16), Box<dyn std::error::Error>> {
    let http_port = gateway.port;
    let admin_port = admin.port;
    let (stdout, stderr) = logs.stdio()?;
    let mut command = std::process::Command::new(gateway_binary_path());
    command
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_ACCEPT_THREADS", "1")
        // Ownership proof for this exact child (issue #3428 / #2132): presenting
        // this token unlocks the authenticated `/health` detail tier, which no
        // foreign gateway can answer.
        .env("FERRUM_METRICS_BEARER_TOKEN", observability_token)
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr);

    // Release both ports only now, immediately before the child binds them.
    drop(gateway);
    drop(admin);

    let child = command.spawn()?;
    Ok((child, http_port, admin_port))
}

/// Prove *this* child owns its admin and proxy listeners before returning.
///
/// An unauthenticated `/health` plus a bare TCP accept is not identity
/// (issue #2132): the reservations above are released before the subprocess
/// binds, so a competing process can still claim the proxy port. The child then
/// dies with `Address already in use` while the foreign listener keeps answering
/// the probe, and every later data-path assertion is made against a stranger.
///
/// Barrier (same contract as `TestGateway` / `functional_grpc_plugins_test`):
/// 1. `Child::try_wait` before and after every probe — a dead child voids the
///    attempt instead of being polled for until the timeout.
/// 2. Authenticated `/health` detail tier for this attempt's bearer token with
///    `ready: true`, which flips only after every listener bind (proxy included).
/// 3. TCP connect to the proxy port once identity is proven.
async fn wait_for_owned_gateway(
    child: &mut std::process::Child,
    admin_port: u16,
    observability_token: &str,
    gateway_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    const STARTUP_TIMEOUT_SECS: u64 = 30;
    const PROBE_SLICE: Duration = Duration::from_secs(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(STARTUP_TIMEOUT_SECS);
    let addr = format!("127.0.0.1:{}", gateway_port);

    let mut last_observation = String::from("no response yet");
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "Gateway exited during startup with {status} \
                 (last observation: {last_observation})"
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "Gateway did not prove ownership of admin port {admin_port} within \
                 {STARTUP_TIMEOUT_SECS} seconds (last observation: {last_observation})"
            )
            .into());
        }
        match crate::common::probe_gateway_identity(
            admin_port,
            observability_token,
            remaining.min(PROBE_SLICE),
        )
        .await
        {
            Ok(()) => break,
            Err(err) => last_observation = err.to_string(),
        }
    }

    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("Gateway exited after reporting ready with {status}").into());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Gateway port {gateway_port} did not accept TCP connections within \
                 {STARTUP_TIMEOUT_SECS} seconds (last observation: {last_observation})"
            )
            .into());
        }
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => return Ok(()),
            Err(err) => last_observation = err.to_string(),
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Bounded spawn retry for the ONE non-deterministic startup failure.
///
/// Every attempt takes fresh, simultaneously-held port reservations and a fresh
/// ownership token, so a failed attempt never leaves a half-claimed port or a
/// reusable credential behind. What changed for the root review is *when* a
/// retry happens at all: a retry is only taken when the child's own captured
/// diagnostics DEMONSTRATE an address-in-use bind race
/// ([`bind_race_diagnosed`]) — the race that exists because a reservation must
/// be released before the child can bind it.
///
/// Every other failure is deterministic and fails immediately with the child's
/// stdout/stderr tail attached. A config parse error, a rejected plugin
/// composition, a panic, or an authentication mismatch reproduces identically on
/// fresh ports, so retrying it only replaces an actionable diagnostic with
/// "did not start after 3 attempts" — the exact failure mode this repair
/// removes.
async fn start_gateway_with_retry(
    config_path: &str,
    log_dir: &Path,
) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        // `reserve_port_pair` fails only by being unable to bind a free
        // ephemeral loopback port, which is the same contention this retry loop
        // exists for — so it is retried, and exhausting the attempts is fatal.
        let reserved = reserve_port_pair().await;
        let (gateway_reservation, admin_reservation) = match reserved {
            Ok(pair) => pair,
            Err(error) => {
                assert!(
                    attempt < MAX_ATTEMPTS,
                    "no free gateway/admin port pair after {MAX_ATTEMPTS} attempts: {error}"
                );
                eprintln!("Gateway port reservation attempt {attempt}/{MAX_ATTEMPTS}: {error}");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let observability_token = mint_observability_token();
        let logs = AttemptLogs::create(log_dir, attempt);
        let started = start_gateway(
            config_path,
            gateway_reservation,
            admin_reservation,
            &observability_token,
            &logs,
        );
        // Spawning is deterministic: a missing or non-executable gateway binary
        // will not become executable on the next attempt.
        let (mut child, gateway_port, admin_port) = match started {
            Ok(started) => started,
            Err(error) => {
                let binary = gateway_binary_path();
                panic!(
                    "Gateway spawn failed deterministically on attempt \
                     {attempt}/{MAX_ATTEMPTS} ({binary}): {error}"
                );
            }
        };

        match wait_for_owned_gateway(&mut child, admin_port, &observability_token, gateway_port)
            .await
        {
            Ok(()) => return (child, gateway_port, admin_port),
            Err(readiness_error) => {
                // A still-live child from a void attempt must not outlive it and
                // keep holding ports the next attempt could be offered. Reaping
                // it first also closes its capture files, so the tail read below
                // sees everything it managed to write.
                let _ = child.kill();
                let _ = child.wait();
                let diagnostics = logs.read_bounded(&observability_token);
                let stdout = diagnostics.stdout;
                let stderr = diagnostics.stderr;
                assert!(
                    bind_race_diagnosed(&stdout, &stderr),
                    "Gateway startup failed on attempt {attempt}/{MAX_ATTEMPTS} for a reason \
                     that is NOT an address-in-use bind race, so it was not retried: \
                     {readiness_error}\n\
                     --- gateway stdout (last {MAX_DIAGNOSTIC_BYTES} bytes) ---\n{stdout}\n\
                     --- gateway stderr (last {MAX_DIAGNOSTIC_BYTES} bytes) ---\n{stderr}"
                );
                assert!(
                    attempt < MAX_ATTEMPTS,
                    "Gateway lost an address-in-use race on all {MAX_ATTEMPTS} attempts \
                     (last: {readiness_error})\n\
                     --- gateway stderr (last {MAX_DIAGNOSTIC_BYTES} bytes) ---\n{stderr}"
                );
                eprintln!(
                    "Gateway attempt {attempt}/{MAX_ATTEMPTS} lost an address-in-use race \
                     ({readiness_error}); retrying on fresh ports"
                );
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
    unreachable!("every attempt either returns, retries, or asserts");
}

struct GrpcCall {
    status: u16,
    headers: HashMap<String, String>,
    trailers: HashMap<String, String>,
    body: Vec<u8>,
}

impl GrpcCall {
    fn terminal_grpc_status(&self) -> &str {
        self.trailers
            .get("grpc-status")
            .or_else(|| self.headers.get("grpc-status"))
            .map(String::as_str)
            .unwrap_or("")
    }
}

/// A successful message-carrying gRPC response: HTTP 200, `grpc-status: 0` in
/// terminal TRAILERS, and no terminal metadata in the initial HEADERS block.
fn assert_ok_message_carrying(call: &GrpcCall, context: &str) {
    assert_eq!(call.status, 200, "{context}: gRPC rides HTTP 200");
    assert_eq!(
        call.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "{context}: expected grpc-status: 0 in terminal trailers (headers={:?})",
        call.headers.get("grpc-status"),
    );
    assert!(
        !call.headers.contains_key("grpc-status"),
        "{context}: a message-carrying response must not expose grpc-status in initial HEADERS",
    );
    assert_eq!(
        call.headers.get("content-type").map(String::as_str),
        Some("application/grpc"),
        "{context}: content-type must stay application/grpc",
    );
}

/// A fail-closed rewrite refusal: HTTP 200 Trailers-Only with a nonzero
/// `grpc-status` and an EMPTY body. An HTTP JSON error body here would be an
/// HTTP-body leak onto a native gRPC stream.
fn assert_trailers_only_failure(call: &GrpcCall, context: &str) {
    assert_eq!(
        call.status, 200,
        "{context}: a gRPC failure rides HTTP 200, not a synthetic 5xx",
    );
    let raw = call.terminal_grpc_status();
    assert!(
        !raw.is_empty(),
        "{context}: expected a present terminal grpc-status, got empty/missing",
    );
    let code: u32 = raw
        .parse()
        .unwrap_or_else(|_| panic!("{context}: grpc-status {raw:?} is not a parseable u32"));
    assert_ne!(
        code, 0,
        "{context}: expected a nonzero terminal grpc-status"
    );
    assert!(
        call.body.is_empty(),
        "{context}: a gRPC rewrite refusal must be trailers-only, not an HTTP body ({} bytes)",
        call.body.len(),
    );
}

/// Hard ceiling on ONE live gRPC exchange — TCP connect, HTTP/2 handshake,
/// request, and full body+trailer collection.
///
/// Every call in this file goes through [`send_grpc_request`], so nothing can
/// block on the data path without a bound. A gateway that accepts the
/// connection and then never answers (a wedged rewrite, a stalled reload, a
/// half-dead child) surfaces as a named timeout error rather than as a test that
/// hangs until the whole suite is killed and reports nothing.
const GRPC_CALL_TIMEOUT: Duration = Duration::from_secs(10);

async fn send_grpc_request(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<GrpcCall, Box<dyn std::error::Error + Send + Sync>> {
    send_grpc_request_within(gateway_addr, path, body, extra_headers, GRPC_CALL_TIMEOUT).await
}

/// [`send_grpc_request`] under an explicit budget.
///
/// A polling loop passes the time it has left so one blocked call can never
/// outlive the outer behavioral deadline: the budget is the smaller of the
/// per-call ceiling and the loop's own remaining time.
async fn send_grpc_request_within(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
    budget: Duration,
) -> Result<GrpcCall, Box<dyn std::error::Error + Send + Sync>> {
    let call = send_grpc_request_unbounded(gateway_addr, path, body, extra_headers);
    match tokio::time::timeout(budget, call).await {
        Ok(result) => result,
        Err(_) => {
            let message = format!(
                "gRPC call to {path} did not complete within {budget:?} \
                 (no response, or the connection stalled mid-stream)"
            );
            Err(message.into())
        }
    }
}

async fn send_grpc_request_unbounded(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<GrpcCall, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Client h2 connection error: {}", e);
        }
    });

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    for (key, value) in extra_headers {
        req_builder = req_builder.header(*key, *value);
    }
    let req = req_builder.body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(text) = value.to_str() {
            headers.insert(key.as_str().to_string(), text.to_string());
        }
    }
    let collected = response.into_body().collect().await?;
    let mut trailers = HashMap::new();
    if let Some(trailer_map) = collected.trailers() {
        for (key, value) in trailer_map {
            if let Ok(text) = value.to_str() {
                trailers.insert(key.as_str().to_string(), text.to_string());
            }
        }
    }

    Ok(GrpcCall {
        status,
        headers,
        trailers,
        body: collected.to_bytes().to_vec(),
    })
}

/// A file-mode config with one `a2a_gateway` instance. The backend port stays a
/// placeholder so the same template can be re-rendered for a reload against the
/// harness's already-running backend.
fn config_template(
    public_base: &str,
    rewrite_agent_card_urls: bool,
    protocol_versions: &str,
) -> String {
    config_template_with_services(
        public_base,
        rewrite_agent_card_urls,
        protocol_versions,
        DEFAULT_GRPC_SERVICES,
    )
}

fn config_template_with_services(
    public_base: &str,
    rewrite_agent_card_urls: bool,
    protocol_versions: &str,
    grpc_services: &str,
) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "a2a-grpc-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: BACKEND_PORT_PLACEHOLDER
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "a2a-grpc"

consumers: []

plugin_configs:
  - id: "a2a-grpc"
    plugin_name: "a2a_gateway"
    scope: proxy
    proxy_id: "a2a-grpc-proxy"
    enabled: true
    config:
      enabled: true
      endpoint:
        path: "/a2a"
        protocol_versions: {protocol_versions}
        grpc_services: {grpc_services}
      detection:
        bindings: [grpc]
      discovery:
        rewrite_agent_card_urls: {rewrite_agent_card_urls}
        public_base_url: "{public_base}"
      observability:
        emit_metadata: true
"#
    )
}

struct Harness {
    gateway: std::process::Child,
    backend: tokio::task::JoinHandle<()>,
    /// Only read by the Unix-only SIGHUP reload path.
    #[cfg_attr(not(unix), allow(dead_code))]
    backend_port: u16,
    addr: String,
    /// Only read by the Unix-only SIGHUP reload path.
    #[cfg_attr(not(unix), allow(dead_code))]
    config_path: std::path::PathBuf,
    _temp: TempDir,
}

impl Harness {
    async fn start_with(template: String) -> Self {
        build_gateway().expect("build gateway binary");
        let (backend_port, backend) = start_grpc_echo_backend().await;
        let temp = TempDir::new().expect("temp dir");
        let config_path = temp.path().join("config.yaml");
        write_config(&config_path, &render(&template, backend_port));
        let (gateway, port, _admin) =
            start_gateway_with_retry(config_path.to_str().expect("utf-8 path"), temp.path()).await;
        Self {
            gateway,
            backend,
            backend_port,
            addr: format!("127.0.0.1:{}", port),
            config_path,
            _temp: temp,
        }
    }

    /// Default harness: rewriting on, public base `PUBLIC_BASE`, `0.3.0` only.
    async fn start() -> Self {
        Self::start_with(config_template(PUBLIC_BASE, true, r#"["0.3.0"]"#)).await
    }

    /// Rewrite the config file and SIGHUP the RUNNING child. Callers then poll
    /// the behavior that proves the new generation is active; an unconditional
    /// sleep is not a reload-completion signal and becomes flaky under runner
    /// contention.
    #[cfg(unix)]
    async fn reload_with(&self, template: String) {
        write_config(&self.config_path, &render(&template, self.backend_port));
        let pid = self.gateway.id();
        let output = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output()
            .expect("send SIGHUP to gateway");
        assert!(
            output.status.success(),
            "sending SIGHUP to gateway failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Poll the live data path until one response proves a reload has taken
    /// effect, or fail with the last observed response/error. This waits on the
    /// actual behavior under test instead of guessing how long a runner needs.
    ///
    /// Two bounds, and both are load-bearing. Each call gets an explicit budget
    /// of `min(per-call ceiling, time left on the behavioral deadline)`, so a
    /// gateway that accepts the connection and then never answers cannot make
    /// one iteration outlive the loop. And the child is checked for death on
    /// every iteration, so a gateway that died on the SIGHUP fails with its exit
    /// status instead of being polled at until the deadline reports a
    /// meaningless "behavior did not appear".
    #[cfg(unix)]
    async fn wait_for_reloaded_call(
        &mut self,
        path: &str,
        body: &[u8],
        context: &str,
        mut ready: impl FnMut(&GrpcCall) -> bool,
    ) -> GrpcCall {
        const RELOAD_DEADLINE: Duration = Duration::from_secs(10);
        let deadline = Instant::now() + RELOAD_DEADLINE;
        let mut last_observation = String::from("no request issued yet");
        loop {
            if let Ok(Some(status)) = self.gateway.try_wait() {
                panic!(
                    "{context}: gateway exited with {status} while waiting for the reload to take \
                     effect (last observation: {last_observation})"
                );
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "{context}: reloaded behavior did not appear within {RELOAD_DEADLINE:?}; \
                 last observation: {last_observation}"
            );
            let budget = remaining.min(GRPC_CALL_TIMEOUT);
            let outcome = send_grpc_request_within(&self.addr, path, body, &[], budget).await;
            last_observation = match outcome {
                Ok(call) if ready(&call) => return call,
                Ok(call) => {
                    let status = call.status;
                    let terminal = call.terminal_grpc_status().to_string();
                    let bytes = call.body.len();
                    format!("HTTP {status}, grpc-status {terminal:?}, body {bytes} bytes")
                }
                Err(error) => format!("request failed: {error}"),
            };
            sleep(Duration::from_millis(50)).await;
        }
    }

    fn shutdown(self) {
        drop(self);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        self.backend.abort();
    }
}

fn render(template: &str, backend_port: u16) -> String {
    template.replace("BACKEND_PORT_PLACEHOLDER", &backend_port.to_string())
}

fn write_config(path: &std::path::Path, config: &str) {
    let mut file = std::fs::File::create(path).expect("create config file");
    file.write_all(config.as_bytes()).expect("write config");
}

// ============================================================================
// Tests
// ============================================================================

/// The core acceptance: a unary `GetAgentCard` response is re-framed with the
/// JSON-RPC endpoints pointed at the public base, the advertised gRPC interface
/// left alone, and the now-invalid signature block removed — with
/// protocol-correct HTTP status, headers, and terminal trailers.
#[tokio::test]
#[ignore]
async fn a2a_grpc_agent_card_is_rewritten_on_the_live_data_path() {
    let harness = Harness::start().await;
    let card = encode_agent_card("0.3.0");
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&card),
        &[],
    )
    .await
    .expect("gRPC call");

    assert_ok_message_carrying(&call, "rewritten agent card");
    assert!(
        !call.headers.contains_key("grpc-encoding"),
        "a rewritten frame is uncompressed identity, so grpc-encoding must be gone",
    );
    // Validators and integrity digests describe the backend's ORIGINAL
    // representation and are invalidated by the rewrite. `content-length` is
    // deliberately not asserted here: it is transport-owned on this path and
    // the gateway recomputes it from the bytes it actually sends.
    assert!(
        !call.headers.contains_key("etag")
            && !call.headers.contains_key("content-digest")
            && !call.headers.contains_key("content-encoding"),
        "body-coupled headers must not describe the backend's replaced representation",
    );

    let message = single_frame_payload(&call.body);
    assert_eq!(
        string_field(&message, 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
        "AgentCard.url must point at the public JSON-RPC endpoint",
    );
    let interfaces = repeated_messages(&message, 15);
    assert_eq!(interfaces.len(), 2, "both interfaces must survive");
    assert_eq!(
        string_field(&interfaces[0], 1).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
        "the JSONRPC interface must be rewritten",
    );
    assert_eq!(
        string_field(&interfaces[1], 1).as_deref(),
        Some("https://planner.internal/grpc"),
        "a non-JSONRPC interface must be preserved verbatim",
    );
    assert!(
        !has_field(&message, 17),
        "signatures must be removed: the rewrite invalidated them",
    );
    assert_eq!(
        string_field(&message, 1).as_deref(),
        Some("planner"),
        "unrelated fields must round-trip unchanged",
    );
    assert_eq!(string_field(&message, 16).as_deref(), Some("0.3.0"));
    harness.shutdown();
}

/// `GetExtendedAgentCard` is the other card RPC and takes the same path.
#[tokio::test]
#[ignore]
async fn a2a_grpc_extended_agent_card_is_rewritten_too() {
    let harness = Harness::start().await;
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetExtendedAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[],
    )
    .await
    .expect("gRPC call");

    assert_ok_message_carrying(&call, "extended agent card");
    let message = single_frame_payload(&call.body);
    assert_eq!(
        string_field(&message, 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );
    harness.shutdown();
}

/// A non-card A2A RPC on the same service must be forwarded byte-for-byte: the
/// rewriter is scoped to Agent Card responses, not to A2A traffic generally.
#[tokio::test]
#[ignore]
async fn a2a_grpc_non_card_rpc_is_forwarded_untouched() {
    let harness = Harness::start().await;
    let body = grpc_frame(&encode_agent_card("0.3.0"));
    let call = send_grpc_request(&harness.addr, &format!("{A2A_SERVICE}/GetTask"), &body, &[])
        .await
        .expect("gRPC call");

    assert_ok_message_carrying(&call, "non-card RPC");
    assert_eq!(
        call.body, body,
        "a non-card RPC response must be forwarded verbatim",
    );
    harness.shutdown();
}

/// A card whose wire `protocol_version` is not an exactly-configured 0.3 version
/// fails closed. Serving it un-rewritten would hand discovery clients internal
/// URLs; rewriting it with 0.3 field numbers could corrupt a renumbered layout.
#[tokio::test]
#[ignore]
async fn a2a_grpc_unconfigured_card_version_fails_closed() {
    let harness = Harness::start().await;

    // Same 0.3 family, but not the configured `0.3.0`.
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.99")),
        &[],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "unconfigured 0.3.x version");

    // A renumbered 1.0 layout.
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("1.0.0")),
        &[],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "non-0.3 layout");
    harness.shutdown();
}

/// Malformed framing and message-level compression both fail closed with
/// protocol-correct gRPC semantics rather than a partially-rewritten card.
#[tokio::test]
#[ignore]
async fn a2a_grpc_malformed_and_compressed_cards_fail_closed() {
    let harness = Harness::start().await;

    let mut truncated = grpc_frame(&encode_agent_card("0.3.0"));
    truncated.pop();
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &truncated,
        &[],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "truncated gRPC frame");

    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[("x-set-grpc-encoding", "gzip")],
    )
    .await
    .expect("gRPC call");
    assert_trailers_only_failure(&call, "message-compressed card");
    harness.shutdown();
}

/// A non-OK upstream reply that still carries a DATA frame must reach the client
/// as the backend's own failure. The terminal status arrives in TRAILERS, so a
/// rewriter that only inspects initial HEADERS would mistake it for a successful
/// Agent Card and then blame itself for failing to rewrite it.
#[tokio::test]
#[ignore]
async fn a2a_grpc_non_ok_upstream_reply_is_not_mistaken_for_a_card() {
    let harness = Harness::start().await;
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[("x-set-grpc-status", "7")],
    )
    .await
    .expect("gRPC call");

    assert_eq!(call.status, 200);
    assert_eq!(
        call.terminal_grpc_status(),
        "7",
        "the backend's own PERMISSION_DENIED must survive, not become a rewrite INTERNAL",
    );
    harness.shutdown();
}

/// Reload/update: a changed `discovery.public_base_url` takes effect on the
/// running gateway. First construction being correct is not enough — issue #3297
/// asks for reload coverage explicitly.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn a2a_grpc_card_rewrite_follows_a_reloaded_public_base() {
    let mut harness = Harness::start().await;
    let path = format!("{A2A_SERVICE}/GetAgentCard");
    let body = grpc_frame(&encode_agent_card("0.3.0"));

    let call = send_grpc_request(&harness.addr, &path, &body, &[])
        .await
        .expect("pre-reload gRPC call");
    assert_ok_message_carrying(&call, "pre-reload");
    assert_eq!(
        string_field(&single_frame_payload(&call.body), 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );

    harness
        .reload_with(config_template(ALTERNATE_PUBLIC_BASE, true, r#"["0.3.0"]"#))
        .await;

    let expected_url = format!("{ALTERNATE_PUBLIC_BASE}/a2a");
    let call = harness
        .wait_for_reloaded_call(&path, &body, "public-base reload", |call| {
            call.terminal_grpc_status() == "0"
                && call
                    .body
                    .windows(expected_url.len())
                    .any(|window| window == expected_url.as_bytes())
        })
        .await;
    assert_ok_message_carrying(&call, "post-reload");
    let message = single_frame_payload(&call.body);
    assert_eq!(
        string_field(&message, 3).as_deref(),
        Some(format!("{ALTERNATE_PUBLIC_BASE}/a2a").as_str()),
        "the reloaded public base must be the one advertised",
    );
    assert_eq!(
        string_field(&repeated_messages(&message, 15)[0], 1).as_deref(),
        Some(format!("{ALTERNATE_PUBLIC_BASE}/a2a").as_str()),
    );
    harness.shutdown();
}

/// Reload/withdrawal: turning `rewrite_agent_card_urls` off must actually stop
/// the rewrite on the running gateway — including stopping the fail-closed
/// refusal for versions it can no longer rewrite, which is the documented way an
/// operator fronts a non-0.3 backend.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn a2a_grpc_card_rewrite_withdrawal_takes_effect_on_reload() {
    let mut harness = Harness::start().await;
    let path = format!("{A2A_SERVICE}/GetAgentCard");
    let card = encode_agent_card("0.3.0");
    let body = grpc_frame(&card);

    let call = send_grpc_request(&harness.addr, &path, &body, &[])
        .await
        .expect("pre-reload gRPC call");
    assert_ne!(
        call.body, body,
        "the rewrite must be active before withdrawal"
    );

    harness
        .reload_with(config_template(PUBLIC_BASE, false, r#"["0.3.0"]"#))
        .await;

    let call = harness
        .wait_for_reloaded_call(&path, &body, "rewrite withdrawal", |call| {
            call.terminal_grpc_status() == "0" && call.body.as_slice() == body
        })
        .await;
    assert_ok_message_carrying(&call, "withdrawn rewrite");
    assert_eq!(
        call.body, body,
        "with rewriting withdrawn, the backend's signed card must pass through verbatim",
    );

    // And a version this gateway cannot rewrite is no longer refused either.
    let unsupported = grpc_frame(&encode_agent_card("1.0.0"));
    let call = send_grpc_request(&harness.addr, &path, &unsupported, &[])
        .await
        .expect("gRPC call");
    assert_ok_message_carrying(&call, "withdrawn rewrite, 1.0 card");
    assert_eq!(call.body, unsupported);
    harness.shutdown();
}

/// Reload/update of the version allow-list: adding the wire version an upstream
/// actually serves turns a fail-closed refusal into a rewrite, without a
/// restart.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn a2a_grpc_card_version_allow_list_reload_admits_a_new_version() {
    let mut harness = Harness::start().await;
    let path = format!("{A2A_SERVICE}/GetAgentCard");
    let body = grpc_frame(&encode_agent_card("0.3.7"));

    let call = send_grpc_request(&harness.addr, &path, &body, &[])
        .await
        .expect("pre-reload gRPC call");
    assert_trailers_only_failure(&call, "0.3.7 before it is configured");

    harness
        .reload_with(config_template(PUBLIC_BASE, true, r#"["0.3.0", "0.3.7"]"#))
        .await;

    let expected_url = format!("{PUBLIC_BASE}/a2a");
    let call = harness
        .wait_for_reloaded_call(&path, &body, "version allow-list reload", |call| {
            call.terminal_grpc_status() == "0"
                && call
                    .body
                    .windows(expected_url.len())
                    .any(|window| window == expected_url.as_bytes())
        })
        .await;
    assert_ok_message_carrying(&call, "0.3.7 after it is configured");
    assert_eq!(
        string_field(&single_frame_payload(&call.body), 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );
    harness.shutdown();
}

// ============================================================================
// gRPC service identity vs Agent Card schema, on the live data path
// ============================================================================

/// The canonical A2A **1.0** identity must never be rewritten as 0.3, even when
/// the operator configured it and the backend happens to return 0.3-shaped
/// bytes with an admitted `protocol_version`.
///
/// This is the pairing the root review flagged: `lf.a2a.v1.A2AService` is
/// package `lf.a2a.v1` with a RENUMBERED `AgentCard`, so applying 0.3 field
/// numbers to it would replace each `AgentInterface` submessage with a bare URL
/// string and leave the real signatures in place. The decoder follows the
/// declared service schema, never the bytes, so the reply is refused with the
/// accurate schema disposition instead.
#[tokio::test]
#[ignore]
async fn a2a_grpc_10_service_identity_is_never_rewritten_as_0_3() {
    let harness = Harness::start_with(config_template_with_services(
        PUBLIC_BASE,
        true,
        r#"["0.3.0"]"#,
        r#"["lf.a2a.v1.A2AService"]"#,
    ))
    .await;

    let body = grpc_frame(&encode_agent_card("0.3.0"));
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_10_SERVICE}/GetAgentCard"),
        &body,
        &[],
    )
    .await
    .expect("gRPC call");

    assert_trailers_only_failure(&call, "A2A 1.0 service identity");
    assert!(
        !call
            .body
            .windows(PUBLIC_BASE.len())
            .any(|window| window == PUBLIC_BASE.as_bytes()),
        "a 1.0 service's reply must never be re-encoded with the public base",
    );
    harness.shutdown();
}

/// The canonical 0.3 service is the DEFAULT, and the 1.0 service is not: a 0.3
/// gateway left at its defaults does not treat 1.0 traffic as an Agent Card path
/// at all, so a 1.0 card is forwarded byte for byte.
#[tokio::test]
#[ignore]
async fn a2a_grpc_default_service_set_is_the_canonical_0_3_identity() {
    let harness = Harness::start().await;
    let body = grpc_frame(&encode_agent_card("0.3.0"));

    // The canonical 0.3 identity is detected and rewritten by default.
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &body,
        &[],
    )
    .await
    .expect("gRPC call");
    assert_ok_message_carrying(&call, "default 0.3 service");
    assert_eq!(
        string_field(&single_frame_payload(&call.body), 3).as_deref(),
        Some(format!("{PUBLIC_BASE}/a2a").as_str()),
    );

    // The 1.0 identity is not in the default set, so it is untouched.
    let call = send_grpc_request(
        &harness.addr,
        &format!("{A2A_10_SERVICE}/GetAgentCard"),
        &body,
        &[],
    )
    .await
    .expect("gRPC call");
    assert_ok_message_carrying(&call, "undetected 1.0 service");
    assert_eq!(
        call.body, body,
        "a service outside endpoint.grpc_services must be forwarded verbatim",
    );
    harness.shutdown();
}

// ============================================================================
// Harness guards
//
// Plain (non-`#[ignore]`) tests: they exercise the harness's own decision
// functions and its per-call bound, need no gateway binary, and run in the same
// CI shard as the E2E cells above (`--run-ignored=all`).
// ============================================================================

/// Retry classification is POSITIVE: only a demonstrated address-in-use bind
/// race is retried. Every deterministic startup failure must be reported, not
/// re-rolled into "did not start after 3 attempts".
#[test]
fn only_a_demonstrated_address_in_use_race_is_retryable() {
    for (stdout, stderr, label) in [
        (
            "",
            "ERROR failed to bind 127.0.0.1:8080: Address already in use (os error 48)",
            "macOS EADDRINUSE",
        ),
        (
            "",
            "Os { code: 98, kind: AddrInUse, message: \"Address already in use\" }",
            "Linux AddrInUse debug",
        ),
        (
            "bind failed: os error 10048",
            "",
            "Windows WSAEADDRINUSE on stdout",
        ),
    ] {
        assert!(
            bind_race_diagnosed(stdout, stderr),
            "{label} must be classified as a retryable bind race"
        );
    }

    for (stdout, stderr, label) in [
        ("", "", "no diagnostics at all"),
        (
            "",
            "ERROR Configuration error: a2a_gateway: 'endpoint.path' must be absolute",
            "config parse failure",
        ),
        (
            "",
            "thread 'main' panicked at src/startup.rs:1: boom",
            "child panic",
        ),
        (
            "",
            "ERROR admin JWT secret must be at least 32 characters",
            "deterministic admission failure",
        ),
        (
            "",
            "WARN connection refused (os error 61)",
            "an unrelated errno",
        ),
        (
            "",
            "ERROR backend unreachable: Connection reset by peer",
            "a backend-side failure",
        ),
    ] {
        assert!(
            !bind_race_diagnosed(stdout, stderr),
            "{label} is deterministic and must NOT be retried"
        );
    }
}

/// Child diagnostics are captured, bounded to the tail, and stripped of the
/// attempt's bearer token before they can reach a CI log.
#[test]
fn child_diagnostics_are_bounded_and_redact_the_probe_token() {
    let temp = TempDir::new().expect("temp dir");
    let logs = AttemptLogs::create(temp.path(), 1);
    let token = "ferrum-edge-a2a-grpc-card-probe-deadbeef";

    let filler = "x".repeat(MAX_DIAGNOSTIC_BYTES as usize * 3);
    let mut out = std::fs::File::create(&logs.stdout).expect("create stdout capture");
    write!(out, "{filler}TAIL-MARKER").expect("write stdout capture");
    let mut err = std::fs::File::create(&logs.stderr).expect("create stderr capture");
    write!(err, "probing with bearer {token} -> 401").expect("write stderr capture");
    drop(out);
    drop(err);

    let diagnostics = logs.read_bounded(token);
    let stdout = diagnostics.stdout;
    let stderr = diagnostics.stderr;
    let stdout_len = stdout.len();
    assert!(
        stdout_len <= MAX_DIAGNOSTIC_BYTES as usize,
        "captured stdout must be bounded, got {stdout_len} bytes"
    );
    assert!(
        stdout.ends_with("TAIL-MARKER"),
        "the TAIL is what explains a startup failure, so it must be the part kept"
    );
    assert!(
        !stderr.contains(token),
        "the per-attempt bearer token must never be surfaced in a diagnostic"
    );
    assert!(
        stderr.contains("<redacted-probe-token>"),
        "redaction must be visible rather than silently dropping the line: {stderr}"
    );

    // A missing capture is reported, never panicked on: the point of these files
    // is to explain a failure, so reading them must not become a second one.
    let missing = AttemptLogs::create(temp.path(), 99).read_bounded(token);
    assert!(missing.stdout.starts_with("<unavailable"));
}

/// A peer that accepts the connection and then says nothing must fail the call
/// within its budget, not hang. This is what keeps a wedged gateway from
/// outliving the reload loop's behavioral deadline.
#[tokio::test]
async fn a_silent_peer_fails_within_the_per_call_budget() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent peer");
    let addr = listener.local_addr().expect("silent peer addr").to_string();
    // Accept and hold the connection open without ever writing an HTTP/2
    // preface, so the client's handshake blocks indefinitely.
    let accepted = tokio::spawn(async move {
        let _held = listener.accept().await;
        sleep(Duration::from_secs(30)).await;
    });

    let budget = Duration::from_millis(400);
    let started = Instant::now();
    let outcome = send_grpc_request_within(
        &addr,
        &format!("{A2A_SERVICE}/GetAgentCard"),
        &grpc_frame(&encode_agent_card("0.3.0")),
        &[],
        budget,
    )
    .await;
    let elapsed = started.elapsed();
    let error = match outcome {
        Ok(call) => {
            let status = call.status;
            panic!("a silent peer must not produce a gRPC response (got HTTP {status})")
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("did not complete within"),
        "the failure must name the per-call budget, got: {error}"
    );
    assert!(
        elapsed < budget + Duration::from_secs(5),
        "the call must be cut at its budget, took {elapsed:?}"
    );
    accepted.abort();
}
