//! Live transport-admission coverage for the SPIFFE Workload API listener
//! (issue #3758).
//!
//! The unit suite (`tests/unit/identity/workload_api_admission_tests.rs`) pins
//! the *decision* half — ceilings, refusal of `0`, the total bound across
//! several UIDs, per-UID fair share (sequentially and under a concurrent burst),
//! and the closed reason-label set — because a single-uid test process cannot
//! reach the second-UID case through real sockets. That division is not a
//! convenience: the per-UID quota must stay **strictly below** the global
//! ceiling, so a single-UID process *cannot* saturate the global pool at all,
//! and no test here claims to. These tests pin the half that only real sockets
//! can prove:
//!
//! - an over-quota connection is shed **without allocating a gRPC connection** —
//!   the shed peer sees an immediate EOF, not a session — and the listener keeps
//!   serving through a sustained flood of them;
//! - the per-UID quota binds for this process's own UID while the global pool
//!   still has room, so the quota is genuinely per principal;
//! - `SETTINGS_MAX_CONCURRENT_STREAMS` is actually advertised on the wire at the
//!   configured value, read straight off a raw HTTP/2 handshake, **and** a peer
//!   that ignores it and opens one stream too many gets a bounded protocol
//!   refusal rather than an unbounded server-side allocation;
//! - the service-wide RPC ceiling **sheds** with `RESOURCE_EXHAUSTED` rather
//!   than queueing, and releases exactly when the streaming RPC that held the
//!   permit ends;
//! - permits come back on every close path a test can drive: the watchdog's
//!   initial-connection deadline, a client disconnect, and shutdown;
//! - **both** connection-deadline branches, not just the first: a peer that
//!   never speaks is closed on the initial deadline, and a peer that speaks once
//!   and then stops is closed on the *idle* deadline — the post-first-read
//!   branch, reached with a truncated HTTP/2 preface because a completed
//!   handshake would be closed by HTTP/2 keepalive first;
//! - and the property that deadline must not break: an application-idle but
//!   keepalive-refreshed `FetchX509SVID` stream survives well past the idle
//!   deadline and still receives a later rotation, which is exactly what a
//!   healthy Workload API client looks like;
//! - shutdown completes inside its bounded deadline while clients hold an idle
//!   socket, a half-finished HTTP/2 session, and a long-lived Workload API
//!   stream — the shape that hangs a purely graceful drain forever;
//! - normal X.509-SVID rotation, JWT-SVID mint/validate, bundle streaming, peer
//!   attestation, and socket-inode cleanup all still work under tight limits;
//! - a **fatal accept** reaches the bounded drain even while an established
//!   long-lived rotation stream is open, so termination cannot stay pending
//!   indefinitely;
//! - the exported metric families stay fixed-cardinality, and the RPC families
//!   state the *one-way* stream relationship in their help text — every
//!   admitted RPC is one HTTP/2 stream, but not every live stream is an
//!   admitted RPC — so nothing here claims an observation this layer does not
//!   make.
//!
//! Everything runs on the ordinary hosted Linux CI runner: Unix sockets in a
//! per-test temp directory, no root, no network. Nothing here sleeps for a fixed
//! duration where a bounded poll would do, so the flood assertions are
//! deterministic rather than timing-lucky.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ferrum_edge::identity::attestation::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{CertificateAuthority, bootstrap, internal};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use ferrum_edge::identity::workload_api::proto::{
    JwtsvidRequest, ValidateJwtsvidRequest, X509BundlesRequest, X509svidRequest,
};
use ferrum_edge::identity::workload_api::{
    WorkloadApiAdmissionConfig, WorkloadApiListener, WorkloadApiService, WorkloadApiSocketConfig,
    close_reason, reject_reason, serve_workload_api_with_admission,
};
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

const TRUST_DOMAIN: &str = "workload-admission.test";

/// Long enough that no test's held connection is closed by a lifetime deadline
/// unless that is what the test is about.
const GENEROUS_INITIAL_SECS: u64 = 60;
const GENEROUS_IDLE_SECS: u64 = 120;

fn trust_domain() -> TrustDomain {
    TrustDomain::new(TRUST_DOMAIN.to_string()).expect("test trust domain is valid")
}

fn workload_id() -> SpiffeId {
    SpiffeId::from_parts(&trust_domain(), "ns/test/sa/app").expect("test SPIFFE ID is valid")
}

/// Stands in for a peer-credential rule: it authorizes exactly one identity, so
/// the subject is never caller-selected. Retained under the limits so the
/// attestation half of the surface is exercised, not bypassed.
struct FixedAttestor;

#[async_trait]
impl Attestor for FixedAttestor {
    fn kind(&self) -> &'static str {
        "test-fixed"
    }

    async fn attest(&self, _peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: workload_id(),
            selectors: Default::default(),
            attestor_kind: "test-fixed".to_string(),
        })
    }
}

/// A dev-root-backed internal CA with an ephemeral JWT authority.
///
/// Ephemeral is correct here: none of these tests depends on JWT continuity
/// across a restart, and the dev posture keeps the fixture free of configured
/// key material.
fn internal_ca() -> Arc<internal::InternalCa> {
    // SAFETY: set before any Workload API server is constructed in this test
    // binary, and only ever to these values, so no concurrently running test
    // observes a different value for them.
    unsafe {
        std::env::set_var("FERRUM_MESH_PRODUCTION_MODE", "false");
        std::env::set_var("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    }
    let root = bootstrap::bootstrap_dev_root(bootstrap::BootstrapConfig::new(trust_domain()))
        .expect("dev root bootstraps");
    Arc::new(
        internal::InternalCa::new(internal::InternalCaConfig {
            root_cert_pem: root.root_cert_pem,
            root_key_pem: root.root_key_pem,
            trust_domain: root.trust_domain,
            bundle_refresh_hint_secs: None,
            default_svid_ttl_secs: 600,
            max_svid_ttl_secs: 3600,
            jwt_signing_key_pem: None,
            jwt_retired_key_pems: Vec::new(),
            jwt_key_lifetime_secs: 0,
            allow_ephemeral_jwt_key: true,
        })
        .expect("internal CA builds"),
    )
}

/// A unique socket path under the system temp dir.
///
/// Deliberately short: `sockaddr_un.sun_path` is ~104 bytes, and a long per-test
/// path is the classic reason a UDS test fails with a bare `EINVAL`.
fn socket_path(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("fe-wa-{label}-{}.sock", unique % 1_000_000_000))
}

/// Limits built from the shipped defaults, so a test only states the bound it is
/// actually about and every other bound stays at its production value.
fn limits() -> WorkloadApiAdmissionConfig {
    WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_secs(GENEROUS_INITIAL_SECS),
        idle_timeout: Duration::from_secs(GENEROUS_IDLE_SECS),
        ..WorkloadApiAdmissionConfig::default()
    }
}

struct Harness {
    listener: WorkloadApiListener,
    path: PathBuf,
    rotation_signal: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Harness {
    async fn start(label: &str, admission: WorkloadApiAdmissionConfig) -> Self {
        admission
            .validate()
            .expect("every fixture configuration must itself be acceptable configuration");
        let path = socket_path(label);
        let ca = internal_ca();
        let rotation_signal = Arc::new(tokio::sync::watch::channel(0u64).0);
        let service = WorkloadApiService::with_rotation_signal(
            vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
            ca as Arc<dyn CertificateAuthority>,
            trust_domain(),
            600,
            Arc::clone(&rotation_signal),
        )
        .with_jwt_svid_ttl_secs(300);
        let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660")
            .expect("socket config is well formed");
        let listener = serve_workload_api_with_admission(service, socket, admission)
            .await
            .expect("Workload API listener binds");
        Self {
            listener,
            path,
            rotation_signal,
        }
    }

    /// Shut down and return how long that took, so a caller can assert the
    /// bounded-drain contract rather than merely that it eventually finished.
    async fn shutdown_within(self, budget: Duration) -> Duration {
        let path = self.path.clone();
        let started = Instant::now();
        tokio::time::timeout(budget, self.listener.shutdown())
            .await
            .expect("Workload API shutdown must complete inside its bounded deadline");
        let elapsed = started.elapsed();
        assert!(
            !path.exists(),
            "the socket artifact Ferrum created must still be unlinked on the bounded path"
        );
        elapsed
    }
}

/// Dial a Unix socket with the same connector shape the production client uses.
async fn connect(path: &Path) -> SpiffeWorkloadApiClient<Channel> {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::1]:0")
        .expect("dummy endpoint parses")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .expect("Workload API socket accepts a connection");
    SpiffeWorkloadApiClient::new(channel)
}

/// Every Workload API RPC must carry the mandatory metadata header.
fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        AsciiMetadataValue::from_static("true"),
    );
    req
}

/// The two `reason`-labelled admission metric families.
const REJECTED_FAMILY: &str = "ferrum_mesh_workload_api_connections_rejected_total";
const CLOSED_FAMILY: &str = "ferrum_mesh_workload_api_connections_closed_total";

/// The HTTP/2 client connection preface followed by an empty SETTINGS frame.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Connect a raw socket and confirm the listener handed it to the gRPC stack.
///
/// The discriminator is exact rather than timing-based: an HTTP/2 server flushes
/// its own SETTINGS frame before it reads the client preface, so an *admitted*
/// connection always yields bytes and a *shed* one always yields EOF. Neither
/// outcome depends on how fast the runner is.
async fn connect_admitted(path: &Path) -> UnixStream {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("the socket accepts a connection");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
        .await
        .expect("an admitted connection reaches the HTTP/2 server")
        .expect("an admitted connection is not torn down");
    assert!(
        read > 0,
        "an admitted connection must receive server SETTINGS; EOF means it was shed"
    );
    stream
}

/// Connect a raw socket and require the listener to have shed it before any
/// gRPC session existed.
async fn connect_expecting_shed(path: &Path) {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("the listener still accepts, then sheds; it does not stop listening");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
        .await
        .expect("an over-limit connection must be shed promptly, never queued")
        .expect("a shed connection is closed cleanly, not with an error");
    assert_eq!(read, 0, "a shed peer observes EOF with no HTTP/2 exchanged");
}

/// Poll until a full RPC succeeds, or fail after `budget`.
///
/// Used where the property under test is that capacity *came back*: the release
/// happens on the server's own schedule (a dropped connection task, a watchdog
/// close), so the assertion is "within a bound", never "on the next attempt".
async fn wait_for_service(path: &Path, budget: Duration) {
    let deadline = Instant::now() + budget;
    let mut last: Option<String> = None;
    while Instant::now() < deadline {
        let mut client = connect(path).await;
        match client
            .fetch_jwtsvid(workload_request(JwtsvidRequest {
                audience: vec!["spiffe://audience.test/api".to_string()],
                spiffe_id: String::new(),
            }))
            .await
        {
            Ok(_) => return,
            Err(status) => last = Some(status.code().to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "capacity was never released within {budget:?}; last RPC outcome: {}",
        last.unwrap_or_else(|| "no attempt completed".to_string())
    );
}

#[tokio::test]
async fn an_over_quota_connection_is_shed_before_any_grpc_allocation() {
    // The bound observed here is the **per-UID quota**, and it says so: the test
    // process has one UID, and a fair configuration keeps that quota strictly
    // below the global ceiling, so a single-UID client can never reach the
    // global bound. The global bound across several UIDs is pinned against the
    // same accounting in the unit suite.
    const QUOTA: usize = 3;
    let harness = Harness::start(
        "quota",
        WorkloadApiAdmissionConfig {
            max_connections: QUOTA + 1,
            max_connections_per_uid: QUOTA,
            ..limits()
        },
    )
    .await;

    // Every connection up to the quota is admitted and stays open.
    let mut held = Vec::new();
    for _ in 0..QUOTA {
        held.push(connect_admitted(&harness.path).await);
    }

    // The next one is shed. Accepts are FIFO, so the three above are already
    // charged by the time this one reaches admission.
    connect_expecting_shed(&harness.path).await;
    // Repeatedly, and without the listener degrading: a flood is refused for as
    // long as it lasts rather than knocking the accept loop over.
    for _ in 0..20 {
        connect_expecting_shed(&harness.path).await;
    }

    // Releasing one returns exactly one slot's worth of capacity.
    drop(held.pop());
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    drop(held);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_saturated_peer_uid_is_shed_while_the_global_pool_still_has_room() {
    // The test process has one UID, so this proves the *quota* half live: the
    // global ceiling is four times the per-UID quota and cannot be what refuses
    // the third connection. The fair-share half — a second UID still being
    // served — is a different-UID case a single-uid process cannot produce and
    // is pinned in the unit suite against the same accounting.
    const PER_UID: usize = 2;
    let harness = Harness::start(
        "peruid",
        WorkloadApiAdmissionConfig {
            max_connections: PER_UID * 4,
            max_connections_per_uid: PER_UID,
            ..limits()
        },
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..PER_UID {
        held.push(connect_admitted(&harness.path).await);
    }
    connect_expecting_shed(&harness.path).await;

    drop(held.pop());
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    drop(held);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn the_configured_stream_ceiling_is_advertised_on_the_wire() {
    // Read off a real HTTP/2 handshake rather than inferred from behaviour: a
    // conforming client obeys SETTINGS, so an unadvertised ceiling would be
    // invisible to every gRPC-level assertion while leaving the server
    // unbounded against a client that does not.
    const STREAMS: u32 = 7;
    let harness = Harness::start(
        "settings",
        WorkloadApiAdmissionConfig {
            max_concurrent_streams: STREAMS,
            ..limits()
        },
    )
    .await;

    let mut stream = UnixStream::connect(&harness.path)
        .await
        .expect("the socket accepts a connection");
    stream
        .write_all(H2_PREFACE)
        .await
        .expect("the client preface is written");

    let settings = read_max_concurrent_streams(&mut stream);
    let advertised = tokio::time::timeout(Duration::from_secs(10), settings)
        .await
        .expect("the server sends its SETTINGS frame promptly");
    assert_eq!(
        advertised,
        Some(STREAMS),
        "SETTINGS_MAX_CONCURRENT_STREAMS must carry the configured ceiling"
    );

    drop(stream);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

/// Read HTTP/2 frames until the peer's SETTINGS frame, and return its
/// `SETTINGS_MAX_CONCURRENT_STREAMS` (identifier `0x3`) if it carries one.
async fn read_max_concurrent_streams(stream: &mut UnixStream) -> Option<u32> {
    loop {
        let frame = read_frame(stream).await;
        // Type 0x4 is SETTINGS; the ACK flag marks the peer's answer to ours
        // rather than its own parameters.
        if frame.frame_type == H2_SETTINGS && (frame.flags & H2_ACK) == 0 {
            return settings_max_concurrent_streams(&frame.payload);
        }
    }
}

fn settings_max_concurrent_streams(payload: &[u8]) -> Option<u32> {
    for entry in payload.chunks_exact(6) {
        if u16::from_be_bytes([entry[0], entry[1]]) == 0x3 {
            return Some(u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Raw HTTP/2 frame helpers
//
// A conforming client obeys `SETTINGS_MAX_CONCURRENT_STREAMS` and simply queues
// its extra requests locally, so the *server's* enforcement of that ceiling is
// unreachable through any real gRPC client. Reaching it needs a client that
// deliberately ignores the advertised value, which is what these frames are.
// ---------------------------------------------------------------------------

const H2_HEADERS: u8 = 0x1;
const H2_RST_STREAM: u8 = 0x3;
const H2_SETTINGS: u8 = 0x4;
const H2_GOAWAY: u8 = 0x7;
const H2_ACK: u8 = 0x1;
const H2_END_HEADERS: u8 = 0x4;
/// `REFUSED_STREAM`, the error code RFC 9113 §5.1.2 defines for a stream opened
/// past the advertised concurrency limit.
const H2_REFUSED_STREAM: u32 = 0x7;
/// `ENHANCE_YOUR_CALM` — the only other code RFC 9113 §5.1.2 sanctions for
/// excess-stream enforcement, and then only at connection level.
const H2_ENHANCE_YOUR_CALM: u32 = 0xb;

/// What the server answered a stream opened past the advertised ceiling with.
#[derive(Debug)]
enum ExcessStreamRefusal {
    /// `RST_STREAM` on the excess stream itself, carrying its error code.
    ResetStream(u32),
    /// A connection-level `GOAWAY`: its error code and last-stream-id.
    GoAway {
        error_code: u32,
        last_stream_id: u32,
    },
}

struct H2Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut frame = Vec::with_capacity(9 + length);
    frame.push((length >> 16) as u8);
    frame.push((length >> 8) as u8);
    frame.push(length as u8);
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn read_frame(stream: &mut UnixStream) -> H2Frame {
    let mut header = [0u8; 9];
    stream
        .read_exact(&mut header)
        .await
        .expect("the server sends well-formed HTTP/2 frames");
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let mut payload = vec![0u8; length];
    if length > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .expect("a frame's payload follows its header");
    }
    H2Frame {
        frame_type: header[3],
        flags: header[4],
        // The reserved high bit is masked off, per RFC 9113 §4.1.
        stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
        payload,
    }
}

/// An HPACK indexed header field (RFC 7541 §6.1) from the static table.
fn hpack_indexed(index: u8) -> Vec<u8> {
    vec![0x80 | index]
}

/// An HPACK literal header field **without** indexing, indexed name
/// (RFC 7541 §6.2.2), with a raw (non-Huffman) value.
///
/// Without indexing on purpose: nothing here needs a dynamic-table entry, and
/// not creating one keeps the encoder stateless and the bytes auditable.
fn hpack_literal(name_index: u8, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if name_index < 15 {
        out.push(name_index);
    } else {
        // 4-bit prefix saturated, then the remainder as a one-octet varint.
        out.push(0x0f);
        assert!(name_index - 15 < 128, "index needs a multi-octet varint");
        out.push(name_index - 15);
    }
    assert!(value.len() < 128, "value needs a multi-octet length varint");
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
}

/// An HPACK literal header field without indexing, **new** name, raw strings.
fn hpack_literal_new_name(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x00];
    assert!(
        name.len() < 128 && value.len() < 128,
        "lengths stay one octet"
    );
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
}

/// A gRPC request header block for `FetchX509SVID`.
///
/// Static-table indices: 3 = `:method: POST`, 6 = `:scheme: http`, 4 = `:path`,
/// 1 = `:authority`, 31 = `content-type`.
fn grpc_request_header_block() -> Vec<u8> {
    let mut block = hpack_indexed(3);
    block.extend(hpack_indexed(6));
    block.extend(hpack_literal(4, "/SpiffeWorkloadAPI/FetchX509SVID"));
    block.extend(hpack_literal(1, "localhost"));
    block.extend(hpack_literal(31, "application/grpc"));
    block.extend(hpack_literal_new_name("te", "trailers"));
    block
}

#[tokio::test]
async fn a_stream_past_the_advertised_ceiling_is_refused_at_the_protocol_level() {
    // The complement to the SETTINGS assertion above. Advertising a ceiling is
    // only half of a bound: a peer that ignores `SETTINGS_MAX_CONCURRENT_STREAMS`
    // has to be *refused*, or the advertised value protects nobody but the
    // well-behaved. This client ignores it deliberately — no real gRPC client
    // can, because a conforming HTTP/2 client queues its extra requests locally
    // rather than putting them on the wire.
    let harness = Harness::start(
        "streamcap",
        WorkloadApiAdmissionConfig {
            max_concurrent_streams: 1,
            ..limits()
        },
    )
    .await;

    let mut stream = UnixStream::connect(&harness.path)
        .await
        .expect("the socket accepts a connection");
    stream
        .write_all(H2_PREFACE)
        .await
        .expect("the client preface and SETTINGS are written");

    // The server's ceiling takes effect once its SETTINGS has been acknowledged,
    // so the ACK is sent before the streams rather than left implicit.
    let advertised = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = read_frame(&mut stream).await;
            if frame.frame_type == H2_SETTINGS && (frame.flags & H2_ACK) == 0 {
                return settings_max_concurrent_streams(&frame.payload);
            }
        }
    })
    .await
    .expect("the server sends its SETTINGS frame promptly");
    assert_eq!(advertised, Some(1));
    stream
        .write_all(&h2_frame(H2_SETTINGS, H2_ACK, 0, &[]))
        .await
        .expect("the settings acknowledgement is written");

    // Stream 1 stays open: the headers carry no END_STREAM and no request
    // message ever follows, so the server is still waiting for the body and the
    // stream is counted as active. Stream 3 is therefore one too many.
    let block = grpc_request_header_block();
    let mut streams = h2_frame(H2_HEADERS, H2_END_HEADERS, 1, &block);
    streams.extend(h2_frame(H2_HEADERS, H2_END_HEADERS, 3, &block));
    stream
        .write_all(&streams)
        .await
        .expect("both header blocks are written");

    let refusal = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = read_frame(&mut stream).await;
            match frame.frame_type {
                H2_RST_STREAM if frame.stream_id == 3 => {
                    assert_eq!(frame.payload.len(), 4, "RST_STREAM carries a 4-byte code");
                    return ExcessStreamRefusal::ResetStream(u32::from_be_bytes([
                        frame.payload[0],
                        frame.payload[1],
                        frame.payload[2],
                        frame.payload[3],
                    ]));
                }
                // A connection-level refusal is a bounded rejection too; RFC
                // 9113 §5.1.2 permits either. Its payload is parsed rather
                // than accepted on sight — see the assertions below.
                H2_GOAWAY => {
                    assert!(
                        frame.payload.len() >= 8,
                        "GOAWAY carries a 4-byte last-stream-id and a 4-byte error code"
                    );
                    return ExcessStreamRefusal::GoAway {
                        // The reserved high bit of the last-stream-id is
                        // masked off, per RFC 9113 §6.8.
                        last_stream_id: u32::from_be_bytes([
                            frame.payload[0],
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                        ]) & 0x7fff_ffff,
                        error_code: u32::from_be_bytes([
                            frame.payload[4],
                            frame.payload[5],
                            frame.payload[6],
                            frame.payload[7],
                        ]),
                    };
                }
                // Anything the server says about stream 1 (or a window update)
                // is not what is being asserted here.
                _ => continue,
            }
        }
    })
    .await
    .expect(
        "a stream opened past the advertised ceiling must be refused promptly; parking it is the \
         unbounded allocation the ceiling exists to prevent",
    );

    // The refusal has to be an RFC-appropriate *excess-stream* refusal, not
    // merely "the connection ended somehow". A `PROTOCOL_ERROR` GOAWAY is what a
    // malformed HPACK block or a bad request sequence produces, so accepting any
    // GOAWAY would let this test pass without the concurrency ceiling ever being
    // enforced.
    match refusal {
        ExcessStreamRefusal::ResetStream(code) => assert_eq!(
            code, H2_REFUSED_STREAM,
            "the excess stream must be reset with REFUSED_STREAM, which tells a conforming client \
             the request may be retried on a new stream"
        ),
        ExcessStreamRefusal::GoAway {
            error_code,
            last_stream_id,
        } => {
            // Both halves are required: the code proves it was an excess-stream
            // refusal, the last-stream-id proves it was *this* stream that was
            // refused rather than one already served.
            assert!(
                error_code == H2_REFUSED_STREAM || error_code == H2_ENHANCE_YOUR_CALM,
                "a connection-level refusal of the excess stream must carry REFUSED_STREAM (0x7) \
                 or ENHANCE_YOUR_CALM (0xb); {error_code:#x} — PROTOCOL_ERROR is 0x1 — is a \
                 generic malformed-request failure and does not prove the concurrency ceiling was \
                 enforced"
            );
            assert!(
                last_stream_id < 3,
                "the GOAWAY must declare stream 3 unprocessed (last-stream-id {last_stream_id} \
                 must be below 3); a GOAWAY that already processed it is not a refusal of the \
                 excess stream"
            );
        }
    }

    drop(stream);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn the_rpc_ceiling_sheds_rather_than_queueing_and_releases_exactly() {
    // The bound observed here is the **per-UID RPC quota**, and it says so: the
    // test process has one UID, and a fair configuration keeps that quota
    // strictly below the service-wide ceiling, so a single-UID client can never
    // reach the service-wide bound. Both halves are pinned against the same
    // accounting in the unit suite, including the fair-share property that a
    // *different* UID keeps being served — which a single-uid process cannot
    // produce through real sockets.
    let harness = Harness::start(
        "rpccap",
        WorkloadApiAdmissionConfig {
            max_concurrent_rpcs: 2,
            max_concurrent_rpcs_per_uid: 1,
            ..limits()
        },
    )
    .await;

    // A streaming RPC holds its permit for the whole stream — the producer task,
    // the rotation subscription, and the pending material all live that long.
    let mut holder = connect(&harness.path).await;
    let mut bundles = holder
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("the first RPC is admitted")
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(10), bundles.next())
        .await
        .expect("the bundle stream produces a frame")
        .expect("the bundle stream did not end")
        .expect("the bundle frame is not an error");
    assert!(
        !first.bundles.is_empty(),
        "the held RPC must be doing real work, or it is not holding a real permit"
    );

    // The next call is shed immediately — from a *second connection*, so the
    // refusal is the RPC bound rather than anything per-connection. The
    // promptness matters as much as the code: a queued identity request served
    // far too late is worse than a refusal the client can retry, and an
    // unbounded backlog is the exhaustion itself.
    let mut second = connect(&harness.path).await;
    let started = Instant::now();
    let shed = tokio::time::timeout(
        Duration::from_secs(5),
        second.fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        })),
    )
    .await
    .expect("an over-ceiling RPC must be answered, not parked behind the limit")
    .expect_err("an over-ceiling RPC must be refused");
    assert_eq!(shed.code(), tonic::Code::ResourceExhausted);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the shed must be immediate; anything else is a queue"
    );

    // Ending the streaming RPC releases the permit exactly.
    drop(bundles);
    drop(holder);
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_connection_that_never_speaks_is_closed_on_its_deadline_and_returns_its_permit() {
    // The cheapest flood shape there is, and the one no per-request timeout can
    // see. This process's own UID quota is 1, so the follow-up RPC can only
    // succeed if the silent connection's permit was actually released.
    let harness = Harness::start(
        "initial",
        WorkloadApiAdmissionConfig {
            max_connections: 2,
            max_connections_per_uid: 1,
            initial_connection_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(2),
            ..limits()
        },
    )
    .await;

    let mut silent = UnixStream::connect(&harness.path)
        .await
        .expect("the socket accepts a connection");

    // An admitted connection is handed to tonic, which may flush HTTP/2 SETTINGS
    // before the client sends anything. Keep the client silent and drain the
    // finite server bytes until EOF proves the initial-connection deadline closed
    // it — the first byte is not evidence of a half-open socket.
    const MAX_SERVER_BYTES: usize = 512;
    const READ_CHUNK: usize = 64;
    let mut total_read = 0usize;
    let mut buf = [0u8; READ_CHUNK];

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if total_read >= MAX_SERVER_BYTES {
                panic!(
                    "server sent {total_read} bytes without closing; a silent connection must be closed on its initial deadline (cap {MAX_SERVER_BYTES})"
                );
            }
            let remaining = MAX_SERVER_BYTES - total_read;
            let read_len = remaining.min(READ_CHUNK);
            let read = silent
                .read(&mut buf[..read_len])
                .await
                .expect("the close is a clean transport teardown");
            if read == 0 {
                break;
            }
            total_read += read;
        }
    })
    .await
    .expect("a connection that never sends a byte must be closed on its initial deadline");

    wait_for_service(&harness.path, Duration::from_secs(15)).await;
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_connection_that_speaks_once_and_then_goes_silent_is_closed_on_its_idle_deadline() {
    // The *post-first-read* branch, which the never-spoke test above cannot
    // reach: once a byte has been read the initial deadline no longer applies,
    // and only the idle deadline can end the connection.
    //
    // The shape is a peer that writes a **truncated** HTTP/2 preface and then
    // stops. That is deliberate rather than incidental: a peer that completes
    // the handshake and then goes quiet is closed by HTTP/2's own keepalive
    // first (the interval is derived from the idle deadline, so an unanswered
    // PING always expires earlier), so the transport deadline would never be
    // what was observed. With the handshake never finished there is no HTTP/2
    // connection to ping, and the transport-level idle deadline is the only
    // thing standing between this peer and an indefinitely held slot.
    const INITIAL_SECS: u64 = 1;
    const IDLE_SECS: u64 = 4;
    let harness = Harness::start(
        "idle",
        WorkloadApiAdmissionConfig {
            max_connections: 2,
            max_connections_per_uid: 1,
            initial_connection_timeout: Duration::from_secs(INITIAL_SECS),
            idle_timeout: Duration::from_secs(IDLE_SECS),
            ..limits()
        },
    )
    .await;

    let mut speaks_once = UnixStream::connect(&harness.path)
        .await
        .expect("the socket accepts a connection");
    let started = Instant::now();
    speaks_once
        .write_all(&H2_PREFACE[..12])
        .await
        .expect("a truncated preface is written");

    // Drain whatever the server flushes and wait for the close, exactly as the
    // never-spoke test does: the first byte is not evidence of a half-open
    // socket, EOF is.
    const MAX_SERVER_BYTES: usize = 512;
    const READ_CHUNK: usize = 64;
    let mut total_read = 0usize;
    let mut buf = [0u8; READ_CHUNK];
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if total_read >= MAX_SERVER_BYTES {
                panic!(
                    "server sent {total_read} bytes without closing; a connection idle since its \
                     first byte must be closed on the idle deadline (cap {MAX_SERVER_BYTES})"
                );
            }
            let remaining = MAX_SERVER_BYTES - total_read;
            let read_len = remaining.min(READ_CHUNK);
            let read = speaks_once
                .read(&mut buf[..read_len])
                .await
                .expect("the close is a clean transport teardown");
            if read == 0 {
                break;
            }
            total_read += read;
        }
    })
    .await
    .expect("a connection that stops speaking must be closed on its idle deadline");
    let elapsed = started.elapsed();

    // The discriminator between the two branches, and the whole point of this
    // test: a peer that has spoken must get the *idle* budget. Being closed on
    // the initial deadline instead would land at roughly one second, so the
    // threshold sits comfortably above it and comfortably below the idle
    // deadline, leaving both directions unambiguous on a slow runner.
    assert!(
        elapsed >= Duration::from_secs(2),
        "a connection that has already been read from must be judged against the idle deadline \
         ({IDLE_SECS}s), not the initial one ({INITIAL_SECS}s); it closed after {elapsed:?}"
    );

    wait_for_service(&harness.path, Duration::from_secs(15)).await;
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_keepalive_refreshed_svid_stream_outlives_the_idle_deadline_and_still_rotates() {
    // The complement, and the property the idle deadline would otherwise break:
    // a Workload API client is *designed* to hold `FetchX509SVID` open across
    // rotations, so it is application-idle for as long as nothing rotates. If
    // the deadline counted application traffic, that healthy client would be
    // closed on a timer and every workload on the node would churn its
    // identity stream.
    //
    // What keeps it alive is that the deadline counts bytes **read from the
    // peer**, and the HTTP/2 keepalive interval is derived from the deadline
    // (a third of it): the server pings, a live peer ACKs, and the ACK is a
    // read. Nothing here writes application traffic — the client sends its
    // request and then does nothing at all — so surviving past the deadline can
    // only be the keepalive relationship holding.
    const IDLE_SECS: u64 = 4;
    let harness = Harness::start(
        "keepalive",
        WorkloadApiAdmissionConfig {
            initial_connection_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(IDLE_SECS),
            ..limits()
        },
    )
    .await;
    assert!(
        harness.listener.socket_path().exists(),
        "the listener is serving before the idle window opens"
    );

    let mut client = connect(&harness.path).await;
    let mut svids = client
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("the long-lived SVID stream is established")
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(10), svids.next())
        .await
        .expect("the SVID stream produces its first frame")
        .expect("the SVID stream did not end")
        .expect("the first frame is not an error");
    assert_eq!(first.svids.len(), 1);

    // Application-idle well past the deadline. Half again the idle window, so a
    // regression that closed the stream on the deadline cannot be explained by
    // runner slowness in either direction.
    let idle_started = Instant::now();
    tokio::time::sleep(Duration::from_secs(IDLE_SECS + IDLE_SECS / 2)).await;
    assert!(
        idle_started.elapsed() > Duration::from_secs(IDLE_SECS),
        "the stream must actually have been idle past the deadline for this to prove anything"
    );

    // Still live, and still doing its job: a rotation published after the idle
    // deadline elapsed is delivered on the same stream.
    harness
        .rotation_signal
        .send_modify(|revision| *revision += 1);
    let rotated = tokio::time::timeout(Duration::from_secs(15), svids.next())
        .await
        .expect(
            "a keepalive-refreshed SVID stream must survive past the idle deadline; closing it \
             would churn the identity stream of every healthy workload on the node",
        )
        .expect("the SVID stream did not end")
        .expect("the rotated frame is not an error");
    assert_eq!(rotated.svids.len(), 1);
    assert_eq!(rotated.svids[0].spiffe_id, workload_id().as_str());
    assert!(
        !rotated.svids[0].x509_svid.is_empty() && !rotated.svids[0].x509_svid_key.is_empty(),
        "the rotation delivers real material, not an empty frame"
    );

    drop(svids);
    drop(client);
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_client_disconnect_returns_its_connection_permit() {
    let harness = Harness::start(
        "release",
        WorkloadApiAdmissionConfig {
            max_connections: 2,
            max_connections_per_uid: 1,
            ..limits()
        },
    )
    .await;

    {
        let mut client = connect(&harness.path).await;
        client
            .fetch_x509svid(workload_request(X509svidRequest {}))
            .await
            .expect("the only permitted connection is served normally");
    }

    // This UID's quota was full while that client existed; it can only be served now if
    // the permit followed the connection object rather than any one code path.
    wait_for_service(&harness.path, Duration::from_secs(15)).await;
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn shutdown_is_bounded_while_clients_hold_idle_partial_and_long_lived_connections() {
    // All three shapes at once, because each defeats a different half-measure: a
    // purely graceful drain waits forever on the idle socket and the half-open
    // HTTP/2 session, and the long-lived stream is what a Workload API client is
    // *designed* to hold across rotations.
    let grace = Duration::from_secs(1);
    let harness = Harness::start(
        "drain",
        WorkloadApiAdmissionConfig {
            shutdown_grace: grace,
            ..limits()
        },
    )
    .await;

    let _idle = UnixStream::connect(&harness.path)
        .await
        .expect("an idle socket connects");

    let mut partial = UnixStream::connect(&harness.path)
        .await
        .expect("a partial HTTP/2 session connects");
    partial
        .write_all(&H2_PREFACE[..12])
        .await
        .expect("a truncated preface is written");

    let mut streaming = connect(&harness.path).await;
    let _svids = streaming
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("a long-lived SVID stream is established")
        .into_inner();

    // Generous enough that a real regression is unambiguous, tight enough that
    // an unbounded drain cannot pass: grace + the force-close settle window is
    // 6s, so 25s of budget is failure only if shutdown does not terminate.
    let elapsed = harness.shutdown_within(Duration::from_secs(25)).await;
    assert!(
        elapsed < Duration::from_secs(20),
        "shutdown must be bounded by the drain deadline plus the settle window, took {elapsed:?}"
    );
}

#[tokio::test]
async fn normal_identity_service_is_unchanged_under_tight_limits() {
    // Every limit in force, none of them binding: attestation, X.509-SVID
    // issuance, rotation republication on an open stream, JWT-SVID mint and
    // validate, bundle streaming, and socket cleanup must all behave exactly as
    // they do without the admission boundary.
    let harness = Harness::start(
        "normal",
        WorkloadApiAdmissionConfig {
            max_connections: 4,
            max_connections_per_uid: 3,
            max_concurrent_streams: 8,
            max_concurrent_rpcs: 8,
            max_concurrent_rpcs_per_uid: 7,
            shutdown_grace: Duration::from_secs(5),
            ..limits()
        },
    )
    .await;
    let mut client = connect(&harness.path).await;

    // X.509-SVID for the attested identity — never a caller-selected subject.
    let mut svids = client
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("FetchX509SVID succeeds")
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(10), svids.next())
        .await
        .expect("the SVID stream produces a frame")
        .expect("the SVID stream did not end")
        .expect("the SVID frame is not an error");
    assert_eq!(first.svids.len(), 1);
    assert_eq!(first.svids[0].spiffe_id, workload_id().as_str());
    assert!(
        !first.svids[0].x509_svid.is_empty() && !first.svids[0].x509_svid_key.is_empty(),
        "a real leaf and its private key are delivered under the limits"
    );

    // Rotation still republishes on the already-open stream.
    harness
        .rotation_signal
        .send_modify(|revision| *revision += 1);
    let rotated = tokio::time::timeout(Duration::from_secs(10), svids.next())
        .await
        .expect("rotation republishes on the open stream")
        .expect("the SVID stream did not end")
        .expect("the rotated frame is not an error");
    assert_eq!(rotated.svids.len(), 1);

    // JWT mint and round-trip validation.
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds")
        .into_inner();
    assert_eq!(minted.svids.len(), 1);
    let token = minted.svids[0].svid.clone();
    let validated = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: token,
        }))
        .await
        .expect("ValidateJWTSVID succeeds")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // Bundle streaming.
    let mut bundles = client
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("FetchX509Bundles succeeds")
        .into_inner();
    let bundle = tokio::time::timeout(Duration::from_secs(10), bundles.next())
        .await
        .expect("the bundle stream produces a frame")
        .expect("the bundle stream did not end")
        .expect("the bundle frame is not an error");
    assert!(
        bundle.bundles.contains_key(TRUST_DOMAIN),
        "the local trust domain's X.509 bundle is published under the limits"
    );

    // An unentitled subject is still refused: the ceilings did not become a
    // substitute for the entitlement check.
    let denied = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: format!("spiffe://{TRUST_DOMAIN}/ns/other/sa/victim"),
        }))
        .await
        .expect_err("an unentitled subject must still be refused");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    drop(svids);
    drop(bundles);
    drop(client);
    // Socket inode cleanup is asserted inside `shutdown_within`.
    harness.shutdown_within(Duration::from_secs(30)).await;
}

#[tokio::test]
async fn the_exported_admission_metrics_stay_fixed_cardinality() {
    // Drive at least one rejection so the families are actually rendered, then
    // assert every `reason` value present belongs to the closed compile-time
    // set. Nothing peer-controlled — UID, PID, SPIFFE ID, token material — may
    // reach a label: each is both an unbounded cardinality dimension and a
    // disclosure surface.
    let harness = Harness::start(
        "metrics",
        WorkloadApiAdmissionConfig {
            max_connections: 2,
            max_connections_per_uid: 1,
            ..limits()
        },
    )
    .await;
    let _held = connect_admitted(&harness.path).await;
    connect_expecting_shed(&harness.path).await;
    // This family is conditional, so make its HELP/sample deterministic for the
    // contract assertions below instead of depending on another concurrent test
    // having already driven the service-wide RPC ceiling.
    ferrum_edge::plugins::mesh::prometheus_helpers::increment_workload_api_rpc_rejected();
    ferrum_edge::plugins::mesh::prometheus_helpers::increment_workload_api_connection_rejected(
        "attacker_controlled_reason",
    );

    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);
    assert!(
        !rendered.contains("attacker_controlled_reason"),
        "an unexpected reason must be dropped rather than creating a metric series"
    );

    let allowed_reject = [
        reject_reason::PEER_CREDENTIALS,
        reject_reason::MAX_CONNECTIONS,
        reject_reason::MAX_CONNECTIONS_PER_UID,
        reject_reason::SHUTTING_DOWN,
    ];
    let allowed_close = [
        close_reason::INITIAL_TIMEOUT,
        close_reason::IDLE_TIMEOUT,
        close_reason::SHUTDOWN_DEADLINE,
    ];

    let mut saw_rejection_series = false;
    for line in rendered.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(reason) = metric_reason(line, REJECTED_FAMILY) {
            saw_rejection_series = true;
            assert!(
                allowed_reject.contains(&reason.as_str()),
                "an unexpected rejection reason label appeared: {reason}"
            );
        }
        if let Some(reason) = metric_reason(line, CLOSED_FAMILY) {
            assert!(
                allowed_close.contains(&reason.as_str()),
                "an unexpected close reason label appeared: {reason}"
            );
        }
        // The gauges and the RPC-shed counter carry no per-caller dimension at
        // all, so any `reason`/`uid`/`pid` on them would be a regression.
        for family in [
            "ferrum_mesh_workload_api_active_connections",
            "ferrum_mesh_workload_api_active_rpcs",
            "ferrum_mesh_workload_api_rpcs_rejected_total",
        ] {
            if line.starts_with(family) {
                assert!(
                    !line.contains("reason=")
                        && !line.contains("uid=")
                        && !line.contains("pid=")
                        && !line.contains("spiffe"),
                    "{family} must carry no per-caller label: {line}"
                );
            }
        }
    }
    assert!(
        saw_rejection_series,
        "the rejection counter must be exported once a connection has been shed"
    );

    // The issue asks for stream observability, and the honest answer is a
    // *one-way* relationship: every admitted RPC is one HTTP/2 stream, but not
    // every live stream is an admitted RPC. The help text has to state the
    // limitation rather than the converse, or an operator reading `/metrics`
    // will take `active_rpcs` for the live stream count and a shed RPC for a
    // protocol-level stream refusal — neither of which is true.
    for (family, expected) in [
        (
            "# HELP ferrum_mesh_workload_api_active_rpcs",
            "service-dispatched RPC streams only",
        ),
        (
            "# HELP ferrum_mesh_workload_api_rpcs_rejected_total",
            "not a protocol-level stream refusal",
        ),
    ] {
        let line = rendered
            .lines()
            .find(|line| line.starts_with(family))
            .unwrap_or_else(|| panic!("{family} must be rendered for its contract assertion"));
        assert!(
            line.contains(expected),
            "{family} must state the one-way relationship to HTTP/2 streams: {line}"
        );
    }
    // And the converse claim must not creep back in.
    for line in rendered
        .lines()
        .filter(|line| line.starts_with("# HELP ferrum_mesh_workload_api_"))
    {
        assert!(
            !line.contains("live admitted-stream count") && !line.contains("refused HTTP/2 stream"),
            "no Workload API help text may claim that every live HTTP/2 stream is an admitted \
             RPC, or that a shed RPC is a protocol-level stream refusal: {line}"
        );
    }

    harness.shutdown_within(Duration::from_secs(30)).await;
}

/// The hosted-Linux flood gate.
///
/// This is the "run a flood from an authorized socket-group process" check the
/// issue asks for, in the form a hosted runner can actually make: the test
/// process *is* an authorized socket-group member (it owns the socket), so a
/// sustained connection flood from it is exactly the hostile shape. What it
/// pins is that the flood costs the server nothing that accumulates —
/// descriptors return to their baseline, identity service continues for the
/// peers inside the pool, and shutdown stays bounded afterwards.
///
/// What it deliberately does **not** claim: the flood saturates this process's
/// own per-UID quota, not the global ceiling — under strict fair share a single
/// UID cannot reach the global ceiling at all — and the "an independent peer UID
/// keeps being served" half needs a second UID, which an unprivileged CI process
/// cannot create. Both properties are pinned against the same accounting in
/// `tests/unit/identity/workload_api_admission_tests.rs`, including under a
/// concurrent burst.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_sustained_connection_flood_leaves_descriptors_and_shutdown_bounded() {
    const TOTAL: usize = 4;
    let harness = Harness::start(
        "flood",
        WorkloadApiAdmissionConfig {
            max_connections: TOTAL + 1,
            max_connections_per_uid: TOTAL,
            shutdown_grace: Duration::from_secs(1),
            ..limits()
        },
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..TOTAL {
        held.push(connect_admitted(&harness.path).await);
    }
    let baseline = open_descriptors();

    for _ in 0..200 {
        connect_expecting_shed(&harness.path).await;
    }

    let after = open_descriptors();
    assert!(
        after <= baseline + 16,
        "a 200-connection flood must not accumulate descriptors: {baseline} -> {after}"
    );

    // Identity service is still available to a peer inside the pool.
    drop(held.pop());
    wait_for_service(&harness.path, Duration::from_secs(15)).await;

    let elapsed = harness.shutdown_within(Duration::from_secs(25)).await;
    assert!(
        elapsed < Duration::from_secs(20),
        "shutdown must stay bounded after a flood, took {elapsed:?}"
    );
    drop(held);
}

/// Descriptors this process currently holds.
#[cfg(target_os = "linux")]
fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// The `reason` label of `line` when it belongs to `family`.
fn metric_reason(line: &str, family: &str) -> Option<String> {
    let rest = line.strip_prefix(family)?.strip_prefix("{reason=\"")?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[tokio::test]
async fn a_fatal_accept_terminates_the_listener_within_its_bounded_drain() {
    // The failure this pins is a *lifecycle* one, and it is invisible to the
    // accept-retry policy the unit suite exercises. A fatal accept used to end
    // the incoming stream and nothing else — but under
    // `serve_with_incoming_shutdown`, tonic reads any end of input as a
    // *graceful* shutdown and then waits for every established connection. A
    // Workload API rotation stream is designed to stay open indefinitely, so the
    // serve future never completed, the exit guard never published termination,
    // the socket was never cleaned up, and mesh mode went on serving traffic
    // with no identity surface behind it.
    //
    // The seam is the fatal-accept channel itself — the exact channel the accept
    // loop publishes on — because a real fatal `accept(2)` cannot be provoked
    // from a test. Nothing here sleeps or polls for the outcome: the trigger is
    // a channel publication and the wait is on the termination watch channel.
    const GRACE: Duration = Duration::from_secs(1);
    let harness = Harness::start(
        "fatalacc",
        WorkloadApiAdmissionConfig {
            shutdown_grace: GRACE,
            ..limits()
        },
    )
    .await;

    // An established, deliberately long-lived rotation stream: exactly the shape
    // a purely graceful drain waits on forever.
    let mut client = connect(&harness.path).await;
    let mut rotation = client
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("the long-lived rotation stream is admitted")
        .into_inner();
    tokio::time::timeout(Duration::from_secs(10), rotation.next())
        .await
        .expect("the rotation stream responds promptly")
        .expect("the rotation stream yields its first response")
        .expect("the first rotation response is not an error");

    let mut terminated = harness.listener.termination_signal();
    assert!(
        !*terminated.borrow(),
        "the listener must still be serving before the fatal accept, or this test proves nothing"
    );

    harness.listener.fatal_accept_signal().raise();

    // The configured graceful budget, plus the fixed post-force-close settle,
    // plus generous runner margin. The point is that the wait terminates at all
    // — an unbounded drain would sit here until the timeout.
    let budget = GRACE + Duration::from_secs(5) + Duration::from_secs(25);
    tokio::time::timeout(budget, async {
        while !*terminated.borrow() {
            if terminated.changed().await.is_err() {
                return;
            }
        }
    })
    .await
    .expect(
        "a fatal accept must reach the bounded drain and publish termination; waiting out an \
         established rotation stream is the unbounded hang this path exists to prevent",
    );
    assert!(
        *terminated.borrow(),
        "termination must be published as `true`, not merely inferred from a closed channel"
    );

    // The exit guard runs the identity-checked socket cleanup *before* it
    // publishes termination, so by here the artifact must be gone.
    assert!(
        !harness.path.exists(),
        "the fatal-accept drain must still unlink the socket Ferrum created"
    );

    drop(rotation);
    drop(client);
}
