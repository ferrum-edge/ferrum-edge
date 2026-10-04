//! Capability-probe vs request-time gRPC establishment logging (issue #3923).
//!
//! An ordinary HTTP/1.1 origin failing the startup/reload h2c probe must stay
//! quiet at the documented default `warn` level. Live gRPC failures, timeouts,
//! TLS failures, and port exhaustion must remain WARN/ERROR.

use async_trait::async_trait;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::pool::{CoalescedCreateAttempt, GenericPool, PoolManager};
use ferrum_edge::proxy::grpc_proxy::{
    GrpcBackendUnavailableKind, GrpcEstablishmentLogLevel, GrpcEstablishmentPurpose,
    GrpcProxyError, GrpcTimeoutKind, grpc_establishment_failure_log_level,
    log_grpc_coalesced_establishment_failure, note_grpc_establishment_join,
    note_grpc_establishment_waiter_failure, upgrade_grpc_coalesced_establishment_log,
};
use std::io::{Error as IoError, ErrorKind, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tracing_subscriber::fmt::MakeWriter;

fn h2c_handshake_miss() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::H2cHandshake,
        "h2c handshake failed: http2 error".into(),
    )
}

fn connect_refused() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable_with_source(
        GrpcBackendUnavailableKind::Connect,
        "Connection failed: connection refused".into(),
        IoError::new(ErrorKind::ConnectionRefused, "connection refused"),
    )
}

fn tls_handshake_fail() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::TlsHandshake,
        "TLS handshake failed: invalid peer certificate".into(),
    )
}

fn dns_fail() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::DnsResolution,
        "DNS resolution failed for backend.example: lookup failed".into(),
    )
}

fn connect_timeout() -> GrpcProxyError {
    GrpcProxyError::BackendTimeout {
        kind: GrpcTimeoutKind::Connect,
        message: "Connect timeout after 100ms establishing gRPC HTTP/2 to 127.0.0.1:18081".into(),
    }
}

fn port_exhaustion() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable_with_source(
        GrpcBackendUnavailableKind::Connect,
        "Connection failed: address not available".into(),
        IoError::from_raw_os_error(99),
    )
}

#[test]
fn expected_h2c_capability_miss_is_debug_not_warn() {
    assert_eq!(
        grpc_establishment_failure_log_level(
            GrpcEstablishmentPurpose::CapabilityProbe,
            &h2c_handshake_miss(),
        ),
        GrpcEstablishmentLogLevel::Debug,
        "ordinary HTTP/1.1 classification must not WARN at default log level"
    );
}

#[test]
fn request_time_h2c_handshake_failure_stays_warn() {
    assert_eq!(
        grpc_establishment_failure_log_level(
            GrpcEstablishmentPurpose::Request,
            &h2c_handshake_miss(),
        ),
        GrpcEstablishmentLogLevel::Warn,
        "live gRPC h2c establishment failures must remain actionable"
    );
}

#[test]
fn unexpected_probe_failures_stay_warn() {
    for (label, error) in [
        ("connect", connect_refused()),
        ("tls", tls_handshake_fail()),
        ("dns", dns_fail()),
        ("timeout", connect_timeout()),
    ] {
        assert_eq!(
            grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::CapabilityProbe, &error,),
            GrpcEstablishmentLogLevel::Warn,
            "{label} during a capability probe must stay WARN"
        );
        assert_eq!(
            grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::Request, &error),
            GrpcEstablishmentLogLevel::Warn,
            "{label} during request-time gRPC must stay WARN"
        );
    }
}

#[test]
fn port_exhaustion_is_error_for_probe_and_request() {
    let error = port_exhaustion();
    assert_eq!(
        grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::CapabilityProbe, &error),
        GrpcEstablishmentLogLevel::Error,
    );
    assert_eq!(
        grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::Request, &error),
        GrpcEstablishmentLogLevel::Error,
    );
}

#[test]
fn probe_h2c_threads_capability_probe_purpose_not_request_get_sender() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let probe = source
        .split("async fn probe_h2c(")
        .nth(1)
        .expect("probe_h2c")
        .split("async fn probe_h2_tls(")
        .next()
        .expect("bounded probe_h2c body");
    assert!(
        probe.contains("get_sender_for_capability_probe(probe_proxy)"),
        "h2c capability probes must carry probe purpose into the gRPC pool"
    );
    assert!(
        !probe.contains("grpc_pool.get_sender(probe_proxy)"),
        "request-time get_sender would WARN on expected HTTP/1.1 misses"
    );
}

#[test]
fn request_time_get_sender_keeps_request_purpose() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let get_sender = source
        .split("pub async fn get_sender(")
        .nth(1)
        .expect("get_sender")
        .split("pub async fn get_sender_for_capability_probe(")
        .next()
        .expect("bounded get_sender");
    assert!(
        get_sender.contains("GrpcEstablishmentPurpose::Request"),
        "live gRPC dispatch must keep request-time establishment logging"
    );
    assert!(
        !get_sender.contains("CapabilityProbe"),
        "request-time get_sender must not inherit probe quieting"
    );
}

#[test]
fn establishment_logger_is_not_a_blanket_warn_downgrade() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let create = source
        .split("async fn create_connection(")
        .nth(1)
        .expect("create_connection")
        .split("fn build_h2_builder(")
        .next()
        .expect("bounded create_connection");
    assert!(
        create.contains("purpose: GrpcEstablishmentPurpose"),
        "create_connection must receive explicit probe vs request context"
    );
    assert!(
        create.contains("attempt: Option<CoalescedCreateAttempt>"),
        "create_connection must share the coalesced attempt with waiters"
    );
    assert!(
        create.contains("log_grpc_coalesced_establishment_failure("),
        "coalesced creates must log through the attempt-ranked logger"
    );
    assert!(
        create.contains("log_grpc_protocol_establishment_failure("),
        "Failed establishment must go through the purpose-aware logger"
    );
    assert!(
        create.contains("&source"),
        "the logger must receive the typed establishment error, not a formatted secret"
    );
    assert!(
        create.contains("protocol establishment budget exhausted"),
        "timeouts must keep their dedicated WARN diagnostic"
    );
    assert!(
        create.contains("warn!"),
        "timeouts must still emit WARN rather than being folded into debug"
    );

    let classifier = source
        .split("pub fn grpc_establishment_failure_log_level(")
        .nth(1)
        .expect("classifier")
        .split("pub fn log_grpc_protocol_establishment_failure(")
        .next()
        .expect("bounded classifier");
    assert!(
        classifier.contains("GrpcBackendUnavailableKind::H2cHandshake"),
        "only the expected h2c classification miss is quieted"
    );
    assert!(
        classifier.contains("is_port_exhaustion(error)"),
        "port exhaustion must stay ERROR even during probes"
    );
}

#[test]
fn establishment_failure_messages_name_only_host_and_address() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let logger = source
        .split("pub fn log_grpc_protocol_establishment_failure(")
        .nth(1)
        .expect("logger")
        .split("/// Which phase of a gRPC backend interaction timed out.")
        .next()
        .expect("bounded logger");
    assert!(
        logger.contains("last={}"),
        "quiet and warn lines must name the last candidate address"
    );
    assert!(
        logger.contains("for backend {}"),
        "lines must name the backend host only"
    );
    assert!(
        logger.contains("host, last_addr, error"),
        "debug/warn interpolations must be host + address + error"
    );
    assert!(
        !logger.contains("authorization"),
        "establishment logs must not interpolate credential headers"
    );
    assert!(
        !logger.contains("cookie"),
        "establishment logs must not interpolate cookies"
    );
}

#[test]
fn get_sender_with_purpose_joins_coalesced_attempt_for_probe_and_request() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let with_purpose = source
        .split("async fn get_sender_with_purpose(")
        .nth(1)
        .expect("get_sender_with_purpose")
        .split("async fn get_sender_with_purpose_unprofiled(")
        .next()
        .expect("bounded get_sender_with_purpose");
    assert!(
        with_purpose.contains("self.get_sender_with_purpose_unprofiled(proxy, purpose)"),
        "the profiled wrapper must preserve purpose when delegating"
    );

    let unprofiled = source
        .split("async fn get_sender_with_purpose_unprofiled(")
        .nth(1)
        .expect("get_sender_with_purpose_unprofiled")
        .split("enum GrpcPhase1")
        .next()
        .expect("bounded get_sender_with_purpose_unprofiled");
    assert!(
        unprofiled.contains("create_or_get_existing_owned_with_recovery("),
        "the unprofiled path must use the shared recovery/coalescing operation"
    );
    assert!(
        unprofiled.contains("|attempt| note_grpc_establishment_join(attempt, purpose)"),
        "probe and request must join the coalesced pending attempt"
    );
    assert!(
        unprofiled
            .contains("|attempt| note_grpc_establishment_waiter_failure(attempt, purpose)"),
        "a request waiter must be able to upgrade a probe-only DEBUG"
    );
    assert!(
        unprofiled.contains("|key, attempt| async move {"),
        "the creator must receive the coalesced attempt"
    );
    assert!(
        unprofiled.contains("create_connection(proxy, svid_generation, purpose, Some(attempt))"),
        "the creator must log against the same attempt waiters joined"
    );

    let pool_source = include_str!("../../../src/pool/mod.rs");
    let coalesced_recovery = pool_source
        .split("pub(crate) async fn create_or_get_existing_owned_with_recovery<")
        .nth(1)
        .expect("create_or_get_existing_owned_with_recovery")
        .split("fn register_pending_creation(")
        .next()
        .expect("bounded create_or_get_existing_owned_with_recovery");
    assert!(
        coalesced_recovery.contains(concat!(
            "let attempt = CoalescedCreateAttempt {\n",
            "                inner: Arc::clone(&pending),\n",
            "            };"
        )),
        "joiners and the creator must derive from the registered pending entry"
    );
    assert!(
        coalesced_recovery.contains("on_join(&attempt)"),
        "join bookkeeping must receive the pending attempt identity"
    );
    assert!(
        coalesced_recovery.contains("on_waiter_failure(&attempt)"),
        "waiter failure bookkeeping must receive that pending attempt identity"
    );
    assert!(
        coalesced_recovery.contains(concat!(
            "let attempt = attempt.clone();\n",
            "                    move |key| create(key, attempt)"
        )),
        "the creator must receive a clone of the same attempt given to waiters"
    );
}

const WARN_ESTABLISH: &str = "gRPC: all DNS candidates failed protocol establishment";
const DEBUG_PROBE: &str = "gRPC capability probe: expected h2c classification miss";

#[derive(Clone, Default)]
struct CapturedLogs {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl CapturedLogs {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct CapturedLogsGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for CapturedLogsGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogsGuard;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogsGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

fn capture_debug_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    let writer = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(writer.clone())
        .finish();
    (writer, tracing::subscriber::set_default(subscriber))
}

fn count_substr(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

struct DummyPoolManager;

#[async_trait]
impl PoolManager for DummyPoolManager {
    type Connection = ();

    fn build_key(
        &self,
        _proxy: &ferrum_edge::config::types::Proxy,
        host: &str,
        port: u16,
        shard: usize,
        buf: &mut String,
    ) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(buf, "{host}|{port}|{shard}");
    }

    async fn create(
        &self,
        _key: &str,
        _proxy: &ferrum_edge::config::types::Proxy,
    ) -> anyhow::Result<Self::Connection> {
        panic!("tests must use create_or_get_existing_owned_with_attempt");
    }

    fn is_healthy(&self, _conn: &Self::Connection) -> bool {
        true
    }

    fn destroy(&self, _conn: Self::Connection) {}
}

fn test_pool() -> Arc<GenericPool<DummyPoolManager>> {
    GenericPool::new(
        Arc::new(DummyPoolManager),
        PoolConfig::default(),
        Duration::from_secs(60),
        64,
    )
}

async fn establish_h2c_miss(
    pool: &GenericPool<DummyPoolManager>,
    key: String,
    purpose: GrpcEstablishmentPurpose,
    hold: Option<(Arc<Notify>, Arc<Notify>)>,
    joined: Option<Arc<AtomicUsize>>,
) -> Result<(), GrpcProxyError> {
    pool.create_or_get_existing_owned_with_attempt(
        key,
        move |attempt| {
            note_grpc_establishment_join(attempt, purpose);
            if purpose == GrpcEstablishmentPurpose::Request
                && let Some(joined) = &joined
            {
                joined.fetch_add(1, Ordering::SeqCst);
            }
        },
        move |attempt| note_grpc_establishment_waiter_failure(attempt, purpose),
        move |_key, attempt| async move {
            if let Some((started, release)) = hold {
                started.notify_waiters();
                release.notified().await;
            }
            let err = h2c_handshake_miss();
            log_grpc_coalesced_establishment_failure(
                &attempt,
                purpose,
                "backend.example",
                "127.0.0.1:80",
                &err,
            );
            Err(err)
        },
    )
    .await
    .map(|_| ())
}

#[test]
fn request_joining_after_probe_debug_upgrades_once() {
    let (logs, _guard) = capture_debug_logs();
    let attempt = CoalescedCreateAttempt::new();
    let err = h2c_handshake_miss();
    log_grpc_coalesced_establishment_failure(
        &attempt,
        GrpcEstablishmentPurpose::CapabilityProbe,
        "backend.example",
        "127.0.0.1:80",
        &err,
    );
    let after_probe = logs.contents();
    assert_eq!(count_substr(&after_probe, DEBUG_PROBE), 1, "{after_probe}");
    assert_eq!(
        count_substr(&after_probe, WARN_ESTABLISH),
        0,
        "{after_probe}"
    );

    attempt.mark_request_participant();
    upgrade_grpc_coalesced_establishment_log(&attempt);
    upgrade_grpc_coalesced_establishment_log(&attempt);
    upgrade_grpc_coalesced_establishment_log(&attempt);

    let captured = logs.contents();
    assert_eq!(
        count_substr(&captured, DEBUG_PROBE),
        1,
        "probe DEBUG is retained; request upgrades rather than duplicating it: {captured}"
    );
    assert_eq!(
        count_substr(&captured, WARN_ESTABLISH),
        1,
        "exactly one request-severity upgrade: {captured}"
    );
}

#[test]
fn coalesced_port_exhaustion_stays_error_and_does_not_upgrade_to_warn() {
    let (logs, _guard) = capture_debug_logs();
    let attempt = CoalescedCreateAttempt::new();
    log_grpc_coalesced_establishment_failure(
        &attempt,
        GrpcEstablishmentPurpose::CapabilityProbe,
        "backend.example",
        "127.0.0.1:80",
        &port_exhaustion(),
    );
    attempt.mark_request_participant();
    upgrade_grpc_coalesced_establishment_log(&attempt);
    upgrade_grpc_coalesced_establishment_log(&attempt);
    let captured = logs.contents();
    assert_eq!(count_substr(&captured, "PORT EXHAUSTION"), 1, "{captured}");
    assert_eq!(count_substr(&captured, DEBUG_PROBE), 0, "{captured}");
    assert_eq!(count_substr(&captured, WARN_ESTABLISH), 0, "{captured}");
}

#[tokio::test(flavor = "current_thread")]
async fn probe_only_h2c_miss_stays_debug() {
    let (logs, _guard) = capture_debug_logs();
    let pool = test_pool();
    let result = establish_h2c_miss(
        &pool,
        "backend.example.com|80|0".to_string(),
        GrpcEstablishmentPurpose::CapabilityProbe,
        None,
        None,
    )
    .await;
    assert!(result.is_err());
    let captured = logs.contents();
    assert_eq!(count_substr(&captured, DEBUG_PROBE), 1, "{captured}");
    assert_eq!(count_substr(&captured, WARN_ESTABLISH), 0, "{captured}");
}

#[tokio::test(flavor = "current_thread")]
async fn request_only_h2c_miss_stays_warn() {
    let (logs, _guard) = capture_debug_logs();
    let pool = test_pool();
    let result = establish_h2c_miss(
        &pool,
        "backend.example.com|80|0".to_string(),
        GrpcEstablishmentPurpose::Request,
        None,
        None,
    )
    .await;
    assert!(result.is_err());
    let captured = logs.contents();
    assert_eq!(count_substr(&captured, WARN_ESTABLISH), 1, "{captured}");
    assert_eq!(count_substr(&captured, DEBUG_PROBE), 0, "{captured}");
}

#[tokio::test(flavor = "current_thread")]
async fn probe_creator_plus_request_waiter_logs_request_severity_once() {
    let (logs, _guard) = capture_debug_logs();
    let pool = test_pool();
    let key = "backend.example.com|80|0".to_string();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let joined = Arc::new(AtomicUsize::new(0));
    let waiter_count = 8;

    let probe = {
        let pool = pool.clone();
        let key = key.clone();
        let started = started.clone();
        let release = release.clone();
        tokio::spawn(async move {
            establish_h2c_miss(
                &pool,
                key,
                GrpcEstablishmentPurpose::CapabilityProbe,
                Some((started, release)),
                None,
            )
            .await
        })
    };

    started.notified().await;

    let mut requests = Vec::new();
    for _ in 0..waiter_count {
        let pool = pool.clone();
        let key = key.clone();
        let joined = joined.clone();
        requests.push(tokio::spawn(async move {
            establish_h2c_miss(
                &pool,
                key,
                GrpcEstablishmentPurpose::Request,
                None,
                Some(joined),
            )
            .await
        }));
    }

    let mut spins = 0usize;
    while joined.load(Ordering::SeqCst) < waiter_count {
        tokio::task::yield_now().await;
        spins += 1;
        assert!(
            spins < 10_000,
            "request waiters must join the probe creator's pending entry"
        );
    }

    release.notify_waiters();

    assert!(
        probe.await.expect("probe task").is_err(),
        "probe creator must observe the h2c miss"
    );
    for request in requests {
        assert!(
            request.await.expect("request task").is_err(),
            "coalesced request waiters must observe the shared failure"
        );
    }

    let captured = logs.contents();
    let warns = count_substr(&captured, WARN_ESTABLISH);
    let debugs = count_substr(&captured, DEBUG_PROBE);
    assert_eq!(
        warns, 1,
        "request severity must dominate once with no per-waiter storm: {captured}"
    );
    assert!(
        debugs <= 1,
        "at most one probe DEBUG before a possible single upgrade: {captured}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn request_waiter_after_probe_debug_publication_upgrades_once() {
    let (logs, _guard) = capture_debug_logs();
    let pool = test_pool();
    let key = "backend.example.com|80|1".to_string();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let logged = Arc::new(Notify::new());

    let probe = {
        let pool = pool.clone();
        let key = key.clone();
        let started = started.clone();
        let release = release.clone();
        let logged = logged.clone();
        tokio::spawn(async move {
            pool.create_or_get_existing_owned_with_attempt(
                key,
                |attempt| {
                    note_grpc_establishment_join(
                        attempt,
                        GrpcEstablishmentPurpose::CapabilityProbe,
                    );
                },
                |_| {},
                move |_key, attempt| async move {
                    started.notify_waiters();
                    release.notified().await;
                    let err = h2c_handshake_miss();
                    log_grpc_coalesced_establishment_failure(
                        &attempt,
                        GrpcEstablishmentPurpose::CapabilityProbe,
                        "backend.example",
                        "127.0.0.1:80",
                        &err,
                    );
                    logged.notify_waiters();
                    Err(err)
                },
            )
            .await
            .map(|_| ())
        })
    };

    started.notified().await;

    let request_registered = Arc::new(Notify::new());
    let request: tokio::task::JoinHandle<Result<(), GrpcProxyError>> = {
        let pool = pool.clone();
        let key = key.clone();
        let request_registered = request_registered.clone();
        tokio::spawn(async move {
            // Pin `E = GrpcProxyError`: the create closure is a never-type
            // panic (this task must stay a waiter), so rustc cannot choose
            // among ShareablePoolCreateError impls (hosted E0283).
            pool.create_or_get_existing_owned_with_attempt::<_, _, GrpcProxyError, _, _>(
                key,
                |_attempt| {
                    request_registered.notify_waiters();
                    // Intentionally do not mark at join: this models a request
                    // that attaches before failure publication but after the
                    // creator has already claimed probe-only DEBUG.
                },
                |attempt| {
                    attempt.mark_request_participant();
                    note_grpc_establishment_waiter_failure(
                        attempt,
                        GrpcEstablishmentPurpose::Request,
                    );
                },
                |_key, _attempt| async move {
                    panic!("request must remain a waiter on the probe create");
                    #[allow(unreachable_code)]
                    Err(h2c_handshake_miss())
                },
            )
            .await
            .map(|_| ())
        })
    };

    request_registered.notified().await;
    release.notify_waiters();
    logged.notified().await;

    assert!(probe.await.expect("probe task").is_err());
    assert!(request.await.expect("request task").is_err());

    let captured = logs.contents();
    assert_eq!(count_substr(&captured, DEBUG_PROBE), 1, "{captured}");
    assert_eq!(
        count_substr(&captured, WARN_ESTABLISH),
        1,
        "request joining after probe DEBUG must upgrade once: {captured}"
    );
}
