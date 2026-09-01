//! Integration tests for opt-in frontend TLS cert/key live reload
//! (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`).
//!
//! Validates that:
//! 1. The HTTPS listener reads from the shared `SharedFrontendTls` ArcSwap
//!    slot on every new accept, so swapping the slot takes effect on the
//!    next handshake without restarting the listener.
//! 2. A swap to a config bearing a different leaf certificate is observed
//!    by the next handshake (we compare the cert chain length / SAN
//!    indirectly via certificate-equality assertions on the peer-cert seen
//!    by the rustls client).
//! 3. Existing in-flight TLS sessions are NOT torn down by a swap (rustls
//!    consults the `ServerConfig` only during the handshake).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_dynamic_tls_and_signal};
use ferrum_edge::tls::NoVerifier;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::scaffolding::ports::reserve_port;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn test_env_config() -> EnvConfig {
    EnvConfig {
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        accept_threads: 1,
        frontend_tls_handshake_timeout_seconds: 2,
        ..EnvConfig::default()
    }
}

fn test_proxy_state(env: EnvConfig) -> ProxyState {
    ProxyState::new(
        GatewayConfig::default(),
        DnsCache::new(DnsConfig::default()),
        env,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

fn generate_server_config_with_san(san: &str) -> (Arc<ServerConfig>, Vec<u8>) {
    ensure_crypto_provider();
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![san.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");

    let cert_pem = cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(Result::ok)
        .collect();
    let cert_der = certs[0].as_ref().to_vec();
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("read private key")
        .expect("private key present");

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("server cert");

    (Arc::new(config), cert_der)
}

fn no_verify_client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    // Use the gateway's shared NoVerifier so peer certs are accepted
    // unconditionally. We compare cert DERs after the handshake to verify
    // the slot's current cert is being served.
    let mut cfg = cfg;
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    Arc::new(cfg)
}

async fn fetch_peer_cert_der(addr: SocketAddr) -> Vec<u8> {
    let client_config = no_verify_client_config();
    let connector = TlsConnector::from(client_config);
    let stream = TcpStream::connect(addr).await.expect("connect TCP");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");
    // Write a tiny dummy request so the server processes the connection;
    // we only care about the handshake's peer cert chain.
    let _ = tls
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    // Drain (best-effort) so the connection is fully exchanged.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(500), tls.read_to_end(&mut buf)).await;

    let (_io, conn) = tls.into_inner();
    conn.peer_certificates()
        .expect("server cert presented")
        .first()
        .expect("at least one cert")
        .as_ref()
        .to_vec()
}

async fn start_dynamic_tls_listener_with_retry(
    state: &ProxyState,
    slot: ferrum_edge::tls::SharedFrontendTls,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    JoinHandle<Result<(), anyhow::Error>>,
) {
    let mut errors = Vec::new();
    for attempt in 1..=5 {
        let reservation = reserve_port().await.expect("reserve proxy port");
        let port = reservation.drop_and_take_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener_state = state.clone();
        let listener_slot = slot.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let listener = tokio::spawn(async move {
            start_proxy_listener_with_dynamic_tls_and_signal(
                addr,
                listener_state,
                shutdown_rx,
                listener_slot,
                Some(started_tx),
            )
            .await
        });

        let start_result = tokio::time::timeout(Duration::from_secs(2), started_rx).await;
        let mut attempt_error = match start_result {
            Ok(Ok(())) => return (addr, shutdown_tx, listener),
            Ok(Err(error)) => {
                format!("attempt {attempt}: listener start signal dropped: {error}")
            }
            Err(error) => format!("attempt {attempt}: listener start timed out: {error}"),
        };

        let _ = shutdown_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(2), listener).await {
            Ok(Ok(Err(error))) => {
                attempt_error = format!("{attempt_error}; listener returned error: {error}");
            }
            Ok(Err(error)) => {
                attempt_error = format!("{attempt_error}; listener task join error: {error}");
            }
            Err(error) => {
                attempt_error = format!("{attempt_error}; listener task did not stop: {error}");
            }
            Ok(Ok(Ok(()))) => {}
        }
        errors.push(attempt_error);
    }

    panic!(
        "listener did not bind after retries: {}",
        errors.join(" | ")
    );
}

/// New TLS handshakes after an `ArcSwap` cert swap present the new
/// certificate chain. This is the load-bearing contract for opt-in frontend
/// TLS live reload — the listener reads from the slot on each accept, so a
/// successful reload flips the served cert on the very next handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_tls_listener_serves_rotated_cert_after_slot_swap() {
    ensure_crypto_provider();
    let state = test_proxy_state(test_env_config());

    let (initial_config, initial_der) = generate_server_config_with_san("localhost");
    let slot: ferrum_edge::tls::SharedFrontendTls =
        Arc::new(ArcSwap::new(Arc::new(Some(initial_config))));

    let (addr, shutdown_tx, listener) =
        start_dynamic_tls_listener_with_retry(&state, slot.clone()).await;

    let first_seen = fetch_peer_cert_der(addr).await;
    assert_eq!(
        first_seen, initial_der,
        "first handshake must present the startup-loaded cert"
    );

    // Rotate: build a fresh self-signed cert and swap the slot. The next
    // handshake should pick it up — no listener restart, no port rebind.
    let (rotated_config, rotated_der) = generate_server_config_with_san("localhost");
    assert_ne!(initial_der, rotated_der, "rotated cert must differ");
    slot.store(Arc::new(Some(rotated_config)));

    let second_seen = fetch_peer_cert_der(addr).await;
    assert_eq!(
        second_seen, rotated_der,
        "second handshake must present the rotated cert without restarting the listener"
    );

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener should stop")
        .expect("listener task should join")
        .expect("listener should return cleanly");
}

#[test]
fn repeated_tls_source_failures_record_only_transitions_but_count_every_attempt() {
    use chrono::TimeZone;
    use ferrum_edge::tls::events::{
        TlsEventFilter, TlsEventLog, TlsSourceEvent, TlsSourceEventMaterial, event_source_id,
    };
    use ferrum_edge::tls::source::subscription::{
        LoadFailureTransitionTracker, WatchedMaterialSource, record_refresh_for_sources,
    };
    use ferrum_edge::tls::source::{CertSource, MaterialKind};

    const SURFACE: &str = "issue_4435_transition_test";
    let source = CertSource::parse(
        "vault://user:password@provider/secret/path?token=credential&kind=cert",
        MaterialKind::Cert,
    );
    let watched = vec![WatchedMaterialSource::new(
        "gateway_svid_cert",
        source.clone(),
        MaterialKind::Cert,
    )];
    let raw_source_id = source.source_id();
    let expected_source_id = event_source_id(&raw_source_id);
    let cert_id = "cert-transition-test".to_string();
    let at = chrono::Utc
        .timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("fixed timestamp");
    let event = |outcome: &str, error: Option<&str>| TlsSourceEvent {
        id: 0,
        at,
        surface: SURFACE.to_string(),
        outcome: outcome.to_string(),
        sources: vec![TlsSourceEventMaterial {
            label: "gateway_svid_cert".to_string(),
            cert_id: cert_id.clone(),
            source_id: raw_source_id.clone(),
            scheme: "vault".to_string(),
            kind: "cert".to_string(),
            fingerprint_sha256: None,
        }],
        revision: None,
        error: error.map(str::to_string),
    };

    let log = TlsEventLog::new(1024);
    let mut transitions = LoadFailureTransitionTracker::default();
    for _ in 0..1_000 {
        record_refresh_for_sources(SURFACE, &watched, "load_error");
        if transitions.observe_failure("deadline_exceeded") {
            log.record(event("load_error", Some("deadline_exceeded")));
        }
    }

    let first_snapshot = log.list(&TlsEventFilter::default());
    assert_eq!(first_snapshot.len(), 1);
    assert_eq!(first_snapshot[0].sources[0].source_id, expected_source_id);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry().render_uncached();
    let counter = metrics
        .lines()
        .find(|line| {
            line.contains("surface=\"issue_4435_transition_test\"")
                && line.contains("outcome=\"load_error\"")
        })
        .expect("refresh counter series");
    assert!(counter.ends_with(" 1000"), "unexpected counter: {counter}");

    record_refresh_for_sources(SURFACE, &watched, "load_error");
    assert!(transitions.observe_failure("secret"));
    log.record(event("load_error", Some("secret")));
    assert!(transitions.observe_recovery());
    log.record(event("recovered", None));
    record_refresh_for_sources(SURFACE, &watched, "load_error");
    assert!(transitions.observe_failure("deadline_exceeded"));
    log.record(event("load_error", Some("deadline_exceeded")));

    let snapshot = log.list(&TlsEventFilter::default());
    assert_eq!(snapshot.len(), 4);
    assert_eq!(snapshot[0].outcome, "load_error");
    assert_eq!(snapshot[1].error.as_deref(), Some("secret"));
    assert_eq!(snapshot[2].outcome, "recovered");
    assert_eq!(snapshot[3].outcome, "load_error");

    let serialized = serde_json::to_string(&snapshot).expect("serialize event snapshot");
    for secret in ["user", "password", "secret/path", "token", "credential"] {
        assert!(
            !serialized.contains(secret),
            "event snapshot leaked secret fragment {secret}: {serialized}"
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP/3 accepted-candidate binding (issue #3857)
// ---------------------------------------------------------------------------

/// Materials for a frontend surface that terminates client certificates.
struct ClientAuthMaterials {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
    ca_path: String,
    crl_path: String,
    client_der: Vec<u8>,
}

/// Write a server identity, a client CA, one client certificate under that CA,
/// and a CRL that already revokes it. The revocation is in the STARTUP CRL on
/// purpose: it is what proves the accepted candidate's verifier is compiled
/// from the CRLs of the same load, rather than from an unrelated list.
fn write_client_auth_materials() -> ClientAuthMaterials {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Frontend Client CA");
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let client_serial = 0x3857u64;
    let client_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "frontend-client");
    client_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    client_params.serial_number = Some(rcgen::SerialNumber::from(client_serial));
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert");

    let now = time::OffsetDateTime::now_utc();
    let crl_pem = rcgen::CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from(client_serial),
            revocation_time: now,
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .expect("sign CRL")
    .pem()
    .expect("CRL PEM");

    let server_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_cert = server_params
        .self_signed(&server_key)
        .expect("self-signed server cert");

    let cert_path = dir.path().join("server-cert.pem");
    let key_path = dir.path().join("server-key.pem");
    let ca_path = dir.path().join("client-ca.pem");
    let crl_path = dir.path().join("revocations.pem");
    std::fs::write(&cert_path, server_cert.pem()).expect("write server cert");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("write server key");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write client CA");
    std::fs::write(&crl_path, &crl_pem).expect("write CRL");

    ClientAuthMaterials {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        ca_path: ca_path.to_string_lossy().into_owned(),
        crl_path: crl_path.to_string_lossy().into_owned(),
        client_der: client_cert.der().to_vec(),
        _dir: dir,
    }
}

/// The proxy frontend reload wiring must hand the HTTP/3 listener ONE accepted
/// candidate (issue #3857), and arm the proxy client-trust baseline from that
/// same load.
///
/// The H3 endpoint applies its config asynchronously, so before this it rebuilt
/// a verifier from a re-read client-CA source plus the startup CRL clone and
/// then published the proxy scope's latest material as its own generation —
/// three different instants, one published generation. Here the config in the
/// serving slot, the verifier, and the identity are asserted to be one value:
/// the accepted candidate's `config` is the very `Arc` the listeners serve, its
/// verifier enforces the CRLs of that load, and its identity is what the proxy
/// scope was armed with.
#[tokio::test]
async fn proxy_frontend_reload_publishes_one_accepted_candidate_for_http3() {
    ensure_crypto_provider();
    let materials = write_client_auth_materials();

    let env = EnvConfig {
        frontend_tls_live_reload_enabled: true,
        frontend_tls_cert_path: Some(materials.cert_path.clone()),
        frontend_tls_key_path: Some(materials.key_path.clone()),
        frontend_tls_client_ca_bundle_path: Some(materials.ca_path.clone()),
        tls_crl_file_path: Some(materials.crl_path.clone()),
        // Long enough that no background poll can interleave with the
        // assertions below; every assertion is on the startup publication.
        frontend_tls_watch_interval_seconds: 3600,
        ..EnvConfig::default()
    };
    let tls_policy = ferrum_edge::tls::TlsPolicy::from_env_config(&env).expect("tls policy");
    let crls = ferrum_edge::tls::load_crls(env.tls_crl_file_path.as_deref()).expect("load CRLs");
    assert!(!crls.is_empty(), "the startup CRL must parse");

    let candidate = ferrum_edge::modes::startup_security::try_load_frontend_tls_candidate(
        &env,
        &tls_policy,
        &crls,
    )
    .expect("startup frontend TLS load")
    .expect("cert and key are configured");
    let startup_material = candidate.client_trust.material.clone();

    // The registry is process-global; serialize with every other test in this
    // file that publishes into it.
    let _registry = isolated_client_trust_registry().await;

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut handles = ferrum_edge::modes::tls_reload::prepare_proxy_frontend_tls(
        candidate.config.clone(),
        Some(candidate.client_trust),
        &env,
        &tls_policy,
        &crls,
        Some(shutdown_rx),
    );

    let slot = handles.slot.clone().expect("live reload publishes a slot");
    let accepted_slot = handles
        .accepted_slot
        .clone()
        .expect("live reload publishes an accepted candidate for the H3 listener");
    let accepted = accepted_slot
        .load_full()
        .as_ref()
        .clone()
        .expect("the accepted slot is pre-populated at startup");

    let served = slot.load_full().as_ref().clone().expect("slot config");
    assert!(
        Arc::ptr_eq(&accepted.config, &served),
        "the accepted candidate must carry the very ServerConfig the listeners serve, not a \
         separately loaded one"
    );

    // The verifier the H3 endpoint would install enforces the CRLs of this same
    // load: the client certificate the startup CRL revokes is refused.
    let verifier = accepted
        .client_trust
        .verifier
        .as_ref()
        .expect("a configured client CA must yield a verifier");
    assert!(
        verifier
            .verify_client_cert(
                &rustls::pki_types::CertificateDer::from(materials.client_der.clone()),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .is_err(),
        "the accepted candidate's verifier must enforce the CRLs of its own load"
    );

    // ...and the identity published alongside it is the identity of exactly
    // that material, which is also the proxy scope's armed baseline. A baseline
    // re-read from the client-CA source could describe a different generation.
    assert_eq!(
        accepted.client_trust.material, startup_material,
        "the accepted candidate's identity must be the startup load's identity"
    );
    assert_eq!(
        ferrum_edge::tls::client_trust::current_material(
            ferrum_edge::tls::ClientTrustScope::ProxyFrontend
        ),
        Some(startup_material),
        "the proxy client-trust baseline must be armed from the served load, not a re-read"
    );

    if let Some(watcher) = handles.watcher_handle.take() {
        watcher.abort();
    }
}

// ---------------------------------------------------------------------------
// Admin HTTPS client-trust ownership, and unarmed no-client-auth listeners
// (issue #3857)
// ---------------------------------------------------------------------------

/// The frontend client-trust registry is process-global by design — it is the
/// thing every listener consults — so every test below serializes on one lock
/// and resets it on entry.
async fn isolated_client_trust_registry() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let guard = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    ferrum_edge::tls::client_trust::reset_for_test();
    guard
}

fn trust_snapshot(
    scope: ferrum_edge::tls::ClientTrustScope,
) -> ferrum_edge::tls::client_trust::ClientTrustScopeSnapshot {
    ferrum_edge::tls::client_trust::snapshot()
        .into_iter()
        .find(|row| row.scope == scope)
        .expect("every scope is present in the snapshot")
}

/// A client CA, one client leaf under it, and a server identity — enough to run
/// a real mTLS admin listener.
struct AdminMtlsPki {
    server_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    client_roots: Arc<RootCertStore>,
    /// PEM of the client CA, for building the semantic baseline identity that
    /// a withdrawal is published against.
    client_ca_pem: String,
    client_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    client_key: rustls::pki_types::PrivateKeyDer<'static>,
}

fn admin_mtls_pki() -> AdminMtlsPki {
    ensure_crypto_provider();

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Admin Client CA");
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(ca_cert.der().clone())
        .expect("add client CA root");

    let client_key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "admin-client");
    client_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    let client_cert = client_params
        .signed_by(&client_key_pair, &issuer)
        .expect("sign client leaf");

    let server_key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_cert = server_params
        .self_signed(&server_key_pair)
        .expect("self-signed server cert");

    let server_key_pem = server_key_pair.serialize_pem();
    let server_key = rustls_pemfile::private_key(&mut server_key_pem.as_bytes())
        .expect("read server key")
        .expect("server key present");
    let client_key_pem = client_key_pair.serialize_pem();
    let client_key = rustls_pemfile::private_key(&mut client_key_pem.as_bytes())
        .expect("read client key")
        .expect("client key present");

    AdminMtlsPki {
        server_certs: vec![server_cert.der().clone()],
        server_key,
        client_roots: Arc::new(client_roots),
        client_ca_pem: ca_cert.pem(),
        client_chain: vec![client_cert.der().clone()],
        client_key,
    }
}

/// Admin `ServerConfig` requiring a client certificate from `pki`'s CA.
fn admin_mtls_server_config(pki: &AdminMtlsPki) -> Arc<ServerConfig> {
    let verifier = rustls::server::WebPkiClientVerifier::builder(pki.client_roots.clone())
        .build()
        .expect("build admin client verifier");
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(pki.server_certs.clone(), pki.server_key.clone_key())
            .expect("admin server cert"),
    )
}

/// Admin `ServerConfig` with no client-certificate authentication, matching an
/// admin listener without `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH`.
fn admin_no_client_auth_server_config(pki: &AdminMtlsPki) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(pki.server_certs.clone(), pki.server_key.clone_key())
            .expect("admin server cert"),
    )
}

/// Publish the same verifier/config/material transaction production admin TLS
/// uses into an existing serving slot.
fn publish_admin_mtls_candidate(
    pki: &AdminMtlsPki,
    slot: &ferrum_edge::tls::SharedFrontendTls,
) -> ferrum_edge::tls::client_trust::ClientTrustPublication {
    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder(pki.client_roots.clone())
            .build()
            .expect("build admin client verifier");
    let bound = ferrum_edge::tls::client_trust::bind_live_handshake_verifier(
        ferrum_edge::tls::ClientTrustScope::AdminHttps,
        verifier.clone(),
    );
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_client_cert_verifier(bound)
            .with_single_cert(pki.server_certs.clone(), pki.server_key.clone_key())
            .expect("admin server cert"),
    );
    let material =
        ferrum_edge::tls::ClientTrustMaterial::from_parts(Some(pki.client_ca_pem.as_bytes()), &[])
            .expect("summarize the admin client CA");
    ferrum_edge::tls::client_trust::publish_accepted_rustls_candidate(
        ferrum_edge::tls::ClientTrustScope::AdminHttps,
        material,
        verifier,
        || slot.store(Arc::new(Some(config))),
    )
}

/// Publish the first accepted admin mTLS candidate and return its serving slot.
fn publish_admin_mtls_slot(pki: &AdminMtlsPki) -> ferrum_edge::tls::SharedFrontendTls {
    let slot: ferrum_edge::tls::SharedFrontendTls = Arc::new(ArcSwap::new(Arc::new(None)));
    let publication = publish_admin_mtls_candidate(pki, &slot);
    assert_eq!(
        publication.outcome,
        ferrum_edge::tls::client_trust::ClientTrustPublicationOutcome::Armed,
        "the first accepted admin client-trust candidate must arm its scope"
    );
    slot
}

fn admin_client_config(pki: &AdminMtlsPki, with_client_cert: bool, alpn: &[&[u8]]) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier));
    let mut config = if with_client_cert {
        builder
            .with_client_auth_cert(pki.client_chain.clone(), pki.client_key.clone_key())
            .expect("client auth cert")
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// `header_read_timeout_seconds` selects which of the two connection-drive
/// paths in `serve_admin_io` runs: `0` takes the plain await, anything else
/// takes the slowloris watchdog loop. Both must fence a retired connection, so
/// the tests cover both.
fn trust_test_admin_state(header_read_timeout_seconds: u64) -> ferrum_edge::admin::AdminState {
    ferrum_edge::admin::AdminState {
        db: None,
        jwt_manager: ferrum_edge::admin::jwt_auth::JwtManager::new(
            ferrum_edge::admin::jwt_auth::JwtConfig {
                secret: "client-trust-admin-integration-secret-32chars!!".to_string(),
                issuer: "ferrum-edge-client-trust-tests".to_string(),
                audience: None,
                max_ttl_seconds: 3600,
                algorithm: jsonwebtoken::Algorithm::HS256,
            },
        ),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "127.0.0.1".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        // File mode runs no database poll loop, so there is no live-apply
        // coordinator to wait on (issue #3926).
        runtime_config_apply: None,
    }
}

/// Start the admin HTTPS accept loop that reads its `ServerConfig` from a
/// hot-swappable slot — the production path under frontend TLS live reload.
async fn start_admin_https_listener(
    slot: ferrum_edge::tls::SharedFrontendTls,
    header_read_timeout_seconds: u64,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    JoinHandle<Result<(), anyhow::Error>>,
) {
    let mut errors = Vec::new();
    for attempt in 1..=5 {
        let reservation = reserve_port().await.expect("reserve admin port");
        let port = reservation.drop_and_take_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                errors.push(format!("attempt {attempt}: bind failed: {error}"));
                continue;
            }
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = trust_test_admin_state(header_read_timeout_seconds);
        let listener_slot = slot.clone();
        let task = tokio::spawn(async move {
            ferrum_edge::admin::serve_admin_on_listener_with_dynamic_tls(
                listener,
                state,
                shutdown_rx,
                listener_slot,
                ferrum_edge::admin::AdminConnLimiter::unlimited(),
            )
            .await
        });
        return (addr, shutdown_tx, task);
    }
    panic!("admin HTTPS listener did not bind: {}", errors.join(" | "));
}

/// One established admin HTTPS connection that can issue further requests
/// without a new handshake — the property under test.
enum AdminTransport {
    H1(hyper::client::conn::http1::SendRequest<http_body_util::Empty<bytes::Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>>),
}

/// Outcome of one request on an already-established admin connection.
#[derive(Debug, PartialEq, Eq)]
enum AdminAttempt {
    Status(u16),
    TransportFailed,
}

impl AdminTransport {
    async fn live_probe(&mut self) -> AdminAttempt {
        let result = match self {
            AdminTransport::H1(sender) => {
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri("/live")
                    .header("host", "localhost")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .expect("build H1 probe");
                sender.send_request(req).await
            }
            AdminTransport::H2(sender) => {
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri("https://localhost/live")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .expect("build H2 probe");
                sender.send_request(req).await
            }
        };
        match result {
            Ok(response) => AdminAttempt::Status(response.status().as_u16()),
            Err(_) => AdminAttempt::TransportFailed,
        }
    }
}

/// Establish one admin HTTPS connection, returning the request sender and the
/// spawned task that drives its hyper connection.
async fn establish_admin_connection(
    addr: SocketAddr,
    config: ClientConfig,
    http2: bool,
) -> std::io::Result<(AdminTransport, JoinHandle<()>)> {
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls = connector.connect(server_name, tcp).await?;
    let io = hyper_util::rt::TokioIo::new(tls);
    if http2 {
        let (sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((AdminTransport::H2(sender), driver))
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((AdminTransport::H1(sender), driver))
    }
}

/// Poll the SAME admin connection until it stops being authorized, bounded.
async fn admin_wait_until_unauthorized(transport: &mut AdminTransport) -> AdminAttempt {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut last = AdminAttempt::Status(200);
    while tokio::time::Instant::now() < deadline {
        last = transport.live_probe().await;
        if last != AdminAttempt::Status(200) {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    last
}

/// A client-certificate-authenticated admin HTTPS connection joins the
/// `admin_https` retirement domain for its whole lifetime, and leaves it on
/// teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_https_registers_a_client_certificate_authenticated_connection() {
    let _registry = isolated_client_trust_registry().await;
    let pki = admin_mtls_pki();

    let slot = publish_admin_mtls_slot(&pki);
    let (addr, shutdown_tx, listener) = start_admin_https_listener(slot, 10).await;

    let (mut transport, driver) =
        establish_admin_connection(addr, admin_client_config(&pki, true, &[b"http/1.1"]), false)
            .await
            .expect("establish admin mTLS connection");
    assert_eq!(
        transport.live_probe().await,
        AdminAttempt::Status(200),
        "the admin connection must be usable before any withdrawal"
    );

    assert_eq!(
        trust_snapshot(ferrum_edge::tls::ClientTrustScope::AdminHttps).tracked_sessions,
        1,
        "a client-certificate-authenticated admin connection must be tracked for retirement"
    );

    drop(transport);
    driver.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline
        && trust_snapshot(ferrum_edge::tls::ClientTrustScope::AdminHttps).tracked_sessions != 0
    {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        trust_snapshot(ferrum_edge::tls::ClientTrustScope::AdminHttps).tracked_sessions,
        0,
        "the registration guard must deregister when the admin connection ends"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}

/// An admin HTTPS connection that presents NO client certificate holds no trust
/// decision a CRL or client-CA withdrawal could revoke, so it must be neither
/// tracked nor retired — a pure pass-through case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_https_does_not_register_a_connection_without_a_client_certificate() {
    let _registry = isolated_client_trust_registry().await;
    let pki = admin_mtls_pki();

    let slot: ferrum_edge::tls::SharedFrontendTls = Arc::new(ArcSwap::new(Arc::new(Some(
        admin_no_client_auth_server_config(&pki),
    ))));
    let (addr, shutdown_tx, listener) = start_admin_https_listener(slot, 10).await;

    let (mut transport, driver) = establish_admin_connection(
        addr,
        admin_client_config(&pki, false, &[b"http/1.1"]),
        false,
    )
    .await
    .expect("establish anonymous admin TLS connection");
    assert_eq!(
        transport.live_probe().await,
        AdminAttempt::Status(200),
        "an anonymous admin TLS connection must be served normally"
    );
    assert_eq!(
        trust_snapshot(ferrum_edge::tls::ClientTrustScope::AdminHttps).tracked_sessions,
        0,
        "a connection with no gateway-verified client certificate must not be tracked"
    );

    // ...and a withdrawal must leave it entirely alone.
    ferrum_edge::tls::client_trust::force_withdrawal_fence_for_test(
        ferrum_edge::tls::ClientTrustScope::AdminHttps,
        2,
        ferrum_edge::tls::client_trust::ClientTrustRetirementReason::ClientCaWithdrawn,
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        transport.live_probe().await,
        AdminAttempt::Status(200),
        "an untracked admin connection must survive a withdrawal untouched"
    );

    drop(transport);
    driver.abort();
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}

/// The admin accept loop must capture the client-trust generation BEFORE it
/// loads the `ServerConfig` for the handshake.
///
/// Made deterministic by moving the fence AHEAD of the armed generation before
/// the connection is made: a listener that captures the *current* generation
/// registers below the fence and is retired by the post-insert re-check, while
/// one that reconstructed a generation after the fact would land at or above
/// the fence and survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_https_captures_the_generation_in_force_before_selecting_its_config() {
    let _registry = isolated_client_trust_registry().await;
    let pki = admin_mtls_pki();

    ferrum_edge::tls::client_trust::arm_at_generation_for_test(
        ferrum_edge::tls::ClientTrustScope::AdminHttps,
        1,
    );
    ferrum_edge::tls::client_trust::force_withdrawal_fence_for_test(
        ferrum_edge::tls::ClientTrustScope::AdminHttps,
        2,
        ferrum_edge::tls::client_trust::ClientTrustRetirementReason::CrlChanged,
    );

    let slot: ferrum_edge::tls::SharedFrontendTls =
        Arc::new(ArcSwap::new(Arc::new(Some(admin_mtls_server_config(&pki)))));
    // `0` selects `serve_admin_io`'s untimed connection-drive path; the other
    // admin tests here run the slowloris-watchdog path, so both are covered.
    let (addr, shutdown_tx, listener) = start_admin_https_listener(slot, 0).await;

    let (mut transport, driver) =
        establish_admin_connection(addr, admin_client_config(&pki, true, &[b"http/1.1"]), false)
            .await
            .expect("establish admin mTLS connection");

    let outcome = admin_wait_until_unauthorized(&mut transport).await;
    assert!(
        matches!(
            outcome,
            AdminAttempt::Status(401) | AdminAttempt::TransportFailed
        ),
        "a connection captured below the published fence must be refused or closed, got {outcome:?}"
    );

    driver.abort();
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}

/// An established admin keep-alive (HTTP/1.1) and an established multiplexed
/// admin HTTP/2 connection both stop being authorized after an ACCEPTED
/// client-CA withdrawal, with no reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_https_established_connections_are_fenced_after_an_accepted_withdrawal() {
    let _registry = isolated_client_trust_registry().await;
    let pki = admin_mtls_pki();

    // A real rustls publication chain: install the live verifier, expose its
    // bound config, then arm the matching material/generation atomically.
    let slot = publish_admin_mtls_slot(&pki);
    let (addr, shutdown_tx, listener) = start_admin_https_listener(slot.clone(), 10).await;

    let (mut keepalive, keepalive_driver) =
        establish_admin_connection(addr, admin_client_config(&pki, true, &[b"http/1.1"]), false)
            .await
            .expect("establish admin H1 keep-alive");
    let (mut multiplexed, multiplexed_driver) =
        establish_admin_connection(addr, admin_client_config(&pki, true, &[b"h2"]), true)
            .await
            .expect("establish admin H2 connection");

    assert_eq!(keepalive.live_probe().await, AdminAttempt::Status(200));
    assert_eq!(multiplexed.live_probe().await, AdminAttempt::Status(200));
    assert_eq!(
        trust_snapshot(ferrum_edge::tls::ClientTrustScope::AdminHttps).tracked_sessions,
        2,
        "both established admin connections must be tracked"
    );

    // Rotate to a different client CA through the same verifier/config/material
    // transaction production reload uses. The new anchor set is not a superset
    // of the baseline, so this narrows authority.
    let replacement_pki = admin_mtls_pki();
    let withdrawal = publish_admin_mtls_candidate(&replacement_pki, &slot);
    assert!(
        withdrawal.withdrew(),
        "removing the admin client CA must publish a withdrawal"
    );
    assert_eq!(
        withdrawal.retired_sessions, 2,
        "both established admin connections must be retired by the publication"
    );

    let keepalive_outcome = admin_wait_until_unauthorized(&mut keepalive).await;
    assert!(
        matches!(
            keepalive_outcome,
            AdminAttempt::Status(401) | AdminAttempt::TransportFailed
        ),
        "a reused admin keep-alive connection must not stay authorized, got {keepalive_outcome:?}"
    );
    let multiplexed_outcome = admin_wait_until_unauthorized(&mut multiplexed).await;
    assert!(
        matches!(
            multiplexed_outcome,
            AdminAttempt::Status(401) | AdminAttempt::TransportFailed
        ),
        "a new stream on the original admin H2 connection must not be authorized, got {multiplexed_outcome:?}"
    );

    keepalive_driver.abort();
    multiplexed_driver.abort();
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}

// ---------------------------------------------------------------------------
// Unarmed no-client-auth listeners (issue #3857)
// ---------------------------------------------------------------------------

/// A frontend TLS candidate that performs NO client-certificate authentication
/// must leave `ClientTrustScope::ProxyFrontend` unarmed under live reload.
///
/// Arming it would publish an empty baseline, export retirement series for a
/// protection with nothing to protect, and — because the TCP+TLS relay decides
/// kTLS eligibility from `capture(ProxyFrontend).is_none()` — decline the kTLS
/// fast path on a listener that authenticates no client at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_frontend_without_client_auth_stays_unarmed_and_keeps_ktls_eligibility() {
    let _registry = isolated_client_trust_registry().await;
    ensure_crypto_provider();
    let materials = write_client_auth_materials();

    // Cert + key only: no client-CA bundle, so no client certificate is ever
    // verified on this listener.
    let env = EnvConfig {
        frontend_tls_live_reload_enabled: true,
        frontend_tls_cert_path: Some(materials.cert_path.clone()),
        frontend_tls_key_path: Some(materials.key_path.clone()),
        frontend_tls_client_ca_bundle_path: None,
        tls_crl_file_path: Some(materials.crl_path.clone()),
        frontend_tls_watch_interval_seconds: 3600,
        ..EnvConfig::default()
    };
    let tls_policy = ferrum_edge::tls::TlsPolicy::from_env_config(&env).expect("tls policy");
    let crls = ferrum_edge::tls::load_crls(env.tls_crl_file_path.as_deref()).expect("load CRLs");

    let candidate = ferrum_edge::modes::startup_security::try_load_frontend_tls_candidate(
        &env,
        &tls_policy,
        &crls,
    )
    .expect("startup frontend TLS load")
    .expect("cert and key are configured");
    assert!(
        candidate.client_trust.verifier.is_none(),
        "a listener with no client-CA bundle installs no client verifier"
    );

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut handles = ferrum_edge::modes::tls_reload::prepare_proxy_frontend_tls(
        candidate.config.clone(),
        Some(candidate.client_trust),
        &env,
        &tls_policy,
        &crls,
        Some(shutdown_rx),
    );

    // Certificate/key-only live reload still works — the slot is published.
    assert!(
        handles.slot.is_some(),
        "certificate/key live reload must remain available without client authentication"
    );

    let row = trust_snapshot(ferrum_edge::tls::ClientTrustScope::ProxyFrontend);
    assert!(
        !row.armed,
        "a listener that authenticates no client certificate must not arm a trust scope"
    );
    assert_eq!(row.generation, 0, "an unarmed scope has no generation");
    assert!(
        ferrum_edge::tls::client_trust::capture(ferrum_edge::tls::ClientTrustScope::ProxyFrontend)
            .is_none(),
        "capture must stay None, which is exactly what keeps the TCP+TLS kTLS fast path eligible"
    );

    // The HTTP/3 scope is unarmed for the same reason, and H3 0-RTT admission
    // is decided by whether client authentication is CONFIGURED — never by
    // whether a trust scope is armed — so a no-client-auth listener keeps its
    // full early-data eligibility.
    assert!(
        !trust_snapshot(ferrum_edge::tls::ClientTrustScope::ProxyH3).armed,
        "the H3 scope must not be armed for a listener with no client-CA bundle"
    );
    assert!(
        ferrum_edge::http3::peer_identity::zero_rtt_admitted(true, false),
        "0-RTT admission on a no-client-auth listener is unchanged"
    );
    assert_eq!(
        ferrum_edge::http3::peer_identity::quic_max_early_data_size(true, false),
        u32::MAX,
        "the QUIC early-data advertisement on a no-client-auth listener is unchanged"
    );

    // Nothing at all is scraped for an unarmed deployment.
    let mut rendered = String::new();
    ferrum_edge::tls::client_trust::render_prometheus(&mut rendered, "");
    assert!(
        rendered.is_empty(),
        "no client-trust series may be exported when no scope is armed:\n{rendered}"
    );

    if let Some(watcher) = handles.watcher_handle.take() {
        watcher.abort();
    }
}

/// The same rule on the admin surface: admin HTTPS without
/// `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` must leave `admin_https` unarmed,
/// so nothing is captured, tracked, or exported for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_https_without_client_auth_stays_unarmed() {
    let _registry = isolated_client_trust_registry().await;
    ensure_crypto_provider();
    let materials = write_client_auth_materials();

    let env = EnvConfig {
        frontend_tls_live_reload_enabled: true,
        admin_tls_cert_path: Some(materials.cert_path.clone()),
        admin_tls_key_path: Some(materials.key_path.clone()),
        admin_tls_client_ca_bundle_path: None,
        tls_crl_file_path: Some(materials.crl_path.clone()),
        frontend_tls_watch_interval_seconds: 3600,
        ..EnvConfig::default()
    };
    let tls_policy = ferrum_edge::tls::TlsPolicy::from_env_config(&env).expect("tls policy");
    let crls = ferrum_edge::tls::load_crls(env.tls_crl_file_path.as_deref()).expect("load CRLs");

    let candidate = ferrum_edge::modes::startup_security::load_admin_tls_candidate(
        &env,
        &tls_policy,
        &crls,
        "Invalid admin TLS configuration",
    )
    .expect("startup admin TLS load");
    assert!(
        candidate.client_trust.verifier.is_none(),
        "admin HTTPS without a client-CA bundle installs no client verifier"
    );

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut handles = ferrum_edge::modes::tls_reload::prepare_admin_frontend_tls(
        candidate.config.clone(),
        Some(candidate.client_trust),
        &env,
        &tls_policy,
        &crls,
        Some(shutdown_rx),
    );

    assert!(
        handles.slot.is_some(),
        "admin certificate/key live reload must remain available without client authentication"
    );
    assert!(
        !trust_snapshot(ferrum_edge::tls::ClientTrustScope::AdminHttps).armed,
        "admin HTTPS without client authentication must not arm a trust scope"
    );
    assert!(
        ferrum_edge::tls::client_trust::capture(ferrum_edge::tls::ClientTrustScope::AdminHttps)
            .is_none(),
        "an unarmed admin scope must never hand an accept loop an admission to carry"
    );

    if let Some(watcher) = handles.watcher_handle.take() {
        watcher.abort();
    }
}

/// A listener WITH verified client-certificate authentication does arm, so the
/// unarmed assertions above are about the authentication mode and not about the
/// wiring being inert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_frontend_with_client_auth_arms_its_scope() {
    let _registry = isolated_client_trust_registry().await;
    ensure_crypto_provider();
    let materials = write_client_auth_materials();

    let env = EnvConfig {
        frontend_tls_live_reload_enabled: true,
        frontend_tls_cert_path: Some(materials.cert_path.clone()),
        frontend_tls_key_path: Some(materials.key_path.clone()),
        frontend_tls_client_ca_bundle_path: Some(materials.ca_path.clone()),
        tls_crl_file_path: Some(materials.crl_path.clone()),
        frontend_tls_watch_interval_seconds: 3600,
        ..EnvConfig::default()
    };
    let tls_policy = ferrum_edge::tls::TlsPolicy::from_env_config(&env).expect("tls policy");
    let crls = ferrum_edge::tls::load_crls(env.tls_crl_file_path.as_deref()).expect("load CRLs");
    let candidate = ferrum_edge::modes::startup_security::try_load_frontend_tls_candidate(
        &env,
        &tls_policy,
        &crls,
    )
    .expect("startup frontend TLS load")
    .expect("cert and key are configured");
    assert!(
        candidate.client_trust.verifier.is_some(),
        "a configured client-CA bundle installs a verifier"
    );

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut handles = ferrum_edge::modes::tls_reload::prepare_proxy_frontend_tls(
        candidate.config.clone(),
        Some(candidate.client_trust),
        &env,
        &tls_policy,
        &crls,
        Some(shutdown_rx),
    );

    let row = trust_snapshot(ferrum_edge::tls::ClientTrustScope::ProxyFrontend);
    assert!(row.armed, "verified client authentication arms the scope");
    assert!(
        ferrum_edge::tls::client_trust::capture(ferrum_edge::tls::ClientTrustScope::ProxyFrontend)
            .is_some(),
        "an armed scope hands each accept an admission to carry"
    );

    if let Some(watcher) = handles.watcher_handle.take() {
        watcher.abort();
    }
}
