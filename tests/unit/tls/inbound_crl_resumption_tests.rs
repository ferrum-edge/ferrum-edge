//! Inbound CRL enforcement must survive session resumption (issue #6538).
//!
//! A resumed TLS 1.2 or TLS 1.3 handshake restores the client certificate chain
//! from the session and never calls the client-certificate verifier, so it also
//! skips the verifier's CRL `nextUpdate` check. These tests drive the
//! production frontend (proxy HTTPS/H2, TCP+TLS, admin HTTPS, CP gRPC) and mesh
//! inbound builders: they prime a session while the CRL is valid, then move a
//! controlled rustls clock past `nextUpdate` and reconnect with the same
//! client session store. The reconnect must be refused. The controls show that
//! a listener without CRLs still resumes, so the tests can tell a full
//! handshake from a resumed one. The HTTP/3 builder is covered in
//! `src/http3/server.rs`, because its rustls conversion is private.

use std::io::{Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferrum_edge::tls::{
    MeshClientAuth, TlsPolicy, load_mesh_server_identity, load_mesh_tls_config_with_identity,
    load_tls_config_with_client_auth,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::{CertificateError, ClientConnection, HandshakeKind, ServerConnection};
use tempfile::TempDir;
use time::{Duration as TimeDuration, OffsetDateTime};

const HOST: &str = "frontend.crl-resumption.test";
const VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS12, &rustls::version::TLS13];

#[derive(Debug)]
struct Clock(AtomicU64);

impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.0.load(Ordering::Relaxed),
        )))
    }
}

struct Pki {
    _dir: TempDir,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    ca_der: CertificateDer<'static>,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    now: OffsetDateTime,
}

impl Pki {
    fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "inbound CRL resumption CA");
        ca.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca.self_signed(&ca_key).expect("CA cert");
        let issuer = Issuer::new(ca, ca_key);

        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
        let server_cert = CertificateParams::new(vec![HOST.to_string()])
            .expect("server params")
            .signed_by(&server_key, &issuer)
            .expect("server cert");
        let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
        let mut client_params =
            CertificateParams::new(vec!["client.crl-resumption.test".to_string()])
                .expect("client params");
        client_params
            .distinguished_name
            .push(DnType::CommonName, "resuming client");
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client cert");

        let server_cert_path = dir.path().join("server.pem");
        let server_key_path = dir.path().join("server-key.pem");
        let client_ca_path = dir.path().join("client-ca.pem");
        std::fs::write(&server_cert_path, server_cert.pem()).expect("write server cert");
        std::fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
        std::fs::write(&client_ca_path, ca_cert.pem()).expect("write client CA");

        Self {
            _dir: dir,
            server_cert: server_cert_path,
            server_key: server_key_path,
            client_ca: client_ca_path,
            ca_der: ca_cert.der().clone(),
            client_chain: vec![client_cert.der().clone()],
            client_key: client_key.serialize_der(),
            issuer,
            now: OffsetDateTime::now_utc(),
        }
    }

    /// One CRL from the client's issuer, valid for one more minute and
    /// revoking nothing: only its `nextUpdate` can refuse the client.
    fn crls(&self) -> Vec<CertificateRevocationListDer<'static>> {
        let params = CertificateRevocationListParams {
            this_update: self.now - TimeDuration::hours(1),
            next_update: self.now + TimeDuration::minutes(1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        vec![CertificateRevocationListDer::from(
            params.signed_by(&self.issuer).expect("CRL").der().to_vec(),
        )]
    }

    fn path(path: &std::path::Path) -> &str {
        path.to_str().expect("utf8 path")
    }

    fn policy(version: &'static rustls::SupportedProtocolVersion) -> TlsPolicy {
        TlsPolicy {
            protocol_versions: vec![version],
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 64,
            early_data_max_size: 0,
        }
    }

    /// One client config, and so one client session store, reused across
    /// every reconnect of a test.
    fn client(
        &self,
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca_der.clone()).expect("client root");
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .expect("client protocol version")
        .with_root_certificates(roots)
        .with_client_auth_cert(
            self.client_chain.clone(),
            PrivatePkcs8KeyDer::from(self.client_key.clone()).into(),
        )
        .expect("client auth cert");
        Arc::new(config)
    }

    fn frontend(
        &self,
        version: &'static rustls::SupportedProtocolVersion,
        crls: &[CertificateRevocationListDer<'static>],
    ) -> (Arc<rustls::ServerConfig>, Arc<Clock>) {
        let built = load_tls_config_with_client_auth(
            Self::path(&self.server_cert),
            Self::path(&self.server_key),
            Some(Self::path(&self.client_ca)),
            false,
            &Self::policy(version),
            30,
            30,
            crls,
        )
        .expect("production frontend builder");
        self.with_clock(&built)
    }

    fn mesh(
        &self,
        version: &'static rustls::SupportedProtocolVersion,
        crls: &[CertificateRevocationListDer<'static>],
        client_auth: MeshClientAuth,
    ) -> (Arc<rustls::ServerConfig>, Arc<Clock>) {
        let identity = load_mesh_server_identity(
            Self::path(&self.server_cert),
            Self::path(&self.server_key),
            30,
        )
        .expect("mesh server identity");
        let built = load_mesh_tls_config_with_identity(
            &identity,
            Some(Self::path(&self.client_ca)),
            client_auth,
            &Self::policy(version),
            30,
            crls,
            None,
        )
        .expect("production mesh operator-CA builder");
        self.with_clock(&built)
    }

    fn with_clock(
        &self,
        built: &Arc<rustls::ServerConfig>,
    ) -> (Arc<rustls::ServerConfig>, Arc<Clock>) {
        let clock = Arc::new(Clock(AtomicU64::new(self.now.unix_timestamp() as u64)));
        let mut config = rustls::ServerConfig::clone(built);
        config.time_provider = clock.clone();
        (Arc::new(config), clock)
    }

    fn expire(&self, clock: &Clock) {
        clock.0.store(
            (self.now + TimeDuration::minutes(2)).unix_timestamp() as u64,
            Ordering::Relaxed,
        );
    }
}

fn exchange(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    for _ in 0..32 {
        let mut progressed = false;
        if client.wants_write() {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).expect("client write");
            server
                .read_tls(&mut Cursor::new(wire))
                .expect("server read");
            server.process_new_packets()?;
            progressed = true;
        }
        if server.wants_write() {
            let mut wire = Vec::new();
            server.write_tls(&mut wire).expect("server write");
            client
                .read_tls(&mut Cursor::new(wire))
                .expect("client read");
            client.process_new_packets()?;
            progressed = true;
        }
        if !progressed {
            assert!(!client.is_handshaking() && !server.is_handshaking());
            return Ok(());
        }
    }
    panic!("handshake did not quiesce");
}

fn connect(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Result<(ClientConnection, ServerConnection), rustls::Error> {
    let mut client = ClientConnection::new(client, ServerName::try_from(HOST).expect("name"))?;
    let mut server = ServerConnection::new(server)?;
    exchange(&mut client, &mut server)?;
    Ok((client, server))
}

fn assert_expired_crl(error: rustls::Error, surface: &str) {
    assert!(
        matches!(
            error,
            rustls::Error::InvalidCertificate(
                CertificateError::ExpiredRevocationListContext { .. }
            ) | rustls::Error::InvalidCertificate(CertificateError::ExpiredRevocationList)
        ),
        "{surface}: a reconnect after the CRL's nextUpdate must fail the CRL expiry check, got {error:?}"
    );
}

/// Prime a session before `nextUpdate`, then reconnect after it. A resumed
/// session would skip the verifier, so the reconnect must instead be a full
/// handshake that the expired CRL refuses. A connection established before the
/// expiry keeps working.
fn assert_crl_expiry_refuses_reconnect(
    pki: &Pki,
    version: &'static rustls::SupportedProtocolVersion,
    server: Arc<rustls::ServerConfig>,
    clock: &Clock,
    surface: &str,
) {
    let client = pki.client(version);
    let (mut established, mut peer) =
        connect(client.clone(), server.clone()).expect("initial healthy handshake");
    let (second, _) = connect(client.clone(), server.clone()).expect("healthy reconnect");
    assert_eq!(
        second.handshake_kind(),
        Some(HandshakeKind::Full),
        "{surface} {version:?}: a CRL-enforcing listener must not resume sessions"
    );

    pki.expire(clock);
    let error = connect(client, server).expect_err("expired CRL refuses the reconnect");
    assert_expired_crl(error, surface);

    established
        .writer()
        .write_all(b"in-flight")
        .expect("existing write");
    exchange(&mut established, &mut peer).expect("existing session survives CRL expiry");
    let mut payload = [0u8; 9];
    peer.reader()
        .read_exact(&mut payload)
        .expect("existing read");
    assert_eq!(&payload, b"in-flight");
}

/// Without enforced CRLs nothing can expire, so the listener keeps resuming.
/// This also proves the client above was able to resume had the server let it.
fn assert_resumes(
    pki: &Pki,
    version: &'static rustls::SupportedProtocolVersion,
    server: Arc<rustls::ServerConfig>,
    surface: &str,
) {
    let client = pki.client(version);
    connect(client.clone(), server.clone()).expect("prime session");
    let (resumed, _) = connect(client, server).expect("control reconnect");
    assert_eq!(
        resumed.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "{surface} {version:?}: a listener without CRLs keeps session resumption"
    );
}

#[test]
fn frontend_mtls_reconnect_after_crl_next_update_is_refused_without_live_reload() {
    for version in VERSIONS {
        let pki = Pki::new();
        let crls = pki.crls();
        let (server, clock) = pki.frontend(version, &crls);
        assert_crl_expiry_refuses_reconnect(&pki, version, server, &clock, "frontend mTLS");
    }
}

#[test]
fn frontend_mtls_without_crls_still_resumes() {
    for version in VERSIONS {
        let pki = Pki::new();
        let (server, _clock) = pki.frontend(version, &[]);
        assert_resumes(&pki, version, server, "frontend mTLS");
    }
}

#[test]
fn mesh_operator_ca_reconnect_after_crl_next_update_is_refused() {
    for version in VERSIONS {
        for client_auth in [MeshClientAuth::Required, MeshClientAuth::Optional] {
            let pki = Pki::new();
            let crls = pki.crls();
            let (server, clock) = pki.mesh(version, &crls, client_auth);
            assert_crl_expiry_refuses_reconnect(&pki, version, server, &clock, "mesh operator-CA");
        }
    }
}

#[test]
fn mesh_operator_ca_without_crls_still_resumes() {
    for version in VERSIONS {
        let pki = Pki::new();
        let (server, _clock) = pki.mesh(version, &[], MeshClientAuth::Required);
        assert_resumes(&pki, version, server, "mesh operator-CA");
    }
}

/// The SPIFFE verifier reads the enforced CRL records and peer trust bundles
/// live on every handshake (issue #5574), so the mesh listener that installs
/// it must never let a peer skip it by resuming, whether or not CRLs are
/// enforced at build time.
#[test]
fn mesh_spiffe_verifier_listener_disables_every_resumption_mechanism() {
    let pki = Pki::new();
    let identity =
        load_mesh_server_identity(Pki::path(&pki.server_cert), Pki::path(&pki.server_key), 30)
            .expect("mesh server identity");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).expect("root");
    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("stand-in live verifier");
    let config = load_mesh_tls_config_with_identity(
        &identity,
        None,
        MeshClientAuth::Required,
        &Pki::policy(&rustls::version::TLS13),
        30,
        &[],
        Some(verifier),
    )
    .expect("mesh SPIFFE-verifier config");
    assert_eq!(config.send_tls13_tickets, 0, "TLS 1.3 tickets");
    assert!(!config.ticketer.enabled(), "TLS 1.2 tickets");
    assert!(
        !config.session_storage.can_cache(),
        "stateful session cache"
    );
}
