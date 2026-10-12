//! Cached backend configs must reverify CRLs on each new physical connection.
//! A ticket-capable server and a controlled rustls clock distinguish full
//! handshakes from resumption without relying on sleeps or disabling tickets.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferrum_edge::config::types::{BackendTlsConfig, Proxy};
use ferrum_edge::tls::TlsPolicy;
use ferrum_edge::tls::backend::BackendTlsConfigBuilder;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateRevocationListDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConnection, HandshakeKind, ServerConnection};
use tempfile::TempDir;
use time::{Duration as TimeDuration, OffsetDateTime};

const HOST: &str = "backend.crl-resumption.test";

#[derive(Debug)]
struct Clock(AtomicU64);

impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.0.load(Ordering::Relaxed),
        )))
    }
}

struct Fixture {
    _dir: TempDir,
    ca_path: std::path::PathBuf,
    issuer: Issuer<'static, KeyPair>,
    server: Arc<rustls::ServerConfig>,
    now: OffsetDateTime,
}

impl Fixture {
    fn new(version: &'static rustls::SupportedProtocolVersion, tickets: bool) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name.push(DnType::CommonName, "covered CA");
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = ca.self_signed(&ca_key).expect("CA cert");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, cert.pem()).expect("write CA");
        let issuer = Issuer::new(ca, ca_key);
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let leaf = CertificateParams::new(vec![HOST.to_string()])
            .expect("leaf params")
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .expect("protocol version")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
        .expect("server config");
        if tickets {
            server.ticketer = rustls::crypto::ring::Ticketer::new().expect("ticket producer");
        }
        Self {
            _dir: dir,
            ca_path,
            issuer,
            server: Arc::new(server),
            now: OffsetDateTime::now_utc(),
        }
    }

    fn crl(&self, covered: bool) -> Vec<CertificateRevocationListDer<'static>> {
        self.crl_until(covered, self.now + TimeDuration::minutes(1))
    }

    fn crl_until(
        &self,
        covered: bool,
        next_update: OffsetDateTime,
    ) -> Vec<CertificateRevocationListDer<'static>> {
        let mut unrelated_params =
            CertificateParams::new(Vec::<String>::new()).expect("unrelated params");
        unrelated_params
            .distinguished_name
            .push(DnType::CommonName, "uncovered CA");
        unrelated_params.key_usages = vec![KeyUsagePurpose::CrlSign];
        let unrelated = Issuer::new(
            unrelated_params,
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("unrelated key"),
        );
        let params = CertificateRevocationListParams {
            this_update: self.now - TimeDuration::hours(1),
            next_update,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        vec![CertificateRevocationListDer::from(
            params
                .signed_by(if covered { &self.issuer } else { &unrelated })
                .expect("CRL")
                .der()
                .to_vec(),
        )]
    }

    #[allow(clippy::too_many_arguments)]
    fn client(
        &self,
        version: &'static rustls::SupportedProtocolVersion,
        crls: &[CertificateRevocationListDer<'static>],
        verify: bool,
        global_no_verify: bool,
        san: bool,
        variant: u8,
    ) -> (Arc<rustls::ClientConfig>, Arc<Clock>) {
        let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
            "id": "crl-resumption", "listen_path": "/", "backend_scheme": "https",
            "backend_host": HOST, "backend_port": 443
        }))
        .expect("proxy");
        proxy.resolved_tls = BackendTlsConfig::default_verify();
        proxy.resolved_tls.verify_server_cert = verify;
        if san {
            proxy.resolved_tls.san_allow_list = vec![HOST.to_string()];
            proxy.resolved_tls.recompute_san_digest();
        }
        let policy = TlsPolicy {
            protocol_versions: vec![version],
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 123,
            early_data_max_size: 0,
        };
        let builder = BackendTlsConfigBuilder {
            proxy: &proxy,
            policy: Some(&policy),
            global_ca: Some(&self.ca_path),
            global_no_verify,
            global_client_cert: None,
            global_client_key: None,
            crls,
        };
        let mut config = match variant {
            0 => builder.build_rustls(),
            1 => builder.build_rustls_for_reqwest(true),
            2 => builder.build_rustls_quic(),
            _ => unreachable!("fixture variant"),
        }
        .expect("production backend builder");
        let clock = Arc::new(Clock(AtomicU64::new(self.now.unix_timestamp() as u64)));
        config.time_provider = clock.clone();
        (Arc::new(config), clock)
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
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<(ClientConnection, ServerConnection), rustls::Error> {
    let mut client = ClientConnection::new(client_config, ServerName::try_from(HOST).unwrap())?;
    let mut server = ServerConnection::new(server_config)?;
    exchange(&mut client, &mut server)?;
    Ok((client, server))
}

#[test]
fn cached_crl_backend_reconnect_reverifies_expiry_and_preserves_established_traffic() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for tickets in [false, true] {
            for variant in 0..=2 {
                for san in [false, true] {
                    let fixture = Fixture::new(version, tickets);
                    let crls = fixture.crl(true);
                    let (config, clock) = fixture.client(version, &crls, true, false, san, variant);
                    let (mut established, mut peer) =
                        connect(config.clone(), fixture.server.clone())
                            .expect("initial healthy handshake");
                    let (second, _) =
                        connect(config.clone(), fixture.server.clone()).expect("healthy reconnect");
                    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
                    clock.0.store(
                        (fixture.now + TimeDuration::minutes(1)).unix_timestamp() as u64,
                        Ordering::Relaxed,
                    );
                    let error = connect(config, fixture.server.clone())
                        .expect_err("expired CRL refuses reconnect");
                    assert!(matches!(
                        error,
                        rustls::Error::InvalidCertificate(
                            CertificateError::ExpiredRevocationListContext { .. }
                        )
                    ));
                    established
                        .writer()
                        .write_all(b"in-flight")
                        .expect("existing write");
                    exchange(&mut established, &mut peer)
                        .expect("existing session survives expiry");
                    let mut payload = [0u8; 9];
                    peer.reader()
                        .read_exact(&mut payload)
                        .expect("existing read");
                    assert_eq!(&payload, b"in-flight");
                }
            }
        }
    }
}

#[test]
fn empty_crl_and_effective_skip_verify_configs_still_resume() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for tickets in [false, true] {
            let fixture = Fixture::new(version, tickets);
            let crls = fixture.crl(true);
            for (records, verify, global_no_verify) in [
                (&[][..], true, false),
                (crls.as_slice(), false, false),
                (crls.as_slice(), true, true),
            ] {
                let (config, clock) =
                    fixture.client(version, records, verify, global_no_verify, false, 0);
                connect(config.clone(), fixture.server.clone()).expect("prime tickets/session ID");
                clock.0.store(
                    (fixture.now + TimeDuration::minutes(1)).unix_timestamp() as u64,
                    Ordering::Relaxed,
                );
                let (resumed, _) =
                    connect(config, fixture.server.clone()).expect("control reconnect");
                assert_eq!(resumed.handshake_kind(), Some(HandshakeKind::Resumed));
            }
        }
    }
}

#[test]
fn uncovered_issuer_remains_accepted_after_another_issuers_crl_expires() {
    let fixture = Fixture::new(&rustls::version::TLS13, true);
    let crls = fixture.crl(false);
    let (config, clock) = fixture.client(&rustls::version::TLS13, &crls, true, false, false, 0);
    connect(config.clone(), fixture.server.clone()).expect("uncovered initial connection");
    clock.0.store(
        (fixture.now + TimeDuration::minutes(1)).unix_timestamp() as u64,
        Ordering::Relaxed,
    );
    let (client, _) = connect(config, fixture.server.clone()).expect("uncovered issuer accepted");
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
#[ignore = "natural-expiry validation under the serial runtime lease"]
fn ticket_enabled_backend_reconnect_is_refused_after_natural_crl_expiry() {
    let fixture = Fixture::new(&rustls::version::TLS13, true);
    let deadline = fixture.now + TimeDuration::seconds(5);
    let crls = fixture.crl_until(true, deadline);
    let (mut config, _) = fixture.client(&rustls::version::TLS13, &crls, true, false, true, 0);
    Arc::get_mut(&mut config)
        .expect("fixture owns the config before priming")
        .time_provider = Arc::new(rustls::time_provider::DefaultTimeProvider);
    let (mut established, mut peer) =
        connect(config.clone(), fixture.server.clone()).expect("prime ticket-capable handshake");
    assert!(
        UnixTime::now().as_secs() < deadline.unix_timestamp() as u64,
        "fixture must prime before its CRL expires"
    );
    // Wait for the actual wall clock, without changing source bytes or draining
    // the cached ClientConfig. The origin's ticket producer remains enabled.
    while UnixTime::now().as_secs() < deadline.unix_timestamp() as u64 {
        std::thread::sleep(Duration::from_millis(100));
    }
    let error = connect(config, fixture.server.clone())
        .expect_err("natural CRL expiry must refuse the new connection");
    assert!(matches!(
        error,
        rustls::Error::InvalidCertificate(CertificateError::ExpiredRevocationListContext { .. })
    ));
    established.writer().write_all(b"held").expect("held write");
    exchange(&mut established, &mut peer).expect("established connection survives");
    let mut payload = [0u8; 4];
    peer.reader().read_exact(&mut payload).expect("held read");
    assert_eq!(&payload, b"held");
}
