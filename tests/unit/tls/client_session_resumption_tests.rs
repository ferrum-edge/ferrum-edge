//! Outbound session resumption policy (`tls::apply_client_session_resumption`).
//!
//! Each test performs real in-memory handshakes against a server that issues
//! sessions, so the second connection from the same client config reports
//! whether the client offered a cached session: without enforced CRLs the
//! client resumes, and with enforced CRLs it must not, because a resumed
//! handshake would skip the verifier's CRL checks.

use std::io::Cursor;
use std::sync::Arc;

use ferrum_edge::tls::{TlsPolicy, apply_client_session_resumption};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivatePkcs8KeyDer, ServerName,
};
use rustls::{ClientConnection, HandshakeKind, ServerConnection};

const HOST: &str = "client-resumption.test";
const VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS12, &rustls::version::TLS13];

struct Peer {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Peer {
    fn new() -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
        let cert = CertificateParams::new(vec![HOST.to_string()])
            .expect("server params")
            .self_signed(&key)
            .expect("server cert");
        Self {
            cert: cert.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn server(
        &self,
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Arc<rustls::ServerConfig> {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .expect("server protocol version")
        .with_no_client_auth()
        .with_single_cert(
            vec![self.cert.clone()],
            PrivatePkcs8KeyDer::from(self.key.clone()).into(),
        )
        .expect("server cert");
        Arc::new(config)
    }

    /// A client config whose resumption the test then sets through the
    /// production helper. The builder default is replaced, so the outcome
    /// reflects only `apply_client_session_resumption`.
    fn client(&self, version: &'static rustls::SupportedProtocolVersion) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.clone()).expect("client root");
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .expect("client protocol version")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        config
    }
}

fn exchange(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..32 {
        let mut progressed = false;
        if client.wants_write() {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).expect("client write");
            server
                .read_tls(&mut Cursor::new(wire))
                .expect("server read");
            server.process_new_packets().expect("server process");
            progressed = true;
        }
        if server.wants_write() {
            let mut wire = Vec::new();
            server.write_tls(&mut wire).expect("server write");
            client
                .read_tls(&mut Cursor::new(wire))
                .expect("client read");
            client.process_new_packets().expect("client process");
            progressed = true;
        }
        if !progressed {
            assert!(!client.is_handshaking() && !server.is_handshaking());
            return;
        }
    }
    panic!("handshake did not quiesce");
}

/// Handshake twice with one client config and return the second connection's
/// handshake kind.
fn reconnect_kind(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Option<HandshakeKind> {
    let name = ServerName::try_from(HOST).expect("server name");
    for attempt in 0..2 {
        let mut client_conn =
            ClientConnection::new(client.clone(), name.clone()).expect("client connection");
        let mut server_conn = ServerConnection::new(server.clone()).expect("server connection");
        exchange(&mut client_conn, &mut server_conn);
        if attempt == 1 {
            return client_conn.handshake_kind();
        }
    }
    unreachable!()
}

fn policy(session_cache_size: usize) -> TlsPolicy {
    TlsPolicy {
        protocol_versions: vec![&rustls::version::TLS12, &rustls::version::TLS13],
        crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        prefer_server_cipher_order: false,
        session_cache_size,
        early_data_max_size: 0,
    }
}

#[test]
fn client_resumes_without_enforced_crls_and_default_policy() {
    let peer = Peer::new();
    for version in VERSIONS {
        let mut client = peer.client(version);
        apply_client_session_resumption(&mut client, None, &[]);
        assert_eq!(
            reconnect_kind(Arc::new(client), peer.server(version)),
            Some(HandshakeKind::Resumed),
            "{version:?}: without enforced CRLs the client must cache and offer its session"
        );
    }
}

#[test]
fn client_resumes_with_a_policy_session_cache() {
    let peer = Peer::new();
    let policy = policy(123);
    for version in VERSIONS {
        let mut client = peer.client(version);
        apply_client_session_resumption(&mut client, Some(&policy), &[]);
        assert_eq!(
            reconnect_kind(Arc::new(client), peer.server(version)),
            Some(HandshakeKind::Resumed),
            "{version:?}: the policy session cache must store and offer the session"
        );
    }
}

#[test]
fn client_does_not_resume_when_crls_are_enforced() {
    let peer = Peer::new();
    let policy = policy(123);
    // Only the presence of enforced CRLs matters to the policy; the bytes are
    // never parsed by this helper.
    let crls = vec![CertificateRevocationListDer::from(vec![0x30, 0x00])];
    for version in VERSIONS {
        let mut client = peer.client(version);
        apply_client_session_resumption(&mut client, Some(&policy), &crls);
        assert_eq!(
            reconnect_kind(Arc::new(client), peer.server(version)),
            Some(HandshakeKind::Full),
            "{version:?}: a CRL-enforcing client must not resume, or the CRL checks are skipped"
        );
    }
}
