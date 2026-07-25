//! Deterministic coverage for the rustls -> kTLS handoff gate
//! ([issue #2955](https://github.com/ferrum-edge/ferrum-edge/issues/2955)).
//!
//! `try_ktls_splice` consumes the tokio-rustls `TlsStream` and resumes
//! decryption from the raw socket. rustls's `dangerous_into_kernel_connection`
//! refuses only when *outbound* TLS records are still buffered, so two classes
//! of inbound state were dropped silently:
//!
//! 1. plaintext rustls had already decrypted but the gateway had not read, and
//! 2. residual bytes in rustls's private deframer — the head of a partial TLS
//!    record — which desynchronize the kernel record layer.
//!
//! Class (1) is observable through the public buffered API. Class (2) is not:
//! a session holding a partial inbound record is byte-for-byte
//! indistinguishable, through every public accessor, from a completely idle
//! one. These tests pin that the gate therefore refuses unconditionally, and
//! that refusing never disturbs the session — every application byte stays
//! readable for the userspace relay that takes over.
//!
//! The transport is in memory (`Vec<u8>` pumped between two rustls
//! connections) so record coalescing is exact and nothing depends on socket or
//! thread timing.

use std::io::{Read, Write};
use std::sync::Arc;

use ferrum_edge::tls::NoVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

const OPENING: &[u8] = b"OPENING-CMD-2955";
const CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/certs/server.crt");
const KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/certs/server.key");

/// Bytes withheld from the final application record in the partial-record test.
const WITHHELD_TAIL: usize = 8;

/// Ferrum's production handoff gate, reached through the crate test surface.
fn handoff_allowed(server: &ServerConnection) -> bool {
    ferrum_edge::_test_support::ktls_rustls_buffers_safe_for_kernel_handoff(server)
}

fn test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_pem = std::fs::read(CERT_PATH).expect("read test certificate");
    let key_pem = std::fs::read(KEY_PATH).expect("read test private key");
    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("parse test certificate chain");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse test private key")
        .expect("test private key present");
    (certs, key)
}

/// TLS 1.2 only: that is the sole version `try_ktls_splice` ever hands off, and
/// its abbreviated handshake is what lets a client coalesce Finished with
/// application data.
fn tls12_server_config() -> Arc<ServerConfig> {
    let (certs, key) = test_certs();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 is a supported protocol version")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("test server certificate and key");
    // Session-ID resumption backs the abbreviated-handshake test below.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(32);
    Arc::new(config)
}

fn tls12_client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 is a supported protocol version")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::in_memory_sessions(32);
    Arc::new(config)
}

fn tls12_pair_from(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    let name = ServerName::try_from("localhost").expect("static DNS name");
    let client = ClientConnection::new(client_config, name).expect("client connection");
    let server = ServerConnection::new(server_config).expect("server connection");
    (client, server)
}

/// Drain every TLS record the client currently wants to send.
fn take_client_records(client: &mut ClientConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut out).expect("client write_tls");
    }
    out
}

/// Drain every TLS record the server currently wants to send.
fn take_server_records(server: &mut ServerConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut out).expect("server write_tls");
    }
    out
}

fn feed_client(client: &mut ClientConnection, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let read = client.read_tls(&mut bytes).expect("client read_tls");
        assert!(read > 0, "client read_tls stalled");
        client.process_new_packets().expect("client packets");
    }
}

/// Deliver `bytes` to the server as one logical arrival, then let rustls
/// process whatever became complete. Passing a concatenated handshake flight
/// plus application record reproduces the TCP coalescing from issue #2955.
fn feed_server(server: &mut ServerConnection, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let read = server.read_tls(&mut bytes).expect("server read_tls");
        assert!(read > 0, "server read_tls stalled");
        server.process_new_packets().expect("server packets");
    }
}

/// Pump both directions until neither side is handshaking.
fn drive_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..16 {
        let to_server = take_client_records(client);
        if !to_server.is_empty() {
            feed_server(server, &to_server);
        }
        let to_client = take_server_records(server);
        if !to_client.is_empty() {
            feed_client(client, &to_client);
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    panic!("TLS 1.2 handshake did not converge");
}

/// Buffer application bytes on the client's plaintext writer. Before the
/// handshake completes rustls stages them and flushes them into the same
/// outbound record burst as the client Finished.
fn stage_app_data(client: &mut ClientConnection, data: &[u8]) {
    let mut writer = client.writer();
    writer.write_all(data).expect("stage application data");
}

fn read_plaintext(server: &mut ServerConnection, len: usize) -> Vec<u8> {
    let mut got = vec![0u8; len];
    let mut reader = server.reader();
    reader.read_exact(&mut got).expect("read staged plaintext");
    got
}

/// A completed TLS 1.2 handshake with nothing left on either side — the state a
/// tokio-rustls `accept()` hands to `try_ktls_splice`.
fn completed_tls12_pair() -> (ClientConnection, ServerConnection) {
    let client_cfg = tls12_client_config();
    let server_cfg = tls12_server_config();
    let (mut client, mut server) = tls12_pair_from(client_cfg, server_cfg);
    drive_handshake(&mut client, &mut server);
    (client, server)
}

#[test]
fn clean_buffered_handshake_is_not_treated_as_kernel_handoff_safe() {
    let (_client, mut server) = completed_tls12_pair();

    let io = server.process_new_packets().expect("server packets");
    assert_eq!(io.plaintext_bytes_to_read(), 0);
    assert_eq!(io.tls_bytes_to_write(), 0);
    assert!(server.wants_read());
    assert!(!server.wants_write());
    let version = server.protocol_version();
    assert_eq!(version, Some(rustls::ProtocolVersion::TLSv1_2));

    // A clean IoState is necessary but not sufficient. Nothing observable here
    // proves rustls's private inbound deframer is empty and record-aligned, so
    // the gate must still refuse.
    assert!(!handoff_allowed(&server));
}

#[test]
fn plaintext_buffered_after_handshake_refuses_handoff_and_survives() {
    let (mut client, mut server) = completed_tls12_pair();

    stage_app_data(&mut client, OPENING);
    let record = take_client_records(&mut client);
    feed_server(&mut server, &record);

    let io = server.process_new_packets().expect("server packets");
    assert_eq!(io.plaintext_bytes_to_read(), OPENING.len());
    assert!(!server.wants_read());

    assert!(!handoff_allowed(&server));
    assert_eq!(read_plaintext(&mut server, OPENING.len()), OPENING);
}

#[test]
fn resumed_handshake_coalescing_finished_with_app_data_refuses_handoff() {
    let client_cfg = tls12_client_config();
    let server_cfg = tls12_server_config();

    // Warm-up full handshake so both sides cache a resumable TLS 1.2 session.
    let warm_pair = tls12_pair_from(client_cfg.clone(), server_cfg.clone());
    let (mut warm_client, mut warm_server) = warm_pair;
    drive_handshake(&mut warm_client, &mut warm_server);

    // Abbreviated handshake: the server sends CCS+Finished first, so the
    // client's single reply flight carries CCS, Finished and the opening
    // application record together — the coalescing described in issue #2955.
    let (mut client, mut server) = tls12_pair_from(client_cfg, server_cfg);
    let hello = take_client_records(&mut client);
    feed_server(&mut server, &hello);
    let server_flight = take_server_records(&mut server);
    stage_app_data(&mut client, OPENING);
    feed_client(&mut client, &server_flight);
    assert!(!client.is_handshaking());
    let client_flight = take_client_records(&mut client);
    feed_server(&mut server, &client_flight);

    let kind = server.handshake_kind();
    assert_eq!(kind, Some(rustls::HandshakeKind::Resumed));
    let io = server.process_new_packets().expect("server packets");
    assert_eq!(io.plaintext_bytes_to_read(), OPENING.len());

    // Handing off here is exactly the silent-truncation bug: the kernel would
    // resume from the socket and these bytes would never reach the backend.
    assert!(!handoff_allowed(&server));
    assert_eq!(read_plaintext(&mut server, OPENING.len()), OPENING);
}

#[test]
fn partial_inbound_record_looks_idle_yet_handoff_is_refused() {
    let (mut client, mut server) = completed_tls12_pair();

    stage_app_data(&mut client, OPENING);
    let record = take_client_records(&mut client);
    assert!(record.len() > WITHHELD_TAIL, "expected a full record");

    // Deliver all but the tail of the record. rustls keeps the fragment in its
    // private deframer, which no public accessor reports.
    let split = record.len() - WITHHELD_TAIL;
    feed_server(&mut server, &record[..split]);

    // Observably identical to the clean, idle connection above.
    let io = server.process_new_packets().expect("server packets");
    assert_eq!(io.plaintext_bytes_to_read(), 0);
    assert_eq!(io.tls_bytes_to_write(), 0);
    assert!(server.wants_read());
    assert!(!server.wants_write());

    // Handing off would strand the fragment and desynchronize the kernel
    // record layer, so the gate refuses on this indistinguishable state too.
    assert!(!handoff_allowed(&server));

    // The refusal left the session intact: the record completes normally.
    feed_server(&mut server, &record[split..]);
    assert_eq!(read_plaintext(&mut server, OPENING.len()), OPENING);
}

#[test]
fn handoff_gate_never_consumes_staged_plaintext() {
    let (mut client, mut server) = completed_tls12_pair();

    stage_app_data(&mut client, OPENING);
    let record = take_client_records(&mut client);
    feed_server(&mut server, &record);

    for _ in 0..4 {
        assert!(!handoff_allowed(&server));
        let io = server.process_new_packets().expect("server packets");
        assert_eq!(io.plaintext_bytes_to_read(), OPENING.len());
    }

    assert_eq!(read_plaintext(&mut server, OPENING.len()), OPENING);
}
