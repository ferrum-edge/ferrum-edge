//! `TlsBackendWithoutQuic` — TCP+TLS backend that advertises `h2` +
//! `http/1.1` in ALPN but has NO QUIC listener on the same port.
//!
//! Used to test the gateway's initial capability probe behaviour: it should
//! classify `h2_tls = Supported` and `h3 = Unsupported` when the backend is
//! reachable via TCP but not QUIC.
//!
//! This is a thin helper that pairs a [`super::tls::ScriptedTlsBackend`]
//! (with `h2` + `http/1.1` ALPN) with an explicit "no UDP bound on this
//! port" contract. Since the TLS backend binds TCP only, the UDP side is
//! naturally absent — callers rely on the port's UDP half remaining
//! unbound.
//!
//! Behavior: any client (typically the gateway's H2 pool warmup) that
//! connects via TCP completes the TLS + ALPN handshake; any client that
//! tries QUIC on the same port sees ICMP `port unreachable` (no UDP
//! listener), which the gateway classifies as `ConnectionRefused`.

use tokio::net::TcpListener;

use super::tcp::TcpStep;
use super::tls::{ScriptedTlsBackend, ScriptedTlsBackendBuilder, TlsConfig};

/// Build a TCP+TLS backend that advertises `h2` and `http/1.1` in ALPN
/// but has nothing listening on the UDP side of the same port.
///
/// Returns a builder the caller can extend with a response script (e.g.
/// write a canned HTTP/1.1 OK response so the gateway's pool probe
/// considers the connection viable).
pub fn tls_backend_without_quic(
    listener: TcpListener,
    cert_pem: String,
    key_pem: String,
) -> ScriptedTlsBackendBuilder {
    ScriptedTlsBackend::builder(
        listener,
        TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
}

/// Same as [`tls_backend_without_quic`] but pre-wired with a minimal script
/// that reads an HTTP/1.1 request prelude (so the gateway's ALPN-learning
/// pool probe passes) and writes a 200 OK response. Use when tests don't
/// care about the request semantics — they only need the TCP path to be
/// healthy while the UDP path is silent.
pub fn tls_backend_without_quic_with_ok_response(
    listener: TcpListener,
    cert_pem: String,
    key_pem: String,
) -> ScriptedTlsBackend {
    let response: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    tls_backend_without_quic(listener, cert_pem, key_pem)
        .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
        .step(TcpStep::Write(response))
        .step(TcpStep::Drop)
        .spawn()
        .expect("tls_backend_without_quic spawn")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::certs::TestCa;
    use crate::scaffolding::ports::reserve_port;

    #[tokio::test]
    async fn builder_sets_alpn_with_h2_and_http1() {
        let ca = TestCa::new("tls-no-quic-test").expect("ca");
        let (cert, key) = ca.valid().expect("leaf");
        let reservation = reserve_port().await.expect("port");
        let _backend =
            tls_backend_without_quic_with_ok_response(reservation.into_listener(), cert, key);
        // Smoke: spawn succeeds, handshake state starts at zero. The
        // real behaviour (H2 pool probe against this backend) is
        // exercised by the Phase-3 acceptance tests.
    }
}
