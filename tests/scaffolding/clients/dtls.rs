//! DTLS client for scripted-backend tests.
//!
//! Wraps `ferrum_edge::dtls::DtlsConnection` so a test can assert against
//! a gateway's DTLS frontend (or a scripted DTLS backend) with the same
//! ergonomics as [`super::udp::UdpClient`]. The underlying crypto is the
//! production code path — `dimpl`, ECDSA P-256, handshake timing from
//! the gateway's defaults — so tests exercise the same DTLS behaviour
//! the gateway itself does.
//!
//! ## SNI
//!
//! Phase 4 test #3 needs SNI-routed DTLS passthrough. The `dimpl` crate
//! does NOT currently emit the SNI (`server_name`, extension type
//! 0x0000) extension in its ClientHello (its `server_name` parameter
//! feeds server-cert hostname verification only — see
//! `src/dtls/mod.rs::BackendDtlsParams`). Because Phase 4 test #3 tests
//! the gateway's DTLS passthrough SNI-peek path — which requires an SNI
//! extension in the ClientHello — we can't use `dimpl` to generate the
//! ClientHello for that test.
//!
//! For test #3 specifically, [`dtls_client_hello_with_sni`] in this
//! module emits a **minimum-viable DTLS 1.2 ClientHello** record that
//! includes the `server_name` extension. It is not intended as a
//! general-purpose DTLS client — it never completes a handshake — it
//! exists so the gateway's SNI-peek logic has something to peek at.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dimpl::Config as DimplConfig;
use ferrum_edge::dtls::{BackendDtlsParams, DtlsConnection};
use tokio::net::UdpSocket;

/// A DTLS client connected to a specific peer.
pub struct DtlsClient {
    inner: DtlsConnection,
}

impl DtlsClient {
    /// Connect and complete the DTLS handshake. `peer` is the UDP
    /// destination; SNI defaults to `None` (no server_name sent).
    pub async fn connect(
        peer: impl Into<SocketAddr>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::connect_with_sni(peer, None::<&str>).await
    }

    /// Like [`Self::connect`] but allows the caller to supply an SNI
    /// hostname for the DTLS ClientHello.
    pub async fn connect_with_sni(
        peer: impl Into<SocketAddr>,
        sni: Option<impl AsRef<str>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure rustls crypto provider is installed before generating
        // the ephemeral client cert.
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let peer = peer.into();
        socket.connect(peer).await?;

        let certificate = dimpl::certificate::generate_self_signed_certificate()
            .map_err(|e| format!("generate client dtls cert: {e}"))?;

        let server_name = match sni {
            Some(s) => Some(
                rustls::pki_types::ServerName::try_from(s.as_ref().to_string())
                    .map_err(|e| format!("invalid SNI {:?}: {e}", s.as_ref()))?,
            ),
            None => None,
        };

        let params = BackendDtlsParams {
            config: Arc::new(DimplConfig::default()),
            certificate,
            server_name,
            server_cert_verifier: None,
        };

        let inner = tokio::time::timeout(
            Duration::from_secs(15),
            DtlsConnection::connect(socket, params),
        )
        .await
        .map_err(|_| "DTLS handshake timeout".to_string())??;

        Ok(Self { inner })
    }

    /// Send application data through the DTLS tunnel.
    pub async fn send_datagram(
        &self,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.send(bytes).await.map_err(|e| e.into())
    }

    /// Wait up to `deadline` for decrypted application data.
    pub async fn recv_datagram_with_timeout(
        &self,
        deadline: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        match tokio::time::timeout(deadline, self.inner.recv()).await {
            Ok(Ok(data)) => Ok(data),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err("DTLS recv timed out".into()),
        }
    }

    /// Close the DTLS connection.
    pub async fn close(self) {
        self.inner.close().await;
    }
}

/// Build a minimal DTLS 1.2 ClientHello datagram that includes the
/// `server_name` (SNI) extension pointing at `sni`.
///
/// Purpose: the gateway's DTLS passthrough path peeks at the first
/// datagram for an SNI extension and dispatches by host. `dimpl`'s
/// ClientHello (used by the production `DtlsConnection`) does not emit
/// SNI — so we hand-roll a ClientHello just rich enough for the
/// gateway's peek code (`src/proxy/sni.rs::extract_sni_from_dtls_client_hello`)
/// to parse. The handshake never completes; the record is "just
/// enough" to exercise the SNI-peek + proxy-routing branch.
///
/// Byte layout (RFC 6347 §4.2 + RFC 6066 §3):
///
///   DTLS record header (13 bytes):
///     content_type = 0x16 (Handshake)
///     version      = 0xFEFD (DTLS 1.2)
///     epoch        = 0x0000
///     seqno        = 0x000000000000
///     length       = <rest of record>
///
///   DTLS handshake header (12 bytes):
///     msg_type         = 0x01 (ClientHello)
///     length           = <fragment length>
///     message_seq      = 0x0000
///     fragment_offset  = 0x000000
///     fragment_length  = <same as length>
///
///   ClientHello body:
///     version      = 0xFEFD
///     random       = 32 zero bytes (deterministic for tests)
///     session_id   = 1 byte len = 0x00
///     cookie       = 1 byte len = 0x00
///     cipher_suites = 2-byte len + 2 bytes (0x00,0x9E = TLS_DHE_RSA_AES128_GCM_SHA256)
///     compression  = 1-byte len = 0x01 + 1 byte (0x00 = null)
///     extensions   = 2-byte len + SNI extension
///
///   SNI extension (RFC 6066 §3):
///     type         = 0x0000
///     ext_len      = 2 + 1 + 2 + len(sni)
///     list_len     = 3 + len(sni)
///     name_type    = 0x00 (host_name)
///     name_len     = 2-byte len(sni)
///     name         = sni bytes
pub fn dtls_client_hello_with_sni(sni: &str) -> Vec<u8> {
    let sni = sni.as_bytes();
    let name_len = sni.len() as u16;
    let list_len = 3u16 + name_len;
    let ext_data_len = 2u16 + list_len;

    // SNI extension body (type + len + data).
    let mut sni_ext = Vec::with_capacity(4 + ext_data_len as usize);
    sni_ext.extend_from_slice(&[0x00, 0x00]); // extension_type = server_name (0x0000)
    sni_ext.extend_from_slice(&ext_data_len.to_be_bytes()); // extension_data length
    sni_ext.extend_from_slice(&list_len.to_be_bytes()); // server_name_list length
    sni_ext.push(0x00); // name_type = host_name
    sni_ext.extend_from_slice(&name_len.to_be_bytes()); // HostName length
    sni_ext.extend_from_slice(sni); // HostName

    let extensions_len = sni_ext.len() as u16;

    // ClientHello body.
    let mut body = Vec::with_capacity(64 + extensions_len as usize);
    body.extend_from_slice(&[0xFE, 0xFD]); // client_version = DTLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random (deterministic)
    body.push(0x00); // session_id length
    body.push(0x00); // cookie length
    body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length = 2
    body.extend_from_slice(&[0x00, 0x9E]); // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    body.push(0x01); // compression_methods length = 1
    body.push(0x00); // null compression
    body.extend_from_slice(&extensions_len.to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let body_len = body.len();

    // DTLS handshake header.
    let mut handshake = Vec::with_capacity(12 + body_len);
    handshake.push(0x01); // msg_type = ClientHello
    // length (3 bytes) = body_len.
    handshake.extend_from_slice(&[
        ((body_len >> 16) & 0xFF) as u8,
        ((body_len >> 8) & 0xFF) as u8,
        (body_len & 0xFF) as u8,
    ]);
    handshake.extend_from_slice(&[0x00, 0x00]); // message_seq
    handshake.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
    handshake.extend_from_slice(&[
        ((body_len >> 16) & 0xFF) as u8,
        ((body_len >> 8) & 0xFF) as u8,
        (body_len & 0xFF) as u8,
    ]); // fragment_length = body_len
    handshake.extend_from_slice(&body);

    let record_len = handshake.len() as u16;

    // DTLS record header.
    let mut record = Vec::with_capacity(13 + handshake.len());
    record.push(0x16); // content_type = Handshake
    record.extend_from_slice(&[0xFE, 0xFD]); // version = DTLS 1.2
    record.extend_from_slice(&[0x00, 0x00]); // epoch
    record.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seqno
    record.extend_from_slice(&record_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtls_client_hello_with_sni_is_parseable_by_the_gateway_sni_peek() {
        let hello = dtls_client_hello_with_sni("backend-a.test");
        let extracted = ferrum_edge::proxy::sni::extract_sni_from_dtls_client_hello(&hello);
        assert_eq!(extracted.as_deref(), Some("backend-a.test"));
    }

    #[test]
    fn dtls_client_hello_with_sni_lowercases_for_the_gateway() {
        // The gateway lowercases before matching; ensure the extracted
        // string is what we expect the gateway to see.
        let hello = dtls_client_hello_with_sni("Backend-B.Test");
        let extracted = ferrum_edge::proxy::sni::extract_sni_from_dtls_client_hello(&hello);
        assert_eq!(extracted.as_deref(), Some("backend-b.test"));
    }
}
