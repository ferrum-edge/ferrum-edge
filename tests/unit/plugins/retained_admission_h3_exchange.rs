//! One real QUIC request with a deliberately small client receive window.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;

pub(super) struct Exchange {
    pub server_stream: Option<h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>,
    pub client_stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _server_connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _endpoints: (quinn::Endpoint, quinn::Endpoint),
    client_driver: tokio::task::JoinHandle<()>,
}

impl Drop for Exchange {
    fn drop(&mut self) {
        self.client_driver.abort();
    }
}

pub(super) async fn exchange() -> Exchange {
    let _ = ferrum_edge::fips::base_crypto_provider().install_default();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let mut server_crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let runtime = quinn::default_runtime().unwrap();
    let server_socket = std::net::UdpSocket::bind(loopback).unwrap();
    server_socket.set_nonblocking(true).unwrap();
    let server = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        server_socket,
        Arc::clone(&runtime),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(1024u32.into());
    transport.receive_window(1024u32.into());
    client_config.transport_config(Arc::new(transport));
    let client_socket = std::net::UdpSocket::bind(loopback).unwrap();
    client_socket.set_nonblocking(true).unwrap();
    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        client_socket,
        runtime,
    )
    .unwrap();
    client.set_default_client_config(client_config);

    let accept_endpoint = server.clone();
    let accept = tokio::spawn(async move {
        let connection = accept_endpoint.accept().await.unwrap().await.unwrap();
        let mut server_connection: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = server_connection.accept().await.unwrap().unwrap();
        let (_, stream) = resolver.resolve_request().await.unwrap();
        (server_connection, stream)
    });
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
    let client_driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .unwrap();
    let mut client_stream = send_request.send_request(request).await.unwrap();
    client_stream.finish().await.unwrap();
    let (server_connection, server_stream) = accept.await.unwrap();
    Exchange {
        server_stream: Some(server_stream),
        client_stream,
        _server_connection: server_connection,
        _send_request: send_request,
        _endpoints: (server, client),
        client_driver,
    }
}
