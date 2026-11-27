//! Unit tests for per-core `current_thread` relay shards (`relay_shards`),
//! `RehomedTlsStream`, `PrefixedIo`, and `ClientWriteStallIo` detach/reattach.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::proxy::client_write_stall::ClientWriteStallIo;
use ferrum_edge::proxy::relay_shards::{
    DropArcOnMainRuntime, PrefixedIo, RehomedTlsStream, RelayShardPool, resolve_shard_count,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn test_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key = rcgen::KeyPair::generate_for(ecdsa).expect("leaf key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key).expect("self-signed leaf");

    let certs = CertificateDer::pem_slice_iter(cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse test leaf certificate");
    let private_key =
        PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).expect("parse test leaf key");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("test TLS server config");
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ferrum_edge::tls::NoVerifier))
        .with_no_client_auth();

    (Arc::new(server), Arc::new(client))
}

#[test]
fn resolve_shard_count_clamps_configured_bounds() {
    assert_eq!(resolve_shard_count(Some(0)), 1);
    assert_eq!(resolve_shard_count(Some(4)), 4);
    assert_eq!(resolve_shard_count(Some(128)), 64);
    let auto = resolve_shard_count(None);
    assert!((1..=64).contains(&auto));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_shard_pool_distributes_connections_round_robin_and_shuts_down_cleanly() {
    let (pool, guard) = RelayShardPool::new(3).expect("spawn 3 relay shards");
    assert_eq!(pool.shard_count(), 3);

    let mut thread_ids = HashSet::new();
    for _ in 0..6 {
        let handle = pool.next_handle();
        let tid = handle
            .spawn(async move { std::thread::current().id() })
            .await
            .expect("shard task completed");
        thread_ids.insert(tid);
    }
    assert_eq!(
        thread_ids.len(),
        3,
        "round-robin dispatch must hit every shard thread"
    );

    // Verify a TCP socket accepted on the main runtime can be detached via
    // `into_std`, re-registered on a shard, and echo bytes cleanly.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let connect_fut = TcpStream::connect(addr);
    let accept_fut = listener.accept();
    let (client_res, accept_res) = tokio::join!(connect_fut, accept_fut);
    let mut client = client_res.expect("connect");
    let (server, _) = accept_res.expect("accept");

    let std_server = server.into_std().expect("detach accepted TcpStream");
    let shard_task = pool.next_handle().spawn(async move {
        let mut s = TcpStream::from_std(std_server).expect("re-register on shard");
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.expect("shard read");
        s.write_all(&buf[..n]).await.expect("shard write");
        s.shutdown().await.expect("shard shutdown");
    });

    client.write_all(b"hello-relay-shard").await.expect("write");
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.expect("read");
    assert_eq!(echoed, b"hello-relay-shard");
    shard_task.await.expect("shard task join");

    drop(pool);
    drop(guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehomed_tls_stream_round_trips_prefix_large_payloads_and_clean_close_notify() {
    let (server_cfg, client_cfg) = test_tls_configs();
    let (pool, guard) = RelayShardPool::new(2).expect("spawn relay shards");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let server_name = ServerName::try_from("localhost").expect("server name");

    let (client_tls, server_tls) = tokio::join!(
        async {
            let tcp = TcpStream::connect(addr).await.expect("connect");
            connector
                .connect(server_name, tcp)
                .await
                .expect("client TLS handshake")
        },
        async {
            let (tcp, _) = listener.accept().await.expect("accept");
            acceptor.accept(tcp).await.expect("server TLS handshake")
        }
    );

    // Detach BOTH client and server TLS streams onto separate relay shards.
    let (server_tcp, server_session) = server_tls.into_inner();
    let std_server_tcp = server_tcp.into_std().expect("detach server tcp");
    let (client_tcp, client_session) = client_tls.into_inner();
    let std_client_tcp = client_tcp.into_std().expect("detach client tcp");

    let prefix = Bytes::from_static(b"PREFIX:");
    let payload: Vec<u8> = (0..(64 * 1024 + 333)).map(|i| (i % 251) as u8).collect();
    let expected_server_read = {
        let mut v = prefix.to_vec();
        v.extend_from_slice(&payload);
        v
    };

    let server_task = pool.next_handle().spawn(async move {
        let tcp = TcpStream::from_std(std_server_tcp).expect("re-register server tcp");
        let mut tls = RehomedTlsStream::new(tcp, server_session, prefix);
        let mut received = Vec::with_capacity(expected_server_read.len());
        tls.read_to_end(&mut received)
            .await
            .expect("server read_to_end after clean close_notify");
        assert_eq!(received, expected_server_read);
        tls.write_all(b"server-ack").await.expect("server write");
        tls.flush().await.expect("server flush");
        tls.shutdown().await.expect("server close_notify shutdown");
    });

    let payload_to_send = payload.clone();
    let client_task = pool.next_handle().spawn(async move {
        let tcp = TcpStream::from_std(std_client_tcp).expect("re-register client tcp");
        let mut tls = RehomedTlsStream::new(tcp, client_session, Bytes::new());
        tls.write_all(&payload_to_send).await.expect("client write");
        tls.flush().await.expect("client flush");
        tls.shutdown().await.expect("client close_notify shutdown");
        let mut ack = Vec::new();
        tls.read_to_end(&mut ack)
            .await
            .expect("client read_to_end after server close_notify");
        assert_eq!(ack, b"server-ack");
    });

    server_task.await.expect("server shard task");
    client_task.await.expect("client shard task");

    drop(pool);
    drop(guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehomed_tls_stream_reports_unexpected_eof_without_close_notify() {
    let (server_cfg, client_cfg) = test_tls_configs();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let server_name = ServerName::try_from("localhost").expect("server name");

    let (mut client_tls, server_tls) = tokio::join!(
        async {
            let tcp = TcpStream::connect(addr).await.expect("connect");
            connector
                .connect(server_name, tcp)
                .await
                .expect("client TLS handshake")
        },
        async {
            let (tcp, _) = listener.accept().await.expect("accept");
            acceptor.accept(tcp).await.expect("server TLS handshake")
        }
    );

    let (server_tcp, server_session) = server_tls.into_inner();
    let mut rehomed_server = RehomedTlsStream::new(server_tcp, server_session, Bytes::new());

    // Write one TLS record, flush it, then half-close ONLY the raw TCP write
    // side without sending TLS `close_notify` (keeping `client_tcp` open so
    // unread TLS 1.3 post-handshake session tickets do not trigger a TCP RST
    // on Linux when the socket closes).
    client_tls
        .write_all(b"before-truncation")
        .await
        .expect("write");
    client_tls.flush().await.expect("flush");
    let (mut client_tcp, _client_session) = client_tls.into_inner();
    client_tcp
        .shutdown()
        .await
        .expect("raw tcp write half-close");

    // The valid record must be delivered intact before the trailing
    // UnexpectedEof surfaces (matching `tokio-rustls` deferred-error behavior).
    let mut first = [0u8; 64];
    let n = rehomed_server
        .read(&mut first)
        .await
        .expect("valid plaintext before unclean EOF");
    assert_eq!(&first[..n], b"before-truncation");

    let err = rehomed_server
        .read(&mut first)
        .await
        .expect_err("unclean TCP EOF without close_notify must error");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert!(
        err.to_string().contains("without sending TLS close_notify"),
        "expected rustls close_notify message, got: {err}"
    );
    drop(client_tcp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehomed_tls_stream_preserves_deferred_error_order_and_connection_aborted_eof() {
    let (server_cfg, client_cfg) = test_tls_configs();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let server_name = ServerName::try_from("localhost").expect("server name");

    let (_client_tls, server_tls) = tokio::join!(
        async {
            let tcp = TcpStream::connect(addr).await.expect("connect");
            connector
                .connect(server_name, tcp)
                .await
                .expect("client TLS handshake")
        },
        async {
            let (tcp, _) = listener.accept().await.expect("accept");
            acceptor.accept(tcp).await.expect("server TLS handshake")
        }
    );

    let (server_tcp, server_session) = server_tls.into_inner();
    let mut rehomed = RehomedTlsStream::with_deferred_read_error(
        server_tcp,
        server_session,
        Bytes::from_static(b"pre-bytes"),
        Some(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "simulated transport abort",
        )),
    );

    // 1. Prefix bytes must arrive first.
    let mut buf = [0u8; 32];
    let n = rehomed
        .read(&mut buf)
        .await
        .expect("prefix delivered first");
    assert_eq!(&buf[..n], b"pre-bytes");

    // 2. Deferred ConnectionAborted surfaces next.
    let err = rehomed
        .read(&mut buf)
        .await
        .expect_err("deferred ConnectionAborted must surface after prefix");
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);

    // 3. Subsequent reads see clean EOF (read_eof transition matching tokio-rustls).
    let eof = rehomed
        .read(&mut buf)
        .await
        .expect("reads after ConnectionAborted must return clean EOF");
    assert_eq!(eof, 0);
}

#[tokio::test]
async fn prefixed_io_yields_prefix_then_inner_bytes() {
    let (mut client, server) = tokio::io::duplex(256);
    let mut prefixed = PrefixedIo::new(server, Bytes::from_static(b"pre-"));

    client.write_all(b"body").await.expect("write body");
    client.shutdown().await.expect("shutdown");

    let mut out = Vec::new();
    prefixed.read_to_end(&mut out).await.expect("read_to_end");
    assert_eq!(out, b"pre-body");
}

#[tokio::test]
async fn client_write_stall_io_detaches_when_idle_and_refuses_when_armed() {
    let (client, _peer) = tokio::io::duplex(64);
    let stall = ClientWriteStallIo::new(client, 30);
    assert!(stall.can_detach());
    let (inner, timeout) = stall.try_into_parts().ok().expect("idle stall detaches");
    assert_eq!(timeout, Some(Duration::from_secs(30)));
    let rebuilt = ClientWriteStallIo::from_parts(inner, timeout);
    assert!(rebuilt.can_detach());
    assert!(!rebuilt.is_expired());

    // Fill a tiny duplex buffer so a write parks (`Pending`), arming the stall timer.
    let (small_client, _unread_peer) = tokio::io::duplex(16);
    let mut armed_stall = ClientWriteStallIo::new(small_client, 30);
    let payload = [b'x'; 64];
    {
        let mut fut = std::pin::pin!(armed_stall.write_all(&payload));
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(std::future::Future::poll(fut.as_mut(), &mut cx).is_pending());
    }

    assert!(
        !armed_stall.can_detach(),
        "armed write-stall timer must refuse cross-runtime detach"
    );
    assert!(armed_stall.try_into_parts().is_err());
}

#[tokio::test]
async fn drop_arc_on_main_runtime_drops_inner_inline_when_no_global_pool_is_installed() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FlagDrop(Arc<AtomicBool>);
    impl Drop for FlagDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    {
        let guard = DropArcOnMainRuntime::new(Arc::new(FlagDrop(Arc::clone(&dropped))));
        assert!(!guard.0.load(Ordering::SeqCst));
    }
    assert!(
        dropped.load(Ordering::SeqCst),
        "DropArcOnMainRuntime must drop its value when no global shard pool is active"
    );
}
