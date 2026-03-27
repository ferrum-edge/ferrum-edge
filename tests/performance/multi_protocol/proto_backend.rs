//! Multi-protocol echo backend server for performance testing Ferrum Gateway.
//!
//! Starts servers on the following ports:
//!   HTTP/2 h2c:     3002    HTTPS/H2:  3443
//!   WebSocket:      3003    gRPC h2c:  50052
//!   TCP echo:       3004    TCP+TLS:   3444
//!   UDP echo:       3005    DTLS echo: 3006
//!   HTTP/3 (QUIC):  3445

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, UdpSocket};

use multi_protocol_perf::tls_utils;

// ── gRPC service ─────────────────────────────────────────────────────────────

pub mod bench_proto {
    tonic::include_proto!("bench");
}

use bench_proto::bench_service_server::{BenchService, BenchServiceServer};
use bench_proto::{EchoRequest, EchoResponse};

#[derive(Default)]
struct BenchServiceImpl;

#[tonic::async_trait]
impl BenchService for BenchServiceImpl {
    async fn unary_echo(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        let payload = request.into_inner().payload;
        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;
        Ok(tonic::Response::new(EchoResponse {
            payload,
            timestamp_us,
        }))
    }

    type ServerStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<EchoResponse, tonic::Status>>;

    async fn server_stream(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<Self::ServerStreamStream>, tonic::Status> {
        let payload = request.into_inner().payload;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        tokio::spawn(async move {
            for i in 0..10 {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as i64
                    + i;
                let _ = tx
                    .send(Ok(EchoResponse {
                        payload: payload.clone(),
                        timestamp_us: ts,
                    }))
                    .await;
            }
        });
        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }
}

// ── HTTP handler (shared by HTTP/2 + HTTP/3) ─────────────────────────────────

async fn handle_http(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let resp = match (req.method().clone(), req.uri().path()) {
        (_, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(b"{\"status\":\"healthy\"}")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        (ref m, "/api/users") if m == hyper::Method::GET => {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(
                    b"{\"users\":[{\"id\":1,\"name\":\"Alice\"},{\"id\":2,\"name\":\"Bob\"}]}",
                )))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        }
        (_, "/echo") => {
            use http_body_util::BodyExt;
            let body = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(body))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
    };
    Ok(resp)
}

// ── Servers ──────────────────────────────────────────────────────────────────

/// HTTP/1.1 API server for performance testing.
async fn run_http1_server(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding http1 listener")?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
        });
    }
}

/// Simple HTTP/1.1 health endpoint so all protocol tests have a reliable health check target.
async fn run_http1_health_server(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding http1 health listener")?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
        });
    }
}

async fn run_h2c_server(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding h2c listener")?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
        });
    }
}

async fn run_h2_tls_server(
    addr: SocketAddr,
    tls_cfg: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding h2-tls listener")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let io = TokioIo::new(tls_stream);
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
        });
    }
}

async fn run_ws_server(addr: SocketAddr) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    let listener = TcpListener::bind(addr)
        .await
        .context("binding ws listener")?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                return;
            };
            let (mut write, mut read) = ws.split();
            while let Some(Ok(msg)) = read.next().await {
                if (msg.is_text() || msg.is_binary()) && write.send(msg).await.is_err() {
                    break;
                }
            }
        });
    }
}

async fn run_grpc_server(addr: SocketAddr) -> anyhow::Result<()> {
    tonic::transport::Server::builder()
        .add_service(BenchServiceServer::new(BenchServiceImpl))
        .serve(addr)
        .await
        .context("gRPC server error")
}

async fn run_tcp_echo(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding tcp echo listener")?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let (mut rd, mut wr) = stream.split();
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
    }
}

async fn run_tcp_tls_echo(
    addr: SocketAddr,
    tls_cfg: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding tcp-tls echo listener")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let (mut rd, mut wr) = tokio::io::split(tls_stream);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
    }
}

async fn run_udp_echo(addr: SocketAddr) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(addr)
        .await
        .context("binding udp echo socket")?;
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let _ = sock.send_to(&buf[..n], peer).await;
    }
}

async fn run_h3_server(addr: SocketAddr, server_config: quinn::ServerConfig) -> anyhow::Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, addr).context("creating h3 endpoint")?;

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let Ok(mut conn) =
                h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
            else {
                return;
            };

            while let Ok(Some(resolver)) = conn.accept().await {
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let (status, body) = match req.uri().path() {
                        "/health" => (StatusCode::OK, b"{\"status\":\"healthy\"}" as &[u8]),
                        "/api/users" => (
                            StatusCode::OK,
                            b"{\"users\":[{\"id\":1,\"name\":\"Alice\"},{\"id\":2,\"name\":\"Bob\"}]}"
                                as &[u8],
                        ),
                        _ => (StatusCode::NOT_FOUND, b"not found" as &[u8]),
                    };

                    let resp = http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();

                    let _ = stream.send_response(resp).await;
                    let _ = stream.send_data(bytes::Bytes::copy_from_slice(body)).await;
                    let _ = stream.finish().await;
                });
            }
        });
    }
    Ok(())
}

async fn run_dtls_echo(addr: SocketAddr, cert_path: &str, key_path: &str) -> anyhow::Result<()> {
    use webrtc_dtls::config::Config as DtlsConfig;
    use webrtc_dtls::crypto::Certificate as DtlsCert;
    use webrtc_dtls::listener;
    use webrtc_util::conn::Listener;

    // from_pem expects key PEM before cert PEM
    let cert_pem = std::fs::read_to_string(cert_path).context("reading DTLS cert")?;
    let key_pem = std::fs::read_to_string(key_path).context("reading DTLS key")?;
    let key_pem = key_pem
        .replace("BEGIN PRIVATE KEY", "BEGIN PRIVATE_KEY")
        .replace("END PRIVATE KEY", "END PRIVATE_KEY");
    let combined_pem = format!("{key_pem}\n{cert_pem}");
    let cert = DtlsCert::from_pem(&combined_pem)
        .map_err(|e| anyhow::anyhow!("loading DTLS certificate: {e}"))?;

    let cfg = DtlsConfig {
        certificates: vec![cert],
        ..Default::default()
    };

    let listener = listener::listen(addr.to_string(), cfg)
        .await
        .map_err(|e| anyhow::anyhow!("DTLS listener bind error: {e}"))?;

    loop {
        let (conn, _peer): (Arc<dyn webrtc_util::Conn + Send + Sync>, SocketAddr) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("DTLS accept error: {e}"))?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match conn.recv(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                if conn.send(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Generate self-signed certs for TLS/DTLS servers
    let cert_dir = std::env::current_dir()?.join("certs");
    let (cert_path, key_path) =
        tls_utils::generate_self_signed_certs(&cert_dir).context("generating certs")?;

    let tls_cfg = Arc::new(
        tls_utils::make_server_tls_config(&cert_path, &key_path)
            .context("building server TLS config")?,
    );
    let h3_cfg = tls_utils::make_h3_server_config(&cert_path, &key_path)
        .context("building H3 server config")?;

    println!("Multi-Protocol Backend Server");
    println!("=============================");
    println!("HTTP/1.1 API:     127.0.0.1:3001");
    println!("HTTP/1.1 Health:  127.0.0.1:3010");
    println!("HTTP/2 (h2c):    127.0.0.1:3002");
    println!("HTTPS/H2 (TLS):  127.0.0.1:3443");
    println!("WebSocket:        127.0.0.1:3003");
    println!("gRPC (h2c):       127.0.0.1:50052");
    println!("TCP Echo:          127.0.0.1:3004");
    println!("TCP+TLS Echo:      127.0.0.1:3444");
    println!("UDP Echo:          127.0.0.1:3005");
    println!("HTTP/3 (QUIC):     127.0.0.1:3445");
    println!("DTLS Echo:         127.0.0.1:3006");
    println!("=============================");

    let cert_str = cert_path.to_string_lossy().to_string();
    let key_str = key_path.to_string_lossy().to_string();

    // Spawn all servers independently so one failure doesn't kill the rest
    tokio::spawn(async {
        if let Err(e) = run_http1_server("127.0.0.1:3001".parse().unwrap()).await {
            eprintln!("http1 server error: {e}");
        }
    });
    tokio::spawn(async {
        if let Err(e) = run_http1_health_server("127.0.0.1:3010".parse().unwrap()).await {
            eprintln!("http1 health error: {e}");
        }
    });
    tokio::spawn(async {
        if let Err(e) = run_h2c_server("127.0.0.1:3002".parse().unwrap()).await {
            eprintln!("h2c server error: {e}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = run_h2_tls_server("127.0.0.1:3443".parse().unwrap(), tls_cfg.clone()).await
        {
            eprintln!("h2-tls server error: {e}");
        }
    });
    tokio::spawn(async {
        if let Err(e) = run_ws_server("127.0.0.1:3003".parse().unwrap()).await {
            eprintln!("ws server error: {e}");
        }
    });
    tokio::spawn(async {
        if let Err(e) = run_grpc_server("127.0.0.1:50052".parse().unwrap()).await {
            eprintln!("grpc server error: {e}");
        }
    });
    tokio::spawn(async {
        if let Err(e) = run_tcp_echo("127.0.0.1:3004".parse().unwrap()).await {
            eprintln!("tcp echo error: {e}");
        }
    });
    {
        let tls_cfg2 = Arc::new(
            tls_utils::make_server_tls_config(&cert_path, &key_path)
                .context("building tcp-tls server config")?,
        );
        tokio::spawn(async move {
            if let Err(e) = run_tcp_tls_echo("127.0.0.1:3444".parse().unwrap(), tls_cfg2).await {
                eprintln!("tcp-tls echo error: {e}");
            }
        });
    }
    tokio::spawn(async {
        if let Err(e) = run_udp_echo("127.0.0.1:3005".parse().unwrap()).await {
            eprintln!("udp echo error: {e}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = run_h3_server("127.0.0.1:3445".parse().unwrap(), h3_cfg).await {
            eprintln!("h3 server error: {e}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = run_dtls_echo("127.0.0.1:3006".parse().unwrap(), &cert_str, &key_str).await
        {
            eprintln!("dtls echo error: {e}");
        }
    });

    // Wait for ctrl-c
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");
    Ok(())
}
