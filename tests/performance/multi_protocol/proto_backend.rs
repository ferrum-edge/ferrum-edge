//! Multi-protocol echo backend server for performance testing Ferrum Edge.
//!
//! Starts servers on the following ports:
//!   HTTP/2 h2c:     3002    HTTPS/H2:  3443
//!   WebSocket:      3003    WSS:       3446
//!   TCP echo:       3004    TCP+TLS:   3444
//!   UDP echo:       3005    DTLS echo: 3006
//!   HTTP/3 (QUIC):  3445    H1+TLS:    3447
//!   gRPC h2c:      50052    gRPC+TLS: 50053
//!
//! `--h3-only` serves only QUIC 3445 and HTTP health 3010 for the H3 proof lane.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, UdpSocket};

use multi_protocol_perf::h2_observation::Observer;
use multi_protocol_perf::tls_utils;

// ── gRPC service ─────────────────────────────────────────────────────────────

pub mod bench_proto {
    tonic::include_proto!("bench");
}

use bench_proto::bench_service_server::{BenchService, BenchServiceServer};
use bench_proto::{EchoRequest, EchoResponse};

// Max inbound+outbound protobuf message size for the bench gRPC service.
// tonic defaults to 4 MiB; the benchmark sweeps payloads up to 5 MiB, so
// keep client (proto_bench) and server (proto_backend) in lockstep here.
const GRPC_MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

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

/// Response body for the HTTP handler.
///
/// Boxed rather than `Full<Bytes>` because `/trickle` must emit its frames over
/// time; every other route still answers with a one-shot `Full`.
type BackendBody = BoxBody<Bytes, Infallible>;

fn one_shot(bytes: Bytes) -> BackendBody {
    Full::new(bytes).boxed()
}

/// Bytes reserved at the head of every `/trickle` frame for its emission
/// timestamp: `TS:` + 16 digits of microseconds-since-epoch + `;`.
pub const TRICKLE_STAMP_LEN: usize = 20;

/// Parse a bounded unsigned query parameter, falling back to `default`.
fn query_param(query: Option<&str>, key: &str, default: u64, max: u64) -> u64 {
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .unwrap_or(default)
        .min(max)
}

async fn handle_http(req: Request<Incoming>) -> Result<Response<BackendBody>, Infallible> {
    let resp = match (req.method().clone(), req.uri().path()) {
        (_, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(one_shot(Bytes::from_static(b"{\"status\":\"healthy\"}")))
            .unwrap_or_else(|_| Response::new(one_shot(Bytes::new()))),
        (ref m, "/api/users") if m == hyper::Method::GET => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(one_shot(Bytes::from_static(
                b"{\"users\":[{\"id\":1,\"name\":\"Alice\"},{\"id\":2,\"name\":\"Bob\"}]}",
            )))
            .unwrap_or_else(|_| Response::new(one_shot(Bytes::new()))),
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
                .body(one_shot(body))
                .unwrap_or_else(|_| Response::new(one_shot(Bytes::new())))
        }
        // Trickle: emit `frames` frames of `size` bytes, `gap_ms` apart. This is
        // the shape a response-aggregation window can actually hurt — an SSE or
        // long-poll stream whose frames are small and far apart, where holding
        // one back to wait for a sibling adds latency no throughput gain offsets.
        // The emission schedule is deterministic, so a client can compare each
        // frame's arrival against when it is known to have been sent.
        (_, "/trickle") => {
            let query = req.uri().query().map(str::to_string);
            let frames = query_param(query.as_deref(), "frames", 20, 10_000);
            let size = query_param(query.as_deref(), "size", 1024, 1 << 20) as usize;
            let gap_ms = query_param(query.as_deref(), "gap_ms", 10, 60_000);
            // Each frame opens with its own emission timestamp. A client that
            // subtracts the NOMINAL schedule instead measures the accumulated
            // overshoot of `sleep` rather than anything the gateway did: the
            // residual grows linearly with frame index and swamps a hold of a
            // millisecond or two. Stamping the real emission time makes each
            // frame's latency a direct measurement. Both processes are on one
            // host, so a shared wall clock is the right reference.
            let size = size.max(TRICKLE_STAMP_LEN);
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(1);
            tokio::spawn(async move {
                for index in 0..frames {
                    // Gap BEFORE every frame but the first, so frame k is sent at
                    // k * gap_ms and the first byte is not itself delayed.
                    if index > 0 && gap_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(gap_ms)).await;
                    }
                    let micros = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_micros() as u64)
                        .unwrap_or(0);
                    let mut frame = vec![b'x'; size];
                    frame[..TRICKLE_STAMP_LEN]
                        .copy_from_slice(format!("TS:{micros:016};").as_bytes());
                    if tx.send(Ok(Frame::data(Bytes::from(frame)))).await.is_err() {
                        break;
                    }
                }
            });
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-store")
                .body(StreamBody::new(stream).boxed())
                .unwrap_or_else(|_| Response::new(one_shot(Bytes::new())))
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(one_shot(Bytes::from_static(b"not found")))
            .unwrap_or_else(|_| Response::new(one_shot(Bytes::new()))),
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
        let _ = stream.set_nodelay(true);
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
    let observer = Observer::new(
        std::env::var("BENCH_H2_OBSERVE").as_deref() == Ok("1"),
        "backend_h2c",
        true,
    );
    let listener = TcpListener::bind(addr)
        .await
        .context("binding h2c listener")?;
    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let observer = observer.clone();
        let connection_id = observer.connection_id();
        tokio::spawn(async move {
            observer.record(connection_id, None, None, "connection_opened", None);
            let io = TokioIo::new(stream);
            let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(8_388_608) // 8 MiB
                .initial_connection_window_size(33_554_432) // 32 MiB
                .adaptive_window(true)
                .max_frame_size(1_048_576) // 1 MiB
                .max_concurrent_streams(1000)
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
            observer.record(
                connection_id,
                None,
                None,
                "driver_terminated",
                result.as_ref().err().map(|e| e as &dyn std::error::Error),
            );
        });
    }
}

async fn run_h1_tls_server(
    addr: SocketAddr,
    tls_cfg: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .context("binding h1-tls listener")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let io = TokioIo::new(tls_stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
        });
    }
}

async fn run_h2_tls_server(
    addr: SocketAddr,
    tls_cfg: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let observer = Observer::new(
        std::env::var("BENCH_H2_OBSERVE").as_deref() == Ok("1"),
        "backend_h2_tls",
        true,
    );
    let listener = TcpListener::bind(addr)
        .await
        .context("binding h2-tls listener")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        let observer = observer.clone();
        let connection_id = observer.connection_id();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            observer.record(connection_id, None, None, "connection_opened", None);
            let io = TokioIo::new(tls_stream);
            let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(8_388_608) // 8 MiB
                .initial_connection_window_size(33_554_432) // 32 MiB
                .adaptive_window(true)
                .max_frame_size(1_048_576) // 1 MiB
                .max_concurrent_streams(1000)
                .serve_connection(io, hyper::service::service_fn(handle_http))
                .await;
            observer.record(
                connection_id,
                None,
                None,
                "driver_terminated",
                result.as_ref().err().map(|e| e as &dyn std::error::Error),
            );
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
        let _ = stream.set_nodelay(true);
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

async fn run_wss_server(
    addr: SocketAddr,
    tls_cfg: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    let listener = TcpListener::bind(addr)
        .await
        .context("binding wss listener")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let Ok(ws) = tokio_tungstenite::accept_async(tls_stream).await else {
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
        .initial_stream_window_size(8_388_608) // 8 MiB (vs 64 KB default)
        .initial_connection_window_size(33_554_432) // 32 MiB
        .tcp_nodelay(true)
        .add_service(
            BenchServiceServer::new(BenchServiceImpl)
                // tonic defaults to a 4 MiB cap on request + response message
                // size; the bench sweeps up to 5 MiB payloads. Without raising
                // this, every 5 MiB RPC fails with RESOURCE_EXHAUSTED on both
                // the direct-backend baseline and every gateway.
                .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES),
        )
        .serve(addr)
        .await
        .context("gRPC server error")
}

async fn run_grpcs_server(
    addr: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<()> {
    let cert_pem = std::fs::read(cert_path).context("reading grpcs cert")?;
    let key_pem = std::fs::read(key_path).context("reading grpcs key")?;
    let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
    let tls = tonic::transport::ServerTlsConfig::new().identity(identity);

    tonic::transport::Server::builder()
        .tls_config(tls)
        .context("configuring grpcs TLS")?
        .initial_stream_window_size(8_388_608)
        .initial_connection_window_size(33_554_432)
        .tcp_nodelay(true)
        .add_service(
            BenchServiceServer::new(BenchServiceImpl)
                .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES),
        )
        .serve(addr)
        .await
        .context("grpcs server error")
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
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let (mut rd, mut wr) = tokio::io::split(tls_stream);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
            // Complete the TLS response-side shutdown after the echo drains.
            // Dropping the stream alone omits the peer's close_notify.
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut wr).await;
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
    let profile = std::env::var("H3_PROFILE").is_ok_and(|value| value != "0");
    let mut connection_id = 0u64;

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        connection_id += 1;
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let accepted = Arc::new(AtomicU64::new(0));
            let completed = Arc::new(AtomicU64::new(0));
            let bytes = Arc::new(AtomicU64::new(0));
            if profile {
                let transport = conn.clone();
                let accepted = accepted.clone();
                let completed = completed.clone();
                let bytes = bytes.clone();
                tokio::spawn(async move {
                    loop {
                        let unix_secs = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_or(0.0, |elapsed| elapsed.as_secs_f64());
                        eprintln!(
                            "H3_PROFILE {}",
                            serde_json::json!({
                                "unix_secs": unix_secs,
                                "connection_id": connection_id,
                                "peer": transport.remote_address().to_string(),
                                "accepted": accepted.load(Ordering::Relaxed),
                                "completed": completed.load(Ordering::Relaxed),
                                "bytes": bytes.load(Ordering::Relaxed),
                                "close_reason": transport.close_reason().map(|e| e.to_string()),
                            })
                        );
                        if transport.close_reason().is_some() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                });
            }
            let Ok(mut conn) =
                h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
            else {
                return;
            };

            while let Ok(Some(resolver)) = conn.accept().await {
                let accepted = accepted.clone();
                let completed = completed.clone();
                let bytes = bytes.clone();
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let path = req.uri().path().to_string();

                    if path == "/echo" {
                        if profile {
                            accepted.fetch_add(1, Ordering::Relaxed);
                        }
                        // Collect request body from H3 stream
                        let mut body_data = Vec::new();
                        while let Ok(Some(chunk)) = stream.recv_data().await {
                            use bytes::Buf;
                            body_data.extend_from_slice(chunk.chunk());
                        }
                        let resp = http::Response::builder()
                            .status(StatusCode::OK)
                            .header("content-length", body_data.len().to_string())
                            .body(())
                            .unwrap();
                        let body_len = body_data.len();
                        if stream.send_response(resp).await.is_ok()
                            && stream
                                .send_data(bytes::Bytes::from(body_data))
                                .await
                                .is_ok()
                            && stream.finish().await.is_ok()
                            && profile
                        {
                            completed.fetch_add(1, Ordering::Relaxed);
                            bytes.fetch_add(body_len as u64, Ordering::Relaxed);
                        }
                        return;
                    }

                    let (status, body) = match path.as_str() {
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
    use dimpl::{Config, Dtls, DtlsCertificate, Output};

    // Load certificate from PEM files
    let cert_pem = std::fs::read(cert_path).context("reading DTLS cert")?;
    let key_pem = std::fs::read(key_path).context("reading DTLS key")?;

    let cert_der = rustls_pemfile::certs(&mut &cert_pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("No cert in PEM"))?
        .map_err(|e| anyhow::anyhow!("cert parse: {e}"))?;
    let key_der = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| anyhow::anyhow!("key parse: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("No key in PEM"))?;

    let certificate = DtlsCertificate {
        certificate: cert_der.to_vec(),
        private_key: key_der.secret_der().to_vec(),
    };

    let config = Arc::new(
        Config::builder()
            .require_client_certificate(false)
            .build()
            .map_err(|e| anyhow::anyhow!("DTLS config build: {e}"))?,
    );
    let socket = Arc::new(tokio::net::UdpSocket::bind(addr).await?);
    eprintln!("  DTLS echo server listening on {addr}");

    // Sans-IO demuxer: track per-client DTLS state machines
    let sessions: Arc<dashmap::DashMap<SocketAddr, tokio::sync::mpsc::Sender<Vec<u8>>>> =
        Arc::new(dashmap::DashMap::new());

    let mut buf = vec![0u8; 65536];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..len].to_vec();

        if let Some(tx) = sessions.get(&peer) {
            let _ = tx.send(data).await;
        } else {
            // New client — spawn a DTLS server session
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            let _ = tx.send(data).await;
            sessions.insert(peer, tx);

            let socket = socket.clone();
            let config = config.clone();
            let cert = certificate.clone();
            let sessions = sessions.clone();

            tokio::spawn(async move {
                let mut dtls = Dtls::new_auto(config, cert, std::time::Instant::now());
                let mut out_buf = vec![0u8; 65536];
                let mut connected = false;

                // Initialize server state (random, etc.) — required before
                // handle_packet or dimpl panics in send_server_hello.
                let _ = dtls.handle_timeout(std::time::Instant::now());
                // Drain the resulting Timeout output
                let mut next_timeout = loop {
                    if let Output::Timeout(t) = dtls.poll_output(&mut out_buf) {
                        break Some(t);
                    }
                };

                loop {
                    let sleep_dur = next_timeout
                        .map(|t| t.saturating_duration_since(std::time::Instant::now()))
                        .unwrap_or(std::time::Duration::from_secs(60));

                    tokio::select! {
                        Some(pkt) = rx.recv() => {
                            if let Err(e) = dtls.handle_packet(&pkt) {
                                eprintln!("  DTLS server handle_packet error for {peer}: {e}");
                                break;
                            }
                        }
                        _ = tokio::time::sleep(sleep_dur) => {
                            if let Some(t) = next_timeout
                                && std::time::Instant::now() >= t
                            {
                                if dtls.handle_timeout(std::time::Instant::now()).is_err() {
                                    break;
                                }
                                next_timeout = None;
                            }
                        }
                    }

                    // Drain all outputs until Timeout (dimpl docs: Timeout is
                    // always the last variant). Handle all known variants to
                    // avoid breaking before the Timeout sentinel.
                    let mut just_connected = false;
                    loop {
                        match dtls.poll_output(&mut out_buf) {
                            Output::Packet(d) => {
                                let _ = socket.send_to(d, peer).await;
                            }
                            Output::Timeout(t) => {
                                next_timeout = Some(t);
                                if just_connected {
                                    just_connected = false;
                                    continue;
                                }
                                break;
                            }
                            Output::Connected => {
                                just_connected = true;
                                connected = true;
                            }
                            Output::ApplicationData(d) if connected => {
                                let echo_failed = dtls.send_application_data(d).is_err();
                                if echo_failed {
                                    break;
                                }
                            }
                            Output::PeerCert(_) | Output::KeyingMaterial(_, _) => {}
                            _ => {} // future non_exhaustive variants
                        }
                    }

                    // After echoing, drain the resulting Packet outputs
                    if connected {
                        loop {
                            match dtls.poll_output(&mut out_buf) {
                                Output::Packet(d) => {
                                    let _ = socket.send_to(d, peer).await;
                                }
                                Output::Timeout(t) => {
                                    next_timeout = Some(t);
                                    break;
                                }
                                // Late app data arrival — echo it.
                                Output::ApplicationData(d) => {
                                    let echo_failed = dtls.send_application_data(d).is_err();
                                    if echo_failed {
                                        break;
                                    }
                                }
                                _ => {} // PeerCert, KeyingMaterial, future variants
                            }
                        }
                    }
                }
                sessions.remove(&peer);
            });
        }
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let h3_only = match args.as_slice() {
        [] => false,
        [flag] if flag == "--h3-only" => true,
        _ => anyhow::bail!("usage: proto_backend [--h3-only]"),
    };
    // Generate self-signed certs for TLS/DTLS servers
    let cert_dir = std::env::current_dir()?.join("certs");
    let (cert_path, key_path) =
        tls_utils::generate_self_signed_certs(&cert_dir).context("generating certs")?;

    // Each TLS listener now builds its own ServerConfig with protocol-specific
    // ALPN (h2-only for 3443, h1-only for 3447, wss for 3446, etc.) so silent
    // protocol mismatches can't slip through. See make_server_tls_config_*.
    let h3_cfg = tls_utils::make_h3_server_config(&cert_path, &key_path)
        .context("building H3 server config")?;

    if h3_only {
        // The proof accounts for every owned UDP socket. Do not start unrelated
        // UDP/DTLS listeners, and fail readiness if either fixture server exits.
        println!("H3-only Backend Server: QUIC 127.0.0.1:3445, health 127.0.0.1:3010");
        return tokio::select! {
            result = run_h3_server("127.0.0.1:3445".parse()?, h3_cfg) => result,
            result = run_http1_health_server("127.0.0.1:3010".parse()?) => result,
            result = tokio::signal::ctrl_c() => {
                result?;
                println!("\nShutting down...");
                Ok(())
            }
        };
    }

    println!("Multi-Protocol Backend Server");
    println!("=============================");
    println!("HTTP/1.1 API:     127.0.0.1:3001");
    println!("HTTP/1.1 Health:  127.0.0.1:3010");
    println!("HTTP/2 (h2c):    127.0.0.1:3002");
    println!("HTTPS/H2 (TLS):  127.0.0.1:3443");
    println!("HTTP/1.1+TLS:     127.0.0.1:3447");
    println!("WebSocket:        127.0.0.1:3003");
    println!("WSS (TLS):         127.0.0.1:3446");
    println!("gRPC (h2c):       127.0.0.1:50052");
    println!("gRPC+TLS:         127.0.0.1:50053");
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
    {
        // H2-only ALPN — the hyper server at 3443 is H2-exclusive. The
        // generic tls_cfg (used for TCP+TLS, DTLS, etc.) advertises both
        // `h2` and `http/1.1`, which lets an upstream client that
        // negotiates http/1.1 through the handshake and then the H2 byte
        // parser rejects its requests. Restricting ALPN to `h2` here gives
        // a clean TLS failure for any non-H2 client instead of a silent
        // protocol mismatch.
        let h2_tls = Arc::new(
            tls_utils::make_server_tls_config_h2_only(&cert_path, &key_path)
                .context("building h2-tls server config")?,
        );
        tokio::spawn(async move {
            if let Err(e) = run_h2_tls_server("127.0.0.1:3443".parse().unwrap(), h2_tls).await {
                eprintln!("h2-tls server error: {e}");
            }
        });
    }
    {
        // H1-only ALPN — critical so gateway upstream clients that offer `h2`
        // (Go net/http defaults in Kong/Tyk/KrakenD) cannot silently negotiate
        // h2 against our HTTP/1.1-only hyper server and then fail mid-parse.
        // Using the generic make_server_tls_config here advertises both `h2`
        // and `http/1.1`, which lets h2-preferring clients through and then
        // the HTTP/1.1 byte parser rejects every request.
        let h1_tls = Arc::new(
            tls_utils::make_server_tls_config_h1_only(&cert_path, &key_path)
                .context("building h1-tls server config")?,
        );
        tokio::spawn(async move {
            if let Err(e) = run_h1_tls_server("127.0.0.1:3447".parse().unwrap(), h1_tls).await {
                eprintln!("h1-tls server error: {e}");
            }
        });
    }
    tokio::spawn(async {
        if let Err(e) = run_ws_server("127.0.0.1:3003".parse().unwrap()).await {
            eprintln!("ws server error: {e}");
        }
    });
    {
        // WSS uses HTTP/1.1 for the upgrade handshake — advertise only
        // `http/1.1` so a gateway upstream client that also offers `h2`
        // can't negotiate `h2` and break the WebSocket upgrade.
        let wss_tls = Arc::new(
            tls_utils::make_server_tls_config_h1_only(&cert_path, &key_path)
                .context("building wss server config")?,
        );
        tokio::spawn(async move {
            if let Err(e) = run_wss_server("127.0.0.1:3446".parse().unwrap(), wss_tls).await {
                eprintln!("wss server error: {e}");
            }
        });
    }
    tokio::spawn(async {
        if let Err(e) = run_grpc_server("127.0.0.1:50052".parse().unwrap()).await {
            eprintln!("grpc server error: {e}");
        }
    });
    {
        let grpcs_cert = cert_path.clone();
        let grpcs_key = key_path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_grpcs_server("127.0.0.1:50053".parse().unwrap(), &grpcs_cert, &grpcs_key).await
            {
                eprintln!("grpcs server error: {e}");
            }
        });
    }
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
