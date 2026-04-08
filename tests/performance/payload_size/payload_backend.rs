//! Multi-protocol echo backend for payload size benchmarks.
//!
//! Starts servers on:
//! - HTTP/1.1:  port 4001 (echo) + port 4010 (health)
//! - HTTPS/H2:  port 4443
//! - HTTP/3:    port 4445 (QUIC)
//! - gRPC h2c:  port 50053
//! - WebSocket: port 4003
//! - TCP echo:  port 4004
//! - UDP echo:  port 4005
//!
//! All endpoints echo the request body back with the same Content-Type and
//! approximately the same payload size.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, UdpSocket};
use tonic::Status;

mod bench_proto {
    tonic::include_proto!("bench");
}

use bench_proto::bench_service_server::{BenchService, BenchServiceServer};
use bench_proto::{EchoRequest, EchoResponse};

use payload_size_perf::tls_utils;

// -- Main ---------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("[backend] Starting payload-size backend servers...");

    // Generate self-signed certs for TLS servers
    let cert_dir = PathBuf::from("certs");
    let (cert_path, key_path) = tls_utils::generate_self_signed_certs(&cert_dir)?;
    eprintln!(
        "[backend] Generated self-signed certs in {}",
        cert_dir.display()
    );

    // Build H3 server config
    let h3_server_config = tls_utils::make_h3_server_config(&cert_path, &key_path)?;

    // Spawn all servers concurrently
    let h1_handle = tokio::spawn(run_http1_server(4001));
    let health_handle = tokio::spawn(run_health_server(4010));
    let h2_handle = tokio::spawn(run_https_h2_server(
        4443,
        cert_path.clone(),
        key_path.clone(),
    ));
    let h3_handle = tokio::spawn(run_h3_server(4445, h3_server_config));
    let grpc_handle = tokio::spawn(run_grpc_server(50053));
    let ws_handle = tokio::spawn(run_ws_server(4003));
    let tcp_handle = tokio::spawn(run_tcp_echo(4004));
    let udp_handle = tokio::spawn(run_udp_echo(4005));

    eprintln!("[backend] All servers starting...");
    eprintln!("[backend]   HTTP/1.1 echo:    http://127.0.0.1:4001/echo");
    eprintln!("[backend]   Health:           http://127.0.0.1:4010/health");
    eprintln!("[backend]   HTTPS/H2 echo:   https://127.0.0.1:4443/echo");
    eprintln!("[backend]   HTTP/3 echo:     https://127.0.0.1:4445/echo (QUIC)");
    eprintln!("[backend]   gRPC (h2c):      http://127.0.0.1:50053");
    eprintln!("[backend]   WebSocket:        ws://127.0.0.1:4003");
    eprintln!("[backend]   TCP echo:        127.0.0.1:4004");
    eprintln!("[backend]   UDP echo:        127.0.0.1:4005");

    tokio::select! {
        r = h1_handle => { eprintln!("[backend] HTTP/1.1 server exited: {r:?}"); }
        r = health_handle => { eprintln!("[backend] Health server exited: {r:?}"); }
        r = h2_handle => { eprintln!("[backend] HTTPS/H2 server exited: {r:?}"); }
        r = h3_handle => { eprintln!("[backend] HTTP/3 server exited: {r:?}"); }
        r = grpc_handle => { eprintln!("[backend] gRPC server exited: {r:?}"); }
        r = ws_handle => { eprintln!("[backend] WebSocket server exited: {r:?}"); }
        r = tcp_handle => { eprintln!("[backend] TCP server exited: {r:?}"); }
        r = udp_handle => { eprintln!("[backend] UDP server exited: {r:?}"); }
    }

    Ok(())
}

// -- HTTP/1.1 Echo Server -----------------------------------------------------

async fn run_http1_server(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[backend] HTTP/1.1 echo listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service_fn(handle_http_echo))
                .await;
        });
    }
}

async fn handle_http_echo(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    match path.as_str() {
        "/health" => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(r#"{"status":"healthy"}"#)))
            .unwrap()),

        "/echo" | "/echo/" => {
            // Extract content-type from request
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            // Read the full body
            let body = req.collect().await?.to_bytes();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", content_type)
                .header("content-length", body.len().to_string())
                .body(Full::new(body))
                .unwrap())
        }

        "/sse" => {
            // SSE endpoint: read request body, echo back as SSE events
            let body = req.collect().await?.to_bytes();
            let total_size = body.len();

            let mut sse_buf = String::with_capacity(total_size + total_size / 10);
            let chunk_data_size = 4000;
            let mut offset = 0;
            let mut id = 0u64;
            while offset < total_size {
                let end = (offset + chunk_data_size).min(total_size);
                let data: String = body[offset..end].iter().map(|b| format!("{b:02x}")).collect();
                sse_buf.push_str(&format!("id: {id}\nevent: data\ndata: {data}\n\n"));
                offset = end;
                id += 1;
            }

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .body(Full::new(Bytes::from(sse_buf)))
                .unwrap())
        }

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"not found"}"#)))
            .unwrap()),
    }
}

// -- Health Server ------------------------------------------------------------

async fn run_health_server(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[backend] Health server listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|_| async {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(r#"{"status":"healthy"}"#)))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        });
    }
}

// -- HTTPS/HTTP2 Echo Server --------------------------------------------------

async fn run_https_h2_server(
    port: u16,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let tls_config = tls_utils::make_server_tls_config(&cert_path, &key_path)?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[backend] HTTPS/H2 echo listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };

            let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
            let io = TokioIo::new(tls_stream);

            if is_h2 {
                let mut builder = hyper::server::conn::http2::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                );
                let _ = builder
                    .initial_stream_window_size(8 * 1024 * 1024)
                    .initial_connection_window_size(32 * 1024 * 1024)
                    .max_frame_size(1_048_576)
                    .max_concurrent_streams(1000)
                    .serve_connection(io, service_fn(handle_http_echo))
                    .await;
            } else {
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service_fn(handle_http_echo))
                    .await;
            }
        });
    }
}

// -- HTTP/3 (QUIC) Echo Server ------------------------------------------------

async fn run_h3_server(port: u16, server_config: quinn::ServerConfig) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let endpoint =
        quinn::Endpoint::server(server_config, addr).map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("[backend] HTTP/3 echo listening on {addr}");

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let Ok(mut conn) =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
            else {
                return;
            };

            while let Ok(Some(resolver)) = conn.accept().await {
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };

                    let path = req.uri().path().to_string();
                    let (status, body) = match path.as_str() {
                        "/health" => (
                            StatusCode::OK,
                            Bytes::from_static(b"{\"status\":\"healthy\"}"),
                        ),
                        "/echo" | "/echo/" => {
                            // Read body from stream
                            use bytes::Buf;
                            let mut body_data = Vec::new();
                            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                let remaining = chunk.remaining();
                                let mut buf = vec![0u8; remaining];
                                chunk.copy_to_slice(&mut buf);
                                body_data.extend_from_slice(&buf);
                            }
                            (StatusCode::OK, Bytes::from(body_data))
                        }
                        _ => (
                            StatusCode::NOT_FOUND,
                            Bytes::from_static(b"{\"error\":\"not found\"}"),
                        ),
                    };

                    let content_type = req
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/octet-stream");

                    let resp = http::Response::builder()
                        .status(status)
                        .header("content-type", content_type)
                        .body(())
                        .unwrap();

                    let _ = stream.send_response(resp).await;
                    let _ = stream.send_data(body).await;
                    let _ = stream.finish().await;
                });
            }
        });
    }
    Ok(())
}

// -- gRPC Echo Server ---------------------------------------------------------

#[derive(Debug)]
struct BenchServiceImpl;

#[tonic::async_trait]
impl BenchService for BenchServiceImpl {
    async fn unary_echo(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, Status> {
        let payload = request.into_inner().payload;
        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        Ok(tonic::Response::new(EchoResponse {
            payload,
            timestamp_us,
        }))
    }

    type ServerStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<EchoResponse, Status>>;

    async fn server_stream(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<Self::ServerStreamStream>, Status> {
        let payload = request.into_inner().payload;
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            let chunk_size = 32768; // 32 KB chunks
            let mut offset = 0;
            while offset < payload.len() {
                let end = (offset + chunk_size).min(payload.len());
                let chunk = payload[offset..end].to_vec();
                let timestamp_us = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_micros() as i64)
                    .unwrap_or(0);

                if tx
                    .send(Ok(EchoResponse {
                        payload: chunk,
                        timestamp_us,
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
                offset = end;
            }
        });

        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }
}

async fn run_grpc_server(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    eprintln!("[backend] gRPC server listening on {addr}");

    tonic::transport::Server::builder()
        .add_service(
            BenchServiceServer::new(BenchServiceImpl)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
        )
        .serve(addr)
        .await?;
    Ok(())
}

// -- WebSocket Echo Server ----------------------------------------------------

async fn run_ws_server(port: u16) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[backend] WebSocket echo listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        tokio::spawn(async move {
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("[ws] accept error: {e}");
                    return;
                }
            };

            let (mut writer, mut reader) = ws_stream.split();
            while let Some(Ok(msg)) = reader.next().await {
                match msg {
                    Message::Binary(data) => {
                        if writer.send(Message::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    Message::Text(text) => {
                        if writer.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    Message::Ping(data) => {
                        if writer.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
    }
}

// -- TCP Echo Server ----------------------------------------------------------

async fn run_tcp_echo(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[backend] TCP echo listening on {addr}");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let (mut rd, mut wr) = stream.split();
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
    }
}

// -- UDP Echo Server ----------------------------------------------------------

async fn run_udp_echo(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let sock = UdpSocket::bind(addr).await?;
    eprintln!("[backend] UDP echo listening on {addr}");

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let _ = sock.send_to(&buf[..n], peer).await;
    }
}
