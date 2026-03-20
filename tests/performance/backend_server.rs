//! High-performance backend server for performance testing
//! Uses hyper for fast HTTP responses
//! Supports both HTTP (port 3001) and HTTPS (port 3443)

use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use std::convert::Infallible;
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{Duration, sleep};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

async fn handle_request(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let start_time = Instant::now();

    let (method, uri) = (req.method(), req.uri());

    // Simulate different response types based on path
    let response: Response<Full<Bytes>> = match (method, uri.path()) {
        (&Method::GET, "/health") => {
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(r#"{"status":"healthy","timestamp":"2024-01-01T00:00:00Z"}"#)))
                .unwrap()
        }
        (&Method::GET, "/api/users") => {
            // Simulate some processing time
            sleep(Duration::from_micros(100)).await;
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(r#"{"users":[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]}"#)))
                .unwrap()
        }
        (&Method::GET, path) if path.starts_with("/api/users/") => {
            // Extract user ID from path
            let user_id = path.trim_start_matches("/api/users/");
            let response = format!(r#"{{"id":{},"name":"User {}","email":"user{}@example.com"}}"#, user_id, user_id, user_id);
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response)))
                .unwrap()
        }
        (&Method::POST, "/api/users") => {
            // Simulate user creation
            sleep(Duration::from_micros(200)).await;
            Response::builder()
                .status(StatusCode::CREATED)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(r#"{"id":3,"name":"New User","created":true}"#)))
                .unwrap()
        }
        (&Method::GET, "/api/data") => {
            // Larger payload for testing
            let data = (0..100).map(|i| format!(r#"{{"id":{},"value":"data_{}"}}"#, i, i)).collect::<Vec<_>>().join(",");
            let response = format!(r#"{{"data":[{}]}}"#, data);
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response)))
                .unwrap()
        }
        _ => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(r#"{"error":"Not Found"}"#)))
                .unwrap()
        }
    };

    let elapsed = start_time.elapsed();

    // Add timing headers for monitoring
    let mut response_with_timing = response;
    response_with_timing.headers_mut().insert("X-Backend-Processing-Time",
        format!("{}μs", elapsed.as_micros()).parse().unwrap());

    Ok(response_with_timing)
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert_file = fs::File::open(cert_path)?;
    let key_file = fs::File::open(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or("no private key found")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}

async fn run_http_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("  HTTP server listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let conn = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service_fn(handle_request));

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                eprintln!("Error serving HTTP connection: {}", err);
            }
        });
    }
}

async fn run_https_server(
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("  HTTPS server listening on https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let conn = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn(handle_request));
                    if let Err(err) = conn.await {
                        eprintln!("Error serving HTTPS connection: {}", err);
                    }
                }
                Err(err) => {
                    eprintln!("TLS handshake error: {}", err);
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let https_addr = SocketAddr::from(([127, 0, 0, 1], 3443));

    println!("Backend server starting...");
    println!("  Available endpoints:");
    println!("   GET  /health - Health check");
    println!("   GET  /api/users - List users");
    println!("   GET  /api/users/:id - Get user by ID");
    println!("   POST /api/users - Create user");
    println!("   GET  /api/data - Large dataset");

    // Try to load TLS config from well-known cert paths
    let cert_path = std::env::var("BACKEND_TLS_CERT")
        .unwrap_or_default();
    let key_path = std::env::var("BACKEND_TLS_KEY")
        .unwrap_or_default();

    if !cert_path.is_empty() && !key_path.is_empty() {
        let tls_config = load_tls_config(&cert_path, &key_path)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // Run both HTTP and HTTPS servers concurrently
        tokio::select! {
            res = run_http_server(http_addr) => { res?; }
            res = run_https_server(https_addr, tls_acceptor) => { res?; }
        }
    } else {
        println!("  (HTTPS disabled — set BACKEND_TLS_CERT and BACKEND_TLS_KEY to enable)");
        run_http_server(http_addr).await?;
    }

    Ok(())
}
