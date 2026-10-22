//! Plaintext HTTP/1.1 echo backend for the mesh-runtime benchmark.
//!
//! Every request body is echoed back with `200 OK`; `/health` answers `ok`
//! without echoing. The load generator verifies the echoed length, so a
//! proxy that short-circuits or truncates bodies is counted as errors
//! rather than as throughput.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use mesh_runtime_perf::header_diagnostic::{
    HeaderDiagnostic, HeaderDiagnosticArgs, RECEIPT_HEADER,
};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:18080")]
    listen: SocketAddr,
    #[command(flatten)]
    diagnostic_headers: HeaderDiagnosticArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let cli = Cli::parse();
    let diagnostic_headers = cli.diagnostic_headers.profile()?.map(Arc::new);
    let listener = TcpListener::bind(cli.listen).await?;
    let bound = listener.local_addr()?;
    println!("listening on {bound}");
    eprintln!("mesh_backend listening on {bound}");

    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let diagnostic_headers = diagnostic_headers.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, diagnostic_headers.clone()));
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!("connection: {e}");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    diagnostic: Option<Arc<HeaderDiagnostic>>,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    let diagnostic_valid = diagnostic
        .as_ref()
        .is_none_or(|profile| profile.validate_request_headers(req.headers()));
    let body = req.into_body().collect().await?.to_bytes();
    if path == "/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"ok")))
            .unwrap());
    }
    if !diagnostic_valid {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from_static(b"diagnostic headers invalid")))?);
    }
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("content-length", body.len().to_string());
    if let Some(profile) = &diagnostic {
        response = response.header(RECEIPT_HEADER, profile.receipt().clone());
    }
    Ok(response.body(Full::new(body))?)
}
