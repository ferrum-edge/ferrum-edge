//! High-performance backend server for performance testing
//! Uses hyper for fast HTTP responses

use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::time::{Duration, sleep};
use tokio::net::TcpListener;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    
    let listener = TcpListener::bind(addr).await?;
    println!("🚀 Backend server running on http://{}", addr);
    println!("📊 Available endpoints:");
    println!("   GET  /health - Health check");
    println!("   GET  /api/users - List users");
    println!("   GET  /api/users/:id - Get user by ID");
    println!("   POST /api/users - Create user");
    println!("   GET  /api/data - Large dataset");
    
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let conn = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service_fn(handle_request));
        
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                eprintln!("Error serving connection: {}", err);
            }
        });
    }
}
