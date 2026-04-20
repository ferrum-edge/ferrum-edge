//! Shared echo-server spawners for functional tests.
//!
//! All spawners bind an ephemeral port, keep the listener inside the
//! background task, and return an [`EchoServer`] handle with the assigned
//! port. This eliminates the bind-drop-rebind race documented in CLAUDE.md
//! ("Backend/echo server ports should be held, not dropped") which used to
//! surface as flaky failures under parallel test load.
//!
//! The HTTP variants are written as plain TCP reads/writes rather than a
//! full hyper server so they compile quickly (tests/common/ is built
//! alongside every functional test binary).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

/// Handle to a running echo server. Dropping the handle aborts the task.
pub struct EchoServer {
    pub port: u16,
    handle: Option<JoinHandle<()>>,
}

impl EchoServer {
    /// Abort the background task. Safe to call multiple times.
    pub fn abort(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Shared HTTP/1.1 single-shot writer. `body` is any JSON string, `status`
/// is an HTTP numeric status code. Writes `Connection: close` so each
/// request drives one accept → respond → close cycle (matches existing
/// echo-server behaviour).
async fn write_http_response(stream: &mut tokio::net::TcpStream, status: u16, body: &str) {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Parse the request path from the first line of an HTTP/1.x request.
fn parse_path(request: &str) -> String {
    request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string()
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).to_string()
}

/// HTTP echo server: replies `{"echo":"<path>"}` with 200 OK.
///
/// Special path `/health` returns `{"status":"healthy"}` so the same server
/// can double as a health-check backend.
pub async fn spawn_http_echo() -> std::io::Result<EchoServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let request = read_request(&mut stream).await;
                        let path = parse_path(&request);
                        let (status, body) = if path == "/health" {
                            (200, r#"{"status":"healthy"}"#.to_string())
                        } else {
                            (
                                200,
                                format!(r#"{{"echo":"{}"}}"#, path.replace('"', "\\\"")),
                            )
                        };
                        write_http_response(&mut stream, status, &body).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}

/// HTTP server that identifies itself with `name` in the response body.
///
/// Replies with `{"server":"<name>","path":"<path>"}`. Used by
/// load-balancer tests to verify distribution across backends.
pub async fn spawn_http_identifying(name: &'static str) -> std::io::Result<EchoServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let request = read_request(&mut stream).await;
                        let path = parse_path(&request);
                        let (status, body) = if path == "/health" {
                            (
                                200,
                                format!(r#"{{"server":"{}","status":"healthy"}}"#, name),
                            )
                        } else {
                            (200, format!(r#"{{"server":"{}","path":"{}"}}"#, name, path))
                        };
                        write_http_response(&mut stream, status, &body).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}

/// HTTP server that always responds with a specific status code.
/// Body is `{"server":"<name>","status_code":<n>}`.
pub async fn spawn_http_status(name: &'static str, status: u16) -> std::io::Result<EchoServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let _ = read_request(&mut stream).await;
                        let body = format!(r#"{{"server":"{}","status_code":{}}}"#, name, status);
                        write_http_response(&mut stream, status, &body).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}

/// HTTP server that returns 500 for its first `fail_count` calls then
/// switches to 200 for all subsequent calls. Used to exercise retry and
/// circuit-breaker behaviour.
pub async fn spawn_http_flapping(
    name: &'static str,
    fail_count: u32,
) -> std::io::Result<EchoServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let counter = counter.clone();
                    tokio::spawn(async move {
                        let _ = read_request(&mut stream).await;
                        let call = counter.fetch_add(1, Ordering::Relaxed);
                        let status = if call < fail_count { 500 } else { 200 };
                        let body = format!(
                            r#"{{"server":"{}","call":{},"status_code":{}}}"#,
                            name, call, status
                        );
                        write_http_response(&mut stream, status, &body).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}

/// HTTP server that sleeps `delay_ms` before replying. Keeps connections
/// alive long enough for least-connections load balancing to see non-zero
/// counts.
pub async fn spawn_http_slow_identifying(
    name: &'static str,
    delay_ms: u64,
) -> std::io::Result<EchoServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let request = read_request(&mut stream).await;
                        let path = parse_path(&request);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        let body = format!(r#"{{"server":"{}","path":"{}"}}"#, name, path);
                        write_http_response(&mut stream, 200, &body).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}

/// Raw TCP echo server — reads a chunk and writes it back unchanged. Used
/// for TCP/TLS stream-proxy tests.
pub async fn spawn_tcp_echo() -> std::io::Result<EchoServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65_536];
                        while let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}

/// UDP echo server — echoes each received datagram back to its sender.
/// Used for UDP / DTLS stream-proxy tests.
pub async fn spawn_udp_echo() -> std::io::Result<EchoServer> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let port = socket.local_addr()?.port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let _ = socket.send_to(&buf[..n], src).await;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    Ok(EchoServer {
        port,
        handle: Some(handle),
    })
}
