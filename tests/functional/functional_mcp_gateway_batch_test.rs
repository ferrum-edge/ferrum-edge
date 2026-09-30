//! Functional coverage for mcp_gateway JSON-RPC batch admission on the live
//! proxy path (transparent mode forwards admitted batches; empty batches are
//! rejected before upstream).
//!
//! Run with:
//! `cargo build --bin ferrum-edge && cargo test --test functional_tests functional_mcp_gateway_batch -- --ignored`

use crate::scaffolding::port_registry::TestSocket;

use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

use crate::common::TestGateway;

/// Hard ceiling on a single buffered request. Larger requests are refused
/// rather than grown without bound.
const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// Fail-closed reply for a request the backend could not frame completely.
const BAD_REQUEST_RESPONSE: &str =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Read one complete HTTP/1.1 request: return the headers before `\r\n\r\n`
/// and exactly `Content-Length` body bytes.
///
/// TCP does not guarantee that a single `read` returns the whole request, so a
/// single-read server can echo a truncated body under runner load. This loops
/// until the parsed framing is satisfied and returns `None` (fail closed, no
/// echo) on EOF-before-complete, a missing/invalid `Content-Length`, or an
/// oversized request. There are no sleeps or retries: termination is decided
/// entirely by the bytes on the wire.
async fn read_complete_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let mut header_end = None;
    let mut content_length = None;

    loop {
        if let Some(end) = header_end {
            let need = end + content_length?;
            if buf.len() >= need {
                let headers = std::str::from_utf8(&buf[..end - 4]).ok()?.to_string();
                return Some((headers, buf[end..need].to_vec()));
            }
        } else if let Some(offset) = find_header_terminator(&buf) {
            let headers = std::str::from_utf8(&buf[..offset]).ok()?;
            content_length = Some(parse_content_length(headers)?);
            header_end = Some(offset + 4);
            continue;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            // Peer finished without completing the framing: fail closed.
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Body length from the request headers. Absent `Content-Length` means an empty
/// body (a bodyless HTTP/1.1 request). `Transfer-Encoding` is refused rather
/// than guessed at, and an unparseable or oversized length fails closed.
fn parse_content_length(headers: &str) -> Option<usize> {
    let mut length = Some(0usize);
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        }
    }
    length.filter(|value| *value <= MAX_REQUEST_BYTES)
}

async fn start_mcp_echo_server_on(listener: TcpListener) {
    start_mcp_recording_echo_server_on(listener, None).await;
}

async fn start_mcp_recording_echo_server_on(
    listener: TcpListener,
    requests: Option<tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>>,
) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let requests = requests.clone();
            tokio::spawn(async move {
                let Some((headers, body)) = read_complete_http_request(&mut stream).await else {
                    // Malformed, oversized, or truncated request: answer 400
                    // rather than echoing a partial or defaulted body.
                    let _ = stream.write_all(BAD_REQUEST_RESPONSE.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return;
                };
                // Echo the JSON-RPC body so tests can assert transparent batch
                // forwarding preserved the array order/ids.
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend_from_slice(&body);
                if let Some(requests) = requests {
                    // The gateway's backend capability refresh opens an h2c
                    // prior-knowledge connection (`PRI * HTTP/2.0`) to classify
                    // the upstream. It is answered like any other request but
                    // is not a forwarded MCP request, so it stays out of the
                    // recorded sequence the tests assert on.
                    if !headers.starts_with("PRI * HTTP/2.0") {
                        let _ = requests.send((headers, body));
                    }
                }
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

async fn start_gateway_with_mcp(backend_port: u16) -> TestGateway {
    start_gateway_with_mcp_at(backend_port, "/mcp").await
}

async fn start_gateway_with_mcp_at(backend_port: u16, listen_path: &str) -> TestGateway {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "mcp-batch"
    listen_path: "{listen_path}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    upstream_id: "mcp-batch-upstream"
    plugins:
      - plugin_config_id: "mcp-gw"

consumers: []
upstreams:
  - id: "mcp-batch-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {backend_port}
        weight: 1

plugin_configs:
  - id: "mcp-gw"
    plugin_name: "mcp_gateway"
    scope: "proxy"
    proxy_id: "mcp-batch"
    enabled: true
    config:
      mode: transparent_proxy
      endpoint:
        path: /mcp
        protocol_versions: ["2025-03-26", "2025-11-25"]
      servers:
        tools:
          upstream_url: http://127.0.0.1:{backend_port}/mcp
          namespace: tools
      validation:
        max_batch_items: 8
        max_batch_bytes: 65536
        max_batch_item_bytes: 8192
"#
    );

    TestGateway::builder()
        .mode_file(config)
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start mcp_gateway batch gateway")
}

#[tokio::test]
#[ignore]
async fn functional_mcp_gateway_batch_rejects_trailing_slash_alias() {
    let listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, mut requests) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(start_mcp_recording_echo_server_on(listener, Some(sender)));
    // The whole origin routes to this proxy, as in #5536: the plugin itself
    // must refuse aliases it cannot mediate, even with a permissive backend.
    let gateway = start_gateway_with_mcp_at(port, "/").await;
    let client = reqwest::Client::new();
    let initialize = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "slash-test", "version": "1"}
        }
    });
    {
        let path = "/mcp";
        let response = client
            .post(gateway.proxy_url(path))
            .json(&initialize)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.json::<Value>().await.unwrap(), initialize);
        let (headers, body) = requests
            .try_recv()
            .expect("backend recorded the initialize");
        assert_eq!(headers.lines().next(), Some("POST /mcp HTTP/1.1"));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), initialize);

        // Exact-path admission still validates JSON-RPC before forwarding.
        let response = client
            .post(gateway.proxy_url(path))
            .header("content-type", "application/json")
            .body("not-json")
            .send()
            .await
            .unwrap();
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], -32600);
        assert!(requests.try_recv().is_err());
    }
    for path in ["/mcp/", "/mcp/tools", "/mcp/tools/", "/MCP", "/mCp/"] {
        let response = client
            .post(gateway.proxy_url(path))
            .json(&initialize)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{path}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], -32600);
        assert_eq!(body["error"]["message"], "Unknown MCP endpoint");
        assert!(requests.try_recv().is_err());
    }
    // An empty inner segment is refused by the shared frontend before any
    // plugin runs (`empty_segment`, HTTP 400), so it never reaches the backend.
    let response = client
        .post(gateway.proxy_url("/mcp//"))
        .json(&initialize)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400, "/mcp//");
    assert!(requests.try_recv().is_err());
    // Use raw HTTP so a client URL parser cannot erase the dot segment. The
    // shared frontend rejects these before any plugin runs (HTTP 400); direct
    // plugin tests separately assert the Unknown MCP endpoint backstop.
    for path in ["/mcp%2F", "/mcp/."] {
        let body = initialize.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", gateway.proxy_port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 400")
        );
        assert!(requests.try_recv().is_err());
    }
}

#[tokio::test]
#[ignore]
async fn functional_mcp_gateway_batch_backend_handles_fragmented_requests() {
    // The backend reads in 8 KiB chunks, so a body larger than one chunk needs
    // more than one `read` by construction — regardless of how the kernel or the
    // gateway happens to segment the stream. A single-read server truncates here
    // (or echoes its default body); the framing-aware one reassembles. The two
    // client writes additionally split the headers themselves. No sleeps or
    // retries: completion is decided entirely by the parsed framing.
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    tokio::spawn(start_mcp_echo_server_on(backend_listener));

    let padding = "p".repeat(40_000);
    let body = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": { "pad": padding } },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ])
    .to_string();
    assert!(body.len() > 8192, "body must exceed the backend read chunk");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let request = request.into_bytes();

    // Split mid-headers so the first write cannot contain the header terminator.
    let split = 20;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", backend_port))
        .await
        .expect("connect to echo backend");
    stream.set_nodelay(true).unwrap();
    stream.write_all(&request[..split]).await.unwrap();
    stream.flush().await.unwrap();
    stream.write_all(&request[split..]).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).expect("echo response is utf-8");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "fragmented request must not be refused: {response}"
    );
    let echoed = response
        .split("\r\n\r\n")
        .nth(1)
        .expect("echo response must carry a body");
    let echoed: Value = serde_json::from_str(echoed)
        .unwrap_or_else(|error| panic!("echoed body must be complete JSON ({error}): {echoed}"));
    let echoed = echoed.as_array().expect("echoed body must be the batch");
    assert_eq!(echoed.len(), 2);
    assert_eq!(echoed[0]["id"], 1);
    assert_eq!(echoed[1]["id"], 2);
}

#[tokio::test]
#[ignore]
async fn functional_mcp_gateway_batch_empty_rejected_before_upstream() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    tokio::spawn(start_mcp_echo_server_on(backend_listener));

    let gateway = start_gateway_with_mcp(backend_port).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(gateway.proxy_url("/mcp"))
        .header("content-type", "application/json")
        .body("[]")
        .send()
        .await
        .expect("empty batch request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.is_object(),
        "empty batch must be a single Response object"
    );
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Invalid Request");
}

#[tokio::test]
#[ignore]
async fn functional_mcp_gateway_batch_transparent_forwards_ordered_array() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    tokio::spawn(start_mcp_echo_server_on(backend_listener));

    let gateway = start_gateway_with_mcp(backend_port).await;
    let client = reqwest::Client::new();
    let batch = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]);
    let resp = client
        .post(gateway.proxy_url("/mcp"))
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(5))
        .json(&batch)
        .send()
        .await
        .expect("batch request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let responses = body
        .as_array()
        .expect("transparent mode must forward the batch array to upstream");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["id"], 2);
    // Keep the gateway handle alive through assertions.
    sleep(Duration::from_millis(10)).await;
    drop(gateway);
}
