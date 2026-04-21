//! Functional test for regex `listen_path` routing (P0-5).
//!
//! Exercises the `IndexedRegexRoutes` RegexSet path in `src/router_cache.rs`:
//! - Basic regex routing alongside prefix routing
//! - Full-path anchoring (`~/users/[^/]+` matches `/users/42` but not `/users/42/profile`)
//! - Prefix-regex with `.*` suffix for opt-in prefix matching
//! - First-match-wins / config order for overlapping regex patterns
//! - Prefix routes winning over regex routes on the same host
//! - Scale correctness (50 distinct regex patterns via RegexSet DFA)
//!
//! Each proxy points at its own echo backend which responds with a unique body
//! (`backend-<N>`), so the test can prove WHICH proxy routed the request.
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_regex_routing --nocapture

use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Identified Echo Server Helper
// ============================================================================

/// Start an HTTP echo server on a pre-bound listener that responds with a fixed
/// identifier string in the response body. Used to prove WHICH backend handled
/// the request.
async fn start_identified_echo_server(listener: TcpListener, identifier: String) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let body = identifier.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Bind an ephemeral-port listener and spawn an identified echo server on it.
/// Returns the bound port and the server task handle.
async fn spawn_backend(identifier: &str) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let id = identifier.to_string();
    let handle = tokio::spawn(async move {
        start_identified_echo_server(listener, id).await;
    });
    (port, handle)
}

// ============================================================================
// Gateway helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> std::process::Child {
    let binary_path = gateway_binary_path();

    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);

    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start the gateway with retry to handle ephemeral port races.
/// Fresh ports each attempt; the gateway is killed before retry.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway_in_file_mode(config_path, proxy_port, admin_port);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

/// Issue a GET and return `(status_u16, body_text)`.
async fn get_with_body(client: &reqwest::Client, url: &str) -> (u16, String) {
    let resp = client
        .get(url)
        .send()
        .await
        .expect("HTTP GET should complete");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

// ============================================================================
// Test 1: Basic regex routing alongside prefix routing
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_regex_routing_basic_mixed_routes() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // 5 backends: prefix + 2 prefix + 2 regex.
    let (port_a, h_a) = spawn_backend("backend-A-prefix-api").await;
    let (port_b, h_b) = spawn_backend("backend-B-prefix-admin").await;
    let (port_c, h_c) = spawn_backend("backend-C-regex-users").await;
    let (port_d, h_d) = spawn_backend("backend-D-regex-orders").await;
    let (port_e, h_e) = spawn_backend("backend-E-prefix-health").await;
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "prefix-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_a}
    strip_listen_path: false

  - id: "prefix-admin"
    listen_path: "/admin"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_b}
    strip_listen_path: false

  - id: "regex-users"
    listen_path: "~/users/[^/]+"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_c}
    strip_listen_path: false

  - id: "regex-orders"
    listen_path: "~/orders/[0-9]+"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_d}
    strip_listen_path: false

  - id: "prefix-health"
    listen_path: "/health-check"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_e}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    // Prefix /api → backend A
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api/v1")).await;
    assert_eq!(status, 200, "prefix /api/v1 should 200");
    assert_eq!(
        body, "backend-A-prefix-api",
        "prefix /api must hit backend A"
    );

    // Prefix /admin → backend B
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/admin")).await;
    assert_eq!(status, 200, "prefix /admin should 200");
    assert_eq!(
        body, "backend-B-prefix-admin",
        "prefix /admin must hit backend B"
    );

    // Regex /users/42 → backend C
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/users/42")).await;
    assert_eq!(status, 200, "regex /users/42 should 200");
    assert_eq!(
        body, "backend-C-regex-users",
        "regex ~/users/[^/]+ must hit backend C"
    );

    // Regex /users/alice → backend C
    let (status, body) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/users/alice"),
    )
    .await;
    assert_eq!(status, 200, "regex /users/alice should 200");
    assert_eq!(
        body, "backend-C-regex-users",
        "regex must match alphanumeric segment"
    );

    // Regex /orders/123 → backend D
    let (status, body) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/orders/123"),
    )
    .await;
    assert_eq!(status, 200, "regex /orders/123 should 200");
    assert_eq!(
        body, "backend-D-regex-orders",
        "regex ~/orders/[0-9]+ must hit backend D"
    );

    // Prefix /health-check → backend E
    let (status, body) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/health-check"),
    )
    .await;
    assert_eq!(status, 200, "prefix /health-check should 200");
    assert_eq!(body, "backend-E-prefix-health");

    let _ = gw.kill();
    let _ = gw.wait();
    h_a.abort();
    h_b.abort();
    h_c.abort();
    h_d.abort();
    h_e.abort();
}

// ============================================================================
// Test 2: Full-path anchoring
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_regex_routing_full_path_anchoring() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (port_users, h_users) = spawn_backend("backend-users").await;
    sleep(Duration::from_millis(200)).await;

    // ~/users/[^/]+ is auto-anchored to ^/users/[^/]+$. No catch-all, so deeper
    // paths must 404.
    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "regex-users"
    listen_path: "~/users/[^/]+"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_users}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    // Exact single-segment match → 200
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/users/42")).await;
    assert_eq!(status, 200, "/users/42 should match anchored regex");
    assert_eq!(body, "backend-users");

    // Extra path segment must NOT match (full-path anchoring: `$` appended)
    let (status, _body) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/users/42/profile"),
    )
    .await;
    assert_eq!(
        status, 404,
        "/users/42/profile must NOT match ^/users/[^/]+$ — expected 404"
    );

    // Trailing slash extension must also not match
    let (status, _body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/users/42/")).await;
    assert_eq!(
        status, 404,
        "/users/42/ must NOT match ^/users/[^/]+$ — expected 404"
    );

    // Missing segment → 404 (pattern requires at least one path char after /users/)
    let (status, _body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/users/")).await;
    assert_eq!(status, 404, "/users/ must NOT match ^/users/[^/]+$");

    let _ = gw.kill();
    let _ = gw.wait();
    h_users.abort();
}

// ============================================================================
// Test 3: Prefix-style regex with explicit `.*` suffix
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_regex_routing_dot_star_suffix_matches_deep_paths() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (port_v, h_v) = spawn_backend("backend-versioned-api").await;
    sleep(Duration::from_millis(200)).await;

    // Explicit `.*` suffix opts out of the `$` anchor effect (^.../.*$ matches anything).
    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "regex-versioned"
    listen_path: "~/api/v[0-9]+/.*"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_v}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    for path in [
        "/api/v1/anything",
        "/api/v2/deep/path",
        "/api/v42/items/99/detail",
    ] {
        let (status, body) =
            get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}{path}")).await;
        assert_eq!(status, 200, "{path} should match ^/api/v[0-9]+/.*$");
        assert_eq!(
            body, "backend-versioned-api",
            "{path} must hit versioned backend"
        );
    }

    // Missing trailing segment: `.*` requires the `/` separator, so /api/v1 fails.
    let (status, _body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api/v1")).await;
    assert_eq!(
        status, 404,
        "/api/v1 without trailing slash+content must NOT match /api/v[0-9]+/.*"
    );

    // Non-numeric version fails.
    let (status, _body) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/api/vX/items"),
    )
    .await;
    assert_eq!(status, 404, "/api/vX/items must NOT match /api/v[0-9]+/.*");

    let _ = gw.kill();
    let _ = gw.wait();
    h_v.abort();
}

// ============================================================================
// Test 4: First-match-wins / config order for overlapping regex patterns
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_regex_routing_first_match_wins_config_order() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (port_first, h_first) = spawn_backend("backend-first-specific").await;
    let (port_second, h_second) = spawn_backend("backend-second-greedy").await;
    sleep(Duration::from_millis(200)).await;

    // Both patterns match `/thing/42`. The first declared pattern must win
    // (RegexSet reports the lowest matching index — `src/router_cache.rs`
    // `find_regex_match_indexed`).
    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "regex-first-specific"
    listen_path: "~/thing/[^/]+"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_first}
    strip_listen_path: false

  - id: "regex-second-greedy"
    listen_path: "~/thing/.*"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_second}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    // Single segment → both match; FIRST (specific) wins.
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/thing/42")).await;
    assert_eq!(status, 200, "/thing/42 should 200");
    assert_eq!(
        body, "backend-first-specific",
        "first-declared regex must win when both patterns match /thing/42"
    );

    // Deeper path → only the greedy (second) pattern matches.
    let (status, body) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/thing/42/extra"),
    )
    .await;
    assert_eq!(status, 200, "/thing/42/extra should 200");
    assert_eq!(
        body, "backend-second-greedy",
        "greedy fallback must handle deeper path that the specific pattern cannot"
    );

    let _ = gw.kill();
    let _ = gw.wait();
    h_first.abort();
    h_second.abort();
}

// ============================================================================
// Test 5: Prefix wins over regex on same host
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_regex_routing_prefix_wins_over_regex() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (port_prefix, h_prefix) = spawn_backend("backend-prefix-api").await;
    let (port_regex, h_regex) = spawn_backend("backend-regex-api").await;
    sleep(Duration::from_millis(200)).await;

    // Same host (catch-all), both could match `/api/users`. Router checks prefix
    // FIRST within each host tier (`src/router_cache.rs::search_route_table`).
    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "prefix-api"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_prefix}
    strip_listen_path: false

  - id: "regex-api-catchall"
    listen_path: "~/api/.*"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_regex}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    // /api/users → prefix wins (prefix tier checked before regex tier).
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api/users")).await;
    assert_eq!(status, 200, "/api/users should 200");
    assert_eq!(
        body, "backend-prefix-api",
        "prefix route must win over regex route on same host (prefix tier checked first)"
    );

    // Bare /api also hits prefix.
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api")).await;
    assert_eq!(status, 200, "/api should 200");
    assert_eq!(body, "backend-prefix-api", "/api must hit prefix proxy");

    let _ = gw.kill();
    let _ = gw.wait();
    h_prefix.abort();
    h_regex.abort();
}

// ============================================================================
// Test 6: Scale — 50 distinct regex listen_paths via RegexSet DFA
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_regex_routing_scale_50_regex_routes() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // 50 distinct backends, one per regex pattern.
    const N: usize = 50;
    let mut backends: Vec<(u16, tokio::task::JoinHandle<()>)> = Vec::with_capacity(N);
    for i in 0..N {
        backends.push(spawn_backend(&format!("backend-r{:02}", i)).await);
    }
    sleep(Duration::from_millis(300)).await;

    // Build YAML with 50 regex proxies: ~/rNN/[^/]+ → backend-rNN.
    let mut yaml = String::from("proxies:\n");
    for (i, (port, _)) in backends.iter().enumerate() {
        yaml.push_str(&format!(
            "  - id: \"regex-r{:02}\"\n    listen_path: \"~/r{:02}/[^/]+\"\n    backend_scheme: http\n    backend_host: \"127.0.0.1\"\n    backend_port: {}\n    strip_listen_path: false\n\n",
            i, i, port
        ));
    }
    yaml.push_str("consumers: []\nplugin_configs: []\n");

    let config_path = temp_dir.path().join("config.yaml");
    std::fs::write(&config_path, yaml).expect("write scale config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    // Each request hits a distinct pattern; all must route to the correct backend.
    for i in 0..N {
        let url = format!("http://127.0.0.1:{}/r{:02}/item-{}", proxy_port, i, i);
        let (status, body) = get_with_body(&client, &url).await;
        let expected = format!("backend-r{:02}", i);
        assert_eq!(status, 200, "pattern ~/r{:02}/[^/]+ vs {url} should 200", i);
        assert_eq!(
            body, expected,
            "pattern ~/r{:02}/[^/]+ must route to {expected}, got {body}",
            i
        );
    }

    // Paths that don't match any of the 50 patterns must 404.
    let (status, _) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/r99/item")).await;
    assert_eq!(
        status, 404,
        "/r99/... is not registered — must 404 via RegexSet miss"
    );

    let (status, _) = get_with_body(
        &client,
        &format!("http://127.0.0.1:{proxy_port}/r00/item/extra"),
    )
    .await;
    assert_eq!(
        status, 404,
        "/r00/item/extra has an extra segment — must 404 under full-path anchoring"
    );

    let _ = gw.kill();
    let _ = gw.wait();
    for (_, handle) in backends {
        handle.abort();
    }
}
