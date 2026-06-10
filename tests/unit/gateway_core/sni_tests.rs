use ferrum_edge::proxy::sni::{
    extract_sni_from_client_hello, extract_sni_from_dtls_client_hello, extract_sni_from_tcp_stream,
    resolve_proxy_by_sni,
};

fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let sni_entry_len = 1 + 2 + name_bytes.len();
    let sni_list_len = sni_entry_len;
    let sni_ext_data_len = 2 + sni_list_len;

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
    sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);

    let extensions_len = sni_ext.len();

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    let hs_len = handshake.len();
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

fn build_dtls_client_hello(hostname: &str) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let sni_entry_len = 1 + 2 + name_bytes.len();
    let sni_list_len = sni_entry_len;
    let sni_ext_data_len = 2 + sni_list_len;

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
    sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);

    let extensions_len = sni_ext.len();

    let mut body = Vec::new();
    body.extend_from_slice(&[0xfe, 0xfd]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.push(0); // cookie length: 0 (DTLS-specific)
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&[0x00, 0x00]); // message_seq: 0
    handshake.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset: 0
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0xfe, 0xfd]);
    record.extend_from_slice(&[0x00, 0x00]); // epoch: 0
    record.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // sequence: 1
    let hs_len = handshake.len();
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

fn set_sni_list_len(data: &mut [u8], hostname: &str, list_len: u16) {
    let hostname_offset = data
        .windows(hostname.len())
        .position(|window| window == hostname.as_bytes())
        .expect("hostname should be present in test ClientHello");
    data[hostname_offset - 5..hostname_offset - 3].copy_from_slice(&list_len.to_be_bytes());
}

fn make_test_config(
    proxies: Vec<ferrum_edge::config::types::Proxy>,
) -> ferrum_edge::config::types::GatewayConfig {
    ferrum_edge::config::types::GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn make_proxy(id: &str, hosts: Vec<&str>) -> ferrum_edge::config::types::Proxy {
    ferrum_edge::config::types::Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: hosts.into_iter().map(String::from).collect(),
        listen_path: None,
        backend_scheme: Some(ferrum_edge::config::types::BackendScheme::Tcp),
        dispatch_kind: ferrum_edge::config::types::DispatchKind::from(
            ferrum_edge::config::types::BackendScheme::Tcp,
        ),
        backend_host: "localhost".into(),
        backend_port: 443,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: ferrum_edge::config::types::AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(8444),
        frontend_tls: false,
        passthrough: true,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// ── TLS SNI extraction ───────────────────────────────────────────────────────

#[test]
fn test_extract_sni_from_tls_client_hello() {
    let data = build_tls_client_hello("example.com");
    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some("example.com".to_string())
    );
}

#[test]
fn test_extract_sni_case_normalized() {
    let data = build_tls_client_hello("Example.COM");
    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some("example.com".to_string())
    );
}

#[test]
fn test_extract_sni_long_hostname() {
    let hostname = "very-long-subdomain.another.example.internal.corp.example.com";
    let data = build_tls_client_hello(hostname);
    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some(hostname.to_string())
    );
}

#[test]
fn test_extract_sni_no_sni_extension() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes());

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    let hs_len = handshake.len();
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    assert_eq!(extract_sni_from_client_hello(&record), None);
}

#[test]
fn test_extract_sni_truncated_data() {
    assert_eq!(extract_sni_from_client_hello(&[]), None);
    assert_eq!(extract_sni_from_client_hello(&[0x16, 0x03]), None);
    assert_eq!(
        extract_sni_from_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]),
        None
    );
}

#[test]
fn test_extract_sni_wrong_content_type() {
    let mut data = build_tls_client_hello("example.com");
    data[0] = 0x17;
    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_wrong_handshake_type() {
    let mut data = build_tls_client_hello("example.com");
    data[5] = 0x02;
    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_rejects_short_server_name_list_length() {
    let hostname = "example.com";
    let mut data = build_tls_client_hello(hostname);
    set_sni_list_len(&mut data, hostname, 0);

    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_rejects_oversized_server_name_list_length() {
    let hostname = "example.com";
    let mut data = build_tls_client_hello(hostname);
    set_sni_list_len(&mut data, hostname, (1 + 2 + hostname.len() + 1) as u16);

    assert_eq!(extract_sni_from_client_hello(&data), None);
}

// ── DTLS SNI extraction ──────────────────────────────────────────────────────

#[test]
fn test_extract_sni_from_dtls_client_hello() {
    let data = build_dtls_client_hello("dtls.example.com");
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        Some("dtls.example.com".to_string())
    );
}

#[test]
fn test_extract_sni_from_dtls_case_normalized() {
    let data = build_dtls_client_hello("DTLS.Example.COM");
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        Some("dtls.example.com".to_string())
    );
}

#[test]
fn test_extract_sni_from_dtls_truncated() {
    assert_eq!(extract_sni_from_dtls_client_hello(&[]), None);
    assert_eq!(extract_sni_from_dtls_client_hello(&[0x16; 10]), None);
}

#[test]
fn test_extract_sni_from_dtls_wrong_content_type() {
    let mut data = build_dtls_client_hello("example.com");
    data[0] = 0x17;
    assert_eq!(extract_sni_from_dtls_client_hello(&data), None);
}

// ── Malformed ClientHello edge cases ────────────────────────────────────────

#[test]
fn test_extract_sni_oversized_session_id() {
    let mut data = build_tls_client_hello("example.com");
    data[43] = 0xFF;
    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_oversized_cipher_suites() {
    let mut data = build_tls_client_hello("example.com");
    data[44] = 0xFF;
    data[45] = 0xFF;
    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_oversized_extensions_len() {
    let mut data = build_tls_client_hello("example.com");
    data[59] = 0xFF;
    data[60] = 0xFF;
    let _ = extract_sni_from_client_hello(&data); // must not panic
}

#[test]
fn test_extract_sni_zero_length_record() {
    let data = [0x16, 0x03, 0x01, 0x00, 0x00];
    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_non_sni_extension_only() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    let alpn_ext = [0x00, 0x10, 0x00, 0x03, 0x02, 0x68, 0x32];
    body.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&alpn_ext);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    let hs_len = handshake.len();
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    assert_eq!(extract_sni_from_client_hello(&record), None);
}

#[test]
fn test_extract_sni_truncated_sni_extension_data() {
    let mut data = build_tls_client_hello("example.com");
    data.truncate(data.len().saturating_sub(5));
    let new_len = (data.len() - 5) as u16;
    data[3] = (new_len >> 8) as u8;
    data[4] = new_len as u8;
    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_random_garbage_bytes() {
    let garbage = [
        0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(extract_sni_from_client_hello(&garbage), None);
}

#[test]
fn test_extract_sni_dtls_oversized_cookie() {
    let mut data = build_dtls_client_hello("example.com");
    data[60] = 0xFF;
    assert_eq!(extract_sni_from_dtls_client_hello(&data), None);
}

#[test]
fn test_extract_sni_dtls_wrong_handshake_type() {
    let mut data = build_dtls_client_hello("example.com");
    data[13] = 0x02;
    assert_eq!(extract_sni_from_dtls_client_hello(&data), None);
}

// ── resolve_proxy_by_sni ─────────────────────────────────────────────────────

#[test]
fn test_resolve_proxy_exact_match() {
    let config = make_test_config(vec![
        make_proxy("p1", vec!["a.example.com"]),
        make_proxy("p2", vec!["b.example.com"]),
    ]);
    let ids = vec!["p1".to_string(), "p2".to_string()];
    assert_eq!(
        resolve_proxy_by_sni(Some("a.example.com"), &ids, &config),
        Some("p1")
    );
    assert_eq!(
        resolve_proxy_by_sni(Some("b.example.com"), &ids, &config),
        Some("p2")
    );
}

#[test]
fn test_resolve_proxy_wildcard_match() {
    let config = make_test_config(vec![
        make_proxy("wild", vec!["*.example.com"]),
        make_proxy("other", vec!["other.org"]),
    ]);
    let ids = vec!["wild".to_string(), "other".to_string()];
    assert_eq!(
        resolve_proxy_by_sni(Some("foo.example.com"), &ids, &config),
        Some("wild")
    );
    assert_eq!(
        resolve_proxy_by_sni(Some("other.org"), &ids, &config),
        Some("other")
    );
}

#[test]
fn test_resolve_proxy_fallback() {
    let config = make_test_config(vec![
        make_proxy("specific", vec!["specific.com"]),
        make_proxy("fallback", vec![]),
    ]);
    let ids = vec!["specific".to_string(), "fallback".to_string()];
    assert_eq!(
        resolve_proxy_by_sni(Some("unknown.com"), &ids, &config),
        Some("fallback")
    );
}

#[test]
fn test_resolve_proxy_no_match_no_fallback() {
    let config = make_test_config(vec![
        make_proxy("p1", vec!["a.com"]),
        make_proxy("p2", vec!["b.com"]),
    ]);
    let ids = vec!["p1".to_string(), "p2".to_string()];
    assert_eq!(resolve_proxy_by_sni(Some("c.com"), &ids, &config), None);
}

#[test]
fn test_resolve_proxy_no_sni_uses_fallback() {
    let config = make_test_config(vec![
        make_proxy("specific", vec!["specific.com"]),
        make_proxy("fallback", vec![]),
    ]);
    let ids = vec!["specific".to_string(), "fallback".to_string()];
    assert_eq!(resolve_proxy_by_sni(None, &ids, &config), Some("fallback"));
}

#[test]
fn test_resolve_proxy_single_id_enforces_hosts() {
    let config = make_test_config(vec![make_proxy("only", vec!["specific.com"])]);
    let ids = vec!["only".to_string()];
    assert_eq!(
        resolve_proxy_by_sni(Some("specific.com"), &ids, &config),
        Some("only")
    );
    assert_eq!(
        resolve_proxy_by_sni(Some("anything.com"), &ids, &config),
        None
    );
    assert_eq!(resolve_proxy_by_sni(None, &ids, &config), None);
}

#[test]
fn test_resolve_proxy_single_id_empty_hosts_is_fallback() {
    let config = make_test_config(vec![make_proxy("only", vec![])]);
    let ids = vec!["only".to_string()];
    assert_eq!(
        resolve_proxy_by_sni(Some("anything.com"), &ids, &config),
        Some("only")
    );
    assert_eq!(resolve_proxy_by_sni(None, &ids, &config), Some("only"));
}

// ── TCP stream peek timeout (slow-loris defense) ─────────────────────────────

/// A peer that connects but never writes must not park the SNI peek forever.
/// With `Some(timeout)`, the call returns `None` shortly after the deadline.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_times_out_when_peer_silent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        let started = std::time::Instant::now();
        let result =
            extract_sni_from_tcp_stream(&server_stream, Some(std::time::Duration::from_millis(50)))
                .await;
        (result, started.elapsed())
    });

    // Connect but never write — simulates the slow-loris attacker.
    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");

    let (result, elapsed) = accept_task.await.expect("accept_task");
    assert_eq!(result, None, "timeout must surface as None");
    assert!(
        elapsed >= std::time::Duration::from_millis(40),
        "returned before timeout fired: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "took far longer than timeout, suggests no bound: {elapsed:?}"
    );
}

/// `None` preserves the historical unbounded behavior. We can't wait
/// "forever" in a unit test, so instead we drive the success path:
/// peer writes a valid ClientHello and the peek returns it.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_no_timeout_succeeds_on_clienthello() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello("example.com");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        extract_sni_from_tcp_stream(&server_stream, None).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&hello).await.expect("write");
    client.flush().await.expect("flush");

    let result = accept_task.await.expect("accept_task");
    assert_eq!(result, Some("example.com".to_string()));
}

/// A peer that writes a valid ClientHello within the timeout still gets
/// its SNI extracted — the timeout only fires when the peer is silent.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_succeeds_within_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello("inside.example.com");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        extract_sni_from_tcp_stream(&server_stream, Some(std::time::Duration::from_secs(5))).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&hello).await.expect("write");
    client.flush().await.expect("flush");

    let result = accept_task.await.expect("accept_task");
    assert_eq!(result, Some("inside.example.com".to_string()));
}

/// A ClientHello that arrives split across multiple TCP segments must still
/// have its SNI extracted: `peek()` returns as soon as ≥1 byte is buffered, so
/// a single peek sees a truncated record (routine for ~1.7 KB post-quantum
/// ClientHellos). The bounded peek loop must wait for the full first record.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_handles_split_clienthello() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello("split.example.com");
    // Split inside the random bytes — well before the SNI extension — so a
    // single-peek parse of the first fragment cannot find the hostname.
    let split_at = 20.min(hello.len() - 1);
    let (first, rest) = hello.split_at(split_at);
    let (first, rest) = (first.to_vec(), rest.to_vec());

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        extract_sni_from_tcp_stream(&server_stream, Some(std::time::Duration::from_secs(5))).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&first).await.expect("write first");
    client.flush().await.expect("flush first");
    // Let the server's first peek observe only the truncated prefix.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    client.write_all(&rest).await.expect("write rest");
    client.flush().await.expect("flush rest");

    let result = accept_task.await.expect("accept_task");
    assert_eq!(result, Some("split.example.com".to_string()));
}

/// Exact host matches must beat wildcard matches regardless of the order the
/// candidate proxies appear in `proxy_ids` (routing tier order: exact,
/// wildcard, catch-all). A wildcard proxy listed first must not steal traffic
/// from an exact-host proxy listed later.
#[test]
fn test_resolve_proxy_exact_beats_wildcard_listed_first() {
    let config = make_test_config(vec![
        make_proxy("wild", vec!["*.example.com"]),
        make_proxy("exact", vec!["foo.example.com"]),
        make_proxy("fallback", vec![]),
    ]);
    let ids = vec![
        "wild".to_string(),
        "exact".to_string(),
        "fallback".to_string(),
    ];
    assert_eq!(
        resolve_proxy_by_sni(Some("foo.example.com"), &ids, &config),
        Some("exact"),
        "exact host must win over an earlier-listed wildcard"
    );
    // Wildcard still matches other subdomains.
    assert_eq!(
        resolve_proxy_by_sni(Some("bar.example.com"), &ids, &config),
        Some("wild")
    );
    // Catch-all still picks up non-matching SNI.
    assert_eq!(
        resolve_proxy_by_sni(Some("other.org"), &ids, &config),
        Some("fallback")
    );
}
