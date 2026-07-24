use ferrum_edge::proxy::sni::{
    DtlsSniResult, extract_sni_from_client_hello, extract_sni_from_dtls_client_hello,
    extract_sni_from_tcp_stream, resolve_proxy_by_sni,
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

/// Read a 3-byte big-endian unsigned integer (mirrors `u24_to_usize` in `sni.rs`).
fn u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize)
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
        dispatch_port_override_fallback: None,
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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
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
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
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
fn test_extract_sni_rejects_oversized_hostname() {
    let hostname = "a".repeat(254);
    let data = build_tls_client_hello(&hostname);

    assert_eq!(extract_sni_from_client_hello(&data), None);
}

#[test]
fn test_extract_sni_rejects_invalid_dns_hostname_characters() {
    for hostname in [
        "bad_name.example.com",
        "-bad.example.com",
        "bad-.example.com",
        "bad..example.com",
        "bad.example.com.",
        "bäd.example.com",
    ] {
        let data = build_tls_client_hello(hostname);
        assert_eq!(
            extract_sni_from_client_hello(&data),
            None,
            "hostname {hostname:?} must be rejected"
        );
    }
}

#[test]
fn test_extract_sni_rejects_oversized_label() {
    let hostname = format!("{}.example.com", "a".repeat(64));
    let data = build_tls_client_hello(&hostname);

    assert_eq!(extract_sni_from_client_hello(&data), None);
}

/// Build a presentation-form DNS hostname of exactly 253 bytes where every
/// label is within the 63-byte DNS label limit (63+63+63+61 plus three dots).
fn max_length_dns_hostname(label_byte: u8) -> String {
    let label63 = String::from_utf8(vec![label_byte; 63]).expect("ASCII label byte");
    let label61 = String::from_utf8(vec![label_byte; 61]).expect("ASCII label byte");
    let hostname = format!("{label63}.{label63}.{label63}.{label61}");
    assert_eq!(
        hostname.len(),
        253,
        "fixture must sit on the DNS hostname length boundary"
    );
    assert!(
        hostname.split('.').all(|label| label.len() <= 63),
        "every label must stay within the DNS label limit"
    );
    hostname
}

#[test]
fn test_extract_sni_accepts_max_length_dns_hostname() {
    let hostname = max_length_dns_hostname(b'a');
    let data = build_tls_client_hello(&hostname);

    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some(hostname),
        "a valid 253-byte DNS hostname with labels ≤63 must be accepted"
    );
}

#[test]
fn test_extract_sni_normalizes_uppercase_at_max_length_boundary() {
    let hostname = max_length_dns_hostname(b'A');
    let data = build_tls_client_hello(&hostname);

    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some(hostname.to_ascii_lowercase()),
        "ASCII uppercase SNI at the 253-byte boundary must normalize to lowercase"
    );
}

#[test]
fn test_extract_sni_from_dtls_rejects_oversized_hostname() {
    let hostname = "a".repeat(254);
    let data = build_dtls_client_hello(&hostname);

    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        DtlsSniResult::NoSni
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

/// Re-frame a single-record TLS ClientHello into two TLS records that carry the
/// same handshake message, split at `split_at` handshake bytes — exercises
/// record-fragmentation reassembly.
fn split_tls_client_hello_into_records(single: &[u8], split_at: usize) -> Vec<u8> {
    // single = [0x16, version(2), record_len(2), handshake...]
    let handshake = &single[5..];
    let split = split_at.min(handshake.len());
    let (h1, h2) = handshake.split_at(split);
    let mut out = Vec::new();
    for part in [h1, h2] {
        out.push(0x16);
        out.extend_from_slice(&[0x03, 0x01]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[test]
fn extract_sni_reassembles_clienthello_across_tls_records() {
    let single = build_tls_client_hello("split.example.com");
    // Split mid-handshake so the SNI (in the trailing extensions) lands in the
    // SECOND record — the old single-record parser silently missed it.
    let two_records = split_tls_client_hello_into_records(&single, 10);
    assert_eq!(
        extract_sni_from_client_hello(&two_records),
        Some("split.example.com".to_string()),
        "SNI in a later TLS record must be reassembled across records and found"
    );
}

#[test]
fn extract_sni_single_record_fast_path_unchanged() {
    // The common single-record case must still parse (fast path, no reassembly).
    let data = build_tls_client_hello("whole.example.com");
    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some("whole.example.com".to_string())
    );
}

/// Build a DTLS ClientHello record marked as a continuation fragment
/// (`fragment_offset` > 0). The handshake header starts at record offset 13;
/// `fragment_offset` is handshake bytes 6..9 → record bytes 19..22.
fn build_dtls_continuation_fragment(hostname: &str) -> Vec<u8> {
    let mut record = build_dtls_client_hello(hostname);
    record[19] = 0x00;
    record[20] = 0x00;
    record[21] = 0x10; // fragment_offset = 16 (mid-message)
    record
}

#[test]
fn extract_dtls_sni_fails_closed_on_continuation_fragment() {
    let frag = build_dtls_continuation_fragment("frag.example.com");
    assert_eq!(
        extract_sni_from_dtls_client_hello(&frag),
        DtlsSniResult::InvalidFragment,
        "a DTLS continuation fragment (fragment_offset > 0) must signal \
         InvalidFragment so the caller DROPS it — returning NoSni would let it \
         bind to the empty-host catch-all instead of being dropped"
    );
}

/// Build the INITIAL fragment (`fragment_offset == 0`) of a DTLS ClientHello that
/// is fragmented across datagrams: the handshake `length` stays the full message
/// length while `fragment_length` (and the buffered body) is truncated to
/// `frag_body_len` bytes, so the SNI extension (in the trailing extensions) is
/// NOT present in this datagram. Layout (record-relative): handshake starts at
/// offset 13; `length` = handshake bytes 1..4 (record 14..17), `fragment_offset`
/// = handshake bytes 6..9 (record 19..22), `fragment_length` = handshake bytes
/// 9..12 (record 22..25), body starts at record offset 25.
fn build_dtls_first_fragment(hostname: &str, frag_body_len: usize) -> Vec<u8> {
    let full = build_dtls_client_hello(hostname);
    // Total handshake message length (handshake bytes 1..4 → record 14..16).
    let total_len = u24(&full[14..17]);
    assert!(
        frag_body_len < total_len,
        "first fragment must carry fewer body bytes than the full message"
    );

    // Rebuild a record that keeps the full `length` but a truncated body and a
    // matching `fragment_length`, so offset 0 + fragment_length < length.
    let mut record = Vec::new();
    record.extend_from_slice(&full[..13]); // DTLS record header (rewrite len below)
    record.extend_from_slice(&full[13..14]); // msg_type (0x01)
    record.extend_from_slice(&full[14..17]); // length: full message length (unchanged)
    record.extend_from_slice(&full[17..19]); // message_seq
    record.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset: 0 (initial)
    record.push((frag_body_len >> 16) as u8); // fragment_length: truncated
    record.push((frag_body_len >> 8) as u8);
    record.push(frag_body_len as u8);
    // Only the first `frag_body_len` body bytes (body starts at record offset 25).
    record.extend_from_slice(&full[25..25 + frag_body_len]);

    // Fix the DTLS record length (bytes 11..13) = 12-byte handshake header + body.
    let record_payload_len = (12 + frag_body_len) as u16;
    record[11..13].copy_from_slice(&record_payload_len.to_be_bytes());
    record
}

#[test]
fn extract_dtls_sni_fails_closed_on_initial_fragment_without_sni() {
    // Initial fragment (offset 0) carrying only 16 body bytes — version (2) +
    // part of random (14): well before the SNI extension. Because the full
    // message is longer, `fragment_length < length`, so the parser cannot find
    // SNI in this datagram and must fail closed rather than route to catch-all.
    let frag = build_dtls_first_fragment("frag.example.com", 16);
    assert_eq!(
        extract_sni_from_dtls_client_hello(&frag),
        DtlsSniResult::InvalidFragment,
        "an initial DTLS fragment (offset 0, fragment_length < length) whose SNI \
         lives in a later fragment must signal InvalidFragment — returning NoSni \
         would bind the partial ClientHello to the empty-host catch-all"
    );
}

#[test]
fn extract_dtls_sni_unfragmented_still_parses() {
    let data = build_dtls_client_hello("whole.example.com");
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        DtlsSniResult::Hostname("whole.example.com".to_string()),
        "an unfragmented DTLS ClientHello (offset 0, full length) must still parse"
    );
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
        DtlsSniResult::Hostname("dtls.example.com".to_string())
    );
}

#[test]
fn test_extract_sni_from_dtls_case_normalized() {
    let data = build_dtls_client_hello("DTLS.Example.COM");
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        DtlsSniResult::Hostname("dtls.example.com".to_string())
    );
}

#[test]
fn test_extract_sni_from_dtls_truncated() {
    // Too short to be a DTLS handshake — not a continuation fragment, so it stays
    // catch-all eligible (NoSni), preserving the historical no-SNI routing.
    assert_eq!(
        extract_sni_from_dtls_client_hello(&[]),
        DtlsSniResult::NoSni
    );
    assert_eq!(
        extract_sni_from_dtls_client_hello(&[0x16; 10]),
        DtlsSniResult::NoSni
    );
}

#[test]
fn test_extract_sni_from_dtls_wrong_content_type() {
    let mut data = build_dtls_client_hello("example.com");
    data[0] = 0x17;
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        DtlsSniResult::NoSni
    );
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
    // Malformed body (offset 0, so not a continuation fragment) → catch-all
    // eligible NoSni, not InvalidFragment.
    let mut data = build_dtls_client_hello("example.com");
    data[60] = 0xFF;
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        DtlsSniResult::NoSni
    );
}

#[test]
fn test_extract_sni_dtls_wrong_handshake_type() {
    // Non-ClientHello handshake type → NoSni (catch-all eligible), matching the
    // historical no-SNI routing; only a continuation fragment is InvalidFragment.
    let mut data = build_dtls_client_hello("example.com");
    data[13] = 0x02;
    assert_eq!(
        extract_sni_from_dtls_client_hello(&data),
        DtlsSniResult::NoSni
    );
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

/// A peer that writes one non-TLS byte and stalls must be rejected as soon as
/// that prefix is visible, not kept around until the full handshake timeout.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_rejects_non_tls_prefix_immediately() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        let started = std::time::Instant::now();
        let result =
            extract_sni_from_tcp_stream(&server_stream, Some(std::time::Duration::from_secs(1)))
                .await;
        (result, started.elapsed())
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(b"G").await.expect("write prefix");
    client.flush().await.expect("flush prefix");

    let (result, elapsed) = accept_task.await.expect("accept_task");
    assert_eq!(result, None, "non-TLS prefix must not produce SNI");
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "non-TLS prefix waited for the handshake timeout: {elapsed:?}"
    );
}

/// A peer that writes a COMPLETE handshake record whose `msg_type` is not
/// ClientHello (`0x01`) — here a ServerHello (`0x02`) — and then stalls must be
/// rejected as soon as that record is buffered, not re-peeked until the full
/// handshake timeout. The msg_type alone is enough to decide this is not a
/// ClientHello, so the peek loop must stop promptly.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_rejects_complete_non_clienthello_record_immediately() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // A valid TLS handshake record, but with msg_type flipped to ServerHello.
    // Record layout: [0x16, version(2), record_len(2), msg_type, ...]; the
    // handshake msg_type is at record offset 5.
    let mut not_hello = build_tls_client_hello("example.com");
    not_hello[5] = 0x02; // ServerHello, a complete-but-not-ClientHello handshake.

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        let started = std::time::Instant::now();
        let result =
            extract_sni_from_tcp_stream(&server_stream, Some(std::time::Duration::from_secs(1)))
                .await;
        (result, started.elapsed())
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&not_hello).await.expect("write record");
    client.flush().await.expect("flush record");
    // Keep the socket open and silent — a non-prompt loop would re-peek the same
    // bytes until the 1s handshake timeout.

    let (result, elapsed) = accept_task.await.expect("accept_task");
    assert_eq!(
        result, None,
        "a complete non-ClientHello record must not produce SNI"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "complete non-ClientHello record re-peeked until the handshake timeout \
         instead of rejecting promptly: {elapsed:?}"
    );
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

/// Record fragmentation can split the handshake message *inside* its own 4-byte
/// header — here after only the 1-byte msg_type, so the u24 length lives in the
/// SECOND TLS record. The wire-span computation must reassemble those 4 header
/// bytes across records before reading the length; reading a fixed `buf[6..9]`
/// would capture the next record's header, compute a bogus span, and stall the
/// peek until the handshake timeout. Each record is delivered in its own TCP
/// segment so the peek loop genuinely observes the partial header first.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_header_split_across_records() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let single = build_tls_client_hello("hdrsplit.example.com");
    // Split at handshake byte 1: record 1 carries ONLY the msg_type (0x01); the
    // 3-byte handshake length (and everything after) lands in record 2.
    let two_records = split_tls_client_hello_into_records(&single, 1);
    // record 1 = 5-byte TLS header + 1 handshake byte = 6 bytes.
    let (first, rest) = two_records.split_at(6);
    let (first, rest) = (first.to_vec(), rest.to_vec());

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        let started = std::time::Instant::now();
        let result =
            extract_sni_from_tcp_stream(&server_stream, Some(std::time::Duration::from_secs(5)))
                .await;
        (result, started.elapsed())
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&first).await.expect("write first");
    client.flush().await.expect("flush first");
    // Let the server's first peek observe only the first record (partial header).
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    client.write_all(&rest).await.expect("write rest");
    client.flush().await.expect("flush rest");

    let (result, elapsed) = accept_task.await.expect("accept_task");
    assert_eq!(
        result,
        Some("hdrsplit.example.com".to_string()),
        "SNI must be found when the handshake header is split across TLS records"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "header-split ClientHello stalled until the handshake timeout instead of \
         reassembling the handshake header across records: {elapsed:?}"
    );
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
