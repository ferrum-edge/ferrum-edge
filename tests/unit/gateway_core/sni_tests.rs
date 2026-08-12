use ferrum_edge::proxy::sni::{
    DtlsSniResult, extract_sni_from_client_hello, extract_sni_from_dtls_client_hello,
    extract_sni_from_tcp_stream, initial_peek_capacity, next_peek_capacity,
    no_deadline_peek_capacity, resolve_proxy_by_sni,
};

fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
    build_tls_client_hello_with_padding_before_sni(hostname, 0)
}

/// Build a TLS ClientHello whose extensions are `padding_len` bytes of TLS
/// padding (type 0x0015) followed by SNI. Used to synthesize modern oversized
/// hellos where SNI lands after fat extensions (PQ key_share / ECH stand-in).
fn build_tls_client_hello_with_padding_before_sni(hostname: &str, padding_len: usize) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let sni_entry_len = 1 + 2 + name_bytes.len();
    let sni_list_len = sni_entry_len;
    let sni_ext_data_len = 2 + sni_list_len;

    let mut extensions = Vec::new();
    if padding_len > 0 {
        // TLS padding extension (RFC 7685): type 0x0015 + length + zeros.
        extensions.extend_from_slice(&0x0015u16.to_be_bytes());
        extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
        extensions.extend_from_slice(&vec![0u8; padding_len]);
    }

    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(name_bytes);

    let extensions_len = extensions.len();
    assert!(
        extensions_len <= u16::MAX as usize,
        "extensions must fit in u16 length field"
    );

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    // A single TLS record can carry at most u16::MAX payload bytes. Fixtures
    // stay under that so they remain one record unless callers re-frame them.
    // The >16 KiB fail-closed peek test intentionally exceeds the peek bound.
    assert!(
        handshake.len() <= u16::MAX as usize,
        "handshake must fit in one TLS record length field"
    );

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
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        pending_limit_scope: None,
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

/// Padding sized so the framed ClientHello exceeds the historical 4096-byte peek
/// cap while remaining under the raised 16 KiB hard bound. SNI is serialized
/// AFTER the padding — matching modern clients that put fat extensions first.
const OVERSIZED_HELLO_PADDING: usize = 4500;

#[test]
fn extract_sni_from_oversized_clienthello_with_sni_after_padding() {
    let data =
        build_tls_client_hello_with_padding_before_sni("pq.example.com", OVERSIZED_HELLO_PADDING);
    assert!(
        data.len() > 4096,
        "fixture must exceed the historical 4096-byte peek cap (got {} bytes)",
        data.len()
    );
    assert!(
        data.len() <= 16 * 1024,
        "fixture must fit in the raised 16 KiB peek bound (got {} bytes)",
        data.len()
    );
    assert_eq!(
        extract_sni_from_client_hello(&data),
        Some("pq.example.com".to_string()),
        "SNI after large padding must still be recovered from an oversized ClientHello"
    );
}

#[test]
fn extract_sni_reassembles_oversized_clienthello_across_tls_records() {
    let single = build_tls_client_hello_with_padding_before_sni(
        "pq-split.example.com",
        OVERSIZED_HELLO_PADDING,
    );
    assert!(single.len() > 4096, "fixture must exceed 4096 bytes");
    // Split early so the padding+SNI trail lives in the second record — exercises
    // multi-record reassembly on an oversized hello, not only the tiny fixture.
    let two_records = split_tls_client_hello_into_records(&single, 64);
    assert_eq!(
        extract_sni_from_client_hello(&two_records),
        Some("pq-split.example.com".to_string()),
        "oversized ClientHello fragmented across TLS records must still yield SNI"
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

/// Regression for issue #2962 on the NO-DEADLINE path: an oversized (>4 KiB)
/// ClientHello whose SNI is serialized after fat extensions must still yield
/// SNI when `handshake_timeout` is `None`. Sizing that path's peek buffer at the
/// 4 KiB lazy floor would truncate the parse and silently misroute the
/// connection to the catch-all proxy whenever
/// `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=0`.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_no_timeout_recovers_oversized_clienthello() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello_with_padding_before_sni(
        "pq-notimeout.example.com",
        OVERSIZED_HELLO_PADDING,
    );
    assert!(
        hello.len() > initial_peek_capacity(),
        "fixture must exceed the lazy peek floor (got {} bytes)",
        hello.len()
    );
    assert!(
        hello.len() < no_deadline_peek_capacity(),
        "fixture must fit inside the hard peek cap (got {} bytes)",
        hello.len()
    );

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        // Let the whole hello land in the receive buffer before the first peek.
        // The no-deadline path does re-peek, but only on a small fixed budget
        // (one initial peek plus at most `MAX_PEEK_READINESS_RETRIES` more, a
        // few milliseconds apart), so this test does not lean on that budget:
        // the hostname must be readable from the very first peek.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        extract_sni_from_tcp_stream(&server_stream, None).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&hello).await.expect("write");
    client.flush().await.expect("flush");

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), accept_task)
        .await
        .expect("no-deadline peek must not hang once the socket is readable")
        .expect("accept_task");
    assert_eq!(
        result,
        Some("pq-notimeout.example.com".to_string()),
        "no-deadline peek must inspect up to the hard cap, not stop at the \
         4 KiB lazy floor (issue #2962)"
    );
}

/// A silent peer on the no-deadline path must leave the peek suspended on
/// socket readiness — holding no ClientHello buffer — rather than returning
/// early, spinning, or blocking. The buffer only exists after the socket is
/// readable, so an idle connection cannot pin a hard-cap allocation.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_no_timeout_waits_on_readiness_when_peer_silent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Held open and deliberately silent for the duration of the test.
    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (server_stream, _) = listener.accept().await.expect("accept");

    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(150),
        extract_sni_from_tcp_stream(&server_stream, None),
    )
    .await;

    assert!(
        outcome.is_err(),
        "no-deadline peek must stay parked on readiness for a silent peer \
         (callers that need a bound pass Some(timeout)); got {outcome:?}"
    );
}

/// Sizing seam for the no-deadline path: every one of its bounded peeks uses the
/// full hard cap, not the lazy-growth floor that the deadline-driven loop starts
/// from.
#[test]
fn no_deadline_peek_uses_hard_cap_not_lazy_floor() {
    assert_eq!(
        no_deadline_peek_capacity(),
        16 * 1024,
        "each no-deadline peek must be able to inspect a standards-valid \
         oversized ClientHello up to the hard cap"
    );
    assert!(
        no_deadline_peek_capacity() > initial_peek_capacity(),
        "the no-deadline peek must not be capped at the lazy-growth floor"
    );
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

/// An oversized (>4096-byte) ClientHello with SNI after padding, delivered in
/// split TCP writes, must still yield SNI under the raised peek bound. A single
/// peek of the first fragment cannot see the hostname.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_handles_split_oversized_clienthello() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello_with_padding_before_sni(
        "pq-tcp.example.com",
        OVERSIZED_HELLO_PADDING,
    );
    assert!(hello.len() > 4096, "fixture must exceed 4096 bytes");
    // Split well before the trailing SNI (inside the early handshake / padding).
    let split_at = 128.min(hello.len() - 1);
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
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    client.write_all(&rest).await.expect("write rest");
    client.flush().await.expect("flush rest");

    let result = accept_task.await.expect("accept_task");
    assert_eq!(
        result,
        Some("pq-tcp.example.com".to_string()),
        "split-write oversized ClientHello with SNI after padding must yield SNI"
    );
}

/// Oversized ClientHello fragmented across TLS records and delivered as separate
/// TCP segments: the peek loop must buffer the full multi-record span (under the
/// 16 KiB hard bound) and reassemble before parsing SNI.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_oversized_split_across_records() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let single = build_tls_client_hello_with_padding_before_sni(
        "pq-rec.example.com",
        OVERSIZED_HELLO_PADDING,
    );
    assert!(single.len() > 4096, "fixture must exceed 4096 bytes");
    let two_records = split_tls_client_hello_into_records(&single, 64);
    // First record = 5-byte TLS header + 64 handshake bytes.
    let (first, rest) = two_records.split_at(5 + 64);
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
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    client.write_all(&rest).await.expect("write rest");
    client.flush().await.expect("flush rest");

    let (result, elapsed) = accept_task.await.expect("accept_task");
    assert_eq!(
        result,
        Some("pq-rec.example.com".to_string()),
        "oversized multi-record ClientHello must yield SNI after reassembly"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "oversized multi-record peek stalled until handshake timeout: {elapsed:?}"
    );
}

/// Lazy peek-buffer sizing: ordinary small ClientHellos must not grow the
/// buffer to the 16 KiB hard cap. The accept path starts at the historical
/// 4 KiB floor and only steps up when the initial buffer is full.
#[test]
fn peek_buffer_starts_small_and_grows_lazily_toward_hard_cap() {
    let initial = initial_peek_capacity();
    assert_eq!(
        initial,
        4 * 1024,
        "initial peek floor must stay at the historical 4 KiB size so ordinary \
         connections do not pay the 16 KiB hard-cap allocation"
    );
    assert!(
        initial < 16 * 1024,
        "initial peek capacity must be strictly below the 16 KiB hard cap"
    );
    // An ordinary small ClientHello (~200-600 bytes) must not trigger growth.
    assert_eq!(
        next_peek_capacity(512),
        initial,
        "small observed prefix must keep capacity at the initial floor"
    );
    assert_eq!(
        next_peek_capacity(initial - 1),
        initial,
        "partial fill of the initial buffer must not grow toward the hard cap"
    );
    // Growth happens only once the initial buffer is full.
    assert_eq!(
        next_peek_capacity(initial),
        16 * 1024,
        "full initial buffer grows to the hard cap in one step"
    );
    assert_eq!(
        next_peek_capacity(16 * 1024),
        16 * 1024,
        "capacity must never exceed the hard peek bound"
    );
}

/// A ClientHello whose handshake span exceeds the 16 KiB hard peek bound, with
/// SNI serialized after the padding, must fail closed (no SNI) rather than
/// allocate unboundedly, wait out the handshake deadline, or invent a hostname
/// from a truncated prefix.
#[tokio::test]
async fn test_extract_sni_from_tcp_stream_fails_closed_when_hello_exceeds_peek_cap() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Padding large enough that the framed hello exceeds 16 KiB and SNI sits
    // past the peek buffer — the parser on the full buffer still finds SNI, but
    // the bounded peek must not.
    let hello = build_tls_client_hello_with_padding_before_sni("overcap.example.com", 20_000);
    assert!(
        hello.len() > 16 * 1024,
        "fixture must exceed the 16 KiB peek bound (got {} bytes)",
        hello.len()
    );
    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("overcap.example.com".to_string()),
        "full-buffer parse control: SNI is present past the peek cap"
    );

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
    client.write_all(&hello).await.expect("write");
    client.flush().await.expect("flush");

    let (result, elapsed) = accept_task.await.expect("accept_task");
    assert_eq!(
        result, None,
        "ClientHello exceeding the hard peek bound with SNI past the cap must \
         fail closed (None), not allocate past the bound or mis-parse a hostname"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "over-cap peek must fail closed at the hard bound without waiting out \
         the handshake deadline: {elapsed:?}"
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

// ── Issue #3264: typed ClientHello classification + opaque-TLS SNI admission ──
//
// The historical `Option<String>` collapsed "well-formed hello with no
// server_name", "not TLS at all", "hello never finished arriving", and
// "malformed hello" into one `None`, and SNI route selection sent all four to
// the listener's catch-all proxy. These tests lock the typed replacement: the
// a complete valid hostname still routes identically, while incomplete or
// malformed hellos are now distinguishable and fail closed even if the lenient
// raw-slice extractor could read an early SNI.

use ferrum_edge::proxy::sni::{
    ClientHelloSni, SniAdmission, SniPeekFailure, SniRefusal, admit_opaque_tls_sni,
    classify_client_hello, peek_client_hello_sni,
};

/// Frame an arbitrary ClientHello extension block into a complete, otherwise
/// well-formed TLS record + handshake message.
fn build_client_hello_with_extension_block(extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session_id_len
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1); // compression_methods_len
    body.push(0); // null compression
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// One complete, non-SNI extension (`status_request`, type 0x0005).
fn non_sni_extension_block() -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0005u16.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext
}

/// One complete RFC 6066 `server_name` extension containing a DNS hostname.
fn sni_extension_block(hostname: &str) -> Vec<u8> {
    let hostname = hostname.as_bytes();
    let hostname_len = u16::try_from(hostname.len()).expect("test hostname fits in u16");
    let server_name_list_len = hostname_len
        .checked_add(3)
        .expect("test ServerNameList length fits in u16");
    let extension_len = server_name_list_len
        .checked_add(2)
        .expect("test extension length fits in u16");

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&extension_len.to_be_bytes());
    ext.extend_from_slice(&server_name_list_len.to_be_bytes());
    ext.push(0x00); // host_name
    ext.extend_from_slice(&hostname_len.to_be_bytes());
    ext.extend_from_slice(hostname);
    ext
}

#[test]
fn classify_reports_hostname_for_a_valid_client_hello() {
    let hello = build_tls_client_hello("tenant-a.example.com");
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Sni("tenant-a.example.com".to_string())
    );
    // Parity with the historical extractor: every `Sni` is a `Some`.
    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("tenant-a.example.com".to_string())
    );
}

#[test]
fn classify_reports_no_sni_for_a_complete_hello_without_server_name() {
    let hello = build_client_hello_with_extension_block(&non_sni_extension_block());
    assert_eq!(classify_client_hello(&hello), ClientHelloSni::NoSni);
    assert_eq!(extract_sni_from_client_hello(&hello), None);
}

#[test]
fn classify_reports_no_sni_for_a_hello_with_no_extension_block() {
    // A TLS 1.0-era hello with an empty extension vector cannot name a host.
    let hello = build_client_hello_with_extension_block(&[]);
    assert_eq!(classify_client_hello(&hello), ClientHelloSni::NoSni);
}

#[test]
fn classify_reports_not_tls_for_plaintext_application_bytes() {
    assert_eq!(
        classify_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ClientHelloSni::NotTls
    );
    // A SOCKS5 greeting, an SMTP banner — anything whose first byte is not a
    // TLS handshake record — is determinately not TLS.
    assert_eq!(
        classify_client_hello(&[0x05, 0x01, 0x00]),
        ClientHelloSni::NotTls
    );
}

#[test]
fn classify_reports_not_tls_for_a_handshake_record_that_is_not_a_client_hello() {
    // Handshake record carrying msg_type 0x02 (ServerHello).
    let record = [0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
    assert_eq!(classify_client_hello(&record), ClientHelloSni::NotTls);
}

#[test]
fn classify_reports_truncated_for_a_partial_client_hello() {
    let hello = build_tls_client_hello("slow.example.com");
    // Cut inside the random bytes, well before the SNI extension.
    let prefix = &hello[..20.min(hello.len() - 1)];
    assert_eq!(
        classify_client_hello(prefix),
        ClientHelloSni::Indeterminate(SniPeekFailure::Truncated)
    );
    // An empty buffer is likewise indeterminate, never "no SNI".
    assert_eq!(
        classify_client_hello(&[]),
        ClientHelloSni::Indeterminate(SniPeekFailure::Truncated)
    );
}

#[test]
fn classify_reports_malformed_for_a_complete_but_invalid_extension_block() {
    // Two bytes of extension block: an extension type with no length field.
    // The lenient walker stops (no SNI) and the strict whole-hello parser
    // refuses, so this must be indeterminate rather than "no SNI".
    let hello = build_client_hello_with_extension_block(&[0x00, 0x0f]);
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::Malformed)
    );
}

#[test]
fn classify_rejects_malformed_data_after_an_early_valid_sni() {
    let mut extensions = sni_extension_block("early.example.com");
    // A second extension begins but omits its length. The historical lenient
    // extractor has already found the first SNI by this point, which is why
    // classification must validate the entire declared ClientHello first.
    extensions.extend_from_slice(&[0x00, 0x0f]);
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("early.example.com".to_string())
    );
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::Malformed),
        "a valid early SNI must not hide malformed trailing extension data"
    );
}

#[test]
fn classify_rejects_duplicate_server_name_extensions() {
    let mut extensions = sni_extension_block("first.example.com");
    extensions.extend_from_slice(&sni_extension_block("second.example.com"));
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("first.example.com".to_string())
    );
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::Malformed),
        "duplicate SNI extensions are malformed and must never select the first tenant"
    );
}

#[test]
fn classify_rejects_duplicate_host_names_inside_one_server_name_extension() {
    let first = sni_extension_block("first.example.com");
    let second = sni_extension_block("second.example.com");
    let first_entry = &first[6..];
    let second_entry = &second[6..];
    let list_len = u16::try_from(first_entry.len() + second_entry.len())
        .expect("test ServerNameList fits in u16");
    let extension_len = list_len
        .checked_add(2)
        .expect("test extension length fits in u16");

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&extension_len.to_be_bytes());
    extensions.extend_from_slice(&list_len.to_be_bytes());
    extensions.extend_from_slice(first_entry);
    extensions.extend_from_slice(second_entry);
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("first.example.com".to_string())
    );
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::Malformed),
        "RFC 6066 permits at most one host_name in a ServerNameList"
    );
}

/// One complete extension of an arbitrary type carrying an empty body.
fn empty_extension_block(ext_type: u16) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&ext_type.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext
}

/// One `server_name` extension whose `ServerNameList` carries the given
/// `(name_type, name_length)` entries, each filled with placeholder bytes.
fn server_name_extension_with_name_types(entries: &[(u8, usize)]) -> Vec<u8> {
    let mut list = Vec::new();
    for &(name_type, name_len) in entries {
        list.push(name_type);
        let encoded_len = u16::try_from(name_len).expect("test name length fits in u16");
        list.extend_from_slice(&encoded_len.to_be_bytes());
        list.extend(std::iter::repeat_n(b'x', name_len));
    }
    let server_name_list_len =
        u16::try_from(list.len()).expect("test ServerNameList length fits in u16");
    let extension_len = server_name_list_len
        .checked_add(2)
        .expect("test extension length fits in u16");

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&extension_len.to_be_bytes());
    ext.extend_from_slice(&server_name_list_len.to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

/// RFC 8446 §4.2 forbids repeating ANY extension type, not only the two the
/// strict whole-hello scan interprets. The lenient extractor returns from the
/// FIRST `server_name` it sees, so without a general duplicate check a hello
/// with a valid early SNI followed by a duplicated generic extension would still
/// be admitted and select a tenant route off a structure the TLS grammar
/// forbids.
#[test]
fn classify_rejects_a_duplicate_generic_extension_after_a_valid_early_sni() {
    let mut extensions = sni_extension_block("early.example.com");
    // `status_request` (0x0005), twice. Neither copy is `server_name` nor
    // `supported_versions`, and each is individually well formed.
    extensions.extend_from_slice(&empty_extension_block(0x0005));
    extensions.extend_from_slice(&empty_extension_block(0x0005));
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("early.example.com".to_string()),
        "the lenient extractor still reads the early SNI — which is exactly why \
         classification has to validate the entire declared ClientHello"
    );
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::Malformed),
        "a duplicate extension of ANY type makes the hello malformed, even when \
         an earlier valid server_name is readable"
    );
}

/// Control for the general duplicate check: distinct extension types after the
/// SNI are ordinary and must still classify as a routable hostname.
#[test]
fn classify_accepts_distinct_generic_extensions_after_a_valid_early_sni() {
    let mut extensions = sni_extension_block("early.example.com");
    extensions.extend_from_slice(&empty_extension_block(0x0005));
    extensions.extend_from_slice(&empty_extension_block(0x0017));
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Sni("early.example.com".to_string()),
        "distinct extension types are not duplicates and must not be refused"
    );
}

/// RFC 6066 §3: "The ServerNameList MUST NOT contain more than one name of the
/// same name_type." That is not a `host_name`-only rule — a list repeating an
/// unknown future type is malformed too.
#[test]
fn classify_rejects_duplicate_unknown_server_name_types() {
    let extensions = server_name_extension_with_name_types(&[(0x7f, 4), (0x7f, 4)]);
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::Malformed),
        "two ServerName entries sharing a name_type are malformed for every \
         name_type, not just host_name"
    );
}

/// The conservative classifier contract for unknown future name types, pinned
/// exactly: DISTINCT unknown types stay structurally valid, so the hello is NOT
/// `Malformed`. It is still refused, because a `server_name` extension is
/// present yet yields no representable `host_name` — `UnrepresentableName` is
/// the fail-closed answer an SNI-routing listener needs, and it must not decay
/// into `NoSni` (which would silently take the catch-all route).
#[test]
fn classify_treats_distinct_unknown_server_name_types_as_unrepresentable_not_malformed() {
    let extensions = server_name_extension_with_name_types(&[(0x7f, 4), (0x80, 4)]);
    let hello = build_client_hello_with_extension_block(&extensions);

    assert_eq!(extract_sni_from_client_hello(&hello), None);
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::UnrepresentableName),
        "distinct unknown name types are structurally accepted; the present but \
         unreadable server_name is what fails the hello closed"
    );
}

#[test]
fn classify_reports_unrepresentable_when_server_name_is_present_but_unreadable() {
    // Underscore labels are accepted by rustls's `DnsName` but deliberately
    // refused by this parser (see `.claude/rules/tls-security.md` — the kTLS
    // handoff depends on the stricter validator). The client still NAMED a
    // host, so an SNI listener must refuse rather than default it to the
    // catch-all.
    let hello = build_tls_client_hello("foo_bar.example.com");
    assert_eq!(extract_sni_from_client_hello(&hello), None);
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Indeterminate(SniPeekFailure::UnrepresentableName)
    );

    // A trailing root dot is the same story: RFC 6066 forbids it in SNI, and
    // this parser rejects it, but the extension was present.
    let dotted = build_tls_client_hello("trailing.example.com.");
    assert_eq!(extract_sni_from_client_hello(&dotted), None);
    assert_eq!(
        classify_client_hello(&dotted),
        ClientHelloSni::Indeterminate(SniPeekFailure::UnrepresentableName)
    );
}

#[test]
fn classify_normalizes_case_the_same_way_the_extractor_does() {
    let hello = build_tls_client_hello("Tenant-A.EXAMPLE.com");
    assert_eq!(
        classify_client_hello(&hello),
        ClientHelloSni::Sni("tenant-a.example.com".to_string()),
        "wire SNI is ASCII-lowercased so it compares against normalized config hosts"
    );
}

#[test]
fn classify_resolves_a_record_fragmented_client_hello() {
    let hello = build_tls_client_hello("fragmented.example.com");
    let split = split_tls_client_hello_into_records(&hello, 25);
    assert_eq!(
        classify_client_hello(&split),
        ClientHelloSni::Sni("fragmented.example.com".to_string()),
        "record fragmentation is protocol-valid and must not read as malformed"
    );
}

#[test]
fn admission_routes_determinate_outcomes_and_refuses_indeterminate_ones() {
    // A named host routes by that host.
    assert_eq!(
        admit_opaque_tls_sni(ClientHelloSni::Sni("a.example.com".into()), false),
        SniAdmission::Route(Some("a.example.com".to_string()))
    );
    // A well-formed hello with no server_name uses the catch-all tier.
    assert_eq!(
        admit_opaque_tls_sni(ClientHelloSni::NoSni, false),
        SniAdmission::Route(None)
    );
    // Non-TLS bytes are refused unless the operator authorized a fallback.
    assert_eq!(
        admit_opaque_tls_sni(ClientHelloSni::NotTls, false),
        SniAdmission::Refuse(SniRefusal::NotTls)
    );
    assert_eq!(
        admit_opaque_tls_sni(ClientHelloSni::NotTls, true),
        SniAdmission::Route(None)
    );
}

/// Security regression: the plaintext-fallback authorization must NOT extend to
/// any indeterminate outcome. Such a connection may have declared any tenant's
/// hostname, so routing it to the catch-all is a cross-tenant downgrade.
#[test]
fn admission_never_lets_the_plaintext_fallback_rescue_an_indeterminate_hello() {
    for failure in [
        SniPeekFailure::Timeout,
        SniPeekFailure::Oversized,
        SniPeekFailure::Eof,
        SniPeekFailure::Truncated,
        SniPeekFailure::Malformed,
        SniPeekFailure::UnrepresentableName,
        SniPeekFailure::Io,
    ] {
        for authorized in [false, true] {
            assert_eq!(
                admit_opaque_tls_sni(ClientHelloSni::Indeterminate(failure), authorized),
                SniAdmission::Refuse(SniRefusal::Indeterminate(failure)),
                "{failure:?} must fail closed regardless of plaintext-fallback authorization"
            );
        }
    }
}

#[tokio::test]
async fn peek_reports_timeout_for_a_silent_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        peek_client_hello_sni(&server_stream, Some(std::time::Duration::from_millis(150))).await
    });

    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    assert_eq!(
        accept_task.await.expect("accept_task"),
        ClientHelloSni::Indeterminate(SniPeekFailure::Timeout),
        "a slow-loris peer must be attributed to the handshake deadline, not routed"
    );
}

#[tokio::test]
async fn peek_unrepresentable_timeout_fails_closed_without_panicking() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        peek_client_hello_sni(&server_stream, Some(std::time::Duration::MAX)).await
    });

    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), accept_task)
        .await
        .expect("an unrepresentable deadline must fail immediately")
        .expect("accept task");

    assert_eq!(
        outcome,
        ClientHelloSni::Indeterminate(SniPeekFailure::Timeout)
    );
}

#[tokio::test]
async fn peek_reports_oversized_when_the_hello_exceeds_the_hard_bound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello_with_padding_before_sni("overcap.example.com", 20_000);
    assert!(hello.len() > 16 * 1024);

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        peek_client_hello_sni(&server_stream, Some(std::time::Duration::from_secs(5))).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&hello).await.expect("write");
    client.flush().await.expect("flush");

    assert_eq!(
        accept_task.await.expect("accept_task"),
        ClientHelloSni::Indeterminate(SniPeekFailure::Oversized),
        "a hello past the 16 KiB peek bound must be attributed, never defaulted"
    );
}

#[tokio::test]
async fn peek_rejects_an_oversized_hello_with_sni_before_the_hard_bound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let mut extensions = sni_extension_block("early-overcap.example.com");
    extensions.extend_from_slice(&0x0015u16.to_be_bytes()); // padding
    extensions.extend_from_slice(&20_000u16.to_be_bytes());
    extensions.extend_from_slice(&vec![0u8; 20_000]);
    let hello = build_client_hello_with_extension_block(&extensions);
    assert!(hello.len() > 16 * 1024);
    assert_eq!(
        extract_sni_from_client_hello(&hello),
        Some("early-overcap.example.com".to_string()),
        "the regression requires the lenient extractor to see SNI before the cap"
    );

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        peek_client_hello_sni(&server_stream, Some(std::time::Duration::from_secs(5))).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&hello).await.expect("write");
    client.flush().await.expect("flush");

    assert_eq!(
        accept_task.await.expect("accept_task"),
        ClientHelloSni::Indeterminate(SniPeekFailure::Oversized),
        "an early SNI must not make an oversized ClientHello routable"
    );
}

#[tokio::test]
async fn peek_reports_not_tls_for_plaintext_bytes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let accept_task = tokio::spawn(async move {
        let (server_stream, _) = listener.accept().await.expect("accept");
        peek_client_hello_sni(&server_stream, Some(std::time::Duration::from_secs(5))).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");

    assert_eq!(
        accept_task.await.expect("accept_task"),
        ClientHelloSni::NotTls
    );
}

/// A ClientHello split across TCP segments must resolve to the SAME hostname
/// (not a truncated refusal), and every peeked byte must still be readable
/// afterwards — peeking is what makes opaque relay byte-exact.
#[tokio::test]
async fn peek_resolves_a_segmented_hello_and_consumes_nothing() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let hello = build_tls_client_hello("segmented.example.com");
    let split_at = 20.min(hello.len() - 1);
    let (first, rest) = hello.split_at(split_at);
    let (first, rest) = (first.to_vec(), rest.to_vec());
    let expected = hello.clone();

    let accept_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let (mut server_stream, _) = listener.accept().await.expect("accept");
        let outcome =
            peek_client_hello_sni(&server_stream, Some(std::time::Duration::from_secs(5))).await;
        // Replay: everything the peek inspected must still be on the socket.
        let mut relayed = vec![0u8; expected.len()];
        server_stream
            .read_exact(&mut relayed)
            .await
            .expect("peeked bytes must still be readable");
        (outcome, relayed)
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    client.write_all(&first).await.expect("write first");
    client.flush().await.expect("flush first");
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    client.write_all(&rest).await.expect("write rest");
    client.flush().await.expect("flush rest");

    let (outcome, relayed) = accept_task.await.expect("accept_task");
    assert_eq!(
        outcome,
        ClientHelloSni::Sni("segmented.example.com".to_string())
    );
    assert_eq!(
        relayed, hello,
        "the peek must not consume: the backend receives the ClientHello verbatim"
    );
}

/// `extract_sni_from_tcp_stream` must keep its exact historical contract: it is
/// now a projection of the typed peek, and every non-`Sni` outcome is `None`.
#[tokio::test]
async fn extractor_stays_a_projection_of_the_typed_peek() {
    for (label, payload) in [
        ("not tls", b"PLAINTEXT-BYTES".to_vec()),
        (
            "no sni",
            build_client_hello_with_extension_block(&non_sni_extension_block()),
        ),
        (
            "malformed",
            build_client_hello_with_extension_block(&[0x00, 0x0f]),
        ),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let accept_task = tokio::spawn(async move {
            let (server_stream, _) = listener.accept().await.expect("accept");
            let typed =
                peek_client_hello_sni(&server_stream, Some(std::time::Duration::from_secs(5)))
                    .await;
            let flat = extract_sni_from_tcp_stream(
                &server_stream,
                Some(std::time::Duration::from_secs(5)),
            )
            .await;
            (typed, flat)
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        use tokio::io::AsyncWriteExt;
        client.write_all(&payload).await.expect("write");
        client.flush().await.expect("flush");

        let (typed, flat) = accept_task.await.expect("accept_task");
        assert!(
            !matches!(typed, ClientHelloSni::Sni(_)),
            "{label}: fixture must not yield a hostname"
        );
        assert_eq!(flat, None, "{label}: the flat extractor still reports None");
    }
}
