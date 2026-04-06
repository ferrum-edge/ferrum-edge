//! SNI (Server Name Indication) extraction from TLS/DTLS ClientHello messages.
//!
//! Used by passthrough mode to peek at the ClientHello without terminating TLS,
//! extracting the SNI hostname for logging and routing decisions.

/// Maximum bytes to peek from a TCP stream for ClientHello SNI extraction.
/// A typical ClientHello is 200-600 bytes; 4096 covers large cipher suite lists.
const MAX_CLIENT_HELLO_LEN: usize = 4096;

/// Extract the SNI hostname from a TLS ClientHello by peeking at a TCP stream.
///
/// Uses `TcpStream::peek()` to read bytes without consuming them, so the same
/// stream can be forwarded to the backend with the ClientHello intact.
///
/// Returns `None` if the data is not a valid TLS ClientHello or has no SNI extension.
pub async fn extract_sni_from_tcp_stream(stream: &tokio::net::TcpStream) -> Option<String> {
    let mut buf = vec![0u8; MAX_CLIENT_HELLO_LEN];
    let n = stream.peek(&mut buf).await.ok()?;
    extract_sni_from_client_hello(&buf[..n])
}

/// Extract the SNI hostname from a TLS ClientHello byte slice.
///
/// Parses the TLS record layer and handshake message to find the
/// server_name extension (type 0x0000) per RFC 6066 §3.
///
/// Works for both TLS 1.2 and TLS 1.3 ClientHello messages.
pub fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // TLS record header: content_type (1) + version (2) + length (2) = 5 bytes
    if data.len() < 5 {
        return None;
    }

    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let handshake_data = data.get(5..5 + record_len.min(data.len() - 5))?;

    parse_client_hello_sni(handshake_data)
}

/// Extract the SNI hostname from a DTLS ClientHello datagram.
///
/// DTLS uses a 13-byte record header (vs 5 for TLS) and a 12-byte handshake
/// header (vs 4 for TLS) with epoch, sequence number, and fragment offsets.
pub fn extract_sni_from_dtls_client_hello(data: &[u8]) -> Option<String> {
    // DTLS record header: content_type (1) + version (2) + epoch (2) +
    //                     sequence_number (6) + length (2) = 13 bytes
    if data.len() < 13 {
        return None;
    }

    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[11], data[12]]) as usize;
    let handshake_data = data.get(13..13 + record_len.min(data.len() - 13))?;

    // DTLS handshake header: msg_type (1) + length (3) + message_seq (2) +
    //                        fragment_offset (3) + fragment_length (3) = 12 bytes
    if handshake_data.len() < 12 {
        return None;
    }

    // msg_type 0x01 = ClientHello
    if handshake_data[0] != 0x01 {
        return None;
    }

    let fragment_len = u24_to_usize(&handshake_data[9..12]);
    let client_hello = handshake_data.get(12..12 + fragment_len.min(handshake_data.len() - 12))?;

    parse_dtls_client_hello_body(client_hello)
}

/// Parse the SNI from a TLS handshake payload (after the 5-byte TLS record header).
fn parse_client_hello_sni(handshake: &[u8]) -> Option<String> {
    // Handshake header: msg_type (1) + length (3) = 4 bytes
    if handshake.len() < 4 {
        return None;
    }

    // msg_type 0x01 = ClientHello
    if handshake[0] != 0x01 {
        return None;
    }

    let body_len = u24_to_usize(&handshake[1..4]);
    let body = handshake.get(4..4 + body_len.min(handshake.len() - 4))?;

    parse_tls_client_hello_body(body)
}

/// Parse the SNI from a TLS ClientHello body (after handshake header).
///
/// Layout: version (2) + random (32) + session_id_len (1) + session_id (N) +
///         cipher_suites_len (2) + cipher_suites (N) + compression_len (1) +
///         compression (N) + extensions_len (2) + extensions (N)
fn parse_tls_client_hello_body(body: &[u8]) -> Option<String> {
    let mut pos: usize = 0;

    // version (2) + random (32)
    pos = pos.checked_add(34)?;
    if body.len() < pos {
        return None;
    }

    // session_id
    let session_id_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + session_id_len)?;
    if body.len() < pos {
        return None;
    }

    // cipher_suites
    if body.len() < pos + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2 + cipher_suites_len)?;
    if body.len() < pos {
        return None;
    }

    // compression_methods
    let compression_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + compression_len)?;
    if body.len() < pos {
        return None;
    }

    // extensions
    if body.len() < pos + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len.min(body.len() - pos);
    parse_sni_from_extensions(&body[pos..extensions_end])
}

/// Parse the SNI from a DTLS ClientHello body (after handshake header).
///
/// Layout: version (2) + random (32) + session_id_len (1) + session_id (N) +
///         cookie_len (1) + cookie (N) + cipher_suites_len (2) + cipher_suites (N) +
///         compression_len (1) + compression (N) + extensions_len (2) + extensions (N)
fn parse_dtls_client_hello_body(body: &[u8]) -> Option<String> {
    let mut pos: usize = 0;

    // version (2) + random (32)
    pos = pos.checked_add(34)?;
    if body.len() < pos {
        return None;
    }

    // session_id
    let session_id_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + session_id_len)?;
    if body.len() < pos {
        return None;
    }

    // cookie (DTLS-specific, not present in TLS)
    let cookie_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + cookie_len)?;
    if body.len() < pos {
        return None;
    }

    // cipher_suites
    if body.len() < pos + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2 + cipher_suites_len)?;
    if body.len() < pos {
        return None;
    }

    // compression_methods
    let compression_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + compression_len)?;
    if body.len() < pos {
        return None;
    }

    // extensions
    if body.len() < pos + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len.min(body.len() - pos);
    parse_sni_from_extensions(&body[pos..extensions_end])
}

/// Walk the TLS extensions list and extract the hostname from the SNI extension.
///
/// Extension format: type (2) + length (2) + data (N)
/// SNI extension (type 0x0000) data: list_length (2) + name_type (1) + name_length (2) + name (N)
fn parse_sni_from_extensions(mut ext: &[u8]) -> Option<String> {
    while ext.len() >= 4 {
        let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
        let ext_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;

        if ext.len() < 4 + ext_len {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI extension
            let sni_data = &ext[4..4 + ext_len];
            return parse_sni_hostname(sni_data);
        }

        ext = &ext[4 + ext_len..];
    }
    None
}

/// Parse the hostname from SNI extension data.
///
/// SNI list: total_length (2) + entries...
/// Each entry: name_type (1) + name_length (2) + name (N)
/// name_type 0x00 = host_name (DNS hostname)
fn parse_sni_hostname(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;

    while pos + 3 <= data.len() {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > data.len() {
            return None;
        }

        if name_type == 0x00 {
            // host_name
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.to_lowercase());
        }

        pos += name_len;
    }
    None
}

/// Read a 3-byte big-endian unsigned integer.
fn u24_to_usize(data: &[u8]) -> usize {
    ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize)
}

/// Resolve which proxy should handle a connection based on SNI hostname.
///
/// Given an extracted SNI and a list of candidate proxy IDs (all sharing the
/// same listen_port with `passthrough: true`), finds the matching proxy by
/// comparing the SNI against each proxy's `hosts` field.
///
/// Matching rules (in priority order):
/// 1. Exact host match (case-insensitive, SNI is already lowercased)
/// 2. Wildcard host match (e.g., `*.example.com` matches `foo.example.com`)
/// 3. Fallback: first proxy with empty `hosts` (catch-all/default)
/// 4. If no match and no fallback: `None`
pub fn resolve_proxy_by_sni<'a>(
    sni: Option<&str>,
    proxy_ids: &'a [String],
    config: &crate::config::types::GatewayConfig,
) -> Option<&'a str> {
    if proxy_ids.len() == 1 {
        return Some(&proxy_ids[0]);
    }

    let mut fallback: Option<&'a str> = None;

    for proxy_id in proxy_ids {
        let proxy = config.proxies.iter().find(|p| p.id == *proxy_id)?;

        if proxy.hosts.is_empty() {
            // Empty hosts = catch-all, use as fallback
            if fallback.is_none() {
                fallback = Some(proxy_id.as_str());
            }
            continue;
        }

        if let Some(hostname) = sni {
            for host in &proxy.hosts {
                if host == hostname || crate::config::types::wildcard_matches(host, hostname) {
                    return Some(proxy_id.as_str());
                }
            }
        }
    }

    // No exact/wildcard match — use fallback (catch-all proxy) if available
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.2 ClientHello with the given SNI hostname.
    fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
        // SNI extension data
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 1 + 2 + name_bytes.len(); // name_type + name_len + name
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len; // list_length + entries

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type: server_name
        sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes()); // extension data length
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes()); // server name list length
        sni_ext.push(0x00); // name_type: host_name
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        // Extensions total
        let extensions_len = sni_ext.len();

        // ClientHello body
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version: TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length: 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length: 2
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(1); // compression_methods length: 1
        body.push(0); // null compression
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);

        // Handshake header
        let mut handshake = Vec::new();
        handshake.push(0x01); // msg_type: ClientHello
        let body_len = body.len();
        handshake.push((body_len >> 16) as u8);
        handshake.push((body_len >> 8) as u8);
        handshake.push(body_len as u8);
        handshake.extend_from_slice(&body);

        // TLS record header
        let mut record = Vec::new();
        record.push(0x16); // content_type: Handshake
        record.extend_from_slice(&[0x03, 0x01]); // version: TLS 1.0 (record layer)
        let hs_len = handshake.len();
        record.extend_from_slice(&(hs_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    /// Build a minimal DTLS 1.2 ClientHello datagram with the given SNI hostname.
    fn build_dtls_client_hello(hostname: &str) -> Vec<u8> {
        // SNI extension data (same format as TLS)
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

        // DTLS ClientHello body (has cookie field that TLS doesn't)
        let mut body = Vec::new();
        body.extend_from_slice(&[0xfe, 0xfd]); // version: DTLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length: 0
        body.push(0); // cookie length: 0 (DTLS-specific)
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length: 2
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(1); // compression_methods length: 1
        body.push(0); // null compression
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);

        // DTLS handshake header (12 bytes vs TLS 4 bytes)
        let mut handshake = Vec::new();
        handshake.push(0x01); // msg_type: ClientHello
        let body_len = body.len();
        handshake.push((body_len >> 16) as u8);
        handshake.push((body_len >> 8) as u8);
        handshake.push(body_len as u8);
        handshake.extend_from_slice(&[0x00, 0x00]); // message_seq: 0
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset: 0
        handshake.push((body_len >> 16) as u8);
        handshake.push((body_len >> 8) as u8);
        handshake.push(body_len as u8); // fragment_length = body_len

        handshake.extend_from_slice(&body);

        // DTLS record header (13 bytes vs TLS 5 bytes)
        let mut record = Vec::new();
        record.push(0x16); // content_type: Handshake
        record.extend_from_slice(&[0xfe, 0xfd]); // version: DTLS 1.2
        record.extend_from_slice(&[0x00, 0x00]); // epoch: 0
        record.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // sequence: 1
        let hs_len = handshake.len();
        record.extend_from_slice(&(hs_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_extract_sni_from_tls_client_hello() {
        let data = build_tls_client_hello("example.com");
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_case_normalized() {
        let data = build_tls_client_hello("Example.COM");
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_long_hostname() {
        let hostname = "very-long-subdomain.another.example.internal.corp.example.com";
        let data = build_tls_client_hello(hostname);
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_extract_sni_no_sni_extension() {
        // Build a ClientHello with no extensions
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length: 0
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes()); // extensions length: 0

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
        data[0] = 0x17; // Application data, not handshake
        assert_eq!(extract_sni_from_client_hello(&data), None);
    }

    #[test]
    fn test_extract_sni_wrong_handshake_type() {
        let mut data = build_tls_client_hello("example.com");
        data[5] = 0x02; // ServerHello, not ClientHello
        assert_eq!(extract_sni_from_client_hello(&data), None);
    }

    #[test]
    fn test_extract_sni_from_dtls_client_hello() {
        let data = build_dtls_client_hello("dtls.example.com");
        let sni = extract_sni_from_dtls_client_hello(&data);
        assert_eq!(sni, Some("dtls.example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_from_dtls_case_normalized() {
        let data = build_dtls_client_hello("DTLS.Example.COM");
        let sni = extract_sni_from_dtls_client_hello(&data);
        assert_eq!(sni, Some("dtls.example.com".to_string()));
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

    // --- resolve_proxy_by_sni tests ---

    fn make_test_config(
        proxies: Vec<crate::config::types::Proxy>,
    ) -> crate::config::types::GatewayConfig {
        crate::config::types::GatewayConfig {
            version: "1".to_string(),
            proxies,
            consumers: vec![],
            plugin_configs: vec![],
            upstreams: vec![],
            loaded_at: chrono::Utc::now(),
        }
    }

    fn make_proxy(id: &str, hosts: Vec<&str>) -> crate::config::types::Proxy {
        crate::config::types::Proxy {
            id: id.to_string(),
            name: None,
            hosts: hosts.into_iter().map(String::from).collect(),
            listen_path: String::new(),
            backend_protocol: crate::config::types::BackendProtocol::Tcp,
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
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: crate::config::types::AuthMode::Single,
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
            upstream_id: None,
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
    fn test_resolve_proxy_single_id_always_matches() {
        let config = make_test_config(vec![make_proxy("only", vec!["specific.com"])]);
        let ids = vec!["only".to_string()];
        assert_eq!(
            resolve_proxy_by_sni(Some("anything.com"), &ids, &config),
            Some("only")
        );
    }
}
