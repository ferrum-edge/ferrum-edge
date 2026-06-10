//! SNI (Server Name Indication) extraction from TLS/DTLS ClientHello messages.
//!
//! Used by passthrough mode to peek at the ClientHello without terminating TLS,
//! extracting the SNI hostname for logging and routing decisions.

/// Maximum bytes to peek from a TCP stream for ClientHello SNI extraction.
/// A typical ClientHello is 200-600 bytes; 4096 covers large cipher suite lists.
const MAX_CLIENT_HELLO_LEN: usize = 4096;

/// Polling interval between peeks while waiting for the rest of a partially
/// arrived ClientHello (mirrors `STREAM_FIRST_BYTES_PEEK_RETRY_INTERVAL` in
/// `tcp_proxy.rs` — `peek()` returns as soon as ≥1 byte is readable, so
/// back-to-back peeks would busy-loop).
const SNI_PEEK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Extract the SNI hostname from a TLS ClientHello by peeking at a TCP stream.
///
/// Uses `TcpStream::peek()` to read bytes without consuming them, so the same
/// stream can be forwarded to the backend with the ClientHello intact.
///
/// `handshake_timeout` bounds how long the peek can wait for the ClientHello
/// before giving up. A `None` value preserves the single-peek behavior used by
/// internal callers that have already enforced a deadline elsewhere; passthrough
/// listeners pass `Some(d)` (mapped from `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`)
/// so a peer that opens a TCP connection and sends nothing cannot park a
/// connection-handler task indefinitely.
///
/// When a deadline is set, the peek LOOPS until the full first TLS record
/// (`5 + record_len` bytes, capped at [`MAX_CLIENT_HELLO_LEN`]) is buffered.
/// `peek()` returns as soon as ≥1 byte is readable, so a single peek sees a
/// truncated ClientHello whenever it spans multiple TCP segments — routine for
/// modern ~1.7 KB post-quantum ClientHellos — and a truncated parse silently
/// misroutes the connection to the catch-all proxy. Mirrors the bounded peek
/// loop in `tcp_proxy::peek_tcp_first_bytes`.
///
/// Returns `None` if the data is not a valid TLS ClientHello, has no SNI
/// extension, the peek fails, or the timeout fires.
pub async fn extract_sni_from_tcp_stream(
    stream: &tokio::net::TcpStream,
    handshake_timeout: Option<std::time::Duration>,
) -> Option<String> {
    let mut buf = vec![0u8; MAX_CLIENT_HELLO_LEN];
    let Some(d) = handshake_timeout else {
        // No deadline: take a single peek and never loop, so a stalled peer
        // cannot park the task waiting for a record that never completes.
        let n = stream.peek(&mut buf).await.ok()?;
        return extract_sni_from_client_hello(&buf[..n]);
    };

    let deadline = tokio::time::Instant::now() + d;
    let mut have = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(0)) => return None, // EOF before a complete ClientHello
            Ok(Ok(n)) => have = n,
            Ok(Err(_)) => return None,
            Err(_) => {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                tracing::debug!(
                    peer = %peer,
                    timeout_ms = d.as_millis() as u64,
                    buffered = have,
                    "TCP passthrough SNI peek timed out before full ClientHello arrived"
                );
                // Parse whatever prefix was observed — a complete-but-slow
                // record already parsed below, so this only salvages the
                // (unlikely) case where SNI sits inside the partial prefix.
                return extract_sni_from_client_hello(&buf[..have]);
            }
        }
        // Need the 5-byte record header to know the full record length.
        if have >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let want = (5 + record_len).min(MAX_CLIENT_HELLO_LEN);
            if have >= want || buf[0] != 0x16 {
                // Full first record buffered (or not a TLS handshake record at
                // all — parse fails fast without waiting out the deadline).
                return extract_sni_from_client_hello(&buf[..have]);
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return extract_sni_from_client_hello(&buf[..have]);
        }
        let wake = (now + SNI_PEEK_RETRY_INTERVAL).min(deadline);
        tokio::time::sleep_until(wake).await;
    }
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

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + list_len {
        return None;
    }

    let names = &data[2..];
    let mut pos = 0;

    while pos + 3 <= names.len() {
        let name_type = names[pos];
        let name_len = u16::from_be_bytes([names[pos + 1], names[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > names.len() {
            return None;
        }

        if name_type == 0x00 {
            // host_name
            return std::str::from_utf8(&names[pos..pos + name_len])
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
    let mut fallback: Option<&'a str> = None;
    let mut wildcard_match: Option<&'a str> = None;

    for proxy_id in proxy_ids {
        let Some(proxy) = config.proxies.iter().find(|p| p.id == *proxy_id) else {
            continue;
        };

        if proxy.hosts.is_empty() {
            // Empty hosts = catch-all, use as fallback
            if fallback.is_none() {
                fallback = Some(proxy_id.as_str());
            }
            continue;
        }

        if let Some(hostname) = sni {
            for host in &proxy.hosts {
                if host == hostname {
                    // Exact match wins immediately — a wildcard proxy listed
                    // earlier in `proxy_ids` must not steal traffic from an
                    // exact-host proxy (routing tier order: exact, wildcard,
                    // catch-all).
                    return Some(proxy_id.as_str());
                }
                if wildcard_match.is_none()
                    && crate::config::types::wildcard_matches(host, hostname)
                {
                    wildcard_match = Some(proxy_id.as_str());
                }
            }
        }
    }

    // No exact match — first wildcard match, then catch-all fallback
    wildcard_match.or(fallback)
}
