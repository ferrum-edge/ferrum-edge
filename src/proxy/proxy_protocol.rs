//! Inbound PROXY protocol v1 (text) and v2 (binary) parser.
//!
//! This module parses the PROXY protocol header that a load balancer or
//! reverse proxy prepends to each TCP connection before forwarding it. The
//! header carries the original client address so the backend can see the real
//! source IP rather than the LB's own IP.
//!
//! # Security model
//!
//! Only enable PROXY protocol on listeners that are exclusively reachable via
//! a trusted load balancer. The per-proxy `stream_proxy_protocol: true` flag
//! is opt-in; when set, **every** connection must begin with a valid PROXY
//! header — a connection that does not is closed immediately (fail closed),
//! preventing a direct-connect client from bypassing IP-based authz.
//!
//! Additionally, the forwarded address is honored only when the socket peer
//! (the LB's own IP) belongs to the configured `FERRUM_TRUSTED_PROXIES` CIDR
//! set. An un-trusted peer causes the connection to be closed; silently
//! ignoring the header would mislead downstream authz plugins.
//!
//! # Spec references
//!
//! - PROXY protocol v1: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//! - PROXY protocol v2: same document, section 2.2 onwards.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::warn;

/// Outcome of parsing the PROXY protocol header from an inbound TCP stream.
#[derive(Debug)]
pub enum ProxyProtocolResult {
    /// A forwarded source address was parsed and should be used as the
    /// resolved `client_ip`. The socket peer remains the `direct_client_ip`.
    Forwarded {
        src: SocketAddr,
        #[allow(dead_code)]
        dst: SocketAddr,
    },
    /// The header was a v2 LOCAL command or a v1/v2 UNKNOWN/unrecognised
    /// family — treat the socket peer as the client (health checks from the LB
    /// itself; pass-through for connection-level checks).
    NoAddress,
}

/// Error variants for PROXY protocol parsing.
#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolError {
    /// The header did not begin with a valid v1 or v2 signature.
    #[error("invalid PROXY protocol signature")]
    InvalidSignature,
    /// A v1 line exceeded the 108-byte limit before CRLF was found.
    #[error("PROXY v1 header too long (max 107 bytes before CRLF)")]
    V1TooLong,
    /// A v2 header declared an address-block length that exceeds the safety cap.
    #[error("PROXY v2 address block length {0} exceeds safety cap")]
    V2LengthExceeded(u16),
    /// Malformed content that does not match the spec.
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(String),
    /// Underlying I/O error.
    #[error("I/O error reading PROXY header: {0}")]
    Io(#[from] std::io::Error),
    /// Read timeout waiting for the PROXY header bytes.
    #[error("timeout reading PROXY protocol header")]
    Timeout,
}

// PROXY v2 signature: 12-byte fixed prefix
const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
// PROXY v1 prefix
const V1_PREFIX: &[u8; 6] = b"PROXY ";
// Maximum v2 address-block length we will read. The fixed address
// blocks are at most 36 bytes (AF_INET6: 16+16+2+2). We set the cap
// to 512 to allow for implementation-defined TLV extensions (e.g. AWS
// VPC Lattice, HAProxy custom TLVs) that appear after the address pair.
// Anything longer is rejected to bound memory; per spec the address
// block can carry arbitrary TLVs after the AF_INET / AF_INET6 portion.
const V2_MAX_ADDR_LEN: u16 = 512;
// PROXY v1: maximum total line length is 107 bytes + CRLF = 109 bytes.
// `rest` holds the full line including the 6-byte "PROXY " prefix and the
// CRLF terminator, so the cap must cover all 109 bytes.
const V1_MAX_LEN: usize = 109;

/// Parse the PROXY protocol header from `stream`.
///
/// Reads just enough bytes to auto-detect v1 vs v2. On success returns the
/// forwarded address pair (or `NoAddress` for LOCAL / UNKNOWN). On error the
/// caller must close the connection immediately — do not continue relaying.
///
/// The `timeout` is applied to the entire read. A `None` timeout means
/// the default 5-second safety timeout is used.
pub async fn read_proxy_header<R>(
    stream: &mut R,
    timeout_secs: Option<u64>,
) -> Result<ProxyProtocolResult, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let secs = timeout_secs.unwrap_or(5);
    let fut = parse_proxy_header(stream);
    match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProxyProtocolError::Timeout),
    }
}

async fn parse_proxy_header<R>(stream: &mut R) -> Result<ProxyProtocolResult, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    // Read the first 6 bytes to decide v1 vs v2.
    let mut prefix = [0u8; 6];
    stream.read_exact(&mut prefix).await?;

    if &prefix == V1_PREFIX {
        // PROXY v1 text format: "PROXY <PROTO> <SRC> <DST> <SRC_PORT> <DST_PORT>\r\n"
        parse_v1(stream, &prefix).await
    } else if prefix[..] == V2_SIG[..6] {
        // PROXY v2 binary format: 12-byte signature then 4-byte fixed header.
        parse_v2(stream, &prefix).await
    } else {
        Err(ProxyProtocolError::InvalidSignature)
    }
}

// ── v1 parser ────────────────────────────────────────────────────────────────

async fn parse_v1<R>(
    stream: &mut R,
    prefix: &[u8; 6],
) -> Result<ProxyProtocolResult, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    // We already consumed "PROXY " (6 bytes). Read remaining bytes one-by-one
    // until CRLF, capped at V1_MAX_LEN total (including the consumed prefix).
    let mut rest: Vec<u8> = prefix.to_vec(); // start with what we have
    let mut buf = [0u8; 1];
    loop {
        if rest.len() >= V1_MAX_LEN {
            return Err(ProxyProtocolError::V1TooLong);
        }
        stream.read_exact(&mut buf).await?;
        rest.push(buf[0]);
        // Check for CRLF terminator
        let n = rest.len();
        if n >= 2 && rest[n - 2] == b'\r' && rest[n - 1] == b'\n' {
            break;
        }
    }
    // `rest` now contains "PROXY ...\r\n". Strip trailing CRLF.
    let line = std::str::from_utf8(&rest[..rest.len() - 2])
        .map_err(|_| ProxyProtocolError::Malformed("non-UTF-8 v1 header".into()))?;
    parse_v1_line(line)
}

fn parse_v1_line(line: &str) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    // Format: "PROXY <PROTO> <SRC_ADDR> <DST_ADDR> <SRC_PORT> <DST_PORT>"
    let mut parts = line.split_ascii_whitespace();
    let keyword = parts.next().unwrap_or("");
    if keyword != "PROXY" {
        return Err(ProxyProtocolError::Malformed(format!(
            "expected 'PROXY' keyword, got {:?}",
            keyword
        )));
    }
    let proto = parts.next().ok_or_else(|| {
        ProxyProtocolError::Malformed("missing protocol field in v1 header".into())
    })?;
    match proto {
        "UNKNOWN" => {
            // Per spec: the rest of the line is to be ignored; keep socket peer.
            return Ok(ProxyProtocolResult::NoAddress);
        }
        "TCP4" | "TCP6" => {}
        other => {
            return Err(ProxyProtocolError::Malformed(format!(
                "unsupported v1 protocol {:?}",
                other
            )));
        }
    }
    let src_addr = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Malformed("missing src address in v1 header".into()))?;
    let dst_addr = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Malformed("missing dst address in v1 header".into()))?;
    let src_port: u16 = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Malformed("missing src port in v1 header".into()))?
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed("invalid src port in v1 header".into()))?;
    let dst_port: u16 = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Malformed("missing dst port in v1 header".into()))?
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed("invalid dst port in v1 header".into()))?;

    let src_ip: IpAddr = src_addr
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed(format!("invalid src IP {:?}", src_addr)))?;
    let dst_ip: IpAddr = dst_addr
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed(format!("invalid dst IP {:?}", dst_addr)))?;

    // Validate family consistency (spec-required).
    if proto == "TCP4" && (!matches!(src_ip, IpAddr::V4(_)) || !matches!(dst_ip, IpAddr::V4(_))) {
        return Err(ProxyProtocolError::Malformed(
            "TCP4 addresses must be IPv4".into(),
        ));
    }
    if proto == "TCP6" && (!matches!(src_ip, IpAddr::V6(_)) || !matches!(dst_ip, IpAddr::V6(_))) {
        return Err(ProxyProtocolError::Malformed(
            "TCP6 addresses must be IPv6".into(),
        ));
    }

    Ok(ProxyProtocolResult::Forwarded {
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
    })
}

// ── v2 parser ────────────────────────────────────────────────────────────────

async fn parse_v2<R>(
    stream: &mut R,
    prefix: &[u8; 6],
) -> Result<ProxyProtocolResult, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    // Read the remaining 6 bytes of the 12-byte signature.
    let mut sig_rest = [0u8; 6];
    stream.read_exact(&mut sig_rest).await?;

    // Reconstruct the full 12-byte prefix for comparison.
    let mut full_sig = [0u8; 12];
    full_sig[..6].copy_from_slice(prefix);
    full_sig[6..].copy_from_slice(&sig_rest);
    if &full_sig != V2_SIG {
        return Err(ProxyProtocolError::InvalidSignature);
    }

    // Fixed 4-byte header following the signature:
    // [0]: version (high nibble) + command (low nibble)
    // [1]: address family (high nibble) + transport (low nibble)
    // [2..4]: length of remaining address block (big-endian u16)
    let mut fixed = [0u8; 4];
    stream.read_exact(&mut fixed).await?;

    let ver_cmd = fixed[0];
    let fam_transport = fixed[1];
    let addr_len = u16::from_be_bytes([fixed[2], fixed[3]]);

    // Version must be 2 (high nibble == 0x2).
    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(ProxyProtocolError::Malformed(format!(
            "unsupported PROXY v2 version {version}"
        )));
    }

    let command = ver_cmd & 0x0f;
    let af = fam_transport >> 4;
    let transport = fam_transport & 0x0f;

    // Safety cap: reject oversized address blocks.
    if addr_len > V2_MAX_ADDR_LEN {
        return Err(ProxyProtocolError::V2LengthExceeded(addr_len));
    }

    // Read the full address block (even if we only consume part of it).
    let mut addr_block = vec![0u8; addr_len as usize];
    stream.read_exact(&mut addr_block).await?;

    match command {
        0x00 => {
            // LOCAL: health check from the proxy itself; keep socket peer.
            Ok(ProxyProtocolResult::NoAddress)
        }
        0x01 => {
            // PROXY: forwarded connection, parse address family.
            parse_v2_addresses(af, transport, &addr_block)
        }
        other => Err(ProxyProtocolError::Malformed(format!(
            "unsupported PROXY v2 command 0x{other:02x}"
        ))),
    }
}

fn parse_v2_addresses(
    af: u8,
    transport: u8,
    block: &[u8],
) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    match af {
        0x00 => {
            // AF_UNSPEC — treat as no address (keep socket peer).
            Ok(ProxyProtocolResult::NoAddress)
        }
        0x01 => {
            // AF_INET (IPv4): 4+4+2+2 = 12 bytes
            if block.len() < 12 {
                return Err(ProxyProtocolError::Malformed(format!(
                    "AF_INET address block too short: {} bytes",
                    block.len()
                )));
            }
            let src_ip = Ipv4Addr::from([block[0], block[1], block[2], block[3]]);
            let dst_ip = Ipv4Addr::from([block[4], block[5], block[6], block[7]]);
            let src_port = u16::from_be_bytes([block[8], block[9]]);
            let dst_port = u16::from_be_bytes([block[10], block[11]]);

            if transport != 0x01 {
                // Non-STREAM transport (DGRAM=0x02 or other) — treat as no address.
                return Ok(ProxyProtocolResult::NoAddress);
            }
            Ok(ProxyProtocolResult::Forwarded {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
            })
        }
        0x02 => {
            // AF_INET6 (IPv6): 16+16+2+2 = 36 bytes
            if block.len() < 36 {
                return Err(ProxyProtocolError::Malformed(format!(
                    "AF_INET6 address block too short: {} bytes",
                    block.len()
                )));
            }
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&block[..16]);
            dst_bytes.copy_from_slice(&block[16..32]);
            let src_ip = Ipv6Addr::from(src_bytes);
            let dst_ip = Ipv6Addr::from(dst_bytes);
            let src_port = u16::from_be_bytes([block[32], block[33]]);
            let dst_port = u16::from_be_bytes([block[34], block[35]]);

            if transport != 0x01 {
                return Ok(ProxyProtocolResult::NoAddress);
            }
            Ok(ProxyProtocolResult::Forwarded {
                src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
            })
        }
        0x03 => {
            // AF_UNIX — not supported in this gateway context; keep socket peer.
            Ok(ProxyProtocolResult::NoAddress)
        }
        other => Err(ProxyProtocolError::Malformed(format!(
            "unsupported PROXY v2 address family 0x{other:02x}"
        ))),
    }
}

/// Apply the PROXY protocol header result to compute the resolved `client_ip`.
///
/// Returns `(resolved_ip_string, direct_ip_string)` where:
/// - `resolved_ip_string` is the forwarded client IP (becomes `client_ip`).
/// - `direct_ip_string` is the raw socket peer (always `direct_client_ip`).
///
/// On `NoAddress` both strings are the socket peer IP.
pub fn apply_proxy_result(
    result: ProxyProtocolResult,
    socket_peer: &std::net::SocketAddr,
) -> (String, String) {
    let direct = socket_peer.ip().to_string();
    match result {
        ProxyProtocolResult::Forwarded { src, .. } => {
            let resolved = src.ip().to_string();
            (resolved, direct)
        }
        ProxyProtocolResult::NoAddress => (direct.clone(), direct),
    }
}

/// Warn and signal that a connection should be closed due to an untrusted peer
/// sending a PROXY-protocol-enabled connection.
///
/// Returns a structured log record; the caller must drop/close the stream.
pub fn warn_untrusted_proxy_peer(peer: &std::net::SocketAddr, proxy_id: &str) {
    warn!(
        proxy_id = %proxy_id,
        peer = %peer,
        "Closing connection: inbound PROXY protocol enabled but socket peer is not in \
         FERRUM_TRUSTED_PROXIES — refusing to honor forwarded address to prevent IP spoofing"
    );
}

/// Warn and close a connection when PROXY protocol is enabled but the
/// initial bytes were not a valid PROXY header.
pub fn warn_invalid_proxy_header(
    peer: &std::net::SocketAddr,
    proxy_id: &str,
    err: &ProxyProtocolError,
) {
    warn!(
        proxy_id = %proxy_id,
        peer = %peer,
        error = %err,
        "Closing connection: inbound PROXY protocol is required on this listener but the \
         connection did not start with a valid PROXY header"
    );
}
