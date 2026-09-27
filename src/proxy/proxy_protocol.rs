//! Inbound PROXY protocol v1 (text) and v2 (binary) parser, plus outbound
//! PROXY protocol v2 encoder.
//!
//! This module parses the PROXY protocol header that a load balancer or
//! reverse proxy prepends to each TCP connection before forwarding it. The
//! header carries the original client address so the backend can see the real
//! source IP rather than the LB's own IP.
//!
//! UDP and DTLS listeners use a sibling per-datagram parser in
//! [`crate::proxy::datagram_client_address`]: same v2 signature, version,
//! family codes, and 512-byte address-block cap, but a distinct `DGRAM`
//! transport, auth-TLV, dest-port, and hot-path contract. Keep those constants
//! aligned; do not merge the parsers.
//!
//! Outbound encoding ([`encode_v2_proxy_header`])
//! prepends the same v2 binary framing to backend TCP connections when a
//! stream proxy opts in via `backend_proxy_protocol: v2`, so L4 backends
//! (PostgreSQL, MySQL, Redis, …) can see the originating client identity.
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
//! Outbound PROXY is separately opt-in (`backend_proxy_protocol`). It
//! advertises the already-trusted `client_ip` from
//! [`crate::plugins::StreamConnectionContext`] — never an untrusted
//! application header — so enabling it does not widen the inbound trust
//! boundary.
//!
//! # Spec references
//!
//! - PROXY protocol v1: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//! - PROXY protocol v2: same document, section 2.2 onwards.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
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

/// Which PROXY protocol versions one listener accepts.
///
/// Stream proxies accept either version ([`read_proxy_header`]). The
/// process-global HTTP/HTTPS listeners can be pinned to one version
/// (`FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP` / `_HTTPS` = `v1` / `v2`), in which
/// case a header of the other version is refused exactly like a malformed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedProxyVersions {
    /// Only the v1 text header (`PROXY TCP4 ...\r\n`).
    V1Only,
    /// Only the v2 binary header.
    V2Only,
    /// Either version, auto-detected from the first bytes.
    Any,
}

impl AcceptedProxyVersions {
    fn allows_v1(self) -> bool {
        matches!(self, Self::V1Only | Self::Any)
    }

    fn allows_v2(self) -> bool {
        matches!(self, Self::V2Only | Self::Any)
    }
}

/// Maximum in-memory PROXY header size accepted by [`parse_proxy_protocol_header_bytes`].
#[cfg(feature = "fuzzing")]
pub(crate) const PROXY_PROTOCOL_MAX_HEADER_BYTES: usize = {
    const V2_MAX_LEN: usize = V2_SIG.len() + 4 + V2_MAX_ADDR_LEN as usize;
    if V1_MAX_LEN > V2_MAX_LEN {
        V1_MAX_LEN
    } else {
        V2_MAX_LEN
    }
};

/// Error variants for PROXY protocol parsing.
#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolError {
    /// The supplied byte slice exceeded the safety cap for in-memory parsing.
    #[error("PROXY protocol header exceeds safety cap of {0} bytes")]
    #[cfg(feature = "fuzzing")]
    InputTooLong(usize),
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
    /// A well-formed signature for a PROXY version this listener does not accept.
    #[error("PROXY protocol {0} header is not accepted on this listener")]
    VersionNotAccepted(&'static str),
}

// PROXY v2 signature: 12-byte fixed prefix. Keep byte-identical to
// `datagram_client_address::V2_SIG`; the parsers are deliberately separate.
const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
// PROXY v1 prefix
const V1_PREFIX: &[u8; 6] = b"PROXY ";
// Maximum v2 address-block length we will read. The fixed address
// blocks are at most 36 bytes (AF_INET6: 16+16+2+2). We set the cap
// to 512 to allow for implementation-defined TLV extensions (e.g. AWS
// VPC Lattice, HAProxy custom TLVs) that appear after the address pair.
// Anything longer is rejected to bound memory; per spec the address
// block can carry arbitrary TLVs after the AF_INET / AF_INET6 portion.
// Keep equal to `datagram_client_address::MAX_ADDR_BLOCK_LEN`.
const V2_MAX_ADDR_LEN: u16 = 512;
// PROXY v1: maximum total line length is 107 bytes + CRLF = 109 bytes.
// `rest` holds the full line including the 6-byte "PROXY " prefix and the
// CRLF terminator, so the cap must cover all 109 bytes.
const V1_MAX_LEN: usize = 109;
// Fixed address-block sizes shared with the datagram parser.
const V2_INET_ADDR_LEN: usize = 12;
const V2_INET6_ADDR_LEN: usize = 36;

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
    read_proxy_header_accepting(stream, timeout_secs, AcceptedProxyVersions::Any).await
}

/// [`read_proxy_header`] restricted to the `accepted` PROXY versions.
///
/// The version is decided from the first six bytes, before any
/// version-specific bytes are consumed, so a refused version never reads past
/// the signature prefix. The header-size caps and the whole-read timeout are
/// the same as [`read_proxy_header`]'s.
pub async fn read_proxy_header_accepting<R>(
    stream: &mut R,
    timeout_secs: Option<u64>,
    accepted: AcceptedProxyVersions,
) -> Result<ProxyProtocolResult, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let secs = timeout_secs.unwrap_or(5);
    let fut = parse_proxy_header(stream, accepted);
    match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProxyProtocolError::Timeout),
    }
}

async fn parse_proxy_header<R>(
    stream: &mut R,
    accepted: AcceptedProxyVersions,
) -> Result<ProxyProtocolResult, ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let (version, prefix) = read_signature_prefix(stream, accepted).await?;
    match version {
        // PROXY v1 text format: "PROXY <PROTO> <SRC> <DST> <SRC_PORT> <DST_PORT>\r\n"
        HeaderVersion::V1 => parse_v1(stream, &prefix).await,
        // PROXY v2 binary format: 12-byte signature then 4-byte fixed header.
        HeaderVersion::V2 => parse_v2(stream, &prefix).await,
    }
}

/// [`read_proxy_header_accepting`] for a raw [`TcpStream`].
///
/// Identical outcomes, caps, and timeout; the only difference is that a v1
/// line is located with `peek` and then consumed with `read_exact` of exactly
/// the header length (typically one peek and one read) instead of one read per
/// byte. Bytes after the CRLF are never consumed, so the TLS ClientHello or the
/// first HTTP byte stays in the socket for the next reader.
pub async fn read_proxy_header_accepting_tcp(
    stream: &mut TcpStream,
    timeout_secs: Option<u64>,
    accepted: AcceptedProxyVersions,
) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    let secs = timeout_secs.unwrap_or(5);
    let fut = parse_proxy_header_tcp(stream, accepted);
    match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProxyProtocolError::Timeout),
    }
}

async fn parse_proxy_header_tcp(
    stream: &mut TcpStream,
    accepted: AcceptedProxyVersions,
) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    let (version, prefix) = read_signature_prefix(stream, accepted).await?;
    match version {
        HeaderVersion::V1 => parse_v1_peek(stream, &prefix).await,
        HeaderVersion::V2 => parse_v2(stream, &prefix).await,
    }
}

#[derive(Clone, Copy)]
enum HeaderVersion {
    V1,
    V2,
}

/// Read the first 6 bytes and decide v1 vs v2, refusing a version this
/// listener does not accept before any version-specific byte is consumed.
async fn read_signature_prefix<R>(
    stream: &mut R,
    accepted: AcceptedProxyVersions,
) -> Result<(HeaderVersion, [u8; 6]), ProxyProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 6];
    stream.read_exact(&mut prefix).await?;

    if &prefix == V1_PREFIX {
        if !accepted.allows_v1() {
            return Err(ProxyProtocolError::VersionNotAccepted("v1"));
        }
        Ok((HeaderVersion::V1, prefix))
    } else if prefix[..] == V2_SIG[..6] {
        if !accepted.allows_v2() {
            return Err(ProxyProtocolError::VersionNotAccepted("v2"));
        }
        Ok((HeaderVersion::V2, prefix))
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
    // A generic reader cannot peek, so one byte per read is the only way to
    // never consume past the CRLF; `TcpStream` callers use `parse_v1_peek`.
    let mut line = [0u8; V1_MAX_LEN];
    line[..prefix.len()].copy_from_slice(prefix);
    let mut filled = prefix.len();
    loop {
        if filled >= V1_MAX_LEN {
            return Err(ProxyProtocolError::V1TooLong);
        }
        stream.read_exact(&mut line[filled..filled + 1]).await?;
        filled += 1;
        // Check for CRLF terminator
        if line[filled - 2] == b'\r' && line[filled - 1] == b'\n' {
            break;
        }
    }
    // `line[..filled]` now contains "PROXY ...\r\n". Strip trailing CRLF.
    parse_v1_bytes(&line[..filled - 2])
}

/// [`parse_v1`] for a raw `TcpStream`: same cap, errors, and first-CRLF
/// termination, without a syscall per byte.
///
/// Each round peeks whatever is buffered (up to the remaining cap). When the
/// peeked bytes contain the CRLF, exactly the bytes through it are consumed
/// and nothing after it is touched. Otherwise every peeked byte precedes the
/// terminator and so belongs to the header: those bytes are consumed before
/// peeking again, which also makes the next peek wait for new data instead of
/// returning the same buffered bytes in a busy loop. A peer that closes before
/// the CRLF gets the same `UnexpectedEof` I/O error as the byte-wise reader.
async fn parse_v1_peek(
    stream: &mut TcpStream,
    prefix: &[u8; 6],
) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    let mut line = [0u8; V1_MAX_LEN];
    line[..prefix.len()].copy_from_slice(prefix);
    let mut filled = prefix.len();
    loop {
        if filled >= V1_MAX_LEN {
            return Err(ProxyProtocolError::V1TooLong);
        }
        let peeked = stream.peek(&mut line[filled..]).await?;
        if peeked == 0 {
            return Err(ProxyProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "early eof",
            )));
        }
        let available = filled + peeked;
        let terminator = v1_line_end(&line, filled, available);
        let end = terminator.unwrap_or(available);
        stream.read_exact(&mut line[filled..end]).await?;
        filled = end;
        if terminator.is_some() {
            break;
        }
    }
    // `line[..filled]` now contains "PROXY ...\r\n". Strip trailing CRLF.
    parse_v1_bytes(&line[..filled - 2])
}

/// Locate the end of a PROXY v1 line during an incremental peek read.
///
/// `line[..filled]` holds bytes already consumed from the socket (always the
/// 6-byte `PROXY ` prefix at least, none of them ending the line) and
/// `line[filled..available]` holds newly peeked bytes. Returns the index just
/// past the first CRLF that ends inside the new bytes, so a CR consumed in an
/// earlier round pairs with an LF peeked now, while a CRLF lying entirely in
/// consumed bytes is never matched again. `None` means no terminator yet.
pub fn v1_line_end(line: &[u8], filled: usize, available: usize) -> Option<usize> {
    let available = available.min(line.len());
    let search_from = filled.saturating_sub(1);
    if available < search_from + 2 {
        return None;
    }
    line[search_from..available]
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .map(|offset| search_from + offset + 2)
}

fn parse_v1_bytes(line: &[u8]) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    let line = std::str::from_utf8(line)
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

/// Parse a complete PROXY protocol v1 or v2 header from an in-memory byte slice.
///
/// Production listeners use the async stream reader; this entry point exists for
/// unit tests and the adversarial fuzz lane. Oversized inputs fail closed before
/// allocation beyond the declared address block.
#[cfg(feature = "fuzzing")]
pub(crate) fn parse_proxy_protocol_header_bytes(
    data: &[u8],
) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    if data.len() > PROXY_PROTOCOL_MAX_HEADER_BYTES {
        return Err(ProxyProtocolError::InputTooLong(
            PROXY_PROTOCOL_MAX_HEADER_BYTES,
        ));
    }
    if data.starts_with(V1_PREFIX) {
        if data.len() > V1_MAX_LEN {
            return Err(ProxyProtocolError::V1TooLong);
        }
        if data.len() < 2 || data[data.len() - 2] != b'\r' || data[data.len() - 1] != b'\n' {
            return Err(ProxyProtocolError::Malformed(
                "v1 header missing CRLF terminator".into(),
            ));
        }
        let line = std::str::from_utf8(&data[..data.len() - 2])
            .map_err(|_| ProxyProtocolError::Malformed("non-UTF-8 v1 header".into()))?;
        return parse_v1_line(line);
    }
    if data.len() < 6 {
        return Err(ProxyProtocolError::InvalidSignature);
    }
    if data[..6] != V2_SIG[..6] {
        return Err(ProxyProtocolError::InvalidSignature);
    }
    if data.len() < V2_SIG.len() + 4 {
        return Err(ProxyProtocolError::Malformed(
            "truncated PROXY v2 fixed header".into(),
        ));
    }
    if &data[..V2_SIG.len()] != V2_SIG {
        return Err(ProxyProtocolError::InvalidSignature);
    }
    let fixed = &data[V2_SIG.len()..V2_SIG.len() + 4];
    let ver_cmd = fixed[0];
    let fam_transport = fixed[1];
    let addr_len = u16::from_be_bytes([fixed[2], fixed[3]]);
    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(ProxyProtocolError::Malformed(format!(
            "unsupported PROXY v2 version {version}"
        )));
    }
    if addr_len > V2_MAX_ADDR_LEN {
        return Err(ProxyProtocolError::V2LengthExceeded(addr_len));
    }
    let total = V2_SIG.len() + 4 + addr_len as usize;
    if data.len() < total {
        return Err(ProxyProtocolError::Malformed(
            "truncated PROXY v2 address block".into(),
        ));
    }
    if data.len() > total {
        return Err(ProxyProtocolError::Malformed(
            "trailing bytes after PROXY v2 address block".into(),
        ));
    }
    let command = ver_cmd & 0x0f;
    let af = fam_transport >> 4;
    let transport = fam_transport & 0x0f;
    let addr_block = &data[V2_SIG.len() + 4..];
    match command {
        0x00 => Ok(ProxyProtocolResult::NoAddress),
        0x01 => parse_v2_addresses(af, transport, addr_block),
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
            // AF_INET (IPv4): 4+4+2+2. Keep equal to the datagram parser.
            if block.len() < V2_INET_ADDR_LEN {
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
            // AF_INET6 (IPv6): 16+16+2+2. Keep equal to the datagram parser.
            if block.len() < V2_INET6_ADDR_LEN {
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
/// - `direct_ip_string` is the socket peer (always `direct_client_ip`).
///
/// Both values canonicalize IPv4-mapped IPv6 to native IPv4 before stream
/// plugins run. On `NoAddress` both strings are the canonical socket peer IP.
pub fn apply_proxy_result(
    result: ProxyProtocolResult,
    socket_peer: &std::net::SocketAddr,
) -> (String, String) {
    let direct = crate::util::client_identity::canonical_ip_string(socket_peer.ip());
    match result {
        ProxyProtocolResult::Forwarded { src, .. } => {
            // A PROXY v2 `AF_INET6` block legitimately carries the mapped form for
            // an IPv4 client; fold it so the forwarded principal matches the
            // native-IPv4 one (GHSA-vjwj-657f-5w9g).
            let resolved = crate::util::client_identity::canonical_ip_string(src.ip());
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

// ── v2 encoder (outbound) ────────────────────────────────────────────────────

/// Maximum encoded PROXY v2 header size this module emits (signature + fixed
/// header + AF_INET6 address block). Callers may stack-allocate against this.
pub const V2_ENCODED_MAX_LEN: usize = V2_SIG.len() + 4 + V2_INET6_ADDR_LEN;

/// Build source/destination socket addresses for an outbound PROXY v2 header.
///
/// - `client_ip` / `client_port` are the trusted stream identity (after inbound
///   PROXY trust gating when that is enabled).
/// - `destination_ip` / `destination_port` are the complete trusted original
///   destination tuple (inbound PROXY, `SO_ORIGINAL_DST`, or capture metadata).
/// - When neither component is present, `local_fallback` supplies the complete
///   accepted-socket address the client connected to.
///
/// Returns `None` when no destination is available or when only half of the
/// original tuple is populated — callers must fail closed rather than combine
/// unrelated evidence or invent addresses.
pub fn outbound_v2_addrs(
    client_ip: IpAddr,
    client_port: u16,
    destination_ip: Option<IpAddr>,
    destination_port: Option<u16>,
    local_fallback: Option<SocketAddr>,
) -> Option<(SocketAddr, SocketAddr)> {
    let destination = match (destination_ip, destination_port) {
        (Some(ip), Some(port)) => {
            SocketAddr::new(crate::util::client_identity::canonical_ip(ip), port)
        }
        (None, None) => crate::util::client_identity::canonical_socket_addr(local_fallback?),
        _ => return None,
    };
    let src_ip = crate::util::client_identity::canonical_ip(client_ip);
    Some((SocketAddr::new(src_ip, client_port), destination))
}

/// Encode a PROXY protocol v2 binary header (PROXY command, STREAM transport).
///
/// When `src` and `dst` share an IPv4 family (after IPv4-mapped canonicalization)
/// the header uses `AF_INET` (28 bytes total). Mixed or IPv6 pairs are encoded
/// as `AF_INET6`, promoting any IPv4 address to its IPv4-mapped form so a
/// single address family is advertised (spec requirement).
///
/// The returned buffer never exceeds [`V2_ENCODED_MAX_LEN`] and contains no
/// TLVs — only the fixed address block.
pub fn encode_v2_proxy_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let src_ip = crate::util::client_identity::canonical_ip(src.ip());
    let dst_ip = crate::util::client_identity::canonical_ip(dst.ip());
    match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => encode_v2_inet(s, d, src.port(), dst.port()),
        (s, d) => encode_v2_inet6(ip_to_v6(s), ip_to_v6(d), src.port(), dst.port()),
    }
}

fn ip_to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

fn encode_v2_inet(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    // 12 sig + 4 fixed + 12 addr = 28
    let mut buf = Vec::with_capacity(28);
    buf.extend_from_slice(V2_SIG);
    buf.push(0x21); // version=2, command=PROXY
    buf.push(0x11); // AF_INET + STREAM
    buf.extend_from_slice(&12u16.to_be_bytes());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf
}

fn encode_v2_inet6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    // 12 sig + 4 fixed + 36 addr = 52
    let mut buf = Vec::with_capacity(V2_ENCODED_MAX_LEN);
    buf.extend_from_slice(V2_SIG);
    buf.push(0x21); // version=2, command=PROXY
    buf.push(0x21); // AF_INET6 + STREAM
    buf.extend_from_slice(&36u16.to_be_bytes());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf
}
