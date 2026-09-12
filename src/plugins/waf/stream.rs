//! Stream (TCP/UDP) inspection for the WAF plugin.
//!
//! Extends the WAF beyond HTTP-family traffic to raw TCP streams and UDP
//! datagrams. Two capabilities, both gated by the top-level `mode`
//! (`enforce` blocks, `monitor` only records):
//!
//! 1. `tcp_require_tls` — reject a TCP connection whose opening bytes are not a
//!    TLS ClientHello. A transport-shape guard for ports that must only carry
//!    TLS. It inspects raw wire bytes, so it applies to plain TCP and
//!    passthrough proxies; on TLS-terminating frontends the handshake already
//!    proved the transport, so it is a no-op there.
//! 2. `signatures` — byte-pattern (regex) matching over *plaintext application*
//!    bytes: the opening bytes of a plain TCP stream, the first decrypted bytes
//!    of a TLS-terminated stream, or a (decrypted) UDP/DTLS datagram. Encrypted
//!    passthrough bytes are forwarded ciphertext the gateway never decrypts and
//!    are therefore never L7-scanned.
//!
//! Content inspection requires the bytes to traverse userspace, so a TCP proxy
//! with stream inspection enabled falls back from the kTLS-splice fast path to a
//! userspace relay for the connections it inspects.

use regex::bytes::RegexSet as BytesRegexSet;
use serde_json::{Map, Value};
use std::collections::HashSet;

use super::rules::{RuleAction, Severity, parse_rule_action};
use super::{optional_bool, optional_string, parse_severity};
use crate::util::unknown_keys::reject_unknown_keys;

/// Fixed-shape `stream` block keys.
const STREAM_CONFIG_KEYS: &[&str] = &[
    "tcp_require_tls",
    "inspect_tcp",
    "inspect_udp",
    "inspect_response",
    "signatures",
];

/// Fixed-shape stream signature object keys.
const STREAM_SIGNATURE_KEYS: &[&str] = &["id", "pattern", "severity", "action"];

/// One compiled stream signature's metadata, indexed in lockstep with the
/// `RegexSet` so a match index maps straight back to its id/severity/action.
#[derive(Debug)]
pub(super) struct StreamSignatureMeta {
    pub(super) id: String,
    pub(super) severity: Severity,
    pub(super) action: RuleAction,
}

/// Compiled stream signatures: a single bytes `RegexSet` (linear-time match
/// regardless of pattern count) plus parallel per-pattern metadata.
#[derive(Debug)]
pub(super) struct CompiledStreamSignatures {
    set: BytesRegexSet,
    meta: Vec<StreamSignatureMeta>,
}

impl CompiledStreamSignatures {
    /// Metadata for every signature matching `data`.
    pub(super) fn matches<'a>(&'a self, data: &[u8]) -> Vec<&'a StreamSignatureMeta> {
        if self.meta.is_empty() {
            return Vec::new();
        }
        self.set
            .matches(data)
            .into_iter()
            .map(|i| &self.meta[i])
            .collect()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }

    /// Whether any compiled signature is enforce-action, i.e. could actually
    /// reject a matching payload under global `enforce` mode. A monitor-only set
    /// never blocks a present match, so callers use this to avoid failing closed
    /// (e.g. on missing first bytes) when no configured signature could block.
    pub(super) fn has_enforce_action(&self) -> bool {
        self.meta.iter().any(|m| m.action == RuleAction::Enforce)
    }
}

/// Parsed `stream` sub-config for the WAF plugin.
#[derive(Debug)]
pub(super) struct StreamWafConfig {
    pub(super) tcp_require_tls: bool,
    pub(super) inspect_tcp: bool,
    pub(super) inspect_udp: bool,
    pub(super) inspect_response: bool,
    pub(super) signatures: CompiledStreamSignatures,
}

impl StreamWafConfig {
    /// Whether the TCP proxy must capture the opening client bytes for this
    /// config via a non-destructive peek (plain/passthrough) — either to
    /// signature-scan them or to run the TLS-shape guard.
    pub(super) fn needs_tcp_first_bytes(&self) -> bool {
        self.tcp_require_tls || (self.inspect_tcp && !self.signatures.is_empty())
    }

    /// Whether the TCP proxy must capture the opening *decrypted* bytes of a
    /// TLS-terminating frontend (a consuming read that disables kTLS splice).
    /// Only signature scanning needs this; `tcp_require_tls` is a no-op once the
    /// TLS handshake has completed, so a guard-only config must not trigger it.
    pub(super) fn needs_tcp_decrypted_first_bytes(&self) -> bool {
        self.inspect_tcp && !self.signatures.is_empty()
    }

    /// Whether per-datagram UDP hooks are needed for this config.
    pub(super) fn needs_udp_datagrams(&self) -> bool {
        self.inspect_udp && !self.signatures.is_empty()
    }

    /// Whether an enforce-action signature can actually be applied by some
    /// runtime hook — the admission-side mirror of the two capability
    /// predicates above.
    ///
    /// `inspect_response` is NOT an independent inspection surface. It is a
    /// direction switch read INSIDE the datagram hook, after `inspect_udp` has
    /// already admitted that hook, so a response-only policy with `inspect_tcp`
    /// and `inspect_udp` both false has no hook to fire from. Counting it on
    /// its own admitted a stream policy that could never block anything, while
    /// telling the operator stream inspection was active (issue #5121).
    pub(super) fn enforcing_signature_is_reachable(&self) -> bool {
        self.signatures.has_enforce_action() && (self.inspect_tcp || self.inspect_udp)
    }
}

/// Parse the optional `stream` config block. Returns `Ok(None)` when absent or
/// when it carries no actionable inspection, so a WAF without real stream rules
/// stays HTTP-only and never attaches to stream proxies.
pub(super) fn parse_stream_config(
    object: &Map<String, Value>,
) -> Result<Option<StreamWafConfig>, String> {
    let Some(raw) = object.get("stream") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let stream = raw
        .as_object()
        .ok_or_else(|| "waf: 'stream' must be an object".to_string())?;
    reject_unknown_keys(stream, "config.stream", STREAM_CONFIG_KEYS, "waf: ")?;

    let tcp_require_tls = optional_bool(stream, "tcp_require_tls")?.unwrap_or(false);
    let inspect_tcp = optional_bool(stream, "inspect_tcp")?.unwrap_or(true);
    let inspect_udp = optional_bool(stream, "inspect_udp")?.unwrap_or(true);
    let inspect_response = optional_bool(stream, "inspect_response")?.unwrap_or(false);

    let signatures = compile_stream_signatures(stream)?;

    // A `stream` block with neither signatures nor the TLS-shape guard is a
    // no-op; treat it as absent so the plugin does not attach to stream proxies
    // for nothing.
    if signatures.is_empty() && !tcp_require_tls {
        return Ok(None);
    }

    Ok(Some(StreamWafConfig {
        tcp_require_tls,
        inspect_tcp,
        inspect_udp,
        inspect_response,
        signatures,
    }))
}

fn compile_stream_signatures(
    stream: &Map<String, Value>,
) -> Result<CompiledStreamSignatures, String> {
    let mut patterns: Vec<String> = Vec::new();
    let mut meta: Vec<StreamSignatureMeta> = Vec::new();

    if let Some(value) = stream.get("signatures").filter(|v| !v.is_null()) {
        let array = value
            .as_array()
            .ok_or_else(|| "waf: 'stream.signatures' must be an array".to_string())?;
        let mut seen_ids = HashSet::new();
        for (idx, entry) in array.iter().enumerate() {
            let obj = entry
                .as_object()
                .ok_or_else(|| format!("waf: 'stream.signatures[{idx}]' must be an object"))?;
            let path = format!("config.stream.signatures[{idx}]");
            reject_unknown_keys(obj, &path, STREAM_SIGNATURE_KEYS, "waf: ")?;
            let id = optional_string(obj, "id")?
                .ok_or_else(|| format!("waf: 'stream.signatures[{idx}]' requires 'id'"))?;
            if !seen_ids.insert(id.clone()) {
                return Err(format!("waf: duplicate stream signature id '{id}'"));
            }
            let pattern = optional_string(obj, "pattern")?
                .ok_or_else(|| format!("waf: stream signature '{id}' requires 'pattern'"))?;
            // Compile each pattern individually first so the error names the
            // offending signature rather than a combined-set position.
            regex::bytes::Regex::new(&pattern)
                .map_err(|e| format!("waf: stream signature '{id}' has invalid pattern: {e}"))?;
            let severity = match optional_string(obj, "severity")? {
                Some(s) => parse_severity(&s).ok_or_else(|| {
                    format!("waf: stream signature '{id}' has invalid severity '{s}'")
                })?,
                None => Severity::Medium,
            };
            let action = match optional_string(obj, "action")? {
                Some(a) => parse_rule_action(&a, "stream.signatures.action")?,
                None => RuleAction::Enforce,
            };
            // Drop disabled signatures from the active set (parity with HTTP WAF
            // rules) so a temporarily disabled rule produces no matches, no
            // `waf.rule_hits` metadata, and no stdout events while it is off.
            if action == RuleAction::Disabled {
                continue;
            }
            patterns.push(pattern);
            meta.push(StreamSignatureMeta {
                id,
                severity,
                action,
            });
        }
    }

    // `RegexSet::new` over an empty pattern list yields a set that matches
    // nothing, which is exactly what we want when only `tcp_require_tls` is set.
    let set = BytesRegexSet::new(&patterns)
        .map_err(|e| format!("waf: failed to build stream signature set: {e}"))?;

    Ok(CompiledStreamSignatures { set, meta })
}

/// Smallest TLS handshake-record prefix needed to classify a ClientHello:
/// `content_type(1) + version(2) + length(2) + handshake type(1)`. The TCP proxy
/// reads `stream_first_bytes_min_len()` to know it must reassemble at least this
/// many opening bytes before running the `tcp_require_tls` guard, so a
/// ClientHello fragmented across TCP segments is not misread as a short non-TLS
/// chunk and rejected.
pub(super) const TLS_CLIENT_HELLO_MIN_PREFIX: usize = 6;

/// Whether these raw TCP wire bytes begin a TLS ClientHello handshake record.
/// Backs `tcp_require_tls`, which runs only on raw (non-terminated) TCP, so this
/// validates a TLS record specifically (DTLS is UDP and out of scope here).
///
/// A TLS record is `content_type(0x16 handshake) | version(2) | length(2) |
/// handshake_message...`, and the handshake message's first byte is its type —
/// `0x01` for ClientHello. Requiring that type (not just the record header)
/// stops a non-TLS client from prefixing `0x16 0x03 0xNN` to arbitrary plaintext
/// to slip past the guard.
pub(super) fn looks_like_tls_client_hello(data: &[u8]) -> bool {
    // type(1) + version(2) + length(2) + handshake type(1) = 6 bytes minimum.
    if data.len() < TLS_CLIENT_HELLO_MIN_PREFIX || data[0] != 0x16 {
        return false;
    }
    // TLS 1.x legacy record version (TLS 1.3 still uses 0x0301/0x0303 here).
    if data[1] != 0x03 || !(0x00..=0x04).contains(&data[2]) {
        return false;
    }
    // Record length must at least cover a 4-byte handshake header.
    if u16::from_be_bytes([data[3], data[4]]) < 4 {
        return false;
    }
    // Handshake message type: ClientHello.
    data[5] == 0x01
}
