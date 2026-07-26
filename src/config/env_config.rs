//! Environment variable and `ferrum.conf` parsing for gateway runtime settings.
//!
//! **Three-tier resolution** (highest precedence first):
//! 1. Environment variable (`std::env::var`)
//! 2. Conf file value (`ferrum.conf`, parsed by `ConfFile`)
//! 3. Hardcoded default in this file
//!
//! The `resolve_var()` helper implements this precedence chain and logs an
//! info message when a conf file value is overridden by an env var, helping
//! operators debug "why isn't my conf file change taking effect?" issues.

use super::conf_file::ConfFile;
use super::db_backend::redact_url;
use crate::ebpf::NodeAgentProxyMode;
use crate::tls::inventory_cache::DEFAULT_SNAPSHOT_TTL_SECONDS;
use crate::util::cidr::CidrSet;
use std::collections::{HashMap, HashSet};
use std::env;

#[macro_use]
#[path = "env_config_macro.rs"]
mod env_config_macro;

pub const DEFAULT_TLS_MANAGED_STORE_PATH: &str = "./ferrum-managed-tls";

pub fn tls_managed_store_path_from_env() -> String {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_TLS_MANAGED_STORE_PATH")
        .unwrap_or_else(|| DEFAULT_TLS_MANAGED_STORE_PATH.to_string())
}

/// SQL connection target for secondary consumers that must track the gateway
/// configuration database (`FERRUM_DB_TYPE` + effective `FERRUM_DB_URL`).
///
/// `effective_url` includes canonical `FERRUM_DB_TLS_*` query parameters for
/// PostgreSQL and MySQL. Callers must never log or echo it — the value may
/// embed credentials. `Debug` redacts the URL for the same reason.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectiveSqlBackend {
    pub db_type: String,
    pub effective_url: String,
}

impl std::fmt::Debug for EffectiveSqlBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectiveSqlBackend")
            .field("db_type", &self.db_type)
            .field("effective_url", &redact_url(&self.effective_url))
            .finish()
    }
}

/// The operating mode of the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatingMode {
    Database,
    File,
    ControlPlane,
    DataPlane,
    Mesh,
    Injector,
    NodeAgent,
    Migrate,
}

impl OperatingMode {
    #[allow(dead_code)] // Used by integration/unit tests via the lib crate
    pub fn from_env() -> Result<Self, String> {
        Self::resolve(&ConfFile::default())
    }

    fn resolve(conf: &ConfFile) -> Result<Self, String> {
        let raw = resolve_var(conf, "FERRUM_MODE").unwrap_or_default();
        match raw.to_lowercase().as_str() {
            "database" => Ok(Self::Database),
            "file" => Ok(Self::File),
            "cp" => Ok(Self::ControlPlane),
            "dp" => Ok(Self::DataPlane),
            "mesh" => Ok(Self::Mesh),
            "injector" => Ok(Self::Injector),
            "node_agent" => Ok(Self::NodeAgent),
            "migrate" => Ok(Self::Migrate),
            other => {
                const MODES: &str = "database, file, cp, dp, mesh, injector, node_agent, migrate";
                // Withheld by key, not by shape, and this is the *only*
                // defense here rather than a belt-and-braces one. The site
                // lowercases before echoing, so what an operator sees is a
                // rendering of the resolved value rather than the value
                // itself, and for a short value (`DB` -> `db`) the textual
                // backstop cannot cover that rendering at all: a two-byte
                // derived candidate is below `MIN_DERIVED_CANDIDATE_LEN` and
                // is dropped, because arming `db` process-wide would shred
                // every unrelated diagnostic containing it.
                // `is_external_secret_key` is exact: the
                // variable is known by name to have been externally resolved,
                // so no rendering of it escapes here. The expected-value list
                // is the actionable part and is kept. Same boundary and same
                // shape as `env_config_macro::invalid_env_value`, which this
                // hand-written `format!` does not go through.
                if crate::secrets::is_external_secret_key("FERRUM_MODE") {
                    return Err(format!(
                        "Invalid FERRUM_MODE {}. Expected: {MODES}",
                        crate::secrets::EXTERNAL_SECRET_PLACEHOLDER
                    ));
                }
                Err(format!("Invalid FERRUM_MODE '{other}'. Expected: {MODES}"))
            }
        }
    }
}

/// Backend IP allowlist policy for SSRF protection.
///
/// Controls which resolved backend IPs are permitted as proxy/upstream targets:
/// - `Private`: only private/reserved IPs (RFC 1918, loopback, link-local, CGNAT)
/// - `Public`: only public IPs (blocks internal/metadata endpoints)
/// - `Both`: all IPs allowed (default, no restriction)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendAllowIps {
    /// Only private/reserved IPs allowed as backends.
    Private,
    /// Only public (non-private) IPs allowed as backends.
    Public,
    /// All IPs allowed — no restriction (default).
    Both,
}

impl std::fmt::Display for BackendAllowIps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Private => write!(f, "private"),
            Self::Public => write!(f, "public"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// Database TLS policy shared by SQL backends and MongoDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbTlsMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl DbTlsMode {
    fn postgres_value(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Allow => "allow",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }

    fn mysql_value(self) -> Result<&'static str, String> {
        match self {
            Self::Disable => Ok("DISABLED"),
            Self::Prefer => Ok("PREFERRED"),
            Self::Require => Ok("REQUIRED"),
            Self::VerifyCa => Ok("VERIFY_CA"),
            Self::VerifyFull => Ok("VERIFY_IDENTITY"),
            Self::Allow => Err(
                "FERRUM_DB_TLS_MODE=allow is PostgreSQL-only; cannot build MySQL TLS URL parameters"
                    .into(),
            ),
        }
    }

    pub fn enables_tls(self) -> bool {
        !matches!(self, Self::Disable)
    }

    pub fn allows_invalid_certificates(self) -> bool {
        matches!(self, Self::Require)
    }
}

impl std::fmt::Display for DbTlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disable => "disable",
            Self::Allow => "allow",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        })
    }
}

fn validate_k8s_namespace(ns: &str) -> Result<(), String> {
    if ns.is_empty() {
        return Err("namespace must not be empty".to_string());
    }
    if ns.len() > 63 {
        return Err(format!(
            "namespace must be at most 63 characters, got {}",
            ns.len()
        ));
    }
    let bytes = ns.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!(
            "namespace '{}' is invalid: must start with lowercase alphanumeric",
            ns
        ));
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(format!(
            "namespace '{}' is invalid: must end with lowercase alphanumeric",
            ns
        ));
    }
    if !ns
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "namespace '{}' is invalid: use lowercase alphanumeric characters or '-'",
            ns
        ));
    }
    Ok(())
}

/// Classify a DP CP gRPC URL for the secure-by-default plaintext gate.
///
/// Returns `Ok(true)` when the URL is plaintext (`http://`/`grpc://`) AND its
/// host is non-loopback — the only case the gate blocks without an explicit
/// opt-in. Returns `Ok(false)` for TLS URLs (`https://`/`grpcs://`) and for
/// loopback plaintext (`127.0.0.1`, `::1`, `localhost`, `*.localhost`). A URL
/// that does not parse, or that carries an unsupported scheme, is an `Err` so
/// the misconfiguration surfaces at startup rather than at first dial.
fn cp_dp_grpc_url_is_nonloopback_plaintext(url: &str) -> Result<bool, String> {
    // `url` is a trimmed list segment and `scheme()` is a lowercased fragment of
    // it, so both are transformed renderings; withhold by key.
    let shown = crate::secrets::quoted_env_value("FERRUM_DP_CP_GRPC_URLS", url);
    let parsed = url::Url::parse(url)
        .map_err(|e| format!("FERRUM_DP_CP_GRPC_URLS entry {shown} is not a valid URL: {e}"))?;
    let plaintext = match parsed.scheme() {
        "https" | "grpcs" => return Ok(false),
        "http" | "grpc" => true,
        other => {
            return Err(format!(
                "FERRUM_DP_CP_GRPC_URLS entry {shown} has unsupported scheme {} \
                 (expected http:// or https://)",
                crate::secrets::quoted_env_value("FERRUM_DP_CP_GRPC_URLS", &format!("{other}://"))
            ));
        }
    };
    let host = parsed
        .host()
        .ok_or_else(|| format!("FERRUM_DP_CP_GRPC_URLS entry {shown} is missing a host"))?;
    let is_loopback = match host {
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
        url::Host::Domain(d) => {
            let d = d.to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
    };
    Ok(plaintext && !is_loopback)
}

/// Check whether an IP address falls within private/reserved ranges.
///
/// Private/reserved ranges (denied in `Public` mode, allowed in `Private` mode):
/// - IPv4: loopback, RFC1918, link-local / cloud metadata, 0.0.0.0/8,
///   CGNAT, documentation, benchmarking, multicast, and reserved ranges.
/// - IPv6: loopback, unspecified, IPv4-mapped/compatible private/reserved
///   addresses, NAT64 private/reserved embeddings, discard-only,
///   documentation, IETF special-purpose, deprecated 6to4, ULA, link-local,
///   and multicast ranges.
pub fn is_private_ip(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            ip.is_loopback()                // 127.0.0.0/8
            || ip.is_private()              // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || ip.is_link_local()           // 169.254.0.0/16
            || ip.is_unspecified()          // 0.0.0.0
            || a == 0                       // 0.0.0.0/8 (full range)
            || (a == 100 && (b & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
            || is_non_global_ietf_protocol_assignment_v4(a, b, c, d)
            || (a == 192 && b == 0 && c == 2) // 192.0.2.0/24 (TEST-NET-1)
            || (a == 192 && b == 88 && c == 99) // 192.88.99.0/24 (deprecated 6to4 relay)
            || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 (benchmarking)
            || (a == 198 && b == 51 && c == 100) // 198.51.100.0/24 (TEST-NET-2)
            || (a == 203 && b == 0 && c == 113) // 203.0.113.0/24 (TEST-NET-3)
            || (224..=239).contains(&a)     // 224.0.0.0/4 (multicast)
            || a >= 240 // 240.0.0.0/4 + 255.255.255.255
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_private_ip(&std::net::IpAddr::V4(mapped));
            }
            if let Some(compatible) = ip.to_ipv4() {
                return is_private_ip(&std::net::IpAddr::V4(compatible));
            }

            let segments = ip.segments();
            ip.is_loopback()                            // ::1
            || ip.is_unspecified()                      // ::
            || is_well_known_nat64_private_ip(segments) // 64:ff9b::/96 with private/reserved embedded IPv4
            || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001) // 64:ff9b:1::/48
            || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0) // 100::/64 (discard-only)
            || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 1) // 100:0:0:1::/64 (dummy prefix)
            || is_non_global_ietf_protocol_assignment_v6(segments)
            || (segments[0] == 0x2001 && segments[1] == 0x0db8) // 2001:db8::/32 (documentation)
            || segments[0] == 0x2002                  // 2002::/16 (deprecated 6to4)
            || (segments[0] & 0xfe00) == 0xfc00        // fc00::/7 (unique local)
            || (segments[0] & 0xffc0) == 0xfe80        // fe80::/10 (link-local)
            || (segments[0] & 0xff00) == 0xff00 // ff00::/8 (multicast)
        }
    }
}

fn is_non_global_ietf_protocol_assignment_v4(a: u8, b: u8, c: u8, d: u8) -> bool {
    if !(a == 192 && b == 0 && c == 0) {
        return false;
    }

    // 192.0.0.9/32 and 192.0.0.10/32 are globally reachable anycast
    // assignments inside the otherwise non-global 192.0.0.0/24 parent.
    d != 9 && d != 10
}

fn is_non_global_ietf_protocol_assignment_v6(segments: [u16; 8]) -> bool {
    if !(segments[0] == 0x2001 && segments[1] < 0x0200) {
        return false;
    }

    // Allow the globally reachable more-specific assignments in 2001::/23.
    if segments[1] == 0x0001
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && segments[6] == 0
        && matches!(segments[7], 1..=3)
    {
        return false;
    }

    if segments[1] == 0x0003 {
        return false;
    }

    if segments[1] == 0x0004 && segments[2] == 0x0112 {
        return false;
    }

    if (segments[1] & 0xfff0) == 0x0020 || (segments[1] & 0xfff0) == 0x0030 {
        return false;
    }

    true
}

fn is_well_known_nat64_private_ip(segments: [u16; 8]) -> bool {
    if segments[0] != 0x0064
        || segments[1] != 0xff9b
        || segments[2] != 0
        || segments[3] != 0
        || segments[4] != 0
        || segments[5] != 0
    {
        return false;
    }

    let [a, b] = segments[6].to_be_bytes();
    let [c, d] = segments[7].to_be_bytes();
    is_private_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)))
}

/// Check whether an IP is allowed under the given backend IP *mode* alone.
///
/// This is the legacy `FERRUM_BACKEND_ALLOW_IPS` primitive. It is the mode
/// component of [`BackendEgressPolicy`] and is still used directly where a
/// fixed mode is wanted regardless of CIDR overlays or the dangerous-range
/// baseline (e.g. ACME, which always demands a public IP). New egress
/// decisions should go through [`BackendEgressPolicy::is_allowed`].
pub fn check_backend_ip_allowed(addr: &std::net::IpAddr, policy: &BackendAllowIps) -> bool {
    match policy {
        BackendAllowIps::Both => true,
        BackendAllowIps::Private => is_private_ip(addr),
        BackendAllowIps::Public => !is_private_ip(addr),
    }
}

/// The "never a legitimate backend" ranges that the egress baseline denies by
/// default — even under `FERRUM_BACKEND_ALLOW_IPS=both`.
///
/// This is deliberately a STRICT SUBSET of [`is_private_ip`]: loopback
/// (`127.0.0.0/8`, `::1`) and RFC1918 (`10/8`, `172.16/12`, `192.168/16`) and
/// their IPv6 ULA equivalent (`fc00::/7`) are intentionally NOT here. The
/// gateway's whole job is to reach private backends — mesh inbound dials
/// `127.0.0.1:<appPort>`, sidecars and same-host services use loopback, and
/// internal upstreams use RFC1918 — so blocking those by default would break
/// normal deployments. What this blocks instead is the set of ranges that are
/// essentially never a real backend yet are the classic SSRF pivots:
///
/// - **Cloud metadata / link-local**: `169.254.0.0/16` (incl. `169.254.169.254`,
///   the AWS/GCP/Azure IMDS) and IPv6 `fe80::/10`, plus the Alibaba Cloud / ENS
///   IMDS host `100.100.100.200` (which sits in CGNAT, not link-local).
/// - **Multicast**: `224.0.0.0/4` and `ff00::/8`.
/// - **Unspecified / "this host"**: `0.0.0.0`, `0.0.0.0/8`, and IPv6 `::`.
/// - **Limited broadcast**: `255.255.255.255`.
///
/// Operators who genuinely need one of these (e.g. an IMDS proxy) re-allow it
/// explicitly with `FERRUM_BACKEND_ALLOW_CIDRS`.
pub fn is_always_blocked_range(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(ip) => {
            ip.is_link_local()      // 169.254.0.0/16 (cloud metadata)
            || ip.is_unspecified()  // 0.0.0.0
            || ip.octets()[0] == 0  // 0.0.0.0/8 ("this host on this network")
            || ip.is_multicast()    // 224.0.0.0/4
            || ip.is_broadcast() // 255.255.255.255
            // Alibaba Cloud / ENS instance metadata service. Unlike AWS/GCP/Azure
            // (all on 169.254.169.254), Alibaba's IMDS lives at 100.100.100.200,
            // which sits inside CGNAT (100.64.0.0/10) and is otherwise NOT
            // link-local — so block the EXACT host (not the whole /10, which can
            // carry legitimate CGNAT backends). Re-allow with FERRUM_BACKEND_ALLOW_CIDRS.
            || ip.octets() == [100, 100, 100, 200]
        }
        std::net::IpAddr::V6(ip) => {
            // Loopback (`::1`) is explicitly allowed and must NOT be caught by
            // the IPv4-compat mapping below — `::1`.to_ipv4() is `0.0.0.1`,
            // which is inside the blocked `0.0.0.0/8`. Guard it first.
            if ip.is_loopback() {
                return false;
            }
            // Canonicalise an IPv4-mapped (`::ffff:a.b.c.d`) or deprecated
            // IPv4-compatible (`::a.b.c.d`) address to its v4 form so a
            // mapped/compat metadata/multicast/unspecified/this-host address is
            // caught too (parity with `is_private_ip`).
            if let Some(v4) = ip.to_ipv4_mapped().or_else(|| ip.to_ipv4()) {
                return is_always_blocked_range(&std::net::IpAddr::V4(v4));
            }
            // NAT64 well-known prefix (64:ff9b::/96): decode the embedded IPv4
            // and apply the same baseline, so a NAT64-encoded metadata/multicast
            // address (e.g. 64:ff9b::a9fe:a9fe for 169.254.169.254) cannot bypass
            // the default block via an IPv6-only / NAT64 DNS answer (rebinding).
            let segments = ip.segments();
            if segments[0] == 0x0064
                && segments[1] == 0xff9b
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0
            {
                let [a, b] = segments[6].to_be_bytes();
                let [c, d] = segments[7].to_be_bytes();
                return is_always_blocked_range(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    a, b, c, d,
                )));
            }
            // NAT64 local-use prefix (RFC 8215, `64:ff9b:1::/48`): a DNS64
            // resolver configured with this prefix embeds the IPv4 in the bits
            // after the /48. The exact octet positions depend on the embedding —
            // RFC 6052 reserves the u-byte at bits 64-71 — so decode BOTH the
            // contiguous form (IPv4 in `segments[3..=4]`, e.g. `64:ff9b:1:a9fe:a9fe::`
            // for 169.254.169.254) and the RFC 6052 /48 form (IPv4 split across the
            // u-byte) and block if EITHER lands in a dangerous range, so an
            // IPv6-only / DNS64 answer cannot rebind to IMDS through this prefix.
            // `is_private_ip` already treats the whole `64:ff9b:1::/48` as private,
            // so this stays a strict subset of it.
            if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
                let [s3hi, s3lo] = segments[3].to_be_bytes();
                let [s4hi, s4lo] = segments[4].to_be_bytes();
                let [s5hi, _] = segments[5].to_be_bytes();
                let contiguous = std::net::Ipv4Addr::new(s3hi, s3lo, s4hi, s4lo);
                let rfc6052_48 = std::net::Ipv4Addr::new(s3hi, s3lo, s4lo, s5hi);
                if is_always_blocked_range(&std::net::IpAddr::V4(contiguous))
                    || is_always_blocked_range(&std::net::IpAddr::V4(rfc6052_48))
                {
                    return true;
                }
            }
            ip.is_unspecified()                     // ::
            // AWS EC2 IPv6 instance metadata (IMDSv6) lives at fd00:ec2::254,
            // inside the otherwise-allowed ULA range (fc00::/7) — block the
            // exact metadata host so the IPv6 IMDS SSRF pivot is closed by
            // default while ordinary ULA backends stay reachable.
            || segments == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
            || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
            || ip.is_multicast() // ff00::/8
        }
    }
}

/// Extract the IPv4 address embedded in an IPv4-mapped (`::ffff:a.b.c.d`),
/// deprecated IPv4-compatible (`::a.b.c.d`), or NAT64 (`64:ff9b::a.b.c.d`) IPv6
/// address. Used so operator allow/deny CIDR rules written in IPv4 form also
/// apply to a backend that resolves to the IPv6 encoding of that address.
/// Loopback (`::1`) is excluded — its compat form `0.0.0.1` would be a false
/// embedded match.
fn embedded_ipv4(addr: &std::net::IpAddr) -> Option<std::net::Ipv4Addr> {
    let std::net::IpAddr::V6(ip) = addr else {
        return None;
    };
    if ip.is_loopback() {
        return None;
    }
    let segments = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let [a, b] = segments[6].to_be_bytes();
        let [c, d] = segments[7].to_be_bytes();
        return Some(std::net::Ipv4Addr::new(a, b, c, d));
    }
    // NAT64 local-use prefix `64:ff9b:1::/48` (RFC 8215): the embedded IPv4
    // follows the /48 contiguously in `segments[3..=4]` (e.g. `64:ff9b:1:a00:1::`
    // = 10.0.0.1), so a deny CIDR written in IPv4 form (e.g. `10.0.0.0/8`) is
    // matched by the decoded address instead of being bypassed by the IPv6
    // encoding. `is_always_blocked_range` additionally decodes the RFC 6052 /48
    // u-byte-split form for the dangerous baseline; the contiguous form is the
    // realistic DNS64 encoding for CIDR-list matching.
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
        let [a, b] = segments[3].to_be_bytes();
        let [c, d] = segments[4].to_be_bytes();
        return Some(std::net::Ipv4Addr::new(a, b, c, d));
    }
    // IPv4-mapped (`::ffff:a.b.c.d`) and deprecated IPv4-compatible (`::a.b.c.d`).
    ip.to_ipv4_mapped().or_else(|| ip.to_ipv4())
}

/// The IPv4 embedded in a NAT64 *local-use* prefix (`64:ff9b:1::/48`, RFC 8215)
/// under the RFC 6052 /48 layout, where the low two octets are split around the
/// reserved `u` byte (bits 64-71): IPv4 = `[s3.hi, s3.lo, s4.lo, s5.hi]`.
/// [`embedded_ipv4`] returns the contiguous-layout candidate (`[s3.hi, s3.lo,
/// s4.hi, s4.lo]`); CIDR-list matching checks BOTH so neither DNS64 octet layout
/// can evade a narrow deny CIDR (e.g. `64:ff9b:1:a01:2:500::` is `10.1.2.5` here
/// but `10.1.0.2` contiguously). `None` for any address outside the local-use
/// prefix. (The dangerous-range baseline decodes both inline in
/// [`is_always_blocked_range`].)
fn embedded_ipv4_local_use_rfc6052(addr: &std::net::IpAddr) -> Option<std::net::Ipv4Addr> {
    let std::net::IpAddr::V6(ip) = addr else {
        return None;
    };
    let segments = ip.segments();
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
        let [a, b] = segments[3].to_be_bytes();
        let [_u, c] = segments[4].to_be_bytes();
        let [d, _] = segments[5].to_be_bytes();
        return Some(std::net::Ipv4Addr::new(a, b, c, d));
    }
    None
}

/// Resolved backend egress policy: the `FERRUM_BACKEND_ALLOW_IPS` mode plus an
/// explicit allow/deny CIDR overlay and the dangerous-range baseline.
///
/// Evaluation precedence for a resolved IP (first match wins):
/// 1. `FERRUM_BACKEND_ALLOW_CIDRS` — explicit ALLOW, overrides everything below
///    (the escape hatch for an operator who truly needs e.g. `169.254.169.254`
///    or a private host under a `public` mode).
/// 2. `FERRUM_BACKEND_DENY_CIDRS` — explicit DENY.
/// 3. Dangerous-range baseline ([`is_always_blocked_range`]) when
///    `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES` is enabled (the default).
/// 4. `FERRUM_BACKEND_ALLOW_IPS` mode (`both` allows; `private`/`public` filter
///    on [`is_private_ip`]).
///
/// The whole point of this type is that a *default* gateway (no env vars set)
/// is `both` + baseline-on: it still reaches loopback/RFC1918 backends, but it
/// is no longer an unrestricted bridge to cloud-metadata / multicast /
/// unspecified addresses.
#[derive(Debug, Clone)]
pub struct BackendEgressPolicy {
    allow_ips: BackendAllowIps,
    allow_cidrs: CidrSet,
    deny_cidrs: CidrSet,
    block_dangerous: bool,
}

impl BackendEgressPolicy {
    /// A truly unrestricted policy: `both` mode, no CIDR overlays, no baseline.
    ///
    /// Used by back-compat helpers and tests that intentionally want *no*
    /// egress screening (the historical behaviour of `BackendAllowIps::Both`).
    /// This is NOT the production default — see [`Self::from_env`].
    pub fn unrestricted() -> Self {
        Self {
            allow_ips: BackendAllowIps::Both,
            allow_cidrs: CidrSet::default(),
            deny_cidrs: CidrSet::default(),
            block_dangerous: false,
        }
    }

    /// Build a policy from a bare mode with the production dangerous-range
    /// baseline enabled and no CIDR overlays. Useful for tests and for callers
    /// that only have a mode in hand.
    pub fn from_allow_ips(allow_ips: BackendAllowIps) -> Self {
        Self {
            allow_ips,
            allow_cidrs: CidrSet::default(),
            deny_cidrs: CidrSet::default(),
            block_dangerous: true,
        }
    }

    /// Build the resolved policy from parsed env inputs.
    pub fn from_env(
        allow_ips: BackendAllowIps,
        allow_cidrs_raw: &str,
        deny_cidrs_raw: &str,
        block_dangerous: bool,
    ) -> Result<Self, String> {
        let allow_cidrs = CidrSet::parse_strict(allow_cidrs_raw)
            .map_err(|e| format!("FERRUM_BACKEND_ALLOW_CIDRS: {e}"))?;
        let deny_cidrs = CidrSet::parse_strict(deny_cidrs_raw)
            .map_err(|e| format!("FERRUM_BACKEND_DENY_CIDRS: {e}"))?;
        let policy = Self {
            allow_ips,
            allow_cidrs,
            deny_cidrs,
            block_dangerous,
        };
        if policy.is_fully_open() {
            tracing::warn!(
                "FERRUM_BACKEND_ALLOW_IPS=both with the dangerous-range baseline disabled \
                 (FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false) and no FERRUM_BACKEND_DENY_CIDRS: \
                 backend egress is UNRESTRICTED. The gateway will proxy/forward to ANY resolved \
                 address including cloud-metadata (169.254.169.254), loopback, and link-local. \
                 Leave the baseline enabled and/or set FERRUM_BACKEND_ALLOW_IPS=public for \
                 internet-only backends."
            );
        }
        Ok(policy)
    }

    /// The underlying allow-ips mode.
    pub fn allow_ips(&self) -> &BackendAllowIps {
        &self.allow_ips
    }

    /// Whether a resolved backend IP is permitted to be dialed.
    pub fn is_allowed(&self, addr: &std::net::IpAddr) -> bool {
        self.deny_reason(addr).is_none()
    }

    /// Returns a short human-readable reason if `addr` is denied, else `None`.
    /// Used to build actionable errors at config-load and resolution time.
    pub fn deny_reason(&self, addr: &std::net::IpAddr) -> Option<&'static str> {
        // Match allow/deny CIDR rules against both the address and the IPv4
        // embedded in a NAT64 / IPv4-mapped / IPv4-compatible IPv6 address, so a
        // rule written in IPv4 form (e.g. `FERRUM_BACKEND_DENY_CIDRS=10.0.0.0/8`)
        // can't be bypassed by a backend that resolves to the IPv6 encoding of
        // that address (`64:ff9b::0a00:1`, `::ffff:10.0.0.1`, …).
        let embedded = embedded_ipv4(addr).map(std::net::IpAddr::V4);
        let embedded_rfc6052 = embedded_ipv4_local_use_rfc6052(addr).map(std::net::IpAddr::V4);
        // Deny-wins for an ambiguous NAT64 *local-use* address (`64:ff9b:1::/48`,
        // RFC 8215): it decodes to TWO IPv4s depending on the DNS64 octet layout —
        // the contiguous layout (`embedded`) and the RFC 6052 /48 u-byte-split
        // layout (`embedded_rfc6052`) — and the gateway can't know which the
        // backend resolves to. Evaluate EACH decode through the full precedence
        // FIRST; if either is denied (and not itself allow-listed) the address is
        // denied, so an allow match on one decode can't short-circuit a
        // deny/baseline match on the other. Recursion terminates: a decode is an
        // IPv4, for which `embedded_ipv4_local_use_rfc6052` is `None`.
        if let Some(rfc6052_decode) = embedded_rfc6052 {
            let contiguous_decode = embedded.unwrap_or(rfc6052_decode);
            if let Some(reason) = self.deny_reason(&contiguous_decode) {
                return Some(reason);
            }
            if let Some(reason) = self.deny_reason(&rfc6052_decode) {
                return Some(reason);
            }
        }
        // Shared precedence. `cidr_match` covers the address AND every embedded
        // IPv4 decode (both NAT64 layouts for local-use, the single well-known /96
        // / IPv4-mapped / IPv4-compatible decode otherwise), so neither an
        // IPv4-form rule (matched via a decode) nor an IPv6-form rule (matched via
        // the literal — e.g. `FERRUM_BACKEND_DENY_CIDRS=64:ff9b:1::/48`) is
        // bypassed. `mode_reason` then runs on the original literal, so the
        // private/reserved local-use NAT64 prefix is still rejected under
        // `public`/`private` mode even when both decoded IPv4s would pass.
        let cidr_match = |set: &CidrSet| {
            set.contains(addr)
                || embedded.as_ref().is_some_and(|e| set.contains(e))
                || embedded_rfc6052.as_ref().is_some_and(|e| set.contains(e))
        };
        // 1. Explicit allow overrides every deny below.
        if cidr_match(&self.allow_cidrs) {
            return None;
        }
        // 2. Explicit deny.
        if cidr_match(&self.deny_cidrs) {
            return Some("listed in FERRUM_BACKEND_DENY_CIDRS");
        }
        // 3. Dangerous-range baseline.
        if self.block_dangerous && is_always_blocked_range(addr) {
            return Some(
                "cloud-metadata/link-local/multicast/unspecified range blocked by default \
                 (set FERRUM_BACKEND_ALLOW_CIDRS to permit, or \
                 FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false to disable the baseline)",
            );
        }
        // 4. Legacy mode.
        self.mode_reason(addr)
    }

    /// The `FERRUM_BACKEND_ALLOW_IPS` mode verdict for `addr` (step 4 of
    /// [`deny_reason`]): `None` if the mode permits it, else a reason. Factored
    /// out so the ambiguous local-use NAT64 branch can apply the mode check on the
    /// original IPv6 literal (which `is_private_ip` classifies as private/reserved)
    /// after its decode checks, instead of bypassing the mode entirely.
    fn mode_reason(&self, addr: &std::net::IpAddr) -> Option<&'static str> {
        if check_backend_ip_allowed(addr, &self.allow_ips) {
            None
        } else {
            match self.allow_ips {
                BackendAllowIps::Public => {
                    Some("private/reserved IP rejected by FERRUM_BACKEND_ALLOW_IPS=public")
                }
                BackendAllowIps::Private => {
                    Some("public IP rejected by FERRUM_BACKEND_ALLOW_IPS=private")
                }
                // `Both` can never reach this arm.
                BackendAllowIps::Both => None,
            }
        }
    }

    /// True only when the policy can never deny any address — lets callers
    /// skip literal-IP validation work entirely. Note explicit ALLOW CIDRs do
    /// not affect this (they only ever permit), so a fully-open policy is
    /// `both` mode + no deny CIDRs + baseline disabled.
    pub fn is_fully_open(&self) -> bool {
        matches!(self.allow_ips, BackendAllowIps::Both)
            && self.deny_cidrs.is_empty()
            && !self.block_dangerous
    }
}

impl std::fmt::Display for BackendEgressPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "allow_ips={}", self.allow_ips)?;
        if self.block_dangerous {
            write!(f, "+block-dangerous-ranges")?;
        }
        if !self.deny_cidrs.is_empty() {
            write!(f, "+deny_cidrs({})", self.deny_cidrs.len())?;
        }
        if !self.allow_cidrs.is_empty() {
            write!(f, "+allow_cidrs({})", self.allow_cidrs.len())?;
        }
        Ok(())
    }
}

/// Resolve a configuration value: env var takes precedence over conf file.
fn resolve_var(conf: &ConfFile, key: &str) -> Option<String> {
    if let Ok(env_val) = env::var(key) {
        if conf.get(key).is_some_and(|conf_val| conf_val != env_val) {
            tracing::info!("{key}: environment variable overrides ferrum.conf default");
        }
        return Some(env_val);
    }
    conf.get(key).map(|v| v.to_string())
}

fn resolve_tls_source_override(
    conf: &ConfFile,
    source_key: &str,
    path_key: &str,
    path_value: Option<String>,
) -> Option<String> {
    match resolve_var(conf, source_key) {
        Some(source_value) => {
            if path_value.as_ref().is_some_and(|value| !value.is_empty()) {
                tracing::warn!(
                    source_key,
                    path_key,
                    "{source_key} is set; it overrides {path_key}"
                );
            }
            Some(source_value)
        }
        None => path_value,
    }
}

/// Resolve the same source-over-path contract through the process-wide
/// conf-aware resolver for consumers that do not hold the `ConfFile` used by
/// `EnvConfig::from_env_with_conf`.
fn resolve_cached_tls_source_override(source_key: &str, path_key: &str) -> Option<String> {
    let path_value = crate::config::conf_file::resolve_ferrum_var(path_key);
    match crate::config::conf_file::resolve_ferrum_var(source_key) {
        Some(source_value) => {
            if path_value.as_ref().is_some_and(|value| !value.is_empty()) {
                tracing::warn!(
                    source_key,
                    path_key,
                    "{source_key} is set; it overrides {path_key}"
                );
            }
            Some(source_value)
        }
        None => path_value,
    }
}

fn resolve_tls_key_exchange_groups(
    configured: Option<String>,
    legacy_curves: Option<String>,
) -> Option<String> {
    match (configured, legacy_curves) {
        (Some(value), Some(legacy)) => {
            if value != legacy {
                tracing::warn!(
                    "FERRUM_TLS_KEY_EXCHANGE_GROUPS is set; it overrides FERRUM_TLS_CURVES"
                );
            }
            Some(value)
        }
        (Some(value), None) => Some(value),
        (None, legacy) => legacy,
    }
}

/// Detect whether this process is running inside a Kubernetes pod.
///
/// The Kubernetes API server injects `KUBERNETES_SERVICE_HOST` and
/// `KUBERNETES_SERVICE_PORT` into every pod's environment unless the pod
/// opts out via `enableServiceLinks: false` *and* the operator also removes
/// the projected ServiceAccount volume — which is unusual. Checking for
/// `KUBERNETES_SERVICE_HOST` matches the same heuristic used by
/// `kube::Config::incluster()` and the standard `kubectl`/client-go
/// libraries, so a pod that loses this var also can't talk to the API
/// server (and would fail loudly elsewhere anyway).
///
/// Used by [`resolve_in_cluster_default_bool`] to flip Kubernetes-related
/// defaults to `true` for pod deployments without forcing operators to
/// set the env var explicitly.
fn is_in_cluster() -> bool {
    env::var("KUBERNETES_SERVICE_HOST").is_ok_and(|host| !host.trim().is_empty())
}

/// Resolve a boolean configuration value with a conditional in-cluster
/// default. An explicit operator value (env var or conf file) always wins;
/// only when neither is set does the fallback consider in-cluster context.
///
/// Returns:
/// - `Some(v)` (env var or conf file) → use `v` exactly as the operator set it.
/// - `None` (unset) + in a K8s pod → `true` (default-on for in-cluster).
/// - `None` (unset) + not in a K8s pod → `false` (default-off for local/dev).
///
/// Used by the two `FERRUM_K8S_*_ENABLED` switches that the T2-B follow-on
/// flipped to default-on inside a Kubernetes pod. CLI / Docker runs without
/// `KUBERNETES_SERVICE_HOST` see the historic `false` default; explicit
/// `=false` from the operator still wins over the in-cluster heuristic, so
/// pod-side opt-out remains one env var away.
fn resolve_in_cluster_default_bool(conf: &ConfFile, key: &str) -> Result<bool, String> {
    use env_config_macro::EnvValue;
    match resolve_var(conf, key) {
        Some(raw) => <bool as EnvValue>::parse_env(&raw, key),
        None => Ok(is_in_cluster()),
    }
}

/// Tri-state toggle: `auto` (detect at runtime), `true` (force on), `false` (force off).
///
/// Used for Linux-specific optimizations that can probe the kernel at startup.
/// When `auto`, the feature is enabled if the kernel supports it and disabled otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoBool {
    /// Detect support at runtime and enable if available.
    Auto,
    /// Force enabled (fail or warn if unsupported).
    True,
    /// Force disabled.
    False,
}

impl AutoBool {
    /// Resolve to a concrete bool using a runtime probe function.
    ///
    /// - `Auto` → call `probe()` and use its result
    /// - `True` → `true` (caller is responsible for handling unsupported case)
    /// - `False` → `false`
    pub fn resolve(self, probe: impl FnOnce() -> bool) -> bool {
        match self {
            Self::Auto => probe(),
            Self::True => true,
            Self::False => false,
        }
    }

    /// Returns `true` if the resolved value could POSSIBLY be `true` — i.e.
    /// every variant except `False`. Used by callers that must commit to a
    /// side-effect (e.g. setting `ServerConfig::enable_secret_extraction`)
    /// before the actual probe runs, and would rather over-enable than
    /// under-enable.
    pub fn could_be_enabled(self) -> bool {
        !matches!(self, Self::False)
    }
}

impl std::fmt::Display for AutoBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
        }
    }
}

/// All environment-driven configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields are used only in specific modes or feature paths.
pub struct EnvConfig {
    pub mode: OperatingMode,
    /// Namespace this gateway instance loads and manages. Resources from other
    /// namespaces are ignored. Default: "ferrum".
    pub namespace: String,
    pub log_level: String,
    /// Per-sink admitted record limit for process logging. Stdout/access logs
    /// share one sink and stderr owns another. Default: 4096.
    /// Note: consumed in main() before EnvConfig is constructed (tracing must init
    /// first), but stored here for completeness alongside other FERRUM_* vars.
    #[allow(dead_code)]
    pub log_buffer_capacity: usize,
    /// Per-sink aggregate reserved-byte budget. Default: 32 MiB.
    #[allow(dead_code)]
    pub log_buffer_bytes: usize,
    /// Maximum serialized bytes in one process log record. Default: 64 KiB.
    #[allow(dead_code)]
    pub log_max_record_bytes: usize,
    /// Shared observability lifecycle and per-process-sink drain timeout.
    /// Default: 2000 ms.
    pub log_shutdown_drain_timeout_ms: u64,
    /// Aggregate admitted terminal/mirror/deadline-cleanup task budget.
    /// Default: 4096.
    pub log_delivery_max_tasks: usize,
    /// Default poll interval in seconds for external TLS material sources
    /// (`vault://`, `aws://`, `azure://`, `gcp://`, `k8s://`, `managed://`) when a source URI does not
    /// include its own `?poll=` option. Clamped to 1 second minimum and 24 hours
    /// maximum.
    pub secret_refresh_interval_seconds: u64,
    /// Enable the ACME renewal scheduler. Requires the `acme` Cargo feature
    /// to perform renewals; builds without that feature log a warning and do
    /// not spawn the scheduler.
    pub acme_auto_renew_enabled: bool,
    /// Renew ACME-issued certificates when `not_after` is within this many
    /// days. Default: 30.
    pub acme_renew_when_remaining_days: u64,
    /// ACME renewal scheduler scan interval in seconds. Default: 3600.
    pub acme_renew_check_interval_seconds: u64,
    /// Challenge type the scheduler prepares for automatic renewal.
    /// Supported values: `http01`, `tls_alpn01`, `dns01`.
    pub acme_renew_challenge_type: String,
    /// Maximum time the scheduler waits for ACME authorization/order readiness
    /// and certificate issuance.
    pub acme_renew_poll_timeout_seconds: u64,
    /// Optional DNS-01 provider hook command. The scheduler invokes it with
    /// challenge details in environment variables before finalizing DNS-01
    /// renewal orders.
    pub acme_dns01_hook_command: Option<String>,
    /// Seconds to wait after DNS-01 hook publication before marking the ACME
    /// challenge ready.
    pub acme_dns01_propagation_seconds: u64,
    /// When true, streaming responses are wrapped with a lightweight tracker
    /// that records the final transfer time via a deferred task. Adds one
    /// `Arc<StreamingMetrics>` + one `tokio::spawn` per streaming request.
    /// Default: false (maximum throughput).
    pub enable_streaming_latency_tracking: bool,

    // Proxy traffic
    pub proxy_http_port: u16,
    pub proxy_https_port: u16,
    /// Global gzip content-coding gate for the built-in compression plugin.
    /// Intersects with each plugin instance's `algorithms` list and also
    /// disables opt-in gzip request decompression when false.
    pub compression_gzip_enabled: bool,
    /// Global Brotli content-coding gate for the built-in compression plugin.
    /// Intersects with each plugin instance's `algorithms` list and also
    /// disables opt-in Brotli request decompression when false.
    pub compression_brotli_enabled: bool,
    pub frontend_tls_cert_path: Option<String>,
    pub frontend_tls_key_path: Option<String>,
    /// DER OCSP response bytes, or a source URI resolving to DER bytes, to
    /// staple on frontend proxy TLS handshakes.
    pub frontend_tls_ocsp_response_source: Option<String>,
    /// Opt in to live reload of frontend TLS cert/key sources for the proxy
    /// HTTPS / H2 / H3 listeners, the admin HTTPS listener, and (in mesh
    /// mode) the mesh inbound TLS listener. When `false` (the default)
    /// cert/key sources are read once at startup and require a restart to
    /// rotate. When `true`, a background watcher polls the configured sources
    /// every [`frontend_tls_watch_interval_seconds`] seconds for file-backed
    /// sources or [`secret_refresh_interval_seconds`] seconds for provider-
    /// backed sources, then atomically
    /// swaps a rebuilt `rustls::ServerConfig` into the listener's
    /// `ArcSwap`-backed slot on a validated change. A rebuild that fails
    /// validation (parse / expired / not-yet-valid / key mismatch) keeps
    /// the previous config and emits a `warn!` — the gateway never serves a
    /// known-bad config. In-flight TLS sessions keep their original
    /// `ServerConfig`; only new handshakes pick up the new config.
    /// Operator-supplied per-proxy backend TLS paths and the DTLS frontend
    /// stay static under this knob.
    pub frontend_tls_live_reload_enabled: bool,
    /// Poll interval in seconds for the frontend TLS file-backed source watcher when
    /// [`frontend_tls_live_reload_enabled`] is `true`. Defaults to `30`.
    /// Ignored when live reload is disabled. Clamped to a 1-second minimum
    /// so an accidental `0` does not busy-loop the filesystem.
    pub frontend_tls_watch_interval_seconds: u64,
    /// Enable live reload for backend TLS identity and trust sources. When
    /// enabled, Ferrum watches global and per-proxy backend TLS cert/key/CA
    /// sources, validates the active backend TLS configs on change, then
    /// clears backend client pools so new backend connections rebuild with
    /// the rotated material. Existing in-flight requests keep their current
    /// connections.
    pub backend_tls_live_reload_enabled: bool,
    /// Poll interval in seconds for file-backed backend TLS source refresh.
    /// Provider-backed sources use [`secret_refresh_interval_seconds`] unless
    /// the URI includes its own `?poll=` override.
    pub backend_tls_watch_interval_seconds: u64,
    /// Bind address for proxy listeners (HTTP, HTTPS, HTTP/3).
    /// Default: "0.0.0.0" (IPv4 only). Set to "::" for dual-stack IPv4+IPv6.
    /// On most operating systems, binding to "::" accepts both IPv4 and IPv6
    /// connections via IPv4-mapped IPv6 addresses (dual-stack). This requires
    /// the OS to have dual-stack support enabled (the default on Linux, macOS,
    /// and Windows). If `net.ipv6.bindv6only=1` is set (Linux sysctl), binding
    /// to "::" will only accept IPv6 connections.
    pub proxy_bind_address: String,

    // Admin API
    pub admin_http_port: u16,
    pub admin_https_port: u16,
    pub admin_tls_cert_path: Option<String>,
    pub admin_tls_key_path: Option<String>,
    /// Bind address for Admin API listeners (HTTP, HTTPS).
    ///
    /// Default: `127.0.0.1` (loopback) — the admin API is a management plane and
    /// is safe-by-default, NOT exposed on the network. Set to `0.0.0.0` (or a
    /// specific address, or `::` for dual-stack) to expose it, but in the
    /// writable `database`/`cp` modes a public plaintext bind also requires an
    /// allowlist, TLS, or the `FERRUM_ALLOW_INSECURE_ADMIN_HTTP` opt-in — see
    /// [`EnvConfig::admin_insecure_plaintext_startup_error`]. The proxy data
    /// plane (`FERRUM_PROXY_BIND_ADDRESS`) still defaults to `0.0.0.0`.
    pub admin_bind_address: String,

    /// Dev-only escape hatch: allow the plaintext admin HTTP listener to bind a
    /// publicly reachable address (e.g. `0.0.0.0`) with no
    /// `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist in the writable `database`/`cp`
    /// modes. Without this, such a posture is a hard startup error (see
    /// [`EnvConfig::admin_insecure_plaintext_startup_error`]) because the
    /// writable admin API and operator bearer tokens would be exposed in
    /// cleartext on all matching interfaces. Default: `false`. Never enable in
    /// production — bind to loopback, set an allowlist, or serve admin over TLS
    /// instead.
    pub allow_insecure_admin_http: bool,

    // Admin JWT
    pub admin_jwt_secret: Option<String>,
    /// JWT issuer claim (iss) for Admin API tokens. Tokens with a different issuer
    /// are rejected during verification. Default: "ferrum-edge".
    /// Note: Also resolved via `resolve_ferrum_var()` in `jwt_auth.rs` for use sites
    /// that don't have `EnvConfig` in scope (e.g., `create_jwt_manager_from_env()`).
    #[allow(dead_code)]
    pub admin_jwt_issuer: String,
    /// Maximum accepted TTL in seconds for externally minted Admin API JWT tokens.
    ///
    /// Enforced against verifier time, with the 60s clock-skew leeway counted
    /// exactly once: the nominal lifetime (`exp - iat`) must be positive and
    /// within this value, `iat` must not be later than `now + leeway`, the
    /// remaining lifetime (`exp - now`) must be within this value plus that
    /// leeway, and `exp` must still be in the future at verifier time (no
    /// additional expiry grace). Effective maximum real validity is therefore
    /// `max_ttl + 60s`. `0` is an intentional disable sentinel that skips the
    /// lifetime cap entirely; a value above `i64::MAX` is rejected as invalid
    /// rather than treated as unlimited. Default: 3600.
    /// Note: Also resolved via `resolve_ferrum_var()` in `jwt_auth.rs`.
    #[allow(dead_code)]
    pub admin_jwt_max_ttl: u64,
    /// Optional required `aud` (audience) claim for externally minted Admin API
    /// JWT tokens. When set, verification requires the token to carry an `aud`
    /// claim matching this value; when unset (default), audience is not checked.
    /// Note: Also resolved via `resolve_ferrum_var()` in `jwt_auth.rs`.
    #[allow(dead_code)]
    pub admin_jwt_audience: Option<String>,

    // Database
    pub db_type: Option<String>,
    pub db_url: Option<String>,
    pub db_poll_interval: u64,
    /// Database-mode initial backoff, in seconds, after a database incremental
    /// delta is rejected by validation. CP mode uses the normal DB poll interval.
    pub db_rejected_delta_backoff_initial_seconds: u64,
    /// Database-mode maximum rejected-delta retry backoff, in seconds.
    pub db_rejected_delta_backoff_max_seconds: u64,
    /// Database-mode number of identical rejected deltas before the poller
    /// attempts an authoritative primary-backed full reload.
    pub db_rejected_delta_full_reload_threshold: u64,
    pub db_tls_mode: Option<DbTlsMode>,
    pub db_tls_ca_cert_path: Option<String>,
    pub db_tls_client_cert_path: Option<String>,
    pub db_tls_client_key_path: Option<String>,
    /// Enable live reload for database TLS sources in database and CP modes.
    /// When enabled, file/provider-backed DB CA/client cert/client key sources
    /// are fingerprinted and the active database pool/client is reconnected
    /// after validated byte changes. Defaults to `false`.
    pub db_tls_live_reload_enabled: bool,
    /// Poll interval in seconds for file-backed database TLS source refresh.
    /// Provider-backed sources use [`secret_refresh_interval_seconds`] unless
    /// the URI includes its own `?poll=` override.
    pub db_tls_watch_interval_seconds: u64,

    // File mode
    pub file_config_path: Option<String>,

    /// Path to an externally provided backup config file (JSON). When set in
    /// database mode and the database is unreachable at startup, the gateway
    /// loads config from this file so pods can restart with stale config while
    /// the database recovers. The file is expected to be provisioned externally
    /// (e.g. via ConfigMap, PersistentVolume, or sidecar export).
    pub db_config_backup_path: Option<String>,

    /// Comma-separated list of failover database URLs. When the primary
    /// `FERRUM_DB_URL` is unreachable, the gateway tries each failover URL in
    /// order. All URLs must use the same `FERRUM_DB_TYPE` and share TLS settings.
    pub db_failover_urls: Vec<String>,

    /// Connection URL for a SQL read replica database. When set, eligible
    /// admin-only reads can use this replica and fall back to primary if the
    /// replica is unreachable. Runtime config polling and Admin API writes
    /// always use the primary. MongoDB read preferences are ignored by the
    /// authoritative config store.
    pub db_read_replica_url: Option<String>,

    /// Threshold in milliseconds for logging slow database queries.
    /// When a database query exceeds this duration, a warning is logged with
    /// the operation name and elapsed time. Default: disabled (None).
    pub db_slow_query_threshold_ms: Option<u64>,

    // SQL database connection pool tuning. MongoDB manages its own driver pool;
    // tune it with URI options such as maxPoolSize and minPoolSize.
    /// Maximum rows fetched per query during full config loading from SQL
    /// databases. Prevents unbounded `SELECT *` from hitting statement
    /// timeouts or causing memory spikes at scale (100k+ rows). Raw `AnyRow`
    /// buffers are freed between chunks, so peak memory is proportional to
    /// this value, not table size. Default: 10000. Range: 100..=100000.
    pub db_full_load_page_size: u64,

    /// Maximum number of connections in the SQL database pool. Default: 32.
    /// Increase for CP mode with many DPs or high admin API concurrency.
    pub db_pool_max_connections: u32,
    /// Minimum number of idle connections maintained in the SQL pool. Default: 1.
    /// Higher values reduce cold-start latency at the cost of holding open
    /// connections. Set to 0 to allow the pool to shrink to zero idle.
    pub db_pool_min_connections: u32,
    /// Maximum time (seconds) to wait for a connection from the SQL pool before
    /// returning an error. Default: 30. Prevents unbounded waits when the
    /// pool is exhausted under load.
    pub db_pool_acquire_timeout_seconds: u64,
    /// Maximum time (seconds) a SQL connection can sit idle before being closed.
    /// Default: 600 (10 minutes). Keeps the pool from holding stale connections.
    pub db_pool_idle_timeout_seconds: u64,
    /// Maximum lifetime (seconds) of a SQL connection before it is closed and
    /// replaced. Default: 300 (5 minutes). Forces DNS re-resolution and
    /// prevents stale server-side state. Defence-in-depth alongside the
    /// explicit DnsCache-based reconnect.
    pub db_pool_max_lifetime_seconds: u64,
    /// Maximum time (seconds) to wait for a new SQL TCP connection to the database.
    /// Default: 10. Separate from `acquire_timeout_seconds` (which covers
    /// waiting for a pool slot + connecting). 0 = disabled (falls back to OS
    /// TCP timeout, which can be 60–120s).
    pub db_pool_connect_timeout_seconds: u64,
    /// Maximum execution time (seconds) for any single SQL statement. Default:
    /// 30, max 3600 (1 hour). Values above 3600 are clamped at parse time with
    /// a warning. Set via `SET statement_timeout` (PostgreSQL) or `SET SESSION
    /// max_execution_time` (MySQL) on every new connection. 0 = disabled.
    /// Ignored for SQLite (not supported).
    pub db_pool_statement_timeout_seconds: u64,

    // MongoDB-specific settings (when FERRUM_DB_TYPE=mongodb).
    // These fields are read by `mongo_store::MongoStore::connect()` when the
    // active database backend is `FERRUM_DB_TYPE=mongodb`.
    /// MongoDB database name to use. Default: "ferrum".
    pub mongo_database: String,
    /// MongoDB application name for server-side connection tracking.
    pub mongo_app_name: Option<String>,
    /// MongoDB replica set name. Required for change streams and transactions.
    pub mongo_replica_set: Option<String>,
    /// MongoDB auth mechanism override (e.g. "SCRAM-SHA-256", "MONGODB-X509").
    pub mongo_auth_mechanism: Option<String>,
    /// Explicit MongoDB server selection timeout in seconds.
    ///
    /// `None` (unset) preserves `serverSelectionTimeoutMS` from `FERRUM_DB_URL`
    /// or the driver default. When set, overrides the URI value.
    pub mongo_server_selection_timeout_seconds: Option<u64>,
    /// Explicit MongoDB connection timeout in seconds.
    ///
    /// `None` (unset) preserves `connectTimeoutMS` from `FERRUM_DB_URL` or the
    /// driver default. When set, overrides the URI value.
    pub mongo_connect_timeout_seconds: Option<u64>,

    // CP/DP
    pub cp_grpc_listen_addr: Option<String>,
    pub cp_dp_grpc_jwt_secret: Option<String>,
    /// Expected `iss` claim on CP/DP gRPC JWTs. The CP rejects any token whose
    /// `iss` claim does not exactly match this value, and the DP mints tokens
    /// with this value. Defaults to "ferrum-edge-cp-dp". Operators rotating
    /// the issuer must update CP and all DPs together.
    pub cp_dp_grpc_jwt_issuer: String,
    /// Comma-separated, priority-ordered list of CP gRPC URLs for DP failover.
    /// The DP connects to the first URL and fails over to subsequent URLs when
    /// unreachable.
    pub dp_cp_grpc_urls: Vec<String>,
    /// How often (in seconds) the DP retries the primary (first) CP URL while
    /// connected to a fallback CP. Default: 300 (5 minutes). 0 = disabled.
    pub dp_cp_failover_primary_retry_secs: u64,
    /// Allow plaintext (non-TLS) CP/DP gRPC config sync on a non-loopback
    /// address. Off by default (secure-by-default): the CP gRPC listener refuses
    /// to bind a non-loopback address without TLS, and the DP rejects a
    /// non-loopback `http://` CP URL, unless this is `true`. Loopback
    /// (`127.0.0.1`/`::1`/`localhost`) plaintext is always permitted for local
    /// development. Even when permitted, plaintext config sync emits a
    /// high-severity startup warning — the DP authentication JWT and the full
    /// gateway configuration travel unencrypted and unauthenticated against MITM.
    /// `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT`.
    pub cp_dp_grpc_allow_plaintext: bool,

    // CP gRPC TLS (server-side)
    /// Path to PEM certificate for the CP gRPC server. When set (with key),
    /// the gRPC listener uses TLS instead of plaintext.
    pub cp_grpc_tls_cert_path: Option<String>,
    /// Path to PEM private key for the CP gRPC server.
    pub cp_grpc_tls_key_path: Option<String>,
    /// Path to PEM CA bundle for verifying DP client certificates (mTLS).
    /// When set, the CP requires and verifies client certificates from DPs.
    pub cp_grpc_tls_client_ca_path: Option<String>,
    /// Maximum concurrent CP gRPC listener connections, counted from **before**
    /// the TLS/mTLS handshake starts through the end of the served HTTP/2
    /// session. A permit is acquired before any per-socket handshake task is
    /// allocated, so an unauthenticated client cannot grow descriptor, memory,
    /// or scheduler usage past this bound by opening sockets and withholding
    /// the TLS ClientHello (advisory GHSA-2xqr-7j7p-77qp). Shared across the
    /// plaintext listener and every TLS certificate-reload generation.
    /// `FERRUM_CP_GRPC_MAX_CONNECTIONS`. Default 1024; `0` = unlimited (not
    /// recommended on a reachable CP).
    pub cp_grpc_max_connections: usize,
    /// Maximum concurrent CP gRPC listener connections from one source IP, so a
    /// single host cannot consume the whole `cp_grpc_max_connections` budget.
    /// `FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP`. Default 64; `0` disables per-IP
    /// limiting. Must not exceed `cp_grpc_max_connections` when both are set —
    /// a larger per-IP cap can never fire and is refused at startup rather than
    /// silently ignored.
    pub cp_grpc_max_connections_per_ip: usize,
    /// Capacity of the tokio broadcast channel used to fan out config deltas
    /// to subscribed Data Planes. When a DP lags behind by more than this many
    /// updates, it receives a full config snapshot instead of the missed deltas.
    /// Higher values trade memory for fewer full-snapshot recoveries under
    /// high config churn. Default: 128.
    pub cp_broadcast_channel_capacity: usize,
    /// CP namespace scope. Accepts:
    /// - empty / unset — back-compat: CP serves only `FERRUM_NAMESPACE`.
    /// - `"*"` — CP serves every namespace present in the database (multi-tenant).
    /// - CSV (e.g. `"ns-a,ns-b"`) — CP serves only the listed namespaces.
    ///
    /// Per-namespace broadcast partitioning ensures a DP subscribing to one
    /// namespace never receives another namespace's config delta.
    /// Only meaningful in CP mode. Defaults to the empty list (back-compat).
    pub cp_namespaces: Vec<String>,
    /// When `true`, the CP requires every DP/mesh JWT to carry an `ns` claim
    /// (single string or list of strings). The CP rejects subscriptions whose
    /// requested namespace is not in the claim. When `false` (default), DPs
    /// with no claim fall back to the legacy CP-scope check, so existing
    /// deployments keep working unchanged. Multi-tenant CPs should set this
    /// to `true` so a compromised DP for tenant A cannot subscribe to tenant
    /// B by changing only its `FERRUM_NAMESPACE` value.
    pub cp_require_namespace_claim: bool,
    /// Mount Envoy ADS (`AggregatedDiscoveryService`) on the CP gRPC listener.
    /// Default false so existing CP/DP deployments expose only ConfigSync.
    pub xds_enabled: bool,
    /// Capacity of the per-ADS-stream response queue between the request
    /// reader task and tonic response stream. Default: 32.
    pub xds_stream_channel_capacity: usize,
    /// Maximum concurrent ADS streams the CP admits per node id. A DP keeps a
    /// single stream; the default headroom tolerates brief reconnect overlap.
    /// `0` disables the cap. Only meaningful when `xds_enabled` is true.
    /// Default: 4.
    pub xds_max_streams_per_node: usize,
    /// Mesh CA backend. `internal` uses Ferrum's own CA (root cert+key on
    /// disk); `spire` delegates to a SPIRE Agent over UDS; `none` (default)
    /// disables mesh identity features.
    pub mesh_ca_backend: String,
    /// Path to the SPIRE Agent's Workload API Unix domain socket. Only used
    /// when `mesh_ca_backend` is `spire`.
    pub mesh_spire_agent_socket: String,
    /// SVID lifetime hint (seconds) passed to the CA backend. The CA may
    /// clamp or ignore this value.
    pub mesh_cert_ttl_seconds: u64,
    /// Mesh runtime config source. `native` consumes Ferrum MeshSubscribe;
    /// `xds` consumes Envoy-compatible ADS; `file` loads a localized mesh
    /// config document from `FERRUM_MESH_FILE_CONFIG_PATH` (no control plane).
    pub mesh_config_protocol: String,
    /// Path to the localized mesh config document (YAML/JSON) consumed when
    /// `mesh_config_protocol` is `file`. The document carries only the `mesh`
    /// section of a gateway config; reloaded on SIGHUP (Unix).
    pub mesh_file_config_path: Option<String>,
    /// Additional SPIFFE trust domains accepted as equivalent to the peer
    /// cert's trust domain when validating HBONE baggage `source.principal`.
    /// Default empty: strict same-trust-domain match. Each entry must parse
    /// as a valid `TrustDomain` (lowercase host-form, no path).
    pub mesh_trust_domain_aliases: Vec<String>,
    /// Identity-asserting infrastructure SVIDs trusted to rewrite the authz
    /// principal via HBONE baggage `source.principal`. Each entry is either a
    /// bare Kubernetes service-account name (Istio convention,
    /// `ns/<ns>/sa/<sa>`) or a full SPIFFE id pinning a specific assertor
    /// identity. Default empty: mesh_authz uses its built-in defaults of
    /// `["ztunnel", "waypoint"]`. Operators with custom waypoint SA names
    /// (Gateway-managed waypoints often use `<gateway-name>` or
    /// `<gateway-name>-istio`) must set this to include their names.
    pub mesh_trusted_hbone_assertors: Vec<String>,
    /// Comma-separated W3C `baggage` key prefixes stripped from outbound
    /// requests at dispatch. Default empty: forward unchanged. Operators set
    /// this to keep mesh-internal identity claims (e.g. `source.`) from
    /// leaking to non-mesh upstream services.
    pub mesh_egress_strip_baggage_keys: Vec<String>,
    /// Istio-compatible mesh outbound traffic policy. Accepted values:
    /// `allow_any` (default — sidecar accepts traffic to any destination),
    /// `registry_only` (sidecar only accepts traffic to mesh-registered
    /// destinations; unknown destinations are rejected at the outbound
    /// capture listener via the auto-injected `mesh_outbound_registry`
    /// plugin).
    pub mesh_outbound_traffic_policy: String,
    /// HTTP status returned by the auto-injected mesh outbound registry plugin
    /// when `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only` rejects an
    /// unknown destination. Must be 4xx/5xx. Default: 502.
    pub mesh_outbound_registry_reject_status: u16,
    /// When `true`, the slice builder applies Istio `Sidecar` egress scope
    /// narrowing: services / service-entries / destination-rules outside the
    /// applicable Sidecar's egress scope are filtered out before being sent
    /// to data planes. Default `false` for safe rollout — operators opt in
    /// after vetting their `Sidecar` resources. Parsing of `Sidecar` CRDs
    /// happens unconditionally; this flag only gates the slice-narrowing
    /// pass.
    pub mesh_sidecar_enforced: bool,
    /// When true, compute and expose the Sidecar egress scope but keep the
    /// unenforced slice so traffic remains admitted.
    pub mesh_sidecar_enforced_dry_run: bool,
    /// When `true`, and only when `FERRUM_MESH_SIDECAR_ENFORCED=true`, the
    /// slice builder also narrows `workloads` to SPIFFE identities referenced
    /// by admitted services. Default `false` for a one-release rollout window.
    pub mesh_sidecar_identity_narrowing: bool,
    /// Opt-in for stream-family (TCP/UDP) egress proxy materialization in
    /// `EgressGateway` topology. Default `false`. When enabled, the per-port
    /// stream egress listeners terminate SVID-mTLS (reusing the mesh-inbound
    /// `ServerConfig`) and run `mesh_authz` at accept — the same authn/z as
    /// HTTP egress — unless `mesh_egress_stream_allow_plaintext` is set.
    pub mesh_egress_stream_enabled: bool,
    /// Explicit opt-out that makes stream-family egress listeners plaintext +
    /// unauthenticated again (the legacy posture). Default `false`: with
    /// `mesh_egress_stream_enabled=true` the per-port stream listeners
    /// terminate SVID-mTLS and run `mesh_authz`. Set to `true` ONLY when
    /// operators genuinely need plaintext and have compensating network
    /// controls — any pod that can reach the gateway then reaches the external
    /// service through it with no SPIFFE authn/z. A loud warning is emitted at
    /// startup when enabled. Ignored unless `mesh_egress_stream_enabled=true`.
    pub mesh_egress_stream_allow_plaintext: bool,

    /// Opt-in live reload for PeerAuthentication-derived inbound mTLS mode
    /// and client CA verifier. Cert/key paths remain static operational
    /// inputs.
    pub mesh_peer_auth_live_reload_enabled: bool,
    /// Whether the auto-injected mesh `RequestAuthentication` (`jwks_auth`)
    /// plugin requires the JWT `exp` claim to be present. Defaults to `true`
    /// (secure): tokens that omit `exp` are rejected so they cannot live
    /// forever. Set `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=false` to accept
    /// `exp`-less tokens (some Istio issuers legitimately omit `exp`).
    /// Independent of expiry *validation*: a present-but-expired `exp` is
    /// always rejected regardless of this flag.
    pub mesh_request_auth_require_exp: bool,
    /// SPIFFE trust-bundle federation polling interval in seconds.
    /// `0` disables the federation poller entirely; cross-cluster trust
    /// bundles must then be provided via the slice's `TrustBundleSet.federated`
    /// from the control plane.
    pub mesh_federation_poll_interval_seconds: u64,
    /// Per-request HTTP timeout for SPIFFE federation bundle fetches, in seconds.
    pub mesh_federation_poll_timeout_seconds: u64,
    /// Maximum age for a last-good polled federation bundle after poll
    /// failures, in seconds. `0` keeps last-good bundles indefinitely in
    /// non-production only; production validation rejects that posture.
    pub mesh_federation_max_stale_seconds: u64,
    /// When `true`, a poll failure that leaves a remote-cluster trust domain
    /// with no cached bundle still allows the mesh to start / continue (the
    /// remote trust domain is effectively unverifiable until the next
    /// successful poll). When `false` (the default), missing bundles cause
    /// cross-cluster mTLS verifications to fail closed.
    pub mesh_federation_fail_open: bool,
    /// Cross-cluster endpoint discovery polling interval in seconds. Each
    /// `RemoteCluster.control_plane_url` is dialed on this cadence to fetch the
    /// remote cluster's service endpoints, which are aggregated into local
    /// upstream targets (tagged with remote locality) for local→remote
    /// failover. `0` disables remote-cluster endpoint discovery entirely
    /// (multi-cluster then remains east-west SNI passthrough + federated trust
    /// only). Discovery is additionally fail-closed on trust: a remote cluster
    /// is only dialed when a federated trust bundle for its trust domain exists.
    pub mesh_remote_discovery_poll_interval_seconds: u64,
    /// Per-poll timeout for the remote-cluster MeshSubscribe fetch, in seconds.
    pub mesh_remote_discovery_poll_timeout_seconds: u64,
    /// Maximum age for last-good remote-cluster endpoints after poll failures,
    /// in seconds. `0` keeps endpoints indefinitely in non-production only;
    /// production validation rejects that posture.
    pub mesh_remote_discovery_max_stale_seconds: u64,
    /// Per-RemoteCluster discovery credentials as a JSON object mapping a
    /// credential reference (matched against `RemoteCluster.discovery_credential_ref`)
    /// to the JWT secret the remote cluster's control plane accepts. Resolvable
    /// through the external-secret suffixes (`_VAULT/_AWS/_AZURE/_GCP/_FILE`).
    /// A token minted with one cluster's secret will not verify at another, so a
    /// per-remote credential cannot authenticate to the wrong cluster. Never
    /// logged. Unset falls back to the shared CP-DP JWT secret.
    pub mesh_remote_discovery_credentials: Option<String>,
    /// Strict local-first locality load balancing. Default `false` (fail-open):
    /// when a mesh upstream's source locality is absent/unresolved the
    /// locality-aware LB returns local **and** remote endpoints together so
    /// traffic keeps flowing. When `true` (fail-closed-to-local): with an absent
    /// source locality the LB restricts selection to LOCAL-locality endpoints
    /// (targets not tagged with the synthetic `remote-<cluster>` locality) and
    /// will not widen to remote unless there are no local endpoints, in which
    /// case it falls back to the full healthy pool with a one-time warning
    /// rather than black-holing. Only affects mesh upstreams. Sourced from
    /// `FERRUM_MESH_LOCALITY_LB_STRICT`.
    pub mesh_locality_lb_strict: bool,
    /// Node-waypoint cgroup-inode lifecycle sweep interval (seconds).
    /// Identities enrolled with a cgroup v2 path are evicted when the
    /// cgroup is gone or its inode/fingerprint changes (pod restart,
    /// including inode-reuse cases). Set to `0` to disable. Defaults to `30`.
    pub mesh_node_waypoint_cgroup_sweep_interval_secs: u64,
    /// Node-waypoint lazy identity GC interval (seconds). Identities enrolled
    /// without a cgroup binding are evicted when no live cookie record and no
    /// open connection still references the pod. Set to `0` to disable.
    /// Defaults to `30`.
    pub mesh_node_waypoint_idle_gc_interval_secs: u64,
    /// Directory where the node-agent publishes the enrolled-pod registry (one
    /// file per pod, name=pod_uid, contents=cgroup path) for the mesh proxy's
    /// in-netns capture listeners to consume.
    pub mesh_node_waypoint_pod_registry_dir: String,
    /// Seconds to wait after a backend client SVID rotation before force-draining
    /// old-generation backend pool entries. 0 leaves existing connections to
    /// expire naturally.
    pub mesh_svid_rotation_drain_seconds: u64,
    /// Ring capacity of the in-memory `mesh_authz` deny recorder consumed by
    /// `GET /mesh/policy-denies/recent`. Each entry is ~200–400 bytes. The
    /// recorder is exception-path only (touched only on a deny) and bounded
    /// FIFO: oldest evicted first. `0` disables the recorder entirely (the
    /// admin endpoint still returns an empty grouped array with
    /// `total_denies: 0`). Default `10000`.
    pub mesh_policy_deny_log_capacity: usize,

    // Node agent
    /// Node-agent capture topology between the per-node capture manager and
    /// proxy. `local_pod` redirects to a co-located pod proxy;
    /// `node_waypoint` reserves the Phase 2 node-waypoint contract surface.
    pub node_agent_proxy_mode: NodeAgentProxyMode,
    /// Opt in to the node-agent read-only admin listener. Default false so
    /// node-agent upgrades do not expose unauthenticated admin endpoints on
    /// the global admin bind address by accident.
    pub node_agent_admin_enabled: bool,
    /// HBONE redirect/listener port included in the node-agent capture
    /// contract and BPF config map. Default: 15008.
    pub node_agent_hbone_redirect_port: u16,
    /// Opt in to the node-agent CNI plugin lifecycle hook. When `true`, the
    /// node-agent listens on `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` for ADD /
    /// DEL / CHECK calls forwarded by the `ferrum-cni` binary that the
    /// Helm install drops into `/opt/cni/bin/`. Default `false` so existing
    /// operators with a working install do not change behavior on upgrade;
    /// the kube-rs pod watcher remains the source of truth for enrollment
    /// regardless of this flag — CNI is an optimization, not a hard
    /// dependency.
    pub node_agent_cni_enabled: bool,
    /// Path the node-agent listens on for the CNI plugin RPC. Default
    /// `/var/run/ferrum/node-agent-cni.sock` — a sibling of the existing
    /// `DEFAULT_NODE_AGENT_SOCKET_PATH` so the two surfaces don't collide.
    /// Only consulted when `node_agent_cni_enabled` is `true`.
    pub node_agent_cni_socket_path: String,

    // Kubernetes CRD controller (Layer 8)
    /// Enable the Kubernetes CRD controller in CP mode. When true, the CP
    /// watches Istio and Gateway API CRDs and reconciles them into Ferrum
    /// config via `translate_k8s_objects()`. Default: false.
    pub k8s_controller_enabled: bool,
    /// Enable core Kubernetes Pod/Service/EndpointSlice discovery. Default:
    /// false for one release; when true, CP also watches core resources and
    /// derives mesh services/workloads from ready pods.
    pub k8s_pod_discovery_enabled: bool,
    /// Namespace where the Ferrum K8s controller and ambient NodeWaypoint
    /// DaemonSet are installed. Defaults to `FERRUM_NAMESPACE`; Helm sets it
    /// to `.Release.Namespace` so managed workload namespace overrides do not
    /// break trusted NodeWaypoint discovery.
    pub k8s_controller_namespace: String,
    /// Enable cluster-scoped Node watching to enrich auto-discovered pod
    /// workloads with topology.kubernetes.io/{region,zone}. Requires
    /// `FERRUM_K8S_POD_DISCOVERY_ENABLED=true` and Node RBAC. Default: false.
    pub k8s_node_locality_enabled: bool,
    /// Comma-separated namespaces to watch for CRDs. Empty = all namespaces
    /// (requires ClusterRole). Default: "" (all).
    pub k8s_watch_namespaces: Vec<String>,
    /// Override kubeconfig path for out-of-cluster development. Empty = use
    /// in-cluster config or infer from `~/.kube/config`.
    pub k8s_kubeconfig_path: Option<String>,
    /// Debounce window in milliseconds for CRD event coalescing. Events
    /// arriving within this window are batched into a single reconciliation.
    /// Default: 500.
    pub k8s_reconcile_debounce_ms: u64,
    /// Periodic full re-list interval in seconds. Safety valve against missed
    /// watch events. Default: 300 (5 minutes).
    pub k8s_full_sync_interval_secs: u64,
    /// Enable watching Istio CRDs (security.istio.io, networking.istio.io,
    /// telemetry.istio.io). Default: true.
    pub k8s_watch_istio_crds: bool,
    /// Enable watching the root-namespace `istio` ConfigMap for
    /// `meshConfig.extensionProviders` / `defaultProviders.tracing` lookup.
    /// Requires `configmaps` `get/list/watch` RBAC in the istio root
    /// namespace. When `false`, Telemetry name-only provider references
    /// resolve as unknown and inline-provider Telemetry continues to work.
    /// Default: true (only effective when `FERRUM_K8S_WATCH_ISTIO_CRDS=true`).
    pub k8s_watch_mesh_config: bool,
    /// Enable watching Gateway API CRDs (gateway.networking.k8s.io).
    /// Default: true.
    pub k8s_watch_gateway_api_crds: bool,
    /// SPIFFE trust domain for K8s-sourced mesh policies. Used by
    /// `translate_k8s_objects()` when building SPIFFE IDs from K8s
    /// ServiceAccount references. Default: "cluster.local".
    pub k8s_trust_domain: String,
    /// Kubernetes cluster DNS domain for FQDN host matching in the K8s
    /// translator. Hosts like `<svc>.<ns>.svc.<cluster_domain>` are accepted.
    /// Default: "cluster.local".
    pub k8s_cluster_domain: String,
    /// Istio root namespace used by the K8s translator when resolving
    /// mesh-wide Istio resources such as root-namespace Sidecar defaults.
    /// Default: "istio-system".
    pub k8s_istio_root_namespace: String,
    /// Namespace of the routable Ferrum Gateway API data-plane Service used
    /// to gate Gateway `Programmed=True` on serving endpoint readiness.
    /// Unset preserves legacy controller-only readiness behavior.
    pub gateway_api_data_plane_service_namespace: Option<String>,
    /// Name of the routable Ferrum Gateway API data-plane Service used to
    /// gate Gateway `Programmed=True` on serving endpoint readiness.
    /// Unset preserves legacy controller-only readiness behavior.
    pub gateway_api_data_plane_service_name: Option<String>,
    /// Address published into `Gateway.status.addresses[]` for Gateway API
    /// request-path conformance clients. Unset leaves status addresses
    /// untouched.
    pub gateway_api_status_address: Option<String>,

    // DP gRPC TLS (client-side)
    /// Path to PEM CA certificate for verifying the CP server certificate.
    /// When set, the DP verifies the CP server's identity.
    pub dp_grpc_tls_ca_cert_path: Option<String>,
    /// Path to PEM client certificate for DP-to-CP mTLS authentication.
    pub dp_grpc_tls_client_cert_path: Option<String>,
    /// Path to PEM client private key for DP-to-CP mTLS authentication.
    pub dp_grpc_tls_client_key_path: Option<String>,
    /// Skip TLS certificate verification for the DP gRPC client (testing only).
    pub dp_grpc_tls_no_verify: bool,

    // Request/Response limits
    pub max_header_size_bytes: usize,
    pub max_single_header_size_bytes: usize,
    /// Maximum number of request headers allowed. 0 = unlimited.
    pub max_header_count: usize,
    pub max_request_body_size_bytes: usize,
    pub max_response_body_size_bytes: usize,
    /// Cutoff (bytes) below which response bodies with a known Content-Length
    /// are eagerly buffered into a single allocation instead of streamed
    /// frame-by-frame. For small JSON API responses the single `bytes().await`
    /// allocation is cheaper than spinning up the async coalescing adapter.
    /// SSE (`text/event-stream`) responses always stream regardless of size.
    /// 0 = disabled (always stream). Default: 65536 (64 KiB).
    pub response_buffer_cutoff_bytes: usize,
    /// Target chunk size (bytes) for HTTP/2 response body coalescing.
    /// The `CoalescingH2Body` adapter accumulates small HTTP/2 DATA frames into
    /// chunks of at least this size before forwarding to the client, reducing
    /// per-frame overhead on gRPC and HTTP/2 direct pool paths.
    /// Default: 131072 (128 KiB). Minimum: 16384 (16 KiB). Maximum: 1048576 (1 MiB).
    pub h2_coalesce_target_bytes: usize,
    /// Maximum URL length in bytes (path + query string). 0 = unlimited.
    pub max_url_length_bytes: usize,
    /// Maximum number of query parameters allowed. 0 = unlimited.
    pub max_query_params: usize,
    /// Maximum total received gRPC payload size in bytes. For unary RPCs this is
    /// effectively a per-message limit (plus 5 bytes of gRPC framing). For streaming
    /// RPCs this caps the cumulative body size across all messages. 0 = unlimited.
    pub max_grpc_recv_size_bytes: usize,
    /// Maximum WebSocket frame size in bytes. Applied to both client and backend connections.
    pub max_websocket_frame_size_bytes: usize,
    /// WebSocket write buffer size in bytes. Controls how much data is buffered
    /// before flushing to the underlying transport. Larger values reduce syscalls
    /// for large WS frames but increase per-connection memory. The default (128 KB)
    /// is optimal for 10KB-100KB payloads. Increase to 4 MB+ for workloads with
    /// large WS frames (1 MB+). Only applies when frame-level plugins are active;
    /// tunnel mode uses raw copy_bidirectional which bypasses tungstenite entirely.
    pub websocket_write_buffer_size: usize,
    /// When true AND no frame-level plugins are configured on a proxy, bypass
    /// WebSocket frame parsing entirely and use raw TCP bidirectional copy after
    /// the upgrade handshake. This avoids per-frame header parsing, masking
    /// validation, and opcode dispatch — critical for large frames (9 MB+).
    ///
    /// Trade-offs when enabled:
    /// - `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` is NOT enforced (data streams
    ///   through a fixed-size copy buffer, so no large allocation risk)
    /// - Server-push protocols that send frames piggybacked with the HTTP 101
    ///   response may lose the first frame (rare in practice)
    ///
    /// Default: false (safe, frame-parsed path for all connections)
    pub websocket_tunnel_mode: bool,
    /// Global default WebSocket relay idle timeout in seconds. When non-zero, an
    /// upgraded session is closed if neither side produces data (frames, including
    /// Ping/Pong, or transport bytes) for this duration. Activity from EITHER
    /// direction refreshes the shared watermark, so heartbeating clients stay
    /// open. The per-proxy `websocket_idle_timeout_seconds` overrides this.
    /// `0` = disabled (idle sessions live forever, bounded only by
    /// `websocket_max_connections`). Default: 300 (5 minutes).
    ///
    /// HTTP/3 caveat: on QUIC frontends the transport-level connection idle
    /// timeout (`FERRUM_HTTP3_IDLE_TIMEOUT`, default 30s) can close an
    /// otherwise-idle H3 connection before a longer WebSocket idle timer fires.
    /// Multiplexed H3 connections with other active streams may stay open. Raise
    /// `FERRUM_HTTP3_IDLE_TIMEOUT` when isolated H3 WebSockets need a longer
    /// idle window.
    pub websocket_idle_timeout_seconds: u64,
    /// Maximum number of credential entries per type per consumer (for zero-downtime rotation).
    pub max_credentials_per_type: usize,
    /// HTTP/1.1 header read timeout in seconds. Protects against slowloris attacks
    /// by closing connections that take too long to send complete request headers.
    /// 0 = disabled (no timeout). Default: 10 seconds.
    pub http_header_read_timeout_seconds: u64,
    /// Frontend TLS handshake timeout in seconds. Applies before HTTP header
    /// parsing, so slow TLS handshakes cannot hold connection slots forever.
    /// 0 = disabled (no timeout). Default: 10 seconds.
    pub frontend_tls_handshake_timeout_seconds: u64,

    // DNS
    pub dns_overrides: HashMap<String, String>,
    /// Comma-separated nameserver addresses (ip[:port], IPv4 or IPv6).
    /// Default: parsed from /etc/resolv.conf
    pub dns_resolver_address: Option<String>,
    /// Path to hosts file. Default: /etc/hosts (system default)
    pub dns_resolver_hosts_file: Option<String>,
    /// Order of record types to query (comma-separated, case-insensitive).
    /// Valid values: CACHE, SRV, A, AAAA, CNAME. Default: "CACHE,SRV,A,CNAME"
    pub dns_order: Option<String>,
    /// Global TTL override (seconds) for positive DNS records. When set, ALL
    /// records use this TTL regardless of their native DNS TTL. Default: None
    /// (disabled — the cache respects each record's native TTL).
    pub dns_ttl_override: Option<u64>,
    /// Minimum TTL floor (seconds) for cached DNS records. Prevents 0-TTL or
    /// very short TTLs from causing excessive DNS queries. Default: 5
    pub dns_min_ttl: u64,
    /// Stale data usage time (seconds) during refresh. Default: 3600
    pub dns_stale_ttl: u64,
    /// TTL (seconds) for errors/empty responses. Default: 5
    pub dns_error_ttl: u64,
    /// Maximum number of entries in the DNS cache. Default: 10000
    pub dns_cache_max_size: usize,
    /// Maximum number of concurrent DNS warmup resolutions. Default: 500.
    pub dns_warmup_concurrency: usize,
    /// Threshold in milliseconds above which DNS resolutions are logged as slow. Default: disabled
    pub dns_slow_threshold_ms: Option<u64>,
    /// Percentage of TTL elapsed before background refresh triggers (1-99). Default: 90
    pub dns_refresh_threshold_percent: u8,
    /// Interval (seconds) for the background task that retries failed DNS lookups.
    /// Default: 10. Set to 0 to disable.
    pub dns_failed_retry_interval: u64,
    /// Retry DNS queries over TCP when UDP responses are truncated or fail. Default: true.
    pub dns_try_tcp_on_error: bool,
    /// Number of nameservers to query concurrently per lookup. Default: 3.
    pub dns_num_concurrent_reqs: usize,
    /// Maximum in-flight queries per multiplexed connection. Default: 512.
    pub dns_max_active_requests: usize,
    /// Maximum number of concurrent stale-while-revalidate background refresh
    /// tasks system-wide. Prevents unbounded task spawning under DNS storms.
    /// Default: 64.
    pub dns_max_concurrent_refreshes: usize,

    /// Path to a PEM file containing trusted CA certificates for outbound TLS verification.
    /// Used by backend proxy connections, service discovery, and plugin HTTP calls.
    pub tls_ca_bundle_path: Option<String>,
    /// Path to a PEM file containing the client certificate for backend TLS verification
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM file containing the client key for backend TLS verification
    pub backend_tls_client_key_path: Option<String>,
    /// Leaf-first PEM X.509-SVID certificate chain for gateway-to-mesh identity.
    pub gateway_svid_cert_path: Option<String>,
    /// PKCS#8 private key for `gateway_svid_cert_path`.
    pub gateway_svid_key_path: Option<String>,
    /// PEM trust bundle for gateway-to-mesh SPIFFE peer verification.
    pub gateway_svid_trust_bundle_path: Option<String>,
    /// Explicit SPIFFE ID fallback when the SVID certificate lacks a URI SAN.
    pub gateway_spiffe_id: Option<String>,
    /// Path to a PEM file containing trusted CA certificates for client certificate verification
    pub frontend_tls_client_ca_bundle_path: Option<String>,
    /// DER OCSP response bytes, or a source URI resolving to DER bytes, to
    /// staple on admin API TLS handshakes.
    pub admin_tls_ocsp_response_source: Option<String>,

    /// Admin API TLS client CA bundle for mTLS verification
    pub admin_tls_client_ca_bundle_path: Option<String>,
    /// Disable outbound TLS certificate verification for all outbound connections
    /// (backend proxy, service discovery, plugin HTTP calls). For testing only.
    pub tls_no_verify: bool,
    /// Admin API read-only mode (default: false, always true in DP mode)
    pub admin_read_only: bool,
    /// Enable database-backed Admin API mutation audit events. Default: false.
    pub admin_audit_enabled: bool,
    /// Optional age-based audit retention in days (`FERRUM_AUDIT_RETENTION_DAYS`).
    /// Unset disables age prune. When set, must be in `1..=36_500`. Distinct from
    /// audit delivery-loss hardening (#2421): this only bounds retained rows.
    pub audit_retention_days: Option<u64>,
    /// Per-namespace audit row cap (`FERRUM_AUDIT_RETENTION_MAX_ROWS`).
    /// Defaults to 100,000. Set to `0` to disable the row cap (retain audit rows
    /// indefinitely by count). Non-zero values must be in `1..=10_000_000`.
    /// Newest events win under deterministic `(ts, id)` ordering.
    pub audit_retention_max_rows: Option<u64>,
    /// Require admin JWTs to carry an `ns` claim authorizing the
    /// `X-Ferrum-Namespace` value on namespace-scoped admin routes.
    /// Mirrors `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` on the gRPC plane.
    /// Default: false (namespace header is a routing selector only).
    pub admin_require_namespace_claim: bool,
    /// Disable admin TLS certificate verification (for testing only)
    pub admin_tls_no_verify: bool,

    // HTTP/3 / QUIC
    /// Enable HTTP/3 listener (default: false)
    pub enable_http3: bool,
    /// HTTP/3 idle timeout in seconds (default: 30)
    pub http3_idle_timeout: u64,
    /// HTTP/3 max concurrent streams (default: 1000)
    pub http3_max_streams: u32,
    /// HTTP/3 per-stream receive window in bytes (default: 8 MiB).
    /// Controls how much data a peer can send on a single QUIC stream
    /// before the receiver must send a flow-control credit update.
    pub http3_stream_receive_window: u64,
    /// HTTP/3 connection-level receive window in bytes (default: 32 MiB).
    /// Aggregate budget shared across all concurrent streams on one QUIC connection.
    pub http3_receive_window: u64,
    /// HTTP/3 per-connection send window in bytes (default: 8 MiB).
    /// Controls how much data can be in flight (sent but unacknowledged)
    /// across all streams on a single QUIC connection.
    pub http3_send_window: u64,
    /// Number of QUIC connections to maintain per HTTP/3 backend (default: 4).
    /// Multiple connections distribute QUIC frame processing across driver tasks.
    pub http3_connections_per_backend: usize,
    /// HTTP/3 pool idle timeout in seconds (default: 120).
    /// Connections idle longer than this are evicted from the pool.
    pub http3_pool_idle_timeout_seconds: u64,
    /// Minimum bytes buffered before flushing a coalesced HTTP/3 DATA frame
    /// on the response streaming path (default: 32_768). Acts as the flush
    /// target — once the buffer reaches this size on chunk arrival, it is
    /// flushed. Clamped to `<= http3_coalesce_max_bytes` at parse time.
    /// Legal range: [1024, http3_coalesce_max_bytes].
    pub http3_coalesce_min_bytes: usize,
    /// Maximum bytes for the HTTP/3 response streaming coalesce buffer
    /// (default: 32_768). Used as the `BytesMut::with_capacity` initial
    /// allocation and as the upper bound that clamps `coalesce_min_bytes`
    /// at parse time. Higher values reduce reallocations for large-backend
    /// responses at the cost of per-stream memory. Legal range:
    /// [1024, 1_048_576].
    pub http3_coalesce_max_bytes: usize,
    /// Time-based flush interval on the HTTP/3 response streaming path in
    /// microseconds (default: 200). Floor: 50 µs to prevent "flush every
    /// poll" footguns. Legal range: [50, 100_000].
    pub http3_flush_interval_micros: u64,
    /// Bounded mpsc channel capacity for the H3→HTTP/HTTPS cross-protocol
    /// request-body bridge (default: 32). The bridge pushes H3 `recv_data`
    /// chunks into the channel; `reqwest::Body::wrap_stream` drains the
    /// receiver and feeds the backend TCP socket. This bounds in-flight
    /// request body memory to approximately `capacity × average_chunk_size`
    /// during a streaming cross-protocol upload (default ~32 × 16 KiB ≈
    /// 512 KiB per upload — enough pipeline depth to absorb backend jitter
    /// without starving throughput, while keeping 1 K concurrent uploads
    /// under ~500 MiB). Increase for high-bandwidth uploads where the
    /// client produces faster than the backend drains; decrease on
    /// memory-constrained hosts. Legal range: [1, 1024].
    pub http3_request_body_channel_capacity: usize,
    /// Whether the HTTP/3 listener advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`
    /// and accepts WebSocket-over-HTTP/3 Extended CONNECT requests per
    /// [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) (default: `true`).
    ///
    /// When `true`, the server signals to H3 clients that they may bootstrap a
    /// WebSocket via `:method = CONNECT` + `:protocol = "websocket"`, and the
    /// gateway bridges those streams to the backend WebSocket
    /// (HTTP/1.1 Upgrade or H2 Extended CONNECT) just like the HTTP/1.1
    /// and HTTP/2 frontends. WebSocket plugins (`on_ws_connect`,
    /// `on_ws_frame`, `on_ws_disconnect`) run unchanged.
    ///
    /// When `false`, the server does not advertise the setting and the
    /// listener returns 501 Not Implemented to any Extended CONNECT
    /// WebSocket request that still arrives. Use this to opt out of the
    /// RFC 9220 path while keeping plain HTTP/3 enabled — for instance,
    /// to constrain the attack surface of a public H3 listener until you
    /// have validated WebSocket-over-H3 in your environment.
    pub http3_websocket_enabled: bool,
    /// Milliseconds the HTTP/3 listener spends draining already-buffered
    /// request-body bytes before issuing STOP_SENDING when a
    /// small/successful response is emitted while the client is likely
    /// still uploading (default: 50). Small 2xx echo / idempotent
    /// uploads typically complete inside this window so the QUIC stream
    /// terminates via natural FIN rather than STOP_SENDING — avoiding
    /// the "stopped by peer" signal on happy-path traffic. Zero
    /// disables the drain and issues the halt immediately. Error
    /// responses (413, 502, plugin reject) always halt immediately —
    /// this setting only governs the fast-response path. Legal range:
    /// [0, 1000].
    pub h3_request_body_drain_ms: u64,
    /// Initial QUIC path MTU in bytes used to build `TransportConfig`
    /// (default: 1500). quinn's baseline of 1200 forces ~9 packets for a
    /// 10 KiB payload; 1500 is safe on modern networks and quinn backs off
    /// via black-hole detection if a smaller MTU is required. Legal range:
    /// [1200, 65527] (quinn's accepted bounds).
    pub http3_initial_mtu: u16,
    /// Milliseconds the gRPC backend pool waits on a saturated HTTP/2 sender
    /// for a free stream before opening a fresh connection (default: 1).
    /// Lower values reduce queueing for unary gRPC under load. Set to 0 to
    /// skip the wait and open a new backend connection immediately.
    pub grpc_pool_ready_wait_ms: u64,

    // Connection pool warmup
    /// Pre-establish backend connections at startup (default: true).
    /// Warms HTTP, gRPC, HTTP/2, and HTTP/3 pools after DNS warmup completes.
    /// Skipped for TCP/UDP stream proxies (no persistent connection pools).
    pub pool_warmup_enabled: bool,
    /// Maximum concurrent connection warmup attempts at startup (default: 500).
    pub pool_warmup_concurrency: usize,

    // Connection pool cleanup
    /// Interval in seconds between connection pool cleanup sweeps (default: 30).
    /// Applies to HTTP, gRPC, HTTP/2, and HTTP/3 connection pools.
    pub pool_cleanup_interval_seconds: u64,

    /// Interval in seconds between backend capability reprobes (default:
    /// 86400 = 24 hours). Startup classification runs before pool warmup;
    /// this interval controls the background refresh that re-checks HTTPS
    /// backends for HTTP/2 and HTTP/3 support and plaintext HTTP backends
    /// for h2c support outside the request hot path.
    pub backend_capability_refresh_interval_secs: u64,

    // Router cache
    /// Maximum entries in the router prefix/negative lookup cache (default: 0 = auto).
    /// When set to 0 (auto), the cache size is computed as `max(10_000, proxies × 3)`,
    /// scaling with proxy count to prevent eviction thrashing at high scale.
    /// Set an explicit value to cap memory usage on memory-constrained deployments.
    /// Minimum effective value: 1_000. Maximum: 10_000_000.
    pub router_cache_max_entries: usize,

    // TCP proxy
    /// Default TCP idle timeout in seconds (default: 300 / 5 min).
    /// Per-proxy `tcp_idle_timeout_seconds` overrides this. Set to 0 to disable.
    ///
    /// See [`Self::tcp_half_close_max_wait_seconds`] for how this interacts
    /// with the bidirectional-relay fast path.
    pub tcp_idle_timeout_seconds: u64,
    /// Hard cap on Phase 2 (half-close drain) of the TCP bidirectional relay.
    ///
    /// After one side of a TCP proxy stream finishes cleanly (EOF), the other
    /// direction is awaited so slow-response protocols (SMTP, IMAP,
    /// HTTP-over-TCP passthrough) are not truncated. Normally the session
    /// idle timeout bounds this wait, but `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0`
    /// disables idle entirely — in that case a stalled peer could wedge the
    /// Phase 2 future forever.
    ///
    /// This cap fires even when the idle timeout is disabled. Default 300
    /// (5 minutes). Set to `0` to disable.
    ///
    /// # Bidirectional-relay performance modes
    ///
    /// When **both** `tcp_idle_timeout_seconds` and
    /// `tcp_half_close_max_wait_seconds` are `0` and the selected proxy's
    /// `backend_read_timeout_ms` / `backend_write_timeout_ms` are also `0`,
    /// the relay selects a **fast path** that delegates to
    /// `tokio::io::copy_bidirectional_with_sizes` directly. Any non-zero
    /// relay timeout selects the **direction-tracking path**:
    ///
    /// | Mode | Trigger | Benefits | Downsides |
    /// |------|---------|----------|-----------|
    /// | Fast path | all four relay timeouts == 0 | no Phase 1/2 loop, max TCP throughput, per-direction bytes preserved on clean completion | no idle watchdog (OS TCP timers only), no half-close hard cap, `disconnect_direction` reported as `unknown` on error |
    /// | Direction-tracking | any relay timeout != 0 (default) | idle timeout, half-close cap, per-direction byte counts, first-failure direction attribution in logs/metrics | manual relay state machine plus watchdog timer work |
    ///
    /// Pick the fast path only when an external L4 load balancer already
    /// enforces per-connection timeouts and per-direction failure attribution
    /// is not consumed by your dashboards/alerts.
    pub tcp_half_close_max_wait_seconds: u64,

    // UDP proxy
    /// Maximum concurrent UDP sessions per proxy (default: 10000).
    pub udp_max_sessions: usize,
    /// UDP session cleanup interval in seconds (default: 10).
    pub udp_cleanup_interval_seconds: u64,
    /// Number of datagrams per `recvmmsg` syscall on Linux (default: 64).
    /// Controls how many datagrams are received in a single kernel crossing.
    /// Higher values reduce syscall overhead for high-throughput UDP proxies.
    /// Ignored on non-Linux platforms (falls back to individual `try_recv_from`).
    pub udp_recvmmsg_batch_size: usize,

    // Adaptive Buffer Sizing
    /// Enable adaptive buffer sizing for TCP/WebSocket tunnel copy buffers (default: true).
    pub adaptive_buffer_enabled: bool,
    /// Enable adaptive UDP batch limit per proxy (default: true).
    pub adaptive_batch_limit_enabled: bool,
    /// EWMA smoothing factor (1-999, fixed-point where 1000 = 1.0). Default: 300 (α = 0.3).
    pub adaptive_buffer_ewma_alpha: u64,
    /// Minimum buffer size in bytes (floor). Default: 8192 (8 KiB).
    pub adaptive_buffer_min_size: usize,
    /// Maximum buffer size in bytes (ceiling). Default: 262144 (256 KiB).
    pub adaptive_buffer_max_size: usize,
    /// Default buffer size when no data recorded yet. Default: 65536 (64 KiB).
    pub adaptive_buffer_default_size: usize,
    /// Default batch limit when no data recorded yet. Default: 6000.
    pub adaptive_batch_limit_default: usize,

    // TLS Hardening
    /// Minimum TLS version: "1.2" or "1.3" (default: "1.2")
    pub tls_min_version: String,
    /// Maximum TLS version: "1.2" or "1.3" (default: "1.3")
    pub tls_max_version: String,
    /// Comma-separated cipher suites (OpenSSL names). If empty, uses secure defaults.
    /// TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    /// TLS 1.2: ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256,
    ///          ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305,
    ///          ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384
    pub tls_cipher_suites: Option<String>,
    /// Prefer server cipher order for TLS 1.2 (default: true)
    pub tls_prefer_server_cipher_order: bool,
    /// Comma-separated ECDH curves/groups: X25519, secp256r1, secp384r1 (default: "X25519,secp256r1")
    pub tls_curves: Option<String>,
    /// TLS session resumption cache size for TLS 1.2 stateful session IDs.
    /// TLS 1.3 uses stateless tickets (unlimited). Applies to inbound listeners
    /// and outbound/backend client configs that opt into rustls session caching.
    /// (default: 4096)
    pub tls_session_cache_size: usize,
    /// Number of days before certificate expiration to emit a warning log.
    /// Expired certificates are rejected at startup/config-load time.
    /// Set to 0 to disable near-expiry warnings. (default: 30)
    pub tls_cert_expiry_warning_days: u64,
    /// Maximum age of the cached, non-secret TLS inventory snapshot that backs
    /// the `/metrics` certificate gauges. A scrape only ever reads the snapshot;
    /// when it is older than this bound the scrape schedules a single-flight
    /// background refresh (bounded, off the request path) that re-reads public
    /// certificate material only. `0` disables the background refresh entirely,
    /// leaving certificate gauges absent. (default: 300)
    pub tls_inventory_snapshot_ttl_seconds: u64,
    /// Comma-separated HTTP methods allowed to be sent as TLS 1.3 0-RTT early data.
    /// When non-empty, the gateway advertises 0-RTT support on HTTPS and HTTP/3
    /// listeners and enforces that only the listed methods are accepted as early data.
    /// Default: empty (0-RTT disabled — `max_early_data_size=0`).
    /// Example: "GET" or "GET,HEAD,OPTIONS"
    pub tls_early_data_methods: HashSet<String>,

    // Stream proxy (TCP/UDP)
    /// Bind address for TCP/UDP stream proxy listeners (default: 0.0.0.0).
    #[allow(dead_code)] // Used in Phase 2 (stream listener startup)
    pub stream_proxy_bind_address: String,

    // DTLS frontend certificates (ECDSA P-256 or P-384 required)
    /// Path to DTLS server certificate (PEM) for frontend DTLS termination.
    /// If not set, a self-signed ECDSA P-256 certificate is generated at startup.
    pub dtls_cert_path: Option<String>,
    /// Path to DTLS server private key (PEM) for frontend DTLS termination.
    pub dtls_key_path: Option<String>,
    /// Path to CA certificate (PEM) for verifying DTLS client certificates (mTLS).
    /// When set, the gateway requires and verifies client certificates for frontend
    /// DTLS connections using this trust store. Separate from the TLS client CA used
    /// for TCP frontend mTLS (`FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`).
    pub dtls_client_ca_cert_path: Option<String>,
    /// Maximum plaintext payload bytes per DTLS record. Datagrams exceeding this are
    /// dropped with a warning. Default: 16384 (2^14, per RFC 9147 §4.1). Increase only
    /// if your UDP application sends datagrams larger than 16 KB over DTLS.
    pub dtls_max_plaintext_bytes: usize,
    /// DTLS record overhead bytes (header + auth tag). Default: 64. The output buffer
    /// per DTLS session is `dtls_max_plaintext_bytes + dtls_record_overhead_bytes`.
    pub dtls_record_overhead_bytes: usize,

    // Client IP resolution
    /// Comma-separated trusted proxy CIDRs/IPs for X-Forwarded-For resolution.
    /// When set, the gateway walks the XFF chain right-to-left, skipping trusted
    /// proxy IPs, to determine the real client IP. When unset, the TCP socket
    /// address is always used (secure default for edge deployments).
    /// Example: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1"
    pub trusted_proxies: String,
    /// Resolved backend egress policy for SSRF protection: the
    /// `FERRUM_BACKEND_ALLOW_IPS` mode (`private`/`public`/`both`) composed with
    /// `FERRUM_BACKEND_ALLOW_CIDRS`, `FERRUM_BACKEND_DENY_CIDRS`, and the
    /// dangerous-range baseline (`FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES`, on by
    /// default). See [`BackendEgressPolicy`]. The field name is retained for
    /// continuity with the many carriers that thread it through.
    pub backend_allow_ips: BackendEgressPolicy,
    /// When true, add a Via header on both request and response paths per RFC 9110 §7.6.3.
    pub add_via_header: bool,
    /// Pseudonym used in the Via header. Defaults to "ferrum-edge".
    pub via_pseudonym: String,
    /// When true, add a Forwarded header (RFC 7239) alongside X-Forwarded-* headers.
    pub add_forwarded_header: bool,
    /// Header to use as the authoritative source of client IP. When set, this
    /// header is checked first (e.g., "CF-Connecting-IP" for Cloudflare,
    /// "X-Real-IP" for nginx, or CloudFront's "CloudFront-Viewer-Address"
    /// ip:source-port value). If the configured header is absent, falls back to
    /// the X-Forwarded-For walk. If it is present but rejected, the socket IP
    /// remains the source of truth.
    pub real_ip_header: Option<String>,

    /// HMAC-SHA256 server secret for the basic_auth plugin. Mandatory when that
    /// plugin is enabled; must be a unique random value of at least 32 bytes.
    /// There is no default. Rotating it invalidates all existing Basic-auth
    /// password hashes.
    /// Note: Also resolved via `resolve_ferrum_var()` in `basic_auth.rs` and
    /// `admin/mod.rs` for use sites that don't have `EnvConfig` in scope.
    #[allow(dead_code)]
    pub basic_auth_hmac_secret: Option<String>,

    /// Threshold in milliseconds for logging slow plugin outbound HTTP calls.
    /// When a plugin HTTP request (e.g. http_logging, JWKS fetch,
    /// OIDC discovery, OTLP export) exceeds this duration, a warning is logged.
    /// Default: 1000 (1 second).
    pub plugin_http_slow_threshold_ms: u64,
    /// Maximum retry attempts for safe/idempotent plugin outbound HTTP calls
    /// when the failure is transport-level (connection refused/reset/closed,
    /// connect timeout, DNS lookup failure). Default: 0 (disabled).
    pub plugin_http_max_retries: u32,
    /// Delay in milliseconds between automatic plugin outbound HTTP retries.
    /// Default: 100.
    pub plugin_http_retry_delay_ms: u64,

    /// Path to a PEM file containing Certificate Revocation Lists (CRLs).
    /// When set, all TLS/DTLS surfaces (frontend mTLS, backend verification, gRPC, WebSocket)
    /// will reject certificates listed in the CRL. Supports multiple CRLs in one file.
    /// Uses `-----BEGIN X509 CRL-----` PEM blocks.
    pub tls_crl_file_path: Option<String>,
    /// Comma-separated CIDRs/IPs allowed to connect to the admin API.
    /// When empty (default), all IPs are permitted. When set, connections from
    /// non-matching IPs are rejected at the TCP level before any request processing.
    /// Example: "10.0.100.0/24,10.0.200.5,::1"
    pub admin_allowed_cidrs: String,

    /// Comma-separated CIDRs/IPs allowed to scrape `/metrics` (and the detailed
    /// `/health` / `/overload` views) WITHOUT a JWT or metrics bearer token.
    /// Empty (default) means unauthenticated scraping is disabled — `/metrics`
    /// returns 401 unless the caller presents a valid admin JWT or
    /// `FERRUM_METRICS_BEARER_TOKEN`. Set this to opt the listed source ranges
    /// (e.g. a Prometheus subnet) back into unauthenticated scraping.
    /// Example: "10.0.0.0/8,127.0.0.1,::1"
    pub metrics_allowed_cidrs: String,

    /// Dedicated bearer token that authorizes `/metrics` scraping (and the
    /// detailed `/health` / `/overload` views) without a full admin JWT.
    /// When set, a request whose `Authorization: Bearer <token>` matches this
    /// value (constant-time compare) is allowed. Empty/unset disables this path.
    /// Use this for Prometheus deployments that cannot mint admin JWTs.
    pub metrics_bearer_token: Option<String>,

    /// Maximum concurrent connections across all admin/management-plane
    /// listeners (plaintext + TLS share one cap). Independent of the data-plane
    /// `max_connections` (`FERRUM_MAX_CONNECTIONS`) so proxy traffic and
    /// management traffic can be sized separately. Enforced after the admin CIDR
    /// allowlist and before the TLS handshake / request parsing; over-limit
    /// connections are dropped (TCP RST). Default: 1024. Set to 0 to disable.
    pub admin_max_connections: usize,
    /// Maximum concurrent admin connections per resolved source IP. Default: 0
    /// (disabled) so a single monitoring/load-balancer source IP is not capped
    /// by accident. When set, over-limit connections from that IP are dropped.
    pub admin_max_connections_per_ip: usize,

    /// Max request body size in MiB for POST /restore (large config backups).
    /// Default: 100 MiB.
    pub admin_restore_max_body_size_mib: usize,

    /// Max request body size in MiB for POST/PUT /api-specs.
    /// Default: 25 MiB.
    pub admin_spec_max_body_size_mib: usize,

    /// Absolute deadline (seconds) for reading a **1 MiB** admin request body,
    /// applied to every admin body-collecting handler including the API-spec
    /// ones. A size cap alone does not bound *time*: a client that trickles one
    /// byte per interval pins a task and its buffer indefinitely, and over
    /// HTTP/2 a single connection can multiplex many such streams.
    ///
    /// Routes with a larger size cap scale the deadline by that cap, so the
    /// bound is one shared minimum throughput rather than a flat wall clock
    /// that would demand 25x/100x the upload rate from `POST`/`PUT /api-specs`
    /// (`FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB`) and `POST /restore`
    /// (`FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB`). At the defaults that is
    /// 30 s for 1 MiB, 750 s for a 25 MiB spec, and 3000 s for a 100 MiB
    /// restore. `0` disables the deadline on every route (bodies are then
    /// bounded only by size). Default: 30 seconds.
    pub admin_body_read_timeout_seconds: u64,

    /// Server-advertised `SETTINGS_MAX_CONCURRENT_STREAMS` for admin HTTP/2
    /// connections (TLS via ALPN `h2`, plaintext via h2c prior knowledge).
    /// Bounds how many requests one admin connection can multiplex, so the
    /// admin connection cap (`FERRUM_ADMIN_MAX_CONNECTIONS`) also bounds the
    /// number of retained request tasks/buffers. Default: 64.
    pub admin_http2_max_concurrent_streams: u32,

    /// Server-advertised `SETTINGS_MAX_HEADER_LIST_SIZE` for admin HTTP/2
    /// connections. Bounds the header block a single stream may accumulate
    /// across `HEADERS` + `CONTINUATION` frames before the peer is reset, which
    /// is the HTTP/2 analogue of the HTTP/1.1 header-read bound. Admin requests
    /// carry only a bearer token and a few small headers. Clamped to a 1 KiB
    /// floor so a misconfiguration cannot lock out ordinary JWTs.
    /// Default: 65536 (64 KiB).
    pub admin_http2_max_header_list_size_bytes: u32,

    /// Migration action: up, status, config (migrate mode only).
    /// Default: "up".
    pub migrate_action: String,

    /// When true, migration commands preview changes without applying.
    /// Default: false.
    pub migrate_dry_run: bool,

    /// When true, automatically apply pending custom-plugin database
    /// migrations at gateway startup in `database` and `cp` modes.
    ///
    /// Default: `false` (opt-in). Most operators expect schema changes to
    /// only run via an explicit `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up`
    /// step, so the gateway never silently mutates the database. When this
    /// flag is `false` and pending plugin migrations exist, the gateway
    /// emits a `warn!` listing them so the operator knows to run the
    /// migration command before serving traffic that depends on the new
    /// schema.
    ///
    /// Set to `true` for environments where a single binary upgrade should
    /// also apply bundled custom-plugin schema changes (e.g. embedded
    /// SQLite deployments where the binary owns the database).
    pub auto_apply_plugin_migrations: bool,

    // ── Runtime & listener tuning ────────────────────────────────────────
    /// Number of tokio worker threads. Default: number of CPU cores.
    pub worker_threads: Option<usize>,
    /// Maximum number of tokio blocking threads. Default: 512 (tokio default).
    pub blocking_threads: Option<usize>,
    /// Maximum concurrent connections the proxy will accept.
    /// Default: 100000. When the limit is reached, new connections queue
    /// until a slot frees up. Set to 0 to disable the limit entirely.
    pub max_connections: usize,
    /// Maximum concurrent in-flight requests (global, all protocols).
    /// Tracks HTTP/1.1 requests, HTTP/2 streams, HTTP/3 streams, and gRPC
    /// requests independently of the connection limit. Default: 0 (unlimited).
    /// When exceeded, new requests receive 503 Service Unavailable.
    pub max_requests: usize,
    /// Maximum concurrent proxy requests per resolved client IP.
    /// Uses the same client IP resolution as trusted proxy XFF walk.
    /// Default: 0 (disabled). When exceeded, returns 429 Too Many Requests.
    pub max_concurrent_requests_per_ip: u64,
    /// Interval in seconds between cleanup sweeps for per-IP request counters.
    /// Removes entries where the active request count has dropped to zero.
    /// Only relevant when `max_concurrent_requests_per_ip > 0`. Default: 60.
    pub per_ip_cleanup_interval_seconds: u64,
    /// Maximum entries in the circuit breaker cache. Entries are keyed by
    /// proxy_id::host:port. Stale entries from removed upstream targets are
    /// pruned during config reload. This cap prevents unbounded growth from
    /// target churn in dynamic environments (e.g., Kubernetes pod cycling).
    /// Default: 10000.
    pub circuit_breaker_cache_max_entries: usize,
    /// DashMap shard count for hot pool/cache maps (HTTP/H2/gRPC connection
    /// pools, DNS cache, per-IP request counters, TCP connection-throttle
    /// counters, router prefix/regex caches, response_caching
    /// cache/Vary-index/predictor maps, and shared local/Redis-fallback
    /// rate-limiter token-state maps). DashMap defaults to `4 * num_cpus`,
    /// which is fine for small maps but starves on write contention at high
    /// cardinality (1K+ unique pool keys, distinct DNS hosts, distinct
    /// client IPs). Higher shard counts give concurrent inserts more
    /// independent locks.
    ///
    /// Resolution: `0` (default) auto-derives `next_power_of_two(max(64,
    /// num_cpus * 16))` — 64 on small dev hosts, 256 on a 16-core box,
    /// 1024 on a 64-core box. Any positive value is rounded up to the
    /// next power of two (DashMap's API requires power-of-two shard counts).
    /// Default: 0.
    pub pool_shard_amount: usize,
    /// Maximum entries in the HTTP status code counters map. Common codes
    /// (200, 404, 500, etc.) are pre-populated at startup. Rare/exotic codes
    /// create entries on first occurrence up to this cap. Prevents unbounded
    /// growth from adversarial backends returning many distinct status codes.
    /// Default: 200.
    pub status_counts_max_entries: usize,
    /// Interval for the `/metrics/runtime` process/system sampler. Default: 1000.
    pub runtime_metrics_system_sample_interval_ms: u64,
    /// Runtime metrics status-rate window. Default: 60.
    pub runtime_metrics_window_1m_seconds: u64,
    /// Runtime metrics status-rate window. Default: 300.
    pub runtime_metrics_window_5m_seconds: u64,
    /// Count Ferrum tracing warn/error/etc. events by bounded category. Default: true.
    pub runtime_metrics_log_counter_enabled: bool,
    /// Admin `/metrics/runtime` JSON response cache TTL. Default: 1000.
    pub runtime_metrics_cache_ttl_ms: u64,
    /// Count backend pool creation/failure/eviction churn. Default: true.
    pub runtime_metrics_pool_tracking_enabled: bool,
    /// Count extra `/metrics/runtime` HTTP status windows. Default: true.
    pub runtime_metrics_status_tracking_enabled: bool,
    /// TCP listen backlog size for proxy listeners. Default: 2048.
    /// Higher values absorb connection bursts without SYN drops.
    pub tcp_listen_backlog: u32,
    /// Number of parallel accept() loops per proxy listener port. Each loop binds
    /// its own socket to the same address via SO_REUSEPORT, giving the kernel
    /// separate accept queues to distribute SYN processing across — eliminating
    /// the single socket lock bottleneck at high connection rates (50K+ new
    /// conn/sec). This is orthogonal to `FERRUM_WORKER_THREADS` which controls
    /// the tokio runtime thread pool for all async work; `accept_threads`
    /// specifically parallelizes connection intake at the kernel level.
    /// Default: 0 (auto-detect = available CPU cores). Set to 1 to disable
    /// multi-listener. Only effective on Unix with SO_REUSEPORT (Linux 3.9+,
    /// macOS, BSDs).
    pub accept_threads: usize,
    /// Frontend HTTP/2 per-stream flow-control window (bytes).
    /// Conservative default for untrusted clients; raise for benchmarking.
    /// Clamped to 65535..128 MiB. Default: 256 KiB.
    pub frontend_h2_initial_stream_window_size: u32,
    /// Frontend HTTP/2 connection-level flow-control window (bytes).
    /// Conservative default for untrusted clients; raise for benchmarking.
    /// Clamped to 65535..128 MiB. Default: 2 MiB.
    pub frontend_h2_initial_connection_window_size: u32,
    /// Frontend HTTP/2 max frame size (bytes).
    /// Clamped to 16384..1 MiB (RFC 9113 range). Default: 16384.
    pub frontend_h2_max_frame_size: u32,
    /// Server-side HTTP/2 max concurrent streams per inbound connection.
    /// Limits how many requests a single HTTP/2 client can multiplex.
    /// Default: 1000 (nginx=128, envoy=100, unlimited by spec).
    pub server_http2_max_concurrent_streams: u32,
    /// Server-side HTTP/2 max pending accept-reset streams per connection.
    /// When exceeded, the server sends GOAWAY to mitigate rapid-reset abuse.
    /// Default: 64.
    pub server_http2_max_pending_accept_reset_streams: usize,
    /// Server-side HTTP/2 max locally reset streams per connection.
    /// When exceeded, the server sends GOAWAY to bound repeated local reset churn.
    /// Default: 256.
    pub server_http2_max_local_error_reset_streams: usize,
    /// Maximum concurrently upgraded WebSocket connections.
    /// Default: 20_000. Set to 0 to disable the dedicated WebSocket cap and
    /// rely only on the global connection limit.
    pub websocket_max_connections: usize,

    // ── Overload management ──────────────────────────────────────────────
    /// How often the overload monitor checks resource pressure in milliseconds.
    /// Default: 1000 (1 second).
    pub overload_check_interval_ms: u64,
    /// FD usage ratio above which keepalive is disabled. Default: 0.80 (80%).
    pub overload_fd_pressure_threshold: f64,
    /// FD usage ratio above which new connections are rejected. Default: 0.95 (95%).
    pub overload_fd_critical_threshold: f64,
    /// Connection semaphore usage ratio above which keepalive is disabled. Default: 0.85 (85%).
    pub overload_conn_pressure_threshold: f64,
    /// Connection semaphore usage ratio above which new connections are rejected. Default: 0.95 (95%).
    pub overload_conn_critical_threshold: f64,
    /// Request usage ratio above which keepalive is disabled. Default: 0.85 (85%).
    /// Only relevant when `max_requests > 0`.
    pub overload_req_pressure_threshold: f64,
    /// Request usage ratio above which new requests are rejected with 503. Default: 0.95 (95%).
    /// Only relevant when `max_requests > 0`.
    pub overload_req_critical_threshold: f64,
    /// Event loop latency in microseconds above which a warning is logged. Default: 10000 (10ms).
    pub overload_loop_warn_us: u64,
    /// Event loop latency in microseconds above which new connections are rejected. Default: 500000 (500ms).
    pub overload_loop_critical_us: u64,

    // ── Graceful shutdown ────────────────────────────────────────────────
    /// Seconds to wait for in-flight connections to drain on shutdown.
    /// During the drain period, the gateway stops accepting new connections,
    /// sets `Connection: close` on responses, and waits for existing requests
    /// to complete. Default: 30. Set to 0 to skip draining (immediate shutdown).
    pub shutdown_drain_seconds: u64,

    // ── Admin status metrics ─────────────────────────────────────────────
    /// Window size in seconds for computing per-second rate metrics on the
    /// admin `/status` endpoint.  A background task snapshots cumulative
    /// counters every N seconds and computes average rates.  Minimum: 1.
    pub status_metrics_window_seconds: u64,

    // ── TLS handshake offload ───────────────────────────────────────────
    /// Total dedicated threads for offloading TLS handshakes from the main
    /// event loop. 0 = disabled (handshakes run on tokio worker threads).
    /// When enabled, threads are organized into shards for TLS session cache
    /// affinity. Default: 0 (disabled).
    pub tls_offload_threads: usize,

    // ── TCP socket optimizations (Linux only) ────────────────────────────
    /// Enable TCP Fast Open on server (listening) and client (connecting) sockets.
    /// Saves 1 RTT on repeat connections by allowing data in the SYN packet.
    /// Requires Linux 4.11+ and `net.ipv4.tcp_fastopen` sysctl bit 0x1 (server)
    /// or 0x2 (client) enabled. No-op on non-Linux.
    /// Values: `auto` (check sysctl at startup), `true` (force on), `false` (force off).
    /// Default: `auto`.
    pub tcp_fastopen_enabled: AutoBool,
    /// TCP Fast Open server queue length — maximum pending TFO connections.
    /// Only used when `tcp_fastopen_enabled` is true. Default: 256.
    pub tcp_fastopen_queue_len: u16,

    // ── Stream proxy performance optimizations (Linux only) ─────────────
    /// Enable kTLS (kernel TLS) probing/gating on TCP proxy TLS paths (Linux 4.13+).
    /// Startup still probes kernel ULP + dummy key install when `auto`/`true`.
    /// Handoff from the buffered tokio-rustls accept path is currently refuse-closed
    /// (issue #2955): the public buffered rustls API cannot prove inbound deframer
    /// emptiness, so frontend-TLS connections retain the userspace relay.
    /// Values: `auto` (detect kernel support), `true` (force on), `false` (force off).
    /// Default: `auto`.
    pub ktls_enabled: AutoBool,
    /// Enable io_uring-based splice for TCP proxy zero-copy relay (Linux 5.6+ only).
    /// Uses IORING_OP_SPLICE submission queue entries instead of direct libc splice
    /// syscalls. Falls back to libc splice if io_uring is unavailable.
    /// Values: `auto` (detect kernel support), `true` (force on), `false` (force off).
    /// Default: `auto`.
    pub io_uring_splice_enabled: AutoBool,
    /// Enable UDP GRO (Generic Receive Offload) on frontend UDP sockets (Linux 5.0+).
    /// Kernel coalesces multiple same-size UDP datagrams into a single large buffer,
    /// more efficient than recvmmsg.
    /// Values: `auto` (probe setsockopt on temp socket), `true`, `false`.
    /// Default: `auto`.
    pub udp_gro_enabled: AutoBool,
    /// Enable UDP GSO (Generic Segmentation Offload) for batched UDP sending (Linux 4.18+).
    /// Sends multiple datagrams in a single sendmsg() by specifying a segment size via
    /// ancillary data. The kernel splits them at the NIC level.
    /// Values: `auto` (probe sendmsg with UDP_SEGMENT on temp socket), `true`, `false`.
    /// Default: `auto`.
    pub udp_gso_enabled: AutoBool,
    /// Enable IP_PKTINFO / IPV6_PKTINFO on frontend UDP sockets (Linux only).
    /// Captures the per-datagram local destination address on recv and reuses
    /// it as the reply source on send, so the kernel skips the routing-table
    /// lookup. Complements UDP_SEGMENT (GSO) — both cmsgs ride in one sendmsg.
    /// Values: `auto` (probe setsockopt on temp socket), `true`, `false`.
    /// Default: `auto`.
    pub udp_pktinfo_enabled: AutoBool,
    /// SO_BUSY_POLL duration in microseconds for latency-sensitive UDP sockets (Linux 3.11+).
    /// When > 0, the kernel spins for this many microseconds waiting for incoming data
    /// before sleeping. Reduces receive latency at the cost of CPU. 0 = disabled. Default: 0.
    pub so_busy_poll_us: u32,
}

/// Network-exposure classification of the gateway's **plaintext** admin HTTP
/// listener (`FERRUM_ADMIN_HTTP_PORT`).
///
/// Used to gate startup (writable `database`/`cp` modes hard-fail on
/// [`AdminHttpExposure::ReachableUnrestricted`] unless
/// `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true`) and to emit graded startup
/// warnings. The admin HTTPS listener is a separate port and does not affect
/// this classification — to serve admin TLS-only, disable plaintext with
/// `FERRUM_ADMIN_HTTP_PORT=0`.
///
/// The safe boundary is **loopback only**. A private / VPC / link-local
/// address (e.g. a pod or VM interface IP) is still reachable by other hosts on
/// that network, so it is treated as exposed — binding the writable admin there
/// in cleartext without an allowlist is a guarded posture, not a safe one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminHttpExposure {
    /// `FERRUM_ADMIN_HTTP_PORT=0` — no plaintext admin listener.
    Disabled,
    /// Bound to a loopback address (`127.0.0.0/8`, `::1`) — reachable only from
    /// within the host/network namespace.
    Loopback,
    /// Bound to a non-loopback address reachable beyond the host (incl.
    /// `0.0.0.0` / `::`, a public IP, or a private/VPC address) but
    /// `FERRUM_ADMIN_ALLOWED_CIDRS` restricts which source IPs may connect.
    /// Bearer tokens still traverse cleartext on this port.
    ReachableAllowlisted,
    /// Bound to a non-loopback address reachable beyond the host with no
    /// allowlist — the admin API and any bearer tokens are exposed in cleartext
    /// to every host that can route to that interface.
    ReachableUnrestricted,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            mode: OperatingMode::File,
            namespace: "ferrum".into(),
            log_level: "error".into(),
            log_buffer_capacity: crate::logging::LOG_BUFFER_CAPACITY_DEFAULT,
            log_buffer_bytes: crate::logging::LOG_BUFFER_BYTES_DEFAULT,
            log_max_record_bytes: crate::logging::LOG_MAX_RECORD_BYTES_DEFAULT,
            log_shutdown_drain_timeout_ms: crate::logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_DEFAULT
                as u64,
            log_delivery_max_tasks: crate::logging::LOG_DELIVERY_MAX_TASKS_DEFAULT,
            secret_refresh_interval_seconds:
                crate::tls::source::subscription::DEFAULT_SECRET_REFRESH_INTERVAL_SECS,
            acme_auto_renew_enabled: false,
            acme_renew_when_remaining_days: 30,
            acme_renew_check_interval_seconds: 3600,
            acme_renew_challenge_type: "http01".to_string(),
            acme_renew_poll_timeout_seconds: 60,
            acme_dns01_hook_command: None,
            acme_dns01_propagation_seconds: 60,
            enable_streaming_latency_tracking: false,
            proxy_http_port: 8000,
            proxy_https_port: 8443,
            compression_gzip_enabled: true,
            compression_brotli_enabled: true,
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_ocsp_response_source: None,
            frontend_tls_live_reload_enabled: false,
            frontend_tls_watch_interval_seconds: 30,
            backend_tls_live_reload_enabled: true,
            backend_tls_watch_interval_seconds: 30,
            proxy_bind_address: "0.0.0.0".into(),
            admin_http_port: 9000,
            admin_https_port: 9443,
            admin_tls_cert_path: None,
            admin_tls_key_path: None,
            admin_bind_address: "127.0.0.1".into(),
            allow_insecure_admin_http: false,
            admin_jwt_secret: None,
            admin_jwt_issuer: "ferrum-edge".into(),
            admin_jwt_max_ttl: 3600,
            admin_jwt_audience: None,
            db_type: None,
            db_url: None,
            db_poll_interval: 30,
            db_rejected_delta_backoff_initial_seconds: 1,
            db_rejected_delta_backoff_max_seconds: 30,
            db_rejected_delta_full_reload_threshold: 3,
            db_tls_mode: None,
            db_tls_ca_cert_path: None,
            db_tls_client_cert_path: None,
            db_tls_client_key_path: None,
            db_tls_live_reload_enabled: false,
            db_tls_watch_interval_seconds: 30,
            file_config_path: None,
            db_config_backup_path: None,
            db_failover_urls: Vec::new(),
            db_read_replica_url: None,
            db_slow_query_threshold_ms: None,
            db_full_load_page_size: 10_000,
            db_pool_max_connections: 32,
            db_pool_min_connections: 1,
            db_pool_acquire_timeout_seconds: 30,
            db_pool_idle_timeout_seconds: 600,
            db_pool_max_lifetime_seconds: 300,
            db_pool_connect_timeout_seconds: 10,
            db_pool_statement_timeout_seconds: 30,
            mongo_database: "ferrum".to_string(),
            mongo_app_name: None,
            mongo_replica_set: None,
            mongo_auth_mechanism: None,
            mongo_server_selection_timeout_seconds: None,
            mongo_connect_timeout_seconds: None,
            cp_grpc_listen_addr: None,
            cp_dp_grpc_jwt_secret: None,
            cp_dp_grpc_jwt_issuer: "ferrum-edge-cp-dp".to_string(),
            dp_cp_grpc_urls: Vec::new(),
            dp_cp_failover_primary_retry_secs: 300,
            cp_dp_grpc_allow_plaintext: false,
            cp_grpc_tls_cert_path: None,
            cp_grpc_tls_key_path: None,
            cp_grpc_tls_client_ca_path: None,
            cp_grpc_max_connections: 1024,
            cp_grpc_max_connections_per_ip: 64,
            cp_broadcast_channel_capacity: 128,
            cp_namespaces: Vec::new(),
            cp_require_namespace_claim: false,
            xds_enabled: false,
            xds_stream_channel_capacity: 32,
            xds_max_streams_per_node: 4,
            mesh_ca_backend: "none".to_string(),
            mesh_spire_agent_socket: "/run/spire/sockets/agent.sock".to_string(),
            mesh_cert_ttl_seconds: 3600,
            mesh_config_protocol: "native".to_string(),
            mesh_file_config_path: None,
            mesh_trust_domain_aliases: Vec::new(),
            mesh_trusted_hbone_assertors: Vec::new(),
            mesh_egress_strip_baggage_keys: Vec::new(),
            mesh_outbound_traffic_policy: "allow_any".to_string(),
            mesh_outbound_registry_reject_status: 502,
            mesh_sidecar_enforced: false,
            mesh_sidecar_enforced_dry_run: false,
            mesh_sidecar_identity_narrowing: false,
            mesh_egress_stream_enabled: false,
            mesh_egress_stream_allow_plaintext: false,
            mesh_peer_auth_live_reload_enabled: false,
            mesh_request_auth_require_exp: true,
            mesh_federation_poll_interval_seconds: 300,
            mesh_federation_poll_timeout_seconds: 30,
            mesh_federation_max_stale_seconds: 3600,
            mesh_federation_fail_open: false,
            mesh_remote_discovery_poll_interval_seconds: 0,
            mesh_remote_discovery_poll_timeout_seconds: 30,
            mesh_remote_discovery_max_stale_seconds: 300,
            mesh_remote_discovery_credentials: None,
            mesh_locality_lb_strict: false,
            mesh_node_waypoint_cgroup_sweep_interval_secs: 30,
            mesh_node_waypoint_idle_gc_interval_secs: 30,
            mesh_node_waypoint_pod_registry_dir: "/run/ferrum/node-waypoint-pods".to_string(),
            mesh_svid_rotation_drain_seconds: 0,
            mesh_policy_deny_log_capacity: crate::modes::mesh::policy_deny_log::DEFAULT_CAPACITY,
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            node_agent_admin_enabled: false,
            node_agent_hbone_redirect_port: ferrum_ebpf_common::INBOUND_HBONE_PORT,
            node_agent_cni_enabled: false,
            node_agent_cni_socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
            k8s_controller_enabled: false,
            k8s_pod_discovery_enabled: false,
            k8s_controller_namespace: "ferrum".to_string(),
            k8s_node_locality_enabled: false,
            k8s_watch_namespaces: Vec::new(),
            k8s_kubeconfig_path: None,
            k8s_reconcile_debounce_ms: 500,
            k8s_full_sync_interval_secs: 300,
            k8s_watch_istio_crds: true,
            k8s_watch_mesh_config: true,
            k8s_watch_gateway_api_crds: true,
            k8s_trust_domain: "cluster.local".to_string(),
            k8s_cluster_domain: "cluster.local".to_string(),
            k8s_istio_root_namespace: "istio-system".to_string(),
            gateway_api_data_plane_service_namespace: None,
            gateway_api_data_plane_service_name: None,
            gateway_api_status_address: None,
            dp_grpc_tls_ca_cert_path: None,
            dp_grpc_tls_client_cert_path: None,
            dp_grpc_tls_client_key_path: None,
            dp_grpc_tls_no_verify: false,
            max_header_size_bytes: 32_768,
            max_single_header_size_bytes: 16_384,
            max_header_count: 100,
            max_request_body_size_bytes: 10_485_760,
            max_response_body_size_bytes: 10_485_760,
            response_buffer_cutoff_bytes: 65_536,
            h2_coalesce_target_bytes: 131_072,
            max_url_length_bytes: 8_192,
            max_query_params: 100,
            max_grpc_recv_size_bytes: 4_194_304,
            max_websocket_frame_size_bytes: 16_777_216,
            websocket_write_buffer_size: 131_072, // 128 KB
            websocket_tunnel_mode: false,
            websocket_idle_timeout_seconds: 300,
            max_credentials_per_type: 2,
            http_header_read_timeout_seconds: 10,
            frontend_tls_handshake_timeout_seconds: 10,
            dns_overrides: HashMap::new(),
            dns_resolver_address: None,
            dns_resolver_hosts_file: None,
            dns_order: None,
            dns_ttl_override: None,
            dns_min_ttl: 5,
            dns_stale_ttl: 3600,
            dns_error_ttl: 5,
            dns_cache_max_size: 10_000,
            dns_warmup_concurrency: 500,
            dns_slow_threshold_ms: None,
            dns_refresh_threshold_percent: 90,
            dns_failed_retry_interval: 10,
            dns_try_tcp_on_error: true,
            dns_num_concurrent_reqs: 3,
            dns_max_active_requests: 512,
            dns_max_concurrent_refreshes: 64,
            tls_ca_bundle_path: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            gateway_svid_cert_path: None,
            gateway_svid_key_path: None,
            gateway_svid_trust_bundle_path: None,
            gateway_spiffe_id: None,
            frontend_tls_client_ca_bundle_path: None,
            admin_tls_ocsp_response_source: None,
            admin_tls_client_ca_bundle_path: None,
            tls_no_verify: false,
            admin_read_only: false,
            admin_audit_enabled: false,
            audit_retention_days: None,
            audit_retention_max_rows: Some(crate::admin::audit::AUDIT_RETENTION_MAX_ROWS_DEFAULT),
            admin_require_namespace_claim: false,
            admin_tls_no_verify: false,
            stream_proxy_bind_address: "0.0.0.0".into(),
            dtls_cert_path: None,
            dtls_key_path: None,
            dtls_client_ca_cert_path: None,
            dtls_max_plaintext_bytes: 16_384,
            dtls_record_overhead_bytes: 64,
            enable_http3: false,
            http3_idle_timeout: 30,
            http3_max_streams: 1000,
            http3_stream_receive_window: crate::http3::config::H3_FRONTEND_STREAM_RECEIVE_WINDOW,
            http3_receive_window: crate::http3::config::H3_FRONTEND_RECEIVE_WINDOW,
            http3_send_window: crate::http3::config::H3_FRONTEND_SEND_WINDOW,
            http3_connections_per_backend: 4,
            http3_pool_idle_timeout_seconds: 120,
            http3_coalesce_min_bytes: crate::http3::config::H3_COALESCE_MAX_DEFAULT,
            http3_coalesce_max_bytes: crate::http3::config::H3_COALESCE_MAX_DEFAULT,
            http3_flush_interval_micros: 200,
            http3_request_body_channel_capacity: 32,
            http3_websocket_enabled: true,
            h3_request_body_drain_ms: 50,
            http3_initial_mtu: 1500,
            grpc_pool_ready_wait_ms: 1,
            pool_warmup_enabled: true,
            pool_warmup_concurrency: 500,
            pool_cleanup_interval_seconds: 30,
            backend_capability_refresh_interval_secs: 86_400,
            router_cache_max_entries: 0, // 0 = auto-scale based on proxy count
            tcp_idle_timeout_seconds: 300,
            tcp_half_close_max_wait_seconds: 300,
            udp_max_sessions: 10_000,
            udp_cleanup_interval_seconds: 10,
            udp_recvmmsg_batch_size: 64,
            adaptive_buffer_enabled: true,
            adaptive_batch_limit_enabled: true,
            adaptive_buffer_ewma_alpha: 300,
            adaptive_buffer_min_size: 8_192,
            adaptive_buffer_max_size: 262_144,
            adaptive_buffer_default_size: 65_536,
            adaptive_batch_limit_default: 6_000,
            tls_min_version: "1.2".into(),
            tls_max_version: "1.3".into(),
            tls_cipher_suites: None,
            tls_prefer_server_cipher_order: true,
            tls_curves: None,
            tls_session_cache_size: 4096,
            tls_cert_expiry_warning_days: 30,
            tls_inventory_snapshot_ttl_seconds: DEFAULT_SNAPSHOT_TTL_SECONDS,
            tls_early_data_methods: HashSet::new(),
            trusted_proxies: String::new(),
            backend_allow_ips: BackendEgressPolicy::unrestricted(),
            add_via_header: true,
            via_pseudonym: "ferrum-edge".into(),
            add_forwarded_header: false,
            real_ip_header: None,
            basic_auth_hmac_secret: None,
            plugin_http_slow_threshold_ms: 1000,
            plugin_http_max_retries: 0,
            plugin_http_retry_delay_ms: 100,
            tls_crl_file_path: None,
            admin_allowed_cidrs: String::new(),
            metrics_allowed_cidrs: String::new(),
            metrics_bearer_token: None,
            admin_max_connections: 1024,
            admin_max_connections_per_ip: 0,
            admin_restore_max_body_size_mib: 100,
            admin_spec_max_body_size_mib: 25,
            admin_body_read_timeout_seconds: crate::admin::DEFAULT_ADMIN_BODY_READ_TIMEOUT_SECONDS,
            admin_http2_max_concurrent_streams:
                crate::admin::DEFAULT_ADMIN_HTTP2_MAX_CONCURRENT_STREAMS,
            admin_http2_max_header_list_size_bytes:
                crate::admin::DEFAULT_ADMIN_HTTP2_MAX_HEADER_LIST_SIZE_BYTES,
            migrate_action: "up".into(),
            migrate_dry_run: false,
            auto_apply_plugin_migrations: false,
            worker_threads: None,
            blocking_threads: None,
            max_connections: 100_000,
            max_requests: 0,
            max_concurrent_requests_per_ip: 0,
            per_ip_cleanup_interval_seconds: 60,
            circuit_breaker_cache_max_entries: 10_000,
            pool_shard_amount: 0,
            status_counts_max_entries: 200,
            runtime_metrics_system_sample_interval_ms: 1000,
            runtime_metrics_window_1m_seconds: 60,
            runtime_metrics_window_5m_seconds: 300,
            runtime_metrics_log_counter_enabled: true,
            runtime_metrics_cache_ttl_ms: 1000,
            runtime_metrics_pool_tracking_enabled: true,
            runtime_metrics_status_tracking_enabled: true,
            tcp_listen_backlog: 2048,
            accept_threads: 0,
            frontend_h2_initial_stream_window_size:
                crate::proxy::FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE,
            frontend_h2_initial_connection_window_size:
                crate::proxy::FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE,
            frontend_h2_max_frame_size: crate::proxy::FRONTEND_H2_MAX_FRAME_SIZE,
            server_http2_max_concurrent_streams: 1000,
            server_http2_max_pending_accept_reset_streams: 64,
            server_http2_max_local_error_reset_streams: 256,
            websocket_max_connections: 20_000,
            overload_check_interval_ms: 1000,
            overload_fd_pressure_threshold: 0.80,
            overload_fd_critical_threshold: 0.95,
            overload_conn_pressure_threshold: 0.85,
            overload_conn_critical_threshold: 0.95,
            overload_req_pressure_threshold: 0.85,
            overload_req_critical_threshold: 0.95,
            overload_loop_warn_us: 10_000,
            overload_loop_critical_us: 500_000,
            shutdown_drain_seconds: 30,
            status_metrics_window_seconds: 30,
            tls_offload_threads: 0,
            tcp_fastopen_enabled: AutoBool::Auto,
            tcp_fastopen_queue_len: 256,
            ktls_enabled: AutoBool::Auto,
            io_uring_splice_enabled: AutoBool::Auto,
            udp_gro_enabled: AutoBool::Auto,
            udp_gso_enabled: AutoBool::Auto,
            udp_pktinfo_enabled: AutoBool::Auto,
            so_busy_poll_us: 0,
        }
    }
}

impl EnvConfig {
    /// Load configuration from environment variables and validate.
    ///
    /// When using external secret sources (`_FILE`, `_VAULT`, `_AWS`, `_GCP`,
    /// `_AZURE`), call `secrets::resolve_all_env_secrets()` before this method
    /// so that resolved values are available as plain env vars.
    pub fn from_env() -> Result<Self, String> {
        let conf = ConfFile::load()?;
        Self::from_env_with_conf(&conf)
    }

    /// Build config using values from the given conf file (takes precedence)
    /// with fallback to environment variables.
    pub fn from_env_with_conf(conf: &ConfFile) -> Result<Self, String> {
        let mode = OperatingMode::resolve(conf)?;

        // Mechanical env vars are declared in one place so parse/default semantics
        // stay consistent and malformed values fail loudly instead of silently
        // falling back to defaults.
        env_config! {
            conf = conf, mode = &mode;
            [core]
            dns_overrides: HashMap<String, String> = "FERRUM_DNS_OVERRIDES" => HashMap::new();
            namespace: String = "FERRUM_NAMESPACE" => "ferrum".to_string();
            log_level: String = "FERRUM_LOG_LEVEL" => "warn".to_string();
            log_buffer_capacity: usize = "FERRUM_LOG_BUFFER_CAPACITY" => crate::logging::LOG_BUFFER_CAPACITY_DEFAULT, clamp(crate::logging::LOG_BUFFER_CAPACITY_MIN, crate::logging::LOG_BUFFER_CAPACITY_MAX);
            log_buffer_bytes: usize = "FERRUM_LOG_BUFFER_BYTES" => crate::logging::LOG_BUFFER_BYTES_DEFAULT, clamp(crate::logging::LOG_BUFFER_BYTES_MIN, crate::logging::LOG_BUFFER_BYTES_MAX);
            log_max_record_bytes: usize = "FERRUM_LOG_MAX_RECORD_BYTES" => crate::logging::LOG_MAX_RECORD_BYTES_DEFAULT, clamp(crate::logging::LOG_MAX_RECORD_BYTES_MIN, crate::logging::LOG_MAX_RECORD_BYTES_MAX);
            log_shutdown_drain_timeout_ms: u64 = "FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS" => crate::logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_DEFAULT as u64, clamp(crate::logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_MIN as u64, crate::logging::LOG_SHUTDOWN_DRAIN_TIMEOUT_MS_MAX as u64);
            log_delivery_max_tasks: usize = "FERRUM_LOG_DELIVERY_MAX_TASKS" => crate::logging::LOG_DELIVERY_MAX_TASKS_DEFAULT, clamp(crate::logging::LOG_DELIVERY_MAX_TASKS_MIN, crate::logging::LOG_DELIVERY_MAX_TASKS_MAX);
            secret_refresh_interval_seconds: u64 = "FERRUM_SECRET_REFRESH_INTERVAL_SECONDS" => crate::tls::source::subscription::DEFAULT_SECRET_REFRESH_INTERVAL_SECS, clamp(1u64, 86_400u64);
            acme_auto_renew_enabled: bool = "FERRUM_ACME_AUTO_RENEW_ENABLED" => false;
            acme_renew_when_remaining_days: u64 = "FERRUM_ACME_RENEW_WHEN_REMAINING_DAYS" => 30u64, clamp(1u64, 365u64);
            acme_renew_check_interval_seconds: u64 = "FERRUM_ACME_RENEW_CHECK_INTERVAL_SECONDS" => 3600u64, clamp(60u64, 86_400u64);
            acme_renew_challenge_type: String = "FERRUM_ACME_RENEW_CHALLENGE_TYPE" => "http01".to_string();
            acme_renew_poll_timeout_seconds: u64 = "FERRUM_ACME_RENEW_POLL_TIMEOUT_SECONDS" => 60u64, clamp(1u64, 600u64);
            acme_dns01_hook_command: Option<String> = "FERRUM_ACME_DNS01_HOOK_COMMAND";
            acme_dns01_propagation_seconds: u64 = "FERRUM_ACME_DNS01_PROPAGATION_SECONDS" => 60u64, clamp(0u64, 3600u64);
            enable_streaming_latency_tracking: bool = "FERRUM_ENABLE_STREAMING_LATENCY_TRACKING" => false;
        }
        let log_buffer_bytes = log_buffer_bytes.max(log_max_record_bytes);

        env_config! {
            conf = conf, mode = &mode;
            [proxy]
            proxy_http_port: u16 = "FERRUM_PROXY_HTTP_PORT" => 8000u16;
            proxy_https_port: u16 = "FERRUM_PROXY_HTTPS_PORT" => 8443u16;
            compression_gzip_enabled: bool = "FERRUM_COMPRESSION_GZIP_ENABLED" => true;
            compression_brotli_enabled: bool = "FERRUM_COMPRESSION_BROTLI_ENABLED" => true;
            frontend_tls_cert_path: Option<String> = "FERRUM_FRONTEND_TLS_CERT_PATH";
            frontend_tls_key_path: Option<String> = "FERRUM_FRONTEND_TLS_KEY_PATH";
            frontend_tls_live_reload_enabled: bool = "FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED" => false;
            frontend_tls_watch_interval_seconds: u64 = "FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS" => 30u64, clamp(1u64, 3600u64);
            backend_tls_live_reload_enabled: bool = "FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED" => true;
            backend_tls_watch_interval_seconds: u64 = "FERRUM_BACKEND_TLS_WATCH_INTERVAL_SECONDS" => 30u64, clamp(1u64, 3600u64);
            proxy_bind_address: String = "FERRUM_PROXY_BIND_ADDRESS" => "0.0.0.0".to_string();
        }

        env_config! {
            conf = conf, mode = &mode;
            [admin]
            admin_http_port: u16 = "FERRUM_ADMIN_HTTP_PORT" => 9000u16;
            admin_https_port: u16 = "FERRUM_ADMIN_HTTPS_PORT" => 9443u16;
            admin_tls_cert_path: Option<String> = "FERRUM_ADMIN_TLS_CERT_PATH";
            admin_tls_key_path: Option<String> = "FERRUM_ADMIN_TLS_KEY_PATH";
            admin_bind_address: String = "FERRUM_ADMIN_BIND_ADDRESS" => "127.0.0.1".to_string();
            allow_insecure_admin_http: bool = "FERRUM_ALLOW_INSECURE_ADMIN_HTTP" => false;
            admin_jwt_secret: Option<String> = "FERRUM_ADMIN_JWT_SECRET"
                => required_for(["database", "cp"]) min_len(crate::config::types::MIN_JWT_SECRET_LENGTH);
            admin_jwt_issuer: String = "FERRUM_ADMIN_JWT_ISSUER" => "ferrum-edge".to_string();
            admin_jwt_max_ttl: u64 = "FERRUM_ADMIN_JWT_MAX_TTL" => 3600u64;
            admin_jwt_audience: Option<String> = "FERRUM_ADMIN_JWT_AUDIENCE";
            admin_audit_enabled: bool = "FERRUM_ADMIN_AUDIT_ENABLED" => false;
            audit_retention_days: Option<u64> = "FERRUM_AUDIT_RETENTION_DAYS";
            audit_retention_max_rows: u64 = "FERRUM_AUDIT_RETENTION_MAX_ROWS"
                => crate::admin::audit::AUDIT_RETENTION_MAX_ROWS_DEFAULT;
            admin_require_namespace_claim: bool = "FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM" => false;
        }
        let audit_retention_policy = crate::admin::audit::AuditRetentionPolicy::from_parts(
            audit_retention_days,
            Some(audit_retention_max_rows),
        )?;
        let audit_retention_days = audit_retention_policy.retention_days;
        let audit_retention_max_rows = audit_retention_policy.max_rows_per_namespace;

        env_config! {
            conf = conf, mode = &mode;
            [database]
            db_type: Option<String> = "FERRUM_DB_TYPE";
            db_url: Option<String> = "FERRUM_DB_URL";
            db_poll_interval: u64 = "FERRUM_DB_POLL_INTERVAL" => 30u64, max(1u64);
            db_rejected_delta_backoff_initial_seconds: u64 = "FERRUM_DB_REJECTED_DELTA_BACKOFF_INITIAL_SECONDS" => 1u64, clamp(1u64, 3600u64);
            db_rejected_delta_backoff_max_seconds: u64 = "FERRUM_DB_REJECTED_DELTA_BACKOFF_MAX_SECONDS" => 30u64, clamp(1u64, 3600u64);
            db_rejected_delta_full_reload_threshold: u64 = "FERRUM_DB_REJECTED_DELTA_FULL_RELOAD_THRESHOLD" => 3u64, max(1u64);
            db_tls_mode: Option<DbTlsMode> = "FERRUM_DB_TLS_MODE";
            db_tls_ca_cert_path: Option<String> = "FERRUM_DB_TLS_CA_CERT_PATH";
            db_tls_client_cert_path: Option<String> = "FERRUM_DB_TLS_CLIENT_CERT_PATH";
            db_tls_client_key_path: Option<String> = "FERRUM_DB_TLS_CLIENT_KEY_PATH";
            db_tls_live_reload_enabled: bool = "FERRUM_DB_TLS_LIVE_RELOAD_ENABLED" => false;
            db_tls_watch_interval_seconds: u64 = "FERRUM_DB_TLS_WATCH_INTERVAL_SECONDS" => 30u64, clamp(1u64, 3600u64);
            file_config_path: Option<String> = "FERRUM_FILE_CONFIG_PATH";
            db_config_backup_path: Option<String> = "FERRUM_DB_CONFIG_BACKUP_PATH";
            db_read_replica_url: Option<String> = "FERRUM_DB_READ_REPLICA_URL";
            db_slow_query_threshold_ms: Option<u64> = "FERRUM_DB_SLOW_QUERY_THRESHOLD_MS";
            db_full_load_page_size: u64 = "FERRUM_DB_FULL_LOAD_PAGE_SIZE" => 10_000u64, clamp(100u64, 100_000u64);
            db_pool_max_connections: u32 = "FERRUM_DB_POOL_MAX_CONNECTIONS" => 32u32, max(1u32);
            db_pool_min_connections: u32 = "FERRUM_DB_POOL_MIN_CONNECTIONS" => 1u32;
            db_pool_acquire_timeout_seconds: u64 = "FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS" => 30u64;
            db_pool_idle_timeout_seconds: u64 = "FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS" => 600u64;
            db_pool_max_lifetime_seconds: u64 = "FERRUM_DB_POOL_MAX_LIFETIME_SECONDS" => 300u64;
            db_pool_connect_timeout_seconds: u64 = "FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS" => 10u64;
            db_pool_statement_timeout_seconds: u64 = "FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS" => 30u64;
            mongo_database: String = "FERRUM_MONGO_DATABASE" => "ferrum".to_string();
            mongo_app_name: Option<String> = "FERRUM_MONGO_APP_NAME";
            mongo_replica_set: Option<String> = "FERRUM_MONGO_REPLICA_SET";
            mongo_auth_mechanism: Option<String> = "FERRUM_MONGO_AUTH_MECHANISM";
            mongo_server_selection_timeout_seconds: Option<u64> = "FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS";
            mongo_connect_timeout_seconds: Option<u64> = "FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS";
        }
        if resolve_var(conf, "FERRUM_DB_POLL_INTERVAL")
            .as_deref()
            .is_some_and(|raw| raw.trim() == "0")
        {
            tracing::warn!(
                "{} is clamped to 1 second; set a positive interval to avoid this implicit floor",
                crate::secrets::report_env_assignment("FERRUM_DB_POLL_INTERVAL", "0")
            );
        }
        let db_rejected_delta_backoff_max_seconds = if db_rejected_delta_backoff_max_seconds
            < db_rejected_delta_backoff_initial_seconds
        {
            tracing::warn!(
                configured_initial = %crate::secrets::report_env_field(
                    "FERRUM_DB_REJECTED_DELTA_BACKOFF_INITIAL_SECONDS",
                    &db_rejected_delta_backoff_initial_seconds.to_string()
                ),
                configured_max = %crate::secrets::report_env_field(
                    "FERRUM_DB_REJECTED_DELTA_BACKOFF_MAX_SECONDS",
                    &db_rejected_delta_backoff_max_seconds.to_string()
                ),
                "FERRUM_DB_REJECTED_DELTA_BACKOFF_MAX_SECONDS is below the initial backoff; clamped to the initial value"
            );
            db_rejected_delta_backoff_initial_seconds
        } else {
            db_rejected_delta_backoff_max_seconds
        };
        // Clamp statement timeout at parse time so the warning fires once at
        // startup instead of on every new database connection.
        const MAX_STATEMENT_TIMEOUT_SECONDS: u64 = 3600;
        let db_pool_statement_timeout_seconds =
            if db_pool_statement_timeout_seconds > MAX_STATEMENT_TIMEOUT_SECONDS {
                tracing::warn!(
                    configured = %crate::secrets::report_env_field(
                        "FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS",
                        &db_pool_statement_timeout_seconds.to_string()
                    ),
                    clamped = MAX_STATEMENT_TIMEOUT_SECONDS,
                    max = MAX_STATEMENT_TIMEOUT_SECONDS,
                    "FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS exceeds maximum, clamped"
                );
                MAX_STATEMENT_TIMEOUT_SECONDS
            } else {
                db_pool_statement_timeout_seconds
            };

        env_config! {
            conf = conf, mode = &mode;
            [cp_dp]
            // Mesh mode also requires this secret unless the localized `file`
            // config protocol is active — that conditional check lives in
            // `EnvConfig::validate()`'s Mesh arm (the macro cannot see
            // FERRUM_MESH_CONFIG_PROTOCOL).
            cp_dp_grpc_jwt_secret: Option<String> = "FERRUM_CP_DP_GRPC_JWT_SECRET"
                => required_for(["cp", "dp"]) min_len(crate::config::types::MIN_JWT_SECRET_LENGTH);
            cp_dp_grpc_jwt_issuer: String = "FERRUM_CP_DP_GRPC_JWT_ISSUER" => "ferrum-edge-cp-dp".to_string();
            dp_cp_grpc_urls: Vec<String> = "FERRUM_DP_CP_GRPC_URLS" => Vec::new();
            dp_cp_failover_primary_retry_secs: u64 = "FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS" => 300u64;
            cp_dp_grpc_allow_plaintext: bool = "FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT" => false;
            cp_grpc_tls_cert_path: Option<String> = "FERRUM_CP_GRPC_TLS_CERT_PATH";
            cp_grpc_tls_key_path: Option<String> = "FERRUM_CP_GRPC_TLS_KEY_PATH";
            cp_grpc_tls_client_ca_path: Option<String> = "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH";
            cp_grpc_max_connections: usize = "FERRUM_CP_GRPC_MAX_CONNECTIONS" => 1024usize;
            cp_grpc_max_connections_per_ip: usize = "FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP" => 64usize;
            cp_broadcast_channel_capacity: usize = "FERRUM_CP_BROADCAST_CHANNEL_CAPACITY" => 128usize;
            cp_namespaces: Vec<String> = "FERRUM_CP_NAMESPACES" => Vec::new();
            cp_require_namespace_claim: bool = "FERRUM_CP_REQUIRE_NAMESPACE_CLAIM" => false;
            xds_enabled: bool = "FERRUM_XDS_ENABLED" => false;
            xds_stream_channel_capacity: usize = "FERRUM_XDS_STREAM_CHANNEL_CAPACITY" => 32usize;
            xds_max_streams_per_node: usize = "FERRUM_XDS_MAX_STREAMS_PER_NODE" => 4usize;
            mesh_ca_backend: String = "FERRUM_MESH_CA_BACKEND" => "none".to_string();
            mesh_spire_agent_socket: String = "FERRUM_MESH_SPIRE_AGENT_SOCKET" => "/run/spire/sockets/agent.sock".to_string();
            mesh_cert_ttl_seconds: u64 = "FERRUM_MESH_CERT_TTL_SECONDS" => 3600u64;
            mesh_config_protocol: String = "FERRUM_MESH_CONFIG_PROTOCOL" => "native".to_string();
            mesh_file_config_path: Option<String> = "FERRUM_MESH_FILE_CONFIG_PATH";
            mesh_trust_domain_aliases: Vec<String> = "FERRUM_MESH_TRUST_DOMAIN_ALIASES" => Vec::new();
            mesh_trusted_hbone_assertors: Vec<String> = "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS" => Vec::new();
            mesh_egress_strip_baggage_keys: Vec<String> = "FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS" => Vec::new();
            mesh_outbound_traffic_policy: String = "FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY" => "allow_any".to_string();
            mesh_outbound_registry_reject_status: u16 = "FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS" => 502u16;
            mesh_sidecar_enforced: bool = "FERRUM_MESH_SIDECAR_ENFORCED" => false;
            mesh_sidecar_enforced_dry_run: bool = "FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN" => false;
            mesh_sidecar_identity_narrowing: bool = "FERRUM_MESH_SIDECAR_IDENTITY_NARROWING" => false;
            mesh_egress_stream_enabled: bool = "FERRUM_MESH_EGRESS_STREAM_ENABLED" => false;
            mesh_egress_stream_allow_plaintext: bool = "FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT" => false;
            mesh_peer_auth_live_reload_enabled: bool = "FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED" => false;
            mesh_request_auth_require_exp: bool = "FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP" => true;
            mesh_federation_poll_interval_seconds: u64 = "FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS" => 300u64;
            mesh_federation_poll_timeout_seconds: u64 = "FERRUM_MESH_FEDERATION_POLL_TIMEOUT_SECONDS" => 30u64;
            mesh_federation_max_stale_seconds: u64 = "FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS" => 3600u64;
            mesh_federation_fail_open: bool = "FERRUM_MESH_FEDERATION_FAIL_OPEN" => false;
            mesh_remote_discovery_poll_interval_seconds: u64 = "FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS" => 0u64;
            mesh_remote_discovery_poll_timeout_seconds: u64 = "FERRUM_MESH_REMOTE_DISCOVERY_POLL_TIMEOUT_SECONDS" => 30u64;
            mesh_remote_discovery_max_stale_seconds: u64 = "FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS" => 300u64;
            mesh_remote_discovery_credentials: Option<String> = "FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS";
            mesh_locality_lb_strict: bool = "FERRUM_MESH_LOCALITY_LB_STRICT" => false;
            mesh_node_waypoint_cgroup_sweep_interval_secs: u64 = "FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS" => 30u64;
            mesh_node_waypoint_idle_gc_interval_secs: u64 = "FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS" => 30u64;
            mesh_node_waypoint_pod_registry_dir: String = "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR" => "/run/ferrum/node-waypoint-pods".to_string();
            mesh_svid_rotation_drain_seconds: u64 = "FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS" => 0u64;
            mesh_policy_deny_log_capacity: usize = "FERRUM_MESH_POLICY_DENY_LOG_CAPACITY" => crate::modes::mesh::policy_deny_log::DEFAULT_CAPACITY;
            node_agent_proxy_mode: NodeAgentProxyMode = "FERRUM_NODE_AGENT_PROXY_MODE" => NodeAgentProxyMode::LocalPod;
            node_agent_admin_enabled: bool = "FERRUM_NODE_AGENT_ADMIN_ENABLED" => false;
            node_agent_hbone_redirect_port: u16 = "FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT" => ferrum_ebpf_common::INBOUND_HBONE_PORT;
            node_agent_cni_enabled: bool = "FERRUM_NODE_AGENT_CNI_ENABLED" => false;
            node_agent_cni_socket_path: String = "FERRUM_NODE_AGENT_CNI_SOCKET_PATH" => "/var/run/ferrum/node-agent-cni.sock".to_string();
            k8s_controller_namespace: String = "FERRUM_K8S_CONTROLLER_NAMESPACE" => namespace.clone();
            k8s_node_locality_enabled: bool = "FERRUM_K8S_NODE_LOCALITY_ENABLED" => false;
            k8s_watch_namespaces: Vec<String> = "FERRUM_K8S_WATCH_NAMESPACES" => Vec::new();
            k8s_kubeconfig_path: Option<String> = "FERRUM_K8S_KUBECONFIG_PATH";
            k8s_reconcile_debounce_ms: u64 = "FERRUM_K8S_RECONCILE_DEBOUNCE_MS" => 500u64;
            k8s_full_sync_interval_secs: u64 = "FERRUM_K8S_FULL_SYNC_INTERVAL_SECS" => 300u64;
            k8s_watch_istio_crds: bool = "FERRUM_K8S_WATCH_ISTIO_CRDS" => true;
            k8s_watch_mesh_config: bool = "FERRUM_K8S_WATCH_MESH_CONFIG" => true;
            k8s_watch_gateway_api_crds: bool = "FERRUM_K8S_WATCH_GATEWAY_API_CRDS" => true;
            k8s_trust_domain: String = "FERRUM_K8S_TRUST_DOMAIN" => "cluster.local".to_string();
            k8s_cluster_domain: String = "FERRUM_K8S_CLUSTER_DOMAIN" => "cluster.local".to_string();
            k8s_istio_root_namespace: String = "FERRUM_K8S_ISTIO_ROOT_NAMESPACE" => "istio-system".to_string();
            gateway_api_data_plane_service_namespace: Option<String> = "FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE";
            gateway_api_data_plane_service_name: Option<String> = "FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAME";
            gateway_api_status_address: Option<String> = "FERRUM_GATEWAY_API_STATUS_ADDRESS";
            dp_grpc_tls_ca_cert_path: Option<String> = "FERRUM_DP_GRPC_TLS_CA_CERT_PATH";
            dp_grpc_tls_client_cert_path: Option<String> = "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH";
            dp_grpc_tls_client_key_path: Option<String> = "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH";
            dp_grpc_tls_no_verify: bool = "FERRUM_DP_GRPC_TLS_NO_VERIFY" => false;
        }

        // T2-B: `FERRUM_K8S_CONTROLLER_ENABLED` and
        // `FERRUM_K8S_POD_DISCOVERY_ENABLED` default to `true` when the
        // process is running inside a Kubernetes pod (detected via
        // `KUBERNETES_SERVICE_HOST`). Outside a pod the historic `false`
        // default applies. Explicit `false` from the operator (env var or
        // ferrum.conf) always wins, so pod-side opt-out remains one
        // setting away. See `resolve_in_cluster_default_bool` for the
        // contract.
        let k8s_controller_enabled =
            resolve_in_cluster_default_bool(conf, "FERRUM_K8S_CONTROLLER_ENABLED")?;
        let k8s_pod_discovery_enabled =
            resolve_in_cluster_default_bool(conf, "FERRUM_K8S_POD_DISCOVERY_ENABLED")?;

        env_config! {
            conf = conf, mode = &mode;
            [limits]
            max_header_size_bytes: usize = "FERRUM_MAX_HEADER_SIZE_BYTES" => 32_768usize;
            max_single_header_size_bytes: usize = "FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES" => 16_384usize;
            max_header_count: usize = "FERRUM_MAX_HEADER_COUNT" => 100usize;
            max_request_body_size_bytes: usize = "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES" => 10_485_760usize;
            max_response_body_size_bytes: usize = "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES" => 10_485_760usize;
            response_buffer_cutoff_bytes: usize = "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES" => 65_536usize;
            h2_coalesce_target_bytes: usize = "FERRUM_H2_COALESCE_TARGET_BYTES" => 131_072usize, clamp(16_384usize, 1_048_576usize);
            max_url_length_bytes: usize = "FERRUM_MAX_URL_LENGTH_BYTES" => 8_192usize;
            max_query_params: usize = "FERRUM_MAX_QUERY_PARAMS" => 100usize;
            max_grpc_recv_size_bytes: usize = "FERRUM_MAX_GRPC_RECV_SIZE_BYTES" => 4_194_304usize;
            max_websocket_frame_size_bytes: usize = "FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES" => 16_777_216usize;
            websocket_write_buffer_size: usize = "FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE" => 131_072usize;
            websocket_tunnel_mode: bool = "FERRUM_WEBSOCKET_TUNNEL_MODE" => false;
            websocket_idle_timeout_seconds: u64 = "FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS" => 300u64;
            max_credentials_per_type: usize = "FERRUM_MAX_CREDENTIALS_PER_TYPE" => 2usize;
            http_header_read_timeout_seconds: u64 = "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS" => 10u64;
            frontend_tls_handshake_timeout_seconds: u64 = "FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS" => 10u64;
        }

        env_config! {
            conf = conf, mode = &mode;
            [dns]
            dns_resolver_address: Option<String> = "FERRUM_DNS_RESOLVER_ADDRESS";
            dns_resolver_hosts_file: Option<String> = "FERRUM_DNS_RESOLVER_HOSTS_FILE";
            dns_order: Option<String> = "FERRUM_DNS_ORDER";
            dns_ttl_override: Option<u64> = "FERRUM_DNS_TTL_OVERRIDE_SECONDS";
            dns_min_ttl: u64 = "FERRUM_DNS_MIN_TTL_SECONDS" => 5u64;
            dns_stale_ttl: u64 = "FERRUM_DNS_STALE_TTL" => 3600u64;
            dns_error_ttl: u64 = "FERRUM_DNS_ERROR_TTL" => 5u64;
            dns_cache_max_size: usize = "FERRUM_DNS_CACHE_MAX_SIZE" => 10_000usize;
            dns_warmup_concurrency: usize = "FERRUM_DNS_WARMUP_CONCURRENCY" => 500usize, max(1usize);
            dns_slow_threshold_ms: Option<u64> = "FERRUM_DNS_SLOW_THRESHOLD_MS";
            dns_refresh_threshold_percent: u8 = "FERRUM_DNS_REFRESH_THRESHOLD_PERCENT" => 90u8, clamp(1u8, 99u8);
            dns_failed_retry_interval: u64 = "FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS" => 10u64;
            dns_try_tcp_on_error: bool = "FERRUM_DNS_TRY_TCP_ON_ERROR" => true;
            dns_num_concurrent_reqs: usize = "FERRUM_DNS_NUM_CONCURRENT_REQS" => 3usize, clamp(1usize, 10usize);
            dns_max_active_requests: usize = "FERRUM_DNS_MAX_ACTIVE_REQUESTS" => 512usize, clamp(1usize, 4096usize);
            dns_max_concurrent_refreshes: usize = "FERRUM_DNS_MAX_CONCURRENT_REFRESHES" => 64usize, clamp(1usize, 1000usize);
        }

        env_config! {
            conf = conf, mode = &mode;
            [tls]
            tls_ca_bundle_path: Option<String> = "FERRUM_TLS_CA_BUNDLE_PATH";
            backend_tls_client_cert_path: Option<String> = "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH";
            backend_tls_client_key_path: Option<String> = "FERRUM_BACKEND_TLS_CLIENT_KEY_PATH";
            gateway_svid_cert_path: Option<String> = "FERRUM_GATEWAY_SVID_CERT_PATH";
            gateway_svid_key_path: Option<String> = "FERRUM_GATEWAY_SVID_KEY_PATH";
            gateway_svid_trust_bundle_path: Option<String> = "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH";
            gateway_spiffe_id: Option<String> = "FERRUM_GATEWAY_SPIFFE_ID";
            frontend_tls_client_ca_bundle_path: Option<String> = "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH";
            frontend_tls_ocsp_response_source: Option<String> = "FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE";
            admin_tls_ocsp_response_source: Option<String> = "FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE";
            admin_tls_client_ca_bundle_path: Option<String> = "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH";
            tls_no_verify: bool = "FERRUM_TLS_NO_VERIFY" => false;
            admin_tls_no_verify: bool = "FERRUM_ADMIN_TLS_NO_VERIFY" => false;
            admin_read_only: bool = "FERRUM_ADMIN_READ_ONLY" => false;
            stream_proxy_bind_address: String = "FERRUM_STREAM_PROXY_BIND_ADDRESS" => "0.0.0.0".to_string();
            dtls_cert_path: Option<String> = "FERRUM_DTLS_CERT_PATH";
            dtls_key_path: Option<String> = "FERRUM_DTLS_KEY_PATH";
            dtls_client_ca_cert_path: Option<String> = "FERRUM_DTLS_CLIENT_CA_CERT_PATH";
            dtls_max_plaintext_bytes: usize = "FERRUM_DTLS_MAX_PLAINTEXT_BYTES" => 16_384usize;
            dtls_record_overhead_bytes: usize = "FERRUM_DTLS_RECORD_OVERHEAD_BYTES" => 64usize;
            enable_http3: bool = "FERRUM_ENABLE_HTTP3" => false;
            http3_idle_timeout: u64 = "FERRUM_HTTP3_IDLE_TIMEOUT" => 30u64;
            http3_max_streams: u32 = "FERRUM_HTTP3_MAX_STREAMS" => 1000u32;
            http3_stream_receive_window: u64 = "FERRUM_HTTP3_STREAM_RECEIVE_WINDOW" => crate::http3::config::H3_FRONTEND_STREAM_RECEIVE_WINDOW;
            http3_receive_window: u64 = "FERRUM_HTTP3_RECEIVE_WINDOW" => crate::http3::config::H3_FRONTEND_RECEIVE_WINDOW;
            http3_send_window: u64 = "FERRUM_HTTP3_SEND_WINDOW" => crate::http3::config::H3_FRONTEND_SEND_WINDOW;
            http3_connections_per_backend: usize = "FERRUM_HTTP3_CONNECTIONS_PER_BACKEND" => 4usize, max(1usize);
            http3_pool_idle_timeout_seconds: u64 = "FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS" => 120u64;
            http3_coalesce_max_bytes: usize = "FERRUM_HTTP3_COALESCE_MAX_BYTES" => crate::http3::config::H3_COALESCE_MAX_DEFAULT, clamp(crate::http3::config::H3_COALESCE_MIN_FLOOR, crate::http3::config::H3_COALESCE_MAX_CAP);
            http3_flush_interval_micros: u64 = "FERRUM_HTTP3_FLUSH_INTERVAL_MICROS" => 200u64, clamp(crate::http3::config::H3_FLUSH_INTERVAL_MIN_MICROS, crate::http3::config::H3_FLUSH_INTERVAL_MAX_MICROS);
            http3_request_body_channel_capacity: usize = "FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY" => 32usize, clamp(1usize, 1024usize);
            http3_websocket_enabled: bool = "FERRUM_HTTP3_WEBSOCKET_ENABLED" => true;
            h3_request_body_drain_ms: u64 = "FERRUM_H3_REQUEST_BODY_DRAIN_MS" => 50u64, clamp(0u64, 1000u64);
            http3_initial_mtu: u16 = "FERRUM_HTTP3_INITIAL_MTU" => 1500u16;
            grpc_pool_ready_wait_ms: u64 = "FERRUM_GRPC_POOL_READY_WAIT_MS" => 1u64;
            pool_warmup_enabled: bool = "FERRUM_POOL_WARMUP_ENABLED" => true;
            pool_warmup_concurrency: usize = "FERRUM_POOL_WARMUP_CONCURRENCY" => 500usize, max(1usize);
            pool_cleanup_interval_seconds: u64 = "FERRUM_POOL_CLEANUP_INTERVAL_SECONDS" => 30u64;
            backend_capability_refresh_interval_secs: u64 = "FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS" => 86_400u64;
            router_cache_max_entries: usize = "FERRUM_ROUTER_CACHE_MAX_ENTRIES" => 0usize;
            tcp_idle_timeout_seconds: u64 = "FERRUM_TCP_IDLE_TIMEOUT_SECONDS" => 300u64;
            tcp_half_close_max_wait_seconds: u64 = "FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS" => 300u64;
            udp_max_sessions: usize = "FERRUM_UDP_MAX_SESSIONS" => 10_000usize, max(1usize);
            udp_cleanup_interval_seconds: u64 = "FERRUM_UDP_CLEANUP_INTERVAL_SECONDS" => 10u64;
            udp_recvmmsg_batch_size: usize = "FERRUM_UDP_RECVMMSG_BATCH_SIZE" => 64usize, clamp(1usize, 1024usize);
            adaptive_buffer_enabled: bool = "FERRUM_ADAPTIVE_BUFFER_ENABLED" => true;
            adaptive_batch_limit_enabled: bool = "FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED" => true;
            adaptive_buffer_ewma_alpha: u64 = "FERRUM_ADAPTIVE_BUFFER_EWMA_ALPHA" => 300u64, clamp(1u64, 999u64);
            adaptive_buffer_min_size: usize = "FERRUM_ADAPTIVE_BUFFER_MIN_SIZE" => 8_192usize, clamp(1024usize, 1_048_576usize);
            adaptive_buffer_max_size: usize = "FERRUM_ADAPTIVE_BUFFER_MAX_SIZE" => 262_144usize, clamp(1024usize, 1_048_576usize);
            adaptive_buffer_default_size: usize = "FERRUM_ADAPTIVE_BUFFER_DEFAULT_SIZE" => 65_536usize, clamp(1024usize, 1_048_576usize);
            adaptive_batch_limit_default: usize = "FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT" => 6_000usize, max(1usize);
            tls_min_version: String = "FERRUM_TLS_MIN_VERSION" => "1.2".to_string();
            tls_max_version: String = "FERRUM_TLS_MAX_VERSION" => "1.3".to_string();
            tls_cipher_suites: Option<String> = "FERRUM_TLS_CIPHER_SUITES";
            tls_prefer_server_cipher_order: bool = "FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER" => true;
            tls_key_exchange_groups: Option<String> = "FERRUM_TLS_KEY_EXCHANGE_GROUPS";
            tls_curves_legacy: Option<String> = "FERRUM_TLS_CURVES";
            tls_session_cache_size: usize = "FERRUM_TLS_SESSION_CACHE_SIZE" => 4096usize;
            tls_cert_expiry_warning_days: u64 = "FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS" => 30u64;
            tls_inventory_snapshot_ttl_seconds: u64 = "FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS" => DEFAULT_SNAPSHOT_TTL_SECONDS, clamp(0u64, 86_400u64);
        }
        let tls_curves =
            resolve_tls_key_exchange_groups(tls_key_exchange_groups, tls_curves_legacy);

        env_config! {
            conf = conf, mode = &mode;
            [client_ip]
            trusted_proxies: String = "FERRUM_TRUSTED_PROXIES" => String::new();
            backend_allow_ips: BackendAllowIps = "FERRUM_BACKEND_ALLOW_IPS" => BackendAllowIps::Both;
            backend_allow_cidrs: String = "FERRUM_BACKEND_ALLOW_CIDRS" => String::new();
            backend_deny_cidrs: String = "FERRUM_BACKEND_DENY_CIDRS" => String::new();
            backend_block_dangerous_ranges: bool = "FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES" => true;
            add_via_header: bool = "FERRUM_ADD_VIA_HEADER" => true;
            via_pseudonym: String = "FERRUM_VIA_PSEUDONYM" => "ferrum-edge".to_string();
            add_forwarded_header: bool = "FERRUM_ADD_FORWARDED_HEADER" => false;
            basic_auth_hmac_secret: Option<String> = "FERRUM_BASIC_AUTH_HMAC_SECRET";
            plugin_http_slow_threshold_ms: u64 = "FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS" => 1000u64;
            plugin_http_max_retries: u32 = "FERRUM_PLUGIN_HTTP_MAX_RETRIES" => 0u32;
            plugin_http_retry_delay_ms: u64 = "FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS" => 100u64;
            tls_crl_file_path: Option<String> = "FERRUM_TLS_CRL_FILE_PATH";
            admin_allowed_cidrs: String = "FERRUM_ADMIN_ALLOWED_CIDRS" => String::new();
            metrics_allowed_cidrs: String = "FERRUM_METRICS_ALLOWED_CIDRS" => String::new();
            metrics_bearer_token: Option<String> = "FERRUM_METRICS_BEARER_TOKEN";
            admin_max_connections: usize = "FERRUM_ADMIN_MAX_CONNECTIONS" => 1024usize;
            admin_max_connections_per_ip: usize = "FERRUM_ADMIN_MAX_CONNECTIONS_PER_IP" => 0usize;
            admin_restore_max_body_size_mib: usize = "FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB" => 100usize;
            admin_spec_max_body_size_mib: usize = "FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB" => 25usize;
            admin_body_read_timeout_seconds: u64 = "FERRUM_ADMIN_BODY_READ_TIMEOUT_SECONDS" => crate::admin::DEFAULT_ADMIN_BODY_READ_TIMEOUT_SECONDS;
            admin_http2_max_concurrent_streams: u32 = "FERRUM_ADMIN_HTTP2_MAX_CONCURRENT_STREAMS" => crate::admin::DEFAULT_ADMIN_HTTP2_MAX_CONCURRENT_STREAMS, max(1u32);
            admin_http2_max_header_list_size_bytes: u32 = "FERRUM_ADMIN_HTTP2_MAX_HEADER_LIST_SIZE_BYTES" => crate::admin::DEFAULT_ADMIN_HTTP2_MAX_HEADER_LIST_SIZE_BYTES, max(1_024u32);
            migrate_action: String = "FERRUM_MIGRATE_ACTION" => "up".to_string(), lowercase();
            migrate_dry_run: bool = "FERRUM_MIGRATE_DRY_RUN" => false;
            auto_apply_plugin_migrations: bool = "FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS" => false;
        }

        env_config! {
            conf = conf, mode = &mode;
            [runtime]
            max_connections: usize = "FERRUM_MAX_CONNECTIONS" => 100_000usize;
            max_requests: usize = "FERRUM_MAX_REQUESTS" => 0usize;
            max_concurrent_requests_per_ip: u64 = "FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP" => 0u64;
            per_ip_cleanup_interval_seconds: u64 = "FERRUM_PER_IP_CLEANUP_INTERVAL_SECONDS" => 60u64;
            circuit_breaker_cache_max_entries: usize = "FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES" => 10_000usize;
            pool_shard_amount: usize = "FERRUM_POOL_SHARD_AMOUNT" => 0usize;
            status_counts_max_entries: usize = "FERRUM_STATUS_COUNTS_MAX_ENTRIES" => 200usize;
            runtime_metrics_system_sample_interval_ms: u64 = "FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS" => 1000u64, max(100u64);
            runtime_metrics_window_1m_seconds: u64 = "FERRUM_METRICS_WINDOW_1M_SECONDS" => 60u64, max(1u64);
            runtime_metrics_window_5m_seconds: u64 = "FERRUM_METRICS_WINDOW_5M_SECONDS" => 300u64, max(1u64);
            runtime_metrics_log_counter_enabled: bool = "FERRUM_METRICS_LOG_COUNTER_ENABLED" => true;
            runtime_metrics_cache_ttl_ms: u64 = "FERRUM_METRICS_RUNTIME_CACHE_MS" => 1000u64;
            runtime_metrics_pool_tracking_enabled: bool = "FERRUM_METRICS_POOL_TRACKING_ENABLED" => true;
            runtime_metrics_status_tracking_enabled: bool = "FERRUM_METRICS_STATUS_TRACKING_ENABLED" => true;
            tcp_listen_backlog: u32 = "FERRUM_TCP_LISTEN_BACKLOG" => 2048u32, max(128u32);
            frontend_h2_initial_stream_window_size: u32 = "FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE" => crate::proxy::FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE, clamp(65_535u32, 128 * 1024 * 1024u32);
            frontend_h2_initial_connection_window_size: u32 = "FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE" => crate::proxy::FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE, clamp(65_535u32, 128 * 1024 * 1024u32);
            frontend_h2_max_frame_size: u32 = "FERRUM_FRONTEND_H2_MAX_FRAME_SIZE" => crate::proxy::FRONTEND_H2_MAX_FRAME_SIZE, clamp(16_384u32, 1_048_576u32);
            server_http2_max_concurrent_streams: u32 = "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS" => 1000u32, max(1u32);
            server_http2_max_pending_accept_reset_streams: usize = "FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS" => 64usize, max(1usize);
            server_http2_max_local_error_reset_streams: usize = "FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS" => 256usize, max(1usize);
            websocket_max_connections: usize = "FERRUM_WEBSOCKET_MAX_CONNECTIONS" => 20_000usize;
            overload_check_interval_ms: u64 = "FERRUM_OVERLOAD_CHECK_INTERVAL_MS" => 1000u64, max(100u64);
            overload_fd_pressure_threshold: f64 = "FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD" => 0.80f64, clamp(0.0f64, 1.0f64);
            overload_fd_critical_threshold: f64 = "FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD" => 0.95f64, clamp(0.0f64, 1.0f64);
            overload_conn_pressure_threshold: f64 = "FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD" => 0.85f64, clamp(0.0f64, 1.0f64);
            overload_conn_critical_threshold: f64 = "FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD" => 0.95f64, clamp(0.0f64, 1.0f64);
            overload_req_pressure_threshold: f64 = "FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD" => 0.85f64, clamp(0.0f64, 1.0f64);
            overload_req_critical_threshold: f64 = "FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD" => 0.95f64, clamp(0.0f64, 1.0f64);
            overload_loop_warn_us: u64 = "FERRUM_OVERLOAD_LOOP_WARN_US" => 10_000u64;
            overload_loop_critical_us: u64 = "FERRUM_OVERLOAD_LOOP_CRITICAL_US" => 500_000u64;
            shutdown_drain_seconds: u64 = "FERRUM_SHUTDOWN_DRAIN_SECONDS" => 30u64;
            status_metrics_window_seconds: u64 = "FERRUM_STATUS_METRICS_WINDOW_SECONDS" => 30u64, max(1u64);
            tls_offload_threads: usize = "FERRUM_TLS_OFFLOAD_THREADS" => 0usize;
            tcp_fastopen_queue_len: u16 = "FERRUM_TCP_FASTOPEN_QUEUE_LEN" => 256u16;
            so_busy_poll_us: u32 = "FERRUM_SO_BUSY_POLL_US" => 0u32;
        }

        // The CP gRPC listener is a JWT-authenticated config-distribution server
        // that data planes connect to over the network, so it defaults to
        // 0.0.0.0 (all interfaces) — deliberately NOT coupled to the admin bind,
        // which is loopback-by-default. Inheriting the loopback admin default
        // here would make a fresh CP unreachable by remote DPs. Operators narrow
        // it (or go TLS-only with port 0) via an explicit FERRUM_CP_GRPC_LISTEN_ADDR.
        let cp_grpc_listen_addr =
            match env_config_macro::resolve_optional::<String>(conf, "FERRUM_CP_GRPC_LISTEN_ADDR")?
            {
                Some(addr) => Some(addr),
                None if matches!(mode, OperatingMode::ControlPlane) => {
                    Some("0.0.0.0:50051".to_string())
                }
                None => None,
            };

        // Keep this hand-written: failover URLs are part of a broader
        // cross-variable validation path (TLS consistency vs. the primary).
        let db_failover_urls =
            env_config_macro::resolve_optional::<Vec<String>>(conf, "FERRUM_DB_FAILOVER_URLS")?
                .unwrap_or_default();

        // Keep this hand-written: 0-RTT methods emit startup warnings/info and
        // normalize each token to uppercase.
        let tls_early_data_methods: HashSet<String> = env_config_macro::resolve_optional::<
            Vec<String>,
        >(
            conf, "FERRUM_TLS_EARLY_DATA_METHODS"
        )?
        .unwrap_or_default()
        .into_iter()
        .map(|method| method.to_ascii_uppercase())
        .filter(|method| !method.is_empty())
        .collect();
        for method in &tls_early_data_methods {
            if method != "GET" {
                tracing::warn!(
                    "FERRUM_TLS_EARLY_DATA_METHODS includes non-GET method {} — \
                     0-RTT early data is replayable, which is dangerous for \
                     non-idempotent operations",
                    crate::secrets::quoted_env_value("FERRUM_TLS_EARLY_DATA_METHODS", method)
                );
            }
        }
        if !tls_early_data_methods.is_empty() {
            // The `{:?}` rendering is uppercased and re-quoted, so it is a
            // transformed form like the warning above; withhold by key.
            tracing::info!(
                "TLS 1.3 0-RTT early data enabled for methods: {}",
                crate::secrets::report_env_field(
                    "FERRUM_TLS_EARLY_DATA_METHODS",
                    &format!("{:?}", tls_early_data_methods)
                )
            );
        }

        // Keep this hand-written: the value is pre-lowercased at load time so
        // request handling can avoid allocating on every lookup.
        let real_ip_header =
            env_config_macro::resolve_optional::<String>(conf, "FERRUM_REAL_IP_HEADER")?
                .map(|header| header.to_ascii_lowercase());

        // Keep these hand-written: optional runtime tunables clamp only when
        // set, and accept_threads has an `auto` runtime probe fallback.
        let worker_threads =
            env_config_macro::resolve_optional::<usize>(conf, "FERRUM_WORKER_THREADS")?
                .map(|threads| threads.max(1));
        let blocking_threads =
            env_config_macro::resolve_optional::<usize>(conf, "FERRUM_BLOCKING_THREADS")?
                .map(|threads| threads.max(1));
        let accept_threads_raw =
            env_config_macro::resolve_default::<usize, _>(conf, "FERRUM_ACCEPT_THREADS", || {
                0usize
            })?;
        let accept_threads = if accept_threads_raw == 0 {
            std::thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1)
        } else {
            accept_threads_raw
        };

        // Keep these hand-written: `auto` probe toggles deliberately stay out
        // of the macro escape hatch so their startup semantics remain obvious.
        let tcp_fastopen_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_TCP_FASTOPEN_ENABLED",
            || AutoBool::Auto,
        )?;
        let ktls_enabled =
            env_config_macro::resolve_default::<AutoBool, _>(conf, "FERRUM_KTLS_ENABLED", || {
                AutoBool::Auto
            })?;
        let io_uring_splice_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_IO_URING_SPLICE_ENABLED",
            || AutoBool::Auto,
        )?;
        let udp_gro_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_UDP_GRO_ENABLED",
            || AutoBool::Auto,
        )?;
        let udp_gso_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_UDP_GSO_ENABLED",
            || AutoBool::Auto,
        )?;
        let udp_pktinfo_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_UDP_PKTINFO_ENABLED",
            || AutoBool::Auto,
        )?;

        // `http3_coalesce_min_bytes` depends on the runtime-parsed
        // `http3_coalesce_max_bytes`, so it lives outside the macro block.
        let http3_coalesce_min_bytes: usize = {
            let raw: usize =
                env_config_macro::resolve_default(conf, "FERRUM_HTTP3_COALESCE_MIN_BYTES", || {
                    crate::http3::config::H3_COALESCE_MAX_DEFAULT
                })?;
            let clamped = raw.clamp(
                crate::http3::config::H3_COALESCE_MIN_FLOOR,
                http3_coalesce_max_bytes,
            );
            if raw > http3_coalesce_max_bytes {
                tracing::warn!(
                    "{} exceeds {}; clamping MIN to MAX",
                    crate::secrets::report_env_assignment(
                        "FERRUM_HTTP3_COALESCE_MIN_BYTES",
                        &raw.to_string()
                    ),
                    crate::secrets::report_env_assignment(
                        "FERRUM_HTTP3_COALESCE_MAX_BYTES",
                        &http3_coalesce_max_bytes.to_string()
                    ),
                );
            }
            clamped
        };

        let frontend_tls_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_FRONTEND_TLS_CERT_SOURCE",
            "FERRUM_FRONTEND_TLS_CERT_PATH",
            frontend_tls_cert_path,
        );
        let frontend_tls_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_FRONTEND_TLS_KEY_SOURCE",
            "FERRUM_FRONTEND_TLS_KEY_PATH",
            frontend_tls_key_path,
        );
        let frontend_tls_client_ca_bundle_path = resolve_tls_source_override(
            conf,
            "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_SOURCE",
            "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH",
            frontend_tls_client_ca_bundle_path,
        );
        let admin_tls_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_ADMIN_TLS_CERT_SOURCE",
            "FERRUM_ADMIN_TLS_CERT_PATH",
            admin_tls_cert_path,
        );
        let admin_tls_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_ADMIN_TLS_KEY_SOURCE",
            "FERRUM_ADMIN_TLS_KEY_PATH",
            admin_tls_key_path,
        );
        let admin_tls_client_ca_bundle_path = resolve_tls_source_override(
            conf,
            "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE",
            "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH",
            admin_tls_client_ca_bundle_path,
        );
        let db_tls_ca_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_DB_TLS_CA_CERT_SOURCE",
            "FERRUM_DB_TLS_CA_CERT_PATH",
            db_tls_ca_cert_path,
        );
        let db_tls_client_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_DB_TLS_CLIENT_CERT_SOURCE",
            "FERRUM_DB_TLS_CLIENT_CERT_PATH",
            db_tls_client_cert_path,
        );
        let db_tls_client_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_DB_TLS_CLIENT_KEY_SOURCE",
            "FERRUM_DB_TLS_CLIENT_KEY_PATH",
            db_tls_client_key_path,
        );
        let cp_grpc_tls_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_CP_GRPC_TLS_CERT_SOURCE",
            "FERRUM_CP_GRPC_TLS_CERT_PATH",
            cp_grpc_tls_cert_path,
        );
        let cp_grpc_tls_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_CP_GRPC_TLS_KEY_SOURCE",
            "FERRUM_CP_GRPC_TLS_KEY_PATH",
            cp_grpc_tls_key_path,
        );
        let cp_grpc_tls_client_ca_path = resolve_tls_source_override(
            conf,
            "FERRUM_CP_GRPC_TLS_CLIENT_CA_SOURCE",
            "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH",
            cp_grpc_tls_client_ca_path,
        );
        let dp_grpc_tls_ca_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_DP_GRPC_TLS_CA_CERT_SOURCE",
            "FERRUM_DP_GRPC_TLS_CA_CERT_PATH",
            dp_grpc_tls_ca_cert_path,
        );
        let dp_grpc_tls_client_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_DP_GRPC_TLS_CLIENT_CERT_SOURCE",
            "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH",
            dp_grpc_tls_client_cert_path,
        );
        let dp_grpc_tls_client_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_DP_GRPC_TLS_CLIENT_KEY_SOURCE",
            "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH",
            dp_grpc_tls_client_key_path,
        );
        let tls_ca_bundle_path = resolve_tls_source_override(
            conf,
            "FERRUM_TLS_CA_BUNDLE_SOURCE",
            "FERRUM_TLS_CA_BUNDLE_PATH",
            tls_ca_bundle_path,
        );
        let backend_tls_client_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_BACKEND_TLS_CLIENT_CERT_SOURCE",
            "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH",
            backend_tls_client_cert_path,
        );
        let backend_tls_client_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE",
            "FERRUM_BACKEND_TLS_CLIENT_KEY_PATH",
            backend_tls_client_key_path,
        );
        let gateway_svid_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_GATEWAY_SVID_CERT_SOURCE",
            "FERRUM_GATEWAY_SVID_CERT_PATH",
            gateway_svid_cert_path,
        );
        let gateway_svid_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_GATEWAY_SVID_KEY_SOURCE",
            "FERRUM_GATEWAY_SVID_KEY_PATH",
            gateway_svid_key_path,
        );
        let gateway_svid_trust_bundle_path = resolve_tls_source_override(
            conf,
            "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_SOURCE",
            "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
            gateway_svid_trust_bundle_path,
        );
        // Normalize blank/whitespace SVID paths to "unset" so every consumer —
        // the no-identity startup gate and `load_gateway_svid_bundle` — agrees
        // that an empty `FERRUM_GATEWAY_SVID_*` value means "no material", not
        // `Some("")` (which would otherwise be treated as configured).
        let gateway_svid_cert_path = gateway_svid_cert_path.filter(|s| !s.trim().is_empty());
        let gateway_svid_key_path = gateway_svid_key_path.filter(|s| !s.trim().is_empty());
        let gateway_svid_trust_bundle_path =
            gateway_svid_trust_bundle_path.filter(|s| !s.trim().is_empty());
        // Same blank-means-unset normalization for the localized mesh config
        // file path so the `file` protocol's required-path validation can use
        // a plain presence check.
        let mesh_file_config_path = mesh_file_config_path.filter(|s| !s.trim().is_empty());
        // Blank-means-unset so the per-remote credential map is `None` (shared
        // secret fallback) rather than an empty-string JSON parse attempt.
        let mesh_remote_discovery_credentials =
            mesh_remote_discovery_credentials.filter(|s| !s.trim().is_empty());
        let dtls_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_DTLS_CERT_SOURCE",
            "FERRUM_DTLS_CERT_PATH",
            dtls_cert_path,
        );
        let dtls_key_path = resolve_tls_source_override(
            conf,
            "FERRUM_DTLS_KEY_SOURCE",
            "FERRUM_DTLS_KEY_PATH",
            dtls_key_path,
        );
        let dtls_client_ca_cert_path = resolve_tls_source_override(
            conf,
            "FERRUM_DTLS_CLIENT_CA_CERT_SOURCE",
            "FERRUM_DTLS_CLIENT_CA_CERT_PATH",
            dtls_client_ca_cert_path,
        );
        let tls_crl_file_path = resolve_tls_source_override(
            conf,
            "FERRUM_TLS_CRL_SOURCE",
            "FERRUM_TLS_CRL_FILE_PATH",
            tls_crl_file_path,
        );

        // Compose the raw allow-ips mode + CIDR overlays + baseline flag into
        // the resolved egress policy, shadowing the bare-mode local. Invalid
        // CIDR entries fail startup loudly rather than silently opening egress.
        let backend_allow_ips = BackendEgressPolicy::from_env(
            backend_allow_ips,
            &backend_allow_cidrs,
            &backend_deny_cidrs,
            backend_block_dangerous_ranges,
        )?;

        let mut config = Self {
            mode: mode.clone(),
            namespace,
            log_level,
            log_buffer_capacity,
            log_buffer_bytes,
            log_max_record_bytes,
            log_shutdown_drain_timeout_ms,
            log_delivery_max_tasks,
            secret_refresh_interval_seconds,
            acme_auto_renew_enabled,
            acme_renew_when_remaining_days,
            acme_renew_check_interval_seconds,
            acme_renew_challenge_type,
            acme_renew_poll_timeout_seconds,
            acme_dns01_hook_command,
            acme_dns01_propagation_seconds,
            enable_streaming_latency_tracking,
            proxy_http_port,
            proxy_https_port,
            compression_gzip_enabled,
            compression_brotli_enabled,
            frontend_tls_cert_path,
            frontend_tls_key_path,
            frontend_tls_live_reload_enabled,
            frontend_tls_watch_interval_seconds,
            backend_tls_live_reload_enabled,
            backend_tls_watch_interval_seconds,
            proxy_bind_address,
            admin_http_port,
            admin_https_port,
            admin_tls_cert_path,
            admin_tls_key_path,
            admin_bind_address,
            allow_insecure_admin_http,
            admin_jwt_secret,
            admin_jwt_issuer,
            admin_jwt_max_ttl,
            admin_jwt_audience,
            db_type,
            db_url,
            db_poll_interval,
            db_rejected_delta_backoff_initial_seconds,
            db_rejected_delta_backoff_max_seconds,
            db_rejected_delta_full_reload_threshold,
            db_tls_mode,
            db_tls_ca_cert_path,
            db_tls_client_cert_path,
            db_tls_client_key_path,
            db_tls_live_reload_enabled,
            db_tls_watch_interval_seconds,
            file_config_path,
            db_config_backup_path,
            db_failover_urls,
            db_read_replica_url,
            db_slow_query_threshold_ms,
            db_full_load_page_size,
            db_pool_max_connections,
            db_pool_min_connections,
            db_pool_acquire_timeout_seconds,
            db_pool_idle_timeout_seconds,
            db_pool_max_lifetime_seconds,
            db_pool_connect_timeout_seconds,
            db_pool_statement_timeout_seconds,
            mongo_database,
            mongo_app_name,
            mongo_replica_set,
            mongo_auth_mechanism,
            mongo_server_selection_timeout_seconds,
            mongo_connect_timeout_seconds,
            cp_grpc_listen_addr,
            cp_dp_grpc_jwt_secret,
            cp_dp_grpc_jwt_issuer,
            dp_cp_grpc_urls,
            dp_cp_failover_primary_retry_secs,
            cp_dp_grpc_allow_plaintext,
            cp_grpc_tls_cert_path,
            cp_grpc_tls_key_path,
            cp_grpc_tls_client_ca_path,
            cp_grpc_max_connections,
            cp_grpc_max_connections_per_ip,
            cp_broadcast_channel_capacity,
            cp_namespaces,
            cp_require_namespace_claim,
            xds_enabled,
            xds_stream_channel_capacity,
            xds_max_streams_per_node,
            mesh_ca_backend,
            mesh_spire_agent_socket,
            mesh_cert_ttl_seconds,
            mesh_config_protocol,
            mesh_file_config_path,
            mesh_trust_domain_aliases,
            mesh_trusted_hbone_assertors,
            mesh_egress_strip_baggage_keys,
            mesh_outbound_traffic_policy,
            mesh_outbound_registry_reject_status,
            mesh_sidecar_enforced,
            mesh_sidecar_enforced_dry_run,
            mesh_sidecar_identity_narrowing,
            mesh_egress_stream_enabled,
            mesh_egress_stream_allow_plaintext,
            mesh_peer_auth_live_reload_enabled,
            mesh_request_auth_require_exp,
            mesh_federation_poll_interval_seconds,
            mesh_federation_poll_timeout_seconds,
            mesh_federation_max_stale_seconds,
            mesh_federation_fail_open,
            mesh_remote_discovery_poll_interval_seconds,
            mesh_remote_discovery_poll_timeout_seconds,
            mesh_remote_discovery_max_stale_seconds,
            mesh_remote_discovery_credentials,
            mesh_locality_lb_strict,
            mesh_node_waypoint_cgroup_sweep_interval_secs,
            mesh_node_waypoint_idle_gc_interval_secs,
            mesh_node_waypoint_pod_registry_dir,
            mesh_svid_rotation_drain_seconds,
            mesh_policy_deny_log_capacity,
            node_agent_proxy_mode,
            node_agent_admin_enabled,
            node_agent_hbone_redirect_port,
            node_agent_cni_enabled,
            node_agent_cni_socket_path,
            k8s_controller_enabled,
            k8s_pod_discovery_enabled,
            k8s_controller_namespace,
            k8s_node_locality_enabled,
            k8s_watch_namespaces,
            k8s_kubeconfig_path,
            k8s_reconcile_debounce_ms,
            k8s_full_sync_interval_secs,
            k8s_watch_istio_crds,
            k8s_watch_mesh_config,
            k8s_watch_gateway_api_crds,
            k8s_trust_domain,
            k8s_cluster_domain,
            k8s_istio_root_namespace,
            gateway_api_data_plane_service_namespace,
            gateway_api_data_plane_service_name,
            gateway_api_status_address,
            dp_grpc_tls_ca_cert_path,
            dp_grpc_tls_client_cert_path,
            dp_grpc_tls_client_key_path,
            dp_grpc_tls_no_verify,
            max_header_size_bytes,
            max_single_header_size_bytes,
            max_header_count,
            max_request_body_size_bytes,
            max_response_body_size_bytes,
            response_buffer_cutoff_bytes,
            h2_coalesce_target_bytes,
            max_url_length_bytes,
            max_query_params,
            max_grpc_recv_size_bytes,
            max_websocket_frame_size_bytes,
            websocket_write_buffer_size,
            websocket_tunnel_mode,
            websocket_idle_timeout_seconds,
            max_credentials_per_type,
            http_header_read_timeout_seconds,
            frontend_tls_handshake_timeout_seconds,
            dns_overrides,
            dns_resolver_address,
            dns_resolver_hosts_file,
            dns_order,
            dns_ttl_override,
            dns_min_ttl,
            dns_stale_ttl,
            dns_error_ttl,
            dns_cache_max_size,
            dns_warmup_concurrency,
            dns_slow_threshold_ms,
            dns_refresh_threshold_percent,
            dns_failed_retry_interval,
            dns_try_tcp_on_error,
            dns_num_concurrent_reqs,
            dns_max_active_requests,
            dns_max_concurrent_refreshes,
            tls_ca_bundle_path,
            backend_tls_client_cert_path,
            backend_tls_client_key_path,
            gateway_svid_cert_path,
            gateway_svid_key_path,
            gateway_svid_trust_bundle_path,
            gateway_spiffe_id,
            frontend_tls_client_ca_bundle_path,
            frontend_tls_ocsp_response_source,
            admin_tls_ocsp_response_source,
            admin_tls_client_ca_bundle_path,
            tls_no_verify,
            admin_read_only,
            admin_audit_enabled,
            audit_retention_days,
            audit_retention_max_rows,
            admin_require_namespace_claim,
            admin_tls_no_verify,
            enable_http3,
            http3_idle_timeout,
            http3_max_streams,
            http3_stream_receive_window,
            http3_receive_window,
            http3_send_window,
            http3_connections_per_backend,
            http3_pool_idle_timeout_seconds,
            http3_coalesce_min_bytes,
            http3_coalesce_max_bytes,
            http3_flush_interval_micros,
            http3_request_body_channel_capacity,
            http3_websocket_enabled,
            h3_request_body_drain_ms,
            http3_initial_mtu,
            grpc_pool_ready_wait_ms,
            pool_warmup_enabled,
            pool_warmup_concurrency,
            pool_cleanup_interval_seconds,
            backend_capability_refresh_interval_secs,
            router_cache_max_entries,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            udp_recvmmsg_batch_size,
            adaptive_buffer_enabled,
            adaptive_batch_limit_enabled,
            adaptive_buffer_ewma_alpha,
            adaptive_buffer_min_size,
            adaptive_buffer_max_size,
            adaptive_buffer_default_size,
            adaptive_batch_limit_default,
            tls_min_version,
            tls_max_version,
            tls_cipher_suites,
            tls_prefer_server_cipher_order,
            tls_curves,
            tls_session_cache_size,
            tls_cert_expiry_warning_days,
            tls_inventory_snapshot_ttl_seconds,
            tls_early_data_methods,
            stream_proxy_bind_address,
            dtls_cert_path,
            dtls_key_path,
            dtls_client_ca_cert_path,
            dtls_max_plaintext_bytes,
            dtls_record_overhead_bytes,
            trusted_proxies,
            backend_allow_ips,
            add_via_header,
            via_pseudonym,
            add_forwarded_header,
            real_ip_header,
            basic_auth_hmac_secret,
            plugin_http_slow_threshold_ms,
            plugin_http_max_retries,
            plugin_http_retry_delay_ms,
            tls_crl_file_path,
            admin_allowed_cidrs,
            metrics_allowed_cidrs,
            metrics_bearer_token,
            admin_max_connections,
            admin_max_connections_per_ip,
            admin_restore_max_body_size_mib,
            admin_spec_max_body_size_mib,
            admin_body_read_timeout_seconds,
            admin_http2_max_concurrent_streams,
            admin_http2_max_header_list_size_bytes,
            migrate_action,
            migrate_dry_run,
            auto_apply_plugin_migrations,
            worker_threads,
            blocking_threads,
            max_connections,
            max_requests,
            max_concurrent_requests_per_ip,
            per_ip_cleanup_interval_seconds,
            circuit_breaker_cache_max_entries,
            pool_shard_amount,
            status_counts_max_entries,
            runtime_metrics_system_sample_interval_ms,
            runtime_metrics_window_1m_seconds,
            runtime_metrics_window_5m_seconds,
            runtime_metrics_log_counter_enabled,
            runtime_metrics_cache_ttl_ms,
            runtime_metrics_pool_tracking_enabled,
            runtime_metrics_status_tracking_enabled,
            tcp_listen_backlog,
            accept_threads,
            frontend_h2_initial_stream_window_size,
            frontend_h2_initial_connection_window_size,
            frontend_h2_max_frame_size,
            server_http2_max_concurrent_streams,
            server_http2_max_pending_accept_reset_streams,
            server_http2_max_local_error_reset_streams,
            websocket_max_connections,
            overload_check_interval_ms,
            overload_fd_pressure_threshold,
            overload_fd_critical_threshold,
            overload_conn_pressure_threshold,
            overload_conn_critical_threshold,
            overload_req_pressure_threshold,
            overload_req_critical_threshold,
            overload_loop_warn_us,
            overload_loop_critical_us,
            shutdown_drain_seconds,
            status_metrics_window_seconds,
            tls_offload_threads,
            tcp_fastopen_enabled,
            tcp_fastopen_queue_len,
            ktls_enabled,
            io_uring_splice_enabled,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            so_busy_poll_us,
        };

        config.validate()?;
        Ok(config)
    }

    /// Build a `SocketAddr` from the proxy bind address and the given port.
    /// The bind address is validated at config load time, so the parse is safe.
    /// Build an [`OverloadConfig`] from the parsed env vars.
    pub fn overload_config(&self) -> crate::overload::OverloadConfig {
        crate::overload::OverloadConfig {
            check_interval_ms: self.overload_check_interval_ms,
            fd_pressure_threshold: self.overload_fd_pressure_threshold,
            fd_critical_threshold: self.overload_fd_critical_threshold,
            conn_pressure_threshold: self.overload_conn_pressure_threshold,
            conn_critical_threshold: self.overload_conn_critical_threshold,
            req_pressure_threshold: self.overload_req_pressure_threshold,
            req_critical_threshold: self.overload_req_critical_threshold,
            loop_warn_us: self.overload_loop_warn_us,
            loop_critical_us: self.overload_loop_critical_us,
        }
    }

    pub fn proxy_socket_addr(&self, port: u16) -> std::net::SocketAddr {
        let ip: std::net::IpAddr = self
            .proxy_bind_address
            .parse()
            .expect("proxy_bind_address validated at config load");
        std::net::SocketAddr::new(ip, port)
    }

    /// Build a `SocketAddr` from the admin bind address and the given port.
    pub fn admin_socket_addr(&self, port: u16) -> std::net::SocketAddr {
        let ip: std::net::IpAddr = self
            .admin_bind_address
            .parse()
            .expect("admin_bind_address validated at config load");
        std::net::SocketAddr::new(ip, port)
    }

    /// Whether a **binary-owned** admin HTTPS listener should be started: TLS
    /// cert and key are configured AND `FERRUM_ADMIN_HTTPS_PORT` is not the
    /// disable sentinel (`0`). Every serving mode must gate creation of a
    /// listener it binds itself, plus the matching TLS reload watchers and
    /// startup signals, on this predicate — with port 0 the process must never
    /// bind an ephemeral admin HTTPS socket.
    ///
    /// This predicate is deliberately EnvConfig-only, so it does not describe
    /// listeners the process did not bind. Embedded file mode
    /// (`file::serve` with `ServeOptions.admin_https`) can serve a caller-owned,
    /// already-bound HTTPS socket under port 0 when both admin TLS paths are
    /// configured: the pre-bound listener wins over the port setting, loads
    /// the TLS material, and sets up frontend TLS live reload, starting the
    /// watcher when enabled. Without both TLS paths, file mode drops the socket
    /// unused. The `ferrum-edge` binary never passes a pre-bound socket, so for
    /// the binary this predicate alone decides the listener.
    ///
    /// It is also config-level, and therefore says nothing about
    /// `secrets::resolve_all_env_secrets()`, which runs before `EnvConfig` is
    /// parsed: suffixed admin TLS inputs are resolved (and can fail startup)
    /// regardless of this gate.
    pub fn admin_https_listener_enabled(&self) -> bool {
        self.admin_https_port != 0
            && self.admin_tls_cert_path.is_some()
            && self.admin_tls_key_path.is_some()
    }

    /// Classify the network exposure of the **plaintext** admin HTTP listener
    /// (`FERRUM_ADMIN_HTTP_PORT`). This is independent of whether an admin
    /// HTTPS listener is also configured: a TLS listener on the HTTPS port does
    /// not protect the separate plaintext HTTP port. To run admin TLS-only, set
    /// `FERRUM_ADMIN_HTTP_PORT=0`.
    ///
    /// Only a **loopback** bind is treated as safe. Any other bind — `0.0.0.0` /
    /// `::`, a public IP, or a private/VPC/link-local interface address — is
    /// reachable by other hosts on that network and is classified as exposed.
    pub fn admin_http_exposure(&self) -> AdminHttpExposure {
        if self.admin_http_port == 0 {
            return AdminHttpExposure::Disabled;
        }
        // An unparseable bind address is rejected separately in `validate()`;
        // treat it as non-exposing here so this method never panics.
        let Ok(ip) = self.admin_bind_address.parse::<std::net::IpAddr>() else {
            return AdminHttpExposure::Loopback;
        };
        // Loopback (127.0.0.0/8, ::1) is the only bind reachable solely from
        // within the host. Everything else (unspecified/public/private/
        // link-local) is reachable beyond loopback and must be protected.
        if ip.is_loopback() {
            return AdminHttpExposure::Loopback;
        }
        // An empty allowlist — or a catch-all one (a `/0` CIDR like `0.0.0.0/0`,
        // `::/0`, or an IPv4-mapped spelling the filter folds to a `/0`, which
        // the admin middleware then matches against every source) — provides no
        // real restriction, so the listener is still unrestricted. Reuse the
        // runtime filter's own canonicalization via `cidr_list_permits_all`.
        if self.admin_allowed_cidrs.trim().is_empty()
            || crate::proxy::client_ip::TrustedProxies::cidr_list_permits_all(
                &self.admin_allowed_cidrs,
            )
        {
            AdminHttpExposure::ReachableUnrestricted
        } else {
            AdminHttpExposure::ReachableAllowlisted
        }
    }

    /// Hard-fail guard for the admin API. Returns `Some(error)` when a
    /// `database`/`cp`-mode gateway would start a plaintext admin HTTP listener
    /// reachable beyond loopback with no (effective) `FERRUM_ADMIN_ALLOWED_CIDRS`
    /// allowlist and without the explicit `FERRUM_ALLOW_INSECURE_ADMIN_HTTP` dev
    /// opt-in.
    ///
    /// `FERRUM_ADMIN_READ_ONLY=true` blocks admin mutations, but it is not a
    /// substitute for loopback binding, TLS-only admin, or an effective IP
    /// allowlist: read-only admin still serves sensitive management-plane reads
    /// (for example unredacted backups), and plaintext listeners still expose
    /// operator bearer tokens on the network. The read-only modes
    /// (`file`/`dp`/`mesh`) warn instead of failing; the node-agent admin listener
    /// has its own safe-by-default loopback fallback.
    ///
    /// Pure (reads only `self`), so it is unit-testable without touching the
    /// process environment.
    pub fn admin_insecure_plaintext_startup_error(&self) -> Option<String> {
        if !matches!(
            self.mode,
            OperatingMode::Database | OperatingMode::ControlPlane
        ) {
            return None;
        }
        if self.admin_http_exposure() != AdminHttpExposure::ReachableUnrestricted {
            return None;
        }
        if self.allow_insecure_admin_http {
            return None;
        }
        Some(format!(
            "Refusing to start {mode:?} mode: the plaintext admin HTTP listener \
             (FERRUM_ADMIN_HTTP_PORT={port}) is bound to '{bind}', a non-loopback address \
             reachable beyond this host, with no FERRUM_ADMIN_ALLOWED_CIDRS allowlist. The \
             admin API (read endpoints still serve sensitive management-plane data, e.g. \
             unredacted backups) and any operator bearer tokens would be served in cleartext to \
             every host that can route to it (a private/VPC interface IP is still LAN-reachable). \
             Choose one: \
             (1) bind admin to loopback — FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1; \
             (2) restrict callers — FERRUM_ADMIN_ALLOWED_CIDRS=<cidr-list>; \
             (3) serve admin over TLS and disable plaintext — set FERRUM_ADMIN_TLS_CERT_PATH \
             and FERRUM_ADMIN_TLS_KEY_PATH, then FERRUM_ADMIN_HTTP_PORT=0; \
             or (4) for local development only — FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true.",
            mode = self.mode,
            port = crate::secrets::report_env_field(
                "FERRUM_ADMIN_HTTP_PORT",
                &self.admin_http_port.to_string()
            ),
            bind = crate::secrets::report_env_field(
                "FERRUM_ADMIN_BIND_ADDRESS",
                &self.admin_bind_address
            ),
        ))
    }

    /// Returns the resolved list of CP gRPC URLs for DP failover, priority-ordered.
    pub fn resolved_dp_cp_grpc_urls(&self) -> Vec<String> {
        self.dp_cp_grpc_urls.clone()
    }

    /// Collect all ports reserved by the gateway's own listeners.
    ///
    /// Stream proxy `listen_port` values must not collide with these ports.
    /// Includes proxy HTTP/HTTPS, admin HTTP/HTTPS, and CP gRPC (when configured).
    pub fn reserved_gateway_ports(&self) -> std::collections::HashSet<u16> {
        let mut ports = std::collections::HashSet::new();
        // Port 0 means "disabled" — skip it so stream proxy validation
        // doesn't treat 0 as a reserved conflict.
        for &p in &[
            self.proxy_http_port,
            self.proxy_https_port,
            self.admin_http_port,
            self.admin_https_port,
        ] {
            if p != 0 {
                ports.insert(p);
            }
        }
        // CP gRPC listen address is "host:port" — extract the port if present.
        if let Some(ref addr) = self.cp_grpc_listen_addr
            && let Some(port_str) = addr.rsplit(':').next()
            && let Ok(port) = port_str.parse::<u16>()
            && port != 0
        {
            ports.insert(port);
        }
        // Mesh UDP TPROXY capture listener port (F3 §3.3): when UDP capture is
        // enabled the mesh runtime binds a real UDP socket on this port, so
        // reserve it for stream-listener validation. Otherwise a mesh UDP/DTLS
        // stream proxy or ServiceEntry declaring the same listen port passes
        // validation and then races the capture listener at startup, failing one
        // UDP bind and aborting startup (codex r4). Default-off, so non-capture
        // deployments are unaffected; a malformed setting is handled fail-closed
        // by the dedicated startup validation, so a parse error is ignored here.
        //
        // SIDECAR only (#2013): the CURRENT-netns capture listener
        // (`MeshRuntimeConfig::udp_capture_listener()`) binds this port in the
        // sidecar's own (pod) netns, so a UDP/DTLS stream proxy or ServiceEntry
        // declaring the same listen port would race that bind at startup —
        // reserve it. AMBIENT no longer binds a host-netns listener: its
        // per-pod-netns UDP producer (`NetnsUdpCaptureManager`) binds the capture
        // socket INSIDE each enrolled pod's netns, so the mesh proxy's OWN (host)
        // netns leaves this port free and reserving it here would wrongly reject a
        // valid host-netns UDP/DTLS stream proxy on it. So gate the reservation on
        // the SAME condition `udp_capture_listener()` now uses: Sidecar emits the
        // listener; Ambient/other return `None`. UNSET `FERRUM_MESH_TOPOLOGY`
        // defaults to `sidecar` in `MeshRuntimeConfig::from_env_config` (which
        // binds the listener), so treat unset as `sidecar` here too, or a UDP/DTLS
        // stream proxy on it would pass validation then race the sidecar's bind.
        // MESH MODE ONLY (codex r2): `reserved_gateway_ports()` is shared by
        // file/database/CP/DP validation, where no mesh capture listener ever binds
        // (`MeshRuntimeConfig::listener_plan()` runs only in mesh mode). Reserving
        // the mesh-only UDP capture port outside mesh mode would wrongly reject a
        // valid UDP/DTLS stream proxy or ServiceEntry on it.
        let udp_capture_topology =
            crate::config::conf_file::resolve_ferrum_var("FERRUM_MESH_TOPOLOGY")
                .unwrap_or_else(|| "sidecar".to_string());
        let udp_capture_topology = udp_capture_topology.trim();
        if self.mode == OperatingMode::Mesh
            && let Ok(udp) = crate::capture::udp_capture_settings_from_env()
            && udp.udp_capture_enabled
            && udp.udp_outbound_port != 0
            && udp_capture_topology.eq_ignore_ascii_case("sidecar")
        {
            ports.insert(udp.udp_outbound_port);
        }
        ports
    }

    fn append_db_tls_params_to_url(&self, base_url: &str, db_type: &str) -> Result<String, String> {
        let Some(mode) = self.db_tls_mode else {
            return Ok(base_url.to_string());
        };

        if db_type == "mongodb"
            && let Some(source) = Self::mongodb_uri_tls_source(base_url)
        {
            return Err(format!(
                "FERRUM_DB_TLS_MODE conflicts with MongoDB URI TLS settings ({source}) in {}. Configure MongoDB TLS in exactly one source",
                redact_url(base_url)
            ));
        }

        Self::warn_on_existing_db_tls_url_params(base_url, db_type);

        let Some(params) = self.db_tls_params(db_type, mode)? else {
            return Ok(base_url.to_string());
        };

        if params.is_empty() {
            return Ok(base_url.to_string());
        }

        let separator = if base_url.contains('?') { "&" } else { "?" };
        Ok(format!("{}{}{}", base_url, separator, params.join("&")))
    }

    fn db_tls_params(&self, db_type: &str, mode: DbTlsMode) -> Result<Option<Vec<String>>, String> {
        let mut params = Vec::new();

        match db_type {
            "postgres" => {
                params.push(format!("sslmode={}", mode.postgres_value()));
                if mode.enables_tls() {
                    if matches!(mode, DbTlsMode::VerifyCa | DbTlsMode::VerifyFull)
                        && let Some(ref cert) = self.db_tls_ca_cert_path
                    {
                        params.push(format!(
                            "sslrootcert={}",
                            Self::db_tls_source_param_value(
                                cert,
                                crate::tls::source::MaterialKind::CaBundle,
                                "ferrum-db-ca-",
                            )?
                        ));
                    }
                    if let Some(ref cert) = self.db_tls_client_cert_path {
                        params.push(format!(
                            "sslcert={}",
                            Self::db_tls_source_param_value(
                                cert,
                                crate::tls::source::MaterialKind::Cert,
                                "ferrum-db-client-cert-",
                            )?
                        ));
                    }
                    if let Some(ref key) = self.db_tls_client_key_path {
                        params.push(format!(
                            "sslkey={}",
                            Self::db_tls_source_param_value(
                                key,
                                crate::tls::source::MaterialKind::Key,
                                "ferrum-db-client-key-",
                            )?
                        ));
                    }
                }
            }
            "mysql" => {
                let mysql_mode = mode.mysql_value()?;
                params.push(format!("ssl-mode={}", mysql_mode));
                if mode.enables_tls() {
                    if matches!(mode, DbTlsMode::VerifyCa | DbTlsMode::VerifyFull)
                        && let Some(ref cert) = self.db_tls_ca_cert_path
                    {
                        params.push(format!(
                            "ssl-ca={}",
                            Self::db_tls_source_param_value(
                                cert,
                                crate::tls::source::MaterialKind::CaBundle,
                                "ferrum-db-ca-",
                            )?
                        ));
                    }
                    if let Some(ref cert) = self.db_tls_client_cert_path {
                        params.push(format!(
                            "ssl-cert={}",
                            Self::db_tls_source_param_value(
                                cert,
                                crate::tls::source::MaterialKind::Cert,
                                "ferrum-db-client-cert-",
                            )?
                        ));
                    }
                    if let Some(ref key) = self.db_tls_client_key_path {
                        params.push(format!(
                            "ssl-key={}",
                            Self::db_tls_source_param_value(
                                key,
                                crate::tls::source::MaterialKind::Key,
                                "ferrum-db-client-key-",
                            )?
                        ));
                    }
                }
            }
            _ => return Ok(None),
        }

        Ok(Some(params))
    }

    fn db_tls_source_param_value(
        source_value: &str,
        kind: crate::tls::source::MaterialKind,
        temp_prefix: &str,
    ) -> Result<String, String> {
        let source = crate::tls::source::CertSource::parse(source_value, kind);
        if let Some(path) = source.as_file_path() {
            return Ok(path.display().to_string());
        }

        let source_id = source.redacted_source_id();
        let material = crate::tls::source::load_material_blocking(&source, kind)
            .map_err(|e| format!("Failed to load database TLS material: {e}"))?;
        let temp_file = tempfile::Builder::new()
            .prefix(temp_prefix)
            .suffix(".pem")
            .tempfile()
            .map_err(|e| format!("Failed to create database TLS temp PEM file: {e}"))?;
        let (_file, material_path) = temp_file.keep().map_err(|e| {
            format!(
                "Failed to persist database TLS temp PEM file '{}': {}",
                e.file.path().display(),
                e.error
            )
        })?;
        std::fs::write(&material_path, material.bytes.expose_secret()).map_err(|e| {
            format!(
                "Failed to write database TLS material to '{}': {}",
                material_path.display(),
                e
            )
        })?;
        tracing::info!(
            "Materialized database TLS source {} into {}",
            source_id,
            material_path.display()
        );
        Ok(material_path.display().to_string())
    }

    fn warn_on_existing_db_tls_url_params(base_url: &str, db_type: &str) {
        let existing = Self::existing_db_tls_url_params(base_url, db_type);
        if existing.is_empty() {
            return;
        }

        let existing_tls_params = existing.join(",");
        let redacted_url = redact_url(base_url);
        match db_type {
            "postgres" | "mysql" => tracing::warn!(
                db_type,
                url = %redacted_url,
                existing_tls_params = %existing_tls_params,
                "FERRUM_DB_TLS_MODE is set but the database URL already contains potentially TLS-related query parameters; env-derived TLS parameters will be appended and duplicate or overlapping driver options can be ambiguous. Remove URL TLS parameters or unset FERRUM_DB_TLS_MODE"
            ),
            _ => {}
        }
    }

    fn existing_db_tls_url_params(base_url: &str, db_type: &str) -> Vec<String> {
        let tls_param_names = Self::db_tls_url_param_names(db_type);
        if tls_param_names.is_empty() {
            return Vec::new();
        }

        let Ok(parsed) = url::Url::parse(base_url) else {
            return Vec::new();
        };

        let mut existing = Vec::new();
        for (name, _) in parsed.query_pairs() {
            let name = name.to_ascii_lowercase();
            if tls_param_names.iter().any(|known| name == *known) && !existing.contains(&name) {
                existing.push(name);
            }
        }
        existing
    }

    fn mongodb_uri_tls_source(base_url: &str) -> Option<String> {
        let explicit = Self::mongodb_uri_tls_query_params(base_url);
        if !explicit.is_empty() {
            return Some(explicit.join(","));
        }
        if base_url
            .get(..14)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("mongodb+srv://"))
        {
            return Some("mongodb+srv implicit TLS".to_string());
        }
        None
    }

    /// Extract MongoDB TLS/SSL query option names from a connection string
    /// without going through `url::Url`, which rejects the common multi-host
    /// seed-list authority (`mongodb://db0:27017,db1:27017/ferrum?tls=true`) as
    /// unparseable and would silently miss the TLS option. Only the query
    /// portion is inspected, so no credential/authority material is retained.
    fn mongodb_uri_tls_query_params(base_url: &str) -> Vec<String> {
        let tls_param_names = Self::db_tls_url_param_names("mongodb");
        let Some((_, query)) = base_url.rsplit_once('?') else {
            return Vec::new();
        };
        // Strip any fragment and split on the `&`/`;` option separators that
        // MongoDB connection strings accept.
        let query = query.split('#').next().unwrap_or(query);
        let mut existing = Vec::new();
        for pair in query.split(['&', ';']) {
            let Some((name, _)) = url::form_urlencoded::parse(pair.as_bytes()).next() else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            if tls_param_names.iter().any(|known| name == *known) && !existing.contains(&name) {
                existing.push(name);
            }
        }
        existing
    }

    fn db_tls_url_param_names(db_type: &str) -> &'static [&'static str] {
        match db_type {
            "postgres" => &["sslmode", "sslrootcert", "sslcert", "sslkey", "tls", "ssl"],
            "mysql" => &[
                "ssl-mode", "ssl_mode", "ssl-ca", "ssl_ca", "ssl-cert", "ssl_cert", "ssl-key",
                "ssl_key", "tls", "ssl",
            ],
            "mongodb" => &[
                "tls",
                "ssl",
                "tlsinsecure",
                "tlsallowinvalidcertificates",
                "tlsallowinvalidhostnames",
                "tlscafile",
                "tlscertificatekeyfile",
                "tlscertificatekeyfilepassword",
                "tlsdisableocspendpointcheck",
            ],
            _ => &[],
        }
    }

    pub fn db_tls_enabled(&self) -> bool {
        self.db_tls_mode.is_some_and(DbTlsMode::enables_tls)
    }

    pub fn mongodb_tls_allows_invalid_certs(&self) -> bool {
        // SECURITY: MongoDB maps `FERRUM_DB_TLS_MODE=require` to
        // `TlsOptions::allow_invalid_certificates=true`: encryption is required,
        // but server CA and hostname verification are intentionally disabled.
        self.db_tls_mode
            .is_some_and(DbTlsMode::allows_invalid_certificates)
    }

    /// Returns the database URL with canonical `FERRUM_DB_TLS_*` query
    /// parameters appended for PostgreSQL and MySQL. SQLite and MongoDB URLs are
    /// returned unchanged: SQLite has no network TLS, and MongoDB uses driver
    /// `TlsOptions` or MongoDB URI TLS options.
    ///
    /// The `Err` path is reachable only if `validate_db_tls_config()` was not
    /// called first (defense-in-depth for invalid backend+mode combos).
    pub fn effective_db_url(&self) -> Result<Option<String>, String> {
        let Some(base_url) = self.db_url.as_ref() else {
            return Ok(None);
        };
        let db_type = self.db_type.as_deref().unwrap_or("");
        self.append_db_tls_params_to_url(base_url, db_type)
            .map(Some)
    }

    /// Resolve the gateway SQL backend for secondary SQL consumers that must
    /// track the configuration database.
    ///
    /// Reads only `FERRUM_DB_TYPE`, `FERRUM_DB_URL`, and `FERRUM_DB_TLS_*`
    /// through the same environment-over-`ferrum.conf` path as
    /// [`Self::from_env`], then applies [`Self::effective_db_url`] so PostgreSQL
    /// and MySQL receive the canonical TLS query parameters. Unlike
    /// [`Self::from_env`], this does **not** require a complete gateway mode
    /// configuration (JWT secrets, file paths, CP/DP settings, etc.).
    ///
    /// MongoDB is rejected because callers need a SQL pool. Errors never include
    /// the raw database URL or credentials.
    pub fn resolve_effective_sql_backend() -> Result<EffectiveSqlBackend, String> {
        use env_config_macro::EnvValue;

        let db_tls_mode = match crate::config::conf_file::resolve_ferrum_var("FERRUM_DB_TLS_MODE") {
            Some(raw) => Some(DbTlsMode::parse_env(&raw, "FERRUM_DB_TLS_MODE")?),
            None => None,
        };

        let cfg = Self {
            db_type: crate::config::conf_file::resolve_ferrum_var("FERRUM_DB_TYPE"),
            db_url: crate::config::conf_file::resolve_ferrum_var("FERRUM_DB_URL"),
            db_tls_mode,
            db_tls_ca_cert_path: resolve_cached_tls_source_override(
                "FERRUM_DB_TLS_CA_CERT_SOURCE",
                "FERRUM_DB_TLS_CA_CERT_PATH",
            ),
            db_tls_client_cert_path: resolve_cached_tls_source_override(
                "FERRUM_DB_TLS_CLIENT_CERT_SOURCE",
                "FERRUM_DB_TLS_CLIENT_CERT_PATH",
            ),
            db_tls_client_key_path: resolve_cached_tls_source_override(
                "FERRUM_DB_TLS_CLIENT_KEY_SOURCE",
                "FERRUM_DB_TLS_CLIENT_KEY_PATH",
            ),
            ..Self::default()
        };

        cfg.effective_sql_backend()
    }

    /// Derive an [`EffectiveSqlBackend`] from an already-populated config.
    ///
    /// Prefer [`Self::resolve_effective_sql_backend`] when loading from the
    /// process environment / `ferrum.conf`. This method is useful for tests that
    /// construct a partial [`EnvConfig`] without opening a network connection.
    pub fn effective_sql_backend(&self) -> Result<EffectiveSqlBackend, String> {
        let db_type = self
            .db_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "FERRUM_DB_TYPE is required for SQL gateway database consumers".to_string()
            })?;

        if db_type == "mongodb" {
            return Err(
                "MongoDB is not supported for SQL-only gateway database consumers; \
                 use postgres, mysql, or sqlite"
                    .into(),
            );
        }

        match db_type {
            "postgres" | "mysql" | "sqlite" => {}
            other => {
                return Err(format!(
                    "unsupported FERRUM_DB_TYPE {} for SQL gateway database consumers \
                     (expected sqlite, postgres, or mysql)",
                    crate::secrets::quoted_env_value("FERRUM_DB_TYPE", other)
                ));
            }
        }

        self.validate_db_tls_config()?;

        let effective_url = self.effective_db_url()?.ok_or_else(|| {
            "FERRUM_DB_URL is required for SQL gateway database consumers".to_string()
        })?;

        Ok(EffectiveSqlBackend {
            db_type: db_type.to_string(),
            effective_url,
        })
    }

    /// Returns the read replica URL with database TLS query parameters appended,
    /// using the same logic as `effective_db_url()`.
    ///
    /// `FERRUM_DB_READ_REPLICA_URL` is a SQL-only feature: the MongoDB config
    /// store always reads from the primary and never opens a replica pool, so
    /// the value is ignored for `mongodb` backends. Returning `None` here keeps
    /// it consistent with that runtime behavior and, critically, prevents the
    /// shared `append_db_tls_params_to_url()` MongoDB URI-TLS-conflict check
    /// from failing startup over a stale/unused replica URI (e.g. one carrying
    /// `?tls=true`) that would never actually be used.
    pub fn effective_db_read_replica_url(&self) -> Result<Option<String>, String> {
        let db_type = self.db_type.as_deref().unwrap_or("");
        if db_type == "mongodb" {
            return Ok(None);
        }
        let Some(base_url) = self.db_read_replica_url.as_ref() else {
            return Ok(None);
        };
        self.append_db_tls_params_to_url(base_url, db_type)
            .map(Some)
    }

    /// Returns the failover database URLs with database TLS query parameters appended,
    /// using the same logic as `effective_db_url()`.
    pub fn effective_db_failover_urls(&self) -> Result<Vec<String>, String> {
        let db_type = self.db_type.as_deref().unwrap_or("");

        self.db_failover_urls
            .iter()
            .map(|base_url| self.append_db_tls_params_to_url(base_url, db_type))
            .collect()
    }

    fn validate_db_tls_config(&self) -> Result<(), String> {
        const DEPRECATED_DB_TLS_ENV_VARS: [&str; 6] = [
            "FERRUM_DB_TLS_ENABLED",
            "FERRUM_DB_TLS_INSECURE",
            "FERRUM_DB_SSL_MODE",
            "FERRUM_DB_SSL_ROOT_CERT",
            "FERRUM_DB_SSL_CLIENT_CERT",
            "FERRUM_DB_SSL_CLIENT_KEY",
        ];

        let deprecated_tls_vars: Vec<&str> = DEPRECATED_DB_TLS_ENV_VARS
            .into_iter()
            .filter(|name| std::env::var_os(name).is_some())
            .collect();
        if !deprecated_tls_vars.is_empty() {
            return Err(format!(
                "Deprecated database TLS environment variables are no longer supported: {}. Use FERRUM_DB_TLS_MODE and FERRUM_DB_TLS_{{CA_CERT_PATH,CLIENT_CERT_PATH,CLIENT_KEY_PATH}} instead.",
                deprecated_tls_vars.join(", ")
            ));
        }

        let Some(db_type) = self.db_type.as_deref() else {
            return Ok(());
        };

        let has_tls_material = self.db_tls_ca_cert_path.is_some()
            || self.db_tls_client_cert_path.is_some()
            || self.db_tls_client_key_path.is_some();

        let Some(mode) = self.db_tls_mode else {
            if has_tls_material {
                return Err(
                    "FERRUM_DB_TLS_MODE is required when database TLS certificate paths are set"
                        .into(),
                );
            }
            return Ok(());
        };

        if matches!(mode, DbTlsMode::Disable) && has_tls_material {
            return Err(
                "FERRUM_DB_TLS_* certificate paths cannot be set when FERRUM_DB_TLS_MODE=disable"
                    .into(),
            );
        }

        match (&self.db_tls_client_cert_path, &self.db_tls_client_key_path) {
            (Some(_), None) if db_type != "mongodb" => {
                return Err(
                    "FERRUM_DB_TLS_CLIENT_CERT_PATH is set but FERRUM_DB_TLS_CLIENT_KEY_PATH is missing: SQL database mTLS requires both client cert and key"
                        .into(),
                );
            }
            (None, Some(_)) => {
                return Err(
                    "FERRUM_DB_TLS_CLIENT_KEY_PATH is set but FERRUM_DB_TLS_CLIENT_CERT_PATH is missing: database mTLS requires a client cert when a client key is set"
                        .into(),
                );
            }
            _ => {}
        }

        match db_type {
            "postgres" => {}
            "mysql" => {
                if matches!(mode, DbTlsMode::Allow) {
                    return Err(
                        "FERRUM_DB_TLS_MODE=allow is PostgreSQL-only; MySQL supports disable, prefer, require, verify-ca, verify-full"
                            .into(),
                    );
                }
            }
            "mongodb" => {
                if matches!(
                    mode,
                    DbTlsMode::Allow | DbTlsMode::Prefer | DbTlsMode::VerifyCa
                ) {
                    return Err(
                        "MongoDB supports FERRUM_DB_TLS_MODE values: disable, require, verify-full. Use MongoDB URI TLS options for more specialized policies"
                            .into(),
                    );
                }
                for url in self.db_url.iter().chain(self.db_failover_urls.iter()) {
                    if let Some(source) = Self::mongodb_uri_tls_source(url) {
                        return Err(format!(
                            "FERRUM_DB_TLS_MODE conflicts with MongoDB URI TLS settings ({source}) in {}. Configure MongoDB TLS in exactly one source",
                            redact_url(url)
                        ));
                    }
                }
            }
            "sqlite" => {
                if matches!(mode, DbTlsMode::Disable) {
                    tracing::debug!(
                        "FERRUM_DB_TLS_MODE=disable is a no-op when FERRUM_DB_TYPE=sqlite"
                    );
                } else {
                    return Err("Database TLS settings are not valid when FERRUM_DB_TYPE=sqlite; SQLite has no network TLS. Use FERRUM_DB_TLS_MODE=disable only as a no-op, or remove database TLS settings.".into());
                }
            }
            _ => {}
        }

        if self.db_tls_ca_cert_path.is_some()
            && !matches!(mode, DbTlsMode::VerifyCa | DbTlsMode::VerifyFull)
        {
            return Err(
                "FERRUM_DB_TLS_CA_CERT_PATH requires FERRUM_DB_TLS_MODE=verify-ca or verify-full"
                    .into(),
            );
        }

        Ok(())
    }

    fn validate(&mut self) -> Result<(), String> {
        match &self.mode {
            OperatingMode::Database | OperatingMode::ControlPlane => {
                if self.db_type.is_none() {
                    return Err("FERRUM_DB_TYPE is required in database/cp mode".into());
                }
                if self.db_url.is_none() {
                    return Err("FERRUM_DB_URL is required in database/cp mode".into());
                }
            }
            OperatingMode::File => {
                if self.file_config_path.is_none() {
                    return Err("FERRUM_FILE_CONFIG_PATH is required in file mode".into());
                }
            }
            OperatingMode::DataPlane => {
                if self.dp_cp_grpc_urls.is_empty() {
                    return Err("FERRUM_DP_CP_GRPC_URLS is required in dp mode".into());
                }
            }
            OperatingMode::Mesh => {
                // Validate the protocol value before the per-protocol CP
                // requirements so a typo'd FERRUM_MESH_CONFIG_PROTOCOL fails
                // with the protocol error, not a misleading missing-CP-URL one.
                match self
                    .mesh_config_protocol
                    .trim()
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "native" | "xds" | "file" => {}
                    other => {
                        return Err(format!(
                            "Invalid FERRUM_MESH_CONFIG_PROTOCOL {}. \
                             Expected: native, xds, or file",
                            crate::secrets::quoted_env_value("FERRUM_MESH_CONFIG_PROTOCOL", other)
                        ));
                    }
                }
                // The localized `file` protocol has no control plane: the CP
                // URL and CP/DP JWT secret are not required (nor consumed).
                // Native/xDS keep both hard requirements, including the
                // minimum secret length the env macro used to enforce when
                // `required_for` still listed "mesh".
                let file_protocol = self
                    .mesh_config_protocol
                    .trim()
                    .eq_ignore_ascii_case("file");
                if file_protocol {
                    if self.mesh_file_config_path.is_none() {
                        return Err("FERRUM_MESH_FILE_CONFIG_PATH is required when \
                             FERRUM_MESH_CONFIG_PROTOCOL=file"
                            .into());
                    }
                } else {
                    if self.dp_cp_grpc_urls.is_empty() {
                        return Err("FERRUM_DP_CP_GRPC_URLS is required in mesh mode".into());
                    }
                    crate::config::env_config::env_config_macro::validate_required_string_in_modes(
                        "FERRUM_CP_DP_GRPC_JWT_SECRET",
                        self.cp_dp_grpc_jwt_secret.as_deref(),
                        &OperatingMode::Mesh,
                        &["mesh"],
                        crate::config::types::MIN_JWT_SECRET_LENGTH,
                    )?;
                }
                // Validate the mesh CA backend value (reject unknown strings).
                let mesh_ca_backend =
                    crate::identity::ca::CaBackend::from_str_lossy(&self.mesh_ca_backend)
                        .map_err(|e| format!("Invalid FERRUM_MESH_CA_BACKEND: {e}"))?;
                // File-based SVID material is the explicit identity override.
                // Blank paths were normalized to `None` at parse, so a presence
                // check is exact.
                let has_file_workload_identity = self.gateway_svid_cert_path.is_some()
                    && self.gateway_svid_key_path.is_some()
                    && self.gateway_svid_trust_bundle_path.is_some();
                if mesh_ca_backend != crate::identity::ca::CaBackend::None
                    && !has_file_workload_identity
                {
                    let workload_spiffe_id = crate::config::conf_file::resolve_ferrum_var(
                        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    )
                    .filter(|value| !value.trim().is_empty());
                    match workload_spiffe_id {
                        None => {
                            return Err(
                                "FERRUM_MESH_CA_BACKEND requires FERRUM_MESH_WORKLOAD_SPIFFE_ID so \
                                 the issued runtime SVID matches the local mesh workload identity"
                                    .into(),
                            );
                        }
                        Some(id) => {
                            // Parse it exactly like startup's
                            // `configured_mesh_workload_spiffe_id` so `validate`
                            // and mesh startup agree: a non-SPIFFE value (e.g.
                            // `not-a-spiffe-id`) must fail here, not silently pass
                            // settings validation then abort at boot.
                            crate::identity::SpiffeId::new(id).map_err(|e| {
                                format!(
                                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID must be a valid SPIFFE URI when \
                                     FERRUM_MESH_CA_BACKEND is enabled: {e}"
                                )
                            })?;
                        }
                    }
                    // Mirror `bootstrap_dev_root`'s refusal so `validate` agrees
                    // with startup: the internal self-signed CA only bootstraps in
                    // non-production with FERRUM_MESH_CA_BOOTSTRAP_DEV=true. Without
                    // this, `validate` reports OK for an internal-CA mesh that
                    // cannot actually start.
                    if mesh_ca_backend == crate::identity::ca::CaBackend::Internal {
                        if crate::identity::production_mode() {
                            return Err(
                                "FERRUM_MESH_CA_BACKEND=internal cannot bootstrap a self-signed root \
                                 under FERRUM_MESH_PRODUCTION_MODE=true; use file-based \
                                 FERRUM_GATEWAY_SVID_* material or FERRUM_MESH_CA_BACKEND=spire"
                                    .into(),
                            );
                        }
                        let bootstrap_dev = std::env::var("FERRUM_MESH_CA_BOOTSTRAP_DEV")
                            .map(|v| v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);
                        if !bootstrap_dev {
                            return Err(
                                "FERRUM_MESH_CA_BACKEND=internal requires FERRUM_MESH_CA_BOOTSTRAP_DEV=true \
                                 (dev/test only) to bootstrap its self-signed root"
                                    .into(),
                            );
                        }
                    }
                }
                // Validate the production-mode flag value loudly — like
                // `EnvConfig`'s bool parser — so a typo (e.g. `tru` / `yes`)
                // can't silently fall through to the non-production posture and
                // let the dev opt-out re-open the no-identity gate.
                if let Ok(raw) = std::env::var("FERRUM_MESH_PRODUCTION_MODE") {
                    let v = raw.trim().to_ascii_lowercase();
                    if !matches!(v.as_str(), "" | "true" | "false" | "1" | "0") {
                        return Err(format!(
                            "Invalid FERRUM_MESH_PRODUCTION_MODE value '{raw}'. \
                             Expected true, false, 1, or 0"
                        ));
                    }
                }
                if crate::identity::production_mode() {
                    if self.mesh_federation_poll_interval_seconds > 0
                        && self.mesh_federation_max_stale_seconds == 0
                    {
                        return Err(
                            "FERRUM_MESH_PRODUCTION_MODE=true requires \
                             FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS > 0 when federation \
                             polling is enabled; unbounded last-good trust bundles are dev/test only"
                                .into(),
                        );
                    }
                    // (FERRUM_DP_GRPC_TLS_NO_VERIFY is rejected unconditionally by
                    // validate_cp_dp_grpc_transport_security() — it is not honored
                    // on the tonic-managed CP/DP gRPC client, so it can never
                    // silently disable verification under remote discovery either.)
                    if self.mesh_remote_discovery_poll_interval_seconds > 0
                        && self.mesh_remote_discovery_max_stale_seconds == 0
                    {
                        return Err("FERRUM_MESH_PRODUCTION_MODE=true requires \
                             FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS > 0 when remote \
                             discovery is enabled; unbounded last-good endpoints are dev/test only"
                            .into());
                    }
                }
                // Advisory (any mode, never an error): with cross-cluster
                // remote endpoint discovery enabled and non-strict locality
                // LB, an ABSENT source locality makes the locality-aware LB
                // return mixed local + remote candidates even while local
                // endpoints are healthy (see the strict-mode doc on
                // `LoadBalancer` in src/load_balancer.rs). Cross-cluster
                // east-west GATEWAY failover targets are unaffected (always
                // local-first regardless of the flag); this only affects
                // plain remote workload endpoints from the Experimental
                // remote-discovery path.
                if self.mesh_remote_discovery_poll_interval_seconds > 0
                    && !self.mesh_locality_lb_strict
                {
                    tracing::warn!(
                        "FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0 with \
                         FERRUM_MESH_LOCALITY_LB_STRICT=false: if the local workload's source \
                         locality cannot be resolved, the locality-aware load balancer will mix \
                         remote-cluster endpoints into selection even while local endpoints are \
                         healthy. Recommend FERRUM_MESH_LOCALITY_LB_STRICT=true so an absent \
                         source locality fails closed to local endpoints (east-west gateway \
                         failover targets are already local-first and unaffected)."
                    );
                }
                // The running mesh's workload identity comes either from
                // file-based gateway SVID material (all three
                // FERRUM_GATEWAY_SVID_* paths, loaded together by
                // `load_gateway_svid_bundle`) or an automatic CA backend wired
                // at mesh startup (`FERRUM_MESH_CA_BACKEND=spire|internal`).
                let has_workload_identity = has_file_workload_identity
                    || mesh_ca_backend != crate::identity::ca::CaBackend::None;
                // Security gate: without a workload identity the mesh can neither
                // establish nor verify mTLS, so PeerAuthentication's PERMISSIVE
                // default would silently accept unauthenticated plaintext. Same
                // class of insecure dev posture as the self-signed CA bootstrap
                // and the static attestor, so it joins that guardrail family
                // (see .claude/rules/tls-security.md). The production guard and
                // the opt-out are BOTH read directly from the environment (not
                // ferrum.conf / EnvConfig) so a config-file-only value can never
                // make them disagree and silently re-open the posture.
                //
                // This stays the fast early *presence* check for the obvious
                // misconfig (no identity material named at all). It cannot see
                // whether the SVID files actually load, nor whether the resolved
                // PeerAuthentication mode would still leave the inbound listener
                // serving plaintext. The robust runtime complement (#1523) closes
                // those escapes at the mesh TLS-setup path where the listener's
                // real posture is known, at startup and on PeerAuthentication
                // live reload (`enforce_mesh_inbound_fail_closed` /
                // `plan_mesh_inbound_tls_reload` in `src/modes/mesh`): an inbound
                // termination listener that would come up plaintext is fatal in
                // production (dev warns — an explicit DISABLE, or the no-identity
                // posture this gate already acknowledges, is intentional), while a
                // configured-but-unloadable SVID verifier or unavailable CA-backed
                // initial SVID is fatal (a real fault, like a broken cert/key).
                if !has_workload_identity {
                    if crate::identity::production_mode() {
                        // Master prod guardrail: like bootstrap_dev_root and
                        // StaticAttestor, refuse unconditionally — the
                        // FERRUM_MESH_ALLOW_NO_CA dev opt-out does not apply.
                        return Err(
                            "FERRUM_MESH_PRODUCTION_MODE=true but the mesh has no workload \
                             identity: set FERRUM_GATEWAY_SVID_CERT_PATH, \
                             FERRUM_GATEWAY_SVID_KEY_PATH, and FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH \
                             to file-based SVID material, or configure FERRUM_MESH_CA_BACKEND with \
                             FERRUM_MESH_WORKLOAD_SPIFFE_ID. Without identity the mesh cannot \
                             establish or verify mTLS."
                                .into(),
                        );
                    }
                    // Canonical env-only read (shared with the runtime
                    // inbound-TLS fail-closed gate so the two can never disagree),
                    // matching the rest of the guardrail family.
                    let allow_no_ca = crate::identity::allow_no_ca();
                    if allow_no_ca {
                        tracing::warn!(
                            "FERRUM_MESH_ALLOW_NO_CA=true: mesh is starting with NO workload \
                             identity (no file-based gateway SVID material). It cannot establish \
                             or verify mTLS and will accept unauthenticated plaintext traffic. \
                             Dev/test only — set FERRUM_MESH_PRODUCTION_MODE=true (with gateway \
                             SVID material) for production."
                        );
                    } else {
                        return Err(
                            "mesh mode has no workload identity: no file-based gateway SVID \
                             material (FERRUM_GATEWAY_SVID_CERT_PATH / KEY_PATH / \
                             TRUST_BUNDLE_PATH). Without identity the mesh cannot establish or \
                             verify mTLS, so it would accept unauthenticated plaintext traffic \
                             (PeerAuthentication defaults to PERMISSIVE). Supply gateway SVID \
                             material, configure FERRUM_MESH_CA_BACKEND with \
                             FERRUM_MESH_WORKLOAD_SPIFFE_ID, or — for dev/test only — set the \
                             FERRUM_MESH_ALLOW_NO_CA=true environment variable (not honored from \
                             ferrum.conf)."
                                .into(),
                        );
                    }
                }
            }
            OperatingMode::Injector | OperatingMode::NodeAgent => {}
            OperatingMode::Migrate => {
                // Migrate mode: validation depends on FERRUM_MIGRATE_ACTION.
                // For "config", FERRUM_FILE_CONFIG_PATH is required.
                // For "up" and "status", FERRUM_DB_TYPE and FERRUM_DB_URL are required.
                match self.migrate_action.as_str() {
                    "config" => {
                        if self.file_config_path.is_none() {
                            return Err(
                                "FERRUM_FILE_CONFIG_PATH is required for migrate config action"
                                    .into(),
                            );
                        }
                    }
                    "up" | "status" => {
                        if self.db_type.is_none() {
                            return Err(
                                "FERRUM_DB_TYPE is required for migrate up/status action".into()
                            );
                        }
                        if self.db_url.is_none() {
                            return Err(
                                "FERRUM_DB_URL is required for migrate up/status action".into()
                            );
                        }
                    }
                    other => {
                        // `migrate_action` is declared `lowercase()`, so this
                        // echoes a case-folded form the textual redactor cannot
                        // admit at one or two bytes. Withhold by key.
                        return Err(format!(
                            "Invalid FERRUM_MIGRATE_ACTION {}. Expected: up, status, config",
                            crate::secrets::quoted_env_value("FERRUM_MIGRATE_ACTION", other)
                        ));
                    }
                }
            }
        }

        if matches!(self.mode, OperatingMode::NodeAgent) {
            if self.node_agent_hbone_redirect_port == 0 {
                return Err("FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT must be non-zero".into());
            }
            if self.node_agent_hbone_redirect_port == ferrum_ebpf_common::OUTBOUND_CAPTURE_PORT {
                return Err(
                    "FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT must differ from the outbound capture port"
                        .into(),
                );
            }
            if self.node_agent_cni_enabled && self.node_agent_cni_socket_path.trim().is_empty() {
                return Err("FERRUM_NODE_AGENT_CNI_SOCKET_PATH must not be empty when \
                     FERRUM_NODE_AGENT_CNI_ENABLED is true"
                    .into());
            }
        }

        self.validate_db_tls_config()?;

        // Validate namespace
        crate::config::types::validate_namespace(&self.namespace)
            .map_err(|e| format!("Invalid FERRUM_NAMESPACE: {}", e))?;
        validate_k8s_namespace(&self.k8s_istio_root_namespace)
            .map_err(|e| format!("Invalid FERRUM_K8S_ISTIO_ROOT_NAMESPACE: {}", e))?;
        validate_k8s_namespace(&self.k8s_controller_namespace)
            .map_err(|e| format!("Invalid FERRUM_K8S_CONTROLLER_NAMESPACE: {}", e))?;

        // Validate FERRUM_CP_NAMESPACES entries. Special token `"*"` means
        // "all namespaces" — any other value must be a valid namespace label.
        // Whitespace-only entries are rejected so a typo like `"ns-a, "` is
        // caught early rather than producing an unreachable subscriber.
        for raw in &self.cp_namespaces {
            let entry = raw.trim();
            if entry.is_empty() {
                return Err(
                    "FERRUM_CP_NAMESPACES contains an empty / whitespace-only entry; \
                     use `*` for cluster-wide or remove the extra comma"
                        .to_string(),
                );
            }
            if entry == "*" {
                continue;
            }
            // `entry` is the *trimmed* segment, so a padded one- or two-byte
            // entry renders as a form below the derived-candidate minimum.
            crate::config::types::validate_namespace(entry).map_err(|e| {
                format!(
                    "Invalid FERRUM_CP_NAMESPACES entry {}: {}",
                    crate::secrets::quoted_env_value("FERRUM_CP_NAMESPACES", entry),
                    e
                )
            })?;
        }
        // `*` must stand alone. A mixed set like `"*,prod"` is ambiguous: it
        // implies "everything plus an extra one" or "wildcard subset of one".
        // Reject so operators choose a single semantics.
        if self.cp_namespaces.iter().any(|raw| raw.trim() == "*") && self.cp_namespaces.len() > 1 {
            return Err(
                "FERRUM_CP_NAMESPACES: `*` (all namespaces) cannot be combined with \
                 explicit namespace entries; use either `*` alone or a comma-separated list"
                    .to_string(),
            );
        }

        // Validate TLS version settings
        match self.tls_min_version.as_str() {
            "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "Invalid FERRUM_TLS_MIN_VERSION '{}'. Expected: 1.2, 1.3",
                    other
                ));
            }
        }
        match self.tls_max_version.as_str() {
            "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "Invalid FERRUM_TLS_MAX_VERSION '{}'. Expected: 1.2, 1.3",
                    other
                ));
            }
        }
        if self.tls_min_version == "1.3" && self.tls_max_version == "1.2" {
            return Err(
                "FERRUM_TLS_MIN_VERSION (1.3) cannot be greater than FERRUM_TLS_MAX_VERSION (1.2)"
                    .into(),
            );
        }

        if self.mode == OperatingMode::ControlPlane {
            assert!(
                self.cp_grpc_listen_addr.is_some(),
                "cp_grpc_listen_addr is populated during from_env_with_conf()"
            );
        }

        // Validate bind addresses are valid IP addresses
        if self.proxy_bind_address.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "Invalid FERRUM_PROXY_BIND_ADDRESS {}. Expected a valid IP address (e.g., 0.0.0.0 or ::)",
                crate::secrets::quoted_env_value(
                    "FERRUM_PROXY_BIND_ADDRESS",
                    &self.proxy_bind_address
                )
            ));
        }
        if self.admin_bind_address.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "Invalid FERRUM_ADMIN_BIND_ADDRESS {}. Expected a valid IP address (e.g., 0.0.0.0 or ::)",
                crate::secrets::quoted_env_value(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    &self.admin_bind_address
                )
            ));
        }

        // Safe-by-default management plane. The admin bind defaults to loopback,
        // so a fresh startup is never exposed. This guard catches the case where
        // an operator has EXPLICITLY moved the writable (`database`/`cp`) admin
        // API to a publicly reachable plaintext bind with no IP allowlist:
        // refuse to start unless they opt in via FERRUM_ALLOW_INSECURE_ADMIN_HTTP,
        // because the writable admin API and operator bearer tokens would be
        // served in cleartext on all matching interfaces. Read-only modes
        // (file/dp/mesh) are warned (not failed) in main.rs; node-agent has its
        // own loopback fallback.
        if let Some(err) = self.admin_insecure_plaintext_startup_error() {
            return Err(err);
        }

        // Validate global backend TLS cert/key files exist and are parseable
        match (
            &self.backend_tls_client_cert_path,
            &self.backend_tls_client_key_path,
        ) {
            (Some(_), None) => {
                return Err(
                    "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH is set but FERRUM_BACKEND_TLS_CLIENT_KEY_PATH is missing — both must be configured together".into(),
                );
            }
            (None, Some(_)) => {
                return Err(
                    "FERRUM_BACKEND_TLS_CLIENT_KEY_PATH is set but FERRUM_BACKEND_TLS_CLIENT_CERT_PATH is missing — both must be configured together".into(),
                );
            }
            _ => {}
        }
        if let Some(ref path) = self.backend_tls_client_cert_path {
            crate::config::types::validate_pem_cert_file(
                "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH",
                path,
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(ref path) = self.backend_tls_client_key_path {
            crate::config::types::validate_pem_key_file("FERRUM_BACKEND_TLS_CLIENT_KEY_PATH", path)
                .map_err(|e| e.to_string())?;
        }
        if let Some(ref path) = self.tls_ca_bundle_path {
            crate::config::types::validate_pem_cert_file("FERRUM_TLS_CA_BUNDLE_PATH", path)
                .map_err(|e| e.to_string())?;
        }

        // The admin JWT lifetime cap is a security control: `0` is the only
        // documented way to disable it, so a value that cannot be represented
        // as a JWT `NumericDate` bound (i64 seconds) is a misconfiguration
        // and must not silently degrade into an effectively unlimited cap.
        // `JwtManager::verify_token()` fails closed on the same condition.
        if i64::try_from(self.admin_jwt_max_ttl).is_err() {
            return Err(format!(
                "FERRUM_ADMIN_JWT_MAX_TTL ({}) exceeds the maximum supported value ({}); \
                 use 0 to disable the lifetime cap",
                crate::secrets::report_env_field(
                    "FERRUM_ADMIN_JWT_MAX_TTL",
                    &self.admin_jwt_max_ttl.to_string()
                ),
                i64::MAX
            ));
        }

        if self.http3_initial_mtu < crate::http3::config::QUIC_INITIAL_MTU_MIN
            || self.http3_initial_mtu > crate::http3::config::QUIC_INITIAL_MTU_MAX
        {
            // Key-tied for the same reason as the overload thresholds below: the
            // rejected MTU is re-rendered as its canonical `u16` `Display`, so a
            // secret-backed `071` surfaces as `71` — two bytes, below
            // `MIN_DERIVED_CANDIDATE_LEN`, which the textual pass may not admit.
            // Only values under `QUIC_INITIAL_MTU_MIN` (1200) can reach here in
            // practice, so the leaked rendering is always 1-4 digits.
            return Err(format!(
                "FERRUM_HTTP3_INITIAL_MTU ({}) is outside quinn's legal range [{}, {}]",
                crate::secrets::report_env_field(
                    "FERRUM_HTTP3_INITIAL_MTU",
                    &self.http3_initial_mtu.to_string()
                ),
                crate::http3::config::QUIC_INITIAL_MTU_MIN,
                crate::http3::config::QUIC_INITIAL_MTU_MAX,
            ));
        }

        // Overload threshold ordering: critical > pressure for each pair.
        //
        // The RED probabilistic shedding ramp in src/overload.rs computes
        //   probability = (ratio - pressure) / (critical - pressure) * SCALE
        // When critical == pressure the divisor is 0 → 0/0 = NaN, and
        // (NaN as u32) saturates to 0 in Rust — so the binary
        // disable_keepalive flag fires at the pressure threshold while the
        // RED ramp silently produces 0% drop probability. critical < pressure
        // is even worse: a negative range yields a negative ratio that also
        // saturates to 0 on the u32 cast. Auto-correct strictly inverted
        // thresholds by swapping; reject equal thresholds because swapping
        // equal values cannot create the positive RED ramp width the hot path
        // requires.
        if self.overload_fd_pressure_threshold == self.overload_fd_critical_threshold {
            return Err(format!(
                "FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD ({}) must be less than FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD ({})",
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD",
                    &self.overload_fd_pressure_threshold.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD",
                    &self.overload_fd_critical_threshold.to_string()
                )
            ));
        }
        if self.overload_fd_pressure_threshold > self.overload_fd_critical_threshold {
            // Key-tied: `1.0` renders as `1`, below the derived-candidate minimum.
            tracing::warn!(
                "FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD ({}) is greater than FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD ({}); swapping to correct ordering",
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD",
                    &self.overload_fd_pressure_threshold.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD",
                    &self.overload_fd_critical_threshold.to_string()
                )
            );
            std::mem::swap(
                &mut self.overload_fd_pressure_threshold,
                &mut self.overload_fd_critical_threshold,
            );
        }
        if self.overload_conn_pressure_threshold == self.overload_conn_critical_threshold {
            return Err(format!(
                "FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD ({}) must be less than FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD ({})",
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD",
                    &self.overload_conn_pressure_threshold.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD",
                    &self.overload_conn_critical_threshold.to_string()
                )
            ));
        }
        if self.overload_conn_pressure_threshold > self.overload_conn_critical_threshold {
            tracing::warn!(
                "FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD ({}) is greater than FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD ({}); swapping to correct ordering",
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD",
                    &self.overload_conn_pressure_threshold.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD",
                    &self.overload_conn_critical_threshold.to_string()
                )
            );
            std::mem::swap(
                &mut self.overload_conn_pressure_threshold,
                &mut self.overload_conn_critical_threshold,
            );
        }
        if self.overload_req_pressure_threshold == self.overload_req_critical_threshold {
            return Err(format!(
                "FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD ({}) must be less than FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD ({})",
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD",
                    &self.overload_req_pressure_threshold.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD",
                    &self.overload_req_critical_threshold.to_string()
                )
            ));
        }
        if self.overload_req_pressure_threshold > self.overload_req_critical_threshold {
            tracing::warn!(
                "FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD ({}) is greater than FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD ({}); swapping to correct ordering",
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD",
                    &self.overload_req_pressure_threshold.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD",
                    &self.overload_req_critical_threshold.to_string()
                )
            );
            std::mem::swap(
                &mut self.overload_req_pressure_threshold,
                &mut self.overload_req_critical_threshold,
            );
        }

        // Non-fatal configuration warnings
        if self.db_pool_min_connections > self.db_pool_max_connections {
            tracing::warn!(
                "WARNING: FERRUM_DB_POOL_MIN_CONNECTIONS ({}) exceeds FERRUM_DB_POOL_MAX_CONNECTIONS ({}). \
                 The pool will clamp min to max, wasting the higher setting.",
                crate::secrets::report_env_field(
                    "FERRUM_DB_POOL_MIN_CONNECTIONS",
                    &self.db_pool_min_connections.to_string()
                ),
                crate::secrets::report_env_field(
                    "FERRUM_DB_POOL_MAX_CONNECTIONS",
                    &self.db_pool_max_connections.to_string()
                )
            );
        }

        // Non-fatal security warnings
        if self.tls_no_verify {
            tracing::warn!(
                "WARNING: FERRUM_TLS_NO_VERIFY=true — outbound TLS certificate verification is DISABLED. Do not use in production."
            );
        }
        if self.admin_tls_no_verify {
            tracing::warn!(
                "WARNING: FERRUM_ADMIN_TLS_NO_VERIFY=true — admin TLS certificate verification is DISABLED. Do not use in production."
            );
        }

        // Secure-by-default CP/DP gRPC transport: refuse non-loopback plaintext
        // config sync (and reject the non-functional no-verify flag) unless the
        // operator made an explicit, auditable choice to permit it.
        self.validate_cp_dp_grpc_transport_security()?;

        // Bounded pre-authentication admission on the CP gRPC listener.
        self.validate_cp_grpc_connection_limits()?;

        // The forwarding trust boundary is parsed strictly here so a typo fails
        // `ferrum-edge validate` and fails startup before any listener binds,
        // rather than quietly shrinking the trust set at runtime.
        self.validate_trusted_proxies()?;

        Ok(())
    }

    /// Reject a `FERRUM_TRUSTED_PROXIES` list that is not entirely valid.
    ///
    /// This list decides whose `X-Forwarded-For`, `X-Forwarded-Proto`,
    /// configured real-IP header, and inbound PROXY-protocol header Ferrum
    /// believes. Retaining only the parseable entries after a typo is not a
    /// smaller trust set in any useful sense — it silently moves an
    /// authorization and abuse-control identity boundary: the mistyped hop stops
    /// being trusted, so every client behind it collapses onto that hop's socket
    /// address for `ip_restriction`, GeoIP, bot/client attribution, per-IP rate
    /// and concurrency keys, and logs. Every entry must therefore parse, and
    /// empty/trailing/doubled comma segments are typos, not empty configuration.
    /// A wholly empty value stays valid: it is the secure default in which
    /// forwarded metadata is ignored altogether.
    ///
    /// Parses through the shared `CidrSet` so validation and the runtime filter
    /// agree on canonical IPv4/IPv6/mapped forms; the set is discarded here
    /// because `ProxyState` builds the enforcing one (strictly, again) at
    /// construction.
    fn validate_trusted_proxies(&self) -> Result<(), String> {
        crate::util::cidr::CidrSet::parse_strict(&self.trusted_proxies).map_err(|e| {
            format!(
                "Invalid FERRUM_TRUSTED_PROXIES {}: {e}. Every entry must be a valid IP or CIDR \
                 and empty comma segments are rejected — a partially parsed forwarding trust \
                 boundary would silently change which peers may assert a client identity.",
                crate::secrets::quoted_env_value("FERRUM_TRUSTED_PROXIES", &self.trusted_proxies)
            )
        })?;
        Ok(())
    }

    /// Validate the CP gRPC pre-authentication admission caps
    /// (`FERRUM_CP_GRPC_MAX_CONNECTIONS` / `..._PER_IP`, advisory
    /// GHSA-2xqr-7j7p-77qp). Scoped to CP mode — no other mode builds the
    /// limiter, so a stray variable elsewhere must not fail startup.
    ///
    /// Two rules, both fail-closed rather than silently degrading:
    ///
    /// 1. Neither value may exceed the tokio semaphore ceiling. `ConnLimiter`
    ///    clamps, and a silent clamp hides that the configured number is not
    ///    the enforced number.
    /// 2. A per-IP cap larger than the global cap can never fire, so one host
    ///    could still consume the entire global budget. That is exactly the
    ///    condition the per-IP cap exists to prevent, so it is a configuration
    ///    error rather than a no-op.
    pub fn validate_cp_grpc_connection_limits(&self) -> Result<(), String> {
        if !matches!(self.mode, OperatingMode::ControlPlane) {
            return Ok(());
        }
        let max_conn_limit = crate::util::conn_limit::MAX_CONN_LIMIT;
        if self.cp_grpc_max_connections > max_conn_limit {
            return Err(format!(
                "FERRUM_CP_GRPC_MAX_CONNECTIONS ({}) exceeds the maximum supported value \
                 {max_conn_limit}. Use 0 to disable the cap entirely.",
                self.cp_grpc_max_connections
            ));
        }
        if self.cp_grpc_max_connections_per_ip > max_conn_limit {
            return Err(format!(
                "FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP ({}) exceeds the maximum supported value \
                 {max_conn_limit}. Use 0 to disable the per-IP cap.",
                self.cp_grpc_max_connections_per_ip
            ));
        }
        if self.cp_grpc_max_connections > 0
            && self.cp_grpc_max_connections_per_ip > self.cp_grpc_max_connections
        {
            return Err(format!(
                "FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP ({}) is greater than \
                 FERRUM_CP_GRPC_MAX_CONNECTIONS ({}), so the per-IP cap can never be reached and \
                 a single source IP could consume the entire CP gRPC connection budget. Lower the \
                 per-IP cap, raise the global cap, or set the per-IP cap to 0 to disable it \
                 deliberately.",
                self.cp_grpc_max_connections_per_ip, self.cp_grpc_max_connections
            ));
        }
        Ok(())
    }

    /// Resolve the CP gRPC listen address: an explicit
    /// `FERRUM_CP_GRPC_LISTEN_ADDR`, else the hardcoded `0.0.0.0:50051` default.
    /// The default is deliberately NOT derived from `admin_bind_address` (which
    /// defaults to loopback) — a Data Plane in another pod/host must be able to
    /// reach the CP gRPC listener. `from_env_with_conf` already populates this
    /// to `Some("0.0.0.0:50051")` for CP mode; the fallback keeps hand-built
    /// configs (tests) consistent with that default. Returns `Err` for a
    /// malformed explicit address so startup (and `ferrum-edge validate`) fail
    /// with a clear message instead of an `expect()` panic at bind time.
    pub fn cp_grpc_socket_addr(&self) -> Result<std::net::SocketAddr, String> {
        if let Some(addr) = &self.cp_grpc_listen_addr {
            addr.parse().map_err(|e| {
                format!("FERRUM_CP_GRPC_LISTEN_ADDR '{addr}' is not a valid socket address: {e}")
            })
        } else {
            Ok(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                50051,
            ))
        }
    }

    /// Enforce the secure-by-default CP/DP gRPC transport policy.
    ///
    /// 1. `FERRUM_DP_GRPC_TLS_NO_VERIFY=true` is rejected outright: the
    ///    tonic-managed CP/DP gRPC client exposes no hook to skip server
    ///    verification, so the flag never actually disabled it — keeping it
    ///    would only grant false confidence. Pin the CP CA via
    ///    `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` for self-signed test certs instead.
    /// 2. In CP mode, a plaintext gRPC listener bound to a non-loopback address
    ///    is refused unless `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true`.
    /// 3. In DP mode, a non-loopback `http://` CP URL is refused unless the same
    ///    escape hatch is set. (Mesh mode reaches a CP over the same URLs but has
    ///    its own `FERRUM_MESH_PRODUCTION_MODE` TLS posture, so it is not gated
    ///    here.)
    ///
    /// Loopback (`127.0.0.1`/`::1`/`localhost`) plaintext is always permitted so
    /// the local-dev quickstart keeps working without the flag.
    fn validate_cp_dp_grpc_transport_security(&self) -> Result<(), String> {
        if self.dp_grpc_tls_no_verify {
            return Err(
                "FERRUM_DP_GRPC_TLS_NO_VERIFY=true is not supported: the CP/DP gRPC client cannot \
                 skip server certificate verification, so the flag offers only false confidence. \
                 To connect to a CP with a self-signed certificate, pin its CA via \
                 FERRUM_DP_GRPC_TLS_CA_CERT_PATH (one-way TLS) or supply the full \
                 FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH/KEY_PATH (mTLS)."
                    .into(),
            );
        }

        // CP server side: a plaintext listener on a non-loopback address leaks
        // DP JWTs and the full gateway config to anyone on the network.
        if matches!(self.mode, OperatingMode::ControlPlane) {
            let grpc_addr = self.cp_grpc_socket_addr()?;
            // Port 0 disables the plaintext listener entirely (TLS-only or off),
            // so there is no plaintext surface to guard.
            let tls_configured =
                self.cp_grpc_tls_cert_path.is_some() && self.cp_grpc_tls_key_path.is_some();
            if grpc_addr.port() != 0
                && !tls_configured
                && !grpc_addr.ip().is_loopback()
                && !self.cp_dp_grpc_allow_plaintext
            {
                return Err(format!(
                    "CP gRPC config sync would bind PLAINTEXT on non-loopback address {grpc_addr} \
                     with no TLS configured — DP authentication JWTs and the full gateway \
                     configuration would be exposed to the network. Configure \
                     FERRUM_CP_GRPC_TLS_CERT_PATH + FERRUM_CP_GRPC_TLS_KEY_PATH, bind a loopback \
                     address (e.g. 127.0.0.1:50051), or set FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true \
                     to explicitly permit plaintext config sync."
                ));
            }
        }

        // DP client side: each CP URL must be https:// (TLS) or loopback http://.
        // Scoped to DP mode — mesh mode dials a CP over the same URLs but governs
        // plaintext through FERRUM_MESH_PRODUCTION_MODE instead.
        if matches!(self.mode, OperatingMode::DataPlane) {
            for url in &self.dp_cp_grpc_urls {
                if cp_dp_grpc_url_is_nonloopback_plaintext(url)? && !self.cp_dp_grpc_allow_plaintext
                {
                    return Err(format!(
                        "DP CP URL '{url}' is PLAINTEXT to a non-loopback host — the DP \
                         authentication JWT and config data would be exposed to the network. Use \
                         an https:// URL with FERRUM_DP_GRPC_TLS_CA_CERT_PATH, target a loopback \
                         host, or set FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true to explicitly permit \
                         plaintext config sync."
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Resolve the effective authoritative client-IP header for cold paths that
/// do not own an `EnvConfig` (notably CP snapshot and admin admission). This
/// uses the same env-over-conf precedence as startup and matches the lowercase
/// normalization stored in `EnvConfig::real_ip_header`. CP config sync rejects
/// DPs that do not explicitly advertise this same cluster ownership value.
pub(crate) fn resolve_real_ip_header() -> Option<String> {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_REAL_IP_HEADER")
        .map(|header| header.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_key_exchange_groups_prefer_canonical_env_name() {
        assert_eq!(
            resolve_tls_key_exchange_groups(
                Some("X25519,secp384r1".to_string()),
                Some("secp256r1".to_string()),
            ),
            Some("X25519,secp384r1".to_string())
        );
    }

    #[test]
    fn tls_key_exchange_groups_accept_legacy_curves_alias() {
        assert_eq!(
            resolve_tls_key_exchange_groups(None, Some("X25519,secp256r1".to_string())),
            Some("X25519,secp256r1".to_string())
        );
    }

    #[test]
    fn existing_db_tls_url_params_detects_sql_tls_options_case_insensitively() {
        assert_eq!(
            EnvConfig::existing_db_tls_url_params(
                "postgres://localhost/ferrum?connect_timeout=10&SSLMode=verify-full&TLS=true",
                "postgres",
            ),
            vec!["sslmode".to_string(), "tls".to_string()]
        );

        assert_eq!(
            EnvConfig::existing_db_tls_url_params(
                "mysql://localhost/ferrum?ssl_mode=VERIFY_IDENTITY&ssl-ca=/certs/ca.pem",
                "mysql",
            ),
            vec!["ssl_mode".to_string(), "ssl-ca".to_string()]
        );
    }

    #[test]
    fn existing_db_tls_url_params_detects_mongodb_uri_tls_options() {
        assert_eq!(
            EnvConfig::existing_db_tls_url_params(
                "mongodb://localhost/ferrum?tls=true&tlsAllowInvalidCertificates=true",
                "mongodb",
            ),
            vec!["tls".to_string(), "tlsallowinvalidcertificates".to_string()]
        );
    }

    #[test]
    fn existing_db_tls_url_params_ignores_unparseable_urls() {
        assert!(
            EnvConfig::existing_db_tls_url_params(
                "mysql://user:pass@[::1/ferrum?ssl-mode=VERIFY_IDENTITY",
                "mysql",
            )
            .is_empty()
        );
    }

    fn file_mode_config() -> EnvConfig {
        EnvConfig {
            mode: OperatingMode::File,
            file_config_path: Some("/tmp/dummy.yaml".into()),
            ..Default::default()
        }
    }

    fn cp_mode_config() -> EnvConfig {
        EnvConfig {
            mode: OperatingMode::ControlPlane,
            ..Default::default()
        }
    }

    fn dp_mode_config() -> EnvConfig {
        EnvConfig {
            mode: OperatingMode::DataPlane,
            ..Default::default()
        }
    }

    // --- CP/DP gRPC transport security (secure-by-default plaintext gate) ---

    #[test]
    fn cp_default_bind_plaintext_is_rejected_without_allow_flag() {
        // Default CP gRPC bind resolves to 0.0.0.0:50051 (hardcoded, NOT derived
        // from admin_bind_address) — non-loopback + no TLS, so it must be refused.
        let config = cp_mode_config();
        let err = config
            .validate_cp_dp_grpc_transport_security()
            .expect_err("non-loopback plaintext CP must be rejected by default");
        assert!(err.contains("PLAINTEXT"), "unexpected error: {err}");
        assert!(err.contains("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT"));
    }

    #[test]
    fn cp_explicit_nonloopback_plaintext_is_rejected_without_allow_flag() {
        let config = EnvConfig {
            cp_grpc_listen_addr: Some("0.0.0.0:50051".into()),
            ..cp_mode_config()
        };
        assert!(config.validate_cp_dp_grpc_transport_security().is_err());
    }

    #[test]
    fn cp_nonloopback_plaintext_allowed_with_explicit_flag() {
        let config = EnvConfig {
            cp_grpc_listen_addr: Some("0.0.0.0:50051".into()),
            cp_dp_grpc_allow_plaintext: true,
            ..cp_mode_config()
        };
        config
            .validate_cp_dp_grpc_transport_security()
            .expect("explicit opt-in must permit non-loopback plaintext CP");
    }

    #[test]
    fn cp_nonloopback_with_tls_is_allowed() {
        let config = EnvConfig {
            cp_grpc_listen_addr: Some("0.0.0.0:50051".into()),
            cp_grpc_tls_cert_path: Some("/certs/server.pem".into()),
            cp_grpc_tls_key_path: Some("/certs/server-key.pem".into()),
            ..cp_mode_config()
        };
        config
            .validate_cp_dp_grpc_transport_security()
            .expect("TLS-configured CP must be allowed on any address");
    }

    #[test]
    fn cp_loopback_plaintext_is_allowed_for_dev() {
        for addr in ["127.0.0.1:50051", "[::1]:50051"] {
            let config = EnvConfig {
                cp_grpc_listen_addr: Some(addr.into()),
                ..cp_mode_config()
            };
            config
                .validate_cp_dp_grpc_transport_security()
                .unwrap_or_else(|e| panic!("loopback plaintext CP {addr} must be allowed: {e}"));
        }
    }

    #[test]
    fn cp_disabled_listener_port_zero_skips_plaintext_gate() {
        // Port 0 disables the plaintext listener, so there is no surface to guard
        // even on a non-loopback bind address.
        let config = EnvConfig {
            cp_grpc_listen_addr: Some("0.0.0.0:0".into()),
            ..cp_mode_config()
        };
        config
            .validate_cp_dp_grpc_transport_security()
            .expect("port 0 disables the plaintext listener");
    }

    #[test]
    fn dp_nonloopback_http_url_is_rejected_without_allow_flag() {
        let config = EnvConfig {
            dp_cp_grpc_urls: vec!["http://cp-host:50051".into()],
            ..dp_mode_config()
        };
        let err = config
            .validate_cp_dp_grpc_transport_security()
            .expect_err("non-loopback http:// CP URL must be rejected by default");
        assert!(err.contains("PLAINTEXT"), "unexpected error: {err}");
        assert!(err.contains("cp-host"));
    }

    #[test]
    fn dp_nonloopback_http_url_allowed_with_explicit_flag() {
        let config = EnvConfig {
            dp_cp_grpc_urls: vec!["http://cp-host:50051".into()],
            cp_dp_grpc_allow_plaintext: true,
            ..dp_mode_config()
        };
        config
            .validate_cp_dp_grpc_transport_security()
            .expect("explicit opt-in must permit non-loopback http:// CP URL");
    }

    #[test]
    fn dp_https_url_is_allowed() {
        let config = EnvConfig {
            dp_cp_grpc_urls: vec!["https://cp-host:50051".into()],
            ..dp_mode_config()
        };
        config
            .validate_cp_dp_grpc_transport_security()
            .expect("https:// CP URL must always be allowed");
    }

    #[test]
    fn dp_loopback_http_urls_are_allowed_for_dev() {
        for url in [
            "http://localhost:50051",
            "http://127.0.0.1:50051",
            "http://[::1]:50051",
        ] {
            let config = EnvConfig {
                dp_cp_grpc_urls: vec![url.into()],
                ..dp_mode_config()
            };
            config
                .validate_cp_dp_grpc_transport_security()
                .unwrap_or_else(|e| panic!("loopback dev URL {url} must be allowed: {e}"));
        }
    }

    #[test]
    fn dp_mixed_url_list_rejects_the_nonloopback_plaintext_entry() {
        // One secure + one loopback-plaintext + one non-loopback-plaintext: the
        // last must trip the gate even though the list is partly safe.
        let config = EnvConfig {
            dp_cp_grpc_urls: vec![
                "https://cp1:50051".into(),
                "http://localhost:50051".into(),
                "http://cp3:50051".into(),
            ],
            ..dp_mode_config()
        };
        assert!(config.validate_cp_dp_grpc_transport_security().is_err());
    }

    #[test]
    fn dp_grpc_tls_no_verify_is_rejected() {
        // The flag is not honored by the tonic-managed client, so it must fail
        // closed rather than provide false confidence — in any mode.
        let config = EnvConfig {
            dp_grpc_tls_no_verify: true,
            ..file_mode_config()
        };
        let err = config
            .validate_cp_dp_grpc_transport_security()
            .expect_err("FERRUM_DP_GRPC_TLS_NO_VERIFY=true must be rejected");
        assert!(err.contains("FERRUM_DP_GRPC_TLS_NO_VERIFY"));
        assert!(err.contains("FERRUM_DP_GRPC_TLS_CA_CERT_PATH"));
    }

    #[test]
    fn cp_dp_grpc_url_classifier_distinguishes_secure_loopback_and_exposed() {
        // Non-loopback plaintext → blocked (true).
        assert!(cp_dp_grpc_url_is_nonloopback_plaintext("http://cp-host:50051").unwrap());
        assert!(cp_dp_grpc_url_is_nonloopback_plaintext("http://10.0.0.5:50051").unwrap());
        // TLS → not blocked (false).
        assert!(!cp_dp_grpc_url_is_nonloopback_plaintext("https://cp-host:50051").unwrap());
        assert!(!cp_dp_grpc_url_is_nonloopback_plaintext("grpcs://cp-host:50051").unwrap());
        // Loopback plaintext → not blocked (false).
        assert!(!cp_dp_grpc_url_is_nonloopback_plaintext("http://localhost:50051").unwrap());
        assert!(!cp_dp_grpc_url_is_nonloopback_plaintext("http://127.0.0.1:50051").unwrap());
        assert!(!cp_dp_grpc_url_is_nonloopback_plaintext("http://[::1]:50051").unwrap());
        // Malformed / unsupported → error.
        assert!(cp_dp_grpc_url_is_nonloopback_plaintext("not a url").is_err());
        assert!(cp_dp_grpc_url_is_nonloopback_plaintext("ftp://cp-host:50051").is_err());
    }

    #[test]
    fn validate_accepts_default_overload_thresholds() {
        let mut config = file_mode_config();
        // Defaults: pressure 0.80/0.85/0.85 < critical 0.95/0.95/0.95.
        config.validate().expect("default thresholds must validate");
    }

    #[test]
    fn validate_swaps_overload_fd_pressure_above_critical() {
        let mut config = file_mode_config();
        config.overload_fd_pressure_threshold = 0.85;
        config.overload_fd_critical_threshold = 0.80;
        config
            .validate()
            .expect("inverted FD thresholds should be auto-corrected");
        assert!(
            config.overload_fd_pressure_threshold < config.overload_fd_critical_threshold,
            "pressure ({}) must be less than critical ({}) after swap",
            config.overload_fd_pressure_threshold,
            config.overload_fd_critical_threshold,
        );
        assert!(
            (config.overload_fd_pressure_threshold - 0.80).abs() < f64::EPSILON,
            "pressure should be 0.80 after swap"
        );
        assert!(
            (config.overload_fd_critical_threshold - 0.85).abs() < f64::EPSILON,
            "critical should be 0.85 after swap"
        );
    }

    #[test]
    fn validate_rejects_overload_fd_pressure_equals_critical() {
        let mut config = file_mode_config();
        config.overload_fd_pressure_threshold = 0.90;
        config.overload_fd_critical_threshold = 0.90;
        let err = config
            .validate()
            .expect_err("equal FD thresholds create a zero-width RED ramp");
        assert!(err.contains("FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD"));
    }

    #[test]
    fn validate_rejects_overload_conn_pressure_equals_critical() {
        let mut config = file_mode_config();
        config.overload_conn_pressure_threshold = 0.90;
        config.overload_conn_critical_threshold = 0.90;
        let err = config
            .validate()
            .expect_err("equal connection thresholds create a zero-width RED ramp");
        assert!(err.contains("FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD"));
    }

    #[test]
    fn validate_rejects_overload_req_pressure_equals_critical() {
        let mut config = file_mode_config();
        config.overload_req_pressure_threshold = 0.90;
        config.overload_req_critical_threshold = 0.90;
        let err = config
            .validate()
            .expect_err("equal request thresholds create a zero-width RED ramp");
        assert!(err.contains("FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD"));
    }

    #[test]
    fn validate_swaps_overload_conn_pressure_above_critical() {
        let mut config = file_mode_config();
        config.overload_conn_pressure_threshold = 0.95;
        config.overload_conn_critical_threshold = 0.85;
        config
            .validate()
            .expect("inverted connection thresholds should be auto-corrected");
        assert!(
            config.overload_conn_pressure_threshold < config.overload_conn_critical_threshold,
            "pressure ({}) must be less than critical ({}) after swap",
            config.overload_conn_pressure_threshold,
            config.overload_conn_critical_threshold,
        );
    }

    #[test]
    fn validate_swaps_overload_req_pressure_above_critical() {
        let mut config = file_mode_config();
        config.overload_req_pressure_threshold = 0.99;
        config.overload_req_critical_threshold = 0.50;
        config
            .validate()
            .expect("inverted request thresholds should be auto-corrected");
        assert!(
            config.overload_req_pressure_threshold < config.overload_req_critical_threshold,
            "pressure ({}) must be less than critical ({}) after swap",
            config.overload_req_pressure_threshold,
            config.overload_req_critical_threshold,
        );
    }

    #[test]
    fn validate_warns_db_pool_min_above_max() {
        let mut config = file_mode_config();
        config.db_pool_min_connections = 10;
        config.db_pool_max_connections = 5;
        // validate() should still succeed (warning, not error)
        config
            .validate()
            .expect("db_pool_min > max is a warning, not a fatal error");
    }

    #[test]
    fn validate_accepts_db_pool_min_equal_max() {
        let mut config = file_mode_config();
        config.db_pool_min_connections = 5;
        config.db_pool_max_connections = 5;
        config
            .validate()
            .expect("db_pool_min == max should be valid");
    }

    // ── FERRUM_CP_NAMESPACES validation ────────────────────────────────────

    #[test]
    fn validate_accepts_empty_cp_namespaces() {
        // Back-compat default: unset / empty means "single-namespace CP".
        let mut config = file_mode_config();
        config.cp_namespaces = Vec::new();
        config
            .validate()
            .expect("empty cp_namespaces must be valid");
    }

    #[test]
    fn validate_accepts_star_cp_namespaces() {
        let mut config = file_mode_config();
        config.cp_namespaces = vec!["*".to_string()];
        config.validate().expect("`*` cp_namespaces must be valid");
    }

    #[test]
    fn validate_accepts_csv_cp_namespaces() {
        let mut config = file_mode_config();
        config.cp_namespaces = vec!["prod".to_string(), "staging".to_string()];
        config.validate().expect("CSV cp_namespaces must be valid");
    }

    #[test]
    fn validate_rejects_empty_entry_in_cp_namespaces() {
        let mut config = file_mode_config();
        // Simulates `FERRUM_CP_NAMESPACES="ns-a, ,ns-c"`.
        config.cp_namespaces = vec!["ns-a".to_string(), " ".to_string(), "ns-c".to_string()];
        let err = config
            .validate()
            .expect_err("whitespace-only entry must be rejected");
        assert!(
            err.contains("empty"),
            "error should mention empty entry, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_invalid_namespace_in_cp_namespaces() {
        let mut config = file_mode_config();
        config.cp_namespaces = vec!["Bad Namespace!".to_string()];
        let err = config
            .validate()
            .expect_err("invalid namespace label must be rejected");
        assert!(
            err.contains("FERRUM_CP_NAMESPACES"),
            "error should mention FERRUM_CP_NAMESPACES, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_star_combined_with_explicit_namespace() {
        // `*` plus an explicit entry is ambiguous — reject.
        let mut config = file_mode_config();
        config.cp_namespaces = vec!["*".to_string(), "prod".to_string()];
        let err = config
            .validate()
            .expect_err("`*` cannot be combined with explicit entries");
        assert!(
            err.contains("`*`"),
            "error should explain the `*` constraint, got: {err}"
        );
    }

    // ── T2-B: in-cluster default for K8s controller / pod discovery ────────
    //
    // These tests mutate process-global env vars so they hold the global
    // ENV_LOCK to prevent races with sibling tests.

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env_lock<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (key, value) in vars {
            // SAFETY: ENV_LOCK serialises test access to the process-global env.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        f();
        for (key, _) in vars {
            // SAFETY: ENV_LOCK still held; restore to "unset" state.
            unsafe {
                std::env::remove_var(key);
            }
        }
    }

    #[test]
    fn in_cluster_default_returns_true_inside_pod_when_unset() {
        // KUBERNETES_SERVICE_HOST is the standard injected marker for "this
        // process is running inside a pod". When the operator hasn't set the
        // K8s switch explicitly, default it to on.
        with_env_lock(
            &[
                ("KUBERNETES_SERVICE_HOST", Some("10.96.0.1")),
                ("FERRUM_K8S_CONTROLLER_ENABLED", None),
            ],
            || {
                let conf = ConfFile::default();
                let resolved =
                    resolve_in_cluster_default_bool(&conf, "FERRUM_K8S_CONTROLLER_ENABLED")
                        .expect("in-cluster default must resolve");
                assert!(resolved, "in-cluster + unset should default to true");
            },
        );
    }

    #[test]
    fn in_cluster_default_returns_false_outside_pod_when_unset() {
        with_env_lock(
            &[
                ("KUBERNETES_SERVICE_HOST", None),
                ("FERRUM_K8S_CONTROLLER_ENABLED", None),
            ],
            || {
                let conf = ConfFile::default();
                let resolved =
                    resolve_in_cluster_default_bool(&conf, "FERRUM_K8S_CONTROLLER_ENABLED")
                        .expect("outside-cluster default must resolve");
                assert!(
                    !resolved,
                    "outside-cluster + unset should default to false (back-compat)"
                );
            },
        );
    }

    #[test]
    fn in_cluster_default_explicit_false_wins_over_pod_default() {
        // Explicit operator opt-out: pod is in a K8s cluster but operator set
        // `=false`, so the in-cluster heuristic must be overridden. This is
        // the documented pod-side disable path.
        with_env_lock(
            &[
                ("KUBERNETES_SERVICE_HOST", Some("10.96.0.1")),
                ("FERRUM_K8S_CONTROLLER_ENABLED", Some("false")),
            ],
            || {
                let conf = ConfFile::default();
                let resolved =
                    resolve_in_cluster_default_bool(&conf, "FERRUM_K8S_CONTROLLER_ENABLED")
                        .expect("explicit false must resolve");
                assert!(
                    !resolved,
                    "explicit operator =false must win over in-cluster auto-on"
                );
            },
        );
    }

    #[test]
    fn in_cluster_default_explicit_true_wins_outside_cluster() {
        // Operator force-on outside K8s (CLI debugging, dev container, etc.).
        with_env_lock(
            &[
                ("KUBERNETES_SERVICE_HOST", None),
                ("FERRUM_K8S_CONTROLLER_ENABLED", Some("true")),
            ],
            || {
                let conf = ConfFile::default();
                let resolved =
                    resolve_in_cluster_default_bool(&conf, "FERRUM_K8S_CONTROLLER_ENABLED")
                        .expect("explicit true must resolve");
                assert!(
                    resolved,
                    "explicit operator =true must take effect even outside K8s"
                );
            },
        );
    }

    #[test]
    fn in_cluster_default_rejects_garbage_value() {
        // Make sure the in-cluster path still surfaces the standard bool
        // parser error so typos are caught at startup.
        with_env_lock(
            &[
                ("KUBERNETES_SERVICE_HOST", Some("10.96.0.1")),
                ("FERRUM_K8S_CONTROLLER_ENABLED", Some("yes-please")),
            ],
            || {
                let conf = ConfFile::default();
                let err = resolve_in_cluster_default_bool(&conf, "FERRUM_K8S_CONTROLLER_ENABLED")
                    .expect_err("garbage value must be rejected");
                assert!(err.contains("FERRUM_K8S_CONTROLLER_ENABLED"));
                assert!(err.contains("yes-please"));
            },
        );
    }

    #[test]
    fn in_cluster_default_treats_empty_kubernetes_host_as_outside_cluster() {
        // Some test/CI harnesses set `KUBERNETES_SERVICE_HOST=""` explicitly
        // — that should not flip the default to true (the var would be
        // useless to kube-rs anyway).
        with_env_lock(
            &[
                ("KUBERNETES_SERVICE_HOST", Some("")),
                ("FERRUM_K8S_CONTROLLER_ENABLED", None),
            ],
            || {
                let conf = ConfFile::default();
                let resolved =
                    resolve_in_cluster_default_bool(&conf, "FERRUM_K8S_CONTROLLER_ENABLED")
                        .expect("empty K8s host must not panic");
                assert!(
                    !resolved,
                    "empty KUBERNETES_SERVICE_HOST should not flip default to true"
                );
            },
        );
    }
}
