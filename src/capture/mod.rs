//! Mesh traffic-capture planning (Layer 7).
//!
//! The proxy hot path never shells out to iptables or eBPF. This module builds
//! declarative plans that init containers / node agents can apply outside the
//! request path.

use std::net::IpAddr;

use tracing::warn;

use crate::config::conf_file::resolve_ferrum_var;

pub const DEFAULT_PROXY_UID: u32 = 1337;
pub(crate) const XTABLES_LOCK_WAIT_SECONDS: u8 = 5;

/// Default UDP TPROXY listener port (Stage 3 consumer). Distinct from the TCP
/// outbound REDIRECT port (15001) because UDP and TCP cannot share one listener
/// socket — a UDP datagram delivered transparently by TPROXY has to land on a
/// `SO_REUSEADDR`/`IP_TRANSPARENT` UDP socket, not the TCP outbound listener.
pub const DEFAULT_UDP_OUTBOUND_PORT: u16 = 15011;

/// Default firewall mark (a.k.a. `fwmark`) stamped on TPROXY'd UDP datagrams so
/// the policy routing rule (`ip rule add fwmark <mark> lookup <table>`) steers
/// them to the local-delivery table. `0x733` == 1843 decimal.
///
/// **Ferrum-owned, deliberately NOT Istio's `0x539` (codex r3).** The default
/// must NOT collide with a co-resident Istio install's marks. Ferrum's higher-
/// priority fwmark `ip rule` (priority [`TPROXY_ROUTE_RULE_PRIORITY`] == 100,
/// below `main`) matches this mark and steers it to the Ferrum-owned table
/// [`TPROXY_ROUTE_TABLE`]; if the default were Istio's conventional TPROXY mark
/// `0x539`, Istio's own marked packets would be hijacked into Ferrum's table and
/// Istio traffic would break. `0x733` sits outside Istio
/// (`0x539`/`0x53a`/`0x111`/`0x222`), Cilium masked mark classes
/// (`0x200`/`0xA00`/`0xF00`/`0x800`), and Calico (`0x10000`+) marks.
///
/// Collision analysis (within Ferrum): Ferrum uses NO other packet marks
/// anywhere (verified: the only `1337` is the proxy `--uid-owner` UID, a *socket
/// owner* match in a disjoint namespace from `skb->mark`, and
/// `node_agent_hbone_redirect_port` `16008` is a port, not a mark). Operators
/// can override via `FERRUM_MESH_TPROXY_MARK`.
pub const DEFAULT_TPROXY_MARK: u32 = 0x733;

// Compile-time guards on the default mark, at MODULE level (NOT `cfg(test)`) so a
// regression fails ANY build — `cargo build`/release — not only `cargo test`:
//  - codex r3: the default must be Ferrum-owned and NOT Istio's conventional
//    TPROXY mark `0x539`. With Ferrum's higher-priority fwmark rule (priority
//    100) matching the mark, defaulting to `0x539` would hijack a co-resident
//    Istio's marked packets into Ferrum's table and break Istio traffic.
//  - the default must not ALIAS a co-resident CNI's masked magic-mark class:
//    Cilium matches `skb->mark & 0xF00`, so the prior `0xFE3` aliased the `0xF00`
//    class (`0xFE3 & 0xF00 == 0xF00`); `0x733 & 0xF00 == 0x700` does not.
const _: () = assert!(
    DEFAULT_TPROXY_MARK != 0x539,
    "default TPROXY mark must not collide with Istio's conventional `0x539`"
);
const _: () = assert!(
    DEFAULT_TPROXY_MARK == 0x733,
    "default TPROXY mark is the Ferrum-owned `0x733` (1843)"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0xF00,
    "default TPROXY mark must not alias CNI 0xF00/0xF00 masked mark class"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0xA00,
    "default TPROXY mark must not alias CNI 0xA00/0xF00 masked mark class"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0x800,
    "default TPROXY mark must not alias CNI 0x800/0xF00 masked mark class"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0x200,
    "default TPROXY mark must not alias CNI 0x200/0xF00 masked mark class"
);

/// `skb->mark` mask matched alongside [`DEFAULT_TPROXY_MARK`]. A full-width mask
/// keeps the TPROXY mark from aliasing onto other mark bits a co-resident CNI
/// might use; rendered as `<mark>/<mask>` in the `--tproxy-mark` argument and as
/// the `ip rule` `fwmark <mark>/<mask>` selector.
pub(crate) const TPROXY_MARK_MASK: u32 = 0xffff_ffff;

/// Dedicated **Ferrum-owned** policy routing table for transparent UDP local
/// delivery. Deliberately NOT Istio's inbound-TPROXY table `133`: a co-resident
/// Istio install owns `133`, so cleanup must never flush it. This high constant
/// is unlikely to collide with another component's table; combined with
/// exact-rule/exact-route teardown (never `ip route flush table`), Ferrum only
/// ever removes routing state it created. Inert until the Stage 3 UDP listener
/// binds.
pub(crate) const TPROXY_ROUTE_TABLE: u16 = 33133;

/// Explicit `ip rule` priority for the Ferrum UDP TPROXY fwmark selector.
///
/// Two things this controls, kept deliberately SEPARATE from the routing TABLE
/// number ([`TPROXY_ROUTE_TABLE`]):
/// 1. **Idempotency / exact teardown.** An explicit priority makes setup
///    delete-by-priority before add (so a node-agent fallback crash/retry never
///    appends a duplicate rule) and lets cleanup delete the EXACT Ferrum-owned
///    rule (`ip rule del priority <P>`) instead of `ip rule del lookup <table>`
///    (which would also drop an unrelated rule pointing at the same table).
/// 2. **RPDB ordering — MUST sit BELOW the kernel's built-in `main` table rule.**
///    The routing policy database is priority-ordered (lowest number wins) and
///    the kernel installs `main` at priority **32766**. If Ferrum's fwmark rule
///    sat ABOVE 32766, `main` would resolve a marked datagram to its normal
///    (forwarding/remote) route BEFORE the fwmark rule ever steered it to the
///    local-delivery table — transparent local delivery would never engage and
///    captured UDP would silently black-hole. A low constant (`100`) keeps the
///    fwmark lookup ahead of `main` (and of `local` at 0, which only matches
///    genuinely-local destinations and never the marked egress). The TABLE
///    number stays the high Ferrum-owned `33133`; only this RULE priority is low.
pub(crate) const TPROXY_ROUTE_RULE_PRIORITY: u32 = 100;

/// Istio-compatible `includeOutboundPorts` annotation. The injector and the
/// node-agent eBPF backend both read this key — keep the spelling exactly
/// in sync with Istio so existing operator annotations apply unchanged.
pub const ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION: &str =
    "traffic.sidecar.istio.io/includeOutboundPorts";
/// Ferrum-native alias for [`ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION`]. Both
/// keys are read; values from the two annotations merge per
/// [`include_outbound_ports_from_annotations`].
pub const FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION: &str = "ferrum.io/includeOutboundPorts";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Explicit,
    Iptables,
    Ebpf,
}

impl CaptureMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "explicit" => Ok(Self::Explicit),
            "iptables" => Ok(Self::Iptables),
            "ebpf" => Ok(Self::Ebpf),
            other => Err(format!(
                "Invalid FERRUM_MESH_CAPTURE_MODE '{other}'. Expected: explicit, iptables, or ebpf"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ip6TablesMode {
    Auto,
    Required,
    Disabled,
}

impl Ip6TablesMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "true" | "required" => Ok(Self::Required),
            "false" | "disabled" => Ok(Self::Disabled),
            other => Err(format!(
                "Invalid FERRUM_MESH_IP6TABLES_ENABLED '{other}'. Expected: auto, true, or false"
            )),
        }
    }

    pub fn as_env_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Required => "true",
            Self::Disabled => "false",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub mode: CaptureMode,
    pub proxy_uid: Option<u32>,
    pub inbound_port: u16,
    pub outbound_port: u16,
    /// Whether outbound capture is enabled. The node-agent sets this `false`
    /// when `FERRUM_MESH_OUTBOUND_LISTEN_ADDR`'s port is `0` (the mesh proxy
    /// disables its outbound listener), so it neither attaches the connect4/
    /// connect6 redirect nor publishes the in-netns registry — otherwise a
    /// captured pod's egress would be rewritten to a loopback port with no
    /// listener. Inbound capture is unaffected.
    pub outbound_capture_enabled: bool,
    pub include_cidrs: Vec<String>,
    /// True when `include_cidrs` came from operator or pod configuration rather
    /// than the implicit catch-all default. When includeOutboundPorts is set,
    /// the implicit default must not swallow all ports before port rules match.
    pub include_cidrs_explicit: bool,
    /// True when includeOutboundPorts was explicitly set to `*`. This must be
    /// distinct from an empty `include_outbound_ports`, which means the
    /// annotation was absent or empty and CIDR includes should drive capture.
    pub include_all_outbound_ports: bool,
    pub include_outbound_ports: Vec<u16>,
    pub exclude_cidrs: Vec<String>,
    pub exclude_ports: Vec<u16>,
    /// True when `exclude_ports` came from operator configuration rather than the
    /// implicit sidecar defaults. Ambient per-pod UDP capture runs inside workload
    /// netns with no co-located sidecar, so it must drop the implicit sidecar port
    /// excludes while preserving explicit operator exclusions.
    pub exclude_ports_explicit: bool,
    /// TCP destination ports excluded from the inbound capture chain. Each
    /// listed port emits a `RETURN` rule placed BEFORE the inbound REDIRECT,
    /// so traffic to the port bypasses the mesh sidecar entirely.
    pub exclude_inbound_ports: Vec<u16>,
    pub ip6tables_mode: Ip6TablesMode,
    /// Whether UDP TPROXY capture rules are emitted (F3 §3.3 Stage 2). Default
    /// `false`: UDP cannot use the TCP REDIRECT model (REDIRECT rewrites the
    /// destination and offers no per-datagram recoverable original address), so
    /// captured UDP uses TPROXY in the `mangle` table, which delivers the
    /// datagram WITHOUT rewriting its destination (recovered per-datagram from
    /// the `IP_RECVORIGDSTADDR` cmsg by the Stage 3 listener). This stage emits
    /// rules ONLY; the consuming UDP listener arrives in Stage 3, so leaving
    /// this off keeps an upgraded injector from redirecting UDP into a void.
    pub udp_capture_enabled: bool,
    /// UDP TPROXY listener port the captured datagrams are delivered to. Distinct
    /// from [`Self::outbound_port`] (the TCP REDIRECT target) because UDP+TCP
    /// cannot share one listener socket.
    pub udp_outbound_port: u16,
    /// Firewall mark stamped on TPROXY'd UDP datagrams; the policy routing rule
    /// matches it to steer them to the local-delivery table. See
    /// [`DEFAULT_TPROXY_MARK`] for the collision analysis.
    pub tproxy_mark: u32,
    /// `true` when these rules are applied in the HOST network namespace (the
    /// node-agent DaemonSet, `hostNetwork: true`), `false` for the injector init
    /// container (the POD's own network namespace).
    ///
    /// This gates ONLY the UDP TPROXY direction split. The TCP path separates
    /// inbound vs outbound by netfilter HOOK (`nat PREROUTING` vs `nat OUTPUT`),
    /// which is netns-agnostic, so it is unaffected. The UDP TPROXY path cannot
    /// use `OUTPUT` (TPROXY is `PREROUTING`-only) so it splits direction by
    /// destination ADDRESS TYPE (`-m addrtype --dst-type LOCAL`). That
    /// discriminator is only correct in the POD netns, where the pod's own IP is
    /// `LOCAL`: in the HOST netns pod IPs are FORWARDED (not `LOCAL`), so inbound
    /// UDP to a pod would match the OUTBOUND chain's `! --dst-type LOCAL`
    /// discriminator and be mis-captured. There is no host-netns-safe
    /// `addrtype`-style discriminator without per-pod IP knowledge the iptables
    /// fallback does not carry, so the host-netns UDP iptables fallback emits NO
    /// UDP TPROXY rules (eBPF is the node-agent's supported UDP capture path). See
    /// [`udp_tproxy_commands_for_family`].
    pub host_netns: bool,
}

impl CaptureConfig {
    /// Whether the Ambient UDP producer's per-pod setup will FATALLY require
    /// `ip6tables`: `FERRUM_MESH_IP6TABLES_ENABLED=required` AND at least one IPv6
    /// UDP include/exclude CIDR, so `udp_iptables_script` emits its required-mode
    /// `ip6tables` preflight (which `exit 1`s the per-pod script when `ip6tables`
    /// is missing). The producer's STARTUP preflight (`preflight_capture_tools`)
    /// consults this to fail fast when the runtime image lacks `ip6tables`, rather
    /// than letting every per-pod setup fail and retry forever (codex). The exact
    /// condition mirrors `udp_only_for_config`'s v6-command gate.
    pub(crate) fn udp_ipv6_capture_required(&self) -> bool {
        self.udp_capture_enabled
            && self.ip6tables_mode == Ip6TablesMode::Required
            && self
                .include_cidrs
                .iter()
                .chain(self.exclude_cidrs.iter())
                .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6))
    }

    /// Build an `Explicit`-mode capture config with the implicit `0.0.0.0/0`
    /// include CIDR default.
    ///
    /// `include_cidrs_explicit` is set to `false` here because the included
    /// `0.0.0.0/0` is the implicit catch-all default, not an operator-supplied
    /// value. Callers populating `include_cidrs` manually (e.g., tests) that
    /// want the operator-supplied-`0.0.0.0/0` semantics — where the catch-all
    /// is treated as an explicit choice rather than swallowed by
    /// `includeOutboundPorts` narrowing — should also set
    /// `include_cidrs_explicit: true` after construction.
    pub fn explicit(inbound_port: u16, outbound_port: u16) -> Self {
        Self {
            mode: CaptureMode::Explicit,
            proxy_uid: Some(DEFAULT_PROXY_UID),
            inbound_port,
            outbound_port,
            outbound_capture_enabled: true,
            include_cidrs: vec!["0.0.0.0/0".to_string()],
            include_cidrs_explicit: false,
            include_all_outbound_ports: false,
            include_outbound_ports: Vec::new(),
            exclude_cidrs: Vec::new(),
            exclude_ports: Vec::new(),
            exclude_ports_explicit: false,
            exclude_inbound_ports: Vec::new(),
            ip6tables_mode: Ip6TablesMode::Auto,
            udp_capture_enabled: false,
            udp_outbound_port: DEFAULT_UDP_OUTBOUND_PORT,
            tproxy_mark: DEFAULT_TPROXY_MARK,
            // The injector (pod netns) is the canonical `explicit`-config caller;
            // the node-agent (host netns) sets this `true` after `from_env`.
            host_netns: false,
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let mode = CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let proxy_uid = match resolve_ferrum_var("FERRUM_MESH_PROXY_UID") {
            Some(raw) => Some(parse_proxy_uid(&raw)?),
            None => Some(DEFAULT_PROXY_UID),
        };
        let include_cidrs_raw = resolve_ferrum_var("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS");
        let include_cidrs_explicit = include_cidrs_raw.is_some();
        let include_cidrs =
            parse_cidr_env(&include_cidrs_raw.unwrap_or_else(|| "0.0.0.0/0".to_string()));
        validate_cidr_list(&include_cidrs)?;
        let exclude_cidrs = parse_cidr_env(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS").unwrap_or_default(),
        );
        if !exclude_cidrs.is_empty() {
            validate_cidr_list(&exclude_cidrs)?;
        }
        let exclude_ports_raw = resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_PORTS");
        let exclude_ports_explicit = exclude_ports_raw.is_some();
        let exclude_ports = parse_port_list(
            &exclude_ports_raw.unwrap_or_else(|| "15001,15006,15008,15020".to_string()),
        )?;
        let exclude_inbound_ports = parse_port_list(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS").unwrap_or_default(),
        )?;
        let ip6tables_mode = Ip6TablesMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_IP6TABLES_ENABLED")
                .unwrap_or_else(|| "auto".to_string()),
        )?;
        let UdpCaptureSettings {
            udp_capture_enabled,
            udp_outbound_port,
            tproxy_mark,
        } = udp_capture_settings_from_env()?;
        Ok(Self {
            mode,
            proxy_uid,
            inbound_port: 15006,
            outbound_port: 15001,
            outbound_capture_enabled: true,
            include_cidrs,
            include_cidrs_explicit,
            include_all_outbound_ports: false,
            include_outbound_ports: Vec::new(),
            exclude_cidrs,
            exclude_ports,
            exclude_ports_explicit,
            exclude_inbound_ports,
            ip6tables_mode,
            udp_capture_enabled,
            udp_outbound_port,
            tproxy_mark,
            // `from_env` is the node-agent's capture-config source. The node-agent
            // runs `hostNetwork: true`, but the host-netns flag is set explicitly
            // by `NodeAgentConfig::from_env_config` (not inferred here) so a test
            // or future non-host-netns caller of `from_env` is not forced into the
            // host-netns UDP suppression. Default `false`; the node-agent flips it.
            host_netns: false,
        })
    }

    pub fn ensure_exclude_port(&mut self, port: u16) {
        if !self.exclude_ports.contains(&port) {
            self.exclude_ports.push(port);
        }
        self.exclude_ports_explicit = true;
    }

    pub fn clear_implicit_exclude_ports(&mut self) {
        if !self.exclude_ports_explicit {
            self.exclude_ports.clear();
        }
    }
}

/// UDP TPROXY capture settings parsed from the environment (F3 §3.3 Stage 2).
/// Shared by [`CaptureConfig::from_env`] (node-agent capture fallback) and the
/// injector so the three vars are parsed in exactly one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpCaptureSettings {
    pub udp_capture_enabled: bool,
    pub udp_outbound_port: u16,
    pub tproxy_mark: u32,
}

/// Parse `FERRUM_MESH_CAPTURE_UDP_ENABLED` (default `false`),
/// `FERRUM_MESH_CAPTURE_UDP_PORT` (default [`DEFAULT_UDP_OUTBOUND_PORT`]), and
/// `FERRUM_MESH_TPROXY_MARK` (default [`DEFAULT_TPROXY_MARK`]).
pub fn udp_capture_settings_from_env() -> Result<UdpCaptureSettings, String> {
    let udp_capture_enabled = parse_bool_env(
        resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_ENABLED").as_deref(),
        "FERRUM_MESH_CAPTURE_UDP_ENABLED",
    )?;
    let udp_outbound_port = match resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_PORT") {
        Some(raw) => parse_single_port(&raw, "FERRUM_MESH_CAPTURE_UDP_PORT")?,
        None => DEFAULT_UDP_OUTBOUND_PORT,
    };
    let tproxy_mark = match resolve_ferrum_var("FERRUM_MESH_TPROXY_MARK") {
        Some(raw) => parse_tproxy_mark(&raw)?,
        None => DEFAULT_TPROXY_MARK,
    };
    Ok(UdpCaptureSettings {
        udp_capture_enabled,
        udp_outbound_port,
        tproxy_mark,
    })
}

fn parse_cidr_env(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_port_list(raw: &str) -> Result<Vec<u16>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid port '{s}' in capture exclude ports"))?;
            if port == 0 {
                return Err(format!(
                    "Invalid port '{s}' in capture exclude ports: port must be 1-65535"
                ));
            }
            Ok(port)
        })
        .collect()
}

/// Pod-level `includeOutboundPorts` annotation parsed once, shared by the
/// injector (writes iptables rules in the init container) and the node-agent
/// eBPF capture path (writes a per-cgroup BPF map entry). Keeping a single
/// parser prevents the two surfaces from drifting apart on edge cases
/// (wildcard handling, duplicates, malformed tokens).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncludeOutboundPorts {
    /// `true` when the annotation was `*` — capture all outbound ports.
    pub all_ports: bool,
    /// Explicit destination ports to capture. Sorted, deduplicated. Empty
    /// when `all_ports == true`.
    pub ports: Vec<u16>,
}

impl IncludeOutboundPorts {
    /// Returns `true` when the annotation was absent / blank (capture
    /// driven purely by include CIDRs).
    pub fn is_absent(&self) -> bool {
        !self.all_ports && self.ports.is_empty()
    }
}

/// One annotation's parse result, before two annotations get merged together.
/// Kept private so the merge contract stays in
/// [`include_outbound_ports_from_annotations`].
#[derive(Debug, PartialEq, Eq)]
pub enum ParsedIncludePorts {
    Absent,
    All,
    Ports(Vec<u16>),
}

/// Parse a single `includeOutboundPorts` annotation value.
///
/// Returns:
/// - `Absent` for `None`, empty string, or whitespace-only string.
/// - `All` when the value is `*`.
/// - `Ports(_)` for a comma-separated list of 1..=65535 integers.
///
/// Errors on: mixing `*` with explicit ports, repeated `*`, non-numeric
/// tokens, port `0`, port outside `u16`.
pub fn parse_include_port_list(raw: Option<&str>) -> Result<ParsedIncludePorts, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(ParsedIncludePorts::Absent);
    };

    let mut ports = Vec::new();
    let mut saw_wildcard = false;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        if token == "*" {
            if saw_wildcard || !ports.is_empty() {
                return Err("wildcard '*' must be the only includeOutboundPorts token".to_string());
            }
            saw_wildcard = true;
            continue;
        }
        if saw_wildcard {
            return Err("wildcard '*' must be the only includeOutboundPorts token".to_string());
        }
        let port = token
            .parse::<u16>()
            .map_err(|e| format!("port '{token}': {e}"))?;
        if port == 0 {
            return Err("port '0': port must be 1-65535".to_string());
        }
        ports.push(port);
    }
    if saw_wildcard {
        return Ok(ParsedIncludePorts::All);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ParsedIncludePorts::Ports(ports))
}

/// Merge the two parallel `includeOutboundPorts` annotations
/// (Istio + Ferrum-native alias) into a single [`IncludeOutboundPorts`].
///
/// `annotations` is an iterator over `(annotation_key, raw_value)` pairs.
/// Callers pass the keys they want to consider, in priority order — typically
/// Istio first, then Ferrum's alias. The iterator should yield each key at
/// most once; duplicates are tolerated but only the first non-absent entry
/// per key sets the wildcard / explicit-ports keys for error messages.
///
/// Wildcard semantics: once any annotation says `*` no explicit ports may be
/// added from another annotation, and vice-versa. This is the same rule
/// `injector::include_outbound_ports_for_pod` previously enforced inline.
pub fn include_outbound_ports_from_annotations<'a, I>(
    annotations: I,
) -> Result<IncludeOutboundPorts, String>
where
    I: IntoIterator<Item = (&'a str, Option<&'a str>)>,
{
    let mut ports: Vec<u16> = Vec::new();
    let mut saw_wildcard = false;
    let mut wildcard_key: Option<&str> = None;
    let mut explicit_ports_key: Option<&str> = None;
    for (key, raw) in annotations {
        match parse_include_port_list(raw).map_err(|e| format!("invalid {key}: {e}"))? {
            ParsedIncludePorts::Absent => {}
            ParsedIncludePorts::All => {
                if !ports.is_empty() {
                    let explicit_key =
                        explicit_ports_key.unwrap_or("another includeOutboundPorts annotation");
                    return Err(format!(
                        "invalid {key}: wildcard '*' cannot be combined with explicit includeOutboundPorts in {explicit_key}"
                    ));
                }
                saw_wildcard = true;
                wildcard_key.get_or_insert(key);
            }
            ParsedIncludePorts::Ports(annotation_ports) => {
                if saw_wildcard && !annotation_ports.is_empty() {
                    let wildcard_key =
                        wildcard_key.unwrap_or("another includeOutboundPorts annotation");
                    return Err(format!(
                        "invalid {key}: explicit includeOutboundPorts cannot be combined with wildcard '*' in {wildcard_key}"
                    ));
                }
                if !annotation_ports.is_empty() {
                    explicit_ports_key.get_or_insert(key);
                }
                ports.extend(annotation_ports);
            }
        }
    }
    if saw_wildcard {
        return Ok(IncludeOutboundPorts {
            all_ports: true,
            ports: Vec::new(),
        });
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(IncludeOutboundPorts {
        all_ports: false,
        ports,
    })
}

/// Parse a boolean capture env var. Absent / blank defaults to `false`. Accepts
/// the repo-wide boolean env forms (`EnvValue for bool` in
/// `config::env_config_macro`): case-insensitive `true`/`false` plus `1`/`0`.
/// Rust's `bool::from_str` (used previously) rejected `1`/`0`/`TRUE`, diverging
/// from every sibling `FERRUM_MESH_*` bool env (codex r3).
fn parse_bool_env(raw: Option<&str>, var: &str) -> Result<bool, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(false),
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(format!(
                "Invalid {var} '{value}'. Expected true, false, 1, or 0"
            )),
        },
    }
}

/// Parse a single 1..=65535 destination port from an env var.
fn parse_single_port(raw: &str, var: &str) -> Result<u16, String> {
    let trimmed = raw.trim();
    let port = trimmed
        .parse::<u16>()
        .map_err(|_| format!("Invalid {var} '{raw}'. Expected a port in 1-65535"))?;
    if port == 0 {
        return Err(format!("Invalid {var} '{raw}': port must be 1-65535"));
    }
    Ok(port)
}

/// Parse the TPROXY firewall mark, accepting `0x`-prefixed hex or decimal. A
/// zero mark is rejected — the policy routing rule and `--tproxy-mark` selector
/// would match unmarked packets and steer all local traffic into the TPROXY
/// table.
fn parse_tproxy_mark(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u32>()
    }
    .map_err(|_| {
        format!("Invalid FERRUM_MESH_TPROXY_MARK '{raw}'. Expected a 32-bit hex (0x...) or decimal value")
    })?;
    if parsed == 0 {
        return Err("Invalid FERRUM_MESH_TPROXY_MARK '0': mark must be non-zero".to_string());
    }
    Ok(parsed)
}

fn parse_proxy_uid(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_PROXY_UID);
    }
    trimmed
        .parse::<u32>()
        .map_err(|_| format!("Invalid FERRUM_MESH_PROXY_UID '{raw}'. Expected unsigned integer"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesPlan {
    pub v4_commands: Vec<String>,
    pub v6_commands: Vec<String>,
    pub ip6tables_mode: Ip6TablesMode,
}

impl IptablesPlan {
    pub fn for_config(config: &CaptureConfig) -> Self {
        // IPv4 always emits chains because inbound capture is protocol-wide for
        // an active address family, even when only IPv6 outbound CIDRs exist.
        let v4_commands = commands_for_family("iptables", config, CidrFamily::V4, true);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            commands_for_family("ip6tables", config, CidrFamily::V6, false)
        } else if v6_has_cidrs {
            warn!(
                "Skipping IPv6 mesh capture rules because FERRUM_MESH_IP6TABLES_ENABLED is disabled"
            );
            Vec::new()
        } else {
            Vec::new()
        };

        Self {
            v4_commands,
            v6_commands,
            ip6tables_mode: config.ip6tables_mode,
        }
    }

    /// Build a plan containing ONLY the UDP TPROXY capture rules — never the TCP
    /// `nat` REDIRECT chains — for the Ambient per-pod-netns UDP producer
    /// (`src/proxy/netns_udp_capture.rs`).
    ///
    /// The Ambient proxy installs these from INSIDE each enrolled pod's netns.
    /// Ambient's TCP capture rides eBPF/HBONE (not iptables), so emitting the TCP
    /// nat chains here would be wrong; the Sidecar injector keeps using
    /// [`Self::for_config`] (TCP REDIRECT + UDP TPROXY together). The UDP rules
    /// themselves are generated by the SAME `udp_tproxy_commands_for_family`
    /// the injector uses, so producer and injector never diverge.
    ///
    /// Family gating mirrors [`Self::for_config`]: IPv4 always, IPv6 only when
    /// `ip6tables` is enabled AND a v6 CIDR is configured. The whole plan is
    /// empty when `udp_capture_enabled` is `false` or `host_netns` is `true`
    /// (the latter via `udp_tproxy_commands_for_family`'s host-netns
    /// suppression, preserving the "no host-netns UDP rules" invariant even
    /// though the producer never runs in host netns).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_only_for_config(config: &CaptureConfig) -> Self {
        if !config.udp_capture_enabled {
            return Self {
                v4_commands: Vec::new(),
                v6_commands: Vec::new(),
                ip6tables_mode: config.ip6tables_mode,
            };
        }
        let v4_commands = udp_only_commands_for_family(config, CidrFamily::V4);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            udp_only_commands_for_family(config, CidrFamily::V6)
        } else {
            Vec::new()
        };
        Self {
            v4_commands,
            v6_commands,
            ip6tables_mode: config.ip6tables_mode,
        }
    }

    /// Generate iptables commands that reverse the setup performed by
    /// [`for_config`]. The cleanup order matters:
    ///
    /// 1. Delete the jump rules from the built-in chains (`PREROUTING`,
    ///    `OUTPUT`) so no new traffic enters the custom chains.
    /// 2. Flush the custom chains (remove all rules inside them).
    /// 3. Delete the now-empty custom chains.
    ///
    /// Each command uses `2>/dev/null || true` so partial cleanup (e.g.
    /// chains already removed by a previous run) does not fail the overall
    /// teardown.
    /// TCP-chain teardown plus, when `udp_capture_enabled`, the UDP TPROXY
    /// `mangle` chains and the Ferrum-owned routing rule/route. The UDP teardown
    /// is gated so a non-UDP install never touches routing state it never
    /// created (codex r1); pass the install's `udp_capture_enabled` flag.
    /// Flat IPv4 cleanup (iptables-table teardown then raw routing teardown).
    /// Test-only convenience; production node-agent code uses [`Self::cleanup_split`]
    /// so it can guard only the table portion behind the `ip6tables` probe.
    #[cfg(test)]
    pub fn cleanup_commands(udp_capture_enabled: bool) -> Vec<String> {
        cleanup_commands_for("iptables", udp_capture_enabled).into_flat()
    }

    /// Flat IPv6 cleanup. Test-only; see [`Self::cleanup_v6_split`].
    #[cfg(test)]
    pub fn cleanup_v6_commands(udp_capture_enabled: bool) -> Vec<String> {
        cleanup_commands_for("ip6tables", udp_capture_enabled).into_flat()
    }

    /// The IPv4 cleanup split into the iptables-table teardown vs. the raw `ip`
    /// routing teardown. The node-agent emits the routing teardown UNCONDITIONALLY
    /// (it is `ip`, not `iptables`/`ip6tables`); see [`Self::cleanup_v6_split`].
    pub fn cleanup_split(udp_capture_enabled: bool) -> CleanupCommands {
        cleanup_commands_for("iptables", udp_capture_enabled)
    }

    /// The IPv6 cleanup split into the **ip6tables-table** teardown (`iptables`,
    /// which the node-agent guards behind an `ip6tables` availability probe) and
    /// the **raw `ip -6` routing** teardown (`ip_routing`, the fwmark rule + local
    /// route). The routing teardown MUST be emitted UNCONDITIONALLY — `ip -6` can
    /// remove the rule/route even when `ip6tables` is missing, so wrapping it in
    /// the ip6tables guard would leak the fwmark rule + local route and keep
    /// diverting marked UDP after shutdown (codex r3).
    pub fn cleanup_v6_split(udp_capture_enabled: bool) -> CleanupCommands {
        cleanup_commands_for("ip6tables", udp_capture_enabled)
    }

    /// The EXACT Ferrum-owned **IPv4** UDP TPROXY teardown (mangle chains +
    /// fwmark rule by stable priority + local route), split like
    /// [`Self::cleanup_split`]. Contains ONLY UDP state — never the TCP nat
    /// chains — so the node-agent runs it UNCONDITIONALLY before setup to reap
    /// stale UDP state left by a prior UDP-enabled-then-crashed run, even when the
    /// current `FERRUM_MESH_CAPTURE_UDP_ENABLED` is `false` (codex r4). Idempotent
    /// and best-effort; a no-op when no UDP state exists.
    pub fn udp_teardown_split() -> CleanupCommands {
        udp_teardown_for("iptables")
    }

    /// The EXACT Ferrum-owned **IPv6** UDP TPROXY teardown, split like
    /// [`Self::cleanup_v6_split`] (the `iptables`/ip6tables-table half is guarded
    /// behind the node-agent's `ip6tables` probe; the raw `ip -6` routing half is
    /// emitted unconditionally). See [`Self::udp_teardown_split`].
    pub fn udp_teardown_v6_split() -> CleanupCommands {
        udp_teardown_for("ip6tables")
    }
}

/// A capture-cleanup command list split by whether each command touches an
/// iptables/ip6tables TABLE (`iptables`) or is a raw `ip`/`ip -6` routing command
/// (`ip_routing`). The node-agent guards only the `iptables` portion behind an
/// `ip6tables`-availability probe for IPv6; the `ip_routing` portion is always
/// emitted so routing state is torn down regardless of `ip6tables` availability.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanupCommands {
    /// `iptables`/`ip6tables` table teardown (jump deletes, chain flush, chain
    /// delete) — for the IPv6 family these are guarded behind an `ip6tables`
    /// availability probe by the node-agent.
    pub iptables: Vec<String>,
    /// Raw `ip`/`ip -6` routing teardown (fwmark `ip rule` + local `ip route`).
    /// Emitted unconditionally — `ip` does not depend on `ip6tables`.
    pub ip_routing: Vec<String>,
}

impl CleanupCommands {
    /// iptables-table teardown first, then the routing teardown — preserving the
    /// original flat ordering for the init-container cleanup script. Test-only
    /// (production composes the two halves with per-half guarding).
    #[cfg(test)]
    fn into_flat(self) -> Vec<String> {
        let mut commands = self.iptables;
        commands.extend(self.ip_routing);
        commands
    }
}

// EbpfPlan and helpers are consumed by the node-agent eBPF capture path
// (ambient DaemonSet integration). The sidecar injector deliberately does NOT
// inject an init container for eBPF mode — privileged capabilities would cause
// Pod Security Baseline/Restricted admission rejection on every pod, even when
// the script does nothing on 5.7+ kernels.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfPlan {
    pub enabled: bool,
    pub fallback: IptablesPlan,
    pub required_kernel: &'static str,
}

#[allow(dead_code)]
impl EbpfPlan {
    pub fn for_config(config: &CaptureConfig) -> Self {
        Self {
            enabled: config.mode == CaptureMode::Ebpf,
            fallback: IptablesPlan::for_config(config),
            required_kernel: "5.7",
        }
    }

    pub fn fallback_script(&self) -> String {
        let fallback_cmds = self.fallback.script();
        let (major, minor) = parse_kernel_requirement(self.required_kernel);
        format!(
            "MAJOR=$(uname -r | cut -d. -f1)\n\
             MINOR=$(uname -r | cut -d. -f2)\n\
             if [ \"$MAJOR\" -lt {major} ] || \
             {{ [ \"$MAJOR\" -eq {major} ] && [ \"$MINOR\" -lt {minor} ]; }}; then\n\
             echo \"Kernel $(uname -r) < {req}, falling back to iptables\"\n\
             {fallback_cmds}\n\
             else\n\
             echo \"Kernel $(uname -r) supports eBPF capture, skipping iptables\"\n\
             fi",
            req = self.required_kernel,
        )
    }
}

impl IptablesPlan {
    pub fn script(&self) -> String {
        // `set -e` makes the injected init container fail **closed**: if any
        // iptables rule fails to apply, the script exits non-zero and the pod's
        // init phase fails, instead of starting the workload with a partial
        // capture ruleset that would let egress silently bypass the mesh proxy
        // (and therefore `mesh_authz`). The idempotent command shapes are
        // `set -e`-safe — `-N ... || true` and `-C ... || -A ...` only abort on
        // a real `-A` append failure, never on the expected `-C`/`-N` misses.
        format!(
            "set -e\n{}",
            iptables_script(
                &self.v4_commands,
                &self.v6_commands,
                self.ip6tables_mode,
                true,
            )
        )
    }

    /// The UDP-only `set -e` setup script the Ambient per-pod-netns producer runs
    /// INSIDE each enrolled pod's netns. Builds [`Self::udp_only_for_config`] and
    /// renders it fail-closed: any rule failure aborts (`set -e`), so the producer
    /// treats a partial install as a failure, tears its partial state back down,
    /// and retries — never leaving a pod half-captured.
    ///
    /// The IPv6 block probes the **`mangle`** table (where the UDP TPROXY chains
    /// live), NOT `nat` — a host with `mangle` but no `nat` table must still run
    /// the UDP v6 rules. Empty (`""`) when UDP capture is off, `host_netns` is
    /// set, or no family emitted rules.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_setup_script(config: &CaptureConfig) -> String {
        let plan = Self::udp_only_for_config(config);
        if plan.v4_commands.is_empty() && plan.v6_commands.is_empty() {
            return String::new();
        }
        format!(
            "set -e\n{}",
            udp_iptables_script(
                &plan.v4_commands,
                &plan.v6_commands,
                plan.ip6tables_mode,
                true
            )
        )
    }

    /// The UDP-only teardown script the Ambient producer runs INSIDE a pod netns
    /// on pod removal, config change, install failure, or shutdown. Reuses the
    /// EXACT Ferrum-owned UDP teardown ([`Self::udp_teardown_split`] /
    /// [`Self::udp_teardown_v6_split`]) so producer cleanup and injector/node-agent
    /// cleanup never diverge, and is best-effort throughout (NO `set -e`): a
    /// partially installed ruleset or an already-gone netns must not abort
    /// teardown. The raw `ip`/`ip -6` routing teardown is emitted unconditionally
    /// (it does not depend on `ip6tables`); only the `ip6tables`-TABLE teardown is
    /// guarded behind an `ip6tables` (`mangle`) availability probe.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_teardown_script(include_v6: bool) -> String {
        let v4 = Self::udp_teardown_split();
        let mut chunks: Vec<String> = Vec::new();
        chunks.extend(v4.iptables);
        chunks.extend(v4.ip_routing);
        if include_v6 {
            let v6 = Self::udp_teardown_v6_split();
            chunks.extend(
                v6.iptables
                    .iter()
                    .map(|cmd| ip6tables_probe_guard(cmd, "mangle")),
            );
            chunks.extend(v6.ip_routing);
        }
        chunks.join("\n")
    }

    #[cfg(test)]
    pub fn cleanup_script(
        include_v6: bool,
        ip6tables_mode: Ip6TablesMode,
        udp_capture_enabled: bool,
    ) -> String {
        let v4_commands = Self::cleanup_commands(udp_capture_enabled);
        let v6_commands = if include_v6 {
            Self::cleanup_v6_commands(udp_capture_enabled)
        } else {
            Vec::new()
        };
        iptables_script(&v4_commands, &v6_commands, ip6tables_mode, false)
    }
}

#[allow(dead_code)]
fn parse_kernel_requirement(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(5);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(7);
    (major, minor)
}

pub fn should_fallback_to_iptables(kernel_release: &str) -> bool {
    let mut parts = kernel_release.split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major < 5 || (major == 5 && minor < 7),
        _ => true,
    }
}

pub fn validate_cidr_list(cidrs: &[String]) -> Result<(), String> {
    for cidr in cidrs {
        let Some((addr, prefix)) = cidr.split_once('/') else {
            return Err(format!("CIDR '{cidr}' must include a prefix length"));
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("CIDR '{cidr}' has invalid IP address"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("CIDR '{cidr}' has invalid prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!(
                "CIDR '{cidr}' prefix length {prefix} exceeds max {max}"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CidrFamily {
    V4,
    V6,
}

fn cidr_family(cidr: &str) -> Option<CidrFamily> {
    cidr.split_once('/')
        .and_then(|(addr, _)| addr.parse::<IpAddr>().ok())
        .map(|ip| {
            if ip.is_ipv4() {
                CidrFamily::V4
            } else {
                CidrFamily::V6
            }
        })
}

fn commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    emit_inbound_regardless: bool,
) -> Vec<String> {
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    // Inbound capture is protocol-wide for an active address family; IPv4
    // therefore keeps inbound chains even when only IPv6 outbound CIDRs exist.
    if !emit_inbound_regardless && include_cidrs.is_empty() && exclude_cidrs.is_empty() {
        return Vec::new();
    }

    let mut commands = Vec::new();
    commands.push(idempotent_new_chain(binary, "nat", "FERRUM_MESH_INBOUND"));
    commands.push(idempotent_new_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"));

    for cidr in &exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    if let Some(uid) = config.proxy_uid {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-m owner --uid-owner {uid} -j RETURN"),
        ));
    }
    if config.include_all_outbound_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-p tcp -j REDIRECT --to-ports {}", config.outbound_port),
        ));
    } else {
        // includeOutboundPorts without an explicit include-CIDR annotation means
        // "capture only these ports" rather than "add these ports to the
        // implicit 0.0.0.0/0 catch-all". Explicit include CIDRs stay additive.
        let emit_include_cidrs =
            config.include_outbound_ports.is_empty() || config.include_cidrs_explicit;
        if emit_include_cidrs {
            if include_cidrs.is_empty() {
                let has_include_cidrs_for_other_family = config
                    .include_cidrs
                    .iter()
                    .any(|cidr| cidr_family(cidr).is_some_and(|cidr_family| cidr_family != family));
                if config.include_cidrs_explicit || !has_include_cidrs_for_other_family {
                    commands.push(idempotent_append(
                        binary,
                        "nat",
                        "FERRUM_MESH_OUTBOUND",
                        &format!("-p tcp -j REDIRECT --to-ports {}", config.outbound_port),
                    ));
                }
            } else {
                for cidr in &include_cidrs {
                    commands.push(idempotent_append(
                        binary,
                        "nat",
                        "FERRUM_MESH_OUTBOUND",
                        &format!(
                            "-p tcp -d {cidr} -j REDIRECT --to-ports {}",
                            config.outbound_port
                        ),
                    ));
                }
            }
        }
        for port in &config.include_outbound_ports {
            commands.push(idempotent_append(
                binary,
                "nat",
                "FERRUM_MESH_OUTBOUND",
                &format!(
                    "-p tcp --dport {port} -j REDIRECT --to-ports {}",
                    config.outbound_port
                ),
            ));
        }
    }
    // Inbound port exclusions MUST be appended before the catch-all REDIRECT
    // below — once REDIRECT fires the chain returns, so any RETURN rule placed
    // after it would be silently bypassed.
    for port in &config.exclude_inbound_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_INBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    // CIDR include/exclude settings scope outbound capture only. Once this
    // address family is active, inbound capture stays protocol-wide so replies
    // and server-initiated inbound connections are consistently redirected.
    commands.push(idempotent_append(
        binary,
        "nat",
        "FERRUM_MESH_INBOUND",
        &format!("-p tcp -j REDIRECT --to-ports {}", config.inbound_port),
    ));
    commands.push(idempotent_append(
        binary,
        "nat",
        "PREROUTING",
        "-p tcp -j FERRUM_MESH_INBOUND",
    ));
    commands.push(idempotent_append(
        binary,
        "nat",
        "OUTPUT",
        "-p tcp -j FERRUM_MESH_OUTBOUND",
    ));
    if config.udp_capture_enabled {
        commands.extend(udp_tproxy_commands_for_family(
            binary,
            config,
            family,
            &include_cidrs,
            &exclude_cidrs,
            // Injector (Sidecar): capture inbound-to-pod UDP too (fail-closed).
            true,
        ));
    }
    commands
}

/// Emit UDP TPROXY capture rules for one address family (F3 §3.3 Stage 2).
///
/// Unlike the TCP path (`nat`-table REDIRECT, which rewrites the destination to
/// the proxy port), UDP capture uses TPROXY in the `mangle` table: TPROXY
/// delivers the datagram to a transparent socket WITHOUT rewriting its
/// destination, so the Stage 3 listener recovers the original destination
/// per-datagram from the `IP_RECVORIGDSTADDR` cmsg. Transparent delivery
/// additionally needs a firewall mark plus an `ip rule`/`ip route local` so the
/// kernel routes the marked datagram to the local socket.
///
/// The include/exclude/CIDR/uid logic mirrors the TCP outbound chain so
/// operator capture scoping (`includeOutboundPorts`, `excludeOutboundPorts`,
/// include/exclude CIDRs, the proxy-UID self-exclusion) applies identically to
/// UDP.
///
/// **Direction scoping mirrors the TCP chains (codex r2).** The TCP path keeps
/// the two directions disjoint by HOOK — inbound rides `nat PREROUTING`, outbound
/// rides `nat OUTPUT` — so neither swallows the other. TPROXY cannot use that
/// trick (it is `PREROUTING`-only; see below), so BOTH UDP chains are jumped from
/// `mangle PREROUTING`. To keep them from clobbering each other we instead
/// discriminate by DESTINATION ADDRESS TYPE, the pod-IP-agnostic equivalent:
/// - the OUTBOUND chain's TPROXY rules carry `-m addrtype ! --dst-type LOCAL`
///   (egress = a remote/non-local destination), and
/// - the INBOUND catch-all TPROXY carries `-m addrtype --dst-type LOCAL`
///   (inbound = a destination configured on this box, i.e. the pod's own IP).
///
/// The OUTBOUND jump is also installed BEFORE the INBOUND jump so egress is
/// matched/routed first. Without this, the inbound catch-all (xt_TPROXY returns
/// `NF_ACCEPT`, ending PREROUTING traversal) would grab pod EGRESS too — the
/// outbound include/exclude/CIDR/port rules would be silently bypassed.
///
/// **TPROXY is PREROUTING-only; locally-generated egress rides an OUTPUT MARK →
/// lo-reroute → PREROUTING-TPROXY loop (codex r6).** The TPROXY target runs ONLY
/// in `PREROUTING`, never for locally-generated (OUTPUT) packets — jumping into a
/// `-j TPROXY` chain from `mangle OUTPUT` is invalid and can make iptables setup
/// fail. But Linux routes a pod's OWN application UDP egress through
/// OUTPUT→POSTROUTING and NEVER through PREROUTING, so the PREROUTING TPROXY
/// chains alone would never see the primary egress case (outbound UDP capture
/// would be inert in the pod netns). The standard "TPROXY for locally-generated
/// traffic" pattern closes this: a `mangle OUTPUT` chain (`FERRUM_MESH_UDP_OUTPUT_
/// MARK`) MARKs the egress (NOT TPROXY) with the same fwmark the PREROUTING rules
/// use; the existing fwmark `ip rule` (priority [`TPROXY_ROUTE_RULE_PRIORITY`] →
/// table [`TPROXY_ROUTE_TABLE`]) + `ip route add local ... dev lo` reroute the
/// marked datagram to loopback; it re-enters the INPUT path, traverses PREROUTING
/// once, and a mark-match `-j TPROXY` rule (in `FERRUM_MESH_UDP_REINJECT`, jumped
/// from PREROUTING FIRST) captures it to the UDP port. The `local`-route delivery
/// diverts the looped datagram to the INPUT side, so OUTPUT is hit exactly once
/// (no loop), and the OUTPUT chain leads with a `-m mark --mark <mark> -j RETURN`
/// anti-loop guard plus a proxy-UID `-m owner --uid-owner <uid> -j RETURN`
/// self-exclusion (owner-match IS valid in OUTPUT — it is invalid in PREROUTING,
/// which is why the dst-based OUTBOUND chain carries no owner RETURN). The full
/// datapath correctness of this loop is validated by the Stage-7
/// `netns-capture-live` e2e (see `docs/mesh.md`).
///
/// **Fail closed when policy routing is unavailable (codex r2).** TPROXY local
/// delivery REQUIRES the `ip rule` + `ip route local` plumbing; installing the
/// mangle TPROXY rules without it is a silent black-hole (the pod comes up
/// "ready" but captured UDP is never delivered). So when UDP capture is enabled
/// this emits a FATAL `command -v ip` preflight BEFORE any UDP rule (no `ip` ⇒
/// the `set -e` script exits non-zero, installing neither the TPROXY rules nor
/// the routing), and the load-bearing routing ADD commands are NOT `|| true`
/// (a failed add aborts the script). Only the delete-before-add (idempotence)
/// keeps `|| true`. TPROXY rules and routing are installed TOGETHER or not at
/// all — never the half-state of TPROXY-without-routing.
///
/// **Routing is installed BEFORE the PREROUTING jumps (codex r5).** The two
/// `mangle PREROUTING` jumps are what actually start steering UDP into the
/// (initially empty of route) chains; the fwmark `ip rule` + local `ip route`
/// are what make the marked datagrams deliverable. The injector init container
/// runs the whole `set -e` script with NO cleanup trap, so if `ip rule`/`ip
/// route` failed AFTER the jumps were appended the pod would come up with TPROXY
/// chains live but no policy routing — exactly the black-hole this stage avoids.
/// Emitting the routing FIRST means a routing failure aborts the `set -e` script
/// BEFORE any capture is wired (and benefits the node-agent's sequential runner
/// identically). The chains/rules themselves are inert until the jumps are
/// appended last.
///
/// **Host-netns direction split (codex r5).** The inbound vs outbound split
/// below uses `-m addrtype --dst-type LOCAL` / `! --dst-type LOCAL`. That is
/// correct ONLY in the POD netns (the injector), where the pod's own IP is
/// `LOCAL`. The node-agent runs `hostNetwork: true` (host netns) where pod IPs
/// are FORWARDED, not `LOCAL`, so inbound UDP to a pod would match the OUTBOUND
/// `! --dst-type LOCAL` discriminator and be TPROXY'd by the outbound chain
/// (bypassing inbound exclusions). There is no host-netns-safe `addrtype`-style
/// discriminator here without per-pod IP knowledge the iptables fallback does not
/// carry, and this path is inert (flag-gated default-off, no Stage-3 listener,
/// eBPF is the node-agent's primary/supported UDP capture path), so the
/// host-netns case emits NO UDP TPROXY rules rather than silently
/// mis-capturing inbound as outbound. See [`CaptureConfig::host_netns`].
fn udp_tproxy_commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    include_cidrs: &[&str],
    exclude_cidrs: &[&str],
    emit_inbound: bool,
) -> Vec<String> {
    // Host-netns UDP suppression (codex r5, finding #1). The `addrtype --dst-type
    // LOCAL` direction split below is only valid in the pod netns; in the host
    // netns it mis-captures inbound-to-pod UDP as outbound. Rather than wire a
    // wrong direction split, the host-netns iptables fallback emits no UDP TPROXY
    // rules at all — eBPF is the node-agent's supported UDP capture path. The
    // node-agent logs the limitation once when it would otherwise emit these.
    if config.host_netns {
        return Vec::new();
    }

    // Cross-family CATCH-ALL suppression (codex r4 finding #1, narrowed by codex
    // r5 finding #2): when the include list is EXPLICIT and NONE of its CIDRs
    // belong to THIS family (e.g. an IPv6-only include leaving the IPv4 family
    // with no include CIDR), this family was NOT selected by CIDR. We must NOT
    // emit the unqualified `-j TPROXY` CATCH-ALLs (the implicit outbound catch-all
    // AND the inbound `--dst-type LOCAL` catch-all) — an unqualified UDP TPROXY
    // would divert ALL of this family's UDP (DNS included) into the marked routing
    // table, and until the Stage 3 UDP listener exists that is a silent
    // black-hole. This is DELIBERATELY the OPPOSITE of the TCP cross-family
    // fallback (`emit_outbound_redirect_commands`, which fails closed to a
    // catch-all REDIRECT that delivers to the existing TCP outbound listener).
    //
    // BUT port includes (`includeOutboundPorts`/`--dport`) are NOT family-scoped:
    // an IPv4 DNS-port (53) include must still emit its IPv4 `--dport` TPROXY rule
    // even when only an IPv6 CIDR is set (codex r5 finding #2 — the old whole-
    // family early-return silently dropped it). So this suppresses only the
    // unqualified catch-alls; the per-port `--dport` and per-CIDR `-d` rules below
    // still emit. If nothing else emits a TPROXY rule the family produces no UDP
    // state at all (computed at the end), preserving the original behavior for the
    // pure-CIDR cross-family case. An IMPLICIT default (`!include_cidrs_explicit`)
    // or a genuinely-empty/ports-only explicit config (no family carries an
    // include CIDR) does NOT trip this — the catch-all is the intended capture.
    let suppress_catch_all = config.include_cidrs_explicit
        && include_cidrs.is_empty()
        && config
            .include_cidrs
            .iter()
            .any(|cidr| cidr_family(cidr).is_some_and(|cidr_family| cidr_family != family));

    let mark = config.tproxy_mark;
    let mark_arg = format!("0x{mark:x}/0x{TPROXY_MARK_MASK:x}");
    let tproxy_jump = format!(
        "-j TPROXY --on-port {} --tproxy-mark {mark_arg}",
        config.udp_outbound_port
    );
    // OUTPUT-path MARK jump (codex r6): stamps the same fwmark the PREROUTING
    // TPROXY rules use, so a locally-generated pod UDP datagram is rerouted to
    // loopback by the fwmark `ip rule` and re-enters PREROUTING to be TPROXY'd.
    let mark_jump = format!("-j MARK --set-mark {mark_arg}");
    // Outbound (egress) discriminator: a remote/non-local destination. Mirrors
    // the TCP path's hook-based direction separation (which TPROXY can't use,
    // being PREROUTING-only) via destination address type, so this OUTBOUND chain
    // never grabs traffic destined for the pod's own IP (that is the INBOUND
    // chain's job, scoped with the complementary `--dst-type LOCAL`).
    let outbound_dst_scope = "-m addrtype ! --dst-type LOCAL";

    // Compute the OUTBOUND selector specs ONCE (the `-p udp [-d <cidr>|--dport
    // <port>]` portion before any direction-scope / jump), then render two rule
    // sets from them so the PREROUTING TPROXY chain and the OUTPUT MARK chain
    // share identical capture scoping (codex r6):
    //   - PREROUTING TPROXY rules append the `! --dst-type LOCAL` egress scope so
    //     they never grab inbound (the INBOUND chain's `--dst-type LOCAL` job).
    //   - OUTPUT MARK rules ALSO append the SAME `! --dst-type LOCAL` egress scope
    //     (codex r9): in the OUTPUT context the pod's OWN IP and loopback are
    //     `--dst-type LOCAL` (locally generated AND locally destined), while real
    //     egress to other hosts is non-LOCAL. Without this scope the catch-all
    //     `-p udp -d 0.0.0.0/0 -j MARK` would also fwmark pod-to-self / loopback
    //     UDP, reroute it to `lo`, and TPROXY-capture it — but self/loopback UDP
    //     must NOT be captured (only genuine outbound egress). The proxy's own
    //     egress is still separately excluded by the owner-match RETURN at the top
    //     of the OUTPUT chain (owner-match is OUTPUT-context-only — invalid in
    //     PREROUTING); the dst-type scope handles non-proxy local destinations the
    //     owner RETURN cannot (a different UID's pod-to-self/loopback datagram).
    // `catch_all` selectors (the implicit-CIDR / `include_all_outbound_ports`
    // catch-alls) are suppressed when this family was NOT CIDR-selected
    // (cross-family case); the per-CIDR `-d` and per-port `--dport` selectors
    // always emit (codex r5 finding #2 — port includes are not family-scoped).
    let mut outbound_selectors: Vec<String> = Vec::new();
    if config.include_all_outbound_ports {
        if !suppress_catch_all {
            outbound_selectors.push("-p udp".to_string());
        }
    } else {
        let emit_include_cidrs =
            config.include_outbound_ports.is_empty() || config.include_cidrs_explicit;
        if emit_include_cidrs {
            if include_cidrs.is_empty() {
                // Unqualified outbound catch-all — emitted only when this family is
                // NOT cross-family-suppressed (an IMPLICIT `0.0.0.0/0`/`::/0`
                // default or a genuinely-empty / ports-only explicit config — both
                // of which intend full-family UDP capture). Suppressed for a family
                // the operator did not select by CIDR (codex r4 + r5).
                if !suppress_catch_all {
                    outbound_selectors.push("-p udp".to_string());
                }
            } else {
                for cidr in include_cidrs {
                    outbound_selectors.push(format!("-p udp -d {cidr}"));
                }
            }
        }
        // Port includes (`--dport`) are NOT family-scoped: an IPv4 DNS-port (53)
        // include emits its IPv4 `--dport` rule even when only an IPv6 CIDR is set
        // (codex r5 finding #2). These survive the cross-family catch-all
        // suppression above.
        for port in &config.include_outbound_ports {
            outbound_selectors.push(format!("-p udp --dport {port}"));
        }
    }
    let outbound_tproxy_rules: Vec<String> = outbound_selectors
        .iter()
        .map(|sel| format!("{sel} {outbound_dst_scope} {tproxy_jump}"))
        .collect();
    let outbound_mark_rules: Vec<String> = outbound_selectors
        .iter()
        .map(|sel| format!("{sel} {outbound_dst_scope} {mark_jump}"))
        .collect();

    // Whether to emit the INBOUND `--dst-type LOCAL` TPROXY chain/jump, decided by
    // the CALLER (the `emit_inbound` parameter):
    //
    // * The **injector** (Sidecar, `commands_for_family`) passes `true`: inbound
    //   UDP to the pod is captured so unauthenticated pod-destined UDP can't bypass
    //   mesh identity/authz, fail-closing in the egress-only listener.
    //
    // * The **Ambient per-pod-netns producer** (`udp_only_commands_for_family`)
    //   passes `false` — OUTBOUND-ONLY. The producer installs rules INSIDE every
    //   enrolled pod netns, including DESTINATION pods, where an inbound
    //   `--dst-type LOCAL` chain would capture the HBONE datagram relay's own
    //   delivery to the local app (`handle_hbone_udp_request` → local `UdpSocket`
    //   send to the pod app) AND the source pod's return-path reply to the client,
    //   TPROXY them into the egress-only listener, and DROP them — black-holing the
    //   relayed UDP both ways. The producer only needs to capture the pod's
    //   OUTBOUND egress (to relay it); inbound-to-pod UDP must flow to the app
    //   untouched (codex).

    // If this family emits NO TPROXY rule at all (e.g. a pure-CIDR cross-family
    // skip with no port includes), produce NO UDP state for it — no chains, no
    // PREROUTING jumps, no routing — preserving the original cross-family behavior
    // (codex r4) while letting port includes survive (codex r5).
    if outbound_tproxy_rules.is_empty() && !emit_inbound {
        return Vec::new();
    }

    // The fixed prefix (in order):
    //   1. FAIL CLOSED if `ip` is missing — TPROXY local delivery is useless
    //      without the `ip rule`/`ip route local` plumbing, so a runtime image
    //      without `iproute2` must NOT come up with TPROXY-without-routing (a
    //      silent UDP black-hole). Emitted FIRST, before any UDP mangle/TPROXY
    //      rule, so the `set -e` script exits non-zero and installs NOTHING when
    //      `ip` is absent — TPROXY rules and routing go in together or not at all
    //      (codex r2).
    //   2/3. (idempotently) create both mangle chains.
    //   4/5. FLUSH the UDP chains after creating them, BEFORE adding any rule
    //      (codex r3). The per-rule `-C ... || -A` guard is an EXACT match, so on
    //      a reconfiguration that changes `FERRUM_MESH_CAPTURE_UDP_PORT` /
    //      `FERRUM_MESH_TPROXY_MARK` the new TPROXY rule never matches the old
    //      one's `-C` check and is APPENDED AFTER it; iptables preserves rule
    //      order, so the stale rule (old port/mark) stays ahead and black-holes
    //      UDP. Flushing first clears any prior rules so the chain is rebuilt with
    //      only the current config. Flush is idempotent (`-F ... || true`) and
    //      harmless on a fresh chain, keeping the create+flush+populate sequence
    //      rerun-safe.
    let mut commands = vec![
        "command -v ip >/dev/null 2>&1 || { echo \"iproute2 (ip) is required for UDP TPROXY transparent routing\" >&2; exit 1; }"
            .to_string(),
        idempotent_new_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        // OUTPUT MARK chain (codex r6): captures the pod's OWN locally-generated
        // UDP egress, which never traverses PREROUTING (Linux routes locally-
        // generated traffic OUTPUT -> POSTROUTING). It MARKs (does not TPROXY —
        // TPROXY is PREROUTING-only) so the fwmark `ip rule` reroutes the datagram
        // to loopback, where it re-enters PREROUTING and the reinject chain (below)
        // captures it.
        idempotent_new_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        // REINJECT chain (codex r6): holds the single mark-match `-j TPROXY` rule
        // that captures the OUTPUT-marked datagram after the fwmark route loops it
        // back to loopback and it re-enters PREROUTING. It lives in its OWN custom
        // chain (jumped from PREROUTING first) rather than as a bare PREROUTING
        // rule so the stale-rule-on-mark-change hazard the create+flush sequence
        // already fixes for the other chains (codex r3) covers it too: the built-in
        // PREROUTING chain cannot be flushed, but a custom chain can, and teardown
        // reaps it by name (mark-independent), exactly like the OUTBOUND/INBOUND
        // chains and the priority-keyed fwmark `ip rule`.
        idempotent_new_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
    ];

    // Outbound exclusions first (RETURN wins by rule order), mirroring TCP.
    for cidr in exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTBOUND",
            &format!("-p udp -d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTBOUND",
            &format!("-p udp --dport {port} -j RETURN"),
        ));
    }
    // NOTE: no proxy-UID (`-m owner --uid-owner`) self-exclusion in THIS chain.
    // `-m owner` matches only locally-generated packets, so it is valid only in an
    // OUTPUT-context chain — and this OUTBOUND chain is reached from PREROUTING
    // (TPROXY is PREROUTING-only). The proxy's own UDP egress is locally generated,
    // so its self-exclusion lives in the OUTPUT MARK chain below (the owner-match
    // RETURN), not here.
    for rule in &outbound_tproxy_rules {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTBOUND",
            rule,
        ));
    }

    // OUTPUT MARK chain population (codex r6): the pod's OWN locally-generated UDP
    // egress goes OUTPUT -> POSTROUTING and NEVER hits PREROUTING, so the OUTBOUND
    // TPROXY chain above (reached only from PREROUTING) never sees it. This chain —
    // jumped from `mangle OUTPUT` (added below) — MARKs that egress with the same
    // fwmark the PREROUTING TPROXY rules use, so the fwmark `ip rule` (priority
    // <P> -> table <T>) + `ip route add local ... dev lo table <T>` reroute the
    // marked datagram to loopback, where it re-enters the INPUT path, traverses
    // PREROUTING a single time, and is captured by the mark-match TPROXY rule
    // (added below). It uses MARK, NOT TPROXY, because TPROXY is invalid for
    // locally-generated (OUTPUT) packets. The chain order is:
    //   1. `-m mark --mark <mark>/<mask> -j RETURN` — never re-mark an already-
    //      marked packet (anti-loop belt-and-suspenders; the `local` route diverts
    //      the looped datagram to the INPUT side so OUTPUT is hit once, but this
    //      guard is the canonical safety rail).
    //   2. proxy-UID `-m owner --uid-owner <uid> -j RETURN` — exclude the proxy's
    //      OWN egress so it is neither captured nor looped. Owner-match is valid
    //      here precisely because OUTPUT sees the originating socket (it is invalid
    //      in PREROUTING, which is why the OUTBOUND chain has no owner RETURN).
    //   3. the same exclude-CIDR / exclude-port RETURNs as the OUTBOUND chain.
    //   4. the MARK rules derived from the SAME outbound selectors as the TPROXY
    //      rules AND carrying the SAME `! --dst-type LOCAL` egress scope (codex r9),
    //      so OUTPUT capture scoping matches PREROUTING capture scoping exactly.
    //      The dst-type scope is what keeps pod-to-self / loopback (`--dst-type
    //      LOCAL` in OUTPUT) OUT of the mark set so it is never fwmark-rerouted to
    //      `lo` and TPROXY-captured — only genuine egress to other hosts is marked.
    //      The proxy's OWN egress is separately excluded by the owner RETURN above;
    //      the dst-type scope additionally covers a NON-proxy local destination
    //      (another UID's loopback / self UDP) the owner RETURN cannot.
    // The chain is populated regardless of whether any selector matched: if it is
    // empty of MARK rules nothing is marked, and the OUTPUT jump below is a no-op.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "FERRUM_MESH_UDP_OUTPUT_MARK",
        &format!("-m mark --mark {mark_arg} -j RETURN"),
    ));
    if let Some(uid) = config.proxy_uid {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            &format!("-m owner --uid-owner {uid} -j RETURN"),
        ));
    }
    for cidr in exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            &format!("-p udp -d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            &format!("-p udp --dport {port} -j RETURN"),
        ));
    }
    for rule in &outbound_mark_rules {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            rule,
        ));
    }

    // Inbound UDP chain — created, flushed, populated, and (below) jumped from
    // PREROUTING when `emit_inbound` is set. Co-located here so all inbound
    // wiring lives behind one gate. Teardown reaps the chain UNCONDITIONALLY so a
    // pod upgraded from a prior version that DID install it is cleaned up.
    if emit_inbound {
        commands.push(idempotent_new_chain(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_INBOUND",
        ));
        commands.push(flush_chain(binary, "mangle", "FERRUM_MESH_UDP_INBOUND"));
        // Inbound exclusions before the catch-all TPROXY (RETURN must precede it,
        // mirroring the TCP inbound chain).
        for port in &config.exclude_inbound_ports {
            commands.push(idempotent_append(
                binary,
                "mangle",
                "FERRUM_MESH_UDP_INBOUND",
                &format!("-p udp --dport {port} -j RETURN"),
            ));
        }
        // Inbound catch-all scoped to a LOCAL destination (the pod's own IP) so it
        // captures ONLY genuinely-inbound UDP — never pod egress that fell through
        // the OUTBOUND chain. The complement of the OUTBOUND chain's
        // `! --dst-type LOCAL`, keeping the two PREROUTING chains direction-disjoint
        // without knowing the pod IP (codex r2).
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_INBOUND",
            &format!("-p udp -m addrtype --dst-type LOCAL {tproxy_jump}"),
        ));
    }

    // Transparent-routing plumbing: raw `ip` commands (NOT iptables). The fwmark
    // selector must match the `--tproxy-mark` value above so marked datagrams are
    // steered to the local-delivery table.
    //
    // INSTALLED BEFORE THE PREROUTING JUMPS (codex r5 finding #3). The jumps are
    // what start steering UDP into the chains; if `ip rule`/`ip route` failed
    // AFTER the jumps were appended, the injector's trap-less `set -e` init script
    // would leave the pod with TPROXY chains live but no policy routing — the
    // half-installed black-hole. Emitting routing first means a routing failure
    // aborts the script BEFORE any capture is wired (the chains/rules above are
    // inert until the jumps below are appended).
    //
    // FAIL CLOSED (codex r2): TPROXY local delivery is USELESS without this
    // routing, so the load-bearing ADD commands are NOT `|| true` — under the
    // (set -e) setup script a failed add aborts, rather than leaving a pod that
    // is "ready" but silently black-holes captured UDP. (`command -v ip` was
    // already asserted FATALLY at the top of this function, before any UDP rule,
    // so the adds run only when `ip` exists.) Only the delete-before-add stays
    // best-effort (`|| true`).
    //
    // Idempotency: `ip rule add` APPENDS, so a retry (e.g. a node-agent fallback
    // crash before cleanup ran) would stack a duplicate rule. We assign an
    // EXPLICIT priority and delete-by-priority before adding; cleanup deletes the
    // same exact priority. The local route is likewise delete-before-add so a
    // rerun never errors on an already-present route.
    let (ip, local_route) = match family {
        CidrFamily::V4 => ("ip", "local 0.0.0.0/0 dev lo"),
        CidrFamily::V6 => ("ip -6", "local ::/0 dev lo"),
    };
    // Delete the prior fwmark rule by its STABLE Ferrum-owned priority + table
    // ONLY — NOT keyed on the mark value (codex r4). The Ferrum-owned priority
    // (`TPROXY_ROUTE_RULE_PRIORITY`) and table (`TPROXY_ROUTE_TABLE`) are fixed,
    // but `FERRUM_MESH_TPROXY_MARK` is operator-overridable: if the mark changed
    // since a prior run, a delete keyed on the NEW `fwmark <mark>` selector would
    // not match the OLD mark's priority-100 rule, leaving a stale selector that
    // keeps routing the old mark into table 33133. Deleting by priority + table
    // (mark-independent, exactly as the cleanup teardown does) removes whichever
    // mark the prior rule carried before the add installs the current one. Stays
    // best-effort (`|| true`): an already-absent rule must not abort `set -e`.
    commands.push(ip_delete_best_effort(&format!(
        "{ip} rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
    )));
    commands.push(format!(
        "{ip} rule add priority {TPROXY_ROUTE_RULE_PRIORITY} fwmark 0x{mark:x}/0x{TPROXY_MARK_MASK:x} lookup {TPROXY_ROUTE_TABLE}"
    ));
    commands.push(ip_delete_best_effort(&format!(
        "{ip} route del {local_route} table {TPROXY_ROUTE_TABLE}"
    )));
    commands.push(format!(
        "{ip} route add {local_route} table {TPROXY_ROUTE_TABLE}"
    ));

    // PREROUTING jumps + the locally-generated reinjection capture, all LAST
    // (codex r5 finding #3): these start steering UDP into the now-fully-built
    // chains, and the routing above is already installed, so there is no window
    // where TPROXY is wired without policy routing.
    //
    // (1) REINJECT chain: the mark-match `-j TPROXY` rule, populated then jumped
    // from PREROUTING FIRST (codex r6). The OUTPUT MARK chain marks the pod's OWN
    // egress; the fwmark `ip rule` + `local ... dev lo` route then reroute that
    // marked datagram to loopback, where it re-enters the INPUT path and traverses
    // PREROUTING. This rule captures the rerouted datagram by its MARK (the only
    // reliable selector — TPROXY/loopback do NOT rewrite the header, so the
    // datagram still carries its ORIGINAL remote destination and would also match
    // the dst-based OUTBOUND chain). Because xt_TPROXY returns NF_ACCEPT and ends
    // PREROUTING traversal, jumping into this chain BEFORE the OUTBOUND/INBOUND
    // chain jumps guarantees the rerouted datagram is TPROXY'd exactly once and
    // never double-processed by the dst-based chains. It carries the SAME mark
    // (`--tproxy-mark`) so TPROXY re-stamps the mark the local-delivery route
    // already used. The chain is inert for ordinary inbound/forwarded UDP (which
    // carries no Ferrum mark) — only the OUTPUT-marked, rerouted datagrams match.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "FERRUM_MESH_UDP_REINJECT",
        &format!("-p udp -m mark --mark {mark_arg} {tproxy_jump}"),
    ));
    commands.push(idempotent_append(
        binary,
        "mangle",
        "PREROUTING",
        "-p udp -j FERRUM_MESH_UDP_REINJECT",
    ));
    // (2) The OUTBOUND jump is installed BEFORE the INBOUND jump so pod EGRESS is
    // matched/routed first: the inbound catch-all (xt_TPROXY returns NF_ACCEPT,
    // ending traversal) must not swallow egress and bypass the outbound
    // include/exclude/CIDR/port rules. The two chains are also destination-scoped
    // (`! --dst-type LOCAL` outbound, `--dst-type LOCAL` inbound) so each captures
    // only its own direction regardless of order; the ordering is the
    // belt-and-suspenders mirror of the TCP chains (codex r2). These see only
    // genuinely PREROUTING-visible UDP (forwarded / inbound-to-pod), NOT the pod's
    // own locally-generated egress — that is the OUTPUT MARK chain's job (1).
    commands.push(idempotent_append(
        binary,
        "mangle",
        "PREROUTING",
        "-p udp -j FERRUM_MESH_UDP_OUTBOUND",
    ));
    // The INBOUND jump is emitted when `emit_inbound` is set so pod-destined UDP
    // cannot bypass mesh identity and authorization by flowing directly to the app.
    if emit_inbound {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_INBOUND",
        ));
    }
    // (3) The OUTPUT jump into the MARK-only chain (codex r6). This is the path for
    // the pod's OWN locally-generated UDP egress (OUTPUT -> POSTROUTING never hits
    // PREROUTING). The chain MARKs (does NOT TPROXY — TPROXY is invalid in OUTPUT
    // and jumping into a `-j TPROXY` chain from OUTPUT can fail iptables setup
    // outright); the fwmark route reroutes to lo and (1) above completes the
    // capture loop: OUTPUT-MARK -> lo-reroute (fwmark `ip rule` -> local route) ->
    // PREROUTING mark-match TPROXY -> the Stage 3 transparent UDP socket.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "OUTPUT",
        "-p udp -j FERRUM_MESH_UDP_OUTPUT_MARK",
    ));

    commands
}

/// Wrap a best-effort `ip` DELETE (the idempotence delete-before-add and the
/// cleanup teardown) with `|| true` so an already-absent rule/route never aborts
/// the (`set -e`) script. NOTE: this is for DELETES only — the load-bearing
/// setup ADDs deliberately do NOT use it (they must fail closed; see
/// `udp_tproxy_commands_for_family`). A `command -v ip` preflight is asserted
/// separately and fatally by callers before the load-bearing adds.
fn ip_delete_best_effort(cmd: &str) -> String {
    format!("{cmd} 2>/dev/null || true")
}

fn iptables_script(
    v4_commands: &[String],
    v6_commands: &[String],
    ip6tables_mode: Ip6TablesMode,
    emit_required_mode_preflight: bool,
) -> String {
    let mut chunks = Vec::new();
    if emit_required_mode_preflight
        && !v6_commands.is_empty()
        && ip6tables_mode == Ip6TablesMode::Required
    {
        chunks.push(format!(
            "command -v ip6tables >/dev/null 2>&1 || {{ echo \"ip6tables is required for IPv6 mesh capture\" >&2; exit 1; }}\n\
             ip6tables -t nat -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1 || {{ echo \"ip6tables nat table is required for IPv6 mesh capture\" >&2; exit 1; }}"
        ));
    }
    if !v4_commands.is_empty() {
        chunks.push(v4_commands.join("\n"));
    }
    if !v6_commands.is_empty() {
        let v6_script = v6_commands.join("\n");
        match ip6tables_mode {
            Ip6TablesMode::Auto => chunks.push(format!(
                "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t nat -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {}\n  else\n    echo \"ip6tables nat table unavailable; skipping IPv6 mesh capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi",
                v6_script.replace('\n', "\n    ")
            )),
            Ip6TablesMode::Required => chunks.push(v6_script),
            Ip6TablesMode::Disabled => {
                debug_assert!(
                    v6_commands.is_empty(),
                    "IptablesPlan::for_config must clear v6 commands when ip6tables is disabled"
                );
            }
        }
    }
    chunks.join("\n")
}

/// Like [`iptables_script`], but the IPv6 availability probe checks the
/// **`mangle`** table (where the UDP TPROXY chains live) rather than `nat`.
/// A host with `mangle` support but no `nat` table must still run the UDP v6
/// rules — probing `nat` would wrongly skip them. Used by
/// [`IptablesPlan::udp_setup_script`] for the Ambient per-pod-netns producer.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_iptables_script(
    v4_commands: &[String],
    v6_commands: &[String],
    ip6tables_mode: Ip6TablesMode,
    emit_required_mode_preflight: bool,
) -> String {
    let mut chunks = Vec::new();
    if emit_required_mode_preflight
        && !v6_commands.is_empty()
        && ip6tables_mode == Ip6TablesMode::Required
    {
        chunks.push(format!(
            "command -v ip6tables >/dev/null 2>&1 || {{ echo \"ip6tables is required for IPv6 mesh UDP capture\" >&2; exit 1; }}\n\
             ip6tables -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1 || {{ echo \"ip6tables mangle table is required for IPv6 mesh UDP capture\" >&2; exit 1; }}"
        ));
    }
    if !v4_commands.is_empty() {
        chunks.push(v4_commands.join("\n"));
    }
    if !v6_commands.is_empty() {
        let v6_script = v6_commands.join("\n");
        match ip6tables_mode {
            Ip6TablesMode::Auto => chunks.push(format!(
                "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {}\n  else\n    echo \"ip6tables mangle table unavailable; skipping IPv6 mesh UDP capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh UDP capture rules\"\nfi",
                v6_script.replace('\n', "\n    ")
            )),
            Ip6TablesMode::Required => chunks.push(v6_script),
            Ip6TablesMode::Disabled => {
                debug_assert!(
                    v6_commands.is_empty(),
                    "udp_only_for_config must clear v6 commands when ip6tables is disabled"
                );
            }
        }
    }
    chunks.join("\n")
}

/// Wrap a single IPv6 command behind an `ip6tables` availability probe on the
/// given table (`nat` for the TCP capture chains, `mangle` for the UDP TPROXY
/// chains), echoing and skipping when `ip6tables` or that table is unavailable.
/// Shared by the Ambient producer's UDP teardown and the node-agent fallback
/// cleanup so the probe shape can never drift between them.
pub(crate) fn ip6tables_probe_guard(cmd: &str, table: &str) -> String {
    format!(
        "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {cmd}\n  else\n    echo \"ip6tables {table} table unavailable; skipping IPv6 mesh capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi"
    )
}

/// The UDP-only command list for one address family, filtering include/exclude
/// CIDRs to that family exactly like [`commands_for_family`] before delegating
/// to the shared `udp_tproxy_commands_for_family`. This is what keeps the
/// Ambient producer's UDP rules byte-identical to the injector's UDP rules.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_only_commands_for_family(config: &CaptureConfig, family: CidrFamily) -> Vec<String> {
    let binary = match family {
        CidrFamily::V4 => "iptables",
        CidrFamily::V6 => "ip6tables",
    };
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    // OUTBOUND-ONLY for the Ambient producer: it installs rules inside every
    // enrolled pod netns (incl. destination pods), where capturing inbound
    // `--dst-type LOCAL` UDP would black-hole the HBONE relay's delivery to the
    // local app and the source pod's return-path reply (codex).
    udp_tproxy_commands_for_family(
        binary,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
        false,
    )
}

fn cleanup_commands_for(binary: &str, udp_capture_enabled: bool) -> CleanupCommands {
    let iptables = vec![
        // Step 1: remove jump rules from built-in chains
        idempotent_delete(binary, "nat", "OUTPUT", "-p tcp -j FERRUM_MESH_OUTBOUND"),
        idempotent_delete(binary, "nat", "PREROUTING", "-p tcp -j FERRUM_MESH_INBOUND"),
        // Step 2: flush custom chains
        flush_chain(binary, "nat", "FERRUM_MESH_INBOUND"),
        flush_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"),
        // Step 3: delete custom chains (must be empty first)
        delete_chain(binary, "nat", "FERRUM_MESH_INBOUND"),
        delete_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"),
    ];

    let mut combined = CleanupCommands {
        iptables,
        ip_routing: Vec::new(),
    };

    // UDP TPROXY teardown is GATED on `udp_capture_enabled` HERE: when this
    // install never emitted UDP rules, the normal shutdown/setup-failure cleanup
    // must not touch routing state it never created. (The node-agent runs a
    // SEPARATE UNCONDITIONAL pre-setup teardown via [`udp_teardown_for`] to reap
    // stale state from a prior UDP-enabled-then-crashed run — codex r4.)
    if udp_capture_enabled {
        let udp = udp_teardown_for(binary);
        combined.iptables.extend(udp.iptables);
        combined.ip_routing.extend(udp.ip_routing);
    }

    combined
}

/// The EXACT Ferrum-owned UDP TPROXY teardown for one `iptables`/`ip6tables`
/// family, split into the table teardown (`iptables`) and the raw `ip` routing
/// teardown (`ip_routing`). Contains ONLY UDP-specific state — never the TCP nat
/// chains — so it is safe to run UNCONDITIONALLY before setup to reap stale state
/// from a prior UDP-enabled run, without disturbing the TCP chains setup is about
/// to (re)build. Every command targets an EXACT Ferrum-owned object (mangle
/// chains by name, the fwmark rule by its stable priority, the route by its exact
/// table spec) and is idempotent/best-effort, so running it when no UDP state
/// exists is a no-op.
fn udp_teardown_for(binary: &str) -> CleanupCommands {
    let family = if binary == "ip6tables" {
        CidrFamily::V6
    } else {
        CidrFamily::V4
    };

    // mangle chain teardown: jumps first, then flush, then delete. The OUTPUT MARK
    // path (codex r6) adds a `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump and
    // a `mangle PREROUTING -j FERRUM_MESH_UDP_REINJECT` jump that must also be torn
    // down (the legacy "no OUTPUT jump" note is obsolete). Every target is an EXACT
    // Ferrum-owned object (chain by name, jump by exact `-j <chain>` spec —
    // mark-independent), so this teardown is fully mark-independent and can run
    // UNCONDITIONALLY pre-setup to reap stale state even across a changed
    // `FERRUM_MESH_TPROXY_MARK` (the mark-match rule lives INSIDE the reinject
    // chain, which is reaped by name, never as a bare PREROUTING rule). These are
    // ip6tables-TABLE commands, so for IPv6 the node-agent guards them behind its
    // `ip6tables` availability probe.
    let iptables = vec![
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_REINJECT",
        ),
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_INBOUND",
        ),
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_OUTBOUND",
        ),
        idempotent_delete(
            binary,
            "mangle",
            "OUTPUT",
            "-p udp -j FERRUM_MESH_UDP_OUTPUT_MARK",
        ),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_INBOUND"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_INBOUND"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
    ];

    // Remove ONLY the EXACT Ferrum-owned routing rule + route from the
    // Ferrum-specific table — never `ip rule del lookup <table>` (would drop an
    // unrelated rule pointing at the table) and never `ip route flush table`
    // (would wipe any co-resident route, e.g. an Istio table). Delete the rule by
    // its explicit priority (mark-independent) and the route by its exact spec.
    //
    // These are RAW `ip`/`ip -6` commands — independent of `iptables`/`ip6tables`.
    // They go in `ip_routing` so the node-agent emits them UNCONDITIONALLY: gating
    // the `ip -6 rule/route del` behind an `ip6tables` probe (codex r3) would leak
    // the fwmark rule + local route whenever `ip6tables` is missing, and marked
    // UDP would keep diverting after shutdown even though `ip -6` could have
    // removed it.
    let (ip, local_route) = match family {
        CidrFamily::V6 => ("ip -6", "local ::/0 dev lo"),
        CidrFamily::V4 => ("ip", "local 0.0.0.0/0 dev lo"),
    };
    // Cleanup deletes stay best-effort (`|| true`): teardown must never fail on
    // already-absent routing state or a missing `ip` binary.
    let ip_routing = vec![
        ip_delete_best_effort(&format!(
            "{ip} rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
        )),
        ip_delete_best_effort(&format!(
            "{ip} route del {local_route} table {TPROXY_ROUTE_TABLE}"
        )),
    ];

    CleanupCommands {
        iptables,
        ip_routing,
    }
}

fn idempotent_new_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -N {chain} 2>/dev/null || true")
}

fn idempotent_append(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -C {chain} {rule} 2>/dev/null || {binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} {rule}"
    )
}

fn idempotent_delete(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -D {chain} {rule} 2>/dev/null || true"
    )
}

fn flush_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -F {chain} 2>/dev/null || true")
}

fn delete_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -X {chain} 2>/dev/null || true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_plan_is_idempotent() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);
        config.exclude_cidrs.push("10.0.0.0/8".to_string());
        config.exclude_ports.push(15020);

        let plan = IptablesPlan::for_config(&config);

        assert!(plan.v4_commands.iter().any(|cmd| cmd.contains("-C OUTPUT")));
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("--to-ports 15001"))
        );
    }

    #[test]
    fn iptables_setup_script_fails_closed_with_set_e() {
        // The injector runs this script as the init container's `/bin/sh -c`
        // body. Without `set -e` a rule that fails mid-script would still exit 0,
        // starting the pod with a partial ruleset that lets egress bypass mesh
        // capture (and mesh_authz). It must fail closed.
        let plan = IptablesPlan::for_config(&CaptureConfig::explicit(15006, 15001));
        let script = plan.script();
        assert!(
            script.starts_with("set -e\n"),
            "setup script must start with `set -e` to fail closed on a partial ruleset, got:\n{script}"
        );
        // The idempotent guards must survive `set -e`: `-N ... || true` and
        // `-C ... || -A ...` must not abort on the expected chain-exists /
        // rule-absent misses.
        assert!(
            script.contains("|| true"),
            "chain creation must stay idempotent under set -e"
        );
        assert!(
            script.contains(" -C ") && script.contains("|| iptables"),
            "append must stay check-then-add idempotent under set -e"
        );
    }

    #[test]
    fn explicit_capture_defaults_to_proxy_uid_exclusion() {
        let config = CaptureConfig::explicit(15006, 15001);

        assert_eq!(config.proxy_uid, Some(DEFAULT_PROXY_UID));
        assert!(
            IptablesPlan::for_config(&config)
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
    }

    #[test]
    fn ebpf_falls_back_on_old_kernel() {
        assert!(should_fallback_to_iptables("5.4.0"));
        assert!(!should_fallback_to_iptables("5.7.0"));
        assert!(!should_fallback_to_iptables("6.6.12"));
    }

    #[test]
    fn ebpf_plan_carries_iptables_fallback() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;

        let plan = EbpfPlan::for_config(&config);

        assert!(plan.enabled);
        assert_eq!(plan.required_kernel, "5.7");
        assert_eq!(plan.fallback.ip6tables_mode, Ip6TablesMode::Auto);
        assert!(
            plan.fallback
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.fallback
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--to-ports 15001"))
        );
    }

    #[test]
    fn ebpf_fallback_script_contains_kernel_check_and_iptables() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;

        let plan = EbpfPlan::for_config(&config);
        let script = plan.fallback_script();

        assert!(script.contains("uname -r"));
        assert!(script.contains("-lt 5"));
        assert!(script.contains("-lt 7"));
        assert!(script.contains("falling back to iptables"));
        assert!(script.contains("supports eBPF"));
        assert!(script.contains("--to-ports 15001"));
        assert!(script.contains("--to-ports 15006"));
    }

    #[test]
    fn ebpf_fallback_script_preserves_required_ip6tables_mode() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;
        config.ip6tables_mode = Ip6TablesMode::Required;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = EbpfPlan::for_config(&config);
        let script = plan.fallback_script();

        assert_eq!(plan.fallback.ip6tables_mode, Ip6TablesMode::Required);
        assert!(script.contains("ip6tables is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables nat table is required for IPv6 mesh capture"));
    }

    #[test]
    fn cidr_validation_checks_prefix_range() {
        assert!(validate_cidr_list(&["10.0.0.0/8".to_string()]).is_ok());
        assert!(validate_cidr_list(&["10.0.0.0/64".to_string()]).is_err());
    }

    #[test]
    fn cleanup_commands_reverses_setup() {
        let cleanup = IptablesPlan::cleanup_commands(true);

        // Must remove jumps from built-in chains first
        assert!(cleanup.iter().any(|cmd| cmd.contains("-D OUTPUT")));
        assert!(cleanup.iter().any(|cmd| cmd.contains("-D PREROUTING")));

        // Must flush then delete custom chains
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-F FERRUM_MESH_INBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-F FERRUM_MESH_OUTBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-X FERRUM_MESH_INBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-X FERRUM_MESH_OUTBOUND"))
        );

        // Flush must come before delete (chain must be empty before removal)
        let flush_inbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-F FERRUM_MESH_INBOUND"))
            .unwrap();
        let delete_inbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-X FERRUM_MESH_INBOUND"))
            .unwrap();
        assert!(
            flush_inbound_pos < delete_inbound_pos,
            "flush must precede delete for FERRUM_MESH_INBOUND"
        );

        let flush_outbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-F FERRUM_MESH_OUTBOUND"))
            .unwrap();
        let delete_outbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-X FERRUM_MESH_OUTBOUND"))
            .unwrap();
        assert!(
            flush_outbound_pos < delete_outbound_pos,
            "flush must precede delete for FERRUM_MESH_OUTBOUND"
        );

        // Jump deletions must come before flush (no new traffic enters chains
        // while they are being torn down)
        let delete_output_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-D OUTPUT"))
            .unwrap();
        assert!(
            delete_output_pos < flush_outbound_pos,
            "OUTPUT jump delete must precede OUTBOUND flush"
        );
        let delete_prerouting_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-D PREROUTING"))
            .unwrap();
        assert!(
            delete_prerouting_pos < flush_inbound_pos,
            "PREROUTING jump delete must precede INBOUND flush"
        );
    }

    #[test]
    fn cleanup_commands_all_tolerate_missing_chains() {
        let cleanup = IptablesPlan::cleanup_commands(true);

        // Every cleanup command must have "|| true" so partial cleanup doesn't
        // fail the overall teardown
        for cmd in &cleanup {
            assert!(
                cmd.contains("|| true"),
                "cleanup command must tolerate missing chains: {cmd}"
            );
        }
    }

    #[test]
    fn iptables_plan_waits_for_xtables_lock() {
        let plan = IptablesPlan::for_config(&CaptureConfig::explicit(15006, 15001));

        for cmd in plan.v4_commands {
            assert!(
                cmd.contains(" -w 5 "),
                "iptables command should wait briefly for xtables lock: {cmd}"
            );
        }
    }

    #[test]
    fn setup_then_cleanup_covers_all_chains() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);

        let setup = IptablesPlan::for_config(&config);
        let cleanup = IptablesPlan::cleanup_commands(true);

        // Every custom chain created in setup must be deleted in cleanup
        let setup_chains: Vec<&str> = setup
            .v4_commands
            .iter()
            .filter(|cmd| cmd.contains("-N "))
            .filter_map(|cmd| cmd.split("-N ").nth(1))
            .filter_map(|s| s.split_whitespace().next())
            .collect();

        for chain in &setup_chains {
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-X {chain}"))),
                "chain {chain} created in setup but not deleted in cleanup"
            );
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-F {chain}"))),
                "chain {chain} created in setup but not flushed in cleanup"
            );
        }

        // Every built-in chain jump in setup must have a corresponding delete in cleanup
        let setup_jumps: Vec<(&str, &str)> = setup
            .v4_commands
            .iter()
            .filter(|cmd| {
                (cmd.contains("-A PREROUTING") || cmd.contains("-C PREROUTING"))
                    || (cmd.contains("-A OUTPUT") || cmd.contains("-C OUTPUT"))
            })
            .filter_map(|cmd| {
                if cmd.contains("PREROUTING") {
                    Some(("PREROUTING", "FERRUM_MESH_INBOUND"))
                } else if cmd.contains("OUTPUT") {
                    Some(("OUTPUT", "FERRUM_MESH_OUTBOUND"))
                } else {
                    None
                }
            })
            .collect();

        for (chain, target) in &setup_jumps {
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-D {chain}"))
                        && cmd.contains(&format!("-j {target}"))),
                "jump from {chain} to {target} in setup but no -D in cleanup"
            );
        }
    }

    #[test]
    fn parse_cidr_env_splits_and_trims() {
        let result = parse_cidr_env("10.0.0.0/8, 172.16.0.0/12 , 192.168.0.0/16");
        assert_eq!(
            result,
            vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ]
        );
    }

    #[test]
    fn parse_cidr_env_empty_string_returns_empty() {
        assert!(parse_cidr_env("").is_empty());
    }

    #[test]
    fn parse_port_list_valid() {
        let result = parse_port_list("15001, 15006, 15008 ,15020").unwrap();
        assert_eq!(result, vec![15001, 15006, 15008, 15020]);
    }

    #[test]
    fn parse_port_list_rejects_non_numeric() {
        assert!(parse_port_list("15001,abc").is_err());
    }

    #[test]
    fn parse_port_list_empty_string_returns_empty() {
        assert!(parse_port_list("").unwrap().is_empty());
    }

    #[test]
    fn parse_port_list_rejects_port_zero() {
        let err = parse_port_list("15001,0,15006").unwrap_err();
        assert!(err.contains("port must be 1-65535"), "actual: {err}");
    }

    #[test]
    fn parse_proxy_uid_rejects_invalid_env_value() {
        assert!(parse_proxy_uid("not-a-uid").is_err());
    }

    #[test]
    fn parse_proxy_uid_trims_valid_value() {
        assert_eq!(parse_proxy_uid(" 1338 ").unwrap(), 1338);
    }

    #[test]
    fn parse_proxy_uid_empty_uses_default() {
        assert_eq!(parse_proxy_uid("").unwrap(), DEFAULT_PROXY_UID);
    }

    #[test]
    fn iptables_plan_emits_inbound_exclude_return_rules_before_redirect() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_inbound_ports = vec![15090, 22];

        let plan = IptablesPlan::for_config(&config);

        for port in [15090, 22] {
            assert!(
                plan.v4_commands
                    .iter()
                    .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND")
                        && cmd.contains(&format!("--dport {port} -j RETURN"))),
                "inbound RETURN rule missing for port {port}"
            );
        }

        // CRITICAL: every RETURN rule must precede the inbound REDIRECT,
        // otherwise the catch-all REDIRECT fires first and the exclusion is
        // silently bypassed.
        let redirect_pos = plan
            .v4_commands
            .iter()
            .position(|cmd| {
                cmd.contains("FERRUM_MESH_INBOUND")
                    && cmd.contains(&format!("REDIRECT --to-ports {}", config.inbound_port))
            })
            .expect("inbound REDIRECT command");
        for port in [15090, 22] {
            let return_pos = plan
                .v4_commands
                .iter()
                .position(|cmd| {
                    cmd.contains("FERRUM_MESH_INBOUND")
                        && cmd.contains(&format!("--dport {port} -j RETURN"))
                })
                .expect("inbound RETURN command");
            assert!(
                return_pos < redirect_pos,
                "inbound RETURN for port {port} must precede the REDIRECT"
            );
        }
    }

    #[test]
    fn iptables_plan_omits_inbound_returns_when_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;

        let plan = IptablesPlan::for_config(&config);

        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND") && cmd.contains("-j RETURN")),
            "no inbound RETURN rules expected when exclude_inbound_ports is empty"
        );
    }

    #[test]
    fn iptables_plan_keeps_cidr_redirect_when_include_ports_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "CIDR-only include rule should remain when includeOutboundPorts is unset"
        );
    }

    #[test]
    fn iptables_plan_emits_per_port_redirects_when_include_ports_set() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_outbound_ports = vec![5432, 9092];

        let plan = IptablesPlan::for_config(&config);

        for port in [5432, 9092] {
            assert!(
                plan.v4_commands.iter().any(|cmd| cmd.contains(&format!(
                    "-p tcp --dport {port} -j REDIRECT --to-ports 15001"
                ))),
                "includeOutboundPorts REDIRECT missing for port {port}: {:?}",
                plan.v4_commands
            );
        }
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 0.0.0.0/0 -j REDIRECT")),
            "implicit catch-all CIDR must not capture all ports before port rules"
        );
    }

    #[test]
    fn iptables_plan_adds_include_ports_to_include_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config);

        let scoped_port_rule = plan
            .v4_commands
            .iter()
            .position(|cmd| cmd.contains("-p tcp --dport 5432 -j REDIRECT --to-ports 15001"))
            .expect("includeOutboundPorts should redirect port 5432 independently");
        assert!(
            scoped_port_rule > 0,
            "port include rule should be emitted after chain setup: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT")),
            "includeOutboundPorts should not suppress CIDR-only redirects"
        );
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 --dport 5432 -j REDIRECT")),
            "includeOutboundPorts must be additive, not intersected with include CIDRs"
        );
    }

    #[test]
    fn iptables_plan_wildcard_include_ports_redirects_all_destinations() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_all_outbound_ports = true;

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -j REDIRECT --to-ports 15001")),
            "wildcard includeOutboundPorts must redirect all outbound ports regardless of destination IP: {:?}",
            plan.v4_commands
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("--dport")),
            "wildcard includeOutboundPorts should not emit port-narrowing rules: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn iptables_plan_falls_back_to_catch_all_when_ipv4_include_set_filters_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;
        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| { cmd.contains("-p tcp -j REDIRECT --to-ports 15001") }),
            "When no IPv4 CIDR include remains for iptables, plan must fail closed with catch-all IPv4 redirect: {:?}",
            plan.v4_commands
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("fd00::/8")),
            "IPv6 include CIDR must not appear in the IPv4 iptables plan: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| { cmd.contains("-p tcp -d fd00::/8 -j REDIRECT --to-ports 15001") }),
            "IPv6 include CIDR should be rendered into ip6tables: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn iptables_plan_orders_exclude_port_before_overlapping_include_port() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_ports = vec![5432];
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config);
        let exclude_idx = plan
            .v4_commands
            .iter()
            .position(|cmd| cmd.contains("-p tcp --dport 5432 -j RETURN"))
            .expect("exclude port RETURN rule should be emitted");
        let include_idx = plan
            .v4_commands
            .iter()
            .position(|cmd| cmd.contains("--dport 5432 -j REDIRECT --to-ports 15001"))
            .expect("include port REDIRECT rule should be emitted");

        assert!(
            exclude_idx < include_idx,
            "excludeOutboundPorts must win over includeOutboundPorts by rule order: {:?}",
            plan.v4_commands
        );
    }
    #[test]
    fn iptables_plan_partitions_ipv4_and_ipv6_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];
        config.include_cidrs = vec!["172.16.0.0/12".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j RETURN")),
            "IPv4 exclude CIDR must still appear in the plan"
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 172.16.0.0/12 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the IPv4 plan"
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("::/")),
            "IPv6 CIDRs must not appear in IPv4 commands: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .all(|cmd| cmd.starts_with("ip6tables ")),
            "IPv6 commands must use ip6tables: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| cmd.contains("-d fd00::/8 -j RETURN")),
            "IPv6 exclude CIDR must appear in the IPv6 plan"
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| cmd.contains("-d 2001:db8::/32 -j REDIRECT --to-ports 15001")),
            "IPv6 include CIDR must appear in the IPv6 plan"
        );
    }

    #[test]
    fn iptables_plan_v6_empty_when_ip6tables_disabled() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.ip6tables_mode = Ip6TablesMode::Disabled;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the plan"
        );
        assert!(
            plan.v6_commands.is_empty(),
            "disabled ip6tables mode must suppress IPv6 commands"
        );
    }

    #[test]
    fn iptables_plan_routes_ipv6_include_to_v6_commands_only() {
        // Spec change (PR #926 / 4b273b1f): when the include-CIDR list
        // contains only IPv6 entries (so the IPv4 family has no specific
        // CIDR to redirect), the plan must fall back to a catch-all
        // IPv4 outbound REDIRECT rather than silently leaving IPv4 traffic
        // un-captured. Operators who relied on the previous behavior to
        // narrow capture to one address family should either set
        // `include_cidrs_explicit=false` (so the catch-all rules out IPv4
        // entirely) or add an explicit IPv4 CIDR.
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;

        let plan = IptablesPlan::for_config(&config);

        assert!(
            plan.v4_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND")
                    && cmd.contains("-p tcp -j REDIRECT --to-ports 15001")
            }),
            "IPv6-only include set must fall back to a catch-all IPv4 outbound REDIRECT (fail-closed): {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_INBOUND") && cmd.contains("REDIRECT --to-ports 15006")
            }),
            "IPv4 inbound REDIRECT must remain active even when the only include CIDR is IPv6"
        );
        assert!(
            plan.v6_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND")
                    && cmd.contains("-d fd00::/8 -j REDIRECT --to-ports 15001")
            }),
            "IPv6 outbound REDIRECT should be emitted through ip6tables"
        );
    }

    #[test]
    fn iptables_script_wraps_ipv6_commands_for_auto_probe() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let script = IptablesPlan::for_config(&config).script();

        assert!(script.contains("command -v ip6tables"));
        assert!(script.contains("ip6tables -t nat -w 5 -L"));
        assert!(script.contains("ip6tables nat table unavailable"));
        assert!(script.contains("skipping IPv6 mesh capture rules"));
        assert!(script.contains("ip6tables -t nat"));
    }

    #[test]
    fn iptables_script_requires_ip6tables_when_configured_true() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.ip6tables_mode = Ip6TablesMode::Required;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = IptablesPlan::for_config(&config);
        let script = plan.script();

        assert!(script.contains("ip6tables is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables nat table is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables -t nat -w 5 -L"));
        assert!(script.contains("exit 1"));
        assert!(script.contains("ip6tables -t nat"));
        assert!(
            script
                .find("ip6tables is required for IPv6 mesh capture")
                .expect("ip6tables preflight")
                < script.find("iptables -t nat").expect("IPv4 setup"),
            "hard-required ip6tables preflight should run before IPv4 setup: {script}"
        );
    }

    #[test]
    fn cleanup_script_does_not_preflight_required_ip6tables() {
        let script = IptablesPlan::cleanup_script(true, Ip6TablesMode::Required, false);

        assert!(script.contains("iptables -t nat"));
        assert!(script.contains("ip6tables -t nat"));
        assert!(
            !script.contains("ip6tables is required for IPv6 mesh capture"),
            "cleanup must remain best-effort and avoid aborting v4 teardown when ip6tables is unavailable: {script}"
        );
        assert!(
            !script.contains("ip6tables -t nat -L"),
            "cleanup must not probe ip6tables nat availability before best-effort teardown: {script}"
        );
    }

    #[test]
    fn cidr_family_classifies_families() {
        assert_eq!(cidr_family("10.0.0.0/8"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("0.0.0.0/0"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("127.0.0.0/8"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("fd00::/8"), Some(CidrFamily::V6));
        assert_eq!(cidr_family("2001:db8::/32"), Some(CidrFamily::V6));
        assert_eq!(cidr_family("::/0"), Some(CidrFamily::V6));
        // Malformed shapes are not IPv4; admission validator catches these earlier.
        assert_eq!(cidr_family("not-a-cidr"), None);
        assert_eq!(cidr_family("10.0.0.0"), None);
    }

    #[test]
    fn ip6tables_mode_parse_accepts_documented_values() {
        assert_eq!(Ip6TablesMode::parse("auto").unwrap(), Ip6TablesMode::Auto);
        assert_eq!(
            Ip6TablesMode::parse("true").unwrap(),
            Ip6TablesMode::Required
        );
        assert_eq!(
            Ip6TablesMode::parse("required").unwrap(),
            Ip6TablesMode::Required
        );
        assert_eq!(
            Ip6TablesMode::parse("false").unwrap(),
            Ip6TablesMode::Disabled
        );
        assert!(Ip6TablesMode::parse("sometimes").is_err());
    }

    // Serialize env-driven tests in this module so parallel cargo test runs do
    // not race on the same `FERRUM_MESH_CAPTURE_*` vars consumed by `from_env`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_capture_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MESH_CAPTURE_MODE",
            "FERRUM_MESH_PROXY_UID",
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_PORTS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS",
            "FERRUM_MESH_IP6TABLES_ENABLED",
            "FERRUM_MESH_CAPTURE_UDP_ENABLED",
            "FERRUM_MESH_CAPTURE_UDP_PORT",
            "FERRUM_MESH_TPROXY_MARK",
        ];
        for key in keys {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::set_var(key, value) };
        }
        f();
        for key in keys {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn from_env_parses_exclude_inbound_ports() {
        with_capture_env(
            &[("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS", "15090, 22")],
            || {
                let config = CaptureConfig::from_env().expect("config");
                assert_eq!(config.exclude_inbound_ports, vec![15090, 22]);
            },
        );
    }

    #[test]
    fn from_env_defaults_exclude_inbound_ports_to_empty() {
        with_capture_env(&[], || {
            let config = CaptureConfig::from_env().expect("config");
            assert!(config.exclude_inbound_ports.is_empty());
            assert_eq!(config.ip6tables_mode, Ip6TablesMode::Auto);
        });
    }

    #[test]
    fn from_env_marks_default_exclude_ports_as_implicit() {
        with_capture_env(&[], || {
            let mut config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.exclude_ports, vec![15001, 15006, 15008, 15020]);
            assert!(!config.exclude_ports_explicit);
            config.clear_implicit_exclude_ports();
            assert!(config.exclude_ports.is_empty());
        });
    }

    #[test]
    fn from_env_preserves_explicit_exclude_ports_for_ambient_udp() {
        with_capture_env(&[("FERRUM_MESH_CAPTURE_EXCLUDE_PORTS", "53,123")], || {
            let mut config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.exclude_ports, vec![53, 123]);
            assert!(config.exclude_ports_explicit);
            config.clear_implicit_exclude_ports();
            assert_eq!(config.exclude_ports, vec![53, 123]);
        });
    }

    #[test]
    fn from_env_rejects_invalid_exclude_inbound_ports() {
        with_capture_env(
            &[("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS", "not-a-port")],
            || {
                let result = CaptureConfig::from_env();
                assert!(result.is_err());
            },
        );
    }

    #[test]
    fn from_env_parses_ip6tables_mode() {
        with_capture_env(&[("FERRUM_MESH_IP6TABLES_ENABLED", "true")], || {
            let config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.ip6tables_mode, Ip6TablesMode::Required);
        });
    }

    #[test]
    fn from_env_rejects_invalid_ip6tables_mode() {
        with_capture_env(&[("FERRUM_MESH_IP6TABLES_ENABLED", "maybe")], || {
            let result = CaptureConfig::from_env();
            assert!(result.is_err());
        });
    }

    // Parser tests for the shared `includeOutboundPorts` surface used by both
    // the injector (iptables init container) and the node-agent eBPF backend.
    // The injector previously owned a private copy of these tests; centralizing
    // them here keeps the two surfaces from drifting.

    #[test]
    fn parse_include_port_list_absent_inputs() {
        assert_eq!(
            parse_include_port_list(None).expect("None"),
            ParsedIncludePorts::Absent
        );
        assert_eq!(
            parse_include_port_list(Some("")).expect("empty"),
            ParsedIncludePorts::Absent
        );
        assert_eq!(
            parse_include_port_list(Some("   ")).expect("blank"),
            ParsedIncludePorts::Absent
        );
        // A list of nothing but separator whitespace is also absent — we
        // never want to inject a phantom wildcard.
        assert_eq!(
            parse_include_port_list(Some(",")).expect("comma-only"),
            ParsedIncludePorts::Ports(Vec::new())
        );
    }

    #[test]
    fn parse_include_port_list_wildcard() {
        assert_eq!(
            parse_include_port_list(Some("*")).expect("wildcard"),
            ParsedIncludePorts::All
        );
        // Surrounding whitespace allowed.
        assert_eq!(
            parse_include_port_list(Some("  *  ")).expect("padded wildcard"),
            ParsedIncludePorts::All
        );
    }

    #[test]
    fn parse_include_port_list_single_port() {
        assert_eq!(
            parse_include_port_list(Some("80")).expect("single port"),
            ParsedIncludePorts::Ports(vec![80])
        );
    }

    #[test]
    fn parse_include_port_list_multiple_ports() {
        assert_eq!(
            parse_include_port_list(Some("80,443,5432")).expect("comma list"),
            ParsedIncludePorts::Ports(vec![80, 443, 5432])
        );
    }

    #[test]
    fn parse_include_port_list_handles_whitespace_and_dups() {
        // Sorted + deduped. Whitespace inside the list is tolerated to match
        // what humans actually type in pod annotations.
        assert_eq!(
            parse_include_port_list(Some("80, 443, 80")).expect("padded list"),
            ParsedIncludePorts::Ports(vec![80, 443])
        );
    }

    #[test]
    fn parse_include_port_list_rejects_mixed_wildcard() {
        let err = parse_include_port_list(Some("*,80")).expect_err("mixed wildcard");
        assert_eq!(
            err,
            "wildcard '*' must be the only includeOutboundPorts token"
        );
        let err = parse_include_port_list(Some("80,*")).expect_err("ports-then-wildcard");
        assert_eq!(
            err,
            "wildcard '*' must be the only includeOutboundPorts token"
        );
    }

    #[test]
    fn parse_include_port_list_rejects_repeated_wildcard() {
        let err = parse_include_port_list(Some("*,*")).expect_err("repeated wildcard");
        assert_eq!(
            err,
            "wildcard '*' must be the only includeOutboundPorts token"
        );
    }

    #[test]
    fn parse_include_port_list_rejects_malformed() {
        assert!(parse_include_port_list(Some("not-a-port")).is_err());
        // Port `0` is reserved; iptables --dport 0 and BPF gate alike would
        // be nonsensical.
        assert!(parse_include_port_list(Some("0")).is_err());
        // Out of range — `u16::MAX + 1`.
        assert!(parse_include_port_list(Some("65536")).is_err());
        assert!(parse_include_port_list(Some("80,bogus")).is_err());
    }

    #[test]
    fn include_outbound_ports_from_annotations_absent() {
        let result = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", None),
            ("ferrum.io/includeOutboundPorts", None),
        ])
        .expect("absent annotations");
        assert!(result.is_absent());
        assert_eq!(result, IncludeOutboundPorts::default());
    }

    #[test]
    fn include_outbound_ports_from_annotations_merges_two_aliases() {
        let result = include_outbound_ports_from_annotations([
            (
                "traffic.sidecar.istio.io/includeOutboundPorts",
                Some("80, 443"),
            ),
            ("ferrum.io/includeOutboundPorts", Some("5432, 80")),
        ])
        .expect("merged");
        assert!(!result.all_ports);
        // Sorted + deduped across both annotations.
        assert_eq!(result.ports, vec![80, 443, 5432]);
    }

    #[test]
    fn include_outbound_ports_from_annotations_wildcard_in_either_wins() {
        let result = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", Some("*")),
            ("ferrum.io/includeOutboundPorts", None),
        ])
        .expect("wildcard");
        assert!(result.all_ports);
        assert!(result.ports.is_empty());
    }

    #[test]
    fn include_outbound_ports_from_annotations_rejects_mixed_aliases() {
        let err = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", Some("80")),
            ("ferrum.io/includeOutboundPorts", Some("*")),
        ])
        .expect_err("mixed wildcard across aliases");
        assert!(err.contains("ferrum.io/includeOutboundPorts"));
        assert!(err.contains("wildcard '*' cannot be combined"));
        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
    }

    #[test]
    fn include_outbound_ports_from_annotations_wildcard_then_explicit_rejected() {
        let err = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", Some("*")),
            ("ferrum.io/includeOutboundPorts", Some("80")),
        ])
        .expect_err("explicit-after-wildcard");
        assert!(err.contains("ferrum.io/includeOutboundPorts"));
        assert!(err.contains("explicit includeOutboundPorts cannot be combined with wildcard"));
        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
    }

    #[test]
    fn include_outbound_ports_from_annotations_surfaces_parse_errors() {
        let err = include_outbound_ports_from_annotations([(
            "ferrum.io/includeOutboundPorts",
            Some("80,bogus"),
        )])
        .expect_err("malformed token");
        assert!(err.contains("invalid ferrum.io/includeOutboundPorts"));
    }

    // ---- F3 §3.3 Stage 2: UDP TPROXY capture rules (flag-gated, default-off) ----

    fn udp_enabled_iptables_config() -> CaptureConfig {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.udp_capture_enabled = true;
        config
    }

    // ── Ambient per-pod-netns UDP producer builders (#2013) ──────────────────

    #[test]
    fn udp_only_plan_emits_udp_chains_and_no_tcp_nat_chains() {
        // The Ambient per-pod-netns producer installs ONLY the UDP TPROXY chains;
        // Ambient TCP capture rides eBPF/HBONE, so the plan must never touch the
        // `nat` table or emit a TCP REDIRECT.
        let config = udp_enabled_iptables_config();
        let plan = IptablesPlan::udp_only_for_config(&config);
        let cmds = &plan.v4_commands;
        assert!(!cmds.is_empty(), "UDP-only plan should emit v4 commands");
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "missing UDP outbound mangle chain: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("TPROXY")),
            "missing UDP TPROXY jump: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip rule add") && c.contains("fwmark")),
            "missing fwmark policy-routing rule: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip route add") && c.contains(&TPROXY_ROUTE_TABLE.to_string())),
            "missing local route into the Ferrum table: {cmds:?}"
        );
        for cmd in cmds {
            assert!(
                !cmd.contains("-t nat"),
                "UDP-only plan must never touch the nat table: {cmd}"
            );
            assert!(
                !cmd.contains("REDIRECT"),
                "UDP-only plan must never emit a TCP REDIRECT: {cmd}"
            );
        }
    }

    #[test]
    fn udp_only_plan_is_outbound_only_unlike_injector() {
        // The Ambient producer installs rules INSIDE every enrolled pod netns
        // (including DESTINATION pods), so it must be OUTBOUND-ONLY: an inbound
        // `--dst-type LOCAL` chain would capture + drop the HBONE relay's delivery
        // to the local app AND the source pod's return-path reply (codex). The
        // injector (Sidecar) still emits the inbound chain. Both flow through the
        // SAME `udp_tproxy_commands_for_family`, so the producer's OUTBOUND rules
        // stay byte-identical to the injector's — only the inbound chain differs.
        let config = udp_enabled_iptables_config();
        let producer = IptablesPlan::udp_only_for_config(&config).v4_commands;
        let injector = IptablesPlan::for_config(&config).v4_commands;
        assert!(!producer.is_empty());

        // Producer captures egress: OUTBOUND chain + OUTPUT MARK loop + routing.
        assert!(
            producer
                .iter()
                .any(|c| c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "producer must create the outbound UDP chain: {producer:#?}"
        );
        assert!(
            producer
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")),
            "producer must emit the OUTPUT MARK loop for locally-generated egress"
        );
        assert!(
            producer
                .iter()
                .any(|c| c.contains("ip rule add") && c.contains("fwmark")),
            "producer must install the fwmark policy route"
        );

        // Producer emits NO inbound chain/jump (outbound-only) — this is what keeps
        // the destination relay's delivery + the return-path reply from being
        // captured and dropped in the pod netns.
        for cmd in &producer {
            assert!(
                !cmd.contains("FERRUM_MESH_UDP_INBOUND"),
                "producer must not emit the inbound UDP chain: {cmd}"
            );
        }
        // The injector (Sidecar) DOES still emit the inbound chain — contrast.
        assert!(
            injector
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")),
            "injector should still emit the inbound UDP chain"
        );

        // Every producer (outbound) rule matches an injector rule verbatim: the
        // producer is the injector's UDP rules MINUS the inbound chain, so
        // Ambient-produced and Sidecar-injected pods capture EGRESS identically.
        for cmd in &producer {
            assert!(
                injector.contains(cmd),
                "producer outbound rule must equal an injector rule: {cmd}"
            );
        }
    }

    #[test]
    fn udp_only_plan_host_netns_emits_nothing() {
        // Host-netns UDP suppression survives into the producer path even though
        // the producer never runs in host netns — the invariant is defense in depth.
        let mut config = udp_enabled_iptables_config();
        config.host_netns = true;
        let plan = IptablesPlan::udp_only_for_config(&config);
        assert!(
            plan.v4_commands.is_empty() && plan.v6_commands.is_empty(),
            "host-netns UDP-only plan must be empty: {plan:?}"
        );
    }

    #[test]
    fn udp_only_plan_disabled_emits_nothing() {
        let mut config = udp_enabled_iptables_config();
        config.udp_capture_enabled = false;
        let plan = IptablesPlan::udp_only_for_config(&config);
        assert!(plan.v4_commands.is_empty() && plan.v6_commands.is_empty());
    }

    #[test]
    fn udp_only_plan_v6_gated_on_configured_v6_cidr() {
        // IPv4-only include → no v6 commands. A ::/0 include → v6 commands emit.
        let v4_only = udp_enabled_iptables_config();
        assert!(
            IptablesPlan::udp_only_for_config(&v4_only)
                .v6_commands
                .is_empty(),
            "v4-only config must not emit v6 UDP rules"
        );

        let mut dual = udp_enabled_iptables_config();
        dual.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
        dual.include_cidrs_explicit = true;
        let dual_plan = IptablesPlan::udp_only_for_config(&dual);
        assert!(
            dual_plan
                .v6_commands
                .iter()
                .any(|c| c.contains("-t mangle") && c.contains("FERRUM_MESH_UDP_OUTBOUND")),
            "::/0 include must emit v6 UDP chains: {:?}",
            dual_plan.v6_commands
        );

        let mut disabled_v6 = dual;
        disabled_v6.ip6tables_mode = Ip6TablesMode::Disabled;
        assert!(
            IptablesPlan::udp_only_for_config(&disabled_v6)
                .v6_commands
                .is_empty(),
            "ip6tables disabled must drop v6 UDP rules"
        );
    }

    #[test]
    fn udp_setup_script_is_fail_closed_and_udp_only() {
        let config = udp_enabled_iptables_config();
        let script = IptablesPlan::udp_setup_script(&config);
        assert!(
            script.starts_with("set -e"),
            "producer UDP setup must fail closed: {script}"
        );
        assert!(script.contains("FERRUM_MESH_UDP_OUTBOUND"));
        assert!(script.contains("TPROXY"));
        assert!(script.contains("ip rule add") && script.contains("fwmark"));
        assert!(
            script.contains("command -v ip >/dev/null"),
            "must fatally preflight iproute2 before any UDP rule: {script}"
        );
        assert!(
            !script.contains("-t nat") && !script.contains("REDIRECT"),
            "producer setup must not touch TCP nat capture: {script}"
        );
    }

    #[test]
    fn udp_setup_script_empty_when_disabled_or_host_netns() {
        let mut disabled = udp_enabled_iptables_config();
        disabled.udp_capture_enabled = false;
        assert_eq!(IptablesPlan::udp_setup_script(&disabled), "");

        let mut host = udp_enabled_iptables_config();
        host.host_netns = true;
        assert_eq!(
            IptablesPlan::udp_setup_script(&host),
            "",
            "host-netns must emit no UDP setup (no host-netns-safe direction split)"
        );
    }

    #[test]
    fn udp_setup_script_v6_probe_is_mangle_not_nat() {
        // The UDP TPROXY chains live in `mangle`; the producer's v6 availability
        // probe must check `mangle`, not `nat` (codex r10 parity).
        let mut dual = udp_enabled_iptables_config();
        dual.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
        dual.include_cidrs_explicit = true;
        let script = IptablesPlan::udp_setup_script(&dual);
        assert!(
            script.contains("ip6tables -t mangle"),
            "v6 UDP probe must check the mangle table: {script}"
        );
        assert!(
            !script.contains("ip6tables -t nat"),
            "v6 UDP probe must not check the nat table: {script}"
        );
    }

    #[test]
    fn udp_teardown_script_reaps_udp_state_only() {
        let script = IptablesPlan::udp_teardown_script(true);
        for chain in [
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                script.contains(chain),
                "teardown must reap {chain}: {script}"
            );
        }
        // Exact Ferrum-owned routing teardown (never a table flush / by-lookup rule).
        assert!(
            script.contains(&format!(
                "ip rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
            )),
            "v4 fwmark rule teardown missing: {script}"
        );
        assert!(
            script.contains(&format!(
                "ip route del local 0.0.0.0/0 dev lo table {TPROXY_ROUTE_TABLE}"
            )),
            "v4 local route teardown missing: {script}"
        );
        // v6 table teardown guarded behind the ip6tables (mangle) probe...
        assert!(script.contains("command -v ip6tables") && script.contains("ip6tables -t mangle"));
        // ...but v6 routing (`ip -6`) emitted UNCONDITIONALLY (not behind the probe).
        assert!(
            script.contains(&format!(
                "ip -6 rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
            )),
            "v6 fwmark rule teardown must be unconditional: {script}"
        );
        // No TCP nat teardown.
        assert!(!script.contains("-t nat") && !script.contains("REDIRECT"));
    }

    #[test]
    fn udp_teardown_script_v4_only_omits_v6() {
        let script = IptablesPlan::udp_teardown_script(false);
        assert!(script.contains("FERRUM_MESH_UDP_OUTBOUND"));
        assert!(
            !script.contains("ip -6") && !script.contains("ip6tables"),
            "v4-only teardown must emit no v6 commands: {script}"
        );
    }

    #[test]
    fn udp_capture_disabled_by_default_emits_no_mangle_or_tproxy() {
        // The default (UDP off) plan must contain NO mangle/TPROXY/ip-routing
        // rules — Stage 2 is inert until explicitly enabled.
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        assert!(!config.udp_capture_enabled);
        assert_eq!(config.udp_outbound_port, DEFAULT_UDP_OUTBOUND_PORT);
        assert_eq!(config.tproxy_mark, DEFAULT_TPROXY_MARK);

        let plan = IptablesPlan::for_config(&config);
        for cmd in plan.v4_commands.iter().chain(plan.v6_commands.iter()) {
            assert!(
                !cmd.contains("mangle")
                    && !cmd.contains("TPROXY")
                    && !cmd.contains("FERRUM_MESH_UDP")
                    && !cmd.contains("-p udp")
                    && !cmd.contains("ip rule")
                    && !cmd.contains("ip route")
                    && !cmd.contains("fwmark"),
                "UDP-disabled plan must emit no UDP/TPROXY/routing rules: {cmd}"
            );
        }
    }

    #[test]
    fn udp_capture_enabled_emits_mangle_chains_tproxy_and_routing() {
        let config = udp_enabled_iptables_config();
        let plan = IptablesPlan::for_config(&config);
        let cmds = &plan.v4_commands;

        // New mangle-table chains are created. Inbound UDP capture stays enabled
        // for LOCAL destinations so unauthenticated UDP cannot bypass the mesh.
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "missing UDP outbound mangle chain: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_INBOUND")),
            "missing UDP inbound mangle chain: {cmds:?}"
        );

        // Catch-all TPROXY jump on both directions, on the UDP port with the mark.
        let tproxy_arg = format!(
            "-j TPROXY --on-port {} --tproxy-mark 0x{:x}/0x{:x}",
            DEFAULT_UDP_OUTBOUND_PORT, DEFAULT_TPROXY_MARK, TPROXY_MARK_MASK
        );
        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-p udp")
                && c.contains(&tproxy_arg)),
            "missing outbound UDP TPROXY jump: {cmds:?}"
        );

        // mangle PREROUTING jumps for both dst-based chains, plus the reinject chain
        // jump. TPROXY is PREROUTING-only, so the OUTPUT path is MARK-only (codex
        // r6): a `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump MUST exist, but
        // the OUTPUT chain must NEVER jump into a `-j TPROXY` chain (which would be
        // invalid).
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("PREROUTING")
                && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")),
            "missing mangle PREROUTING -> UDP outbound jump: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("PREROUTING")
                && c.contains("-j FERRUM_MESH_UDP_REINJECT")),
            "missing mangle PREROUTING -> UDP reinject jump (codex r6): {cmds:?}"
        );
        // The OUTPUT jump must target the MARK-only chain, NOT a TPROXY chain.
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("-A OUTPUT")
                && c.contains("-j FERRUM_MESH_UDP_OUTPUT_MARK")),
            "missing mangle OUTPUT -> UDP OUTPUT MARK jump (codex r6): {cmds:?}"
        );
        assert!(
            !cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("-A OUTPUT")
                && c.contains("TPROXY")),
            "mangle OUTPUT must never jump into a TPROXY rule (invalid in OUTPUT): {cmds:?}"
        );

        // Transparent-routing plumbing: a FATAL `command -v ip` preflight (codex
        // r2 fail-closed) + idempotent (delete-before-add) ip rule by explicit
        // priority + ip route local (delete-before-add). The fwmark selector still
        // matches the --tproxy-mark above. The load-bearing ADDs are bare (NOT
        // `command -v ip`-guarded, NOT `|| true`) — they must fail closed.
        assert!(
            cmds.iter()
                .any(|c| c.contains("command -v ip >/dev/null 2>&1")
                    && c.contains("exit 1")
                    && c.contains("iproute2")),
            "missing FATAL `command -v ip || exit 1` preflight for routing: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c
                .contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains("fwmark")
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "missing `ip rule add priority <P> fwmark ... lookup <table>`: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}"))),
            "missing idempotent `ip rule del priority <P>` before the add: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("route add local 0.0.0.0/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "missing `ip route add local ... table <table>`: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("route del local 0.0.0.0/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "missing idempotent `ip route del local ... table <table>` before the add: {cmds:?}"
        );
        // The Ferrum routing table must NOT be Istio's shared inbound-TPROXY
        // table 133 (cleanup of ours must never risk a co-resident Istio table).
        assert_ne!(
            TPROXY_ROUTE_TABLE, 133,
            "Ferrum UDP routing table must not reuse Istio's table 133"
        );
    }

    #[test]
    fn udp_setup_flushes_chains_before_adding_rules() {
        // codex r3: changing FERRUM_MESH_CAPTURE_UDP_PORT / FERRUM_MESH_TPROXY_MARK
        // on reconfiguration must NOT leave a stale rule ahead of the new one. The
        // per-rule `-C ... || -A` guard is exact-match, so a changed rule is
        // appended AFTER the old one and (iptables preserves order) the stale rule
        // black-holes UDP. Setup must FLUSH each UDP chain after creating it and
        // BEFORE adding any rule to it.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let cmds = &plan.v4_commands;

        for chain in [
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            "FERRUM_MESH_UDP_REINJECT",
            "FERRUM_MESH_UDP_INBOUND",
        ] {
            let flush = cmds
                .iter()
                .position(|c| c.contains("-t mangle") && c.contains(&format!("-F {chain}")))
                .unwrap_or_else(|| panic!("setup missing flush of {chain}: {cmds:?}"));
            // The flush must precede every append/check into this chain so the
            // chain is rebuilt cleanly.
            let first_rule = cmds.iter().position(|c| {
                c.contains("-t mangle")
                    && (c.contains(&format!("-A {chain}")) || c.contains(&format!("-C {chain}")))
            });
            if let Some(first_rule) = first_rule {
                assert!(
                    flush < first_rule,
                    "flush of {chain} must precede its first rule add: {cmds:?}"
                );
            }
        }
    }

    #[test]
    fn udp_setup_ip_rule_and_route_are_idempotent_delete_before_add() {
        // A node-agent fallback crash before cleanup then a re-run must not stack
        // a duplicate `ip rule`: setup deletes by explicit priority before adding,
        // and deletes the exact route before adding it.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let cmds = &plan.v4_commands;

        let rule_del = cmds
            .iter()
            .position(|c| c.contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule del present");
        let rule_add = cmds
            .iter()
            .position(|c| c.contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule add present");
        assert!(
            rule_del < rule_add,
            "ip rule del must precede add for idempotency: {cmds:?}"
        );

        let route_del = cmds
            .iter()
            .position(|c| c.contains("route del local 0.0.0.0/0 dev lo"))
            .expect("ip route del present");
        let route_add = cmds
            .iter()
            .position(|c| c.contains("route add local 0.0.0.0/0 dev lo"))
            .expect("ip route add present");
        assert!(
            route_del < route_add,
            "ip route del must precede add for idempotency: {cmds:?}"
        );
    }

    // codex r2 finding 3: the RPDB is priority-ordered and the kernel's built-in
    // `main` table rule is priority 32766. The Ferrum fwmark rule MUST sit BELOW
    // it (lower number = evaluated first), or `main` resolves the marked datagram
    // to its normal route before the fwmark lookup steers it to local delivery —
    // captured UDP would black-hole. Compile-time assertion (the value is a
    // const), so a regression to a >=32766 priority fails the build.
    const _: () = assert!(
        TPROXY_ROUTE_RULE_PRIORITY < 32766,
        "fwmark ip-rule priority must be below the kernel `main` rule (32766)"
    );
    // The routing TABLE number is intentionally NOT the rule priority — they are
    // separate concepts (table stays the high Ferrum-owned constant).
    const _: () = assert!(
        TPROXY_ROUTE_TABLE as u32 != TPROXY_ROUTE_RULE_PRIORITY,
        "rule priority must be separate from the routing table number"
    );

    #[test]
    fn udp_prerouting_emits_outbound_and_inbound_jumps() {
        // The OUTBOUND and INBOUND chains are jumped from `mangle PREROUTING`
        // (TPROXY is PREROUTING-only). The inbound jump keeps pod-destined UDP
        // from bypassing mesh identity and authorization.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let cmds = &plan.v4_commands;

        assert!(
            cmds.iter().any(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")
            }),
            "missing PREROUTING -> UDP outbound jump: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_INBOUND")
            }),
            "missing PREROUTING -> UDP inbound jump: {cmds:?}"
        );
    }

    #[test]
    fn udp_chains_are_direction_scoped_by_dst_addrtype() {
        // codex r2 finding 2: the two PREROUTING chains stay direction-disjoint by
        // destination address type (the pod-IP-agnostic mirror of the TCP chains'
        // hook separation). Outbound TPROXY = `! --dst-type LOCAL` (remote dest);
        // the inbound catch-all = `--dst-type LOCAL` (the pod's own IP).
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let cmds = &plan.v4_commands;

        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-m addrtype ! --dst-type LOCAL")
                && c.contains("-j TPROXY")),
            "outbound UDP TPROXY must be scoped to a non-local destination: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                && c.contains("-m addrtype --dst-type LOCAL")
                && c.contains("-j TPROXY")),
            "inbound UDP TPROXY must be scoped to a local destination: {cmds:?}"
        );
    }

    #[test]
    fn udp_routing_fails_closed_when_ip_unavailable() {
        // codex r2 finding 1: TPROXY local delivery is useless without the
        // `ip rule`/`ip route` plumbing. When UDP capture is enabled the setup
        // must (a) fatally preflight `command -v ip` BEFORE installing any UDP
        // rule, and (b) NOT `|| true` the load-bearing routing ADDs.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let cmds = &plan.v4_commands;
        let script = plan.script();

        // (a) Fatal `command -v ip` preflight present, and ordered before any UDP
        // mangle/TPROXY rule and before the routing adds.
        let preflight = cmds
            .iter()
            .position(|c| {
                c.contains("command -v ip >/dev/null 2>&1")
                    && c.contains("exit 1")
                    && c.contains("iproute2")
            })
            .expect("fatal `command -v ip` preflight");
        let first_udp_rule = cmds
            .iter()
            .position(|c| c.contains("FERRUM_MESH_UDP") || c.contains("-p udp"))
            .expect("a UDP rule");
        assert!(
            preflight < first_udp_rule,
            "fatal `command -v ip` preflight must precede any UDP rule (install together or not at all): {cmds:?}"
        );
        let rule_add = cmds
            .iter()
            .position(|c| c.contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule add");
        assert!(
            preflight < rule_add,
            "preflight must precede the routing add: {cmds:?}"
        );

        // (b) Load-bearing ADDs are NOT `|| true` (must fail the `set -e` script).
        for needle in ["rule add priority", "route add local"] {
            let add = cmds
                .iter()
                .find(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("missing `{needle}` command: {cmds:?}"));
            assert!(
                !add.contains("|| true"),
                "load-bearing routing add must NOT be `|| true` (fail closed): {add}"
            );
        }
        // The delete-before-add (idempotence) DOES stay best-effort.
        for needle in ["rule del priority", "route del local"] {
            let del = cmds
                .iter()
                .find(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("missing `{needle}` command: {cmds:?}"));
            assert!(
                del.contains("|| true"),
                "idempotence delete must stay best-effort (`|| true`): {del}"
            );
        }

        // The fatal preflight survives into the `set -e` script (it is the gate
        // that makes `ip`-missing exit non-zero before installing TPROXY).
        assert!(
            script.contains("command -v ip >/dev/null 2>&1")
                && script.contains("iproute2 (ip) is required"),
            "setup script must carry the fatal `command -v ip` preflight: {script}"
        );
    }

    #[test]
    fn udp_capture_mirrors_exclude_rules_and_scopes_owner_match_to_output() {
        let mut config = udp_enabled_iptables_config();
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string()];
        config.exclude_ports = vec![53];
        config.exclude_inbound_ports = vec![5353];

        let plan = IptablesPlan::for_config(&config);
        let cmds = &plan.v4_commands;

        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-p udp -d 10.0.0.0/8 -j RETURN")),
            "UDP outbound exclude CIDR RETURN missing: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-p udp --dport 53 -j RETURN")),
            "UDP outbound exclude port RETURN missing: {cmds:?}"
        );
        // The OUTPUT MARK chain mirrors the SAME exclude rules (codex r6) so a
        // locally-generated egress to an excluded CIDR/port is not marked/looped.
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains("-p udp -d 10.0.0.0/8 -j RETURN")),
            "UDP OUTPUT MARK exclude CIDR RETURN missing: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains("-p udp --dport 53 -j RETURN")),
            "UDP OUTPUT MARK exclude port RETURN missing: {cmds:?}"
        );
        // Owner-match self-exclusion is OUTPUT-context ONLY (codex r6): it MUST
        // appear in the OUTPUT MARK chain (locally-generated egress sees the
        // originating socket) and MUST NOT appear in any PREROUTING-reached chain
        // (OUTBOUND/INBOUND/REINJECT — owner-match is invalid there). (The TCP `nat`
        // chain still uses `-m owner` legitimately, so scope this to the UDP chains.)
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!(
                        "-m owner --uid-owner {} -j RETURN",
                        DEFAULT_PROXY_UID
                    ))),
            "UDP OUTPUT MARK chain must carry the proxy-UID owner RETURN: {cmds:?}"
        );
        for chain in [
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                !cmds
                    .iter()
                    .any(|c| c.contains(chain) && c.contains("-m owner")),
                "PREROUTING-reached chain {chain} must NOT emit `-m owner` (invalid context): {cmds:?}"
            );
        }

        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                && c.contains("-p udp --dport 5353 -j RETURN")),
            "UDP inbound exclude port RETURN missing: {cmds:?}"
        );
    }

    #[test]
    fn udp_output_mark_loop_captures_locally_generated_egress() {
        // codex r6: the pod's OWN locally-generated UDP egress goes OUTPUT ->
        // POSTROUTING and never PREROUTING, so it is captured via an OUTPUT MARK
        // chain -> fwmark reroute to lo -> a mark-match PREROUTING TPROXY rule (in
        // the reinject chain). Assert the whole loop is wired in the injector
        // (pod-netns) path.
        let config = udp_enabled_iptables_config();
        assert!(!config.host_netns, "this test exercises the pod-netns path");
        let plan = IptablesPlan::for_config(&config);
        let cmds = &plan.v4_commands;

        let mark_arg = format!("0x{:x}/0x{:x}", DEFAULT_TPROXY_MARK, TPROXY_MARK_MASK);

        // (a) The OUTPUT MARK chain is created and jumped from `mangle OUTPUT`.
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_OUTPUT_MARK")),
            "missing OUTPUT MARK chain creation: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("-A OUTPUT")
                && c.contains("-p udp -j FERRUM_MESH_UDP_OUTPUT_MARK")),
            "missing `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump: {cmds:?}"
        );

        // (b) The OUTPUT MARK chain leads with an anti-loop mark RETURN and a
        // proxy-UID owner RETURN, then MARKs egress with the TPROXY fwmark (NOT
        // TPROXY — invalid in OUTPUT).
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!("-m mark --mark {mark_arg} -j RETURN"))),
            "missing anti-loop mark RETURN at top of OUTPUT MARK chain: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!("-j MARK --set-mark {mark_arg}"))),
            "missing `-j MARK --set-mark <mark>` rule in OUTPUT MARK chain: {cmds:?}"
        );
        assert!(
            !cmds
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("TPROXY")),
            "OUTPUT MARK chain must MARK, never TPROXY (invalid in OUTPUT): {cmds:?}"
        );

        // (c) The reinject chain holds the mark-match TPROXY rule and is jumped from
        // PREROUTING BEFORE the dst-based OUTBOUND/INBOUND chains (so the looped
        // datagram is TPROXY'd once, never double-processed by the dst-based chain).
        let reinject_tproxy = format!(
            "-p udp -m mark --mark {mark_arg} -j TPROXY --on-port {} --tproxy-mark {mark_arg}",
            DEFAULT_UDP_OUTBOUND_PORT
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_REINJECT") && c.contains(&reinject_tproxy)),
            "missing mark-match TPROXY rule in reinject chain: {cmds:?}"
        );
        let reinject_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_REINJECT")
            })
            .expect("PREROUTING -> reinject jump");
        let outbound_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")
            })
            .expect("PREROUTING -> outbound jump");
        let inbound_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_INBOUND")
            })
            .expect("PREROUTING -> inbound jump");
        assert!(
            reinject_jump < outbound_jump && outbound_jump < inbound_jump,
            "PREROUTING jump order must be reinject, outbound, inbound: {cmds:?}"
        );

        // (d) Host-netns (node-agent) path emits NO UDP rules at all — including no
        // OUTPUT MARK chain / OUTPUT jump — because the addrtype direction split is
        // wrong in the host netns (round-5 limitation, preserved).
        let mut host_config = config.clone();
        host_config.host_netns = true;
        let host_plan = IptablesPlan::for_config(&host_config);
        for cmd in host_plan
            .v4_commands
            .iter()
            .chain(host_plan.v6_commands.iter())
        {
            assert!(
                !(cmd.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    || cmd.contains("FERRUM_MESH_UDP_REINJECT")
                    || cmd.contains("-j MARK --set-mark")
                    || (cmd.contains("-t mangle") && cmd.contains("OUTPUT"))),
                "host-netns path must emit NO UDP OUTPUT MARK / reinject rules: {cmd}"
            );
        }
    }

    #[test]
    fn udp_output_mark_mirrors_outbound_capture_scope() {
        // The OUTPUT MARK chain must mirror the SAME include scoping as the
        // PREROUTING outbound TPROXY chain (codex r6): per-port includes emit a
        // per-port `-j MARK` and the implicit catch-all emits a catch-all `-j MARK`,
        // so OUTPUT capture exactly matches PREROUTING capture.
        // Default config (`include_cidrs = ["0.0.0.0/0"]`, NOT explicit): the
        // OUTPUT MARK chain mirrors the OUTBOUND TPROXY chain's selector exactly —
        // a `-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j MARK` rule (same
        // `-d 0.0.0.0/0` selector AND the same `! --dst-type LOCAL` egress scope the
        // TPROXY rule carries). Only the jump differs (MARK vs TPROXY).
        let default_plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let mark_arg = format!("0x{:x}/0x{:x}", DEFAULT_TPROXY_MARK, TPROXY_MARK_MASK);
        // The OUTBOUND TPROXY chain carries `-p udp -d 0.0.0.0/0 -m addrtype ! ...`.
        assert!(
            default_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains("-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j TPROXY")),
            "default OUTBOUND TPROXY rule shape changed: {:?}",
            default_plan.v4_commands
        );
        // The OUTPUT MARK chain mirrors the SAME `-p udp -d 0.0.0.0/0` selector AND
        // the SAME `! --dst-type LOCAL` egress scope, with a MARK jump (codex r9):
        // loopback / the pod's own IP are `--dst-type LOCAL` in OUTPUT and must NOT
        // be marked (else they would be fwmark-rerouted to `lo` + TPROXY-captured);
        // only genuine non-local egress is marked.
        assert!(
            default_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!(
                        "-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j MARK --set-mark {mark_arg}"
                    ))),
            "OUTPUT MARK must mirror the OUTBOUND selector AND `! --dst-type LOCAL` scope: {:?}",
            default_plan.v4_commands
        );
        // Every OUTPUT MARK `-j MARK` rule MUST carry the `! --dst-type LOCAL` scope
        // (codex r9 — exclude loopback / self), and NONE may carry the inbound
        // `--dst-type LOCAL` (without the `!`) discriminator. We assert each marking
        // rule contains `addrtype ! --dst-type LOCAL` and that no marking rule
        // carries a bare (non-negated) `--dst-type LOCAL`.
        let mark_rules: Vec<&String> = default_plan
            .v4_commands
            .iter()
            .filter(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("-j MARK"))
            .collect();
        assert!(
            !mark_rules.is_empty(),
            "expected at least one OUTPUT MARK marking rule: {:?}",
            default_plan.v4_commands
        );
        for rule in &mark_rules {
            assert!(
                rule.contains("-m addrtype ! --dst-type LOCAL"),
                "OUTPUT MARK rule must exclude LOCAL (loopback/self) destinations: {rule}"
            );
            assert!(
                !rule.contains("addrtype --dst-type LOCAL"),
                "OUTPUT MARK rule must NOT carry the inbound (non-negated) `--dst-type LOCAL`: {rule}"
            );
        }

        // Per-port includes: a `--dport` MARK rule per port (each carrying the
        // `! --dst-type LOCAL` egress scope), and NO catch-all MARK.
        let mut port_config = udp_enabled_iptables_config();
        port_config.include_outbound_ports = vec![5432, 9092];
        let port_plan = IptablesPlan::for_config(&port_config);
        for port in [5432, 9092] {
            assert!(
                port_plan
                    .v4_commands
                    .iter()
                    .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                        && c.contains(&format!(
                            "-p udp --dport {port} -m addrtype ! --dst-type LOCAL -j MARK --set-mark {mark_arg}"
                        ))),
                "per-port OUTPUT MARK (with `! --dst-type LOCAL`) missing for {port}: {:?}",
                port_plan.v4_commands
            );
        }
        // Every per-port MARK rule still excludes LOCAL destinations.
        for rule in port_plan
            .v4_commands
            .iter()
            .filter(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("-j MARK"))
        {
            assert!(
                rule.contains("-m addrtype ! --dst-type LOCAL"),
                "per-port OUTPUT MARK rule must exclude LOCAL (loopback/self): {rule}"
            );
        }
        assert!(
            !port_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains("-j MARK")
                    && !c.contains("--dport")),
            "implicit catch-all MARK must not fire when includeOutboundPorts narrows: {:?}",
            port_plan.v4_commands
        );
    }

    #[test]
    fn udp_capture_per_port_tproxy_when_include_ports_set() {
        let mut config = udp_enabled_iptables_config();
        config.include_outbound_ports = vec![5432, 9092];

        let plan = IptablesPlan::for_config(&config);
        for port in [5432, 9092] {
            assert!(
                plan.v4_commands.iter().any(|c| c.contains(&format!(
                    "-p udp --dport {port} -m addrtype ! --dst-type LOCAL -j TPROXY --on-port {}",
                    DEFAULT_UDP_OUTBOUND_PORT
                ))),
                "per-port UDP TPROXY (non-local-scoped) missing for {port}: {:?}",
                plan.v4_commands
            );
        }
        // includeOutboundPorts without explicit include CIDRs must not also emit
        // an OUTBOUND catch-all (no `--dport`/`-d` narrowing) `-p udp ... -j TPROXY`
        // (mirrors the TCP narrowing semantics). The INBOUND chain keeps its
        // protocol-wide catch-all, so scope this check to the outbound chain.
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains("-j TPROXY")
                    && !c.contains("--dport")
                    && !c.contains("-d ")),
            "implicit catch-all outbound UDP TPROXY must not fire when includeOutboundPorts narrows: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn udp_capture_partitions_ipv4_and_ipv6() {
        let mut config = udp_enabled_iptables_config();
        config.include_cidrs = vec!["172.16.0.0/12".to_string(), "2001:db8::/32".to_string()];
        config.include_cidrs_explicit = true;

        let plan = IptablesPlan::for_config(&config);

        // IPv4 TPROXY rules use `iptables` + IPv4 routing; no IPv6 leakage. The
        // outbound CIDR rule carries the non-local destination scope.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("iptables -t mangle")
                    && c.contains(
                        "-p udp -d 172.16.0.0/12 -m addrtype ! --dst-type LOCAL -j TPROXY"
                    )),
            "IPv4 UDP TPROXY CIDR rule missing: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands.iter().any(|c| c.contains(&format!(
                "ip rule add priority {TPROXY_ROUTE_RULE_PRIORITY} fwmark"
            )) && !c.contains("ip -6")),
            "IPv4 transparent routing must use `ip` (not `ip -6`): {:?}",
            plan.v4_commands
        );
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("::/") || c.contains("2001:db8") || c.contains("ip -6")),
            "IPv6 UDP rules must not appear in IPv4 commands: {:?}",
            plan.v4_commands
        );

        // IPv6 TPROXY rules use `ip6tables -t mangle` + `ip -6` routing.
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip6tables -t mangle")
                    && c.contains(
                        "-p udp -d 2001:db8::/32 -m addrtype ! --dst-type LOCAL -j TPROXY"
                    )),
            "IPv6 UDP TPROXY CIDR rule missing: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains(&format!(
                    "ip -6 rule add priority {TPROXY_ROUTE_RULE_PRIORITY} fwmark"
                )) && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "IPv6 transparent routing rule missing: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip -6 route add local ::/0 dev lo")),
            "IPv6 local route missing: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn cleanup_removes_udp_tproxy_chains_and_routing() {
        let cleanup = IptablesPlan::cleanup_commands(true);

        // mangle chain teardown (jumps, flush, delete) for ALL FOUR UDP chains —
        // the dst-based PREROUTING pair plus the OUTPUT MARK + reinject chains
        // (codex r6).
        for chain in [
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                cleanup
                    .iter()
                    .any(|c| c.contains("-t mangle") && c.contains(&format!("-F {chain}"))),
                "cleanup missing flush of {chain}"
            );
            assert!(
                cleanup
                    .iter()
                    .any(|c| c.contains("-t mangle") && c.contains(&format!("-X {chain}"))),
                "cleanup missing delete of {chain}"
            );
        }
        // PREROUTING jump deletes for the three PREROUTING-jumped chains.
        for chain in [
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                cleanup.iter().any(|c| c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-D")
                    && c.contains(chain)),
                "cleanup missing mangle PREROUTING jump delete for {chain}"
            );
        }
        // The `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump (codex r6) MUST be
        // deleted — and the OUTPUT delete must target the MARK chain, never a TPROXY
        // chain (none was installed there).
        assert!(
            cleanup.iter().any(|c| c.contains("-t mangle")
                && c.contains("-D OUTPUT")
                && c.contains("-j FERRUM_MESH_UDP_OUTPUT_MARK")),
            "cleanup missing mangle OUTPUT MARK jump delete (codex r6): {cleanup:?}"
        );
        assert!(
            !cleanup.iter().any(|c| c.contains("-t mangle")
                && c.contains("-D OUTPUT")
                && c.contains("TPROXY")),
            "cleanup OUTPUT delete must not reference a TPROXY chain: {cleanup:?}"
        );

        // Routing teardown deletes ONLY the EXACT Ferrum-owned rule (by explicit
        // priority) + exact route — never `ip rule del lookup` / `ip route flush
        // table` (which could drop a co-resident route, e.g. an Istio table).
        // Cleanup deletes are best-effort (`|| true`), not `command -v ip`-gated.
        assert!(
            cleanup.iter().any(|c| c
                .contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "cleanup missing exact `ip rule del priority <P> lookup <table>`: {cleanup:?}"
        );
        assert!(
            cleanup
                .iter()
                .any(|c| c.contains("route del local 0.0.0.0/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "cleanup missing exact `ip route del local ... table <table>`: {cleanup:?}"
        );
        assert!(
            !cleanup
                .iter()
                .any(|c| c.contains("route flush table") || c.contains("rule del lookup")),
            "cleanup must NOT flush a table or delete-by-lookup (shared-table hazard): {cleanup:?}"
        );
        // Every cleanup command stays best-effort.
        for cmd in &cleanup {
            assert!(
                cmd.contains("|| true"),
                "UDP cleanup command must tolerate missing state: {cmd}"
            );
        }
    }

    #[test]
    fn cleanup_v6_split_separates_raw_ip_routing_from_ip6tables_tables() {
        // codex r3: the raw `ip -6 rule/route del` teardown must be in `ip_routing`
        // (emitted unconditionally by the node-agent) and NOT in `iptables` (which
        // the node-agent guards behind an `ip6tables` availability probe). Wrapping
        // the `ip -6` teardown in that probe would leak the fwmark rule + local
        // route when `ip6tables` is missing.
        let split = IptablesPlan::cleanup_v6_split(true);

        // The raw `ip -6` rule/route teardown lives in `ip_routing`.
        assert!(
            split.ip_routing.iter().any(|c| c.contains("ip -6 rule del")
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "v6 ip_routing must carry `ip -6 rule del ... lookup <table>`: {:?}",
            split.ip_routing
        );
        assert!(
            split
                .ip_routing
                .iter()
                .any(|c| c.contains("ip -6 route del local ::/0 dev lo")),
            "v6 ip_routing must carry `ip -6 route del local ::/0 dev lo`: {:?}",
            split.ip_routing
        );
        // The `iptables`/table portion must NOT contain any raw `ip -6` routing.
        assert!(
            !split
                .iptables
                .iter()
                .any(|c| c.contains("ip -6 rule") || c.contains("ip -6 route")),
            "v6 iptables (table) portion must not contain raw `ip -6` routing: {:?}",
            split.iptables
        );
        // The table portion still tears down the mangle chains (ip6tables-guarded).
        assert!(
            split
                .iptables
                .iter()
                .any(|c| c.contains("ip6tables") && c.contains("FERRUM_MESH_UDP")),
            "v6 iptables portion must tear down the UDP mangle chains: {:?}",
            split.iptables
        );
    }

    #[test]
    fn cleanup_v6_split_routing_empty_when_udp_disabled() {
        // When UDP capture was never enabled, there is no routing state to tear
        // down (gated like the v4 path); both halves carry only the TCP nat-chain
        // teardown and no `ip -6` routing.
        let split = IptablesPlan::cleanup_v6_split(false);
        assert!(
            split.ip_routing.is_empty(),
            "UDP-disabled v6 cleanup must emit no routing teardown: {:?}",
            split.ip_routing
        );
    }

    #[test]
    fn cleanup_gated_off_emits_no_udp_or_routing_teardown() {
        // When this install never enabled UDP capture, cleanup must not touch any
        // UDP mangle chain OR routing state it never created (codex r1).
        let cleanup = IptablesPlan::cleanup_commands(false);
        for cmd in &cleanup {
            assert!(
                !cmd.contains("FERRUM_MESH_UDP")
                    && !cmd.contains("mangle")
                    && !cmd.contains("ip rule")
                    && !cmd.contains("ip route")
                    && !cmd.contains(&format!("table {TPROXY_ROUTE_TABLE}"))
                    && !cmd.contains(&format!("priority {TPROXY_ROUTE_RULE_PRIORITY}")),
                "UDP-disabled cleanup must emit no UDP/mangle/routing teardown: {cmd}"
            );
        }
        // The TCP nat-chain teardown still runs.
        assert!(
            cleanup
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "UDP-disabled cleanup must still tear down the TCP nat chains: {cleanup:?}"
        );
    }

    #[test]
    fn udp_capture_v6_suppressed_when_ip6tables_disabled() {
        let mut config = udp_enabled_iptables_config();
        config.ip6tables_mode = Ip6TablesMode::Disabled;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config);
        assert!(
            plan.v6_commands.is_empty(),
            "disabled ip6tables must suppress IPv6 UDP TPROXY rules: {:?}",
            plan.v6_commands
        );
        // IPv4 UDP rules still emit.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND") && c.contains("TPROXY")),
            "IPv4 UDP TPROXY must remain when ip6tables disabled: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn udp_capture_ipv6_only_includes_emit_no_ipv4_catch_all() {
        // codex r4 (finding #1): with an IPv6-only EXPLICIT include set, the IPv4
        // family has no include CIDR but `include_cidrs_explicit` is still true.
        // Unlike the TCP REDIRECT path (which fails closed to an IPv4 catch-all
        // delivering to the existing outbound listener), the UDP path must SKIP the
        // unqualified IPv4 `-j TPROXY` catch-all entirely — an unqualified UDP
        // TPROXY would divert ALL IPv4 UDP (DNS included) into the marked routing
        // table though only IPv6 was selected, black-holing it (no Stage 3 listener
        // yet). Capturing nothing for the unselected family is the safe failure.
        let mut config = udp_enabled_iptables_config();
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;

        let plan = IptablesPlan::for_config(&config);

        // The IPv4 family must emit no OUTBOUND UDP catch-all or MARK rule when
        // only IPv6 CIDRs are selected. Inbound LOCAL capture is still emitted for
        // the active IPv4 family so pod-destined UDP fail-closes behind the mesh
        // relay instead of bypassing mTLS/authz.
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND") && c.contains("-j TPROXY")),
            "IPv6-only explicit includes must not emit IPv4 outbound UDP TPROXY state: {:?}",
            plan.v4_commands
        );
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("-j MARK")),
            "IPv6-only explicit includes must not MARK IPv4 outbound UDP egress: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                    && c.contains("-m addrtype --dst-type LOCAL")
                    && c.contains("-j TPROXY")),
            "IPv4 inbound UDP LOCAL capture must stay installed for fail-closed inbound protection: {:?}",
            plan.v4_commands
        );
        // The TCP IPv4 chains are still present (CIDR scoping is outbound-UDP-only).
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "IPv4 TCP capture chains must remain: {:?}",
            plan.v4_commands
        );
        // The IPv6 family still gets its narrowed TPROXY rule (the selected family).
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip6tables -t mangle")
                    && c.contains("-p udp -d fd00::/8 -m addrtype ! --dst-type LOCAL -j TPROXY")),
            "IPv6 UDP TPROXY CIDR rule must still be emitted for the selected family: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn udp_port_includes_survive_cross_family_catch_all_skip() {
        // codex r5 (finding #2): the cross-family CATCH-ALL skip (codex r4) must
        // NOT also drop family-agnostic `--dport` port includes. With an IPv6-only
        // include CIDR plus an `includeOutboundPorts` port (e.g. DNS/53), the IPv4
        // family is cross-family-skipped for the CIDR catch-all but must STILL emit
        // its IPv4 `--dport 53` TPROXY rule — a port include is not family-scoped.
        let mut config = udp_enabled_iptables_config();
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_outbound_ports = vec![53];

        let plan = IptablesPlan::for_config(&config);

        // The IPv4 `--dport 53` outbound TPROXY rule MUST be present (the port
        // include survives the catch-all skip).
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("iptables -t mangle")
                    && c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains(&format!(
                        "-p udp --dport 53 -m addrtype ! --dst-type LOCAL -j TPROXY --on-port {}",
                        DEFAULT_UDP_OUTBOUND_PORT
                    ))),
            "IPv4 --dport port include must survive the cross-family catch-all skip: {:?}",
            plan.v4_commands
        );
        // Because the port include emits an IPv4 UDP rule, the IPv4 family now also
        // gets its mangle chains, PREROUTING jumps, and routing.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("iptables -t mangle")
                    && c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "IPv4 UDP chains must be created when a port include emits a rule: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("ip rule add priority")
                    && c.contains("fwmark")
                    && !c.contains("ip -6")),
            "IPv4 routing must be installed when a port include emits a rule: {:?}",
            plan.v4_commands
        );
        // But the IPv4 family must STILL NOT get an unqualified OUTBOUND
        // catch-all. Inbound `--dst-type LOCAL` capture is deliberately present
        // for fail-closed inbound protection even when the outbound CIDR selector
        // is IPv6-only.
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains("-j TPROXY")
                    && !c.contains("--dport")
                    && !c.contains("-d ")),
            "IPv4 outbound catch-all must stay suppressed for the unselected family: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                    && c.contains("-m addrtype --dst-type LOCAL")
                    && c.contains("-j TPROXY")),
            "IPv4 inbound LOCAL capture must stay installed for fail-closed inbound protection: {:?}",
            plan.v4_commands
        );
        // The IPv6 family keeps its CIDR-qualified OUTBOUND rule (it IS the selected
        // family). The port include also fans onto IPv6 (port includes are
        // family-agnostic). Inbound UDP capture also emits the LOCAL catch-all for
        // the selected family so pod-destined UDP remains fail-closed.
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip6tables -t mangle")
                    && c.contains("-p udp -d fd00::/8 -m addrtype ! --dst-type LOCAL -j TPROXY")),
            "IPv6 selected-family CIDR rule missing: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                    && c.contains("-m addrtype --dst-type LOCAL")
                    && c.contains("-j TPROXY")),
            "IPv6 inbound catch-all must protect the selected family: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn udp_host_netns_emits_no_udp_tproxy_rules() {
        // codex r5 (finding #1): the node-agent runs `hostNetwork: true` (host
        // netns), where the `addrtype --dst-type LOCAL` direction split is wrong
        // (pod IPs are FORWARDED, not LOCAL). The host-netns iptables fallback must
        // therefore emit NO UDP TPROXY rules at all (eBPF is the supported
        // node-agent UDP path) rather than silently mis-capturing inbound as
        // outbound. TCP capture is unaffected.
        let mut config = udp_enabled_iptables_config();
        config.host_netns = true;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_outbound_ports = vec![53];

        let plan = IptablesPlan::for_config(&config);

        for cmd in plan.v4_commands.iter().chain(plan.v6_commands.iter()) {
            assert!(
                !cmd.contains("mangle")
                    && !cmd.contains("TPROXY")
                    && !cmd.contains("FERRUM_MESH_UDP")
                    && !cmd.contains("-p udp")
                    && !cmd.contains("fwmark")
                    && !cmd.starts_with("ip rule")
                    && !cmd.starts_with("ip -6 rule")
                    && !cmd.starts_with("ip route")
                    && !cmd.starts_with("ip -6 route"),
                "host-netns UDP-enabled plan must emit no UDP/TPROXY/routing rules: {cmd}"
            );
        }
        // TCP capture chains MUST remain — only the UDP TPROXY path is suppressed.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "host-netns plan must keep TCP capture chains: {:?}",
            plan.v4_commands
        );
        // The pod-netns (injector) equivalent DOES emit UDP rules — confirm the
        // suppression is keyed strictly on `host_netns`.
        let mut pod_config = config.clone();
        pod_config.host_netns = false;
        let pod_plan = IptablesPlan::for_config(&pod_config);
        assert!(
            pod_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP")),
            "pod-netns plan with the same config must still emit UDP rules: {:?}",
            pod_plan.v4_commands
        );
    }

    #[test]
    fn udp_routing_installed_before_prerouting_jumps() {
        // codex r5 (finding #3): the injector init container runs the whole `set -e`
        // script with NO cleanup trap, so the routing plumbing (`ip rule`/`ip
        // route`) must be installed BEFORE the `mangle PREROUTING` jumps that start
        // steering UDP into the chains. Otherwise an `ip rule`/`ip route` failure
        // after the jumps were appended leaves TPROXY live without policy routing —
        // a half-installed black-hole.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config());
        let cmds = &plan.v4_commands;

        let route_add = cmds
            .iter()
            .position(|c| c.contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule add present");
        let local_route_add = cmds
            .iter()
            .position(|c| c.contains("route add local 0.0.0.0/0 dev lo"))
            .expect("ip route add present");
        let outbound_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")
            })
            .expect("PREROUTING -> UDP outbound jump");

        // Routing plumbing must precede the first dst-based PREROUTING jump.
        assert!(
            route_add < outbound_jump,
            "fwmark `ip rule add` must precede the PREROUTING jump: {cmds:?}"
        );
        assert!(
            local_route_add < outbound_jump,
            "`ip route add local` must precede the PREROUTING jump: {cmds:?}"
        );
    }

    #[test]
    fn udp_setup_rule_delete_is_priority_keyed_not_mark_keyed() {
        // codex r4 (finding #2): the delete-before-add for the fwmark `ip rule`
        // must delete by the STABLE Ferrum-owned PRIORITY + table only — NOT keyed
        // on the (operator-overridable) mark value. Otherwise a changed
        // `FERRUM_MESH_TPROXY_MARK` leaves the OLD mark's priority-100 rule in
        // place (the new-mark-keyed delete never matches it) and the old mark keeps
        // routing into table 33133.
        let mut config = udp_enabled_iptables_config();
        config.tproxy_mark = 0xABCD;

        let plan = IptablesPlan::for_config(&config);

        // The DELETE must be priority+table keyed and must NOT carry a `fwmark`
        // selector (so it matches whatever mark the prior run installed).
        let del = plan
            .v4_commands
            .iter()
            .find(|c| {
                c.contains("ip rule del")
                    && c.contains(&format!("priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                    && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))
            })
            .expect("priority-keyed `ip rule del` must be emitted");
        assert!(
            !del.contains("fwmark"),
            "the fwmark `ip rule` delete-before-add must NOT be keyed on the mark value: {del}"
        );
        assert!(
            del.contains("|| true"),
            "the delete-before-add must stay best-effort: {del}"
        );
        // The ADD still carries the current mark in its fwmark selector.
        assert!(
            plan.v4_commands.iter().any(|c| c.contains("ip rule add")
                && c.contains(&format!("priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains("fwmark 0xabcd/")
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "the `ip rule add` must install the current mark: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn udp_teardown_split_is_unconditional_and_udp_only() {
        // codex r4 (finding #3, capture half): the dedicated UDP teardown is NOT
        // gated on `udp_capture_enabled` (it takes no flag) and contains ONLY the
        // exact Ferrum-owned UDP state — never the TCP nat chains — so the
        // node-agent can run it unconditionally before setup to reap stale UDP
        // state from a prior UDP-enabled-then-crashed run without disturbing the
        // TCP chains setup is about to rebuild.
        let v4 = IptablesPlan::udp_teardown_split();
        let v6 = IptablesPlan::udp_teardown_v6_split();

        // UDP mangle chain teardown is present (both halves).
        for chain in ["FERRUM_MESH_UDP_INBOUND", "FERRUM_MESH_UDP_OUTBOUND"] {
            assert!(
                v4.iptables
                    .iter()
                    .any(|c| c.contains("-t mangle") && c.contains(&format!("-X {chain}"))),
                "v4 UDP teardown missing delete of {chain}: {:?}",
                v4.iptables
            );
        }
        // The exact Ferrum-owned routing teardown is present and priority-keyed.
        assert!(
            v4.ip_routing.iter().any(|c| c
                .contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))
                && !c.contains("fwmark")),
            "v4 UDP teardown must delete the fwmark rule by priority (mark-independent): {:?}",
            v4.ip_routing
        );
        assert!(
            v6.ip_routing
                .iter()
                .any(|c| c.contains("ip -6 route del local ::/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "v6 UDP teardown must delete the exact local route: {:?}",
            v6.ip_routing
        );
        // CRITICAL: the UDP-only teardown must NOT touch the TCP nat chains.
        for cmd in v4.iptables.iter().chain(v6.iptables.iter()) {
            assert!(
                !cmd.contains("-t nat")
                    && !cmd.contains("FERRUM_MESH_INBOUND")
                    && !cmd.contains("FERRUM_MESH_OUTBOUND"),
                "UDP-only teardown must not touch the TCP nat chains: {cmd}"
            );
        }
        // Never flush-by-table or delete-by-lookup (shared-table hazard).
        for cmd in v4
            .iptables
            .iter()
            .chain(v4.ip_routing.iter())
            .chain(v6.iptables.iter())
            .chain(v6.ip_routing.iter())
        {
            assert!(
                !cmd.contains("route flush table") && !cmd.contains("rule del lookup"),
                "UDP teardown must not flush a table or delete-by-lookup: {cmd}"
            );
            assert!(
                cmd.contains("|| true") || cmd.contains("if command -v ip6tables"),
                "UDP teardown command must be best-effort (or ip6tables-probe-wrapped): {cmd}"
            );
        }
    }

    #[test]
    fn udp_setup_script_keeps_set_e_and_idempotent_guards() {
        // The TPROXY rules ride the same fail-closed `set -e` script as the TCP
        // rules; the raw `ip` commands must stay self-guarded so they never abort
        // it (missing `iproute2` or an already-present rule).
        let script = IptablesPlan::for_config(&udp_enabled_iptables_config()).script();
        assert!(script.starts_with("set -e\n"));
        assert!(script.contains("command -v ip >/dev/null 2>&1"));
        assert!(script.contains("FERRUM_MESH_UDP_OUTBOUND"));
        assert!(script.contains("-j TPROXY"));
    }

    #[test]
    fn from_env_defaults_udp_capture_off() {
        with_capture_env(&[], || {
            let config = CaptureConfig::from_env().expect("config");
            assert!(!config.udp_capture_enabled);
            assert_eq!(config.udp_outbound_port, DEFAULT_UDP_OUTBOUND_PORT);
            assert_eq!(config.tproxy_mark, DEFAULT_TPROXY_MARK);
        });
    }

    #[test]
    fn from_env_parses_udp_capture_settings() {
        with_capture_env(
            &[
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true"),
                ("FERRUM_MESH_CAPTURE_UDP_PORT", "16011"),
                ("FERRUM_MESH_TPROXY_MARK", "0x1234"),
            ],
            || {
                let config = CaptureConfig::from_env().expect("config");
                assert!(config.udp_capture_enabled);
                assert_eq!(config.udp_outbound_port, 16011);
                assert_eq!(config.tproxy_mark, 0x1234);
            },
        );
    }

    #[test]
    fn from_env_parses_decimal_tproxy_mark() {
        with_capture_env(&[("FERRUM_MESH_TPROXY_MARK", "1337")], || {
            let config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.tproxy_mark, 1337);
        });
    }

    #[test]
    fn from_env_rejects_invalid_udp_settings() {
        with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_ENABLED", "maybe")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
        with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_PORT", "0")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
        with_capture_env(&[("FERRUM_MESH_TPROXY_MARK", "0")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
        with_capture_env(&[("FERRUM_MESH_TPROXY_MARK", "nothex")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
    }

    #[test]
    fn from_env_accepts_repo_wide_bool_forms_for_udp_enabled() {
        // codex r3: `FERRUM_MESH_CAPTURE_UDP_ENABLED` must accept the same forms as
        // every other `FERRUM_MESH_*` bool env (`EnvValue for bool`): case-
        // insensitive `true`/`false` plus `1`/`0`. The previous `bool::from_str`
        // rejected `1`/`0`/`TRUE`.
        for truthy in ["true", "TRUE", "True", "1"] {
            with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_ENABLED", truthy)], || {
                let config = CaptureConfig::from_env().expect("config");
                assert!(
                    config.udp_capture_enabled,
                    "'{truthy}' must parse as UDP-enabled"
                );
            });
        }
        for falsy in ["false", "FALSE", "False", "0"] {
            with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_ENABLED", falsy)], || {
                let config = CaptureConfig::from_env().expect("config");
                assert!(
                    !config.udp_capture_enabled,
                    "'{falsy}' must parse as UDP-disabled"
                );
            });
        }
    }
}
