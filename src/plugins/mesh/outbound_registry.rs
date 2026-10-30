//! Mesh outbound registry plugin.
//!
//! Implements Istio `MeshConfig.outboundTrafficPolicy.mode: REGISTRY_ONLY`.
//! When the slice declares `RegistryOnly`, the gateway auto-injects this
//! global plugin with a pre-built set of known destinations from the slice
//! (services with their FQDN/namespace-qualified forms, local-namespace
//! bare-name forms, service entries with their declared hosts, and workload
//! addresses) plus their declared ports. Mesh-generated destinations that do
//! not declare ports include a `host:*` marker so HTTP Host headers with an
//! explicit port still match the known service. At request time the plugin
//! reads the destination Host header and rejects unknown destinations with 502
//! (configurable).
//!
//! The plugin is **not** registered when policy is `AllowAny` (default),
//! so permissive mesh deployments pay zero per-request cost. Operators can
//! still configure the plugin directly on non-mesh gateways, where it behaves
//! as a generic HTTP Host allowlist.
//!
//! ## Destination resolution
//!
//! - HTTP family only: this plugin relies on the `Host` header. Stream-family
//!   REGISTRY_ONLY egress is enforced by
//!   [`crate::modes::mesh::outbound_enforcement::MeshOutboundEnforcement`]
//!   at connect / first-datagram time on mesh outbound capture listener ports.
//! - `Host` header is split into `host` and optional `:port`. Bare registry
//!   hosts match requests with no explicit Host port. `host:port` entries
//!   match only that explicit port. `host:*` entries match any explicit Host
//!   port and are emitted by the mesh registry builder when a known service,
//!   ServiceEntry, or workload address has no declared ports.
//! - Mesh-internal service-cluster-local hostnames are matched as-is; the
//!   registry-build helper records the short, namespace-qualified, `.svc`,
//!   and FQDN forms.
//! - Wildcard hosts (`*.example.com`) match exactly one DNS label below the
//!   suffix by default (`wildcard_match: one_label`). That is the Ferrum mesh
//!   wildcard contract shared with Sidecar egress scoping, the mesh DNS proxy,
//!   and the stream-family REGISTRY_ONLY lane, so mesh auto-injection always
//!   uses it. Envoy virtual-host domains and Istio's host matcher treat
//!   `*.example.com` as an any-depth DNS suffix; operator-managed instances
//!   can opt into that with `wildcard_match: dns_suffix`. Lookups probe a
//!   precomputed suffix `HashSet` with the candidate after the request host's
//!   first label (and, in `dns_suffix` mode, each shorter candidate), so cost
//!   is bounded by the request host's label count and does not grow with
//!   unrelated wildcard count.
//! - An empty registry is valid and fails closed: every enforced request is rejected,
//!   but the plugin remains installed so REGISTRY_ONLY never silently falls
//!   back to ALLOW_ANY.
//! - Every instance skips requests stamped with the Inbound mesh direction:
//!   inbound sidecar/ambient traffic is never egress, even when its listener
//!   shares a numeric port with an outbound listener. Auto-injected instances
//!   also scope enforcement to the outbound capture listener ports.
//!   Operator-managed instances without `outbound_listen_ports` enforce on
//!   every other direction, including non-mesh listeners.
//!   Port `0` is rejected at construction; intentional global scope is only
//!   represented by an empty `outbound_listen_ports` vector.
//! - Reuse is advertised only for CONNECTs the registry did not decide.
//!   `allows_hbone_inner_reuse_for` shares the enforcement gate using the
//!   admitting listener's direction and port, recorded for every later sweep.
//!   A matching Outbound listener can terminate an authenticated CONNECT (for
//!   example NodeWaypoint capture); its scoped registry verdict is not reusable
//!   because the fence never re-runs the lookup. Unscoped instances always
//!   refuse reuse, including on Inbound listeners they skip.
//!
//! ## Wire compatibility
//!
//! Registry is shipped as a serde `Vec<String>` in plugin config. Order is
//! stable (alphabetical) to keep `MeshSlice::content_eq` deterministic
//! across reloads.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::modes::mesh::MeshTrafficDirection;
use crate::plugins::{
    HTTP_FAMILY_PROTOCOLS, HboneReuseContext, Plugin, PluginResult, ProxyProtocol, RequestContext,
    priority,
};
use crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter;
use crate::util::json_object::JsonObject;

thread_local! {
    /// Scratch buffer for normalised host lookups. Reused across requests on
    /// the same worker thread so the steady-state hot path performs zero
    /// allocations for the contains() check. Sized for typical
    /// `service.namespace.svc.cluster.local:65535` lengths (~80 bytes).
    static HOST_NORMALISE_BUF: RefCell<String> = RefCell::new(String::with_capacity(96));
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
// Unknown root keys fail closed at construction. A misspelled `registry`
// would otherwise build an empty registry, and a misspelled
// `outbound_listen_ports` would widen enforcement to every listener.
// serde's message names the offending field, which is the diagnostic the
// operator needs; `OutboundRegistry::new` wraps it with the plugin prefix.
#[serde(deny_unknown_fields)]
pub struct OutboundRegistryConfig {
    /// Operator-supplied list of known destinations. Each entry is a bare
    /// hostname (`reviews.default.svc.cluster.local`), a `host:port` pair,
    /// or a `host:*` any-explicit-port pair, optionally with a leading `*.`
    /// wildcard (see `wildcard_match`). IPv6 literals are canonicalized; numeric ports
    /// require brackets and must be 1..=65535. Hostnames use ASCII labels
    /// (punycode for IDNs). Empty entries are ignored; malformed entries fail
    /// construction. Matches are exact after ASCII-lowercase normalisation.
    #[serde(default)]
    pub registry: Vec<String>,
    /// Status code returned when a request's destination is not in the
    /// registry. Defaults to 502 (Bad Gateway). Operators may override
    /// to 404 when they prefer to mask unknown destinations.
    #[serde(default = "default_reject_status")]
    pub reject_status: u16,
    /// Optional frontend listener ports where the registry should be enforced.
    /// The listener-stamped Inbound mesh direction always skips enforcement,
    /// independently of this list. Mesh auto-injection sets this to the
    /// outbound capture listener ports. Empty enforces on every HTTP-family
    /// request in any other direction, including non-mesh listeners. Entries must be
    /// `>= 1`; port `0` is rejected (use `[]` for intentional global scope).
    #[serde(default)]
    pub outbound_listen_ports: Vec<u16>,
    /// Mesh namespace label used by the Prometheus decision counter.
    #[serde(default = "default_namespace_label")]
    pub namespace: String,
    /// How `*.suffix` registry entries match request hosts. Defaults to
    /// `one_label`, the mesh wildcard contract mesh auto-injection relies on.
    #[serde(default)]
    pub wildcard_match: WildcardMatch,
}

/// Matching semantics for `*.suffix` registry entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WildcardMatch {
    /// `*.example.com` matches exactly one DNS label below the suffix
    /// (`api.example.com`, not `a.b.example.com`). Shared with Sidecar egress
    /// scoping, the mesh DNS proxy, and the stream-family lane.
    #[default]
    OneLabel,
    /// `*.example.com` matches any DNS name below the suffix
    /// (`api.example.com` and `a.b.example.com`), like Envoy virtual-host
    /// domains and Istio's host matcher. The base domain never matches.
    DnsSuffix,
}

/// How an admitted request matched the registry; maps to the fixed metric
/// `host` bucket without re-deriving the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryMatch {
    Explicit,
    Wildcard,
}

impl RegistryMatch {
    #[inline]
    fn metric_bucket(self) -> &'static str {
        match self {
            Self::Explicit => EXPLICIT_HOST_BUCKET,
            Self::Wildcard => ADMITTED_WILDCARD_BUCKET,
        }
    }
}

fn default_reject_status() -> u16 {
    502
}

fn default_namespace_label() -> String {
    crate::config::types::default_namespace()
}

#[derive(Debug)]
pub struct OutboundRegistry {
    /// Bare-hostname entries from the operator-supplied registry, normalised
    /// to ASCII-lowercase at construction. A request matches these only when
    /// its Host header does not carry an explicit port.
    hosts: HashSet<String>,
    /// `host:port` entries from the operator-supplied registry. A request
    /// matches only when its Host header carries the same `host:port` pair.
    /// Stored separately from `hosts` so the request hot path can perform
    /// two zero-allocation `contains` lookups instead of building a single
    /// formatted key per request.
    host_ports: HashSet<String>,
    /// `host:*` entries from mesh-generated no-port resources. A request
    /// matches these only when its Host header carries an explicit port.
    any_port_hosts: HashSet<String>,
    /// Suffixes from wildcard host entries such as `*.example.com`, indexed
    /// for O(1) average one-label candidate-suffix lookup.
    wildcard_suffixes: HashSet<String>,
    /// Port-specific wildcard host suffixes from entries like
    /// `*.example.com:443`.
    wildcard_port_suffixes: HashMap<u16, HashSet<String>>,
    /// Any-explicit-port wildcard host suffixes from entries like
    /// `*.example.com:*`.
    wildcard_any_port_suffixes: HashSet<String>,
    wildcard_match: WildcardMatch,
    /// Most labels in any configured wildcard suffix. `dns_suffix` probing
    /// never tries a candidate with more labels than this.
    max_wildcard_suffix_labels: usize,
    outbound_listen_ports: Vec<u16>,
    reject_status: u16,
    namespace: String,
}

impl OutboundRegistry {
    /// Build an empty registry when a mesh-derived registry cannot be admitted.
    /// Keeping the gate installed preserves REGISTRY_ONLY enforcement.
    pub(crate) fn deny_all() -> Self {
        Self {
            hosts: HashSet::new(),
            host_ports: HashSet::new(),
            any_port_hosts: HashSet::new(),
            wildcard_suffixes: HashSet::new(),
            wildcard_port_suffixes: HashMap::new(),
            wildcard_any_port_suffixes: HashSet::new(),
            wildcard_match: WildcardMatch::OneLabel,
            max_wildcard_suffix_labels: 0,
            outbound_listen_ports: Vec::new(),
            reject_status: default_reject_status(),
            namespace: default_namespace_label(),
        }
    }

    pub fn new(config: &Value) -> Result<Self, String> {
        let parsed = super::diagnostics::from_value::<JsonObject<OutboundRegistryConfig>>(
            config.clone(),
            super::diagnostics::Schema::Registry,
        )
        .map_err(|e| format!("mesh_outbound_registry: {e}"))?
        .0;
        if !(400..=599).contains(&parsed.reject_status) {
            return Err(format!(
                "mesh_outbound_registry: `reject_status` must be 4xx/5xx (got \"{}\")",
                parsed.reject_status
            ));
        }
        if parsed.outbound_listen_ports.contains(&0) {
            return Err(
                "mesh_outbound_registry: `outbound_listen_ports` entries must be >= 1; \
                 use [] for intentional global/unscoped enforcement"
                    .to_string(),
            );
        }
        let mut hosts: HashSet<String> = HashSet::with_capacity(parsed.registry.len());
        let mut host_ports: HashSet<String> = HashSet::new();
        let mut any_port_hosts: HashSet<String> = HashSet::new();
        let mut wildcard_suffixes: HashSet<String> = HashSet::new();
        let mut wildcard_port_suffixes: HashMap<u16, HashSet<String>> = HashMap::new();
        let mut wildcard_any_port_suffixes: HashSet<String> = HashSet::new();
        let mut max_wildcard_suffix_labels = 0usize;
        let mut note_suffix = |suffix: &str| {
            max_wildcard_suffix_labels = max_wildcard_suffix_labels.max(suffix.split('.').count());
        };
        for (index, entry) in parsed.registry.iter().enumerate() {
            let normalised = normalise_registry_entry(entry)
                .map_err(|error| format!("mesh_outbound_registry: `registry[{index}]`: {error}"))?;
            let Some(normalised) = normalised else {
                continue;
            };
            if let Some(host) = split_registry_host_any_port(&normalised) {
                if let Some(suffix) = wildcard_suffix(host) {
                    note_suffix(suffix);
                    wildcard_any_port_suffixes.insert(suffix.to_string());
                } else {
                    any_port_hosts.insert(host.to_string());
                }
            } else if let Some((host, port)) = split_registry_host_port(&normalised) {
                if let Some(suffix) = wildcard_suffix(host) {
                    note_suffix(suffix);
                    wildcard_port_suffixes
                        .entry(port)
                        .or_default()
                        .insert(suffix.to_string());
                } else {
                    host_ports.insert(format!("{host}:{port}"));
                }
            } else if let Some(suffix) = wildcard_suffix(&normalised) {
                note_suffix(suffix);
                wildcard_suffixes.insert(suffix.to_string());
            } else {
                hosts.insert(normalised);
            }
        }
        let mut outbound_listen_ports = parsed.outbound_listen_ports;
        outbound_listen_ports.sort_unstable();
        outbound_listen_ports.dedup();
        Ok(Self {
            hosts,
            host_ports,
            any_port_hosts,
            wildcard_suffixes,
            wildcard_port_suffixes,
            wildcard_any_port_suffixes,
            wildcard_match: parsed.wildcard_match,
            max_wildcard_suffix_labels,
            outbound_listen_ports,
            reject_status: parsed.reject_status,
            namespace: parsed.namespace,
        })
    }

    #[allow(dead_code)]
    pub fn registry_size(&self) -> usize {
        self.hosts.len()
            + self.host_ports.len()
            + self.any_port_hosts.len()
            + self.wildcard_suffixes.len()
            + self.wildcard_any_port_suffixes.len()
            + self
                .wildcard_port_suffixes
                .values()
                .map(HashSet::len)
                .sum::<usize>()
    }

    /// Per-request hot-path lookup. Uses a thread-local scratch `String` so
    /// the steady-state cost is hash-set probes plus an in-place lowercase
    /// copy (no heap allocation after the first call on each worker thread).
    /// Wildcard admission probes the precomputed suffix sets with candidates
    /// derived from the request host — cost is bounded by the request host's
    /// label count and independent of unrelated wildcard count.
    pub(crate) fn contains(&self, host: &str, port: Option<u16>) -> bool {
        self.lookup(host, port).is_some()
    }

    /// Normalise `host` once and report how it matched, if at all.
    fn lookup(&self, host: &str, port: Option<u16>) -> Option<RegistryMatch> {
        HOST_NORMALISE_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            buf.clear();
            buf.reserve(host.len() + 6); // host + ':' + up to 5-digit port
            normalise_request_host_into(host, &mut buf);
            self.lookup_normalised(&mut buf, port)
        })
    }

    /// Explicit entries are probed before wildcards so an admit that both
    /// would satisfy is classified as explicit, matching the metric contract.
    fn lookup_normalised(&self, buf: &mut String, port: Option<u16>) -> Option<RegistryMatch> {
        if buf.is_empty() {
            return None;
        }
        let wildcards = WildcardProbe {
            mode: self.wildcard_match,
            max_suffix_labels: self.max_wildcard_suffix_labels,
        };
        let Some(port) = port else {
            if self.hosts.contains(buf.as_str()) {
                return Some(RegistryMatch::Explicit);
            }
            return wildcards
                .matches(buf.as_str(), &self.wildcard_suffixes)
                .then_some(RegistryMatch::Wildcard);
        };
        // Port 0 is never a destination port. Callers that split the
        // authority themselves (the outbound route-miss gate, stream lane)
        // must not let it satisfy `host:*` or `*.suffix:*` entries.
        if port == 0 {
            return None;
        }
        if self.any_port_hosts.contains(buf.as_str()) {
            return Some(RegistryMatch::Explicit);
        }
        // Empty `host_ports` is common (operators register bare hosts
        // most often). Skip the format!-equivalent write entirely.
        if !self.host_ports.is_empty() {
            // Reuse the same scratch buffer to append `:port` — no second
            // allocation. `write!` into `String` is infallible. Truncate back
            // so the wildcard probes below see the bare host.
            let host_len = buf.len();
            let _ = write!(buf, ":{port}");
            let matched = self.host_ports.contains(buf.as_str());
            buf.truncate(host_len);
            if matched {
                return Some(RegistryMatch::Explicit);
            }
        }
        let wildcard = wildcards.matches(buf.as_str(), &self.wildcard_any_port_suffixes)
            || self
                .wildcard_port_suffixes
                .get(&port)
                .is_some_and(|suffixes| wildcards.matches(buf.as_str(), suffixes));
        wildcard.then_some(RegistryMatch::Wildcard)
    }

    #[inline]
    fn should_enforce_for_request(&self, ctx: &RequestContext) -> bool {
        self.should_enforce_for_request_facts(ctx.mesh_direction, ctx.frontend_listen_port)
    }

    #[inline]
    fn should_enforce_for_request_facts(
        &self,
        mesh_direction: Option<MeshTrafficDirection>,
        frontend_listen_port: Option<u16>,
    ) -> bool {
        if mesh_direction == Some(MeshTrafficDirection::Inbound) {
            return false;
        }
        self.outbound_listen_ports.is_empty()
            || frontend_listen_port
                .is_some_and(|port| self.outbound_listen_ports.binary_search(&port).is_ok())
    }

    /// Record an admit under its precomputed fixed-cardinality bucket. The
    /// bucket is a constant, so nothing is normalised here.
    fn record_admit_decision(&self, matched: RegistryMatch) {
        crate::plugins::prometheus_metrics::global_registry()
            .record_mesh_outbound_registry_decision(
                &self.namespace,
                matched.metric_bucket(),
                "admit",
            );
    }

    /// Record a deny decision into the metrics registry under a fixed-
    /// cardinality `host` bucket. The Host header is attacker-controllable on
    /// the deny path; using the actual value as a Prometheus label exposes
    /// `/metrics` to memory-exhaustion / cardinality-DoS via curl loops with
    /// distinct synthetic Host values. The denied destination is reported by
    /// the rate-limited [`warn_http_registry_deny`] log line instead.
    fn record_deny_decision(&self) {
        crate::plugins::prometheus_metrics::global_registry()
            .record_mesh_outbound_registry_decision(&self.namespace, DENIED_HOST_BUCKET, "deny");
    }
}

/// Constant Prometheus `host` label value used for every deny decision; see
/// [`OutboundRegistry::record_deny_decision`].
pub(crate) const DENIED_HOST_BUCKET: &str = "<denied>";
/// Constant Prometheus `host` label for admits matched by a wildcard
/// registry entry (`*.example.com`). Keeps admit cardinality bounded
/// independently of registry size.
pub(crate) const ADMITTED_WILDCARD_BUCKET: &str = "<admit_wildcard>";
/// Constant Prometheus `host` label for admits matched by an exact registry
/// entry (bare host, `host:port`, or `host:*`). Keeps admit cardinality
/// bounded independently of registry size.
pub(crate) const EXPLICIT_HOST_BUCKET: &str = "<admit_explicit>";

/// Validate one destination against the registry entry grammar without
/// building a registry. Mesh-derived registries use this to drop entries the
/// plugin would refuse, so one malformed slice resource narrows the registry
/// identically on the HTTP and stream lanes instead of failing construction.
pub(crate) fn validate_registry_entry(entry: &str) -> Result<(), &'static str> {
    normalise_registry_entry(entry).map(|_| ())
}

fn normalise_registry_entry(entry: &str) -> Result<Option<String>, &'static str> {
    let entry = entry.trim().to_ascii_lowercase();
    if entry.is_empty() {
        return Ok(None);
    }
    if !entry.is_ascii() || entry.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("destination must be ASCII without internal whitespace; use punycode for IDNs");
    }
    if let Some(host) = split_registry_host_any_port(&entry) {
        return normalise_host_part(host).map(|host| Some(format!("{host}:*")));
    }
    if let Some((host, port)) = split_registry_host_port(&entry) {
        return normalise_host_part(host).map(|host| Some(format!("{host}:{port}")));
    }
    normalise_host_part(&entry).map(Some)
}

fn normalise_host_part(host: &str) -> Result<String, &'static str> {
    if host.starts_with('[') {
        if host.ends_with(']')
            && let Ok(IpAddr::V6(addr)) = host[1..host.len() - 1].parse::<IpAddr>()
        {
            return Ok(format!("[{addr}]"));
        }
        return Err("expected a bracketed IPv6 literal with an optional port in 1..=65535 or *");
    }
    if let Ok(IpAddr::V6(addr)) = host.parse::<IpAddr>() {
        return Ok(format!("[{addr}]"));
    }
    let host = host.trim_end_matches('.');
    let suffix = host.strip_prefix("*.").unwrap_or(host);
    if suffix.split('.').any(|label| {
        label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(
            "expected an ASCII hostname, IPv6 literal, or leading *. wildcard; \
             optional ports must be decimal 1..=65535 or *",
        );
    }
    Ok(host.to_string())
}

fn normalise_request_host_into(host: &str, buf: &mut String) {
    let host = host.trim();
    let host = if host.starts_with('[') {
        host
    } else {
        host.trim_end_matches('.')
    };
    if host.starts_with('[')
        && host.ends_with(']')
        && let Ok(IpAddr::V6(addr)) = host[1..host.len() - 1].parse::<IpAddr>()
    {
        let _ = write!(buf, "[{addr}]");
        return;
    }
    for byte in host.bytes() {
        buf.push(byte.to_ascii_lowercase() as char);
    }
}

fn wildcard_suffix(host: &str) -> Option<&str> {
    let suffix = host.strip_prefix("*.")?;
    if suffix.is_empty() || suffix.contains('*') {
        return None;
    }
    Some(suffix)
}

/// Wildcard candidate: the portion of `host` after its first DNS
/// label. Returns `None` when the host has fewer than two labels (so the base
/// domain never matches `*.suffix`) or the first label is empty.
#[inline]
fn one_label_wildcard_candidate(host: &str) -> Option<&str> {
    let (label, rest) = host.split_once('.')?;
    if label.is_empty() || rest.is_empty() {
        return None;
    }
    Some(rest)
}

/// Longest DNS textual name (RFC 1035 §2.3.4, without the trailing dot).
/// `dns_suffix` matching treats longer authorities as non-DNS names that never
/// match, which bounds probing work independently of HTTP header limits.
const MAX_DNS_NAME_BYTES: usize = 253;

/// Per-registry wildcard matching parameters.
#[derive(Clone, Copy)]
struct WildcardProbe {
    mode: WildcardMatch,
    max_suffix_labels: usize,
}

impl WildcardProbe {
    #[inline]
    fn matches(self, host: &str, suffixes: &HashSet<String>) -> bool {
        if suffixes.is_empty() {
            return false;
        }
        match self.mode {
            // One-label semantics: the candidate after the first label must
            // equal a configured suffix. Multi-label hosts produce a deeper
            // candidate (e.g. `a.b.example.com` → `b.example.com`) that misses
            // `example.com` without scanning the set. One probe per lookup.
            WildcardMatch::OneLabel => one_label_wildcard_candidate(host)
                .is_some_and(|candidate| suffixes.contains(candidate)),
            WildcardMatch::DnsSuffix => {
                dns_suffix_set_matches(host, suffixes, self.max_suffix_labels)
            }
        }
    }
}

/// DNS-suffix semantics: `host` matches when some proper suffix of whole
/// labels is configured and at least one non-empty label precedes it.
///
/// Work is bounded independently of attacker-supplied authority length: names
/// over [`MAX_DNS_NAME_BYTES`] or with an empty label never match, and probes
/// run right to left over at most `max_suffix_labels` candidates (the deepest
/// configured suffix), each at most `MAX_DNS_NAME_BYTES` long. The base domain
/// itself never matches `*.base`.
fn dns_suffix_set_matches(
    host: &str,
    suffixes: &HashSet<String>,
    max_suffix_labels: usize,
) -> bool {
    if host.len() > MAX_DNS_NAME_BYTES || host.split('.').any(str::is_empty) {
        return false;
    }
    let mut end = host.len();
    for _ in 0..max_suffix_labels {
        // No empty labels, so whenever a dot exists `host[..dot]` holds at
        // least one non-empty label in front of the candidate.
        let Some(dot) = host[..end].rfind('.') else {
            return false;
        };
        if suffixes.contains(&host[dot + 1..]) {
            return true;
        }
        end = dot;
    }
    false
}

fn split_registry_host_port(entry: &str) -> Option<(&str, u16)> {
    let (host, port_str) = if entry.starts_with('[') {
        let end = entry.rfind("]:")?;
        (&entry[..end + 1], &entry[end + 2..])
    } else {
        let (host, port_str) = entry.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port_str)
    };
    if !port_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    (port != 0).then_some((host, port))
}

fn split_registry_host_any_port(entry: &str) -> Option<&str> {
    let host = entry.strip_suffix(":*")?;
    if entry.starts_with('[') {
        return host.ends_with(']').then_some(host);
    }
    if host.contains(':') && !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        return None;
    }
    Some(host)
}

/// Classify a normalised registry entry as a `host:port` pair (port is a
/// 1-5 digit u16 suffix after a final `:`) or a bare hostname.
#[cfg(test)]
fn is_host_port_entry(entry: &str) -> bool {
    split_registry_host_port(entry).is_some()
}

#[cfg(test)]
fn is_host_any_port_entry(entry: &str) -> bool {
    split_registry_host_any_port(entry).is_some()
}

#[async_trait]
impl Plugin for OutboundRegistry {
    fn name(&self) -> &str {
        "mesh_outbound_registry"
    }

    fn priority(&self) -> u16 {
        priority::MESH_OUTBOUND_REGISTRY
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::ON_REQUEST_RECEIVED
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        // Host-header gating only applies to HTTP-family traffic. Raw
        // TCP/UDP stream proxies have no Host header; mesh-level egress
        // scoping for those protocols is enforced at connect / first-datagram
        // time by MeshOutboundEnforcement, not by this plugin.
        HTTP_FAMILY_PROTOCOLS
    }

    /// Reuse is advertised only for CONNECTs the registry did not decide.
    /// A matching outbound (or non-mesh) listener can terminate CONNECT too;
    /// port scoping alone does not make its registry verdict reusable. Share
    /// the request hook's gate so every sweep judges the recorded admission
    /// facts against the current scope without re-running the registry lookup.
    /// Unscoped instances, including `deny_all`, remain fail-closed.
    fn allows_hbone_inner_reuse_for(&self, admission: &HboneReuseContext) -> bool {
        !self.outbound_listen_ports.is_empty()
            && !self.should_enforce_for_request_facts(
                admission.mesh_direction,
                admission.frontend_listen_port,
            )
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if !self.should_enforce_for_request(ctx) {
            return PluginResult::Continue;
        }
        // The shared HTTP/2, HTTP/3, and gRPC paths backfill `:authority`
        // into `host` before plugin execution, so one lookup covers all
        // HTTP-family frontends.
        let Some(host_header) = ctx.headers.get("host") else {
            // Use the fixed-cardinality bucket — see `record_deny_decision`.
            self.record_deny_decision();
            warn_http_registry_deny(
                None,
                None,
                ctx.frontend_listen_port,
                &ctx.client_ip,
                DENY_SOURCE_PLUGIN,
            );
            return reject(self.reject_status, "host header required");
        };
        let (host, port) = split_host_header(host_header);
        if let Some(matched) = self.lookup(host, port) {
            self.record_admit_decision(matched);
        } else {
            // Deny path uses a constant bucket label so the Prometheus
            // `host` label remains bounded (the request Host header is
            // attacker-controlled); the destination goes to the
            // rate-limited log line instead.
            self.record_deny_decision();
            warn_http_registry_deny(
                Some(host),
                port,
                ctx.frontend_listen_port,
                &ctx.client_ip,
                DENY_SOURCE_PLUGIN,
            );
            return reject(
                self.reject_status,
                "destination not in mesh registry (REGISTRY_ONLY policy)",
            );
        }
        PluginResult::Continue
    }
}

/// Split a request authority into host and optional port. The port uses the
/// registry grammar: ASCII decimal digits only (leading zeros allowed) in
/// 1..=65535. Anything else (`:0`, `:+443`, `:http`) leaves the whole value as
/// the host so it falls into the normal deny path.
pub(crate) fn split_host_header(value: &str) -> (&str, Option<u16>) {
    // IPv6-bracketed literals: `[::1]:8080` — split on `]:`.
    if value.starts_with('[')
        && let Some(end) = value.rfind("]:")
    {
        if let Some(port) = parse_authority_port(&value[end + 2..]) {
            return (&value[..end + 1], Some(port));
        }
        return (value, None);
    }
    // Unbracketed IPv6 Host values are malformed per RFC 7230/9110. Treat the
    // whole value as the host so it falls into the normal reject path instead
    // of misparsing a trailing hextet as a decimal port.
    if value.matches(':').count() > 1 {
        return (value, None);
    }
    if let Some((host, port_str)) = value.rsplit_once(':')
        && let Some(port) = parse_authority_port(port_str)
    {
        return (host, Some(port));
    }
    (value, None)
}

/// Digits-only, non-zero `u16` port, mirroring `split_registry_host_port`.
#[inline]
fn parse_authority_port(port_str: &str) -> Option<u16> {
    if port_str.is_empty() || !port_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

/// `source` label on [`warn_http_registry_deny`] for plugin-hook denials.
pub(crate) const DENY_SOURCE_PLUGIN: &str = "plugin";
/// `source` label on [`warn_http_registry_deny`] for outbound-capture route
/// misses denied before the plugin chain.
pub(crate) const DENY_SOURCE_ROUTE_MISS: &str = "route_miss";

/// Longest denied host echoed into the log line. A DNS name is at most 253
/// bytes; anything longer is truncated rather than logged whole.
const DENY_LOG_HOST_MAX_BYTES: usize = 256;

/// Process-wide limiter for HTTP-lane REGISTRY_ONLY denial logs: the first
/// denial logs immediately, then at most one line per second carrying the
/// number suppressed since the previous line. Process-wide (not per plugin
/// instance) so reloads and multiple instances cannot multiply the rate.
static HTTP_DENY_WARN: AtomicLogRateLimiter = AtomicLogRateLimiter::new();
static HTTP_DENY_WARN_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Emit the rate-limited structured warning for an HTTP-lane REGISTRY_ONLY
/// denial, naming the denied destination like the stream lane does. The
/// metric keeps its fixed `<denied>` bucket; this log line is the
/// attribution channel operators use to find missing registry entries.
pub(crate) fn warn_http_registry_deny(
    host: Option<&str>,
    port: Option<u16>,
    listen_port: Option<u16>,
    client_ip: &str,
    source: &'static str,
) {
    let now_ms = u64::try_from(HTTP_DENY_WARN_EPOCH.elapsed().as_millis()).unwrap_or(u64::MAX);
    warn_http_registry_deny_with(
        &HTTP_DENY_WARN,
        now_ms,
        host,
        port,
        listen_port,
        client_ip,
        source,
    );
}

/// [`warn_http_registry_deny`] against a caller-owned limiter and clock, so
/// focused tests do not share the process-wide window with other denials.
pub(crate) fn warn_http_registry_deny_with(
    limiter: &AtomicLogRateLimiter,
    now_ms: u64,
    host: Option<&str>,
    port: Option<u16>,
    listen_port: Option<u16>,
    client_ip: &str,
    source: &'static str,
) {
    let Some(suppressed) = limiter.on_event(now_ms) else {
        return;
    };
    let host = match host.filter(|host| !host.is_empty()) {
        None => "<missing>".to_string(),
        Some(host) => diagnostic_log_host(host),
    };
    tracing::warn!(
        host = ?host,
        port = ?port,
        listen_port = ?listen_port,
        client = %client_ip,
        source,
        suppressed_since_last = suppressed,
        "Mesh REGISTRY_ONLY: rejecting HTTP egress to unadmitted destination"
    );
}

/// Clear the HTTP denial-log limiter. Test-only (via `_test_support`).
pub(crate) fn reset_http_deny_warn_for_test() {
    HTTP_DENY_WARN.reset_for_test();
}

/// Render a denied request host for the log line. Only authority-shaped
/// values are echoed: hostname characters (ASCII alphanumerics, `-`, `.`, `_`)
/// or a bracketed IPv6 literal (hex digits, `:`, `.`), truncated to
/// [`DENY_LOG_HOST_MAX_BYTES`]. Anything else (userinfo, ports that failed the
/// port grammar, percent-escapes, quotes, control bytes) is withheld through
/// the startup diagnostic sanitizer, so a credential-bearing value never
/// reaches the log.
fn diagnostic_log_host(host: &str) -> String {
    let hostname = host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
    let bracketed_ip = host.len() > 2
        && host.starts_with('[')
        && host.ends_with(']')
        && host[1..host.len() - 1]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'));
    if hostname || bracketed_ip {
        // ASCII-only, so every byte offset is a char boundary.
        host[..host.len().min(DENY_LOG_HOST_MAX_BYTES)].to_string()
    } else {
        crate::startup::sanitize_startup_cause(format!("{:?}", host.to_string()), &[])
    }
}

fn reject(status: u16, message: &str) -> PluginResult {
    PluginResult::Reject {
        status_code: status,
        body: format!("{{\"error\":\"{message}\"}}"),
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry_plugin(entries: &[&str]) -> OutboundRegistry {
        registry_plugin_with_ports(entries, &[])
    }

    fn registry_plugin_with_ports(
        entries: &[&str],
        outbound_listen_ports: &[u16],
    ) -> OutboundRegistry {
        let config = json!({
            "registry": entries,
            "outbound_listen_ports": outbound_listen_ports,
        });
        OutboundRegistry::new(&config).expect("valid registry")
    }

    #[test]
    fn empty_registry_matches_nothing() {
        let plugin = registry_plugin(&[]);
        assert_eq!(plugin.registry_size(), 0);
        assert!(!plugin.contains("reviews.svc", None));
        assert!(!plugin.contains("reviews.svc", Some(8080)));
    }

    #[test]
    fn rejects_invalid_status() {
        let err = OutboundRegistry::new(&json!({"registry": ["a.svc"], "reject_status": 200}))
            .unwrap_err();
        assert!(err.contains("reject_status"), "got: {err}");
    }

    #[test]
    fn rejects_zero_outbound_listen_port() {
        let err = OutboundRegistry::new(&json!({
            "registry": ["reviews.svc"],
            "outbound_listen_ports": [0],
        }))
        .unwrap_err();
        assert!(
            err.contains("`outbound_listen_ports`") && err.contains("must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mixed_zero_outbound_listen_ports() {
        let err = OutboundRegistry::new(&json!({
            "registry": ["reviews.svc"],
            "outbound_listen_ports": [0, 15001],
        }))
        .unwrap_err();
        assert!(err.contains("outbound_listen_ports"), "got: {err}");
    }

    #[test]
    fn empty_outbound_listen_ports_remain_global() {
        let plugin = registry_plugin_with_ports(&["reviews.svc"], &[]);
        assert!(plugin.outbound_listen_ports.is_empty());
    }

    #[test]
    fn scoped_outbound_listen_ports_are_retained() {
        let plugin = registry_plugin_with_ports(&["reviews.svc"], &[15001]);
        assert_eq!(plugin.outbound_listen_ports, vec![15001]);
    }

    #[test]
    fn host_only_match() {
        let plugin = registry_plugin(&["reviews.default.svc.cluster.local"]);
        assert!(plugin.contains("reviews.default.svc.cluster.local", None));
        assert!(!plugin.contains("reviews.default.svc.cluster.local", Some(8080)));
        assert!(!plugin.contains("ratings.default.svc.cluster.local", None));
    }

    #[test]
    fn host_port_match_is_specific() {
        let plugin = registry_plugin(&["reviews.svc:8080"]);
        assert!(plugin.contains("reviews.svc", Some(8080)));
        // Bare host not present; falls through.
        assert!(!plugin.contains("reviews.svc", None));
        assert!(!plugin.contains("reviews.svc", Some(9090)));
    }

    #[test]
    fn host_any_port_match_is_explicit_port_only() {
        let plugin = registry_plugin(&["reviews.svc:*"]);
        assert!(plugin.contains("reviews.svc", Some(80)));
        assert!(plugin.contains("reviews.svc", Some(8080)));
        assert!(!plugin.contains("reviews.svc", None));
        assert!(!plugin.contains("ratings.svc", Some(8080)));
    }

    #[test]
    fn ipv6_host_any_port_match_uses_bracketed_request_host() {
        let plugin = registry_plugin(&["2001:db8::1:*"]);
        assert!(plugin.contains("[2001:db8::1]", Some(8080)));
        assert!(!plugin.contains("2001:db8::1", Some(8080)));
        assert!(!plugin.contains("[2001:db8::1]", None));
    }

    #[test]
    fn case_insensitive_match() {
        let plugin = registry_plugin(&["Reviews.Default.Svc.Cluster.Local"]);
        assert!(plugin.contains("reviews.default.svc.cluster.local", None));
        assert!(plugin.contains("REVIEWS.DEFAULT.SVC.CLUSTER.LOCAL", None));
    }

    #[test]
    fn trailing_dot_match() {
        let plugin = registry_plugin(&["Reviews.Default.Svc.Cluster.Local."]);
        assert!(plugin.contains("reviews.default.svc.cluster.local", None));
        assert!(!plugin.contains("reviews.default.svc.cluster.local.", Some(8080)));
    }

    #[test]
    fn wildcard_host_matches_one_label() {
        let plugin = registry_plugin(&["*.example.com"]);
        assert!(plugin.contains("api.example.com", None));
        assert!(!plugin.contains("API.EXAMPLE.COM.", Some(443)));
        assert!(!plugin.contains("example.com", None));
        assert!(!plugin.contains("a.b.example.com", None));
    }

    #[test]
    fn wildcard_host_port_is_specific() {
        let plugin = registry_plugin(&["*.example.com:443"]);
        assert!(plugin.contains("api.example.com", Some(443)));
        assert!(!plugin.contains("api.example.com", None));
        assert!(!plugin.contains("api.example.com", Some(80)));
        assert!(!plugin.contains("a.b.example.com", Some(443)));
    }

    #[test]
    fn wildcard_host_any_port_matches_one_label_with_explicit_port() {
        let plugin = registry_plugin(&["*.example.com:*"]);
        assert!(plugin.contains("api.example.com", Some(443)));
        assert!(plugin.contains("api.example.com", Some(8080)));
        assert!(!plugin.contains("api.example.com", None));
        assert!(!plugin.contains("example.com", Some(443)));
        assert!(!plugin.contains("a.b.example.com", Some(443)));
    }

    #[test]
    fn indexed_wildcard_lookup_independent_of_unrelated_suffix_count() {
        // Large registry of unrelated tenant wildcards must not prevent an
        // O(1)-style candidate-suffix hit for the matching entry, including
        // port-specific and any-port buckets.
        let mut entries: Vec<String> = (0..10_000)
            .map(|i| format!("*.tenant{i:05}.example"))
            .collect();
        entries.push("*.match.example:443".to_string());
        entries.push("*.anyport.example:*".to_string());
        let plugin = OutboundRegistry::new(&json!({ "registry": entries })).expect("valid");
        assert!(plugin.contains("x.tenant09999.example", None));
        assert!(plugin.contains("api.match.example", Some(443)));
        assert!(!plugin.contains("api.match.example", Some(80)));
        assert!(plugin.contains("svc.anyport.example", Some(8443)));
        assert!(!plugin.contains("a.b.tenant00000.example", None));
        assert!(!plugin.contains("missing.example", None));
    }

    #[test]
    fn one_label_wildcard_candidate_extracts_suffix_after_first_label() {
        assert_eq!(
            one_label_wildcard_candidate("api.example.com"),
            Some("example.com")
        );
        assert_eq!(
            one_label_wildcard_candidate("a.b.example.com"),
            Some("b.example.com")
        );
        assert_eq!(one_label_wildcard_candidate("example.com"), Some("com"));
        assert_eq!(one_label_wildcard_candidate("bare"), None);
    }

    #[test]
    fn unbracketed_ipv6_registry_entry_is_canonicalized() {
        let plugin = registry_plugin(&["2001:db8::1"]);
        assert!(plugin.contains("[2001:db8::1]", None));
        assert!(plugin.contains("[2001:0DB8::1]", None));
        assert!(!plugin.contains("[2001:db8::1]", Some(8080)));
        assert!(!is_host_port_entry("2001:db8::1"));
    }

    #[test]
    fn host_header_split_strips_port() {
        let (host, port) = split_host_header("reviews.svc:9090");
        assert_eq!(host, "reviews.svc");
        assert_eq!(port, Some(9090));
    }

    #[test]
    fn host_header_split_no_port() {
        let (host, port) = split_host_header("reviews.svc");
        assert_eq!(host, "reviews.svc");
        assert_eq!(port, None);
    }

    #[test]
    fn host_header_ipv6_split() {
        let (host, port) = split_host_header("[::1]:8080");
        assert_eq!(host, "[::1]");
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn host_header_bracketed_ipv6_invalid_port_is_not_split() {
        let (host, port) = split_host_header("[::1]:http");
        assert_eq!(host, "[::1]:http");
        assert_eq!(port, None);
    }

    #[test]
    fn host_header_unbracketed_ipv6_is_not_split_as_port() {
        let (host, port) = split_host_header("2001:db8::1");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, None);
    }

    #[tokio::test]
    async fn unbracketed_ipv6_host_header_rejects_instead_of_matching() {
        let plugin = registry_plugin(&["2001:db8::1"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), "2001:db8::1".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_unknown_destination() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let headers = HashMap::from([("host".to_string(), "evil.external.com:443".to_string())]);
        ctx.headers = headers;
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn scoped_plugin_skips_non_outbound_listener() {
        let plugin = registry_plugin_with_ports(&["reviews.svc"], &[15001]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.frontend_listen_port = Some(15006);
        ctx.headers = HashMap::from([("host".to_string(), "unknown.example.com".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn scoped_plugin_enforces_outbound_listener() {
        let plugin = registry_plugin_with_ports(&["reviews.svc"], &[15001]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.frontend_listen_port = Some(15001);
        ctx.headers = HashMap::from([("host".to_string(), "unknown.example.com".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn unscoped_plugin_enforces_without_frontend_port() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), "unknown.example.com".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn passes_known_destination() {
        let plugin = registry_plugin(&["reviews.svc:9090"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let headers = HashMap::from([("host".to_string(), "reviews.svc:9090".to_string())]);
        ctx.headers = headers;
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn records_admit_and_deny_decision_metrics() {
        let plugin = OutboundRegistry::new(&json!({
            "namespace": "gap2n-metrics",
            "registry": ["reviews.svc:9090"],
        }))
        .expect("valid registry");

        let mut admitted = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        admitted.headers = HashMap::from([("host".to_string(), "reviews.svc:9090".to_string())]);
        assert!(matches!(
            plugin.on_request_received(&mut admitted).await,
            PluginResult::Continue
        ));

        let mut denied = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        denied.headers = HashMap::from([("host".to_string(), "unknown.svc:9090".to_string())]);
        assert!(matches!(
            plugin.on_request_received(&mut denied).await,
            PluginResult::Reject { .. }
        ));

        let rendered = crate::plugins::prometheus_metrics::global_registry().render_uncached();
        assert!(rendered.contains(
            "ferrum_mesh_outbound_registry_decisions_total{mesh_namespace=\"gap2n-metrics\",host=\"<admit_explicit>\",decision=\"admit\""
        ));
        // Deny decisions always bucket under the fixed `<denied>` label to
        // keep Prometheus cardinality bounded against attacker-supplied Host
        // headers. The actual rejected host never appears as a label value.
        assert!(rendered.contains(
            "ferrum_mesh_outbound_registry_decisions_total{mesh_namespace=\"gap2n-metrics\",host=\"<denied>\",decision=\"deny\""
        ));
        assert!(!rendered.contains("host=\"unknown.svc\",decision=\"deny\""));
    }

    #[tokio::test]
    async fn buckets_wildcard_admit_decisions() {
        let plugin = OutboundRegistry::new(&json!({
            "namespace": "gap2n-wildcard-metrics",
            "registry": ["*.example.com"],
        }))
        .expect("valid wildcard registry");

        for i in 0..8 {
            let mut admitted = RequestContext::new(
                "127.0.0.1".to_string(),
                "GET".to_string(),
                "/api".to_string(),
            );
            admitted.headers = HashMap::from([("host".to_string(), format!("a{i}.example.com"))]);
            assert!(matches!(
                plugin.on_request_received(&mut admitted).await,
                PluginResult::Continue
            ));
        }

        let rendered = crate::plugins::prometheus_metrics::global_registry().render_uncached();
        assert!(rendered.contains(
            "ferrum_mesh_outbound_registry_decisions_total{mesh_namespace=\"gap2n-wildcard-metrics\",host=\"<admit_wildcard>\",decision=\"admit\""
        ));
        assert!(!rendered.contains("host=\"a0.example.com\",decision=\"admit\""));
    }

    #[tokio::test]
    async fn rejects_missing_host_header() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[test]
    fn classify_host_port_vs_bare_host() {
        assert!(is_host_port_entry("reviews.svc:8080"));
        assert!(is_host_port_entry("api.example.com:443"));
        assert!(!is_host_port_entry("reviews.svc"));
        assert!(!is_host_port_entry("api.example.com"));
        // Trailing colon without digits → not a host:port pair.
        assert!(!is_host_port_entry("reviews.svc:"));
        // Non-numeric port → not a host:port pair.
        assert!(!is_host_port_entry("reviews.svc:http"));
        // u16 boundary: 65535 OK, 65536 must be rejected.
        assert!(is_host_port_entry("svc:65535"));
        assert!(!is_host_port_entry("svc:65536"));
        // Bracketed IPv6 literals.
        assert!(is_host_port_entry("[::1]:8080"));
        assert!(!is_host_port_entry("[::1]"));
        assert!(!is_host_port_entry("2001:db8::1"));
        // Any-port markers are distinct from numeric host:port entries.
        assert!(is_host_any_port_entry("reviews.svc:*"));
        assert!(is_host_any_port_entry("[::1]:*"));
        assert!(is_host_any_port_entry("2001:db8::1:*"));
        assert!(!is_host_port_entry("reviews.svc:*"));
        assert!(!is_host_any_port_entry("not:ipv6:*"));
    }

    #[test]
    fn normalizes_unbracketed_ipv6_any_port_registry_entry() {
        assert_eq!(
            normalise_registry_entry("2001:db8::1:*"),
            Ok(Some("[2001:db8::1]:*".to_string()))
        );
    }

    #[test]
    fn registry_with_only_whitespace_entries_matches_nothing() {
        // After trim+lowercase normalisation every entry is empty — the
        // plugin stays installed and rejects every destination.
        let plugin = OutboundRegistry::new(&json!({"registry": ["", "  ", "\t"]}))
            .expect("empty effective registry is valid");
        assert_eq!(plugin.registry_size(), 0);
        assert!(!plugin.contains("reviews.svc", Some(8080)));
    }

    #[test]
    fn supported_protocols_excludes_raw_streams() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let protocols = plugin.supported_protocols();
        // Host-header gating is HTTP-family only.
        assert!(protocols.contains(&ProxyProtocol::Http));
        assert!(protocols.contains(&ProxyProtocol::Grpc));
        assert!(protocols.contains(&ProxyProtocol::WebSocket));
        assert!(!protocols.contains(&ProxyProtocol::Tcp));
        assert!(!protocols.contains(&ProxyProtocol::Udp));
    }

    #[test]
    fn registry_size_reflects_dual_buckets() {
        // Mixed bare-host + host:port entries are placed into separate
        // buckets internally; `registry_size()` reports the sum.
        let plugin = registry_plugin(&[
            "reviews.svc",
            "reviews.svc:8080",
            "reviews.svc:*",
            "api:443",
            "*.example.com",
            "*.example.com:443",
            "*.internal.example:*",
        ]);
        assert_eq!(plugin.registry_size(), 7);
    }

    #[test]
    fn lookup_avoids_alloc_on_already_lowercase_host() {
        // Smoke test the hot-path lookup with both buckets populated. The
        // important invariant is that bare-host registration matches any
        // no-port Host header while host:port registration only matches the
        // exact explicit port.
        let plugin = registry_plugin(&["reviews.svc", "tightly-bound:8080", "loose:*"]);
        // Bare-host entries only match Host headers without an explicit port.
        assert!(plugin.contains("reviews.svc", None));
        assert!(!plugin.contains("reviews.svc", Some(80)));
        assert!(!plugin.contains("reviews.svc", Some(65535)));
        // host:port is exact.
        assert!(plugin.contains("tightly-bound", Some(8080)));
        assert!(!plugin.contains("tightly-bound", Some(8081)));
        assert!(!plugin.contains("tightly-bound", None));
        // host:* is explicit-port-only.
        assert!(plugin.contains("loose", Some(1)));
        assert!(plugin.contains("loose", Some(65535)));
        assert!(!plugin.contains("loose", None));
    }

    #[tokio::test]
    async fn empty_host_header_rejected() {
        // RFC 9110 §7.2 requires Host be non-empty; defensive coverage in
        // case an upstream pre-processor leaves a blank `host: ` line.
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), String::new())]);
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn empty_registry_rejects_all_requests() {
        let plugin = registry_plugin(&[]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), "reviews.svc".to_string())]);
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }
}
