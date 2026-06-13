//! Transparent DNS proxy for mesh ServiceEntry / MeshService resolution.
//!
//! Intercepts DNS queries (typically redirected from port 53 via iptables/eBPF)
//! and resolves mesh-internal hostnames from a pre-built resolution table.
//! Non-mesh queries are forwarded transparently to the upstream system resolver.
//!
//! The resolution table is rebuilt atomically (via `ArcSwap`) whenever the
//! `MeshSlice` is updated, so there are no locks on the query hot path.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::modes::mesh::slice::MeshSlice;

// ── DNS wire-format constants ────────────────────────────────────────────

const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_UDP_PACKET_SIZE: usize = 4096;
const DNS_UDP_SAFE_PACKET_SIZE: usize = 512;
const DNS_MAX_TCP_PACKET_SIZE: usize = u16::MAX as usize;
const DNS_MAX_CACHEABLE_RESPONSE_SIZE: usize = DNS_MAX_UDP_PACKET_SIZE;
const DNS_UPSTREAM_TIMEOUT_SECS: u64 = 5;
const DNS_UPSTREAM_ID_SPACE: usize = u16::MAX as usize + 1;
const DNS_TCP_QUERY_READ_TIMEOUT_SECS: u64 = 5;
const DNS_TCP_WRITE_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES: usize = 4096;
pub const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

// QTYPE values
const QTYPE_A: u16 = 1;
#[cfg(test)]
const QTYPE_TXT: u16 = 16;
const QTYPE_OPT: u16 = 41;
const QTYPE_AAAA: u16 = 28;

// QCLASS
const QCLASS_IN: u16 = 1;

// Response flags
const FLAGS_QR: u16 = 0x8000; // Response
const FLAGS_AA: u16 = 0x0400; // Authoritative Answer
const FLAGS_TC: u16 = 0x0200; // Truncated
const FLAGS_RD: u16 = 0x0100; // Recursion Desired
const FLAGS_RA: u16 = 0x0080; // Recursion Available

const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;

// ── DNS query representation ─────────────────────────────────────────────

/// Parsed DNS question extracted from an incoming query packet.
#[derive(Clone)]
struct DnsQuery {
    /// Transaction ID (echoed back in responses).
    id: u16,
    /// Original flags from the query (we copy RD etc.).
    flags: u16,
    /// Normalized hostname: lowercase, trailing dot stripped.
    name: Arc<str>,
    /// Query type (1 = A, 28 = AAAA).
    qtype: u16,
    /// Query class (1 = IN).
    qclass: u16,
    /// EDNS(0) OPT pseudo-record from the query, echoed when it fits.
    opt_record: Option<Arc<[u8]>>,
    /// Client-advertised UDP response size from EDNS(0), clamped at response time.
    udp_payload_size: usize,
}

struct DnsRecordSet {
    ips: Vec<IpAddr>,
    authoritative: bool,
}

struct WildcardRecordSet {
    suffix: String,
    records: DnsRecordSet,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct DnsResponseCacheKey {
    name: Arc<str>,
    qtype: u16,
    qclass: u16,
    rd: bool,
    cd: bool,
    ad: bool,
    ttl: u32,
    max_response_size: usize,
    opt_record: Option<Arc<[u8]>>,
}

const FLAGS_CD: u16 = 0x0010;
const FLAGS_AD: u16 = 0x0020;

impl DnsResponseCacheKey {
    fn from_query(query: &DnsQuery, ttl: u32, max_response_size: usize) -> Self {
        Self {
            name: Arc::clone(&query.name),
            qtype: query.qtype,
            qclass: query.qclass,
            rd: query.flags & FLAGS_RD != 0,
            cd: query.flags & FLAGS_CD != 0,
            ad: query.flags & FLAGS_AD != 0,
            ttl,
            max_response_size,
            opt_record: query.opt_record.clone(),
        }
    }
}

pub struct ResolvedDnsRecords<'a> {
    ips: &'a [IpAddr],
    authoritative: bool,
}

impl<'a> ResolvedDnsRecords<'a> {
    #[cfg(test)]
    fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ips.len()
    }

    #[cfg(test)]
    fn iter(&self) -> std::slice::Iter<'a, IpAddr> {
        self.ips.iter()
    }
}

// ── Resolution table ─────────────────────────────────────────────────────

/// FQDN-to-IP resolution table built from mesh config.
///
/// Rebuilt atomically from `MeshSlice` on config updates. The `ArcSwap`
/// wrapper ensures the query hot path never blocks on a rebuild.
pub struct DnsResolutionTable {
    /// Exact hostname matches (lowercase, trailing dot stripped).
    exact: HashMap<String, DnsRecordSet>,
    /// Wildcard matches bucketed by final suffix label for bounded lookup.
    wildcard_suffixes: HashMap<String, Vec<WildcardRecordSet>>,
    /// Per-slice cache of serialized mesh DNS response templates.
    response_cache: DashMap<DnsResponseCacheKey, Vec<u8>>,
    response_cache_entries: AtomicUsize,
    response_cache_max_entries: usize,
}

impl DnsResolutionTable {
    #[cfg(test)]
    fn empty() -> Self {
        Self::empty_with_response_cache_max_entries(DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES)
    }

    fn empty_with_response_cache_max_entries(response_cache_max_entries: usize) -> Self {
        Self {
            exact: HashMap::new(),
            wildcard_suffixes: HashMap::new(),
            response_cache: DashMap::new(),
            response_cache_entries: AtomicUsize::new(0),
            response_cache_max_entries: response_cache_max_entries.max(1),
        }
    }

    /// Build a resolution table from a mesh slice.
    ///
    /// Indexes `ServiceEntry.hosts` mapped to their endpoint IPs, plus
    /// `MeshService` short names (`{name}.{namespace}.svc.cluster.local`)
    /// mapped to workload addresses resolved through the slice.
    #[allow(dead_code)]
    pub fn from_mesh_slice(slice: &MeshSlice) -> Self {
        Self::from_mesh_slice_with_cluster_domain(slice, DEFAULT_CLUSTER_DOMAIN)
    }

    pub fn from_mesh_slice_with_cluster_domain(slice: &MeshSlice, cluster_domain: &str) -> Self {
        Self::from_mesh_slice_with_cluster_domain_and_response_cache_max_entries(
            slice,
            cluster_domain,
            DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
        )
    }

    pub fn from_mesh_slice_with_cluster_domain_and_response_cache_max_entries(
        slice: &MeshSlice,
        cluster_domain: &str,
        response_cache_max_entries: usize,
    ) -> Self {
        let cluster_domain = normalize_dns_name(cluster_domain);
        let mut exact: HashMap<String, DnsRecordSet> = HashMap::new();
        let mut wildcard_suffixes: HashMap<String, Vec<WildcardRecordSet>> = HashMap::new();

        // Index workload addresses by SPIFFE ID and namespace, keeping the
        // workload's service identity alongside its IPs. Multiple Kubernetes
        // services commonly share a service-account SPIFFE ID; when a matching
        // service identity exists we prefer it so auto-discovered refs do not
        // bleed endpoints across services. The fallback below preserves older
        // explicit MeshService refs whose workload.service_name differs.
        type WorkloadDnsKey<'a> = (&'a str, &'a str);
        type WorkloadDnsEntry<'a> = (&'a str, Vec<IpAddr>);
        let mut workload_ips: HashMap<WorkloadDnsKey<'_>, Vec<WorkloadDnsEntry<'_>>> =
            HashMap::new();
        for wl in &slice.workloads {
            let ips: Vec<IpAddr> = wl
                .addresses
                .iter()
                .filter_map(|addr| addr.parse::<IpAddr>().ok())
                .filter(is_routable_mesh_dns_ip)
                .collect();
            if !ips.is_empty() {
                let entries = workload_ips
                    .entry((wl.spiffe_id.as_str(), wl.namespace.as_str()))
                    .or_default();
                if let Some((_, existing_ips)) = entries
                    .iter_mut()
                    .find(|(service_name, _)| *service_name == wl.service_name.as_str())
                {
                    for ip in ips {
                        if !existing_ips.contains(&ip) {
                            existing_ips.push(ip);
                        }
                    }
                } else {
                    entries.push((wl.service_name.as_str(), ips));
                }
            }
        }

        // From ServiceEntries: hosts -> endpoint IPs
        for entry in &slice.service_entries {
            let ips: Vec<IpAddr> = entry
                .endpoints
                .iter()
                .filter_map(|ep| ep.address.parse::<IpAddr>().ok())
                .filter(is_routable_mesh_dns_ip)
                .collect();
            if ips.is_empty() {
                continue;
            }

            for host in &entry.hosts {
                let normalized = normalize_dns_name(host);
                if normalized.is_empty() {
                    continue;
                }
                if let Some(suffix) = normalized.strip_prefix("*.") {
                    if !suffix.is_empty() {
                        let authoritative = is_authoritative_mesh_dns_name(suffix, &cluster_domain);
                        extend_wildcard_record_set(
                            &mut wildcard_suffixes,
                            suffix.to_string(),
                            ips.iter().copied(),
                            authoritative,
                        );
                    }
                } else {
                    let authoritative =
                        is_authoritative_mesh_dns_name(&normalized, &cluster_domain);
                    extend_record_set(&mut exact, normalized, ips.iter().copied(), authoritative);
                }
            }
        }

        // From MeshServices: construct FQDN from name + namespace and resolve
        // workload addresses through SPIFFE ID references.
        for svc in &slice.services {
            let mut svc_ips: Vec<IpAddr> = Vec::new();
            let mut seen_workload_refs = HashSet::new();
            for wl_ref in &svc.workloads {
                if !seen_workload_refs.insert(wl_ref.spiffe_id.as_str()) {
                    continue;
                }
                if let Some(entries) =
                    workload_ips.get(&(wl_ref.spiffe_id.as_str(), svc.namespace.as_str()))
                {
                    let mut found_matching_service = false;
                    for (service_name, ips) in entries {
                        if *service_name == svc.name.as_str() {
                            found_matching_service = true;
                            svc_ips.extend(ips.iter());
                        }
                    }
                    if !found_matching_service {
                        if entries.len() == 1 {
                            let (_, ips) = &entries[0];
                            svc_ips.extend(ips.iter());
                        } else {
                            warn!(
                                service = %svc.name,
                                namespace = %svc.namespace,
                                spiffe_id = %wl_ref.spiffe_id,
                                service_identities = entries.len(),
                                "Skipping ambiguous mesh DNS workload fallback"
                            );
                        }
                    }
                }
            }
            if svc_ips.is_empty() {
                continue;
            }

            // Register the Kubernetes-style FQDN:
            // {name}.{namespace}.svc.{cluster_domain}
            let fqdn = normalize_dns_name(&format!(
                "{}.{}.svc.{}",
                svc.name, svc.namespace, cluster_domain
            ));
            extend_record_set(&mut exact, fqdn, svc_ips.iter().copied(), true);

            // Also register short name: {name}.{namespace}
            let short = normalize_dns_name(&format!("{}.{}", svc.name, svc.namespace));
            extend_record_set(&mut exact, short, svc_ips.iter().copied(), true);
        }

        // Deduplicate IPs within each entry
        for records in exact.values_mut() {
            records.ips.sort();
            records.ips.dedup();
        }
        for bucket in wildcard_suffixes.values_mut() {
            bucket.sort_by_key(|entry| Reverse(entry.suffix.len()));
            for entry in bucket {
                entry.records.ips.sort();
                entry.records.ips.dedup();
            }
        }

        Self {
            exact,
            wildcard_suffixes,
            response_cache: DashMap::new(),
            response_cache_entries: AtomicUsize::new(0),
            response_cache_max_entries: response_cache_max_entries.max(1),
        }
    }

    /// Resolve a hostname against the table. Returns `None` for non-mesh names.
    #[allow(dead_code)]
    pub fn resolve(&self, name: &str) -> Option<ResolvedDnsRecords<'_>> {
        let normalized = normalize_dns_name(name);
        self.resolve_normalized(&normalized)
    }

    fn resolve_normalized(&self, normalized: &str) -> Option<ResolvedDnsRecords<'_>> {
        // Exact match first (O(1))
        if let Some(records) = self.exact.get(normalized) {
            return Some(ResolvedDnsRecords {
                ips: records.ips.as_slice(),
                authoritative: records.authoritative,
            });
        }

        let last_label = normalized.rsplit('.').next()?;
        let bucket = self.wildcard_suffixes.get(last_label)?;
        for wildcard in bucket {
            if single_label_wildcard_matches(normalized, &wildcard.suffix) {
                return Some(ResolvedDnsRecords {
                    ips: wildcard.records.ips.as_slice(),
                    authoritative: wildcard.records.authoritative,
                });
            }
        }

        None
    }

    fn cached_mesh_response<F>(
        &self,
        key: DnsResponseCacheKey,
        query_id: u16,
        build_response: F,
    ) -> Vec<u8>
    where
        F: FnOnce() -> Vec<u8>,
    {
        if let Some(template) = self.response_cache.get(&key) {
            return response_from_cached_template(template.value(), query_id);
        }

        let mut template = build_response();
        clear_response_transaction_id(&mut template);
        let response = response_from_cached_template(&template, query_id);
        if self.reserve_response_cache_slot() && self.response_cache.insert(key, template).is_some()
        {
            self.response_cache_entries.fetch_sub(1, Ordering::Relaxed);
        }
        response
    }

    fn reserve_response_cache_slot(&self) -> bool {
        let mut current = self.response_cache_entries.load(Ordering::Relaxed);
        loop {
            if current >= self.response_cache_max_entries {
                return false;
            }

            match self.response_cache_entries.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    fn response_cache_len(&self) -> usize {
        self.response_cache.len()
    }

    /// Number of exact entries in the table.
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    /// Number of wildcard entries in the table.
    pub fn wildcard_count(&self) -> usize {
        self.wildcard_suffixes.values().map(Vec::len).sum()
    }
}

fn extend_record_set(
    exact: &mut HashMap<String, DnsRecordSet>,
    name: String,
    ips: impl IntoIterator<Item = IpAddr>,
    authoritative: bool,
) {
    let records = exact.entry(name).or_insert_with(|| DnsRecordSet {
        ips: Vec::new(),
        authoritative,
    });
    records.authoritative |= authoritative;
    records.ips.extend(ips);
}

fn extend_wildcard_record_set(
    wildcard_suffixes: &mut HashMap<String, Vec<WildcardRecordSet>>,
    suffix: String,
    ips: impl IntoIterator<Item = IpAddr>,
    authoritative: bool,
) {
    let last_label = suffix.rsplit('.').next().unwrap_or(&suffix).to_string();
    let bucket = wildcard_suffixes.entry(last_label).or_default();
    let records = bucket
        .iter_mut()
        .find(|entry| entry.suffix == suffix)
        .map(|entry| &mut entry.records);
    match records {
        Some(records) => {
            records.authoritative |= authoritative;
            records.ips.extend(ips);
        }
        None => bucket.push(WildcardRecordSet {
            suffix,
            records: DnsRecordSet {
                ips: ips.into_iter().collect(),
                authoritative,
            },
        }),
    }
}

fn single_label_wildcard_matches(name: &str, suffix: &str) -> bool {
    if name.len() <= suffix.len() + 1 {
        return false;
    }
    if !name.ends_with(suffix) {
        return false;
    }
    let prefix_len = name.len() - suffix.len() - 1;
    name.as_bytes()[prefix_len] == b'.' && !name[..prefix_len].contains('.')
}

fn is_authoritative_mesh_dns_name(name: &str, cluster_domain: &str) -> bool {
    let svc_suffix = format!(".svc.{cluster_domain}");
    name.ends_with(&svc_suffix) || name == format!("svc.{cluster_domain}")
}

fn is_routable_mesh_dns_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            !addr.is_unspecified()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_broadcast()
                && !addr.is_multicast()
        }
        IpAddr::V6(addr) => {
            !addr.is_unspecified()
                && !addr.is_loopback()
                && !addr.is_unicast_link_local()
                && !addr.is_multicast()
        }
    }
}

/// Normalize a DNS name: lowercase + strip trailing dot.
fn normalize_dns_name(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

// ── DNS proxy server ─────────────────────────────────────────────────────

/// Transparent mesh DNS proxy.
///
/// Listens on a UDP port and resolves mesh-internal names from a lock-free
/// resolution table. Non-mesh queries are forwarded to the upstream resolver.
pub struct MeshDnsProxy {
    listen_addr: SocketAddr,
    resolution_table: Arc<ArcSwap<DnsResolutionTable>>,
    upstream_resolver: SocketAddr,
    ttl_seconds: u32,
    max_concurrent_queries: usize,
    response_cache_max_entries: usize,
    cluster_domain: String,
}

pub struct MeshDnsBoundSockets {
    udp_socket: Arc<UdpSocket>,
    tcp_listener: TcpListener,
}

impl MeshDnsProxy {
    /// Create a new DNS proxy (does not bind yet; call `run()` to start).
    pub fn new(
        listen_addr: SocketAddr,
        upstream_resolver: SocketAddr,
        ttl_seconds: u32,
        max_concurrent_queries: usize,
        response_cache_max_entries: usize,
        cluster_domain: String,
    ) -> Self {
        let response_cache_max_entries = response_cache_max_entries.max(1);
        Self {
            listen_addr,
            resolution_table: Arc::new(ArcSwap::new(Arc::new(
                DnsResolutionTable::empty_with_response_cache_max_entries(
                    response_cache_max_entries,
                ),
            ))),
            upstream_resolver,
            ttl_seconds,
            max_concurrent_queries: max_concurrent_queries.max(1),
            response_cache_max_entries,
            cluster_domain: normalize_dns_name(&cluster_domain),
        }
    }

    /// Bind UDP and TCP DNS listeners before spawning the server loop.
    pub async fn bind(&self) -> std::io::Result<MeshDnsBoundSockets> {
        let udp_socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        let tcp_listener = TcpListener::bind(self.listen_addr).await?;
        Ok(MeshDnsBoundSockets {
            udp_socket,
            tcp_listener,
        })
    }

    /// Rebuild the resolution table from a new mesh slice.
    pub fn update_from_slice(&self, slice: &MeshSlice) {
        let new_table =
            DnsResolutionTable::from_mesh_slice_with_cluster_domain_and_response_cache_max_entries(
                slice,
                &self.cluster_domain,
                self.response_cache_max_entries,
            );
        let exact_count = new_table.exact_count();
        let wildcard_count = new_table.wildcard_count();
        self.resolution_table.store(Arc::new(new_table));
        debug!(
            exact_entries = exact_count,
            wildcard_entries = wildcard_count,
            "DNS resolution table rebuilt from mesh slice"
        );
    }

    /// Run the DNS proxy server loop with listeners that were bound during startup.
    pub async fn run_bound(
        self: Arc<Self>,
        sockets: MeshDnsBoundSockets,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let socket = sockets.udp_socket;
        let tcp_listener = sockets.tcp_listener;

        let (forward_tx, forward_rx) = mpsc::channel(self.max_concurrent_queries.saturating_mul(2));
        let forward_shutdown = shutdown_rx.clone();
        let forward_handle = tokio::spawn(run_udp_forwarder(
            forward_rx,
            socket.clone(),
            self.upstream_resolver,
            self.max_concurrent_queries,
            forward_shutdown,
        ));

        info!(
            addr = %self.listen_addr,
            upstream = %self.upstream_resolver,
            max_concurrent_queries = self.max_concurrent_queries,
            "Mesh DNS proxy listening on UDP and TCP"
        );

        let query_semaphore = Arc::new(Semaphore::new(self.max_concurrent_queries));
        let tcp_session_semaphore = Arc::new(Semaphore::new(self.max_concurrent_queries));
        let mut buf = vec![0u8; DNS_MAX_UDP_PACKET_SIZE];
        // Bounds the TCP accept() busy-loop under fd exhaustion (the UDP recv
        // branch shares one datagram socket and is not an fd-accept loop).
        let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
        let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let Ok(permit) = query_semaphore.clone().try_acquire_owned() else {
                                if let Some(response) = build_dns_error_response_from_packet(
                                    &buf[..len],
                                    RCODE_SERVFAIL,
                                    DNS_UDP_SAFE_PACKET_SIZE,
                                ) {
                                    let _ = socket.send_to(&response, src).await;
                                }
                                warn!(src = %src, "DNS proxy query concurrency limit reached");
                                continue;
                            };
                            let packet = buf[..len].to_vec();
                            let socket = socket.clone();
                            let table = self.resolution_table.clone();
                            let ttl = self.ttl_seconds;
                            let forward_tx = forward_tx.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                handle_dns_query_udp(packet, src, &socket, &table, &forward_tx, ttl).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "DNS proxy recv error");
                        }
                    }
                }
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, src)) => {
                            accept_backoff.on_success();
                            let Some(session_permit) = try_acquire_dns_tcp_session_permit(
                                &tcp_session_semaphore,
                                src,
                            ) else {
                                drop(stream);
                                continue;
                            };
                            let table = self.resolution_table.clone();
                            let upstream = self.upstream_resolver;
                            let ttl = self.ttl_seconds;
                            let query_semaphore = query_semaphore.clone();
                            tokio::spawn(async move {
                                let _session_permit = session_permit;
                                handle_dns_tcp_connection(
                                    stream,
                                    src,
                                    &table,
                                    upstream,
                                    ttl,
                                    query_semaphore,
                                )
                                .await;
                            });
                        }
                        Err(e) => {
                            // Bound the log rate independently of the backoff
                            // (an abort/reset flood is not backed off): emit the
                            // first error then one summary per second with the
                            // suppressed count.
                            if let Some(suppressed) =
                                accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                            {
                                warn!(error = %e, suppressed, "DNS proxy TCP accept error");
                            }
                            if let Some(delay) = accept_backoff.on_error(e.kind()) {
                                tokio::time::sleep(delay).await;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Mesh DNS proxy shutting down");
                        break;
                    }
                }
            }
        }

        drop(forward_tx);
        let _ = forward_handle.await;
    }
}

fn try_acquire_dns_tcp_session_permit(
    semaphore: &Arc<Semaphore>,
    src: SocketAddr,
) -> Option<OwnedSemaphorePermit> {
    match semaphore.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            warn!(client = %src, "DNS proxy TCP session concurrency limit reached");
            None
        }
    }
}

// ── Query handler ────────────────────────────────────────────────────────

struct UdpForwardRequest {
    packet: Vec<u8>,
    src: SocketAddr,
    query: DnsQuery,
}

enum DnsDecision {
    Respond(Vec<u8>),
    Forward(DnsQuery),
    Drop,
}

async fn handle_dns_query_udp(
    packet: Vec<u8>,
    src: SocketAddr,
    socket: &UdpSocket,
    table: &ArcSwap<DnsResolutionTable>,
    forward_tx: &mpsc::Sender<UdpForwardRequest>,
    ttl: u32,
) {
    match evaluate_dns_query(&packet, table, ttl, DnsResponseSizing::Udp) {
        DnsDecision::Respond(response) => {
            let _ = socket.send_to(&response, src).await;
        }
        DnsDecision::Forward(query) => {
            // Size the queue-full error response from the already-parsed query
            // (no second parse), matching the clamp evaluate_dns_query applied.
            let max_response_size = query
                .udp_payload_size
                .clamp(DNS_UDP_SAFE_PACKET_SIZE, DNS_MAX_UDP_PACKET_SIZE);
            let request = UdpForwardRequest { packet, src, query };
            if let Err(err) = forward_tx.try_send(request) {
                let request = err.into_inner();
                let response = build_dns_error_response(
                    &request.query,
                    RCODE_SERVFAIL,
                    false,
                    max_response_size,
                );
                let _ = socket.send_to(&response, src).await;
                warn!(client = %src, "DNS upstream forward queue is full");
            }
        }
        DnsDecision::Drop => {}
    }
}

async fn handle_dns_tcp_connection(
    mut stream: TcpStream,
    src: SocketAddr,
    table: &ArcSwap<DnsResolutionTable>,
    upstream: SocketAddr,
    ttl: u32,
    semaphore: Arc<Semaphore>,
) {
    loop {
        let len = match read_dns_tcp_length_with_timeout(
            &mut stream,
            Duration::from_secs(DNS_TCP_QUERY_READ_TIMEOUT_SECS),
        )
        .await
        {
            Ok(len) => len,
            Err(DnsTcpQueryReadError::Io(e)) => {
                trace!(client = %src, error = %e, "DNS TCP connection closed");
                return;
            }
            Err(DnsTcpQueryReadError::Timeout) => {
                warn!(client = %src, "Timed out reading DNS TCP query length");
                return;
            }
        };
        if len == 0 {
            continue;
        }

        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            warn!(client = %src, payload_bytes = len, "DNS proxy TCP query concurrency limit reached");
            return;
        };

        let mut packet = vec![0u8; len];
        match read_dns_tcp_payload_with_timeout(
            &mut stream,
            &mut packet,
            Duration::from_secs(DNS_TCP_QUERY_READ_TIMEOUT_SECS),
        )
        .await
        {
            Ok(()) => {}
            Err(DnsTcpQueryReadError::Io(e)) => {
                debug!(client = %src, error = %e, "Failed to read DNS TCP query");
                return;
            }
            Err(DnsTcpQueryReadError::Timeout) => {
                warn!(client = %src, payload_bytes = len, "Timed out reading DNS TCP query payload");
                return;
            }
        }

        let response = match evaluate_dns_query(&packet, table, ttl, DnsResponseSizing::Tcp) {
            DnsDecision::Respond(response) => response,
            DnsDecision::Forward(_) => match forward_to_upstream_tcp(&packet, upstream).await {
                Some(response) => response,
                None => build_dns_error_response_from_packet(
                    &packet,
                    RCODE_SERVFAIL,
                    DNS_MAX_TCP_PACKET_SIZE,
                )
                .unwrap_or_default(),
            },
            DnsDecision::Drop => continue,
        };
        drop(permit);

        if !write_dns_tcp_response(&mut stream, &response).await {
            return;
        }
    }
}

#[derive(Debug)]
enum DnsTcpQueryReadError {
    Io(std::io::Error),
    Timeout,
}

async fn read_dns_tcp_length_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<usize, DnsTcpQueryReadError> {
    let mut len_buf = [0u8; 2];
    match tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await {
        Ok(Ok(_)) => Ok(u16::from_be_bytes(len_buf) as usize),
        Ok(Err(e)) => Err(DnsTcpQueryReadError::Io(e)),
        Err(_) => Err(DnsTcpQueryReadError::Timeout),
    }
}

async fn read_dns_tcp_payload_with_timeout(
    stream: &mut TcpStream,
    packet: &mut [u8],
    timeout: Duration,
) -> Result<(), DnsTcpQueryReadError> {
    match tokio::time::timeout(timeout, stream.read_exact(packet)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(DnsTcpQueryReadError::Io(e)),
        Err(_) => Err(DnsTcpQueryReadError::Timeout),
    }
}

async fn write_dns_tcp_response(stream: &mut TcpStream, response: &[u8]) -> bool {
    if response.len() > u16::MAX as usize {
        warn!(
            bytes_received = response.len(),
            "DNS TCP response too large"
        );
        return false;
    }
    let write_timeout = Duration::from_secs(DNS_TCP_WRITE_TIMEOUT_SECS);
    match tokio::time::timeout(
        write_timeout,
        stream.write_all(&(response.len() as u16).to_be_bytes()),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return false,
        Err(_) => {
            warn!("Timed out writing DNS TCP response length");
            return false;
        }
    }
    match tokio::time::timeout(write_timeout, stream.write_all(response)).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => false,
        Err(_) => {
            warn!(
                response_bytes = response.len(),
                "Timed out writing DNS TCP response payload"
            );
            false
        }
    }
}

fn evaluate_dns_query(
    packet: &[u8],
    table: &ArcSwap<DnsResolutionTable>,
    ttl: u32,
    sizing: DnsResponseSizing,
) -> DnsDecision {
    // Parse the packet exactly once. The response-size cap is derived from the
    // parsed query (UDP) or a transport constant (TCP) — the UDP path no longer
    // re-parses the packet just to read `udp_payload_size`.
    let query = match parse_dns_query(packet) {
        Some(q) => q,
        None => {
            let max_response_size = sizing.parse_failure_cap();
            return build_dns_error_response_from_packet(packet, RCODE_FORMERR, max_response_size)
                .map(DnsDecision::Respond)
                .unwrap_or(DnsDecision::Drop);
        }
    };
    let max_response_size = sizing.response_cap(&query);

    // Only handle IN-class queries locally.
    if query.qclass != QCLASS_IN {
        return DnsDecision::Forward(query);
    }

    let table = table.load();
    let cacheable_response = max_response_size <= DNS_MAX_CACHEABLE_RESPONSE_SIZE;
    if query.qtype != QTYPE_A && query.qtype != QTYPE_AAAA {
        return match table.resolve_normalized(&query.name) {
            Some(records) => {
                if cacheable_response {
                    let cache_key = DnsResponseCacheKey::from_query(&query, ttl, max_response_size);
                    DnsDecision::Respond(table.cached_mesh_response(cache_key, query.id, || {
                        build_dns_empty_response(&query, records.authoritative, max_response_size)
                    }))
                } else {
                    DnsDecision::Respond(build_dns_empty_response(
                        &query,
                        records.authoritative,
                        max_response_size,
                    ))
                }
            }
            None => DnsDecision::Forward(query),
        };
    }

    match table.resolve_normalized(&query.name) {
        Some(records) => {
            // Filter by query type: A gets IPv4, AAAA gets IPv6
            let filtered: Vec<&IpAddr> = records
                .ips
                .iter()
                .filter(|ip| {
                    matches!(
                        (query.qtype, **ip),
                        (QTYPE_A, IpAddr::V4(_)) | (QTYPE_AAAA, IpAddr::V6(_))
                    )
                })
                .collect();

            if filtered.is_empty() {
                // Have the name but no matching record type -- return empty (not NXDOMAIN)
                let response = if cacheable_response {
                    let cache_key = DnsResponseCacheKey::from_query(&query, ttl, max_response_size);
                    table.cached_mesh_response(cache_key, query.id, || {
                        build_dns_empty_response(&query, records.authoritative, max_response_size)
                    })
                } else {
                    build_dns_empty_response(&query, records.authoritative, max_response_size)
                };
                DnsDecision::Respond(response)
            } else {
                let response = if cacheable_response {
                    let cache_key = DnsResponseCacheKey::from_query(&query, ttl, max_response_size);
                    table.cached_mesh_response(cache_key, query.id, || {
                        build_dns_response(
                            &query,
                            &filtered,
                            ttl,
                            records.authoritative,
                            max_response_size,
                        )
                    })
                } else {
                    build_dns_response(
                        &query,
                        &filtered,
                        ttl,
                        records.authoritative,
                        max_response_size,
                    )
                };
                trace!(
                    name = %query.name,
                    qtype = query.qtype,
                    answers = filtered.len(),
                    authoritative = records.authoritative,
                    "DNS query resolved from mesh table"
                );
                DnsDecision::Respond(response)
            }
        }
        None => {
            // Not a mesh name -- forward to upstream
            DnsDecision::Forward(query)
        }
    }
}

async fn forward_to_upstream_tcp(packet: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        TcpStream::connect(upstream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream, "Failed to connect to upstream DNS over TCP");
            return None;
        }
        Err(_) => {
            warn!(upstream = %upstream, "Timed out connecting to upstream DNS over TCP");
            return None;
        }
    };

    if stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .is_err()
    {
        warn!(upstream = %upstream, "Failed to write upstream DNS TCP query length");
        return None;
    }
    if stream.write_all(packet).await.is_err() {
        warn!(upstream = %upstream, "Failed to write upstream DNS TCP query");
        return None;
    }

    let mut len_buf = [0u8; 2];
    match tokio::time::timeout(
        Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        stream.read_exact(&mut len_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream, "Upstream DNS TCP length read failed");
            return None;
        }
        Err(_) => {
            warn!(upstream = %upstream, "Upstream DNS TCP query timed out");
            return None;
        }
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    match tokio::time::timeout(
        Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        stream.read_exact(&mut response),
    )
    .await
    {
        Ok(Ok(_)) => {
            if response.len() < 2 || response[..2] != packet[..2] {
                warn!(upstream = %upstream, "Ignoring upstream DNS TCP response with mismatched transaction ID");
                None
            } else {
                Some(response)
            }
        }
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream, "Upstream DNS TCP response read failed");
            None
        }
        Err(_) => {
            warn!(upstream = %upstream, "Upstream DNS TCP response timed out");
            None
        }
    }
}

struct PendingForward {
    client: SocketAddr,
    original_id: u16,
    query: DnsQuery,
    expires_at: Instant,
}

async fn run_udp_forwarder(
    mut requests: mpsc::Receiver<UdpForwardRequest>,
    client_socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    max_outstanding: usize,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let bind_addr = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let upstream_socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, upstream = %upstream, "Failed to bind shared upstream DNS socket");
            while let Some(request) = requests.recv().await {
                send_udp_servfail(&client_socket, &request.query, request.src).await;
            }
            return;
        }
    };
    if let Err(e) = upstream_socket.connect(upstream).await {
        error!(error = %e, upstream = %upstream, "Failed to connect shared upstream DNS socket");
        while let Some(request) = requests.recv().await {
            send_udp_servfail(&client_socket, &request.query, request.src).await;
        }
        return;
    }

    let mut pending: HashMap<u16, PendingForward> = HashMap::new();
    let mut next_id = 0u16;
    let mut response_buf = vec![0u8; DNS_MAX_UDP_PACKET_SIZE];
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            maybe_request = requests.recv() => {
                let Some(request) = maybe_request else {
                    break;
                };
                if pending.len() >= max_outstanding {
                    if upstream_id_space_exhausted(pending.len()) {
                        record_upstream_id_exhaustion();
                        warn!("DNS upstream transaction ID space exhausted");
                    } else {
                        warn!(client = %request.src, outstanding = pending.len(), "DNS upstream forward limit reached");
                    }
                    send_udp_servfail(&client_socket, &request.query, request.src).await;
                    continue;
                }

                let Some(upstream_id) = allocate_upstream_id(&mut next_id, &pending) else {
                    record_upstream_id_exhaustion();
                    warn!("DNS upstream transaction ID space exhausted");
                    send_udp_servfail(&client_socket, &request.query, request.src).await;
                    continue;
                };

                let mut upstream_packet = request.packet;
                upstream_packet[..2].copy_from_slice(&upstream_id.to_be_bytes());
                match upstream_socket.send(&upstream_packet).await {
                    Ok(_) => {
                        pending.insert(upstream_id, PendingForward {
                            client: request.src,
                            original_id: request.query.id,
                            query: request.query,
                            expires_at: Instant::now() + Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, upstream = %upstream, "Failed to send DNS query to upstream");
                        send_udp_servfail(&client_socket, &request.query, request.src).await;
                    }
                }
            }
            result = upstream_socket.recv(&mut response_buf), if !pending.is_empty() => {
                match result {
                    Ok(len) => {
                        if len < 2 {
                            warn!("Ignoring short upstream DNS response");
                            continue;
                        }
                        let upstream_id = u16::from_be_bytes([response_buf[0], response_buf[1]]);
                        let Some(pending_request) = pending.remove(&upstream_id) else {
                            warn!(upstream_id, "Ignoring upstream DNS response with unknown transaction ID");
                            continue;
                        };
                        if !upstream_response_matches_pending_query(
                            &response_buf[..len],
                            &pending_request.query,
                        ) {
                            warn!(
                                client = %pending_request.client,
                                upstream_id,
                                qname = %pending_request.query.name,
                                qtype = pending_request.query.qtype,
                                qclass = pending_request.query.qclass,
                                "Ignoring upstream DNS response with mismatched question"
                            );
                            send_udp_servfail(
                                &client_socket,
                                &pending_request.query,
                                pending_request.client,
                            )
                            .await;
                            continue;
                        }
                        let mut response = response_buf[..len].to_vec();
                        response[..2].copy_from_slice(&pending_request.original_id.to_be_bytes());
                        let _ = client_socket.send_to(&response, pending_request.client).await;
                        trace!(client = %pending_request.client, bytes = response.len(), "Forwarded DNS response from upstream");
                    }
                    Err(e) => {
                        warn!(error = %e, upstream = %upstream, "Upstream DNS recv error");
                    }
                }
            }
            _ = cleanup.tick() => {
                let now = Instant::now();
                let expired: Vec<u16> = pending
                    .iter()
                    .filter_map(|(id, request)| (request.expires_at <= now).then_some(*id))
                    .collect();
                for id in expired {
                    if let Some(request) = pending.remove(&id) {
                        warn!(client = %request.client, upstream = %upstream, "Upstream DNS query timed out");
                        send_udp_servfail(&client_socket, &request.query, request.client).await;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

fn allocate_upstream_id(next_id: &mut u16, pending: &HashMap<u16, PendingForward>) -> Option<u16> {
    for _ in 0..=u16::MAX {
        let candidate = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn upstream_id_space_exhausted(pending_len: usize) -> bool {
    pending_len >= DNS_UPSTREAM_ID_SPACE
}

fn record_upstream_id_exhaustion() {
    crate::plugins::prometheus_metrics::global_registry().record_mesh_dns_upstream_id_exhaustion();
}

fn upstream_response_matches_pending_query(response: &[u8], pending: &DnsQuery) -> bool {
    if response.len() < DNS_HEADER_SIZE {
        return false;
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & FLAGS_QR == 0 {
        return false;
    }

    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount != 1 {
        return false;
    }

    let Some((name, offset)) = parse_dns_name(response, DNS_HEADER_SIZE) else {
        return false;
    };
    if offset + 4 > response.len() {
        return false;
    }

    let qtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
    let qclass = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);

    *normalize_dns_name(&name) == *pending.name
        && qtype == pending.qtype
        && qclass == pending.qclass
}

async fn send_udp_servfail(socket: &UdpSocket, query: &DnsQuery, client: SocketAddr) {
    let response = build_dns_error_response(query, RCODE_SERVFAIL, false, DNS_UDP_SAFE_PACKET_SIZE);
    let _ = socket.send_to(&response, client).await;
}

/// How `evaluate_dns_query` caps the response size for the calling transport.
/// Passing the transport (rather than a precomputed size) lets the evaluator
/// parse the inbound packet exactly once: UDP derives the cap from the query's
/// EDNS `udp_payload_size` (clamped), TCP uses the 64 KiB framed maximum.
#[derive(Clone, Copy)]
enum DnsResponseSizing {
    Udp,
    Tcp,
}

impl DnsResponseSizing {
    /// Response-size cap for a successfully parsed query.
    fn response_cap(self, query: &DnsQuery) -> usize {
        match self {
            DnsResponseSizing::Udp => query
                .udp_payload_size
                .clamp(DNS_UDP_SAFE_PACKET_SIZE, DNS_MAX_UDP_PACKET_SIZE),
            DnsResponseSizing::Tcp => DNS_MAX_TCP_PACKET_SIZE,
        }
    }

    /// Response-size cap when the packet failed to parse (no EDNS info present).
    fn parse_failure_cap(self) -> usize {
        match self {
            DnsResponseSizing::Udp => DNS_UDP_SAFE_PACKET_SIZE,
            DnsResponseSizing::Tcp => DNS_MAX_TCP_PACKET_SIZE,
        }
    }
}

// ── DNS wire format parsing ──────────────────────────────────────────────

/// Parse an incoming DNS query packet. Returns `None` if the packet is
/// malformed or not a standard query.
fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);

    // Must be a standard query (QR=0, OPCODE=0)
    if flags & 0xF800 != 0 {
        return None;
    }

    if ancount != 0 || nscount != 0 {
        return None;
    }

    // Must have exactly one question
    if qdcount != 1 {
        return None;
    }

    // Parse QNAME (label-encoded)
    let (name, offset) = parse_dns_name(packet, DNS_HEADER_SIZE)?;
    if name.is_empty() {
        return None;
    }

    // Need at least 4 more bytes for QTYPE + QCLASS
    if offset + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let question_end = offset + 4;

    let normalized = normalize_dns_name(&name);
    if normalized.is_empty() {
        return None;
    }

    let mut additional_offset = question_end;
    let mut opt_record = None;
    let mut udp_payload_size = DNS_UDP_SAFE_PACKET_SIZE;
    for _ in 0..arcount {
        let record_start = additional_offset;
        let (_, record_name_end) = parse_dns_name(packet, additional_offset)?;
        if record_name_end + 10 > packet.len() {
            return None;
        }
        let record_type =
            u16::from_be_bytes([packet[record_name_end], packet[record_name_end + 1]]);
        let record_class =
            u16::from_be_bytes([packet[record_name_end + 2], packet[record_name_end + 3]]);
        let rdlen =
            u16::from_be_bytes([packet[record_name_end + 8], packet[record_name_end + 9]]) as usize;
        let record_end = record_name_end + 10 + rdlen;
        if record_end > packet.len() {
            return None;
        }
        if record_type == QTYPE_OPT {
            if opt_record.is_some() {
                return None;
            }
            udp_payload_size = usize::from(record_class);
            opt_record = Some(packet[record_start..record_end].to_vec());
        }
        additional_offset = record_end;
    }
    if additional_offset != packet.len() {
        return None;
    }

    Some(DnsQuery {
        id,
        flags,
        name: Arc::from(normalized.as_str()),
        qtype,
        qclass,
        opt_record: opt_record.map(|v| Arc::from(v.into_boxed_slice())),
        udp_payload_size,
    })
}

/// Parse a DNS label-encoded name starting at `offset`. Returns the
/// decoded name and the byte position immediately after it.
///
/// Supports pointer compression (0xC0xx) for completeness but the
/// question section of standard queries does not use pointers.
fn parse_dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::with_capacity(64);
    let mut offset = start;
    let mut return_offset = None;
    // Compression-pointer loop guard. Between pointer jumps the offset strictly
    // advances (labels move it forward), so only a backward compression pointer
    // can stall progress — bounding the number of jumps therefore guarantees
    // termination, together with the 255-byte total-name cap below. This
    // replaces a per-call `vec![false; packet.len()]` visited bitmap that
    // allocated proportionally to packet length on EVERY name parse (a query
    // can carry hundreds of additional-record names), a needless hot-path
    // allocation amplifier. 16 jumps is far more than any legitimate query
    // name needs (a QNAME never uses compression; AR names rarely do).
    let mut pointer_jumps = 0u32;
    const MAX_POINTER_JUMPS: u32 = 16;

    loop {
        if offset >= packet.len() {
            return None;
        }

        let len = packet[offset] as usize;

        if len == 0 {
            // End of name
            if return_offset.is_none() {
                return_offset = Some(offset + 1);
            }
            break;
        }

        // Pointer compression
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            if return_offset.is_none() {
                return_offset = Some(offset + 2);
            }
            pointer_jumps += 1;
            if pointer_jumps > MAX_POINTER_JUMPS {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | packet[offset + 1] as usize;
            if pointer >= packet.len() {
                return None;
            }
            offset = pointer;
            continue;
        }

        // Label length must be <= 63
        if len > 63 {
            return None;
        }

        offset += 1;
        if offset + len > packet.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }
        // DNS labels are case-insensitive; we normalize in the caller
        for &byte in &packet[offset..offset + len] {
            if !is_valid_dns_label_byte(byte) {
                return None;
            }
            name.push(byte as char);
        }
        if name.len() + 1 > 255 {
            return None;
        }
        offset += len;
    }

    Some((name, return_offset.unwrap_or(offset)))
}

fn is_valid_dns_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Build a DNS response with answer records.
fn build_dns_response(
    query: &DnsQuery,
    answers: &[&IpAddr],
    ttl: u32,
    authoritative: bool,
    max_response_size: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(max_response_size.min(DNS_MAX_UDP_PACKET_SIZE));
    write_dns_response_header(&mut response, query, 0, authoritative, false, 0, 0);
    encode_dns_name(&query.name, &mut response).expect("parsed DNS names are encodable");
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());

    let opt_len = query.opt_record.as_ref().map_or(0, |r| r.len());
    let mut answer_count = 0u16;
    let mut truncated = false;

    for ip in answers.iter().take(u16::MAX as usize) {
        let record_len = dns_answer_record_len(ip);
        if response.len() + record_len + opt_len > max_response_size {
            truncated = true;
            break;
        }
        write_dns_answer_record(&mut response, ip, ttl);
        answer_count = answer_count.saturating_add(1);
    }
    if answers.len() > usize::from(answer_count) {
        truncated = true;
    }

    let arcount = append_opt_record(query, &mut response, max_response_size);
    patch_dns_response_header(
        &mut response,
        query,
        answer_count,
        authoritative,
        truncated,
        0,
        arcount,
    );
    response
}

/// Build an empty DNS response (name exists, but no records of the requested type).
fn build_dns_empty_response(
    query: &DnsQuery,
    authoritative: bool,
    max_response_size: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(max_response_size.min(DNS_UDP_SAFE_PACKET_SIZE));
    write_dns_response_header(&mut response, query, 0, authoritative, false, 0, 0);
    encode_dns_name(&query.name, &mut response).expect("parsed DNS names are encodable");
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());
    let arcount = append_opt_record(query, &mut response, max_response_size);
    patch_dns_response_header(&mut response, query, 0, authoritative, false, 0, arcount);
    response
}

fn build_dns_error_response(
    query: &DnsQuery,
    rcode: u16,
    authoritative: bool,
    max_response_size: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(max_response_size.min(DNS_UDP_SAFE_PACKET_SIZE));
    write_dns_response_header(&mut response, query, 0, authoritative, false, rcode, 0);
    encode_dns_name(&query.name, &mut response).expect("parsed DNS names are encodable");
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());
    let arcount = append_opt_record(query, &mut response, max_response_size);
    patch_dns_response_header(
        &mut response,
        query,
        0,
        authoritative,
        false,
        rcode,
        arcount,
    );
    response
}

fn build_dns_error_response_from_packet(
    packet: &[u8],
    rcode: u16,
    max_response_size: usize,
) -> Option<Vec<u8>> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let rd_flag = flags & FLAGS_RD;
    let response_flags = FLAGS_QR | FLAGS_RA | rd_flag | (rcode & 0x000F);
    let mut response = Vec::with_capacity(max_response_size.min(DNS_UDP_SAFE_PACKET_SIZE));
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    Some(response)
}

fn clear_response_transaction_id(response: &mut [u8]) {
    if response.len() >= 2 {
        response[..2].copy_from_slice(&0u16.to_be_bytes());
    }
}

fn response_from_cached_template(template: &[u8], query_id: u16) -> Vec<u8> {
    let mut response = template.to_vec();
    if response.len() >= 2 {
        response[..2].copy_from_slice(&query_id.to_be_bytes());
    }
    response
}

fn write_dns_response_header(
    response: &mut Vec<u8>,
    query: &DnsQuery,
    answer_count: u16,
    authoritative: bool,
    truncated: bool,
    rcode: u16,
    arcount: u16,
) {
    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(
        &dns_response_flags(query, authoritative, truncated, rcode).to_be_bytes(),
    );
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    response.extend_from_slice(&answer_count.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&arcount.to_be_bytes()); // ARCOUNT
}

fn patch_dns_response_header(
    response: &mut [u8],
    query: &DnsQuery,
    answer_count: u16,
    authoritative: bool,
    truncated: bool,
    rcode: u16,
    arcount: u16,
) {
    response[2..4]
        .copy_from_slice(&dns_response_flags(query, authoritative, truncated, rcode).to_be_bytes());
    response[6..8].copy_from_slice(&answer_count.to_be_bytes());
    response[10..12].copy_from_slice(&arcount.to_be_bytes());
}

fn dns_response_flags(query: &DnsQuery, authoritative: bool, truncated: bool, rcode: u16) -> u16 {
    let rd_flag = query.flags & FLAGS_RD;
    let aa_flag = if authoritative { FLAGS_AA } else { 0 };
    let tc_flag = if truncated { FLAGS_TC } else { 0 };
    FLAGS_QR | aa_flag | tc_flag | rd_flag | FLAGS_RA | (rcode & 0x000F)
}

fn dns_answer_record_len(ip: &IpAddr) -> usize {
    12 + match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fn write_dns_answer_record(response: &mut Vec<u8>, ip: &IpAddr, ttl: u32) {
    // NAME pointer: 0xC00C points to QNAME at byte 12
    response.extend_from_slice(&[0xC0, 0x0C]);

    match ip {
        IpAddr::V4(v4) => {
            response.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE
            response.extend_from_slice(&QCLASS_IN.to_be_bytes()); // CLASS
            response.extend_from_slice(&ttl.to_be_bytes()); // TTL
            response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            response.extend_from_slice(&v4.octets()); // RDATA
        }
        IpAddr::V6(v6) => {
            response.extend_from_slice(&QTYPE_AAAA.to_be_bytes()); // TYPE
            response.extend_from_slice(&QCLASS_IN.to_be_bytes()); // CLASS
            response.extend_from_slice(&ttl.to_be_bytes()); // TTL
            response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
            response.extend_from_slice(&v6.octets()); // RDATA
        }
    }
}

fn append_opt_record(query: &DnsQuery, response: &mut Vec<u8>, max_response_size: usize) -> u16 {
    let Some(opt_record) = query.opt_record.as_ref() else {
        return 0;
    };
    if response.len() + opt_record.len() > max_response_size {
        return 0;
    }
    response.extend_from_slice(opt_record);
    1
}

/// Encode a hostname into DNS label format and append to the buffer.
fn encode_dns_name(name: &str, buf: &mut Vec<u8>) -> Option<()> {
    if name.is_empty() || name.len() + 1 > 255 {
        return None;
    }
    for label in name.split('.') {
        let len = label.len();
        if len > 63
            || len == 0
            || !label
                .as_bytes()
                .iter()
                .copied()
                .all(is_valid_dns_label_byte)
        {
            return None;
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // Root label terminator
    Some(())
}

// ── Unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::identity::spiffe::SpiffeId;
    use crate::modes::mesh::config::{AppProtocol, Workload, WorkloadPort, WorkloadSelector};
    use crate::modes::mesh::config::{
        MeshEndpoint, MeshService, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
        WorkloadRef,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── DNS wire format tests ────────────────────────────────────────────

    fn build_a_query(name: &str) -> Vec<u8> {
        build_query_packet(name, QTYPE_A)
    }

    fn build_aaaa_query(name: &str) -> Vec<u8> {
        build_query_packet(name, QTYPE_AAAA)
    }

    fn build_query_packet(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // QNAME
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label
        // QTYPE + QCLASS
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        packet
    }

    fn build_response_question(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = build_query_packet(name, qtype);
        packet[2..4].copy_from_slice(&(FLAGS_QR | FLAGS_RA | FLAGS_RD).to_be_bytes());
        packet
    }

    fn build_query_with_opt(name: &str, qtype: u16, udp_payload_size: u16) -> Vec<u8> {
        let mut packet = build_query_packet(name, qtype);
        packet[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        packet.push(0); // Root owner name
        packet.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        packet.extend_from_slice(&udp_payload_size.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL / extended RCODE / flags
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
        packet
    }

    #[test]
    fn parse_dns_query_valid_a_query() {
        let packet = build_a_query("example.com");
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.id, 0x1234);
        assert_eq!(&*query.name, "example.com");
        assert_eq!(query.qtype, QTYPE_A);
        assert_eq!(query.qclass, QCLASS_IN);
    }

    #[test]
    fn parse_dns_query_valid_aaaa_query() {
        let packet = build_aaaa_query("ipv6.example.com");
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(&*query.name, "ipv6.example.com");
        assert_eq!(query.qtype, QTYPE_AAAA);
    }

    #[test]
    fn upstream_response_question_must_match_pending_query() {
        let query_packet = build_a_query("example.com");
        let pending = parse_dns_query(&query_packet).expect("query parses");
        let matching = build_response_question("example.com", QTYPE_A);
        let wrong_name = build_response_question("other.example.com", QTYPE_A);
        let wrong_type = build_response_question("example.com", QTYPE_AAAA);
        let not_a_response = build_a_query("example.com");

        assert!(upstream_response_matches_pending_query(&matching, &pending));
        assert!(!upstream_response_matches_pending_query(
            &wrong_name,
            &pending
        ));
        assert!(!upstream_response_matches_pending_query(
            &wrong_type,
            &pending
        ));
        assert!(!upstream_response_matches_pending_query(
            &not_a_response,
            &pending
        ));
    }

    #[test]
    fn allocate_upstream_id_reports_exhaustion_when_all_ids_pending() {
        let query_packet = build_a_query("example.com");
        let query = parse_dns_query(&query_packet).expect("query parses");
        let mut pending = HashMap::with_capacity(u16::MAX as usize + 1);
        let client = "127.0.0.1:53000".parse().expect("client addr");
        let expires_at = Instant::now() + Duration::from_secs(1);
        for id in 0..=u16::MAX {
            pending.insert(
                id,
                PendingForward {
                    client,
                    original_id: id,
                    query: query.clone(),
                    expires_at,
                },
            );
        }
        let mut next_id = 0u16;

        assert!(allocate_upstream_id(&mut next_id, &pending).is_none());
    }

    #[test]
    fn upstream_id_space_exhaustion_is_only_full_16_bit_occupancy() {
        assert!(!upstream_id_space_exhausted(1024));
        assert!(!upstream_id_space_exhausted(DNS_UPSTREAM_ID_SPACE - 1));
        assert!(upstream_id_space_exhausted(DNS_UPSTREAM_ID_SPACE));
    }

    #[test]
    fn parse_dns_query_truncated_packet() {
        let packet = vec![0u8; 5]; // Too short for header
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_root_name() {
        let packet = build_a_query("");
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_non_ascii_labels() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(1);
        packet.push(0xff);
        packet.push(0);
        packet.extend_from_slice(&QTYPE_A.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_honors_edns_payload_size() {
        let packet = build_query_with_opt("example.com", QTYPE_A, 1232);
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.udp_payload_size, 1232);
        assert!(query.opt_record.is_some());
    }

    #[test]
    fn parse_dns_query_non_query_opcode() {
        let mut packet = build_a_query("test.com");
        // Set QR=1 (response)
        packet[2] |= 0x80;
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_non_in_class() {
        let mut packet = build_a_query("test.com");
        // Change QCLASS from 1 (IN) to 3 (CH)
        let qclass_offset = packet.len() - 2;
        packet[qclass_offset] = 0;
        packet[qclass_offset + 1] = 3;
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.qclass, 3);
    }

    #[test]
    fn parse_dns_query_truncated_after_name() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        // QNAME with no QTYPE/QCLASS
        packet.push(3);
        packet.extend_from_slice(b"foo");
        packet.push(0);
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_name_rejects_compression_pointer_loop() {
        // A name whose first byte is a compression pointer back to itself must
        // be rejected (bounded jump guard), not loop forever. Before, an O(n)
        // `visited` bitmap caught this; the bounded-jump guard must preserve the
        // protection without the per-call allocation.
        let mut packet = vec![0u8; 12]; // 12-byte header placeholder
        packet.push(0xC0); // pointer marker, high 6 bits of offset = 0
        packet.push(12); // low byte → offset 12 (points at this very pointer)
        assert!(
            parse_dns_name(&packet, 12).is_none(),
            "self-referential compression pointer must be rejected"
        );
    }

    #[test]
    fn build_dns_response_a_record() {
        let packet = build_a_query("api.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 60, true, DNS_UDP_SAFE_PACKET_SIZE);

        // Verify header
        assert_eq!(response[0..2], query.id.to_be_bytes());
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & FLAGS_QR != 0); // Is response
        assert!(flags & FLAGS_AA != 0); // Authoritative
        assert!(flags & FLAGS_RA != 0); // Recursion available is server state
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);

        // Find the answer section (after reconstructed question)
        // The answer uses a name pointer 0xC00C and then TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)+RDATA(4)
        // Verify the A record data is present at the end
        let rdata_start = response.len() - 4;
        assert_eq!(&response[rdata_start..], &[10, 0, 0, 1]);
    }

    #[test]
    fn build_dns_response_aaaa_record() {
        let packet = build_aaaa_query("ipv6.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "::1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 120, true, DNS_UDP_SAFE_PACKET_SIZE);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);

        // AAAA RDATA is 16 bytes at the end
        let rdata_start = response.len() - 16;
        let expected_ip: Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(&response[rdata_start..], &expected_ip.octets());
    }

    #[test]
    fn build_dns_response_multiple_answers() {
        let packet = build_a_query("multi.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let response =
            build_dns_response(&query, &[&ip1, &ip2], 60, true, DNS_UDP_SAFE_PACKET_SIZE);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 2);
    }

    #[test]
    fn build_dns_response_sets_tc_when_udp_response_would_exceed_limit() {
        let packet = build_a_query("many.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ips: Vec<IpAddr> = (1..=20)
            .map(|octet| IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)))
            .collect();
        let answer_refs: Vec<&IpAddr> = ips.iter().collect();
        let response = build_dns_response(&query, &answer_refs, 60, true, 96);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert!(flags & FLAGS_TC != 0);
        assert!(usize::from(ancount) < ips.len());
        assert!(response.len() <= 96);
    }

    #[test]
    fn build_dns_response_echoes_opt_record_when_present() {
        let packet = build_query_with_opt("edns.example.com", QTYPE_A, 1232);
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 60, true, 1232);
        let arcount = u16::from_be_bytes([response[10], response[11]]);
        assert_eq!(arcount, 1);
        assert!(response.ends_with(query.opt_record.as_ref().unwrap()));
    }

    #[test]
    fn build_dns_response_omits_aa_for_external_service_entry_names() {
        let packet = build_a_query("api.external.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 60, false, DNS_UDP_SAFE_PACKET_SIZE);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & FLAGS_AA, 0);
        assert!(flags & FLAGS_RA != 0);
    }

    #[test]
    fn build_dns_empty_response_correct_flags() {
        let packet = build_aaaa_query("no-aaaa.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let response = build_dns_empty_response(&query, true, DNS_UDP_SAFE_PACKET_SIZE);

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & FLAGS_QR != 0);
        assert!(flags & FLAGS_AA != 0);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0);
    }

    #[test]
    fn evaluate_dns_query_returns_empty_for_unsupported_mesh_owned_type() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.example.com"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };
        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_query_packet("api.example.com", QTYPE_TXT);

        let response = match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Respond(response) => response,
            DnsDecision::Forward(_) => panic!("mesh-owned unsupported qtype should not forward"),
            DnsDecision::Drop => panic!("valid DNS query should not drop"),
        };

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000f, 0);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0);
        let (name, offset) =
            parse_dns_name(&response, DNS_HEADER_SIZE).expect("response question should parse");
        assert_eq!(name, "api.example.com");
        assert_eq!(
            u16::from_be_bytes([response[offset], response[offset + 1]]),
            QTYPE_TXT
        );
    }

    #[test]
    fn evaluate_dns_query_caches_mesh_response_templates_without_query_id() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["api.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };
        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let first_packet = build_a_query("api.example.com");
        let mut second_packet = build_a_query("api.example.com");
        second_packet[..2].copy_from_slice(&0x5678u16.to_be_bytes());

        let first_response =
            match evaluate_dns_query(&first_packet, &table, 60, DnsResponseSizing::Udp) {
                DnsDecision::Respond(response) => response,
                DnsDecision::Forward(_) => panic!("mesh name should not forward"),
                DnsDecision::Drop => panic!("valid DNS query should not drop"),
            };
        assert_eq!(table.load().response_cache_len(), 1);

        let second_response =
            match evaluate_dns_query(&second_packet, &table, 60, DnsResponseSizing::Udp) {
                DnsDecision::Respond(response) => response,
                DnsDecision::Forward(_) => panic!("mesh name should not forward"),
                DnsDecision::Drop => panic!("valid DNS query should not drop"),
            };

        assert_eq!(table.load().response_cache_len(), 1);
        assert_eq!(&first_response[..2], &0x1234u16.to_be_bytes());
        assert_eq!(&second_response[..2], &0x5678u16.to_be_bytes());
        assert_eq!(&first_response[2..], &second_response[2..]);
    }

    #[test]
    fn evaluate_dns_query_does_not_cache_large_tcp_sized_responses() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["api.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };
        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_a_query("api.example.com");

        let _ = match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Tcp) {
            DnsDecision::Respond(response) => response,
            DnsDecision::Forward(_) => panic!("mesh name should not forward"),
            DnsDecision::Drop => panic!("valid DNS query should not drop"),
        };

        assert_eq!(table.load().response_cache_len(), 0);
    }

    #[test]
    fn mesh_response_cache_never_exceeds_entry_cap() {
        let table = DnsResolutionTable::empty();

        for index in 0..(DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES + 16) {
            let key = DnsResponseCacheKey {
                name: Arc::from(format!("svc-{index}.example.com").as_str()),
                qtype: QTYPE_A,
                qclass: QCLASS_IN,
                rd: true,
                cd: false,
                ad: false,
                ttl: 60,
                max_response_size: DNS_UDP_SAFE_PACKET_SIZE,
                opt_record: None,
            };
            let _ = table.cached_mesh_response(key, 0x1234, || vec![0x12, 0x34, 0x81, 0x80]);
        }

        assert_eq!(
            table.response_cache_len(),
            DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES
        );
    }

    #[test]
    fn mesh_response_cache_honors_configured_entry_cap() {
        let table = DnsResolutionTable::empty_with_response_cache_max_entries(2);

        for index in 0..4 {
            let key = DnsResponseCacheKey {
                name: Arc::from(format!("svc-{index}.example.com").as_str()),
                qtype: QTYPE_A,
                qclass: QCLASS_IN,
                rd: true,
                cd: false,
                ad: false,
                ttl: 60,
                max_response_size: DNS_UDP_SAFE_PACKET_SIZE,
                opt_record: None,
            };
            let _ = table.cached_mesh_response(key, 0x1234, || vec![0x12, 0x34, 0x81, 0x80]);
        }

        assert_eq!(table.response_cache_len(), 2);
    }

    #[test]
    fn mesh_response_cache_differentiates_cd_ad_flags() {
        let table = DnsResolutionTable::empty();
        let base = || DnsResponseCacheKey {
            name: Arc::from("svc.example.com"),
            qtype: QTYPE_A,
            qclass: QCLASS_IN,
            rd: true,
            cd: false,
            ad: false,
            ttl: 60,
            max_response_size: DNS_UDP_SAFE_PACKET_SIZE,
            opt_record: None,
        };

        let _ = table.cached_mesh_response(base(), 0x1234, || vec![0x00, 0x00, 0xAA]);

        let mut cd_key = base();
        cd_key.cd = true;
        let _ = table.cached_mesh_response(cd_key, 0x1234, || vec![0x00, 0x00, 0xBB]);

        let mut ad_key = base();
        ad_key.ad = true;
        let _ = table.cached_mesh_response(ad_key, 0x1234, || vec![0x00, 0x00, 0xCC]);

        assert_eq!(table.response_cache_len(), 3);
    }

    #[tokio::test]
    async fn dns_tcp_rejects_before_payload_read_when_limit_saturated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let semaphore = Arc::new(Semaphore::new(0));

        let server = tokio::spawn(async move {
            let (stream, src) = listener.accept().await.unwrap();
            let table = ArcSwap::from_pointee(DnsResolutionTable::empty());
            handle_dns_tcp_connection(stream, src, &table, listen_addr, 60, semaphore).await;
        });

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        client.write_all(&u16::MAX.to_be_bytes()).await.unwrap();

        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .expect("server should close without waiting for payload")
            .expect("read should complete");
        assert_eq!(read, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dns_tcp_session_limit_rejects_before_length_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let session_semaphore = Arc::new(Semaphore::new(0));

        let server = tokio::spawn(async move {
            let (stream, src) = listener.accept().await.unwrap();
            assert!(try_acquire_dns_tcp_session_permit(&session_semaphore, src).is_none());
            drop(stream);
        });

        let mut client = TcpStream::connect(listen_addr).await.unwrap();

        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .expect("server should close without waiting for a length prefix")
            .expect("read should complete");
        assert_eq!(read, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dns_tcp_length_read_has_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_dns_tcp_length_with_timeout(&mut stream, Duration::from_millis(10)).await
        });

        let _client = TcpStream::connect(listen_addr).await.unwrap();

        let err = server
            .await
            .unwrap()
            .expect_err("length read should time out");
        assert!(matches!(err, DnsTcpQueryReadError::Timeout));
    }

    #[tokio::test]
    async fn dns_tcp_payload_read_has_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut packet = vec![0u8; 8];
            read_dns_tcp_payload_with_timeout(&mut stream, &mut packet, Duration::from_millis(10))
                .await
        });

        let _client = TcpStream::connect(listen_addr).await.unwrap();

        let err = server
            .await
            .unwrap()
            .expect_err("payload read should time out");
        assert!(matches!(err, DnsTcpQueryReadError::Timeout));
    }

    #[test]
    fn encode_and_parse_roundtrip() {
        let name = "foo.bar.baz.example.com";
        let mut encoded = Vec::new();
        // Build a minimal packet with header + encoded name
        encoded.extend_from_slice(&[0u8; DNS_HEADER_SIZE]); // dummy header
        encode_dns_name(name, &mut encoded).unwrap();
        let (parsed, _) = parse_dns_name(&encoded, DNS_HEADER_SIZE).unwrap();
        assert_eq!(parsed, name);
    }

    // ── Resolution table tests ───────────────────────────────────────────

    fn test_service_entry(hosts: Vec<&str>, endpoints: Vec<&str>) -> ServiceEntry {
        ServiceEntry {
            name: "test-se".to_string(),
            namespace: "default".to_string(),
            hosts: hosts.into_iter().map(String::from).collect(),
            endpoints: endpoints
                .into_iter()
                .map(|addr| MeshEndpoint {
                    address: addr.to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                })
                .collect(),
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Http,
                name: Some("https".to_string()),
                target_port: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }
    }

    fn test_workload(spiffe_id: &str, addresses: Vec<&str>) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        Workload {
            spiffe_id: SpiffeId::new(spiffe_id.to_string()).unwrap(),
            selector: WorkloadSelector::default(),
            service_name: "test-svc".to_string(),
            addresses: addresses.into_iter().map(String::from).collect(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
        }
    }

    fn test_workload_for_service(
        spiffe_id: &str,
        service_name: &str,
        namespace: &str,
        addresses: Vec<&str>,
    ) -> Workload {
        let mut workload = test_workload(spiffe_id, addresses);
        workload.service_name = service_name.to_string();
        workload.namespace = namespace.to_string();
        workload.selector.namespace = Some(namespace.to_string());
        workload
    }

    fn test_mesh_service(name: &str, namespace: &str, workload_refs: Vec<&str>) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: workload_refs
                .into_iter()
                .map(|id| WorkloadRef {
                    spiffe_id: SpiffeId::new(id.to_string()).unwrap(),
                })
                .collect(),
            protocol_overrides: HashMap::new(),
        }
    }

    #[test]
    fn resolution_table_from_service_entries() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["api.external.com", "db.external.com"],
                vec!["10.0.0.1", "10.0.0.2"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.exact_count(), 2);

        let ips = table.resolve("api.external.com").unwrap();
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));

        let ips = table.resolve("db.external.com").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn resolution_table_from_mesh_services() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1", "10.1.0.2"])],
            services: vec![test_mesh_service("my-api", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // FQDN: my-api.default.svc.cluster.local
        let ips = table.resolve("my-api.default.svc.cluster.local").unwrap();
        assert!(ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.1.0.2".parse::<IpAddr>().unwrap()));

        // Short name: my-api.default
        let ips = table.resolve("my-api.default").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn resolution_table_merges_duplicate_spiffe_workload_entries() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![
                test_workload(spiffe, vec!["10.1.0.1", "10.1.0.2"]),
                test_workload(spiffe, vec!["10.1.0.2", "10.1.0.3"]),
            ],
            services: vec![test_mesh_service("my-api", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("my-api.default.svc.cluster.local").unwrap();

        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.1.0.2".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.1.0.3".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn resolution_table_dedups_duplicate_service_workload_refs() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1", "10.1.0.2"])],
            services: vec![test_mesh_service(
                "my-api",
                "default",
                vec![spiffe, spiffe, spiffe],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("my-api.default.svc.cluster.local").unwrap();

        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.1.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn resolution_table_does_not_cross_match_same_spiffe_other_services() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
        let api = test_workload(spiffe, vec!["10.1.0.1"]);
        let mut metrics = test_workload(spiffe, vec!["10.1.0.2"]);
        metrics.service_name = "metrics".to_string();

        let slice = MeshSlice {
            workloads: vec![api, metrics],
            services: vec![
                test_mesh_service("test-svc", "default", vec![spiffe]),
                test_mesh_service("metrics", "default", vec![spiffe]),
            ],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let api_ips = table.resolve("test-svc.default.svc.cluster.local").unwrap();
        let metrics_ips = table.resolve("metrics.default.svc.cluster.local").unwrap();

        assert_eq!(api_ips.len(), 1);
        assert!(api_ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
        assert_eq!(metrics_ips.len(), 1);
        assert!(metrics_ips.contains(&"10.1.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn resolution_table_skips_ambiguous_mismatched_service_fallback() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
        let api = test_workload_for_service(spiffe, "api", "default", vec!["10.1.0.1"]);
        let metrics = test_workload_for_service(spiffe, "metrics", "default", vec!["10.1.0.2"]);
        let slice = MeshSlice {
            workloads: vec![api, metrics],
            services: vec![test_mesh_service("reviews", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        assert!(
            table.resolve("reviews.default.svc.cluster.local").is_none(),
            "ambiguous fallback must not include every service sharing the SPIFFE ID"
        );
    }

    #[test]
    fn resolution_table_wildcard_matching() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.example.com"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.wildcard_count(), 1);

        // Should match subdomains
        assert!(table.resolve("foo.example.com").is_some());
        assert!(table.resolve("bar.example.com").is_some());
        assert!(table.resolve("deep.sub.example.com").is_none());

        // Should NOT match the bare suffix itself
        assert!(table.resolve("example.com").is_none());

        // Should NOT match a non-subdomain that merely ends with the suffix
        assert!(table.resolve("fooexample.com").is_none());
    }

    #[test]
    fn resolution_table_merges_duplicate_wildcard_suffixes() {
        let slice = MeshSlice {
            service_entries: vec![
                test_service_entry(vec!["*.example.com"], vec!["10.0.0.1"]),
                test_service_entry(vec!["*.example.com"], vec!["10.0.0.2"]),
            ],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.wildcard_count(), 1);

        let ips = table.resolve("api.example.com").unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn resolution_table_case_insensitive() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["API.Example.COM"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // Lookup with different case should match
        assert!(table.resolve("api.example.com").is_some());
        assert!(table.resolve("API.EXAMPLE.COM").is_some());
        assert!(table.resolve("Api.Example.Com").is_some());
    }

    #[test]
    fn resolution_table_trailing_dot() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["api.example.com."],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // Both with and without trailing dot should resolve
        assert!(table.resolve("api.example.com").is_some());
        assert!(table.resolve("api.example.com.").is_some());
    }

    #[test]
    fn resolution_table_uses_custom_cluster_domain_for_mesh_services() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1"])],
            services: vec![test_mesh_service("my-api", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice_with_cluster_domain(&slice, "corp.local");

        assert!(table.resolve("my-api.default.svc.corp.local").is_some());
        assert!(table.resolve("my-api.default.svc.cluster.local").is_none());
    }

    #[test]
    fn resolution_table_no_match() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["known.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("unknown.example.com").is_none());
        assert!(table.resolve("google.com").is_none());
    }

    #[test]
    fn resolution_table_skips_non_ip_and_non_routable_endpoints() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["mixed.example.com"],
                vec!["10.0.0.1", "not-an-ip", "::1", "127.0.0.1", "169.254.1.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("mixed.example.com").unwrap();
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn resolution_table_skips_entries_with_no_valid_ips() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["no-ips.example.com"],
                vec!["hostname.internal"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("no-ips.example.com").is_none());
    }

    #[test]
    fn resolution_table_empty_slice() {
        let table = DnsResolutionTable::from_mesh_slice(&MeshSlice::default());
        assert_eq!(table.exact_count(), 0);
        assert_eq!(table.wildcard_count(), 0);
    }

    #[test]
    fn resolution_table_deduplicates_ips() {
        let spiffe1 = "spiffe://cluster.local/ns/default/sa/api-1";
        let spiffe2 = "spiffe://cluster.local/ns/default/sa/api-2";
        let slice = MeshSlice {
            workloads: vec![
                test_workload(spiffe1, vec!["10.1.0.1"]),
                test_workload(spiffe2, vec!["10.1.0.1"]), // Same IP
            ],
            services: vec![test_mesh_service(
                "shared-ip",
                "default",
                vec![spiffe1, spiffe2],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table
            .resolve("shared-ip.default.svc.cluster.local")
            .unwrap();
        // Should be deduplicated
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn resolution_table_mixed_ipv4_ipv6() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["dual.example.com"],
                vec!["10.0.0.1", "fd00::1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("dual.example.com").unwrap();
        assert_eq!(ips.len(), 2);

        let v4_count = ips.iter().filter(|ip| ip.is_ipv4()).count();
        let v6_count = ips.iter().filter(|ip| ip.is_ipv6()).count();
        assert_eq!(v4_count, 1);
        assert_eq!(v6_count, 1);
    }

    // ── Resolution table construction edge cases ────────────────────────

    #[test]
    fn resolution_table_service_entry_multiple_hosts_share_endpoints() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec![
                    "primary.example.com",
                    "alias.example.com",
                    "backup.example.com",
                ],
                vec!["10.0.0.1", "10.0.0.2"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.exact_count(), 3);

        for host in &[
            "primary.example.com",
            "alias.example.com",
            "backup.example.com",
        ] {
            let resolved = table.resolve(host).expect("each host should resolve");
            assert_eq!(resolved.len(), 2);
            assert!(resolved.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
            assert!(resolved.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));
        }
    }

    #[test]
    fn resolution_table_service_entry_empty_endpoints_skips_host() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["empty-ep.example.com"], vec![])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.exact_count(), 0);
        assert!(table.resolve("empty-ep.example.com").is_none());
    }

    #[test]
    fn resolution_table_mesh_service_produces_fqdn_and_short_name() {
        let spiffe = "spiffe://cluster.local/ns/production/sa/web";
        let slice = MeshSlice {
            workloads: vec![test_workload_for_service(
                spiffe,
                "web-frontend",
                "production",
                vec!["10.2.0.1"],
            )],
            services: vec![test_mesh_service(
                "web-frontend",
                "production",
                vec![spiffe],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // FQDN entry
        let fqdn_ips = table
            .resolve("web-frontend.production.svc.cluster.local")
            .expect("FQDN should resolve");
        assert_eq!(fqdn_ips.len(), 1);
        assert!(fqdn_ips.contains(&"10.2.0.1".parse::<IpAddr>().unwrap()));

        // Short name entry
        let short_ips = table
            .resolve("web-frontend.production")
            .expect("short name should resolve");
        assert_eq!(short_ips.len(), 1);
        assert!(short_ips.contains(&"10.2.0.1".parse::<IpAddr>().unwrap()));

        // Both entries should be exact entries
        assert!(table.exact_count() >= 2);
    }

    #[test]
    fn resolution_table_custom_cluster_domain_fqdn_format() {
        let spiffe = "spiffe://corp.local/ns/staging/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload_for_service(
                spiffe,
                "payments",
                "staging",
                vec!["10.3.0.1"],
            )],
            services: vec![test_mesh_service("payments", "staging", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table =
            DnsResolutionTable::from_mesh_slice_with_cluster_domain(&slice, "my-org.internal");

        // Custom cluster domain should produce the correct FQDN
        assert!(
            table
                .resolve("payments.staging.svc.my-org.internal")
                .is_some()
        );
        // Short name is independent of cluster domain
        assert!(table.resolve("payments.staging").is_some());
        // Default cluster domain should NOT match
        assert!(
            table
                .resolve("payments.staging.svc.cluster.local")
                .is_none()
        );
    }

    #[test]
    fn resolution_table_service_entry_and_mesh_service_duplicate_host() {
        // When a ServiceEntry and MeshService would resolve to the same hostname,
        // both contribute IPs to the same record set.
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1"])],
            services: vec![test_mesh_service("api", "default", vec![spiffe])],
            service_entries: vec![test_service_entry(
                vec!["api.default.svc.cluster.local"],
                vec!["10.9.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let resolved = table
            .resolve("api.default.svc.cluster.local")
            .expect("hostname should resolve");
        // Both sources contribute IPs to the same record
        assert!(resolved.contains(&"10.9.0.1".parse::<IpAddr>().unwrap()));
        assert!(resolved.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn resolution_table_service_entry_resolution_types_all_resolve() {
        // The DNS resolution table indexes endpoint IPs regardless of the
        // ServiceEntry resolution type (Static, Dns, None).
        for resolution in [Resolution::Static, Resolution::Dns, Resolution::None] {
            let se = ServiceEntry {
                name: "test-se".to_string(),
                namespace: "default".to_string(),
                hosts: vec!["res-test.example.com".to_string()],
                endpoints: vec![MeshEndpoint {
                    address: "10.0.0.5".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                }],
                resolution,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![],
                export_to: Vec::new(),
                workload_selector: None,
            };
            let slice = MeshSlice {
                service_entries: vec![se],
                ..MeshSlice::default()
            };

            let table = DnsResolutionTable::from_mesh_slice(&slice);
            assert!(
                table.resolve("res-test.example.com").is_some(),
                "resolution type {resolution:?} should still produce a table entry"
            );
        }
    }

    // ── Wildcard resolution edge cases ──────────────────────────────────

    #[test]
    fn wildcard_does_not_match_base_domain() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.corp.io"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("corp.io").is_none());
    }

    #[test]
    fn wildcard_does_not_match_multi_level_subdomain() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.example.com"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        // Multi-level subdomain should NOT match a single-label wildcard
        assert!(table.resolve("deep.sub.example.com").is_none());
        // Single-level subdomain should match
        assert!(table.resolve("api.example.com").is_some());
    }

    #[test]
    fn wildcard_multiple_overlapping_suffixes() {
        let slice = MeshSlice {
            service_entries: vec![
                test_service_entry(vec!["*.example.com"], vec!["10.0.0.1"]),
                test_service_entry(vec!["*.internal.example.com"], vec!["10.0.0.2"]),
            ],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.wildcard_count(), 2);

        // api.example.com matches *.example.com
        let ips = table.resolve("api.example.com").unwrap();
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));

        // db.internal.example.com matches *.internal.example.com (most specific)
        let ips = table.resolve("db.internal.example.com").unwrap();
        assert!(ips.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn wildcard_single_label_suffix() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.local"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.wildcard_count(), 1);

        assert!(table.resolve("myhost.local").is_some());
        assert!(table.resolve("local").is_none());
        assert!(table.resolve("deep.sub.local").is_none());
    }

    #[test]
    fn wildcard_case_insensitive_matching() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.Example.COM"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("API.EXAMPLE.COM").is_some());
        assert!(table.resolve("api.example.com").is_some());
    }

    // ── IPv6 endpoint edge cases ────────────────────────────────────────

    #[test]
    fn resolution_table_ipv6_only_endpoints() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["v6only.example.com"],
                vec!["fd00::1", "fd00::2", "2001:db8::1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("v6only.example.com").unwrap();
        assert_eq!(ips.len(), 3);
        assert!(ips.iter().all(|ip| ip.is_ipv6()));
    }

    #[test]
    fn resolution_table_mixed_v4_v6_a_vs_aaaa_filtering() {
        // Verifies that evaluate_dns_query correctly filters A vs AAAA
        // from a record set containing both IPv4 and IPv6 addresses.
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["dualstack.example.com"],
                vec!["10.0.0.1", "fd00::1", "10.0.0.2", "fd00::2"],
            )],
            ..MeshSlice::default()
        };

        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));

        // A query should get only IPv4
        let a_packet = build_a_query("dualstack.example.com");
        let a_response = match evaluate_dns_query(&a_packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Respond(r) => r,
            _ => panic!("A query for mesh name should produce a response"),
        };
        let a_ancount = u16::from_be_bytes([a_response[6], a_response[7]]);
        assert_eq!(a_ancount, 2, "A query should return 2 IPv4 answers");

        // AAAA query should get only IPv6
        let aaaa_packet = build_aaaa_query("dualstack.example.com");
        let aaaa_response =
            match evaluate_dns_query(&aaaa_packet, &table, 60, DnsResponseSizing::Udp) {
                DnsDecision::Respond(r) => r,
                _ => panic!("AAAA query for mesh name should produce a response"),
            };
        let aaaa_ancount = u16::from_be_bytes([aaaa_response[6], aaaa_response[7]]);
        assert_eq!(aaaa_ancount, 2, "AAAA query should return 2 IPv6 answers");
    }

    #[test]
    fn resolution_table_a_query_on_ipv6_only_returns_empty() {
        // A record set with only IPv6 addresses should produce an empty
        // (not NXDOMAIN) response for an A query.
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["v6only.example.com"],
                vec!["fd00::1"],
            )],
            ..MeshSlice::default()
        };

        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_a_query("v6only.example.com");
        let response = match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Respond(r) => r,
            _ => panic!("mesh-owned name should produce a response, not forward"),
        };

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(
            ancount, 0,
            "A query for IPv6-only entry should return 0 answers"
        );
        let rcode = u16::from_be_bytes([response[2], response[3]]) & 0x000F;
        assert_eq!(rcode, 0, "should be NOERROR, not NXDOMAIN");
    }

    #[test]
    fn resolution_table_aaaa_query_on_ipv4_only_returns_empty() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["v4only.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_aaaa_query("v4only.example.com");
        let response = match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Respond(r) => r,
            _ => panic!("mesh-owned name should produce a response"),
        };

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(
            ancount, 0,
            "AAAA query for IPv4-only entry should return 0 answers"
        );
    }

    // ── Query resolution edge cases ─────────────────────────────────────

    #[test]
    fn resolution_table_non_mesh_query_returns_none() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["known.internal.io"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("completely-different.org").is_none());
        assert!(table.resolve("not-known.internal.io").is_none());
        assert!(table.resolve("sub.known.internal.io").is_none());
    }

    #[test]
    fn resolution_table_query_forwards_non_mesh_name() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["mesh.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_a_query("google.com");
        match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Forward(_) => {} // expected
            DnsDecision::Respond(_) => panic!("non-mesh name should be forwarded"),
            DnsDecision::Drop => panic!("valid query should not be dropped"),
        }
    }

    #[test]
    fn resolution_table_case_insensitive_query() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["my-service.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("MY-SERVICE.EXAMPLE.COM").is_some());
        assert!(table.resolve("My-Service.Example.Com").is_some());
        assert!(table.resolve("my-service.example.com").is_some());
    }

    #[test]
    fn resolution_table_empty_mesh_slice_produces_empty_table() {
        let table = DnsResolutionTable::from_mesh_slice(&MeshSlice::default());
        assert_eq!(table.exact_count(), 0);
        assert_eq!(table.wildcard_count(), 0);
        assert!(table.resolve("anything.example.com").is_none());
    }

    // ── Authoritative flag edge cases ───────────────────────────────────

    #[test]
    fn resolution_table_mesh_service_fqdn_is_authoritative() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1"])],
            services: vec![test_mesh_service("api-svc", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_a_query("api-svc.default.svc.cluster.local");
        let response = match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Respond(r) => r,
            _ => panic!("mesh service FQDN should produce a response"),
        };

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(
            flags & FLAGS_AA != 0,
            "mesh svc.cluster.local should be authoritative"
        );
    }

    #[test]
    fn resolution_table_external_service_entry_is_not_authoritative() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["external.third-party.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = ArcSwap::from_pointee(DnsResolutionTable::from_mesh_slice(&slice));
        let packet = build_a_query("external.third-party.com");
        let response = match evaluate_dns_query(&packet, &table, 60, DnsResponseSizing::Udp) {
            DnsDecision::Respond(r) => r,
            _ => panic!("service entry host should produce a response"),
        };

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(
            flags & FLAGS_AA,
            0,
            "external host should not be authoritative"
        );
    }

    // ── Workload address filtering edge cases ───────────────────────────

    #[test]
    fn resolution_table_mesh_service_skips_unresolvable_spiffe_refs() {
        // A MeshService referencing a SPIFFE ID that has no workload
        // should still work for the references that do resolve.
        let spiffe_good = "spiffe://cluster.local/ns/default/sa/good";
        let spiffe_missing = "spiffe://cluster.local/ns/default/sa/missing";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe_good, vec!["10.1.0.1"])],
            services: vec![test_mesh_service(
                "partial-svc",
                "default",
                vec![spiffe_good, spiffe_missing],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table
            .resolve("partial-svc.default.svc.cluster.local")
            .expect("should resolve with available workloads");
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn resolution_table_mesh_service_with_no_resolvable_workloads_skipped() {
        let spiffe_missing = "spiffe://cluster.local/ns/default/sa/missing";
        let slice = MeshSlice {
            workloads: vec![],
            services: vec![test_mesh_service(
                "no-workloads",
                "default",
                vec![spiffe_missing],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(
            table
                .resolve("no-workloads.default.svc.cluster.local")
                .is_none()
        );
    }

    #[test]
    fn resolution_table_workload_non_routable_addresses_filtered() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/mixed";
        let slice = MeshSlice {
            workloads: vec![test_workload(
                spiffe,
                vec!["10.1.0.1", "127.0.0.1", "0.0.0.0", "::1", "fe80::1"],
            )],
            services: vec![test_mesh_service("filtered-svc", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table
            .resolve("filtered-svc.default.svc.cluster.local")
            .expect("should resolve with routable addresses only");
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
    }

    // ── single_label_wildcard_matches helper ────────────────────────────

    #[test]
    fn single_label_wildcard_matches_basic() {
        assert!(single_label_wildcard_matches(
            "foo.example.com",
            "example.com"
        ));
        assert!(single_label_wildcard_matches(
            "bar.example.com",
            "example.com"
        ));
    }

    #[test]
    fn single_label_wildcard_rejects_base_domain() {
        assert!(!single_label_wildcard_matches("example.com", "example.com"));
    }

    #[test]
    fn single_label_wildcard_rejects_multi_level() {
        assert!(!single_label_wildcard_matches(
            "a.b.example.com",
            "example.com"
        ));
    }

    #[test]
    fn single_label_wildcard_rejects_suffix_only_match() {
        // "fooexample.com" should not match suffix "example.com"
        assert!(!single_label_wildcard_matches(
            "fooexample.com",
            "example.com"
        ));
    }

    #[test]
    fn single_label_wildcard_rejects_shorter_name() {
        assert!(!single_label_wildcard_matches("com", "example.com"));
    }

    // ── normalize_dns_name helper ───────────────────────────────────────

    #[test]
    fn normalize_dns_name_lowercases_and_strips_dot() {
        assert_eq!(normalize_dns_name("API.Example.COM."), "api.example.com");
        assert_eq!(normalize_dns_name("already.lower"), "already.lower");
        assert_eq!(normalize_dns_name("trailing."), "trailing");
    }

    // ── is_routable_mesh_dns_ip helper ──────────────────────────────────

    #[test]
    fn routable_ip_rejects_non_routable_addresses() {
        assert!(!is_routable_mesh_dns_ip(&"0.0.0.0".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(&"169.254.1.1".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(
            &"255.255.255.255".parse().unwrap()
        ));
        assert!(!is_routable_mesh_dns_ip(&"224.0.0.1".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(&"::".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(&"::1".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(&"fe80::1".parse().unwrap()));
        assert!(!is_routable_mesh_dns_ip(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_accepts_routable_addresses() {
        assert!(is_routable_mesh_dns_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_routable_mesh_dns_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_routable_mesh_dns_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_routable_mesh_dns_ip(&"fd00::1".parse().unwrap()));
        assert!(is_routable_mesh_dns_ip(&"2001:db8::1".parse().unwrap()));
    }

    // ── is_authoritative_mesh_dns_name helper ───────────────────────────

    #[test]
    fn authoritative_mesh_name_detects_svc_cluster_local() {
        assert!(is_authoritative_mesh_dns_name(
            "my-svc.default.svc.cluster.local",
            "cluster.local"
        ));
        assert!(is_authoritative_mesh_dns_name(
            "svc.cluster.local",
            "cluster.local"
        ));
    }

    #[test]
    fn authoritative_mesh_name_rejects_external() {
        assert!(!is_authoritative_mesh_dns_name(
            "api.example.com",
            "cluster.local"
        ));
        assert!(!is_authoritative_mesh_dns_name(
            "cluster.local",
            "cluster.local"
        ));
    }

    #[test]
    fn authoritative_mesh_name_custom_cluster_domain() {
        assert!(is_authoritative_mesh_dns_name(
            "my-svc.ns.svc.corp.internal",
            "corp.internal"
        ));
        assert!(!is_authoritative_mesh_dns_name(
            "my-svc.ns.svc.cluster.local",
            "corp.internal"
        ));
    }

    // ── Multiple MeshServices in different namespaces ────────────────────

    #[test]
    fn resolution_table_same_service_name_different_namespaces() {
        let spiffe_a = "spiffe://cluster.local/ns/ns-a/sa/api";
        let spiffe_b = "spiffe://cluster.local/ns/ns-b/sa/api";
        let slice = MeshSlice {
            workloads: vec![
                test_workload_for_service(spiffe_a, "api", "ns-a", vec!["10.1.0.1"]),
                test_workload_for_service(spiffe_b, "api", "ns-b", vec!["10.2.0.1"]),
            ],
            services: vec![
                test_mesh_service("api", "ns-a", vec![spiffe_a]),
                test_mesh_service("api", "ns-b", vec![spiffe_b]),
            ],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        let ips_a = table
            .resolve("api.ns-a.svc.cluster.local")
            .expect("namespace A FQDN should resolve");
        assert!(ips_a.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));

        let ips_b = table
            .resolve("api.ns-b.svc.cluster.local")
            .expect("namespace B FQDN should resolve");
        assert!(ips_b.contains(&"10.2.0.1".parse::<IpAddr>().unwrap()));

        // Short names also separate by namespace
        let short_a = table.resolve("api.ns-a").expect("short name A");
        assert!(short_a.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));

        let short_b = table.resolve("api.ns-b").expect("short name B");
        assert!(short_b.contains(&"10.2.0.1".parse::<IpAddr>().unwrap()));
    }
}
