use std::net::SocketAddr;

use crate::dns::DnsCache;

/// Resolve `host:port` to a `SocketAddr` via the gateway's shared `DnsCache`.
///
/// Mirrors `resolve_udp_endpoint` for plugins that open their own TCP
/// connections (log shippers, side-channel clients).
///
/// **Authoritative when a cache is present.** `DnsCache::resolve` errors
/// encode configured policy decisions — per-proxy / global static DNS
/// overrides, negative caching, and the gateway's IP-policy denial layer
/// (`check_backend_ip_policy`). Falling through to the OS resolver on error
/// would silently bypass all of those, so this function propagates the cache
/// error instead.
///
/// The OS resolver is consulted **only** when no cache is attached — the
/// rare test/fallback `PluginHttpClient` path that has `dns_cache == None`.
pub async fn resolve_tcp_endpoint(
    host: &str,
    port: u16,
    dns_cache: Option<&DnsCache>,
    plugin_name: &'static str,
) -> Result<SocketAddr, String> {
    if let Some(cache) = dns_cache {
        return cache
            .resolve(host, None, None)
            .await
            .map(|ip| SocketAddr::new(ip, port))
            .map_err(|error| {
                format!("{plugin_name}: DNS resolution failed for '{host}': {error}")
            });
    }

    let addr = format!("{host}:{port}");
    tokio::net::lookup_host(&addr)
        .await
        .map_err(|error| format!("{plugin_name}: DNS resolution failed for {addr}: {error}"))?
        .next()
        .ok_or_else(|| format!("{plugin_name}: no addresses resolved for {addr}"))
}
