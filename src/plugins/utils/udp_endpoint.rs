use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::dns::DnsCache;

pub const UDP_RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

/// Resolve `host:port` to a `SocketAddr` via the gateway's shared `DnsCache`.
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
pub async fn resolve_udp_endpoint(
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

pub async fn bind_connected_udp_socket(
    remote_addr: SocketAddr,
    plugin_name: &'static str,
) -> Result<UdpSocket, String> {
    let bind_addr = if remote_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| format!("{plugin_name}: bind failed: {error}"))?;
    socket
        .connect(remote_addr)
        .await
        .map_err(|error| format!("{plugin_name}: connect to {remote_addr} failed: {error}"))?;
    Ok(socket)
}
