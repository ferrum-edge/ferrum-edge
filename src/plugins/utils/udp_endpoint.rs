use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::warn;

use crate::dns::DnsCache;

pub const UDP_RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

pub async fn resolve_udp_endpoint(
    host: &str,
    port: u16,
    dns_cache: Option<&DnsCache>,
    plugin_name: &'static str,
) -> Result<SocketAddr, String> {
    if let Some(cache) = dns_cache {
        match cache.resolve(host, None, None).await {
            Ok(ip) => return Ok(SocketAddr::new(ip, port)),
            Err(error) => {
                warn!(
                    "{plugin_name}: DNS cache resolution failed for '{host}': {error} — falling back to system DNS"
                );
            }
        }
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
