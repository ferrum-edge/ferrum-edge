use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

pub const UDP_RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

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
