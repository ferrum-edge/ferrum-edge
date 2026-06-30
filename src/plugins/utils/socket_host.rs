use std::net::{IpAddr, Ipv6Addr};

use url::Host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketHost {
    pub dial_host: String,
    pub warmup_hostname: Option<String>,
}

pub fn parse_socket_host(
    plugin_name: &str,
    field: &str,
    raw_host: &str,
) -> Result<SocketHost, String> {
    let host = raw_host.trim();
    if host.is_empty() {
        return Err(format!("{plugin_name}: '{field}' must not be empty"));
    }
    if host
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
        || host.contains("://")
        || host.contains(['/', '?', '#', '@'])
    {
        return Err(format!(
            "{plugin_name}: '{field}' must be a hostname or IP address without scheme, path, query, fragment, or credentials"
        ));
    }

    let bracketed = host.starts_with('[') || host.ends_with(']');
    let host_for_ip = if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        inner
    } else {
        host
    };
    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        return Ok(SocketHost {
            dial_host: ip.to_string(),
            warmup_hostname: None,
        });
    }

    if bracketed || host.contains(':') {
        return Err(format!(
            "{plugin_name}: '{field}' must not include brackets or a port unless it is an IPv6 literal"
        ));
    }

    match Host::parse(host) {
        Ok(Host::Domain(domain)) if !domain.is_empty() => {
            let hostname = domain.to_ascii_lowercase();
            Ok(SocketHost {
                dial_host: hostname.clone(),
                warmup_hostname: Some(hostname),
            })
        }
        _ => Err(format!(
            "{plugin_name}: '{field}' must be a valid hostname or IP address"
        )),
    }
}

impl SocketHost {
    /// Screen a literal-IP `dial_host` against the backend egress policy, so a
    /// socket log sink (tcp/udp/statsd) pointed at a denied address (e.g.
    /// `169.254.169.254`) is rejected at config-load time — these sinks dial
    /// their `host` directly rather than through the policy-screened HTTP
    /// client. A hostname (`warmup_hostname` set) is screened at resolution
    /// time by the DNS cache instead.
    pub fn screen_egress_ip(
        &self,
        plugin_name: &str,
        field: &str,
        backend_allow_ips: &crate::config::BackendEgressPolicy,
    ) -> Result<(), String> {
        if self.warmup_hostname.is_some() {
            return Ok(());
        }
        let Ok(ip) = self.dial_host.parse::<IpAddr>() else {
            return Ok(());
        };
        match backend_allow_ips.deny_reason(&ip) {
            None => Ok(()),
            Some(reason) => Err(format!(
                "{plugin_name}: '{field}' address {ip} is blocked by the backend egress \
                 policy ({reason}); refusing to send telemetry there. Adjust \
                 FERRUM_BACKEND_ALLOW_IPS / FERRUM_BACKEND_ALLOW_CIDRS or point the sink at \
                 an allowed address."
            )),
        }
    }
}

pub fn socket_addr_lookup_input(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::{SocketHost, parse_socket_host, socket_addr_lookup_input};

    #[test]
    fn parse_socket_host_normalizes_hostname_and_ips() {
        assert_eq!(
            parse_socket_host("test_plugin", "host", "LogSink.EXAMPLE.com").unwrap(),
            SocketHost {
                dial_host: "logsink.example.com".to_string(),
                warmup_hostname: Some("logsink.example.com".to_string())
            }
        );
        assert_eq!(
            parse_socket_host("test_plugin", "host", "[2001:db8::10]").unwrap(),
            SocketHost {
                dial_host: "2001:db8::10".to_string(),
                warmup_hostname: None
            }
        );
        assert_eq!(
            parse_socket_host("test_plugin", "host", "127.0.0.1").unwrap(),
            SocketHost {
                dial_host: "127.0.0.1".to_string(),
                warmup_hostname: None
            }
        );
    }

    #[test]
    fn parse_socket_host_rejects_url_and_port_material() {
        for host in [
            "http://logs.example.com",
            "user@logs.example.com",
            "logs.example.com/path",
            "logs.example.com?token=secret",
            "logs.example.com#frag",
            "logs.example.com:9000",
            "[logs.example.com]",
            "bad host",
        ] {
            assert!(
                parse_socket_host("test_plugin", "host", host).is_err(),
                "{host} should be rejected"
            );
        }
    }

    #[test]
    fn socket_addr_lookup_input_brackets_ipv6() {
        assert_eq!(
            socket_addr_lookup_input("2001:db8::10", 5140),
            "[2001:db8::10]:5140"
        );
        assert_eq!(
            socket_addr_lookup_input("logs.example.com", 5140),
            "logs.example.com:5140"
        );
    }
}
