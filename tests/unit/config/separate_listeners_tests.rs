use ferrum_edge::config::EnvConfig;

#[test]
fn proxy_listener_defaults_use_distinct_http_and_https_ports() {
    let config = EnvConfig::default();

    assert_eq!(config.proxy_http_port, 8000);
    assert_eq!(config.proxy_https_port, 8443);
    assert_ne!(config.proxy_http_port, config.proxy_https_port);

    let reserved = config.reserved_gateway_ports();
    assert!(reserved.contains(&config.proxy_http_port));
    assert!(reserved.contains(&config.proxy_https_port));
}

#[test]
fn proxy_socket_addr_uses_proxy_bind_address_for_each_listener_port() {
    let mut config = EnvConfig {
        proxy_bind_address: "127.0.0.1".to_string(),
        ..Default::default()
    };

    let http_addr = config.proxy_socket_addr(config.proxy_http_port);
    assert_eq!(http_addr.to_string(), "127.0.0.1:8000");

    config.proxy_https_port = 18443;
    let https_addr = config.proxy_socket_addr(config.proxy_https_port);
    assert_eq!(https_addr.to_string(), "127.0.0.1:18443");
}

#[test]
fn disabled_proxy_listener_ports_are_not_reserved() {
    let config = EnvConfig {
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        ..Default::default()
    };

    let reserved = config.reserved_gateway_ports();
    assert!(!reserved.contains(&0));
    assert!(reserved.is_empty());
}
