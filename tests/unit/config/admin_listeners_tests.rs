use ferrum_edge::config::EnvConfig;

#[test]
fn admin_listener_defaults_use_distinct_http_and_https_ports() {
    let config = EnvConfig::default();

    assert_eq!(config.admin_http_port, 9000);
    assert_eq!(config.admin_https_port, 9443);
    assert_ne!(config.admin_http_port, config.admin_https_port);

    let reserved = config.reserved_gateway_ports();
    assert!(reserved.contains(&config.admin_http_port));
    assert!(reserved.contains(&config.admin_https_port));
}

#[test]
fn admin_socket_addr_uses_admin_bind_address_not_proxy_bind_address() {
    let config = EnvConfig {
        proxy_bind_address: "127.0.0.1".to_string(),
        admin_bind_address: "127.0.0.2".to_string(),
        ..Default::default()
    };

    assert_eq!(
        config.proxy_socket_addr(config.proxy_http_port).to_string(),
        "127.0.0.1:8000"
    );
    assert_eq!(
        config.admin_socket_addr(config.admin_http_port).to_string(),
        "127.0.0.2:9000"
    );
}

#[test]
fn disabled_admin_listener_ports_do_not_reserve_port_zero() {
    let config = EnvConfig {
        admin_http_port: 0,
        admin_https_port: 0,
        ..Default::default()
    };

    let reserved = config.reserved_gateway_ports();
    assert!(!reserved.contains(&0));
    assert!(!reserved.contains(&9000));
    assert!(!reserved.contains(&9443));
    assert!(reserved.contains(&config.proxy_http_port));
    assert!(reserved.contains(&config.proxy_https_port));
}

#[test]
fn cp_grpc_listener_port_is_reserved_when_configured() {
    let config = EnvConfig {
        cp_grpc_listen_addr: Some("0.0.0.0:50051".to_string()),
        ..Default::default()
    };

    let reserved = config.reserved_gateway_ports();
    assert!(reserved.contains(&50051));
}
