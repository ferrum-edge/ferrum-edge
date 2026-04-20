use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::http3::config::Http3ServerConfig;

#[test]
fn test_http3_server_config_default_values() {
    let config = Http3ServerConfig::default();

    assert_eq!(config.max_concurrent_streams, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(config.stream_receive_window, 8_388_608); // 8 MiB
    assert_eq!(config.receive_window, 33_554_432); // 32 MiB
    assert_eq!(config.send_window, 8_388_608); // 8 MiB
    assert_eq!(config.initial_mtu, 1500);
}

#[test]
fn test_http3_server_config_initial_mtu_from_env() {
    let env = EnvConfig {
        http3_initial_mtu: 1350,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);
    assert_eq!(config.initial_mtu, 1350);
}

#[test]
fn test_http3_server_config_from_env_config_defaults() {
    // EnvConfig::default() should produce the same values as Http3ServerConfig::default()
    let env = EnvConfig::default();
    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(config.stream_receive_window, 8_388_608);
    assert_eq!(config.receive_window, 33_554_432);
    assert_eq!(config.send_window, 8_388_608);
}

#[test]
fn test_http3_server_config_from_env_config_custom_values() {
    let env = EnvConfig {
        http3_max_streams: 500,
        http3_idle_timeout: 60,
        http3_stream_receive_window: 4_194_304, // 4 MiB
        http3_receive_window: 16_777_216,       // 16 MiB
        http3_send_window: 2_097_152,           // 2 MiB
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 500);
    assert_eq!(config.idle_timeout, Duration::from_secs(60));
    assert_eq!(config.stream_receive_window, 4_194_304);
    assert_eq!(config.receive_window, 16_777_216);
    assert_eq!(config.send_window, 2_097_152);
}

#[test]
fn test_http3_server_config_from_env_config_zero_idle_timeout() {
    let env = EnvConfig {
        http3_idle_timeout: 0,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.idle_timeout, Duration::from_secs(0));
}

#[test]
fn test_http3_server_config_from_env_config_large_windows() {
    let env = EnvConfig {
        http3_stream_receive_window: 128 * 1024 * 1024, // 128 MiB
        http3_receive_window: 512 * 1024 * 1024,        // 512 MiB
        http3_send_window: 64 * 1024 * 1024,            // 64 MiB
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.stream_receive_window, 128 * 1024 * 1024);
    assert_eq!(config.receive_window, 512 * 1024 * 1024);
    assert_eq!(config.send_window, 64 * 1024 * 1024);
}

#[test]
fn test_http3_server_config_from_env_config_min_streams() {
    let env = EnvConfig {
        http3_max_streams: 1,
        ..Default::default()
    };

    let config = Http3ServerConfig::from_env_config(&env);

    assert_eq!(config.max_concurrent_streams, 1);
}
