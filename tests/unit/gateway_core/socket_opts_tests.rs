//! Unit tests for platform-specific socket optimizations.

use ferrum_edge::socket_opts::*;

#[test]
fn test_tcp_connection_info_bdp() {
    let info = TcpConnectionInfo {
        rtt_us: 1000, // 1ms RTT
        rtt_var_us: 200,
        snd_cwnd: 10,  // 10 segments
        snd_mss: 1460, // Standard MSS
        total_retrans: 0,
    };
    assert_eq!(info.bdp_bytes(), 14600); // 10 * 1460
}

#[test]
fn test_tcp_connection_info_bdp_zero_cwnd() {
    let info = TcpConnectionInfo {
        rtt_us: 5000,
        rtt_var_us: 500,
        snd_cwnd: 0,
        snd_mss: 1460,
        total_retrans: 0,
    };
    assert_eq!(info.bdp_bytes(), 0);
}

#[test]
fn test_tcp_connection_info_debug() {
    let info = TcpConnectionInfo {
        rtt_us: 1000,
        rtt_var_us: 200,
        snd_cwnd: 10,
        snd_mss: 1460,
        total_retrans: 5,
    };
    let debug = format!("{:?}", info);
    assert!(debug.contains("rtt_us: 1000"));
    assert!(debug.contains("total_retrans: 5"));
}

#[test]
fn test_tcp_connection_info_clone() {
    let info = TcpConnectionInfo {
        rtt_us: 2000,
        rtt_var_us: 400,
        snd_cwnd: 20,
        snd_mss: 1460,
        total_retrans: 3,
    };
    let cloned = info.clone();
    assert_eq!(cloned.rtt_us, 2000);
    assert_eq!(cloned.bdp_bytes(), 29200);
}

// Non-Linux platforms always return None
#[cfg(not(target_os = "linux"))]
#[test]
fn test_get_tcp_info_non_linux_returns_none() {
    assert!(get_tcp_info(0).is_none());
}

// Non-Linux no-ops
#[cfg(not(target_os = "linux"))]
#[test]
fn test_socket_opts_noop_on_non_linux() {
    assert!(set_ip_bind_address_no_port(0, true).is_ok());
    assert!(set_tcp_fastopen_server(0, 256).is_ok());
    assert!(set_tcp_fastopen_client(0).is_ok());
}
