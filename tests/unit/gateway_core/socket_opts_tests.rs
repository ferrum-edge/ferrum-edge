//! Unit tests for platform-specific socket optimizations.
//!
//! The non-Linux stubs all return fixed values (Ok, None, false, Unsupported).
//! These tests verify that every public function is callable and returns the
//! expected stub value on macOS / non-Linux, and that platform-independent
//! functions (monotonic_now_ms, TcpConnectionInfo::bdp_bytes,
//! connect_with_socket_opts) work correctly on all platforms.

use ferrum_edge::socket_opts::*;

// ── monotonic_now_ms (platform-independent) ────────────────────────────

#[test]
fn monotonic_now_ms_returns_value() {
    let t = monotonic_now_ms();
    // First call initializes the OnceLock anchor; result is >= 0.
    assert!(t < u64::MAX);
}

#[test]
fn monotonic_now_ms_is_monotonic() {
    let t1 = monotonic_now_ms();
    // Burn a small amount of wall time so the clock advances.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let t2 = monotonic_now_ms();
    assert!(t2 >= t1, "monotonic clock must not go backwards");
}

#[test]
fn monotonic_now_ms_advances_with_time() {
    let t1 = monotonic_now_ms();
    std::thread::sleep(std::time::Duration::from_millis(15));
    let t2 = monotonic_now_ms();
    assert!(
        t2 - t1 >= 10,
        "expected at least 10ms elapsed, got {}ms",
        t2 - t1
    );
}

// ── TcpConnectionInfo::bdp_bytes (platform-independent) ────────────────

#[test]
fn bdp_bytes_normal_values() {
    let info = TcpConnectionInfo {
        rtt_us: 10_000, // 10ms
        snd_cwnd: 10,   // 10 segments
        snd_mss: 1460,  // typical MSS
    };
    // BDP = cwnd * mss = 10 * 1460 = 14600
    assert_eq!(info.bdp_bytes(), 14_600);
}

#[test]
fn bdp_bytes_zero_rtt_returns_zero() {
    let info = TcpConnectionInfo {
        rtt_us: 0,
        snd_cwnd: 10,
        snd_mss: 1460,
    };
    assert_eq!(info.bdp_bytes(), 0);
}

#[test]
fn bdp_bytes_zero_cwnd_returns_zero() {
    let info = TcpConnectionInfo {
        rtt_us: 10_000,
        snd_cwnd: 0,
        snd_mss: 1460,
    };
    assert_eq!(info.bdp_bytes(), 0);
}

#[test]
fn bdp_bytes_zero_mss_returns_zero() {
    let info = TcpConnectionInfo {
        rtt_us: 10_000,
        snd_cwnd: 10,
        snd_mss: 0,
    };
    assert_eq!(info.bdp_bytes(), 0);
}

#[test]
fn bdp_bytes_does_not_panic_on_large_values() {
    let info = TcpConnectionInfo {
        rtt_us: 1,
        snd_cwnd: u32::MAX,
        snd_mss: u32::MAX,
    };
    // saturating_mul prevents panic; on 64-bit the product fits in usize
    let bdp = info.bdp_bytes();
    assert!(bdp > 0);
    assert_eq!(bdp, (u32::MAX as usize).saturating_mul(u32::MAX as usize));
}

#[test]
fn bdp_bytes_large_realistic_values() {
    let info = TcpConnectionInfo {
        rtt_us: 100_000, // 100ms transatlantic
        snd_cwnd: 500,   // large window
        snd_mss: 1460,
    };
    // 500 * 1460 = 730_000 bytes ~= 712 KB
    assert_eq!(info.bdp_bytes(), 730_000);
}

// ── Non-Linux socket option stubs ──────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod non_linux_stubs {
    use super::*;

    #[test]
    fn set_ip_bind_address_no_port_noop() {
        assert!(set_ip_bind_address_no_port(0, true).is_ok());
        assert!(set_ip_bind_address_no_port(0, false).is_ok());
    }

    #[test]
    fn set_tcp_fastopen_server_noop() {
        assert!(set_tcp_fastopen_server(0, 256).is_ok());
        assert!(set_tcp_fastopen_server(0, 0).is_ok());
    }

    #[test]
    fn set_tcp_fastopen_client_noop() {
        assert!(set_tcp_fastopen_client(0).is_ok());
    }

    #[test]
    fn get_tcp_info_returns_none() {
        assert!(get_tcp_info(0).is_none());
    }

    #[test]
    fn set_so_busy_poll_noop() {
        assert!(set_so_busy_poll(0, 50).is_ok());
        assert!(set_so_busy_poll(0, 0).is_ok());
    }

    #[test]
    fn set_so_prefer_busy_poll_noop() {
        assert!(set_so_prefer_busy_poll(0, true).is_ok());
        assert!(set_so_prefer_busy_poll(0, false).is_ok());
    }

    #[test]
    fn set_udp_gro_noop() {
        assert!(set_udp_gro(0, true).is_ok());
        assert!(set_udp_gro(0, false).is_ok());
    }

    #[test]
    fn send_with_gso_returns_unsupported() {
        let result = send_with_gso(0, b"data", 4, &(), 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn extract_gro_segment_size_returns_none() {
        assert!(extract_gro_segment_size(&()).is_none());
    }

    #[test]
    fn set_ip_pktinfo_noop() {
        assert!(set_ip_pktinfo(0).is_ok());
    }

    #[test]
    fn set_ipv6_recvpktinfo_noop() {
        assert!(set_ipv6_recvpktinfo(0).is_ok());
    }

    #[test]
    fn extract_pktinfo_local_addr_returns_none() {
        assert!(extract_pktinfo_local_addr(&()).is_none());
    }

    #[test]
    fn send_with_pktinfo_returns_unsupported() {
        let local = PktinfoLocal {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ifindex: 0,
        };
        let result = send_with_pktinfo(0, b"data", local, &(), 0, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn is_udp_pktinfo_available_returns_false() {
        assert!(!is_udp_pktinfo_available());
    }

    // ── Availability probes ────────────────────────────────────────────

    #[test]
    fn is_tcp_fastopen_available_returns_false() {
        assert!(!is_tcp_fastopen_available());
    }

    #[test]
    fn is_udp_gro_available_returns_false() {
        assert!(!is_udp_gro_available());
    }

    #[test]
    fn is_udp_gso_available_returns_false() {
        assert!(!is_udp_gso_available());
    }

    // ── kTLS stubs ─────────────────────────────────────────────────────

    #[test]
    fn ktls_enable_returns_false() {
        use zeroize::Zeroizing;
        let params = ktls::KtlsParams {
            tls_version: 0x0303,
            cipher_suite: ktls::KtlsCipher::Aes128Gcm,
            tx_key: Zeroizing::new(vec![0u8; 16]),
            tx_iv: Zeroizing::new(vec![0u8; 12]),
            tx_seq: [0u8; 8],
            rx_key: Zeroizing::new(vec![0u8; 16]),
            rx_iv: Zeroizing::new(vec![0u8; 12]),
            rx_seq: [0u8; 8],
        };
        assert!(!ktls::enable_ktls(0, &params).unwrap());
    }

    #[test]
    fn ktls_availability_all_false() {
        assert!(!ktls::is_ktls_available());
        assert!(!ktls::is_ktls_aes128gcm_available());
        assert!(!ktls::is_ktls_aes256gcm_available());
        assert!(!ktls::is_ktls_chacha20_poly1305_available());
    }

    // ── io_uring stubs ─────────────────────────────────────────────────

    #[test]
    fn io_uring_check_returns_false() {
        assert!(!io_uring_splice::check_io_uring_available());
    }

    #[test]
    fn io_uring_splice_loop_returns_unsupported() {
        let activity = std::sync::atomic::AtomicU64::new(0);
        let result =
            io_uring_splice::io_uring_splice_loop(0, 0, 0, 0, &activity, 1000, None, 0, None, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.is_write_side);
        assert_eq!(err.bytes_so_far, 0);
        assert_eq!(err.source.kind(), std::io::ErrorKind::Unsupported);
    }
}

// ── PktinfoLocal ───────────────────────────────────────────────────────

#[test]
fn pktinfo_local_equality() {
    let a = PktinfoLocal {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ifindex: 2,
    };
    let b = PktinfoLocal {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ifindex: 2,
    };
    assert_eq!(a, b);
}

#[test]
fn pktinfo_local_inequality_ip() {
    let a = PktinfoLocal {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ifindex: 2,
    };
    let b = PktinfoLocal {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
        ifindex: 2,
    };
    assert_ne!(a, b);
}

#[test]
fn pktinfo_local_inequality_ifindex() {
    let a = PktinfoLocal {
        ip: std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ifindex: 1,
    };
    let b = PktinfoLocal {
        ip: std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ifindex: 2,
    };
    assert_ne!(a, b);
}

#[test]
fn pktinfo_local_debug_format() {
    let p = PktinfoLocal {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        ifindex: 0,
    };
    let dbg = format!("{:?}", p);
    assert!(dbg.contains("127.0.0.1"));
    assert!(dbg.contains("ifindex: 0"));
}

// ── connect_with_socket_opts (platform-independent, async) ─────────────

#[tokio::test]
async fn connect_with_socket_opts_connects_to_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let stream = connect_with_socket_opts(addr).await.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), addr);
}

#[tokio::test]
async fn connect_with_socket_opts_and_zero_mark_connects_to_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let stream = connect_with_socket_opts_and_mark(addr, Some(0))
        .await
        .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), addr);
}

#[tokio::test]
async fn connect_with_socket_opts_ipv6_loopback() {
    // Bind on IPv6 loopback — skip if OS doesn't support it.
    let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
        Ok(l) => l,
        Err(_) => return, // IPv6 not available
    };
    let addr = listener.local_addr().unwrap();

    let stream = connect_with_socket_opts(addr).await.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), addr);
}

#[tokio::test]
async fn connect_with_socket_opts_refuses_unreachable() {
    // Port 1 on loopback requires root and is never listening in CI.
    // No bind-drop-rebind race since we never held the port.
    let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let result = connect_with_socket_opts(addr).await;
    assert!(result.is_err());
}
