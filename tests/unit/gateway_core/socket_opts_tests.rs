//! Unit tests for platform-specific socket optimizations.
//!
//! The non-Linux stubs all return fixed values (Ok, None, false, Unsupported).
//! These tests verify that every public function is callable and returns the
//! expected stub value on macOS / non-Linux, and that platform-independent
//! functions (monotonic_now_ms, connect_with_socket_opts) work correctly on all
//! platforms.

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

// ── PktinfoLocal::send_ifindex ─────────────────────────────────────────
//
// The captured `ifindex` is a RECEIVE-side fact (which interface the datagram
// arrived on) and is what NodeWaypoint UDP source attribution is fenced by. In
// an OUTBOUND pktinfo cmsg the same field constrains egress route selection
// instead, so it may only be reused when the reply source address is a scoped
// IPv6 address whose zone is otherwise ambiguous. Every other reply keeps the
// pinned source address (`ipi_spec_dst` / `ipi6_addr`) and lets the route table
// pick the egress device.

fn pktinfo_local(ip: &str, ifindex: u32) -> PktinfoLocal {
    PktinfoLocal {
        ip: ip.parse().expect("valid IP literal"),
        ifindex,
    }
}

#[test]
fn send_ifindex_is_zero_for_ipv4_even_when_ingress_interface_is_known() {
    // Same-node pod ingress: the datagram arrived on the client pod's veth,
    // but the captured local destination is a node address that may live on a
    // different device. A nonzero IPv4 ifindex would make the kernel prefer
    // that device's primary address over the pinned reply source.
    assert_eq!(pktinfo_local("10.244.1.1", 17).send_ifindex(), 0);
    assert_eq!(pktinfo_local("172.18.0.3", 17).send_ifindex(), 0);
    assert_eq!(pktinfo_local("127.0.0.1", 1).send_ifindex(), 0);
}

#[test]
fn send_ifindex_is_zero_for_global_ipv6_reply_sources() {
    // Route-selected egress: a global source address is reachable through
    // whatever device the route table picks, which need not be the receive
    // interface.
    assert_eq!(pktinfo_local("fd00:10:244:1::1", 23).send_ifindex(), 0);
    assert_eq!(pktinfo_local("2001:db8::1", 23).send_ifindex(), 0);
    assert_eq!(pktinfo_local("::1", 1).send_ifindex(), 0);
}

#[test]
fn send_ifindex_is_preserved_for_link_local_ipv6_reply_sources() {
    // fe80::/10 is zone-ambiguous: without the interface index the kernel
    // cannot tell which link the source address belongs to.
    assert_eq!(pktinfo_local("fe80::1", 23).send_ifindex(), 23);
    assert_eq!(pktinfo_local("febf:ffff::1", 9).send_ifindex(), 9);
    // fec0::/10 is site-local (deprecated, not link-local) — not scoped by
    // interface index.
    assert_eq!(pktinfo_local("fec0::1", 9).send_ifindex(), 0);
}

#[test]
fn send_ifindex_is_preserved_for_interface_and_link_scoped_ipv6_multicast() {
    assert_eq!(pktinfo_local("ff01::1", 5).send_ifindex(), 5);
    assert_eq!(pktinfo_local("ff02::1", 5).send_ifindex(), 5);
    // Wider multicast scopes route normally.
    assert_eq!(pktinfo_local("ff05::1", 5).send_ifindex(), 0);
    assert_eq!(pktinfo_local("ff0e::1", 5).send_ifindex(), 0);
}

#[test]
fn send_ifindex_never_invents_an_interface() {
    // A capture that reported no ingress interface must not turn into one on
    // send for any address family or scope.
    assert_eq!(pktinfo_local("fe80::1", 0).send_ifindex(), 0);
    assert_eq!(pktinfo_local("ff02::1", 0).send_ifindex(), 0);
    assert_eq!(pktinfo_local("10.0.0.1", 0).send_ifindex(), 0);
}

#[test]
fn send_ifindex_does_not_disturb_the_captured_attribution_ifindex() {
    // The receive-side evidence NodeWaypoint attribution is fenced by stays
    // readable and unchanged after deriving the send-side value.
    let local = pktinfo_local("10.244.1.1", 42);
    assert_eq!(local.send_ifindex(), 0);
    assert_eq!(local.ifindex, 42);
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

// ── io_uring splice readiness wait (Linux, issue #7226) ────────────────

#[cfg(target_os = "linux")]
mod io_uring_readiness_wait {
    use ferrum_edge::socket_opts::io_uring_splice::wait_fd_ready;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    #[test]
    fn idle_descriptor_waits_until_the_deadline() {
        let (reader, _writer) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        assert!(!wait_fd_ready(reader.as_raw_fd(), libc::POLLIN, 50));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(45),
            "an idle relay must sleep until its deadline, not return at once: {waited:?}"
        );
    }

    #[test]
    fn arriving_data_wakes_the_wait_before_the_deadline() {
        let (reader, mut writer) = UnixStream::pair().expect("socket pair");
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            writer.write_all(b"x").expect("write");
            writer
        });
        let started = Instant::now();
        assert!(wait_fd_ready(reader.as_raw_fd(), libc::POLLIN, 10_000));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "readiness must wake the relay, not the deadline"
        );
        drop(sender.join().expect("sender"));
    }

    #[test]
    fn shutdown_wakes_a_waiting_relay() {
        let (reader, writer) = UnixStream::pair().expect("socket pair");
        let fd = reader.as_raw_fd();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            // The parent cancels a relay with shutdown(SHUT_RDWR).
            reader.shutdown(std::net::Shutdown::Both).expect("shutdown");
            (reader, writer)
        });
        let started = Instant::now();
        assert!(wait_fd_ready(fd, libc::POLLIN, 10_000));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(closer.join().expect("closer"));
    }

    #[test]
    fn writable_descriptor_is_ready_immediately() {
        let (_reader, writer) = UnixStream::pair().expect("socket pair");
        assert!(wait_fd_ready(writer.as_raw_fd(), libc::POLLOUT, 10_000));
    }
}
