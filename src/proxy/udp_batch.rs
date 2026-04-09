//! Batched UDP receive using `recvmmsg(2)` on Linux.
//!
//! Receives multiple datagrams in a single kernel crossing, reducing syscall
//! overhead for high-throughput UDP proxy workloads. On non-Linux platforms,
//! this module provides a no-op stub (the UDP proxy falls back to individual
//! `try_recv_from` calls via the `#[cfg]` gate at the call site).
//!
//! **Performance impact**: Each `recvfrom` call (what `try_recv_from` does
//! internally) is a separate syscall. At 100K+ datagrams/sec, syscall overhead
//! dominates. `recvmmsg` amortizes a single kernel crossing across up to N
//! datagrams, matching the approach Envoy uses via kernel-level GRO.
//!
//! **Default batch size**: 64 datagrams per `recvmmsg` call. Configurable via
//! `FERRUM_UDP_RECVMMSG_BATCH_SIZE`. The drain loop calls `recvmmsg` repeatedly
//! up to the adaptive `batch_limit`, so total datagrams drained per cycle can
//! exceed the batch size.

#[cfg(target_os = "linux")]
use std::net::SocketAddr;

/// Pre-allocated buffers for batched UDP receive via `recvmmsg(2)`.
///
/// Allocates `batch_size` datagram buffers (each `MAX_DGRAM_SIZE` bytes),
/// plus the corresponding `iovec`, `mmsghdr`, and `sockaddr_storage` arrays.
/// All memory is allocated once at listener startup and reused across calls.
///
/// Only available on Linux. On other platforms, the UDP proxy uses the
/// existing `try_recv_from` drain loop with no change in behavior.
#[cfg(target_os = "linux")]
pub struct RecvMmsgBatch {
    /// Per-slot datagram buffers. Each is MAX_DGRAM_SIZE bytes.
    bufs: Vec<Vec<u8>>,
    /// Per-slot source addresses (converted from sockaddr_storage after recv).
    result_addrs: Vec<SocketAddr>,
    /// Per-slot received datagram lengths (from mmsghdr.msg_len).
    result_lens: Vec<u32>,
    /// Pre-allocated sockaddr_storage for recvmmsg (kernel writes source addrs here).
    raw_addrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated iovec array (one per slot, pointing into bufs).
    iovecs: Vec<libc::iovec>,
    /// Pre-allocated mmsghdr array (one per slot).
    msgs: Vec<libc::mmsghdr>,
    /// Maximum datagrams per recvmmsg call.
    capacity: usize,
    /// Number of datagrams received in the last `recv()` call.
    count: usize,
}

#[cfg(target_os = "linux")]
const MAX_DGRAM_SIZE: usize = 65535;

// SAFETY: The raw pointers in `iovecs` (`*mut c_void`) and `msgs` (`*mut iovec`)
// point into `Vec` buffers owned by the same struct. They are only dereferenced
// inside `recv()` which rebuilds them from scratch before each `recvmmsg` call.
// The struct is exclusively owned by a single tokio task (the UDP listener loop).
#[cfg(target_os = "linux")]
unsafe impl Send for RecvMmsgBatch {}

#[cfg(target_os = "linux")]
impl RecvMmsgBatch {
    /// Create a new batch with pre-allocated buffers for `capacity` datagrams.
    ///
    /// Allocates `capacity * 65535` bytes for datagram buffers plus bookkeeping
    /// arrays. This is a one-time allocation at listener startup.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            bufs: (0..capacity).map(|_| vec![0u8; MAX_DGRAM_SIZE]).collect(),
            result_addrs: vec![SocketAddr::from(([0, 0, 0, 0], 0)); capacity],
            result_lens: vec![0u32; capacity],
            raw_addrs: vec![unsafe { std::mem::zeroed() }; capacity],
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                capacity
            ],
            msgs: vec![unsafe { std::mem::zeroed() }; capacity],
            capacity,
            count: 0,
        }
    }

    /// Maximum datagrams this batch can receive in a single call.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the datagram data and source address for slot `i`.
    ///
    /// # Panics
    /// Panics (debug) if `i` is out of bounds.
    pub fn datagram(&self, i: usize) -> (&[u8], SocketAddr) {
        debug_assert!(i < self.count);
        (
            &self.bufs[i][..self.result_lens[i] as usize],
            self.result_addrs[i],
        )
    }

    /// Receive up to `max_count` datagrams in a single `recvmmsg` syscall.
    ///
    /// Uses `MSG_DONTWAIT` for non-blocking operation. Returns `Ok(n)` where
    /// `n > 0` on success, or `Err` with `ErrorKind::WouldBlock` when no data
    /// is available (socket drained).
    ///
    /// After a successful call, use `count()` and `datagram(i)` to iterate
    /// the received datagrams.
    ///
    /// # Safety
    /// Calls `libc::recvmmsg` which writes into pre-allocated buffers via raw
    /// pointers. Safe because:
    /// - Buffers (`bufs`) are heap-allocated Vecs that don't move or resize
    /// - Pointer arrays (`iovecs`, `msgs`, `raw_addrs`) are rebuilt before each call
    /// - The batch outlives the syscall (no dangling pointers)
    pub fn recv(&mut self, fd: std::os::fd::RawFd, max_count: usize) -> std::io::Result<usize> {
        let n = max_count.min(self.capacity);
        if n == 0 {
            self.count = 0;
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }

        // Rebuild pointer arrays. This is cheap (N pointer writes) and avoids
        // self-referential struct issues.
        for i in 0..n {
            self.raw_addrs[i] = unsafe { std::mem::zeroed() };

            self.iovecs[i] = libc::iovec {
                iov_base: self.bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: MAX_DGRAM_SIZE,
            };

            self.msgs[i] = unsafe { std::mem::zeroed() };
            self.msgs[i].msg_hdr.msg_name =
                std::ptr::addr_of_mut!(self.raw_addrs[i]) as *mut libc::c_void;
            self.msgs[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            self.msgs[i].msg_hdr.msg_iov = std::ptr::addr_of_mut!(self.iovecs[i]);
            self.msgs[i].msg_hdr.msg_iovlen = 1;
        }

        // Single syscall to receive up to n datagrams.
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(), // no timeout
            )
        };

        if ret < 0 {
            self.count = 0;
            return Err(std::io::Error::last_os_error());
        }

        let received = ret as usize;
        for i in 0..received {
            self.result_lens[i] = self.msgs[i].msg_len;
            self.result_addrs[i] = sockaddr_storage_to_std(&self.raw_addrs[i])?;
        }
        self.count = received;
        Ok(received)
    }
}

/// Convert a `libc::sockaddr_storage` to `std::net::SocketAddr`.
#[cfg(target_os = "linux")]
fn sockaddr_storage_to_std(addr: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            let a = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))),
                u16::from_be(a.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        family => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported address family: {}", family),
        )),
    }
}

/// Stub for non-Linux platforms. Compile-time no-op. The UDP proxy drain loop
/// is gated with `#[cfg(target_os = "linux")]` and falls back to `try_recv_from`.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub struct RecvMmsgBatch;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl RecvMmsgBatch {
    pub fn new(_capacity: usize) -> Self {
        Self
    }
}
