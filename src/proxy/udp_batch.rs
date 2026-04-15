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

/// Pre-allocated buffers for batched UDP send via `sendmmsg(2)`.
///
/// Collects datagrams and their destination addresses, then flushes them all
/// in a single `sendmmsg` syscall. This reduces syscall overhead on the
/// backend→client reply path, mirroring the `recvmmsg` optimization on recv.
///
/// Only available on Linux. On other platforms, the UDP proxy falls back to
/// individual `send_to` calls.
#[cfg(target_os = "linux")]
pub struct SendMmsgBatch {
    /// Per-slot datagram buffers (data copied in on push).
    bufs: Vec<Vec<u8>>,
    /// Per-slot actual datagram length.
    lens: Vec<usize>,
    /// Per-slot destination addresses.
    dest_addrs: Vec<libc::sockaddr_storage>,
    /// Per-slot destination address lengths.
    dest_addr_lens: Vec<libc::socklen_t>,
    /// Pre-allocated iovec array (one per slot).
    iovecs: Vec<libc::iovec>,
    /// Pre-allocated mmsghdr array (one per slot).
    msgs: Vec<libc::mmsghdr>,
    /// Maximum datagrams per sendmmsg call.
    capacity: usize,
    /// Number of datagrams queued for the next flush.
    count: usize,
}

// SAFETY: Same reasoning as RecvMmsgBatch — raw pointers in iovecs/msgs point
// into Vec buffers owned by the same struct, only dereferenced inside flush()
// which rebuilds them first. Exclusively owned by a single tokio task.
#[cfg(target_os = "linux")]
unsafe impl Send for SendMmsgBatch {}

#[cfg(target_os = "linux")]
impl SendMmsgBatch {
    /// Create a new send batch with pre-allocated buffers for `capacity` datagrams.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            bufs: (0..capacity).map(|_| vec![0u8; MAX_DGRAM_SIZE]).collect(),
            lens: vec![0usize; capacity],
            dest_addrs: vec![unsafe { std::mem::zeroed() }; capacity],
            dest_addr_lens: vec![0; capacity],
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

    /// Queue a datagram for batched sending. Returns `false` if the batch is full.
    pub fn push(&mut self, data: &[u8], dest: SocketAddr) -> bool {
        if self.count >= self.capacity {
            return false;
        }
        let i = self.count;
        let len = data.len().min(MAX_DGRAM_SIZE);
        self.bufs[i][..len].copy_from_slice(&data[..len]);
        self.lens[i] = len;
        let (addr, addr_len) = std_to_sockaddr_storage(dest);
        self.dest_addrs[i] = addr;
        self.dest_addr_lens[i] = addr_len;
        self.count += 1;
        true
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Send all queued datagrams in a single `sendmmsg` syscall.
    ///
    /// Returns the number of datagrams successfully sent. On partial send,
    /// the caller should handle the unsent remainder (or accept the loss for
    /// UDP best-effort semantics).
    ///
    /// Resets the batch count to 0 after the call.
    pub fn flush(&mut self, fd: std::os::fd::RawFd) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }

        // Rebuild pointer arrays before the syscall.
        for i in 0..self.count {
            self.iovecs[i] = libc::iovec {
                iov_base: self.bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: self.lens[i],
            };

            self.msgs[i] = unsafe { std::mem::zeroed() };
            self.msgs[i].msg_hdr.msg_name =
                std::ptr::addr_of_mut!(self.dest_addrs[i]) as *mut libc::c_void;
            self.msgs[i].msg_hdr.msg_namelen = self.dest_addr_lens[i];
            self.msgs[i].msg_hdr.msg_iov = std::ptr::addr_of_mut!(self.iovecs[i]);
            self.msgs[i].msg_hdr.msg_iovlen = 1;
        }

        let ret = unsafe {
            libc::sendmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.count as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            self.count = 0;
            return Err(err);
        }

        let sent = ret as usize;
        let remaining = self.count - sent;
        if remaining > 0 {
            // Shift unsent datagrams to the front so a retry sends them.
            for i in 0..remaining {
                self.bufs.swap(i, sent + i);
                self.lens[i] = self.lens[sent + i];
                self.dest_addrs[i] = self.dest_addrs[sent + i];
                self.dest_addr_lens[i] = self.dest_addr_lens[sent + i];
            }
        }
        self.count = remaining;
        Ok(sent)
    }
}

/// Convert a `std::net::SocketAddr` to `libc::sockaddr_storage` + length.
///
/// Public alias for use by `flush_gso_batch()` in `udp_proxy.rs`.
#[cfg(target_os = "linux")]
pub fn std_to_sockaddr_storage_pub(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    std_to_sockaddr_storage(addr)
}

/// Convert a `std::net::SocketAddr` to `libc::sockaddr_storage` + length.
#[cfg(target_os = "linux")]
fn std_to_sockaddr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits within sockaddr_storage.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const libc::sockaddr_in as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const libc::sockaddr_in6 as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
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

/// Non-Linux stub for SendMmsgBatch.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub struct SendMmsgBatch;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl SendMmsgBatch {
    pub fn new(_capacity: usize) -> Self {
        Self
    }
}

/// GSO batch buffer for sending multiple same-size datagrams in a single `sendmsg()`
/// with `UDP_SEGMENT` ancillary data (Linux 4.18+).
///
/// Concatenates consecutive same-size datagrams into a contiguous buffer and flushes
/// via `send_with_gso()` or `send_with_gso_connected()`. When a different-size datagram
/// arrives, the current batch is flushed and a new batch starts. This is complementary
/// to `SendMmsgBatch` — GSO provides kernel-level segmentation which is more efficient
/// than `sendmmsg` when datagrams share the same size and destination.
///
/// Only available on Linux. On other platforms, the UDP proxy falls back to `SendMmsgBatch`
/// or individual sends.
#[cfg(target_os = "linux")]
pub struct GsoBatchBuf {
    /// Contiguous buffer holding concatenated same-size datagrams.
    buf: Vec<u8>,
    /// Segment size of datagrams currently in the buffer (0 = empty).
    segment_size: usize,
    /// Number of datagrams currently in the buffer.
    count: usize,
    /// Maximum bytes to accumulate before auto-flushing.
    /// Kernel GSO limit is typically 64KB (~65535 bytes).
    max_bytes: usize,
}

#[cfg(target_os = "linux")]
impl GsoBatchBuf {
    /// Create a new GSO batch buffer.
    ///
    /// `max_bytes` caps the concatenated buffer size. The kernel GSO path
    /// has a ~64KB limit per sendmsg, so 65535 is a safe maximum.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(max_bytes.min(65535)),
            segment_size: 0,
            count: 0,
            max_bytes: max_bytes.min(65535),
        }
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Try to append a datagram. Returns `false` if the datagram has a different
    /// size than the current batch or the buffer would exceed `max_bytes`, meaning
    /// the caller should flush first and then call `push` again.
    pub fn push(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true; // skip empty datagrams
        }
        if self.count == 0 {
            // First datagram — set segment size.
            self.segment_size = data.len();
            self.buf.clear();
            self.buf.extend_from_slice(data);
            self.count = 1;
            return true;
        }
        // Same size check: GSO requires all segments to be the same size
        // (the last segment may be shorter, but we only batch exact matches
        // for simplicity and correctness).
        if data.len() != self.segment_size {
            return false; // different size — caller should flush first
        }
        if self.buf.len() + data.len() > self.max_bytes {
            return false; // would exceed max — caller should flush first
        }
        self.buf.extend_from_slice(data);
        self.count += 1;
        true
    }

    /// Flush the buffer via GSO sendmsg to a specific destination address.
    ///
    /// Uses `send_with_gso()` which includes the destination in the msghdr.
    /// Falls back to nothing on error — caller handles errors.
    pub fn flush_to(
        &mut self,
        fd: std::os::fd::RawFd,
        dest: &libc::sockaddr_storage,
        dest_len: libc::socklen_t,
    ) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }
        let result = crate::socket_opts::send_with_gso(
            fd,
            &self.buf,
            self.segment_size as u16,
            dest,
            dest_len,
        );
        let sent_count = self.count;
        self.buf.clear();
        self.count = 0;
        self.segment_size = 0;
        result.map(|_| sent_count)
    }

    /// Flush the buffer via GSO sendmsg on a connected socket (no destination needed).
    pub fn flush_connected(&mut self, fd: std::os::fd::RawFd) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }
        let result =
            crate::socket_opts::send_with_gso_connected(fd, &self.buf, self.segment_size as u16);
        let sent_count = self.count;
        self.buf.clear();
        self.count = 0;
        self.segment_size = 0;
        result.map(|_| sent_count)
    }

    /// Reset the buffer without sending (e.g., on error fallback).
    pub fn clear(&mut self) {
        self.buf.clear();
        self.count = 0;
        self.segment_size = 0;
    }
}

/// Non-Linux stub for GsoBatchBuf.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub struct GsoBatchBuf;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl GsoBatchBuf {
    pub fn new(_max_bytes: usize) -> Self {
        Self
    }
}
