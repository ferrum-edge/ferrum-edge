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
    /// Per-slot cmsg buffers sized for UDP_GRO + IP_PKTINFO / IPV6_PKTINFO.
    /// A single allocation large enough for the worst-case (v6) so both v4
    /// and v6 datagrams land in the same buffer without a resize.
    cmsg_bufs: Vec<Vec<u8>>,
    /// Per-slot GRO segment size parsed from cmsg after recvmmsg.
    /// `None` = single datagram (no GRO coalescing), `Some(n)` = coalesced with segment size n.
    gro_segments: Vec<Option<u16>>,
    /// Per-slot local destination address (from IP(v6)_PKTINFO cmsg). When the
    /// frontend socket has pktinfo enabled, this carries the address the client
    /// targeted on a wildcard bind and is reused as the reply source address so
    /// the kernel can skip the routing-table lookup on send.
    local_addrs: Vec<Option<std::net::IpAddr>>,
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
        // cmsg buffer must hold UDP_GRO (u16) + IP_PKTINFO / IPV6_PKTINFO in the
        // same allocation; sized for the v6 worst case so both families fit.
        let cmsg_space = crate::socket_opts::recv_cmsg_space();
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
            cmsg_bufs: (0..capacity).map(|_| vec![0u8; cmsg_space]).collect(),
            gro_segments: vec![None; capacity],
            local_addrs: vec![None; capacity],
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

    /// Returns the GRO segment size for slot `i`, if the kernel coalesced
    /// multiple datagrams into one buffer via UDP_GRO.
    ///
    /// Returns `None` for single (non-coalesced) datagrams.
    /// When `Some(seg_size)`, the datagram data should be split into
    /// `seg_size`-byte chunks (the last chunk may be shorter).
    pub fn gro_segment_size(&self, i: usize) -> Option<u16> {
        debug_assert!(i < self.count);
        self.gro_segments[i]
    }

    /// Returns the local destination address for slot `i`, parsed from the
    /// IP(v6)_PKTINFO cmsg. `None` when pktinfo is disabled or the socket is
    /// not wildcard-bound. Used as the reply source address on send to skip
    /// the kernel routing lookup.
    pub fn local_addr(&self, i: usize) -> Option<std::net::IpAddr> {
        debug_assert!(i < self.count);
        self.local_addrs[i]
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

            // Zero the cmsg buffer for GRO metadata.
            self.cmsg_bufs[i].fill(0);

            self.msgs[i] = unsafe { std::mem::zeroed() };
            self.msgs[i].msg_hdr.msg_name =
                std::ptr::addr_of_mut!(self.raw_addrs[i]) as *mut libc::c_void;
            self.msgs[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            self.msgs[i].msg_hdr.msg_iov = std::ptr::addr_of_mut!(self.iovecs[i]);
            self.msgs[i].msg_hdr.msg_iovlen = 1;
            // Attach cmsg buffer for GRO segment size metadata.
            self.msgs[i].msg_hdr.msg_control = self.cmsg_bufs[i].as_mut_ptr() as *mut libc::c_void;
            self.msgs[i].msg_hdr.msg_controllen = self.cmsg_bufs[i].len();
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
            // Parse GRO cmsg to get segment size (if kernel coalesced datagrams).
            self.gro_segments[i] =
                crate::socket_opts::extract_gro_segment_size(&self.msgs[i].msg_hdr);
            // Parse IP(v6)_PKTINFO cmsg to recover the local destination address.
            // Present when the socket has IP_PKTINFO / IPV6_RECVPKTINFO enabled;
            // `None` otherwise (non-Linux, pktinfo disabled, or connected socket).
            self.local_addrs[i] =
                crate::socket_opts::extract_pktinfo_local_addr(&self.msgs[i].msg_hdr);
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
    /// Per-slot optional reply source address (from IP_PKTINFO capture on recv).
    /// When `Some`, an IP(v6)_PKTINFO cmsg is attached to this slot's msghdr so
    /// the kernel uses the captured address as the reply source without a
    /// routing-table lookup. When `None`, the kernel picks a source via routing.
    local_ips: Vec<Option<std::net::IpAddr>>,
    /// Per-slot cmsg buffers for the optional IP(v6)_PKTINFO ancillary data.
    /// Sized for the worst case (v6 in6_pktinfo) so a single allocation handles
    /// both families. Empty when no pktinfo is attached.
    cmsg_bufs: Vec<Vec<u8>>,
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
        let cmsg_space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize };
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
            local_ips: vec![None; capacity],
            cmsg_bufs: (0..capacity).map(|_| vec![0u8; cmsg_space]).collect(),
            capacity,
            count: 0,
        }
    }

    /// Queue a datagram for batched sending. Returns `false` if the batch is full.
    pub fn push(&mut self, data: &[u8], dest: SocketAddr) -> bool {
        self.push_with_local(data, dest, None)
    }

    /// Queue a datagram for batched sending, optionally attaching an
    /// IP(v6)_PKTINFO cmsg with `local_ip` as the reply source address.
    ///
    /// Returns `false` if the batch is full. When `local_ip` is `Some`, its
    /// address family must match `dest` — v4 pktinfo cannot be combined with a
    /// v6 destination and vice versa. Mismatches are skipped silently; the
    /// slot is queued without pktinfo so the kernel picks a source itself.
    pub fn push_with_local(
        &mut self,
        data: &[u8],
        dest: SocketAddr,
        local_ip: Option<std::net::IpAddr>,
    ) -> bool {
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
        // Only honor local_ip when address family matches the destination.
        self.local_ips[i] = match (local_ip, dest) {
            (Some(std::net::IpAddr::V4(_)), SocketAddr::V4(_))
            | (Some(std::net::IpAddr::V6(_)), SocketAddr::V6(_)) => local_ip,
            _ => None,
        };
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

            // Attach IP(v6)_PKTINFO cmsg when a local source address is set.
            // The cmsg_buf is pre-allocated for the v6 worst case and reused.
            if let Some(local_ip) = self.local_ips[i] {
                let cmsg_buf = &mut self.cmsg_bufs[i];
                cmsg_buf.fill(0);
                let (pktinfo_len, pktinfo_space) = match local_ip {
                    std::net::IpAddr::V4(_) => unsafe {
                        (
                            libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize,
                            libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32)
                                as usize,
                        )
                    },
                    std::net::IpAddr::V6(_) => unsafe {
                        (
                            libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32)
                                as usize,
                            libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32)
                                as usize,
                        )
                    },
                };
                self.msgs[i].msg_hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                self.msgs[i].msg_hdr.msg_controllen = pktinfo_space;

                let cmsg = unsafe { libc::CMSG_FIRSTHDR(&self.msgs[i].msg_hdr) };
                if !cmsg.is_null() {
                    match local_ip {
                        std::net::IpAddr::V4(v4) => unsafe {
                            (*cmsg).cmsg_level = libc::IPPROTO_IP;
                            (*cmsg).cmsg_type = libc::IP_PKTINFO;
                            (*cmsg).cmsg_len = pktinfo_len;
                            let pi = libc::in_pktinfo {
                                ipi_ifindex: 0,
                                ipi_spec_dst: libc::in_addr {
                                    s_addr: u32::from(v4).to_be(),
                                },
                                ipi_addr: libc::in_addr { s_addr: 0 },
                            };
                            std::ptr::copy_nonoverlapping(
                                &pi as *const libc::in_pktinfo as *const u8,
                                libc::CMSG_DATA(cmsg),
                                std::mem::size_of::<libc::in_pktinfo>(),
                            );
                        },
                        std::net::IpAddr::V6(v6) => unsafe {
                            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                            (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                            (*cmsg).cmsg_len = pktinfo_len;
                            let pi = libc::in6_pktinfo {
                                ipi6_addr: libc::in6_addr {
                                    s6_addr: v6.octets(),
                                },
                                ipi6_ifindex: 0,
                            };
                            std::ptr::copy_nonoverlapping(
                                &pi as *const libc::in6_pktinfo as *const u8,
                                libc::CMSG_DATA(cmsg),
                                std::mem::size_of::<libc::in6_pktinfo>(),
                            );
                        },
                    }
                }
            }
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
            // Clear the batch on error — UDP is best-effort and preserving
            // stale datagrams would cause reorder/requeue across iterations.
            // (GsoBatchBuf preserves on error because it has drain_to_sendmmsg
            // fallback; SendMmsgBatch is the final send path with no fallback.)
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
                self.local_ips[i] = self.local_ips[sent + i];
            }
        }
        self.count = remaining;
        Ok(sent)
    }
}

/// Convert a `std::net::SocketAddr` to `libc::sockaddr_storage` + length.
///
/// `pub(super)` so `flush_gso_batch()` in `udp_proxy.rs` can call it directly
/// without a wrapper.
#[cfg(target_os = "linux")]
pub(super) fn std_to_sockaddr_storage(
    addr: SocketAddr,
) -> (libc::sockaddr_storage, libc::socklen_t) {
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
/// via `send_with_gso()`. When a different-size datagram
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
#[allow(dead_code)]
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
    /// When `local_ip` is `Some`, an IP(v6)_PKTINFO cmsg is attached alongside
    /// the UDP_SEGMENT (GSO) cmsg in a single sendmsg call — this gives the
    /// kernel the reply source address directly and saves one routing-table
    /// lookup per flush. When `None`, the legacy `send_with_gso` path is used.
    pub fn flush_to(
        &mut self,
        fd: std::os::fd::RawFd,
        dest: &libc::sockaddr_storage,
        dest_len: libc::socklen_t,
        local_ip: Option<std::net::IpAddr>,
    ) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }
        let result = if let Some(local) = local_ip {
            crate::socket_opts::send_with_pktinfo(
                fd,
                &self.buf,
                local,
                dest,
                dest_len,
                Some(self.segment_size as u16),
            )
        } else {
            crate::socket_opts::send_with_gso(
                fd,
                &self.buf,
                self.segment_size as u16,
                dest,
                dest_len,
            )
        };
        let sent_count = self.count;
        // Only clear on success — on failure, the buffer is preserved so
        // drain_to_sendmmsg() can replay the datagrams through sendmmsg.
        if result.is_ok() {
            self.buf.clear();
            self.count = 0;
            self.segment_size = 0;
        }
        result.map(|_| sent_count)
    }

    /// Drain buffered datagrams into a `SendMmsgBatch` for fallback sending.
    ///
    /// Splits the contiguous GSO buffer back into individual datagrams by
    /// `segment_size` and pushes each into the sendmmsg batch. If the sendmmsg
    /// batch fills up, the remaining datagrams stay in the GSO buffer (the
    /// caller should flush the sendmmsg batch and call drain again).
    /// Returns the number of datagrams drained.
    pub fn drain_to_sendmmsg(
        &mut self,
        send_batch: &mut SendMmsgBatch,
        dest: std::net::SocketAddr,
        local_ip: Option<std::net::IpAddr>,
    ) -> usize {
        if self.count == 0 || self.segment_size == 0 {
            return 0;
        }
        let mut offset = 0;
        let mut drained = 0;
        while offset < self.buf.len() {
            let end = (offset + self.segment_size).min(self.buf.len());
            if !send_batch.push_with_local(&self.buf[offset..end], dest, local_ip) {
                break; // sendmmsg batch full — remaining stays in GSO buffer
            }
            offset = end;
            drained += 1;
        }
        if offset >= self.buf.len() {
            // All datagrams drained — clear the buffer.
            self.buf.clear();
            self.count = 0;
            self.segment_size = 0;
        } else {
            // Partial drain — shift remaining data to the front.
            self.buf.drain(..offset);
            self.count -= drained;
        }
        drained
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
