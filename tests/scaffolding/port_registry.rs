//! Cross-process leases for the entire test socket namespace (TCP/UDP, all addresses).
//!
//! A global advisory lock serializes allocation, binding and lease-table updates. Each
//! allocator holds a separate owner lock for its lifetime. An unlocked owner is dead, so
//! the next allocation reclaims its table even after a panic, SIGKILL or nextest timeout.
//! Lock files and tables are separate because Windows file locks also exclude reads.
//!
//! Bare port numbers and native sockets cannot carry a Rust lease guard. Their leases
//! stay in the process table until process exit (one test under nextest). Explicit
//! `PortLease` users release on drop. Neither path consumes a descriptor per port.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::future::{Ready, ready};
use std::io;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub struct PortRegistry {
    root: PathBuf,
    owner: PathBuf,
    _owner_lock: File,
    retained: Mutex<BTreeSet<u16>>,
}

pub struct PortLease {
    registry: Arc<PortRegistry>,
    pub port: u16,
    release_on_drop: AtomicBool,
}

fn open_lock(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn allocation_lock(root: &Path) -> io::Result<File> {
    let file = open_lock(&root.join("allocation.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out locking the test port registry",
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}

impl PortRegistry {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Arc<Self>> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let _allocation = allocation_lock(&root)?;
        let owner = root.join(format!("{}.ports", uuid::Uuid::new_v4()));
        let owner_lock = File::create_new(owner.with_extension("owner"))?;
        owner_lock.try_lock().map_err(io::Error::from)?;
        fs::write(&owner, b"[]")?;
        Ok(Arc::new(Self {
            root,
            owner,
            _owner_lock: owner_lock,
            retained: Mutex::new(BTreeSet::new()),
        }))
    }

    fn read_ports(path: &Path) -> io::Result<BTreeSet<u16>> {
        serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)
    }

    // Called only under allocation.lock. Never infer liveness from a PID, which
    // can be reused, or unlink the permanent allocation lock (inode split race).
    fn occupied_ports(&self) -> io::Result<BTreeSet<u16>> {
        let mut occupied = BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path
                .extension()
                .is_none_or(|extension| extension != "ports")
            {
                continue;
            }
            if path != self.owner {
                let owner_path = path.with_extension("owner");
                let owner = open_lock(&owner_path)?;
                match owner.try_lock() {
                    Ok(()) => {
                        fs::remove_file(&path)?;
                        drop(owner);
                        fs::remove_file(owner_path)?;
                        continue;
                    }
                    Err(TryLockError::WouldBlock) => {}
                    Err(TryLockError::Error(error)) => return Err(error),
                }
            }
            occupied.extend(Self::read_ports(&path)?);
        }
        Ok(occupied)
    }

    fn write_ports(&self, ports: &BTreeSet<u16>) -> io::Result<()> {
        fs::write(
            &self.owner,
            serde_json::to_vec(ports).map_err(io::Error::other)?,
        )
    }

    /// Lease the first available candidate, retaining its bound socket until the
    /// table records ownership. Candidate 0 asks the OS to choose; rejected sockets
    /// stay bound until selection finishes so the OS cannot keep returning them.
    pub fn lease_with<S>(
        self: &Arc<Self>,
        candidates: impl IntoIterator<Item = u16>,
        mut bind: impl FnMut(u16) -> io::Result<(u16, S)>,
    ) -> io::Result<(PortLease, S)> {
        let _allocation = allocation_lock(&self.root)?;
        let occupied = self.occupied_ports()?;
        let mut rejected = Vec::new();
        for candidate in candidates {
            if occupied.contains(&candidate) {
                continue;
            }
            let (port, socket) = match bind(candidate) {
                Ok(bound) => bound,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error),
            };
            if port == 0 {
                return Err(io::Error::other(
                    "a test port lease must have a nonzero port",
                ));
            }
            if occupied.contains(&port) {
                rejected.push(socket);
                continue;
            }
            let mut owned = Self::read_ports(&self.owner)?;
            owned.insert(port);
            self.write_ports(&owned)?;
            return Ok((
                PortLease {
                    registry: Arc::clone(self),
                    port,
                    release_on_drop: AtomicBool::new(true),
                },
                socket,
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "no unleased test port available",
        ))
    }

    fn bind_owned<S>(&self, port: u16, bind: impl FnOnce() -> io::Result<S>) -> io::Result<S> {
        let _allocation = allocation_lock(&self.root)?;
        if Self::read_ports(&self.owner)?.contains(&port) {
            let socket = bind()?;
            self.retained
                .lock()
                .map_err(|_| io::Error::other("test port retention lock poisoned"))?
                .insert(port);
            Ok(socket)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("test listener port {port} must be leased before binding"),
            ))
        }
    }
}

impl PortLease {
    /// Preserve ownership across a socket drop or a subprocess handoff. The owner
    /// lock releases all retained leases when this nextest process exits.
    pub fn retain_for_process(&self) -> u16 {
        self.release_on_drop.store(false, Ordering::Relaxed);
        self.port
    }
}

impl Drop for PortLease {
    fn drop(&mut self) {
        if !self.release_on_drop.load(Ordering::Relaxed) {
            return;
        }
        let release = || -> io::Result<()> {
            let _allocation = allocation_lock(&self.registry.root)?;
            if self
                .registry
                .retained
                .lock()
                .map_err(|_| io::Error::other("test port retention lock poisoned"))?
                .contains(&self.port)
            {
                return Ok(());
            }
            let mut owned = PortRegistry::read_ports(&self.registry.owner)?;
            owned.remove(&self.port);
            self.registry.write_ports(&owned)
        };
        if let Err(error) = release() {
            // A failed release must never make the number available optimistically.
            eprintln!("failed to release test port {}: {error}", self.port);
        }
    }
}

pub fn process_registry() -> io::Result<&'static Arc<PortRegistry>> {
    static REGISTRY: OnceLock<Result<Arc<PortRegistry>, io::Error>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
            PortRegistry::new(target.join("test-port-leases-v1"))
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

/// Mesh listeners must also avoid the kernel's automatic source-port range.
/// Call in the actual network namespace where the gateway will bind.
pub fn unbound_port_outside(excluded: std::ops::RangeInclusive<u16>) -> io::Result<u16> {
    let (lease, sockets) = process_registry()?.lease_with(
        (10_240..=u16::MAX).filter(|port| !excluded.contains(port)),
        |port| {
            let tcp = TcpListener::bind(("0.0.0.0", port))?;
            let udp = UdpSocket::bind(("0.0.0.0", port))?;
            Ok((port, (tcp, udp)))
        },
    )?;
    let port = lease.retain_for_process();
    drop(sockets);
    Ok(port)
}

fn bind_registered<S>(
    addr: impl ToSocketAddrs,
    bind: impl Fn(SocketAddr) -> io::Result<S>,
    local_addr: impl Fn(&S) -> io::Result<SocketAddr>,
) -> io::Result<S> {
    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("test socket address resolved to no addresses"))?;
    let registry = process_registry()?;
    if addr.port() != 0 {
        return registry.bind_owned(addr.port(), || bind(addr));
    }
    let (lease, socket) = registry.lease_with(std::iter::repeat_n(0, 256), |_| {
        let socket = bind(addr)?;
        Ok((local_addr(&socket)?.port(), socket))
    })?;
    lease.retain_for_process();
    Ok(socket)
}

/// Native socket construction with registry ownership. Nonzero ports must already
/// belong to this process; use port 0 for fixtures and keep the returned socket.
/// Tokio bindings return an immediately ready future after registering a native
/// nonblocking socket. No registry lock is held across an await.
pub trait TestSocket: Sized {
    type Binding;

    fn bind_test(addr: impl ToSocketAddrs) -> Self::Binding;
}

impl TestSocket for TcpListener {
    type Binding = io::Result<Self>;

    fn bind_test(addr: impl ToSocketAddrs) -> Self::Binding {
        bind_registered(addr, Self::bind, Self::local_addr)
    }
}

impl TestSocket for UdpSocket {
    type Binding = io::Result<Self>;

    fn bind_test(addr: impl ToSocketAddrs) -> Self::Binding {
        bind_registered(addr, Self::bind, Self::local_addr)
    }
}

impl TestSocket for tokio::net::TcpListener {
    type Binding = Ready<io::Result<Self>>;

    fn bind_test(addr: impl ToSocketAddrs) -> Self::Binding {
        ready(TcpListener::bind_test(addr).and_then(|listener| {
            listener.set_nonblocking(true)?;
            Self::from_std(listener)
        }))
    }
}

impl TestSocket for tokio::net::UdpSocket {
    type Binding = Ready<io::Result<Self>>;

    fn bind_test(addr: impl ToSocketAddrs) -> Self::Binding {
        ready(UdpSocket::bind_test(addr).and_then(|socket| {
            socket.set_nonblocking(true)?;
            Self::from_std(socket)
        }))
    }
}

impl TestSocket for tokio::net::TcpSocket {
    type Binding = io::Result<Self>;

    fn bind_test(addr: impl ToSocketAddrs) -> Self::Binding {
        bind_registered(
            addr,
            |addr| {
                let socket = if addr.is_ipv4() {
                    Self::new_v4()?
                } else {
                    Self::new_v6()?
                };
                socket.bind(addr)?;
                Ok(socket)
            },
            Self::local_addr,
        )
    }
}
