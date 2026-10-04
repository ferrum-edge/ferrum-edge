#[cfg(feature = "__tls")]
use http::header::HeaderValue;
#[cfg(feature = "__tls")]
use http::uri::Scheme;
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
#[cfg(any(feature = "socks", feature = "__tls", unix, target_os = "windows"))]
use hyper_util::rt::TokioIo;
#[cfg(feature = "__native-tls")]
use native_tls_crate::{TlsConnector, TlsConnectorBuilder};
use pin_project_lite::pin_project;
use tower::util::{BoxCloneSyncServiceLayer, MapRequestLayer};
use tower::{timeout::TimeoutLayer, util::BoxCloneSyncService, ServiceBuilder};
use tower_service::Service;

use std::future::Future;
use std::io::{self, IoSlice};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(feature = "__native-tls")]
use self::native_tls_conn::NativeTlsConn;
#[cfg(feature = "__rustls")]
use self::rustls_tls_conn::RustlsTlsConn;
use crate::dns::DynResolver;
use crate::error::{cast_to_internal_error, BoxError};
use crate::proxy::{Intercepted, Matcher as ProxyMatcher};
use sealed::{Conn, Unnameable};

pub(crate) type HttpConnector = hyper_util::client::legacy::connect::HttpConnector<DynResolver>;

use std::cell::Cell;

thread_local! {
    static REQUEST_CONNECT_TIMEOUT: Cell<Option<Duration>> = const { Cell::new(None) };
}

pub(crate) fn with_connect_timeout_override<T>(
    timeout: Option<Duration>,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore<'a> {
        slot: &'a Cell<Option<Duration>>,
        previous: Option<Duration>,
    }

    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            self.slot.set(self.previous);
        }
    }

    REQUEST_CONNECT_TIMEOUT.with(|slot| {
        let previous = slot.replace(timeout);
        let _restore = Restore { slot, previous };
        f()
    })
}

fn effective_connect_timeout(default_timeout: Option<Duration>) -> Option<Duration> {
    REQUEST_CONNECT_TIMEOUT.with(|slot| slot.get().or(default_timeout))
}

#[derive(Clone)]
struct ConnectTimeoutService<S> {
    inner: S,
    default_timeout: Option<Duration>,
}

impl<S> ConnectTimeoutService<S> {
    fn new(inner: S, default_timeout: Option<Duration>) -> Self {
        Self {
            inner,
            default_timeout,
        }
    }
}

impl<S, Req> Service<Req> for ConnectTimeoutService<S>
where
    S: Service<Req, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    Req: Send + 'static,
{
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let timeout = effective_connect_timeout(self.default_timeout);
        Box::pin(with_timeout(self.inner.call(req), timeout))
    }
}

#[derive(Clone)]
pub(crate) enum Connector {
    // base service, with or without an embedded timeout
    Simple(ConnectorService),
    // at least one custom layer along with maybe an outer timeout layer
    // from `builder.connect_timeout()`
    WithLayers(BoxCloneSyncService<Unnameable, Conn, BoxError>),
}

impl Service<Uri> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Connector::Simple(service) => service.poll_ready(cx),
            Connector::WithLayers(service) => service.poll_ready(cx),
        }
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        match self {
            Connector::Simple(service) => service.call(dst),
            Connector::WithLayers(service) => service.call(Unnameable(dst)),
        }
    }
}

/// Ferrum patch 003 — physical-connection admission.
///
/// Consulted by the connector **immediately before a new physical connection
/// is dialed**, and only then: a checkout that reuses an already-open pooled
/// connection never reaches the connector, and HTTP/2 streams multiplexed onto
/// an existing connection never reach it either. The returned
/// [`ConnectionAdmissionToken`] is moved into the connection object handed to
/// hyper, so it is dropped exactly when that physical connection is dropped —
/// covering handshake failure, normal close, idle eviction, pool drain,
/// cancellation, and shutdown.
///
/// Returning `Err` refuses the dial; the error is surfaced to the caller as the
/// connect error for that request, with its source chain preserved.
pub trait ConnectionAdmission: Send + Sync + 'static {
    /// Admit one new physical connection to `dst`, or refuse it.
    fn admit(&self, dst: &Uri) -> Result<ConnectionAdmissionToken, BoxError>;

    /// Ferrum patch 004 — the connection admitted by `admit` now exists.
    ///
    /// Called at most once per admitted dial, after the transport (and any TLS
    /// handshake) has produced a socket and before the connection is handed to
    /// hyper, so no request byte has been written yet. `fd` is the raw
    /// descriptor of the underlying `TcpStream`, borrowed for the duration of
    /// the call only: the connection owns it, and an implementation that needs
    /// it afterwards must duplicate it (`dup`). A dial that produced no TCP
    /// socket — a Unix-domain or named-pipe transport, or a connection whose
    /// stream the connector could not reach — does not call this at all.
    ///
    /// `token` is the same token `admit` returned for this connection, so an
    /// implementation can key what it records on the connection's identity.
    ///
    /// Only HTTP/1.1 connections are reported: a connection that negotiated
    /// HTTP/2 over ALPN is multiplexed, and its socket cannot be attributed to
    /// the single request that dialed it.
    ///
    /// The default implementation does nothing, so an existing
    /// `ConnectionAdmission` needs no change.
    #[cfg(unix)]
    fn established(&self, token: &ConnectionAdmissionToken, fd: std::os::fd::RawFd) {
        let _ = (token, fd);
    }
}

/// Opaque handle whose `Drop` marks the end of one physical connection's
/// lifetime. See [`ConnectionAdmission`].
pub struct ConnectionAdmissionToken(Option<Box<dyn std::any::Any + Send + Sync>>);

impl ConnectionAdmissionToken {
    /// Wrap an arbitrary RAII value (typically a permit/guard) as a token.
    pub fn new<T: std::any::Any + Send + Sync>(guard: T) -> Self {
        Self(Some(Box::new(guard)))
    }

    /// A token that holds nothing — the admission hook decided this
    /// destination is not governed by a limit.
    pub fn unlimited() -> Self {
        Self(None)
    }
}

impl std::fmt::Debug for ConnectionAdmissionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionAdmissionToken")
            .field("held", &self.0.is_some())
            .finish()
    }
}

/// Ferrum patch 003: binds an admission token to a physical connection's
/// lifetime by owning it alongside the connection's IO. Every trait method
/// delegates; the token is only ever dropped.
struct AdmittedConn {
    inner: BoxConn,
    _token: ConnectionAdmissionToken,
}

impl Connection for AdmittedConn {
    fn connected(&self) -> Connected {
        self.inner.connected()
    }
}

impl Read for AdmittedConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Read::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

impl Write for AdmittedConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Write::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Write::poll_write_vectored(Pin::new(&mut self.inner), cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Write::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Write::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

#[cfg(feature = "__tls")]
impl TlsInfoFactory for AdmittedConn {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.inner.tls_info()
    }
}

/// Ferrum patch 004: one-shot cell the connect path fills with the raw
/// descriptor of a newly dialed TCP socket.
///
/// The connect future is boxed and `'static`, so the descriptor cannot be
/// returned by borrow; a cheap shared cell carries it from the branch that can
/// still see the concrete stream out to [`with_admission`], which is the only
/// place holding the connection's admission token. `-1` means "no TCP socket
/// was observed" (a local-transport dial, or a stream the connector could not
/// reach), and the hook is then not called at all.
#[derive(Clone)]
struct EstablishedFd(Arc<std::sync::atomic::AtomicI32>);

#[allow(dead_code)]
impl EstablishedFd {
    fn new() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicI32::new(-1)))
    }

    /// Record the descriptor of the socket this dial produced.
    fn set(&self, fd: i32) {
        self.0.store(fd, std::sync::atomic::Ordering::Release);
    }

    #[cfg(unix)]
    fn get(&self) -> Option<std::os::fd::RawFd> {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            -1 => None,
            fd => Some(fd),
        }
    }
}

/// Ferrum patch 004: the raw descriptor of the TCP socket underneath a stream
/// the rustls connector just produced.
///
/// Both variants wrap the `HttpConnector`'s `TokioIo<TcpStream>`; the accessor
/// chain for the TLS variant is the same one this module already uses to reach
/// the stream for `set_nodelay`.
#[cfg(all(unix, feature = "__rustls"))]
fn rustls_stream_raw_fd(
    io: &hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>,
) -> Option<i32> {
    use std::os::fd::AsRawFd;
    match io {
        hyper_rustls::MaybeHttpsStream::Http(tcp) => Some(tcp.inner().as_raw_fd()),
        hyper_rustls::MaybeHttpsStream::Https(stream) => {
            let (tcp, _) = stream.inner().get_ref();
            Some(tcp.inner().inner().as_raw_fd())
        }
    }
}

/// Ferrum patch 003: await one connect attempt and, on success, bind the
/// admission token to the resulting physical connection. On failure the token
/// drops here, releasing the reservation for a handshake that never produced a
/// socket.
async fn with_admission<F>(
    f: F,
    token: Option<ConnectionAdmissionToken>,
    hook: Option<Arc<dyn ConnectionAdmission>>,
    established: EstablishedFd,
) -> Result<Conn, BoxError>
where
    F: Future<Output = Result<Conn, BoxError>>,
{
    let conn = f.await?;
    // Ferrum patch 004: report the socket before the connection reaches hyper,
    // so the hook observes it strictly before the first request byte is
    // written. `hook` and `token` are `Some` together or not at all.
    //
    // Only an HTTP/1.1 connection is reported. A connection that negotiated
    // HTTP/2 over ALPN is multiplexed: its kernel send queue is shared by every
    // stream hyper opens on it, so no per-request consumer of the descriptor
    // (a send-queue drain bound, say) could attribute that queue to the request
    // that caused the dial. Such connections leave the hook uncalled.
    #[cfg(unix)]
    if let (Some(hook), Some(token), Some(fd)) = (hook.as_ref(), token.as_ref(), established.get())
    {
        if !conn.connected().is_negotiated_h2() {
            hook.established(token, fd);
        }
    }
    #[cfg(not(unix))]
    let _ = (&hook, &established);
    Ok(match token {
        None => conn,
        Some(token) => Conn {
            inner: Box::new(AdmittedConn {
                inner: conn.inner,
                _token: token,
            }),
            is_proxy: conn.is_proxy,
            tls_info: conn.tls_info,
        },
    })
}

pub(crate) type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

pub(crate) type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;

pub(crate) struct ConnectorBuilder {
    inner: Inner,
    proxies: Arc<Vec<ProxyMatcher>>,
    verbose: verbose::Wrapper,
    timeout: Option<Duration>,
    #[cfg(feature = "__tls")]
    nodelay: bool,
    #[cfg(feature = "__tls")]
    tls_info: bool,
    #[cfg(feature = "__tls")]
    user_agent: Option<HeaderValue>,
    #[cfg(feature = "socks")]
    resolver: Option<DynResolver>,
    #[cfg(unix)]
    unix_socket: Option<Arc<std::path::Path>>,
    #[cfg(target_os = "windows")]
    windows_named_pipe: Option<Arc<std::ffi::OsStr>>,
}

impl ConnectorBuilder {
    pub(crate) fn build(
        self,
        layers: Vec<BoxedConnectorLayer>,
        // Ferrum patch 003: consulted immediately before every NEW physical
        // connection dial; see `ConnectionAdmission`.
        connection_admission: Option<Arc<dyn ConnectionAdmission>>,
    ) -> Connector
where {
        // construct the inner tower service
        let mut base_service = ConnectorService {
            inner: self.inner,
            proxies: self.proxies,
            verbose: self.verbose,
            connection_admission,
            #[cfg(feature = "__tls")]
            nodelay: self.nodelay,
            #[cfg(feature = "__tls")]
            tls_info: self.tls_info,
            #[cfg(feature = "__tls")]
            user_agent: self.user_agent,
            connect_timeout: None,
            simple_timeout: None,
            #[cfg(feature = "socks")]
            resolver: self.resolver.unwrap_or_else(DynResolver::gai),
            #[cfg(unix)]
            unix_socket: self.unix_socket,
            #[cfg(target_os = "windows")]
            windows_named_pipe: self.windows_named_pipe,
        };

        #[cfg(unix)]
        if base_service.unix_socket.is_some() && !base_service.proxies.is_empty() {
            base_service.proxies = Default::default();
            log::trace!("unix_socket() set, proxies are ignored");
        }
        #[cfg(target_os = "windows")]
        if base_service.windows_named_pipe.is_some() && !base_service.proxies.is_empty() {
            base_service.proxies = Default::default();
            log::trace!("windows_named_pipe() set, proxies are ignored");
        }

        if layers.is_empty() {
            // we have no user-provided layers, only use concrete types
            base_service.simple_timeout = self.timeout;
            return Connector::Simple(base_service);
        }

        // otherwise we have user provided layers
        // so we need type erasure all the way through
        // as well as mapping the unnameable type of the layers back to Uri for the inner service
        let unnameable_service = ServiceBuilder::new()
            .layer(MapRequestLayer::new(|request: Unnameable| request.0))
            .service(base_service);
        let mut service = BoxCloneSyncService::new(unnameable_service);

        for layer in layers {
            service = ServiceBuilder::new().layer(layer).service(service);
        }

        let service = ConnectTimeoutService::new(service, self.timeout);
        let service = ServiceBuilder::new()
            .map_err(|error: BoxError| cast_to_internal_error(error))
            .service(service);
        let service = BoxCloneSyncService::new(service);

        Connector::WithLayers(service)
    }

    #[cfg(not(feature = "__tls"))]
    pub(crate) fn new<T>(
        mut http: HttpConnector,
        proxies: Arc<Vec<ProxyMatcher>>,
        local_addr: T,
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        interface: Option<&str>,
        nodelay: bool,
    ) -> ConnectorBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        if let Some(interface) = interface {
            http.set_interface(interface.to_owned());
        }
        http.set_nodelay(nodelay);

        ConnectorBuilder {
            inner: Inner::Http(http),
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            #[cfg(feature = "socks")]
            resolver: None,
            #[cfg(unix)]
            unix_socket: None,
            #[cfg(target_os = "windows")]
            windows_named_pipe: None,
        }
    }

    #[cfg(feature = "__native-tls")]
    pub(crate) fn new_native_tls<T>(
        http: HttpConnector,
        tls: TlsConnectorBuilder,
        proxies: Arc<Vec<ProxyMatcher>>,
        user_agent: Option<HeaderValue>,
        local_addr: T,
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        interface: Option<&str>,
        nodelay: bool,
        tls_info: bool,
    ) -> crate::Result<ConnectorBuilder>
    where
        T: Into<Option<IpAddr>>,
    {
        let tls = tls.build().map_err(crate::error::builder)?;
        Ok(Self::from_built_native_tls(
            http,
            tls,
            proxies,
            user_agent,
            local_addr,
            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "solaris",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos",
            ))]
            interface,
            nodelay,
            tls_info,
        ))
    }

    #[cfg(feature = "__native-tls")]
    pub(crate) fn from_built_native_tls<T>(
        mut http: HttpConnector,
        tls: TlsConnector,
        proxies: Arc<Vec<ProxyMatcher>>,
        user_agent: Option<HeaderValue>,
        local_addr: T,
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        interface: Option<&str>,
        nodelay: bool,
        tls_info: bool,
    ) -> ConnectorBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        if let Some(interface) = interface {
            http.set_interface(interface);
        }
        http.set_nodelay(nodelay);
        http.enforce_http(false);

        ConnectorBuilder {
            inner: Inner::NativeTls(http, tls),
            proxies,
            verbose: verbose::OFF,
            nodelay,
            tls_info,
            user_agent,
            timeout: None,
            #[cfg(feature = "socks")]
            resolver: None,
            #[cfg(unix)]
            unix_socket: None,
            #[cfg(target_os = "windows")]
            windows_named_pipe: None,
        }
    }

    #[cfg(feature = "__rustls")]
    pub(crate) fn new_rustls_tls<T>(
        mut http: HttpConnector,
        tls: rustls::ClientConfig,
        proxies: Arc<Vec<ProxyMatcher>>,
        user_agent: Option<HeaderValue>,
        local_addr: T,
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        interface: Option<&str>,
        nodelay: bool,
        tls_info: bool,
    ) -> ConnectorBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        if let Some(interface) = interface {
            http.set_interface(interface.to_owned());
        }
        http.set_nodelay(nodelay);
        http.enforce_http(false);

        let (tls, tls_proxy) = if proxies.is_empty() {
            let tls = Arc::new(tls);
            (tls.clone(), tls)
        } else {
            let mut tls_proxy = tls.clone();
            tls_proxy.alpn_protocols.clear();
            (Arc::new(tls), Arc::new(tls_proxy))
        };

        ConnectorBuilder {
            inner: Inner::RustlsTls {
                http,
                tls,
                tls_proxy,
            },
            proxies,
            verbose: verbose::OFF,
            nodelay,
            tls_info,
            user_agent,
            timeout: None,
            #[cfg(feature = "socks")]
            resolver: None,
            #[cfg(unix)]
            unix_socket: None,
            #[cfg(target_os = "windows")]
            windows_named_pipe: None,
        }
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    pub(crate) fn set_verbose(&mut self, enabled: bool) {
        self.verbose.0 = enabled;
    }

    pub(crate) fn set_keepalive(&mut self, dur: Option<Duration>) {
        match &mut self.inner {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, _tls) => http.set_keepalive(dur),
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, .. } => http.set_keepalive(dur),
            #[cfg(not(feature = "__tls"))]
            Inner::Http(http) => http.set_keepalive(dur),
        }
    }

    pub(crate) fn set_keepalive_interval(&mut self, dur: Option<Duration>) {
        match &mut self.inner {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, _tls) => http.set_keepalive_interval(dur),
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, .. } => http.set_keepalive_interval(dur),
            #[cfg(not(feature = "__tls"))]
            Inner::Http(http) => http.set_keepalive_interval(dur),
        }
    }

    pub(crate) fn set_keepalive_retries(&mut self, retries: Option<u32>) {
        match &mut self.inner {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, _tls) => http.set_keepalive_retries(retries),
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, .. } => http.set_keepalive_retries(retries),
            #[cfg(not(feature = "__tls"))]
            Inner::Http(http) => http.set_keepalive_retries(retries),
        }
    }

    #[cfg(feature = "socks")]
    pub(crate) fn set_socks_resolver(&mut self, resolver: DynResolver) {
        self.resolver = Some(resolver);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub(crate) fn set_tcp_user_timeout(&mut self, dur: Option<Duration>) {
        match &mut self.inner {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, _tls) => http.set_tcp_user_timeout(dur),
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, .. } => http.set_tcp_user_timeout(dur),
            #[cfg(not(feature = "__tls"))]
            Inner::Http(http) => http.set_tcp_user_timeout(dur),
        }
    }

    #[cfg(unix)]
    pub(crate) fn set_unix_socket(&mut self, path: Option<Arc<std::path::Path>>) {
        self.unix_socket = path;
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn set_windows_named_pipe(&mut self, pipe: Option<Arc<std::ffi::OsStr>>) {
        self.windows_named_pipe = pipe;
    }
}

#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub(crate) struct ConnectorService {
    inner: Inner,
    proxies: Arc<Vec<ProxyMatcher>>,
    verbose: verbose::Wrapper,
    /// Ferrum patch 003: physical-connection admission hook. `None` (the
    /// upstream default) makes every dial unconditional.
    connection_admission: Option<Arc<dyn ConnectionAdmission>>,
    connect_timeout: Option<Duration>,
    /// When there is a single timeout layer and no other layers,
    /// we embed it directly inside our base Service::call().
    /// This lets us avoid an extra `Box::pin` indirection layer
    /// since `tokio::time::Timeout` is `Unpin`
    simple_timeout: Option<Duration>,
    #[cfg(feature = "__tls")]
    nodelay: bool,
    #[cfg(feature = "__tls")]
    tls_info: bool,
    #[cfg(feature = "__tls")]
    user_agent: Option<HeaderValue>,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
    /// If set, this always takes priority over TCP.
    #[cfg(unix)]
    unix_socket: Option<Arc<std::path::Path>>,
    #[cfg(target_os = "windows")]
    windows_named_pipe: Option<Arc<std::ffi::OsStr>>,
}

#[derive(Clone)]
enum Inner {
    #[cfg(not(feature = "__tls"))]
    Http(HttpConnector),
    #[cfg(feature = "__native-tls")]
    NativeTls(HttpConnector, TlsConnector),
    #[cfg(any(feature = "__rustls"))]
    RustlsTls {
        http: HttpConnector,
        tls: Arc<rustls::ClientConfig>,
        tls_proxy: Arc<rustls::ClientConfig>,
    },
}

impl Inner {
    #[cfg(feature = "socks")]
    fn get_http_connector(&mut self) -> &mut crate::connect::HttpConnector {
        match self {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, _) => http,
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, .. } => http,
            #[cfg(not(feature = "__tls"))]
            Inner::Http(http) => http,
        }
    }
}

impl ConnectorService {
    fn request_connect_timeout(&self) -> Option<Duration> {
        effective_connect_timeout(self.connect_timeout)
    }

    #[cfg(feature = "socks")]
    async fn connect_socks(mut self, dst: Uri, proxy: Intercepted) -> Result<Conn, BoxError> {
        let dns = match proxy.uri().scheme_str() {
            Some("socks4") | Some("socks5") => socks::DnsResolve::Local,
            Some("socks4a") | Some("socks5h") => socks::DnsResolve::Proxy,
            _ => {
                unreachable!("connect_socks is only called for socks proxies");
            }
        };

        match &mut self.inner {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, tls) => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    let host = dst.host().ok_or("no host in url")?.to_string();
                    let conn = socks::connect(proxy, dst, dns, &self.resolver, http).await?;
                    let conn = TokioIo::new(conn);
                    let conn = TokioIo::new(conn);
                    let tls_connector = tokio_native_tls::TlsConnector::from(tls.clone());
                    let io = tls_connector.connect(&host, conn).await?;
                    let io = TokioIo::new(io);
                    return Ok(Conn {
                        inner: self.verbose.wrap(NativeTlsConn { inner: io }),
                        is_proxy: false,
                        tls_info: self.tls_info,
                    });
                }
            }
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, tls, .. } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    use std::convert::TryFrom;
                    use tokio_rustls::TlsConnector as RustlsConnector;

                    let tls = tls.clone();
                    let host = dst.host().ok_or("no host in url")?.to_string();
                    let conn = socks::connect(proxy, dst, dns, &self.resolver, http).await?;
                    let conn = TokioIo::new(conn);
                    let conn = TokioIo::new(conn);
                    let server_name =
                        rustls_pki_types::ServerName::try_from(host.as_str().to_owned())
                            .map_err(|_| "Invalid Server Name")?;
                    let io = RustlsConnector::from(tls)
                        .connect(server_name, conn)
                        .await?;
                    let io = TokioIo::new(io);
                    return Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn { inner: io }),
                        is_proxy: false,
                        tls_info: false,
                    });
                }
            }
            #[cfg(not(feature = "__tls"))]
            Inner::Http(http) => {
                let conn = socks::connect(proxy, dst, dns, &self.resolver, http).await?;
                return Ok(Conn {
                    inner: self.verbose.wrap(TokioIo::new(conn)),
                    is_proxy: false,
                    tls_info: false,
                });
            }
        }

        let resolver = &self.resolver;
        let http = self.inner.get_http_connector();
        socks::connect(proxy, dst, dns, resolver, http)
            .await
            .map(|tcp| Conn {
                inner: self.verbose.wrap(TokioIo::new(tcp)),
                is_proxy: false,
                tls_info: false,
            })
            .map_err(Into::into)
    }

    async fn connect_with_maybe_proxy(
        self,
        dst: Uri,
        is_proxy: bool,
        // Ferrum patch 004: filled with the dialed socket's descriptor.
        established: EstablishedFd,
    ) -> Result<Conn, BoxError> {
        // Ferrum patch 004: not every feature/target combination reaches a
        // branch that can report a descriptor.
        let _ = &established;
        match self.inner {
            #[cfg(not(feature = "__tls"))]
            Inner::Http(mut http) => {
                let io = http.call(dst).await?;
                // Ferrum patch 004.
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    established.set(io.inner().as_raw_fd());
                }
                Ok(Conn {
                    inner: self.verbose.wrap(io),
                    is_proxy,
                    tls_info: false,
                })
            }
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, tls) => {
                let mut http = http.clone();

                // Disable Nagle's algorithm for TLS handshake
                //
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                if !self.nodelay && (dst.scheme() == Some(&Scheme::HTTPS)) {
                    http.set_nodelay(true);
                }

                let tls_connector = tokio_native_tls::TlsConnector::from(tls.clone());
                let mut http = hyper_tls::HttpsConnector::from((http, tls_connector));
                let io = http.call(dst).await?;

                if let hyper_tls::MaybeHttpsStream::Https(stream) = io {
                    if !self.nodelay {
                        stream
                            .inner()
                            .get_ref()
                            .get_ref()
                            .get_ref()
                            .inner()
                            .inner()
                            .set_nodelay(false)?;
                    }
                    Ok(Conn {
                        inner: self.verbose.wrap(NativeTlsConn { inner: stream }),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: false,
                    })
                }
            }
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { http, tls, .. } => {
                let mut http = http.clone();

                // Disable Nagle's algorithm for TLS handshake
                //
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                if !self.nodelay && (dst.scheme() == Some(&Scheme::HTTPS)) {
                    http.set_nodelay(true);
                }

                let mut http = hyper_rustls::HttpsConnector::from((http, tls.clone()));
                let io = http.call(dst).await?;
                // Ferrum patch 004: the socket exists and no request byte has
                // been written yet.
                #[cfg(unix)]
                if let Some(fd) = rustls_stream_raw_fd(&io) {
                    established.set(fd);
                }

                if let hyper_rustls::MaybeHttpsStream::Https(stream) = io {
                    if !self.nodelay {
                        let (io, _) = stream.inner().get_ref();
                        io.inner().inner().set_nodelay(false)?;
                    }
                    Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn { inner: stream }),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: false,
                    })
                }
            }
        }
    }

    /// Connect over a local transport: Unix Domain Socket (on Unix) or Windows Named Pipe (on Windows).
    #[cfg(any(unix, target_os = "windows"))]
    async fn connect_local_transport(self, dst: Uri) -> Result<Conn, BoxError> {
        #[cfg(unix)]
        let svc = {
            let path = self
                .unix_socket
                .as_ref()
                .expect("connect local must have socket path")
                .clone();
            tower::service_fn(move |_| {
                let fut = tokio::net::UnixStream::connect(path.clone());
                async move {
                    let io = fut.await?;
                    Ok::<_, std::io::Error>(TokioIo::new(io))
                }
            })
        };
        #[cfg(target_os = "windows")]
        let svc = {
            use tokio::net::windows::named_pipe::ClientOptions;
            let pipe = self
                .windows_named_pipe
                .as_ref()
                .expect("connect local must have pipe path")
                .clone();
            tower::service_fn(move |_| {
                let pipe = pipe.clone();
                async move { ClientOptions::new().open(pipe).map(TokioIo::new) }
            })
        };
        let is_proxy = false;
        match self.inner {
            #[cfg(not(feature = "__tls"))]
            Inner::Http(..) => {
                let mut svc = svc;
                let io = svc.call(dst).await?;
                Ok(Conn {
                    inner: self.verbose.wrap(io),
                    is_proxy,
                    tls_info: false,
                })
            }
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(_, tls) => {
                let tls_connector = tokio_native_tls::TlsConnector::from(tls.clone());
                let mut http = hyper_tls::HttpsConnector::from((svc, tls_connector));
                let io = http.call(dst).await?;

                if let hyper_tls::MaybeHttpsStream::Https(stream) = io {
                    Ok(Conn {
                        inner: self.verbose.wrap(NativeTlsConn { inner: stream }),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: false,
                    })
                }
            }
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls { tls, .. } => {
                let mut http = hyper_rustls::HttpsConnector::from((svc, tls.clone()));
                let io = http.call(dst).await?;

                if let hyper_rustls::MaybeHttpsStream::Https(stream) = io {
                    Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn { inner: stream }),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: false,
                    })
                }
            }
        }
    }

    async fn connect_via_proxy(
        self,
        dst: Uri,
        proxy: Intercepted,
        // Ferrum patch 004: filled with the dialed socket's descriptor.
        established: EstablishedFd,
    ) -> Result<Conn, BoxError> {
        // Ferrum patch 004: only the plain-HTTP proxy arm reaches a TCP dial
        // this connector can see.
        let _ = &established;
        log::debug!("proxy({proxy:?}) intercepts '{:?}'", dst.host());

        #[cfg(feature = "socks")]
        match proxy.uri().scheme_str().ok_or("proxy scheme expected")? {
            "socks4" | "socks4a" | "socks5" | "socks5h" => {
                return self.connect_socks(dst, proxy).await;
            }
            _ => (),
        }

        let proxy_dst = proxy.uri().clone();
        #[cfg(feature = "__tls")]
        let auth = proxy.basic_auth().cloned();

        #[cfg(feature = "__tls")]
        let misc = proxy.custom_headers().clone();

        match &self.inner {
            #[cfg(feature = "__native-tls")]
            Inner::NativeTls(http, tls) => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    log::trace!("tunneling HTTPS over proxy");
                    let tls_connector = tokio_native_tls::TlsConnector::from(tls.clone());
                    let inner =
                        hyper_tls::HttpsConnector::from((http.clone(), tls_connector.clone()));
                    // TODO: we could cache constructing this
                    let mut tunnel =
                        hyper_util::client::legacy::connect::proxy::Tunnel::new(proxy_dst, inner);
                    if let Some(auth) = auth {
                        tunnel = tunnel.with_auth(auth);
                    }
                    if let Some(ua) = self.user_agent {
                        let mut headers = http::HeaderMap::new();
                        headers.insert(http::header::USER_AGENT, ua);
                        tunnel = tunnel.with_headers(headers);
                    }
                    // Note that custom headers may override the user agent header.
                    if let Some(custom_headers) = misc {
                        tunnel = tunnel.with_headers(custom_headers.clone());
                    }
                    // We don't wrap this again in an HttpsConnector since that uses Maybe,
                    // and we know this is definitely HTTPS.
                    let tunneled = tunnel.call(dst.clone()).await?;
                    let tls_connector = tokio_native_tls::TlsConnector::from(tls.clone());
                    let io = tls_connector
                        .connect(dst.host().ok_or("no host in url")?, TokioIo::new(tunneled))
                        .await?;
                    return Ok(Conn {
                        inner: self.verbose.wrap(NativeTlsConn {
                            inner: TokioIo::new(io),
                        }),
                        is_proxy: false,
                        tls_info: false,
                    });
                }
            }
            #[cfg(feature = "__rustls")]
            Inner::RustlsTls {
                http,
                tls,
                tls_proxy,
            } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    use rustls_pki_types::ServerName;
                    use std::convert::TryFrom;
                    use tokio_rustls::TlsConnector as RustlsConnector;

                    log::trace!("tunneling HTTPS over proxy");
                    let http = http.clone();
                    let inner = hyper_rustls::HttpsConnector::from((http, tls_proxy.clone()));
                    // TODO: we could cache constructing this
                    let mut tunnel =
                        hyper_util::client::legacy::connect::proxy::Tunnel::new(proxy_dst, inner);
                    if let Some(auth) = auth {
                        tunnel = tunnel.with_auth(auth);
                    }
                    if let Some(custom_headers) = misc {
                        tunnel = tunnel.with_headers(custom_headers.clone());
                    }
                    if let Some(ua) = self.user_agent {
                        let mut headers = http::HeaderMap::new();
                        headers.insert(http::header::USER_AGENT, ua);
                        tunnel = tunnel.with_headers(headers);
                    }
                    // We don't wrap this again in an HttpsConnector since that uses Maybe,
                    // and we know this is definitely HTTPS.
                    let tunneled = tunnel.call(dst.clone()).await?;
                    let host = dst.host().ok_or("no host in url")?.to_string();
                    let server_name = ServerName::try_from(host.as_str().to_owned())
                        .map_err(|_| "Invalid Server Name")?;
                    let io = RustlsConnector::from(tls.clone())
                        .connect(server_name, TokioIo::new(tunneled))
                        .await?;

                    return Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn {
                            inner: TokioIo::new(io),
                        }),
                        is_proxy: false,
                        tls_info: false,
                    });
                }
            }
            #[cfg(not(feature = "__tls"))]
            Inner::Http(_) => (),
        }

        self.connect_with_maybe_proxy(proxy_dst, true, established)
            .await
    }

    #[cfg(any(unix, target_os = "windows"))]
    fn should_use_local_transport(&self) -> bool {
        #[cfg(unix)]
        return self.unix_socket.is_some();

        #[cfg(target_os = "windows")]
        return self.windows_named_pipe.is_some();
    }
}

async fn with_timeout<T, F>(f: F, timeout: Option<Duration>) -> Result<T, BoxError>
where
    F: Future<Output = Result<T, BoxError>>,
{
    if let Some(to) = timeout {
        match tokio::time::timeout(to, f).await {
            Err(_elapsed) => Err(Box::new(crate::error::TimedOut) as BoxError),
            Ok(Ok(try_res)) => Ok(try_res),
            Ok(Err(e)) => Err(e),
        }
    } else {
        f.await
    }
}

impl Service<Uri> for ConnectorService {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        log::debug!("starting new connection '{:?}'", dst.host());
        let timeout = effective_connect_timeout(self.simple_timeout);

        // Ferrum patch 003: this method is reached only for a NEW physical
        // connection — pooled reuse and HTTP/2 stream multiplexing never call
        // the connector — so admission belongs exactly here, before any dial.
        // The token is bound to the connection below and released when it dies.
        let admission = match self.connection_admission.as_ref() {
            None => None,
            Some(hook) => match hook.admit(&dst) {
                Ok(token) => Some(token),
                Err(err) => return Box::pin(std::future::ready(Err::<Conn, BoxError>(err))),
            },
        };

        // Ferrum patch 004: the dialed socket's descriptor, reported to the
        // admission hook once the connection exists. Costs one small allocation
        // per NEW physical connection; pooled reuse never reaches `call`.
        let established = EstablishedFd::new();

        // Local transports (UDS, Windows Named Pipes) skip proxies
        #[cfg(any(unix, target_os = "windows"))]
        if self.should_use_local_transport() {
            return Box::pin(with_admission(
                with_timeout(self.clone().connect_local_transport(dst), timeout),
                admission,
                self.connection_admission.clone(),
                established,
            ));
        }

        for prox in self.proxies.iter() {
            if let Some(intercepted) = prox.intercept(&dst) {
                return Box::pin(with_admission(
                    with_timeout(
                        self.clone()
                            .connect_via_proxy(dst, intercepted, established.clone()),
                        timeout,
                    ),
                    admission,
                    self.connection_admission.clone(),
                    established,
                ));
            }
        }

        Box::pin(with_admission(
            with_timeout(
                self.clone()
                    .connect_with_maybe_proxy(dst, false, established.clone()),
                timeout,
            ),
            admission,
            self.connection_admission.clone(),
            established,
        ))
    }
}

#[cfg(feature = "__tls")]
trait TlsInfoFactory {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo>;
}

#[cfg(feature = "__tls")]
impl<T: TlsInfoFactory> TlsInfoFactory for TokioIo<T> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.inner().tls_info()
    }
}

// ===== TcpStream =====

#[cfg(feature = "__tls")]
impl TlsInfoFactory for tokio::net::TcpStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

#[cfg(feature = "__native-tls")]
impl TlsInfoFactory for tokio_native_tls::TlsStream<TokioIo<TokioIo<tokio::net::TcpStream>>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__native-tls")]
impl TlsInfoFactory
    for tokio_native_tls::TlsStream<
        TokioIo<hyper_tls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>>,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__native-tls")]
impl TlsInfoFactory for hyper_tls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_tls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_tls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(feature = "__rustls")]
impl TlsInfoFactory for tokio_rustls::client::TlsStream<TokioIo<TokioIo<tokio::net::TcpStream>>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__rustls")]
impl TlsInfoFactory
    for tokio_rustls::client::TlsStream<
        TokioIo<hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>>,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__rustls")]
impl TlsInfoFactory for hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_rustls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_rustls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

// ===== UnixStream =====

#[cfg(feature = "__tls")]
#[cfg(unix)]
impl TlsInfoFactory for tokio::net::UnixStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

#[cfg(feature = "__native-tls")]
#[cfg(unix)]
impl TlsInfoFactory for tokio_native_tls::TlsStream<TokioIo<TokioIo<tokio::net::UnixStream>>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__native-tls")]
#[cfg(unix)]
impl TlsInfoFactory
    for tokio_native_tls::TlsStream<
        TokioIo<hyper_tls::MaybeHttpsStream<TokioIo<tokio::net::UnixStream>>>,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__native-tls")]
#[cfg(unix)]
impl TlsInfoFactory for hyper_tls::MaybeHttpsStream<TokioIo<tokio::net::UnixStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_tls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_tls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(feature = "__rustls")]
#[cfg(unix)]
impl TlsInfoFactory for tokio_rustls::client::TlsStream<TokioIo<TokioIo<tokio::net::UnixStream>>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__rustls")]
#[cfg(unix)]
impl TlsInfoFactory
    for tokio_rustls::client::TlsStream<
        TokioIo<hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::UnixStream>>>,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__rustls")]
#[cfg(unix)]
impl TlsInfoFactory for hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::UnixStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_rustls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_rustls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

// ===== NamedPipe =====

#[cfg(feature = "__tls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory for tokio::net::windows::named_pipe::NamedPipeClient {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

#[cfg(feature = "__native-tls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory
    for tokio_native_tls::TlsStream<
        TokioIo<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__native-tls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory
    for tokio_native_tls::TlsStream<
        TokioIo<
            hyper_tls::MaybeHttpsStream<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>,
        >,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__native-tls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory
    for hyper_tls::MaybeHttpsStream<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_tls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_tls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(feature = "__rustls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory
    for tokio_rustls::client::TlsStream<
        TokioIo<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__rustls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory
    for tokio_rustls::client::TlsStream<
        TokioIo<
            hyper_rustls::MaybeHttpsStream<
                TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>,
            >,
        >,
    >
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "__rustls")]
#[cfg(target_os = "windows")]
impl TlsInfoFactory
    for hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_rustls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_rustls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

pub(crate) trait AsyncConn:
    Read + Write + Connection + Send + Sync + Unpin + 'static
{
}

impl<T: Read + Write + Connection + Send + Sync + Unpin + 'static> AsyncConn for T {}

#[cfg(feature = "__tls")]
trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}
#[cfg(not(feature = "__tls"))]
trait AsyncConnWithInfo: AsyncConn {}

#[cfg(feature = "__tls")]
impl<T: AsyncConn + TlsInfoFactory> AsyncConnWithInfo for T {}
#[cfg(not(feature = "__tls"))]
impl<T: AsyncConn> AsyncConnWithInfo for T {}

type BoxConn = Box<dyn AsyncConnWithInfo>;

pub(crate) mod sealed {
    use super::*;
    #[derive(Debug)]
    pub struct Unnameable(pub(super) Uri);

    pin_project! {
        /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
        /// This tells hyper whether the URI should be written in
        /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
        /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
        #[allow(missing_debug_implementations)]
        pub struct Conn {
            #[pin]
            pub(super)inner: BoxConn,
            pub(super) is_proxy: bool,
            // Only needed for __tls, but #[cfg()] on fields breaks pin_project!
            pub(super) tls_info: bool,
        }
    }

    impl Connection for Conn {
        fn connected(&self) -> Connected {
            let connected = self.inner.connected().proxy(self.is_proxy);
            #[cfg(feature = "__tls")]
            if self.tls_info {
                if let Some(tls_info) = self.inner.tls_info() {
                    connected.extra(tls_info)
                } else {
                    connected
                }
            } else {
                connected
            }
            #[cfg(not(feature = "__tls"))]
            connected
        }
    }

    impl Read for Conn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl Write for Conn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
            let this = self.project();
            Write::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
            let this = self.project();
            Write::poll_shutdown(this.inner, cx)
        }
    }
}

// Some sealed things for UDS
#[cfg(unix)]
pub(crate) mod uds {
    use std::path::Path;

    /// A provider for Unix Domain Socket paths.
    ///
    /// This trait is sealed. This allows us expand the support in the future
    /// by controlling who can implement the trait.
    ///
    /// It's available in the docs to see what type may be passed in.
    #[cfg(unix)]
    pub trait UnixSocketProvider {
        #[doc(hidden)]
        fn reqwest_uds_path(&self, _: Internal) -> &Path;
    }

    #[allow(missing_debug_implementations)]
    pub struct Internal;

    macro_rules! as_path {
        ($($t:ty,)+) => {
            $(
                impl UnixSocketProvider for $t {
                    #[doc(hidden)]
                    fn reqwest_uds_path(&self, _: Internal) -> &Path {
                        self.as_ref()
                    }
                }
            )+
        }
    }

    as_path![
        String,
        &'_ str,
        &'_ Path,
        std::path::PathBuf,
        std::sync::Arc<Path>,
    ];
}

// Sealed trait for Windows Named Pipe support
#[cfg(target_os = "windows")]
pub(crate) mod windows_named_pipe {
    use std::ffi::OsStr;
    /// A provider for Windows Named Pipe paths.
    ///
    /// This trait is sealed. This allows us to expand support in the future
    /// by controlling who can implement the trait.
    #[cfg(target_os = "windows")]
    pub trait WindowsNamedPipeProvider {
        #[doc(hidden)]
        fn reqwest_windows_named_pipe_path(&self, _: Internal) -> &OsStr;
    }

    #[allow(missing_debug_implementations)]
    pub struct Internal;

    macro_rules! as_os_str {
        ($($t:ty,)+) => {
            $(
                impl WindowsNamedPipeProvider for $t {
                    #[doc(hidden)]
                    fn reqwest_windows_named_pipe_path(&self, _: Internal) -> &OsStr {
                        self.as_ref()
                    }
                }
            )+
        }
    }

    as_os_str![
        String,
        &'_ str,
        std::path::PathBuf,
        &'_ std::path::Path,
        std::ffi::OsString,
        &'_ OsStr,
    ];
}

pub(crate) type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

#[cfg(feature = "__native-tls")]
mod native_tls_conn {
    use super::TlsInfoFactory;
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_tls::MaybeHttpsStream;
    use hyper_util::client::legacy::connect::{Connected, Connection};
    use hyper_util::rt::TokioIo;
    use pin_project_lite::pin_project;
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;
    use tokio_native_tls::TlsStream;

    pin_project! {
        pub(super) struct NativeTlsConn<T> {
            #[pin] pub(super) inner: TokioIo<TlsStream<T>>,
        }
    }

    impl Connection for NativeTlsConn<TokioIo<TokioIo<TcpStream>>> {
        fn connected(&self) -> Connected {
            let connected = self
                .inner
                .inner()
                .get_ref()
                .get_ref()
                .get_ref()
                .inner()
                .connected();
            #[cfg(feature = "__native-tls-alpn")]
            match self.inner.inner().get_ref().negotiated_alpn().ok() {
                Some(Some(alpn_protocol)) if alpn_protocol == b"h2" => connected.negotiated_h2(),
                _ => connected,
            }
            #[cfg(not(feature = "__native-tls-alpn"))]
            connected
        }
    }

    impl Connection for NativeTlsConn<TokioIo<MaybeHttpsStream<TokioIo<TcpStream>>>> {
        fn connected(&self) -> Connected {
            let connected = self
                .inner
                .inner()
                .get_ref()
                .get_ref()
                .get_ref()
                .inner()
                .connected();
            #[cfg(feature = "__native-tls-alpn")]
            match self.inner.inner().get_ref().negotiated_alpn().ok() {
                Some(Some(alpn_protocol)) if alpn_protocol == b"h2" => connected.negotiated_h2(),
                _ => connected,
            }
            #[cfg(not(feature = "__native-tls-alpn"))]
            connected
        }
    }

    #[cfg(unix)]
    impl Connection for NativeTlsConn<TokioIo<TokioIo<tokio::net::UnixStream>>> {
        fn connected(&self) -> Connected {
            let connected = Connected::new();
            #[cfg(feature = "__native-tls-alpn")]
            match self.inner.inner().get_ref().negotiated_alpn().ok() {
                Some(Some(alpn_protocol)) if alpn_protocol == b"h2" => connected.negotiated_h2(),
                _ => connected,
            }
            #[cfg(not(feature = "__native-tls-alpn"))]
            connected
        }
    }

    #[cfg(unix)]
    impl Connection for NativeTlsConn<TokioIo<MaybeHttpsStream<TokioIo<tokio::net::UnixStream>>>> {
        fn connected(&self) -> Connected {
            let connected = Connected::new();
            #[cfg(feature = "__native-tls-alpn")]
            match self.inner.inner().get_ref().negotiated_alpn().ok() {
                Some(Some(alpn_protocol)) if alpn_protocol == b"h2" => connected.negotiated_h2(),
                _ => connected,
            }
            #[cfg(not(feature = "__native-tls-alpn"))]
            connected
        }
    }

    #[cfg(target_os = "windows")]
    impl Connection
        for NativeTlsConn<TokioIo<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>>
    {
        fn connected(&self) -> Connected {
            let connected = Connected::new();
            #[cfg(feature = "__native-tls-alpn")]
            match self.inner.inner().get_ref().negotiated_alpn().ok() {
                Some(Some(alpn_protocol)) if alpn_protocol == b"h2" => connected.negotiated_h2(),
                _ => connected,
            }
            #[cfg(not(feature = "__native-tls-alpn"))]
            connected
        }
    }

    #[cfg(target_os = "windows")]
    impl Connection
        for NativeTlsConn<
            TokioIo<MaybeHttpsStream<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>>,
        >
    {
        fn connected(&self) -> Connected {
            let connected = Connected::new();
            #[cfg(feature = "__native-tls-alpn")]
            match self.inner.inner().get_ref().negotiated_alpn().ok() {
                Some(Some(alpn_protocol)) if alpn_protocol == b"h2" => connected.negotiated_h2(),
                _ => connected,
            }
            #[cfg(not(feature = "__native-tls-alpn"))]
            connected
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Read for NativeTlsConn<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Write for NativeTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            Write::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_shutdown(this.inner, cx)
        }
    }

    impl<T> TlsInfoFactory for NativeTlsConn<T>
    where
        TokioIo<TlsStream<T>>: TlsInfoFactory,
    {
        fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }
}

#[cfg(feature = "__rustls")]
mod rustls_tls_conn {
    use super::TlsInfoFactory;
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_rustls::MaybeHttpsStream;
    use hyper_util::client::legacy::connect::{Connected, Connection};
    use hyper_util::rt::TokioIo;
    use pin_project_lite::pin_project;
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    pin_project! {
        pub(super) struct RustlsTlsConn<T> {
            #[pin] pub(super) inner: TokioIo<TlsStream<T>>,
        }
    }

    impl Connection for RustlsTlsConn<TokioIo<TokioIo<TcpStream>>> {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }
    impl Connection for RustlsTlsConn<TokioIo<MaybeHttpsStream<TokioIo<TcpStream>>>> {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }

    #[cfg(unix)]
    impl Connection for RustlsTlsConn<TokioIo<TokioIo<tokio::net::UnixStream>>> {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }

    #[cfg(unix)]
    impl Connection for RustlsTlsConn<TokioIo<MaybeHttpsStream<TokioIo<tokio::net::UnixStream>>>> {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }

    #[cfg(target_os = "windows")]
    impl Connection
        for RustlsTlsConn<TokioIo<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>>
    {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }

    #[cfg(target_os = "windows")]
    impl Connection
        for RustlsTlsConn<
            TokioIo<MaybeHttpsStream<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>>>,
        >
    {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Read for RustlsTlsConn<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Write for RustlsTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            Write::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_shutdown(this.inner, cx)
        }
    }
    impl<T> TlsInfoFactory for RustlsTlsConn<T>
    where
        TokioIo<TlsStream<T>>: TlsInfoFactory,
    {
        fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }
}

#[cfg(feature = "socks")]
mod socks {
    use tower_service::Service;

    use http::uri::Scheme;
    use http::Uri;
    use hyper_util::client::legacy::connect::proxy::{SocksV4, SocksV5};
    use tokio::net::TcpStream;

    use super::BoxError;
    use crate::proxy::Intercepted;

    pub(super) enum DnsResolve {
        Local,
        Proxy,
    }

    #[derive(Debug)]
    pub(super) enum SocksProxyError {
        SocksNoHostInUrl,
        SocksLocalResolve(BoxError),
        SocksConnect(BoxError),
    }

    pub(super) async fn connect(
        proxy: Intercepted,
        dst: Uri,
        dns_mode: DnsResolve,
        resolver: &crate::dns::DynResolver,
        http_connector: &mut crate::connect::HttpConnector,
    ) -> Result<TcpStream, SocksProxyError> {
        let https = dst.scheme() == Some(&Scheme::HTTPS);
        let original_host = dst.host().ok_or(SocksProxyError::SocksNoHostInUrl)?;
        let mut host = original_host.to_owned();
        let port = match dst.port() {
            Some(p) => p.as_u16(),
            None if https => 443u16,
            _ => 80u16,
        };

        if let DnsResolve::Local = dns_mode {
            let maybe_new_target = resolver
                .http_resolve(&dst)
                .await
                .map_err(SocksProxyError::SocksLocalResolve)?
                .next();
            if let Some(new_target) = maybe_new_target {
                log::trace!("socks local dns resolved {new_target:?}");
                // If the resolved IP is IPv6, wrap it in brackets for URI formatting
                let ip = new_target.ip();
                if ip.is_ipv6() {
                    host = format!("[{}]", ip);
                } else {
                    host = ip.to_string();
                }
            }
        }

        let proxy_uri = proxy.uri().clone();
        // Build a Uri for the destination
        let dst_uri = format!(
            "{}://{}:{}",
            if https { "https" } else { "http" },
            host,
            port
        )
        .parse::<Uri>()
        .map_err(|e| SocksProxyError::SocksConnect(e.into()))?;

        // TODO: can `Scheme::from_static()` be const fn, compare with a SOCKS5 constant?
        match proxy.uri().scheme_str() {
            Some("socks4") | Some("socks4a") => {
                let mut svc = SocksV4::new(proxy_uri, http_connector);
                let stream = Service::call(&mut svc, dst_uri)
                    .await
                    .map_err(|e| SocksProxyError::SocksConnect(e.into()))?;
                Ok(stream.into_inner())
            }
            Some("socks5") | Some("socks5h") => {
                let mut svc = if let Some((username, password)) = proxy.raw_auth() {
                    SocksV5::new(proxy_uri, http_connector)
                        .with_auth(username.to_string(), password.to_string())
                } else {
                    SocksV5::new(proxy_uri, http_connector)
                };
                let stream = Service::call(&mut svc, dst_uri)
                    .await
                    .map_err(|e| SocksProxyError::SocksConnect(e.into()))?;
                Ok(stream.into_inner())
            }
            _ => unreachable!(),
        }
    }

    impl std::fmt::Display for SocksProxyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SocksNoHostInUrl => f.write_str("socks proxy destination has no host"),
                Self::SocksLocalResolve(_) => f.write_str("error resolving for socks proxy"),
                Self::SocksConnect(_) => f.write_str("error connecting to socks proxy"),
            }
        }
    }

    impl std::error::Error for SocksProxyError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::SocksNoHostInUrl => None,
                Self::SocksLocalResolve(ref e) => Some(&**e),
                Self::SocksConnect(ref e) => Some(&**e),
            }
        }
    }
}

mod verbose {
    use crate::util::Escape;
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_util::client::legacy::connect::{Connected, Connection};
    use std::cmp::min;
    use std::fmt;
    use std::io::{self, IoSlice};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub(super) const OFF: Wrapper = Wrapper(false);

    #[derive(Clone, Copy)]
    pub(super) struct Wrapper(pub(super) bool);

    impl Wrapper {
        pub(super) fn wrap<T: super::AsyncConnWithInfo>(&self, conn: T) -> super::BoxConn {
            if self.0 && log::log_enabled!(log::Level::Trace) {
                Box::new(Verbose {
                    // truncate is fine
                    id: crate::util::fast_random() as u32,
                    inner: conn,
                })
            } else {
                Box::new(conn)
            }
        }
    }

    struct Verbose<T> {
        id: u32,
        inner: T,
    }

    impl<T: Connection + Read + Write + Unpin> Connection for Verbose<T> {
        fn connected(&self) -> Connected {
            self.inner.connected()
        }
    }

    impl<T: Read + Write + Unpin> Read for Verbose<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            mut buf: ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            // TODO: This _does_ forget the `init` len, so it could result in
            // re-initializing twice. Needs upstream support, perhaps.
            // SAFETY: Passing to a ReadBuf will never de-initialize any bytes.
            let mut vbuf = hyper::rt::ReadBuf::uninit(unsafe { buf.as_mut() });
            match Pin::new(&mut self.inner).poll_read(cx, vbuf.unfilled()) {
                Poll::Ready(Ok(())) => {
                    log::trace!("{:08x} read: {:?}", self.id, Escape::new(vbuf.filled()));
                    let len = vbuf.filled().len();
                    // SAFETY: The two cursors were for the same buffer. What was
                    // filled in one is safe in the other.
                    unsafe {
                        buf.advance(len);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T: Read + Write + Unpin> Write for Verbose<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    log::trace!("{:08x} write: {:?}", self.id, Escape::new(&buf[..n]));
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
                Poll::Ready(Ok(nwritten)) => {
                    log::trace!(
                        "{:08x} write (vectored): {:?}",
                        self.id,
                        Vectored { bufs, nwritten }
                    );
                    Poll::Ready(Ok(nwritten))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "__tls")]
    impl<T: super::TlsInfoFactory> super::TlsInfoFactory for Verbose<T> {
        fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }

    struct Vectored<'a, 'b> {
        bufs: &'a [IoSlice<'b>],
        nwritten: usize,
    }

    impl fmt::Debug for Vectored<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut left = self.nwritten;
            for buf in self.bufs.iter() {
                if left == 0 {
                    break;
                }
                let n = min(left, buf.len());
                Escape::new(&buf[..n]).fmt(f)?;
                left -= n;
            }
            Ok(())
        }
    }
}
