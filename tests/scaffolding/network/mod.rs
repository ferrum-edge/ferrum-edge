//! Network-simulation stream wrappers for scripted-backend tests.
//!
//! Phase 5 introduces two drop-in adapters that wrap any
//! `AsyncRead + AsyncWrite` stream and alter its timing:
//!
//! - [`latency::DelayedStream`] — inject a per-call `Duration` delay
//!   before every read and write. Models backend-side RTT.
//! - [`bandwidth::BandwidthLimitedStream`] — enforce a bytes-per-second
//!   ceiling on reads and writes using a token-bucket.
//!
//! ## Architecture choice — middleman proxy, not backend hook
//!
//! The wrappers operate at the `AsyncRead + AsyncWrite` layer. The
//! plan (§Phase 5) allowed either plumbing them into each scripted
//! backend's `accept` loop OR adding a stream-level hook via a proxy.
//! We chose the proxy:
//!
//! - **Less surgery.** Existing `ScriptedTcpBackend`, `ScriptedTlsBackend`,
//!   `ScriptedHttp1Backend` all take a concrete `TcpStream` and have
//!   backend-specific state (e.g., `TcpStep::Reset` calls
//!   `stream.into_std()` — TcpStream-only). Making them generic over
//!   `AsyncRead + AsyncWrite` would ripple through all three and their
//!   Phase-1 tests.
//! - **Drop-in composition.** A test wires the gateway at the proxy's
//!   port; the proxy applies the profile and forwards to whichever
//!   backend (http1 / tcp / tls) the test already set up.
//!
//! ## Usage
//!
//! ```ignore
//! // A scripted http1 backend.
//! let res_backend = reserve_port().await?;
//! let backend_port = res_backend.port;
//! let _backend = ScriptedHttp1Backend::builder(res_backend.into_listener())
//!     .step(...)
//!     .spawn()?;
//!
//! // A network-sim middleman in front of it.
//! let res_proxy = reserve_port().await?;
//! let middleman_port = res_proxy.port;
//! let _middleman = NetworkSimProxy::builder(res_proxy.into_listener())
//!     .with_latency(Duration::from_millis(50))
//!     .with_bandwidth_limit(1024 * 1024)
//!     .forward_to(("127.0.0.1", backend_port))
//!     .spawn()?;
//!
//! // Point the gateway at `middleman_port`; the middleman applies the
//! // profile to each accepted connection and relays to `backend_port`.
//! ```
//!
//! See the doc on each wrapper for the exact delay/limit semantics.

pub mod bandwidth;
pub mod latency;
pub mod proxy;

pub use bandwidth::BandwidthLimitedStream;
pub use latency::DelayedStream;
pub use proxy::{NetworkProfile, NetworkSimProxy, NetworkSimProxyBuilder};
