//! Network-simulation stream wrappers for scripted-backend tests.
//!
//! Phase 5 introduces three drop-in adapters that wrap any
//! `AsyncRead + AsyncWrite` stream and alter its timing or length
//! behaviour:
//!
//! - [`latency::DelayedStream`] — inject a per-call `Duration` delay
//!   before every read and write. Models backend-side RTT.
//! - [`bandwidth::BandwidthLimitedStream`] — enforce a bytes-per-second
//!   ceiling on reads and writes using a token-bucket.
//! - [`truncate::TruncatedStream`] — close the stream (EOF on read, error
//!   on write) after N bytes, optionally with a pre-close delay. Models
//!   backend mid-stream disconnection.
//!
//! ## Usage model — per-TCP-stream wrapping
//!
//! The wrappers operate at the `tokio::net::TcpStream` / generic
//! `AsyncRead + AsyncWrite` layer. They do NOT wrap a whole scripted
//! backend post-construction — that would require reaching inside the
//! backend's accept loop.
//!
//! Instead, the TCP scripted backend exposes a `stream_transform` hook:
//! the accept loop applies the transform to each accepted `TcpStream`
//! before running the script. [`ScriptedTcpBackend::with_latency`]
//! etc. are ergonomic shims that register these transforms.
//!
//! For the test authors, the canonical pattern is:
//!
//! ```ignore
//! let backend = ScriptedHttp1Backend::builder(listener)
//!     .step(...)
//!     .with_latency(Duration::from_millis(50))
//!     .with_bandwidth_limit(1024 * 1024)
//!     .with_truncate_after(8192)
//!     .spawn()?;
//! ```
//!
//! See the doc on each type for the exact delay/limit semantics.

pub mod bandwidth;
pub mod latency;
pub mod truncate;

pub use bandwidth::BandwidthLimitedStream;
pub use latency::DelayedStream;
pub use truncate::TruncatedStream;

use std::time::Duration;

/// Declarative description of the transformations applied to an
/// accepted stream. Combined by `ScriptedTcpBackend::with_*` setters;
/// applied in `(latency → bandwidth → truncate)` order so the delay
/// comes before the rate limit and the truncate happens last.
///
/// All fields are optional; an unset field is a no-op for that stage.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkProfile {
    /// Per-call delay for reads and writes.
    pub latency: Option<Duration>,
    /// Bytes-per-second ceiling for reads and writes. `None` = unlimited.
    pub bandwidth_bps: Option<u64>,
    /// Close the stream after this many total bytes have been read from
    /// OR written to the wrapped stream.
    pub truncate_after: Option<usize>,
    /// Delay inserted just before the truncate fires. Lets a test say
    /// "complete the response headers, then 500 ms later FIN the body
    /// at 8 KB". `None` = truncate immediately on reaching the
    /// threshold.
    pub truncate_delay: Option<Duration>,
}

impl NetworkProfile {
    pub fn is_noop(&self) -> bool {
        self.latency.is_none() && self.bandwidth_bps.is_none() && self.truncate_after.is_none()
    }
}
