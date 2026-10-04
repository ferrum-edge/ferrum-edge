//! Extensions specific to the HTTP/2 protocol.

use crate::hpack::BytesStr;

use bytes::Bytes;
use std::fmt;

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// FERRUM PATCH 002: an owned client-stream lifetime extension.
///
/// Insert into a client request to retain `owner` until h2 releases the active
/// stream: both halves have closed and queued frames and DATA have drained,
/// or a reset/connection teardown discards them. Dropping the request body or
/// a public send handle alone is not completion. Frames accepted by the codec
/// count as drained, as in h2's concurrent-stream accounting; this does not
/// promise peer receipt or a socket flush.
///
/// The owner's destructor must be cheap, non-blocking, and must not re-enter
/// h2: normal completion drops it under the existing stream-state lock. Keep
/// no h2 handles in the owner. Requests without this extension pay no new
/// allocation, task, or lock. Clones retain the same owner.
#[derive(Clone)]
pub struct StreamLifetime {
    _owner: std::sync::Arc<dyn Send + Sync>,
}

impl StreamLifetime {
    /// Retain an owner whose last drop records completion.
    pub fn new(owner: std::sync::Arc<dyn Send + Sync>) -> Self {
        Self { _owner: owner }
    }
}

impl fmt::Debug for StreamLifetime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("StreamLifetime").finish_non_exhaustive()
    }
}
