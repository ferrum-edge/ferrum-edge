//! Shared inventory for protocol-managed response-header destination tests.
//!
//! Kept under `tests/` so unit and functional suites can cite the same closed
//! set without adding production-visible test helpers.

/// Destinations rejected at `response_transformer` / `response_mock`
/// construction and stripped (except derived `Content-Length`) at the final
/// client-wire sanitizer.
pub const PROTOCOL_MANAGED_RESPONSE_DESTINATIONS: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
